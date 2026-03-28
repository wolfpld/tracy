#ifdef _WIN32
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <signal.h>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "../../getopt/getopt.h"
#include "../../public/common/TracySocket.hpp"
#include "../../public/common/TracyVersion.hpp"
#include "../../server/TracyBroadcast.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyMemory.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracySysUtil.hpp"
#include "../../server/TracyWorker.hpp"
#include "GitRef.hpp"

#include "CaptureOutput.hpp"

static std::atomic<bool> g_shutdown{false};
static std::mutex g_clientsMutex;
static uint16_t g_listenPort = 8086;
static std::string g_filterName;
static int g_filterPort = 0;
static int64_t g_memoryLimit = -1;

void SigInt( int )
{
    g_shutdown.store( true, std::memory_order_relaxed );
}

struct ClientStats
{
    std::atomic<float> mbps{0};
    std::atomic<int64_t> txBytes{0};
    std::atomic<int64_t> memUsage{0};
    std::atomic<int64_t> firstTime{-1};
};

struct ClientSession
{
    std::string id;
    std::string programName;
    std::string address;
    uint16_t port;
    std::string outputFile;
    std::thread thread;
    std::atomic<bool> active{true};
    std::atomic<bool> finished{false};
    ClientStats stats;
    std::atomic<uint64_t> fileSize{0};
};

static std::map<std::string, ClientSession*> g_clients;
static std::unordered_set<std::string> g_outputFiles;

[[noreturn]] void Usage()
{
    printf( "tracy-capture-daemon %i.%i.%i / %s\n\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Usage: tracy-capture-daemon -o <output_dir> [options]\n\n" );
    printf( "Options:\n" );
    printf( "  -o, --output <dir>       Output directory (required)\n" );
    printf( "  -p, --port <port>        UDP listen port (default: 8086)\n" );
    printf( "  -m, --memory <limit>     Memory limit per client as %% of system RAM\n" );
    printf( "  --filter-name <pattern>  Only capture clients matching program name\n" );
    printf( "  --filter-port <port>     Only capture clients with specific data port\n" );
    printf( "  -h, --help               Show this help\n" );
    printf( "  -V, --version            Show version information\n" );
    exit( 1 );
}

std::string SanitizeName( const std::string& name )
{
    std::string result;
    for( char c : name )
    {
        if( ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' ) || ( c >= '0' && c <= '9' ) || c == '_' || c == '-' )
        {
            result += c;
        }
        else if( c == ' ' || c == '\t' )
        {
            result += '_';
        }
    }
    if( result.empty() ) result = "unknown";
    return result;
}

std::string GenerateOutputFilename( const std::string& outputDir, const std::string& programName, const std::string& address, uint16_t port )
{
    std::string base = SanitizeName( programName ) + "_" + address + "_" + std::to_string( port );
    std::string candidate = base + ".tracy";
    std::string path = outputDir + "/" + candidate;
    
    int idx = 0;
    while( g_outputFiles.count( path ) || std::filesystem::exists( path ) )
    {
        idx++;
        candidate = base + "_" + std::to_string( idx ) + ".tracy";
        path = outputDir + "/" + candidate;
    }
    
    g_outputFiles.insert( path );
    return path;
}

bool MatchesFilters( const tracy::BroadcastMessage& msg )
{
    if( !g_filterName.empty() )
    {
        if( strstr( msg.programName, g_filterName.c_str() ) == nullptr )
        {
            return false;
        }
    }
    if( g_filterPort > 0 && msg.listenPort != g_filterPort )
    {
        return false;
    }
    return true;
}

void CaptureThread( ClientSession* session, const std::string& address, uint16_t port, int64_t memoryLimit, const std::string& outputFile )
{
    printf( "Connecting to %s:%u...\n", address.c_str(), port );
    fflush( stdout );
    
    tracy::Worker worker( address.c_str(), port, memoryLimit );
    
    int result = WaitForConnection( worker );
    if( result != 0 )
    {
        session->active = false;
        session->finished = true;
        return;
    }
    
    printf( "Connected to %s (%s:%u)\n", session->programName.c_str(), address.c_str(), port );
    
    int64_t firstTime = worker.GetFirstTime();
    session->stats.firstTime = firstTime;
    
    while( session->active && worker.IsConnected() )
    {
        auto& lock = worker.GetMbpsDataLock();
        lock.lock();
        float mbps = worker.GetMbpsData().back();
        int64_t txTotal = worker.GetDataTransferred();
        lock.unlock();
        
        session->stats.mbps = mbps;
        session->stats.txBytes = txTotal;
        session->stats.memUsage = tracy::memUsage.load( std::memory_order_relaxed );
        
        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    }
    
    printf( "\nSaving %s...", outputFile.c_str() );
    fflush( stdout );
    
    auto file = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( outputFile.c_str(), tracy::FileCompression::Zstd, 3, 4 ) );
    if( file )
    {
        worker.Write( *file, false );
        file->Finish();
        auto stats = file->GetCompressionStatistics();
        session->fileSize = stats.second;
        AnsiPrintf( ANSI_GREEN ANSI_BOLD, " done!\n" );
    }
    else
    {
        AnsiPrintf( ANSI_RED ANSI_BOLD, " failed!\n" );
    }
    
    session->finished = true;
    session->active = false;
}

void RefreshDisplay( const std::string& listenAddr )
{
    if( !IsTerminal() ) return;
    
    printf( "\033[H\033[J" );
    
    size_t clientCount = 0;
    {
        std::lock_guard<std::mutex> lock( g_clientsMutex );
        clientCount = g_clients.size();
    }
    
    printf( "[%zu client%s] Listening on %s:%u... Press Ctrl+C to stop\n\n", clientCount, clientCount == 1 ? "" : "s", listenAddr.c_str(), g_listenPort );
    
    int idx = 1;
    float totalMbps = 0;
    int64_t totalTx = 0;
    int64_t totalMem = 0;
    
    {
        std::lock_guard<std::mutex> lock( g_clientsMutex );
        for( auto& [id, session] : g_clients )
        {
            printf( "  [%d] %s @ %s:%u    ", idx, session->programName.c_str(), session->address.c_str(), session->port );
            
            if( session->finished )
            {
                printf( "finished (" );
                printf( "%s", tracy::MemSizeToString( session->fileSize.load() ) );
                printf( ")" );
            }
            else if( session->active )
            {
                float mbps = session->stats.mbps.load();
                int64_t tx = session->stats.txBytes.load();
                int64_t mem = session->stats.memUsage.load();
                int64_t firstTime = session->stats.firstTime.load();
                
                printf( "%.1f Mbps | %s | %s", mbps, tracy::MemSizeToString( tx ), tracy::MemSizeToString( mem ) );
                
                totalMbps += mbps;
                totalTx += tx;
                totalMem += mem;
            }
            else
            {
                printf( "connecting..." );
            }
            printf( "\n" );
            idx++;
        }
    }
    
    printf( "\nTotal: %.1f Mbps | %s | Mem: %s", totalMbps, tracy::MemSizeToString( totalTx ), tracy::MemSizeToString( totalMem ) );
    fflush( stdout );
}

void PrintSummary()
{
    printf( "\n\n=== Capture Summary ===\n" );
    
    std::lock_guard<std::mutex> lock( g_clientsMutex );
    int idx = 1;
    int64_t totalSize = 0;
    
    for( auto& [id, session] : g_clients )
    {
        int64_t size = session->fileSize.load();
        totalSize += size;
        printf( "  [%d] %s @ %s:%u -> %s (%s)\n", idx++, session->programName.c_str(), session->address.c_str(), session->port, session->outputFile.c_str(), tracy::MemSizeToString( size ) );
    }
    
    printf( "\nTotal: %zu files, %s\n", g_clients.size(), tracy::MemSizeToString( totalSize ) );
}

int main( int argc, char** argv )
{
#ifdef _WIN32
    if( !AttachConsole( ATTACH_PARENT_PROCESS ) )
    {
        AllocConsole();
        SetConsoleMode( GetStdHandle( STD_OUTPUT_HANDLE ), 0x07 );
    }
#endif
    
    std::string outputDir;
    
    static struct option longOptions[] = {
        { "output", required_argument, nullptr, 'o' },
        { "port", required_argument, nullptr, 'p' },
        { "memory", required_argument, nullptr, 'm' },
        { "filter-name", required_argument, nullptr, 1 },
        { "filter-port", required_argument, nullptr, 2 },
        { "help", no_argument, nullptr, 'h' },
        { "version", no_argument, nullptr, 'V' },
        { nullptr, 0, nullptr, 0 }
    };
    
    int c;
    while( ( c = getopt_long( argc, argv, "o:p:m:hV", longOptions, nullptr ) ) != -1 )
    {
        switch( c )
        {
        case 'o':
            outputDir = optarg;
            break;
        case 'p':
            g_listenPort = atoi( optarg );
            break;
        case 'm':
            g_memoryLimit = std::clamp( atoll( optarg ), 1ll, 999ll ) * tracy::GetPhysicalMemorySize() / 100;
            break;
        case 1:
            g_filterName = optarg;
            break;
        case 2:
            g_filterPort = atoi( optarg );
            break;
        case 'h':
            Usage();
            break;
        case 'V':
            printf( "tracy-capture-daemon %i.%i.%i / %s\n", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
            exit( 0 );
        default:
            Usage();
            break;
        }
    }
    
    if( outputDir.empty() )
    {
        fprintf( stderr, "Error: Output directory is required (-o)\n\n" );
        Usage();
    }
    
    std::filesystem::create_directories( outputDir );
    
    InitTerminalDetection();
    
#ifdef _WIN32
    signal( SIGINT, SigInt );
#else
    struct sigaction sigint, oldsigint;
    memset( &sigint, 0, sizeof( sigint ) );
    sigint.sa_handler = SigInt;
    sigaction( SIGINT, &sigint, &oldsigint );
#endif
    
    tracy::UdpListen udpSocket;
    if( !udpSocket.Listen( g_listenPort ) )
    {
        fprintf( stderr, "Error: Failed to listen on port %u\n", g_listenPort );
        return 1;
    }
    
    printf( "Listening on 0.0.0.0:%u... Press Ctrl+C to stop\n", g_listenPort );
    printf( "Output directory: %s\n", outputDir.c_str() );
    
    const std::string listenAddr = "0.0.0.0";
    auto lastDisplay = std::chrono::steady_clock::now();
    
    while( !g_shutdown )
    {
        tracy::IpAddress clientAddr;
        size_t len;
        const char* msg = udpSocket.Read( len, clientAddr, 100 );
        
        if( msg )
        {
            auto parsed = tracy::ParseBroadcastMessage( msg, len );
            if( parsed )
            {
                std::string clientId = std::to_string( parsed->pid ) + "_" + clientAddr.GetText() + "_" + std::to_string( parsed->listenPort );
                
                bool isNew = false;
                {
                    std::lock_guard<std::mutex> lock( g_clientsMutex );
                    isNew = g_clients.find( clientId ) == g_clients.end();
                }
                
                if( isNew && MatchesFilters( *parsed ) )
                {
                    std::string addressStr = clientAddr.GetText();
                    std::string outputFile = GenerateOutputFilename( outputDir, parsed->programName, addressStr, parsed->listenPort );
                    
                    auto session = new ClientSession();
                    session->id = clientId;
                    session->programName = parsed->programName;
                    session->address = addressStr;
                    session->port = parsed->listenPort;
                    session->outputFile = outputFile;
                    session->active = true;
                    
                    {
                        std::lock_guard<std::mutex> lock( g_clientsMutex );
                        g_clients[clientId] = session;
                    }
                    
                    session->thread = std::thread( CaptureThread, session, addressStr, parsed->listenPort, g_memoryLimit, outputFile );
                }
            }
        }
        
        auto now = std::chrono::steady_clock::now();
        if( std::chrono::duration_cast<std::chrono::milliseconds>( now - lastDisplay ).count() >= 100 )
        {
            RefreshDisplay( listenAddr );
            lastDisplay = now;
        }
    }
    
    printf( "\n\nShutting down... waiting for %zu client(s) to finish\n", g_clients.size() );
    
    {
        std::lock_guard<std::mutex> lock( g_clientsMutex );
        for( auto& [id, session] : g_clients )
        {
            session->active = false;
        }
    }
    
    {
        std::lock_guard<std::mutex> lock( g_clientsMutex );
        for( auto& [id, session] : g_clients )
        {
            if( session->thread.joinable() )
            {
                session->thread.join();
            }
        }
    }
    
    PrintSummary();
    
    {
        std::lock_guard<std::mutex> lock( g_clientsMutex );
        for( auto& [id, session] : g_clients )
        {
            delete session;
        }
        g_clients.clear();
    }
    
    return 0;
}
