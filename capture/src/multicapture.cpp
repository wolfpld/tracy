#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <signal.h>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>
#ifdef _WIN32
#    include <windows.h>
#else
#    include <unistd.h>
#endif

#include "../../getopt/getopt.h" // windows and apple clang don't provide getopt_long

#include "TracyFileWrite.hpp"
#include "TracyPrint.hpp"
#include "TracyProtocol.hpp"
#include "TracyProtocolServer.hpp"
#include "TracySocket.hpp"
#include "TracySysUtil.hpp"
#include "TracyWorker.hpp"
#include "tracy_lz4.hpp"

#include "lib.cpp"

using namespace std::chrono_literals;

constexpr const char* TRACE_FILE_SUFFIX = ".tracy";

static std::atomic<bool> s_disconnect{ false };

void SignalHandler_SigInt( int )
{
    // We don't need stronger ordering since this signal handler doesn't do
    // anything else that would need to be ordered relatively to this.
    s_disconnect.store( true, std::memory_order_relaxed );
}

void SetupDisconnectSignalHandler()
{
#ifdef _WIN32
    signal( SIGINT, SignalHandler_SigInt );
#else
    struct sigaction sigint, oldsigint;
    memset( &sigint, 0, sizeof( sigint ) );
    sigint.sa_handler = SignalHandler_SigInt;
    sigaction( SIGINT, &sigint, &oldsigint );
#endif
}

enum class ClientStatus
{
    DISCOVERED,
    RUNNING,
    FINISHED,
    DISABLED
};

struct RunningClient
{
    uint64_t id;
    ClientStatus status;
    tracy::BroadcastMessage msg;
    char addr[tracy::IpAddress::TEXT_SIZE];
    std::unique_ptr<tracy::Worker> worker = nullptr;
    bool disconnectSent = false;
    std::chrono::time_point<std::chrono::high_resolution_clock> detectedAt;
    std::chrono::time_point<std::chrono::high_resolution_clock> finishedAt;

    RunningClient() = default;

    RunningClient( RunningClient&& in )
        : id{ in.id }
        , status{ in.status }
        , msg{ in.msg }
        , worker{ std::move( in.worker ) }
        , disconnectSent{ in.disconnectSent }
        , detectedAt{ in.detectedAt }
        , finishedAt{ in.finishedAt }
    {
        memcpy( addr, in.addr, tracy::IpAddress::TEXT_SIZE );
    }

    explicit RunningClient( tracy::BroadcastMessage const& inmsg, tracy::IpAddress const& inaddr )
        : msg{ inmsg } // copied from profiler/main.cpp TODO: merge put in stdlib
        , status{ ClientStatus::DISCOVERED }
        , id{ tracy::ClientUniqueID( inaddr, inmsg.listenPort ) }
        , detectedAt( std::chrono::high_resolution_clock::now() )
    {
        memcpy( addr, inaddr.GetText(), tracy::IpAddress::TEXT_SIZE );
    }

    std::string saveName( std::string const& prefix ) const
    {
        std::ostringstream oss;
        oss << prefix << msg.pid << "-" << msg.programName << ".tracy";
        return oss.str();
    }

    std::string runtimeName() const
    {
        std::ostringstream oss;
        oss << "[" << msg.pid << "] " << msg.programName;
        return oss.str();
    }
};

std::optional<RunningClient> receive_client_broadcast( tracy::UdpListen* socket )
{
    tracy::IpAddress addr;
    size_t msgLen;
    auto msg = socket->Read( msgLen, addr, 0 );
    if( !msg ) return std::nullopt;
    auto parsed = tracy::ParseBroadcastMessage( msg, msgLen );
    if( parsed.has_value() )
    {
        auto msg = parsed.value();
        return RunningClient( msg, addr );
    }
    return std::nullopt;
}

std::ostream& operator<<( std::ostream& os, RunningClient const& client )
{
    os << client.msg.programName << "@" << client.msg.pid;
    return os;
}

constexpr const std::chrono::nanoseconds MULTI_CAPTURE_LOOP_INTERVAL = 100ms;
constexpr const std::chrono::nanoseconds PRINT_UPDATE_INTERVAL = 200ms;

[[noreturn]] void Usage()
{
    printf( "Usage: capture -o <output/prefix> [--multi] [-a address] [-p port] [-s seconds] [-m percent]\n" );

    printf( "Options (a SINGLE tag indicates the option is only accessible in single capture mode):\n" );
    printf( "  -o/--output <str>        Output file path (in MULTI mode, it is interpreted as a prefix)\n" );
    printf( "  -f/--force               Overwrite existing files\n" );
    printf( "  -M/--multi               Enable multi-capture mode\n" );
    printf( "  -v/--verbose             Verbose output\n" );

    printf( "  -a/--address <ipv4 str>  [SINGLE] Target IP address\n" );
    printf( "  -p/--port <int>          [SINGLE] Target port\n" );
    printf( "  -s/--stop-after <float>  [SINGLE] Stop profiling after this duration (in seconds) \n" );
    printf( "  -m/--memlimit <float>    [SINGLE] Set a memory limit (in %% of the total RAM)\n" );

    printf( "\nIn single-capture mode, 'capture' directly connects to the TCP data stream at address:port .\n" );
    printf( "In multi-capture mode, profiled targets are detected from UDP broadcast packets;\n" );
    printf( "capture stops once all detected targets disconnect.\n" );
    printf( "Output files are of the form <prefix>.<client_pid>.tracy\n" );

    exit( 1 );
}

struct CaptureArgs
{
    std::filesystem::path outputPath;

    std::filesystem::path outputDirectory; // filled from 'output'
    std::string outputFileName;            // filled from 'output'. In multi mode, contains "<prefix>."

    bool multi = false;
    std::string address = "127.0.0.1";
    uint16_t port = tracy::DEFAULT_CLIENT_DATA_TCP_PORT;
    std::chrono::milliseconds stopAfter = -1ms;
    bool verbose = false;
    bool overwrite = false;
    int64_t memoryLimit = tracy::NO_WORKER_MEMORY_LIMIT;

    // option parsing
    static CaptureArgs parse( int argc, char* argv[] )
    {
        CaptureArgs args;
        bool setIncompatibleOptionWithMultiCapture = false;
        int c;
        const struct option long_options[] = { { "memlimit", required_argument, 0, 'm' },
                                               { "multi", no_argument, 0, 'M' },
                                               { "stop-after", required_argument, 0, 's' },
                                               { "address", required_argument, 0, 'a' },
                                               { "port", required_argument, 0, 'p' },
                                               { "verbose", no_argument, 0, 'v' },
                                               { "output", required_argument, 0, 'o' },
                                               { "force", no_argument, 0, 'f' },
                                               { 0, 0, 0, 0 } };
        while( ( c = getopt_long( argc, argv, "o:m:a:p:s:Mfv", long_options, nullptr ) ) != -1 )
        {
            switch( c )
            {
            case 'o':
                args.outputPath = optarg;
                break;
            case 'M':
                args.multi = true;
                break;
            case 'v':
                args.verbose = true;
                break;
            case 'f':
                args.overwrite = true;
                break;
            case 'm':
                args.memoryLimit = atol( optarg );
                args.memoryLimit = std::clamp( atoll( optarg ), 1ll, 999ll ) * tracy::GetPhysicalMemorySize() / 100;
                setIncompatibleOptionWithMultiCapture = true;
                break;
            case 'a':
                args.address = optarg;
                setIncompatibleOptionWithMultiCapture = true;
                break;
            case 'p':
                args.port = atoi( optarg );
                setIncompatibleOptionWithMultiCapture = true;
                break;
            case 's':
            {
                float stopAfterInSeconds = strtof( optarg, nullptr );
                args.stopAfter = static_cast<int>( stopAfterInSeconds * 1000 ) * 1ms;
                setIncompatibleOptionWithMultiCapture = true;
                break;
            }
            default:
                Usage();
                break;
            }
        }

        if( args.outputPath.empty() )
        {
            Usage();
        }

        if( args.multi and setIncompatibleOptionWithMultiCapture )
        {
            std::cout << "ERROR: both --multi mode, and another option incompatible with it were requested\n\n";
            Usage();
        }

        // process 'outputPath' argument
        // - extract directory / file prefix (for multi mode)
        // - check file existence, fail if --force not given
        args.outputFileName = args.outputPath.filename().generic_string();

        args.outputDirectory = args.outputPath.parent_path();
        if( args.outputDirectory.empty() )
        {
            args.outputDirectory = ".";
        }
        if( not std::filesystem::is_directory( args.outputDirectory ) )
        {
            std::cout << "ERROR: target directory " << args.outputDirectory << " does not exist." << std::endl;
            exit( 1 );
        }

        if( args.multi )
        {
            const size_t SUFFIX_LEN = strlen( TRACE_FILE_SUFFIX );
            if( args.outputFileName.ends_with( TRACE_FILE_SUFFIX ) )
            {
                // convert "<prefix>.tracy" to "<prefix>"
                args.outputFileName = args.outputFileName.substr( 0, args.outputFileName.size() - SUFFIX_LEN );
            }
            // add a final "." to restrict filename matches to the form <prefix>.<pid>.tracy
            args.outputFileName += ".";

            // we need to check all files starting with the prefix
            std::cout << "search for existing files matching '" << args.outputDirectory.string() << "/"
                      << args.outputFileName << "*" << TRACE_FILE_SUFFIX << "'" << std::endl;

            auto foundExisting = false;
            for( auto const& entry : std::filesystem::directory_iterator( args.outputDirectory ) )
            {
                auto filename = entry.path().filename().string();
                if( filename.starts_with( args.outputFileName ) and filename.ends_with( TRACE_FILE_SUFFIX ) )
                {
                    if( args.overwrite )
                    {
                        if( args.verbose )
                        {
                            std::cout << "Deleting " << entry.path() << std::endl;
                        }
                        std::filesystem::remove( entry );
                    }
                    else
                    {
                        std::cout << "Conflict: file already exist: " << entry.path() << std::endl;
                        foundExisting = true;
                    }
                }
            }
            if( foundExisting and not args.overwrite )
            {
                printf( "Files matching the target prefix already exists! Use -f to clear them all before starting "
                        "capture.\n" );
                exit( 1 );
            }
        }
        else
        {
            if( std::filesystem::exists( args.outputDirectory / args.outputFileName ) )
            {
                if( args.overwrite )
                {
                    std::filesystem::remove( args.outputPath );
                }
                else
                {
                    std::cout << "ERROR: Output file " << args.outputPath
                              << " already exists! Use -f to force overwrite." << std::endl;
                    exit( 4 );
                }
            }
        }

        return args;
    }

    // debug - don't merge
    void print()
    {
        std::cout << "memlimit " << memoryLimit << "\n";
        std::cout << "output directory " << outputDirectory << "\n";
        std::cout << "output filename " << outputFileName << "\n";
        std::cout << "verbose " << verbose << "\n";
        std::cout << "address " << address << "\n";
        std::cout << "port " << port << "\n";
        std::cout << "stopAfter (seconds)"
                  << std::chrono::duration_cast<std::chrono::duration<float>>( stopAfter ).count() << "\n";
        std::cout << "multi " << multi << "\n";
    }
};

int runCaptureSingle( CaptureArgs const& args )
{
    std::string const outputStr = ( args.outputDirectory / args.outputFileName ).generic_string();
    char const* output = outputStr.c_str();
    FILE* test = fopen( output, "wb" );
    if( !test )
    {
        printf( "Cannot open output file %s for writing!\n", output );
        return 5;
    }
    fclose( test );
    unlink( output );

    printf( "Connecting to %s:%i...", args.address.c_str(), args.port );
    fflush( stdout );
    tracy::Worker worker( args.address.c_str(), args.port, args.memoryLimit );
    while( !worker.HasData() )
    {
        const auto handshake = static_cast<tracy::HandshakeStatus>( worker.GetHandshakeStatus() );
        int status = checkHandshake( handshake );
        if( status != 0 )
        {
            return status;
        }

        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    }
    printf( "\nQueue delay: %s\nTimer resolution: %s\n", tracy::TimeToString( worker.GetDelay() ),
            tracy::TimeToString( worker.GetResolution() ) );

    SetupDisconnectSignalHandler();

    const auto t0 = std::chrono::high_resolution_clock::now();
    while( worker.IsConnected() )
    {
        // Relaxed order is sufficient here because `s_disconnect` is only ever
        // set by this thread or by the SigInt handler, and that handler does
        // nothing else than storing `s_disconnect`.
        if( s_disconnect.load( std::memory_order_relaxed ) )
        {
            worker.Disconnect();
            // Relaxed order is sufficient because only this thread ever reads
            // this value.
            s_disconnect.store( false, std::memory_order_relaxed );
            break;
        }
        // Output progress info only if destination is a TTY to avoid bloating
        // log files (so this is not just about usage of ANSI color codes).
        if( IsStdoutATerminal() )
        {
            printWorkerUpdate( worker, args.memoryLimit, true, true );
        }

        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
        if( args.stopAfter > 0s )
        {
            const auto dur = std::chrono::high_resolution_clock::now() - t0;
            if( dur >= args.stopAfter )
            {
                // Relaxed order is sufficient because only this thread ever reads
                // this value.
                s_disconnect.store( true, std::memory_order_relaxed );
            }
        }
    }
    const auto t1 = std::chrono::high_resolution_clock::now();

    printWorkerFailure( worker, "" );

    printf( "\nFrames: %" PRIu64 "\nTime span: %s\nZones: %s\nElapsed time: %s\nSaving trace...",
            worker.GetFrameCount( *worker.GetFramesBase() ),
            tracy::TimeToString( worker.GetLastTime() - worker.GetFirstTime() ),
            tracy::RealToString( worker.GetZoneCount() ),
            tracy::TimeToString( std::chrono::duration_cast<std::chrono::nanoseconds>( t1 - t0 ).count() ) );
    fflush( stdout );
    auto f = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output, tracy::FileCompression::Zstd, 3, 4 ) );
    if( f )
    {
        worker.Write( *f, false );
        AnsiPrintf( ANSI_GREEN ANSI_BOLD, " done!\n" );
        f->Finish();
        const auto stats = f->GetCompressionStatistics();
        printf( "Trace size %s (%.2f%% ratio)\n", tracy::MemSizeToString( stats.second ),
                100.f * stats.second / stats.first );
    }
    else
    {
        AnsiPrintf( ANSI_RED ANSI_BOLD, " failed!\n" );
    }

    return 0;
}

int runCaptureMulti( CaptureArgs const& args )
{
    using hr_clock = std::chrono::high_resolution_clock;
    auto const startCaptureTimestamp = hr_clock::now();

    // configure signal handling early
    // to ensure the capture loop halts at some point, once we got the order to stop:
    // - we stop discovering new clients
    // - we send disconnect signal to existing ones
    SetupDisconnectSignalHandler();

    tracy::UdpListen broadListen = tracy::UdpListen();
    if( !broadListen.Listen( tracy::DEFAULT_BROADCAST_UDP_PORT ) )
    {
        std::cout << "Failed to listen to UDP broadcast on port" << tracy::DEFAULT_BROADCAST_UDP_PORT << std::endl;
        return 1;
    }
    if( args.verbose )
    {
        std::cout << "Listening for client UDP broadcast messages on port " << tracy::DEFAULT_BROADCAST_UDP_PORT
                  << std::endl;
    }

    std::vector<RunningClient> knownClients;
    bool stillRunningClients = false;
    bool waitingForFirstClient = true; // set to false if we find a client, or if SIGINT is caught
    auto last_status_print = hr_clock::now();
    // tracks how many lines to erase before print multi-line status update
    // if any other message is printed, it must be reset back to 0 to avoid "eating" a line
    int liveUpdateLines = 0;

    while( stillRunningClients or waitingForFirstClient )
    {
        // discover new clients
        if( not s_disconnect.load( std::memory_order::relaxed ) )
        {
            while( true )
            {
                auto bcastClientOpt = receive_client_broadcast( &broadListen );
                if( not bcastClientOpt.has_value() )
                {
                    break;
                }
                RunningClient& bcastClient = bcastClientOpt.value();

                // check if client already exists
                bool matchesExistingClient = false;
                for( auto const& alreadyKnownClient : knownClients )
                {
                    if( bcastClient.id == alreadyKnownClient.id )
                    {
                        matchesExistingClient = true;
                        break;
                    }
                }
                if( not matchesExistingClient )
                {
                    if( bcastClient.msg.protocolVersion != tracy::ProtocolVersion )
                    {
                        AnsiPrintf( ANSI_RED, "Rejecting client %s; bad protocol version\n",
                                    bcastClient.runtimeName().c_str() );
                        liveUpdateLines = 0;
                        bcastClient.status = ClientStatus::DISABLED;
                        knownClients.emplace_back( std::move( bcastClient ) );
                        continue;
                    }
                    if( args.verbose )
                    {
                        std::cout << "Detected client:" << "\n"
                                  << "\tName: " << bcastClient.msg.programName << "\n"
                                  << "\tID: " << bcastClient.id << "\n"
                                  << "\tAddress: " << bcastClient.addr << "\n"
                                  << "\tPort: " << bcastClient.msg.listenPort << std::endl;
                        liveUpdateLines = 0;
                    }
                    bcastClient.worker = std::make_unique<tracy::Worker>( bcastClient.addr, bcastClient.msg.listenPort,
                                                                          tracy::NO_WORKER_MEMORY_LIMIT );
                    knownClients.emplace_back( std::move( bcastClient ) );
                }
            }
        }

        // review pending clients - once handsake succeeded we move them to the running client list
        for( auto& candidate : knownClients )
        {
            if( candidate.status != ClientStatus::DISCOVERED )
            {
                continue;
            }

            // if data got through, promote it to a running client
            if( candidate.worker->HasData() )
            {
                if( args.verbose )
                {
                    printf( "Connected to client '%s' (from %s:%d, PID: %lu)\n", candidate.msg.programName,
                            candidate.addr, candidate.msg.listenPort, candidate.msg.pid );
                    liveUpdateLines = 0;
                }
                candidate.status = ClientStatus::RUNNING;

                waitingForFirstClient = false;
                continue;
            }

            // check if handshake failed - if so, remove the client
            const auto handshake = static_cast<tracy::HandshakeStatus>( candidate.worker->GetHandshakeStatus() );
            if( checkHandshake( handshake ) != 0 )
            {
                printf( "-> client '%s' (from %s:%d, PID: %lu) was ignored because of failed handshake status\n",
                        candidate.msg.programName, candidate.addr, candidate.msg.listenPort, candidate.msg.pid );
                liveUpdateLines = 0;
                candidate.status = ClientStatus::DISABLED;
                candidate.worker = nullptr;
            }
        }

        // review running clients
        // If we notice a disconnect, print the failure message if relevant
        stillRunningClients = false;
        for( auto& client : knownClients )
        {
            if( client.status == ClientStatus::RUNNING )
            {
                if( client.worker->IsConnected() )
                {
                    stillRunningClients = true;
                }
                else
                {
                    if( printWorkerFailure( *client.worker, client.runtimeName().c_str() ) )
                    {
                        printf( "\n" );
                        liveUpdateLines = 0;
                    }
                    client.status = ClientStatus::FINISHED;
                    client.finishedAt = hr_clock::now();
                }
            }
        }

        // if disconnecting, send disconnect to active workers
        if( s_disconnect.load( std::memory_order::relaxed ) )
        {
            waitingForFirstClient = false;
            for( auto& client : knownClients )
            {
                if( client.status == ClientStatus::RUNNING and not client.disconnectSent )
                {
                    std::cout << "disconnecting " << client << std::endl;
                    client.worker->Disconnect();
                    liveUpdateLines = 0;
                    client.disconnectSent = true;
                }
            }
        }

        // Print status update
        // Done only if we have a terminal output to avoid bloating log files
        // we print at regular time intervals, and one last time when there are no clients left
        auto now = hr_clock::now();
        if( IsStdoutATerminal() and ( now - last_status_print > PRINT_UPDATE_INTERVAL or not stillRunningClients ) )
        {
            for( ; liveUpdateLines > 0; liveUpdateLines-- )
            {
                AnsiPrintf( ANSI_UP_ONE_LINE ANSI_ERASE_LINE, "" );
            }
            double elapsedSeconds =
                std::chrono::duration_cast<std::chrono::duration<double>>( now - startCaptureTimestamp ).count();
            AnsiPrintf( ANSI_YELLOW, "t=%.1lfs", elapsedSeconds );
            AnsiPrintf( ANSI_RED, " | " );
            printCurrentMemoryUsage( tracy::NO_WORKER_MEMORY_LIMIT );
            printf( "\n" );
            liveUpdateLines++;
            for( auto const& client : knownClients )
            {
                char const* statusColor;
                switch( client.status )
                {
                case ClientStatus::RUNNING:
                    statusColor = ANSI_GREEN;
                    break;
                case ClientStatus::FINISHED:
                    statusColor = ANSI_BLUE;
                    break;
                default:
                    continue;
                }
                AnsiPrintf( statusColor, "%s", client.runtimeName().c_str() );
                printWorkerUpdate( *client.worker, tracy::NO_WORKER_MEMORY_LIMIT, false, false );
                printf( "\n" );
                liveUpdateLines++;
            }
            last_status_print = now;
        }

        std::this_thread::sleep_for( MULTI_CAPTURE_LOOP_INTERVAL );
    }

    // end of main loop
    // checking if we have something to save, and if so do it
    auto endCaptureTimestamp = std::chrono::high_resolution_clock::now();
    bool gotAtLeastOneClient =
        std::any_of( knownClients.begin(), knownClients.end(), []( auto const& client )
                     { return client.status == ClientStatus::RUNNING or client.status == ClientStatus::FINISHED; } );
    if( not gotAtLeastOneClient )
    {
        std::cout << "Did not capture data, exiting" << std::endl;
        return 0;
    }

    std::cout << "Writing output..." << std::endl;
    for( auto& client : knownClients )
    {
        if( client.status != ClientStatus::FINISHED )
        {
            continue;
        }
        AnsiPrintf( ANSI_BLUE, "- %s\n", client.runtimeName().c_str() );
        printf( "    Frames: %" PRIu64 "\n    Time span: %s\n    Zones: %s\n    Elapsed time: %s\n  Saving trace...",
                client.worker->GetFrameCount( *client.worker->GetFramesBase() ),
                tracy::TimeToString( client.worker->GetLastTime() - client.worker->GetFirstTime() ),
                tracy::RealToString( client.worker->GetZoneCount() ),
                tracy::TimeToString(
                    std::chrono::duration_cast<std::chrono::nanoseconds>( client.finishedAt - client.detectedAt )
                        .count() ) );
        std::filesystem::path filepath = args.outputDirectory / client.saveName( args.outputFileName );
        auto f = std::unique_ptr<tracy::FileWrite>(
            tracy::FileWrite::Open( filepath.generic_string().c_str(), tracy::FileCompression::Zstd, 3, 4 ) );
        if( f )
        {
            client.worker->Write( *f, false );
            AnsiPrintf( ANSI_GREEN, "done: %s\n", filepath.string().c_str() );
            f->Finish();
            const auto stats = f->GetCompressionStatistics();
            printf( "    Trace size %s (%.2f%% ratio)\n", tracy::MemSizeToString( stats.second ),
                    100.f * stats.second / stats.first );
        }
        else
        {
            AnsiPrintf( ANSI_RED, "failed!\n" );
        }
    }

    return 0;
}

int main( int argc, char* argv[] )
{
#ifdef _WIN32
    if( !AttachConsole( ATTACH_PARENT_PROCESS ) )
    {
        AllocConsole();
        SetConsoleMode( GetStdHandle( STD_OUTPUT_HANDLE ), 0x07 );
    }
#endif

    InitIsStdoutATerminal();

    CaptureArgs args = CaptureArgs::parse( argc, argv );
    args.print(); // remove before merge

    if( args.multi )
    {
        return runCaptureMulti( args );
    }
    else
    {
        return runCaptureSingle( args );
    }
}
