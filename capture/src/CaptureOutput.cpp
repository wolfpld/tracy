#ifdef _WIN32
#  include <io.h>
#  include <windows.h>
#else
#  include <unistd.h>
#endif

#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <inttypes.h>
#include <thread>

#include "CaptureOutput.hpp"
#include "../../public/common/TracyProtocol.hpp"
#include "../../public/common/TracyStackFrames.hpp"
#include "../../server/TracyMemory.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyWorker.hpp"

static bool s_isTerminal = false;

void InitTerminalDetection()
{
#ifdef _WIN32
    s_isTerminal = _isatty( fileno( stdout ) );
#else
    s_isTerminal = isatty( fileno( stdout ) );
#endif
}

bool IsTerminal()
{
    return s_isTerminal;
}

void AnsiPrintf( const char* ansiEscape, const char* format, ... )
{
    if( IsTerminal() )
    {
        char buf[256];
        va_list args;
        va_start( args, format );
        vsnprintf( buf, sizeof buf, format, args );
        va_end( args );
        printf( "%s%s" ANSI_RESET, ansiEscape, buf );
    }
    else
    {
        va_list args;
        va_start( args, format );
        vfprintf( stdout, format, args );
        va_end( args );
    }
}

int WaitForConnection( tracy::Worker& worker )
{
    while( !worker.HasData() )
    {
        const auto handshake = worker.GetHandshakeStatus();
        if( handshake == tracy::HandshakeProtocolMismatch )
        {
            printf( "\nThe client you are trying to connect to uses incompatible protocol version.\nMake sure you are using the same Tracy version on both client and server.\n" );
            return 1;
        }
        if( handshake == tracy::HandshakeNotAvailable )
        {
            printf( "\nThe client you are trying to connect to is no longer able to sent profiling data,\nbecause another server was already connected to it.\nYou can do the following:\n\n  1. Restart the client application.\n  2. Rebuild the client application with on-demand mode enabled.\n" );
            return 2;
        }
        if( handshake == tracy::HandshakeDropped )
        {
            printf( "\nThe client you are trying to connect to has disconnected during the initial\nconnection handshake. Please check your network configuration.\n" );
            return 3;
        }
        std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    }
    return 0;
}

void PrintWorkerFailure( tracy::Worker& worker )
{
    const auto& failure = worker.GetFailureType();
    if( failure == tracy::Worker::Failure::None ) return;

    AnsiPrintf( ANSI_RED ANSI_BOLD, "\nInstrumentation failure: %s", tracy::Worker::GetFailureString( failure ) );
    auto& fd = worker.GetFailureData();
    if( !fd.message.empty() )
    {
        printf( "\nContext: %s", fd.message.c_str() );
    }
    if( fd.callstack != 0 )
    {
        AnsiPrintf( ANSI_BOLD, "\nFailure callstack:\n" );
        auto& cs = worker.GetCallstack( fd.callstack );
        int fidx = 0;
        for( auto& entry : cs )
        {
            auto frameData = worker.GetCallstackFrame( entry );
            if( !frameData )
            {
                printf( "%3i. %p\n", fidx++, (void*)worker.GetCanonicalPointer( entry ) );
            }
            else
            {
                const auto fsz = frameData->size;
                for( uint8_t f = 0; f < fsz; f++ )
                {
                    const auto& frame = frameData->data[f];
                    auto txt = worker.GetString( frame.name );

                    if( fidx == 0 && f != fsz - 1 )
                    {
                        auto test = tracy::s_tracyStackFrames;
                        bool match = false;
                        do
                        {
                            if( strcmp( txt, *test ) == 0 )
                            {
                                match = true;
                                break;
                            }
                        }
                        while( *++test );
                        if( match ) continue;
                    }

                    if( f == fsz - 1 )
                    {
                        printf( "%3i. ", fidx++ );
                    }
                    else
                    {
                        AnsiPrintf( ANSI_BLACK ANSI_BOLD, "inl. " );
                    }
                    AnsiPrintf( ANSI_CYAN, "%s  ", txt );
                    txt = worker.GetString( frame.file );
                    if( frame.line == 0 )
                    {
                        AnsiPrintf( ANSI_YELLOW, "(%s)", txt );
                    }
                    else
                    {
                        AnsiPrintf( ANSI_YELLOW, "(%s:%" PRIu32 ")", txt, frame.line );
                    }
                    if( frameData->imageName.Active() )
                    {
                        AnsiPrintf( ANSI_MAGENTA, " %s\n", worker.GetString( frameData->imageName ) );
                    }
                    else
                    {
                        printf( "\n" );
                    }
                }
            }
        }
    }
}

void PrintCaptureProgress( tracy::Worker& worker, int64_t firstTime, int64_t memoryLimit )
{
    if( !IsTerminal() ) return;

    auto& lock = worker.GetMbpsDataLock();
    lock.lock();
    const auto mbps = worker.GetMbpsData().back();
    const auto compRatio = worker.GetCompRatio();
    const auto netTotal = worker.GetDataTransferred();
    const auto queueSize = worker.GetSendQueueSize();
    lock.unlock();

    const char* unit = "Mbps";
    float unitsPerMbps = 1.f;
    if( mbps < 0.1f )
    {
        unit = "Kbps";
        unitsPerMbps = 1000.f;
    }
    AnsiPrintf( ANSI_ERASE_LINE ANSI_CYAN ANSI_BOLD, "\r%7.2f %s", mbps * unitsPerMbps, unit );
    printf( " /" );
    AnsiPrintf( ANSI_CYAN ANSI_BOLD, "%5.1f%%", compRatio * 100.f );
    printf( " =" );
    AnsiPrintf( ANSI_YELLOW ANSI_BOLD, "%7.2f Mbps", mbps / compRatio );
    printf( " | " );
    AnsiPrintf( ANSI_YELLOW, "Tx: " );
    AnsiPrintf( ANSI_GREEN, "%s", tracy::MemSizeToString( netTotal ) );
    printf( " | " );
    AnsiPrintf( ANSI_RED ANSI_BOLD, "%s", tracy::MemSizeToString( tracy::memUsage.load( std::memory_order_relaxed ) ) );
    if( memoryLimit > 0 )
    {
        printf( " / " );
        AnsiPrintf( ANSI_BLUE ANSI_BOLD, "%s", tracy::MemSizeToString( memoryLimit ) );
    }
    printf( " | " );
    AnsiPrintf( ANSI_RED, "%s", tracy::TimeToString( worker.GetLastTime() - firstTime ) );
    printf( " | " );
    AnsiPrintf( ANSI_RED ANSI_BOLD, "%s query backlog", tracy::RealToString( queueSize ) );
    fflush( stdout );
}
