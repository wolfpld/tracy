// common library file for capture utilities
#ifdef _WIN32
#    include <io.h>
#    include <windows.h>
#else
#    include <unistd.h>
#endif
#include <cstdarg>
#include <inttypes.h>

#include "TracyPrint.hpp"
#include "TracyStackFrames.hpp"
#include "TracyWorker.hpp"

static bool s_isStdoutATerminal = false;

void InitIsStdoutATerminal() {
#ifdef _WIN32
    s_isStdoutATerminal = _isatty( fileno( stdout ) );
#else
    s_isStdoutATerminal = isatty( fileno( stdout ) );
#endif
}

bool IsStdoutATerminal() { return s_isStdoutATerminal; }


#define ANSI_RESET "\033[0m"
#define ANSI_BOLD "\033[1m"
#define ANSI_BLACK "\033[30m"
#define ANSI_RED "\033[31m"
#define ANSI_GREEN "\033[32m"
#define ANSI_YELLOW "\033[33m"
#define ANSI_BLUE "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN "\033[36m"
#define ANSI_ERASE_LINE "\033[2K"
#define ANSI_UP_ONE_LINE "\033[1;A"

// Like printf, but if stdout is a terminal, prepends the output with
// the given `ansiEscape` and appends ANSI_RESET.
#ifdef __GNUC__
[[gnu::format(__printf__, 2, 3)]]
#endif
void AnsiPrintf( const char* ansiEscape, const char* format, ... ) {
    if( IsStdoutATerminal() )
    {
        // Prepend ansiEscape and append ANSI_RESET.
        char buf[256];
        va_list args;
        va_start( args, format );
        vsnprintf( buf, sizeof buf, format, args );
        va_end( args );
        printf( "%s%s" ANSI_RESET, ansiEscape, buf );
    }
    else
    {
        // Just a normal printf.
        va_list args;
        va_start( args, format );
        vfprintf( stdout, format, args );
        va_end( args );
    }
}

// Check handshake status
// If failure, printf helpful message and return non-zero
int checkHandshake(tracy::HandshakeStatus handshake)
{
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
    return 0;
}

void printCurrentMemoryUsage(int64_t memoryLimit)
{
    AnsiPrintf( ANSI_RED ANSI_BOLD, "%s", tracy::MemSizeToString( tracy::memUsage.load( std::memory_order_relaxed ) ) );
    if( memoryLimit > 0 )
    {
        printf( " / " );
        AnsiPrintf( ANSI_BLUE ANSI_BOLD, "%s", tracy::MemSizeToString( memoryLimit ) );
    }
}

void printWorkerUpdate(tracy::Worker& worker, int64_t memoryLimit, bool erase, bool memoryUsage)
{
    auto& lock = worker.GetMbpsDataLock();
    lock.lock();
    const auto mbps = worker.GetMbpsData().back();
    const auto compRatio = worker.GetCompRatio();
    const auto netTotal = worker.GetDataTransferred();
    lock.unlock();

    const char* unit = "Mbps";
    float unitsPerMbps = 1.f;
    if( mbps < 0.1f )
    {
        unit = "Kbps";
        unitsPerMbps = 1000.f;
    }
    if(erase)
    {
        AnsiPrintf(ANSI_ERASE_LINE, "\r");
    }
    AnsiPrintf( ANSI_CYAN ANSI_BOLD, "%7.2f %s", mbps * unitsPerMbps, unit );
    printf( " /");
    AnsiPrintf( ANSI_CYAN ANSI_BOLD, "%5.1f%%", compRatio * 100.f );
    printf( " =");
    AnsiPrintf( ANSI_YELLOW ANSI_BOLD, "%7.2f Mbps", mbps / compRatio );
    printf( " | ");
    AnsiPrintf( ANSI_YELLOW, "Tx: ");
    AnsiPrintf( ANSI_GREEN, "%s", tracy::MemSizeToString( netTotal ) );
    if (memoryUsage)
    {
        printf( " | ");
        printCurrentMemoryUsage(memoryLimit);
    }

    printf( " | ");
    AnsiPrintf( ANSI_RED, "%s", tracy::TimeToString( worker.GetLastTime() - worker.GetFirstTime() ) );
    fflush( stdout );
}

bool printWorkerFailure(tracy::Worker& worker, char const* prefix)
{
    auto const& failure = worker.GetFailureType();
    if( failure == tracy::Worker::Failure::None )
    {
        return false;
    }
    else
    {
        AnsiPrintf( ANSI_RED ANSI_BOLD, "\n%s Instrumentation failure: %s", prefix, tracy::Worker::GetFailureString( failure ) );
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
                    for( uint8_t f=0; f<fsz; f++ )
                    {
                        const auto& frame = frameData->data[f];
                        auto txt = worker.GetString( frame.name );

                        if( fidx == 0 && f != fsz-1 )
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

                        if( f == fsz-1 )
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
        return true;
    }
}
