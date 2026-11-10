#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../public/common/TracyVersion.hpp"
#include "GitRef.hpp"

static void Usage()
{
    printf( "tracy-import-strace %d.%d.%d / %s\n\n",
            tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch, tracy::GitRef );
    printf( "Usage: tracy-import-strace input.strace output.tracy\n" );
    printf( "       tracy-import-strace - output.tracy   (read from stdin)\n\n" );
    printf( "Recommended strace invocation:\n" );
    printf( "  strace -ttt -T -f -o trace.log <program> [args...]\n" );
    printf( "  strace -ttt -T -f -p <pid> -o trace.log\n\n" );
    printf( "Mapped events:\n" );
    printf( "  syscall entry/return  ->  timeline zones\n" );
    printf( "  signals               ->  messages\n" );
    printf( "  process exit/kill     ->  messages\n" );
    exit( 1 );
}

// Parse "SSSSSSSSSS.UUUUUU" → nanoseconds without floating-point precision loss.
// Advances *p past the consumed characters. Returns UINT64_MAX on parse error.
static uint64_t ParseTimestamp( const char*& p )
{
    if( !isdigit( (unsigned char)*p ) ) return UINT64_MAX;

    uint64_t sec = 0;
    while( isdigit( (unsigned char)*p ) )
        sec = sec * 10 + ( *p++ - '0' );

    if( *p != '.' ) return UINT64_MAX;
    p++;

    uint64_t usec = 0;
    int digits = 0;
    while( isdigit( (unsigned char)*p ) && digits < 6 )
    {
        usec = usec * 10 + ( *p++ - '0' );
        digits++;
    }
    for( ; digits < 6; digits++ ) usec *= 10;  // pad to microseconds if fewer digits
    while( isdigit( (unsigned char)*p ) ) p++;  // discard extra precision

    return sec * 1000000000ULL + usec * 1000ULL;
}

// Consume "[pid N]" prefix and return N, or return default_tid if not present.
// Advances *p past the consumed characters (including trailing space).
static uint64_t ConsumePidPrefix( const char*& p, uint64_t default_tid )
{
    if( p[0] != '[' || strncmp( p, "[pid", 4 ) != 0 ) return default_tid;

    const char* q = p + 4;
    while( *q == ' ' ) q++;
    if( !isdigit( (unsigned char)*q ) ) return default_tid;

    uint64_t tid = 0;
    while( isdigit( (unsigned char)*q ) )
        tid = tid * 10 + ( *q++ - '0' );

    while( *q == ' ' ) q++;
    if( *q != ']' ) return default_tid;

    p = q + 1;
    return tid;
}

// Parse "<N.NNNNNN>" trailing duration → nanoseconds. Returns 0 if not present.
static uint64_t ParseTrailingDuration( const char* line )
{
    const char* p = line + strlen( line );
    while( p > line && strchr( " \r\n", p[-1] ) ) p--;
    if( p == line || p[-1] != '>' ) return 0;
    p--;

    const char* end = p;
    while( p > line && p[-1] != '<' ) p--;
    if( p == line || p[-1] != '<' ) return 0;

    char tmp[32];
    size_t len = end - p;
    if( len == 0 || len >= sizeof( tmp ) ) return 0;
    memcpy( tmp, p, len );
    tmp[len] = '\0';

    double dur_sec = 0.0;
    if( sscanf( tmp, "%lf", &dur_sec ) != 1 ) return 0;
    return (uint64_t)( dur_sec * 1e9 );
}

// Return the syscall name — the identifier before the first '('. Empty on failure.
static std::string ParseSyscallName( const char* p )
{
    const char* start = p;
    while( *p && *p != '(' && *p != ' ' && *p != '\n' ) p++;
    if( p == start || *p != '(' ) return {};
    return std::string( start, p );
}

// Extract syscall arguments for a COMPLETE call line.
// Finds the last " = " (the retval separator), then the ')' before it.
// This correctly handles " = " appearing inside string arguments.
static std::string ExtractArgsComplete( const char* line_start )
{
    const char* open = strchr( line_start, '(' );
    if( !open ) return {};
    const char* args = open + 1;

    // Walk the whole line to find the last " = "
    const char* last_eq = nullptr;
    for( const char* p = args; *p; p++ )
        if( p[0] == ' ' && p[1] == '=' && p[2] == ' ' )
            last_eq = p;

    if( !last_eq ) return {};

    // Find the closing ')' that immediately precedes " = "
    const char* close = last_eq;
    while( close > args && *close != ')' ) close--;
    if( close <= args ) return {};

    return std::string( args, close );
}

// Extract syscall arguments for an UNFINISHED call line, up to the delimiter.
static std::string ExtractArgsUnfinished( const char* line_start, const char* delim )
{
    const char* open = strchr( line_start, '(' );
    if( !open ) return {};
    const char* args = open + 1;

    const char* end = strstr( args, delim );
    if( !end || end <= args ) return {};
    while( end > args && end[-1] == ' ' ) end--;  // trim trailing space
    return std::string( args, end );
}

// Extract a quoted string from strace arg output, e.g. the "name" in
// prctl(PR_SET_NAME, "name") = 0.  Returns empty string if not found.
static std::string ExtractQuotedString( const char* p )
{
    const char* open = strchr( p, '"' );
    if( !open ) return {};
    open++;
    const char* close = strchr( open, '"' );
    if( !close ) return {};
    return std::string( open, close );
}

// Parse the integer return value from a complete strace line " = N <dur>".
// Returns -1 on failure.
static int64_t ParseRetval( const char* line )
{
    const char* eq = strstr( line, " = " );
    if( !eq ) return -1;
    const char* p = eq + 3;
    bool neg = ( *p == '-' );
    if( neg ) p++;
    if( !isdigit( (unsigned char)*p ) ) return -1;
    int64_t v = 0;
    while( isdigit( (unsigned char)*p ) ) v = v * 10 + (*p++ - '0');
    return neg ? -v : v;
}

// Extract the function name from a strace -k frame line, e.g.:
//   "/lib/libc.so.6(__read_nocancel+0x7) [0xf1e07]"  →  "__read_nocancel"
static std::string ParseFrameName( const std::string& frame )
{
    const char* p = frame.c_str();
    const char* open = strchr( p, '(' );
    if( !open ) return frame;
    const char* name = open + 1;
    const char* plus  = strchr( name, '+' );
    const char* close = strchr( name, ')' );
    const char* end = ( plus && ( !close || plus < close ) ) ? plus : close;
    if( !end ) return frame;
    return std::string( name, end );
}

struct PendingEntry
{
    uint64_t    ts_begin;
    std::string syscall_name;
    std::string args_text;
};

// A complete or resumed syscall zone held until its trailing callstack frames are collected.
struct PendingComplete
{
    uint64_t                 tid;
    uint64_t                 ts_begin;
    uint64_t                 ts_end;
    std::string              name;
    std::string              args;
    std::vector<std::string> frames;  // innermost-first, as strace emits them
};

int main( int argc, char** argv )
{
    if( argc != 3 ) Usage();

    const char* input_path  = argv[1];
    const char* output_path = argv[2];

    FILE* fin = ( strcmp( input_path, "-" ) == 0 ) ? stdin : fopen( input_path, "r" );
    if( !fin )
    {
        fprintf( stderr, "Cannot open input: %s\n", input_path );
        return 1;
    }

    std::vector<tracy::Worker::ImportEventTimeline> timeline;
    std::vector<tracy::Worker::ImportEventMessages> messages;
    std::vector<tracy::Worker::ImportEventPlots>    plots;       // required by Worker API; unused
    std::unordered_map<uint64_t, std::string>       threadNames;
    std::unordered_map<uint64_t, PendingEntry>      pending;    // tid → in-flight syscall

    // Holds a complete/resumed zone while we collect its trailing callstack frames.
    std::optional<PendingComplete> pending_complete;

    // Emit a pending zone as nested Tracy zones:
    //   outer callstack frames  (one begin per frame, outermost first)
    //     syscall zone          (begin + end)
    //   outer callstack frames  (one end per frame, innermost first)
    //
    // frames[0] is the innermost frame (the libc/kernel syscall stub) and is
    // skipped — it is already represented by the syscall zone itself.
    auto flushComplete = [&]()
    {
        if( !pending_complete ) return;
        const auto& pc = *pending_complete;

        const size_t user_start = pc.frames.empty() ? 0 : 1; // skip innermost stub

        // Open outer frames, outermost first (= reversed from strace order).
        for( int i = (int)pc.frames.size() - 1; i >= (int)user_start; i-- )
            timeline.push_back( { pc.tid, pc.ts_begin,
                                   ParseFrameName( pc.frames[i] ), pc.frames[i],
                                   false, "", 0 } );

        // The syscall zone itself.
        timeline.push_back( { pc.tid, pc.ts_begin, pc.name, pc.args, false, "", 0 } );
        timeline.push_back( { pc.tid, pc.ts_end,   "",      "",      true,  "", 0 } );

        // Close outer frames, innermost first.
        for( size_t i = user_start; i < pc.frames.size(); i++ )
            timeline.push_back( { pc.tid, pc.ts_end, "", "", true, "", 0 } );

        pending_complete.reset();
    };

    char buf[65536];
    // TID used when strace output has no [pid N] prefix (single-threaded traces or
    // the very first calls of a process before any fork).
    constexpr uint64_t kDefaultTid = 0;

    while( fgets( buf, sizeof( buf ), fin ) )
    {
        const char* p = buf;

        // Callstack frame from strace -k: " > /path/lib(func+0xoff) [0xaddr]"
        // Must be checked before the isdigit guard.
        if( p[0] == ' ' && p[1] == '>' )
        {
            if( pending_complete )
            {
                const char* frame = p + 2;
                while( *frame == ' ' ) frame++;
                std::string f( frame );
                while( !f.empty() && strchr( "\r\n", f.back() ) ) f.pop_back();
                if( !f.empty() ) pending_complete->frames.push_back( std::move( f ) );
            }
            continue;
        }

        // Any non-frame line closes the pending zone before we process it.
        flushComplete();

        // Only process lines whose first character is a digit.
        // Silently skips strace warnings, "Process N attached/detached", etc.
        if( !isdigit( (unsigned char)*p ) ) continue;

        // Detect which line format strace used:
        //   Format A (-o to file/pipe): "PID TIMESTAMP syscall..."
        //   Format B (to stderr/tty):   "TIMESTAMP [pid N] syscall..."
        // Distinguish by whether the first numeric token contains a '.' (timestamp)
        // or is followed by a space without a '.' (bare PID).
        uint64_t tid = kDefaultTid;
        {
            const char* q = p;
            while( isdigit( (unsigned char)*q ) ) q++;
            if( *q == ' ' )
            {
                // Format A: leading PID token
                while( isdigit( (unsigned char)*p ) ) tid = tid * 10 + (*p++ - '0');
                while( *p == ' ' ) p++;
            }
            // else: Format B — timestamp comes first, [pid N] (if any) follows it
        }

        uint64_t ts = ParseTimestamp( p );
        if( ts == UINT64_MAX ) continue;

        while( *p == ' ' ) p++;

        // Format B may carry "[pid N]" after the timestamp; Format A already has tid.
        if( tid == kDefaultTid )
            tid = ConsumePidPrefix( p, kDefaultTid );

        while( *p == ' ' ) p++;

        // Register the thread name the first time we see this TID.
        if( threadNames.find( tid ) == threadNames.end() )
        {
            char name[32];
            if( tid == kDefaultTid )
                snprintf( name, sizeof( name ), "main" );
            else
                snprintf( name, sizeof( name ), "%" PRIu64, tid );
            threadNames[tid] = name;
        }

        // --- Resumed syscall -------------------------------------------
        // "<... SYSCALL resumed>) = RETVAL <DUR>"
        if( strncmp( p, "<...", 4 ) == 0 )
        {
            const char* name_start = p + 4;
            while( *name_start == ' ' ) name_start++;
            const char* resumed = strstr( name_start, " resumed" );
            if( !resumed ) continue;

            std::string syscall_name( name_start, resumed );

            auto it = pending.find( tid );
            uint64_t    ts_begin  = ( it != pending.end() ) ? it->second.ts_begin   : ts;
            std::string args_text = ( it != pending.end() ) ? it->second.args_text  : "";
            if( it != pending.end() ) pending.erase( it );

            // ts = timestamp of the return line; use as zone end.
            pending_complete = PendingComplete{ tid, ts_begin, ts,
                                               std::move( syscall_name ),
                                               std::move( args_text ), {} };
        }
        // --- Process exit / kill ----------------------------------------
        // "+++ exited with N +++"  |  "+++ killed by SIGNAL +++"
        else if( strncmp( p, "+++", 3 ) == 0 )
        {
            std::string raw( p );
            while( !raw.empty() && strchr( "\r\n", raw.back() ) ) raw.pop_back();
            messages.push_back( { tid, ts, std::to_string( tid ) + ": " + raw } );
        }
        // --- Signal ------------------------------------------------------
        // "--- SIGNAME {...} ---"
        else if( strncmp( p, "---", 3 ) == 0 )
        {
            std::string raw( p );
            while( !raw.empty() && strchr( "\r\n", raw.back() ) ) raw.pop_back();
            messages.push_back( { tid, ts, std::to_string( tid ) + ": " + raw } );
        }
        // --- Regular syscall (complete or unfinished) --------------------
        else
        {
            std::string syscall_name = ParseSyscallName( p );
            if( syscall_name.empty() ) continue;

            if( strstr( p, "<unfinished ...>" ) )
            {
                // Syscall blocked — park in the pending table.
                std::string args = ExtractArgsUnfinished( p, " <unfinished" );
                pending[tid] = PendingEntry{ ts, std::move( syscall_name ), std::move( args ) };
            }
            else
            {
                // Complete call with return value (and optional duration from -T).
                uint64_t    dur_ns = ParseTrailingDuration( buf );
                std::string args   = ExtractArgsComplete( p );

                // prctl(PR_SET_NAME, "name") — update the thread's display name.
                if( syscall_name == "prctl" && strstr( p, "PR_SET_NAME" ) )
                {
                    std::string name = ExtractQuotedString( strstr( p, "PR_SET_NAME" ) );
                    if( !name.empty() )
                        threadNames[tid] = std::move( name );
                }
                // clone/clone3 with CLONE_THREAD — pre-name the child thread so it
                // has a label before it calls prctl itself.
                else if( ( syscall_name == "clone" || syscall_name == "clone3" ) &&
                         strstr( p, "CLONE_THREAD" ) )
                {
                    int64_t child_tid = ParseRetval( buf );
                    if( child_tid > 0 && threadNames.find( (uint64_t)child_tid ) == threadNames.end() )
                    {
                        char name[32];
                        snprintf( name, sizeof( name ), "%" PRId64, child_tid );
                        threadNames[(uint64_t)child_tid] = name;
                    }
                }

                pending_complete = PendingComplete{ tid, ts, ts + dur_ns,
                                                   syscall_name,
                                                   std::move( args ), {} };
            }
        }
    }

    if( fin != stdin ) fclose( fin );
    flushComplete(); // flush the last zone if the file ends with callstack frames

    // Sort by timestamp. strace output is mostly ordered, but interleaved threads
    // and resumed events can place end-of-zone before begin-of-zone after sorting.
    std::stable_sort( timeline.begin(), timeline.end(),
        []( const auto& a, const auto& b ) { return a.timestamp < b.timestamp; } );
    std::stable_sort( messages.begin(), messages.end(),
        []( const auto& a, const auto& b ) { return a.timestamp < b.timestamp; } );

    // Shift all timestamps so the trace starts at t = 0.
    uint64_t mts = UINT64_MAX;
    for( const auto& e : timeline )  mts = std::min( mts, e.timestamp );
    for( const auto& e : messages )  mts = std::min( mts, e.timestamp );
    if( mts == UINT64_MAX ) mts = 0;

    for( auto& e : timeline )  e.timestamp -= mts;
    for( auto& e : messages )  e.timestamp -= mts;

    const size_t zone_count = timeline.size() / 2;
    fprintf( stderr, "Parsed %zu zones, %zu messages, %zu threads\n",
             zone_count, messages.size(), threadNames.size() );

    // Tracy Worker expects basenames, not full paths.
    auto basename = []( const char* path ) -> const char* {
        const char* s = path;
        for( const char* q = path; *q; q++ )
            if( *q == '/' || *q == '\\' ) s = q + 1;
        return s;
    };

    tracy::Worker worker( basename( output_path ), basename( input_path ),
                          timeline, messages, plots, threadNames );

    auto w = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output_path, tracy::FileCompression::Fast ) );
    if( !w )
    {
        fprintf( stderr, "Cannot open output file: %s\n", output_path );
        return 1;
    }
    worker.Write( *w, false );

    return 0;
}
