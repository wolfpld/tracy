#include "OfflineSymbolResolver.h"

#include <fstream>
#include <iostream>
#include <string>
#include <array>
#include <sstream>
#include <memory>
#include <stdio.h>

#ifdef _WIN32
#  define popen _popen
#  define pclose _pclose
#endif

std::string ExecShellCommand( const char* cmd )
{
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if( !pipe )
    {
        return "";
    }
    while( fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr )
    {
        result += buffer.data();
    }
    return result;
}

class SymbolResolver
{
public:
    SymbolResolver( const std::string& addr2lineToolPath, const std::string& addr2lineArgs )
    {
        // Extra arguments are inserted verbatim into the tool invocation. Tracy records frame
        // offsets as RVAs; for images with a non-zero preferred image base (PE, Mach-O) the user
        // can pass "--relative-address" here so llvm-addr2line / llvm-symbolizer add the base back.
        if( !addr2lineArgs.empty() )
        {
            m_addr2LineArgs = " " + addr2lineArgs;
        }

        if( !addr2lineToolPath.empty() )
        {
            // If the value looks like a path (not a bare command name resolved via PATH), verify
            // it exists so a wrong path fails with an actionable error instead of a cryptic shell one.
            const bool looksLikePath = addr2lineToolPath.find( '/' ) != std::string::npos ||
                                       addr2lineToolPath.find( '\\' ) != std::string::npos;
            if( looksLikePath && !std::ifstream( addr2lineToolPath ).good() )
            {
                std::cerr << "Specified symbol resolution tool not found: '" << addr2lineToolPath
                          << "' (check the path passed to the '-a' option)" << std::endl;
                return;
            }

            // A user-provided path may contain spaces or other shell-special characters.
            escapeShellParam( addr2lineToolPath, m_addr2LinePath );
            std::cout << "Using user-specified symbol resolution tool: '" << addr2lineToolPath.c_str() << "'" << std::endl;
            return;
        }

#ifdef _WIN32
        std::cerr << "No symbol resolution tool specified (use the '-a' option to provide one)" << std::endl;
#else
        std::stringstream result( ExecShellCommand("which addr2line") );
        std::getline(result, m_addr2LinePath);

        if( !m_addr2LinePath.length() )
        {
            std::cerr << "'addr2line' was not found in the system, please install it" << std::endl;
        }
        else
        {
            std::cout << "Using 'addr2line' found at: '" << m_addr2LinePath.c_str() << "'" << std::endl;
        }
#endif
    }

    static void escapeShellParam(std::string const& s, std::string& out)
    {
#ifdef _WIN32
        // cmd.exe / the CRT command parser do not understand POSIX backslash escapes, and
        // backslashes are path separators on Windows. Wrap the parameter in double quotes
        // (which handles spaces) and drop any embedded quotes, which cannot appear in a path.
        out.reserve( s.size() + 2 );
        out.push_back( '"' );
        for( char c : s )
        {
            if( c != '"' ) out.push_back( c );
        }
        out.push_back( '"' );
#else
        out.reserve( s.size() + 2 );
        out.push_back( '"' );
        for( unsigned char c : s )
        {
            if( ' ' <= c and c <= '~' and c != '\\' and c != '"' )
            {
                out.push_back( c );
            }
            else
            {
                out.push_back( '\\' );
                switch( c )
                {
                    case '"':  out.push_back( '"' );  break;
                    case '\\': out.push_back( '\\' ); break;
                    case '\t': out.push_back( 't' );  break;
                    case '\r': out.push_back( 'r' );  break;
                    case '\n': out.push_back( 'n' );  break;
                    default:
                        char const* const hexdig = "0123456789ABCDEF";
                        out.push_back( 'x' );
                        out.push_back( hexdig[c >> 4] );
                        out.push_back( hexdig[c & 0xF] );
                }
            }
        }
        out.push_back( '"' );
#endif
    }

    bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                         SymbolEntryList& resolvedEntries )
    {
        if( !m_addr2LinePath.length() ) return false;

        std:: string escapedPath;
        escapeShellParam( imagePath, escapedPath );

        // Command-line length limits: cmd.exe (used by _popen on Windows) allows ~8191 characters;
        // a single POSIX 'sh -c' argument is capped by MAX_ARG_STRLEN (128 KiB on Linux).
        // 8000 stays under all of these, so a single conservative budget works on every platform.
        const size_t maxCmdLength = 8000;

        size_t entryIdx = 0;
        while( entryIdx < inputEntryList.size() )
        {
            const size_t startIdx = entryIdx;

            // generate a single addr2line cmd line for as many addresses as fit the length budget
            std::stringstream ss;
            ss << m_addr2LinePath << " -C -f" << m_addr2LineArgs << " -e " << escapedPath << " -a ";
            while( entryIdx < inputEntryList.size() )
            {
                const FrameEntry& entry = inputEntryList[entryIdx];
                ss << " 0x" << std::hex << entry.symbolOffset;
                entryIdx++;
                // always include at least one address, then stop once near the length limit
                if( static_cast<size_t>( ss.tellp() ) >= maxCmdLength ) break;
            }
            const size_t batchEndIdx = entryIdx;

            printf( "Resolving symbols [%zu-%zu]\n", startIdx, batchEndIdx );

            std::string cmd = ss.str();
#ifdef _WIN32
            // _popen runs the command through 'cmd.exe /c', which strips the outermost pair of
            // quotes. Wrap the whole command so the quoting around the (possibly spaced) tool
            // and image paths survives.
            cmd = "\"" + cmd + "\"";
#endif

            std::string resultStr = ExecShellCommand( cmd.c_str() );
            std::stringstream result( resultStr );
            
            //printf("executing: '%s' got '%s'\n", ss.str().c_str(), result.str().c_str());

            // The output is 2 lines per entry with the following contents:
            // hex_address_of_symbol
            // symbol_name
            // file:line

            for( size_t i = startIdx ;i < batchEndIdx; i++ )
            {
                const FrameEntry& inputEntry = inputEntryList[i];

                SymbolEntry newEntry;

                std::string addr;
                std::getline( result, addr );
                std::getline( result, newEntry.name );
                if( newEntry.name == "??" )
                {
                    newEntry.name = "[unknown] + " + std::to_string( inputEntry.symbolOffset );
                }

                std::string fileLine;
                std::getline( result, fileLine );
                if( fileLine != "??:?" )
                {
                    size_t pos = fileLine.find_last_of( ':' );
                    if( pos != std::string::npos )
                    {
                        newEntry.file = fileLine.substr( 0, pos );
                        std::string lineStr = fileLine.substr( pos + 1 );
                        char* after = nullptr;
                        newEntry.line = strtol( lineStr.c_str(), &after, 10 );
                    }
                }

                resolvedEntries.push_back( std::move( newEntry ) );
            }
        }

        return true;
    }

private:
    std::string m_addr2LinePath;
    std::string m_addr2LineArgs;
};

bool ResolveSymbolsAddr2Line( const std::string& addr2lineToolPath, const std::string& addr2lineArgs,
                              const std::string& imagePath, const FrameEntryList& inputEntryList,
                              SymbolEntryList& resolvedEntries )
{
    static SymbolResolver symbolResolver( addr2lineToolPath, addr2lineArgs );
    return symbolResolver.ResolveSymbols( imagePath, inputEntryList, resolvedEntries );
}
