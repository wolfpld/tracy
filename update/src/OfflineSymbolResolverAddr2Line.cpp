#ifndef _WIN32

#include "OfflineSymbolResolver.h"

#include <fstream>
#include <iostream>
#include <string>
#include <array>
#include <sstream>
#include <memory>
#include <stdio.h>

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
    SymbolResolver()
    {
        std::stringstream result( ExecShellCommand("which addr2line") );
        std::getline(result, m_addr2LinePath);

        if( !m_addr2LinePath.length() )
        {
            std::cerr << "'addr2line' was not found in the system, please installed it" << std::endl;
        }
        else
        {
            std::cout << "Using 'addr2line' found at: '" << m_addr2LinePath.c_str() << "'" << std::endl;
        }
    }

    static void escapeShellParam(std::string const& s, std::string& out)
    {
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
    }

    bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                         SymbolEntryList& resolvedEntries )
    {
        if( !m_addr2LinePath.length() ) return false;
        
        std:: string escapedPath;
        escapeShellParam( imagePath, escapedPath );

        size_t entryIdx = 0;
        while( entryIdx < inputEntryList.size() )
        {
            const size_t startIdx = entryIdx;
            const size_t batchEndIdx = std::min( inputEntryList.size(), startIdx + (size_t)1024 );

            printf( "Resolving symbols [%zu-%zu[\n", startIdx, batchEndIdx );

            // generate a single addr2line cmd line for all addresses in one invocation
            std::stringstream ss;
            ss << m_addr2LinePath << " -C -f -e " << escapedPath << " -a ";
            for( ; entryIdx < batchEndIdx; entryIdx++ )
            {
                const FrameEntry& entry = inputEntryList[entryIdx];
                ss << " 0x" << std::hex << entry.symbolOffset;
            }

            std::string resultStr = ExecShellCommand( ss.str().c_str() );
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
};

bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                     SymbolEntryList& resolvedEntries )
{
    static SymbolResolver symbolResolver;
    return symbolResolver.ResolveSymbols( imagePath, inputEntryList, resolvedEntries );
}

#endif // #ifndef _WIN32
