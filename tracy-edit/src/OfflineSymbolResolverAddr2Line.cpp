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

    bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                         SymbolEntryList& resolvedEntries )
    {
        if (!m_addr2LinePath.length()) return false;

        // generate a single addr2line cmd line for all addresses in one invocation
        std::stringstream ss;
        ss << m_addr2LinePath << " -C -f -e " << imagePath << " -a ";
        for ( const FrameEntry& entry : inputEntryList )
        {
            ss << " 0x" << std::hex << entry.symbolOffset;
        }

        std::string resultStr = ExecShellCommand( ss.str().c_str() );
        std::stringstream result(resultStr);
        //printf("executing: '%s' got '%s'\n", ss.str().c_str(), result.str().c_str());

        // The output is 2 lines per entry with the following contents:
        // hex_address_of_symbol
        // symbol_name
        // file:line

        for( size_t i = 0; i < inputEntryList.size(); ++i )
        {
            const FrameEntry& inputEntry = inputEntryList[i];

            SymbolEntry newEntry;

            std::string addr;
            std::getline( result, addr );
            std::getline( result, newEntry.name );
            if (newEntry.name == "??")
            {
                newEntry.name = "[unknown] + " + std::to_string(inputEntry.symbolOffset);
            }

            std::string fileLine;
            std::getline(result, fileLine);
            if ( fileLine != "??:?" )
            {
                size_t pos = fileLine.find_last_of(':');
                if ( pos != std::string::npos )
                {
                    newEntry.file = fileLine.substr( 0, pos );
                    std::string lineStr = fileLine.substr( pos + 1 );
                    char* after = nullptr;
                    newEntry.line = strtol( lineStr.c_str(), &after, 10 );
                }
            }

            resolvedEntries.push_back( std::move(newEntry) );
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
