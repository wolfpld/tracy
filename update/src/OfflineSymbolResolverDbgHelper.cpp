#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#   define WIN32_LEAN_AND_MEAN
#endif 

#include <windows.h>
#include <dbghelp.h>

#include <cstdio>
#include <iostream>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <string>

#include "OfflineSymbolResolver.h"

#pragma comment(lib, "dbghelp.lib")

class SymbolResolver
{
public:
    SymbolResolver()
    {
        m_procHandle = GetCurrentProcess();

        if( !SymInitialize(m_procHandle, NULL, FALSE) )
        {
            std::cerr << "SymInitialize() failed with: " << GetLastErrorString() << std::endl;
        }
        else
        {
            const DWORD symopts = SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES;
            SymSetOptions( symopts );
            m_dbgHelpInitialized = true;
        }
    }

    ~SymbolResolver()
    {
        SymCleanup( m_procHandle );
    }

    bool ResolveSymbolsForModule( const std::string& imagePath, const FrameEntryList& inputEntryList,
                                  SymbolEntryList& resolvedEntries )
    {
        if( !m_dbgHelpInitialized ) return false;

        ULONG64 moduleBase = SymLoadModuleEx( m_procHandle, NULL, imagePath.c_str(), NULL, 0, 0, NULL, 0 );
        if( !moduleBase )
        {
            std::cerr << "SymLoadModuleEx() failed for module " << imagePath
                      << ": " << GetLastErrorString() << std::endl;
            return false;
        }

        for( size_t i = 0; i < inputEntryList.size(); ++i )
        {
            uint64_t offset = inputEntryList[i].symbolOffset;
            DWORD64 address = moduleBase + offset;

            SYMBOL_INFO* symbolInfo = (SYMBOL_INFO*)s_symbolResolutionBuffer;
            symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbolInfo->MaxNameLen = MAX_SYM_NAME;

            SymbolEntry newEntry;

            if( SymFromAddr( m_procHandle, address, NULL, symbolInfo ) )
            {
                newEntry.name = symbolInfo->Name;
                //std::cout << "Resolved symbol to: '" << newEntry.name << "'" << std::endl;
            }
            else
            {
                newEntry.name = "[unknown] + " + std::to_string(offset);
            }

            IMAGEHLP_LINE lineInfo = { 0 };
            lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
            DWORD displaceMent = 0;
            if ( SymGetLineFromAddr64( m_procHandle, address, &displaceMent, &lineInfo ) )
            {
                newEntry.file = lineInfo.FileName;
                newEntry.line = int(lineInfo.LineNumber);
                ///std::cout << "\tline_file: " lineInfo.FileName << ":" << int(lineInfo.LineNumber) << std::endl;
            }

            resolvedEntries.push_back(std::move(newEntry));
        }

        SymUnloadModule64( m_procHandle, moduleBase );
        return true;
    }

private:
    static const size_t symbolResolutionBufferSize = sizeof(SYMBOL_INFO) + MAX_SYM_NAME;
    static char s_symbolResolutionBuffer[symbolResolutionBufferSize];

    std::string GetLastErrorString()
    {
        DWORD error = GetLastError();
        if (error == 0)
        {
            return "";
        }

        LPSTR messageBuffer = nullptr;
        DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        size_t size = FormatMessageA( dwFlags, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                     (LPSTR)&messageBuffer, 0, NULL );

        std::string message(messageBuffer, size);
        LocalFree(messageBuffer);

        return message;
    }

    bool m_dbgHelpInitialized = false;
    HANDLE m_procHandle = nullptr;
};

char SymbolResolver::s_symbolResolutionBuffer[symbolResolutionBufferSize];

bool ResolveSymbols( const std::string& imagePath, const FrameEntryList& inputEntryList,
                    SymbolEntryList& resolvedEntries )
{
    static SymbolResolver resolver;
    return resolver.ResolveSymbolsForModule( imagePath, inputEntryList, resolvedEntries );
}

#endif // #ifdef _WIN32
