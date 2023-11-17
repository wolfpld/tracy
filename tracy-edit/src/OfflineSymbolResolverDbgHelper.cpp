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

class SymbolResolver
{
public:
    SymbolResolver()
    {
        m_procHandle = GetCurrentProcess();

        if (!SymInitialize(m_procHandle, NULL, FALSE))
        {
            std::cerr << "SymInitialize() failed with: " << GetLastErrorString() << std::endl;
        }
        else
        {
            const DWORD symopts = SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_DEBUG | SYMOPT_LOAD_LINES;
            SymSetOptions( symopts );
        }
    }

    ~SymbolResolver()
    {
        SymCleanup( m_procHandle );
    }

    bool ResolveSymbolsForModule(const char* fileName, const FrameEntryList& inputEntryList,
                                 SymbolEntryList& resolvedEntries)
    {
        ULONG64 moduleBase = SymLoadModuleEx( m_procHandle, NULL, fileName, NULL, 0, 0, NULL, 0 );
        if (!moduleBase)
        {
            std::cerr << "SymLoadModuleEx() failed for module " << fileName 
                      << ": " << GetLastErrorString() << std::endl;
            return false;
        }

        for (size_t i = 0; i < inputEntryList.size(); ++i)
        {
            uint64_t offset = inputEntryList[i].symbolOffset;
            DWORD64 address = moduleBase + offset;

            SYMBOL_INFO* symbolInfo = (SYMBOL_INFO*)s_symbolResolutionBuffer;
            symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbolInfo->MaxNameLen = MAX_SYM_NAME;

            SymbolEntry newEntry;

            if ( SymFromAddr( m_procHandle, address, NULL, symbolInfo ) )
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

        SymUnloadModule64(m_procHandle, moduleBase);
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

    HANDLE m_procHandle = nullptr;
};

char SymbolResolver::s_symbolResolutionBuffer[symbolResolutionBufferSize];


SymbolResolver* CreateResolver()
{
    SymbolResolver* resolver = new SymbolResolver();
    return resolver;
}

void DestroySymbolResolver(SymbolResolver* resolver)
{
    delete resolver;
}

bool ResolveSymbols(SymbolResolver* resolver, const char* imageName,
                    const FrameEntryList& inputEntryList,
                    SymbolEntryList& resolvedEntries)
{
    if( resolver )
    {
        return resolver->ResolveSymbolsForModule( imageName, inputEntryList, resolvedEntries );
    }
    return false;
}

#endif // #ifdef _WIN32