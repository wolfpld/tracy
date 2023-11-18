#ifdef _WIN32
#  include <windows.h>
#endif

#include <fstream>
#include <iostream>
#include <regex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../getopt/getopt.h"

#include "OfflineSymbolResolver.h"

struct Args 
{
    const char* inputTracyPath = nullptr;
    const char* outputTracyPath = nullptr;
    bool verbose = false;
    bool resolveSymbols = false;
    std::vector<std::string> pathSubstitutions;
    tracy::FileWrite::Compression compressionType = tracy::FileWrite::Compression::Zstd;
    int compressionLevel = 5;
};

void PrintUsageAndExit()
{
    std::cerr << "Modify a tracy file" << std::endl;
    std::cerr << "Usage:" << std::endl;
    std::cerr << "  tracy-edit [OPTION...] <input trace file> <output tracy file>" << std::endl;
    std::cerr << std::endl;
    std::cerr << "  -h, --help                               Print usage" << std::endl;
    std::cerr << "  -v, --verbose                            Enable verbose logging" << std::endl;
    std::cerr << "  -r, --resolveSymbols                     Resolve symbols and patch callstack frames" << std::endl;
    std::cerr << "  -s, --substitutePath \"REGEX_MATCH;REPLACEMENT\" Substitute symbol resolution path with an alternative" << std::endl;
    std::cerr << "  -c, --compression Type                   Set the compression algorithm used for the output [Fast,Slow,Extreme,Zstd]" << std::endl;
    std::cerr << "  -l, --compressesionLevel Level           Level of compression" << std::endl;
    exit( 1 );
}

static const char* compressionTypeStr[]
{
    "Fast",
    "Slow",
    "Extreme",
    "Zstd"
};
static_assert( uint32_t(tracy::FileWrite::Compression::Zstd)+1 == sizeof(compressionTypeStr)/sizeof(compressionTypeStr[0]));
tracy::FileWrite::Compression getCompressionFromString(const char* str)
{
    for( uint32_t i = 0; i < sizeof(compressionTypeStr)/sizeof(compressionTypeStr[0]); ++i )
    {
        if( strcmp( compressionTypeStr[i], str ) == 0 )
        {
            return tracy::FileWrite::Compression( i );
        }
    }
    return tracy::FileWrite::Compression::Zstd;
}

Args ParseArgs( int argc, char** argv )
{
    if ( argc < 3 )
    {
        PrintUsageAndExit();
    }

    Args args;

    struct option long_opts[] = 
    {
        { "help", no_argument, NULL, 'h' },
        { "verbose", no_argument, NULL, 'v' },
        { "resolveSymbols", no_argument, NULL, 'r' },
        { "substitutePath", required_argument, NULL, 's' },
        { "compression", required_argument, NULL, 'c' },
        { "compressesionLevel", required_argument, NULL, 'l' },
        { NULL, 0, NULL, 0 }
    };

    int c;
    while ( (c = getopt_long( argc, argv, "hvrc:l:s:", long_opts, NULL )) != -1 )
    {
        switch (c)
        {
        case 'h':
            PrintUsageAndExit();
            break;
        case 'v':
            args.verbose = true;
            break;
        case 'r':
            args.resolveSymbols = true;
            break;
        case 'c':
            args.compressionType = getCompressionFromString( optarg );
            break;
        case 's':
            args.pathSubstitutions.push_back( optarg );
            break;
        case 'l':
            args.compressionLevel = atoi( optarg );
            break;
        default:
            PrintUsageAndExit();
            break;
        }
    }

    if (argc != optind + 2)
    {
        PrintUsageAndExit();
    }

    args.inputTracyPath = argv[optind + 0];
    args.outputTracyPath = argv[optind + 1];

    return args;
}

void PatchSymbols(tracy::Worker& worker, const Args& args);

int main( int argc, char** argv )
{
#ifdef _WIN32
    if( !AttachConsole( ATTACH_PARENT_PROCESS ) )
    {
        AllocConsole();
        SetConsoleMode( GetStdHandle( STD_OUTPUT_HANDLE ), 0x07 );
    }
#endif // #ifdef _WIN32

    Args args = ParseArgs( argc, argv );

    // load input tracy file
    auto f = std::unique_ptr<tracy::FileRead>(tracy::FileRead::Open( args.inputTracyPath ));
    if (!f)
    {
        std::cerr << "Could not open file: " << args.inputTracyPath;
        return 1;
    }

    std::cout << "Reading ..." << std::endl;

    const bool allowBgThreads = false;
    bool allowStringModification = true;
    tracy::Worker worker( *f, tracy::EventType::All, allowBgThreads, allowStringModification );

    std::cout << "Loaded." << std::endl;

    if(args.resolveSymbols)
    {
        PatchSymbols(worker, args);
    }

    // save out capture file with new compression options
    std::cout << "Saving (using '" << compressionTypeStr[uint32_t(args.compressionType)] 
              << "', level: " << args.compressionLevel << ") ..." << std::endl;

    auto w = std::unique_ptr<tracy::FileWrite>( 
        tracy::FileWrite::Open( args.outputTracyPath, args.compressionType, args.compressionLevel) );
    if( !w )
    {
        std::cerr << "Cannot open output file: '" << args.outputTracyPath << "'" << std::endl;
        exit( 1 );
    }

    worker.Write( *w, false );

    std::cout << "Cleanup..." << std::endl;

    return 0;
}

void PatchSymbols(tracy::Worker& worker, const Args& args)
{
    std::cout << "Resolving and patching symbols..." << std::endl;

    PathSubstitutionList pathSubstitutionList;
    for (const std::string& pathSubst : args.pathSubstitutions)
    {
        std::size_t pos = pathSubst.find(';');
        if (pos == std::string::npos)
        {
            std::cerr << "Ignoring invalid path substitution: '" << pathSubst
                << " '(please separate the regex of the string to replace with a ';')" << std::endl;
            continue;
        }

        try
        {
            std::regex reg(pathSubst.substr(0, pos));
            std::string replacementStr(pathSubst.substr(pos + 1));
            pathSubstitutionList.push_back(std::pair(reg, replacementStr));
        }
        catch (std::exception& e)
        {
            std::cerr << "Ignoring invalid path substitution: '" << pathSubst
                << "' (" << e.what() << ")" << std::endl;
            continue;
        }
    }

    SymbolResolver* resolver = CreateResolver();
    if (resolver)
    {
        PatchSymbols(resolver, worker, pathSubstitutionList, args.verbose);

        DestroySymbolResolver(resolver);
    }
    else
    {
        std::cerr << "Failed to create symbol resolver - skipping resolving" << std::endl;
    }
}
