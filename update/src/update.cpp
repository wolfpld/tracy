#ifdef _WIN32
#  include <windows.h>
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyFileWrite.hpp"
#include "../../server/TracyWorker.hpp"

void Usage()
{
    printf( "Usage: update input.tracy output.tracy\n" );
    exit( 1 );
}

int main( int argc, char** argv )
{
#ifdef _WIN32
    if( !AttachConsole( ATTACH_PARENT_PROCESS ) )
    {
        AllocConsole();
        SetConsoleMode( GetStdHandle( STD_OUTPUT_HANDLE ), 0x07 );
    }
#endif

    if( argc != 3 ) Usage();

    const char* input = argv[1];
    const char* output = argv[2];

    auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( input ) );
    if( !f )
    {
        fprintf( stderr, "Cannot open input file!\n" );
        exit( 1 );
    }

    try
    {
        tracy::Worker worker( *f );

        auto w = std::unique_ptr<tracy::FileWrite>( tracy::FileWrite::Open( output ) );
        if( !w )
        {
            fprintf( stderr, "Cannot open output file!\n" );
            exit( 1 );
        }
        worker.Write( *w );
    }
    catch( const tracy::UnsupportedVersion& e )
    {
        fprintf( stderr, "The file you are trying to open is from the future version.\n" );
        exit( 1 );
    }
    catch( const tracy::NotTracyDump& e )
    {
        fprintf( stderr, "The file you are trying to open is not a tracy dump.\n" );
        exit( 1 );
    }

    return 0;
}
