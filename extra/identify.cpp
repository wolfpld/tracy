// g++ identify.cpp -lpthread ../common/tracy_lz4.cpp ../zstd/common/*.c ../zstd/decompress/*.c

#include <memory>
#include <stdint.h>
#include <stdio.h>

#include "../server/TracyFileRead.hpp"
#include "../server/TracyVersion.hpp"

static const uint8_t FileHeader[8] { 't', 'r', 'a', 'c', 'y', tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch };
enum { FileHeaderMagic = 5 };

int main( int argc, char** argv )
{
    if( argc != 2 )
    {
        fprintf( stderr, "Usage: %s trace\n", argv[0] );
        return -1;
    }

    try
    {
        std::unique_ptr<tracy::FileRead> f( tracy::FileRead::Open( argv[1] ) );
        if( !f )
        {
            fprintf( stderr, "%s: Cannot open!\n", argv[1] );
            return -2;
        }

        uint8_t hdr[8];
        f->Read( hdr, sizeof( hdr ) );
        if( memcmp( FileHeader, hdr, FileHeaderMagic ) != 0 )
        {
            fprintf( stderr, "%s: Bad header!\n", argv[1] );
            return -3;
        }

        printf( "%s: %i.%i.%i\n", argv[1], hdr[FileHeaderMagic], hdr[FileHeaderMagic+1], hdr[FileHeaderMagic+2] );
    }
    catch( const tracy::NotTracyDump& )
    {
        fprintf( stderr, "%s: Not a tracy dump!\n", argv[1] );
        return -4;
    }
    catch( const tracy::FileReadError& )
    {
        fprintf( stderr, "%s: File read error!\n", argv[1] );
        return -5;
    }
}
