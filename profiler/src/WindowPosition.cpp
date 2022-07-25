#include <stdint.h>
#include <stdio.h>

#include "WindowPosition.hpp"

#include "../../server/TracyStorage.hpp"


WindowPosition::WindowPosition()
    : m_fn( tracy::GetSavePath( "window.position" ) )
{
    Defaults();

    FILE* f = fopen( m_fn.c_str(), "rb" );
    if( f )
    {
        uint32_t data[5];
        if( fread( data, 1, sizeof( data ), f ) == sizeof( data ) )
        {
            x = data[0];
            y = data[1];
            w = data[2];
            h = data[3];
            maximize = data[4];
        }
        fclose( f );

        if( w <= 0 || h <= 0 ) Defaults();
    }
}

WindowPosition::~WindowPosition()
{
    FILE* f = fopen( m_fn.c_str(), "wb" );
    if( !f ) return;
    uint32_t data[5] = { uint32_t( x ), uint32_t( y ), uint32_t( w ), uint32_t( h ), uint32_t( maximize ) };
    fwrite( data, 1, sizeof( data ), f );
    fclose( f );
}

void WindowPosition::Defaults()
{
    x = 200;
    y = 200;
    w = 1650;
    h = 960;
    maximize = 0;
}
