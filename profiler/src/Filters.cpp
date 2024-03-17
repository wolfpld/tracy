#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "Filters.hpp"

#include "profiler/TracyStorage.hpp"


Filters::Filters()
    : m_fn( tracy::GetSavePath( "client.filters" ) )
{
    FILE* f = fopen( m_fn.c_str(), "rb" );
    if( !f ) return;

    uint8_t sz;
    fread( &sz, 1, sizeof( sz ), f );
    fread( m_addrFilter.InputBuf, 1, sz, f );
    m_addrFilter.Build();

    fread( &sz, 1, sizeof( sz ), f );
    fread( m_portFilter.InputBuf, 1, sz, f );
    m_portFilter.Build();

    fread( &sz, 1, sizeof( sz ), f );
    fread( m_progFilter.InputBuf, 1, sz, f );
    m_progFilter.Build();

    fclose( f );
}

Filters::~Filters()
{
    FILE* f = fopen( m_fn.c_str(), "wb" );
    if( !f ) return;

    uint8_t sz = (uint8_t)strlen( m_addrFilter.InputBuf );
    fwrite( &sz, 1, sizeof( sz ), f );
    fwrite( m_addrFilter.InputBuf, 1, sz, f );

    sz = (uint8_t)strlen( m_portFilter.InputBuf );
    fwrite( &sz, 1, sizeof( sz ), f );
    fwrite( m_portFilter.InputBuf, 1, sz, f );

    sz = (uint8_t)strlen( m_progFilter.InputBuf );
    fwrite( &sz, 1, sizeof( sz ), f );
    fwrite( m_progFilter.InputBuf, 1, sz, f );

    fclose( f );
}

void Filters::Clear()
{
    m_addrFilter.Clear();
    m_portFilter.Clear();
    m_progFilter.Clear();
}

void Filters::Draw( float w )
{
    m_addrFilter.Draw( "Address filter", w );
    m_portFilter.Draw( "Port filter", w );
    m_progFilter.Draw( "Program filter", w );
}

bool Filters::IsActive() const
{
    return m_addrFilter.IsActive() || m_portFilter.IsActive() || m_progFilter.IsActive();
}

bool Filters::FailAddr( const char* addr )
{
    return m_addrFilter.IsActive() && !m_addrFilter.PassFilter( addr );
}

bool Filters::FailPort( uint16_t port )
{
    if( !m_portFilter.IsActive() ) return false;
    char buf[32];
    sprintf( buf, "%" PRIu16, port );
    return !m_portFilter.PassFilter( buf );
}

bool Filters::FailProg( const char* prog )
{
    return m_progFilter.IsActive() && !m_progFilter.PassFilter( prog );
}
