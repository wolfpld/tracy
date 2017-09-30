#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <algorithm>
#include <stdio.h>

#include "../common/tracy_lz4.hpp"

namespace tracy
{

class FileRead
{
public:
    static FileRead* Open( const char* fn )
    {
        auto f = fopen( fn, "rb" );
        return f ? new FileRead( f ) : nullptr;
    }

    ~FileRead()
    {
        fclose( m_file );
        LZ4_freeStreamDecode( m_stream );
    }

    void Read( void* ptr, size_t size )
    {
        if( size <= BufSize - m_offset )
        {
            memcpy( ptr, m_buf[m_active] + m_offset, size );
            m_offset += size;
        }
        else
        {
            auto dst = (char*)ptr;
            while( size > 0 )
            {
                if( m_offset == BufSize )
                {
                    m_active = 1 - m_active;
                    m_offset = 0;
                    uint32_t sz;
                    fread( &sz, 1, sizeof( sz ), m_file );
                    char lz4[LZ4Size];
                    fread( lz4, 1, sz, m_file );
                    LZ4_decompress_safe_continue( m_stream, lz4, m_buf[m_active], sz, BufSize );
                }

                const auto sz = std::min( size, BufSize - m_offset );
                memcpy( dst, m_buf[m_active] + m_offset, sz );
                m_offset += sz;
                dst += sz;
                size -= sz;
            }
        }
    }

private:
    FileRead( FILE* f )
        : m_stream( LZ4_createStreamDecode() )
        , m_file( f )
        , m_offset( BufSize )
        , m_active( 1 )
    {}

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = LZ4_COMPRESSBOUND( BufSize ) };

    LZ4_streamDecode_t* m_stream;
    FILE* m_file;
    char m_buf[2][BufSize];
    size_t m_offset;
    uint8_t m_active;
};

}

#endif
