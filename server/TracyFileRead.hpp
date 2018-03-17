#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <algorithm>
#include <stdio.h>
#include <string.h>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"

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

    tracy_force_inline void Read( void* ptr, size_t size )
    {
        if( size <= BufSize - m_offset )
        {
            ReadSmall( ptr, size );
        }
        else
        {
            ReadBig( ptr, size );
        }
    }

private:
    FileRead( FILE* f )
        : m_stream( LZ4_createStreamDecode() )
        , m_file( f )
        , m_offset( BufSize )
        , m_active( 1 )
    {}

    tracy_force_inline void ReadSmall( void* ptr, size_t size )
    {
        memcpy( ptr, m_buf[m_active] + m_offset, size );
        m_offset += size;
    }

    void ReadBig( void* ptr, size_t size )
    {
        char m_lz4buf[LZ4Size];
        auto dst = (char*)ptr;
        while( size > 0 )
        {
            if( m_offset == BufSize )
            {
                m_active = 1 - m_active;
                m_offset = 0;
                uint32_t sz;
                fread( &sz, 1, sizeof( sz ), m_file );
                fread( m_lz4buf, 1, sz, m_file );
                LZ4_decompress_safe_continue( m_stream, m_lz4buf, m_buf[m_active], sz, BufSize );
            }

            const auto sz = std::min( size, BufSize - m_offset );
            memcpy( dst, m_buf[m_active] + m_offset, sz );
            m_offset += sz;
            dst += sz;
            size -= sz;
        }
    }

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
