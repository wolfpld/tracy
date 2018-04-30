#ifndef __TRACYFILEWRITE_HPP__
#define __TRACYFILEWRITE_HPP__

#include <algorithm>
#include <stdio.h>
#include <string.h>

#include "TracyFileHeader.hpp"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"

namespace tracy
{

class FileWrite
{
public:
    static FileWrite* Open( const char* fn )
    {
        auto f = fopen( fn, "wb" );
        return f ? new FileWrite( f ) : nullptr;
    }

    ~FileWrite()
    {
        if( m_offset > 0 )
        {
            WriteLz4Block();
        }
        fclose( m_file );
        LZ4_freeStream( m_stream );
    }

    tracy_force_inline void Write( const void* ptr, size_t size )
    {
        if( m_offset + size <= BufSize )
        {
            WriteSmall( ptr, size );
        }
        else
        {
            WriteBig( ptr, size );
        }
    }

private:
    FileWrite( FILE* f )
        : m_stream( LZ4_createStream() )
        , m_file( f )
        , m_buf( m_bufData[0] )
        , m_second( m_bufData[1] )
        , m_offset( 0 )
    {
        fwrite( Lz4Header, 1, sizeof( Lz4Header ), m_file );
    }

    tracy_force_inline void WriteSmall( const void* ptr, size_t size )
    {
        memcpy( m_buf + m_offset, ptr, size );
        m_offset += size;
    }

    void WriteBig( const void* ptr, size_t size )
    {
        auto src = (const char*)ptr;
        while( size > 0 )
        {
            const auto sz = std::min( size, BufSize - m_offset );
            memcpy( m_buf + m_offset, src, sz );
            m_offset += sz;
            src += sz;
            size -= sz;

            if( m_offset == BufSize )
            {
                WriteLz4Block();
            }
        }
    }

    void WriteLz4Block()
    {
        char lz4[LZ4Size];
        const uint32_t sz = LZ4_compress_fast_continue( m_stream, m_buf, lz4, m_offset, LZ4Size, 1 );
        fwrite( &sz, 1, sizeof( sz ), m_file );
        fwrite( lz4, 1, sz, m_file );
        m_offset = 0;
        std::swap( m_buf, m_second );
    }

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = LZ4_COMPRESSBOUND( BufSize ) };

    LZ4_stream_t* m_stream;
    FILE* m_file;
    char m_bufData[2][BufSize];
    char* m_buf;
    char* m_second;
    size_t m_offset;
};

}

#endif
