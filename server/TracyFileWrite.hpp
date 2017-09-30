#ifndef __TRACYFILEWRITE_HPP__
#define __TRACYFILEWRITE_HPP__

#include <algorithm>
#include <stdio.h>

#include "../common/tracy_lz4.hpp"

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

    void Write( const void* ptr, size_t size )
    {
        if( m_offset + size <= BufSize )
        {
            memcpy( m_buf[m_active] + m_offset, ptr, size );
            m_offset += size;
        }
        else
        {
            auto src = (const char*)ptr;
            while( size > 0 )
            {
                const auto sz = std::min( size, BufSize - m_offset );
                memcpy( m_buf[m_active] + m_offset, src, sz );
                m_offset += sz;
                src += sz;
                size -= sz;

                if( m_offset == BufSize )
                {
                    WriteLz4Block();
                }
            }
        }
    }

private:
    FileWrite( FILE* f )
        : m_stream( LZ4_createStream() )
        , m_file( f )
        , m_offset( 0 )
        , m_active( 0 )
    {}

    void WriteLz4Block()
    {
        char lz4[LZ4Size];
        const uint32_t sz = LZ4_compress_fast_continue( m_stream, m_buf[m_active], lz4, m_offset, LZ4Size, 1 );
        fwrite( &sz, 1, sizeof( sz ), m_file );
        fwrite( lz4, 1, sz, m_file );
        m_offset = 0;
        m_active = 1 - m_active;
    }

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = LZ4_COMPRESSBOUND( BufSize ) };

    LZ4_stream_t* m_stream;
    FILE* m_file;
    char m_buf[2][BufSize];
    size_t m_offset;
    uint8_t m_active;
};

}

#endif
