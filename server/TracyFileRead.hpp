#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <algorithm>
#include <stdexcept>
#include <stdio.h>
#include <string.h>

#include "TracyFileHeader.hpp"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"

namespace tracy
{

struct NotTracyDump : public std::exception {};

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

    void Skip( size_t size )
    {
        if( size <= BufSize - m_offset )
        {
            m_offset += size;
        }
        else
        {
            char m_lz4buf[LZ4Size];
            while( size > 0 )
            {
                if( m_offset == BufSize )
                {
                    std::swap( m_buf, m_second );
                    m_offset = 0;
                    uint32_t sz;
                    fread( &sz, 1, sizeof( sz ), m_file );
                    fread( m_lz4buf, 1, sz, m_file );
                    m_lastBlock = LZ4_decompress_safe_continue( m_stream, m_lz4buf, m_buf, sz, BufSize );
                }

                const auto sz = std::min( size, BufSize - m_offset );
                m_offset += sz;
                size -= sz;
            }
        }
    }

    bool IsEOF()
    {
        if( m_lastBlock != BufSize && m_offset == m_lastBlock ) return true;
        if( m_offset == BufSize )
        {
            if( fseek( m_file, 1, SEEK_CUR ) != 0 ) return true;
            fseek( m_file, -1, SEEK_CUR );
        }
        return false;
    }

private:
    FileRead( FILE* f )
        : m_stream( LZ4_createStreamDecode() )
        , m_file( f )
        , m_buf( m_bufData[0] )
        , m_second( m_bufData[1] )
        , m_offset( BufSize )
        , m_lastBlock( 0 )
    {
        char hdr[4];
        if( fread( hdr, 1, sizeof( hdr ), m_file ) != sizeof( hdr ) ) throw NotTracyDump();
        if( memcmp( hdr, Lz4Header, sizeof( hdr ) ) != 0 )
        {
            fseek( m_file, 0, SEEK_SET );
            uint32_t sz;
            static_assert( sizeof( sz ) == sizeof( hdr ), "Size mismatch" );
            memcpy( &sz, hdr, sizeof( sz ) );
            if( sz > LZ4Size ) throw NotTracyDump();
        }
    }

    tracy_force_inline void ReadSmall( void* ptr, size_t size )
    {
        memcpy( ptr, m_buf + m_offset, size );
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
                std::swap( m_buf, m_second );
                m_offset = 0;
                uint32_t sz;
                fread( &sz, 1, sizeof( sz ), m_file );
                fread( m_lz4buf, 1, sz, m_file );
                m_lastBlock = LZ4_decompress_safe_continue( m_stream, m_lz4buf, m_buf, sz, BufSize );
            }

            const auto sz = std::min( size, BufSize - m_offset );
            memcpy( dst, m_buf + m_offset, sz );
            m_offset += sz;
            dst += sz;
            size -= sz;
        }
    }

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = LZ4_COMPRESSBOUND( BufSize ) };

    LZ4_streamDecode_t* m_stream;
    FILE* m_file;
    char m_bufData[2][BufSize];
    char* m_buf;
    char* m_second;
    size_t m_offset;
    int m_lastBlock;
};

}

#endif
