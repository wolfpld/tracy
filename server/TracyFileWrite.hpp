#ifndef __TRACYFILEWRITE_HPP__
#define __TRACYFILEWRITE_HPP__

#ifdef _MSC_VER
#  pragma warning( disable: 4267 )  // conversion from don't care to whatever, possible loss of data 
#endif

#include <algorithm>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <utility>

#include "TracyFileHeader.hpp"
#include "../common/tracy_lz4.hpp"
#include "../common/tracy_lz4hc.hpp"
#include "../common/TracyForceInline.hpp"
#include "../zstd/zstd.h"

namespace tracy
{

class FileWrite
{
public:
    enum class Compression
    {
        Fast,
        Slow,
        Extreme,
        Zstd
    };

    static FileWrite* Open( const char* fn, Compression comp = Compression::Fast, int level = 1 )
    {
        auto f = fopen( fn, "wb" );
        return f ? new FileWrite( f, comp, level ) : nullptr;
    }

    ~FileWrite()
    {
        if( m_offset > 0 ) WriteLz4Block();
        fclose( m_file );

        if( m_stream ) LZ4_freeStream( m_stream );
        if( m_streamHC ) LZ4_freeStreamHC( m_streamHC );
        if( m_streamZstd ) ZSTD_freeCStream( m_streamZstd );
    }

    void Finish()
    {
        if( m_offset > 0 ) WriteLz4Block();
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

    std::pair<size_t, size_t> GetCompressionStatistics() const { return std::make_pair( m_srcBytes, m_dstBytes ); }

private:
    FileWrite( FILE* f, Compression comp, int level )
        : m_stream( nullptr )
        , m_streamHC( nullptr )
        , m_streamZstd( nullptr )
        , m_file( f )
        , m_buf( m_bufData[0] )
        , m_second( m_bufData[1] )
        , m_offset( 0 )
        , m_srcBytes( 0 )
        , m_dstBytes( 0 )
    {
        switch( comp )
        {
        case Compression::Fast:
            m_stream = LZ4_createStream();
            break;
        case Compression::Slow:
            m_streamHC = LZ4_createStreamHC();
            break;
        case Compression::Extreme:
            m_streamHC = LZ4_createStreamHC();
            LZ4_resetStreamHC( m_streamHC, LZ4HC_CLEVEL_MAX );
            break;
        case Compression::Zstd:
            m_streamZstd = ZSTD_createCStream();
            ZSTD_CCtx_setParameter( m_streamZstd, ZSTD_c_compressionLevel, level );
            ZSTD_CCtx_setParameter( m_streamZstd, ZSTD_c_contentSizeFlag, 0 );
            break;
        default:
            assert( false );
            break;
        }

        if( comp == Compression::Zstd )
        {
            fwrite( ZstdHeader, 1, sizeof( ZstdHeader ), m_file );
        }
        else
        {
            fwrite( Lz4Header, 1, sizeof( Lz4Header ), m_file );
        }
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
        uint32_t sz;
        if( m_stream )
        {
            sz = LZ4_compress_fast_continue( m_stream, m_buf, lz4, m_offset, LZ4Size, 1 );
        }
        else if( m_streamZstd )
        {
            ZSTD_outBuffer out = { lz4, LZ4Size, 0 };
            ZSTD_inBuffer in = { m_buf, m_offset, 0 };
            const auto ret = ZSTD_compressStream2( m_streamZstd, &out, &in, ZSTD_e_flush );
            assert( ret == 0 );
            sz = out.pos;
        }
        else
        {
            sz = LZ4_compress_HC_continue( m_streamHC, m_buf, lz4, m_offset, LZ4Size );
        }

        m_srcBytes += m_offset;
        m_dstBytes += sz;

        fwrite( &sz, 1, sizeof( sz ), m_file );
        fwrite( lz4, 1, sz, m_file );
        m_offset = 0;
        std::swap( m_buf, m_second );
    }

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = std::max( LZ4_COMPRESSBOUND( BufSize ), ZSTD_COMPRESSBOUND( BufSize ) ) };

    LZ4_stream_t* m_stream;
    LZ4_streamHC_t* m_streamHC;
    ZSTD_CStream* m_streamZstd;
    FILE* m_file;
    char m_bufData[2][BufSize];
    char* m_buf;
    char* m_second;
    size_t m_offset;
    size_t m_srcBytes;
    size_t m_dstBytes;
};

}

#endif
