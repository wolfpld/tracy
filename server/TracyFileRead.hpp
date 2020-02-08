#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <assert.h>
#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <string>
#include <thread>
#include <utility>

#include "TracyFileHeader.hpp"
#include "TracyYield.hpp"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"
#include "../zstd/zstd.h"

namespace tracy
{

struct NotTracyDump : public std::exception {};

class FileRead
{
public:
    static FileRead* Open( const char* fn )
    {
        auto f = fopen( fn, "rb" );
        return f ? new FileRead( f, fn ) : nullptr;
    }

    ~FileRead()
    {
        m_exit.store( true, std::memory_order_relaxed );
        m_decThread.join();

        fclose( m_file );
        if( m_stream ) LZ4_freeStreamDecode( m_stream );
        if( m_streamZstd ) ZSTD_freeDStream( m_streamZstd );
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

    tracy_force_inline void Skip( size_t size )
    {
        if( size <= BufSize - m_offset )
        {
            m_offset += size;
        }
        else
        {
            SkipBig( size );
        }
    }

    template<class T>
    tracy_force_inline void Read( T& v )
    {
        if( sizeof( T ) < BufSize - m_offset )
        {
            memcpy( &v, m_buf + m_offset, sizeof( T ) );
            m_offset += sizeof( T );
        }
        else
        {
            T tmp;
            ReadBig( &tmp, sizeof( T ) );
            memcpy( &v, &tmp, sizeof( T ) );
        }

    }

    template<class T, class U>
    tracy_force_inline void Read2( T& v0, U& v1 )
    {
        if( sizeof( T ) + sizeof( U ) < BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            m_offset += sizeof( T ) + sizeof( U );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
        }
    }

    template<class T, class U, class V>
    tracy_force_inline void Read3( T& v0, U& v1, V& v2 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) < BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
        }
    }

    template<class T, class U, class V, class W>
    tracy_force_inline void Read4( T& v0, U& v1, V& v2, W& v3 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) < BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
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

    const std::string& GetFilename() const { return m_filename; }

private:
    FileRead( FILE* f, const char* fn )
        : m_stream( nullptr )
        , m_streamZstd( nullptr )
        , m_file( f )
        , m_buf( m_bufData[1] )
        , m_second( m_bufData[0] )
        , m_offset( 0 )
        , m_lastBlock( 0 )
        , m_signalSwitch( false )
        , m_signalAvailable( false )
        , m_exit( false )
        , m_filename( fn )
    {
        char hdr[4];
        if( fread( hdr, 1, sizeof( hdr ), m_file ) != sizeof( hdr ) ) throw NotTracyDump();
        if( memcmp( hdr, Lz4Header, sizeof( hdr ) ) == 0 )
        {
            m_stream = LZ4_createStreamDecode();
        }
        else if( memcmp( hdr, ZstdHeader, sizeof( hdr ) ) == 0 )
        {
            m_streamZstd = ZSTD_createDStream();
        }

        ReadBlock();
        std::swap( m_buf, m_second );
        m_decThread = std::thread( [this] { Worker(); } );
    }

    void Worker()
    {
        for(;;)
        {
            ReadBlock();
            for(;;)
            {
                if( m_exit.load( std::memory_order_relaxed ) == true ) return;
                if( m_signalSwitch.load( std::memory_order_relaxed ) == true ) break;
                YieldThread();
            }
            m_signalSwitch.store( false, std::memory_order_relaxed );
            std::swap( m_buf, m_second );
            m_offset = 0;
            m_signalAvailable.store( true, std::memory_order_release );
            if( m_lastBlock != BufSize ) return;
        }
    }

    tracy_force_inline void ReadSmall( void* ptr, size_t size )
    {
        memcpy( ptr, m_buf + m_offset, size );
        m_offset += size;
    }

    void ReadBig( void* ptr, size_t size )
    {
        auto dst = (char*)ptr;
        while( size > 0 )
        {
            if( m_offset == BufSize )
            {
                m_signalSwitch.store( true, std::memory_order_relaxed );
                while( m_signalAvailable.load( std::memory_order_acquire ) == false ) { YieldThread(); }
                m_signalAvailable.store( false, std::memory_order_relaxed );
            }

            const auto sz = std::min( size, BufSize - m_offset );
            memcpy( dst, m_buf + m_offset, sz );
            m_offset += sz;
            dst += sz;
            size -= sz;
        }
    }

    void SkipBig( size_t size )
    {
        while( size > 0 )
        {
            if( m_offset == BufSize )
            {
                m_signalSwitch.store( true, std::memory_order_relaxed );
                while( m_signalAvailable.load( std::memory_order_acquire ) == false ) { YieldThread(); }
                m_signalAvailable.store( false, std::memory_order_relaxed );
            }

            const auto sz = std::min( size, BufSize - m_offset );
            m_offset += sz;
            size -= sz;
        }
    }

    void ReadBlock()
    {
        char m_lz4buf[LZ4Size];
        uint32_t sz;
        if( fread( &sz, 1, sizeof( sz ), m_file ) == sizeof( sz ) )
        {
            fread( m_lz4buf, 1, sz, m_file );
            if( m_stream )
            {
                m_lastBlock = (size_t)LZ4_decompress_safe_continue( m_stream, m_lz4buf, m_second, sz, BufSize );
            }
            else
            {
                ZSTD_outBuffer out = { m_second, BufSize, 0 };
                ZSTD_inBuffer in = { m_lz4buf, sz, 0 };
                const auto ret = ZSTD_decompressStream( m_streamZstd, &out, &in );
                assert( ret > 0 );
                m_lastBlock = out.pos;
            }
        }
        else
        {
            m_lastBlock = 0;
        }
    }

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = std::max( LZ4_COMPRESSBOUND( BufSize ), ZSTD_COMPRESSBOUND( BufSize ) ) };

    LZ4_streamDecode_t* m_stream;
    ZSTD_DStream* m_streamZstd;
    FILE* m_file;
    char* m_buf;
    char* m_second;
    size_t m_offset;
    size_t m_lastBlock;

    alignas(64) std::atomic<bool> m_signalSwitch;
    alignas(64) std::atomic<bool> m_signalAvailable;
    alignas(64) std::atomic<bool> m_exit;

    std::thread m_decThread;

    std::string m_filename;
    char m_bufData[2][BufSize];
};

}

#endif
