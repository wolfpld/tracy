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

#include <sys/stat.h>

#ifdef _MSC_VER
#  define stat64 _stat64
#endif
#if defined __CYGWIN__ || defined __APPLE__
#  define stat64 stat
#endif

#include "TracyFileHeader.hpp"
#include "TracyMmap.hpp"
#include "TracyYield.hpp"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"
#include "../zstd/zstd.h"

namespace tracy
{

struct NotTracyDump : public std::exception {};
struct FileReadError : public std::exception {};

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

        if( m_data ) munmap( m_data, m_dataSize );
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
        if( sizeof( T ) <= BufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) <= BufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) <= BufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) <= BufSize - m_offset )
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

    template<class T, class U, class V, class W, class X>
    tracy_force_inline void Read5( T& v0, U& v1, V& v2, W& v3, X& v4 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) <= BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
        }
    }

    template<class T, class U, class V, class W, class X, class Y>
    tracy_force_inline void Read6( T& v0, U& v1, V& v2, W& v3, X& v4, Y& v5 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) <= BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
        }
    }

    template<class T, class U, class V, class W, class X, class Y, class Z>
    tracy_force_inline void Read7( T& v0, U& v1, V& v2, W& v3, X& v4, Y& v5, Z& v6 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) <= BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
        }
    }

    template<class T, class U, class V, class W, class X, class Y, class Z, class A>
    tracy_force_inline void Read8( T& v0, U& v1, V& v2, W& v3, X& v4, Y& v5, Z& v6, A& v7 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) <= BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
            memcpy( &v7, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ), sizeof( A ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
            memcpy( &v7, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ), sizeof( A ) );
        }
    }

    template<class T, class U, class V, class W, class X, class Y, class Z, class A, class B>
    tracy_force_inline void Read9( T& v0, U& v1, V& v2, W& v3, X& v4, Y& v5, Z& v6, A& v7, B& v8 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) <= BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( U ) );
            memcpy( &v2, m_buf + m_offset + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
            memcpy( &v7, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ), sizeof( A ) );
            memcpy( &v8, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ), sizeof( B ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
            memcpy( &v7, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ), sizeof( A ) );
            memcpy( &v8, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ), sizeof( B ) );
        }
    }

    const std::string& GetFilename() const { return m_filename; }

private:
    FileRead( FILE* f, const char* fn )
        : m_stream( nullptr )
        , m_streamZstd( nullptr )
        , m_data( nullptr )
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
        if( fread( hdr, 1, sizeof( hdr ), f ) != sizeof( hdr ) )
        {
            fclose( f );
            throw NotTracyDump();
        }
        if( memcmp( hdr, Lz4Header, sizeof( hdr ) ) == 0 )
        {
            m_stream = LZ4_createStreamDecode();
        }
        else if( memcmp( hdr, ZstdHeader, sizeof( hdr ) ) == 0 )
        {
            m_streamZstd = ZSTD_createDStream();
        }
        else
        {
            fclose( f );
            throw NotTracyDump();
        }

        struct stat64 buf;
        if( stat64( fn, &buf ) == 0 )
        {
            m_dataSize = buf.st_size;
        }
        else
        {
            fclose( f );
            throw FileReadError();
        }

        m_data = (char*)mmap( nullptr, m_dataSize, PROT_READ, MAP_SHARED, fileno( f ), 0 );
        fclose( f );
        if( !m_data )
        {
            throw FileReadError();
        }
        m_dataOffset = sizeof( hdr );

        ReadBlock( ReadBlockSize() );
        std::swap( m_buf, m_second );
        m_decThread = std::thread( [this] { Worker(); } );
    }

    tracy_force_inline uint32_t ReadBlockSize()
    {
        uint32_t sz;
        memcpy( &sz, m_data + m_dataOffset, sizeof( sz ) );
        m_dataOffset += sizeof( sz );
        return sz;
    }

    void Worker()
    {
        uint32_t blockSz = ReadBlockSize();
        for(;;)
        {
            ReadBlock( blockSz );
            if( m_lastBlock == BufSize ) blockSz = ReadBlockSize();
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
        assert( size > 0 );
        auto dst = (char*)ptr;
        do
        {
            size_t sz;
            if( m_offset == BufSize )
            {
                sz = std::min<size_t>( size, BufSize );

                m_signalSwitch.store( true, std::memory_order_relaxed );
                while( m_signalAvailable.load( std::memory_order_acquire ) == false ) { YieldThread(); }
                m_signalAvailable.store( false, std::memory_order_relaxed );
                assert( m_offset == 0 );

                memcpy( dst, m_buf, sz );
                m_offset = sz;
            }
            else
            {
                sz = std::min( size, BufSize - m_offset );
                memcpy( dst, m_buf + m_offset, sz );
                m_offset += sz;
            }

            dst += sz;
            size -= sz;
        }
        while( size > 0 );
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

    void ReadBlock( uint32_t sz )
    {
        if( m_stream )
        {
            m_lastBlock = (size_t)LZ4_decompress_safe_continue( m_stream, m_data + m_dataOffset, m_second, sz, BufSize );
            m_dataOffset += sz;
        }
        else
        {
            ZSTD_outBuffer out = { m_second, BufSize, 0 };
            ZSTD_inBuffer in = { m_data + m_dataOffset, sz, 0 };
            m_dataOffset += sz;
            const auto ret = ZSTD_decompressStream( m_streamZstd, &out, &in );
            assert( ret > 0 );
            m_lastBlock = out.pos;
        }
    }

    enum { BufSize = 64 * 1024 };
    enum { LZ4Size = std::max( LZ4_COMPRESSBOUND( BufSize ), ZSTD_COMPRESSBOUND( BufSize ) ) };

    LZ4_streamDecode_t* m_stream;
    ZSTD_DStream* m_streamZstd;
    char* m_data;
    uint64_t m_dataSize;
    uint64_t m_dataOffset;
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
