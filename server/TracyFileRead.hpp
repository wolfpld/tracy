#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <assert.h>
#include <atomic>
#include <algorithm>
#include <condition_variable>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sys/stat.h>

#ifdef _MSC_VER
#  define stat64 _stat64
#endif
#if defined __APPLE__ || defined __FreeBSD__
#  define stat64 stat
#endif

#include "TracyFileHeader.hpp"
#include "TracyFileMeta.hpp"
#include "TracyMmap.hpp"
#include "../public/common/TracyYield.hpp"
#include "../public/common/tracy_lz4.hpp"
#include "../public/common/TracyForceInline.hpp"
#include "../zstd/zstd.h"

namespace tracy
{

struct NotTracyDump : public std::exception {};
struct FileReadError : public std::exception {};

class ReadStream
{
public:
    ReadStream( uint8_t type )
        : m_stream( nullptr )
        , m_streamZstd( nullptr )
        , m_buf( new char[FileBufSize] )
        , m_second( new char[FileBufSize] )
    {
        switch( type )
        {
        case 0:
            m_stream = LZ4_createStreamDecode();
            break;
        case 1:
            m_streamZstd = ZSTD_createDStream();
            break;
        default:
            assert( false );
            break;
        }
    }

    ~ReadStream()
    {
        delete[] m_buf;
        delete[] m_second;

        if( m_stream ) LZ4_freeStreamDecode( m_stream );
        if( m_streamZstd ) ZSTD_freeDStream( m_streamZstd );
    }

    void Decompress( const char* src, uint32_t size )
    {
        std::swap( m_buf, m_second );
        if( m_stream )
        {
            m_size = (size_t)LZ4_decompress_safe_continue( m_stream, src, m_buf, size, FileBufSize );
        }
        else
        {
            ZSTD_outBuffer out = { m_buf, FileBufSize, 0 };
            ZSTD_inBuffer in = { src, size, 0 };
            ZSTD_decompressStream( m_streamZstd, &out, &in );
            m_size = out.pos;
        }
    }

    const char* GetBuffer() const { return m_buf; }
    size_t GetSize() const { return m_size; }

private:
    LZ4_streamDecode_t* m_stream;
    ZSTD_DStream* m_streamZstd;

    char* m_buf;
    char* m_second;

    size_t m_size;
};

class FileRead
{
    struct StreamHandle
    {
        StreamHandle( uint8_t type ) : stream( type ), outputReady( false ) {}

        ReadStream stream;
        const char* src;
        uint32_t size;

        bool inputReady = false;
        bool exit = false;
        alignas(64) std::atomic<bool> outputReady;

        std::mutex signalLock;
        std::condition_variable signal;

        std::thread thread;
    };

public:
    static FileRead* Open( const char* fn )
    {
        auto f = fopen( fn, "rb" );
        return f ? new FileRead( f, fn ) : nullptr;
    }

    ~FileRead()
    {
        for( auto& v : m_streams )
        {
            std::lock_guard lock( v->signalLock );
            v->exit = true;
            v->signal.notify_one();
        }
        for( auto& v : m_streams ) v->thread.join();
        m_streams.clear();
        if( m_data ) munmap( m_data, m_dataSize );
    }

    tracy_force_inline void Read( void* ptr, size_t size )
    {
        if( size <= FileBufSize - m_offset )
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
        if( size <= FileBufSize - m_offset )
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
        if( sizeof( T ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) <= FileBufSize - m_offset )
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
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) <= FileBufSize - m_offset )
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

    template<class T, class U, class V, class W, class X, class Y, class Z, class A, class B, class C>
    tracy_force_inline void Read10( T& v0, U& v1, V& v2, W& v3, X& v4, Y& v5, Z& v6, A& v7, B& v8, C& v9 )
    {
        if( sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) + sizeof( C ) <= FileBufSize - m_offset )
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
            memcpy( &v9, m_buf + m_offset + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ), sizeof( C ) );
            m_offset += sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) + sizeof( C );
        }
        else
        {
            char tmp[sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) + sizeof( C )];
            ReadBig( tmp, sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ) + sizeof( C ) );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp + sizeof( T ), sizeof( U ) );
            memcpy( &v2, tmp + sizeof( T ) + sizeof( U ), sizeof( V ) );
            memcpy( &v3, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ), sizeof( W ) );
            memcpy( &v4, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ), sizeof( X ) );
            memcpy( &v5, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ), sizeof( Y ) );
            memcpy( &v6, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ), sizeof( Z ) );
            memcpy( &v7, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ), sizeof( A ) );
            memcpy( &v8, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ), sizeof( B ) );
            memcpy( &v9, tmp + sizeof( T ) + sizeof( U ) + sizeof( V ) + sizeof( W ) + sizeof( X ) + sizeof( Y ) + sizeof( Z ) + sizeof( A ) + sizeof( B ), sizeof( C ) );
        }
    }

    const std::string& GetFilename() const { return m_filename; }

private:
    FileRead( FILE* f, const char* fn )
        : m_data( nullptr )
        , m_offset( 0 )
        , m_streamId( 0 )
        , m_filename( fn )
    {
        char hdr[4];
        if( fread( hdr, 1, sizeof( hdr ), f ) != sizeof( hdr ) )
        {
            fclose( f );
            throw NotTracyDump();
        }

        uint8_t streams = 1;
        uint8_t type;
        m_dataOffset = sizeof( hdr );

        if( memcmp( hdr, TracyHeader, sizeof( hdr ) ) == 0 )
        {
            if( fread( &type, 1, 1, f ) != 1 || type > 1 )
            {
                fclose( f );
                throw NotTracyDump();
            }
            if( fread( &streams, 1, 1, f ) != 1 )
            {
                fclose( f );
                throw NotTracyDump();
            }
            m_dataOffset += 2;
        }
        else if( memcmp( hdr, Lz4Header, sizeof( hdr ) ) == 0 )
        {
            type = 0;
        }
        else if( memcmp( hdr, ZstdHeader, sizeof( hdr ) ) == 0 )
        {
            type = 1;
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

        for( int i=0; i<(int)streams; i++ )
        {
            if( m_dataOffset == m_dataSize ) break;

            const auto sz = ReadBlockSize();
            auto uptr = std::make_unique<StreamHandle>( type );
            uptr->src = m_data + m_dataOffset;
            uptr->size = sz;
            uptr->inputReady = true;
            uptr->thread = std::thread( [ptr = uptr.get()] { Worker( ptr ); } );
            m_streams.emplace_back( std::move( uptr ) );
            m_dataOffset += sz;
       }

       GetNextDataBlock();
    }

    tracy_force_inline uint32_t ReadBlockSize()
    {
        uint32_t sz;
        memcpy( &sz, m_data + m_dataOffset, sizeof( sz ) );
        m_dataOffset += sizeof( sz );
        return sz;
    }

    static void Worker( StreamHandle* hnd )
    {
        for(;;)
        {
            std::unique_lock lock( hnd->signalLock );
            hnd->signal.wait( lock, [&] { return hnd->inputReady || hnd->exit; } );
            if( hnd->exit ) return;
            lock.unlock();

            hnd->stream.Decompress( hnd->src, hnd->size );
            hnd->inputReady = false;
            hnd->outputReady.store( true, std::memory_order_release );
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
            if( m_offset == FileBufSize )
            {
                sz = std::min<size_t>( size, FileBufSize );
                GetNextDataBlock();
                memcpy( dst, m_buf, sz );
                m_offset = sz;
            }
            else
            {
                sz = std::min( size, FileBufSize - m_offset );
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
            if( m_offset == FileBufSize ) GetNextDataBlock();
            const auto sz = std::min( size, FileBufSize - m_offset );
            m_offset += sz;
            size -= sz;
        }
    }

    void GetNextDataBlock()
    {
        auto& hnd = *m_streams[m_streamId];
        while( hnd.outputReady.load( std::memory_order_acquire ) == false ) { YieldThread(); }
        hnd.outputReady.store( false, std::memory_order_relaxed );
        m_buf = hnd.stream.GetBuffer();
        m_offset = 0;

        if( m_dataOffset < m_dataSize )
        {
            const auto sz = ReadBlockSize();
            std::unique_lock lock( hnd.signalLock );
            hnd.src = m_data + m_dataOffset;
            hnd.size = sz;
            hnd.inputReady = true;
            hnd.signal.notify_one();
            lock.unlock();
            m_dataOffset += sz;
        }

        m_streamId = ( m_streamId + 1 ) % m_streams.size();
    }

    char* m_data;
    const char* m_buf;
    uint64_t m_dataSize;
    uint64_t m_dataOffset;
    size_t m_offset;
    int m_streamId;

    std::string m_filename;

    std::vector<std::unique_ptr<StreamHandle>> m_streams;
};

}

#endif
