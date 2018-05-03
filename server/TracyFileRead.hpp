#ifndef __TRACYFILEREAD_HPP__
#define __TRACYFILEREAD_HPP__

#include <atomic>
#include <algorithm>
#include <stdexcept>
#include <stdio.h>
#include <string.h>
#include <thread>

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
        m_exit.store( true, std::memory_order_relaxed );
        m_decThread.join();

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

    template<class T>
    tracy_force_inline void Read2( T& v0, T& v1 )
    {
        if( sizeof( T ) * 2 < BufSize - m_offset )
        {
            memcpy( &v0, m_buf + m_offset, sizeof( T ) );
            memcpy( &v1, m_buf + m_offset + sizeof( T ), sizeof( T ) );
            m_offset += sizeof( T ) * 2;
        }
        else
        {
            T tmp[2];
            ReadBig( tmp, sizeof( T ) * 2 );
            memcpy( &v0, tmp, sizeof( T ) );
            memcpy( &v1, tmp+1, sizeof( T ) );
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
        , m_buf( m_bufData[1] )
        , m_second( m_bufData[0] )
        , m_offset( 0 )
        , m_lastBlock( 0 )
        , m_signalSwitch( false )
        , m_signalAvailable( false )
        , m_exit( false )
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
                while( m_signalAvailable.load( std::memory_order_acquire ) == false ) {}
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
                while( m_signalAvailable.load( std::memory_order_acquire ) == false ) {}
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
            m_lastBlock = LZ4_decompress_safe_continue( m_stream, m_lz4buf, m_second, sz, BufSize );
        }
        else
        {
            m_lastBlock = 0;
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

    std::atomic<bool> m_signalSwitch;
    std::atomic<bool> m_signalAvailable;
    std::atomic<bool> m_exit;

    std::thread m_decThread;
};

}

#endif
