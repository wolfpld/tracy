#ifndef __TRACYFILEWRITE_HPP__
#define __TRACYFILEWRITE_HPP__

#ifdef _MSC_VER
#  pragma warning( disable: 4267 )  // conversion from don't care to whatever, possible loss of data 
#endif

#include <algorithm>
#include <assert.h>
#include <condition_variable>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <thread>
#include <utility>
#include <vector>

#include "TracyFileHeader.hpp"
#include "TracyFileMeta.hpp"
#include "../public/common/tracy_lz4.hpp"
#include "../public/common/tracy_lz4hc.hpp"
#include "../public/common/TracyForceInline.hpp"
#include "../zstd/zstd.h"

namespace tracy
{

enum class FileCompression
{
    Fast,
    Slow,
    Extreme,
    Zstd
};

class WriteStream
{
public:
    WriteStream( FileCompression comp, int level )
        : m_stream( nullptr )
        , m_streamHC( nullptr )
        , m_streamZstd( nullptr )
        , m_buf( new char[FileBufSize] )
        , m_second( new char[FileBufSize] )
        , m_compressed( new char[FileBoundSize] )
    {
        switch( comp )
        {
        case FileCompression::Fast:
            m_stream = LZ4_createStream();
            break;
        case FileCompression::Slow:
            m_streamHC = LZ4_createStreamHC();
            break;
        case FileCompression::Extreme:
            m_streamHC = LZ4_createStreamHC();
            LZ4_resetStreamHC( m_streamHC, LZ4HC_CLEVEL_MAX );
            break;
        case FileCompression::Zstd:
            m_streamZstd = ZSTD_createCStream();
            ZSTD_CCtx_setParameter( m_streamZstd, ZSTD_c_compressionLevel, level );
            ZSTD_CCtx_setParameter( m_streamZstd, ZSTD_c_contentSizeFlag, 0 );
            break;
        default:
            assert( false );
            break;
        }
    }

    ~WriteStream()
    {
        delete[] m_buf;
        delete[] m_second;
        delete[] m_compressed;

        if( m_stream ) LZ4_freeStream( m_stream );
        if( m_streamHC ) LZ4_freeStreamHC( m_streamHC );
        if( m_streamZstd ) ZSTD_freeCStream( m_streamZstd );
    }

    char* GetInputBuffer() { return m_buf; }
    const char* GetCompressedData() const { return m_compressed; }
    uint32_t GetSize() const { return m_size; }

    void Compress( uint32_t sz )
    {
        if( m_stream )
        {
            m_size = LZ4_compress_fast_continue( m_stream, m_buf, m_compressed, sz, FileBoundSize, 1 );
        }
        else if( m_streamZstd )
        {
            ZSTD_outBuffer out = { m_compressed, FileBoundSize, 0 };
            ZSTD_inBuffer in = { m_buf, sz, 0 };
            const auto ret = ZSTD_compressStream2( m_streamZstd, &out, &in, ZSTD_e_flush );
            assert( ret == 0 );
            m_size = out.pos;
        }
        else
        {
            m_size = LZ4_compress_HC_continue( m_streamHC, m_buf, m_compressed, sz, FileBoundSize );
        }

        std::swap( m_buf, m_second );
    }

private:
    LZ4_stream_t* m_stream;
    LZ4_streamHC_t* m_streamHC;
    ZSTD_CStream* m_streamZstd;

    char* m_buf;
    char* m_second;
    char* m_compressed;
    uint32_t m_size;
};

class FileWrite
{
    struct StreamHandle
    {
        StreamHandle( FileCompression comp, int level ) : stream( comp, level ) {}

        WriteStream stream;
        uint32_t size;

        bool inputReady = false;
        bool outputReady = false;
        bool exit = false;

        std::mutex signalLock;
        std::condition_variable signal;

        std::thread thread;
    };

public:
    static FileWrite* Open( const char* fn, FileCompression comp = FileCompression::Fast, int level = 1, int streams = -1 )
    {
        auto f = fopen( fn, "wb" );
        if( !f ) return nullptr;
        if( streams <= 0 ) streams = std::max<int>( 1, std::thread::hardware_concurrency() );
        if( streams > 255 ) streams = 255;
        return new FileWrite( f, comp, level, streams );
    }

    ~FileWrite()
    {
        Finish();
        fclose( m_file );
    }

    void Finish()
    {
        if( m_offset > 0 ) WriteBlock();
        while( m_streamPending > 0 ) ProcessPending();
        for( auto& v : m_streams )
        {
            std::lock_guard lock( v->signalLock );
            v->exit = true;
            v->signal.notify_one();
        }
        for( auto& v : m_streams ) v->thread.join();
        m_streams.clear();
    }

    tracy_force_inline void Write( const void* ptr, size_t size )
    {
        if( m_offset + size <= FileBufSize )
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
    FileWrite( FILE* f, FileCompression comp, int level, int streams )
        : m_offset( 0 )
        , m_file( f )
        , m_srcBytes( 0 )
        , m_dstBytes( 0 )
    {
        assert( streams > 0 );
        assert( streams < 256 );

        fwrite( TracyHeader, 1, sizeof( TracyHeader ), m_file );
        uint8_t u8 = comp == FileCompression::Zstd ? 1 : 0;
        fwrite( &u8, 1, 1, m_file );
        u8 = streams;
        fwrite( &u8, 1, 1, m_file );

        m_streams.reserve( streams );
        for( int i=0; i<streams; i++ )
        {
            auto uptr = std::make_unique<StreamHandle>( comp, level );
            uptr->thread = std::thread( [ptr = uptr.get()]{ Worker( ptr ); } );
            m_streams.emplace_back( std::move( uptr ) );
        }

        m_buf = m_streams[m_streamId]->stream.GetInputBuffer();
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
            const auto sz = std::min( size, FileBufSize - m_offset );
            memcpy( m_buf + m_offset, src, sz );
            m_offset += sz;
            src += sz;
            size -= sz;

            if( m_offset == FileBufSize )
            {
                WriteBlock();
            }
        }
    }

    void WriteBlock()
    {
        m_srcBytes += m_offset;

        auto& hnd = *m_streams[m_streamId];
        assert( hnd.stream.GetInputBuffer() == m_buf );

        std::unique_lock lock( hnd.signalLock );
        hnd.inputReady = true;
        hnd.size = m_offset;
        hnd.signal.notify_one();
        lock.unlock();

        m_streamPending++;
        m_streamId = ( m_streamId + 1 ) % m_streams.size();
        if( m_streamPending == m_streams.size() ) ProcessPending();

        m_offset = 0;
        m_buf = m_streams[m_streamId]->stream.GetInputBuffer();
    }

    void ProcessPending()
    {
        assert( m_streamPending > 0 );
        int id = ( m_streamId + m_streams.size() - m_streamPending ) % m_streams.size();
        m_streamPending--;
        auto& hnd = *m_streams[id];

        std::unique_lock lock( hnd.signalLock );
        hnd.signal.wait( lock, [&hnd]{ return hnd.outputReady; } );
        lock.unlock();

        hnd.outputReady = false;
        const uint32_t size = hnd.stream.GetSize();
        m_dstBytes += size;
        fwrite( &size, 1, sizeof( size ), m_file );
        fwrite( hnd.stream.GetCompressedData(), 1, size, m_file );
    }

    static void Worker( StreamHandle* hnd )
    {
        std::unique_lock lock( hnd->signalLock );
        for(;;)
        {
            hnd->signal.wait( lock, [&hnd]{ return hnd->inputReady || hnd->exit; } );
            if( hnd->exit ) return;
            lock.unlock();

            hnd->stream.Compress( hnd->size );
            hnd->inputReady = false;

            lock.lock();
            hnd->outputReady = true;
            hnd->signal.notify_one();
        }
    }

    char* m_buf;
    size_t m_offset;

    int m_streamId = 0;
    int m_streamPending = 0;
    std::vector<std::unique_ptr<StreamHandle>> m_streams;
    FILE* m_file;

    size_t m_srcBytes;
    size_t m_dstBytes;
};

}

#endif
