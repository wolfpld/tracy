#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <chrono>
#include <stdint.h>
#include <thread>

#include "concurrentqueue.h"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyQueue.hpp"

#if defined _MSC_VER || defined __CYGWIN__
#  include <intrin.h>
#endif

namespace tracy
{

class Socket;

struct SourceLocation
{
    const char* function;
    const char* file;
    uint32_t line;
    uint32_t color;
};

extern moodycamel::ConcurrentQueue<QueueItem> s_queue;
extern thread_local moodycamel::ProducerToken s_token;;
extern std::atomic<uint64_t> s_id;

using Magic = moodycamel::ConcurrentQueueDefaultTraits::index_t;

class Profiler
{
public:
    Profiler();
    ~Profiler();

    static int64_t GetTime( int8_t& cpu )
    {
#if defined _MSC_VER || defined __CYGWIN__
        unsigned int ui;
        const auto t = int64_t( __rdtscp( &ui ) );
        cpu = (int8_t)ui;
        return t;
#else
        cpu = -1;
        return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
#endif
    }

    static QueueItem* StartItem( Magic& magic ) { return s_queue.enqueue_begin( s_token, magic ); }
    static void FinishItem( Magic magic ) { s_queue.enqueue_finish( s_token, magic ); }
    static uint64_t GetNewId() { return s_id.fetch_add( 1, std::memory_order_relaxed ); }

    static void FrameMark()
    {
        int8_t cpu;
        Magic magic;
        auto item = s_queue.enqueue_begin( s_token, magic );
        item->hdr.type = QueueType::FrameMarkMsg;
        item->hdr.id = (uint64_t)GetTime( cpu );
        s_queue.enqueue_finish( s_token, magic );
    }

    static bool ShouldExit();

private:
    void Worker();

    bool SendData( const char* data, size_t len );
    bool SendString( uint64_t ptr, const char* str, QueueType type );
    void SendSourceLocation( uint64_t ptr );

    bool HandleServerQuery();

    void CalibrateTimer();
    void CalibrateDelay();

    double m_timerMul;
    uint64_t m_resolution;
    uint64_t m_delay;
    int64_t m_timeBegin;
    uint64_t m_mainThread;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::unique_ptr<Socket> m_sock;

    LZ4_stream_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;
};

};

#endif
