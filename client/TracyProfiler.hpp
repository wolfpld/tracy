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

#if defined _MSC_VER || defined __CYGWIN__ || defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
#  define TRACY_RDTSCP_SUPPORTED
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

extern thread_local moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* s_token;

using Magic = moodycamel::ConcurrentQueueDefaultTraits::index_t;

class Profiler
{
public:
    Profiler();
    ~Profiler();

#ifdef TRACY_RDTSCP_SUPPORTED
    static tracy_force_inline int64_t tracy_rdtscp( uint32_t& cpu )
    {
#if defined _MSC_VER || defined __CYGWIN__
        const auto t = int64_t( __rdtscp( &cpu ) );
        return t;
#elif defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
        uint64_t eax, edx;
        asm volatile ( "rdtscp" : "=a" (eax), "=d" (edx), "=c" (cpu) :: );
        return ( edx << 32 ) + eax;
#endif
    }
#endif

    static tracy_force_inline int64_t GetTime( uint32_t& cpu )
    {
#ifdef TRACY_RDTSCP_SUPPORTED
        return tracy_rdtscp( cpu );
#else
        cpu = 0xFFFFFFFF;
        return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
#endif
    }

    static tracy_force_inline void FrameMark()
    {
        uint32_t cpu;
        Magic magic;
        auto& token = s_token;
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::FrameMarkMsg;
        item->frameMark.time = GetTime( cpu );
        token->enqueue_finish( magic );
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
    uint64_t m_epoch;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::unique_ptr<Socket> m_sock;

    LZ4_stream_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;
};

};

#endif
