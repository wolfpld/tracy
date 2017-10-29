#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <chrono>
#include <stdint.h>
#include <string.h>

#include "concurrentqueue.h"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyQueue.hpp"
#include "../common/TracyAlloc.hpp"

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

struct ProducerWrapper
{
    moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptr;
};

extern thread_local ProducerWrapper s_token;

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
        uint32_t eax, edx;
        asm volatile ( "rdtscp" : "=a" (eax), "=d" (edx), "=c" (cpu) :: );
        return ( uint64_t( edx ) << 32 ) + uint64_t( eax );
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
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::FrameMarkMsg;
        item->frameMark.time = GetTime( cpu );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, int64_t val )
    {
        uint32_t cpu;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::PlotData;
        item->plotData.name = (uint64_t)name;
        item->plotData.time = GetTime( cpu );
        item->plotData.type = PlotDataType::Int;
        item->plotData.data.i = val;
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, float val )
    {
        uint32_t cpu;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::PlotData;
        item->plotData.name = (uint64_t)name;
        item->plotData.time = GetTime( cpu );
        item->plotData.type = PlotDataType::Float;
        item->plotData.data.f = val;
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, double val )
    {
        uint32_t cpu;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::PlotData;
        item->plotData.name = (uint64_t)name;
        item->plotData.time = GetTime( cpu );
        item->plotData.type = PlotDataType::Double;
        item->plotData.data.d = val;
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void Message( const char* txt, size_t size )
    {
        uint32_t cpu;
        Magic magic;
        auto& token = s_token.ptr;
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::Message;
        item->message.time = GetTime( cpu );
        item->message.thread = GetThreadHandle();
        item->message.text = (uint64_t)ptr;
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void Message( const char* txt )
    {
        uint32_t cpu;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::MessageLiteral;
        item->message.time = GetTime( cpu );
        item->message.thread = GetThreadHandle();
        item->message.text = (uint64_t)txt;
        tail.store( magic + 1, std::memory_order_release );
    }

    static bool ShouldExit();

private:
    enum DequeueStatus { Success, ConnectionLost, QueueEmpty };

    static void LaunchWorker( void* ptr ) { ((Profiler*)ptr)->Worker(); }
    void Worker();

    DequeueStatus Dequeue( moodycamel::ConsumerToken& token );

    bool SendData( const char* data, size_t len );
    bool SendString( uint64_t ptr, const char* str, QueueType type );
    void SendSourceLocation( uint64_t ptr );

    bool HandleServerQuery();

    void CalibrateTimer();
    void CalibrateDelay();

    double m_timerMul;
    uint64_t m_resolution;
    uint64_t m_delay;
    std::atomic<int64_t> m_timeBegin;
    uint64_t m_mainThread;
    uint64_t m_epoch;
    std::atomic<bool> m_shutdown;
    Socket* m_sock;

    LZ4_stream_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;
};

};

#endif
