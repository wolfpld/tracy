#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <chrono>
#include <stdint.h>
#include <string.h>

#include "concurrentqueue.h"
#include "TracyFastVector.hpp"
#include "../common/tracy_lz4.hpp"
#include "../common/tracy_benaphore.h"
#include "../common/TracyQueue.hpp"
#include "../common/TracyAlign.hpp"
#include "../common/TracyAlloc.hpp"
#include "../common/TracySystem.hpp"

#if defined _MSC_VER || defined __CYGWIN__
#  include <intrin.h>
#endif

#if defined _MSC_VER || defined __CYGWIN__ || ( ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 ) && !defined __ANDROID__ )
#  define TRACY_HW_TIMER
#endif

#if defined __aarch64__ || __ARM_ARCH >= 6
#  define TRACY_HW_TIMER
#endif

namespace tracy
{

class Socket;

struct SourceLocation
{
    const char* name;
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

class GpuCtx;
struct GpuCtxWrapper
{
    GpuCtx* ptr;
};

using Magic = moodycamel::ConcurrentQueueDefaultTraits::index_t;

class Profiler;
extern Profiler s_profiler;

class Profiler
{
public:
    Profiler();
    ~Profiler();

    static tracy_force_inline int64_t GetTime( uint32_t& cpu )
    {
#ifdef TRACY_HW_TIMER
#  if defined __aarch64__
        int64_t t;
        cpu = 0xFFFFFFFF;
        asm volatile ( "mrs %0, cntvct_el0" : "=r" (t) );
        return t;
#  elif __ARM_ARCH >= 6
        int64_t t;
        cpu = 0xFFFFFFFF;
        asm volatile ( "mrrc p15, 1, %Q0, %R0, c14" : "=r" (t) );
        return t;
#  elif defined _MSC_VER || defined __CYGWIN__
        const auto t = int64_t( __rdtscp( &cpu ) );
        return t;
#  elif defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
        uint32_t eax, edx;
        asm volatile ( "rdtscp" : "=a" (eax), "=d" (edx), "=c" (cpu) :: );
        return ( uint64_t( edx ) << 32 ) + uint64_t( eax );
#  endif
#else
        cpu = 0xFFFFFFFF;
        return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
#endif
    }

    static tracy_force_inline int64_t GetTime()
    {
#ifdef TRACY_HW_TIMER
#  if defined __aarch64__
        int64_t t;
        asm volatile ( "mrs %0, cntvct_el0" : "=r" (t) );
        return t;
#  elif __ARM_ARCH >= 6
        int64_t t;
        asm volatile ( "mrrc p15, 1, %Q0, %R0, c14" : "=r" (t) );
        return t;
#  elif defined _MSC_VER || defined __CYGWIN__
        unsigned int dontcare;
        const auto t = int64_t( __rdtscp( &dontcare ) );
        return t;
#  elif defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64
        uint32_t eax, edx;
        asm volatile ( "rdtscp" : "=a" (eax), "=d" (edx) :: "%ecx" );
        return ( uint64_t( edx ) << 32 ) + uint64_t( eax );
#  endif
#else
        return std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
#endif
    }

    static tracy_force_inline void FrameMark()
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::FrameMarkMsg );
        MemWrite( &item->frameMark.time, GetTime() );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, int64_t val )
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::PlotData );
        MemWrite( &item->plotData.name, (uint64_t)name );
        MemWrite( &item->plotData.time, GetTime() );
        MemWrite( &item->plotData.type, PlotDataType::Int );
        MemWrite( &item->plotData.data.i, val );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, float val )
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::PlotData );
        MemWrite( &item->plotData.name, (uint64_t)name );
        MemWrite( &item->plotData.time, GetTime() );
        MemWrite( &item->plotData.type, PlotDataType::Float );
        MemWrite( &item->plotData.data.f, val );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, double val )
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::PlotData );
        MemWrite( &item->plotData.name, (uint64_t)name );
        MemWrite( &item->plotData.time, GetTime() );
        MemWrite( &item->plotData.type, PlotDataType::Double );
        MemWrite( &item->plotData.data.d, val );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void Message( const char* txt, size_t size )
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::Message );
        MemWrite( &item->message.time, GetTime() );
        MemWrite( &item->message.thread, GetThreadHandle() );
        MemWrite( &item->message.text, (uint64_t)ptr );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void Message( const char* txt )
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::MessageLiteral );
        MemWrite( &item->message.time, GetTime() );
        MemWrite( &item->message.thread, GetThreadHandle() );
        MemWrite( &item->message.text, (uint64_t)txt );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void MemAlloc( const void* ptr, size_t size )
    {
        const auto thread = GetThreadHandle();

        s_profiler.m_serialLock.lock();
        auto item = s_profiler.m_serialQueue.push_next();
        MemWrite( &item->hdr.type, QueueType::MemAlloc );
        MemWrite( &item->memAlloc.time, GetTime() );
        MemWrite( &item->memAlloc.thread, thread );
        MemWrite( &item->memAlloc.ptr, (uint64_t)ptr );
        if( sizeof( size ) == 4 )
        {
            memcpy( &item->memAlloc.size, &size, 4 );
            memset( &item->memAlloc.size + 4, 0, 2 );
        }
        else
        {
            assert( sizeof( size ) == 8 );
            memcpy( &item->memAlloc.size, &size, 6 );
        }
        s_profiler.m_serialLock.unlock();
    }

    static tracy_force_inline void MemFree( const void* ptr )
    {
        const auto thread = GetThreadHandle();

        s_profiler.m_serialLock.lock();
        auto item = s_profiler.m_serialQueue.push_next();
        MemWrite( &item->hdr.type, QueueType::MemFree );
        MemWrite( &item->memFree.time, GetTime() );
        MemWrite( &item->memFree.thread, thread );
        MemWrite( &item->memFree.ptr, (uint64_t)ptr );
        s_profiler.m_serialLock.unlock();
    }

    static bool ShouldExit();

private:
    enum DequeueStatus { Success, ConnectionLost, QueueEmpty };

    static void LaunchWorker( void* ptr ) { ((Profiler*)ptr)->Worker(); }
    void Worker();

    DequeueStatus Dequeue( moodycamel::ConsumerToken& token );
    DequeueStatus DequeueSerial();
    bool AppendData( const void* data, size_t len );
    bool CommitData();
    bool NeedDataSize( size_t len );

    bool SendData( const char* data, size_t len );
    bool SendString( uint64_t ptr, const char* str, QueueType type );
    void SendSourceLocation( uint64_t ptr );
    bool SendSourceLocationPayload( uint64_t ptr );

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
    int m_bufferStart;

    QueueItem* m_itemBuf;
    char* m_lz4Buf;

    FastVector<QueueItem> m_serialQueue, m_serialDequeue;
    NonRecursiveBenaphore m_serialLock;
};

};

#endif
