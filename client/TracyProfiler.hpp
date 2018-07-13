#ifndef __TRACYPROFILER_HPP__
#define __TRACYPROFILER_HPP__

#include <atomic>
#include <chrono>
#include <stdint.h>
#include <string.h>

#include "concurrentqueue.h"
#include "TracyCallstack.hpp"
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

#if defined _MSC_VER || defined __CYGWIN__ || ( ( defined __i386 || defined _M_IX86 || defined __x86_64__ || defined _M_X64 ) && !defined __ANDROID__ ) || __ARM_ARCH >= 6
#  define TRACY_HW_TIMER
#  if defined _MSC_VER || defined __CYGWIN__
     // Enable optimization for MSVC __rdtscp() intrin, saving one LHS of a cpu value on the stack.
     // This comes at the cost of an unaligned memory write.
#    define TRACY_RDTSCP_OPT
#  endif
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
    tracy::moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* ptr;
};

extern thread_local ProducerWrapper s_token;

class GpuCtx;
struct GpuCtxWrapper
{
    GpuCtx* ptr;
};

class VkCtx;
struct VkCtxWrapper
{
    VkCtx* ptr;
};

#ifdef TRACY_ON_DEMAND
struct LuaZoneState
{
    uint32_t counter;
    bool active;
};
#endif

using Magic = tracy::moodycamel::ConcurrentQueueDefaultTraits::index_t;

#if __ARM_ARCH >= 6
extern int64_t (*GetTimeImpl)();
#endif

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
#  if __ARM_ARCH >= 6
        cpu = 0xFFFFFFFF;
        return GetTimeImpl();
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
#  if __ARM_ARCH >= 6
        return GetTimeImpl();
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

    static tracy_force_inline void SendFrameMark()
    {
#ifdef TRACY_ON_DEMAND
        s_profiler.m_frameCount.fetch_add( 1, std::memory_order_relaxed );
        if( !s_profiler.IsConnected() ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::FrameMarkMsg );
        MemWrite( &item->frameMark.time, GetTime() );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, int64_t val )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::PlotData );
        MemWrite( &item->plotData.name, (uint64_t)name );
        MemWrite( &item->plotData.time, GetTime() );
        MemWrite( &item->plotData.type, PlotDataType::Int );
        MemWrite( &item->plotData.data.i, val );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, float val )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::PlotData );
        MemWrite( &item->plotData.name, (uint64_t)name );
        MemWrite( &item->plotData.time, GetTime() );
        MemWrite( &item->plotData.type, PlotDataType::Float );
        MemWrite( &item->plotData.data.f, val );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void PlotData( const char* name, double val )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::PlotData );
        MemWrite( &item->plotData.name, (uint64_t)name );
        MemWrite( &item->plotData.time, GetTime() );
        MemWrite( &item->plotData.type, PlotDataType::Double );
        MemWrite( &item->plotData.data.d, val );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void Message( const char* txt, size_t size )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::Message );
        MemWrite( &item->message.time, GetTime() );
        MemWrite( &item->message.thread, GetThreadHandle() );
        MemWrite( &item->message.text, (uint64_t)ptr );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void Message( const char* txt )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::MessageLiteral );
        MemWrite( &item->message.time, GetTime() );
        MemWrite( &item->message.thread, GetThreadHandle() );
        MemWrite( &item->message.text, (uint64_t)txt );
        tail.store( magic + 1, std::memory_order_release );
    }

    static tracy_force_inline void MemAlloc( const void* ptr, size_t size )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        const auto thread = GetThreadHandle();

        s_profiler.m_serialLock.lock();
        SendMemAlloc( QueueType::MemAlloc, thread, ptr, size );
        s_profiler.m_serialLock.unlock();
    }

    static tracy_force_inline void MemFree( const void* ptr )
    {
#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#endif
        const auto thread = GetThreadHandle();

        s_profiler.m_serialLock.lock();
        SendMemFree( QueueType::MemFree, thread, ptr );
        s_profiler.m_serialLock.unlock();
    }

    static tracy_force_inline void MemAllocCallstack( const void* ptr, size_t size, int depth )
    {
#ifdef TRACY_HAS_CALLSTACK
#  ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#  endif
        const auto thread = GetThreadHandle();

        rpmalloc_thread_initialize();
        auto callstack = Callstack( depth );

        s_profiler.m_serialLock.lock();
        SendMemAlloc( QueueType::MemAllocCallstack, thread, ptr, size );
        SendCallstackMemory( callstack );
        s_profiler.m_serialLock.unlock();
#else
        MemAlloc( ptr, size );
#endif
    }

    static tracy_force_inline void MemFreeCallstack( const void* ptr, int depth )
    {
#ifdef TRACY_HAS_CALLSTACK
#  ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() ) return;
#  endif
        const auto thread = GetThreadHandle();

        rpmalloc_thread_initialize();
        auto callstack = Callstack( depth );

        s_profiler.m_serialLock.lock();
        SendMemFree( QueueType::MemFreeCallstack, thread, ptr );
        SendCallstackMemory( callstack );
        s_profiler.m_serialLock.unlock();
#else
        MemFree( ptr );
#endif
    }

    static tracy_force_inline void SendCallstack( int depth, uint64_t thread )
    {
#ifdef TRACY_HAS_CALLSTACK
        auto ptr = Callstack( depth );
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::Callstack );
        MemWrite( &item->callstack.ptr, ptr );
        MemWrite( &item->callstack.thread, thread );
        tail.store( magic + 1, std::memory_order_release );
#endif
    }

    static bool ShouldExit();

#ifdef TRACY_ON_DEMAND
    tracy_force_inline bool IsConnected()
    {
        return m_isConnected.load( std::memory_order_relaxed );
    }

    tracy_force_inline void DeferItem( const QueueItem& item )
    {
        m_deferredLock.lock();
        auto dst = m_deferredQueue.push_next();
        memcpy( dst, &item, sizeof( item ) );
        m_deferredLock.unlock();
    }
#endif

private:
    enum DequeueStatus { Success, ConnectionLost, QueueEmpty };

    static void LaunchWorker( void* ptr ) { ((Profiler*)ptr)->Worker(); }
    void Worker();

    void ClearQueues( tracy::moodycamel::ConsumerToken& token );
    DequeueStatus Dequeue( tracy::moodycamel::ConsumerToken& token );
    DequeueStatus DequeueSerial();
    bool AppendData( const void* data, size_t len );
    bool CommitData();
    bool NeedDataSize( size_t len );

    tracy_force_inline void AppendDataUnsafe( const void* data, size_t len )
    {
        memcpy( m_buffer + m_bufferOffset, data, len );
        m_bufferOffset += int( len );
    }

    bool SendData( const char* data, size_t len );
    void SendString( uint64_t ptr, const char* str, QueueType type );
    void SendSourceLocation( uint64_t ptr );
    void SendSourceLocationPayload( uint64_t ptr );
    void SendCallstackPayload( uint64_t ptr );
    void SendCallstackFrame( uint64_t ptr );

    bool HandleServerQuery();

    void CalibrateTimer();
    void CalibrateDelay();

    static tracy_force_inline void SendCallstackMemory( void* ptr )
    {
#ifdef TRACY_HAS_CALLSTACK
        auto item = s_profiler.m_serialQueue.push_next();
        MemWrite( &item->hdr.type, QueueType::CallstackMemory );
        MemWrite( &item->callstackMemory.ptr, (uint64_t)ptr );
#endif
    }

    static tracy_force_inline void SendMemAlloc( QueueType type, const uint64_t thread, const void* ptr, size_t size )
    {
        assert( type == QueueType::MemAlloc || type == QueueType::MemAllocCallstack );

        auto item = s_profiler.m_serialQueue.push_next();
        MemWrite( &item->hdr.type, type );
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
    }

    static tracy_force_inline void SendMemFree( QueueType type, const uint64_t thread, const void* ptr )
    {
        assert( type == QueueType::MemFree || type == QueueType::MemFreeCallstack );

        auto item = s_profiler.m_serialQueue.push_next();
        MemWrite( &item->hdr.type, type );
        MemWrite( &item->memFree.time, GetTime() );
        MemWrite( &item->memFree.thread, thread );
        MemWrite( &item->memFree.ptr, (uint64_t)ptr );
    }

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

#ifdef TRACY_ON_DEMAND
    std::atomic<bool> m_isConnected;
    std::atomic<uint64_t> m_frameCount;

    NonRecursiveBenaphore m_deferredLock;
    FastVector<QueueItem> m_deferredQueue;
#endif
};

};

#endif
