#ifndef __TRACYOPENGL_HPP__
#define __TRACYOPENGL_HPP__

// Include this file after you include OpenGL 3.2 headers.

#if !defined TRACY_ENABLE || defined __APPLE__

#define TracyGpuContext
#define TracyGpuZone(x)
#define TracyGpuZoneC(x,y)
#define TracyGpuCollect
#define TracyGpuZoneS(x,y)
#define TracyGpuZoneCS(x,y,z)

#else

#include <atomic>
#include <assert.h>
#include <stdlib.h>

#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyCallstack.hpp"
#include "common/TracyAlign.hpp"
#include "common/TracyAlloc.hpp"

#define TracyGpuContext tracy::s_gpuCtx.ptr = (tracy::GpuCtx*)tracy::tracy_malloc( sizeof( tracy::GpuCtx ) ); new(tracy::s_gpuCtx.ptr) tracy::GpuCtx;
#define TracyGpuZone( name ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::GpuCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location );
#define TracyGpuZoneC( name, color ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::GpuCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location );
#define TracyGpuCollect tracy::s_gpuCtx.ptr->Collect();

#ifdef TRACY_HAS_CALLSTACK
#  define TracyGpuZoneS( name, depth ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::GpuCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, depth );
#  define TracyGpuZoneCS( name, color, depth ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::GpuCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, depth );
#else
#  define TracyGpuZoneS( name, depth ) TracyGpuZone( name )
#  define TracyGpuZoneCS( name, color, depth ) TracyGpuZoneC( name, color )
#endif

namespace tracy
{

extern std::atomic<uint8_t> s_gpuCtxCounter;

class GpuCtx
{
    friend class GpuCtxScope;

    enum { QueryCount = 64 * 1024 };

public:
    GpuCtx()
        : m_context( s_gpuCtxCounter.fetch_add( 1, std::memory_order_relaxed ) )
        , m_head( 0 )
        , m_tail( 0 )
    {
        assert( m_context != 255 );

        glGenQueries( QueryCount, m_query );

        int64_t tgpu;
        glGetInteger64v( GL_TIMESTAMP, &tgpu );
        int64_t tcpu = Profiler::GetTime();

        GLint bits;
        glGetQueryiv( GL_TIMESTAMP, GL_QUERY_COUNTER_BITS, &bits );

        const float period = 1.f;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuNewContext );
        MemWrite( &item->gpuNewContext.cpuTime, tcpu );
        MemWrite( &item->gpuNewContext.gpuTime, tgpu );
        MemWrite( &item->gpuNewContext.thread, GetThreadHandle() );
        MemWrite( &item->gpuNewContext.period, period );
        MemWrite( &item->gpuNewContext.context, m_context );
        MemWrite( &item->gpuNewContext.accuracyBits, (uint8_t)bits );

#ifdef TRACY_ON_DEMAND
        s_profiler.DeferItem( *item );
#endif

        tail.store( magic + 1, std::memory_order_release );
    }

    void Collect()
    {
        ZoneScopedC( Color::Red4 );

        if( m_tail == m_head ) return;

#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() )
        {
            m_head = m_tail = 0;
            return;
        }
#endif

        auto start = m_tail;
        auto end = m_head + QueryCount;
        auto cnt = ( end - start ) % QueryCount;
        while( cnt > 1 )
        {
            auto mid = start + cnt / 2;
            GLint available;
            glGetQueryObjectiv( m_query[mid % QueryCount], GL_QUERY_RESULT_AVAILABLE, &available );
            if( available )
            {
                start = mid;
            }
            else
            {
                end = mid;
            }
            cnt = ( end - start ) % QueryCount;
        }

        start %= QueryCount;

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();

        while( m_tail != start )
        {
            uint64_t time;
            glGetQueryObjectui64v( m_query[m_tail], GL_QUERY_RESULT, &time );

            auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::GpuTime );
            MemWrite( &item->gpuTime.gpuTime, (int64_t)time );
            MemWrite( &item->gpuTime.queryId, (uint16_t)m_tail );
            MemWrite( &item->gpuTime.context, m_context );
            tail.store( magic + 1, std::memory_order_release );
            m_tail = ( m_tail + 1 ) % QueryCount;
        }
    }

private:
    tracy_force_inline unsigned int NextQueryId()
    {
        const auto id = m_head;
        m_head = ( m_head + 1 ) % QueryCount;
        assert( m_head != m_tail );
        return id;
    }

    tracy_force_inline unsigned int TranslateOpenGlQueryId( unsigned int id )
    {
        return m_query[id];
    }

    tracy_force_inline uint8_t GetId() const
    {
        return m_context;
    }

    unsigned int m_query[QueryCount];
    uint8_t m_context;

    unsigned int m_head;
    unsigned int m_tail;
};

extern thread_local GpuCtxWrapper s_gpuCtx;

class GpuCtxScope
{
public:
    tracy_force_inline GpuCtxScope( const SourceLocation* srcloc )
#ifdef TRACY_ON_DEMAND
        : m_active( s_profiler.IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto queryId = s_gpuCtx.ptr->NextQueryId();
        glQueryCounter( s_gpuCtx.ptr->TranslateOpenGlQueryId( queryId ), GL_TIMESTAMP );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBegin );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        memset( &item->gpuZoneBegin.thread, 0, sizeof( item->gpuZoneBegin.thread ) );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, s_gpuCtx.ptr->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline GpuCtxScope( const SourceLocation* srcloc, int depth )
#ifdef TRACY_ON_DEMAND
        : m_active( s_profiler.IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto queryId = s_gpuCtx.ptr->NextQueryId();
        glQueryCounter( s_gpuCtx.ptr->TranslateOpenGlQueryId( queryId ), GL_TIMESTAMP );

        const auto thread = GetThreadHandle();

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginCallstack );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, thread );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, s_gpuCtx.ptr->GetId() );
        tail.store( magic + 1, std::memory_order_release );

        s_profiler.SendCallstack( depth, thread );
    }

    tracy_force_inline ~GpuCtxScope()
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto queryId = s_gpuCtx.ptr->NextQueryId();
        glQueryCounter( s_gpuCtx.ptr->TranslateOpenGlQueryId( queryId ), GL_TIMESTAMP );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneEnd );
        MemWrite( &item->gpuZoneEnd.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneEnd.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneEnd.context, s_gpuCtx.ptr->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

private:
#ifdef TRACY_ON_DEMAND
    const bool m_active;
#endif
};

}

#endif

#endif
