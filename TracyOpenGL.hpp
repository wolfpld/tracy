#ifndef __TRACYOPENGL_HPP__
#define __TRACYOPENGL_HPP__

#ifndef TRACY_ENABLE

#define TracyGpuZone(x,y)
#define TracyGpuZoneC(x,y,z)

namespace tracy
{

template<int>
class GpuCtx
{
public:
    void Collect() {}
};

}

#else

#include <atomic>

#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"

#define TracyGpuZone( ctx, name ) static const tracy::SourceLocation __tracy_gpu_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; auto ___tracy_gpu_zone = tracy::detail::__GpuHelper( ctx, name, &__tracy_gpu_source_location );
#define TracyGpuZoneC( ctx, name, color ) static const tracy::SourceLocation __tracy_gpu_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; auto ___tracy_gpu_zone = tracy::detail::__GpuHelper( ctx, name, &__tracy_gpu_source_location );

namespace tracy
{

extern std::atomic<uint16_t> s_gpuCtxCounter;

template<int Num> class GpuCtx;

template<int Num>
class __GpuCtxScope
{
public:
    tracy_force_inline __GpuCtxScope( GpuCtx<Num>& ctx, const char* name, const SourceLocation* srcloc )
        : m_ctx( ctx )
    {
        glQueryCounter( m_ctx.NextQueryId(), GL_TIMESTAMP );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::GpuZoneBegin;
        item->gpuZoneBegin.cpuTime = Profiler::GetTime();
        item->gpuZoneBegin.name = (uint64_t)name;
        item->gpuZoneBegin.srcloc = (uint64_t)srcloc;
        item->gpuZoneBegin.context = m_ctx.GetId();
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline ~__GpuCtxScope()
    {
        glQueryCounter( m_ctx.NextQueryId(), GL_TIMESTAMP );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::GpuZoneEnd;
        item->gpuZoneEnd.cpuTime = Profiler::GetTime();
        item->gpuZoneEnd.thread = GetThreadHandle();
        item->gpuZoneEnd.context = m_ctx.GetId();
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    GpuCtx<Num>& m_ctx;
};

namespace detail
{
template<int Num>
static tracy_force_inline __GpuCtxScope<Num> __GpuHelper( GpuCtx<Num>* ctx, const char* name, const SourceLocation* srcloc )
{
    return ctx->SpawnZone( name, srcloc );
}
}

template<int Num>
class GpuCtx
{
    friend class __GpuCtxScope<Num>;
    friend __GpuCtxScope<Num> detail::__GpuHelper<Num>( GpuCtx<Num>* ctx, const char* name, const SourceLocation* srcloc );

public:
    GpuCtx()
        : m_context( s_gpuCtxCounter.fetch_add( 1, std::memory_order_relaxed ) )
        , m_head( 0 )
        , m_tail( 0 )
    {
        glGenQueries( Num, m_query );

        int64_t tgpu;
        glGetInteger64v( GL_TIMESTAMP, &tgpu );
        int64_t tcpu = Profiler::GetTime();

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::GpuNewContext;
        item->gpuNewContext.cputime = tcpu;
        item->gpuNewContext.gputime = tgpu;
        item->gpuNewContext.context = m_context;
        tail.store( magic + 1, std::memory_order_release );
    }

    void Collect()
    {
        ZoneScopedC( 0x881111 );

        auto start = m_tail;
        auto end = m_head + Num;
        auto cnt = ( end - start ) % Num;
        while( cnt > 1 )
        {
            auto mid = start + cnt / 2;
            GLint available;
            glGetQueryObjectiv( m_query[mid % Num], GL_QUERY_RESULT_AVAILABLE, &available );
            if( available )
            {
                start = mid;
            }
            else
            {
                end = mid;
            }
            cnt = ( end - start ) % Num;
        }

        start %= Num;

        while( m_tail != start )
        {
            uint64_t time;
            glGetQueryObjectui64v( m_query[m_tail], GL_QUERY_RESULT, &time );

            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::GpuTime;
            item->gpuTime.gpuTime = (int64_t)time;
            item->gpuTime.context = m_context;
            tail.store( magic + 1, std::memory_order_release );
            m_tail = ( m_tail + 1 ) % Num;
        }
    }

private:
    tracy_force_inline __GpuCtxScope<Num> SpawnZone( const char* name, const SourceLocation* srcloc )
    {
        return __GpuCtxScope<Num>( *this, name, srcloc );
    }

    tracy_force_inline unsigned int NextQueryId()
    {
        const auto id = m_head;
        m_head = ( m_head + 1 ) % Num;
        assert( m_head != m_tail );
        return m_query[id];
    }

    tracy_force_inline uint16_t GetId() const
    {
        return m_context;
    }

    unsigned int m_query[Num];
    uint16_t m_context;

    unsigned int m_head;
    unsigned int m_tail;
};

}

#endif

#endif
