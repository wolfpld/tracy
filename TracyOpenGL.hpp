#ifndef __TRACYOPENGL_HPP__
#define __TRACYOPENGL_HPP__

#ifdef TRACY_ENABLE

#include <atomic>

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

private:
    tracy_force_inline __GpuCtxScope<Num> SpawnZone( const char* name, const SourceLocation* srcloc )
    {
        return __GpuCtxScope<Num>( *this, name, srcloc );
    }

    tracy_force_inline unsigned int NextQueryId()
    {
        const auto id = m_head;
        m_head = ( m_head + 1 ) % Num;
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
