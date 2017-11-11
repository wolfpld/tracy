#ifndef __TRACYOPENGL_HPP__
#define __TRACYOPENGL_HPP__

#ifdef TRACY_ENABLE

#include <atomic>

#include "client/TracyProfiler.hpp"

namespace tracy
{

extern std::atomic<uint16_t> s_gpuCtxCounter;

template<int Num>
class GpuCtx
{
public:
    GpuCtx()
        : m_context( s_gpuCtxCounter.fetch_add( 1, std::memory_order_relaxed ) )
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
    unsigned int m_query[Num];
    uint16_t m_context;
};

}

#endif

#endif
