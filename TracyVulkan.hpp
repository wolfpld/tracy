#ifndef __TRACYVULKAN_HPP__
#define __TRACYVULKAN_HPP__

#if !defined TRACY_ENABLE

#define TracyVkContext(x,y,z,w)
#define TracyVkDestroy
#define TracyVkZone(x,y)
#define TracyVkZoneC(x,y,z)
#define TracyVkCollect(x)
#define TracyVkZoneS(x,y,z)
#define TracyVkZoneCS(x,y,z,w)

#else

#include <assert.h>
#include <stdlib.h>
#include <vulkan/vulkan.h>
#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyCallstack.hpp"

#define TracyVkContext( physdev, device, queue, cmdbuf ) tracy::s_vkCtx.ptr = (tracy::VkCtx*)tracy::tracy_malloc( sizeof( tracy::VkCtx ) ); new(tracy::s_vkCtx.ptr) tracy::VkCtx( physdev, device, queue, cmdbuf );
#define TracyVkDestroy() tracy::s_vkCtx.ptr->~VkCtx(); tracy::tracy_free( tracy::s_vkCtx.ptr ); tracy::s_vkCtx.ptr = nullptr;
#define TracyVkZone( cmdbuf, name ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, cmdbuf );
#define TracyVkZoneC( cmdbuf, name, color ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, cmdbuf );
#define TracyVkCollect( cmdbuf ) tracy::s_vkCtx.ptr->Collect( cmdbuf );

#ifdef TRACY_HAS_CALLSTACK
#  define TracyVkZoneS( cmdbuf, name, depth ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, cmdbuf, depth );
#  define TracyVkZoneCS( cmdbuf, name, color, depth ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, cmdbuf, depth );
#else
#  define TracyVkZoneS( cmdbuf, name, depth ) TracyVkZone( cmdbuf, name )
#  define TracyVkZoneCS( cmdbuf, name, color, depth ) TracyVkZoneC( cmdbuf, name, color )
#endif

namespace tracy
{

extern std::atomic<uint8_t> s_gpuCtxCounter;

class VkCtx
{
    friend class VkCtxScope;

    enum { QueryCount = 64 * 1024 };

public:
    VkCtx( VkPhysicalDevice physdev, VkDevice device, VkQueue queue, VkCommandBuffer cmdbuf )
        : m_device( device )
        , m_queue( queue )
        , m_context( s_gpuCtxCounter.fetch_add( 1, std::memory_order_relaxed ) )
        , m_head( 0 )
        , m_tail( 0 )
        , m_oldCnt( 0 )
    {
        assert( m_context != 255 );

        VkPhysicalDeviceProperties prop;
        vkGetPhysicalDeviceProperties( physdev, &prop );
        const float period = prop.limits.timestampPeriod;

        VkQueryPoolCreateInfo poolInfo = {};
        poolInfo.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        poolInfo.queryCount = QueryCount;
        poolInfo.queryType = VK_QUERY_TYPE_TIMESTAMP;
        vkCreateQueryPool( device, &poolInfo, nullptr, &m_query );

        VkCommandBufferBeginInfo beginInfo = {};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

        VkSubmitInfo submitInfo = {};
        submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submitInfo.commandBufferCount = 1;
        submitInfo.pCommandBuffers = &cmdbuf;

        vkBeginCommandBuffer( cmdbuf, &beginInfo );
        vkCmdResetQueryPool( cmdbuf, m_query, 0, QueryCount );
        vkEndCommandBuffer( cmdbuf );
        vkQueueSubmit( queue, 1, &submitInfo, VK_NULL_HANDLE );
        vkQueueWaitIdle( queue );

        vkBeginCommandBuffer( cmdbuf, &beginInfo );
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, m_query, 0 );
        vkEndCommandBuffer( cmdbuf );
        vkQueueSubmit( queue, 1, &submitInfo, VK_NULL_HANDLE );
        vkQueueWaitIdle( queue );

        int64_t tcpu = Profiler::GetTime();
        int64_t tgpu;
        vkGetQueryPoolResults( device, m_query, 0, 1, sizeof( tgpu ), &tgpu, sizeof( tgpu ), VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT );

        vkBeginCommandBuffer( cmdbuf, &beginInfo );
        vkCmdResetQueryPool( cmdbuf, m_query, 0, 1 );
        vkEndCommandBuffer( cmdbuf );
        vkQueueSubmit( queue, 1, &submitInfo, VK_NULL_HANDLE );
        vkQueueWaitIdle( queue );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuNewContext );
        MemWrite( &item->gpuNewContext.cpuTime, tcpu );
        MemWrite( &item->gpuNewContext.gpuTime, tgpu );
        memset( &item->gpuNewContext.thread, 0, sizeof( item->gpuNewContext.thread ) );
        MemWrite( &item->gpuNewContext.period, period );
        MemWrite( &item->gpuNewContext.context, m_context );
        MemWrite( &item->gpuNewContext.accuracyBits, uint8_t( 0 ) );

#ifdef TRACY_ON_DEMAND
        s_profiler.DeferItem( *item );
#endif

        tail.store( magic + 1, std::memory_order_release );
    }

    ~VkCtx()
    {
        vkDestroyQueryPool( m_device, m_query, nullptr );
    }

    void Collect( VkCommandBuffer cmdbuf )
    {
        ZoneScopedC( Color::Red4 );

        if( m_tail == m_head ) return;

#ifdef TRACY_ON_DEMAND
        if( !s_profiler.IsConnected() )
        {
            vkCmdResetQueryPool( cmdbuf, m_query, 0, QueryCount );
            m_head = m_tail = 0;
            return;
        }
#endif

        unsigned int cnt;
        if( m_oldCnt != 0 )
        {
            cnt = m_oldCnt;
            m_oldCnt = 0;
        }
        else
        {
            cnt = m_head < m_tail ? QueryCount - m_tail : m_head - m_tail;
        }

        int64_t res[QueryCount];
        if( vkGetQueryPoolResults( m_device, m_query, m_tail, cnt, sizeof( res ), res, sizeof( *res ), VK_QUERY_RESULT_64_BIT ) == VK_NOT_READY )
        {
            m_oldCnt = cnt;
            return;
        }

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();

        for( unsigned int idx=0; idx<cnt; idx++ )
        {
            auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::GpuTime );
            MemWrite( &item->gpuTime.gpuTime, res[idx] );
            MemWrite( &item->gpuTime.queryId, uint16_t( m_tail + idx ) );
            MemWrite( &item->gpuTime.context, m_context );
            tail.store( magic + 1, std::memory_order_release );
        }

        vkCmdResetQueryPool( cmdbuf, m_query, m_tail, cnt );

        m_tail += cnt;
        if( m_tail == QueryCount ) m_tail = 0;
    }

private:
    tracy_force_inline unsigned int NextQueryId()
    {
        const auto id = m_head;
        m_head = ( m_head + 1 ) % QueryCount;
        assert( m_head != m_tail );
        return id;
    }

    tracy_force_inline uint8_t GetId() const
    {
        return m_context;
    }

    VkDevice m_device;
    VkQueue m_queue;
    VkQueryPool m_query;
    uint8_t m_context;

    unsigned int m_head;
    unsigned int m_tail;
    unsigned int m_oldCnt;
};

extern VkCtxWrapper s_vkCtx;

class VkCtxScope
{
public:
    tracy_force_inline VkCtxScope( const SourceLocation* srcloc, VkCommandBuffer cmdbuf )
        : m_cmdbuf( cmdbuf )
#ifdef TRACY_ON_DEMAND
        , m_active( s_profiler.IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        auto ctx = s_vkCtx.ptr;
        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, queryId );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBegin );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline VkCtxScope( const SourceLocation* srcloc, VkCommandBuffer cmdbuf, int depth )
        : m_cmdbuf( cmdbuf )
#ifdef TRACY_ON_DEMAND
        , m_active( s_profiler.IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto thread = GetThreadHandle();

        auto ctx = s_vkCtx.ptr;
        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, queryId );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginCallstack );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, thread );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );

        s_profiler.SendCallstack( depth, thread );
    }

    tracy_force_inline ~VkCtxScope()
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        auto ctx = s_vkCtx.ptr;
        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( m_cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, queryId );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneEnd );
        MemWrite( &item->gpuZoneEnd.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneEnd.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneEnd.context, ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    VkCommandBuffer m_cmdbuf;

#ifdef TRACY_ON_DEMAND
    const bool m_active;
#endif
};

}

#endif

#endif
