#ifndef __TRACYVULKAN_HPP__
#define __TRACYVULKAN_HPP__

#if !defined TRACY_ENABLE

#define TracyVkContext(x,y,z,w)
#define TracyVkDestroy
#define TracyVkZone(x,y)
#define TracyVkZoneC(x,y,z)
#define TracyVkCollect(x)

#else

#include <stdlib.h>
#include <vulkan/vulkan.h>
#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"

#define TracyVkContext( physdev, device, queue, cmdbuf ) tracy::s_vkCtx.ptr = (tracy::VkCtx*)tracy::tracy_malloc( sizeof( tracy::VkCtx ) ); new(tracy::s_vkCtx.ptr) tracy::VkCtx( physdev, device, queue, cmdbuf );
#define TracyVkDestroy() tracy::s_vkCtx.ptr->~VkCtx(); tracy::tracy_free( tracy::s_vkCtx.ptr ); tracy::s_vkCtx.ptr = nullptr;
#define TracyVkZone( cmdbuf, name ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, cmdbuf );
#define TracyVkZoneC( cmdbuf, name, color ) static const tracy::SourceLocation __tracy_gpu_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope ___tracy_gpu_zone( &__tracy_gpu_source_location, cmdbuf );
#define TracyVkCollect( cmdbuf ) tracy::s_vkCtx.ptr->Collect( cmdbuf );

namespace tracy
{

extern std::atomic<uint16_t> s_vkCtxCounter;

class VkCtx
{
    friend class VkCtxScope;

    enum { QueryCount = 64 * 1024 };

public:
    VkCtx( VkPhysicalDevice physdev, VkDevice device, VkQueue queue, VkCommandBuffer cmdbuf )
        : m_device( device )
        , m_queue( queue )
        , m_context( s_vkCtxCounter.fetch_add( 1, std::memory_order_relaxed ) )
        , m_head( 0 )
        , m_tail( 0 )
    {
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
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuNewContext );
        MemWrite( &item->gpuNewContext.cpuTime, tcpu );
        MemWrite( &item->gpuNewContext.gpuTime, tgpu );
        memset( &item->gpuNewContext.thread, 0, sizeof( item->gpuNewContext.thread ) );
        MemWrite( &item->gpuNewContext.period, period );
        MemWrite( &item->gpuNewContext.context, m_context );
        MemWrite( &item->gpuNewContext.accuracyBits, uint8_t( 0 ) );
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

        int64_t res[QueryCount];
        const auto cnt = m_head < m_tail ? QueryCount - m_tail : m_head - m_tail;
        vkGetQueryPoolResults( m_device, m_query, m_tail, cnt, sizeof( res ), res, sizeof( *res ), VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WITH_AVAILABILITY_BIT );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();

        unsigned int idx;
        for( idx=0; idx<cnt; idx++ )
        {
            if( res[idx] == 0 ) break;

            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            MemWrite( &item->hdr.type, QueueType::GpuTime );
            MemWrite( &item->gpuTime.gpuTime, res[idx] );
            MemWrite( &item->gpuTime.context, m_context );
            tail.store( magic + 1, std::memory_order_release );
        }

        vkCmdResetQueryPool( cmdbuf, m_query, m_tail, idx );

        m_tail += idx;
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

    tracy_force_inline uint16_t GetId() const
    {
        return m_context;
    }

    VkDevice m_device;
    VkQueue m_queue;
    VkQueryPool m_query;
    uint16_t m_context;

    unsigned int m_head;
    unsigned int m_tail;
};

extern VkCtxWrapper s_vkCtx;

class VkCtxScope
{
public:
    tracy_force_inline VkCtxScope( const SourceLocation* srcloc, VkCommandBuffer cmdbuf )
        : m_cmdbuf( cmdbuf )
    {
        auto ctx = s_vkCtx.ptr;
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, ctx->NextQueryId() );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBegin );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline ~VkCtxScope()
    {
        auto ctx = s_vkCtx.ptr;
        vkCmdWriteTimestamp( m_cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, ctx->NextQueryId() );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneEnd );
        MemWrite( &item->gpuZoneEnd.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneEnd.context, ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    VkCommandBuffer m_cmdbuf;
};

}

#endif

#endif
