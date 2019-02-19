#ifndef __TRACYVULKAN_HPP__
#define __TRACYVULKAN_HPP__

#if !defined TRACY_ENABLE

#define TracyVkContext(x,y,z,w) nullptr
#define TracyVkDestroy(x)
#define TracyVkNamedZone(c,x,y,z)
#define TracyVkNamedZoneC(c,x,y,z,w)
#define TracyVkZone(c,x,y)
#define TracyVkZoneC(c,x,y,z)
#define TracyVkCollect(c,x)

#define TracyVkNamedZoneS(c,x,y,z,w)
#define TracyVkNamedZoneCS(c,x,y,z,w,v)
#define TracyVkZoneS(c,x,y,z)
#define TracyVkZoneCS(c,x,y,z,w)

namespace tracy
{
class VkCtxScope {};
}

using TracyVkCtx = void*;

#else

#include <assert.h>
#include <stdlib.h>
#include <vulkan/vulkan.h>
#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyCallstack.hpp"

namespace tracy
{

class VkCtx
{
    friend class VkCtxScope;

    enum { QueryCount = 64 * 1024 };

public:
    VkCtx( VkPhysicalDevice physdev, VkDevice device, VkQueue queue, VkCommandBuffer cmdbuf )
        : m_device( device )
        , m_queue( queue )
        , m_context( GetGpuCtxCounter().fetch_add( 1, std::memory_order_relaxed ) )
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
        auto token = GetToken();
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
        GetProfiler().DeferItem( *item );
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
        if( !GetProfiler().IsConnected() )
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
        auto token = GetToken();
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

class VkCtxScope
{
public:
    tracy_force_inline VkCtxScope( VkCtx* ctx, const SourceLocationData* srcloc, VkCommandBuffer cmdbuf )
        : m_cmdbuf( cmdbuf )
        , m_ctx( ctx )
#ifdef TRACY_ON_DEMAND
        , m_active( GetProfiler().IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, queryId );

        Magic magic;
        auto token = GetToken();
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

    tracy_force_inline VkCtxScope( VkCtx* ctx, const SourceLocationData* srcloc, VkCommandBuffer cmdbuf, int depth )
        : m_cmdbuf( cmdbuf )
        , m_ctx( ctx )
#ifdef TRACY_ON_DEMAND
        , m_active( GetProfiler().IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto thread = GetThreadHandle();

        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, ctx->m_query, queryId );

        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginCallstack );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, thread );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );

        GetProfiler().SendCallstack( depth, thread );
    }

    tracy_force_inline ~VkCtxScope()
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto queryId = m_ctx->NextQueryId();
        vkCmdWriteTimestamp( m_cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, m_ctx->m_query, queryId );

        Magic magic;
        auto token = GetToken();
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::GpuZoneEnd );
        MemWrite( &item->gpuZoneEnd.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneEnd.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneEnd.context, m_ctx->GetId() );
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    VkCommandBuffer m_cmdbuf;
    VkCtx* m_ctx;

#ifdef TRACY_ON_DEMAND
    const bool m_active;
#endif
};

static inline VkCtx* CreateVkContext( VkPhysicalDevice physdev, VkDevice device, VkQueue queue, VkCommandBuffer cmdbuf )
{
    auto ctx = (VkCtx*)tracy_malloc( sizeof( VkCtx ) );
    new(ctx) VkCtx( physdev, device, queue, cmdbuf );
    return ctx;
}

static inline void DestroyVkContext( VkCtx* ctx )
{
    ctx->~VkCtx();
    tracy_free( ctx );
}

}

using TracyVkCtx = tracy::VkCtx*;

#define TracyVkContext( physdev, device, queue, cmdbuf ) tracy::CreateVkContext( physdev, device, queue, cmdbuf );
#define TracyVkDestroy( ctx ) tracy::DestroyVkContext( ctx );
#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyVkNamedZone( ctx, varname, cmdbuf, name ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, TRACY_CALLSTACK );
#  define TracyVkNamedZoneC( ctx, varname, cmdbuf, name, color ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, TRACY_CALLSTACK );
#  define TracyVkZone( ctx, cmdbuf, name ) TracyVkNamedZoneS( ctx, ___tracy_gpu_zone, cmdbuf, name, TRACY_CALLSTACK )
#  define TracyVkZoneC( ctx, cmdbuf, name, color ) TracyVkNamedZoneCS( ctx, ___tracy_gpu_zone, cmdbuf, name, color, TRACY_CALLSTACK )
#else
#  define TracyVkNamedZone( ctx, varname, cmdbuf, name ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf );
#  define TracyVkNamedZoneC( ctx, varname, cmdbuf, name, color ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf );
#  define TracyVkZone( ctx, cmdbuf, name ) TracyVkNamedZone( ctx, ___tracy_gpu_zone, cmdbuf, name )
#  define TracyVkZoneC( ctx, cmdbuf, name, color ) TracyVkNamedZoneC( ctx, ___tracy_gpu_zone, cmdbuf, name, color )
#endif
#define TracyVkCollect( ctx, cmdbuf ) ctx->Collect( cmdbuf );

#ifdef TRACY_HAS_CALLSTACK
#  define TracyVkNamedZoneS( ctx, varname, cmdbuf, name, depth ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, depth );
#  define TracyVkNamedZoneCS( ctx, varname, cmdbuf, name, color, depth ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, depth );
#  define TracyVkZoneS( ctx, cmdbuf, name, depth ) TracyVkNamedZoneS( ctx, ___tracy_gpu_zone, cmdbuf, name, depth )
#  define TracyVkZoneCS( ctx, cmdbuf, name, color, depth ) TracyVkNamedZoneCS( ctx, ___tracy_gpu_zone, cmdbuf, name, color, depth )
#else
#  define TracyVkNamedZoneS( ctx, varname, cmdbuf, name, depth ) TracyVkNamedZone( ctx, varname, cmdbuf, name )
#  define TracyVkNamedZoneCS( ctx, varname, cmdbuf, name, color, depth ) TracyVkNamedZoneC( ctx, varname, cmdbuf, name, color )
#  define TracyVkZoneS( ctx, cmdbuf, name, depth ) TracyVkZone( ctx, cmdbuf, name )
#  define TracyVkZoneCS( ctx, cmdbuf, name, color, depth ) TracyVkZoneC( ctx, cmdbuf, name, color )
#endif

#endif

#endif
