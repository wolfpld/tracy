#ifndef __TRACYVULKAN_HPP__
#define __TRACYVULKAN_HPP__

#if !defined TRACY_ENABLE

#define TracyVkContext(x,y,z,w) nullptr
#define TracyVkContextCalibrated(x,y,z,w,a,b) nullptr
#define TracyVkDestroy(x)
#define TracyVkNamedZone(c,x,y,z,w)
#define TracyVkNamedZoneC(c,x,y,z,w,a)
#define TracyVkZone(c,x,y)
#define TracyVkZoneC(c,x,y,z)
#define TracyVkZoneTransient(c,x,y,z,w)
#define TracyVkCollect(c,x)

#define TracyVkNamedZoneS(c,x,y,z,w,a)
#define TracyVkNamedZoneCS(c,x,y,z,w,v,a)
#define TracyVkZoneS(c,x,y,z)
#define TracyVkZoneCS(c,x,y,z,w)
#define TracyVkZoneTransientS(c,x,y,z,w,a)

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
    VkCtx( VkPhysicalDevice physdev, VkDevice device, VkQueue queue, VkCommandBuffer cmdbuf, PFN_vkGetPhysicalDeviceCalibrateableTimeDomainsEXT _vkGetPhysicalDeviceCalibrateableTimeDomainsEXT, PFN_vkGetCalibratedTimestampsEXT _vkGetCalibratedTimestampsEXT )
        : m_device( device )
        , m_timeDomain( VK_TIME_DOMAIN_DEVICE_EXT )
        , m_context( GetGpuCtxCounter().fetch_add( 1, std::memory_order_relaxed ) )
        , m_head( 0 )
        , m_tail( 0 )
        , m_oldCnt( 0 )
        , m_queryCount( QueryCount )
        , m_vkGetCalibratedTimestampsEXT( _vkGetCalibratedTimestampsEXT )
    {
        assert( m_context != 255 );

        if( _vkGetPhysicalDeviceCalibrateableTimeDomainsEXT && _vkGetCalibratedTimestampsEXT )
        {
            uint32_t num;
            _vkGetPhysicalDeviceCalibrateableTimeDomainsEXT( physdev, &num, nullptr );
            if( num > 4 ) num = 4;
            VkTimeDomainEXT data[4];
            _vkGetPhysicalDeviceCalibrateableTimeDomainsEXT( physdev, &num, data );
            for( uint32_t i=0; i<num; i++ )
            {
                // TODO VK_TIME_DOMAIN_CLOCK_MONOTONIC_RAW_EXT
                if( data[i] == VK_TIME_DOMAIN_QUERY_PERFORMANCE_COUNTER_EXT )
                {
                    m_timeDomain = data[i];
                    break;
                }
            }
        }

        VkPhysicalDeviceProperties prop;
        vkGetPhysicalDeviceProperties( physdev, &prop );
        const float period = prop.limits.timestampPeriod;

        VkQueryPoolCreateInfo poolInfo = {};
        poolInfo.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO;
        poolInfo.queryCount = m_queryCount;
        poolInfo.queryType = VK_QUERY_TYPE_TIMESTAMP;
        while( vkCreateQueryPool( device, &poolInfo, nullptr, &m_query ) != VK_SUCCESS )
        {
            m_queryCount /= 2;
            poolInfo.queryCount = m_queryCount;
        }

        VkCommandBufferBeginInfo beginInfo = {};
        beginInfo.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
        beginInfo.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;

        VkSubmitInfo submitInfo = {};
        submitInfo.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
        submitInfo.commandBufferCount = 1;
        submitInfo.pCommandBuffers = &cmdbuf;

        vkBeginCommandBuffer( cmdbuf, &beginInfo );
        vkCmdResetQueryPool( cmdbuf, m_query, 0, m_queryCount );
        vkEndCommandBuffer( cmdbuf );
        vkQueueSubmit( queue, 1, &submitInfo, VK_NULL_HANDLE );
        vkQueueWaitIdle( queue );

        int64_t tcpu, tgpu;
        if( m_timeDomain == VK_TIME_DOMAIN_DEVICE_EXT )
        {
            vkBeginCommandBuffer( cmdbuf, &beginInfo );
            vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, m_query, 0 );
            vkEndCommandBuffer( cmdbuf );
            vkQueueSubmit( queue, 1, &submitInfo, VK_NULL_HANDLE );
            vkQueueWaitIdle( queue );

            tcpu = Profiler::GetTime();
            vkGetQueryPoolResults( device, m_query, 0, 1, sizeof( tgpu ), &tgpu, sizeof( tgpu ), VK_QUERY_RESULT_64_BIT | VK_QUERY_RESULT_WAIT_BIT );

            vkBeginCommandBuffer( cmdbuf, &beginInfo );
            vkCmdResetQueryPool( cmdbuf, m_query, 0, 1 );
            vkEndCommandBuffer( cmdbuf );
            vkQueueSubmit( queue, 1, &submitInfo, VK_NULL_HANDLE );
            vkQueueWaitIdle( queue );
        }
        else
        {
            enum { NumProbes = 32 };

            VkCalibratedTimestampInfoEXT spec[2] = {
                { VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT, nullptr, VK_TIME_DOMAIN_DEVICE_EXT },
                { VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT, nullptr, m_timeDomain },
            };
            uint64_t ts[2];
            uint64_t deviation[NumProbes];
            for( int i=0; i<NumProbes; i++ )
            {
                _vkGetCalibratedTimestampsEXT( device, 2, spec, ts, deviation+i );
            }
            uint64_t minDeviation = deviation[0];
            for( int i=1; i<NumProbes; i++ )
            {
                if( minDeviation > deviation[i] )
                {
                    minDeviation = deviation[i];
                }
            }
            m_deviation = minDeviation * 3 / 2;

            m_qpcToNs = int64_t( 1000000000. / GetFrequencyQpc() );

            Calibrate( device, m_prevCalibration, tgpu );
            tcpu = Profiler::GetTime();
        }

        uint8_t flags = 0;
        if( m_timeDomain != VK_TIME_DOMAIN_DEVICE_EXT ) flags |= GpuContextCalibration;

        auto item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuNewContext );
        MemWrite( &item->gpuNewContext.cpuTime, tcpu );
        MemWrite( &item->gpuNewContext.gpuTime, tgpu );
        memset( &item->gpuNewContext.thread, 0, sizeof( item->gpuNewContext.thread ) );
        MemWrite( &item->gpuNewContext.period, period );
        MemWrite( &item->gpuNewContext.context, m_context );
        MemWrite( &item->gpuNewContext.flags, flags );
        MemWrite( &item->gpuNewContext.type, GpuContextType::Vulkan );

#ifdef TRACY_ON_DEMAND
        GetProfiler().DeferItem( *item );
#endif
        Profiler::QueueSerialFinish();

        m_res = (int64_t*)tracy_malloc( sizeof( int64_t ) * m_queryCount );
    }

    ~VkCtx()
    {
        tracy_free( m_res );
        vkDestroyQueryPool( m_device, m_query, nullptr );
    }

    void Collect( VkCommandBuffer cmdbuf )
    {
        ZoneScopedC( Color::Red4 );

        if( m_tail == m_head ) return;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() )
        {
            vkCmdResetQueryPool( cmdbuf, m_query, 0, m_queryCount );
            m_head = m_tail = 0;
            int64_t tgpu;
            if( m_timeDomain != VK_TIME_DOMAIN_DEVICE_EXT ) Calibrate( m_device, m_prevCalibration, tgpu );
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
            cnt = m_head < m_tail ? m_queryCount - m_tail : m_head - m_tail;
        }

        if( vkGetQueryPoolResults( m_device, m_query, m_tail, cnt, sizeof( int64_t ) * m_queryCount, m_res, sizeof( int64_t ), VK_QUERY_RESULT_64_BIT ) == VK_NOT_READY )
        {
            m_oldCnt = cnt;
            return;
        }

        for( unsigned int idx=0; idx<cnt; idx++ )
        {
            auto item = Profiler::QueueSerial();
            MemWrite( &item->hdr.type, QueueType::GpuTime );
            MemWrite( &item->gpuTime.gpuTime, m_res[idx] );
            MemWrite( &item->gpuTime.queryId, uint16_t( m_tail + idx ) );
            MemWrite( &item->gpuTime.context, m_context );
            Profiler::QueueSerialFinish();
        }

        if( m_timeDomain != VK_TIME_DOMAIN_DEVICE_EXT )
        {
            int64_t tgpu, tcpu;
            Calibrate( m_device, tcpu, tgpu );
            const auto refCpu = Profiler::GetTime();
            const auto delta = tcpu - m_prevCalibration;
            if( delta > 0 )
            {
                m_prevCalibration = tcpu;
                auto item = Profiler::QueueSerial();
                MemWrite( &item->hdr.type, QueueType::GpuCalibration );
                MemWrite( &item->gpuCalibration.gpuTime, tgpu );
                MemWrite( &item->gpuCalibration.cpuTime, refCpu );
                MemWrite( &item->gpuCalibration.cpuDelta, delta );
                MemWrite( &item->gpuCalibration.context, m_context );
                Profiler::QueueSerialFinish();
            }
        }

        vkCmdResetQueryPool( cmdbuf, m_query, m_tail, cnt );

        m_tail += cnt;
        if( m_tail == m_queryCount ) m_tail = 0;
    }

private:
    tracy_force_inline unsigned int NextQueryId()
    {
        const auto id = m_head;
        m_head = ( m_head + 1 ) % m_queryCount;
        assert( m_head != m_tail );
        return id;
    }

    tracy_force_inline uint8_t GetId() const
    {
        return m_context;
    }

    tracy_force_inline void Calibrate( VkDevice device, int64_t& tCpu, int64_t& tGpu )
    {
        assert( m_timeDomain != VK_TIME_DOMAIN_DEVICE_EXT );
        VkCalibratedTimestampInfoEXT spec[2] = {
            { VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT, nullptr, VK_TIME_DOMAIN_DEVICE_EXT },
            { VK_STRUCTURE_TYPE_CALIBRATED_TIMESTAMP_INFO_EXT, nullptr, m_timeDomain },
        };
        uint64_t ts[2];
        uint64_t deviation;
        do
        {
            m_vkGetCalibratedTimestampsEXT( device, 2, spec, ts, &deviation );
        }
        while( deviation > m_deviation );

#if defined _WIN32 || defined __CYGWIN__
        tGpu = ts[0];
        tCpu = ts[1] * m_qpcToNs;
#else
        assert( false );
#endif
    }

    VkDevice m_device;
    VkQueryPool m_query;
    VkTimeDomainEXT m_timeDomain;
    uint64_t m_deviation;
    int64_t m_qpcToNs;
    int64_t m_prevCalibration;
    uint8_t m_context;

    unsigned int m_head;
    unsigned int m_tail;
    unsigned int m_oldCnt;
    unsigned int m_queryCount;

    int64_t* m_res;

    PFN_vkGetCalibratedTimestampsEXT m_vkGetCalibratedTimestampsEXT;
};

class VkCtxScope
{
public:
    tracy_force_inline VkCtxScope( VkCtx* ctx, const SourceLocationData* srcloc, VkCommandBuffer cmdbuf, bool is_active )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        m_cmdbuf = cmdbuf;
        m_ctx = ctx;

        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, ctx->m_query, queryId );

        auto item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginSerial );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        Profiler::QueueSerialFinish();
    }

    tracy_force_inline VkCtxScope( VkCtx* ctx, const SourceLocationData* srcloc, VkCommandBuffer cmdbuf, int depth, bool is_active )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        m_cmdbuf = cmdbuf;
        m_ctx = ctx;

        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, ctx->m_query, queryId );

        auto item = Profiler::QueueSerialCallstack( Callstack( depth ) );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginCallstackSerial );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        Profiler::QueueSerialFinish();
    }

    tracy_force_inline VkCtxScope( VkCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, VkCommandBuffer cmdbuf, bool is_active )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        m_cmdbuf = cmdbuf;
        m_ctx = ctx;

        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, ctx->m_query, queryId );

        const auto srcloc = Profiler::AllocSourceLocation( line, source, sourceSz, function, functionSz, name, nameSz );
        auto item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginAllocSrcLocSerial );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, srcloc );
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        Profiler::QueueSerialFinish();
    }

    tracy_force_inline VkCtxScope( VkCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, VkCommandBuffer cmdbuf, int depth, bool is_active )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        m_cmdbuf = cmdbuf;
        m_ctx = ctx;

        const auto queryId = ctx->NextQueryId();
        vkCmdWriteTimestamp( cmdbuf, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, ctx->m_query, queryId );

        const auto srcloc = Profiler::AllocSourceLocation( line, source, sourceSz, function, functionSz, name, nameSz );
        auto item = Profiler::QueueSerialCallstack( Callstack( depth ) );
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginAllocSrcLocCallstackSerial );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, srcloc );
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        Profiler::QueueSerialFinish();
    }

    tracy_force_inline ~VkCtxScope()
    {
        if( !m_active ) return;

        const auto queryId = m_ctx->NextQueryId();
        vkCmdWriteTimestamp( m_cmdbuf, VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, m_ctx->m_query, queryId );

        auto item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuZoneEndSerial );
        MemWrite( &item->gpuZoneEnd.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneEnd.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneEnd.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneEnd.context, m_ctx->GetId() );
        Profiler::QueueSerialFinish();
    }

private:
    const bool m_active;

    VkCommandBuffer m_cmdbuf;
    VkCtx* m_ctx;
};

static inline VkCtx* CreateVkContext( VkPhysicalDevice physdev, VkDevice device, VkQueue queue, VkCommandBuffer cmdbuf, PFN_vkGetPhysicalDeviceCalibrateableTimeDomainsEXT gpdctd, PFN_vkGetCalibratedTimestampsEXT gct )
{
    InitRPMallocThread();
    auto ctx = (VkCtx*)tracy_malloc( sizeof( VkCtx ) );
    new(ctx) VkCtx( physdev, device, queue, cmdbuf, gpdctd, gct );
    return ctx;
}

static inline void DestroyVkContext( VkCtx* ctx )
{
    ctx->~VkCtx();
    tracy_free( ctx );
}

}

using TracyVkCtx = tracy::VkCtx*;

#define TracyVkContext( physdev, device, queue, cmdbuf ) tracy::CreateVkContext( physdev, device, queue, cmdbuf, nullptr, nullptr );
#define TracyVkContextCalibrated( physdev, device, queue, cmdbuf, gpdctd, gct ) tracy::CreateVkContext( physdev, device, queue, cmdbuf, gpdctd, gct );
#define TracyVkDestroy( ctx ) tracy::DestroyVkContext( ctx );
#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyVkNamedZone( ctx, varname, cmdbuf, name, active ) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, TRACY_CALLSTACK, active );
#  define TracyVkNamedZoneC( ctx, varname, cmdbuf, name, color, active ) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, TRACY_CALLSTACK, active );
#  define TracyVkZone( ctx, cmdbuf, name ) TracyVkNamedZoneS( ctx, ___tracy_gpu_zone, cmdbuf, name, TRACY_CALLSTACK, true )
#  define TracyVkZoneC( ctx, cmdbuf, name, color ) TracyVkNamedZoneCS( ctx, ___tracy_gpu_zone, cmdbuf, name, color, TRACY_CALLSTACK, true )
#  define TracyVkZoneTransient( ctx, varname, cmdbuf, name, active ) TracyVkZoneTransientS( ctx, varname, cmdbuf, name, TRACY_CALLSTACK, active )
#else
#  define TracyVkNamedZone( ctx, varname, cmdbuf, name, active ) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, active );
#  define TracyVkNamedZoneC( ctx, varname, cmdbuf, name, color, active ) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, active );
#  define TracyVkZone( ctx, cmdbuf, name ) TracyVkNamedZone( ctx, ___tracy_gpu_zone, cmdbuf, name, true )
#  define TracyVkZoneC( ctx, cmdbuf, name, color ) TracyVkNamedZoneC( ctx, ___tracy_gpu_zone, cmdbuf, name, color, true )
#  define TracyVkZoneTransient( ctx, varname, cmdbuf, name, active ) tracy::VkCtxScope varname( ctx, __LINE__, __FILE__, strlen( __FILE__ ), __FUNCTION__, strlen( __FUNCTION__ ), name, strlen( name ), cmdbuf, active );
#endif
#define TracyVkCollect( ctx, cmdbuf ) ctx->Collect( cmdbuf );

#ifdef TRACY_HAS_CALLSTACK
#  define TracyVkNamedZoneS( ctx, varname, cmdbuf, name, depth, active ) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, depth, active );
#  define TracyVkNamedZoneCS( ctx, varname, cmdbuf, name, color, depth, active ) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::VkCtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), cmdbuf, depth, active );
#  define TracyVkZoneS( ctx, cmdbuf, name, depth ) TracyVkNamedZoneS( ctx, ___tracy_gpu_zone, cmdbuf, name, depth, true )
#  define TracyVkZoneCS( ctx, cmdbuf, name, color, depth ) TracyVkNamedZoneCS( ctx, ___tracy_gpu_zone, cmdbuf, name, color, depth, true )
#  define TracyVkZoneTransientS( ctx, varname, cmdbuf, name, depth, active ) tracy::VkCtxScope varname( ctx, __LINE__, __FILE__, strlen( __FILE__ ), __FUNCTION__, strlen( __FUNCTION__ ), name, strlen( name ), cmdbuf, depth, active );
#else
#  define TracyVkNamedZoneS( ctx, varname, cmdbuf, name, depth, active ) TracyVkNamedZone( ctx, varname, cmdbuf, name, active )
#  define TracyVkNamedZoneCS( ctx, varname, cmdbuf, name, color, depth, active ) TracyVkNamedZoneC( ctx, varname, cmdbuf, name, color, active )
#  define TracyVkZoneS( ctx, cmdbuf, name, depth ) TracyVkZone( ctx, cmdbuf, name )
#  define TracyVkZoneCS( ctx, cmdbuf, name, color, depth ) TracyVkZoneC( ctx, cmdbuf, name, color )
#  define TracyVkZoneTransientS( ctx, varname, cmdbuf, name, depth, active ) TracyVkZoneTransient( ctx, varname, cmdbuf, name, active )
#endif

#endif

#endif
