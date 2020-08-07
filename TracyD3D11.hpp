#ifndef __TRACYD3D11_HPP__
#define __TRACYD3D11_HPP__

// Include this file after you include DirectX 11 headers.

#if !defined TRACY_ENABLE || !defined _WIN32

#define TracyD3D11Context(x,y)
#define TracyD3D11NamedZone(x,y,z)
#define TracyD3D11NamedZoneC(x,y,z,w)
#define TracyD3D11Zone(x,y)
#define TracyD3D11ZoneC(x,y,z)
#define TracyD3D11Collect(x)

#define TracyD3D11NamedZoneS(x,y,z,w)
#define TracyD3D11NamedZoneCS(x,y,z,w,v)
#define TracyD3D11ZoneS(x,y,z)
#define TracyD3D11ZoneCS(x,y,z,w)

namespace tracy
{
class D3D11CtxScope {};
}

using TracyD3D11Ctx = void*;

#else

#include <atomic>
#include <assert.h>
#include <stdlib.h>

#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyCallstack.hpp"
#include "common/TracyAlign.hpp"
#include "common/TracyAlloc.hpp"

#define TracyD3D11Context( device, devicectx ) tracy::CreateD3D11Context( physdev, device, queue, cmdbuf, nullptr, nullptr );
#define TracyD3D11NamedZone( ctx, varname, name, active ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::Dx11CtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__) );
#define TracyD3D11NamedZoneC( ctx, varname, name, color, active ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::Dx11CtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__) );
#define TracyD3D11Zone( ctx, name ) TracyD3D11NamedZone( ctx, ___tracy_gpu_zone, name )
#define TracyD3D11ZoneC( ctx, name, color ) TracyD3D11NamedZoneC( ctx, ___tracy_gpu_zone, name, color )
#define TracyD3D11Collect( ctx ) ctx->Collect();

#ifdef TRACY_HAS_CALLSTACK
#  define TracyD3D11NamedZoneS( ctx, varname, name, depth, active ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::Dx11CtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), depth );
#  define TracyD3D11NamedZoneCS( ctx, varname, name, color, depth, active ) static const tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::Dx11CtxScope varname( ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), depth );
#  define TracyD3D11ZoneS( ctx, name, depth ) TracyD3D11NamedZoneS( ctx, ___tracy_gpu_zone, name, depth )
#  define TracyD3D11ZoneCS( ctx, name, color, depth ) TracyD3D11NamedZoneCS( ctx, ___tracy_gpu_zone, name, color, depth )
#else
#  define TracyD3D11NamedZoneS( ctx, varname, name, depth, active ) TracyD3D11NamedZone( ctx, varname, name )
#  define TracyD3D11NamedZoneCS( ctx, varname, name, color, depth, active ) TracyD3D11NamedZoneC( ctx, varname, name, color )
#  define TracyD3D11ZoneS( ctx, name, depth, active ) TracyD3D11Zone( ctx, name )
#  define TracyD3D11ZoneCS( ctx, name, color, depth, active ) TracyD3D11ZoneC( name, color )
#endif

#define TRACY_D3D11_NO_SINGLE_THREAD

namespace tracy
{

class D3D11Ctx
{
    friend class D3D11CtxScope;

    enum { QueryCount = 64 * 1024 };

public:
    D3D11Ctx( ID3D11Device* device, ID3D11DeviceContext* devicectx )
        : m_device( device )
        , m_devicectx( devicectx )
        , m_context( GetGpuCtxCounter().fetch_add( 1, std::memory_order_relaxed ) )
        , m_head( 0 )
        , m_tail( 0 )
    {
        assert( m_context != 255 );

        for (int i = 0; i < QueryCount; i++)
        {
            HRESULT hr = S_OK;
            D3D11_QUERY_DESC desc;
            desc.MiscFlags = 0;

            desc.Query = D3D11_QUERY_TIMESTAMP;
            hr |= device->CreateQuery(&desc, &m_queries[i]);

            desc.Query = D3D11_QUERY_TIMESTAMP_DISJOINT;
            hr |= device->CreateQuery(&desc, &m_disjoints[i]);

            m_disjointMap[i] = nullptr;

            assert(SUCCEEDED(hr));
        }

        // Force query the initial GPU timestamp (pipeline stall)
        D3D11_QUERY_DATA_TIMESTAMP_DISJOINT disjoint;
        UINT64 timestamp;
        for (int attempts = 0; attempts < 50; attempts++)
        {
            devicectx->Begin(m_disjoints[0]);
            devicectx->End(m_queries[0]);
            devicectx->End(m_disjoints[0]);
            devicectx->Flush();

            while (devicectx->GetData(m_disjoints[0], &disjoint, sizeof(disjoint), 0) == S_FALSE)
                /* Nothing */;

            if (disjoint.Disjoint)
                continue;

            while (devicectx->GetData(m_queries[0], &timestamp, sizeof(timestamp), 0) == S_FALSE)
                /* Nothing */;

            break;
        }

        int64_t tgpu = timestamp * (1000000000ull / disjoint.Frequency);
        int64_t tcpu = Profiler::GetTime();

        uint8_t flags = 0;

        const float period = 1.f;
        auto* item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuNewContext );
        MemWrite( &item->gpuNewContext.cpuTime, tcpu );
        MemWrite( &item->gpuNewContext.gpuTime, tgpu );
#ifdef TRACY_D3D11_NO_SINGLE_THREAD
        memset(&item->gpuNewContext.thread, 0, sizeof(item->gpuNewContext.thread));
#else
        MemWrite( &item->gpuNewContext.thread, GetThreadHandle() );
#endif
        MemWrite( &item->gpuNewContext.period, period );
        MemWrite( &item->gpuNewContext.context, m_context );
        MemWrite( &item->gpuNewContext.flags, flags );
        MemWrite( &item->gpuNewContext.type, GpuContextType::Direct3D11 );

#ifdef TRACY_ON_DEMAND
        GetProfiler().DeferItem( *item );
#endif

        Profiler::QueueSerialFinish();
    }

    ~D3D11Ctx()
    {
        for (int i = 0; i < QueryCount; i++)
        {
            m_queries[i]->Release();
            m_disjoints[i]->Release();
            m_disjointMap[i] = nullptr;
        }
    }

    void Collect()
    {
        ZoneScopedC( Color::Red4 );

        if( m_tail == m_head ) return;

#ifdef TRACY_ON_DEMAND
        if( !GetProfiler().IsConnected() )
        {
            m_head = m_tail = 0;
            return;
        }
#endif

        auto start = m_tail;
        auto end = m_head + QueryCount;
        auto cnt = (end - start) % QueryCount;
        while (cnt > 1)
        {
            auto mid = start + cnt / 2;

            bool available =
                m_devicectx->GetData(m_disjointMap[mid % QueryCount], nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH) == S_OK &&
                m_devicectx->GetData(m_queries[mid % QueryCount], nullptr, 0, D3D11_ASYNC_GETDATA_DONOTFLUSH) == S_OK;

            if (available)
            {
                start = mid;
            }
            else
            {
                end = mid;
            }
            cnt = (end - start) % QueryCount;
        }

        start %= QueryCount;

        while (m_tail != start)
        {
            D3D11_QUERY_DATA_TIMESTAMP_DISJOINT disjoint;
            UINT64 time;

            m_devicectx->GetData(m_disjointMap[m_tail], &disjoint, sizeof(disjoint), 0);
            m_devicectx->GetData(m_queries[m_tail], &time, sizeof(time), 0);

            time *= (1000000000ull / disjoint.Frequency);

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuTime);
            MemWrite(&item->gpuTime.gpuTime, (int64_t)time);
            MemWrite(&item->gpuTime.queryId, (uint16_t)m_tail);
            MemWrite(&item->gpuTime.context, m_context);
            Profiler::QueueSerialFinish();

            m_tail = (m_tail + 1) % QueryCount;
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

    tracy_force_inline ID3D11Query* TranslateQueryId( unsigned int id )
    {
        return m_queries[id];
    }

    tracy_force_inline ID3D11Query* MapDisjointQueryId( unsigned int id, unsigned int disjointId )
    {
        m_disjointMap[id] = m_disjoints[disjointId];
        return m_disjoints[disjointId];
    }

    tracy_force_inline uint8_t GetId() const
    {
        return m_context;
    }

    ID3D11Device* m_device;
    ID3D11DeviceContext* m_devicectx;

    ID3D11Query* m_queries[QueryCount];
    ID3D11Query* m_disjoints[QueryCount];
    ID3D11Query* m_disjointMap[QueryCount]; // Multiple time queries can have one disjoint query
    uint8_t m_context;

    unsigned int m_head;
    unsigned int m_tail;
};

class D3D11CtxScope
{
public:
    tracy_force_inline D3D11CtxScope( D3D11Ctx* ctx, const SourceLocationData* srcloc, bool is_active )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        m_ctx = ctx;

        const auto queryId = ctx->NextQueryId();
        ctx->m_devicectx->Begin(ctx->MapDisjointQueryId(queryId, queryId));
        ctx->m_devicectx->End(ctx->TranslateQueryId(queryId));

        m_disjointId = queryId;

        auto* item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginSerial );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
#ifdef TRACY_D3D11_NO_SINGLE_THREAD
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
#else
        memset(&item->gpuZoneBegin.thread, 0, sizeof(item->gpuNewContext.thread));
#endif
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );
        
        Profiler::QueueSerialFinish();
    }

    tracy_force_inline D3D11CtxScope( D3D11Ctx* ctx, const SourceLocationData* srcloc, int depth, bool is_active )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        m_ctx = ctx;

        const auto queryId = ctx->NextQueryId();
        ctx->m_devicectx->Begin(ctx->MapDisjointQueryId(queryId, queryId));
        ctx->m_devicectx->End(ctx->TranslateQueryId(queryId));

        m_disjointId = queryId;

        auto* item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuZoneBeginCallstackSerial );
        MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
        MemWrite( &item->gpuZoneBegin.srcloc, (uint64_t)srcloc );
        MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
        MemWrite( &item->gpuZoneBegin.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneBegin.context, ctx->GetId() );

        Profiler::QueueSerialFinish();

        GetProfiler().SendCallstack( depth );
    }

    tracy_force_inline ~D3D11CtxScope()
    {
        if( !m_active ) return;

        const auto queryId = m_ctx->NextQueryId();
        m_ctx->m_devicectx->End(m_ctx->TranslateQueryId(queryId));
        m_ctx->m_devicectx->End(m_ctx->MapDisjointQueryId(queryId, m_disjointId));

        auto* item = Profiler::QueueSerial();
        MemWrite( &item->hdr.type, QueueType::GpuZoneEndSerial );
        MemWrite( &item->gpuZoneEnd.cpuTime, Profiler::GetTime() );
#ifdef TRACY_D3D11_NO_SINGLE_THREAD
        MemWrite( &item->gpuZoneEnd.thread, GetThreadHandle() );
#else
        memset(&item->gpuZoneEnd.thread, 0, sizeof(item->gpuNewContext.thread));
#endif
        MemWrite( &item->gpuZoneEnd.queryId, uint16_t( queryId ) );
        MemWrite( &item->gpuZoneEnd.context, m_ctx->GetId() );
        
        Profiler::QueueSerialFinish();
    }

private:
    const bool m_active;

    D3D11Ctx* m_ctx;
    unsigned int m_disjointId;
};

static inline D3D11Ctx* CreateD3D11Context( ID3D11Device* device, ID3D11DeviceContext* devicectx )
{
    InitRPMallocThread();
    auto ctx = (D3D11Ctx*)tracy_malloc( sizeof( D3D11Ctx ) );
    new(ctx) D3D11Ctx( device, devicectx );
    return ctx;
}

static inline void DestroyD3D11Context( D3D11Ctx* ctx )
{
    ctx->~D3D11Ctx();
    tracy_free( ctx );
}
}

#endif

#endif
