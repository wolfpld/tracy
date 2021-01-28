#ifndef __TRACYOPENCL_HPP__
#define __TRACYOPENCL_HPP__

#if !defined TRACY_ENABLE

#define TracyCLContext(c, x) nullptr
#define TracyCLDestroy(c)

#define TracyCLNamedZone(c, x, y, z)
#define TracyCLNamedZoneC(c, x, y, z, w)
#define TracyCLZone(c, x)
#define TracyCLZoneC(c, x, y)

#define TracyCLNamedZoneS(c, x, y, z, w)
#define TracyCLNamedZoneCS(c, x, y, z, w, v)
#define TracyCLZoneS(c, x, y)
#define TracyCLZoneCS(c, x, y, z)

#define TracyCLNamedZoneSetEvent(x, e)
#define TracyCLZoneSetEvent(e)

#define TracyCLCollect(c)

namespace tracy
{
    class OpenCLCtxScope {};
}

using TracyCLCtx = void*;

#else

#include <CL/cl.h>

#include <atomic>
#include <cassert>

#include "Tracy.hpp"
#include "client/TracyCallstack.hpp"
#include "client/TracyProfiler.hpp"
#include "common/TracyAlloc.hpp"

namespace tracy {

    enum class EventPhase : uint8_t
    {
        Begin,
        End
    };

    struct EventInfo
    {
        cl_event event;
        EventPhase phase;
    };

    class OpenCLCtx
    {
    public:
        enum { QueryCount = 64 * 1024 };

        OpenCLCtx(cl_context context, cl_device_id device)
            : m_contextId(GetGpuCtxCounter().fetch_add(1, std::memory_order_relaxed))
            , m_head(0)
            , m_tail(0)
        {
            int64_t tcpu, tgpu;
            assert(m_contextId != 255);

            cl_int err = CL_SUCCESS;
            cl_command_queue queue = clCreateCommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &err);
            assert(err == CL_SUCCESS);
            uint32_t dummyValue = 42;
            cl_mem dummyBuffer = clCreateBuffer(context, CL_MEM_WRITE_ONLY, sizeof(uint32_t), nullptr, &err);
            assert(err == CL_SUCCESS);
            cl_event writeBufferEvent;
            err = clEnqueueWriteBuffer(queue, dummyBuffer, CL_FALSE, 0, sizeof(uint32_t), &dummyValue, 0, nullptr, &writeBufferEvent);
            assert(err == CL_SUCCESS);
            err = clWaitForEvents(1, &writeBufferEvent);

            tcpu = Profiler::GetTime();

            assert(err == CL_SUCCESS);
            cl_int eventStatus;
            err = clGetEventInfo(writeBufferEvent, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof(cl_int), &eventStatus, nullptr);
            assert(err == CL_SUCCESS);
            assert(eventStatus == CL_COMPLETE);
            err = clGetEventProfilingInfo(writeBufferEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &tgpu, nullptr);
            assert(err == CL_SUCCESS);
            err = clReleaseEvent(writeBufferEvent);
            assert(err == CL_SUCCESS);
            err = clReleaseMemObject(dummyBuffer);
            assert(err == CL_SUCCESS);
            err = clReleaseCommandQueue(queue);
            assert(err == CL_SUCCESS);

            auto item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuNewContext);
            MemWrite(&item->gpuNewContext.cpuTime, tcpu);
            MemWrite(&item->gpuNewContext.gpuTime, tgpu);
            memset(&item->gpuNewContext.thread, 0, sizeof(item->gpuNewContext.thread));
            MemWrite(&item->gpuNewContext.period, 1.0f);
            MemWrite(&item->gpuNewContext.type, GpuContextType::OpenCL);
            MemWrite(&item->gpuNewContext.context, (uint8_t) m_contextId);
            MemWrite(&item->gpuNewContext.flags, (uint8_t)0);
#ifdef TRACY_ON_DEMAND
            GetProfiler().DeferItem(*item);
#endif
            Profiler::QueueSerialFinish();
        }

        void Collect()
        {
            ZoneScopedC(Color::Red4);

            if (m_tail == m_head) return;

#ifdef TRACY_ON_DEMAND
            if (!GetProfiler().IsConnected())
            {
                m_head = m_tail = 0;
            }
#endif

            while (m_tail != m_head)
            {
                EventInfo eventInfo = m_query[m_tail];
                cl_event event = eventInfo.event;
                cl_int eventStatus;
                cl_int err = clGetEventInfo(event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof(cl_int), &eventStatus, nullptr);
                assert(err == CL_SUCCESS);
                if (eventStatus != CL_COMPLETE) return;

                cl_int eventInfoQuery = (eventInfo.phase == EventPhase::Begin)
                    ? CL_PROFILING_COMMAND_START
                    : CL_PROFILING_COMMAND_END;

                cl_ulong eventTimeStamp = 0;
                err = clGetEventProfilingInfo(event, eventInfoQuery, sizeof(cl_ulong), &eventTimeStamp, nullptr);
                assert(err == CL_SUCCESS);
                assert(eventTimeStamp != 0);

                auto item = Profiler::QueueSerial();
                MemWrite(&item->hdr.type, QueueType::GpuTime);
                MemWrite(&item->gpuTime.gpuTime, (int64_t)eventTimeStamp);
                MemWrite(&item->gpuTime.queryId, (uint16_t)m_tail);
                MemWrite(&item->gpuTime.context, m_contextId);
                Profiler::QueueSerialFinish();

                if (eventInfo.phase == EventPhase::End)
                {
                    // Done with the event, so release it
                    err = clReleaseEvent(event);
                    assert(err == CL_SUCCESS);
                }

                m_tail = (m_tail + 1) % QueryCount;
            }
        }

        tracy_force_inline uint8_t GetId() const
        {
            return m_contextId;
        }

        tracy_force_inline unsigned int NextQueryId(EventInfo eventInfo)
        {
            const auto id = m_head;
            m_head = (m_head + 1) % QueryCount;
            assert(m_head != m_tail);
            m_query[id] = eventInfo;
            return id;
        }

        tracy_force_inline EventInfo& GetQuery(unsigned int id)
        {
            assert(id < QueryCount);
            return m_query[id];
        }

    private:

        unsigned int m_contextId;

        EventInfo m_query[QueryCount];
        unsigned int m_head;
        unsigned int m_tail;

    };

    class OpenCLCtxScope {
    public:
        tracy_force_inline OpenCLCtxScope(OpenCLCtx* ctx, const SourceLocationData* srcLoc, bool is_active)
#ifdef TRACY_ON_DEMAND
            : m_active(is_active&& GetProfiler().IsConnected())
#else
            : m_active(is_active)
#endif
            , m_ctx(ctx)
            , m_event(nullptr)
        {
            if (!m_active) return;

            m_beginQueryId = ctx->NextQueryId(EventInfo{ nullptr, EventPhase::Begin });

            auto item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneBeginSerial);
            MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneBegin.srcloc, (uint64_t)srcLoc);
            MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneBegin.queryId, (uint16_t)m_beginQueryId);
            MemWrite(&item->gpuZoneBegin.context, ctx->GetId());
            Profiler::QueueSerialFinish();
        }

        tracy_force_inline OpenCLCtxScope(OpenCLCtx* ctx, const SourceLocationData* srcLoc, int depth, bool is_active)
#ifdef TRACY_ON_DEMAND
            : m_active(is_active&& GetProfiler().IsConnected())
#else
            : m_active(is_active)
#endif
            , m_ctx(ctx)
            , m_event(nullptr)
        {
            if (!m_active) return;

            m_beginQueryId = ctx->NextQueryId(EventInfo{ nullptr, EventPhase::Begin });

            GetProfiler().SendCallstack(depth);

            auto item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneBeginCallstackSerial);
            MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneBegin.srcloc, (uint64_t)srcLoc);
            MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneBegin.queryId, (uint16_t)m_beginQueryId);
            MemWrite(&item->gpuZoneBegin.context, ctx->GetId());
            Profiler::QueueSerialFinish();
        }

        tracy_force_inline void SetEvent(cl_event event)
        {
            if (!m_active) return;
            m_event = event;
            cl_int err = clRetainEvent(m_event);
            assert(err == CL_SUCCESS);
            m_ctx->GetQuery(m_beginQueryId).event = m_event;
        }

        tracy_force_inline ~OpenCLCtxScope()
        {
            if (!m_active) return;
            const auto queryId = m_ctx->NextQueryId(EventInfo{ m_event, EventPhase::End });

            auto item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneEndSerial);
            MemWrite(&item->gpuZoneEnd.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneEnd.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneEnd.queryId, (uint16_t)queryId);
            MemWrite(&item->gpuZoneEnd.context, m_ctx->GetId());
            Profiler::QueueSerialFinish();
        }

        const bool m_active;
        OpenCLCtx* m_ctx;
        cl_event m_event;
        unsigned int m_beginQueryId;
    };

    static inline OpenCLCtx* CreateCLContext(cl_context context, cl_device_id device)
    {
        InitRPMallocThread();
        auto ctx = (OpenCLCtx*)tracy_malloc(sizeof(OpenCLCtx));
        new (ctx) OpenCLCtx(context, device);
        return ctx;
    }

    static inline void DestroyCLContext(OpenCLCtx* ctx)
    {
        ctx->~OpenCLCtx();
        tracy_free(ctx);
    }

}  // namespace tracy

using TracyCLCtx = tracy::OpenCLCtx*;

#define TracyCLContext(context, device) tracy::CreateCLContext(context, device);
#define TracyCLDestroy(ctx) tracy::DestroyCLContext(ctx);
#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyCLNamedZone(ctx, varname, name, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, 0 }; tracy::OpenCLCtxScope varname(ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define TracyCLNamedZoneC(ctx, varname, name, color, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__) { name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, color }; tracy::OpenCLCtxScope varname(ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define TracyCLZone(ctx, name) TracyCLNamedZoneS(ctx, __tracy_gpu_zone, name, TRACY_CALLSTACK, true)
#  define TracyCLZoneC(ctx, name, color) TracyCLNamedZoneCS(ctx, __tracy_gpu_zone, name, color, TRACY_CALLSTACK, true)
#else
#  define TracyCLNamedZone(ctx, varname, name, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__){ name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, 0 }; tracy::OpenCLCtxScope varname(ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), active);
#  define TracyCLNamedZoneC(ctx, varname, name, color, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__){ name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, color }; tracy::OpenCLCtxScope varname(ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), active);
#  define TracyCLZone(ctx, name) TracyCLNamedZone(ctx, __tracy_gpu_zone, name, true)
#  define TracyCLZoneC(ctx, name, color) TracyCLNamedZoneC(ctx, __tracy_gpu_zone, name, color, true )
#endif

#ifdef TRACY_HAS_CALLSTACK
#  define TracyCLNamedZoneS(ctx, varname, name, depth, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__){ name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, 0 }; tracy::OpenCLCtxScope varname(ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), depth, active);
#  define TracyCLNamedZoneCS(ctx, varname, name, color, depth, active) static constexpr tracy::SourceLocationData TracyConcat(__tracy_gpu_source_location,__LINE__){ name, __FUNCTION__, __FILE__, (uint32_t)__LINE__, color }; tracy::OpenCLCtxScope varname(ctx, &TracyConcat(__tracy_gpu_source_location,__LINE__), depth, active);
#  define TracyCLZoneS(ctx, name, depth) TracyCLNamedZoneS(ctx, __tracy_gpu_zone, name, depth, true)
#  define TracyCLZoneCS(ctx, name, color, depth) TracyCLNamedZoneCS(ctx, __tracy_gpu_zone, name, color, depth, true)
#else
#  define TracyCLNamedZoneS(ctx, varname, name, depth, active) TracyCLNamedZone(ctx, varname, name, active)
#  define TracyCLNamedZoneCS(ctx, varname, name, color, depth, active) TracyCLNamedZoneC(ctx, varname, name, color, active)
#  define TracyCLZoneS(ctx, name, depth) TracyCLZone(ctx, name)
#  define TracyCLZoneCS(ctx, name, color, depth) TracyCLZoneC(ctx, name, color)
#endif

#define TracyCLNamedZoneSetEvent(varname, event) varname.SetEvent(event)
#define TracyCLZoneSetEvent(event) __tracy_gpu_zone.SetEvent(event)

#define TracyCLCollect(ctx) ctx->Collect()

#endif

#endif
