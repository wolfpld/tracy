#ifndef __TRACYWEBGPU_HPP__
#define __TRACYWEBGPU_HPP__

#ifndef TRACY_ENABLE

#define TracyWebGPUContext(instance, device, queue) nullptr
#define TracyWebGPUDestroy(ctx)
#define TracyWebGPUContextName(ctx, name, size)

#define TracyWebGPUNewFrame(ctx)

#define TracyWebGPUZone(ctx, encoder, name)
#define TracyWebGPUZoneC(ctx, encoder, name, color)
#define TracyWebGPUNamedZone(ctx, varname, encoder, name, active)
#define TracyWebGPUNamedZoneC(ctx, varname, encoder, name, color, active)
#define TracyWebGPUZoneTransient(ctx, varname, encoder, name, active)

#define TracyWebGPUZoneS(ctx, encoder, name, depth)
#define TracyWebGPUZoneCS(ctx, encoder, name, color, depth)
#define TracyWebGPUNamedZoneS(ctx, varname, encoder, name, depth, active)
#define TracyWebGPUNamedZoneCS(ctx, varname, encoder, name, color, depth, active)
#define TracyWebGPUZoneTransientS(ctx, varname, encoder, name, depth, active)

#define TracyWebGPUCollect(ctx)

namespace tracy
{
    class WebGPUZoneScope {};
}

using TracyWebGPUCtx = void*;

#else

#include "Tracy.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyCallstack.hpp"
#include "common/TracyAlign.hpp"
#include "common/TracyAlloc.hpp"

#include <atomic>
#include <mutex>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <chrono>
#include <thread>

#include <webgpu/webgpu.h>

#ifndef TRACY_WEBGPU_DEBUG_LEVEL
#define TRACY_WEBGPU_DEBUG_LEVEL (0)
#endif//TRACY_WEBGPU_DEBUG_LEVEL

#if TRACY_WEBGPU_DEBUG_LEVEL
#define TracyWebGPUDebug(...) __VA_ARGS__;
#if defined(_MSC_VER)
#define TracyWebGPUBreak() if (IsDebuggerPresent()) __debugbreak()
#else
#define TracyWebGPUBreak() ((void)0)
#endif
#define TracyWebGPUAssert(predicate, ...) if (predicate) {} else { __VA_ARGS__; TracyWebGPUBreak(); }
#else
#define TracyWebGPUDebug(...)
#define TracyWebGPUBreak()
#define TracyWebGPUAssert(predicate, ...) assert(predicate);
#endif

#define TracyWebGPULog(severity, msg) tracy::Profiler::LogString( tracy::MessageSourceType::Tracy, tracy::MessageSeverity::severity, tracy::Color::Red4, 0, msg );
#define TracyWebGPUPanic(msg, ...) do { TracyWebGPULog(Error, msg); TracyWebGPUAssert(false && "TracyWebGPU: " msg); __VA_ARGS__; } while(false);

namespace tracy
{

    class WebGPUQueueCtx
    {
        friend class WebGPUZoneScope;

        uint8_t m_contextId = 255;  // 255 represents "invalid id"

        std::mutex m_collectionMutex;

        WGPUInstance m_instance = nullptr;
        WGPUDevice   m_device   = nullptr;
        WGPUQueue    m_queue    = nullptr;

        WGPUQuerySet m_querySet       = nullptr;
        WGPUBuffer   m_resolveBuffer  = nullptr;  // QueryResolve | CopySrc
        WGPUBuffer   m_readbackBuffer = nullptr;  // CopyDst | MapRead

        using atomic_counter = std::atomic<uint64_t>;
        atomic_counter m_queryCounter      = 0;
        atomic_counter m_previousCheckpoint = 0;

        uint32_t m_queryLimit = 0;

        std::vector<uint64_t> m_shadowBuffer;
        uint64_t m_latestKnownGpuTimestamp = 0;

        // Map-state machine for the readback buffer.
        enum class MapState : uint8_t
        {
            Idle,       // not mapped; GPU may write to it
            Pending,    // MapAsync in flight
            Ready,      // callback has fired, buffer is mapped for read
            Failed      // last map attempt failed
        };
        std::atomic<MapState> m_mapState = MapState::Idle;

        tracy_force_inline void SubmitQueueItem(tracy::QueueItem* item)
        {
#ifdef TRACY_ON_DEMAND
            GetProfiler().DeferItem(*item);
#endif
            Profiler::QueueSerialFinish();
        }

        // Drive the WebGPU event queue. Some implementations (e.g. Dawn) want
        // wgpuDeviceTick(); the canonical webgpu.h uses
        // wgpuInstanceProcessEvents(). We only require the latter here.
        void ProcessEvents()
        {
            if (m_instance)
                wgpuInstanceProcessEvents(m_instance);
        }

        bool Anchor(uint64_t& outCpuTime, uint64_t& outGpuTime)
        {
            // Anchor() establishes a (cpuTime, gpuTime) anchor pair by querying
            // a single timestamp (and synchronously resolving/reading it back)
            WGPUCommandEncoderDescriptor encDesc = {};
            WGPUCommandEncoder enc = wgpuDeviceCreateCommandEncoder(m_device, &encDesc);
            if (!enc) return false;

            // Snapshot CPU time as close to the GPU work as possible.
            outCpuTime = static_cast<uint64_t>(Profiler::GetTime());

            // NOTE: m_querySet slot 0 is used by Anchor(), but it can be immediately
            // reclaimed/reused since Anchor() operates synchronously
            wgpuCommandEncoderWriteTimestamp(enc, m_querySet, 0);
            wgpuCommandEncoderResolveQuerySet(enc, m_querySet, 0, 1, m_resolveBuffer, 0);
            wgpuCommandEncoderCopyBufferToBuffer(enc, m_resolveBuffer, 0, m_readbackBuffer, 0, sizeof(uint64_t));

            WGPUCommandBufferDescriptor cmdDesc = {};
            WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(enc, &cmdDesc);
            wgpuCommandEncoderRelease(enc);
            if (!cmd) return false;

            wgpuQueueSubmit(m_queue, 1, &cmd);
            wgpuCommandBufferRelease(cmd);

            // Map and pump.
            struct MapCtx { std::atomic<int> status{-1}; };
            MapCtx mctx;

            WGPUBufferMapCallbackInfo cbInfo = {};
            cbInfo.mode = WGPUCallbackMode_AllowProcessEvents;
            cbInfo.callback = [](WGPUMapAsyncStatus status, WGPUStringView /*msg*/, void* userdata1, void* /*userdata2*/) {
                auto* c = static_cast<MapCtx*>(userdata1);
                c->status.store(static_cast<int>(status), std::memory_order_release);
            };
            cbInfo.userdata1 = &mctx;

            wgpuBufferMapAsync(m_readbackBuffer, WGPUMapMode_Read, 0, sizeof(uint64_t), cbInfo);

            // Pump until the callback fires (with a generous timeout).
            const auto t0 = std::chrono::steady_clock::now();
            while (mctx.status.load(std::memory_order_acquire) < 0)
            {
                ProcessEvents();
                if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(2))
                {
                    TracyWebGPUPanic("Timed out waiting for anchor timestamp readback.", return false);
                }
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }

            if (mctx.status.load(std::memory_order_acquire) != static_cast<int>(WGPUMapAsyncStatus_Success))
            {
                TracyWebGPUPanic("Failed to map anchor readback buffer.", return false);
            }

            const void* mapped = wgpuBufferGetConstMappedRange(m_readbackBuffer, 0, sizeof(uint64_t));
            if (!mapped)
            {
                wgpuBufferUnmap(m_readbackBuffer);
                return false;
            }
            uint64_t gpuTs;
            std::memcpy(&gpuTs, mapped, sizeof(uint64_t));
            wgpuBufferUnmap(m_readbackBuffer);

            outGpuTime = gpuTs;
            return true;
        }

    public:
        WebGPUQueueCtx(WGPUInstance instance, WGPUDevice device, WGPUQueue queue)
            : m_instance(instance)
            , m_device(device)
            , m_queue(queue)
        {
            ZoneScopedC(Color::Red4);

            // The canonical webgpu.h uses AddRef/Release for refcounting.
            if (m_instance) wgpuInstanceAddRef(m_instance);
            wgpuDeviceAddRef(m_device);
            wgpuQueueAddRef(m_queue);

            // Pick a query budget. WebGPU has no native upper bound on query
            // set size in the spec, but per-implementation maxQueriesPerQuerySet
            // is typically 8192. We start at 64K and halve on failure, mirroring
            // D3D12. Queries are issued in (begin, end) pairs, so the count is
            // always even.
            static constexpr uint32_t MaxQueries = 64 * 1024;
            m_queryLimit = MaxQueries;

            WGPUQuerySetDescriptor qsDesc = {};
            qsDesc.type  = WGPUQueryType_Timestamp;
            qsDesc.count = m_queryLimit;

            for (;;)
            {
                m_querySet = wgpuDeviceCreateQuerySet(m_device, &qsDesc);
                if (m_querySet) break;
                m_queryLimit /= 2;
                qsDesc.count = m_queryLimit;
                if (m_queryLimit < 64)
                {
                    TracyWebGPUPanic("Failed to create timestamp query set (timestamp-query feature missing?).", return);
                }
            }

            // Resolve buffer: the GPU resolves query results into this buffer.
            WGPUBufferDescriptor resolveDesc = {};
            resolveDesc.usage = WGPUBufferUsage_QueryResolve | WGPUBufferUsage_CopySrc;
            resolveDesc.size  = static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t);
            m_resolveBuffer = wgpuDeviceCreateBuffer(m_device, &resolveDesc);
            if (!m_resolveBuffer)
            {
                TracyWebGPUPanic("Failed to create timestamp resolve buffer.", return);
            }

            // Readback buffer: target of CopyBufferToBuffer; mappable for read.
            WGPUBufferDescriptor readbackDesc = {};
            readbackDesc.usage = WGPUBufferUsage_CopyDst | WGPUBufferUsage_MapRead;
            readbackDesc.size  = static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t);
            m_readbackBuffer = wgpuDeviceCreateBuffer(m_device, &readbackDesc);
            if (!m_readbackBuffer)
            {
                TracyWebGPUPanic("Failed to create timestamp readback buffer.", return);
            }

            // Establish the (cpuTime, gpuTime) anchor for Tracy's GpuNewContext.
            // WebGPU has no "clock calibration API", so we use a one-shot anchor
            // to estimate a correlation for the CPU and the GPU timestamps.
            uint64_t cpuTimestamp = 0;
            uint64_t gpuTimestamp = 0;
            if (!Anchor(cpuTimestamp, gpuTimestamp))
            {
                TracyWebGPUPanic("Failed to establish CPU/GPU timestamp anchor.", return);
            }

            m_shadowBuffer.resize(m_queryLimit, gpuTimestamp);
            m_latestKnownGpuTimestamp = gpuTimestamp;

            // WebGPU timestamps are in nanoseconds, as per the spec.
            const float period = 1.0f;  // 1ns/tick

            // All setup completed: register the context.
            m_contextId = GetGpuCtxCounter().fetch_add(1);
            ZoneValue(m_contextId);

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuNewContext);
            MemWrite(&item->gpuNewContext.cpuTime, static_cast<int64_t>(cpuTimestamp));
            MemWrite(&item->gpuNewContext.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuNewContext.thread, static_cast<uint32_t>(0));
            MemWrite(&item->gpuNewContext.period, period);
            MemWrite(&item->gpuNewContext.context, static_cast<uint8_t>(GetId()));
            MemWrite(&item->gpuNewContext.flags, static_cast<uint8_t>(0));  // no calibration available
            MemWrite(&item->gpuNewContext.type, static_cast<uint8_t>(GpuContextType::WebGPU));
            SubmitQueueItem(item);
        }

        ~WebGPUQueueCtx()
        {
            ZoneScopedC(Color::Red4);
            ZoneValue(m_contextId);

            // Drain pending queries.
            uint64_t endTicket = m_queryCounter;
            uint64_t lastIssuedTicket = (endTicket >= 2) ? (endTicket - 2) : 0;
            Drain(lastIssuedTicket, 200);

            if (Distance(endTicket, m_queryCounter) > 0)
                TracyWebGPUPanic("client is still pushing queries.");

            // If the readback buffer is mapped, unmap it before release.
            if (m_readbackBuffer && m_mapState.load() == MapState::Ready)
            {
                wgpuBufferUnmap(m_readbackBuffer);
                m_mapState.store(MapState::Idle);
            }

            if (m_readbackBuffer) { wgpuBufferRelease(m_readbackBuffer); m_readbackBuffer = nullptr; }
            if (m_resolveBuffer)  { wgpuBufferRelease(m_resolveBuffer);  m_resolveBuffer  = nullptr; }
            if (m_querySet)       { wgpuQuerySetRelease(m_querySet);     m_querySet       = nullptr; }
            if (m_queue)          { wgpuQueueRelease(m_queue);           m_queue          = nullptr; }
            if (m_device)         { wgpuDeviceRelease(m_device);         m_device         = nullptr; }
            if (m_instance)       { wgpuInstanceRelease(m_instance);     m_instance       = nullptr; }
        }

        tracy_force_inline uint8_t GetId() const
        {
            return m_contextId;
        }

        void Name(const char* name, uint16_t len)
        {
            auto ptr = (char*)tracy_malloc(len);
            memcpy(ptr, name, len);

            auto item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuContextName);
            MemWrite(&item->gpuContextNameFat.context, GetId());
            MemWrite(&item->gpuContextNameFat.ptr, (uint64_t)ptr);
            MemWrite(&item->gpuContextNameFat.size, len);
            SubmitQueueItem(item);
        }

        void Collect()
        {
#ifdef TRACY_ON_DEMAND
            if (!GetProfiler().IsConnected()) return;
#endif
            if (!m_collectionMutex.try_lock()) return;
            std::unique_lock lock(m_collectionMutex, std::adopt_lock);
            Collect(lock, m_queryCounter, false);
        }

    private:
        // Issue (or progress) the readback for the range [earliest, end). On
        // entry, the buffer is in some MapState; on return, if a complete
        // readback was performed, queries up to the resolved point are emitted
        // to Tracy and m_previousCheckpoint is advanced.
        //
        // Strategy:
        //   * If MapState::Idle, kick off a CopyBufferToBuffer + MapAsync for
        //     the unread range. Pump events briefly so the callback can land
        //     before we return. This is the steady-state code path.
        //   * If MapState::Pending, just pump events.
        //   * If MapState::Ready, read the timestamps, unmap, mark Idle.
        //   * If MapState::Failed, reset to Idle and bail.
        void Collect(std::unique_lock<std::mutex>& lock, uint64_t targetTicket, bool urgent)
        {
            ZoneScopedC(Color::Red4);
            TracyWebGPUAssert(lock.owns_lock());
            TracyWebGPUDebug(ZoneValue(m_contextId));

            uint64_t earliestTicket = m_previousCheckpoint;
            uint64_t endTicket = m_queryCounter;
            if (Distance(earliestTicket, endTicket) <= 0)
                return;

            // Drive the state machine. If the buffer is already mapped, harvest
            // it. Otherwise, kick off a new map for the current unread range.
            MapState state = m_mapState.load(std::memory_order_acquire);

            if (state == MapState::Failed)
            {
                // Try again next time.
                m_mapState.store(MapState::Idle, std::memory_order_release);
                return;
            }

            if (state == MapState::Idle)
            {
                if (!IssueReadback(earliestTicket, endTicket))
                    return;
                state = m_mapState.load(std::memory_order_acquire);
            }

            // If we're in urgent mode, pump until we get a Ready or Failed.
            if (urgent && state == MapState::Pending)
            {
                const auto t0 = std::chrono::steady_clock::now();
                while ((state = m_mapState.load(std::memory_order_acquire)) == MapState::Pending)
                {
                    ProcessEvents();
                    if (std::chrono::steady_clock::now() - t0 > std::chrono::seconds(1))
                    {
                        TracyWebGPULog(Warning, "Timed out waiting for urgent timestamp readback.");
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                }
            }
            else if (state == MapState::Pending)
            {
                // Non-urgent: pump once and bail; the callback may land later.
                ProcessEvents();
                state = m_mapState.load(std::memory_order_acquire);
                if (state != MapState::Ready) return;
            }

            if (state != MapState::Ready) return;

            // We have a mapped range covering [m_pendingFirst, m_pendingLast).
            HarvestMappedRange(targetTicket, urgent);

            // After we've drained, stop. The next Collect() will issue a new
            // readback for whatever has accumulated since.
        }

        // Set when the most recent IssueReadback was called.
        uint64_t m_pendingFirstTicket = 0;
        uint64_t m_pendingEndTicket   = 0;

        // Issue a CopyBufferToBuffer + MapAsync for query slots in [first, end).
        // Note: 'first' and 'end' are ticket numbers (logical, monotonic).
        // Their wrapped slot indices may straddle the end of the ring buffer;
        // in that case we issue two separate copies.
        bool IssueReadback(uint64_t first, uint64_t end)
        {
            const int64_t span = Distance(first, end);
            if (span <= 0) return false;

            // Cap the readback to the ring's size. If span > capacity, the older
            // entries will have been overwritten in the resolve buffer, so we
            // can only meaningfully read the most recent capacity worth of
            // entries.
            uint64_t actualFirst = first;
            if (static_cast<uint64_t>(span) > RingCapacity())
            {
                actualFirst = end - RingCapacity();
            }

            const uint32_t firstSlot = RingIndex(actualFirst);
            const uint32_t lastSlot  = RingIndex(end);  // exclusive end
            const uint32_t cap       = RingCapacity();

            WGPUCommandEncoderDescriptor encDesc = {};
            WGPUCommandEncoder enc = wgpuDeviceCreateCommandEncoder(m_device, &encDesc);
            if (!enc) return false;

            // Either a single contiguous copy, or two copies that wrap around.
            if (firstSlot < lastSlot || lastSlot == 0)
            {
                const uint32_t count = (lastSlot == 0) ? (cap - firstSlot) : (lastSlot - firstSlot);
                wgpuCommandEncoderCopyBufferToBuffer(
                    enc,
                    m_resolveBuffer,
                    static_cast<uint64_t>(firstSlot) * sizeof(uint64_t),
                    m_readbackBuffer,
                    static_cast<uint64_t>(firstSlot) * sizeof(uint64_t),
                    static_cast<uint64_t>(count) * sizeof(uint64_t));
            }
            else
            {
                // Wrap: [firstSlot, cap) and [0, lastSlot).
                wgpuCommandEncoderCopyBufferToBuffer(
                    enc,
                    m_resolveBuffer,
                    static_cast<uint64_t>(firstSlot) * sizeof(uint64_t),
                    m_readbackBuffer,
                    static_cast<uint64_t>(firstSlot) * sizeof(uint64_t),
                    static_cast<uint64_t>(cap - firstSlot) * sizeof(uint64_t));
                wgpuCommandEncoderCopyBufferToBuffer(
                    enc,
                    m_resolveBuffer,
                    0,
                    m_readbackBuffer,
                    0,
                    static_cast<uint64_t>(lastSlot) * sizeof(uint64_t));
            }

            WGPUCommandBufferDescriptor cmdDesc = {};
            WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(enc, &cmdDesc);
            wgpuCommandEncoderRelease(enc);
            if (!cmd) return false;

            wgpuQueueSubmit(m_queue, 1, &cmd);
            wgpuCommandBufferRelease(cmd);

            // Map the entire buffer (covers both contiguous and wrapped cases).
            // We could be tighter and map just the touched range(s), but the
            // single-range MapAsync makes the wrap case awkward, so we map all.
            m_pendingFirstTicket = actualFirst;
            m_pendingEndTicket   = end;
            m_mapState.store(MapState::Pending, std::memory_order_release);

            WGPUBufferMapCallbackInfo cbInfo = {};
            cbInfo.mode = WGPUCallbackMode_AllowProcessEvents;
            cbInfo.callback = &WebGPUQueueCtx::OnMapped;
            cbInfo.userdata1 = this;

            wgpuBufferMapAsync(
                m_readbackBuffer,
                WGPUMapMode_Read,
                0,
                static_cast<uint64_t>(cap) * sizeof(uint64_t),
                cbInfo);

            // A single pump in case the callback can fire immediately.
            ProcessEvents();
            return true;
        }

        static void OnMapped(WGPUMapAsyncStatus status, WGPUStringView /*msg*/, void* userdata1, void* /*userdata2*/)
        {
            auto* self = static_cast<WebGPUQueueCtx*>(userdata1);
            if (status == WGPUMapAsyncStatus_Success)
                self->m_mapState.store(MapState::Ready, std::memory_order_release);
            else
                self->m_mapState.store(MapState::Failed, std::memory_order_release);
        }

        void HarvestMappedRange(uint64_t targetTicket, bool urgent)
        {
            const uint32_t cap = RingCapacity();
            const void* mapped = wgpuBufferGetConstMappedRange(
                m_readbackBuffer, 0, static_cast<uint64_t>(cap) * sizeof(uint64_t));

            if (!mapped)
            {
                wgpuBufferUnmap(m_readbackBuffer);
                m_mapState.store(MapState::Idle, std::memory_order_release);
                TracyWebGPUPanic("Failed to read mapped readback buffer.", return);
            }

            const uint64_t* timestampBuffer = static_cast<const uint64_t*>(mapped);

            uint64_t ticket = m_pendingFirstTicket;
            const uint64_t end = m_pendingEndTicket;

            for (; ticket != end; ticket += 2)
            {
                if (!ResolveTimestamp(ticket, timestampBuffer))
                    break;
            }

            // Urgent: ensure 'targetTicket' is collected before returning.
            if (urgent)
            {
                while (Distance(ticket, targetTicket) >= 0)
                {
                    DropTimestamp(ticket, timestampBuffer);
                    ticket += 2;
                }
            }

            // Overflow handling: drop oldest queries to normalize the situation.
            uint64_t curEnd = m_queryCounter;
            while (Distance(ticket, curEnd) > static_cast<int64_t>(RingCapacity()))
            {
                DropTimestamp(ticket, timestampBuffer);
                ticket += 2;
            }

            wgpuBufferUnmap(m_readbackBuffer);
            m_mapState.store(MapState::Idle, std::memory_order_release);
        }

        bool Wait(uint64_t queryTicket, uint64_t timeout_ms)
        {
            ZoneScopedC(Color::Red4);
            const auto t0 = std::chrono::steady_clock::now();
            int64_t elapsed = 0;
            while ((Distance(m_previousCheckpoint, queryTicket) >= 0)
                   && (static_cast<uint64_t>(elapsed) < timeout_ms))
            {
                std::unique_lock lock(m_collectionMutex);
                Collect(lock, queryTicket, false);
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::microseconds(100));
                elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
            }
            return Distance(m_previousCheckpoint, queryTicket) < 0;
        }

        void Drain(uint64_t queryTicket, uint64_t gracePeriod_ms)
        {
            ZoneScopedC(Color::Red4);
            if (Wait(queryTicket, gracePeriod_ms))
                return;
            std::unique_lock lock(m_collectionMutex);
            Collect(lock, queryTicket, true);
        }

        bool ResolveTimestamp(uint64_t queryTicket, const uint64_t* timestampBuffer)
        {
            uint32_t queryId = RingIndex(queryTicket);
            uint64_t gpuZoneBeginTimestamp = timestampBuffer[queryId];
            uint64_t gpuZoneEndTimestamp   = timestampBuffer[queryId + 1];
            uint64_t baselineTimestamp     = m_shadowBuffer[queryId + 1];
            int64_t  baseline_diff = Distance(baselineTimestamp, gpuZoneEndTimestamp);
            if (baseline_diff <= 0)
                return false;
            EmitGpuTime(gpuZoneBeginTimestamp, queryId);
            EmitGpuTime(gpuZoneEndTimestamp,   queryId + 1);
            RetireTicket(queryTicket);
            if (Distance(m_latestKnownGpuTimestamp, gpuZoneEndTimestamp) > 0)
                m_latestKnownGpuTimestamp = gpuZoneEndTimestamp;
            return true;
        }

        void DropTimestamp(uint64_t queryTicket, const uint64_t* timestampBuffer)
        {
            if (ResolveTimestamp(queryTicket, timestampBuffer))
                return;
            uint32_t queryId = RingIndex(queryTicket);
            uint64_t latestGpuTimestamp = m_latestKnownGpuTimestamp;
            EmitGpuTime(latestGpuTimestamp, queryId);
            EmitGpuTime(latestGpuTimestamp, queryId + 1);
            RetireTicket(queryTicket);
        }

        void EmitGpuTime(uint64_t gpuTimestamp, uint32_t queryId)
        {
            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuTime);
            MemWrite(&item->gpuTime.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuTime.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuTime.context, GetId());
            Profiler::QueueSerialFinish();
            m_shadowBuffer[queryId] = gpuTimestamp;
        }

        tracy_force_inline uint32_t RingCapacity() const
        {
            return m_queryLimit;
        }

        tracy_force_inline uint32_t RingIndex(uint64_t logicalSlot) const
        {
            return static_cast<uint32_t>(logicalSlot % RingCapacity());
        }

        tracy_force_inline static int64_t Distance(uint64_t begin, uint64_t end)
        {
            return static_cast<int64_t>(end - begin);
        }

        void RetireTicket(uint64_t ticket)
        {
            TracyWebGPUAssert(m_previousCheckpoint == ticket);
            uint64_t nextTicket = ticket + 2;
            m_previousCheckpoint.store(nextTicket, std::memory_order_release);
        }

        tracy_force_inline uint32_t NextQueryId()
        {
            const uint64_t ticket = m_queryCounter.fetch_add(2, std::memory_order_relaxed);
            const uint64_t checkpoint = m_previousCheckpoint.load(std::memory_order_relaxed);
            if (Distance(checkpoint, ticket) >= static_cast<int64_t>(RingCapacity()))
            {
                ZoneScopedC(Color::Red4);
                TracyWebGPULog(Warning, "Too many pending GPU queries: stalling!");
                uint64_t oldTicket = ticket - RingCapacity();
                Drain(oldTicket, 0);
            }
            return RingIndex(ticket);
        }
    };

    class WebGPUZoneScope
    {
        const bool m_active;
        WebGPUQueueCtx* m_ctx = nullptr;
        WGPUCommandEncoder m_encoder = nullptr;
        uint32_t m_queryId = 0;

        tracy_force_inline void WriteQueueItem(const SourceLocationData* srcLocation, int32_t callstackDepth, uint32_t sourceLine, const char* sourceFile, size_t sourceFileLen, const char* functionName, size_t functionNameLen, const char* zoneName, size_t zoneNameLen)
        {
            if (!m_active) return;

            const bool captureCallstack = callstackDepth > 0 && has_callstack();
            const bool transientZone = srcLocation == nullptr;
            uint64_t srcLocationAddr = reinterpret_cast<uint64_t>(srcLocation);

            QueueItem* item = nullptr;
            QueueType itemType;
            if (transientZone)
            {
                srcLocationAddr = Profiler::AllocSourceLocation(sourceLine, sourceFile, sourceFileLen, functionName, functionNameLen, zoneName, zoneNameLen);
                if (captureCallstack)
                {
                    item = Profiler::QueueSerialCallstack(Callstack(callstackDepth));
                    itemType = QueueType::GpuZoneBeginAllocSrcLocCallstackSerial;
                }
                else
                {
                    item = Profiler::QueueSerial();
                    itemType = QueueType::GpuZoneBeginAllocSrcLocSerial;
                }
            }
            else
            {
                if (captureCallstack)
                {
                    item = Profiler::QueueSerialCallstack(Callstack(callstackDepth));
                    itemType = QueueType::GpuZoneBeginCallstackSerial;
                }
                else
                {
                    item = Profiler::QueueSerial();
                    itemType = QueueType::GpuZoneBeginSerial;
                }
            }

            MemWrite(&item->hdr.type, itemType);
            MemWrite(&item->gpuZoneBegin.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneBegin.srcloc, srcLocationAddr);
            MemWrite(&item->gpuZoneBegin.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneBegin.queryId, static_cast<uint16_t>(m_queryId));
            MemWrite(&item->gpuZoneBegin.context, m_ctx->GetId());
            Profiler::QueueSerialFinish();
        }

        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, WGPUCommandEncoder encoder, bool active)
#ifdef TRACY_ON_DEMAND
            : m_active(active && GetProfiler().IsConnected())
#else
            : m_active(active)
#endif
        {
            if (!m_active) return;

            m_ctx = ctx;
            m_encoder = encoder;

            m_queryId = m_ctx->NextQueryId();
            wgpuCommandEncoderWriteTimestamp(m_encoder, m_ctx->m_querySet, m_queryId);
        }

    public:
        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, WGPUCommandEncoder encoder, const SourceLocationData* srcLocation, bool active)
            : WebGPUZoneScope(ctx, encoder, active)
        {
            WriteQueueItem(srcLocation, 0, 0, nullptr, 0, nullptr, 0, nullptr, 0);
        }

        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, WGPUCommandEncoder encoder, const SourceLocationData* srcLocation, int32_t depth, bool active)
            : WebGPUZoneScope(ctx, encoder, active)
        {
            WriteQueueItem(srcLocation, depth, 0, nullptr, 0, nullptr, 0, nullptr, 0);
        }

        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, WGPUCommandEncoder encoder, bool active)
            : WebGPUZoneScope(ctx, encoder, active)
        {
            WriteQueueItem(nullptr, 0, line, source, sourceSz, function, functionSz, name, nameSz);
        }

        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, WGPUCommandEncoder encoder, int32_t depth, bool active)
            : WebGPUZoneScope(ctx, encoder, active)
        {
            WriteQueueItem(nullptr, depth, line, source, sourceSz, function, functionSz, name, nameSz);
        }

        tracy_force_inline ~WebGPUZoneScope()
        {
            if (!m_active) return;

            const auto queryId = m_queryId + 1;

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneEndSerial);
            MemWrite(&item->gpuZoneEnd.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneEnd.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneEnd.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuZoneEnd.context, m_ctx->GetId());
            Profiler::QueueSerialFinish();

            // Write the end timestamp and resolve the (begin, end) pair into
            // the resolve buffer right away. We cannot move the resolve to
            // Collect() because the user may finish/destroy the encoder
            // immediately after the zone closes, and ResolveQuerySet must be
            // recorded into an encoder belonging to the same submission as the
            // timestamp writes if we want to read the values for THIS zone in
            // the same frame. Recording it here also matches the D3D12 backend.
            wgpuCommandEncoderWriteTimestamp(m_encoder, m_ctx->m_querySet, queryId);
            wgpuCommandEncoderResolveQuerySet(
                m_encoder,
                m_ctx->m_querySet,
                m_queryId, 2,
                m_ctx->m_resolveBuffer,
                static_cast<uint64_t>(m_queryId) * sizeof(uint64_t));
        }
    };

    static inline void DestroyWebGPUContext(WebGPUQueueCtx* ctx)
    {
        TracyWebGPUAssert(ctx);
        ctx->~WebGPUQueueCtx();
        tracy_free(ctx);
    }

    static inline WebGPUQueueCtx* CreateWebGPUContext(WGPUInstance instance, WGPUDevice device, WGPUQueue queue)
    {
        auto* ctx = static_cast<WebGPUQueueCtx*>(tracy_malloc(sizeof(WebGPUQueueCtx)));
        new (ctx) WebGPUQueueCtx{ instance, device, queue };
        if (ctx->GetId() == 255)
        {
            DestroyWebGPUContext(ctx);
            return nullptr;
        }
        return ctx;
    }

}

#undef TracyWebGPUPanic
#undef TracyWebGPULog
#undef TracyWebGPUAssert
#undef TracyWebGPUBreak
#undef TracyWebGPUDebug
#undef TRACY_WEBGPU_DEBUG_LEVEL

using TracyWebGPUCtx = tracy::WebGPUQueueCtx*;

#define TracyWebGPUContext(instance, device, queue) tracy::CreateWebGPUContext(instance, device, queue);
#define TracyWebGPUDestroy(ctx) tracy::DestroyWebGPUContext(ctx);
#define TracyWebGPUContextName(ctx, name, size) ctx->Name(name, size);

#define TracyWebGPUNewFrame(ctx) ((void)(ctx))

#define TracyWebGPUUnnamedZone ___tracy_gpu_webgpu_zone
#define TracyWebGPUSrcLocSymbol TracyConcat(__tracy_webgpu_source_location,TracyLine)
#define TracyWebGPUSrcLocObject(name, color) static constexpr tracy::SourceLocationData TracyWebGPUSrcLocSymbol { name, TracyFunction, TracyFile, (uint32_t)TracyLine, color };

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyWebGPUZone(ctx, encoder, name) TracyWebGPUNamedZoneS(ctx, TracyWebGPUUnnamedZone, encoder, name, TRACY_CALLSTACK, true)
#  define TracyWebGPUZoneC(ctx, encoder, name, color) TracyWebGPUNamedZoneCS(ctx, TracyWebGPUUnnamedZone, encoder, name, color, TRACY_CALLSTACK, true)
#  define TracyWebGPUNamedZone(ctx, varname, encoder, name, active) TracyWebGPUSrcLocObject(name, 0); tracy::WebGPUZoneScope varname{ ctx, encoder, &TracyWebGPUSrcLocSymbol, TRACY_CALLSTACK, active };
#  define TracyWebGPUNamedZoneC(ctx, varname, encoder, name, color, active) TracyWebGPUSrcLocObject(name, color); tracy::WebGPUZoneScope varname{ ctx, encoder, &TracyWebGPUSrcLocSymbol, TRACY_CALLSTACK, active };
#  define TracyWebGPUZoneTransient(ctx, varname, encoder, name, active) TracyWebGPUZoneTransientS(ctx, varname, encoder, name, TRACY_CALLSTACK, active)
#else
#  define TracyWebGPUZone(ctx, encoder, name) TracyWebGPUNamedZone(ctx, TracyWebGPUUnnamedZone, encoder, name, true)
#  define TracyWebGPUZoneC(ctx, encoder, name, color) TracyWebGPUNamedZoneC(ctx, TracyWebGPUUnnamedZone, encoder, name, color, true)
#  define TracyWebGPUNamedZone(ctx, varname, encoder, name, active) TracyWebGPUSrcLocObject(name, 0); tracy::WebGPUZoneScope varname{ ctx, encoder, &TracyWebGPUSrcLocSymbol, active };
#  define TracyWebGPUNamedZoneC(ctx, varname, encoder, name, color, active) TracyWebGPUSrcLocObject(name, color); tracy::WebGPUZoneScope varname{ ctx, encoder, &TracyWebGPUSrcLocSymbol, active };
#  define TracyWebGPUZoneTransient(ctx, varname, encoder, name, active) tracy::WebGPUZoneScope varname{ ctx, TracyLine, TracyFile, strlen(TracyFile), TracyFunction, strlen(TracyFunction), name, strlen(name), encoder, active };
#endif

#ifdef TRACY_HAS_CALLSTACK
#  define TracyWebGPUZoneS(ctx, encoder, name, depth) TracyWebGPUNamedZoneS(ctx, TracyWebGPUUnnamedZone, encoder, name, depth, true)
#  define TracyWebGPUZoneCS(ctx, encoder, name, color, depth) TracyWebGPUNamedZoneCS(ctx, TracyWebGPUUnnamedZone, encoder, name, color, depth, true)
#  define TracyWebGPUNamedZoneS(ctx, varname, encoder, name, depth, active) TracyWebGPUSrcLocObject(name, 0); tracy::WebGPUZoneScope varname{ ctx, encoder, &TracyWebGPUSrcLocSymbol, depth, active };
#  define TracyWebGPUNamedZoneCS(ctx, varname, encoder, name, color, depth, active) TracyWebGPUSrcLocObject(name, color); tracy::WebGPUZoneScope varname{ ctx, encoder, &TracyWebGPUSrcLocSymbol, depth, active };
#  define TracyWebGPUZoneTransientS(ctx, varname, encoder, name, depth, active) tracy::WebGPUZoneScope varname{ ctx, TracyLine, TracyFile, strlen(TracyFile), TracyFunction, strlen(TracyFunction), name, strlen(name), encoder, depth, active };
#else
#  define TracyWebGPUZoneS(ctx, encoder, name, depth) TracyWebGPUZone(ctx, encoder, name)
#  define TracyWebGPUZoneCS(ctx, encoder, name, color, depth) TracyWebGPUZoneC(ctx, encoder, name, color)
#  define TracyWebGPUNamedZoneS(ctx, varname, encoder, name, depth, active) TracyWebGPUNamedZone(ctx, varname, encoder, name, active)
#  define TracyWebGPUNamedZoneCS(ctx, varname, encoder, name, color, depth, active) TracyWebGPUNamedZoneC(ctx, varname, encoder, name, color, active)
#  define TracyWebGPUZoneTransientS(ctx, varname, encoder, name, depth, active) TracyWebGPUZoneTransient(ctx, varname, encoder, name, active)
#endif

#define TracyWebGPUCollect(ctx) ctx->Collect();

#endif

#endif
