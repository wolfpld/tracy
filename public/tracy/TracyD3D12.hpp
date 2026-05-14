#ifndef __TRACYD3D12_HPP__
#define __TRACYD3D12_HPP__

#ifndef TRACY_ENABLE

#define TracyD3D12Context(device, queue) nullptr
#define TracyD3D12Destroy(ctx)
#define TracyD3D12ContextName(ctx, name, size)

#define TracyD3D12NewFrame(ctx)

#define TracyD3D12Zone(ctx, cmdList, name)
#define TracyD3D12ZoneC(ctx, cmdList, name, color)
#define TracyD3D12NamedZone(ctx, varname, cmdList, name, active)
#define TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active)
#define TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active)

#define TracyD3D12ZoneS(ctx, cmdList, name, depth)
#define TracyD3D12ZoneCS(ctx, cmdList, name, color, depth)
#define TracyD3D12NamedZoneS(ctx, varname, cmdList, name, depth, active)
#define TracyD3D12NamedZoneCS(ctx, varname, cmdList, name, color, depth, active)
#define TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, depth, active)

#define TracyD3D12Collect(ctx)

namespace tracy
{
    class D3D12ZoneScope {};
}

using TracyD3D12Ctx = void*;

#else

#include "Tracy.hpp"
#include "../client/TracyFastVector.hpp"

#include <atomic>
#include <mutex>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <d3d12.h>
#include <dxgi.h>

#ifndef TRACY_D3D12_DEBUG_LEVEL
#define TRACY_D3D12_DEBUG_LEVEL (0)
#endif//TRACY_D3D12_DEBUG_LEVEL

#ifndef TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
#define TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER (1)
#endif//TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER

#if TRACY_D3D12_DEBUG_LEVEL
#   define TracyD3D12Debug(...) __VA_ARGS__;
#   ifdef _MSC_VER
#       define TracyD3D12Break() if (IsDebuggerPresent()) __debugbreak()
#   else
#       define TracyD3D12Break() /* TODO */
#   endif
#   define TracyD3D12Assert(predicate, ...) if (predicate) {} else { __VA_ARGS__; TracyD3D12Break(); }
#else
#   define TracyD3D12Debug(...)
#   define TracyD3D12Break()
#   define TracyD3D12Assert(predicate, ...) assert(predicate);
#endif

#define TracyD3D12Log(severity, msg) tracy::Profiler::LogString( tracy::MessageSourceType::Tracy, tracy::MessageSeverity::severity, tracy::Color::Red4, 0, msg );
#define TracyD3D12Panic(msg, ...) do { TracyD3D12Log(Error, msg); TracyD3D12Assert(false && "TracyD3D12: " msg); __VA_ARGS__; } while(false);

namespace tracy
{

    // Command queue context.
    class D3D12QueueCtx
    {
        friend class D3D12ZoneScope;

        uint8_t m_contextId = 255;  // 255 represents "invalid id"

        std::mutex m_collectionMutex;

        ID3D12Device* m_device = nullptr;
        ID3D12CommandQueue* m_queue = nullptr;
        ID3D12QueryHeap* m_queryHeap = nullptr;
        ID3D12Resource* m_readbackBuffer = nullptr;

#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
        UINT64* m_persistentTimestampBuffer = nullptr;
#endif

        using atomic_counter = std::atomic<uint64_t>;
        atomic_counter m_queryCounter = 0;
        atomic_counter m_previousCheckpoint = 0;

        uint32_t m_queryLimit = 64 * 1024;  // Must be even: each scope is a (begin, end) pair of queries

        FastVector<UINT64> m_shadowBuffer;
        UINT64 m_latestKnownGpuTimestamp = 0;

        UINT64 m_prevCalibrationTicksCPU = 0;

        void RecalibrateClocks()
        {
            UINT64 cpuTimestamp;
            UINT64 gpuTimestamp;
            if (FAILED(m_queue->GetClockCalibration(&gpuTimestamp, &cpuTimestamp)))
            {
                TracyD3D12Panic("failed to obtain queue clock calibration counters.", return);
            }

            int64_t cpuDeltaTicks = cpuTimestamp - m_prevCalibrationTicksCPU;
            if (cpuDeltaTicks > 0)
            {
                // WARNING: technically, we should not emit a GpuCalibration event if the GPU counter
                // did not move, to prevent division by a gpuDelta of zero in later on (in the server).
                // In practice, GetClockCalibration() should be advancing CPU and GPU together.

                static const int64_t nanosecodsPerTick = int64_t(1000000000) / GetFrequencyQpc();
                int64_t cpuDeltaNS = cpuDeltaTicks * nanosecodsPerTick;
                // Save the device cpu timestamp, not the Tracy profiler timestamp:
                m_prevCalibrationTicksCPU = cpuTimestamp;

                cpuTimestamp = Profiler::GetTime();

                auto* item = Profiler::QueueSerial();
                MemWrite(&item->hdr.type, QueueType::GpuCalibration);
                MemWrite(&item->gpuCalibration.gpuTime, gpuTimestamp);
                MemWrite(&item->gpuCalibration.cpuTime, cpuTimestamp);
                MemWrite(&item->gpuCalibration.cpuDelta, cpuDeltaNS);
                MemWrite(&item->gpuCalibration.context, GetId());
                SubmitQueueItem(item);
            }
        }

        tracy_force_inline void SubmitQueueItem(tracy::QueueItem* item)
        {
#ifdef TRACY_ON_DEMAND
            GetProfiler().DeferItem(*item);
#endif
            Profiler::QueueSerialFinish();
        }

    public:
        D3D12QueueCtx(ID3D12Device* device, ID3D12CommandQueue* queue)
            : m_device(device)
            , m_queue(queue)
            , m_shadowBuffer(m_queryLimit)
        {
            ZoneScopedC(Color::Red4);

            m_queue->AddRef();

            // Verify we support timestamp queries on this queue.
            if (queue->GetDesc().Type == D3D12_COMMAND_LIST_TYPE_COPY)
            {
                D3D12_FEATURE_DATA_D3D12_OPTIONS3 featureData{};
                HRESULT hr = device->CheckFeatureSupport(D3D12_FEATURE_D3D12_OPTIONS3, &featureData, sizeof(featureData));
                if (FAILED(hr) || (featureData.CopyQueueTimestampQueriesSupported == FALSE))
                {
                    TracyD3D12Panic("Platform does not support profiling of copy queues.", return);
                }
            }

            D3D12_QUERY_HEAP_DESC heapDesc{};
            heapDesc.Type = queue->GetDesc().Type == D3D12_COMMAND_LIST_TYPE_COPY ? D3D12_QUERY_HEAP_TYPE_COPY_QUEUE_TIMESTAMP : D3D12_QUERY_HEAP_TYPE_TIMESTAMP;
            heapDesc.Count = m_queryLimit;
            heapDesc.NodeMask = 0;  // #TODO: Support multiple adapters.

            while (FAILED(device->CreateQueryHeap(&heapDesc, IID_PPV_ARGS(&m_queryHeap))))
            {
                m_queryLimit /= 2;
                heapDesc.Count = m_queryLimit;
            }

            // Create a readback buffer, which will be used as a destination for the query data.

            D3D12_RESOURCE_DESC readbackBufferDesc{};
            readbackBufferDesc.Alignment = 0;
            readbackBufferDesc.Dimension = D3D12_RESOURCE_DIMENSION_BUFFER;
            readbackBufferDesc.Width = m_queryLimit * sizeof(uint64_t);
            readbackBufferDesc.Height = 1;
            readbackBufferDesc.DepthOrArraySize = 1;
            readbackBufferDesc.Format = DXGI_FORMAT_UNKNOWN;
            readbackBufferDesc.Layout = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;  // Buffers are always row major.
            readbackBufferDesc.MipLevels = 1;
            readbackBufferDesc.SampleDesc.Count = 1;
            readbackBufferDesc.SampleDesc.Quality = 0;
            readbackBufferDesc.Flags = D3D12_RESOURCE_FLAG_NONE;

            D3D12_HEAP_PROPERTIES readbackHeapProps{};
            readbackHeapProps.Type = D3D12_HEAP_TYPE_READBACK;
            readbackHeapProps.CPUPageProperty = D3D12_CPU_PAGE_PROPERTY_UNKNOWN;
            readbackHeapProps.MemoryPoolPreference = D3D12_MEMORY_POOL_UNKNOWN;
            readbackHeapProps.CreationNodeMask = 0;
            readbackHeapProps.VisibleNodeMask = 0;  // #TODO: Support multiple adapters.

            if (FAILED(device->CreateCommittedResource(&readbackHeapProps, D3D12_HEAP_FLAG_NONE, &readbackBufferDesc, D3D12_RESOURCE_STATE_COPY_DEST, nullptr, IID_PPV_ARGS(&m_readbackBuffer))))
            {
                TracyD3D12Panic("Failed to create query readback buffer.", return);
            }

            UINT64* timestampBuffer = MapTimestampBuffer();
            if (timestampBuffer == nullptr) return;
            for (uint64_t i = 0; i < m_queryLimit; ++i)
                timestampBuffer[i] = 0;
            UnmapTimestampBuffer(timestampBuffer);

            float period = [queue]()
            {
                uint64_t timestampFrequency;
                if (FAILED(queue->GetTimestampFrequency(&timestampFrequency)))
                {
                    return 0.0f;
                }
                return static_cast<float>( 1E+09 / static_cast<double>(timestampFrequency) );
            }();

            if (period == 0.0f)
            {
                TracyD3D12Panic("Failed to get timestamp frequency.", return);
            }

            uint64_t cpuTimestamp;
            uint64_t gpuTimestamp;
            if (FAILED(queue->GetClockCalibration(&gpuTimestamp, &cpuTimestamp)))
            {
                TracyD3D12Panic("Failed to get queue clock calibration.", return);
            }

            // FastVector: clean/resize/init
            for (size_t i = 0; i < m_queryLimit; ++i) *m_shadowBuffer.push_next() = gpuTimestamp;

            m_latestKnownGpuTimestamp = gpuTimestamp;

            // Save the device cpu timestamp, not the profiler's timestamp.
            m_prevCalibrationTicksCPU = cpuTimestamp;

            cpuTimestamp = Profiler::GetTime();

            // All setup/init checks completed: ready to create the context.
            m_contextId = GetGpuCtxCounter().fetch_add(1);
            ZoneValue(m_contextId);

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuNewContext);
            MemWrite(&item->gpuNewContext.cpuTime, static_cast<int64_t>(cpuTimestamp));
            MemWrite(&item->gpuNewContext.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuNewContext.thread, static_cast<uint32_t>(0)); // zero means the context is not associated with a specific thread
            MemWrite(&item->gpuNewContext.period, static_cast<float>(period));
            MemWrite(&item->gpuNewContext.context, static_cast<uint8_t>(GetId()));
            MemWrite(&item->gpuNewContext.flags, static_cast<uint8_t>(GpuContextCalibration));
            MemWrite(&item->gpuNewContext.type, static_cast<uint8_t>(GpuContextType::Direct3D12));
            SubmitQueueItem(item);
        }

        ~D3D12QueueCtx()
        {
            ZoneScopedC(Color::Red4);
            ZoneValue(m_contextId);

            // TODO: could use queue->Signal() to inject a progress point in the queue
            // and the immediately wait for the signal, in order to avoid busy-waiting
            // (need to create an ID3D12Fence and associate an Event object to it)
            // NOTE: even with Signal(), there are no guarantees the queries were sent
            // to the GPU for execution, so the Signal() does not give us much "signal"
 
            // collect all pending queries up to the latest known query
            uint64_t endTicket = m_queryCounter;
            uint64_t lastIssuedTicket = endTicket - 2;
            Drain(lastIssuedTicket, 200);

            // if the client is still pushing queries past the latest checkpoint above,
            // assume there's a bug in the client, and ignore them (don't collect)
            if (Distance(endTicket, m_queryCounter) > 0)
                TracyD3D12Panic("client is still pushing queries.");

#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            if (m_readbackBuffer)
            {
                D3D12_RANGE fullRange { 0, m_queryLimit * sizeof(UINT64) };
                m_readbackBuffer->Unmap(0, &fullRange);
                m_persistentTimestampBuffer = nullptr;
            }
#endif
            if (m_readbackBuffer) m_readbackBuffer->Release();
            if (m_queryHeap) m_queryHeap->Release();
            m_queue->Release();
        }

        tracy_force_inline uint8_t GetId() const
        {
            return m_contextId;
        }

        void Name( const char* name, uint16_t len )
        {
            auto ptr = (char*)tracy_malloc( len );
            memcpy( ptr, name, len );

            auto item = Profiler::QueueSerial();
            MemWrite( &item->hdr.type, QueueType::GpuContextName );
            MemWrite( &item->gpuContextNameFat.context, GetId());
            MemWrite( &item->gpuContextNameFat.ptr, (uint64_t)ptr );
            MemWrite( &item->gpuContextNameFat.size, len );
            SubmitQueueItem(item);
        }

        void Collect()
        {
#ifdef TRACY_ON_DEMAND
            if (!GetProfiler().IsConnected()) return;
#endif
            // Only one thread is allowed to collect timestamps at any given time
            // but there's no need to block contending threads
            if (!m_collectionMutex.try_lock()) return;
            std::unique_lock lock (m_collectionMutex, std::adopt_lock);
            uint64_t targetTicket = m_queryCounter;
            Collect(lock, m_queryCounter, false);
        }

    private:
        void Collect(std::unique_lock<std::mutex>& lock, uint64_t targetTicket, bool urgent)
        {
            ZoneScopedC(Color::Red4);
            TracyD3D12Assert( lock.owns_lock() );
            TracyD3D12Debug( ZoneValue(m_contextId) );

            uint64_t earliestTicket = m_previousCheckpoint.load(std::memory_order_relaxed);
            uint64_t endTicket = m_queryCounter;
            TracyD3D12Debug( ZoneValue(earliestTicket) );
            TracyD3D12Debug( ZoneValue(endTicket) );
            if (Distance(earliestTicket, endTicket) <= 0)
                return;

            UINT64* timestampBuffer = MapTimestampBuffer();
            if (timestampBuffer == nullptr) return;

            // Attempt to collect as many resolved queries as possible
            uint64_t ticket = earliestTicket;
            for (ticket = earliestTicket; ticket != endTicket; ticket += 2)
            {
                if (!ResolveTimestamp(ticket, timestampBuffer))
                    // TODO: implement preemptive timeout policy
                    break;
            }

            // Urgent request: ensure 'targetTicket' is collected before returning
            if (urgent)
            {
                TracyD3D12Assert( Distance(targetTicket, endTicket) > 0 );
                while (Distance(ticket, targetTicket) >= 0)
                {
                    DropTimestamp(ticket, timestampBuffer);
                    ticket += 2;
                }
            }

            // Panic: overflow, start dropping queries to normalize the situation
            while (Distance(ticket, endTicket) > RingCapacity())
            {
                DropTimestamp(ticket, timestampBuffer);
                ticket += 2;
            }

            UnmapTimestampBuffer(timestampBuffer);

            // TODO: check for device status (device lost).
            // Technically speaking, values read from the timestamp buffer (readback heap)
            // should only be trusted while the device is "fine". Ideally, queries should
            // be "peeked" first, and those deemed "resolved" should only be "emitted" if
            // the device is fine, or dropped otherwise. All that said, the collect code,
            // as is, should not cause catastrophic issues.

            RecalibrateClocks();
        }

        tracy_force_inline bool IsTicketPending(uint64_t queryTicket)
        {
            auto checkpoint = m_previousCheckpoint.load(std::memory_order_acquire);
            return (Distance(checkpoint, queryTicket) >= 0);
        }

        bool Wait(uint64_t queryTicket, uint64_t timeout_ms)
        {
            ZoneScopedC(Color::Red4);
            TracyD3D12Debug( ZoneValue(m_contextId) );
            TracyD3D12Debug( ZoneValue(queryTicket) );
            TracyD3D12Debug( ZoneValue(RingIndex(queryTicket)) );
            auto ini = GetTickCount64();
            auto elapsed = 0;
            // TODO: could use condition variable to avoid spurious lock + collect iterations
            while (IsTicketPending(queryTicket))
            {
                if (elapsed >= timeout_ms)
                    return false;
                std::unique_lock lock (m_collectionMutex);
                Collect(lock, queryTicket, false);
                elapsed = GetTickCount64() - ini;
            }
            return true;
        }

        void Drain(uint64_t queryTicket, uint64_t gracePeriod_ms)
        {
            ZoneScopedC(Color::Red4);
            TracyD3D12Debug( ZoneValue(m_contextId) );
            TracyD3D12Debug( ZoneValue(queryTicket) );
            TracyD3D12Debug( ZoneValue(RingIndex(queryTicket)) );
            if (Wait(queryTicket, gracePeriod_ms))
                return;
            // can't wait anymore: urgent collect request
            std::unique_lock lock (m_collectionMutex);
            Collect(lock, queryTicket, true);
        }

        bool ResolveTimestamp(uint64_t queryTicket, UINT64* timestampBuffer)
        {
            uint32_t queryId = RingIndex(queryTicket);
            UINT64 gpuZoneBeginTimestamp = timestampBuffer[queryId];
            UINT64 gpuZoneEndTimestamp = timestampBuffer[queryId+1];
            UINT64 baselineTimestamp = m_shadowBuffer[queryId+1];
            int64_t baseline_diff = Distance(baselineTimestamp, gpuZoneEndTimestamp);
            if (baseline_diff <= 0)
                return false;
            EmitGpuTime(gpuZoneBeginTimestamp, queryId);
            EmitGpuTime(gpuZoneEndTimestamp, queryId+1);
            RetireTicket(queryTicket);
            if (Distance(m_latestKnownGpuTimestamp, gpuZoneEndTimestamp) > 0)
                m_latestKnownGpuTimestamp = gpuZoneEndTimestamp;
            return true;
        }

        void DropTimestamp(uint64_t queryTicket, UINT64* timestampBuffer)
        {
            // might as well attempt to resolve it before dropping it
            if (ResolveTimestamp(queryTicket, timestampBuffer))
                return;
            // emit a "bogus" GpuTime to avoid problems with the internal
            // zone tracking and matching logic in the server/profiler
            uint32_t queryId = RingIndex(queryTicket);
            TracyD3D12Debug( ZoneScopedC(Color::Red4) );
            TracyD3D12Debug( ZoneValue(queryTicket) );
            TracyD3D12Debug( ZoneValue(queryId) );
            TracyD3D12Debug( TracyPlot("TracyD3D12|drop", int64_t(0)) );
            TracyD3D12Debug( TracyPlot("TracyD3D12|drop", int64_t(1)) );
            uint64_t latestGpuTimestamp = m_latestKnownGpuTimestamp;
            EmitGpuTime(latestGpuTimestamp, queryId);
            EmitGpuTime(latestGpuTimestamp, queryId+1);
            RetireTicket(queryTicket);
            TracyD3D12Debug( TracyPlot("TracyD3D12|drop", int64_t(1)) );
            TracyD3D12Debug( TracyPlot("TracyD3D12|drop", int64_t(0)) );
        }

        void EmitGpuTime(UINT64 gpuTimestamp, uint32_t queryId)
        {
            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuTime);
            MemWrite(&item->gpuTime.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuTime.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuTime.context, GetId());
            Profiler::QueueSerialFinish();
            m_shadowBuffer[queryId] = gpuTimestamp;
            TracyD3D12Debug(
                TracyFreeN(reinterpret_cast<void*>(uintptr_t(queryId)), "TracyD3D12|Query");
            );
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
            // difference accounting for unsigned wrap-around
            return static_cast<int64_t>(end - begin);
        }

        void RetireTicket(uint64_t ticket)
        {
            TracyD3D12Assert( m_previousCheckpoint == ticket );
            uint64_t nextTicket = ticket + 2;
            m_previousCheckpoint.store(nextTicket, std::memory_order_release);
        }

        tracy_force_inline uint32_t NextQueryId()
        {
            // WARN: the moment m_queryCounter is incremented, Collect() will have instant
            // visibility of the change and may therefore start attempting to collect them.
            // Under most circumstances, this is fine. However, suppose Collect() ends up
            // dropping a query due to timeout, but said query is indeed submitted to the
            // GPU queue for execution later on. This "late" query will eventually become
            // resolved by the GPU asynchronously writting to the corresponding query slot.
            // The newly produced query below could have matching ids/slot with said query.
            // From there, there's no bullet-proof way for Collect() to distinguish between
            // the timestamp written to the query slot belonging to the old/late query, or
            // to the query that has just been generated. The value of the "late" query may
            // may end up being collected as if it belonged to the the new query.
            const uint64_t ticket = m_queryCounter.fetch_add(2, std::memory_order_relaxed);
            const uint64_t checkpoint = m_previousCheckpoint.load(std::memory_order_relaxed);
            if (Distance(checkpoint, ticket) >= RingCapacity())
            {
                ZoneScopedC(Color::Red4);
                TracyD3D12Log(Warning, "Too many pending GPU queries: stalling!");
                uint64_t oldTicket = ticket - RingCapacity();
                Drain(oldTicket, 0);
            }

            const uint32_t queryId = RingIndex(ticket);
            TracyD3D12Debug(
                TracyAllocN(reinterpret_cast<void*>(uintptr_t(queryId+0)), 1, "TracyD3D12|Query");
                TracyAllocN(reinterpret_cast<void*>(uintptr_t(queryId+1)), 1, "TracyD3D12|Query");
            );
            return queryId;
        }

        UINT64* MapTimestampBuffer()
        {
#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            if (m_persistentTimestampBuffer != nullptr)
                return m_persistentTimestampBuffer;
#endif
            D3D12_RANGE fullRange { 0, m_queryLimit * sizeof(UINT64) };
            void* readbackBufferMapping = nullptr;
            if (FAILED(m_readbackBuffer->Map(0, &fullRange, &readbackBufferMapping)))
            {
                TracyD3D12Panic("failed to map timestamp buffer.", return nullptr);
            }
            UINT64* timestampBuffer = static_cast<UINT64*>(readbackBufferMapping);
#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            TracyD3D12Assert( m_persistentTimestampBuffer == nullptr );
            m_persistentTimestampBuffer = timestampBuffer;
#endif
            return timestampBuffer;
        }

        void UnmapTimestampBuffer(UINT64*)
        {
#if !TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            D3D12_RANGE fullRange { 0, m_queryLimit * sizeof(UINT64) };
            m_readbackBuffer->Unmap(0, &fullRange);
#endif
        }

        bool DeviceLost()
        {
            HRESULT status = m_device->GetDeviceRemovedReason();
            return (status != S_OK);
        }
    };

    class D3D12ZoneScope
    {
        const bool m_active;
        D3D12QueueCtx* m_ctx = nullptr;
        ID3D12GraphicsCommandList* m_cmdList = nullptr;
        uint32_t m_queryId = 0;

        tracy_force_inline void WriteQueueItem(const SourceLocationData* srcLocation, int32_t callstackDepth, uint32_t sourceLine, const char* sourceFile, size_t sourceFileLen, const char* functionName, size_t functionNameLen, const char* zoneName, size_t zoneNameLen)
        {
            if (!m_active) return;

            const bool captureCallstack = callstackDepth > 0 && has_callstack();
            const bool transientZone = srcLocation == nullptr;
            uint64_t srcLocationAddr = reinterpret_cast<uint64_t>( srcLocation );

            QueueItem* item = nullptr;
            QueueType itemType;
            if( transientZone )
            {
                srcLocationAddr = Profiler::AllocSourceLocation( sourceLine, sourceFile, sourceFileLen, functionName, functionNameLen, zoneName, zoneNameLen);
                if( captureCallstack )
                {
                    item = Profiler::QueueSerialCallstack( Callstack( callstackDepth ) );
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
                if( captureCallstack )
                {
                    item = Profiler::QueueSerialCallstack( Callstack( callstackDepth ) );
                    itemType = QueueType::GpuZoneBeginCallstackSerial;
                }
                else
                {
                    item = Profiler::QueueSerial();
                    itemType = QueueType::GpuZoneBeginSerial;
                }
            }

            MemWrite( &item->hdr.type, itemType );
            MemWrite( &item->gpuZoneBegin.cpuTime, Profiler::GetTime() );
            MemWrite( &item->gpuZoneBegin.srcloc, srcLocationAddr );
            MemWrite( &item->gpuZoneBegin.thread, GetThreadHandle() );
            MemWrite( &item->gpuZoneBegin.queryId, static_cast<uint16_t>( m_queryId ) );
            MemWrite( &item->gpuZoneBegin.context, m_ctx->GetId() );
            Profiler::QueueSerialFinish();
        }

        tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, ID3D12GraphicsCommandList* cmdList, bool active)
#ifdef TRACY_ON_DEMAND
            : m_active(active&& GetProfiler().IsConnected())
#else
            : m_active(active)
#endif
        {
            if (!m_active) return;

            m_ctx = ctx;
            m_cmdList = cmdList;

            m_queryId = m_ctx->NextQueryId();
            m_cmdList->EndQuery(m_ctx->m_queryHeap, D3D12_QUERY_TYPE_TIMESTAMP, m_queryId);
        }

    public:
        tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, ID3D12GraphicsCommandList* cmdList, const SourceLocationData* srcLocation, bool active)
            : D3D12ZoneScope(ctx, cmdList, active)
        {
            WriteQueueItem(srcLocation, 0, 0, nullptr, 0, nullptr, 0, nullptr, 0 );
        }

        tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, ID3D12GraphicsCommandList* cmdList, const SourceLocationData* srcLocation, int32_t depth, bool active)
            : D3D12ZoneScope(ctx, cmdList, active)
        {
            WriteQueueItem(srcLocation, depth, 0, nullptr, 0, nullptr, 0, nullptr, 0 );
        }

        tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, ID3D12GraphicsCommandList* cmdList, bool active)
            : D3D12ZoneScope(ctx, cmdList, active)
        {
            WriteQueueItem(nullptr, 0, line, source, sourceSz, function, functionSz, name, nameSz);
        }

        tracy_force_inline D3D12ZoneScope(D3D12QueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, ID3D12GraphicsCommandList* cmdList, int32_t depth, bool active)
            : D3D12ZoneScope(ctx, cmdList, active)
        {
            WriteQueueItem(nullptr, depth, line, source, sourceSz, function, functionSz, name, nameSz);
        }

        tracy_force_inline ~D3D12ZoneScope()
        {
            if (!m_active) return;

            const auto queryId = m_queryId + 1;  // Our end query slot is immediately after the begin slot.

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneEndSerial);
            MemWrite(&item->gpuZoneEnd.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneEnd.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneEnd.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuZoneEnd.context, m_ctx->GetId());
            Profiler::QueueSerialFinish();

            m_cmdList->EndQuery(m_ctx->m_queryHeap, D3D12_QUERY_TYPE_TIMESTAMP, queryId);
            // NOTE: can't quite move this ResolveQueryData() call to Collect()...
            // If a command is instrumented, but the command list is never submitted
            // for execution, we should not ask the GPU to resolve the corresponding
            // queries (we'll get stale/garbage data if we do so)
            m_cmdList->ResolveQueryData(m_ctx->m_queryHeap, D3D12_QUERY_TYPE_TIMESTAMP, m_queryId, 2, m_ctx->m_readbackBuffer, m_queryId * sizeof(uint64_t));
        }
    };

    static inline void DestroyD3D12Context(D3D12QueueCtx* ctx)
    {
        TracyD3D12Assert(ctx);
        ctx->~D3D12QueueCtx();
        tracy_free(ctx);
    }

    static inline D3D12QueueCtx* CreateD3D12Context(ID3D12Device* device, ID3D12CommandQueue* queue)
    {
        auto* ctx = static_cast<D3D12QueueCtx*>(tracy_malloc(sizeof(D3D12QueueCtx)));
        new (ctx) D3D12QueueCtx{ device, queue };
        // constructor may have failed:
        if (ctx->GetId() == 255)
        {
            DestroyD3D12Context(ctx);
            return nullptr;
        }
        return ctx;
    }

}

#undef TracyD3D12Panic
#undef TracyD3D12Log
#undef TracyD3D12Assert
#undef TracyD3D12Break
#undef TracyD3D12Debug
#undef TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
#undef TRACY_D3D12_DEBUG_LEVEL

using TracyD3D12Ctx = tracy::D3D12QueueCtx*;

#define TracyD3D12Context(device, queue) tracy::CreateD3D12Context(device, queue);
#define TracyD3D12Destroy(ctx) tracy::DestroyD3D12Context(ctx);
#define TracyD3D12ContextName(ctx, name, size) ctx->Name(name, size);

#define TracyD3D12NewFrame(ctx) ((void)(ctx))

#define TracyD3D12UnnamedZone ___tracy_gpu_d3d12_zone
#define TracyD3D12SrcLocSymbol TracyConcat(__tracy_d3d12_source_location,TracyLine)
#define TracyD3D12SrcLocObject(name, color) static constexpr tracy::SourceLocationData TracyD3D12SrcLocSymbol { name, TracyFunction, TracyFile, (uint32_t)TracyLine, color };

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyD3D12Zone(ctx, cmdList, name) TracyD3D12NamedZoneS(ctx, TracyD3D12UnnamedZone, cmdList, name, TRACY_CALLSTACK, true)
#  define TracyD3D12ZoneC(ctx, cmdList, name, color) TracyD3D12NamedZoneCS(ctx, TracyD3D12UnnamedZone, cmdList, name, color, TRACY_CALLSTACK, true)
#  define TracyD3D12NamedZone(ctx, varname, cmdList, name, active) TracyD3D12SrcLocObject(name, 0); tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyD3D12SrcLocSymbol, TRACY_CALLSTACK, active };
#  define TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active) TracyD3D12SrcLocObject(name, color); tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyD3D12SrcLocSymbol, TRACY_CALLSTACK, active };
#  define TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active) TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, TRACY_CALLSTACK, active)
#else
#  define TracyD3D12Zone(ctx, cmdList, name) TracyD3D12NamedZone(ctx, TracyD3D12UnnamedZone, cmdList, name, true)
#  define TracyD3D12ZoneC(ctx, cmdList, name, color) TracyD3D12NamedZoneC(ctx, TracyD3D12UnnamedZone, cmdList, name, color, true)
#  define TracyD3D12NamedZone(ctx, varname, cmdList, name, active) TracyD3D12SrcLocObject(name, 0); tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyD3D12SrcLocSymbol, active };
#  define TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active) TracyD3D12SrcLocObject(name, color); tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyD3D12SrcLocSymbol, active };
#  define TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active) tracy::D3D12ZoneScope varname{ ctx, TracyLine, TracyFile, strlen(TracyFile), TracyFunction, strlen(TracyFunction), name, strlen(name), cmdList, active };
#endif

#ifdef TRACY_HAS_CALLSTACK
#  define TracyD3D12ZoneS(ctx, cmdList, name, depth) TracyD3D12NamedZoneS(ctx, TracyD3D12UnnamedZone, cmdList, name, depth, true)
#  define TracyD3D12ZoneCS(ctx, cmdList, name, color, depth) TracyD3D12NamedZoneCS(ctx, TracyD3D12UnnamedZone, cmdList, name, color, depth, true)
#  define TracyD3D12NamedZoneS(ctx, varname, cmdList, name, depth, active) TracyD3D12SrcLocObject(name, 0); tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyD3D12SrcLocSymbol, depth, active };
#  define TracyD3D12NamedZoneCS(ctx, varname, cmdList, name, color, depth, active) TracyD3D12SrcLocObject(name, color); tracy::D3D12ZoneScope varname{ ctx, cmdList, &TracyD3D12SrcLocSymbol, depth, active };
#  define TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, depth, active) tracy::D3D12ZoneScope varname{ ctx, TracyLine, TracyFile, strlen(TracyFile), TracyFunction, strlen(TracyFunction), name, strlen(name), cmdList, depth, active };
#else
#  define TracyD3D12ZoneS(ctx, cmdList, name, depth) TracyD3D12Zone(ctx, cmdList, name)
#  define TracyD3D12ZoneCS(ctx, cmdList, name, color, depth) TracyD3D12Zone(ctx, cmdList, name, color)
#  define TracyD3D12NamedZoneS(ctx, varname, cmdList, name, depth, active) TracyD3D12NamedZone(ctx, varname, cmdList, name, active)
#  define TracyD3D12NamedZoneCS(ctx, varname, cmdList, name, color, depth, active) TracyD3D12NamedZoneC(ctx, varname, cmdList, name, color, active)
#  define TracyD3D12ZoneTransientS(ctx, varname, cmdList, name, depth, active) TracyD3D12ZoneTransient(ctx, varname, cmdList, name, active)
#endif

#define TracyD3D12Collect(ctx) ctx->Collect();

#endif

#endif
