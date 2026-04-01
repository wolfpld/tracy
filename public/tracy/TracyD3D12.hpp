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
#include "../client/TracyProfiler.hpp"
#include "../client/TracyCallstack.hpp"

#include <atomic>
#include <chrono>
#include <mutex>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <d3d12.h>
#include <dxgi.h>

#ifndef TRACY_D3D12_TIMESTAMP_COLLECT_TIMEOUT
#define TRACY_D3D12_TIMESTAMP_COLLECT_TIMEOUT 0.005f
#endif

#define TRACY_D3D12_DEBUG (1)
#define TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER (1)

#define TracyD3D12Panic(msg, ...) do { assert(false && "TracyD3D12: " msg); tracy::Profiler::LogString( tracy::MessageSourceType::Tracy, tracy::MessageSeverity::Error, tracy::Color::Red4, 0, msg ); __VA_ARGS__; } while(false);

#if TRACY_D3D12_DEBUG
#define TracyD3D12Debug(...) __VA_ARGS__
#else
#define TracyD3D12Debug(...)
#endif

namespace tracy
{

    // Command queue context.
    class D3D12QueueCtx
    {
        friend class D3D12ZoneScope;

        uint8_t m_contextId = 255;  // TODO: apparently, 255 means "invalid id"; is this documented somewhere?

        std::mutex m_collectionMutex;

        ID3D12Device* m_device = nullptr;
        ID3D12CommandQueue* m_queue = nullptr;
        ID3D12QueryHeap* m_queryHeap = nullptr;
        ID3D12Resource* m_readbackBuffer = nullptr;

#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
        UINT64* m_timestampBuffer = nullptr;
#endif

        using atomic_counter = std::atomic<uint64_t>;
        atomic_counter m_queryCounter = 0;
        atomic_counter m_previousCheckpoint = 0;

        uint32_t m_queryLimit = 0;

        struct CollectWindow
        {
            using AgeClock = std::chrono::high_resolution_clock;
            static constexpr uint64_t capacity = 4 * 1024;
            uint64_t rangeBegin = 0;
            uint64_t rangeEnd   = 0;
            AgeClock::time_point ageStart   = AgeClock::time_point::max();
            UINT64 latestKnownGpuTimestamp = 0;
            UINT64 shadowBuffer[capacity] = {};
        } m_window;

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
        {
            ZoneScopedC(Color::Red4);

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

            static constexpr uint32_t MaxQueries = 64 * 1024;  // Must be even, because queries are (begin, end) pairs
            m_queryLimit = MaxQueries;

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

            {
                D3D12_RANGE zeroRange{ 0, m_queryLimit * sizeof(UINT64) };
                void* buffer = nullptr;
                if (FAILED(m_readbackBuffer->Map(0, &zeroRange, &buffer)))
                {
                    TracyD3D12Panic("Failed to map readback buffer for initialization.", return);
                }
                UINT64* timestampBuffer = static_cast<UINT64*>(buffer);
                for (uint64_t i = 0; i < m_queryLimit; ++i)
                {
                    timestampBuffer[i] = 0;
                }
                // TODO: any advantages to making this Map() persist?
#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
                m_timestampBuffer = timestampBuffer;
#else
                m_readbackBuffer->Unmap(0, &zeroRange);
#endif
            }

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

            // initialize CollectWindow
            UpdateLatestKnownGpuTimestamp(gpuTimestamp);
            AdvanceCollectWindow();

            // Save the device cpu timestamp, not the profiler's timestamp.
            m_prevCalibrationTicksCPU = cpuTimestamp;

            cpuTimestamp = Profiler::GetTime();

            // All setup/init checks completed: ready to create the context.
            m_contextId = GetGpuCtxCounter().fetch_add(1);
            ZoneValue(int64_t(m_contextId));

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
            ZoneValue(int64_t(m_contextId));

            // TODO: could use queue->Signal() to inject a progress point in the queue
            // and the immediately wait for the signal, in order to avoid busy-waiting
            // (need to create an ID3D12Fence and associate an Event object to it)

            // collect all pending queries up to this point
            uint64_t latestQuery = m_queryCounter.load();
            while (m_window.rangeEnd != latestQuery)
                Collect();
            // TODO: ensure we collect a "partial" window (Signal/Wait should do it)

            // if the client is still pushing queries past the latest checkpoint above,
            // assume there's a bug in the client, and ignore them (don't collect)
            if (latestQuery != m_queryCounter.load())
                TracyD3D12Panic("client is still pushing queries.");

#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            D3D12_RANGE fullRange { 0, m_queryLimit * sizeof(UINT64) };
            m_readbackBuffer->Unmap(0, &fullRange);
#endif
            m_readbackBuffer->Release();
            m_queryHeap->Release();
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
            if (!GetProfiler().IsConnected())
            {
                // TODO: reset the collect window here
                m_previousCheckpoint = m_queryCounter.load();
                return;
            }
#endif
            ZoneScopedC(Color::Red4);
            ZoneValue(uint64_t(m_contextId));

            // Only one thread is allowed to collect timestamps at any given time
            // but there's no need to block contending threads
            if (!m_collectionMutex.try_lock())
                return;
            std::unique_lock lock (m_collectionMutex, std::adopt_lock);

            auto now = CollectWindow::AgeClock::now();

            uint64_t windowSize = m_window.rangeEnd - m_window.rangeBegin;
            if (windowSize < m_window.capacity)
            {
                uint64_t latestIssued = m_queryCounter.load();
                uint64_t trail = latestIssued - m_window.rangeBegin;
                windowSize = std::min(trail, m_window.capacity);
                m_window.rangeEnd = m_window.rangeBegin + windowSize;
                m_window.ageStart = now;
            }

            if (windowSize == 0)
                return;

#if TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            UINT64* timestampBuffer = m_timestampBuffer;
#else
            D3D12_RANGE mapRange{ 0, m_queryLimit * sizeof(UINT64) };
            void* readbackBufferMapping = nullptr;
            if (FAILED(m_readbackBuffer->Map(0, &mapRange, &readbackBufferMapping)))
            {
                TracyD3D12Panic("Collect: failed to map timestamp buffer.", return);
            }
            UINT64* timestampBuffer = static_cast<UINT64*>(readbackBufferMapping);
#endif

            auto timeout = std::chrono::duration<double>(TRACY_D3D12_TIMESTAMP_COLLECT_TIMEOUT);
            auto windowAge = now - m_window.ageStart;

            // iterate over every slot (pair) in the window
            int unresolved = 0;
            for (uint64_t i = m_window.rangeBegin; i != m_window.rangeEnd; i += 2)
            {
                uint32_t queryId = RingIndex(i);
                uint32_t shadowIdx = static_cast<uint32_t>(i - m_window.rangeBegin);

                UINT64 gpuZoneBeginTimestamp = timestampBuffer[queryId];
                UINT64 gpuZoneEndTimestamp = timestampBuffer[queryId+1];
                int64_t diff = static_cast<int64_t>(gpuZoneEndTimestamp - m_window.shadowBuffer[shadowIdx+1]);
                if (diff == 0)
                    continue;
                if (diff < 0)
                {
                    ++unresolved;
                    if (windowAge < timeout)
                        continue;
                    // timed-out: drop it
                    TracyD3D12Debug(
                        ZoneScopedNC("tracy::D3D12QueueCtx::Collect::[drop]", Color::Red4);
                        ZoneValue(int64_t(queryId));
                    );
                    // must still emit a bogus GpuTime to avoid problems with
                    // the server/profiler internal tracking/matching logic
                    gpuZoneBeginTimestamp = m_window.latestKnownGpuTimestamp;
                    gpuZoneEndTimestamp = gpuZoneBeginTimestamp + 1;
                }

                EmitGpuTime(gpuZoneBeginTimestamp, queryId);
                EmitGpuTime(gpuZoneEndTimestamp, queryId+1);
                m_window.shadowBuffer[shadowIdx] = gpuZoneBeginTimestamp;
                m_window.shadowBuffer[shadowIdx+1] = gpuZoneEndTimestamp;
                // TODO: maybe only update timestamp for "resolved" queries
                UpdateLatestKnownGpuTimestamp(gpuZoneEndTimestamp);
            }

            if (windowSize == m_window.capacity)
            {
                if ((unresolved == 0) || (windowAge >= timeout))
                {
                    AdvanceCollectWindow();
                    // Publish new checkpoint — NextQueryId can now reuse these slots.
                    m_previousCheckpoint.store(m_window.rangeBegin);
                    // TODO: start collecting the next window immediately...
                }
            }

#if !TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
            m_readbackBuffer->Unmap(0, &mapRange);
#endif

            RecalibrateClocks();
        }

    private:
        // Update the window's latest known GPU timestamp only if ts is strictly "ahead"
        // of the current value. Uses a signed-difference comparison to be robust against
        // counter wrap-around (though UINT64 at any conceivable clock rate won't wrap
        // within the lifetime of the process).
        tracy_force_inline void UpdateLatestKnownGpuTimestamp(UINT64 timestamp)
        {
            int64_t diff = static_cast<int64_t>(timestamp - m_window.latestKnownGpuTimestamp);
            if (diff > 0)
                m_window.latestKnownGpuTimestamp = timestamp;
        }

        void AdvanceCollectWindow()
        {
            m_window.rangeBegin = m_window.rangeEnd;
            m_window.ageStart = CollectWindow::AgeClock::time_point::max();
            for (auto& shadow : m_window.shadowBuffer)
                shadow = m_window.latestKnownGpuTimestamp;
        }

        tracy_force_inline void EmitGpuTime(UINT64 gpuTimestamp, uint32_t queryId)
        {
            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuTime);
            MemWrite(&item->gpuTime.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuTime.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuTime.context, GetId());
            Profiler::QueueSerialFinish();
            TracyD3D12Debug(
                TracyFreeN(reinterpret_cast<void*>(uintptr_t(queryId)), "TracyD3D12 Query");
            );
        }

        tracy_force_inline uint32_t RingSize() const
        {
            return m_queryLimit;
        }

        tracy_force_inline uint32_t RingIndex(uint64_t logicalSlot) const
        {
            return static_cast<uint32_t>(logicalSlot % RingSize());
        }

        tracy_force_inline uint32_t RingCount(uint64_t begin, uint64_t end) const
        {
            return static_cast<uint32_t>(end - begin);
        }

        tracy_force_inline uint32_t NextQueryId()
        {
            // WARN: the moment m_queryCounter is incremented, Collect() will have
            // instant visibility of the query pair and will attempt to collect it!
            // Under normal circumstances, this is fine: the corresponding id slots
            // would have been rset to the InvalidTimestamp sentinel value already,
            // right after the timestamp slots being collected.
            // However, if Collect() decides to timeout-drop a timestamp query that
            // was indeed submitted to the GPU queue for execution, the dropped query
            // will eventually be resolved by the GPU and will arrive "late" at its
            // corrsponding query slot (the GPU will write asynchronously to it).
            // The "new" query pair here will have matching slots with the late query
            // pair of "before". Given that Collect() will "sense" the new query pair
            // immediately upon m_queryCounter being incremented, the late timestamp
            // query may be collected as if it was the timestamp of the new query...
            const uint64_t seqIdx = m_queryCounter.fetch_add(2, std::memory_order_relaxed);
            if (RingCount(m_previousCheckpoint.load(), seqIdx) >= RingSize())
            {
                ZoneScopedC(Color::Red4);
                ZoneValue(int64_t(m_contextId));
                TracyD3D12Panic("Submitted too many GPU queries!");
                // TODO: decide what to do when "full"
                // (maybe a loop with a few iterations attempting to Collect() queries
                // and if it fails, return some "invalid query" id)
            }

            const uint32_t queryId = RingIndex(seqIdx);

            TracyD3D12Debug(
                TracyAllocN(reinterpret_cast<void*>(uintptr_t(queryId+0)), 1, "TracyD3D12 Query");
                TracyAllocN(reinterpret_cast<void*>(uintptr_t(queryId+1)), 1, "TracyD3D12 Query");
            );

            return queryId;
        }

        tracy_force_inline uint8_t GetId() const
        {
            return m_contextId;
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

            QueueItem* item;
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
            m_cmdList->EndQuery(m_ctx->m_queryHeap, D3D12_QUERY_TYPE_TIMESTAMP, queryId);

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneEndSerial);
            MemWrite(&item->gpuZoneEnd.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneEnd.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneEnd.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuZoneEnd.context, m_ctx->GetId());
            Profiler::QueueSerialFinish();

            // TODO: maybe move this to Collect()?
            m_cmdList->ResolveQueryData(m_ctx->m_queryHeap, D3D12_QUERY_TYPE_TIMESTAMP, m_queryId, 2, m_ctx->m_readbackBuffer, m_queryId * sizeof(uint64_t));
        }
    };

    static inline D3D12QueueCtx* CreateD3D12Context(ID3D12Device* device, ID3D12CommandQueue* queue)
    {
        auto* ctx = static_cast<D3D12QueueCtx*>(tracy_malloc(sizeof(D3D12QueueCtx)));
        new (ctx) D3D12QueueCtx{ device, queue };

        return ctx;
    }

    static inline void DestroyD3D12Context(D3D12QueueCtx* ctx)
    {
        ctx->~D3D12QueueCtx();
        tracy_free(ctx);
    }

}

#undef TRACY_D3D12_DEBUG
#undef TRACY_D3D12_PERSISTENT_TIMESTAMP_BUFFER
#undef TRACY_D3D12_TIMESTAMP_COLLECT_TIMEOUT
#undef TracyD3D12Panic

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
