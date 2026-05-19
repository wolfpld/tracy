#ifndef __TRACYWEBGPU_HPP__
#define __TRACYWEBGPU_HPP__

#ifndef TRACY_ENABLE

#define TracyWebGPUContext(instance, device, queue) nullptr
#define TracyWebGPUDestroy(ctx)
#define TracyWebGPUContextName(ctx, name, size)

#define TracyWebGPUZone(ctx, encoder, passDesc, name)
#define TracyWebGPUZoneC(ctx, encoder, passDesc, name, color)
#define TracyWebGPUNamedZone(ctx, varname, encoder, passDesc, name, active)
#define TracyWebGPUNamedZoneC(ctx, varname, encoder, passDesc, name, color, active)
#define TracyWebGPUZoneTransient(ctx, varname, encoder, passDesc, name, active)

#define TracyWebGPUZoneS(ctx, encoder, passDesc, name, depth)
#define TracyWebGPUZoneCS(ctx, encoder, passDesc, name, color, depth)
#define TracyWebGPUNamedZoneS(ctx, varname, encoder, passDesc, name, depth, active)
#define TracyWebGPUNamedZoneCS(ctx, varname, encoder, passDesc, name, color, depth, active)
#define TracyWebGPUZoneTransientS(ctx, varname, encoder, passDesc, name, depth, active)

#define TracyWebGPUCollect(ctx)

namespace tracy
{
    class WebGPUZoneScope {};
}

using TracyWebGPUCtx = void*;

#else

#include "Tracy.hpp"
#include "../client/TracyProfiler.hpp"
#include "../client/TracyCallstack.hpp"
#include "../common/TracyAlign.hpp"
#include "../common/TracyAlloc.hpp"

#include <atomic>
#include <mutex>
#include <vector>
#include <cstdio>
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

#define TracyWebGPULog(severity, msg) fprintf(stdout, "%s", msg), tracy::Profiler::LogString( tracy::MessageSourceType::Tracy, tracy::MessageSeverity::severity, tracy::Color::Red4, 0, msg );
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

        struct ReadbackSlot
        {
            WGPUBuffer            buffer;
            std::atomic<uint64_t> copiedUpto;
            std::atomic<WGPUMapAsyncStatus> mapStatus = {};
            WGPUFuture            pendingFuture = {};
        };
        static_assert(std::atomic<WGPUMapAsyncStatus>::is_always_lock_free, "WGPUMapAsyncStatus must be lock-free atomic");

        WGPUQuerySet  m_querySet        = nullptr;
        WGPUBuffer    m_resolveBuffer   = nullptr;  // QueryResolve | CopySrc
        ReadbackSlot  m_readbackSlots[3];            // CopyDst | MapRead (3-slot ring)
        std::atomic<int> m_writeIdx{0};              // WRITE slot index (ring: 0→1→2→0)

        using atomic_counter = std::atomic<uint64_t>;
        atomic_counter m_queryCounter       = 0;
        atomic_counter m_previousCheckpoint = 0;

        uint32_t m_queryLimit = 0;

        std::vector<uint64_t> m_shadowBuffer;
        uint64_t m_prevCalibGpuTime = 0;

        tracy_force_inline void SubmitQueueItem(tracy::QueueItem* item)
        {
#ifdef TRACY_ON_DEMAND
            GetProfiler().DeferItem(*item);
#endif
            Profiler::QueueSerialFinish();
        }

        bool CalibrateClocks(uint64_t& outCpuTime, uint64_t& outGpuTime)
        {
            ZoneScoped;

            WGPUCommandEncoder enc = wgpuDeviceCreateCommandEncoder(m_device, nullptr);
            if (!enc) { TracyWebGPUPanic("Failed to create calibration command encoder.", return false); }

            // wgpuCommandEncoderWriteTimestamp is deprecated and returns 0 on Metal.
            // Use a render pass with an actual draw call: on Metal TBDR, begin-of-pass
            // timestamps fire at tile rasterization start. An empty render pass (no
            // geometry) may never trigger rasterization, yielding a deferred or
            // meaningless timestamp that doesn't reflect actual GPU execution order.
            static const char kCalibShader[] = R"(
                @vertex fn vs(@builtin(vertex_index) i: u32) -> @builtin(position) vec4f {
                    var p = array(vec4f(-1,-1,.5,1), vec4f(3,-1,.5,1), vec4f(-1,3,.5,1));
                    return p[i];
                }
                @fragment fn fs() -> @location(0) vec4f { return vec4f(0.0); }
            )";
            WGPUShaderSourceWGSL wgslSrc = {};
            wgslSrc.chain.sType = WGPUSType_ShaderSourceWGSL;
            wgslSrc.code        = { kCalibShader, WGPU_STRLEN };
            WGPUShaderModuleDescriptor smDesc = {};
            smDesc.nextInChain  = reinterpret_cast<WGPUChainedStruct*>(&wgslSrc);
            WGPUShaderModule calibShader = wgpuDeviceCreateShaderModule(m_device, &smDesc);
            if (!calibShader) { wgpuCommandEncoderRelease(enc); TracyWebGPUPanic("Failed to create calibration shader.", return false); }

            WGPUTextureDescriptor texDesc = {};
            texDesc.usage         = WGPUTextureUsage_RenderAttachment;
            texDesc.dimension     = WGPUTextureDimension_2D;
            texDesc.size          = { 1, 1, 1 };
            texDesc.format        = WGPUTextureFormat_BGRA8Unorm;
            texDesc.mipLevelCount = 1;
            texDesc.sampleCount   = 1;
            WGPUTexture tex = wgpuDeviceCreateTexture(m_device, &texDesc);
            if (!tex) { wgpuShaderModuleRelease(calibShader); wgpuCommandEncoderRelease(enc); TracyWebGPUPanic("Failed to create calibration scratch texture.", return false); }
            WGPUTextureView texView = wgpuTextureCreateView(tex, nullptr);
            if (!texView) { wgpuTextureRelease(tex); wgpuShaderModuleRelease(calibShader); wgpuCommandEncoderRelease(enc); TracyWebGPUPanic("Failed to create calibration scratch texture view.", return false); }

            WGPUColorTargetState colorTarget = {};
            colorTarget.format    = WGPUTextureFormat_BGRA8Unorm;
            colorTarget.writeMask = WGPUColorWriteMask_All;
            WGPUFragmentState fragState = {};
            fragState.module      = calibShader;
            fragState.entryPoint  = { "fs", WGPU_STRLEN };
            fragState.targetCount = 1;
            fragState.targets     = &colorTarget;
            WGPURenderPipelineDescriptor pipeDesc = {};
            pipeDesc.vertex.module        = calibShader;
            pipeDesc.vertex.entryPoint    = { "vs", WGPU_STRLEN };
            pipeDesc.primitive.topology   = WGPUPrimitiveTopology_TriangleList;
            pipeDesc.multisample.count    = 1;
            pipeDesc.fragment             = &fragState;
            WGPURenderPipeline calibPipeline = wgpuDeviceCreateRenderPipeline(m_device, &pipeDesc);
            if (!calibPipeline) { wgpuTextureViewRelease(texView); wgpuTextureRelease(tex); wgpuShaderModuleRelease(calibShader); wgpuCommandEncoderRelease(enc); TracyWebGPUPanic("Failed to create calibration pipeline.", return false); }

            //const uint64_t calibTicket = NextQueryId();
            //const uint32_t calibSlotB  = RingIndex(calibTicket);
            //const uint32_t calibSlotE  = calibSlotB + 1;
            const uint32_t calibSlotB  = 0;
            const uint32_t calibSlotE  = 1;

            WGPUPassTimestampWrites anchorTs = {};
            anchorTs.querySet                  = m_querySet;
            anchorTs.beginningOfPassWriteIndex = calibSlotB;
            anchorTs.endOfPassWriteIndex       = calibSlotE;

            WGPURenderPassColorAttachment att = {};
            att.view       = texView;
            att.loadOp     = WGPULoadOp_Clear;
            att.storeOp    = WGPUStoreOp_Store;
            att.depthSlice = WGPU_DEPTH_SLICE_UNDEFINED;

            WGPURenderPassDescriptor passDesc = {};
            passDesc.colorAttachmentCount = 1;
            passDesc.colorAttachments     = &att;
            passDesc.timestampWrites      = &anchorTs;

            WGPURenderPassEncoder pass = wgpuCommandEncoderBeginRenderPass(enc, &passDesc);
            wgpuRenderPassEncoderSetPipeline(pass, calibPipeline);
            wgpuRenderPassEncoderDraw(pass, 3, 1, 0, 0);
            wgpuRenderPassEncoderEnd(pass);
            wgpuRenderPassEncoderRelease(pass);
            wgpuRenderPipelineRelease(calibPipeline);
            wgpuShaderModuleRelease(calibShader);
            wgpuTextureViewRelease(texView);
            wgpuTextureRelease(tex);

            wgpuCommandEncoderResolveQuerySet(enc, m_querySet, calibSlotB, 2, m_resolveBuffer, calibSlotB * sizeof(uint64_t));
            wgpuCommandEncoderCopyBufferToBuffer(enc, m_resolveBuffer, calibSlotB * sizeof(uint64_t), m_readbackSlots[0].buffer, calibSlotB * sizeof(uint64_t), 2 * sizeof(uint64_t));

            WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(enc, nullptr);
            wgpuCommandEncoderRelease(enc);
            if (!cmd) { TracyWebGPUPanic("Failed to finish calibration command encoder.", return false); }

            auto t0 = Profiler::GetTime();
            wgpuQueueSubmit(m_queue, 1, &cmd);
            wgpuCommandBufferRelease(cmd);

            // Wait for the GPU to finish executing the command buffer before mapping.
            bool gpuDone = false;
            WGPUQueueWorkDoneCallbackInfo doneCB = {};
            doneCB.mode      = WGPUCallbackMode_AllowProcessEvents;
            doneCB.callback  = [](WGPUQueueWorkDoneStatus, WGPUStringView, void* ud, void*) {
                *static_cast<bool*>(ud) = true;
            };
            doneCB.userdata1 = &gpuDone;
            wgpuQueueOnSubmittedWorkDone(m_queue, doneCB);

            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            while (!gpuDone && std::chrono::steady_clock::now() < deadline)
                wgpuInstanceProcessEvents(m_instance);

            struct MapCtx { WGPUBuffer buffer; uint32_t slotB; uint64_t gpuTime = 0; bool ok = false; };
            MapCtx mctx{ m_readbackSlots[0].buffer, calibSlotB };
            WGPUBufferMapCallbackInfo cbInfo = {};
            cbInfo.mode      = WGPUCallbackMode_AllowProcessEvents;
            cbInfo.callback  = [](WGPUMapAsyncStatus status, WGPUStringView, void* ud, void*) {
                auto* ctx = static_cast<MapCtx*>(ud);
                if (status != WGPUMapAsyncStatus_Success) return;
                const auto* ts = static_cast<const uint64_t*>(
                    wgpuBufferGetConstMappedRange(ctx->buffer, ctx->slotB * sizeof(uint64_t), 2 * sizeof(uint64_t)));
                if (ts)
                {
                    ctx->gpuTime = ts[0];
                    ctx->ok = true;
                    fprintf(stdout, "CalibrateClocks() -> %llu | %llu | %lld\n", ts[0], ts[1], ts[1]-ts[0]);
                }
                wgpuBufferUnmap(ctx->buffer);
            };
            cbInfo.userdata1 = &mctx;
            wgpuBufferMapAsync(m_readbackSlots[0].buffer, WGPUMapMode_Read,
                               calibSlotB * sizeof(uint64_t), 2 * sizeof(uint64_t), cbInfo);

            while (!mctx.ok && std::chrono::steady_clock::now() < deadline)
                wgpuInstanceProcessEvents(m_instance);
            //m_previousCheckpoint = m_queryCounter.load();

            auto t1 = Profiler::GetTime();
            //outCpuTime = static_cast<uint64_t>(t0 + (t1-t0)/2);
            outCpuTime = t1;

            if (!mctx.ok)
            {
                TracyWebGPUPanic("Failed to calibrate CPU/GPU clocks.", return false);
            }

            outGpuTime = mctx.gpuTime;
            fprintf(stdout, "CalibrateClocks() -> %llu\n", outGpuTime);
            if (outGpuTime < m_prevCalibGpuTime)
                fprintf(stdout, "CalibrateClocks() -> WARNING!!! going backwards!\n%llu\n%llu\n%lld\n", m_prevCalibGpuTime, outGpuTime, outGpuTime-m_prevCalibGpuTime);
            m_prevCalibGpuTime = outGpuTime;
            return true;
        }

    public:
        static bool SetupDevice(WGPUDeviceDescriptor& deviceDescriptor)
        {
            // piggy-back on WGPU_DAWN_TOGGLES_DESCRIPTOR_INIT to detect Dawn header
#           ifdef WGPU_DAWN_TOGGLES_DESCRIPTOR_INIT
                fprintf(stderr, "[INFO] [DAWN] ENABLING RAW TIMESTAMP TICKS (disabling ns conversion + quantization)\n");
                // disable_timestamp_query_conversion: resolve timestamps as raw GPU ticks, not nanoseconds.
                // timestamp_quantization: disabled defensively (off by default on Metal, but on elsewhere).
                static const char* dawnDisabledToggles[] = { "timestamp_quantization" };
                static const char* dawnEnabledToggles[]  = { "disable_timestamp_query_conversion" };
                static WGPUDawnTogglesDescriptor togglesDesc = {};
                togglesDesc.chain.sType = WGPUSType_DawnTogglesDescriptor;
                togglesDesc.disabledToggles = dawnDisabledToggles;
                togglesDesc.disabledToggleCount = 1;
                togglesDesc.enabledToggles = dawnEnabledToggles;
                togglesDesc.enabledToggleCount  = 1;
                deviceDescriptor.nextInChain = reinterpret_cast<WGPUChainedStruct*>(&togglesDesc);
#           endif
            return true;
        }

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

            // Graceful early-out: if the logical device was created without the
            // required timestamp features, GPU zones will silently do nothing.
            // m_contextId stays 255 (invalid); CreateWebGPUContext destroys and
            // returns nullptr, and all TracyWebGPU* macros become no-ops.
            if (!wgpuDeviceHasFeature(m_device, WGPUFeatureName_TimestampQuery))
            {
                TracyWebGPUPanic(
                    "timestamp-query feature not enabled on device; GPU profiling disabled.",
                    return
                )
            }
            // wgpuCommandEncoderResolveQuerySet requires the wgpu-native
            // TIMESTAMP_QUERY_INSIDE_ENCODERS feature on some backends.
#ifdef WGPUNativeFeature_TimestampQueryInsideEncoders
            if (!wgpuDeviceHasFeature(m_device, (WGPUFeatureName)WGPUNativeFeature_TimestampQueryInsideEncoders))
            {
                TracyWebGPUPanic(
                    "WGPUNativeFeature_TimestampQueryInsideEncoders not enabled on device; "
                    "GPU profiling disabled (needed for ResolveQuerySet on the command encoder).",
                    return
                );
            }
#endif

            // Pick a query budget. WebGPU has no native upper bound on query
            // set size in the spec. The WebGPU default/max for maxQuerySetSize
            // is 4096. Queries are issued in (begin, end) pairs, so the count is
            // always even.
            static constexpr uint32_t MaxQueries = 512; //4096;
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

            // Readback buffers: targets of CopyBufferToBuffer; mappable for read (3-slot ring).
            WGPUBufferDescriptor readbackDesc = {};
            readbackDesc.usage = WGPUBufferUsage_CopyDst | WGPUBufferUsage_MapRead;
            readbackDesc.size  = static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t);
            for (auto& slot : m_readbackSlots)
            {
                slot.buffer = wgpuDeviceCreateBuffer(m_device, &readbackDesc);
                slot.copiedUpto = 0;
                if (!slot.buffer) { TracyWebGPUPanic("Failed to create timestamp readback buffer.", return); }
            }

            // Establish the (cpuTime, gpuTime) anchor for Tracy's GpuNewContext.
            // WebGPU has no "clock calibration API", so we use a one-shot anchor
            // to estimate a correlation for the CPU and the GPU timestamps.
            uint64_t cpuTimestamp = 0;
            uint64_t gpuTimestamp = 0;
            if (!CalibrateClocks(cpuTimestamp, gpuTimestamp))
            {
                TracyWebGPUPanic("Failed to calibrate CPU/GPU clocks.", return);
            }

            fprintf(stdout, "INFO: gpuTimestamp is %llu\n", gpuTimestamp);
            //m_shadowBuffer.resize(m_queryLimit, gpuTimestamp);
            m_shadowBuffer.resize(m_queryLimit, 0);

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
            Collect(); // best-effort non-blocking flush

            // Block until any in-flight map completes before releasing buffers.
            for (auto& slot : m_readbackSlots)
                if (slot.buffer) { wgpuBufferRelease(slot.buffer); slot.buffer = nullptr; }
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

        void Collect(bool webgpuProcessEvents=false)
        {
#ifdef TRACY_ON_DEMAND
            if (!GetProfiler().IsConnected()) return;
#endif
            if (!m_collectionMutex.try_lock()) return;
            std::unique_lock<std::mutex> lock(m_collectionMutex, std::adopt_lock);

            ZoneScopedC(Color::Red4);

            if (Distance(m_previousCheckpoint, m_queryCounter) <= 0)
                return;

            const int collectIdx = (m_writeIdx + 2) % 3;
            auto& collectSlot = m_readbackSlots[collectIdx];

            // Poll for an in-flight map to complete.
            if (collectSlot.pendingFuture.id != 0)
            {
                if (webgpuProcessEvents)
                    wgpuInstanceProcessEvents(m_instance);
                if (collectSlot.mapStatus == WGPUMapAsyncStatus{})
                    return;  // callback hasn't fired yet
                collectSlot.pendingFuture = {};
            }

            // If a buffer is mapped, process as many resolved queries as possible.
            if (collectSlot.mapStatus == WGPUMapAsyncStatus_Success)
            {
                const uint64_t* ts = static_cast<const uint64_t*>(
                    wgpuBufferGetConstMappedRange(collectSlot.buffer, 0,
                        static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t)));
                if (ts)
                {
                    uint64_t ticket = m_previousCheckpoint;
                    const uint64_t end = collectSlot.copiedUpto;
                    fprintf(stdout, "[TWG] Collect [%d] (%llu, %llu)\n", collectIdx, ticket, end);
                    for (; Distance(ticket, end) > 0; ticket += 2)
                    {
                        const uint32_t slotB = RingIndex(ticket);
                        const uint32_t slotE = slotB + 1;
                        fprintf(stderr,
                            "[TWG] slot B=%4u E=%4u ts[B]=%llu ts[E]=%llu shadow[E]=%llu ts-diff=%lld shadow-diff=%lld\n",
                            slotB, slotE,
                            (unsigned long long)ts[slotB],
                            (unsigned long long)ts[slotE],
                            (unsigned long long)m_shadowBuffer[slotE],
                            (long long)Distance(ts[slotB], ts[slotE]),
                            (long long)Distance(m_shadowBuffer[slotE], ts[slotE]));
                        if (Distance(m_shadowBuffer[slotE], ts[slotE]) <= 0)
                            break; // GPU hasn't written this timestamp yet; retry next Collect()
                        EmitGpuTime(ts[slotB], slotB);
                        EmitGpuTime(ts[slotE], slotE);
                    }
                    m_previousCheckpoint = ticket;

                    if (Distance(ticket, end) > 0)
                        return; // still unresolved queries in this buffer; come back next Collect()
                }

                // All queries resolved (or getMappedRange failed): unmap and fall through to rotate.
                wgpuBufferUnmap(collectSlot.buffer);
                collectSlot.mapStatus = {};
            }

            // Idle: rotate the ring and start the next map if there is committed data to collect.
            //   WRITE   = m_writeIdx
            //   PENDING = (m_writeIdx + 1) % 3  ← map this
            //   COLLECT = (m_writeIdx + 2) % 3  ← recycle as new WRITE
            const int writeIdx   = m_writeIdx;
            const int pendingIdx = (writeIdx + 1) % 3;

            if (m_readbackSlots[writeIdx].copiedUpto <= m_previousCheckpoint)
                return;

            const int newWriteIdx = (writeIdx + 2) % 3;

            m_readbackSlots[newWriteIdx].copiedUpto = m_previousCheckpoint.load();

            m_writeIdx = newWriteIdx;

            WGPUBufferMapCallbackInfo cbInfo = {};
            cbInfo.mode      = WGPUCallbackMode_AllowProcessEvents;
            cbInfo.callback  = &WebGPUQueueCtx::OnMapped;
            cbInfo.userdata1 = this;
            m_readbackSlots[pendingIdx].pendingFuture = wgpuBufferMapAsync(
                m_readbackSlots[pendingIdx].buffer, WGPUMapMode_Read, 0,
                static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t), cbInfo);

            // Optimistic immediate poll: deliver any already-completed callbacks.
            wgpuInstanceProcessEvents(m_instance);
            if (m_readbackSlots[pendingIdx].mapStatus != WGPUMapAsyncStatus{})
                m_readbackSlots[pendingIdx].pendingFuture = {};
        }

    private:
        // Drive the WebGPU event queue to deliver pending callbacks.
        // wgpuInstanceProcessEvents is the canonical webgpu.h API.
        // wgpu-native additionally benefits from wgpuDevicePoll.
        void ProcessEvents()
        {
            if (m_instance)
                wgpuInstanceProcessEvents(m_instance);
#ifdef WGPU_H_
            wgpuDevicePoll(m_device, false, nullptr);
#endif
        }

        static void OnMapped(WGPUMapAsyncStatus status, WGPUStringView, void* ud, void*)
        {
            auto* self = static_cast<WebGPUQueueCtx*>(ud);
            const int collectIdx = (self->m_writeIdx + 2) % 3;
            self->m_readbackSlots[collectIdx].mapStatus = status;
        }

        void EmitGpuTime(uint64_t gpuTimestamp, uint32_t slot)
        {
            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuTime);
            MemWrite(&item->gpuTime.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuTime.queryId, static_cast<uint16_t>(slot));
            MemWrite(&item->gpuTime.context, GetId());
            Profiler::QueueSerialFinish();
            m_shadowBuffer[slot] = gpuTimestamp;
        }

        tracy_force_inline uint32_t RingCapacity() const { return m_queryLimit; }

        tracy_force_inline uint32_t RingIndex(uint64_t t) const
        {
            return static_cast<uint32_t>(t % RingCapacity());
        }

        tracy_force_inline static int64_t Distance(uint64_t begin, uint64_t end)
        {
            return static_cast<int64_t>(end - begin);
        }

        tracy_force_inline uint64_t NextQueryId()
        {
            const uint64_t ticket = m_queryCounter.fetch_add(2, std::memory_order_relaxed);
            if (Distance(m_previousCheckpoint, ticket)
                >= static_cast<int64_t>(RingCapacity()))
            {
                TracyWebGPULog(Warning, "Too many pending GPU queries: stalling!");
                Collect();
            }
            return ticket;
        }
    };

    class WebGPUZoneScope
    {
        const bool         m_active;
        WebGPUQueueCtx*    m_ctx       = nullptr;
        WGPUCommandEncoder m_encoder   = nullptr;
        uint64_t           m_rawTicket = 0;  // raw (non-modded) ticket from NextQueryId
        uint32_t           m_queryId   = 0;  // ring index = m_rawTicket % queryLimit

        WGPUPassTimestampWrites m_timestampWrites = {};

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

        // Fills in m_timestampWrites and assigns its address to passDesc.timestampWrites.
        // Works with both WGPURenderPassDescriptor and WGPUComputePassDescriptor.
        template<typename PassDescriptor>
        tracy_force_inline void InitBase(WebGPUQueueCtx* ctx, WGPUCommandEncoder encoder, PassDescriptor& passDesc)
        {
            m_ctx       = ctx;
            m_encoder   = encoder;

            m_rawTicket = m_ctx->NextQueryId();
            m_queryId   = static_cast<uint32_t>(m_rawTicket % ctx->m_queryLimit);
            m_timestampWrites.querySet                  = m_ctx->m_querySet;
            m_timestampWrites.beginningOfPassWriteIndex = m_queryId;
            m_timestampWrites.endOfPassWriteIndex       = m_queryId + 1;
            passDesc.timestampWrites                    = &m_timestampWrites;
        }

    public:
        template<typename PassDescriptor>
        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, WGPUCommandEncoder encoder, PassDescriptor& passDesc, const SourceLocationData* srcLocation, bool active)
#ifdef TRACY_ON_DEMAND
            : m_active(active && GetProfiler().IsConnected())
#else
            : m_active(active)
#endif
        {
            if (!m_active) return;
            InitBase(ctx, encoder, passDesc);
            WriteQueueItem(srcLocation, 0, 0, nullptr, 0, nullptr, 0, nullptr, 0);
        }

        template<typename PassDescriptor>
        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, WGPUCommandEncoder encoder, PassDescriptor& passDesc, const SourceLocationData* srcLocation, int32_t depth, bool active)
#ifdef TRACY_ON_DEMAND
            : m_active(active && GetProfiler().IsConnected())
#else
            : m_active(active)
#endif
        {
            if (!m_active) return;
            InitBase(ctx, encoder, passDesc);
            WriteQueueItem(srcLocation, depth, 0, nullptr, 0, nullptr, 0, nullptr, 0);
        }

        template<typename PassDescriptor>
        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, WGPUCommandEncoder encoder, PassDescriptor& passDesc, bool active)
#ifdef TRACY_ON_DEMAND
            : m_active(active && GetProfiler().IsConnected())
#else
            : m_active(active)
#endif
        {
            if (!m_active) return;
            InitBase(ctx, encoder, passDesc);
            WriteQueueItem(nullptr, 0, line, source, sourceSz, function, functionSz, name, nameSz);
        }

        template<typename PassDescriptor>
        tracy_force_inline WebGPUZoneScope(WebGPUQueueCtx* ctx, uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, WGPUCommandEncoder encoder, PassDescriptor& passDesc, int32_t depth, bool active)
#ifdef TRACY_ON_DEMAND
            : m_active(active && GetProfiler().IsConnected())
#else
            : m_active(active)
#endif
        {
            if (!m_active) return;
            InitBase(ctx, encoder, passDesc);
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

            if (m_queryId % 32 == 30)
            {
                // 32 queries = 32 * 8 bytes = 256 bytes
                const uint32_t blockStart  = m_queryId - 30;
                const uint64_t blockOffset = static_cast<uint64_t>(blockStart) * sizeof(uint64_t);
                wgpuCommandEncoderResolveQuerySet(
                    m_encoder,
                    m_ctx->m_querySet,
                    blockStart, 32,
                    m_ctx->m_resolveBuffer,
                    blockOffset // MUST be a multiple of (aligned to) 256...
                );
                auto& slot = m_ctx->m_readbackSlots[m_ctx->m_writeIdx];
                auto readbackBuffer = slot.buffer;
                wgpuCommandEncoderCopyBufferToBuffer(
                    m_encoder,
                    m_ctx->m_resolveBuffer,
                    blockOffset,
                    readbackBuffer,
                    blockOffset,
                    32 * sizeof(uint64_t));
                // Advance this slot's high-water mark to cover the block just encoded.
                const uint64_t blockEnd = m_rawTicket + 2;
                uint64_t prev = slot.copiedUpto;
                while (prev < blockEnd &&
                       !slot.copiedUpto.compare_exchange_weak(prev, blockEnd)) {}
                fprintf(stdout, "[TWG] WebGPUZoneScope [%d] (%d,%d)\n", (int)m_ctx->m_writeIdx, blockStart, m_queryId);
            }
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

#define TracyWebGPUUnnamedZone ___tracy_gpu_webgpu_zone
#define TracyWebGPUSrcLocSymbol TracyConcat(__tracy_webgpu_source_location,TracyLine)
#define TracyWebGPUSrcLocObject(name, color) static constexpr tracy::SourceLocationData TracyWebGPUSrcLocSymbol { name, TracyFunction, TracyFile, (uint32_t)TracyLine, color };

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyWebGPUZone(ctx, encoder, passDesc, name) TracyWebGPUNamedZoneS(ctx, TracyWebGPUUnnamedZone, encoder, passDesc, name, TRACY_CALLSTACK, true)
#  define TracyWebGPUZoneC(ctx, encoder, passDesc, name, color) TracyWebGPUNamedZoneCS(ctx, TracyWebGPUUnnamedZone, encoder, passDesc, name, color, TRACY_CALLSTACK, true)
#  define TracyWebGPUNamedZone(ctx, varname, encoder, passDesc, name, active) TracyWebGPUSrcLocObject(name, 0); tracy::WebGPUZoneScope varname{ ctx, encoder, passDesc, &TracyWebGPUSrcLocSymbol, TRACY_CALLSTACK, active };
#  define TracyWebGPUNamedZoneC(ctx, varname, encoder, passDesc, name, color, active) TracyWebGPUSrcLocObject(name, color); tracy::WebGPUZoneScope varname{ ctx, encoder, passDesc, &TracyWebGPUSrcLocSymbol, TRACY_CALLSTACK, active };
#  define TracyWebGPUZoneTransient(ctx, varname, encoder, passDesc, name, active) TracyWebGPUZoneTransientS(ctx, varname, encoder, passDesc, name, TRACY_CALLSTACK, active)
#else
#  define TracyWebGPUZone(ctx, encoder, passDesc, name) TracyWebGPUNamedZone(ctx, TracyWebGPUUnnamedZone, encoder, passDesc, name, true)
#  define TracyWebGPUZoneC(ctx, encoder, passDesc, name, color) TracyWebGPUNamedZoneC(ctx, TracyWebGPUUnnamedZone, encoder, passDesc, name, color, true)
#  define TracyWebGPUNamedZone(ctx, varname, encoder, passDesc, name, active) TracyWebGPUSrcLocObject(name, 0); tracy::WebGPUZoneScope varname{ ctx, encoder, passDesc, &TracyWebGPUSrcLocSymbol, active };
#  define TracyWebGPUNamedZoneC(ctx, varname, encoder, passDesc, name, color, active) TracyWebGPUSrcLocObject(name, color); tracy::WebGPUZoneScope varname{ ctx, encoder, passDesc, &TracyWebGPUSrcLocSymbol, active };
#  define TracyWebGPUZoneTransient(ctx, varname, encoder, passDesc, name, active) tracy::WebGPUZoneScope varname{ ctx, TracyLine, TracyFile, strlen(TracyFile), TracyFunction, strlen(TracyFunction), name, strlen(name), encoder, passDesc, active };
#endif

#ifdef TRACY_HAS_CALLSTACK
#  define TracyWebGPUZoneS(ctx, encoder, passDesc, name, depth) TracyWebGPUNamedZoneS(ctx, TracyWebGPUUnnamedZone, encoder, passDesc, name, depth, true)
#  define TracyWebGPUZoneCS(ctx, encoder, passDesc, name, color, depth) TracyWebGPUNamedZoneCS(ctx, TracyWebGPUUnnamedZone, encoder, passDesc, name, color, depth, true)
#  define TracyWebGPUNamedZoneS(ctx, varname, encoder, passDesc, name, depth, active) TracyWebGPUSrcLocObject(name, 0); tracy::WebGPUZoneScope varname{ ctx, encoder, passDesc, &TracyWebGPUSrcLocSymbol, depth, active };
#  define TracyWebGPUNamedZoneCS(ctx, varname, encoder, passDesc, name, color, depth, active) TracyWebGPUSrcLocObject(name, color); tracy::WebGPUZoneScope varname{ ctx, encoder, passDesc, &TracyWebGPUSrcLocSymbol, depth, active };
#  define TracyWebGPUZoneTransientS(ctx, varname, encoder, passDesc, name, depth, active) tracy::WebGPUZoneScope varname{ ctx, TracyLine, TracyFile, strlen(TracyFile), TracyFunction, strlen(TracyFunction), name, strlen(name), encoder, passDesc, depth, active };
#else
#  define TracyWebGPUZoneS(ctx, encoder, passDesc, name, depth) TracyWebGPUZone(ctx, encoder, passDesc, name)
#  define TracyWebGPUZoneCS(ctx, encoder, passDesc, name, color, depth) TracyWebGPUZoneC(ctx, encoder, passDesc, name, color)
#  define TracyWebGPUNamedZoneS(ctx, varname, encoder, passDesc, name, depth, active) TracyWebGPUNamedZone(ctx, varname, encoder, passDesc, name, active)
#  define TracyWebGPUNamedZoneCS(ctx, varname, encoder, passDesc, name, color, depth, active) TracyWebGPUNamedZoneC(ctx, varname, encoder, passDesc, name, color, active)
#  define TracyWebGPUZoneTransientS(ctx, varname, encoder, passDesc, name, depth, active) TracyWebGPUZoneTransient(ctx, varname, encoder, passDesc, name, active)
#endif

#define TracyWebGPUCollect(ctx) ctx->Collect();

#endif

#endif
