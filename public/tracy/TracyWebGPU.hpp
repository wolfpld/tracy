#ifndef __TRACYWEBGPU_HPP__
#define __TRACYWEBGPU_HPP__

// WebGPU, unlike other graphics APIs, has many annoying restrictions that complicate
// the design of the Tracy WebGPU back-end:
// - there's no CPU/GPU clock calibration API
// - submitting GPU commands that touch a buffer that the host is mapping is not permitted
// - resolving timestamps require destination offsets aligned to 256 bytes
// - timestamps are only available at pass granularity (implementations may need to emulate this)
// - spec mandates timestamps to be in nanoseconds (implementationw may need to emulate this)

#ifndef TRACY_ENABLE

#define TracyWebGPUSetupDeviceDescriptor(deviceDescriptor)

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

// piggy-back on WGPU_DAWN_TOGGLES_DESCRIPTOR_INIT to detect Dawn header
#ifdef WGPU_DAWN_TOGGLES_DESCRIPTOR_INIT
#define TRACY_WEBGPU_DAWN_NATIVE (1)
#include <dawn/native/DawnNative.h>
#else
#define TRACY_WEBGPU_WGPU_NATIVE (1)
#include <webgpu/wgpu.h>
#endif

#ifndef TRACY_WEBGPU_DEBUG_LEVEL
#define TRACY_WEBGPU_DEBUG_LEVEL (0)
#endif//TRACY_WEBGPU_DEBUG_LEVEL

#if TRACY_WEBGPU_DEBUG_LEVEL
#define TracyWebGPUDebug(...) __VA_ARGS__;
#if defined(_MSC_VER)
extern "C" int32_t IsDebuggerPresent(void);
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

#define TracyWebGPULog(severity, msg) do { char buffer [1024]; int len = snprintf(buffer, sizeof(buffer), "TracyWebGPU: %s", msg); tracy::Profiler::LogString( tracy::MessageSourceType::Tracy, tracy::MessageSeverity::severity, tracy::Color::Red4, 0, len, buffer ); } while(false)
#define TracyWebGPUPanic(msg, ...) do { TracyWebGPULog(Error, msg); TracyWebGPUAssert(false && "TracyWebGPU: " msg); __VA_ARGS__; } while(false)

namespace tracy
{

    class WebGPUQueueCtx
    {
        friend class WebGPUZoneScope;

        uint8_t m_contextId = 255;  // 255 represents "invalid id"

        std::mutex m_collectionMutex;

        WGPUInstance m_instance = nullptr;
        WGPUDevice m_device = nullptr;
        WGPUQueue m_queue = nullptr;

        struct ReadbackStage
        {
            WGPUBuffer buffer = nullptr;
            std::atomic<uint64_t> copiedUpto {0};
            std::atomic<WGPUMapAsyncStatus> mapStatus = {};
            WGPUFuture pendingFuture = {};
        };
        static_assert(std::atomic<WGPUMapAsyncStatus>::is_always_lock_free, "WGPUMapAsyncStatus must be lock-free atomic");

        WGPUQuerySet  m_querySet = nullptr;
        WGPUBuffer    m_resolveBuffer = nullptr;
        ReadbackStage m_readbackReel [3];
        std::atomic<int> m_writeIdx {0};

        using atomic_counter = std::atomic<uint64_t>;
        atomic_counter m_queryCounter = 0;
        atomic_counter m_previousCheckpoint = 0;

        uint32_t m_queryLimit = 0;

        std::vector<uint64_t> m_shadowBuffer;

        using WallTime = std::chrono::steady_clock::time_point;
        static tracy_force_inline auto GetWallTime() { return WallTime::clock::now(); }
        static tracy_force_inline auto Milliseconds(int value) { return std::chrono::milliseconds(value); }

        static bool WaitQueueIdle(WGPUQueue queue, WGPUInstance instance)
        {
            bool gpuDone = false;
            WGPUQueueWorkDoneCallbackInfo doneCB = {};
            doneCB.mode = WGPUCallbackMode_AllowProcessEvents;
            doneCB.callback = [](WGPUQueueWorkDoneStatus, WGPUStringView, void* userData, void*) {
                *static_cast<bool*>(userData) = true;
            };
            doneCB.userdata1 = &gpuDone;
            wgpuQueueOnSubmittedWorkDone(queue, doneCB);

            const auto deadline = GetWallTime() + Milliseconds(2000);
            while (!gpuDone && GetWallTime() < deadline)
                wgpuInstanceProcessEvents(instance);
            return gpuDone;
        }

        static const uint64_t* MapBufferSync(WGPUBuffer buffer, WGPUInstance instance)
        {
            struct MapCtx { WGPUMapAsyncStatus status = {}; } ctx;
            WGPUBufferMapCallbackInfo cbInfo = {};
            cbInfo.mode      = WGPUCallbackMode_AllowProcessEvents;
            cbInfo.callback  = [](WGPUMapAsyncStatus status, WGPUStringView, void* userData, void*) {
                auto* ctx = static_cast<MapCtx*>(userData);
                ctx->status = status;
            };
            cbInfo.userdata1 = &ctx;
            size_t offset = 0;
            size_t size = 2 * sizeof(uint64_t);
            wgpuBufferMapAsync(buffer, WGPUMapMode_Read, offset, size, cbInfo);

            const auto deadline = GetWallTime() + Milliseconds(2000);
            while (ctx.status == 0 && GetWallTime() < deadline)
                wgpuInstanceProcessEvents(instance);

            if (ctx.status != WGPUMapAsyncStatus_Success) return nullptr;
            auto data = wgpuBufferGetConstMappedRange(buffer, offset, size);
            return static_cast<const uint64_t*>(data);
        }

        struct Calibration {
            int64_t minCpuRange = ~uint64_t(0) >> 1;
            struct Regression
            {
                int64_t n = 0;
                int64_t mean_x = 0;
                int64_t mean_y = 0;
                int64_t S_xx = 0;
                int64_t S_xy = 0;
                void Update(int64_t x, int64_t y)
                {
                    n += 1;
                    int64_t dx = x - mean_x;
                    int64_t dy = y - mean_y;
                    mean_x += dx / n;
                    mean_y += dy / n;
                    S_xx += dx * (x - mean_x);
                    S_xy += dx * (y - mean_y);
                }
                double Slope() const { return double(S_xy) / S_xx; }
                double Intercept() const { return mean_y - Slope() * mean_x; }
            };
            Regression cpuToGpuModel;   // cpu-ticks to gpu-ticks
            Regression cpuRangeModel;   // cpu-tick interval uncertainty
            Regression wallToGpuModel;  // nanoseconds to gpu-ticks
            void GetReferenceTime(uint64_t& cpuTime, uint64_t& gpuTime) const
            {
                // the mean belongs to the regression line
                cpuTime = cpuToGpuModel.mean_x;
                gpuTime = cpuToGpuModel.mean_y;
            }
            double Period() const { return 1.0 / wallToGpuModel.Slope(); }    // ns/tick
            bool AcceptX(const Regression& r, int64_t x, double threshold = 3.0) const {
                if (r.n < 2) return true;
                auto dx = x - r.mean_x;
                if (dx <= 0) return true; // always accept "tighter" outliers
                double variance = double(r.S_xx) / (r.n - 1);
                if (variance == 0.0) return true;
                // WARN: dx*dx "could" overflow, but very unlikely in practice
                double zz = (double)(dx*dx) / variance;
                return zz <= (threshold*threshold);
            }
            bool Update(WallTime twall0, WallTime twall1, uint64_t tcpu0, uint64_t tcpu1, uint64_t tgpu)
            {
                using namespace std::chrono;
                int64_t cpuRange = tcpu1 - tcpu0;
                cpuRangeModel.Update(cpuRange, 0);
                if (!AcceptX(cpuRangeModel, cpuRange, 1.0)) return false;
                // Process sample:
                int64_t tcpu = tcpu0 + (tcpu1 - tcpu0) / 2; // mid-point
                int64_t twall = duration_cast<nanoseconds>(
                    (twall0 + (twall1 - twall0) / 2)        // mid-point
                    .time_since_epoch()
                ).count();
                // incremental regression:
                cpuToGpuModel.Update(tcpu, tgpu);
                wallToGpuModel.Update(twall, tgpu);
                TracyWebGPUDebug( fprintf(stderr, "----- (sample accepted! wall = %lld | cpu = %lld | gpu = %lld | period = %f)\n", twall, tcpu, tgpu, Period()) );
                return true;
            }
        } m_calibration;

        tracy_force_inline void SubmitQueueItem(tracy::QueueItem* item)
        {
#ifdef TRACY_ON_DEMAND
            GetProfiler().DeferItem(*item);
#endif
            Profiler::QueueSerialFinish();
        }

        bool CalibrateClocks(uint64_t& outCpuTime, uint64_t& outGpuTime, double& period)
        {
            // WebGPU does not have any clock calibration API.
            // This routine attempts to estimates a reasonable (cpuTime, gpuTime) correlation
            // by sampling CPU and GPU timestamps around a "synchronous" draw call.
            // Several samples are taken to tighten the estimation.

            ZoneScoped;

            WGPUShaderSourceWGSL wgslSrc = {};
            wgslSrc.chain.sType = WGPUSType_ShaderSourceWGSL;
            wgslSrc.code =
            {
                R"(
                @vertex fn vs(@builtin(vertex_index) i: u32) -> @builtin(position) vec4f {
                    var p = array(vec4f(-1,-1,.5,1), vec4f(3,-1,.5,1), vec4f(-1,3,.5,1));
                    return p[i];
                }
                @fragment fn fs() -> @location(0) vec4f { return vec4f(0.0); }
                )",
                WGPU_STRLEN
            };
            WGPUShaderModuleDescriptor smDesc = {};
            smDesc.nextInChain  = reinterpret_cast<WGPUChainedStruct*>(&wgslSrc);
            WGPUShaderModule calibShader = wgpuDeviceCreateShaderModule(m_device, &smDesc);
            if (!calibShader) { TracyWebGPUPanic("Failed to create calibration shader.", return false); }

            WGPUTextureDescriptor texDesc = {};
            texDesc.usage         = WGPUTextureUsage_RenderAttachment;
            texDesc.dimension     = WGPUTextureDimension_2D;
            texDesc.size          = { 1, 1, 1 };
            texDesc.format        = WGPUTextureFormat_BGRA8Unorm;
            texDesc.mipLevelCount = 1;
            texDesc.sampleCount   = 1;
            WGPUTexture tex = wgpuDeviceCreateTexture(m_device, &texDesc);
            if (!tex) { wgpuShaderModuleRelease(calibShader); TracyWebGPUPanic("Failed to create calibration scratch texture.", return false); }
            WGPUTextureView texView = wgpuTextureCreateView(tex, nullptr);
            if (!texView) { wgpuTextureRelease(tex); wgpuShaderModuleRelease(calibShader); TracyWebGPUPanic("Failed to create calibration scratch texture view.", return false); }

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
            if (!calibPipeline) { wgpuTextureViewRelease(texView); wgpuTextureRelease(tex); wgpuShaderModuleRelease(calibShader); TracyWebGPUPanic("Failed to create calibration pipeline.", return false); }

            uint32_t queryId = 0;
            WGPUPassTimestampWrites anchorTs = {};
            anchorTs.querySet                  = m_querySet;
            anchorTs.beginningOfPassWriteIndex = queryId;
            anchorTs.endOfPassWriteIndex       = queryId+1;

            WGPURenderPassColorAttachment att = {};
            att.view       = texView;
            att.loadOp     = WGPULoadOp_Clear;
            att.storeOp    = WGPUStoreOp_Store;
            att.depthSlice = WGPU_DEPTH_SLICE_UNDEFINED;

            WGPURenderPassDescriptor passDesc = {};
            passDesc.colorAttachmentCount = 1;
            passDesc.colorAttachments     = &att;
            passDesc.timestampWrites      = &anchorTs;

            // calibration loop
            const auto deadline = GetWallTime() + Milliseconds(100);
            for (int i = 0; i < 1000; ++i)
            {
                // loop until time budget (100ms) allows, but ensure at least 5 iterations
                if ((GetWallTime() >= deadline) && (i > 5))
                    break;

                WGPUCommandEncoder enc = wgpuDeviceCreateCommandEncoder(m_device, nullptr);
                if (!enc) { TracyWebGPUPanic("Failed to create command encoder for time calibration.", return false); }

                WGPURenderPassEncoder pass = wgpuCommandEncoderBeginRenderPass(enc, &passDesc);
                wgpuRenderPassEncoderSetPipeline(pass, calibPipeline);
                wgpuRenderPassEncoderDraw(pass, 3, 1, 0, 0);
                wgpuRenderPassEncoderEnd(pass);
                wgpuRenderPassEncoderRelease(pass);

                WGPUBuffer readBackBuffer = m_readbackReel[0].buffer;
                uint32_t byteOffset = queryId * sizeof(uint64_t);
                uint32_t sizeInBytes = 2 * sizeof(uint64_t);
                wgpuCommandEncoderResolveQuerySet(enc, m_querySet, queryId, 2, m_resolveBuffer, byteOffset);
                wgpuCommandEncoderCopyBufferToBuffer(enc, m_resolveBuffer, byteOffset, readBackBuffer, byteOffset, sizeInBytes);

                WGPUCommandBuffer cmd = wgpuCommandEncoderFinish(enc, nullptr);
                wgpuCommandEncoderRelease(enc);
                if (!cmd) { TracyWebGPUPanic("Failed to finish calibration command encoder.", return false); }

                WaitQueueIdle(m_queue, m_instance);
                int64_t cpu [2] = {};
                int64_t gpu [2] = {};
                WallTime wall [2] = {};
                cpu[0] = Profiler::GetTime();
                wall[0] = GetWallTime();
                wgpuQueueSubmit(m_queue, 1, &cmd);
                wgpuCommandBufferRelease(cmd);
                WaitQueueIdle(m_queue, m_instance);
                wall[1] = GetWallTime();
                cpu[1] = Profiler::GetTime();
                auto gpuTimestamps = MapBufferSync(readBackBuffer, m_instance);
                TracyWebGPUAssert(gpuTimestamps != nullptr);
                gpu[0] = gpuTimestamps[0];
                gpu[1] = gpuTimestamps[1];
                wgpuBufferUnmap(readBackBuffer);
                TracyWebGPUDebug(
                    fprintf(stdout, "[%03d] CalibrateClocks() [CPU] %16lld | %16lld | /// %lld\n", i, cpu[0], cpu[1], cpu[1]-cpu[0]);
                    fprintf(stdout,  "----------------------- [GPU] %16llu | %16llu | /// %lld\n",    gpu[0], gpu[1], gpu[1]-gpu[0]);
                    uint64_t cpuTimeRef, gpuTimeRef;
                    m_calibration.GetReferenceTime(cpuTimeRef, gpuTimeRef);
                    if (gpu[0] < gpuTimeRef)
                        fprintf(stdout, "!!!!! CalibrateClocks() -> WARNING!!! going backwards!\n%llu\n%llu\n%lld\n", gpuTimeRef, gpu[0], gpu[0] - gpuTimeRef);
                );

                // skip first sample since it is quite jittery (lazy intialization of WebGPU objects)
                if (i == 0)
                    continue;

                m_calibration.Update(wall[0], wall[1], cpu[0], cpu[1], gpu[0]);
            };

            TracyWebGPUDebug(
                fprintf(stdout, "##### CalibrateClocks() WALL = %lld | CPU = %lld | GPU = %lld | period = %f\n",
                    m_calibration.wallToGpuModel.mean_x,
                    m_calibration.cpuToGpuModel.mean_x,
                    m_calibration.cpuToGpuModel.mean_y,
                    m_calibration.Period());
            );

            wgpuRenderPipelineRelease(calibPipeline);
            wgpuShaderModuleRelease(calibShader);
            wgpuTextureViewRelease(texView);
            wgpuTextureRelease(tex);

            m_calibration.GetReferenceTime(outCpuTime, outGpuTime);
            period = m_calibration.Period();
            // assume 1 ns/tick if the period estimation is close enough to 1
            if (std::abs(period - 1.0) < 0.001)
                period = 1.0;

            return true;
        }

    public:
        class Requirements
        {
            private:
#           if (TRACY_WEBGPU_DAWN_NATIVE)
                WGPUDawnTogglesDescriptor dawnTogglesDesc = {};
                static constexpr int NumExtras = 0;
#           elif (TRACY_WEBGPU_WGPU_NATIVE)
                static constexpr int NumExtras = 1;
#           endif

            public:
            static constexpr int NumFeatures = 1 + NumExtras;
            WGPUFeatureName  features [NumFeatures] = {};
            WGPUChainedStruct* togglesDesc = nullptr;

            Requirements()
            {
                this->features[0] = WGPUFeatureName_TimestampQuery;
#               if (TRACY_WEBGPU_WGPU_NATIVE)
                    this->features[1] = (WGPUFeatureName)WGPUNativeFeature_TimestampQueryInsideEncoders;
#               endif
#               if (TRACY_WEBGPU_DAWN_NATIVE)
                    static const char* dawnDisabledToggles[] = { "timestamp_quantization" };
                    static const char* dawnEnabledToggles[]  = { "disable_timestamp_query_conversion" };
                    this->dawnTogglesDesc.chain.sType = WGPUSType_DawnTogglesDescriptor;
                    this->dawnTogglesDesc.disabledToggles = dawnDisabledToggles;
                    this->dawnTogglesDesc.disabledToggleCount = 1;
                    this->dawnTogglesDesc.enabledToggles = dawnEnabledToggles;
                    this->dawnTogglesDesc.enabledToggleCount  = 1;
                    this->togglesDesc = reinterpret_cast<WGPUChainedStruct*>(&this->dawnTogglesDesc);
#               endif
            }

            static bool VerifyDevice(WGPUDevice device)
            {
                if (device == nullptr)
                    TracyWebGPUPanic("Invalid WGPUDevice.", return false);
                if (wgpuDeviceHasFeature(device, WGPUFeatureName_TimestampQuery) == WGPU_FALSE)
                    TracyWebGPUPanic("Device is missing feature WGPUFeatureName_TimestampQuery.", return false);
#               if (TRACY_WEBGPU_DAWN_NATIVE)
                    bool hasDisableConversion = false, hasQuantization = false;
                    for (const char* t : ::dawn::native::GetTogglesUsed(device))
                    {
                        if (strcmp(t, "disable_timestamp_query_conversion") == 0)
                            hasDisableConversion = true;
                        if (strcmp(t, "timestamp_quantization") == 0)
                            hasQuantization = true;
                    }
                    if (!hasDisableConversion)
                        TracyWebGPUPanic("Device must toggle disable_timestamp_query_conversion (Dawn).", return false);
                    if (hasQuantization)
                        TracyWebGPUPanic("Device must disable timestamp_quantization (Dawn).", return false);
#               elif (TRACY_WEBGPU_WGPU_NATIVE)
                    if (wgpuDeviceHasFeature(device, (WGPUFeatureName)WGPUNativeFeature_TimestampQueryInsideEncoders) == WGPU_FALSE)
                        TracyWebGPUPanic("Device is missing feature WGPUNativeFeature_TimestampQueryInsideEncoders (wgpu-native).", return false);
#               endif
                return true;
            }

            void ApplyToDeviceDescriptor(WGPUDeviceDescriptor& deviceDescriptor)
            {
                size_t userCount  = deviceDescriptor.requiredFeatureCount;
                size_t totalCount = userCount + NumFeatures;
                // NOTE: this allocation will leak...
                auto* mergedFeatures = static_cast<WGPUFeatureName*>(tracy_malloc(totalCount * sizeof(WGPUFeatureName)));
                if (userCount > 0 && deviceDescriptor.requiredFeatures)
                    memcpy(mergedFeatures, deviceDescriptor.requiredFeatures, userCount * sizeof(WGPUFeatureName));
                memcpy(mergedFeatures + userCount, features, NumFeatures * sizeof(WGPUFeatureName));
                deviceDescriptor.requiredFeatures     = mergedFeatures;
                deviceDescriptor.requiredFeatureCount = totalCount;

                if (togglesDesc)
                {
                    togglesDesc->next            = deviceDescriptor.nextInChain;
                    deviceDescriptor.nextInChain = togglesDesc;
                }
            }
        };

        WebGPUQueueCtx(WGPUInstance instance, WGPUDevice device, WGPUQueue queue)
        {
            ZoneScopedC(Color::Red4);

            if (!Requirements::VerifyDevice(device))
                TracyWebGPUPanic("GPU profiling disabled: the device did not set the required features.", return);

            TracyWebGPUAssert(instance); wgpuInstanceAddRef(instance); m_instance = instance;
            TracyWebGPUAssert(device);   wgpuDeviceAddRef(device);     m_device   = device;
            TracyWebGPUAssert(queue);    wgpuQueueAddRef(queue);       m_queue    = queue;

            // Setup Query Set: must have even size since queries are issued in pairs.
            // (The WebGPU spec mandates 4096, with no way to query the device limit.)
            WGPUQuerySetDescriptor qsDesc = {};
            qsDesc.type = WGPUQueryType_Timestamp;
            qsDesc.count = 4096;
            for (;;)
            {
                m_querySet = wgpuDeviceCreateQuerySet(m_device, &qsDesc);
                if (m_querySet) break;
                qsDesc.count /= 2;
                if (qsDesc.count < 128) break;
            }
            if (m_querySet == nullptr)
                TracyWebGPUPanic("Failed to create timestamp query set.", return);
            m_queryLimit = qsDesc.count;

            WGPUBufferDescriptor resolveDesc = {};
            resolveDesc.usage = WGPUBufferUsage_QueryResolve | WGPUBufferUsage_CopySrc;
            resolveDesc.size  = static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t);
            m_resolveBuffer = wgpuDeviceCreateBuffer(m_device, &resolveDesc);
            if (!m_resolveBuffer)
                TracyWebGPUPanic("Failed to create timestamp resolve buffer.", return);

            WGPUBufferDescriptor readbackDesc = {};
            readbackDesc.usage = WGPUBufferUsage_CopyDst | WGPUBufferUsage_MapRead;
            readbackDesc.size  = static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t);
            for (auto& stage : m_readbackReel)
            {
                stage.buffer = wgpuDeviceCreateBuffer(m_device, &readbackDesc);
                stage.copiedUpto = 0;
                if (!stage.buffer) { TracyWebGPUPanic("Failed to create timestamp readback buffer.", return); }
            }

            uint64_t cpuTimestamp = 0;
            uint64_t gpuTimestamp = 0;
            double period = 0.0;  // in nanoseconds per gpu-tick
            if (!CalibrateClocks(cpuTimestamp, gpuTimestamp, period))
                TracyWebGPUPanic("Failed to calibrate CPU/GPU clocks.", return);

            TracyWebGPUDebug( fprintf(stdout, "[WebGPUQueueCtx] cpuTimestamp: %llu | gpuTimestamp: %llu | period: %f\n", cpuTimestamp, gpuTimestamp, period) );
            m_shadowBuffer.resize(m_queryLimit, gpuTimestamp);

            // All setup completed: register the context.
            m_contextId = GetGpuCtxCounter().fetch_add(1);
            ZoneValue(m_contextId);

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuNewContext);
            MemWrite(&item->gpuNewContext.cpuTime, static_cast<int64_t>(cpuTimestamp));
            MemWrite(&item->gpuNewContext.gpuTime, static_cast<int64_t>(gpuTimestamp));
            MemWrite(&item->gpuNewContext.thread, static_cast<uint32_t>(0));
            MemWrite(&item->gpuNewContext.period, static_cast<float>(period));
            MemWrite(&item->gpuNewContext.context, static_cast<uint8_t>(GetId()));
            MemWrite(&item->gpuNewContext.flags, GpuContextFlags(0));  // no calibration available
            MemWrite(&item->gpuNewContext.type, GpuContextType::WebGPU);
            SubmitQueueItem(item);
        }

        ~WebGPUQueueCtx()
        {
            // TODO: a few problems to address later during this final Collect():
            // 1. ensure "partial" query batches are collected
            // 2. ensure all readback stages are collected and empty
            // 3. ensure readback buffers are not mapped before deleting them
            Collect();

            for (auto& stage : m_readbackReel)
                if (stage.buffer) { wgpuBufferRelease(stage.buffer);     stage.buffer     = nullptr; }
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

            // Current Readback "Reel" Stages:
            const int state = m_writeIdx;
            const int fillingIdx = (state + 0) % 3; // this is where instrumentation is pushing new queries
            const int pendingIdx = (state + 1) % 3; // instrumentation is done here; ready to be collected
            const int collectIdx = (state + 2) % 3; // this is where queries are being collected right now

            // Ensure readback buffer has been mapped to the host
            auto& collectStage = m_readbackReel[collectIdx];
            if (collectStage.pendingFuture.id != 0)
            {
                if (webgpuProcessEvents)
                    wgpuInstanceProcessEvents(m_instance);
                if (collectStage.mapStatus == WGPUMapAsyncStatus{})
                    return;  // callback hasn't fired yet
                collectStage.pendingFuture = {};
                if (collectStage.mapStatus != WGPUMapAsyncStatus_Success)
                    TracyWebGPUPanic("Colect(): unable to map readback buffer.", return);
            }

            if (collectStage.mapStatus == WGPUMapAsyncStatus_Success)
            {
                const uint64_t* ts = static_cast<const uint64_t*>(
                    wgpuBufferGetConstMappedRange(collectStage.buffer, 0,
                        static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t)));
                if (ts)
                {
                    uint64_t ticket = m_previousCheckpoint;
                    const uint64_t end = collectStage.copiedUpto;
                    TracyWebGPUDebug( fprintf(stdout, "[TWG] Collect [%d] (%llu, %llu)\n", collectIdx, ticket, end) );
                    for (; Distance(ticket, end) > 0; ticket += 2)
                    {
                        const uint32_t slotB = RingIndex(ticket);
                        const uint32_t slotE = slotB + 1;
                        TracyWebGPUDebug(
                            fprintf(stderr,
                                "[TWG] slot B=%4u E=%4u ts[B]=%llu ts[E]=%llu shadow[E]=%llu ts-diff=%lld shadow-diff=%lld\n",
                                slotB, slotE,
                                ts[slotB], ts[slotE], m_shadowBuffer[slotE],
                                Distance(ts[slotB], ts[slotE]),
                                Distance(m_shadowBuffer[slotE], ts[slotE]));
                        );
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
                wgpuBufferUnmap(collectStage.buffer);
                collectStage.mapStatus = {};
            }

            // At this point, all queries in the collect buffer have been processed.
            // (it's now tie to "rotate" the buffers around...)

            // Has any ResolveQueryBatch call landed in this reel stage since it was last recycled?
            // (Are there any queries to resolve and collect at all?)
            if (m_readbackReel[fillingIdx].copiedUpto <= m_previousCheckpoint)
                return;

            // Rotate/Cycle the Readback Pipeline State:
            // the buffer that was just collected shall now be used for instrumentation
            collectStage.copiedUpto = m_previousCheckpoint.load();
            m_writeIdx = collectIdx;    // atomically commit the pipeline rotation

            auto& nextToCollect = m_readbackReel[pendingIdx];
            WGPUBufferMapCallbackInfo cbInfo = {};
            cbInfo.mode = WGPUCallbackMode_AllowProcessEvents;
            cbInfo.callback = [](WGPUMapAsyncStatus status, WGPUStringView, void* userData, void*)
            {
                auto* stage = static_cast<ReadbackStage*>(userData);
                stage->mapStatus = status;
            };
            cbInfo.userdata1 = &nextToCollect;
            nextToCollect.pendingFuture = wgpuBufferMapAsync(
                nextToCollect.buffer, WGPUMapMode_Read, 0,
                static_cast<uint64_t>(m_queryLimit) * sizeof(uint64_t), cbInfo);
        }

    private:
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
        const bool m_active;
        WebGPUQueueCtx* m_ctx = nullptr;
        WGPUCommandEncoder m_encoder = nullptr;
        uint64_t m_rawTicket = 0;
        uint32_t m_queryId = 0;

        WGPUPassTimestampWrites m_timestampWrites = {};

        void ResolveQueryBatch(uint32_t queryBatchStartId)
        {
            // Ensure there are pending queries to resolve in the batch
            auto& stage = m_ctx->m_readbackReel[m_ctx->m_writeIdx];
            if (WebGPUQueueCtx::Distance(stage.copiedUpto, m_rawTicket) <= 0) return;

            // 32 queries = 32 * 8 bytes = 256 bytes
            TracyWebGPUAssert(queryBatchStartId % 32 == 0, return);
            queryBatchStartId = m_ctx->RingIndex(queryBatchStartId);

            const uint64_t blockOffset = static_cast<uint64_t>(queryBatchStartId) * sizeof(uint64_t);
            wgpuCommandEncoderResolveQuerySet(
                m_encoder,
                m_ctx->m_querySet,
                queryBatchStartId, 32,
                m_ctx->m_resolveBuffer,
                blockOffset // MUST be a multiple of (aligned to) 256...
            );

            auto readbackBuffer = stage.buffer;
            wgpuCommandEncoderCopyBufferToBuffer(
                m_encoder,
                m_ctx->m_resolveBuffer,
                blockOffset,
                readbackBuffer,
                blockOffset,
                32 * sizeof(uint64_t)
            );

            // Advance this stage's high-water mark to cover the block just encoded.
            // TODO: maybe we can use fetch_add to increment the atomic and not need
            // to keep track of the raw ticket; Collect would need to derive the raw
            // end ticket number.
            const uint64_t blockEnd = m_rawTicket;
            uint64_t prev = stage.copiedUpto;
            while ((WebGPUQueueCtx::Distance(prev, blockEnd) > 0) &&
                   !stage.copiedUpto.compare_exchange_weak(prev, blockEnd)) {}
            TracyWebGPUDebug( fprintf(stdout, "[TWG] WebGPUZoneScope [%d] (%d,%d)\n", (int)m_ctx->m_writeIdx, queryBatchStartId, queryBatchStartId+32) );
        }

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
            m_ctx     = ctx;
            m_encoder = encoder;

            m_rawTicket = m_ctx->NextQueryId();
            m_queryId   = m_ctx->RingIndex(m_rawTicket);

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
            if (!m_active || !ctx) return;
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
            if (!m_active || !ctx) return;
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
            if (!m_active || !ctx) return;
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
            if (!m_active || !ctx) return;
            InitBase(ctx, encoder, passDesc);
            WriteQueueItem(nullptr, depth, line, source, sourceSz, function, functionSz, name, nameSz);
        }

        tracy_force_inline ~WebGPUZoneScope()
        {
            if (!m_active || !m_ctx) return;

            const auto queryId = m_queryId + 1;

            auto* item = Profiler::QueueSerial();
            MemWrite(&item->hdr.type, QueueType::GpuZoneEndSerial);
            MemWrite(&item->gpuZoneEnd.cpuTime, Profiler::GetTime());
            MemWrite(&item->gpuZoneEnd.thread, GetThreadHandle());
            MemWrite(&item->gpuZoneEnd.queryId, static_cast<uint16_t>(queryId));
            MemWrite(&item->gpuZoneEnd.context, m_ctx->GetId());
            Profiler::QueueSerialFinish();

            if (m_queryId % 32 == 0)
                ResolveQueryBatch(m_queryId-32);
        }
    };

    static inline void DestroyWebGPUContext(WebGPUQueueCtx* ctx)
    {
        if (!ctx) return;
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

#define TracyWebGPUSetupDeviceDescriptor(deviceDescriptor) tracy::WebGPUQueueCtx::Requirements TracyConcat(__tracy_wgpu_setup_, TracyLine); TracyConcat(__tracy_wgpu_setup_, TracyLine).ApplyToDeviceDescriptor(deviceDescriptor)

#define TracyWebGPUContext(instance, device, queue) tracy::CreateWebGPUContext(instance, device, queue);
#define TracyWebGPUDestroy(ctx) tracy::DestroyWebGPUContext(ctx);
#define TracyWebGPUContextName(ctx, name, size) if (ctx) ctx->Name(name, size);

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

#define TracyWebGPUCollect(ctx) if (ctx) ctx->Collect();

#endif

#endif
