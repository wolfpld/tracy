// spinning_triangle.cpp — platform-agnostic WebGPU spinning triangle demo.

#include "platform/platform.h"
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <webgpu/webgpu.h>

#include <tracy/Tracy.hpp>
#include <tracy/TracyWebGPU.hpp>

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static const int kWidth  = 800;
static const int kHeight = 600;

static WGPUInstance       gInstance   = nullptr;
static WGPUSurface        gSurface    = nullptr;
static WGPUAdapter        gAdapter    = nullptr;
static WGPUDevice         gDevice     = nullptr;
static WGPUQueue          gQueue      = nullptr;
static WGPURenderPipeline gPipeline   = nullptr;
static WGPUBuffer         gUniformBuf = nullptr;
static WGPUBindGroup      gBindGroup  = nullptr;

static TracyWebGPUCtx     gTracyCtx   = nullptr;

static WGPUTextureFormat gSurfaceFormat = WGPUTextureFormat_BGRA8Unorm;

// TODO: this can become platformError() instead
int error(int code, const char* message) {
    fprintf(stderr, "ERROR: %s (code: %d)\n", message, code);
    return code;
}

// ---------------------------------------------------------------------------
// WGSL shader — vertex colours baked in, rotation via a uniform float.
// ---------------------------------------------------------------------------

static const char* kShaderSource = R"(
struct Uniforms {
    angle: f32,
};
@group(0) @binding(0) var<uniform> u: Uniforms;

struct VSOut {
    @builtin(position) pos: vec4f,
    @location(0) color: vec3f,
};

@vertex
fn vs_main(@builtin(vertex_index) vi: u32) -> VSOut {
    var positions = array<vec2f, 3>(
        vec2f( 0.0,  0.5),
        vec2f(-0.433, -0.25),
        vec2f( 0.433, -0.25),
    );
    var colors = array<vec3f, 3>(
        vec3f(1.0, 0.0, 0.0),
        vec3f(0.0, 1.0, 0.0),
        vec3f(0.0, 0.0, 1.0),
    );

    let c = cos(u.angle);
    let s = sin(u.angle);
    let p = positions[vi];
    let rotated = vec2f(p.x * c - p.y * s, p.x * s + p.y * c);

    var out: VSOut;
    out.pos   = vec4f(rotated, 0.0, 1.0);
    out.color = colors[vi];
    return out;
}

@fragment
fn fs_main(@location(0) color: vec3f) -> @location(0) vec4f {
    return vec4f(color, 1.0);
}
)";

// ---------------------------------------------------------------------------
// Adapter / Device request callbacks  (current wgpu-native API)
// ---------------------------------------------------------------------------

static void onAdapterReady(WGPURequestAdapterStatus status,
                           WGPUAdapter adapter,
                           WGPUStringView message,
                           void* userdata1, void* /*userdata2*/) {
    if (status == WGPURequestAdapterStatus_Success) {
        *(WGPUAdapter*)userdata1 = adapter;
    } else {
        fprintf(stderr, "Adapter request failed: %.*s\n",
                (int)message.length, message.data);
    }
}

static void onDeviceReady(WGPURequestDeviceStatus status,
                          WGPUDevice device,
                          WGPUStringView message,
                          void* userdata1, void* /*userdata2*/) {
    if (status == WGPURequestDeviceStatus_Success) {
        *(WGPUDevice*)userdata1 = device;
    } else {
        fprintf(stderr, "Device request failed: %.*s\n",
                (int)message.length, message.data);
    }
}

// ---------------------------------------------------------------------------
// WebGPU init
// ---------------------------------------------------------------------------

static int initWebGPU() {
    // Adapter
    WGPURequestAdapterOptions adapterOpts = {};
    adapterOpts.compatibleSurface = gSurface;

    WGPURequestAdapterCallbackInfo adapterCB = {};
    adapterCB.mode     = WGPUCallbackMode_AllowProcessEvents;
    adapterCB.callback  = onAdapterReady;
    adapterCB.userdata1 = &gAdapter;
    wgpuInstanceRequestAdapter(gInstance, &adapterOpts, adapterCB);
    while (!gAdapter) { wgpuInstanceProcessEvents(gInstance); }
    if (!gAdapter) return error(11, "No adapter");

    WGPUUncapturedErrorCallbackInfo errorCB = {};
    errorCB.callback = [](WGPUDevice const*, WGPUErrorType type,
                          WGPUStringView message, void*, void*) {
        fprintf(stderr, "[WGPU ERROR] type=%d  %.*s\n",
                (int)type, (int)message.length, message.data);
    };

    WGPUDeviceDescriptor deviceDesc = {};
    deviceDesc.uncapturedErrorCallbackInfo = errorCB;

    TracyWebGPUSetupDeviceDescriptor(deviceDesc);

    WGPURequestDeviceCallbackInfo deviceCB = {};
    deviceCB.mode      = WGPUCallbackMode_AllowProcessEvents;
    deviceCB.callback  = onDeviceReady;
    deviceCB.userdata1 = &gDevice;
    wgpuAdapterRequestDevice(gAdapter, &deviceDesc, deviceCB);
    while (!gDevice) { wgpuInstanceProcessEvents(gInstance); }
    if (!gDevice) return error(12, "No device");

    gQueue = wgpuDeviceGetQueue(gDevice);
    gTracyCtx = TracyWebGPUContext(gInstance, gDevice, gQueue);
    TracyWebGPUContextName(gTracyCtx, "WebGPU", 6);

    // Configure surface
    WGPUSurfaceConfiguration config = {};
    config.device      = gDevice;
    config.format      = gSurfaceFormat;
    config.usage       = WGPUTextureUsage_RenderAttachment;
    config.alphaMode   = WGPUCompositeAlphaMode_Opaque;
    config.width       = kWidth;
    config.height      = kHeight;
    config.presentMode = WGPUPresentMode_Fifo;
    wgpuSurfaceConfigure(gSurface, &config);

    // Shader module
    WGPUShaderSourceWGSL wgslSrc = {};
    wgslSrc.chain.sType = WGPUSType_ShaderSourceWGSL;
    wgslSrc.code = { kShaderSource, WGPU_STRLEN };

    WGPUShaderModuleDescriptor smDesc = {};
    smDesc.nextInChain = (WGPUChainedStruct*)&wgslSrc;
    WGPUShaderModule shaderMod = wgpuDeviceCreateShaderModule(gDevice, &smDesc);

    // Uniform buffer (one f32 for rotation angle)
    WGPUBufferDescriptor bufDesc = {};
    bufDesc.usage = WGPUBufferUsage_Uniform | WGPUBufferUsage_CopyDst;
    bufDesc.size  = sizeof(float);
    gUniformBuf = wgpuDeviceCreateBuffer(gDevice, &bufDesc);

    // Bind group layout + bind group
    WGPUBindGroupLayoutEntry bglEntry = {};
    bglEntry.binding    = 0;
    bglEntry.visibility = WGPUShaderStage_Vertex;
    bglEntry.buffer.type            = WGPUBufferBindingType_Uniform;
    bglEntry.buffer.minBindingSize  = sizeof(float);

    WGPUBindGroupLayoutDescriptor bglDesc = {};
    bglDesc.entryCount = 1;
    bglDesc.entries    = &bglEntry;
    WGPUBindGroupLayout bgl = wgpuDeviceCreateBindGroupLayout(gDevice, &bglDesc);

    WGPUBindGroupEntry bgEntry = {};
    bgEntry.binding = 0;
    bgEntry.buffer  = gUniformBuf;
    bgEntry.size    = sizeof(float);

    WGPUBindGroupDescriptor bgDesc = {};
    bgDesc.layout     = bgl;
    bgDesc.entryCount = 1;
    bgDesc.entries    = &bgEntry;
    gBindGroup = wgpuDeviceCreateBindGroup(gDevice, &bgDesc);

    // Pipeline layout
    WGPUPipelineLayoutDescriptor plDesc = {};
    plDesc.bindGroupLayoutCount = 1;
    plDesc.bindGroupLayouts     = &bgl;
    WGPUPipelineLayout pipelineLayout = wgpuDeviceCreatePipelineLayout(gDevice, &plDesc);

    // Render pipeline
    WGPUColorTargetState colorTarget = {};
    colorTarget.format    = gSurfaceFormat;
    colorTarget.writeMask = WGPUColorWriteMask_All;

    WGPUFragmentState fragState = {};
    fragState.module      = shaderMod;
    fragState.entryPoint  = { "fs_main", WGPU_STRLEN };
    fragState.targetCount = 1;
    fragState.targets     = &colorTarget;

    WGPURenderPipelineDescriptor rpDesc = {};
    rpDesc.layout = pipelineLayout;
    rpDesc.vertex.module     = shaderMod;
    rpDesc.vertex.entryPoint = { "vs_main", WGPU_STRLEN };
    rpDesc.primitive.topology = WGPUPrimitiveTopology_TriangleList;
    rpDesc.multisample.count  = 1;
    rpDesc.multisample.mask   = 0xFFFFFFFF;
    rpDesc.fragment = &fragState;

    gPipeline = wgpuDeviceCreateRenderPipeline(gDevice, &rpDesc);

    // Cleanup intermediates
    wgpuShaderModuleRelease(shaderMod);
    wgpuPipelineLayoutRelease(pipelineLayout);
    wgpuBindGroupLayoutRelease(bgl);
    return 0;
}

// ---------------------------------------------------------------------------
// Frame rendering
// ---------------------------------------------------------------------------

// Returns the surface texture for the current frame, or {.texture=nullptr} on
// a skippable condition (timeout, occlusion) or an error.
static WGPUSurfaceTexture getWindowSurface() {
    WGPUSurfaceTexture surfTex = {};
    wgpuSurfaceGetCurrentTexture(gSurface, &surfTex);
    if (surfTex.status == WGPUSurfaceGetCurrentTextureStatus_SuccessOptimal ||
        surfTex.status == WGPUSurfaceGetCurrentTextureStatus_SuccessSuboptimal)
        return surfTex;

    // Timeout and Occluded are normal OS events (window covered / on a different Space).
    bool silent = surfTex.status == WGPUSurfaceGetCurrentTextureStatus_Timeout;
#ifdef WGPU_H_
    silent = silent || surfTex.status == (WGPUSurfaceGetCurrentTextureStatus)WGPUSurfaceGetCurrentTextureStatus_Occluded;
#endif
    if (!silent)
        fprintf(stderr, "Failed to get surface texture (status %d)\n", surfTex.status);
    if (surfTex.texture) wgpuTextureRelease(surfTex.texture);
    surfTex.texture = nullptr;
    return surfTex;
}

static void renderFrame() {
    ZoneScoped;

    // Update rotation angle
    float angle = (float)platformGetTime();
    wgpuQueueWriteBuffer(gQueue, gUniformBuf, 0, &angle, sizeof(float));

    WGPUSurfaceTexture surfTex = getWindowSurface();
    if (!surfTex.texture) return;

    WGPUTextureView view = wgpuTextureCreateView(surfTex.texture, nullptr);

    // Command encoder
    WGPUCommandEncoder encoder = wgpuDeviceCreateCommandEncoder(gDevice, nullptr);

    // Render pass
    WGPURenderPassColorAttachment colorAtt = {};
    colorAtt.view       = view;
    colorAtt.loadOp     = WGPULoadOp_Clear;
    colorAtt.storeOp    = WGPUStoreOp_Store;
    colorAtt.clearValue  = { 0.05, 0.05, 0.08, 1.0 };
    colorAtt.depthSlice  = WGPU_DEPTH_SLICE_UNDEFINED;

    WGPURenderPassDescriptor passDesc = {};
    passDesc.colorAttachmentCount = 1;
    passDesc.colorAttachments     = &colorAtt;

    {
        ZoneScopedN("render-pass");
        TracyWebGPUNamedZone(gTracyCtx, tracyZone, encoder, passDesc, "triangle draw", true);
        WGPURenderPassEncoder pass = wgpuCommandEncoderBeginRenderPass(encoder, &passDesc);
        wgpuRenderPassEncoderSetPipeline(pass, gPipeline);
        wgpuRenderPassEncoderSetBindGroup(pass, 0, gBindGroup, 0, nullptr);
        wgpuRenderPassEncoderDraw(pass, 3, 1, 0, 0);
        wgpuRenderPassEncoderEnd(pass);
        wgpuRenderPassEncoderRelease(pass);
    }

    // Submit
    WGPUCommandBuffer cmdBuf = wgpuCommandEncoderFinish(encoder, nullptr);
    wgpuQueueSubmit(gQueue, 1, &cmdBuf);

    // Present
    wgpuSurfacePresent(gSurface);

    // Process Events
    wgpuInstanceProcessEvents(gInstance);
    TracyWebGPUCollect(gTracyCtx);

    // Cleanup
    wgpuCommandBufferRelease(cmdBuf);
    wgpuCommandEncoderRelease(encoder);
    wgpuTextureViewRelease(view);
    wgpuTextureRelease(surfTex.texture);
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

static void shutdown() {
    fprintf(stderr, "application is shutting down...\n");
    TracyWebGPUDestroy(gTracyCtx);
    if (gBindGroup)  wgpuBindGroupRelease(gBindGroup);
    if (gUniformBuf) wgpuBufferRelease(gUniformBuf);
    if (gPipeline)   wgpuRenderPipelineRelease(gPipeline);
    if (gQueue)      wgpuQueueRelease(gQueue);
    if (gDevice)     wgpuDeviceRelease(gDevice);
    if (gAdapter)    wgpuAdapterRelease(gAdapter);
    if (gSurface)    wgpuSurfaceRelease(gSurface);
    if (gInstance)   wgpuInstanceRelease(gInstance);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    if (!platformInit(kWidth, kHeight, "WebGPU Spinning Triangle"))
        return 1;

    gInstance = wgpuCreateInstance(nullptr);
    if (!gInstance) return error(2, "Failed to create WebGPU instance.");

    gSurface = platformCreateSurface(gInstance);
    if (!gSurface) return error(3, "Failed to create surface.");

    if (initWebGPU() != 0) return 4;

    platformRunLoop(renderFrame, shutdown);
    return 0;
}
