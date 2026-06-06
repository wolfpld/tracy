// platform.h — interface between platform-agnostic code and platform backends
//
// Each platform_*.mm / platform_*.cpp file implements these five functions.
// Exactly one backend must be linked into the final binary.

#pragma once
#include <webgpu/webgpu.h>

// Initialize the windowing system and create a window of the given dimensions.
// Returns true on success.
bool platformInit(int width, int height, const char* title);

// Create a WebGPU surface backed by the platform window.
// Must be called after wgpuCreateInstance() and platformInit().
WGPUSurface platformCreateSurface(WGPUInstance instance);

// Elapsed wall-clock time in seconds since platformInit().
double platformGetTime();

// Enter the platform event/render loop.
// Calls render() each frame at ~60 fps.
// Calls shutdown() exactly once before returning.
void platformRunLoop(void (*render)(), void (*shutdown)());
