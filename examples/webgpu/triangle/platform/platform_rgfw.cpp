// platform_rgfw.cpp — RGFW windowing backend for the WebGPU example
// https://github.com/ColleagueRiley/RGFW

#include "platform.h"   // webgpu/webgpu.h first so RGFW sees WGPUSurface

#define RGFW_WEBGPU
#define RGFW_IMPLEMENTATION
#include <RGFW.h>

#include <chrono>
#include <cstdio>

#if defined(__linux__)
#include <X11/Xlib.h>
static bool platformHasDisplay() {
    // RGFW workaround: RGFW indiscriminately passes XOpenDisplay(0) unchecked
    // to X11 functions like XCreateWindow(), which will lead to SIGSEGV.
    Display* display = XOpenDisplay(0);
    if (display == nullptr) {
        fprintf(stderr, "ERROR: failed to open X11 display (is $DISPLAY set?)\n");
        return false;
    }
    XCloseDisplay(display);
    return true;
}
#else
static bool platformHasDisplay() {
    return true;
}
#endif

static RGFW_window* sWin = nullptr;
static std::chrono::steady_clock::time_point sStartTime;

bool platformInit(int width, int height, const char* title) {
    if (!platformHasDisplay()) {
        fprintf(stderr, "ERROR: no display found\n");
        return false;
    }

    sWin = RGFW_createWindow(title, 0, 0, width, height, RGFW_windowCenter);
    if (!sWin) {
        fprintf(stderr, "ERROR: failed to create window\n");
        return false;
    }
    RGFW_window_setExitKey(sWin, RGFW_keyEscape);
    sStartTime = std::chrono::steady_clock::now();
    return true;
}

WGPUSurface platformCreateSurface(WGPUInstance instance) {
    return RGFW_window_createSurface_WebGPU(sWin, instance);
}

double platformGetTime() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now() - sStartTime).count();
}

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    while (RGFW_window_shouldClose(sWin) == RGFW_FALSE) {
        RGFW_event event;
        while (RGFW_window_checkEvent(sWin, &event)) {
            if (event.type == RGFW_windowClose) goto done;
        }
        render();
    }
done:
    shutdown();
    RGFW_window_close(sWin);
    sWin = nullptr;
}
