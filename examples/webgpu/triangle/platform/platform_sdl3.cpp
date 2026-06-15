// platform_sdl3.cpp — SDL3 windowing backend for the WebGPU example
#include "platform.h"   // webgpu/webgpu.h first

#define SDL_MAIN_HANDLED    // we don't want SDL_main
#include <SDL3/SDL.h>

#ifdef __APPLE__
#  include <SDL3/SDL_metal.h>
#endif

#include <chrono>
#include <cstdio>

static SDL_Window* sWin = nullptr;
static std::chrono::steady_clock::time_point sStartTime;
#ifdef __APPLE__
static SDL_MetalView sMetalView = nullptr;
#endif

bool platformInit(int width, int height, const char* title) {
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        fprintf(stderr, "ERROR: SDL_Init failed: %s\n", SDL_GetError());
        return false;
    }

    SDL_WindowFlags flags = 0;
#ifdef __APPLE__
    flags |= SDL_WINDOW_METAL;
#endif

    sWin = SDL_CreateWindow(title, width, height, flags);
    if (!sWin) {
        fprintf(stderr, "ERROR: SDL_CreateWindow failed: %s\n", SDL_GetError());
        SDL_Quit();
        return false;
    }
    SDL_SetWindowPosition(sWin, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);

    sStartTime = std::chrono::steady_clock::now();
    return true;
}

WGPUSurface platformCreateSurface(WGPUInstance instance) {
    WGPUSurfaceDescriptor desc = {};
    SDL_PropertiesID props = SDL_GetWindowProperties(sWin);

#if defined(__APPLE__)
    sMetalView = SDL_Metal_CreateView(sWin);
    if (!sMetalView) {
        fprintf(stderr, "ERROR: SDL_Metal_CreateView failed\n");
        return nullptr;
    }
    WGPUSurfaceSourceMetalLayer metalDesc = {};
    metalDesc.chain.sType = WGPUSType_SurfaceSourceMetalLayer;
    metalDesc.layer       = SDL_Metal_GetLayer(sMetalView);
    desc.nextInChain      = &metalDesc.chain;
#elif defined(_WIN32)
    WGPUSurfaceSourceWindowsHWND hwndDesc = {};
    hwndDesc.chain.sType = WGPUSType_SurfaceSourceWindowsHWND;
    hwndDesc.hinstance   = SDL_GetPointerProperty(props, SDL_PROP_WINDOW_WIN32_INSTANCE_POINTER, nullptr);
    hwndDesc.hwnd        = SDL_GetPointerProperty(props, SDL_PROP_WINDOW_WIN32_HWND_POINTER, nullptr);
    desc.nextInChain     = &hwndDesc.chain;
#else   // Linux / X11
    WGPUSurfaceSourceXlibWindow x11Desc = {};
    x11Desc.chain.sType = WGPUSType_SurfaceSourceXlibWindow;
    x11Desc.display     = SDL_GetPointerProperty(props, SDL_PROP_WINDOW_X11_DISPLAY_POINTER, nullptr);
    x11Desc.window      = (uint32_t)SDL_GetNumberProperty(props, SDL_PROP_WINDOW_X11_WINDOW_NUMBER, 0);
    desc.nextInChain    = &x11Desc.chain;
#endif

    return wgpuInstanceCreateSurface(instance, &desc);
}

double platformGetTime() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now() - sStartTime).count();
}

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    bool running = true;
    while (running) {
        SDL_Event e;
        while (SDL_PollEvent(&e)) {
            if (e.type == SDL_EVENT_QUIT) running = false;
            if (e.type == SDL_EVENT_KEY_DOWN && e.key.key == SDLK_ESCAPE) running = false;
        }
        if (running) render();
    }
    shutdown();
#ifdef __APPLE__
    SDL_Metal_DestroyView(sMetalView);
#endif
    SDL_DestroyWindow(sWin);
    SDL_Quit();
}
