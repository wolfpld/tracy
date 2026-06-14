// platform_sdl3.cpp — SDL3 windowing backend (cross-platform)
#include "platform.h"   // GL headers first (gl3.h / glew.h) so SDL sees guards set

#define SDL_MAIN_HANDLED    // we don't want SDL_main
#include <SDL3/SDL.h>

#include <chrono>
#include <cstdio>

static SDL_Window*   sWin = nullptr;
static SDL_GLContext sCtx = nullptr;
static std::chrono::steady_clock::time_point sStartTime;

bool platformInit(int width, int height, const char* title) {
    if (!SDL_Init(SDL_INIT_VIDEO)) {
        fprintf(stderr, "ERROR: SDL_Init failed: %s\n", SDL_GetError());
        return false;
    }

    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 3);
    SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);

    sWin = SDL_CreateWindow(title, width, height, SDL_WINDOW_OPENGL);
    if (!sWin) {
        fprintf(stderr, "ERROR: SDL_CreateWindow failed: %s\n", SDL_GetError());
        SDL_Quit();
        return false;
    }
    SDL_SetWindowPosition(sWin, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED);

    sCtx = SDL_GL_CreateContext(sWin);
    if (!sCtx) {
        fprintf(stderr, "ERROR: SDL_GL_CreateContext failed: %s\n", SDL_GetError());
        SDL_DestroyWindow(sWin);
        SDL_Quit();
        return false;
    }

    SDL_GL_SetSwapInterval(1);
    sStartTime = std::chrono::steady_clock::now();
    return true;
}

bool platformInitGL() {
#ifndef __APPLE__
    glewExperimental = GL_TRUE;
    if (glewInit() != GLEW_OK) {
        fprintf(stderr, "Failed to initialize GLEW\n");
        return false;
    }
#endif
    return true;
}

double platformGetTime() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now() - sStartTime).count();
}

void platformSwapBuffers() { SDL_GL_SwapWindow(sWin); }

void platformGetPixelDensityScale(float* x, float* y) {
    int pw, ph, ww, wh;
    SDL_GetWindowSizeInPixels(sWin, &pw, &ph);
    SDL_GetWindowSize(sWin, &ww, &wh);
    *x = (ww > 0) ? (float)pw / (float)ww : 1.0f;
    *y = (wh > 0) ? (float)ph / (float)wh : 1.0f;
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
    SDL_GL_DestroyContext(sCtx);
    SDL_DestroyWindow(sWin);
    SDL_Quit();
}
