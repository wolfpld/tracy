// platform_rgfw.cpp — RGFW windowing backend (cross-platform)
// https://github.com/ColleagueRiley/RGFW

#include "platform.h"   // GL headers first (gl3.h / glew.h) so RGFW sees guards set

#define RGFW_OPENGL
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

    RGFW_glHints* hints = RGFW_getGlobalHints_OpenGL();
    hints->major = 3;
    hints->minor = 3;
    RGFW_setGlobalHints_OpenGL(hints);

    sWin = RGFW_createWindow(title, 0, 0, width, height,
                              RGFW_windowCenter | RGFW_windowOpenGL);
    if (!sWin) {
        fprintf(stderr, "ERROR: failed to create window\n");
        return false;
    }
    RGFW_window_makeCurrentContext_OpenGL(sWin);
    RGFW_window_swapInterval_OpenGL(sWin, 1);
    RGFW_window_setExitKey(sWin, RGFW_keyEscape);

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

void platformSwapBuffers() { RGFW_window_swapBuffers_OpenGL(sWin); }

void platformGetPixelDensityScale(float* x, float* y) {
    i32 pw, ph;
    RGFW_window_getSizeInPixels(sWin, &pw, &ph);
    *x = (float)pw / (float)sWin->w;
    *y = (float)ph / (float)sWin->h;
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
