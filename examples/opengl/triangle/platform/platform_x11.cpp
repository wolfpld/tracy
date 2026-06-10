// platform_x11.cpp — Linux/X11 backend (GLX)
//
// Creates a GLX 3.3 Core Profile OpenGL context.
// GLEW must be initialized by the caller (initGL) after platformInit() returns.
//
// Dependencies: libX11, libGL, libGLEW
//
// Compile flags:
//   g++ -std=c++17 spinning_triangle.cpp platform/platform_x11.cpp \
//       -lX11 -lGL -lGLEW -o gl_spinning_triangle

#include <X11/Xlib.h>
#include <GL/glx.h>
#include <cstdio>
#include <time.h>
#include "platform.h"

// GLX_ARB_create_context token values (from <GL/glxext.h>)
#ifndef GLX_CONTEXT_MAJOR_VERSION_ARB
#  define GLX_CONTEXT_MAJOR_VERSION_ARB    0x2091
#  define GLX_CONTEXT_MINOR_VERSION_ARB    0x2092
#  define GLX_CONTEXT_PROFILE_MASK_ARB     0x9126
#  define GLX_CONTEXT_CORE_PROFILE_BIT_ARB 0x00000001
#endif

typedef GLXContext (*glXCreateContextAttribsARBProc)(Display*, GLXFBConfig, GLXContext, Bool, const int*);

static Display*       sDpy        = nullptr;
static Window         sWin        = 0;
static GLXContext     sCtx        = nullptr;
static Atom           sWmDelete   = 0;
static bool           sRunning    = false;
static struct timespec sStart     = {};
static void (*sRenderCb)()        = nullptr;
static void (*sShutdownCb)()      = nullptr;

bool platformInit(int width, int height, const char* title) {
    sDpy = XOpenDisplay(nullptr);
    if (!sDpy) { fprintf(stderr, "Cannot open X display\n"); return false; }

    const int fbAttribs[] = {
        GLX_X_RENDERABLE,  True,
        GLX_DRAWABLE_TYPE, GLX_WINDOW_BIT,
        GLX_RENDER_TYPE,   GLX_RGBA_BIT,
        GLX_DOUBLEBUFFER,  True,
        GLX_RED_SIZE,      8,
        GLX_GREEN_SIZE,    8,
        GLX_BLUE_SIZE,     8,
        None
    };
    int fbCount = 0;
    GLXFBConfig* fbc = glXChooseFBConfig(sDpy, DefaultScreen(sDpy), fbAttribs, &fbCount);
    if (!fbc || fbCount == 0) { fprintf(stderr, "No suitable GLXFBConfig\n"); return false; }

    XVisualInfo* vi = glXGetVisualFromFBConfig(sDpy, fbc[0]);

    XSetWindowAttributes swa = {};
    swa.colormap   = XCreateColormap(sDpy, DefaultRootWindow(sDpy), vi->visual, AllocNone);
    swa.event_mask = ExposureMask | KeyPressMask;
    sWin = XCreateWindow(sDpy, DefaultRootWindow(sDpy),
        200, 200, width, height, 0, vi->depth, InputOutput, vi->visual,
        CWColormap | CWEventMask, &swa);
    XFree(vi);

    XStoreName(sDpy, sWin, title);
    XMapWindow(sDpy, sWin);

    sWmDelete = XInternAtom(sDpy, "WM_DELETE_WINDOW", False);
    XSetWMProtocols(sDpy, sWin, &sWmDelete, 1);

    auto glXCreateContextAttribsARB = (glXCreateContextAttribsARBProc)
        glXGetProcAddressARB((const GLubyte*)"glXCreateContextAttribsARB");
    if (!glXCreateContextAttribsARB) {
        fprintf(stderr, "glXCreateContextAttribsARB not found\n");
        XFree(fbc);
        return false;
    }

    const int ctxAttribs[] = {
        GLX_CONTEXT_MAJOR_VERSION_ARB, 3,
        GLX_CONTEXT_MINOR_VERSION_ARB, 3,
        GLX_CONTEXT_PROFILE_MASK_ARB,  GLX_CONTEXT_CORE_PROFILE_BIT_ARB,
        None
    };
    sCtx = glXCreateContextAttribsARB(sDpy, fbc[0], nullptr, True, ctxAttribs);
    XFree(fbc);
    if (!sCtx) { fprintf(stderr, "Failed to create GLX context\n"); return false; }

    glXMakeCurrent(sDpy, sWin, sCtx);
    clock_gettime(CLOCK_MONOTONIC, &sStart);
    return true;
}

bool platformInitGL() {
    glewExperimental = GL_TRUE;
    if (glewInit() != GLEW_OK) {
        fprintf(stderr, "Failed to initialize GLEW\n");
        return false;
    }
    return true;
}

double platformGetTime() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - sStart.tv_sec) + (double)(now.tv_nsec - sStart.tv_nsec) * 1e-9;
}

void platformSwapBuffers() { glXSwapBuffers(sDpy, sWin); }

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    static const long kFrameNs = 1000000000L / 60;
    sRenderCb   = render;
    sShutdownCb = shutdown;
    sRunning    = true;

    while (sRunning) {
        struct timespec frameStart;
        clock_gettime(CLOCK_MONOTONIC, &frameStart);

        while (XPending(sDpy)) {
            XEvent ev;
            XNextEvent(sDpy, &ev);
            if (ev.type == KeyPress) { sRunning = false; break; }
            if (ev.type == ClientMessage && (Atom)ev.xclient.data.l[0] == sWmDelete) {
                sRunning = false;
                break;
            }
        }

        if (sRunning) render();

        struct timespec frameEnd;
        clock_gettime(CLOCK_MONOTONIC, &frameEnd);
        long elapsed = (frameEnd.tv_sec  - frameStart.tv_sec)  * 1000000000L
                     + (frameEnd.tv_nsec - frameStart.tv_nsec);
        long remaining = kFrameNs - elapsed;
        if (remaining > 0) {
            struct timespec ts = { 0, remaining };
            nanosleep(&ts, nullptr);
        }
    }

    shutdown();
    glXMakeCurrent(sDpy, None, nullptr);
    glXDestroyContext(sDpy, sCtx);
    XDestroyWindow(sDpy, sWin);
    XCloseDisplay(sDpy);
}
