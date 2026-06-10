// platform_windows.cpp — Windows backend (Win32 + WGL)
//
// Creates a WGL 3.3 Core Profile OpenGL context.
// GLEW must be initialized by the caller (initGL) after platformInit() returns.
//
// Compile flags (MSVC):
//   cl /std:c++17 spinning_triangle.cpp platform/platform_windows.cpp \
//       /I<glew-include> <glew-lib>/glew32s.lib opengl32.lib \
//       user32.lib gdi32.lib /Fe:gl_spinning_triangle.exe

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <GL/gl.h>
#include <cstdio>
#include "platform.h"

// WGL_ARB_create_context token values
#ifndef WGL_CONTEXT_MAJOR_VERSION_ARB
#  define WGL_CONTEXT_MAJOR_VERSION_ARB    0x2091
#  define WGL_CONTEXT_MINOR_VERSION_ARB    0x2092
#  define WGL_CONTEXT_PROFILE_MASK_ARB     0x9126
#  define WGL_CONTEXT_CORE_PROFILE_BIT_ARB 0x00000001
#endif

typedef HGLRC (WINAPI* PFNWGLCREATECONTEXTATTRIBSARBPROC)(HDC, HGLRC, const int*);

static HWND          sHwnd       = nullptr;
static HDC           sDC         = nullptr;
static HGLRC         sGLRC       = nullptr;
static bool          sRunning    = false;
static LARGE_INTEGER sFreq       = {};
static LARGE_INTEGER sStart      = {};
static void (*sRenderCb)()       = nullptr;
static void (*sShutdownCb)()     = nullptr;

static LRESULT CALLBACK wndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_KEYDOWN:
        if (wp == VK_ESCAPE) { sRunning = false; return 0; }
        break;
    case WM_CLOSE:
    case WM_DESTROY:
        sRunning = false;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, wp, lp);
}

bool platformInit(int width, int height, const char* title) {
    WNDCLASSEXA wc = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.lpfnWndProc   = wndProc;
    wc.hInstance     = GetModuleHandleA(nullptr);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = "GLSpinningTriangle";
    if (!RegisterClassExA(&wc)) { fprintf(stderr, "RegisterClassExA failed\n"); return false; }

    RECT rect = { 0, 0, width, height };
    AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX), FALSE);
    sHwnd = CreateWindowExA(0, "GLSpinningTriangle", title,
        WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        nullptr, nullptr, GetModuleHandleA(nullptr), nullptr);
    if (!sHwnd) { fprintf(stderr, "CreateWindowExA failed\n"); return false; }

    sDC = GetDC(sHwnd);

    // Create a legacy context to get wglCreateContextAttribsARB, then replace it.
    PIXELFORMATDESCRIPTOR pfd = {};
    pfd.nSize      = sizeof(pfd);
    pfd.nVersion   = 1;
    pfd.dwFlags    = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    SetPixelFormat(sDC, ChoosePixelFormat(sDC, &pfd), &pfd);
    HGLRC dummy = wglCreateContext(sDC);
    wglMakeCurrent(sDC, dummy);

    auto wglCreateContextAttribsARB = (PFNWGLCREATECONTEXTATTRIBSARBPROC)
        wglGetProcAddress("wglCreateContextAttribsARB");

    wglMakeCurrent(nullptr, nullptr);
    wglDeleteContext(dummy);

    if (!wglCreateContextAttribsARB) {
        fprintf(stderr, "WGL_ARB_create_context not supported\n");
        return false;
    }

    const int attribs[] = {
        WGL_CONTEXT_MAJOR_VERSION_ARB, 3,
        WGL_CONTEXT_MINOR_VERSION_ARB, 3,
        WGL_CONTEXT_PROFILE_MASK_ARB,  WGL_CONTEXT_CORE_PROFILE_BIT_ARB,
        0
    };
    sGLRC = wglCreateContextAttribsARB(sDC, nullptr, attribs);
    if (!sGLRC) { fprintf(stderr, "wglCreateContextAttribsARB failed\n"); return false; }
    wglMakeCurrent(sDC, sGLRC);

    ShowWindow(sHwnd, SW_SHOW);
    UpdateWindow(sHwnd);

    QueryPerformanceFrequency(&sFreq);
    QueryPerformanceCounter(&sStart);
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
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart - sStart.QuadPart) / (double)sFreq.QuadPart;
}

void platformSwapBuffers() { SwapBuffers(sDC); }

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    static const double kFrameTime = 1.0 / 60.0;
    sRenderCb   = render;
    sShutdownCb = shutdown;
    sRunning    = true;

    while (sRunning) {
        double frameStart = platformGetTime();

        MSG msg;
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { sRunning = false; break; }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        if (sRunning) render();

        double elapsed = platformGetTime() - frameStart;
        if (elapsed < kFrameTime) {
            DWORD ms = (DWORD)((kFrameTime - elapsed) * 1000.0);
            if (ms > 0) Sleep(ms);
        }
    }

    shutdown();
    wglMakeCurrent(nullptr, nullptr);
    wglDeleteContext(sGLRC);
    ReleaseDC(sHwnd, sDC);
    DestroyWindow(sHwnd);
}
