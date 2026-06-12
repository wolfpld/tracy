// platform_windows.cpp — Windows backend (Win32)
//
// Compile flags (MSVC, console subsystem):
//   cl /std:c++17 spinning_triangle.cpp platform_windows.cpp \
//       /I\path\to\wgpu\include \path\to\wgpu\lib\wgpu_native.lib \
//       user32.lib gdi32.lib /Fe:spinning_triangle.exe
//
// MinGW/Clang equivalent:
//   clang++ -std=c++17 spinning_triangle.cpp platform_windows.cpp \
//       -I/path/to/wgpu/include -L/path/to/wgpu/lib -lwgpu_native \
//       -luser32 -lgdi32 -o spinning_triangle.exe

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <webgpu/webgpu.h>
#include <stdio.h>
#include "platform.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "dxguid.lib")    // Dawn: WKPDID_D3DDebugObjectName
#pragma comment(lib, "OneCore")       // Dawn: CompareObjectHandles
#pragma comment(lib, "ntdll.lib")     // wgpu-native: NtReadFile et al.

static HWND   sHwnd      = nullptr;
static bool   sRunning   = false;
static LARGE_INTEGER sFreq      = {};
static LARGE_INTEGER sStartTime = {};

// ---------------------------------------------------------------------------
// Win32 window procedure
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Platform interface implementation
// ---------------------------------------------------------------------------

bool platformInit(int width, int height, const char* title) {
    WNDCLASSEXA wc  = {};
    wc.cbSize        = sizeof(wc);
    wc.style         = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc   = wndProc;
    wc.hInstance     = GetModuleHandleA(nullptr);
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.lpszClassName = "SpinningTriangle";
    if (!RegisterClassExA(&wc)) {
        fprintf(stderr, "RegisterClassExA failed (%lu)\n", GetLastError());
        return false;
    }

    // Adjust client area to match the requested dimensions
    RECT rect = { 0, 0, width, height };
    AdjustWindowRect(&rect, WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX), FALSE);

    sHwnd = CreateWindowExA(
        0, "SpinningTriangle", title,
        WS_OVERLAPPEDWINDOW & ~(WS_THICKFRAME | WS_MAXIMIZEBOX),
        CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        nullptr, nullptr, GetModuleHandleA(nullptr), nullptr);
    if (!sHwnd) {
        fprintf(stderr, "CreateWindowExA failed (%lu)\n", GetLastError());
        return false;
    }

    ShowWindow(sHwnd, SW_SHOW);
    UpdateWindow(sHwnd);

    QueryPerformanceFrequency(&sFreq);
    QueryPerformanceCounter(&sStartTime);
    return true;
}

WGPUSurface platformCreateSurface(WGPUInstance instance) {
    WGPUSurfaceSourceWindowsHWND hwndSrc = {};
    hwndSrc.chain.sType = WGPUSType_SurfaceSourceWindowsHWND;
    hwndSrc.hinstance   = GetModuleHandleA(nullptr);
    hwndSrc.hwnd        = sHwnd;

    WGPUSurfaceDescriptor surfDesc = {};
    surfDesc.nextInChain = (WGPUChainedStruct*)&hwndSrc;
    return wgpuInstanceCreateSurface(instance, &surfDesc);
}

double platformGetTime() {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    return (double)(now.QuadPart - sStartTime.QuadPart) / (double)sFreq.QuadPart;
}

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    // Target ~16.67 ms per frame (60 fps)
    static const double kFrameTime = 1.0 / 60.0;

    sRunning = true;
    while (sRunning) {
        double frameStart = platformGetTime();

        // Drain the Win32 message queue
        MSG msg;
        while (PeekMessageA(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { sRunning = false; break; }
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        if (sRunning) render();

        // Sleep for the remainder of the frame budget
        double elapsed = platformGetTime() - frameStart;
        if (elapsed < kFrameTime) {
            DWORD ms = (DWORD)((kFrameTime - elapsed) * 1000.0);
            if (ms > 0) Sleep(ms);
        }
    }

    shutdown();
    if (sHwnd) DestroyWindow(sHwnd);
}
