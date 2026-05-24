// platform_wayland.cpp — Linux/Wayland backend
//
// Dependencies:
//   libwayland-client, wayland-protocols (for xdg-shell)
//
// Generate xdg-shell protocol glue before building:
//   XML=$(pkg-config --variable=pkgdatadir wayland-protocols)/stable/xdg-shell/xdg-shell.xml
//   wayland-scanner client-header  $XML xdg-shell-client-protocol.h
//   wayland-scanner private-code   $XML xdg-shell-protocol.c
//
// Compile flags (see spinning_triangle.cpp header for full invocation):
//   g++ -std=c++17 spinning_triangle.cpp platform_wayland.cpp \
//       xdg-shell-protocol.c \
//       -I/path/to/wgpu/include -L/path/to/wgpu/lib -lwgpu_native \
//       $(pkg-config --cflags --libs wayland-client) \
//       -o spinning_triangle

#include <wayland-client.h>
#include "xdg-shell-client-protocol.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <webgpu/webgpu.h>
#include "platform.h"

static wl_display*    sDisplay    = nullptr;
static wl_compositor* sCompositor = nullptr;
static xdg_wm_base*   sWmBase     = nullptr;
static wl_seat*       sSeat       = nullptr;
static wl_keyboard*   sKeyboard   = nullptr;
static wl_surface*    sSurface    = nullptr;
static xdg_surface*   sXdgSurface = nullptr;
static xdg_toplevel*  sToplevel   = nullptr;
static bool           sConfigured = false;
static bool           sRunning    = false;
static struct timespec sStartTime  = {};

// ---------------------------------------------------------------------------
// xdg_wm_base listener — ping/pong keepalive
// ---------------------------------------------------------------------------

static void wmBasePing(void*, xdg_wm_base* wm, uint32_t serial) {
    xdg_wm_base_pong(wm, serial);
}
static const xdg_wm_base_listener kWmBaseListener = { wmBasePing };

// ---------------------------------------------------------------------------
// xdg_surface listener — acknowledge configure events
// ---------------------------------------------------------------------------

static void xdgSurfaceConfigure(void*, xdg_surface* surf, uint32_t serial) {
    xdg_surface_ack_configure(surf, serial);
    sConfigured = true;
}
static const xdg_surface_listener kXdgSurfaceListener = { xdgSurfaceConfigure };

// ---------------------------------------------------------------------------
// xdg_toplevel listener — window close / resize
// ---------------------------------------------------------------------------

static void toplevelClose(void*, xdg_toplevel*) {
    sRunning = false;
}
static void toplevelConfigure(void*, xdg_toplevel*, int32_t, int32_t, wl_array*) {}
static const xdg_toplevel_listener kToplevelListener = { toplevelConfigure, toplevelClose };

// ---------------------------------------------------------------------------
// Keyboard listener — Escape to quit
// ---------------------------------------------------------------------------

static void kbdKeymap(void*, wl_keyboard*, uint32_t, int32_t, uint32_t) {}
static void kbdEnter(void*, wl_keyboard*, uint32_t, wl_surface*, wl_array*) {}
static void kbdLeave(void*, wl_keyboard*, uint32_t, wl_surface*) {}
static void kbdKey(void*, wl_keyboard*, uint32_t, uint32_t, uint32_t key, uint32_t state) {
    // key 1 == KEY_ESC in Linux evdev (linux/input-event-codes.h)
    if (key == 1 && state == WL_KEYBOARD_KEY_STATE_PRESSED)
        sRunning = false;
}
static void kbdModifiers(void*, wl_keyboard*, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) {}
static void kbdRepeatInfo(void*, wl_keyboard*, int32_t, int32_t) {}
static const wl_keyboard_listener kKbdListener = {
    kbdKeymap, kbdEnter, kbdLeave, kbdKey, kbdModifiers, kbdRepeatInfo
};

// ---------------------------------------------------------------------------
// wl_seat listener — grab keyboard capability
// ---------------------------------------------------------------------------

static void seatCapabilities(void*, wl_seat* seat, uint32_t caps) {
    if ((caps & WL_SEAT_CAPABILITY_KEYBOARD) && !sKeyboard) {
        sKeyboard = wl_seat_get_keyboard(seat);
        wl_keyboard_add_listener(sKeyboard, &kKbdListener, nullptr);
    } else if (!(caps & WL_SEAT_CAPABILITY_KEYBOARD) && sKeyboard) {
        wl_keyboard_release(sKeyboard);
        sKeyboard = nullptr;
    }
}
static void seatName(void*, wl_seat*, const char*) {}
static const wl_seat_listener kSeatListener = { seatCapabilities, seatName };

// ---------------------------------------------------------------------------
// Registry listener — bind global interfaces
// ---------------------------------------------------------------------------

static void registryGlobal(void*, wl_registry* reg,
                            uint32_t name, const char* iface, uint32_t ver) {
    if (strcmp(iface, wl_compositor_interface.name) == 0)
        sCompositor = (wl_compositor*)wl_registry_bind(reg, name, &wl_compositor_interface, 4);
    else if (strcmp(iface, xdg_wm_base_interface.name) == 0) {
        sWmBase = (xdg_wm_base*)wl_registry_bind(reg, name, &xdg_wm_base_interface, 1);
        xdg_wm_base_add_listener(sWmBase, &kWmBaseListener, nullptr);
    } else if (strcmp(iface, wl_seat_interface.name) == 0) {
        sSeat = (wl_seat*)wl_registry_bind(reg, name, &wl_seat_interface, 5);
        wl_seat_add_listener(sSeat, &kSeatListener, nullptr);
    }
}
static void registryGlobalRemove(void*, wl_registry*, uint32_t) {}
static const wl_registry_listener kRegistryListener = { registryGlobal, registryGlobalRemove };

// ---------------------------------------------------------------------------
// Platform interface implementation
// ---------------------------------------------------------------------------

bool platformInit(int width, int height, const char* title) {
    sDisplay = wl_display_connect(nullptr);
    if (!sDisplay) { fprintf(stderr, "Cannot connect to Wayland display\n"); return false; }

    wl_registry* registry = wl_display_get_registry(sDisplay);
    wl_registry_add_listener(registry, &kRegistryListener, nullptr);

    // Two roundtrips: first to enumerate globals, second for seat capabilities
    wl_display_roundtrip(sDisplay);
    wl_display_roundtrip(sDisplay);

    if (!sCompositor) { fprintf(stderr, "No wl_compositor\n"); return false; }
    if (!sWmBase)     { fprintf(stderr, "No xdg_wm_base\n");  return false; }

    sSurface    = wl_compositor_create_surface(sCompositor);
    sXdgSurface = xdg_wm_base_get_xdg_surface(sWmBase, sSurface);
    sToplevel   = xdg_surface_get_toplevel(sXdgSurface);

    xdg_surface_add_listener(sXdgSurface, &kXdgSurfaceListener, nullptr);
    xdg_toplevel_add_listener(sToplevel, &kToplevelListener, nullptr);
    xdg_toplevel_set_title(sToplevel, title);
    xdg_toplevel_set_app_id(sToplevel, "spinning_triangle");

    wl_surface_commit(sSurface);

    // Wait for the compositor to send the first configure
    while (!sConfigured) wl_display_dispatch(sDisplay);

    clock_gettime(CLOCK_MONOTONIC, &sStartTime);
    return true;
}

WGPUSurface platformCreateSurface(WGPUInstance instance) {
    WGPUSurfaceSourceWaylandSurface waylandSrc = {};
    waylandSrc.chain.sType = WGPUSType_SurfaceSourceWaylandSurface;
    waylandSrc.display     = sDisplay;
    waylandSrc.surface     = sSurface;

    WGPUSurfaceDescriptor surfDesc = {};
    surfDesc.nextInChain = (WGPUChainedStruct*)&waylandSrc;
    return wgpuInstanceCreateSurface(instance, &surfDesc);
}

double platformGetTime() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec  - sStartTime.tv_sec)
         + (double)(now.tv_nsec - sStartTime.tv_nsec) * 1e-9;
}

void platformRunLoop(void (*render)(), void (*shutdown)()) {
    // Target ~16.67 ms per frame (60 fps)
    static const long kFrameNs = 1000000000L / 60;

    sRunning = true;
    while (sRunning) {
        struct timespec frameStart;
        clock_gettime(CLOCK_MONOTONIC, &frameStart);

        // Dispatch pending Wayland events without blocking
        if (wl_display_dispatch_pending(sDisplay) < 0) break;
        wl_display_flush(sDisplay);

        if (sRunning) render();

        // Sleep for the remainder of the frame budget
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

    // Cleanup Wayland objects
    if (sKeyboard)   { wl_keyboard_release(sKeyboard);   sKeyboard   = nullptr; }
    if (sToplevel)   { xdg_toplevel_destroy(sToplevel);  sToplevel   = nullptr; }
    if (sXdgSurface) { xdg_surface_destroy(sXdgSurface); sXdgSurface = nullptr; }
    if (sSurface)    { wl_surface_destroy(sSurface);     sSurface    = nullptr; }
    if (sWmBase)     { xdg_wm_base_destroy(sWmBase);     sWmBase     = nullptr; }
    if (sSeat)       { wl_seat_release(sSeat);           sSeat       = nullptr; }
    if (sCompositor) { wl_compositor_destroy(sCompositor); sCompositor = nullptr; }
    wl_display_disconnect(sDisplay);
}
