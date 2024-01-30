#ifndef __WAYLANDWINDOW_HPP__
#define __WAYLANDWINDOW_HPP__

#include <EGL/egl.h>
#include <functional>
#include <stdint.h>
#include <unordered_set>
#include <wayland-client.h>
#include <wayland-egl.h>

#include "wayland/xdg-activation.h"
#include "wayland/xdg-decoration.h"
#include "wayland/xdg-shell.h"

#include "WaylandDisplay.hpp"
#include "WindowPosition.hpp"

struct WaylandWindowParams
{
    WaylandDisplay& display;
    const char* title;
    WindowPosition& winPos;
    bool& running;
    int32_t& scale;
};

class WaylandWindow
{
public:
    WaylandWindow( const WaylandWindowParams& p );
    ~WaylandWindow();

    void SetTitle( const char* title );
    void Show();
    void Attention();

    void NewFrame();
    void Present();

    [[nodiscard]] int Width() const { return m_width; }
    [[nodiscard]] int Height() const { return m_height; }

    [[nodiscard]] wl_surface* GetCursor( int32_t& x, int32_t& y ) const;

private:
    void Enter( struct wl_surface* surface, struct wl_output* output );
    void Leave( struct wl_surface* surface, struct wl_output* output );

    void XdgSurfaceConfigure( struct xdg_surface *xdg_surface, uint32_t serial );

    void XdgToplevelConfigure( struct xdg_toplevel* toplevel, int32_t width, int32_t height, struct wl_array* states );
    void XdgToplevelClose( struct xdg_toplevel* toplevel );

    void DecorationConfigure( zxdg_toplevel_decoration_v1* tldec, uint32_t mode );

    void TokenDone( xdg_activation_token_v1* activationToken, const char* token );

    void SetupCursor();

    wl_surface* m_surface;
    wl_egl_window* m_eglWindow;
    xdg_surface* m_xdgSurface;
    xdg_toplevel* m_xdgToplevel;
    zxdg_toplevel_decoration_v1* m_xdgToplevelDecoration;

    EGLDisplay m_eglDpy;
    EGLContext m_eglCtx;
    EGLSurface m_eglSurf;

    struct wl_cursor_theme* m_cursorTheme;
    struct wl_surface* m_cursorSurf;
    int32_t m_cursorX, m_cursorY;

    WaylandDisplay& m_display;
    WindowPosition& m_winPos;
    bool& m_running;
    int32_t& m_scale;
    int32_t m_prevScale;

    int m_width, m_height;
    std::unordered_set<uint32_t> m_outputs;

    xdg_activation_token_v1* m_activationToken;
};

#endif
