#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <stdio.h>
#include <stdlib.h>
#include <wayland-cursor.h>

#include "../../server/TracyImGui.hpp"
#include "WaylandMethod.hpp"
#include "WaylandWindow.hpp"

namespace {
void Check( bool condition, const char* msg )
{
    if( !condition )
    {
        fprintf( stderr, "%s\n", msg );
        abort();
    }
}
}

WaylandWindow::WaylandWindow( const WaylandWindowParams& p )
    : m_surface( wl_compositor_create_surface( p.display.GetCompositor() ) )
    , m_eglWindow( wl_egl_window_create( m_surface, p.winPos.w, p.winPos.h ) )
    , m_xdgSurface( xdg_wm_base_get_xdg_surface( p.display.GetWmBase(), m_surface ) )
    , m_xdgToplevel( xdg_surface_get_toplevel( m_xdgSurface ) )
    , m_xdgToplevelDecoration( nullptr )
    , m_cursorTheme( nullptr )
    , m_cursorSurf( nullptr )
    , m_display( p.display )
    , m_winPos( p.winPos )
    , m_running( p.running )
    , m_scale( p.scale )
    , m_prevScale( p.scale )
    , m_width( p.winPos.w )
    , m_height( p.winPos.h )
    , m_activationToken( nullptr )
{
    static constexpr wl_surface_listener surfaceListener = {
        .enter = Method( Enter ),
        .leave = Method( Leave )
    };

    wl_surface_add_listener( m_surface, &surfaceListener, this );

    static constexpr xdg_surface_listener xdgSurfaceListener = {
        .configure = Method( XdgSurfaceConfigure ),
    };

    xdg_surface_add_listener( m_xdgSurface, &xdgSurfaceListener, this );

    static constexpr xdg_toplevel_listener toplevelListener = {
        .configure = Method( XdgToplevelConfigure ),
        .close = Method( XdgToplevelClose )
    };

    xdg_toplevel_add_listener( m_xdgToplevel, &toplevelListener, this );
    xdg_toplevel_set_title( m_xdgToplevel, p.title );
    xdg_toplevel_set_app_id( m_xdgToplevel, "tracy" );

    if( p.display.GetDecorationManager() )
    {
        m_xdgToplevelDecoration = zxdg_decoration_manager_v1_get_toplevel_decoration( p.display.GetDecorationManager(), m_xdgToplevel );

        static constexpr zxdg_toplevel_decoration_v1_listener decorationListener = {
            .configure = Method( DecorationConfigure )
        };

        zxdg_toplevel_decoration_v1_add_listener( m_xdgToplevelDecoration, &decorationListener, this );
        zxdg_toplevel_decoration_v1_set_mode( m_xdgToplevelDecoration, ZXDG_TOPLEVEL_DECORATION_V1_MODE_SERVER_SIDE );
    }

    constexpr EGLint eglConfigAttrib[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_NONE
    };

    m_eglDpy = eglGetPlatformDisplay( EGL_PLATFORM_WAYLAND_KHR, p.display.GetDisplay(), nullptr );
    auto res = eglInitialize( m_eglDpy, nullptr, nullptr );
    Check( res == EGL_TRUE, "Cannot initialize EGL!" );

    EGLint count;
    EGLConfig eglConfig;
    res = eglChooseConfig( m_eglDpy, eglConfigAttrib, &eglConfig, 1, &count );
    Check( res == EGL_TRUE && count == 1, "No suitable EGL config found!" );

    res = eglBindAPI( EGL_OPENGL_API );
    Check( res == EGL_TRUE, "Cannot use OpenGL through EGL!" );

    m_eglSurf = eglCreatePlatformWindowSurface( m_eglDpy, eglConfig, m_eglWindow, nullptr );

    constexpr EGLint eglCtxAttrib[] = {
        EGL_CONTEXT_MAJOR_VERSION, 3,
        EGL_CONTEXT_MINOR_VERSION, 2,
        EGL_CONTEXT_OPENGL_PROFILE_MASK,  EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT,
        EGL_NONE
    };

    m_eglCtx = eglCreateContext( m_eglDpy, eglConfig, EGL_NO_CONTEXT, eglCtxAttrib );
    Check( m_eglCtx != EGL_NO_CONTEXT, "Cannot create OpenGL 3.2 Core Profile context!" );

    res = eglMakeCurrent( m_eglDpy, m_eglSurf, m_eglSurf, m_eglCtx );
    Check( res == EGL_TRUE, "Cannot make EGL context current!" );

    SetupCursor();
}

WaylandWindow::~WaylandWindow()
{
    if( m_activationToken ) xdg_activation_token_v1_destroy( m_activationToken );

    eglMakeCurrent( m_eglDpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT );
    eglDestroySurface( m_eglDpy, m_eglSurf );
    eglDestroyContext( m_eglDpy, m_eglCtx );
    eglTerminate( m_eglDpy );

    if( m_xdgToplevelDecoration ) zxdg_toplevel_decoration_v1_destroy( m_xdgToplevelDecoration );
    xdg_toplevel_destroy( m_xdgToplevel );
    xdg_surface_destroy( m_xdgSurface );
    wl_egl_window_destroy( m_eglWindow );
    wl_surface_destroy( m_surface );

    wl_surface_destroy( m_cursorSurf );
    wl_cursor_theme_destroy( m_cursorTheme );
}

void WaylandWindow::SetTitle( const char* title )
{
    xdg_toplevel_set_title( m_xdgToplevel, title );
}

void WaylandWindow::Show()
{
    wl_surface_commit( m_surface );
}

void WaylandWindow::Attention()
{
    if( !m_display.GetActivation() ) return;
    if( m_activationToken ) return;

    static constexpr xdg_activation_token_v1_listener listener = {
        .done = Method( TokenDone )
    };

    m_activationToken = xdg_activation_v1_get_activation_token( m_display.GetActivation() );
    xdg_activation_token_v1_set_surface( m_activationToken, m_surface );
    xdg_activation_token_v1_commit( m_activationToken );
    xdg_activation_token_v1_add_listener( m_activationToken, &listener, this );
}

void WaylandWindow::NewFrame()
{
    if( m_prevScale != m_scale )
    {
        m_prevScale = m_scale;
        SetupCursor();
        wl_surface_set_buffer_scale( m_surface, m_scale );
        wl_surface_commit( m_surface );
    }

    if( !m_winPos.maximize )
    {
        m_winPos.w = m_width;
        m_winPos.h = m_height;
    }
}

void WaylandWindow::Present()
{
    eglSwapBuffers( m_eglDpy, m_eglSurf );
}

wl_surface* WaylandWindow::GetCursor( int32_t& x, int32_t& y ) const
{
    x = m_cursorX;
    y = m_cursorY;
    return m_cursorSurf;
}

void WaylandWindow::Enter( struct wl_surface* surface, struct wl_output* output )
{
    uint32_t id;
    auto out = m_display.GetOutput( output, id );
    if( !out ) return;
    m_outputs.emplace( id );

    const auto outScale = out->Scale();
    if( outScale > m_scale ) m_scale = outScale;
}

void WaylandWindow::Leave( struct wl_surface* surface, struct wl_output* output )
{
    uint32_t id;
    auto out = m_display.GetOutput( output, id );
    assert( out );
    m_outputs.erase( id );

    if( out->Scale() == m_scale )
    {
        int32_t scale = 1;
        for( auto& id : m_outputs )
        {
            auto out = m_display.GetOutput( id );
            if( out->Scale() > scale ) scale = out->Scale();
        }
        if( scale != m_scale ) m_scale = scale;
    }
}

void WaylandWindow::XdgSurfaceConfigure( struct xdg_surface *xdg_surface, uint32_t serial )
{
    tracy::s_wasActive = true;
    xdg_surface_ack_configure( xdg_surface, serial );
}

void WaylandWindow::XdgToplevelConfigure( struct xdg_toplevel* toplevel, int32_t width, int32_t height, struct wl_array* states )
{
    if( width == 0 || height == 0 ) return;

    bool max = false;
    auto data = (uint32_t*)states->data;
    for( size_t i = 0; i < states->size / sizeof(uint32_t); i++ )
    {
        if( data[i] == XDG_TOPLEVEL_STATE_MAXIMIZED )
        {
            max = true;
            break;
        }
    }
    m_winPos.maximize = max;

    width *= m_scale;
    height *= m_scale;

    if( m_width != width || m_height != height )
    {
        m_width = width;
        m_height = height;

        wl_egl_window_resize( m_eglWindow, width, height, 0, 0 );
        wl_surface_commit( m_surface );
    }
}

void WaylandWindow::XdgToplevelClose( struct xdg_toplevel* toplevel )
{
    m_running = false;
}

void WaylandWindow::DecorationConfigure( zxdg_toplevel_decoration_v1* tldec, uint32_t mode )
{
}

void WaylandWindow::TokenDone( xdg_activation_token_v1* activationToken, const char* token )
{
    xdg_activation_v1_activate( m_display.GetActivation(), token, m_surface );
    xdg_activation_token_v1_destroy( activationToken );
    m_activationToken = nullptr;
}

void WaylandWindow::SetupCursor()
{
    auto env_xcursor_theme = getenv( "XCURSOR_THEME" );
    auto env_xcursor_size = getenv( "XCURSOR_SIZE" );

    int size = env_xcursor_size ? atoi( env_xcursor_size ) : 24;
    size *= m_scale;

    if( m_cursorSurf ) wl_surface_destroy( m_cursorSurf );
    if( m_cursorTheme ) wl_cursor_theme_destroy( m_cursorTheme );

    m_cursorTheme = wl_cursor_theme_load( env_xcursor_theme, size, m_display.GetShm() );
    auto cursor = wl_cursor_theme_get_cursor( m_cursorTheme, "left_ptr" );
    m_cursorSurf = wl_compositor_create_surface( m_display.GetCompositor() );
    if( m_scale != 1 ) wl_surface_set_buffer_scale( m_cursorSurf, m_scale );
    wl_surface_attach( m_cursorSurf, wl_cursor_image_get_buffer( cursor->images[0] ), 0, 0 );
    wl_surface_commit( m_cursorSurf );
    m_cursorX = cursor->images[0]->hotspot_x / m_scale;
    m_cursorY = cursor->images[0]->hotspot_y / m_scale;

    auto pointer = m_display.GetPointer();
    if( pointer ) wl_pointer_set_cursor( pointer, 0, m_cursorSurf, m_cursorX, m_cursorY );
}
