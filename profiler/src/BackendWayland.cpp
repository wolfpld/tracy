#include <EGL/egl.h>
#include <EGL/eglext.h>

#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_opengl3_loader.h"

#include <chrono>
#include <stdio.h>
#include <string.h>
#include <wayland-client.h>
#include <wayland-egl.h>

#include "xdg-shell.h"

#include "Backend.hpp"
#include "RunQueue.hpp"

static std::function<void()> s_redraw;
static RunQueue* s_mainThreadTasks;

static struct wl_display* s_dpy;
static struct wl_compositor* s_comp;
static struct wl_surface* s_surf;
static struct wl_egl_window* s_eglWin;
static struct wl_shm* s_shm;
static struct xdg_wm_base* s_wm;
static EGLDisplay s_eglDpy;
static EGLContext s_eglCtx;
static EGLSurface s_eglSurf;
static struct xdg_surface* s_xdgSurf;
static struct xdg_toplevel* s_toplevel;

static bool s_running = true;
static int s_w, s_h;
static uint64_t s_time;


static void WmPing( void*, struct xdg_wm_base* shell, uint32_t serial )
{
    xdg_wm_base_pong( shell, serial );
}

constexpr struct xdg_wm_base_listener wmListener = {
    .ping = WmPing
};


static void RegistryGlobalCb( void*, struct wl_registry* reg, uint32_t name, const char* interface, uint32_t version )
{
    if( strcmp( interface, wl_compositor_interface.name ) == 0 )
    {
        s_comp = (wl_compositor*)wl_registry_bind( reg, name, &wl_compositor_interface, 4 );
    }
    else if( strcmp( interface, wl_shm_interface.name ) == 0 )
    {
        s_shm = (wl_shm*)wl_registry_bind( reg, name, &wl_shm_interface, 1 );
    }
    else if( strcmp( interface, xdg_wm_base_interface.name ) == 0 )
    {
        s_wm = (xdg_wm_base*)wl_registry_bind( reg, name, &xdg_wm_base_interface, 1 );
        xdg_wm_base_add_listener( s_wm, &wmListener, nullptr );
    }
}

constexpr struct wl_registry_listener registryListener = {
    .global = RegistryGlobalCb
};


static void XdgSurfaceConfigure( void*, struct xdg_surface* surf, uint32_t serial )
{
    xdg_surface_ack_configure( surf, serial );
}

constexpr struct xdg_surface_listener surfaceListener = {
    .configure = XdgSurfaceConfigure
};


static void XdgToplevelConfigure( void*, struct xdg_toplevel* toplevel, int32_t width, int32_t height, struct wl_array* states )
{
    if( width == 0 || height == 0 ) return;
    if( s_w != width || s_h != height )
    {
        s_w = width;
        s_h = height;

        wl_egl_window_resize( s_eglWin, width, height, 0, 0 );
        wl_surface_commit( s_surf );
    }
}

static void XdgToplevelClose( void*, struct xdg_toplevel* toplevel )
{
    s_running = false;
}

constexpr struct xdg_toplevel_listener toplevelListener = {
    .configure = XdgToplevelConfigure,
    .close = XdgToplevelClose
};

Backend::Backend( const char* title, std::function<void()> redraw, RunQueue* mainThreadTasks )
{
    s_redraw = redraw;
    s_mainThreadTasks = mainThreadTasks;
    s_w = m_winPos.w;
    s_h = m_winPos.h;

    s_dpy = wl_display_connect( nullptr );
    if( !s_dpy ) { fprintf( stderr, "Cannot establish wayland display connection!\n" ); exit( 1 ); }

    wl_registry_add_listener( wl_display_get_registry( s_dpy ), &registryListener, nullptr );
    wl_display_roundtrip( s_dpy );

    if( !s_comp ) { fprintf( stderr, "No wayland compositor!\n" ); exit( 1 ); }
    if( !s_shm ) { fprintf( stderr, "No wayland shared memory!\n" ); exit( 1 ); }
    if( !s_wm ) { fprintf( stderr, "No wayland window manager!\n" ); exit( 1 ); }

    s_surf = wl_compositor_create_surface( s_comp );
    s_eglWin = wl_egl_window_create( s_surf, m_winPos.w, m_winPos.h );
    s_xdgSurf = xdg_wm_base_get_xdg_surface( s_wm, s_surf );
    xdg_surface_add_listener( s_xdgSurf, &surfaceListener, nullptr );
    s_toplevel = xdg_surface_get_toplevel( s_xdgSurf );
    xdg_toplevel_add_listener( s_toplevel, &toplevelListener, nullptr );
    xdg_toplevel_set_title( s_toplevel, title );

    constexpr EGLint eglConfigAttrib[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_NONE
    };

    s_eglDpy = eglGetPlatformDisplay( EGL_PLATFORM_WAYLAND_KHR, s_dpy, nullptr );
    EGLBoolean res;
    res = eglInitialize( s_eglDpy, nullptr, nullptr );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot initialize EGL!\n" ); exit( 1 ); }

    EGLint count;
    EGLConfig eglConfig;
    res = eglChooseConfig( s_eglDpy, eglConfigAttrib, &eglConfig, 1, &count );
    if( res != EGL_TRUE || count != 1 ) { fprintf( stderr, "No suitable EGL config found!\n" ); exit( 1 ); }

    res = eglBindAPI( EGL_OPENGL_API );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot use OpenGL through EGL!\n" ); exit( 1 ); }

    s_eglSurf = eglCreatePlatformWindowSurface( s_eglDpy, eglConfig, s_eglWin, nullptr );

    constexpr EGLint eglCtxAttrib[] = {
        EGL_CONTEXT_MAJOR_VERSION, 3,
        EGL_CONTEXT_MINOR_VERSION, 2,
        EGL_CONTEXT_OPENGL_PROFILE_MASK,  EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT,
        EGL_NONE
    };

    s_eglCtx = eglCreateContext( s_eglDpy, eglConfig, EGL_NO_CONTEXT, eglCtxAttrib );
    if( !s_eglCtx ) { fprintf( stderr, "Cannot create OpenGL 3.2 Core Profile context!\n" ); exit( 1 ); }
    res = eglMakeCurrent( s_eglDpy, s_eglSurf, s_eglSurf, s_eglCtx );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot make EGL context current!\n" ); exit( 1 ); }

    ImGui_ImplOpenGL3_Init( "#version 150" );

    ImGuiIO& io = ImGui::GetIO();
    io.BackendPlatformName = "wayland (tracy profiler)";
    s_time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

Backend::~Backend()
{
    eglMakeCurrent( s_eglDpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT );
    eglDestroySurface( s_eglDpy, s_eglSurf );
    eglDestroyContext( s_eglDpy, s_eglCtx );
    eglTerminate( s_eglDpy );
    xdg_toplevel_destroy( s_toplevel );
    xdg_surface_destroy( s_xdgSurf );
    wl_egl_window_destroy( s_eglWin );
    wl_surface_destroy( s_surf );
    xdg_wm_base_destroy( s_wm );
    wl_shm_destroy( s_shm );
    wl_compositor_destroy( s_comp );
    wl_display_disconnect( s_dpy );
}

void Backend::Show()
{
    wl_surface_commit( s_surf );
}

void Backend::Run()
{
    while( s_running && wl_display_dispatch( s_dpy ) != -1 )
    {
        s_redraw();
        s_mainThreadTasks->Run();
    }
}

void Backend::Attention()
{
}

void Backend::NewFrame( int& w, int& h )
{
    w = m_winPos.w = s_w;
    h = m_winPos.h = s_h;

    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2( w, h );
    io.DisplayFramebufferScale = ImVec2( 1, 1 );

    ImGui_ImplOpenGL3_NewFrame();

    uint64_t time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
    io.DeltaTime = ( time - s_time ) / 1000000.f;
    s_time = time;
}

void Backend::EndFrame()
{
    const ImVec4 clear_color = ImColor( 114, 144, 154 );

    ImGui::Render();
    glViewport( 0, 0, s_w, s_h );
    glClearColor( clear_color.x, clear_color.y, clear_color.z, clear_color.w );
    glClear( GL_COLOR_BUFFER_BIT );
    ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData() );

    eglSwapBuffers( s_eglDpy, s_eglSurf );
}

void Backend::SetIcon( uint8_t* data, int w, int h )
{
}

void Backend::SetTitle( const char* title )
{
    xdg_toplevel_set_title( s_toplevel, title );
}

float Backend::GetDpiScale()
{
    return 1.f;
}
