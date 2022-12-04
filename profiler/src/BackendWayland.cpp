#include <EGL/egl.h>
#include <EGL/eglext.h>

#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_opengl3_loader.h"

#include <chrono>
#include <linux/input-event-codes.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>
#include <wayland-client.h>
#include <wayland-cursor.h>
#include <wayland-egl.h>

#include "wayland/xdg-activation.h"
#include "wayland/xdg-decoration.h"
#include "wayland/xdg-shell.h"

#include "../../server/TracyImGui.hpp"

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
static struct wl_seat* s_seat;
static struct wl_pointer* s_pointer;
static struct wl_cursor_theme* s_cursorTheme;
static struct wl_surface* s_cursorSurf;
static int32_t s_cursorX, s_cursorY;
static struct xdg_activation_v1* s_activation;
static struct xdg_activation_token_v1* s_actToken;
static struct zxdg_decoration_manager_v1* s_decoration;
static struct zxdg_toplevel_decoration_v1* s_tldec;

struct Output
{
    int32_t scale;
    wl_output* obj;
};
static std::unordered_map<uint32_t, std::unique_ptr<Output>> s_output;

static bool s_running = true;
static int s_w, s_h;
static uint64_t s_time;

static wl_fixed_t s_wheelAxisX, s_wheelAxisY;
static bool s_wheel;

static void PointerEnter( void*, struct wl_pointer* pointer, uint32_t serial, struct wl_surface* surf, wl_fixed_t sx, wl_fixed_t sy )
{
    wl_pointer_set_cursor( pointer, serial, s_cursorSurf, s_cursorX, s_cursorY );
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( wl_fixed_to_double( sx ), wl_fixed_to_double( sy ) );
}

static void PointerLeave( void*, struct wl_pointer* pointer, uint32_t serial, struct wl_surface* surf )
{
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( -FLT_MAX, -FLT_MAX );
}

static void PointerMotion( void*, struct wl_pointer* pointer, uint32_t time, wl_fixed_t sx, wl_fixed_t sy )
{
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( wl_fixed_to_double( sx ), wl_fixed_to_double( sy ) );
}

static void PointerButton( void*, struct wl_pointer* pointer, uint32_t serial, uint32_t time, uint32_t button, uint32_t state )
{
    int b;
    switch( button )
    {
    case BTN_LEFT: b = 0; break;
    case BTN_MIDDLE: b = 1; break;
    case BTN_RIGHT: b = 2; break;
    default: return;
    }
    ImGuiIO& io = ImGui::GetIO();
    io.AddMouseButtonEvent( b, state == WL_POINTER_BUTTON_STATE_PRESSED );
}

static void PointerAxis( void*, struct wl_pointer* pointer, uint32_t time, uint32_t axis, wl_fixed_t value )
{
    s_wheel = true;
    if( axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL )
    {
        s_wheelAxisX += value;
    }
    else
    {
        s_wheelAxisY += value;
    }
}

static void PointerAxisSource( void*, struct wl_pointer* pointer, uint32_t source )
{
}

static void PointerAxisStop( void*, struct wl_pointer* pointer, uint32_t time, uint32_t axis )
{
}

static void PointerAxisDiscrete( void*, struct wl_pointer* pointer, uint32_t axis, int32_t type )
{
}

static void PointerFrame( void*, struct wl_pointer* pointer )
{
    if( s_wheel )
    {
        s_wheel = false;
        ImGuiIO& io = ImGui::GetIO();
        io.AddMouseWheelEvent( wl_fixed_to_double( s_wheelAxisX ), wl_fixed_to_double( s_wheelAxisY ) );
        s_wheelAxisX = s_wheelAxisY = 0;
    }
}

constexpr struct wl_pointer_listener pointerListener = {
    .enter = PointerEnter,
    .leave = PointerLeave,
    .motion = PointerMotion,
    .button = PointerButton,
    .axis = PointerAxis,
    .frame = PointerFrame,
    .axis_source = PointerAxisSource,
    .axis_stop = PointerAxisStop,
    .axis_discrete = PointerAxisDiscrete
};


static void SeatCapabilities( void*, struct wl_seat* seat, uint32_t caps )
{
    const bool hasPointer = caps & WL_SEAT_CAPABILITY_POINTER;
    if( hasPointer && !s_pointer )
    {
        s_pointer = wl_seat_get_pointer( s_seat );
        wl_pointer_add_listener( s_pointer, &pointerListener, nullptr );
    }
    else if( !hasPointer && s_pointer )
    {
        wl_pointer_release( s_pointer );
        s_pointer = nullptr;
    }
}

static void SeatName( void*, struct wl_seat* seat, const char* name )
{
}

constexpr struct wl_seat_listener seatListener = {
    .capabilities = SeatCapabilities,
    .name = SeatName
};


static void WmPing( void*, struct xdg_wm_base* shell, uint32_t serial )
{
    xdg_wm_base_pong( shell, serial );
}

constexpr struct xdg_wm_base_listener wmListener = {
    .ping = WmPing
};


static void OutputGeometry( void*, struct wl_output* output, int32_t x, int32_t y, int32_t phys_w, int32_t phys_h, int32_t subpixel, const char* make, const char* model, int32_t transform )
{
}

static void OutputMode( void*, struct wl_output* output, uint32_t flags, int32_t w, int32_t h, int32_t refresh )
{
}

static void OutputDone( void*, struct wl_output* output )
{
}

static void OutputScale( void* data, struct wl_output* output, int32_t scale )
{
    auto out = (Output*)data;
    out->scale = scale;
}

constexpr struct wl_output_listener outputListener = {
    .geometry = OutputGeometry,
    .mode = OutputMode,
    .done = OutputDone,
    .scale = OutputScale
};


static void DecorationConfigure( void*, struct zxdg_toplevel_decoration_v1* tldec, uint32_t mode )
{
}

constexpr struct zxdg_toplevel_decoration_v1_listener decorationListener = {
    .configure = DecorationConfigure
};


static void RegistryGlobal( void*, struct wl_registry* reg, uint32_t name, const char* interface, uint32_t version )
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
    else if( strcmp( interface, wl_seat_interface.name ) == 0 )
    {
        s_seat = (wl_seat*)wl_registry_bind( reg, name, &wl_seat_interface, 7 );
        wl_seat_add_listener( s_seat, &seatListener, nullptr );
    }
    else if( strcmp( interface, xdg_activation_v1_interface.name ) == 0 )
    {
        s_activation = (xdg_activation_v1*)wl_registry_bind( reg, name, &xdg_activation_v1_interface, 1 );
    }
    else if( strcmp( interface, wl_output_interface.name ) == 0 )
    {
        auto output = (wl_output*)wl_registry_bind( reg, name, &wl_output_interface, 2 );
        auto ptr = std::make_unique<Output>( Output { 1, output } );
        wl_output_add_listener( output, &outputListener, ptr.get() );
        s_output.emplace( name, std::move( ptr ) );
    }
    else if( strcmp( interface, zxdg_decoration_manager_v1_interface.name ) == 0 )
    {
        s_decoration = (zxdg_decoration_manager_v1*)wl_registry_bind( reg, name, &zxdg_decoration_manager_v1_interface, 1 );
    }
    else if( strcmp( interface, zxdg_toplevel_decoration_v1_interface.name ) == 0 )
    {
        s_tldec = (zxdg_toplevel_decoration_v1*)wl_registry_bind( reg, name, &zxdg_toplevel_decoration_v1_interface, 1 );
        zxdg_toplevel_decoration_v1_add_listener( s_tldec, &decorationListener, nullptr );
        zxdg_toplevel_decoration_v1_set_mode( s_tldec, ZXDG_TOPLEVEL_DECORATION_V1_MODE_SERVER_SIDE );
    }
}

static void RegistryGlobalRemove( void*, struct wl_registry* reg, uint32_t name )
{
    auto it = s_output.find( name );
    if( it == s_output.end() ) return;
    wl_output_destroy( it->second->obj );
    s_output.erase( it );
}

constexpr struct wl_registry_listener registryListener = {
    .global = RegistryGlobal,
    .global_remove = RegistryGlobalRemove
};


static void XdgSurfaceConfigure( void*, struct xdg_surface* surf, uint32_t serial )
{
    tracy::s_wasActive = true;
    xdg_surface_ack_configure( surf, serial );
}

constexpr struct xdg_surface_listener xdgSurfaceListener = {
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
    if( !s_seat ) { fprintf( stderr, "No wayland seat!\n" ); exit( 1 ); }

    s_surf = wl_compositor_create_surface( s_comp );
    s_eglWin = wl_egl_window_create( s_surf, m_winPos.w, m_winPos.h );
    s_xdgSurf = xdg_wm_base_get_xdg_surface( s_wm, s_surf );
    xdg_surface_add_listener( s_xdgSurf, &xdgSurfaceListener, nullptr );

    auto env_xcursor_theme = getenv( "XCURSOR_THEME" );
    auto env_xcursor_size = getenv( "XCURSOR_SIZE" );

    s_cursorTheme = wl_cursor_theme_load( env_xcursor_theme, env_xcursor_size ? atoi( env_xcursor_size ) : 24, s_shm );
    auto cursor = wl_cursor_theme_get_cursor( s_cursorTheme, "left_ptr" );
    s_cursorSurf = wl_compositor_create_surface( s_comp );
    wl_surface_attach( s_cursorSurf, wl_cursor_image_get_buffer( cursor->images[0] ), 0, 0 );
    wl_surface_commit( s_cursorSurf );
    s_cursorX = cursor->images[0]->hotspot_x;
    s_cursorY = cursor->images[0]->hotspot_y;

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

    wl_display_roundtrip( s_dpy );
    s_toplevel = xdg_surface_get_toplevel( s_xdgSurf );
    xdg_toplevel_add_listener( s_toplevel, &toplevelListener, nullptr );
    xdg_toplevel_set_title( s_toplevel, title );
    xdg_toplevel_set_app_id( s_toplevel, "tracy" );

    if( s_decoration )
    {
        zxdg_decoration_manager_v1_get_toplevel_decoration( s_decoration, s_toplevel );
        wl_display_roundtrip( s_dpy );
    }

    ImGuiIO& io = ImGui::GetIO();
    io.BackendPlatformName = "wayland (tracy profiler)";
    s_time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

Backend::~Backend()
{
    if( s_tldec ) zxdg_toplevel_decoration_v1_destroy( s_tldec );
    if( s_decoration ) zxdg_decoration_manager_v1_destroy( s_decoration );
    if( s_actToken ) xdg_activation_token_v1_destroy( s_actToken );
    if( s_activation ) xdg_activation_v1_destroy( s_activation );
    if( s_pointer ) wl_pointer_destroy( s_pointer );
    eglMakeCurrent( s_eglDpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT );
    eglDestroySurface( s_eglDpy, s_eglSurf );
    eglDestroyContext( s_eglDpy, s_eglCtx );
    eglTerminate( s_eglDpy );
    xdg_toplevel_destroy( s_toplevel );
    wl_surface_destroy( s_cursorSurf );
    wl_cursor_theme_destroy( s_cursorTheme );
    xdg_surface_destroy( s_xdgSurf );
    wl_egl_window_destroy( s_eglWin );
    wl_surface_destroy( s_surf );
    for( auto& v : s_output ) wl_output_destroy( v.second->obj );
    s_output.clear();
    wl_seat_destroy( s_seat );
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


static void TokenDone( void*, xdg_activation_token_v1* token, const char* str )
{
    xdg_activation_v1_activate( s_activation, str, s_surf );
    xdg_activation_token_v1_destroy( token );
    s_actToken = nullptr;
}

constexpr struct xdg_activation_token_v1_listener tokenListener = {
    .done = TokenDone
}; 


void Backend::Attention()
{
    if( !s_activation ) return;
    if( s_actToken ) return;
    s_actToken = xdg_activation_v1_get_activation_token( s_activation );
    xdg_activation_token_v1_set_surface( s_actToken, s_surf );
    xdg_activation_token_v1_commit( s_actToken );
    xdg_activation_token_v1_add_listener( s_actToken, &tokenListener, nullptr );
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
