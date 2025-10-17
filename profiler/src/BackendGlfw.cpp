#include <backends/imgui_impl_glfw.h>
#include <backends/imgui_impl_opengl3.h>
#include <backends/imgui_impl_opengl3_loader.h>

#include <chrono>
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>

#include "profiler/TracyConfig.hpp"
#include "profiler/TracyImGui.hpp"

#include "Backend.hpp"
#include "RunQueue.hpp"

#ifdef __APPLE__
#include <objc/objc.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include "icon.hpp"
#endif


static GLFWwindow* s_window;
static std::function<void()> s_redraw;
static std::function<void(float)> s_scaleChanged;
static RunQueue* s_mainThreadTasks;
static WindowPosition* s_winPos;
static bool s_iconified;
static float s_prevScale = -1;

#ifdef __APPLE__
typedef long NSInteger;
typedef unsigned long NSUInteger;

namespace
{

static void EnsureMacAppRegistration()
{
    static bool initialized = false;
    if( initialized ) return;
    initialized = true;

    id pool = ((id (*)(Class, SEL))objc_msgSend)((Class)objc_getClass("NSAutoreleasePool"), sel_getUid("alloc"));
    pool = ((id (*)(id, SEL))objc_msgSend)(pool, sel_getUid("init"));

    id app = ((id (*)(Class, SEL))objc_msgSend)((Class)objc_getClass("NSApplication"), sel_getUid("sharedApplication"));
    ((void (*)(id, SEL, NSInteger))objc_msgSend)(app, sel_getUid("setActivationPolicy:"), (NSInteger)0);
    ((void (*)(id, SEL, BOOL))objc_msgSend)(app, sel_getUid("activateIgnoringOtherApps:"), (BOOL)1);

    ((void (*)(id, SEL))objc_msgSend)(pool, sel_getUid("release"));
}

static void SetMacAppIcon()
{
    id pool = ((id (*)(Class, SEL))objc_msgSend)((Class)objc_getClass("NSAutoreleasePool"), sel_getUid("alloc"));
    pool = ((id (*)(id, SEL))objc_msgSend)(pool, sel_getUid("init"));

    id data = ((id (*)(Class, SEL, const void*, NSUInteger))objc_msgSend)((Class)objc_getClass("NSData"), sel_getUid("dataWithBytes:length:"), (const void*)Icon_data, (NSUInteger)Icon_size);
    id image = ((id (*)(Class, SEL))objc_msgSend)((Class)objc_getClass("NSImage"), sel_getUid("alloc"));
    image = ((id (*)(id, SEL, id))objc_msgSend)(image, sel_getUid("initWithData:"), data);
    if( image )
    {
        id app = ((id (*)(Class, SEL))objc_msgSend)((Class)objc_getClass("NSApplication"), sel_getUid("sharedApplication"));
        ((void (*)(id, SEL, id))objc_msgSend)(app, sel_getUid("setApplicationIconImage:"), image);
        ((void (*)(id, SEL))objc_msgSend)(image, sel_getUid("release"));
    }

    ((void (*)(id, SEL))objc_msgSend)(pool, sel_getUid("release"));
}

}
#endif


static void glfw_error_callback( int error, const char* description )
{
    fprintf(stderr, "Error %d: %s\n", error, description);
}

static void glfw_window_pos_callback( GLFWwindow* window, int x, int y )
{
    if( !glfwGetWindowAttrib( window, GLFW_MAXIMIZED ) )
    {
        s_winPos->x = x;
        s_winPos->y = y;
    }
}

static void glfw_window_size_callback( GLFWwindow* window, int w, int h )
{
    if( !glfwGetWindowAttrib( window, GLFW_MAXIMIZED ) )
    {
        s_winPos->w = w;
        s_winPos->h = h;
    }
    tracy::s_wasActive = true;
}

static void glfw_window_maximize_callback( GLFWwindow*, int maximized )
{
    s_winPos->maximize = maximized;
}

static void glfw_window_iconify_callback( GLFWwindow*, int iconified )
{
    s_iconified = iconified != 0;
}


Backend::Backend( const char* title, const std::function<void()>& redraw, const std::function<void(float)>& scaleChanged, const std::function<int(void)>& isBusy, RunQueue* mainThreadTasks )
{
    glfwSetErrorCallback( glfw_error_callback );
    if( !glfwInit() ) exit( 1 );
#ifdef DISPLAY_SERVER_WAYLAND
    glfwWindowHint( GLFW_ALPHA_BITS, 0 );
#else
    glfwWindowHint( GLFW_VISIBLE, 0 );
#endif
    glfwWindowHint( GLFW_CONTEXT_VERSION_MAJOR, 3 );
    glfwWindowHint( GLFW_CONTEXT_VERSION_MINOR, 2 );
    glfwWindowHint( GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE );
#ifdef __APPLE__
    glfwWindowHint( GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE );
#endif
#ifdef WIN32
#  if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 4 )
    glfwWindowHint( GLFW_WIN32_KEYBOARD_MENU, 1 );
#  endif
#  if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    glfwWindowHint( GLFW_SCALE_TO_MONITOR, 1 );
#  endif
#endif
    s_window = glfwCreateWindow( m_winPos.w, m_winPos.h, title, NULL, NULL );
    if( !s_window ) exit( 1 );

    glfwSetWindowPos( s_window, m_winPos.x, m_winPos.y );
#if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 2 )
    if( m_winPos.maximize ) glfwMaximizeWindow( s_window );
#endif

    glfwMakeContextCurrent( s_window );
    glfwSwapInterval( 1 ); // Enable vsync
    glfwSetWindowRefreshCallback( s_window, []( GLFWwindow* ) { tracy::s_wasActive = true; s_redraw(); } );

    ImGui_ImplGlfw_InitForOpenGL( s_window, true );
    ImGui_ImplOpenGL3_Init( "#version 150" );

    s_redraw = redraw;
    s_scaleChanged = scaleChanged;
    s_mainThreadTasks = mainThreadTasks;
    s_winPos = &m_winPos;
    s_iconified = false;

    glfwSetWindowPosCallback( s_window, glfw_window_pos_callback );
    glfwSetWindowSizeCallback( s_window, glfw_window_size_callback );
#if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    glfwSetWindowMaximizeCallback( s_window, glfw_window_maximize_callback );
#endif
    glfwSetWindowIconifyCallback( s_window, glfw_window_iconify_callback );

#ifdef __APPLE__
    EnsureMacAppRegistration();
#endif
}

Backend::~Backend()
{
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();

    glfwDestroyWindow( s_window );

    glfwTerminate();
}

void Backend::Show()
{
    glfwShowWindow( s_window );
}

void Backend::Run()
{
    while( !glfwWindowShouldClose( s_window ) )
    {
        if( s_iconified )
        {
            glfwWaitEvents();
        }
        else
        {
            glfwPollEvents();
            s_redraw();
            if( tracy::s_config.focusLostLimit && !glfwGetWindowAttrib( s_window, GLFW_FOCUSED ) ) std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
            s_mainThreadTasks->Run();
        }
    }
}

void Backend::Attention()
{
#if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    if( !glfwGetWindowAttrib( s_window, GLFW_FOCUSED ) )
    {
        glfwRequestWindowAttention( s_window );
    }
#endif
}

void Backend::NewFrame( int& w, int& h )
{
    const auto scale = GetDpiScale();
    if( scale != s_prevScale )
    {
        s_prevScale = scale;
        s_scaleChanged( scale );
    }

    glfwGetFramebufferSize( s_window, &w, &h );
#if defined( __APPLE__ )
    w = static_cast<int>( w / scale );
    h = static_cast<int>( h / scale );
#endif
    m_w = w;
    m_h = h;

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
}

void Backend::EndFrame()
{
    const ImVec4 clear_color = ImColor( 20, 20, 17 );

    ImGui::Render();
    glViewport( 0, 0, m_w, m_h );
    glClearColor( clear_color.x, clear_color.y, clear_color.z, clear_color.w );
    glClear( GL_COLOR_BUFFER_BIT );
    ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData() );

    glfwSwapBuffers( s_window );
}

void Backend::SetIcon( uint8_t* data, int w, int h )
{
#ifdef __APPLE__
    EnsureMacAppRegistration();
    SetMacAppIcon();
#else
    GLFWimage icon;
    icon.width = w;
    icon.height = h;
    icon.pixels = data;
    glfwSetWindowIcon( s_window, 1, &icon );
#endif
}

void Backend::SetTitle( const char* title )
{
    glfwSetWindowTitle( s_window, title );
}

float Backend::GetDpiScale()
{
#if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    float x, y;
    glfwGetWindowContentScale( s_window, &x, &y );
    return x;
#else
    return 1;
#endif
}
