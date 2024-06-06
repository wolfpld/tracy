#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
#ifdef __EMSCRIPTEN__
#  include <GLES2/gl2.h>
#  include <emscripten/html5.h>
#else
#  include "imgui/imgui_impl_opengl3_loader.h"
#endif

#include <chrono>
#include <GLFW/glfw3.h>
#include <stdio.h>
#include <stdlib.h>
#include <thread>

#include "profiler/TracyConfig.hpp"
#include "profiler/TracyImGui.hpp"

#include "Backend.hpp"
#include "RunQueue.hpp"


static GLFWwindow* s_window;
static std::function<void()> s_redraw;
static RunQueue* s_mainThreadTasks;
static WindowPosition* s_winPos;
static bool s_iconified;

extern tracy::Config s_config;


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
#ifdef __EMSCRIPTEN__
    ImGui_ImplOpenGL3_Init( "#version 100" );
#else
    ImGui_ImplOpenGL3_Init( "#version 150" );
#endif

    s_redraw = redraw;
    s_mainThreadTasks = mainThreadTasks;
    s_winPos = &m_winPos;
    s_iconified = false;

    glfwSetWindowPosCallback( s_window, glfw_window_pos_callback );
    glfwSetWindowSizeCallback( s_window, glfw_window_size_callback );
#if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    glfwSetWindowMaximizeCallback( s_window, glfw_window_maximize_callback );
#endif
    glfwSetWindowIconifyCallback( s_window, glfw_window_iconify_callback );
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
#ifdef __EMSCRIPTEN__
    emscripten_set_main_loop( []() {
        glfwPollEvents();
        s_redraw();
        s_mainThreadTasks->Run();
    }, 0, 1 );
#else
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
            if( s_config.focusLostLimit && !glfwGetWindowAttrib( s_window, GLFW_FOCUSED ) ) std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
            s_mainThreadTasks->Run();
        }
    }
#endif
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
    glfwGetFramebufferSize( s_window, &w, &h );
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
    GLFWimage icon;
    icon.width = w;
    icon.height = h;
    icon.pixels = data;
    glfwSetWindowIcon( s_window, 1, &icon );
}

void Backend::SetTitle( const char* title )
{
    glfwSetWindowTitle( s_window, title );
}

float Backend::GetDpiScale()
{
#ifdef __EMSCRIPTEN__
    return EM_ASM_DOUBLE( { return window.devicePixelRatio; } );
#elif GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    auto monitor = glfwGetWindowMonitor( s_window );
    if( !monitor ) monitor = glfwGetPrimaryMonitor();
    if( monitor )
    {
        float x, y;
        glfwGetMonitorContentScale( monitor, &x, &y );
        return x;
    }
#endif
    return 1;
}

#ifdef __EMSCRIPTEN__
extern "C" int nativeResize( int width, int height )
{
    glfwSetWindowSize( s_window, width, height );
    return 0;
}
#endif
