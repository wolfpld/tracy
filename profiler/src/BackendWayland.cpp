#include <EGL/egl.h>    // must be here to avoid redefinition of khronos_int64_t

#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_opengl3_loader.h"

#include <functional>
#include <memory>

#include "Backend.hpp"
#include "RunQueue.hpp"
#include "WaylandDisplay.hpp"
#include "WaylandWindow.hpp"

namespace
{
    std::function<void()> s_redraw;
    RunQueue* s_mainThreadTasks;

    int32_t s_scale = 1;

    bool s_running = true;
    uint64_t s_time;

    std::unique_ptr<WaylandDisplay> s_display;
    std::unique_ptr<WaylandWindow> s_window;
}

Backend::Backend( const char* title, const std::function<void()>& redraw, RunQueue* mainThreadTasks )
{
    s_redraw = redraw;
    s_mainThreadTasks = mainThreadTasks;

    s_display = std::make_unique<WaylandDisplay>( s_scale, []( wl_pointer* pointer, uint32_t serial ) {
        int32_t x, y;
        auto surface = s_window->GetCursor( x, y );
        wl_pointer_set_cursor( pointer, serial, surface, x, y );
    } );
    s_window = std::make_unique<WaylandWindow>( WaylandWindowParams {
        .display = *s_display,
        .title = title,
        .winPos = m_winPos,
        .running = s_running,
        .scale = s_scale,
    } );

    ImGui_ImplOpenGL3_Init( "#version 150" );

    ImGuiIO& io = ImGui::GetIO();
    io.BackendPlatformName = "wayland (tracy profiler)";
    s_time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

Backend::~Backend()
{
    ImGui_ImplOpenGL3_Shutdown();

    s_window.reset();
    s_display.reset();
}

void Backend::Show()
{
    s_window->Show();
}

void Backend::Run()
{
    while( s_running && wl_display_dispatch( s_display->GetDisplay() ) != -1 )
    {
        s_mainThreadTasks->Run();
        s_redraw();
    }
}

void Backend::Attention()
{
    s_window->Attention();
}

void Backend::NewFrame( int& w, int& h )
{
    s_window->NewFrame();
    w = s_window->Width();
    h = s_window->Height();

    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2( w, h );
    io.DisplayFramebufferScale = ImVec2( 1, 1 );

    ImGui_ImplOpenGL3_NewFrame();

    uint64_t time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
    io.DeltaTime = std::min( 0.1f, ( time - s_time ) / 1000000.f );
    s_time = time;
}

void Backend::EndFrame()
{
    const ImVec4 clear_color = ImColor( 114, 144, 154 );

    ImGui::Render();
    glViewport( 0, 0, s_window->Width(), s_window->Height() );
    glClearColor( clear_color.x, clear_color.y, clear_color.z, clear_color.w );
    glClear( GL_COLOR_BUFFER_BIT );
    ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData() );

    s_window->Present();
}

void Backend::SetIcon( uint8_t* data, int w, int h )
{
}

void Backend::SetTitle( const char* title )
{
    s_window->SetTitle( title );
}

float Backend::GetDpiScale()
{
    return s_scale;
}
