#include <assert.h>
#include <inttypes.h>
#include <imgui.h>
#include "imgui_impl_glfw_gl3.h"
#include <stdio.h>
#include <stdlib.h>
#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <memory>
#include "../nfd/nfd.h"
#include <sys/stat.h>

#ifdef _WIN32
#  include <windows.h>
#  include <shellapi.h>
#endif

#include "../../server/TracyBadVersion.hpp"
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyView.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../server/TracyVersion.hpp"


#include "Arimo.hpp"

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "Error %d: %s\n", error, description);
}

static void OpenWebpage( const char* url )
{
#ifdef _WIN32
    ShellExecuteA( nullptr, nullptr, url, nullptr, nullptr, 0 );
#else
    char buf[1024];
    sprintf( buf, "xdg-open %s", url );
    system( buf );
#endif
}

static GLFWwindow* s_glfwWindow = nullptr;
static bool s_customTitle = false;
static void SetWindowTitleCallback( const char* title )
{
    assert( s_glfwWindow );
    glfwSetWindowTitle( s_glfwWindow, title );
    s_customTitle = true;
}

int main( int argc, char** argv )
{
    std::unique_ptr<tracy::View> view;
    int badVer = 0;

    if( argc == 2 )
    {
        auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( argv[1] ) );
        if( f )
        {
            view = std::make_unique<tracy::View>( *f );
        }
    }

    char title[128];
    sprintf( title, "Tracy server %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );

    // Setup window
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit())
        return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#if __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif
    GLFWwindow* window = glfwCreateWindow(1650, 960, title, NULL, NULL);
    s_glfwWindow = window;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync
    gl3wInit();

    float dpiScale = 1.f;
#ifdef _WIN32
    typedef UINT(*GDFS)(void);
    GDFS getDpiForSystem = nullptr;
    HMODULE dll = GetModuleHandleW(L"user32.dll");
    if (dll != INVALID_HANDLE_VALUE)
        getDpiForSystem = (GDFS)GetProcAddress(dll, "GetDpiForSystem");
    if (getDpiForSystem)
        dpiScale = getDpiForSystem() / 96.f;
#endif

    // Setup ImGui binding
    ImGui::CreateContext();
    ImGui_ImplGlfwGL3_Init(window, true);

    static const ImWchar ranges[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x03BC, 0x03BC, // micro
        0,
    };

    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::Arimo_compressed_data, tracy::Arimo_compressed_size, 15.0f * dpiScale, nullptr, ranges );
    auto fixedWidth = io.Fonts->AddFontDefault();

    ImGui::StyleColorsDark();
    auto& style = ImGui::GetStyle();
    style.WindowBorderSize = 1.f;
    style.FrameBorderSize = 1.f;
    style.FrameRounding = 5.f;
    style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.11f, 0.11f, 0.08f, 0.94f );
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4( 1, 1, 1, 0.03f );

    ImVec4 clear_color = ImColor(114, 144, 154);

    char addr[1024] = { "127.0.0.1" };

    std::thread loadThread;

    // Main loop
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();

        if( glfwGetWindowAttrib( window, GLFW_ICONIFIED ) )
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
            continue;
        }

        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);

        ImGui_ImplGlfwGL3_NewFrame();

        if( !view )
        {
            if( s_customTitle )
            {
                s_customTitle = false;
                glfwSetWindowTitle( window, title );
            }

            ImGui::Begin( "Tracy server", nullptr, ImGuiWindowFlags_AlwaysAutoResize );
            ImGui::Text( "Tracy %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
            ImGui::SameLine();
            if( ImGui::SmallButton( "User manual" ) )
            {
                OpenWebpage( "https://bitbucket.org/wolfpld/tracy/downloads/tracy.pdf" );
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Homepage" ) )
            {
                OpenWebpage( "https://bitbucket.org/wolfpld/tracy" );
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Tutorial" ) )
            {
                OpenWebpage( "https://www.youtube.com/watch?v=fB5B46lbapc" );
            }
            ImGui::Separator();
            ImGui::Text( "Connect to client" );
            ImGui::InputText( "Address", addr, 1024 );
            if( ImGui::Button( "Connect" ) && *addr && !loadThread.joinable() )
            {
                view = std::make_unique<tracy::View>( addr, fixedWidth, SetWindowTitleCallback );
            }
            ImGui::Separator();
            if( ImGui::Button( "Open saved trace" ) && !loadThread.joinable() )
            {
                nfdchar_t* fn;
                auto res = NFD_OpenDialog( "tracy", nullptr, &fn );
                if( res == NFD_OKAY )
                {
                    try
                    {
                        auto f = std::shared_ptr<tracy::FileRead>( tracy::FileRead::Open( fn ) );
                        if( f )
                        {
                            loadThread = std::thread( [&view, f, &badVer, fixedWidth] {
                                try
                                {
                                    view = std::make_unique<tracy::View>( *f, fixedWidth, SetWindowTitleCallback );
                                }
                                catch( const tracy::UnsupportedVersion& e )
                                {
                                    badVer = e.version;
                                }
                            } );
                        }
                    }
                    catch( const tracy::NotTracyDump& e )
                    {
                        badVer = -1;
                    }
                }
            }

            if( badVer != 0 )
            {
                if( loadThread.joinable() ) { loadThread.join(); }
                tracy::BadVersion( badVer );
            }

            ImGui::End();
        }
        else
        {
            if( loadThread.joinable() ) loadThread.join();
            view->NotifyRootWindowSize( display_w, display_h );
            if( !view->Draw() )
            {
                view.reset();
            }
        }
        auto& progress = tracy::Worker::GetLoadProgress();
        auto totalProgress = progress.total.load( std::memory_order_relaxed );
        if( totalProgress != 0 )
        {
            ImGui::OpenPopup( "Loading trace..." );
        }
        if( ImGui::BeginPopupModal( "Loading trace...", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
        {
            auto currProgress = progress.progress.load( std::memory_order_relaxed );
            if( totalProgress == 0 )
            {
                ImGui::CloseCurrentPopup();
                totalProgress = currProgress;
            }
            switch( currProgress )
            {
            case tracy::LoadProgress::Initialization:
                ImGui::Text( "Initialization..." );
                break;
            case tracy::LoadProgress::Locks:
                ImGui::Text( "Locks..." );
                break;
            case tracy::LoadProgress::Messages:
                ImGui::Text( "Messages..." );
                break;
            case tracy::LoadProgress::Zones:
                ImGui::Text( "CPU zones..." );
                break;
            case tracy::LoadProgress::GpuZones:
                ImGui::Text( "GPU zones..." );
                break;
            case tracy::LoadProgress::Plots:
                ImGui::Text( "Plots..." );
                break;
            case tracy::LoadProgress::Memory:
                ImGui::Text( "Memory..." );
                break;
            case tracy::LoadProgress::CallStacks:
                ImGui::Text( "Call stacks..." );
                break;
            default:
                assert( false );
                break;
            }
            ImGui::ProgressBar( float( currProgress ) / totalProgress, ImVec2( 200 * dpiScale, 0 ) );

            ImGui::Text( "Progress..." );
            auto subTotal = progress.subTotal.load( std::memory_order_relaxed );
            auto subProgress = progress.subProgress.load( std::memory_order_relaxed );
            if( subTotal == 0 )
            {
                ImGui::ProgressBar( 1.f, ImVec2( 200 * dpiScale, 0 ) );
            }
            else
            {
                ImGui::ProgressBar( float( subProgress ) / subTotal, ImVec2( 200 * dpiScale, 0 ) );
            }
            ImGui::EndPopup();
        }

        // Rendering
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui::Render();
        ImGui_ImplGlfwGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);

        if( !glfwGetWindowAttrib( window, GLFW_FOCUSED ) )
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
        }
    }

    // Cleanup
    ImGui_ImplGlfwGL3_Shutdown();
    ImGui::DestroyContext();
    glfwTerminate();

    return 0;
}

#ifdef _WIN32
#include <stdlib.h>
int WINAPI WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpszCmd, int nCmd )
{
    return main( __argc, __argv );
}
#endif
