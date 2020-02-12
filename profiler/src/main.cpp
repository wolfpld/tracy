#include <algorithm>
#include <assert.h>
#include <chrono>
#include <inttypes.h>
#include <imgui.h>
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <mutex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <GL/gl3w.h>
#include <GLFW/glfw3.h>
#include <memory>
#include "../nfd/nfd.h"
#include <sys/stat.h>
#include <locale.h>

#ifdef _WIN32
#  include <windows.h>
#  include <shellapi.h>
#endif

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#include "stb_image.h"

#include "../../common/TracyProtocol.hpp"
#include "../../server/tracy_pdqsort.h"
#include "../../server/tracy_robin_hood.h"
#include "../../server/TracyBadVersion.hpp"
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyImGui.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyStorage.hpp"
#include "../../server/TracyView.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../server/TracyVersion.hpp"
#include "../../server/IconsFontAwesome5.h"

#include "imgui_freetype.h"
#include "Arimo.hpp"
#include "Cousine.hpp"
#include "FontAwesomeSolid.hpp"
#include "icon.hpp"
#include "ResolvService.hpp"

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "Error %d: %s\n", error, description);
}

static void OpenWebpage( const char* url )
{
#ifdef _WIN32
    ShellExecuteA( nullptr, nullptr, url, nullptr, nullptr, 0 );
#elif defined __APPLE__
    char buf[1024];
    sprintf( buf, "open %s", url );
    system( buf );
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

static void DrawContents();
static void WindowRefreshCallback( GLFWwindow* window )
{
    DrawContents();
}

std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> RebuildConnectionHistory( const std::unordered_map<std::string, uint64_t>& connHistMap )
{
    std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> ret;
    ret.reserve( connHistMap.size() );
    for( auto it = connHistMap.begin(); it != connHistMap.end(); ++it )
    {
        ret.emplace_back( it );
    }
    tracy::pdqsort_branchless( ret.begin(), ret.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second > rhs->second; } );
    return ret;
}

struct ClientData
{
    int64_t time;
    uint32_t protocolVersion;
    uint32_t activeTime;
    std::string procName;
    std::string address;
};

enum class ViewShutdown { False, True, Join };

static tracy::unordered_flat_map<uint32_t, ClientData> clients;
static std::unique_ptr<tracy::View> view;
static tracy::BadVersionState badVer;
static int port = 8086;
static const char* connectTo = nullptr;
static char title[128];
static std::thread loadThread;
static std::unique_ptr<tracy::UdpListen> broadcastListen;
static std::mutex resolvLock;
static tracy::unordered_flat_map<std::string, std::string> resolvMap;
static ResolvService resolv( port );
static ImFont* bigFont;
static ImFont* smallFont;
static ImFont* fixedWidth;
static char addr[1024] = { "127.0.0.1" };
static std::unordered_map<std::string, uint64_t> connHistMap;
static std::vector<std::unordered_map<std::string, uint64_t>::const_iterator> connHistVec;
static ViewShutdown viewShutdown = ViewShutdown::False;
static double animTime = 0;
static float dpiScale = 1.f;

int main( int argc, char** argv )
{
    if( argc == 2 )
    {
        auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( argv[1] ) );
        if( f )
        {
            view = std::make_unique<tracy::View>( *f );
        }
    }
    else
    {
        while( argc >= 3 )
        {
            if( strcmp( argv[1], "-a" ) == 0 )
            {
                connectTo = argv[2];
            }
            else if( strcmp( argv[1], "-p" ) == 0 )
            {
                port = atoi( argv[2] );
            }
            else
            {
                fprintf( stderr, "Bad parameter: %s", argv[1] );
                exit( 1 );
            }
            argc -= 2;
            argv += 2;
        }
    }
    if( connectTo )
    {
        view = std::make_unique<tracy::View>( connectTo, port );
    }

    sprintf( title, "Tracy Profiler %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );

    std::string winPosFile = tracy::GetSavePath( "window.position" );
    int x = 200, y = 200, w = 1650, h = 960, maximize = 0;
    {
        FILE* f = fopen( winPosFile.c_str(), "rb" );
        if( f )
        {
            uint32_t data[5];
            fread( data, 1, sizeof( data ), f );
            fclose( f );
            x = data[0];
            y = data[1];
            w = data[2];
            h = data[3];
            maximize = data[4];
        }
        if( w <= 0 || h <= 0 )
        {
            x = 200;
            y = 200;
            w = 1650;
            h = 960;
            maximize = 0;
        }
    }

    std::string connHistFile = tracy::GetSavePath( "connection.history" );
    {
        FILE* f = fopen( connHistFile.c_str(), "rb" );
        if( f )
        {
            uint64_t sz;
            fread( &sz, 1, sizeof( sz ), f );
            for( uint64_t i=0; i<sz; i++ )
            {
                uint64_t ssz, cnt;
                fread( &ssz, 1, sizeof( ssz ), f );
                assert( ssz < 1024 );
                char tmp[1024];
                fread( tmp, 1, ssz, f );
                fread( &cnt, 1, sizeof( cnt ), f );
                connHistMap.emplace( std::string( tmp, tmp+ssz ), cnt );
            }
            fclose( f );
            connHistVec = RebuildConnectionHistory( connHistMap );
        }
    }

    // Setup window
    glfwSetErrorCallback(glfw_error_callback);
    if( !glfwInit() ) return 1;
    glfwWindowHint(GLFW_VISIBLE, 0);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
#if __APPLE__
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#endif
    GLFWwindow* window = glfwCreateWindow( w, h, title, NULL, NULL);
    if( !window ) return 1;

    {
        GLFWimage icon;
        icon.pixels = stbi_load_from_memory( (const stbi_uc*)Icon_data, Icon_size, &icon.width, &icon.height, nullptr, 4 );
        glfwSetWindowIcon( window, 1, &icon );
        free( icon.pixels );
    }

    glfwSetWindowPos( window, x, y );
#ifdef GLFW_MAXIMIZED
    if( maximize ) glfwMaximizeWindow( window );
#endif
    s_glfwWindow = window;
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync
    gl3wInit();
    glfwSetWindowRefreshCallback( window, WindowRefreshCallback );

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
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    std::string iniFileName = tracy::GetSavePath( "imgui.ini" );
    io.IniFilename = iniFileName.c_str();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui_ImplGlfw_InitForOpenGL( window, true );
    ImGui_ImplOpenGL3_Init( "#version 150" );

    static const ImWchar rangesBasic[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x03BC, 0x03BC, // micro
        0x03C3, 0x03C3, // small sigma
        0,
    };
    static const ImWchar rangesIcons[] = {
        ICON_MIN_FA, ICON_MAX_FA,
        0
    };
    ImFontConfig configMerge;
    configMerge.MergeMode = true;

    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::Arimo_compressed_data, tracy::Arimo_compressed_size, 15.0f * dpiScale, nullptr, rangesBasic );
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FontAwesomeSolid_compressed_data, tracy::FontAwesomeSolid_compressed_size, 14.0f * dpiScale, &configMerge, rangesIcons );
    fixedWidth = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::Cousine_compressed_data, tracy::Cousine_compressed_size, 15.0f * dpiScale );
    bigFont = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::Arimo_compressed_data, tracy::Cousine_compressed_size, 20.0f * dpiScale );
    smallFont = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::Arimo_compressed_data, tracy::Cousine_compressed_size, 10.0f * dpiScale );

    ImGuiFreeType::BuildFontAtlas( io.Fonts, ImGuiFreeType::LightHinting );

    ImGui::StyleColorsDark();
    auto& style = ImGui::GetStyle();
    style.WindowBorderSize = 1.f * dpiScale;
    style.FrameBorderSize = 1.f * dpiScale;
    style.FrameRounding = 5.f;
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4( 1, 1, 1, 0.03f );
    style.ScaleAllSizes( dpiScale );

    glfwShowWindow( window );

    // Main loop
    while (!glfwWindowShouldClose(window))
    {
        glfwPollEvents();
        if( glfwGetWindowAttrib( window, GLFW_ICONIFIED ) )
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
            continue;
        }
        DrawContents();
        if( !glfwGetWindowAttrib( window, GLFW_FOCUSED ) )
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 50 ) );
        }
    }

    {
        FILE* f = fopen( winPosFile.c_str(), "wb" );
        if( f )
        {
#ifdef GLFW_MAXIMIZED
            uint32_t maximized = glfwGetWindowAttrib( window, GLFW_MAXIMIZED );
            if( maximized ) glfwRestoreWindow( window );
#else
            uint32_t maximized = 0;
#endif

            glfwGetWindowPos( window, &x, &y );
            glfwGetWindowSize( window, &w, &h );

            uint32_t data[5] = { uint32_t( x ), uint32_t( y ), uint32_t( w ), uint32_t( h ), maximized };
            fwrite( data, 1, sizeof( data ), f );
            fclose( f );
        }
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();

    {
        FILE* f = fopen( connHistFile.c_str(), "wb" );
        if( f )
        {
            uint64_t sz = uint64_t( connHistMap.size() );
            fwrite( &sz, 1, sizeof( uint64_t ), f );
            for( auto& v : connHistMap )
            {
                sz = uint64_t( v.first.size() );
                fwrite( &sz, 1, sizeof( uint64_t ), f );
                fwrite( v.first.c_str(), 1, sz, f );
                fwrite( &v.second, 1, sizeof( v.second ), f );
            }
            fclose( f );
        }
    }

    return 0;
}

static void DrawContents()
{
    const ImVec4 clear_color = ImColor( 114, 144, 154 );

    int display_w, display_h;
    glfwGetFramebufferSize(s_glfwWindow, &display_w, &display_h);

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    if( !view )
    {
        if( s_customTitle )
        {
            s_customTitle = false;
            glfwSetWindowTitle( s_glfwWindow, title );
        }

        const auto time = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count();
        if( !broadcastListen )
        {
            broadcastListen = std::make_unique<tracy::UdpListen>();
            if( !broadcastListen->Listen( port ) )
            {
                broadcastListen.reset();
            }
        }
        else
        {
            tracy::IpAddress addr;
            size_t len;
            auto msg = broadcastListen->Read( len, addr );
            if( msg )
            {
                assert( len <= sizeof( tracy::BroadcastMessage ) );
                tracy::BroadcastMessage bm;
                memcpy( &bm, msg, len );

                if( bm.broadcastVersion == tracy::BroadcastVersion )
                {
                    const uint32_t protoVer = bm.protocolVersion;
                    const auto procname = bm.programName;
                    const auto activeTime = bm.activeTime;
                    auto address = addr.GetText();

                    const auto ipNumerical = addr.GetNumber();
                    auto it = clients.find( ipNumerical );
                    if( it == clients.end() )
                    {
                        std::string ip( address );
                        resolvLock.lock();
                        if( resolvMap.find( ip ) == resolvMap.end() )
                        {
                            resolvMap.emplace( ip, ip );
                            resolv.Query( ipNumerical, [ip] ( std::string&& name ) {
                                std::lock_guard<std::mutex> lock( resolvLock );
                                auto it = resolvMap.find( ip );
                                assert( it != resolvMap.end() );
                                std::swap( it->second, name );
                                } );
                        }
                        resolvLock.unlock();
                        clients.emplace( addr.GetNumber(), ClientData { time, protoVer, activeTime, procname, std::move( ip ) } );
                    }
                    else
                    {
                        it->second.time = time;
                        it->second.activeTime = activeTime;
                        if( it->second.protocolVersion != protoVer ) it->second.protocolVersion = protoVer;
                        if( strcmp( it->second.procName.c_str(), procname ) != 0 ) it->second.procName = procname;
                    }
                }
            }
            auto it = clients.begin();
            while( it != clients.end() )
            {
                const auto diff = time - it->second.time;
                if( diff > 4000 )  // 4s
                {
                    it = clients.erase( it );
                }
                else
                {
                    ++it;
                }
            }
        }

        setlocale( LC_NUMERIC, "C" );
        auto& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.129f, 0.137f, 0.11f, 1.f );
        ImGui::Begin( "Get started", nullptr, ImGuiWindowFlags_AlwaysAutoResize );
        char buf[128];
        sprintf( buf, "Tracy Profiler %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
        ImGui::PushFont( bigFont );
        tracy::TextCentered( buf );
        ImGui::PopFont();
        ImGui::Spacing();
        if( ImGui::Button( ICON_FA_BOOK " Manual" ) )
        {
            OpenWebpage( "https://bitbucket.org/wolfpld/tracy/downloads/tracy.pdf" );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_GLOBE_AMERICAS " Web" ) )
        {
            OpenWebpage( "https://bitbucket.org/wolfpld/tracy" );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_COMMENT " Chat" ) )
        {
            OpenWebpage( "https://discord.gg/pk78auc" );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_VIDEO " Tutorial" ) )
        {
            ImGui::OpenPopup( "tutorial" );
        }
        if( ImGui::BeginPopup( "tutorial" ) )
        {
            if( ImGui::Selectable( ICON_FA_VIDEO " Introduction to the Tracy Profiler" ) )
            {
                OpenWebpage( "https://www.youtube.com/watch?v=fB5B46lbapc" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in Tracy Profiler v0.3" ) )
            {
                OpenWebpage( "https://www.youtube.com/watch?v=3SXpDpDh2Uo" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in Tracy Profiler v0.4" ) )
            {
                OpenWebpage( "https://www.youtube.com/watch?v=eAkgkaO8B9o" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in Tracy Profiler v0.5" ) )
            {
                OpenWebpage( "https://www.youtube.com/watch?v=P6E7qLMmzTQ" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in Tracy Profiler v0.6" ) )
            {
                OpenWebpage( "https://www.youtube.com/watch?v=uJkrFgriuOo" );
            }
            ImGui::EndPopup();
        }
        ImGui::Separator();
        ImGui::TextUnformatted( "Client address" );
        bool connectClicked = false;
        connectClicked |= ImGui::InputTextWithHint( "###connectaddress", "Enter address", addr, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
        if( !connHistVec.empty() )
        {
            ImGui::SameLine();
            if( ImGui::BeginCombo( "##frameCombo", nullptr, ImGuiComboFlags_NoPreview ) )
            {
                int idxRemove = -1;
                const auto sz = std::min<size_t>( 5, connHistVec.size() );
                for( size_t i=0; i<sz; i++ )
                {
                    const auto& str = connHistVec[i]->first;
                    if( ImGui::Selectable( str.c_str() ) )
                    {
                        memcpy( addr, str.c_str(), str.size() + 1 );
                    }
                    if( ImGui::IsItemHovered() && ImGui::IsKeyPressed( ImGui::GetKeyIndex( ImGuiKey_Delete ), false ) )
                    {
                        idxRemove = (int)i;
                    }
                }
                if( idxRemove >= 0 )
                {
                    connHistMap.erase( connHistVec[idxRemove] );
                    connHistVec = RebuildConnectionHistory( connHistMap );
                }
                ImGui::EndCombo();
            }
        }
        connectClicked |= ImGui::Button( ICON_FA_WIFI " Connect" );
        if( connectClicked && *addr && !loadThread.joinable() )
        {
            std::string addrStr( addr );
            auto it = connHistMap.find( addrStr );
            if( it != connHistMap.end() )
            {
                it->second++;
            }
            else
            {
                connHistMap.emplace( std::move( addrStr ), 1 );
            }
            connHistVec = RebuildConnectionHistory( connHistMap );

            view = std::make_unique<tracy::View>( addr, port, fixedWidth, smallFont, bigFont, SetWindowTitleCallback );
        }
        ImGui::SameLine( 0, ImGui::GetFontSize() * 2 );
        if( ImGui::Button( ICON_FA_FOLDER_OPEN " Open saved trace" ) && !loadThread.joinable() )
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
                        loadThread = std::thread( [f] {
                            try
                            {
                                view = std::make_unique<tracy::View>( *f, fixedWidth, smallFont, bigFont, SetWindowTitleCallback );
                            }
                            catch( const tracy::UnsupportedVersion& e )
                            {
                                badVer.state = tracy::BadVersionState::UnsupportedVersion;
                                badVer.version = e.version;
                            }
                            catch( const tracy::LegacyVersion& e )
                            {
                                badVer.state = tracy::BadVersionState::LegacyVersion;
                                badVer.version = e.version;
                            }
                            } );
                    }
                }
                catch( const tracy::NotTracyDump& )
                {
                    badVer.state = tracy::BadVersionState::BadFile;
                }
                catch( const tracy::FileReadError& )
                {
                    badVer.state = tracy::BadVersionState::ReadError;
                }
            }
        }

        if( badVer.state != tracy::BadVersionState::Ok )
        {
            if( loadThread.joinable() ) { loadThread.join(); }
            tracy::BadVersion( badVer );
        }

        if( !clients.empty() )
        {
            ImGui::Separator();
            ImGui::TextUnformatted( "Discovered clients:" );
            ImGui::Separator();
            static bool widthSet = false;
            ImGui::Columns( 3 );
            if( !widthSet )
            {
                widthSet = true;
                const auto w = ImGui::GetWindowWidth();
                ImGui::SetColumnWidth( 0, w * 0.35f );
                ImGui::SetColumnWidth( 1, w * 0.175f );
                ImGui::SetColumnWidth( 2, w * 0.425f );
            }
            std::lock_guard<std::mutex> lock( resolvLock );
            for( auto& v : clients )
            {
                const bool badProto = v.second.protocolVersion != tracy::ProtocolVersion;
                bool sel = false;
                const auto& name = resolvMap.find( v.second.address );
                assert( name != resolvMap.end() );
                ImGuiSelectableFlags flags = ImGuiSelectableFlags_SpanAllColumns;
                if( badProto ) flags |= ImGuiSelectableFlags_Disabled;
                if( ImGui::Selectable( name->second.c_str(), &sel, flags ) && !loadThread.joinable() )
                {
                    view = std::make_unique<tracy::View>( v.second.address.c_str(), port, fixedWidth, smallFont, bigFont, SetWindowTitleCallback );
                }
                ImGui::NextColumn();
                const auto acttime = ( v.second.activeTime + ( time - v.second.time ) / 1000 ) * 1000000000ll;
                if( badProto )
                {
                    tracy::TextDisabledUnformatted( tracy::TimeToString( acttime ) );
                }
                else
                {
                    ImGui::TextUnformatted( tracy::TimeToString( acttime ) );
                }
                ImGui::NextColumn();
                if( badProto )
                {
                    tracy::TextDisabledUnformatted( v.second.procName.c_str() );
                }
                else
                {
                    ImGui::TextUnformatted( v.second.procName.c_str() );
                }
                ImGui::NextColumn();
            }
            ImGui::EndColumns();
        }

        ImGui::End();
    }
    else
    {
        if( broadcastListen )
        {
            broadcastListen.reset();
            clients.clear();
        }
        if( loadThread.joinable() ) loadThread.join();
        view->NotifyRootWindowSize( display_w, display_h );
        if( !view->Draw() )
        {
            viewShutdown = ViewShutdown::True;
            loadThread = std::thread( [view = std::move( view )] () mutable {
                view.reset();
                viewShutdown = ViewShutdown::Join;
            } );
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
        tracy::TextCentered( ICON_FA_HOURGLASS_HALF );

        animTime += ImGui::GetIO().DeltaTime;
        tracy::DrawWaitingDots( animTime );

        auto currProgress = progress.progress.load( std::memory_order_relaxed );
        if( totalProgress == 0 )
        {
            ImGui::CloseCurrentPopup();
            totalProgress = currProgress;
        }
        switch( currProgress )
        {
        case tracy::LoadProgress::Initialization:
            ImGui::TextUnformatted( "Initialization..." );
            break;
        case tracy::LoadProgress::Locks:
            ImGui::TextUnformatted( "Locks..." );
            break;
        case tracy::LoadProgress::Messages:
            ImGui::TextUnformatted( "Messages..." );
            break;
        case tracy::LoadProgress::Zones:
            ImGui::TextUnformatted( "CPU zones..." );
            break;
        case tracy::LoadProgress::GpuZones:
            ImGui::TextUnformatted( "GPU zones..." );
            break;
        case tracy::LoadProgress::Plots:
            ImGui::TextUnformatted( "Plots..." );
            break;
        case tracy::LoadProgress::Memory:
            ImGui::TextUnformatted( "Memory..." );
            break;
        case tracy::LoadProgress::CallStacks:
            ImGui::TextUnformatted( "Call stacks..." );
            break;
        case tracy::LoadProgress::FrameImages:
            ImGui::TextUnformatted( "Frame images..." );
            break;
        case tracy::LoadProgress::ContextSwitches:
            ImGui::TextUnformatted( "Context switches..." );
            break;
        case tracy::LoadProgress::ContextSwitchesPerCpu:
            ImGui::TextUnformatted( "CPU context switches..." );
            break;
        default:
            assert( false );
            break;
        }
        ImGui::ProgressBar( float( currProgress ) / totalProgress, ImVec2( 200 * dpiScale, 0 ) );

        ImGui::TextUnformatted( "Progress..." );
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
    switch( viewShutdown )
    {
    case ViewShutdown::True:
        ImGui::OpenPopup( "Capture cleanup..." );
        break;
    case ViewShutdown::Join:
        loadThread.join();
        viewShutdown = ViewShutdown::False;
        break;
    default:
        break;
    }
    if( ImGui::BeginPopupModal( "Capture cleanup...", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        if( viewShutdown != ViewShutdown::True ) ImGui::CloseCurrentPopup();
        tracy::TextCentered( ICON_FA_BROOM );
        animTime += ImGui::GetIO().DeltaTime;
        tracy::DrawWaitingDots( animTime );
        ImGui::Text( "Please wait, cleanup is in progress" );
        ImGui::EndPopup();
    }

    // Rendering
    ImGui::Render();
    glfwMakeContextCurrent(s_glfwWindow);
    glViewport(0, 0, display_w, display_h);
    glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    glfwMakeContextCurrent(s_glfwWindow);
    glfwSwapBuffers(s_glfwWindow);
}
