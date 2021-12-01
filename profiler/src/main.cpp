#include <algorithm>
#include <assert.h>
#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <imgui.h>
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_opengl3_loader.h"
#include <mutex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <GLFW/glfw3.h>
#include <memory>
#include <sys/stat.h>
#include <locale.h>

#ifndef TRACY_NO_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

#ifdef _WIN32
#  include <windows.h>
#endif

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#include "stb_image.h"

#include "../../common/TracyProtocol.hpp"
#include "../../server/tracy_pdqsort.h"
#include "../../server/tracy_robin_hood.h"
#include "../../server/TracyBadVersion.hpp"
#include "../../server/TracyFileHeader.hpp"
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyImGui.hpp"
#include "../../server/TracyMouse.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyStorage.hpp"
#include "../../server/TracyVersion.hpp"
#include "../../server/TracyView.hpp"
#include "../../server/TracyWeb.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../server/TracyVersion.hpp"
#include "../../server/IconsFontAwesome5.h"

#include "misc/freetype/imgui_freetype.h"
#include "DroidSans.hpp"
#include "FiraCodeRetina.hpp"
#include "FontAwesomeSolid.hpp"
#include "icon.hpp"
#include "ResolvService.hpp"
#include "NativeWindow.hpp"
#include "HttpRequest.hpp"

static void glfw_error_callback(int error, const char* description)
{
    fprintf(stderr, "Error %d: %s\n", error, description);
}

GLFWwindow* s_glfwWindow = nullptr;
static bool s_customTitle = false;
static void SetWindowTitleCallback( const char* title )
{
    assert( s_glfwWindow );
    char tmp[1024];
    sprintf( tmp, "%s - Tracy Profiler %i.%i.%i", title, tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
    glfwSetWindowTitle( s_glfwWindow, tmp );
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
    int32_t activeTime;
    uint16_t port;
    std::string procName;
    std::string address;
};

enum class ViewShutdown { False, True, Join };

static tracy::unordered_flat_map<uint64_t, ClientData> clients;
static std::unique_ptr<tracy::View> view;
static tracy::BadVersionState badVer;
static uint16_t port = 8086;
static const char* connectTo = nullptr;
static char title[128];
static std::thread loadThread, updateThread, updateNotesThread;
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
static std::atomic<ViewShutdown> viewShutdown { ViewShutdown::False };
static double animTime = 0;
static float dpiScale = 1.f;
static ImGuiTextFilter addrFilter, portFilter, progFilter;
static std::thread::id mainThread;
static std::vector<std::function<void()>> mainThreadTasks;
static std::mutex mainThreadLock;
static uint32_t updateVersion = 0;
static bool showReleaseNotes = false;
static std::string releaseNotes;

void RunOnMainThread( std::function<void()> cb, bool forceDelay = false )
{
    if( !forceDelay && std::this_thread::get_id() == mainThread )
    {
        cb();
    }
    else
    {
        std::lock_guard<std::mutex> lock( mainThreadLock );
        mainThreadTasks.emplace_back( cb );
    }
}

static void LoadFonts( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont )
{
    static const ImWchar rangesBasic[] = {
        0x0020, 0x00FF, // Basic Latin + Latin Supplement
        0x03BC, 0x03BC, // micro
        0x03C3, 0x03C3, // small sigma
        0x2013, 0x2013, // en dash
        0x2264, 0x2264, // less-than or equal to
        0,
    };
    static const ImWchar rangesIcons[] = {
        ICON_MIN_FA, ICON_MAX_FA,
        0
    };

    ImGuiIO& io = ImGui::GetIO();

    ImFontConfig configBasic;
    configBasic.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
    ImFontConfig configMerge;
    configMerge.MergeMode = true;
    configMerge.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;

    io.Fonts->Clear();
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::DroidSans_compressed_data, tracy::DroidSans_compressed_size, round( 15.0f * scale ), &configBasic, rangesBasic );
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FontAwesomeSolid_compressed_data, tracy::FontAwesomeSolid_compressed_size, round( 14.0f * scale ), &configMerge, rangesIcons );
    fixedWidth = cb_fixedWidth = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FiraCodeRetina_compressed_data, tracy::FiraCodeRetina_compressed_size, round( 15.0f * scale ), &configBasic );
    bigFont = cb_bigFont = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::DroidSans_compressed_data, tracy::DroidSans_compressed_size, round( 21.0f * scale ), &configBasic );
    io.Fonts->AddFontFromMemoryCompressedTTF( tracy::FontAwesomeSolid_compressed_data, tracy::FontAwesomeSolid_compressed_size, round( 20.0f * scale ), &configMerge, rangesIcons );
    smallFont = cb_smallFont = io.Fonts->AddFontFromMemoryCompressedTTF( tracy::DroidSans_compressed_data, tracy::DroidSans_compressed_size, round( 10.0f * scale ), &configBasic );

    ImGui_ImplOpenGL3_DestroyFontsTexture();
    ImGui_ImplOpenGL3_CreateFontsTexture();
}

static void SetupDPIScale( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont )
{
    LoadFonts( scale, cb_fixedWidth, cb_bigFont, cb_smallFont );

    auto& style = ImGui::GetStyle();
    style = ImGuiStyle();
    ImGui::StyleColorsDark();
    style.WindowBorderSize = 1.f * scale;
    style.FrameBorderSize = 1.f * scale;
    style.FrameRounding = 5.f;
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4( 1, 1, 1, 0.03f );
    style.Colors[ImGuiCol_Header] = ImVec4(0.26f, 0.59f, 0.98f, 0.25f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.59f, 0.98f, 0.35f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.59f, 0.98f, 0.45f);
    style.ScaleAllSizes( scale );
}

static void SetupScaleCallback( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont )
{
    RunOnMainThread( [scale, &cb_fixedWidth, &cb_bigFont, &cb_smallFont] { SetupDPIScale( scale * dpiScale, cb_fixedWidth, cb_bigFont, cb_smallFont ); }, true );
}

int main( int argc, char** argv )
{
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
    std::string filtersFile = tracy::GetSavePath( "client.filters" );
    {
        FILE* f = fopen( filtersFile.c_str(), "rb" );
        if( f )
        {
            uint8_t sz;
            fread( &sz, 1, sizeof( sz ), f );
            fread( addrFilter.InputBuf, 1, sz, f );
            addrFilter.Build();

            fread( &sz, 1, sizeof( sz ), f );
            fread( portFilter.InputBuf, 1, sz, f );
            portFilter.Build();

            fread( &sz, 1, sizeof( sz ), f );
            fread( progFilter.InputBuf, 1, sz, f );
            progFilter.Build();

            fclose( f );
        }
    }

    mainThread = std::this_thread::get_id();

    updateThread = std::thread( [] {
        HttpRequest( "nereid.pl", "/tracy/version", 8099, [] ( int size, char* data ) {
            if( size == 4 )
            {
                uint32_t ver;
                memcpy( &ver, data, 4 );
                RunOnMainThread( [ver] { updateVersion = ver; } );
            }
            delete[] data;
        } );
    } );

    // Setup window
    glfwSetErrorCallback(glfw_error_callback);
    if( !glfwInit() ) return 1;
#ifdef DISPLAY_SERVER_WAYLAND
    glfwWindowHint(GLFW_ALPHA_BITS, 0);
#else
    glfwWindowHint(GLFW_VISIBLE, 0);
#endif
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
    glfwSetWindowRefreshCallback( window, WindowRefreshCallback );

#ifdef _WIN32
    typedef UINT(*GDFS)(void);
    GDFS getDpiForSystem = nullptr;
    HMODULE dll = GetModuleHandleW(L"user32.dll");
    if( dll != INVALID_HANDLE_VALUE ) getDpiForSystem = (GDFS)GetProcAddress(dll, "GetDpiForSystem");
    if( getDpiForSystem ) dpiScale = getDpiForSystem() / 96.f;
#elif defined __linux__
#  if GLFW_VERSION_MAJOR > 3 || ( GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3 )
    auto monitor = glfwGetWindowMonitor( window );
    if( !monitor ) monitor = glfwGetPrimaryMonitor();
    if( monitor )
    {
        float x, y;
        glfwGetMonitorContentScale( monitor, &x, &y );
        dpiScale = x;
    }
#  endif
#endif

    const auto envDpiScale = getenv( "TRACY_DPI_SCALE" );
    if( envDpiScale )
    {
        const auto cnv = atof( envDpiScale );
        if( cnv != 0 ) dpiScale = cnv;
    }

    // Setup ImGui binding
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    std::string iniFileName = tracy::GetSavePath( "imgui.ini" );
    io.IniFilename = iniFileName.c_str();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;

    ImGui_ImplGlfw_InitForOpenGL( window, true );
    ImGui_ImplOpenGL3_Init( "#version 150" );

    SetupDPIScale( dpiScale, fixedWidth, bigFont, smallFont );

    if( argc == 2 )
    {
        auto f = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( argv[1] ) );
        if( f )
        {
            view = std::make_unique<tracy::View>( RunOnMainThread, *f, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
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
                port = (uint16_t)atoi( argv[2] );
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
        view = std::make_unique<tracy::View>( RunOnMainThread, connectTo, port, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
    }

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
        std::unique_lock<std::mutex> lock( mainThreadLock );
        if( !mainThreadTasks.empty() )
        {
            std::vector<std::function<void()>> tmp;
            std::swap( tmp, mainThreadTasks );
            lock.unlock();
            for( auto& cb : tmp ) cb();
        }
    }

    if( loadThread.joinable() ) loadThread.join();
    if( updateThread.joinable() ) updateThread.join();
    if( updateNotesThread.joinable() ) updateNotesThread.join();
    view.reset();

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
    {
        FILE* f = fopen( filtersFile.c_str(), "wb" );
        if( f )
        {
            uint8_t sz = strlen( addrFilter.InputBuf );
            fwrite( &sz, 1, sizeof( sz ), f );
            fwrite( addrFilter.InputBuf, 1, sz, f );

            sz = strlen( portFilter.InputBuf );
            fwrite( &sz, 1, sizeof( sz ), f );
            fwrite( portFilter.InputBuf, 1, sz, f );

            sz = strlen( progFilter.InputBuf );
            fwrite( &sz, 1, sizeof( sz ), f );
            fwrite( progFilter.InputBuf, 1, sz, f );

            fclose( f );
        }
    }

    return 0;
}

static void DrawContents()
{
    static bool reconnect = false;
    static std::string reconnectAddr;
    static uint16_t reconnectPort;
    static bool showFilter = false;

    const ImVec4 clear_color = ImColor( 114, 144, 154 );

    int display_w, display_h;
    glfwGetFramebufferSize(s_glfwWindow, &display_w, &display_h);

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();
    tracy::MouseFrame();

    setlocale( LC_NUMERIC, "C" );

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
            for(;;)
            {
                auto msg = broadcastListen->Read( len, addr, 0 );
                if( !msg ) break;
                if( len > sizeof( tracy::BroadcastMessage ) ) continue;
                tracy::BroadcastMessage bm;
                memcpy( &bm, msg, len );

                if( bm.broadcastVersion == tracy::BroadcastVersion )
                {
                    const uint32_t protoVer = bm.protocolVersion;
                    const auto procname = bm.programName;
                    const auto activeTime = bm.activeTime;
                    const auto listenPort = bm.listenPort;
                    auto address = addr.GetText();

                    const auto ipNumerical = addr.GetNumber();
                    const auto clientId = uint64_t( ipNumerical ) | ( uint64_t( listenPort ) << 32 );
                    auto it = clients.find( clientId );
                    if( activeTime >= 0 )
                    {
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
                            clients.emplace( clientId, ClientData { time, protoVer, activeTime, listenPort, procname, std::move( ip ) } );
                        }
                        else
                        {
                            it->second.time = time;
                            it->second.activeTime = activeTime;
                            it->second.port = listenPort;
                            if( it->second.protocolVersion != protoVer ) it->second.protocolVersion = protoVer;
                            if( strcmp( it->second.procName.c_str(), procname ) != 0 ) it->second.procName = procname;
                        }
                    }
                    else if( it != clients.end() )
                    {
                        clients.erase( it );
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

        auto& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.129f, 0.137f, 0.11f, 1.f );
        ImGui::Begin( "Get started", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse );
        char buf[128];
        sprintf( buf, "Tracy Profiler %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
        ImGui::PushFont( bigFont );
        tracy::TextCentered( buf );
        ImGui::PopFont();
        ImGui::SameLine( ImGui::GetWindowContentRegionMax().x - ImGui::CalcTextSize( ICON_FA_WRENCH ).x - ImGui::GetStyle().FramePadding.x * 2 );
        if( ImGui::Button( ICON_FA_WRENCH ) )
        {
            ImGui::OpenPopup( "About Tracy" );
        }
        bool keepOpenAbout = true;
        if( ImGui::BeginPopupModal( "About Tracy", &keepOpenAbout, ImGuiWindowFlags_AlwaysAutoResize ) )
        {
            ImGui::PushFont( bigFont );
            tracy::TextCentered( buf );
            ImGui::PopFont();
            ImGui::Spacing();
            ImGui::TextUnformatted( "A real time, nanosecond resolution, remote telemetry, hybrid\nframe and sampling profiler for games and other applications." );
            ImGui::Spacing();
            ImGui::TextUnformatted( "Created by Bartosz Taudul" );
            ImGui::SameLine();
            tracy::TextDisabledUnformatted( "<wolf@nereid.pl>" );
            tracy::TextDisabledUnformatted( "Additional authors listed in AUTHORS file and in git history." );
            ImGui::Separator();
            tracy::TextFocused( "Protocol version", tracy::RealToString( tracy::ProtocolVersion ) );
            tracy::TextFocused( "Broadcast version", tracy::RealToString( tracy::BroadcastVersion ) );
            tracy::TextFocused( "Build date", __DATE__ ", " __TIME__ );
            ImGui::EndPopup();
        }
        ImGui::Spacing();
        if( ImGui::Button( ICON_FA_BOOK " Manual" ) )
        {
            tracy::OpenWebpage( "https://github.com/wolfpld/tracy/releases" );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_GLOBE_AMERICAS " Web" ) )
        {
            ImGui::OpenPopup( "web" );
        }
        if( ImGui::BeginPopup( "web" ) )
        {
            if( ImGui::Selectable( ICON_FA_HOME " Tracy Profiler home page" ) )
            {
                tracy::OpenWebpage( "https://github.com/wolfpld/tracy" );
            }
            ImGui::Separator();
            if( ImGui::Selectable( ICON_FA_VIDEO " Overview of v0.2" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=fB5B46lbapc" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.3" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=3SXpDpDh2Uo" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.4" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=eAkgkaO8B9o" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.5" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=P6E7qLMmzTQ" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.6" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=uJkrFgriuOo" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.7" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=_hU7vw00MZ4" );
            }
            ImGui::EndPopup();
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_COMMENT " Chat" ) )
        {
            tracy::OpenWebpage( "https://discord.gg/pk78auc" );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_HEART " Sponsor" ) )
        {
            tracy::OpenWebpage( "https://github.com/sponsors/wolfpld/" );
        }
        if( updateVersion != 0 && updateVersion > tracy::FileVersion( tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch ) )
        {
            ImGui::Separator();
            ImGui::TextColored( ImVec4( 1, 1, 0, 1 ), ICON_FA_EXCLAMATION " Update to %i.%i.%i is available!", ( updateVersion >> 16 ) & 0xFF, ( updateVersion >> 8 ) & 0xFF, updateVersion & 0xFF );
            ImGui::SameLine();
            if( ImGui::SmallButton( ICON_FA_GIFT " Get it!" ) )
            {
                showReleaseNotes = true;
                if( !updateNotesThread.joinable() )
                {
                    updateNotesThread = std::thread( [] {
                        HttpRequest( "nereid.pl", "/tracy/notes", 8099, [] ( int size, char* data ) {
                            std::string notes( data, data+size );
                            delete[] data;
                            RunOnMainThread( [notes = move( notes )] { releaseNotes = std::move( notes ); } );
                        } );
                    } );
                }
            }
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
            const auto addrLen = strlen( addr );
            std::string addrStr( addr, addr+addrLen );
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

            auto ptr = addr + addrLen - 1;
            while( ptr > addr && *ptr != ':' ) ptr--;
            if( *ptr == ':' )
            {
                std::string addrPart = std::string( addr, ptr );
                uint16_t portPart = (uint16_t)atoi( ptr+1 );
                view = std::make_unique<tracy::View>( RunOnMainThread, addrPart.c_str(), portPart, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
            }
            else
            {
                view = std::make_unique<tracy::View>( RunOnMainThread, addr, port, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
            }
        }
        ImGui::SameLine( 0, ImGui::GetFontSize() * 2 );

#ifndef TRACY_NO_FILESELECTOR
        if( ImGui::Button( ICON_FA_FOLDER_OPEN " Open saved trace" ) && !loadThread.joinable() )
        {
            nfdchar_t* fn;
            auto res = NFD_OpenDialog( "tracy", nullptr, &fn, GetMainWindowNative() );
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
                                view = std::make_unique<tracy::View>( RunOnMainThread, *f, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
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
            tracy::BadVersion( badVer, bigFont );
        }
#endif

        if( !clients.empty() )
        {
            ImGui::Separator();
            ImGui::TextUnformatted( "Discovered clients:" );
            ImGui::SameLine();
            tracy::SmallToggleButton( ICON_FA_FILTER " Filter", showFilter );
            if( addrFilter.IsActive() || portFilter.IsActive() || progFilter.IsActive() )
            {
                ImGui::SameLine();
                tracy::TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( "Filters are active" );
                    ImGui::EndTooltip();
                }
                if( showFilter )
                {
                    ImGui::SameLine();
                    if( ImGui::SmallButton( ICON_FA_BACKSPACE " Clear" ) )
                    {
                        addrFilter.Clear();
                        portFilter.Clear();
                        progFilter.Clear();
                    }
                }
            }
            if( showFilter )
            {
                const auto w = ImGui::GetFontSize() * 12;
                ImGui::Separator();
                addrFilter.Draw( "Address filter", w );
                portFilter.Draw( "Port filter", w );
                progFilter.Draw( "Program filter", w );
            }
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
            int idx = 0;
            int passed = 0;
            for( auto& v : clients )
            {
                const bool badProto = v.second.protocolVersion != tracy::ProtocolVersion;
                bool sel = false;
                const auto& name = resolvMap.find( v.second.address );
                assert( name != resolvMap.end() );
                if( addrFilter.IsActive() && !addrFilter.PassFilter( name->second.c_str() ) && !addrFilter.PassFilter( v.second.address.c_str() ) ) continue;
                if( portFilter.IsActive() )
                {
                    char buf[32];
                    sprintf( buf, "%" PRIu16, v.second.port );
                    if( !portFilter.PassFilter( buf ) ) continue;
                }
                if( progFilter.IsActive() && !progFilter.PassFilter( v.second.procName.c_str() ) ) continue;
                ImGuiSelectableFlags flags = ImGuiSelectableFlags_SpanAllColumns;
                if( badProto ) flags |= ImGuiSelectableFlags_Disabled;
                ImGui::PushID( idx++ );
                const bool selected = ImGui::Selectable( name->second.c_str(), &sel, flags );
                ImGui::PopID();
                if( ImGui::IsItemHovered( ImGuiHoveredFlags_AllowWhenDisabled ) )
                {
                    char portstr[32];
                    sprintf( portstr, "%" PRIu16, v.second.port );
                    ImGui::BeginTooltip();
                    if( badProto )
                    {
                        tracy::TextColoredUnformatted( 0xFF0000FF, "Incompatible protocol!" );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(used: %i, required: %i)", v.second.protocolVersion, tracy::ProtocolVersion );
                    }
                    tracy::TextFocused( "IP:", v.second.address.c_str() );
                    tracy::TextFocused( "Port:", portstr );
                    ImGui::EndTooltip();
                }
                if( v.second.port != port )
                {
                    ImGui::SameLine();
                    ImGui::TextDisabled( ":%" PRIu16, v.second.port );
                }
                if( selected && !loadThread.joinable() )
                {
                    view = std::make_unique<tracy::View>( RunOnMainThread, v.second.address.c_str(), v.second.port, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
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
                passed++;
            }
            ImGui::EndColumns();
            if( passed == 0 )
            {
                ImGui::TextUnformatted( "All clients are filtered." );
            }
        }
        ImGui::End();

        if( showReleaseNotes )
        {
            assert( updateNotesThread.joinable() );
            ImGui::SetNextWindowSize( ImVec2( 600 * dpiScale, 400 * dpiScale ), ImGuiCond_FirstUseEver );
            ImGui::Begin( "Update available!", &showReleaseNotes );
            if( ImGui::Button( ICON_FA_DOWNLOAD " Download" ) )
            {
                tracy::OpenWebpage( "https://github.com/wolfpld/tracy/releases" );
            }
            ImGui::BeginChild( "###notes", ImVec2( 0, 0 ), true );
            if( releaseNotes.empty() )
            {
                static float rnTime = 0;
                rnTime += ImGui::GetIO().DeltaTime;
                tracy::TextCentered( "Fetching release notes..." );
                tracy::DrawWaitingDots( rnTime );
            }
            else
            {
                ImGui::PushFont( fixedWidth );
                ImGui::TextUnformatted( releaseNotes.c_str() );
                ImGui::PopFont();
            }
            ImGui::EndChild();
            ImGui::End();
        }
    }
    else
    {
        if( showReleaseNotes ) showReleaseNotes = false;
        if( broadcastListen )
        {
            broadcastListen.reset();
            clients.clear();
        }
        if( loadThread.joinable() ) loadThread.join();
        view->NotifyRootWindowSize( display_w, display_h );
        if( !view->Draw() )
        {
            viewShutdown.store( ViewShutdown::True, std::memory_order_relaxed );
            reconnect = view->ReconnectRequested();
            if( reconnect )
            {
                reconnectAddr = view->GetAddress();
                reconnectPort = view->GetPort();
            }
            loadThread = std::thread( [view = std::move( view )] () mutable {
                view.reset();
                viewShutdown.store( ViewShutdown::Join, std::memory_order_relaxed );
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
        ImGui::PushFont( bigFont );
        tracy::TextCentered( ICON_FA_HOURGLASS_HALF );
        ImGui::PopFont();

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
    switch( viewShutdown.load( std::memory_order_relaxed ) )
    {
    case ViewShutdown::True:
        ImGui::OpenPopup( "Capture cleanup..." );
        break;
    case ViewShutdown::Join:
        loadThread.join();
        viewShutdown.store( ViewShutdown::False, std::memory_order_relaxed );
        if( reconnect )
        {
            view = std::make_unique<tracy::View>( RunOnMainThread, reconnectAddr.c_str(), reconnectPort, fixedWidth, smallFont, bigFont, SetWindowTitleCallback, GetMainWindowNative, SetupScaleCallback );
        }
        break;
    default:
        break;
    }
    if( ImGui::BeginPopupModal( "Capture cleanup...", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        if( viewShutdown.load( std::memory_order_relaxed ) != ViewShutdown::True ) ImGui::CloseCurrentPopup();
        ImGui::PushFont( bigFont );
        tracy::TextCentered( ICON_FA_BROOM );
        ImGui::PopFont();
        animTime += ImGui::GetIO().DeltaTime;
        tracy::DrawWaitingDots( animTime );
        ImGui::TextUnformatted( "Please wait, cleanup is in progress" );
        ImGui::EndPopup();
    }

    // Rendering
    ImGui::Render();
    glViewport(0, 0, display_w, display_h);
    glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    // Update and Render additional Platform Windows
    // (Platform functions may change the current OpenGL context, so we save/restore it to make it easier to paste this code elsewhere.
    //  For this specific demo app we could also call glfwMakeContextCurrent(window) directly)
    if (ImGui::GetIO().ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        GLFWwindow* backup_current_context = glfwGetCurrentContext();
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
        glfwMakeContextCurrent(backup_current_context);
    }

    glfwSwapBuffers(s_glfwWindow);
}
