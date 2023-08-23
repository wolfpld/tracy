#include <algorithm>
#include <assert.h>
#include <atomic>
#include <chrono>
#include <inttypes.h>
#include <imgui.h>
#include <mutex>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <unordered_map>
#include <memory>
#include <sys/stat.h>
#include <locale.h>

#ifdef _WIN32
#  include <windows.h>
#endif

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#include "stb_image.h"

#define STB_IMAGE_RESIZE_IMPLEMENTATION
#include "stb_image_resize.h"

#include "ini.h"

#include "../../public/common/TracyProtocol.hpp"
#include "../../public/common/TracyVersion.hpp"
#include "../../server/tracy_pdqsort.h"
#include "../../server/tracy_robin_hood.h"
#include "../../server/TracyBadVersion.hpp"
#include "../../server/TracyConfig.hpp"
#include "../../server/TracyFileHeader.hpp"
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyFileselector.hpp"
#include "../../server/TracyImGui.hpp"
#include "../../server/TracyMouse.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracyProtoHistory.hpp"
#include "../../server/TracyStorage.hpp"
#include "../../server/TracyTexture.hpp"
#include "../../server/TracyView.hpp"
#include "../../server/TracyWeb.hpp"
#include "../../server/TracyWorker.hpp"
#include "../../server/IconsFontAwesome6.h"

#include "icon.hpp"
#include "zigzag01.hpp"
#include "zigzag02.hpp"
#include "zigzag04.hpp"
#include "zigzag08.hpp"
#include "zigzag16.hpp"
#include "zigzag32.hpp"

#include "Backend.hpp"
#include "ConnectionHistory.hpp"
#include "Filters.hpp"
#include "Fonts.hpp"
#include "HttpRequest.hpp"
#include "IsElevated.hpp"
#include "ImGuiContext.hpp"
#include "ResolvService.hpp"
#include "RunQueue.hpp"


struct ClientData
{
    int64_t time;
    uint32_t protocolVersion;
    int32_t activeTime;
    uint16_t port;
    uint64_t pid;
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
static char addr[1024] = { "127.0.0.1" };
static ConnectionHistory* connHist;
static std::atomic<ViewShutdown> viewShutdown { ViewShutdown::False };
static double animTime = 0;
static float dpiScale = 1.f;
static Filters* filt;
static RunQueue mainThreadTasks;
static uint32_t updateVersion = 0;
static bool showReleaseNotes = false;
static std::string releaseNotes;
static uint8_t* iconPx;
static int iconX, iconY;
static void* iconTex;
static int iconTexSz;
static uint8_t* zigzagPx[6];
static int zigzagX[6], zigzagY[6];
void* zigzagTex;
static Backend* bptr;
static bool s_customTitle = false;
static bool s_isElevated = false;
static tracy::Config s_config;

static void SetWindowTitleCallback( const char* title )
{
    char tmp[1024];
    sprintf( tmp, "%s - Tracy Profiler %i.%i.%i", title, tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
    bptr->SetTitle( tmp );
    s_customTitle = true;
}

static void AttentionCallback()
{
    bptr->Attention();
}

static void DrawContents();

static void RunOnMainThread( const std::function<void()>& cb, bool forceDelay = false )
{
    mainThreadTasks.Queue( cb, forceDelay );
}

static void SetupDPIScale( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont )
{
    LoadFonts( scale, cb_fixedWidth, cb_bigFont, cb_smallFont );

#ifdef __APPLE__
    // No need to upscale the style on macOS, but we need to downscale the fonts.
    ImGuiIO& io = ImGui::GetIO();
    io.FontGlobalScale = 1.0f / dpiScale;
    scale = 1.0f;
#endif

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

    const auto ty = int( 80 * scale );
    iconTexSz = ty;
    auto scaleIcon = new uint8_t[4*ty*ty];
    stbir_resize_uint8( iconPx, iconX, iconY, 0, scaleIcon, ty, ty, 0, 4 );
    tracy::UpdateTextureRGBA( iconTex, scaleIcon, ty, ty );
    delete[] scaleIcon;
}

static void SetupScaleCallback( float scale, ImFont*& cb_fixedWidth, ImFont*& cb_bigFont, ImFont*& cb_smallFont )
{
    RunOnMainThread( [scale, &cb_fixedWidth, &cb_bigFont, &cb_smallFont] { SetupDPIScale( scale * dpiScale, cb_fixedWidth, cb_bigFont, cb_smallFont ); }, true );
}

static void LoadConfig()
{
    const auto fn = tracy::GetSavePath( "tracy.ini" );
    auto ini = ini_load( fn );
    if( !ini ) return;

    int v;
    if( ini_sget( ini, "core", "threadedRendering", "%d", &v ) ) s_config.threadedRendering = v;
    if( ini_sget( ini, "timeline", "targetFps", "%d", &v ) && v >= 1 && v < 10000 ) s_config.targetFps = v;

    ini_free( ini );
}

static bool SaveConfig()
{
    const auto fn = tracy::GetSavePath( "tracy.ini" );
    FILE* f = fopen( fn, "wb" );
    if( !f ) return false;

    fprintf( f, "[core]\n" );
    fprintf( f, "threadedRendering = %i\n", (int)s_config.threadedRendering );

    fprintf( f, "\n[timeline]\n" );
    fprintf( f, "targetFps = %i\n", s_config.targetFps );

    fclose( f );
    return true;
}

int main( int argc, char** argv )
{
    sprintf( title, "Tracy Profiler %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );

    std::unique_ptr<tracy::FileRead> initFileOpen;
#ifdef __EMSCRIPTEN__
    initFileOpen = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( "embed.tracy" ) );
#endif
    if( argc == 2 )
    {
        if( strcmp( argv[1], "--help" ) == 0 )
        {
            printf( "%s\n\n", title );
            printf( "Usage:\n\n" );
            printf( "    Open trace file stored on disk:\n" );
            printf( "      %s file.tracy\n\n", argv[0] );
            printf( "    Connect to a running client:\n" );
            printf( "      %s -a address [-p port]\n", argv[0] );
            exit( 0 );
        }
        initFileOpen = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( argv[1] ) );
        if( !initFileOpen )
        {
            fprintf( stderr, "Cannot open trace file: %s\n", argv[1] );
            exit( 1 );
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

    ConnectionHistory connHistory;
    Filters filters;

    connHist = &connHistory;
    filt = &filters;

#ifndef __EMSCRIPTEN__
    updateThread = std::thread( [] {
        HttpRequest( "nereid.pl", "/tracy/version", 8099, [] ( int size, char* data ) {
            if( size == 4 )
            {
                uint32_t ver;
                memcpy( &ver, data, 4 );
                RunOnMainThread( [ver] { updateVersion = ver; tracy::s_wasActive = true; } );
            }
            delete[] data;
        } );
    } );
#endif

    auto iconThread = std::thread( [] {
        iconPx = stbi_load_from_memory( (const stbi_uc*)Icon_data, Icon_size, &iconX, &iconY, nullptr, 4 );
        zigzagPx[0] = stbi_load_from_memory( (const stbi_uc*)ZigZag32_data, ZigZag32_size, &zigzagX[0], &zigzagY[0], nullptr, 4 );
        zigzagPx[1] = stbi_load_from_memory( (const stbi_uc*)ZigZag16_data, ZigZag16_size, &zigzagX[1], &zigzagY[1], nullptr, 4 );
        zigzagPx[2] = stbi_load_from_memory( (const stbi_uc*)ZigZag08_data, ZigZag08_size, &zigzagX[2], &zigzagY[2], nullptr, 4 );
        zigzagPx[3] = stbi_load_from_memory( (const stbi_uc*)ZigZag04_data, ZigZag04_size, &zigzagX[3], &zigzagY[3], nullptr, 4 );
        zigzagPx[4] = stbi_load_from_memory( (const stbi_uc*)ZigZag02_data, ZigZag02_size, &zigzagX[4], &zigzagY[4], nullptr, 4 );
        zigzagPx[5] = stbi_load_from_memory( (const stbi_uc*)ZigZag01_data, ZigZag01_size, &zigzagX[5], &zigzagY[5], nullptr, 4 );
    } );

    LoadConfig();

    ImGuiTracyContext imguiContext;
    Backend backend( title, DrawContents, &mainThreadTasks );
    tracy::InitTexture();
    iconTex = tracy::MakeTexture();
    zigzagTex = tracy::MakeTexture( true );
    iconThread.join();
    backend.SetIcon( iconPx, iconX, iconY );
    bptr = &backend;

    dpiScale = backend.GetDpiScale();
    const auto envDpiScale = getenv( "TRACY_DPI_SCALE" );
    if( envDpiScale )
    {
        const auto cnv = atof( envDpiScale );
        if( cnv != 0 ) dpiScale = cnv;
    }

    SetupDPIScale( dpiScale, s_fixedWidth, s_bigFont, s_smallFont );

    tracy::UpdateTextureRGBAMips( zigzagTex, (void**)zigzagPx, zigzagX, zigzagY, 6 );
    for( auto& v : zigzagPx ) free( v );

    if( initFileOpen )
    {
        view = std::make_unique<tracy::View>( RunOnMainThread, *initFileOpen, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
        initFileOpen.reset();
    }
    else if( connectTo )
    {
        view = std::make_unique<tracy::View>( RunOnMainThread, connectTo, port, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
    }

    tracy::Fileselector::Init();
    s_isElevated = IsElevated();

    backend.Show();
    backend.Run();

    if( loadThread.joinable() ) loadThread.join();
    if( updateThread.joinable() ) updateThread.join();
    if( updateNotesThread.joinable() ) updateNotesThread.join();
    view.reset();

    tracy::FreeTexture( zigzagTex, RunOnMainThread );
    tracy::FreeTexture( iconTex, RunOnMainThread );
    free( iconPx );

    tracy::Fileselector::Shutdown();

    return 0;
}

static void UpdateBroadcastClients()
{
    if( !view )
    {
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
                uint16_t broadcastVersion;
                memcpy( &broadcastVersion, msg, sizeof( uint16_t ) );
                if( broadcastVersion <= tracy::BroadcastVersion )
                {
                    uint32_t protoVer;
                    char procname[tracy::WelcomeMessageProgramNameSize];
                    int32_t activeTime;
                    uint16_t listenPort;
                    uint64_t pid;

                    switch( broadcastVersion )
                    {
                    case 3:
                    {
                        tracy::BroadcastMessage bm;
                        memcpy( &bm, msg, len );
                        protoVer = bm.protocolVersion;
                        strcpy( procname, bm.programName );
                        activeTime = bm.activeTime;
                        listenPort = bm.listenPort;
                        pid = bm.pid;
                        break;
                    }
                    case 2:
                    {
                        if( len > sizeof( tracy::BroadcastMessage_v2 ) ) continue;
                        tracy::BroadcastMessage_v2 bm;
                        memcpy( &bm, msg, len );
                        protoVer = bm.protocolVersion;
                        strcpy( procname, bm.programName );
                        activeTime = bm.activeTime;
                        listenPort = bm.listenPort;
                        pid = 0;
                        break;
                    }
                    case 1:
                    {
                        if( len > sizeof( tracy::BroadcastMessage_v1 ) ) continue;
                        tracy::BroadcastMessage_v1 bm;
                        memcpy( &bm, msg, len );
                        protoVer = bm.protocolVersion;
                        strcpy( procname, bm.programName );
                        activeTime = bm.activeTime;
                        listenPort = bm.listenPort;
                        pid = 0;
                        break;
                    }
                    case 0:
                    {
                        if( len > sizeof( tracy::BroadcastMessage_v0 ) ) continue;
                        tracy::BroadcastMessage_v0 bm;
                        memcpy( &bm, msg, len );
                        protoVer = bm.protocolVersion;
                        strcpy( procname, bm.programName );
                        activeTime = bm.activeTime;
                        listenPort = 8086;
                        pid = 0;
                        break;
                    }
                    default:
                        assert( false );
                        break;
                    }

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
                            clients.emplace( clientId, ClientData { time, protoVer, activeTime, listenPort, pid, procname, std::move( ip ) } );
                        }
                        else
                        {
                            it->second.time = time;
                            it->second.activeTime = activeTime;
                            it->second.port = listenPort;
                            it->second.pid = pid;
                            it->second.protocolVersion = protoVer;
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
    }
    else if( !clients.empty() )
    {
        clients.clear();
    }
}

static void DrawContents()
{
    static bool reconnect = false;
    static std::string reconnectAddr;
    static uint16_t reconnectPort;
    static bool showFilter = false;

#ifndef __EMSCRIPTEN__
    UpdateBroadcastClients();
#endif

    int display_w, display_h;
    bptr->NewFrame( display_w, display_h );

    static int activeFrames = 3;
    if( tracy::WasActive() || !clients.empty() || ( view && view->WasActive() ) )
    {
        activeFrames = 3;
    }
    else
    {
        auto ctx = ImGui::GetCurrentContext();
        if( ctx->NavWindowingTarget || ( ctx->DimBgRatio != 0 && ctx->DimBgRatio != 1 ) )
        {
            activeFrames = 3;
        }
        else
        {
            auto& inputQueue = ctx->InputEventsQueue;
            if( !inputQueue.empty() )
            {
                for( auto& v : inputQueue )
                {
                    if( v.Type != ImGuiInputEventType_MouseViewport )
                    {
                        activeFrames = 3;
                        break;
                    }
                }
            }
        }
    }
    if( activeFrames == 0 )
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 16 ) );
        return;
    }
    activeFrames--;

    ImGui::NewFrame();
    tracy::MouseFrame();

    setlocale( LC_NUMERIC, "C" );

    if( !view )
    {
        if( s_customTitle )
        {
            s_customTitle = false;
            bptr->SetTitle( title );
        }

        auto& style = ImGui::GetStyle();
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.129f, 0.137f, 0.11f, 1.f );
        ImGui::Begin( "Get started", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse );
        char buf[128];
        sprintf( buf, "Tracy Profiler %i.%i.%i", tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch );
        ImGui::PushFont( s_bigFont );
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
            tracy::ImageCentered( iconTex, ImVec2( iconTexSz, iconTexSz ) );
            ImGui::Spacing();
            ImGui::PushFont( s_bigFont );
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
            if( ImGui::TreeNode( ICON_FA_TOOLBOX " Global settings" ) )
            {
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::TextUnformatted( "Threaded rendering" );
                ImGui::Indent();
                if( ImGui::RadioButton( "Enabled", s_config.threadedRendering ) ) { s_config.threadedRendering = true; SaveConfig(); }
                ImGui::SameLine();
                tracy::DrawHelpMarker( "Uses multiple CPU cores for rendering. May affect performance of the profiled application when running on the same machine." );
                if( ImGui::RadioButton( "Disabled", !s_config.threadedRendering ) ) { s_config.threadedRendering = false; SaveConfig(); }
                ImGui::SameLine();
                tracy::DrawHelpMarker( "Restricts rendering to a single CPU core. Can reduce profiler frame rate." );
                ImGui::Unindent();

                ImGui::Spacing();
                ImGui::TextUnformatted( "Target FPS" );
                ImGui::SameLine();
                int tmp = s_config.targetFps;
                ImGui::SetNextItemWidth( 90 * dpiScale );
                if( ImGui::InputInt( "##targetfps", &tmp ) ) { s_config.targetFps = std::clamp( tmp, 1, 9999 ); SaveConfig(); }
                ImGui::PopStyleVar();
                ImGui::TreePop();
            }
            ImGui::Separator();
            ImGui::PushFont( s_smallFont );
            tracy::TextFocused( "Protocol version", tracy::RealToString( tracy::ProtocolVersion ) );
            ImGui::SameLine();
            ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
            ImGui::SameLine();
            tracy::TextFocused( "Broadcast version", tracy::RealToString( tracy::BroadcastVersion ) );
            ImGui::SameLine();
            ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
            ImGui::SameLine();
            tracy::TextFocused( "Build date", __DATE__ ", " __TIME__ );
            ImGui::PopFont();
            ImGui::EndPopup();
        }
        ImGui::Spacing();
        if( ImGui::Button( ICON_FA_BOOK " Manual" ) )
        {
            tracy::OpenWebpage( "https://github.com/wolfpld/tracy/releases" );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_EARTH_AMERICAS " Web" ) )
        {
            ImGui::OpenPopup( "web" );
        }
        if( ImGui::BeginPopup( "web" ) )
        {
            if( ImGui::Selectable( ICON_FA_HOUSE_CHIMNEY " Tracy Profiler home page" ) )
            {
                tracy::OpenWebpage( "https://github.com/wolfpld/tracy" );
            }
            ImGui::Separator();
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.8" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=30wpRpHTTag" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.7" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=_hU7vw00MZ4" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.6" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=uJkrFgriuOo" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.5" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=P6E7qLMmzTQ" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.4" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=eAkgkaO8B9o" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.3" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=3SXpDpDh2Uo" );
            }
            if( ImGui::Selectable( ICON_FA_VIDEO " Overview of v0.2" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=fB5B46lbapc" );
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
        if( updateVersion > tracy::FileVersion( tracy::Version::Major, tracy::Version::Minor, tracy::Version::Patch ) )
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
                            RunOnMainThread( [notes = std::move( notes )] () mutable { releaseNotes = std::move( notes ); tracy::s_wasActive = true; } );
                        } );
                    } );
                }
            }
        }
        if( s_isElevated )
        {
            ImGui::Separator();
            ImGui::TextColored( ImVec4( 1, 0.25f, 0.25f, 1 ), ICON_FA_TRIANGLE_EXCLAMATION " Profiler has elevated privileges! " ICON_FA_TRIANGLE_EXCLAMATION );
            ImGui::PushFont( s_smallFont );
            ImGui::TextColored( ImVec4( 1, 0.25f, 0.25f, 1 ), "You are running the profiler interface with admin privileges. This is" );
            ImGui::TextColored( ImVec4( 1, 0.25f, 0.25f, 1 ), "most likely a mistake, as there is no reason to do so. Instead, you" );
            ImGui::TextColored( ImVec4( 1, 0.25f, 0.25f, 1 ), "probably wanted to run the client (the application you are profiling)" );
            ImGui::TextColored( ImVec4( 1, 0.25f, 0.25f, 1 ), "with elevated privileges." );
            ImGui::PopFont();
        }
        ImGui::Separator();
        ImGui::TextUnformatted( "Client address" );
        bool connectClicked = false;
        connectClicked |= ImGui::InputTextWithHint( "###connectaddress", "Enter address", addr, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
        if( !connHist->empty() )
        {
            ImGui::SameLine();
            if( ImGui::BeginCombo( "##frameCombo", nullptr, ImGuiComboFlags_NoPreview ) )
            {
                int idxRemove = -1;
                const auto sz = std::min<size_t>( 5, connHist->size() );
                for( size_t i=0; i<sz; i++ )
                {
                    const auto& str = connHist->Name( i );
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
                    connHist->Erase( idxRemove );
                }
                ImGui::EndCombo();
            }
        }
        connectClicked |= ImGui::Button( ICON_FA_WIFI " Connect" );
        if( connectClicked && *addr && !loadThread.joinable() )
        {
            connHist->Count( addr );

            const auto addrLen = strlen( addr );
            auto ptr = addr + addrLen - 1;
            while( ptr > addr && *ptr != ':' ) ptr--;
            if( *ptr == ':' )
            {
                std::string addrPart = std::string( addr, ptr );
                uint16_t portPart = (uint16_t)atoi( ptr+1 );
                view = std::make_unique<tracy::View>( RunOnMainThread, addrPart.c_str(), portPart, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
            }
            else
            {
                view = std::make_unique<tracy::View>( RunOnMainThread, addr, port, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
            }
        }
        ImGui::SameLine( 0, ImGui::GetTextLineHeight() * 2 );

#ifndef TRACY_NO_FILESELECTOR
        if( ImGui::Button( ICON_FA_FOLDER_OPEN " Open saved trace" ) && !loadThread.joinable() )
        {
            tracy::Fileselector::OpenFile( "tracy", "Tracy Profiler trace file", []( const char* fn ) {
                try
                {
                    auto f = std::shared_ptr<tracy::FileRead>( tracy::FileRead::Open( fn ) );
                    if( f )
                    {
                        loadThread = std::thread( [f] {
                            try
                            {
                                view = std::make_unique<tracy::View>( RunOnMainThread, *f, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
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
            } );
        }

        if( badVer.state != tracy::BadVersionState::Ok )
        {
            if( loadThread.joinable() ) { loadThread.join(); }
            tracy::BadVersion( badVer, s_bigFont );
        }
#endif

        if( !clients.empty() )
        {
            ImGui::Separator();
            ImGui::TextUnformatted( "Discovered clients:" );
            ImGui::SameLine();
            tracy::SmallToggleButton( ICON_FA_FILTER " Filter", showFilter );
            if( filt->IsActive() )
            {
                ImGui::SameLine();
                tracy::TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
                tracy::TooltipIfHovered( "Filters are active" );
                if( showFilter )
                {
                    ImGui::SameLine();
                    if( ImGui::SmallButton( ICON_FA_DELETE_LEFT " Clear" ) )
                    {
                        filt->Clear();
                    }
                }
            }
            if( showFilter )
            {
                const auto w = ImGui::GetTextLineHeight() * 12;
                ImGui::Separator();
                filt->Draw( w );
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
            const auto time = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count();
            int idx = 0;
            int passed = 0;
            std::lock_guard<std::mutex> lock( resolvLock );
            for( auto& v : clients )
            {
                const bool badProto = v.second.protocolVersion != tracy::ProtocolVersion;
                bool sel = false;
                const auto& name = resolvMap.find( v.second.address );
                assert( name != resolvMap.end() );
                if( filt->FailAddr( name->second.c_str() ) && filt->FailAddr( v.second.address.c_str() ) ) continue;
                if( filt->FailPort( v.second.port ) ) continue;
                if( filt->FailProg( v.second.procName.c_str() ) ) continue;
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
                        auto ph = tracy::ProtocolHistory;
                        ImGui::TextDisabled( "(used: %i, required: %i)", v.second.protocolVersion, tracy::ProtocolVersion );
                        while( ph->protocol && ph->protocol != v.second.protocolVersion ) ph++;
                        if( ph->protocol )
                        {
                            if( ph->maxVer )
                            {
                                ImGui::TextDisabled( "Compatible Tracy versions: %i.%i.%i to %i.%i.%i", ph->minVer >> 16, ( ph->minVer >> 8 ) & 0xFF, ph->minVer & 0xFF, ph->maxVer >> 16, ( ph->maxVer >> 8 ) & 0xFF, ph->maxVer & 0xFF );
                            }
                            else
                            {
                                ImGui::TextDisabled( "Compatible Tracy version: %i.%i.%i", ph->minVer >> 16, ( ph->minVer >> 8 ) & 0xFF, ph->minVer & 0xFF );
                            }
                        }
                        ImGui::Separator();
                    }
                    tracy::TextFocused( "IP:", v.second.address.c_str() );
                    tracy::TextFocused( "Port:", portstr );
                    if( v.second.pid != 0 )
                    {
                        tracy::TextFocused( "PID:", tracy::RealToString( v.second.pid ) );
                    }
                    ImGui::EndTooltip();
                }
                if( v.second.port != port )
                {
                    ImGui::SameLine();
                    ImGui::TextDisabled( ":%" PRIu16, v.second.port );
                }
                if( selected && !loadThread.joinable() )
                {
                    view = std::make_unique<tracy::View>( RunOnMainThread, v.second.address.c_str(), v.second.port, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
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
                ImGui::PushFont( s_fixedWidth );
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
        ImGui::PushFont( s_bigFont );
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
            view = std::make_unique<tracy::View>( RunOnMainThread, reconnectAddr.c_str(), reconnectPort, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config );
        }
        break;
    default:
        break;
    }
    if( ImGui::BeginPopupModal( "Capture cleanup...", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        if( viewShutdown.load( std::memory_order_relaxed ) != ViewShutdown::True ) ImGui::CloseCurrentPopup();
        ImGui::PushFont( s_bigFont );
        tracy::TextCentered( ICON_FA_BROOM );
        ImGui::PopFont();
        animTime += ImGui::GetIO().DeltaTime;
        tracy::DrawWaitingDots( animTime );
        ImGui::TextUnformatted( "Please wait, cleanup is in progress" );
        ImGui::EndPopup();
    }

    if( tracy::Fileselector::HasFailed() ) ImGui::OpenPopup( "File selector is not available" );
    if( ImGui::BeginPopupModal( "File selector is not available", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::TextUnformatted( "File selector cannot be displayed." );
        ImGui::TextUnformatted( "Check nfd library implementation for details." );
        ImGui::Separator();
        if( ImGui::Button( "Ok" ) ) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    bptr->EndFrame();
}
