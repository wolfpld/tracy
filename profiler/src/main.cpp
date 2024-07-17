#include <algorithm>
#include <assert.h>
#include <atomic>
#include <chrono>
#include <inttypes.h>
#define IMGUI_DEFINE_MATH_OPERATORS 1
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
#include "profiler/TracyAchievements.hpp"
#include "profiler/TracyBadVersion.hpp"
#include "profiler/TracyConfig.hpp"
#include "profiler/TracyFileselector.hpp"
#include "profiler/TracyImGui.hpp"
#include "profiler/TracyMouse.hpp"
#include "profiler/TracyProtoHistory.hpp"
#include "profiler/TracyStorage.hpp"
#include "profiler/TracyTexture.hpp"
#include "profiler/TracyView.hpp"
#include "profiler/TracyWeb.hpp"
#include "profiler/IconsFontAwesome6.h"
#include "../../server/tracy_pdqsort.h"
#include "../../server/tracy_robin_hood.h"
#include "../../server/TracyFileHeader.hpp"
#include "../../server/TracyFileRead.hpp"
#include "../../server/TracyPrint.hpp"
#include "../../server/TracySysUtil.hpp"
#include "../../server/TracyWorker.hpp"

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
static bool dpiScaleOverriddenFromEnv = false;
static float userScale = 1.f;
static float prevScale = 1.f;
static int dpiChanged = 0;
static bool dpiFirstSetup = true;
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
static size_t s_totalMem = tracy::GetPhysicalMemorySize();
tracy::Config s_config;
tracy::AchievementsMgr* s_achievements;
static const tracy::data::AchievementItem* s_achievementItem = nullptr;
static bool s_switchAchievementCategory = false;

static float smoothstep( float x )
{
    return x * x * ( 3.0f - 2.0f * x );
}

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

static void ScaleWindow(ImGuiWindow* window, float scale)
{
    ImVec2 origin = window->Viewport->Pos;
    window->Pos = ImFloor((window->Pos - origin) * scale + origin);
    window->Size = ImTrunc(window->Size * scale);
    window->SizeFull = ImTrunc(window->SizeFull * scale);
    window->ContentSize = ImTrunc(window->ContentSize * scale);
}

static void SetupDPIScale()
{
    auto scale = dpiScale * userScale;

    if( !dpiFirstSetup && prevScale == scale ) return;
    dpiFirstSetup = false;
    dpiChanged = 2;

    LoadFonts( scale );
    if( view ) view->UpdateFont( s_fixedWidth, s_smallFont, s_bigFont );

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

    const auto ratio = scale / prevScale;
    prevScale = scale;
    auto ctx = ImGui::GetCurrentContext();
    for( auto& w : ctx->Windows ) ScaleWindow( w, ratio );
}

static void SetupScaleCallback( float scale )
{
    userScale = scale;
    RunOnMainThread( []{ SetupDPIScale(); }, true );
}

static int IsBusy()
{
    if( loadThread.joinable() ) return 2;
    if( view && !view->IsBackgroundDone() ) return 1;
    return 0;
}

static void LoadConfig()
{
    const auto fn = tracy::GetSavePath( "tracy.ini" );
    auto ini = ini_load( fn );
    if( !ini ) return;

    int v;
    if( ini_sget( ini, "core", "threadedRendering", "%d", &v ) ) s_config.threadedRendering = v;
    if( ini_sget( ini, "core", "focusLostLimit", "%d", &v ) ) s_config.focusLostLimit = v;
    if( ini_sget( ini, "timeline", "targetFps", "%d", &v ) && v >= 1 && v < 10000 ) s_config.targetFps = v;
    if( ini_sget( ini, "timeline", "dynamicColors", "%d", &v ) ) s_config.dynamicColors = v;
    if( ini_sget( ini, "timeline", "forceColors", "%d", &v ) ) s_config.forceColors = v;
    if( ini_sget( ini, "timeline", "shortenName", "%d", &v ) ) s_config.shortenName = v;
    if( ini_sget( ini, "memory", "limit", "%d", &v ) ) s_config.memoryLimit = v;
    if( ini_sget( ini, "memory", "percent", "%d", &v ) && v >= 1 && v < 1000 ) s_config.memoryLimitPercent = v;
    if( ini_sget( ini, "achievements", "enabled", "%d", &v ) ) s_config.achievements = v;
    if( ini_sget( ini, "achievements", "asked", "%d", &v ) ) s_config.achievementsAsked = v;

    ini_free( ini );
}

static bool SaveConfig()
{
    const auto fn = tracy::GetSavePath( "tracy.ini" );
    FILE* f = fopen( fn, "wb" );
    if( !f ) return false;

    fprintf( f, "[core]\n" );
    fprintf( f, "threadedRendering = %i\n", (int)s_config.threadedRendering );
    fprintf( f, "focusLostLimit = %i\n", (int)s_config.focusLostLimit );

    fprintf( f, "\n[timeline]\n" );
    fprintf( f, "targetFps = %i\n", s_config.targetFps );
    fprintf( f, "dynamicColors = %i\n", s_config.dynamicColors );
    fprintf( f, "forceColors = %i\n", (int)s_config.forceColors );
    fprintf( f, "shortenName = %i\n", s_config.shortenName );

    fprintf( f, "\n[memory]\n" );
    fprintf( f, "limit = %i\n", (int)s_config.memoryLimit );
    fprintf( f, "percent = %i\n", s_config.memoryLimitPercent );

    fprintf( f, "\n[achievements]\n" );
    fprintf( f, "enabled = %i\n", (int)s_config.achievements );
    fprintf( f, "asked = %i\n", (int)s_config.achievementsAsked );

    fclose( f );
    return true;
}

static void ScaleChanged( float scale )
{
    if ( dpiScaleOverriddenFromEnv ) return;
    if ( dpiScale == scale ) return;

    dpiScale = scale;
    SetupDPIScale();
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
        try
        {
            initFileOpen = std::unique_ptr<tracy::FileRead>( tracy::FileRead::Open( argv[1] ) );
        }
        catch( const tracy::UnsupportedVersion& e )
        {
            fprintf( stderr, "The file you are trying to open is from the future version.\n" );
            exit( 1 );
        }
        catch( const tracy::NotTracyDump& e )
        {
            fprintf( stderr, "The file you are trying to open is not a tracy dump.\n" );
            exit( 1 );
        }
        catch( const tracy::LegacyVersion& e )
        {
            fprintf( stderr, "The file you are trying to open is from a legacy version.\n" );
            exit( 1 );
        }
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
    tracy::AchievementsMgr achievements;

    connHist = &connHistory;
    filt = &filters;
    s_achievements = &achievements;

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
    Backend backend( title, DrawContents, ScaleChanged, IsBusy, &mainThreadTasks );
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
        if( cnv != 0 )
        {
            dpiScale = cnv;
            dpiScaleOverriddenFromEnv = true;
        }
    }

    s_achievements->Achieve( "achievementsIntro" );

    SetupDPIScale();

    tracy::UpdateTextureRGBAMips( zigzagTex, (void**)zigzagPx, zigzagX, zigzagY, 6 );
    for( auto& v : zigzagPx ) free( v );

    if( initFileOpen )
    {
        view = std::make_unique<tracy::View>( RunOnMainThread, *initFileOpen, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
        initFileOpen.reset();
    }
    else if( connectTo )
    {
        view = std::make_unique<tracy::View>( RunOnMainThread, connectTo, port, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
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

static void TextComment( const char* str )
{
    ImGui::SameLine();
    ImGui::PushFont( s_smallFont );
    ImGui::AlignTextToFramePadding();
    tracy::TextDisabledUnformatted( str );
    ImGui::PopFont();
}

static void DrawAchievements( tracy::data::AchievementItem** items )
{
    while( *items )
    {
        auto& it = *items++;
        if( it->unlockTime > 0 )
        {
            if( it->doneTime > 0 ) ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
            bool isSelected = s_achievementItem == it;
            if( isSelected )
            {
                if( !it->hideNew ) it->hideNew = true;
                if( !it->hideCompleted && it->doneTime > 0 ) it->hideCompleted = true;
            }
            if( ImGui::Selectable( it->name, isSelected ) )
            {
                s_achievementItem = it;
            }
            if( it->doneTime > 0 ) ImGui::PopStyleColor();
            if( !it->hideNew )
            {
                ImGui::SameLine();
                tracy::TextColoredUnformatted( 0xFF4488FF, ICON_FA_CIRCLE_EXCLAMATION );
            }
            if( !it->hideCompleted && it->doneTime > 0 )
            {
                ImGui::SameLine();
                tracy::TextColoredUnformatted( 0xFF44FF44, ICON_FA_CIRCLE_CHECK );
            }
            if( it->items )
            {
                ImGui::Indent();
                DrawAchievements( it->items );
                ImGui::Unindent();
            }
        }
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

    const bool achievementsAttention = s_config.achievements ? s_achievements->NeedsAttention() : false;

    static int activeFrames = 3;
    if( tracy::WasActive() || !clients.empty() || ( view && view->WasActive() ) || achievementsAttention )
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
        if( dpiChanged == 0 )
        {
            ImGui::SameLine( ImGui::GetWindowContentRegionMax().x - ImGui::CalcTextSize( ICON_FA_WRENCH ).x - ImGui::GetStyle().FramePadding.x * 2 );
            if( ImGui::Button( ICON_FA_WRENCH ) )
            {
                ImGui::OpenPopup( "About Tracy" );
            }
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
            tracy::TextDisabledUnformatted( "Additional authors listed in git history." );
            ImGui::Separator();
            if( ImGui::TreeNode( ICON_FA_TOOLBOX " Global settings" ) )
            {
                s_achievements->Achieve( "globalSettings" );

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
                if( ImGui::Checkbox( "Reduce render rate when focus is lost", &s_config.focusLostLimit ) ) SaveConfig();

                ImGui::Spacing();
                ImGui::TextUnformatted( "Target FPS" );
                ImGui::SameLine();
                tracy::DrawHelpMarker( "The default target frame rate for your application. Frames displayed in the frame time graph will be colored accordingly if they are within the target frame rate. This can be adjusted later for each individual trace." );
                ImGui::SameLine();
                int tmp = s_config.targetFps;
                ImGui::SetNextItemWidth( 90 * dpiScale );
                if( ImGui::InputInt( "##targetfps", &tmp ) ) { s_config.targetFps = std::clamp( tmp, 1, 9999 ); SaveConfig(); }

                ImGui::Spacing();
                ImGui::TextUnformatted( ICON_FA_PALETTE " Zone colors" );
                ImGui::SameLine();
                tracy::SmallCheckbox( "Ignore custom", &s_config.forceColors );
                ImGui::Indent();
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::RadioButton( "Static", &s_config.dynamicColors, 0 );
                ImGui::RadioButton( "Thread dynamic", &s_config.dynamicColors, 1 );
                ImGui::RadioButton( "Source location dynamic", &s_config.dynamicColors, 2 );
                ImGui::PopStyleVar();
                ImGui::Unindent();
                ImGui::TextUnformatted( ICON_FA_RULER_HORIZONTAL " Zone name shortening" );
                ImGui::Indent();
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::RadioButton( "Disabled", &s_config.shortenName, (uint8_t)tracy::ShortenName::Never );
                ImGui::RadioButton( "Minimal length", &s_config.shortenName, (uint8_t)tracy::ShortenName::Always );
                ImGui::RadioButton( "Only normalize", &s_config.shortenName, (uint8_t)tracy::ShortenName::OnlyNormalize );
                ImGui::RadioButton( "As needed", &s_config.shortenName, (uint8_t)tracy::ShortenName::NoSpace );
                ImGui::RadioButton( "As needed + normalize", &s_config.shortenName, (uint8_t)tracy::ShortenName::NoSpaceAndNormalize );
                ImGui::PopStyleVar();
                ImGui::Unindent();

                if( s_totalMem == 0 )
                {
                    ImGui::BeginDisabled();
                    s_config.memoryLimit = false;
                }

                ImGui::Spacing();
                if( ImGui::Checkbox( "Memory limit", &s_config.memoryLimit ) ) SaveConfig();
                ImGui::SameLine();
                tracy::DrawHelpMarker( "When enabled, profiler will stop recording data when memory usage exceeds the specified percentage of available memory. Values greater than 100% will rely on swap. You need to make sure that memory is actually available." );
                ImGui::SameLine();
                ImGui::SetNextItemWidth( 70 * dpiScale );
                if( ImGui::InputInt( "##memorylimit", &s_config.memoryLimitPercent ) ) { s_config.memoryLimitPercent = std::clamp( s_config.memoryLimitPercent, 1, 999 ); SaveConfig(); }
                ImGui::SameLine();
                ImGui::TextUnformatted( "%" );
                if( s_totalMem != 0 )
                {
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", tracy::MemSizeToString( s_totalMem * s_config.memoryLimitPercent / 100 ) );
                }
                else
                {
                    ImGui::EndDisabled();
                }

                ImGui::Spacing();
                if( ImGui::Checkbox( "Enable achievements", &s_config.achievements ) ) SaveConfig();

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
            if( ImGui::Selectable( ICON_FA_VIDEO " An Introduction to Tracy Profiler in C++ - Marcos Slomp - CppCon 2023" ) )
            {
                tracy::OpenWebpage( "https://youtu.be/ghXk3Bk5F2U?t=37" );
            }
            ImGui::Separator();
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.8" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=30wpRpHTTag" );
            }
            TextComment( "2022-03-28" );
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.7" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=_hU7vw00MZ4" );
            }
            TextComment( "2020-06-11" );
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.6" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=uJkrFgriuOo" );
            }
            TextComment( "2019-11-17" );
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.5" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=P6E7qLMmzTQ" );
            }
            TextComment( "2019-08-10" );
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.4" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=eAkgkaO8B9o" );
            }
            TextComment( "2018-10-09" );
            if( ImGui::Selectable( ICON_FA_VIDEO " New features in v0.3" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=3SXpDpDh2Uo" );
            }
            TextComment( "2018-07-03" );
            if( ImGui::Selectable( ICON_FA_VIDEO " Overview of v0.2" ) )
            {
                tracy::OpenWebpage( "https://www.youtube.com/watch?v=fB5B46lbapc" );
            }
            TextComment( "2018-03-25" );
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
                view = std::make_unique<tracy::View>( RunOnMainThread, addrPart.c_str(), portPart, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
            }
            else
            {
                view = std::make_unique<tracy::View>( RunOnMainThread, addr, port, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
            }
        }
        if( s_config.memoryLimit )
        {
            ImGui::SameLine();
            tracy::TextColoredUnformatted( 0xFF00FFFF, ICON_FA_TRIANGLE_EXCLAMATION );
            tracy::TooltipIfHovered( "Memory limit is active" );
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
                                view = std::make_unique<tracy::View>( RunOnMainThread, *f, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
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
                            catch( const tracy::LoadFailure& e )
                            {
                                badVer.state = tracy::BadVersionState::LoadFailure;
                                badVer.msg = e.msg;
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
#endif

        if( badVer.state != tracy::BadVersionState::Ok )
        {
            if( loadThread.joinable() ) { loadThread.join(); }
            tracy::BadVersion( badVer, s_bigFont );
        }

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
                    view = std::make_unique<tracy::View>( RunOnMainThread, v.second.address.c_str(), v.second.port, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
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
            view = std::make_unique<tracy::View>( RunOnMainThread, reconnectAddr.c_str(), reconnectPort, s_fixedWidth, s_smallFont, s_bigFont, SetWindowTitleCallback, SetupScaleCallback, AttentionCallback, s_config, s_achievements );
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

#ifndef __EMSCRIPTEN__
    if( !s_config.achievementsAsked )
    {
        s_config.achievementsAsked = true;
        ImGui::OpenPopup( ICON_FA_STAR " Achievements" );
    }
#endif

    if( ImGui::BeginPopupModal( ICON_FA_STAR " Achievements", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::TextUnformatted( "Tracy Profiler is a complex tool with many features. It" );
        ImGui::TextUnformatted( "can be difficult to discover all of them on your own." );
        ImGui::TextUnformatted( "The Achievements system will guide you through the" );
        ImGui::TextUnformatted( "main features and teach you how to use them in an" );
        ImGui::TextUnformatted( "easy-to-handle manner." );
        ImGui::Separator();
        ImGui::TextUnformatted( "Would you like to enable achievements?" );
        ImGui::PushFont( s_smallFont );
        tracy::TextDisabledUnformatted( "You can change this setting later in the global settings." );
        ImGui::PopFont();
        ImGui::Separator();
        if( ImGui::Button( "Yes" ) )
        {
            s_config.achievements = true;
            SaveConfig();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if( ImGui::Button( "No" ) )
        {
            s_config.achievements = false;
            SaveConfig();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if( s_config.achievements )
    {
        ImGui::PushStyleVar( ImGuiStyleVar_WindowRounding, 16 * dpiScale );

        ImGui::PushFont( s_bigFont );
        const auto starSize = ImGui::CalcTextSize( ICON_FA_STAR );
        ImGui::PopFont();

        static int animStage = 0;
        static float animProgress = 0;
        static bool showAchievements = false;
        static float openTimeLeft = 0;

        float aSize = 0;
        const auto aItem = s_achievements->GetNextQueue();

        if( aItem )
        {
            aSize = ImGui::CalcTextSize( aItem->name ).x + ImGui::GetStyle().ItemSpacing.x + ImGui::GetStyle().WindowPadding.x * 0.5f;
            if( animStage == 0 )
            {
                animStage = 1;
            }
        }

        if( animStage > 0 )
        {
            tracy::s_wasActive = true;

            if( animStage == 1 )
            {
                animProgress = std::min( animProgress + ImGui::GetIO().DeltaTime / 0.3f, 1.f );
                if( animProgress == 1 )
                {
                    animStage = 2;
                    openTimeLeft = 8;
                }
                tracy::s_wasActive = true;
            }
            else if( animStage == 3 )
            {
                animProgress = std::max( animProgress - ImGui::GetIO().DeltaTime / 0.3f, 0.f );
                if( animProgress == 0 )
                {
                    s_achievements->PopQueue();
                    animStage = 0;
                }
            }
        }

        ImGui::SetNextWindowPos( ImVec2( display_w - starSize.x - ImGui::GetStyle().WindowPadding.x * 1.5f - aSize * smoothstep( animProgress ), display_h - starSize.y * 2 - ImGui::GetStyle().WindowPadding.y * 2 ) );
        ImGui::SetNextWindowSize( ImVec2( starSize.x + aSize + 100, starSize.y + ImGui::GetStyle().WindowPadding.y * 2 ) );
        ImGui::Begin( "###achievements", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_Tooltip );

        const auto cursor = ImGui::GetCursorPos();
        const auto cursorScreen = ImGui::GetCursorScreenPos();
        uint32_t color = 0xFF888888;
        if( achievementsAttention && !showAchievements )
        {
            const auto t = sin( ImGui::GetTime() * 4 ) * 0.5f + 0.5f;
            const auto c0 = uint32_t( std::lerp( 0x88, 0x00, t ) );
            const auto c1 = uint32_t( std::lerp( 0x88, 0xFF, t ) );
            color = 0xFF000000 | ( c0 << 16 ) | ( c1 << 8 ) | c1;
        }
        if( ( animStage == 0 || animStage == 2 ) && ImGui::IsMouseHoveringRect( cursorScreen - ImVec2( dpiScale * 2, dpiScale * 2 ), cursorScreen + starSize + ImVec2( dpiScale * 4, dpiScale * 4 ) ) )
        {
            color = 0xFFFFFFFF;
            if( ImGui::IsMouseClicked( 0 ) )
            {
                if( animStage == 0 )
                {
                    showAchievements = !showAchievements;
                }
                else
                {
                    showAchievements = true;
                    animStage = 3;
                    s_achievementItem = aItem;
                }
            }
        }
        ImGui::PushFont( s_bigFont );
        tracy::TextColoredUnformatted( color, ICON_FA_STAR );
        ImGui::PopFont();

        if( aItem )
        {
            ImGui::SameLine();
            const auto dismiss = ImGui::GetCursorScreenPos();
            const auto th = ImGui::GetTextLineHeight();
            ImGui::SetCursorPosY( cursor.y - th * 0.175f );
            ImGui::TextUnformatted( aItem->name );
            ImGui::PushFont( s_smallFont );
            ImGui::SetCursorPos( cursor + ImVec2( starSize.x + ImGui::GetStyle().ItemSpacing.x, th ) );
            tracy::TextDisabledUnformatted( "Click to open" );
            ImGui::PopFont();
            if( animStage == 2 )
            {
                if( ImGui::IsMouseHoveringRect( dismiss - ImVec2( 0, dpiScale * 6 ), dismiss + ImVec2( aSize, th * 1.5f + dpiScale * 4 ) ) && ImGui::IsMouseClicked( 0 ) )
                {
                    s_achievementItem = aItem;
                    s_switchAchievementCategory = true;
                    showAchievements = true;
                    animStage = 3;
                }
                if( !aItem->keepOpen )
                {
                    openTimeLeft -= ImGui::GetIO().DeltaTime;
                    if( openTimeLeft < 0 ) animStage = 3;
                }
            }
        }

        ImGui::End();
        ImGui::PopStyleVar();

        if( showAchievements )
        {
            const tracy::data::AchievementCategory* targetCategory = nullptr;
            if( s_switchAchievementCategory )
            {
                s_switchAchievementCategory = false;
                assert( s_achievementItem );
                targetCategory = s_achievements->GetCategoryForAchievement( s_achievementItem->id );
            }

            ImGui::SetNextWindowSize( ImVec2( 700 * dpiScale, 450 * dpiScale ), ImGuiCond_FirstUseEver );
            ImGui::Begin( "Achievements List", &showAchievements, ImGuiWindowFlags_NoDocking );
            ImGui::BeginTabBar( "###categories" );
            auto categories = s_achievements->GetCategories();
            while( *categories )
            {
                auto& c = *categories++;
                if( c->unlockTime > 0 )
                {
                    char tmp[256];
                    if( s_achievements->CategoryNeedsAttention( c->id ) )
                    {
                        snprintf( tmp, 256, ICON_FA_CIRCLE_EXCLAMATION " %s###%s", c->name, c->id );
                    }
                    else
                    {
                        snprintf( tmp, 256, "%s###%s", c->name, c->id );
                    }
                    ImGuiTabItemFlags flags = 0;
                    if( targetCategory == c ) flags |= ImGuiTabItemFlags_SetSelected;
                    if( ImGui::BeginTabItem( tmp, nullptr, flags ) )
                    {
                        ImGui::Columns( 2 );
                        ImGui::SetColumnWidth( 0, 300 * dpiScale );
                        DrawAchievements( c->items );
                        ImGui::NextColumn();
                        if( s_achievementItem )
                        {
                            const tracy::data::ctx ctx = { s_bigFont, s_smallFont, s_fixedWidth };
                            s_achievementItem->description( ctx );
                        }
                        ImGui::EndColumns();
                        ImGui::EndTabItem();
                    }
                }
            }
            ImGui::EndTabBar();
            ImGui::End();
        }
    }

    bptr->EndFrame();
    if( dpiChanged > 0 ) dpiChanged--;
}
