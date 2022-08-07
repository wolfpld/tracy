#ifdef _MSC_VER
#  pragma warning( disable: 4267 )  // conversion from don't care to whatever, possible loss of data
#endif

#ifdef __MINGW32__
#  define __STDC_FORMAT_MACROS
#endif
#include <algorithm>
#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <mutex>

#include "imgui.h"

#include "TracyFileRead.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracySourceView.hpp"
#include "TracyTexture.hpp"
#include "TracyView.hpp"
#include "../public/common/TracyStackFrames.hpp"

#include "imgui_internal.h"

#ifdef _WIN32
#  include <windows.h>
#elif defined __linux__
#  include <sys/sysinfo.h>
#elif defined __APPLE__ || defined BSD
#  include <sys/types.h>
#  include <sys/sysctl.h>
#endif

#include "IconsFontAwesome5.h"

#ifndef M_PI_2
#define M_PI_2 1.57079632679489661923
#endif

namespace tracy
{

double s_time = 0;

static View* s_instance = nullptr;

View::View( void(*cbMainThread)(std::function<void()>, bool), const char* addr, uint16_t port, ImFont* fixedWidth, ImFont* smallFont, ImFont* bigFont, SetTitleCallback stcb, GetWindowCallback gwcb, SetScaleCallback sscb )
    : m_worker( addr, port )
    , m_staticView( false )
    , m_viewMode( ViewMode::LastFrames )
    , m_viewModeHeuristicTry( true )
    , m_forceConnectionPopup( true, true )
    , m_frames( nullptr )
    , m_messagesScrollBottom( true )
    , m_reactToCrash( true )
    , m_reactToLostConnection( true )
    , m_smallFont( smallFont )
    , m_bigFont( bigFont )
    , m_fixedFont( fixedWidth )
    , m_stcb( stcb )
    , m_gwcb( gwcb )
    , m_sscb( sscb )
    , m_userData()
    , m_cbMainThread( cbMainThread )
{
    assert( s_instance == nullptr );
    s_instance = this;

    InitMemory();
    InitTextEditor( fixedWidth );
}

View::View( void(*cbMainThread)(std::function<void()>, bool), FileRead& f, ImFont* fixedWidth, ImFont* smallFont, ImFont* bigFont, SetTitleCallback stcb, GetWindowCallback gwcb, SetScaleCallback sscb )
    : m_worker( f )
    , m_filename( f.GetFilename() )
    , m_staticView( true )
    , m_viewMode( ViewMode::Paused )
    , m_frames( m_worker.GetFramesBase() )
    , m_messagesScrollBottom( false )
    , m_smallFont( smallFont )
    , m_bigFont( bigFont )
    , m_fixedFont( fixedWidth )
    , m_stcb( stcb )
    , m_gwcb( gwcb )
    , m_sscb( sscb )
    , m_userData( m_worker.GetCaptureProgram().c_str(), m_worker.GetCaptureTime() )
    , m_cbMainThread( cbMainThread )
{
    assert( s_instance == nullptr );
    s_instance = this;

    m_notificationTime = 4;
    m_notificationText = std::string( "Trace loaded in " ) + TimeToString( m_worker.GetLoadTime() );

    InitMemory();
    InitTextEditor( fixedWidth );
    SetViewToLastFrames();
    m_userData.StateShouldBePreserved();
    m_userData.LoadState( m_vd );
    m_userData.LoadAnnotations( m_annotations );
    m_sourceRegexValid = m_userData.LoadSourceSubstitutions( m_sourceSubstitutions );

    if( m_worker.GetCallstackFrameCount() == 0 ) m_showUnknownFrames = false;
    if( m_worker.GetCallstackSampleCount() == 0 ) m_showAllSymbols = true;
}

View::~View()
{
    m_worker.Shutdown();

    m_userData.SaveState( m_vd );
    m_userData.SaveAnnotations( m_annotations );
    m_userData.SaveSourceSubstitutions( m_sourceSubstitutions );

    if( m_compare.loadThread.joinable() ) m_compare.loadThread.join();
    if( m_saveThread.joinable() ) m_saveThread.join();

    if( m_frameTexture ) FreeTexture( m_frameTexture, m_cbMainThread );
    if( m_playback.texture ) FreeTexture( m_playback.texture, m_cbMainThread );

    assert( s_instance != nullptr );
    s_instance = nullptr;
}

void View::InitMemory()
{
#ifdef _WIN32
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof( statex );
    GlobalMemoryStatusEx( &statex );
    m_totalMemory = statex.ullTotalPhys;
#elif defined __linux__
    struct sysinfo sysInfo;
    sysinfo( &sysInfo );
    m_totalMemory = sysInfo.totalram;
#elif defined __APPLE__
    size_t memSize;
    size_t sz = sizeof( memSize );
    sysctlbyname( "hw.memsize", &memSize, &sz, nullptr, 0 );
    m_totalMemory = memSize;
#elif defined BSD
    size_t memSize;
    size_t sz = sizeof( memSize );
    sysctlbyname( "hw.physmem", &memSize, &sz, nullptr, 0 );
    m_totalMemory = memSize;
#else
    m_totalMemory = 0;
#endif
}

void View::InitTextEditor( ImFont* font )
{
    m_sourceView = std::make_unique<SourceView>( m_gwcb );
    m_sourceViewFile = nullptr;
}

void View::ViewSource( const char* fileName, int line )
{
    assert( fileName );
    m_sourceViewFile = fileName;
    m_sourceView->OpenSource( fileName, line, *this, m_worker );
}

void View::ViewSymbol( const char* fileName, int line, uint64_t baseAddr, uint64_t symAddr )
{
    assert( fileName || symAddr );
    m_sourceViewFile = fileName ? fileName : (const char*)~uint64_t( 0 );
    m_sourceView->OpenSymbol( fileName, line, baseAddr, symAddr, m_worker, *this );
}

bool View::ViewDispatch( const char* fileName, int line, uint64_t symAddr )
{
    if( line == 0 )
    {
        fileName = nullptr;
    }
    else
    {
        if( !SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
        {
            fileName = nullptr;
            line = 0;
        }
    }
    if( symAddr == 0 )
    {
        if( line != 0 )
        {
            ViewSource( fileName, line );
            return true;
        }
        return false;
    }
    else
    {
        uint64_t baseAddr = 0;
        if( m_worker.HasSymbolCode( symAddr ) )
        {
            baseAddr = symAddr;
        }
        else
        {
            const auto parentAddr = m_worker.GetSymbolForAddress( symAddr );
            if( parentAddr != 0 && m_worker.HasSymbolCode( parentAddr ) )
            {
                baseAddr = parentAddr;
            }
        }
        if( baseAddr != 0 || line != 0 )
        {
            ViewSymbol( fileName, line, baseAddr, symAddr );
            return true;
        }
        return false;
    }
}

static const char* CompressionName[] = {
    "LZ4",
    "LZ4 HC",
    "LZ4 HC extreme",
    "Zstd",
    nullptr
};

static const char* CompressionDesc[] = {
    "Fastest save, fast load time, big file size",
    "Slow save, fastest load time, reasonable file size",
    "Very slow save, fastest load time, file smaller than LZ4 HC",
    "Configurable save time (fast-slowest), reasonable load time, smallest file size",
    nullptr
};

static_assert( sizeof( CompressionName ) == sizeof( CompressionDesc ), "Unmatched compression names and descriptions" );

bool View::Draw()
{
    HandshakeStatus status = (HandshakeStatus)s_instance->m_worker.GetHandshakeStatus();
    switch( status )
    {
    case HandshakeProtocolMismatch:
        ImGui::OpenPopup( "Protocol mismatch" );
        break;
    case HandshakeNotAvailable:
        ImGui::OpenPopup( "Client not ready" );
        break;
    case HandshakeDropped:
        ImGui::OpenPopup( "Client disconnected" );
        break;
    default:
        break;
    }

    const auto& failure = s_instance->m_worker.GetFailureType();
    if( failure != Worker::Failure::None )
    {
        ImGui::OpenPopup( "Instrumentation failure" );
    }

    if( ImGui::BeginPopupModal( "Protocol mismatch", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( s_instance->m_bigFont );
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::PopFont();
        ImGui::TextUnformatted( "The client you are trying to connect to uses incompatible protocol version.\nMake sure you are using the same Tracy version on both client and server." );
        ImGui::Separator();
        if( ImGui::Button( "My bad" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::SameLine();
        if( ImGui::Button( "Reconnect" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            s_instance->m_reconnectRequested = true;
            return false;
        }
        ImGui::EndPopup();
    }

    if( ImGui::BeginPopupModal( "Client not ready", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( s_instance->m_bigFont );
        TextCentered( ICON_FA_LIGHTBULB );
        ImGui::PopFont();
        ImGui::TextUnformatted( "The client you are trying to connect to is no longer able to sent profiling data,\nbecause another server was already connected to it.\nYou can do the following:\n\n  1. Restart the client application.\n  2. Rebuild the client application with on-demand mode enabled." );
        ImGui::Separator();
        if( ImGui::Button( "I understand" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::SameLine();
        if( ImGui::Button( "Reconnect" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            s_instance->m_reconnectRequested = true;
            return false;
        }
        ImGui::EndPopup();
    }

    if( ImGui::BeginPopupModal( "Client disconnected", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( s_instance->m_bigFont );
        TextCentered( ICON_FA_HANDSHAKE );
        ImGui::PopFont();
        ImGui::TextUnformatted( "The client you are trying to connect to has disconnected during the initial\nconnection handshake. Please check your network configuration." );
        ImGui::Separator();
        if( ImGui::Button( "Will do" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::SameLine();
        if( ImGui::Button( "Reconnect" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            s_instance->m_reconnectRequested = true;
            return false;
        }
        ImGui::EndPopup();
    }

    if( ImGui::BeginPopupModal( "Instrumentation failure", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        const auto& data = s_instance->m_worker.GetFailureData();
        ImGui::PushFont( s_instance->m_bigFont );
        TextCentered( ICON_FA_SKULL );
        ImGui::PopFont();
        ImGui::TextUnformatted( "Profiling session terminated due to improper instrumentation.\nPlease correct your program and try again." );
        ImGui::TextUnformatted( "Reason:" );
        ImGui::SameLine();
        ImGui::TextUnformatted( Worker::GetFailureString( failure ) );
        ImGui::Separator();
        if( data.srcloc != 0 )
        {
            const auto& srcloc = s_instance->m_worker.GetSourceLocation( data.srcloc );
            if( srcloc.name.active )
            {
                TextFocused( "Zone name:", s_instance->m_worker.GetString( srcloc.name ) );
            }
            TextFocused( "Function:", s_instance->m_worker.GetString( srcloc.function ) );
            TextDisabledUnformatted( "Location:" );
            ImGui::SameLine();
            ImGui::TextUnformatted( LocationToString( s_instance->m_worker.GetString( srcloc.file ), srcloc.line ) );
        }
        if( data.thread != 0 )
        {
            TextFocused( "Thread:", s_instance->m_worker.GetThreadName( data.thread ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( data.thread ) );
            if( s_instance->m_worker.IsThreadFiber( data.thread ) )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        if( !data.message.empty() )
        {
            TextFocused( "Context:", data.message.c_str() );
        }
        if( data.callstack != 0 )
        {
            if( ImGui::TreeNode( "Call stack" ) )
            {
                ImGui::BeginChild( "##callstackFailure", ImVec2( 1200, 500 ) );
                if( ImGui::BeginTable( "##callstack", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Borders ) )
                {
                    ImGui::TableSetupColumn( "Frame", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                    ImGui::TableSetupColumn( "Function" );
                    ImGui::TableSetupColumn( "Location" );
                    ImGui::TableSetupColumn( "Image" );
                    ImGui::TableHeadersRow();

                    auto& cs = s_instance->m_worker.GetCallstack( data.callstack );
                    int fidx = 0;
                    int bidx = 0;
                    for( auto& entry : cs )
                    {
                        auto frameData = s_instance->m_worker.GetCallstackFrame( entry );
                        if( !frameData )
                        {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::Text( "%i", fidx++ );
                            ImGui::TableNextColumn();
                            char buf[32];
                            sprintf( buf, "%p", (void*)s_instance->m_worker.GetCanonicalPointer( entry ) );
                            ImGui::TextUnformatted( buf );
                            if( ImGui::IsItemHovered() )
                            {
                                ImGui::BeginTooltip();
                                ImGui::TextUnformatted( "Click on entry to copy it to clipboard." );
                                ImGui::EndTooltip();
                                if( ImGui::IsItemClicked() )
                                {
                                    ImGui::SetClipboardText( buf );
                                }
                            }
                        }
                        else
                        {
                            const auto fsz = frameData->size;
                            for( uint8_t f=0; f<fsz; f++ )
                            {
                                const auto& frame = frameData->data[f];
                                auto txt = s_instance->m_worker.GetString( frame.name );

                                if( fidx == 0 && f != fsz-1 )
                                {
                                    auto test = s_tracyStackFrames;
                                    bool match = false;
                                    do
                                    {
                                        if( strcmp( txt, *test ) == 0 )
                                        {
                                            match = true;
                                            break;
                                        }
                                    }
                                    while( *++test );
                                    if( match ) continue;
                                }

                                bidx++;

                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                if( f == fsz-1 )
                                {
                                    ImGui::Text( "%i", fidx++ );
                                }
                                else
                                {
                                    TextDisabledUnformatted( "inline" );
                                }
                                ImGui::TableNextColumn();
                                {
                                    ImGui::PushTextWrapPos( 0.0f );
                                    if( txt[0] == '[' )
                                    {
                                        TextDisabledUnformatted( txt );
                                    }
                                    else
                                    {
                                        ImGui::TextUnformatted( txt );
                                    }
                                    ImGui::PopTextWrapPos();
                                }
                                if( ImGui::IsItemHovered() )
                                {
                                    ImGui::BeginTooltip();
                                    ImGui::TextUnformatted( "Click on entry to copy it to clipboard." );
                                    ImGui::EndTooltip();
                                    if( ImGui::IsItemClicked() )
                                    {
                                        ImGui::SetClipboardText( txt );
                                    }
                                }
                                ImGui::TableNextColumn();
                                ImGui::PushTextWrapPos( 0.0f );
                                txt = s_instance->m_worker.GetString( frame.file );
                                TextDisabledUnformatted( LocationToString( txt, frame.line ) );
                                if( ImGui::IsItemHovered() )
                                {
                                    ImGui::BeginTooltip();
                                    ImGui::TextUnformatted( "Click on entry to copy it to clipboard." );
                                    ImGui::EndTooltip();
                                    if( ImGui::IsItemClicked() )
                                    {
                                        ImGui::SetClipboardText( txt );
                                    }
                                }
                                ImGui::PopTextWrapPos();
                                ImGui::TableNextColumn();
                                if( frameData->imageName.Active() )
                                {
                                    TextDisabledUnformatted( s_instance->m_worker.GetString( frameData->imageName ) );
                                }
                            }
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::EndChild();
                ImGui::TreePop();
            }
        }
        ImGui::Separator();
        if( ImGui::Button( "I understand" ) )
        {
            ImGui::CloseCurrentPopup();
            s_instance->m_worker.ClearFailure();
        }
        ImGui::EndPopup();
    }

    bool saveFailed = false;
    if( !s_instance->m_filenameStaging.empty() )
    {
        ImGui::OpenPopup( "Save trace" );
    }
    if( ImGui::BeginPopupModal( "Save trace", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        assert( !s_instance->m_filenameStaging.empty() );
        auto fn = s_instance->m_filenameStaging.c_str();
        ImGui::PushFont( s_instance->m_bigFont );
        TextFocused( "Path:", fn );
        ImGui::PopFont();
        ImGui::Separator();

        static FileWrite::Compression comp = FileWrite::Compression::Fast;
        static int zlvl = 6;
        ImGui::TextUnformatted( ICON_FA_FILE_ARCHIVE " Trace compression" );
        ImGui::SameLine();
        TextDisabledUnformatted( "Can be changed later with the upgrade utility" );
        ImGui::Indent();
        int idx = 0;
        while( CompressionName[idx] )
        {
            if( ImGui::RadioButton( CompressionName[idx], (int)comp == idx ) ) comp = (FileWrite::Compression)idx;
            ImGui::SameLine();
            TextDisabledUnformatted( CompressionDesc[idx] );
            idx++;
        }
        ImGui::Unindent();
        ImGui::TextUnformatted( "Zstd level" );
        ImGui::SameLine();
        TextDisabledUnformatted( "Increasing level decreases file size, but increases save and load times" );
        ImGui::Indent();
        if( ImGui::SliderInt( "##zstd", &zlvl, 1, 22, "%d", ImGuiSliderFlags_AlwaysClamp ) )
        {
            comp = FileWrite::Compression::Zstd;
        }
        ImGui::Unindent();

        static bool buildDict = false;
        if( s_instance->m_worker.GetFrameImageCount() != 0 )
        {
            ImGui::Separator();
            ImGui::Checkbox( "Build frame images dictionary", &buildDict );
            ImGui::SameLine();
            TextDisabledUnformatted( "Decreases run-time memory requirements" );
        }

        ImGui::Separator();
        if( ImGui::Button( ICON_FA_SAVE " Save trace" ) )
        {
            saveFailed = !s_instance->Save( fn, comp, zlvl, buildDict );
            s_instance->m_filenameStaging.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if( ImGui::Button( "Cancel" ) )
        {
            s_instance->m_filenameStaging.clear();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if( saveFailed ) ImGui::OpenPopup( "Save failed" );
    if( ImGui::BeginPopupModal( "Save failed", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( s_instance->m_bigFont );
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::PopFont();
        ImGui::TextUnformatted( "Could not save trace at the specified location. Try again somewhere else." );
        ImGui::Separator();
        if( ImGui::Button( "Oh well" ) ) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    s_time += ImGui::GetIO().DeltaTime;
    return s_instance->DrawImpl();
}

static const char* MainWindowButtons[] = {
    ICON_FA_PLAY " Resume",
    ICON_FA_PAUSE " Pause",
    ICON_FA_SQUARE " Stopped"
};

enum { MainWindowButtonsCount = sizeof( MainWindowButtons ) / sizeof( *MainWindowButtons ) };

bool View::DrawImpl()
{
    if( !m_worker.HasData() )
    {
        bool keepOpen = true;
        char tmp[2048];
        sprintf( tmp, "%s###Connection", m_worker.GetAddr().c_str() );
        ImGui::Begin( tmp, &keepOpen, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoCollapse );
        ImGui::PushFont( m_bigFont );
        TextCentered( ICON_FA_WIFI );
        ImGui::PopFont();
        ImGui::TextUnformatted( "Waiting for connection..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return keepOpen;
    }

    if( !m_uarchSet )
    {
        m_uarchSet = true;
        m_sourceView->SetCpuId( m_worker.GetCpuId() );
    }
    if( !m_userData.Valid() ) m_userData.Init( m_worker.GetCaptureProgram().c_str(), m_worker.GetCaptureTime() );
    if( m_saveThreadState.load( std::memory_order_acquire ) == SaveThreadState::NeedsJoin )
    {
        m_saveThread.join();
        m_saveThreadState.store( SaveThreadState::Inert, std::memory_order_release );
        const auto src = m_srcFileBytes.load( std::memory_order_relaxed );
        const auto dst = m_dstFileBytes.load( std::memory_order_relaxed );
        m_notificationTime = 4;
        char buf[1024];
        sprintf( buf, "Trace size %s (%.2f%% ratio)", MemSizeToString( dst ), 100.f * dst / src );
        m_notificationText = buf;
    }

    const auto& io = ImGui::GetIO();

    assert( m_shortcut == ShortcutAction::None );
    if( io.KeyCtrl )
    {
        if( ImGui::IsKeyPressed( ImGuiKey_F ) )
        {
            m_findZone.show = true;
            m_shortcut = ShortcutAction::OpenFind;
        }
    }

    if( !m_frames ) m_frames = m_worker.GetFramesBase();

    const auto th = ImGui::GetTextLineHeight();
    float bw = 0;
    for( int i=0; i<MainWindowButtonsCount; i++ )
    {
        bw = std::max( bw, ImGui::CalcTextSize( MainWindowButtons[i] ).x );
    }
    bw += th;

    bool keepOpen = true;
    bool* keepOpenPtr = nullptr;
    (void)keepOpenPtr;
    if( m_staticView )
    {
        keepOpenPtr = &keepOpen;
    }

#ifndef TRACY_NO_ROOT_WINDOW
    if( !m_titleSet && m_stcb )
    {
        m_titleSet = true;
        m_stcb( m_worker.GetCaptureName().c_str() );
    }

    ImGuiViewport* viewport = ImGui::GetMainViewport();
    {
        auto& style = ImGui::GetStyle();
        const auto wrPrev = style.WindowRounding;
        const auto wbsPrev = style.WindowBorderSize;
        const auto wpPrev = style.WindowPadding;
        style.WindowRounding = 0.f;
        style.WindowBorderSize = 0.f;
        style.WindowPadding = ImVec2( 4.f, 4.f );
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.129f, 0.137f, 0.11f, 1.f );

        ImGui::SetNextWindowPos( viewport->Pos );
        ImGui::SetNextWindowSize( ImVec2( m_rootWidth, m_rootHeight ) );
        ImGui::SetNextWindowViewport( viewport->ID );
        ImGui::Begin( "Timeline view###Profiler", nullptr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoNavFocus );

        style.WindowRounding = wrPrev;
        style.WindowBorderSize = wbsPrev;
        style.WindowPadding = wpPrev;
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.11f, 0.11f, 0.08f, 1.f );
    }
#else
    char tmp[2048];
    sprintf( tmp, "%s###Profiler", m_worker.GetCaptureName().c_str() );
    ImGui::SetNextWindowSize( ImVec2( 1550, 800 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( tmp, keepOpenPtr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus );
#endif

    if( !m_staticView )
    {
        if( ImGui::Button( ICON_FA_WIFI ) || m_forceConnectionPopup )
        {
            if( m_forceConnectionPopup )
            {
                m_forceConnectionPopup.Decay( false );
                ImGui::SetNextWindowPos( viewport->Pos + ImGui::GetCursorPos() );
            }
            ImGui::OpenPopup( "TracyConnectionPopup" );
        }
        ImGui::SameLine();
        if( ImGui::BeginPopup( "TracyConnectionPopup" ) )
        {
            const bool wasDisconnectIssued = m_disconnectIssued;
            const bool discardData = !DrawConnection();
            const bool disconnectIssuedJustNow = m_disconnectIssued != wasDisconnectIssued;
            if( discardData ) keepOpen = false;
            if( disconnectIssuedJustNow || discardData ) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }
    std::lock_guard<std::mutex> lock( m_worker.GetDataLock() );
    m_worker.DoPostponedWork();
    if( !m_worker.IsDataStatic() )
    {
        if( m_worker.IsConnected() )
        {
            if( ImGui::Button( m_viewMode == ViewMode::Paused ? MainWindowButtons[0] : MainWindowButtons[1], ImVec2( bw, 0 ) ) )
            {
                if( m_viewMode != ViewMode::Paused )
                {
                    m_viewMode = ViewMode::Paused;
                    m_viewModeHeuristicTry = false;
                }
                else
                {
                    ImGui::OpenPopup( "viewMode" );
                }
            }
        }
        else
        {
            ImGui::BeginDisabled();
            ImGui::ButtonEx( MainWindowButtons[2], ImVec2( bw, 0 ) );
            ImGui::EndDisabled();
        }
        if( ImGui::BeginPopup( "viewMode" ) )
        {
            if( ImGui::Selectable( ICON_FA_SEARCH_PLUS " Newest three frames" ) )
            {
                m_viewMode = ViewMode::LastFrames;
            }
            if( ImGui::Selectable( ICON_FA_RULER_HORIZONTAL " Use current zoom level" ) )
            {
                m_viewMode = ViewMode::LastRange;
            }
            ImGui::EndPopup();
        }
        else if( m_viewModeHeuristicTry )
        {
            const auto lastTime = m_worker.GetLastTime();
            if( lastTime > 5*1000*1000*1000ll )
            {
                if( m_viewMode == ViewMode::LastFrames && m_worker.GetFrameCount( *m_worker.GetFramesBase() ) <= 2 )
                {
                    m_viewMode = ViewMode::LastRange;
                    ZoomToRange( lastTime - 5*1000*1000*1000ll, lastTime, false );
                }
                else
                {
                    m_viewModeHeuristicTry = false;
                }
            }
        }
    }
    else
    {
        ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f) );
        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f) );
        ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f) );
        if( ImGui::Button( ICON_FA_POWER_OFF ) ) keepOpen = false;
        ImGui::PopStyleColor( 3 );
    }
    ImGui::SameLine();
    ToggleButton( ICON_FA_COG " Options", m_showOptions );
    ImGui::SameLine();
    ToggleButton( ICON_FA_TAGS " Messages", m_showMessages );
    ImGui::SameLine();
    ToggleButton( ICON_FA_SEARCH " Find zone", m_findZone.show );
    ImGui::SameLine();
    ToggleButton( ICON_FA_SORT_AMOUNT_UP " Statistics", m_showStatistics );
    ImGui::SameLine();
    ToggleButton( ICON_FA_MEMORY " Memory", m_memInfo.show );
    ImGui::SameLine();
    ToggleButton( ICON_FA_BALANCE_SCALE " Compare", m_compare.show );
    ImGui::SameLine();
    ToggleButton( ICON_FA_FINGERPRINT " Info", m_showInfo );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_TOOLS ) ) ImGui::OpenPopup( "ToolsPopup" );
    if( ImGui::BeginPopup( "ToolsPopup" ) )
    {
        const auto ficnt = m_worker.GetFrameImageCount();
        if( ButtonDisablable( ICON_FA_PLAY " Playback", ficnt == 0 ) )
        {
            m_showPlayback = true;
        }
        const auto& ctd = m_worker.GetCpuThreadData();
        if( ButtonDisablable( ICON_FA_SLIDERS_H " CPU data", ctd.empty() ) )
        {
            m_showCpuDataWindow = true;
        }
        ToggleButton( ICON_FA_STICKY_NOTE " Annotations", m_showAnnotationList );
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
        const auto cscnt = m_worker.GetContextSwitchSampleCount();
        if( ButtonDisablable( ICON_FA_HOURGLASS_HALF " Wait stacks", cscnt == 0 ) )
        {
            m_showWaitStacks = true;
        }
        ImGui::EndPopup();
    }
    if( m_sscb )
    {
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_SEARCH_PLUS ) ) ImGui::OpenPopup( "ZoomPopup" );
        if( ImGui::BeginPopup( "ZoomPopup" ) )
        {
            if( ImGui::Button( "50%" ) )  m_sscb( 1.f/2,     m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "57%" ) )  m_sscb( 1.f/1.75f, m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "66%" ) )  m_sscb( 1.f/1.5f,  m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "80%" ) )  m_sscb( 1.f/1.25f, m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "100%" ) ) m_sscb( 1.f,       m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "125%" ) ) m_sscb( 1.25f,     m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "150%" ) ) m_sscb( 1.5f,      m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "175%" ) ) m_sscb( 1.75f,     m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "200%" ) ) m_sscb( 2.f,       m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "225%" ) ) m_sscb( 2.25f,     m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "250%" ) ) m_sscb( 2.5f,      m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "275%" ) ) m_sscb( 2.75f,     m_fixedFont, m_bigFont, m_smallFont );
            if( ImGui::Button( "300%" ) ) m_sscb( 3.f,       m_fixedFont, m_bigFont, m_smallFont );
            ImGui::EndPopup();
        }
    }
    ImGui::SameLine();
    if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) ) ZoomToPrevFrame();
    ImGui::SameLine();
    {
        const auto vis = Vis( m_frames ).visible;
        if( !vis )
        {
            ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
        }
        ImGui::Text( "%s: %s", GetFrameSetName( *m_frames ), RealToString( m_worker.GetFrameCount( *m_frames ) ) );
        if( !vis )
        {
            ImGui::PopStyleColor();
        }
        if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "GoToFramePopup" );
    }
    ImGui::SameLine();
    if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) ) ZoomToNextFrame();
    ImGui::SameLine();
    if( ImGui::BeginCombo( "##frameCombo", nullptr, ImGuiComboFlags_NoPreview ) )
    {
        auto& frames = m_worker.GetFrames();
        for( auto& fd : frames )
        {
            bool isSelected = m_frames == fd;
            if( ImGui::Selectable( GetFrameSetName( *fd ), isSelected ) )
            {
                m_frames = fd;
            }
            if( isSelected )
            {
                ImGui::SetItemDefaultFocus();
            }
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( fd->frames.size() ) );
        }
        ImGui::EndCombo();
    }
    if( ImGui::BeginPopup( "GoToFramePopup" ) )
    {
        static int frameNum = 1;
        const bool mainFrameSet = m_frames->name == 0;
        const auto numFrames = mainFrameSet ? m_frames->frames.size() - 1 : m_frames->frames.size();
        const auto frameOffset = mainFrameSet ? 0 : 1;
        ImGui::SetNextItemWidth( 120 * GetScale() );
        const bool clicked = ImGui::InputInt( "##goToFrame", &frameNum, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
        frameNum = std::min( std::max( frameNum, 1 ), int( numFrames ) );
        if( clicked ) ZoomToRange( m_worker.GetFrameBegin( *m_frames, frameNum - frameOffset ), m_worker.GetFrameEnd( *m_frames, frameNum - frameOffset ) );
        ImGui::EndPopup();
    }

    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        const auto targetLabelSize = ImGui::CalcTextSize( "WWWWWWW" ).x;

        auto cx = ImGui::GetCursorPosX();
        ImGui::Text( ICON_FA_EYE " %s", TimeToString( m_vd.zvEnd - m_vd.zvStart ) );
        TooltipIfHovered( "View span" );
        ImGui::SameLine();
        auto dx = ImGui::GetCursorPosX() - cx;
        if( dx < targetLabelSize ) ImGui::SameLine( cx + targetLabelSize );

        cx = ImGui::GetCursorPosX();
        ImGui::Text( ICON_FA_DATABASE " %s", TimeToString( m_worker.GetLastTime() ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "Time span" );
            ImGui::EndTooltip();
            if( ImGui::IsItemClicked( 2 ) )
            {
                ZoomToRange( 0, m_worker.GetLastTime() );
            }
        }
        ImGui::SameLine();
        dx = ImGui::GetCursorPosX() - cx;
        if( dx < targetLabelSize ) ImGui::SameLine( cx + targetLabelSize );

        cx = ImGui::GetCursorPosX();
        ImGui::Text( ICON_FA_MEMORY " %s", MemSizeToString( memUsage ) );
        TooltipIfHovered( "Profiler memory usage" );
        if( m_totalMemory != 0 )
        {
            ImGui::SameLine();
            const auto memUse = float( memUsage ) / m_totalMemory * 100;
            if( memUse < 80 )
            {
                ImGui::TextDisabled( "(%.2f%%)", memUse );
            }
            else
            {
                ImGui::TextColored( ImVec4( 1.f, 0.25f, 0.25f, 1.f ), "(%.2f%%)", memUse );
            }
        }
        ImGui::SameLine();
        dx = ImGui::GetCursorPosX() - cx;
        if( dx < targetLabelSize ) ImGui::SameLine( cx + targetLabelSize );
        ImGui::Spacing();
    }
    DrawNotificationArea();

    m_frameHover = -1;

    DrawFrames();

    const auto dockspaceId = ImGui::GetID( "tracyDockspace" );
    ImGui::DockSpace( dockspaceId, ImVec2( 0, 0 ), ImGuiDockNodeFlags_NoDockingInCentralNode );
    if( ImGuiDockNode* node = ImGui::DockBuilderGetCentralNode( dockspaceId ) )
    {
        node->LocalFlags |= ImGuiDockNodeFlags_NoTabBar;
    }
    ImGui::SetNextWindowDockID( dockspaceId );
    {
        auto& style = ImGui::GetStyle();
        const auto wpPrev = style.WindowPadding;
        style.WindowPadding = ImVec2( 1, 0 );
#ifndef TRACY_NO_ROOT_WINDOW
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.129f, 0.137f, 0.11f, 1.f );
#endif

        ImGui::Begin( "Work area", nullptr, ImGuiWindowFlags_NoNavFocus );

        style.WindowPadding = wpPrev;
#ifndef TRACY_NO_ROOT_WINDOW
        style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.11f, 0.11f, 0.08f, 1.f );
#endif
    }

    DrawTimeline();

    ImGui::End();
    ImGui::End();

    m_zoneHighlight = nullptr;
    m_gpuHighlight = nullptr;

    DrawInfoWindow();

    if( m_showOptions ) DrawOptions();
    if( m_showMessages ) DrawMessages();
    if( m_findZone.show ) DrawFindZone();
    if( m_showStatistics ) DrawStatistics();
    if( m_memInfo.show ) DrawMemory();
    if( m_memInfo.showAllocList ) DrawAllocList();
    if( m_compare.show ) DrawCompare();
    if( m_callstackInfoWindow != 0 ) DrawCallstackWindow();
    if( m_memoryAllocInfoWindow >= 0 ) DrawMemoryAllocWindow();
    if( m_showInfo ) DrawInfo();
    if( m_sourceViewFile ) DrawTextEditor();
    if( m_lockInfoWindow != InvalidId ) DrawLockInfoWindow();
    if( m_showPlayback ) DrawPlayback();
    if( m_showCpuDataWindow ) DrawCpuDataWindow();
    if( m_selectedAnnotation ) DrawSelectedAnnotation();
    if( m_showAnnotationList ) DrawAnnotationList();
    if( m_sampleParents.symAddr != 0 ) DrawSampleParents();
    if( m_showRanges ) DrawRanges();
    if( m_showWaitStacks ) DrawWaitStacks();

    if( m_setRangePopup.active )
    {
        m_setRangePopup.active = false;
        ImGui::OpenPopup( "SetZoneRange" );
    }
    if( ImGui::BeginPopup( "SetZoneRange" ) )
    {
        const auto s = std::min( m_setRangePopup.min, m_setRangePopup.max );
        const auto e = std::max( m_setRangePopup.min, m_setRangePopup.max );
        if( ImGui::Selectable( ICON_FA_SEARCH " Limit find zone time range" ) )
        {
            m_findZone.range.active = true;
            m_findZone.range.min = s;
            m_findZone.range.max = e;
        }
        if( ImGui::Selectable( ICON_FA_SORT_AMOUNT_UP " Limit statistics time range" ) )
        {
            m_statRange.active = true;
            m_statRange.min = s;
            m_statRange.max = e;
        }
        if( ImGui::Selectable( ICON_FA_HOURGLASS_HALF " Limit wait stacks range" ) )
        {
            m_waitStackRange.active = true;
            m_waitStackRange.min = s;
            m_waitStackRange.max = e;
        }
        if( ImGui::Selectable( ICON_FA_MEMORY " Limit memory range" ) )
        {
            m_memInfo.range.active = true;
            m_memInfo.range.min = s;
            m_memInfo.range.max = e;
        }
        ImGui::Separator();
        if( ImGui::Selectable( ICON_FA_STICKY_NOTE " Add annotation" ) )
        {
            AddAnnotation( s, e );
        }
        ImGui::EndPopup();
    }
    m_setRangePopupOpen = ImGui::IsPopupOpen( "SetZoneRange" );

    if( m_zoomAnim.active )
    {
        if( m_viewMode == ViewMode::LastRange )
        {
            const auto delta = m_worker.GetLastTime() - m_vd.zvEnd;
            if( delta != 0 )
            {
                m_zoomAnim.start0 += delta;
                m_zoomAnim.start1 += delta;
                m_zoomAnim.end0 += delta;
                m_zoomAnim.end1 += delta;
            }
        }
        m_zoomAnim.progress += io.DeltaTime * 3.33f;
        if( m_zoomAnim.progress >= 1.f )
        {
            m_zoomAnim.active = false;
            m_vd.zvStart = m_zoomAnim.start1;
            m_vd.zvEnd = m_zoomAnim.end1;
        }
        else
        {
            const auto v = sqrt( sin( M_PI_2 * m_zoomAnim.progress ) );
            m_vd.zvStart = int64_t( m_zoomAnim.start0 + ( m_zoomAnim.start1 - m_zoomAnim.start0 ) * v );
            m_vd.zvEnd = int64_t( m_zoomAnim.end0 + ( m_zoomAnim.end1 - m_zoomAnim.end0 ) * v );
        }
    }

    m_callstackBuzzAnim.Update( io.DeltaTime );
    m_sampleParentBuzzAnim.Update( io.DeltaTime );
    m_callstackTreeBuzzAnim.Update( io.DeltaTime );
    m_zoneinfoBuzzAnim.Update( io.DeltaTime );
    m_findZoneBuzzAnim.Update( io.DeltaTime );
    m_optionsLockBuzzAnim.Update( io.DeltaTime );
    m_lockInfoAnim.Update( io.DeltaTime );
    m_statBuzzAnim.Update( io.DeltaTime );

    if( m_firstFrame )
    {
        const auto now = std::chrono::high_resolution_clock::now();
        if( m_firstFrameTime.time_since_epoch().count() == 0 )
        {
            m_firstFrameTime = now;
        }
        else
        {
            if( std::chrono::duration_cast<std::chrono::milliseconds>( now - m_firstFrameTime ).count() > 500 )
            {
                m_firstFrame = false;
            }
        }
    }

    if( m_reactToCrash )
    {
        auto& crash = m_worker.GetCrashEvent();
        if( crash.thread != 0 )
        {
            m_reactToCrash = false;
            ImGui::OpenPopup( "Application crashed!" );
        }
    }
    if( ImGui::BeginPopupModal( "Application crashed!", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        auto& crash = m_worker.GetCrashEvent();
        assert( crash.thread != 0 );
        ImGui::TextUnformatted( ICON_FA_SKULL );
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF4444FF, "Application has crashed" );
        ImGui::SameLine();
        ImGui::TextUnformatted( ICON_FA_SKULL );
        ImGui::Separator();
        TextFocused( "Time:", TimeToString( crash.time ) );
        TextFocused( "Thread:", m_worker.GetThreadName( crash.thread ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( crash.thread ) );
        if( m_worker.IsThreadFiber( crash.thread ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        TextFocused( "Reason:", m_worker.GetString( crash.message ) );
        if( crash.callstack != 0 )
        {
            bool hilite = m_callstackInfoWindow == crash.callstack;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackInfoWindow = crash.callstack;
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
            if( ImGui::IsItemHovered() )
            {
                CallstackTooltip( crash.callstack );
            }
        }
        ImGui::Separator();
        if( ImGui::Button( ICON_FA_MICROSCOPE " Focus" ) ) CenterAtTime( crash.time );
        ImGui::SameLine();
        if( ImGui::Button( "Dismiss" ) ) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if( m_reactToLostConnection && !m_worker.IsConnected() )
    {
        m_reactToLostConnection = false;
        const auto inFlight = m_worker.GetSendInFlight();
        if( inFlight > 1 || ( inFlight == 1 && !m_worker.WasDisconnectIssued() ) )
        {
            ImGui::OpenPopup( "Connection lost!" );
        }
    }
    if( ImGui::BeginPopupModal( "Connection lost!", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( m_bigFont );
        TextCentered( ICON_FA_PLUG );
        ImGui::PopFont();
        ImGui::TextUnformatted(
            "Connection to the profiled application was lost\n"
            "before all required profiling data could be retrieved.\n"
            "This will result in missing source locations,\n"
            "unresolved stack frames, etc." );
        ImGui::Separator();
        if( ImGui::Button( "Dismiss" ) ) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    return keepOpen;
}

void View::DrawTextEditor()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1800 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    bool show = true;
    ImGui::Begin( "Source view", &show, ImGuiWindowFlags_NoScrollbar );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        m_sourceView->UpdateFont( m_fixedFont, m_smallFont );
        m_sourceView->Render( m_worker, *this );
    }
    ImGui::End();
    if( !show ) m_sourceViewFile = nullptr;
}

void View::CrashTooltip()
{
    auto& crash = m_worker.GetCrashEvent();
    ImGui::BeginTooltip();
    TextFocused( "Time:", TimeToString( crash.time ) );
    TextFocused( "Reason:", m_worker.GetString( crash.message ) );
    ImGui::EndTooltip();
}

void View::DrawSourceTooltip( const char* filename, uint32_t srcline, int before, int after, bool separateTooltip )
{
    if( !filename ) return;
    if( !SourceFileValid( filename, m_worker.GetCaptureTime(), *this, m_worker ) ) return;
    m_srcHintCache.Parse( filename, m_worker, *this );
    if( m_srcHintCache.empty() ) return;
    ImGui::PushStyleVar( ImGuiStyleVar_ItemSpacing, ImVec2( 0, 0 ) );
    if( separateTooltip ) ImGui::BeginTooltip();
    ImGui::PushFont( m_fixedFont );
    auto& lines = m_srcHintCache.get();
    const int start = std::max( 0, (int)srcline - ( before+1 ) );
    const int end = std::min<int>( m_srcHintCache.get().size(), srcline + after );
    bool first = true;
    int bottomEmpty = 0;
    for( int i=start; i<end; i++ )
    {
        auto& line = lines[i];
        if( line.begin == line.end )
        {
            if( !first ) bottomEmpty++;
        }
        else
        {
            first = false;
            while( bottomEmpty > 0 )
            {
                ImGui::TextUnformatted( "" );
                bottomEmpty--;
            }

            auto ptr = line.begin;
            auto it = line.tokens.begin();
            while( ptr < line.end )
            {
                if( it == line.tokens.end() )
                {
                    ImGui::TextUnformatted( ptr, line.end );
                    ImGui::SameLine( 0, 0 );
                    break;
                }
                if( ptr < it->begin )
                {
                    ImGui::TextUnformatted( ptr, it->begin );
                    ImGui::SameLine( 0, 0 );
                }
                TextColoredUnformatted( i == srcline-1 ? SyntaxColors[(int)it->color] : SyntaxColorsDimmed[(int)it->color], it->begin, it->end );
                ImGui::SameLine( 0, 0 );
                ptr = it->end;
                ++it;
            }
            ImGui::ItemSize( ImVec2( 0, 0 ), 0 );
        }
    }
    ImGui::PopFont();
    if( separateTooltip ) ImGui::EndTooltip();
    ImGui::PopStyleVar();
}

bool View::Save( const char* fn, FileWrite::Compression comp, int zlevel, bool buildDict )
{
    std::unique_ptr<FileWrite> f( FileWrite::Open( fn, comp, zlevel ) );
    if( !f ) return false;

    m_userData.StateShouldBePreserved();
    m_saveThreadState.store( SaveThreadState::Saving, std::memory_order_relaxed );
    m_saveThread = std::thread( [this, f{std::move( f )}, buildDict] {
        std::lock_guard<std::mutex> lock( m_worker.GetDataLock() );
        m_worker.Write( *f, buildDict );
        f->Finish();
        const auto stats = f->GetCompressionStatistics();
        m_srcFileBytes.store( stats.first, std::memory_order_relaxed );
        m_dstFileBytes.store( stats.second, std::memory_order_relaxed );
        m_saveThreadState.store( SaveThreadState::NeedsJoin, std::memory_order_release );
    } );

    return true;
}

}
