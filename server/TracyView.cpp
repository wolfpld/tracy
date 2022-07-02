#ifdef _MSC_VER
#  pragma warning( disable: 4267 )  // conversion from don't care to whatever, possible loss of data
#endif

#ifdef _WIN32
#  include <malloc.h>
#else
#  include <alloca.h>
#endif

#ifdef __MINGW32__
#  define __STDC_FORMAT_MACROS
#endif
#include <algorithm>
#include <assert.h>
#include <chrono>
#include <inttypes.h>
#include <limits>
#include <math.h>
#include <mutex>
#include <numeric>
#include <sstream>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include "tracy_pdqsort.h"
#include "TracyColor.hpp"
#include "TracyFileRead.hpp"
#include "TracyFilesystem.hpp"
#include "TracyMouse.hpp"
#include "TracyPopcnt.hpp"
#include "TracyPrint.hpp"
#include "TracySort.hpp"
#include "TracySourceView.hpp"
#include "TracyView.hpp"
#include "../common/TracyStackFrames.hpp"

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

static inline uint64_t GetThreadBit( uint8_t thread )
{
    return uint64_t( 1 ) << thread;
}

static inline bool IsThreadWaiting( uint64_t bitlist, uint64_t threadBit )
{
    return ( bitlist & threadBit ) != 0;
}

static inline bool AreOtherWaiting( uint64_t bitlist, uint64_t threadBit )
{
    return ( bitlist & ~threadBit ) != 0;
}


enum { MinVisSize = 3 };
enum { MinFrameSize = 5 };

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

void View::DrawHelpMarker( const char* desc ) const
{
    TextDisabledUnformatted( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        const auto ty = ImGui::GetTextLineHeight();
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos( 450.0f * ty / 15.f );
        ImGui::TextUnformatted( desc );
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void View::AddAnnotation( int64_t start, int64_t end )
{
    auto ann = std::make_unique<Annotation>();
    ann->range.active = true;
    ann->range.min = start;
    ann->range.max = end;
    ann->color = 0x888888;
    m_selectedAnnotation = ann.get();
    m_annotations.emplace_back( std::move( ann ) );
    pdqsort_branchless( m_annotations.begin(), m_annotations.end(), []( const auto& lhs, const auto& rhs ) { return lhs->range.min < rhs->range.min; } );
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
        ImGui::Text( "%s: %s", m_frames->name == 0 ? "Frames" : m_worker.GetString( m_frames->name ), RealToString( m_worker.GetFrameCount( *m_frames ) ) );
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
            if( ImGui::Selectable( fd->name == 0 ? "Frames" : m_worker.GetString( fd->name ), isSelected ) )
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

    DrawZones();

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

void View::HandleRange( Range& range, int64_t timespan, const ImVec2& wpos, float w )
{
    if( !IsMouseDown( 0 ) ) range.modMin = range.modMax = false;
    if( !range.active ) return;
    auto& io = ImGui::GetIO();

    if( range.modMin )
    {
        const auto nspx = double( timespan ) / w;
        range.min = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
        range.hiMin = true;
        ConsumeMouseEvents( 0 );
        ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
        if( range.min > range.max )
        {
            std::swap( range.min, range.max );
            std::swap( range.hiMin, range.hiMax );
            std::swap( range.modMin, range.modMax );
        }
    }
    else if( range.modMax )
    {
        const auto nspx = double( timespan ) / w;
        range.max = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
        range.hiMax = true;
        ConsumeMouseEvents( 0 );
        ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
        if( range.min > range.max )
        {
            std::swap( range.min, range.max );
            std::swap( range.hiMin, range.hiMax );
            std::swap( range.modMin, range.modMax );
        }
    }
    else
    {
        const auto pxns = w / double( timespan );
        const auto px0 = ( range.min - m_vd.zvStart ) * pxns;
        if( abs( px0 - ( io.MousePos.x - wpos.x ) ) < 3 )
        {
            range.hiMin = true;
            ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
            if( IsMouseClicked( 0 ) )
            {
                range.modMin = true;
                range.min = m_vd.zvStart + ( io.MousePos.x - wpos.x ) / pxns;
                ConsumeMouseEvents( 0 );
                if( range.min > range.max )
                {
                    std::swap( range.min, range.max );
                    std::swap( range.hiMin, range.hiMax );
                    std::swap( range.modMin, range.modMax );
                }
            }
        }
        else
        {
            const auto px1 = ( range.max - m_vd.zvStart ) * pxns;
            if( abs( px1 - ( io.MousePos.x - wpos.x ) ) < 3 )
            {
                range.hiMax = true;
                ImGui::SetMouseCursor( ImGuiMouseCursor_ResizeEW );
                if( IsMouseClicked( 0 ) )
                {
                    range.modMax = true;
                    range.max = m_vd.zvStart + ( io.MousePos.x - wpos.x ) / pxns;
                    ConsumeMouseEvents( 0 );
                    if( range.min > range.max )
                    {
                        std::swap( range.min, range.max );
                        std::swap( range.hiMin, range.hiMax );
                        std::swap( range.modMin, range.modMax );
                    }
                }
            }
        }
    }
}

void View::HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns )
{
    assert( timespan > 0 );
    auto& io = ImGui::GetIO();

    const auto nspx = double( timespan ) / w;

    if( IsMouseClicked( 0 ) )
    {
        m_highlight.active = true;
        m_highlight.start = m_highlight.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( IsMouseDragging( 0 ) )
    {
        m_highlight.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( m_highlight.active )
    {
        if( ImGui::GetIO().KeyCtrl && m_highlight.start != m_highlight.end )
        {
            m_setRangePopup = RangeSlim { m_highlight.start, m_highlight.end, true };
        }
        m_highlight.active = false;
    }

    if( IsMouseClicked( 2 ) )
    {
        m_highlightZoom.active = true;
        m_highlightZoom.start = m_highlightZoom.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( IsMouseDragging( 2 ) )
    {
        m_highlightZoom.end = m_vd.zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( m_highlightZoom.active )
    {
        if( m_highlightZoom.start != m_highlightZoom.end )
        {
            const auto s = std::min( m_highlightZoom.start, m_highlightZoom.end );
            const auto e = std::max( m_highlightZoom.start, m_highlightZoom.end );

            // ZoomToRange disables m_highlightZoom.active
            if( io.KeyCtrl )
            {
                const auto tsOld = m_vd.zvEnd - m_vd.zvStart;
                const auto tsNew = e - s;
                const auto mul = double( tsOld ) / tsNew;
                const auto left = s - m_vd.zvStart;
                const auto right = m_vd.zvEnd - e;

                auto start = m_vd.zvStart - left * mul;
                auto end = m_vd.zvEnd + right * mul;
                if( end - start > 1000ll * 1000 * 1000 * 60 * 60 * 24 * 10 )
                {
                    start = -1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                    end = 1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                }

                ZoomToRange( start, end );
            }
            else
            {
                ZoomToRange( s, e );
            }
        }
        else
        {
            m_highlightZoom.active = false;
        }
    }

    const auto hwheel_delta = io.MouseWheelH * 100.f;
    if( IsMouseDragging( 1 ) || hwheel_delta != 0 )
    {
        m_viewMode = ViewMode::Paused;
        m_viewModeHeuristicTry = false;
        m_zoomAnim.active = false;
        if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;
        const auto delta = GetMouseDragDelta( 1 );
        m_yDelta = delta.y;
        const auto dpx = int64_t( (delta.x * nspx) + (hwheel_delta * nspx));
        if( dpx != 0 )
        {
            m_vd.zvStart -= dpx;
            m_vd.zvEnd -= dpx;
            io.MouseClickedPos[1].x = io.MousePos.x;

            if( m_vd.zvStart < -1000ll * 1000 * 1000 * 60 * 60 * 24 * 5 )
            {
                const auto range = m_vd.zvEnd - m_vd.zvStart;
                m_vd.zvStart = -1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                m_vd.zvEnd = m_vd.zvStart + range;
            }
            else if( m_vd.zvEnd > 1000ll * 1000 * 1000 * 60 * 60 * 24 * 5 )
            {
                const auto range = m_vd.zvEnd - m_vd.zvStart;
                m_vd.zvEnd = 1000ll * 1000 * 1000 * 60 * 60 * 24 * 5;
                m_vd.zvStart = m_vd.zvEnd - range;
            }
        }
    }

    const auto wheel = io.MouseWheel;
    if( wheel != 0 )
    {
        if( m_viewMode == ViewMode::LastFrames ) m_viewMode = ViewMode::LastRange;
        const double mouse = io.MousePos.x - wpos.x;
        const auto p = mouse / w;

        int64_t t0, t1;
        if( m_zoomAnim.active )
        {
            t0 = m_zoomAnim.start1;
            t1 = m_zoomAnim.end1;
        }
        else
        {
            t0 = m_vd.zvStart;
            t1 = m_vd.zvEnd;
        }
        const auto zoomSpan = t1 - t0;
        const auto p1 = zoomSpan * p;
        const auto p2 = zoomSpan - p1;

        double mod = 0.25;
        if( io.KeyCtrl ) mod = 0.05;
        else if( io.KeyShift ) mod = 0.5;

        if( wheel > 0 )
        {
            t0 += int64_t( p1 * mod );
            t1 -= int64_t( p2 * mod );
        }
        else if( zoomSpan < 1000ll * 1000 * 1000 * 60 * 60 )
        {
            t0 -= std::max( int64_t( 1 ), int64_t( p1 * mod ) );
            t1 += std::max( int64_t( 1 ), int64_t( p2 * mod ) );
        }
        ZoomToRange( t0, t1, !m_worker.IsConnected() || m_viewMode == ViewMode::Paused );
    }
}

void View::DrawZoneFramesHeader()
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ty025 = round( ty * 0.25f );
    const auto ty0375 = round( ty * 0.375f );
    const auto ty05 = round( ty * 0.5f );

    const auto timespan = m_vd.zvEnd - m_vd.zvStart;
    const auto pxns = w / double( timespan );
    const auto nspx = 1.0 / pxns;
    const auto scale = std::max( 0.0, round( log10( nspx ) + 2 ) );
    const auto step = pow( 10, scale );

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty * 1.5f ) );
    TooltipIfHovered( TimeToStringExact( m_vd.zvStart + ( ImGui::GetIO().MousePos.x - wpos.x ) * nspx ) );

    const auto dx = step * pxns;
    double x = 0;
    int tw = 0;
    int tx = 0;
    int64_t tt = 0;
    while( x < w )
    {
        DrawLine( draw, dpos + ImVec2( x, 0 ), dpos + ImVec2( x, ty05 ), 0x66FFFFFF );
        if( tw == 0 )
        {
            char buf[128];
            auto txt = TimeToStringExact( m_vd.zvStart );
            if( m_vd.zvStart >= 0 )
            {
                sprintf( buf, "+%s", txt );
                txt = buf;
            }
            draw->AddText( wpos + ImVec2( x, ty05 ), 0x66FFFFFF, txt );
            tw = ImGui::CalcTextSize( txt ).x;
        }
        else if( x > tx + tw + ty * 2 )
        {
            tx = x;
            auto txt = TimeToString( tt );
            draw->AddText( wpos + ImVec2( x, ty05 ), 0x66FFFFFF, txt );
            tw = ImGui::CalcTextSize( txt ).x;
        }

        if( scale != 0 )
        {
            for( int i=1; i<5; i++ )
            {
                DrawLine( draw, dpos + ImVec2( x + i * dx / 10, 0 ), dpos + ImVec2( x + i * dx / 10, ty025 ), 0x33FFFFFF );
            }
            DrawLine( draw, dpos + ImVec2( x + 5 * dx / 10, 0 ), dpos + ImVec2( x + 5 * dx / 10, ty0375 ), 0x33FFFFFF );
            for( int i=6; i<10; i++ )
            {
                DrawLine( draw, dpos + ImVec2( x + i * dx / 10, 0 ), dpos + ImVec2( x + i * dx / 10, ty025 ), 0x33FFFFFF );
            }
        }

        x += dx;
        tt += step;
    }
}

static uint32_t DarkenColor( uint32_t color )
{
    return 0xFF000000 |
        ( ( ( ( color & 0x00FF0000 ) >> 16 ) * 2 / 3 ) << 16 ) |
        ( ( ( ( color & 0x0000FF00 ) >> 8  ) * 2 / 3 ) << 8  ) |
        ( ( ( ( color & 0x000000FF )       ) * 2 / 3 )       );
}

static uint32_t MixGhostColor( uint32_t c0, uint32_t c1 )
{
    return 0xFF000000 |
        ( ( ( ( ( c0 & 0x00FF0000 ) >> 16 ) + 3 * ( ( c1 & 0x00FF0000 ) >> 16 ) ) >> 2 ) << 16 ) |
        ( ( ( ( ( c0 & 0x0000FF00 ) >> 8  ) + 3 * ( ( c1 & 0x0000FF00 ) >> 8  ) ) >> 2 ) << 8  ) |
        ( ( ( ( ( c0 & 0x000000FF )       ) + 3 * ( ( c1 & 0x000000FF )       ) ) >> 2 )       );
}

static uint32_t GetColorMuted( uint32_t color, bool active )
{
    if( active )
    {
        return 0xFF000000 | color;
    }
    else
    {
        return 0x66000000 | color;
    }
}

void View::DrawZoneFrames( const FrameData& frames )
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    const auto wh = ImGui::GetContentRegionAvail().y;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    const auto ty025 = ty * 0.25f;
    const auto ty05 = round( ty * 0.5f );

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_vd.zvEnd - m_vd.zvStart;
    auto pxns = w / double( timespan );

    const auto nspx = 1.0 / pxns;

    const std::pair <int, int> zrange = m_worker.GetFrameRange( frames, m_vd.zvStart, m_vd.zvEnd );
    if( zrange.first < 0 ) return;

    int64_t prev = -1;
    int64_t prevEnd = -1;
    int64_t endPos = -1;
    bool tooltipDisplayed = false;
    const auto activeFrameSet = m_frames == &frames;
    const int64_t frameTarget = ( activeFrameSet && m_vd.drawFrameTargets ) ? 1000000000ll / m_vd.frameTarget : std::numeric_limits<int64_t>::max();

    const auto inactiveColor = GetColorMuted( 0x888888, activeFrameSet );
    const auto activeColor = GetColorMuted( 0xFFFFFF, activeFrameSet );
    const auto redColor = GetColorMuted( 0x4444FF, activeFrameSet );

    int i = zrange.first;
    auto x1 = ( m_worker.GetFrameBegin( frames, i ) - m_vd.zvStart ) * pxns;
    while( i < zrange.second )
    {
        const auto ftime = m_worker.GetFrameTime( frames, i );
        const auto fbegin = m_worker.GetFrameBegin( frames, i );
        const auto fend = m_worker.GetFrameEnd( frames, i );
        const auto fsz = pxns * ftime;

        if( hover )
        {
            const auto x0 = frames.continuous ? x1 : ( fbegin - m_vd.zvStart ) * pxns;
            x1 = ( fend - m_vd.zvStart ) * pxns;
            if( ImGui::IsMouseHoveringRect( wpos + ImVec2( x0, 0 ), wpos + ImVec2( x1, ty ) ) )
            {
                tooltipDisplayed = true;
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { fbegin, fend, true };

                ImGui::BeginTooltip();
                ImGui::TextUnformatted( GetFrameText( frames, i, ftime, m_worker.GetFrameOffset() ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / ftime );
                TextFocused( "Time from start of program:", TimeToStringExact( m_worker.GetFrameBegin( frames, i ) ) );
                auto fi = m_worker.GetFrameImage( frames, i );
                if( fi )
                {
                    const auto scale = GetScale();
                    if( fi != m_frameTexturePtr )
                    {
                        if( !m_frameTexture ) m_frameTexture = MakeTexture();
                        UpdateTexture( m_frameTexture, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );
                        m_frameTexturePtr = fi;
                    }
                    ImGui::Separator();
                    if( fi->flip )
                    {
                        ImGui::Image( m_frameTexture, ImVec2( fi->w * scale, fi->h * scale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
                    }
                    else
                    {
                        ImGui::Image( m_frameTexture, ImVec2( fi->w * scale, fi->h * scale ) );
                    }

                    if( ImGui::GetIO().KeyCtrl && IsMouseClicked( 0 ) )
                    {
                        m_showPlayback = true;
                        m_playback.pause = true;
                        SetPlaybackFrame( frames.frames[i].frameImage );
                    }
                }
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( fbegin, fend );
                }

                if( activeFrameSet ) m_frameHover = i;
            }
        }

        if( fsz < MinFrameSize )
        {
            if( !frames.continuous && prev != -1 )
            {
                if( ( fbegin - prevEnd ) * pxns >= MinFrameSize )
                {
                    DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( prevEnd - m_vd.zvStart ) * pxns, ty025, inactiveColor );
                    prev = -1;
                }
                else
                {
                    prevEnd = std::max<int64_t>( fend, fbegin + MinFrameSize * nspx );
                }
            }
            if( prev == -1 )
            {
                prev = fbegin;
                prevEnd = std::max<int64_t>( fend, fbegin + MinFrameSize * nspx );
            }

            const auto begin = frames.frames.begin() + i;
            const auto end = frames.frames.begin() + zrange.second;
            auto it = std::lower_bound( begin, end, int64_t( fbegin + MinVisSize * nspx ), [this, &frames] ( const auto& l, const auto& r ) { return m_worker.GetFrameEnd( frames, std::distance( frames.frames.begin(), &l ) ) < r; } );
            if( it == begin ) ++it;
            i += std::distance( begin, it );
            continue;
        }

        if( prev != -1 )
        {
            if( frames.continuous )
            {
                DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( fbegin - m_vd.zvStart ) * pxns, ty025, inactiveColor );
            }
            else
            {
                DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( prevEnd - m_vd.zvStart ) * pxns, ty025, inactiveColor );
            }
            prev = -1;
        }

        if( activeFrameSet )
        {
            if( fend - fbegin > frameTarget )
            {
                draw->AddRectFilled( wpos + ImVec2( ( fbegin + frameTarget - m_vd.zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_vd.zvStart ) * pxns, wh ), 0x224444FF );
            }
            if( fbegin >= m_vd.zvStart && endPos != fbegin )
            {
                DrawLine( draw, dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns, 0 ), dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            if( fend <= m_vd.zvEnd )
            {
                DrawLine( draw, dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns, 0 ), dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            endPos = fend;
        }

        auto buf = GetFrameText( frames, i, ftime, m_worker.GetFrameOffset() );
        auto tx = ImGui::CalcTextSize( buf ).x;
        uint32_t color = ( frames.name == 0 && i == 0 ) ? redColor : activeColor;

        if( fsz - 7 <= tx )
        {
            static char tmp[256];
            sprintf( tmp, "%s (%s)", RealToString( i ), TimeToString( ftime ) );
            buf = tmp;
            tx = ImGui::CalcTextSize( buf ).x;
        }
        if( fsz - 7 <= tx )
        {
            buf = TimeToString( ftime );
            tx = ImGui::CalcTextSize( buf ).x;
        }

        if( fbegin >= m_vd.zvStart )
        {
            DrawLine( draw, dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns + 2, 1 ), dpos + ImVec2( ( fbegin - m_vd.zvStart ) * pxns + 2, ty - 1 ), color );
        }
        if( fend <= m_vd.zvEnd )
        {
            DrawLine( draw, dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns - 2, 1 ), dpos + ImVec2( ( fend - m_vd.zvStart ) * pxns - 2, ty - 1 ), color );
        }
        if( fsz - 7 > tx )
        {
            const auto f0 = ( fbegin - m_vd.zvStart ) * pxns + 2;
            const auto f1 = ( fend - m_vd.zvStart ) * pxns - 2;
            const auto x0 = f0 + 1;
            const auto x1 = f1 - 1;
            const auto te = x1 - tx;

            auto tpos = ( x0 + te ) / 2;
            if( tpos < 0 )
            {
                tpos = std::min( std::min( 0., te - tpos ), te );
            }
            else if( tpos > w - tx )
            {
                tpos = std::max( double( w - tx ), x0 );
            }
            tpos = round( tpos );

            DrawLine( draw, dpos + ImVec2( std::max( -10.0, f0 ), ty05 ), dpos + ImVec2( tpos, ty05 ), color );
            DrawLine( draw, dpos + ImVec2( std::max( -10.0, tpos + tx + 1 ), ty05 ), dpos + ImVec2( std::min( w + 20.0, f1 ), ty05 ), color );
            draw->AddText( wpos + ImVec2( tpos, 0 ), color, buf );
        }
        else
        {
            DrawLine( draw, dpos + ImVec2( std::max( -10.0, ( fbegin - m_vd.zvStart ) * pxns + 2 ), ty05 ), dpos + ImVec2( std::min( w + 20.0, ( fend - m_vd.zvStart ) * pxns - 2 ), ty05 ), color );
        }

        i++;
    }

    if( prev != -1 )
    {
        if( frames.continuous )
        {
            DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), ( prev - m_vd.zvStart ) * pxns, ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_vd.zvStart ) * pxns, ty025, inactiveColor );
        }
        else
        {
            const auto begin = ( prev - m_vd.zvStart ) * pxns;
            const auto end = ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_vd.zvStart ) * pxns;
            DrawZigZag( draw, wpos + ImVec2( 0, ty05 ), begin, std::max( begin + MinFrameSize, end ), ty025, inactiveColor );
        }
    }

    if( hover )
    {
        if( !tooltipDisplayed )
        {
            ImGui::BeginTooltip();
            TextDisabledUnformatted( "Frame set:" );
            ImGui::SameLine();
            ImGui::TextUnformatted( frames.name == 0 ? "Frames" : m_worker.GetString( frames.name ) );
            ImGui::EndTooltip();
        }
        if( IsMouseClicked( 0 ) )
        {
            m_frames = &frames;
        }
    }
}

float View::AdjustThreadPosition( View::VisData& vis, float wy, int& offset )
{
    if( vis.offset < offset )
    {
        vis.offset = offset;
    }
    else if( vis.offset > offset )
    {
        const auto diff = vis.offset - offset;
        const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
        offset = vis.offset = int( std::max<double>( vis.offset - move, offset ) );
    }

    return offset + wy;
}

void View::AdjustThreadHeight( View::VisData& vis, int oldOffset, int& offset )
{
    const auto h = offset - oldOffset;
    if( vis.height > h )
    {
        vis.height = h;
        offset = oldOffset + vis.height;
    }
    else if( vis.height < h )
    {
        if( m_firstFrame )
        {
            vis.height = h;
            offset = oldOffset + h;
        }
        else
        {
            const auto diff = h - vis.height;
            const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
            vis.height = int( std::min<double>( vis.height + move, h ) );
            offset = oldOffset + vis.height;
        }
    }
}

void View::DrawZones()
{
    m_msgHighlight.Decay( nullptr );
    m_zoneSrcLocHighlight.Decay( 0 );
    m_lockHoverHighlight.Decay( InvalidId );
    m_drawThreadMigrations.Decay( 0 );
    m_drawThreadHighlight.Decay( 0 );
    m_cpuDataThread.Decay( 0 );
    m_zoneHover = nullptr;
    m_zoneHover2.Decay( nullptr );
    m_findZone.range.StartFrame();
    m_statRange.StartFrame();
    m_waitStackRange.StartFrame();
    m_memInfo.range.StartFrame();
    m_yDelta = 0;

    if( m_vd.zvStart == m_vd.zvEnd ) return;
    assert( m_vd.zvStart < m_vd.zvEnd );

    if( ImGui::GetCurrentWindowRead()->SkipItems ) return;

    m_gpuThread = 0;
    m_gpuStart = 0;
    m_gpuEnd = 0;

    const auto linepos = ImGui::GetCursorScreenPos();
    const auto lineh = ImGui::GetContentRegionAvail().y;

    auto draw = ImGui::GetWindowDrawList();
    const auto w = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().ScrollbarSize;
    const auto timespan = m_vd.zvEnd - m_vd.zvStart;
    auto pxns = w / double( timespan );

    const auto winpos = ImGui::GetWindowPos();
    const auto winsize = ImGui::GetWindowSize();
    const bool drawMouseLine = ImGui::IsWindowHovered( ImGuiHoveredFlags_ChildWindows | ImGuiHoveredFlags_AllowWhenBlockedByActiveItem ) && ImGui::IsMouseHoveringRect( winpos, winpos + winsize, false );
    if( drawMouseLine )
    {
        HandleRange( m_findZone.range, timespan, ImGui::GetCursorScreenPos(), w );
        HandleRange( m_statRange, timespan, ImGui::GetCursorScreenPos(), w );
        HandleRange( m_waitStackRange, timespan, ImGui::GetCursorScreenPos(), w );
        HandleRange( m_memInfo.range, timespan, ImGui::GetCursorScreenPos(), w );
        for( auto& v : m_annotations )
        {
            v->range.StartFrame();
            HandleRange( v->range, timespan, ImGui::GetCursorScreenPos(), w );
        }
        HandleZoneViewMouse( timespan, ImGui::GetCursorScreenPos(), w, pxns );
    }

    {
        const auto tbegin = 0;
        const auto tend = m_worker.GetLastTime();
        if( tbegin > m_vd.zvStart )
        {
            draw->AddRectFilled( linepos, linepos + ImVec2( ( tbegin - m_vd.zvStart ) * pxns, lineh ), 0x44000000 );
        }
        if( tend < m_vd.zvEnd )
        {
            draw->AddRectFilled( linepos + ImVec2( ( tend - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( w, lineh ), 0x44000000 );
        }
    }

    DrawZoneFramesHeader();
    auto& frames = m_worker.GetFrames();
    for( auto fd : frames )
    {
        if( Vis( fd ).visible )
        {
            DrawZoneFrames( *fd );
        }
    }

    const auto yMin = ImGui::GetCursorScreenPos().y;
    const auto yMax = linepos.y + lineh;

    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    if( m_yDelta != 0 )
    {
        auto& io = ImGui::GetIO();
        auto y = ImGui::GetScrollY();
        ImGui::SetScrollY( y - m_yDelta );
        io.MouseClickedPos[1].y = io.MousePos.y;
    }

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto h = std::max<float>( m_vd.zvHeight, ImGui::GetContentRegionAvail().y - 4 );    // magic border value

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();
    draw = ImGui::GetWindowDrawList();

    const auto nspx = 1.0 / pxns;

    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    int offset = 0;
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;

    // gpu zones
    if( m_vd.drawGpuZones )
    {
        for( size_t i=0; i<m_worker.GetGpuData().size(); i++ )
        {
            const auto& v = m_worker.GetGpuData()[i];
            auto& vis = Vis( v );
            if( !vis.visible )
            {
                vis.height = 0;
                vis.offset = 0;
                continue;
            }
            bool& showFull = vis.showFull;

            const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
            const auto oldOffset = offset;
            ImGui::PushClipRect( wpos, wpos + ImVec2( w, oldOffset + vis.height ), true );

            ImGui::PushFont( m_smallFont );
            const auto sty = ImGui::GetTextLineHeight();
            const auto sstep = sty + 1;
            ImGui::PopFont();

            const auto singleThread = v->threadData.size() == 1;
            int depth = 0;
            offset += ostep;
            if( showFull && !v->threadData.empty() )
            {
                for( auto& td : v->threadData )
                {
                    auto& tl = td.second.timeline;
                    assert( !tl.empty() );
                    if( tl.is_magic() )
                    {
                        auto& tlm = *(Vector<GpuEvent>*)&tl;
                        if( tlm.front().GpuStart() >= 0 )
                        {
                            const auto begin = tlm.front().GpuStart();
                            const auto drift = GpuDrift( v );
                            if( !singleThread ) offset += sstep;
                            const auto partDepth = DispatchGpuZoneLevel( tl, hover, pxns, int64_t( nspx ), wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                            if( partDepth != 0 )
                            {
                                if( !singleThread )
                                {
                                    ImGui::PushFont( m_smallFont );
                                    DrawTextContrast( draw, wpos + ImVec2( ty, offset-1-sstep ), 0xFFFFAAAA, m_worker.GetThreadName( td.first ) );
                                    DrawLine( draw, dpos + ImVec2( 0, offset+sty-sstep ), dpos + ImVec2( w, offset+sty-sstep ), 0x22FFAAAA );
                                    ImGui::PopFont();
                                }

                                offset += ostep * partDepth;
                                depth += partDepth;
                            }
                            else if( !singleThread )
                            {
                                offset -= sstep;
                            }
                        }
                    }
                    else
                    {
                        if( tl.front()->GpuStart() >= 0 )
                        {
                            const auto begin = tl.front()->GpuStart();
                            const auto drift = GpuDrift( v );
                            if( !singleThread ) offset += sstep;
                            const auto partDepth = DispatchGpuZoneLevel( tl, hover, pxns, int64_t( nspx ), wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                            if( partDepth != 0 )
                            {
                                if( !singleThread )
                                {
                                    ImGui::PushFont( m_smallFont );
                                    DrawTextContrast( draw, wpos + ImVec2( ty, offset-1-sstep ), 0xFFFFAAAA, m_worker.GetThreadName( td.first ) );
                                    DrawLine( draw, dpos + ImVec2( 0, offset+sty-sstep ), dpos + ImVec2( w, offset+sty-sstep ), 0x22FFAAAA );
                                    ImGui::PopFont();
                                }

                                offset += ostep * partDepth;
                                depth += partDepth;
                            }
                            else if( !singleThread )
                            {
                                offset -= sstep;
                            }
                        }
                    }
                }
            }
            offset += ostep * 0.2f;

            if( !m_vd.drawEmptyLabels && showFull && depth == 0 )
            {
                vis.height = 0;
                vis.offset = 0;
                offset = oldOffset;
            }
            else if( yPos + ostep >= yMin && yPos <= yMax )
            {
                DrawLine( draw, dpos + ImVec2( 0, oldOffset + ostep - 1 ), dpos + ImVec2( w, oldOffset + ostep - 1 ), 0x33FFFFFF );

                if( showFull )
                {
                    draw->AddTriangleFilled( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( ty - to/2, oldOffset + to/2 ), wpos + ImVec2( ty * 0.5, oldOffset + to/2 + th ), 0xFFFFAAAA );
                }
                else
                {
                    draw->AddTriangle( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( to/2, oldOffset + ty - to/2 ), wpos + ImVec2( to/2 + th, oldOffset + ty * 0.5 ), 0xFF886666, 2.0f );
                }

                const bool isMultithreaded = (v->type == GpuContextType::Vulkan) || (v->type == GpuContextType::OpenCL) || (v->type == GpuContextType::Direct3D12);

                float boxwidth;
                char buf[64];
                sprintf( buf, "%s context %zu", GpuContextNames[(int)v->type], i );
                if( v->name.Active() )
                {
                    char tmp[4096];
                    sprintf( tmp, "%s: %s", buf, m_worker.GetString( v->name ) );
                    DrawTextContrast( draw, wpos + ImVec2( ty, oldOffset ), showFull ? 0xFFFFAAAA : 0xFF886666, tmp );
                    boxwidth = ImGui::CalcTextSize( tmp ).x;
                }
                else
                {
                    DrawTextContrast( draw, wpos + ImVec2( ty, oldOffset ), showFull ? 0xFFFFAAAA : 0xFF886666, buf );
                    boxwidth = ImGui::CalcTextSize( buf ).x;
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + boxwidth, oldOffset + ty ) ) )
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        showFull = !showFull;
                    }
                    if( IsMouseClicked( 2 ) )
                    {
                        int64_t t0 = std::numeric_limits<int64_t>::max();
                        int64_t t1 = std::numeric_limits<int64_t>::min();
                        for( auto& td : v->threadData )
                        {
                            int64_t _t0;
                            if( td.second.timeline.is_magic() )
                            {
                                _t0 = ((Vector<GpuEvent>*)&td.second.timeline)->front().GpuStart();
                            }
                            else
                            {
                                _t0 = td.second.timeline.front()->GpuStart();
                            }
                            if( _t0 >= 0 )
                            {
                                // FIXME
                                t0 = std::min( t0, _t0 );
                                if( td.second.timeline.is_magic() )
                                {
                                    t1 = std::max( t1, std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( ((Vector<GpuEvent>*)&td.second.timeline)->back() ) ) );
                                }
                                else
                                {
                                    t1 = std::max( t1, std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( *td.second.timeline.back() ) ) );
                                }
                            }
                        }
                        if( t0 < t1 )
                        {
                            ZoomToRange( t0, t1 );
                        }
                    }

                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( buf );
                    if( v->name.Active() ) TextFocused( "Name:", m_worker.GetString( v->name ) );
                    ImGui::Separator();
                    if( !isMultithreaded )
                    {
                        SmallColorBox( GetThreadColor( v->thread, 0 ) );
                        ImGui::SameLine();
                        TextFocused( "Thread:", m_worker.GetThreadName( v->thread ) );
                    }
                    else
                    {
                        if( !v->threadData.empty() )
                        {
                            if( v->threadData.size() == 1 )
                            {
                                auto it = v->threadData.begin();
                                auto tid = it->first;
                                if( tid == 0 )
                                {
                                    if( !it->second.timeline.empty() )
                                    {
                                        if( it->second.timeline.is_magic() )
                                        {
                                            auto& tl = *(Vector<GpuEvent>*)&it->second.timeline;
                                            tid = m_worker.DecompressThread( tl.begin()->Thread() );
                                        }
                                        else
                                        {
                                            tid = m_worker.DecompressThread( (*it->second.timeline.begin())->Thread() );
                                        }
                                    }
                                }
                                SmallColorBox( GetThreadColor( tid, 0 ) );
                                ImGui::SameLine();
                                TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                                if( m_worker.IsThreadFiber( tid ) )
                                {
                                    ImGui::SameLine();
                                    TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                                }
                            }
                            else
                            {
                                ImGui::TextDisabled( "Threads:" );
                                ImGui::Indent();
                                for( auto& td : v->threadData )
                                {
                                    SmallColorBox( GetThreadColor( td.first, 0 ) );
                                    ImGui::SameLine();
                                    ImGui::TextUnformatted( m_worker.GetThreadName( td.first ) );
                                    ImGui::SameLine();
                                    ImGui::TextDisabled( "(%s)", RealToString( td.first ) );
                                }
                                ImGui::Unindent();
                            }
                        }
                    }
                    if( !v->threadData.empty() )
                    {
                        int64_t t0 = std::numeric_limits<int64_t>::max();
                        for( auto& td : v->threadData )
                        {
                            int64_t _t0;
                            if( td.second.timeline.is_magic() )
                            {
                                _t0 = ((Vector<GpuEvent>*)&td.second.timeline)->front().GpuStart();
                            }
                            else
                            {
                                _t0 = td.second.timeline.front()->GpuStart();
                            }
                            if( _t0 >= 0 )
                            {
                                t0 = std::min( t0, _t0 );
                            }
                        }
                        if( t0 != std::numeric_limits<int64_t>::max() )
                        {
                            TextFocused( "Appeared at", TimeToString( t0 ) );
                        }
                    }
                    TextFocused( "Zone count:", RealToString( v->count ) );
                    if( v->period != 1.f )
                    {
                        TextFocused( "Timestamp accuracy:", TimeToString( v->period ) );
                    }
                    if( v->overflow != 0 )
                    {
                        ImGui::Separator();
                        ImGui::TextUnformatted( "GPU timer overflow has been detected." );
                        TextFocused( "Timer resolution:", RealToString( 63 - TracyLzcnt( v->overflow ) ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "bits" );
                    }
                    ImGui::EndTooltip();
                }
            }

            AdjustThreadHeight( vis, oldOffset, offset );
            ImGui::PopClipRect();
        }
    }

    // zones
    if( m_vd.drawCpuData && m_worker.HasContextSwitches() )
    {
        offset = DrawCpuData( offset, pxns, wpos, hover, yMin, yMax );
    }

    const auto& threadData = m_worker.GetThreadData();
    if( threadData.size() != m_threadOrder.size() )
    {
        m_threadOrder.reserve( threadData.size() );
        for( size_t i=m_threadOrder.size(); i<threadData.size(); i++ )
        {
            m_threadOrder.push_back( threadData[i] );
        }
    }

    auto& crash = m_worker.GetCrashEvent();
    LockHighlight nextLockHighlight { -1 };
    for( const auto& v : m_threadOrder )
    {
        auto& vis = Vis( v );
        if( !vis.visible )
        {
            vis.height = 0;
            vis.offset = 0;
            continue;
        }
        bool showFull = vis.showFull;

        const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
        const auto oldOffset = offset;
        ImGui::PushClipRect( wpos, wpos + ImVec2( w, offset + vis.height ), true );

        int depth = 0;
        offset += ostep;
        if( showFull )
        {
            const auto sampleOffset = offset;
            const auto hasSamples = m_vd.drawSamples && !v->samples.empty();
            const auto hasCtxSwitch = m_vd.drawContextSwitches && m_worker.GetContextSwitchData( v->id );

            if( hasSamples )
            {
                if( hasCtxSwitch )
                {
                    offset += round( ostep * 0.5f );
                }
                else
                {
                    offset += round( ostep * 0.75f );
                }
            }

            const auto ctxOffset = offset;
            if( hasCtxSwitch ) offset += round( ostep * 0.75f );

            if( m_vd.drawZones )
            {
#ifndef TRACY_NO_STATISTICS
                if( m_worker.AreGhostZonesReady() && ( vis.ghost || ( m_vd.ghostZones && v->timeline.empty() ) ) )
                {
                    depth = DispatchGhostLevel( v->ghostZones, hover, pxns, int64_t( nspx ), wpos, offset, 0, yMin, yMax, v->id );
                }
                else
#endif
                {
                    depth = DispatchZoneLevel( v->timeline, hover, pxns, int64_t( nspx ), wpos, offset, 0, yMin, yMax, v->id );
                }
                offset += ostep * depth;
            }

            if( hasCtxSwitch )
            {
                auto ctxSwitch = m_worker.GetContextSwitchData( v->id );
                if( ctxSwitch )
                {
                    DrawContextSwitches( ctxSwitch, v->samples, hover, pxns, int64_t( nspx ), wpos, ctxOffset, offset, v->isFiber );
                }
            }

            if( hasSamples )
            {
                DrawSamples( v->samples, hover, pxns, int64_t( nspx ), wpos, sampleOffset );
            }

            if( m_vd.drawLocks )
            {
                const auto lockDepth = DrawLocks( v->id, hover, pxns, wpos, offset, nextLockHighlight, yMin, yMax );
                offset += ostep * lockDepth;
                depth += lockDepth;
            }
        }
        offset += ostep * 0.2f;

        auto msgit = std::lower_bound( v->messages.begin(), v->messages.end(), m_vd.zvStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        auto msgend = std::lower_bound( msgit, v->messages.end(), m_vd.zvEnd+1, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

        if( !m_vd.drawEmptyLabels && showFull && depth == 0 && msgit == msgend && crash.thread != v->id )
        {
            auto& vis = Vis( v );
            vis.height = 0;
            vis.offset = 0;
            offset = oldOffset;
        }
        else if( yPos + ostep >= yMin && yPos <= yMax )
        {
            DrawLine( draw, dpos + ImVec2( 0, oldOffset + ostep - 1 ), dpos + ImVec2( w, oldOffset + ostep - 1 ), 0x33FFFFFF );

            uint32_t labelColor;
            if( crash.thread == v->id ) labelColor = showFull ? 0xFF2222FF : 0xFF111188;
            else if( v->isFiber ) labelColor = showFull ? 0xFF88FF88 : 0xFF448844;
            else labelColor = showFull ? 0xFFFFFFFF : 0xFF888888;

            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( ty - to/2, oldOffset + to/2 ), wpos + ImVec2( ty * 0.5, oldOffset + to/2 + th ), labelColor );

                while( msgit < msgend )
                {
                    const auto next = std::upper_bound( msgit, v->messages.end(), (*msgit)->time + MinVisSize * nspx, [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs->time; } );
                    const auto dist = std::distance( msgit, next );

                    const auto px = ( (*msgit)->time - m_vd.zvStart ) * pxns;
                    const bool isMsgHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, oldOffset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, oldOffset + ty ) );

                    unsigned int color = 0xFFDDDDDD;
                    float animOff = 0;
                    if( dist > 1 )
                    {
                        if( m_msgHighlight && m_worker.DecompressThread( m_msgHighlight->thread ) == v->id )
                        {
                            const auto hTime = m_msgHighlight->time;
                            if( (*msgit)->time <= hTime && ( next == v->messages.end() || (*next)->time > hTime ) )
                            {
                                color = 0xFF4444FF;
                                if( !isMsgHovered )
                                {
                                    animOff = -fabs( sin( s_time * 8 ) ) * th;
                                }
                            }
                        }
                        draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px, animOff + oldOffset + to + th ), color );
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px, animOff + oldOffset + to + th ), color, 2.0f );
                    }
                    else
                    {
                        if( m_msgHighlight == *msgit )
                        {
                            color = 0xFF4444FF;
                            if( !isMsgHovered )
                            {
                                animOff = -fabs( sin( s_time * 8 ) ) * th;
                            }
                        }
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, animOff + oldOffset + to ), wpos + ImVec2( px, animOff + oldOffset + to + th ), color, 2.0f );
                    }
                    if( isMsgHovered )
                    {
                        ImGui::BeginTooltip();
                        if( dist > 1 )
                        {
                            ImGui::Text( "%i messages", (int)dist );
                        }
                        else
                        {
                            TextFocused( "Message at", TimeToStringExact( (*msgit)->time ) );
                            ImGui::PushStyleColor( ImGuiCol_Text, (*msgit)->color );
                            ImGui::TextUnformatted( m_worker.GetString( (*msgit)->ref ) );
                            ImGui::PopStyleColor();
                        }
                        ImGui::EndTooltip();
                        m_msgHighlight = *msgit;

                        if( IsMouseClicked( 0 ) )
                        {
                            m_showMessages = true;
                            m_msgToFocus = *msgit;
                        }
                        if( IsMouseClicked( 2 ) )
                        {
                            CenterAtTime( (*msgit)->time );
                        }
                    }
                    msgit = next;
                }

                if( crash.thread == v->id && crash.time >= m_vd.zvStart && crash.time <= m_vd.zvEnd )
                {
                    const auto px = ( crash.time - m_vd.zvStart ) * pxns;

                    draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px, oldOffset + to + th ), 0xFF2222FF );
                    draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px, oldOffset + to + th ), 0xFF2222FF, 2.0f );

                    const auto crashText = ICON_FA_SKULL " crash " ICON_FA_SKULL;
                    auto ctw = ImGui::CalcTextSize( crashText ).x;
                    DrawTextContrast( draw, wpos + ImVec2( px - ctw * 0.5f, oldOffset + to + th * 0.5f - ty ), 0xFF2222FF, crashText );

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, oldOffset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, oldOffset + ty ) ) )
                    {
                        CrashTooltip();
                        if( IsMouseClicked( 0 ) )
                        {
                            m_showInfo = true;
                        }
                        if( IsMouseClicked( 2 ) )
                        {
                            CenterAtTime( crash.time );
                        }
                    }
                }
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( to/2, oldOffset + ty - to/2 ), wpos + ImVec2( to/2 + th, oldOffset + ty * 0.5 ), labelColor, 2.0f );
            }
            const auto txt = m_worker.GetThreadName( v->id );
            const auto txtsz = ImGui::CalcTextSize( txt );
            if( m_gpuThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x228888DD );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x448888DD );
            }
            if( m_gpuInfoWindow && m_gpuInfoWindowThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x2288DD88 );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x4488DD88 );
            }
            if( m_cpuDataThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x2DFF8888 );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( w, offset ), 0x4DFF8888 );
            }
            DrawTextContrast( draw, wpos + ImVec2( ty, oldOffset ), labelColor, txt );

#ifndef TRACY_NO_STATISTICS
            const bool hasGhostZones = showFull && m_worker.AreGhostZonesReady() && !v->ghostZones.empty();
            float ghostSz;
            if( hasGhostZones && !v->timeline.empty() )
            {
                auto& vis = Vis( v );
                const auto color = vis.ghost ? 0xFFAA9999 : 0x88AA7777;
                draw->AddText( wpos + ImVec2( 1.5f * ty + txtsz.x, oldOffset ), color, ICON_FA_GHOST );
                ghostSz = ImGui::CalcTextSize( ICON_FA_GHOST ).x;
            }
#endif

            if( hover )
            {
#ifndef TRACY_NO_STATISTICS
                if( hasGhostZones && !v->timeline.empty() && ImGui::IsMouseHoveringRect( wpos + ImVec2( 1.5f * ty + txtsz.x, oldOffset ), wpos + ImVec2( 1.5f * ty + txtsz.x + ghostSz, oldOffset + ty ) ) )
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        auto& vis = Vis( v );
                        vis.ghost = !vis.ghost;
                    }
                }
                else
#endif
                if( ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x, oldOffset + ty ) ) )
                {
                    m_drawThreadMigrations = v->id;
                    m_drawThreadHighlight = v->id;
                    ImGui::BeginTooltip();
                    SmallColorBox( GetThreadColor( v->id, 0 ) );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( m_worker.GetThreadName( v->id ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( v->id ) );
                    if( crash.thread == v->id )
                    {
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
                    }
                    if( v->isFiber )
                    {
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                    }

                    const auto ctx = m_worker.GetContextSwitchData( v->id );

                    ImGui::Separator();
                    int64_t first = std::numeric_limits<int64_t>::max();
                    int64_t last = -1;
                    if( ctx && !ctx->v.empty() )
                    {
                        const auto& back = ctx->v.back();
                        first = ctx->v.begin()->Start();
                        last = back.IsEndValid() ? back.End() : back.Start();
                    }
                    if( !v->timeline.empty() )
                    {
                        if( v->timeline.is_magic() )
                        {
                            auto& tl = *((Vector<ZoneEvent>*)&v->timeline);
                            first = std::min( first, tl.front().Start() );
                            last = std::max( last, m_worker.GetZoneEnd( tl.back() ) );
                        }
                        else
                        {
                            first = std::min( first, v->timeline.front()->Start() );
                            last = std::max( last, m_worker.GetZoneEnd( *v->timeline.back() ) );
                        }
                    }
                    if( !v->messages.empty() )
                    {
                        first = std::min( first, v->messages.front()->time );
                        last = std::max( last, v->messages.back()->time );
                    }
                    size_t lockCnt = 0;
                    for( const auto& lock : m_worker.GetLockMap() )
                    {
                        const auto& lockmap = *lock.second;
                        if( !lockmap.valid ) continue;
                        auto it = lockmap.threadMap.find( v->id );
                        if( it == lockmap.threadMap.end() ) continue;
                        lockCnt++;
                        const auto thread = it->second;
                        auto lptr = lockmap.timeline.data();
                        auto eptr = lptr + lockmap.timeline.size() - 1;
                        while( lptr->ptr->thread != thread ) lptr++;
                        if( lptr->ptr->Time() < first ) first = lptr->ptr->Time();
                        while( eptr->ptr->thread != thread ) eptr--;
                        if( eptr->ptr->Time() > last ) last = eptr->ptr->Time();
                    }

                    if( last >= 0 )
                    {
                        const auto lifetime = last - first;
                        const auto traceLen = m_worker.GetLastTime();

                        TextFocused( "Appeared at", TimeToString( first ) );
                        TextFocused( "Last event at", TimeToString( last ) );
                        TextFocused( "Lifetime:", TimeToString( lifetime ) );
                        ImGui::SameLine();
                        char buf[64];
                        PrintStringPercent( buf, lifetime / double( traceLen ) * 100 );
                        TextDisabledUnformatted( buf );

                        if( ctx )
                        {
                            TextFocused( "Time in running state:", TimeToString( ctx->runningTime ) );
                            ImGui::SameLine();
                            PrintStringPercent( buf, ctx->runningTime / double( lifetime ) * 100 );
                            TextDisabledUnformatted( buf );
                        }
                    }

                    ImGui::Separator();
                    if( !v->timeline.empty() )
                    {
                        TextFocused( "Zone count:", RealToString( v->count ) );
                        TextFocused( "Top-level zones:", RealToString( v->timeline.size() ) );
                    }
                    if( !v->messages.empty() )
                    {
                        TextFocused( "Messages:", RealToString( v->messages.size() ) );
                    }
                    if( lockCnt != 0 )
                    {
                        TextFocused( "Locks:", RealToString( lockCnt ) );
                    }
                    if( ctx )
                    {
                        TextFocused( "Running state regions:", RealToString( ctx->v.size() ) );
                    }
                    if( !v->samples.empty() )
                    {
                        TextFocused( "Call stack samples:", RealToString( v->samples.size() ) );
                        if( v->kernelSampleCnt != 0 )
                        {
                            TextFocused( "Kernel samples:", RealToString( v->kernelSampleCnt ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%.2f%%)", 100.f * v->kernelSampleCnt / v->samples.size() );
                        }
                    }
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 0 ) )
                    {
                        Vis( v ).showFull = !showFull;
                    }
                    if( last >= 0 && IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( first, last );
                    }
                }
            }
        }

        AdjustThreadHeight( Vis( v ), oldOffset, offset );
        ImGui::PopClipRect();
    }
    m_lockHighlight = nextLockHighlight;

    if( m_vd.drawPlots )
    {
        offset = DrawPlots( offset, pxns, wpos, hover, yMin, yMax );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( scrollPos == 0 && m_vd.zvScroll != 0 )
    {
        m_vd.zvHeight = 0;
    }
    else
    {
        if( offset > m_vd.zvHeight ) m_vd.zvHeight = offset;
    }
    m_vd.zvScroll = scrollPos;

    ImGui::EndChild();

    for( auto& ann : m_annotations )
    {
        if( ann->range.min < m_vd.zvEnd && ann->range.max > m_vd.zvStart )
        {
            uint32_t c0 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0x44000000 : 0x22000000 );
            uint32_t c1 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0x66000000 : 0x44000000 );
            uint32_t c2 = ( ann->color & 0xFFFFFF ) | ( m_selectedAnnotation == ann.get() ? 0xCC000000 : 0xAA000000 );
            draw->AddRectFilled( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns, lineh ), c0 );
            DrawLine( draw, linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + 0.5f, 0.5f ), linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + 0.5f, lineh + 0.5f ), ann->range.hiMin ? c2 : c1, ann->range.hiMin ? 2 : 1 );
            DrawLine( draw, linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns + 0.5f, 0.5f ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns + 0.5f, lineh + 0.5f ), ann->range.hiMax ? c2 : c1, ann->range.hiMax ? 2 : 1 );
            if( drawMouseLine && ImGui::IsMouseHoveringRect( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns, lineh ) ) )
            {
                ImGui::BeginTooltip();
                if( ann->text.empty() )
                {
                    TextDisabledUnformatted( "Empty annotation" );
                }
                else
                {
                    ImGui::TextUnformatted( ann->text.c_str() );
                }
                ImGui::Separator();
                TextFocused( "Annotation begin:", TimeToStringExact( ann->range.min ) );
                TextFocused( "Annotation end:", TimeToStringExact( ann->range.max ) );
                TextFocused( "Annotation length:", TimeToString( ann->range.max - ann->range.min ) );
                ImGui::EndTooltip();
            }
            const auto aw = ( ann->range.max - ann->range.min ) * pxns;
            if( aw > th * 4 )
            {
                draw->AddCircleFilled( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 2, th * 2 ), th, 0x88AABB22 );
                draw->AddCircle( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 2, th * 2 ), th, 0xAAAABB22 );
                if( drawMouseLine && IsMouseClicked( 0 ) && ImGui::IsMouseHoveringRect( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th, th ), linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 3, th * 3 ) ) )
                {
                    m_selectedAnnotation = ann.get();
                }

                if( !ann->text.empty() )
                {
                    const auto tw = ImGui::CalcTextSize( ann->text.c_str() ).x;
                    if( aw - th*4 > tw )
                    {
                        draw->AddText( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 4, th * 0.5 ), 0xFFFFFFFF, ann->text.c_str() );
                    }
                    else
                    {
                        draw->PushClipRect( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns, 0 ), linepos + ImVec2( ( ann->range.max - m_vd.zvStart ) * pxns, lineh ), true );
                        draw->AddText( linepos + ImVec2( ( ann->range.min - m_vd.zvStart ) * pxns + th * 4, th * 0.5 ), 0xFFFFFFFF, ann->text.c_str() );
                        draw->PopClipRect();
                    }
                }
            }
        }
    }

    if( m_gpuStart != 0 && m_gpuEnd != 0 )
    {
        const auto px0 = ( m_gpuStart - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuEnd - m_vd.zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x228888DD );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x448888DD );
    }
    if( m_gpuInfoWindow )
    {
        const auto px0 = ( m_gpuInfoWindow->CpuStart() - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuInfoWindow->CpuEnd() - m_vd.zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x2288DD88 );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x4488DD88 );
    }

    const auto scale = GetScale();
    if( m_findZone.range.active && ( m_findZone.show || m_showRanges ) )
    {
        const auto px0 = ( m_findZone.range.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_findZone.range.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x2288DD88, true, true );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_findZone.range.hiMin ? 0x9988DD88 : 0x3388DD88, m_findZone.range.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_findZone.range.hiMax ? 0x9988DD88 : 0x3388DD88, m_findZone.range.hiMax ? 2 : 1 );
    }

    if( m_statRange.active && ( m_showStatistics || m_showRanges || ( m_sourceViewFile && m_sourceView->IsSymbolView() ) ) )
    {
        const auto px0 = ( m_statRange.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_statRange.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x228888EE, true, false );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_statRange.hiMin ? 0x998888EE : 0x338888EE, m_statRange.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_statRange.hiMax ? 0x998888EE : 0x338888EE, m_statRange.hiMax ? 2 : 1 );
    }

    if( m_waitStackRange.active && ( m_showWaitStacks || m_showRanges ) )
    {
        const auto px0 = ( m_waitStackRange.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_waitStackRange.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x22EEB588, true, true );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_waitStackRange.hiMin ? 0x99EEB588 : 0x33EEB588, m_waitStackRange.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_waitStackRange.hiMax ? 0x99EEB588 : 0x33EEB588, m_waitStackRange.hiMax ? 2 : 1 );
    }

    if( m_memInfo.range.active && ( m_memInfo.show || m_showRanges ) )
    {
        const auto px0 = ( m_memInfo.range.min - m_vd.zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_memInfo.range.max - m_vd.zvStart ) * pxns );
        DrawStripedRect( draw, wpos, px0, linepos.y, px1, linepos.y + lineh, 10 * scale, 0x2288EEE3, true, false );
        DrawLine( draw, ImVec2( dpos.x + px0, linepos.y + 0.5f ), ImVec2( dpos.x + px0, linepos.y + lineh + 0.5f ), m_memInfo.range.hiMin ? 0x9988EEE3 : 0x3388EEE3, m_memInfo.range.hiMin ? 2 : 1 );
        DrawLine( draw, ImVec2( dpos.x + px1, linepos.y + 0.5f ), ImVec2( dpos.x + px1, linepos.y + lineh + 0.5f ), m_memInfo.range.hiMax ? 0x9988EEE3 : 0x3388EEE3, m_memInfo.range.hiMax ? 2 : 1 );
    }

    if( m_setRangePopup.active || m_setRangePopupOpen )
    {
        const auto s = std::min( m_setRangePopup.min, m_setRangePopup.max );
        const auto e = std::max( m_setRangePopup.min, m_setRangePopup.max );
        DrawStripedRect( draw, wpos, ( s - m_vd.zvStart ) * pxns, linepos.y, ( e - m_vd.zvStart ) * pxns, linepos.y + lineh, 5 * scale, 0x55DD8888, true, false );
        draw->AddRect( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x77DD8888 );
    }

    if( m_highlight.active && m_highlight.start != m_highlight.end )
    {
        const auto s = std::min( m_highlight.start, m_highlight.end );
        const auto e = std::max( m_highlight.start, m_highlight.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x22DD8888 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x44DD8888 );

        ImGui::BeginTooltip();
        ImGui::TextUnformatted( TimeToString( e - s ) );
        ImGui::EndTooltip();
    }
    else if( drawMouseLine )
    {
        auto& io = ImGui::GetIO();
        DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, linepos.y + 0.5f ), ImVec2( io.MousePos.x + 0.5f, linepos.y + lineh + 0.5f ), 0x33FFFFFF );
    }

    if( m_highlightZoom.active && m_highlightZoom.start != m_highlightZoom.end )
    {
        const auto s = std::min( m_highlightZoom.start, m_highlightZoom.end );
        const auto e = std::max( m_highlightZoom.start, m_highlightZoom.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x1688DD88 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_vd.zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_vd.zvStart ) * pxns, linepos.y + lineh ), 0x2C88DD88 );
    }
}

void View::DrawSamples( const Vector<SampleData>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset )
{
    auto it = std::lower_bound( vec.begin(), vec.end(), m_vd.zvStart, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
    if( it == vec.end() ) return;
    const auto itend = std::lower_bound( it, vec.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
    if( it == itend ) return;

    const auto ty0375 = offset + round( ImGui::GetTextLineHeight() * 0.375f );
    const auto ty02 = round( ImGui::GetTextLineHeight() * 0.2f );
    const auto ty01 = round( ImGui::GetTextLineHeight() * 0.1f );
    const auto y0 = ty0375 - ty02 - 3;
    const auto y1 = ty0375 + ty02 - 1;
    auto draw = ImGui::GetWindowDrawList();

    const auto MinVis = 6 * GetScale();
    bool tooltipDisplayed = false;

    while( it < itend )
    {
        bool visible = true;
        const auto px0 = ( it->time.Val() - m_vd.zvStart ) * pxns;
        double px1;
        auto next = it+1;
        int num;
        if( next != itend )
        {
            auto px1ns = next->time.Val() - m_vd.zvStart;
            px1 = px1ns * pxns;
            if( px1 - px0 < MinVis )
            {
                const auto MinVisNs = MinVis * nspx;
                visible = false;
                auto nextTime = px0 + MinVisNs;
                for(;;)
                {
                    const auto prev = next;
                    next = std::lower_bound( next, itend, nextTime, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                    if( prev == next ) ++next;
                    if( next == itend ) break;
                    const auto nsnext = next->time.Val() - m_vd.zvStart;
                    if( nsnext - px1ns >= MinVisNs ) break;
                    px1ns = nsnext;
                    nextTime = next->time.Val() + nspx;
                }
                num = next - it;
                px1 = px1ns * pxns;
            }
        }
        if( visible )
        {
            draw->AddCircleFilled( wpos + ImVec2( px0, ty0375 ), ty02, 0xFFDD8888 );
            if( !tooltipDisplayed && hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0 - ty02 - 2, y0 ), wpos + ImVec2( px0 + ty02 + 1, y1 ) ) )
            {
                tooltipDisplayed = true;
                CallstackTooltip( it->callstack.Val() );
                if( IsMouseClicked( 0 ) )
                {
                    m_callstackInfoWindow = it->callstack.Val();
                }
            }
        }
        else
        {
            DrawZigZag( draw, wpos + ImVec2( 0, ty0375 ), px0, std::max( px1, px0+MinVis ), ty01, 0xFF997777 );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, y0 ), wpos + ImVec2( std::max( px1, px0+MinVis ), y1 ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Multiple call stack samples" );
                TextFocused( "Number of samples:", RealToString( num ) );
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) )
                {
                    const auto prev = next-1;
                    ZoomToRange( it->time.Val(), prev->time.Val() + 1 );
                }
            }
        }
        it = next;
    }
}

#ifndef TRACY_NO_STATISTICS
int View::DispatchGhostLevel( const Vector<GhostZone>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax, uint64_t tid )
{
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    // Inline frames have to be taken into account, hence the multiply by 16 (arbitrary limit for inline frames in client)
    if( yPos + 16 * ostep >= yMin && yPos <= yMax )
    {
        return DrawGhostLevel( vec, hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
    }
    else
    {
        return SkipGhostLevel( vec, hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
    }
}

int View::DrawGhostLevel( const Vector<GhostZone>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax, uint64_t tid )
{
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart ), [] ( const auto& l, const auto& r ) { return l.end.Val() < r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.start.Val() < r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = *it;
        const auto end = ev.end.Val();
        const auto zsz = std::max( ( end - ev.start.Val() ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto MinVisNs = MinVisSize * nspx;
            const auto color = MixGhostColor( GetThreadColor( tid, depth ), 0x665555 );
            const auto px0 = ( ev.start.Val() - m_vd.zvStart ) * pxns;
            auto px1ns = ev.end.Val() - m_vd.zvStart;
            auto rend = end;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { return l.end.Val() < r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = it->end.Val();
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                rend = nend;
                nextTime = nend + nspx;
            }
            const auto px1 = px1ns * pxns;
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
            {
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.start.Val(), rend , true };
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Multiple ghost zones" );
                ImGui::Separator();
                TextFocused( "Execution time:", TimeToString( rend - ev.start.Val() ) );
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) && rend - ev.start.Val() > 0 )
                {
                    ZoomToRange( ev.start.Val(), rend );
                }
            }
        }
        else
        {
            const auto& ghostKey = m_worker.GetGhostFrame( ev.frame );
            const auto frame = m_worker.GetCallstackFrame( ghostKey.frame );

            uint32_t color;
            if( m_vd.dynamicColors == 2 )
            {
                if( frame )
                {
                    const auto& sym = frame->data[ghostKey.inlineFrame];
                    color = GetHsvColor( sym.name.Idx(), depth );
                }
                else
                {
                    color = GetHsvColor( ghostKey.frame.data, depth );
                }
            }
            else
            {
                color = MixGhostColor( GetThreadColor( tid, depth ), 0x665555 );
            }

            const auto pr0 = ( ev.start.Val() - m_vd.zvStart ) * pxns;
            const auto pr1 = ( ev.end.Val() - m_vd.zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            if( !frame )
            {
                char symName[64];
                sprintf( symName, "0x%" PRIx64, m_worker.GetCanonicalPointer( ghostKey.frame ) );
                const auto tsz = ImGui::CalcTextSize( symName );

                const auto accentColor = HighlightColor( color );
                const auto darkColor = DarkenColor( color );
                const auto txtColor = 0xFF888888;
                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), DarkenColor( color ) );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), accentColor, 1.f );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, 1.f );

                if( tsz.x < zsz )
                {
                    const auto x = ( ev.start.Val() - m_vd.zvStart ) * pxns + ( ( end - ev.start.Val() ) * pxns - tsz.x ) / 2;
                    if( x < 0 || x > w - tsz.x )
                    {
                        ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                        DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), txtColor, symName );
                        ImGui::PopClipRect();
                    }
                    else if( ev.start.Val() == ev.end.Val() )
                    {
                        DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), txtColor, symName );
                    }
                    else
                    {
                        DrawTextContrast( draw, wpos + ImVec2( x, offset ), txtColor, symName );
                    }
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( ( ev.start.Val() - m_vd.zvStart ) * pxns, offset ), txtColor, symName );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
                {
                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.start.Val(), ev.end.Val() , true };
                    ImGui::BeginTooltip();
                    TextDisabledUnformatted( ICON_FA_GHOST " Ghost zone" );
                    ImGui::Separator();
                    TextFocused( "Unknown frame:", symName );
                    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                    if( m_worker.IsThreadFiber( tid ) )
                    {
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                    }
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( ev.end.Val() - ev.start.Val() ) );
                    ImGui::EndTooltip();
                    if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.start.Val(), ev.end.Val() );
                    }
                }
            }
            else
            {
                const auto& sym = frame->data[ghostKey.inlineFrame];
                const auto isInline = ghostKey.inlineFrame != frame->size-1;
                const auto col = isInline ? DarkenColor( color ) : color;
                auto symName = m_worker.GetString( sym.name );
                uint32_t txtColor;
                if( symName[0] == '[' )
                {
                    txtColor = 0xFF999999;
                }
                else if( !isInline && ( m_worker.GetCanonicalPointer( ghostKey.frame ) >> 63 != 0 ) )
                {
                    txtColor = 0xFF8888FF;
                }
                else
                {
                    txtColor = 0xFFFFFFFF;
                }
                auto tsz = ImGui::CalcTextSize( symName );

                const auto accentColor = HighlightColor( col );
                const auto darkColor = DarkenColor( col );
                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), col );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), accentColor, 1.f );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, 1.f );

                auto origSymName = symName;
                if( tsz.x > zsz )
                {
                    symName = ShortenNamespace( symName );
                    tsz = ImGui::CalcTextSize( symName );
                }

                if( tsz.x < zsz )
                {
                    const auto x = ( ev.start.Val() - m_vd.zvStart ) * pxns + ( ( end - ev.start.Val() ) * pxns - tsz.x ) / 2;
                    if( x < 0 || x > w - tsz.x )
                    {
                        ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                        DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), txtColor, symName );
                        ImGui::PopClipRect();
                    }
                    else if( ev.start.Val() == ev.end.Val() )
                    {
                        DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), txtColor, symName );
                    }
                    else
                    {
                        DrawTextContrast( draw, wpos + ImVec2( x, offset ), txtColor, symName );
                    }
                }
                else
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( ( ev.start.Val() - m_vd.zvStart ) * pxns, offset ), txtColor, symName );
                    ImGui::PopClipRect();
                }

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
                {
                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.start.Val(), ev.end.Val(), true };
                    ImGui::BeginTooltip();
                    TextDisabledUnformatted( ICON_FA_GHOST " Ghost zone" );
                    if( sym.symAddr >> 63 != 0 )
                    {
                        ImGui::SameLine();
                        TextDisabledUnformatted( ICON_FA_HAT_WIZARD " kernel" );
                    }
                    ImGui::Separator();
                    ImGui::TextUnformatted( origSymName );
                    if( isInline )
                    {
                        ImGui::SameLine();
                        TextDisabledUnformatted( "[inline]" );
                    }
                    const auto symbol = m_worker.GetSymbolData( sym.symAddr );
                    if( symbol ) TextFocused( "Image:", m_worker.GetString( symbol->imageName ) );
                    TextDisabledUnformatted( "Location:" );
                    ImGui::SameLine();
                    const char* file = m_worker.GetString( sym.file );
                    uint32_t line = sym.line;
                    ImGui::TextUnformatted( LocationToString( file, line ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(0x%" PRIx64 ")", sym.symAddr );
                    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                    if( m_worker.IsThreadFiber( tid ) )
                    {
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                    }
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( ev.end.Val() - ev.start.Val() ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 0 ) )
                    {
                        ViewDispatch( file, line, sym.symAddr );
                    }
                    else if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.start.Val(), ev.end.Val() );
                    }
                }
            }

            if( ev.child >= 0 )
            {
                const auto d = DispatchGhostLevel( m_worker.GetGhostChildren( ev.child ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }

    return maxdepth;
}

int View::SkipGhostLevel( const Vector<GhostZone>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax, uint64_t tid )
{
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart ), [] ( const auto& l, const auto& r ) { return l.end.Val() < r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.start.Val() < r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = *it;
        const auto end = ev.end.Val();
        const auto zsz = std::max( ( end - ev.start.Val() ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto MinVisNs = MinVisSize * nspx;
            auto px1ns = ev.end.Val() - m_vd.zvStart;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { return l.end.Val() < r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = it->end.Val();
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                nextTime = nend + nspx;
            }
        }
        else
        {
            if( ev.child >= 0 )
            {
                const auto d = DispatchGhostLevel( m_worker.GetGhostChildren( ev.child ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }

    return maxdepth;
}
#endif

int View::DispatchZoneLevel( const Vector<short_ptr<ZoneEvent>>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax, uint64_t tid )
{
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        if( vec.is_magic() )
        {
            return DrawZoneLevel<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &vec ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
        }
        else
        {
            return DrawZoneLevel<VectorAdapterPointer<ZoneEvent>>( vec, hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
        }
    }
    else
    {
        if( vec.is_magic() )
        {
            return SkipZoneLevel<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &vec ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
        }
        else
        {
            return SkipZoneLevel<VectorAdapterPointer<ZoneEvent>>( vec, hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
        }
    }
}

template<typename Adapter, typename V>
int View::DrawZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax, uint64_t tid )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart - delay ), [] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)a(l).End() < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_vd.zvEnd + resolution, [] ( const auto& l, const auto& r ) { Adapter a; return a(l).Start() < r; } );
    if( it == zitend ) return depth;
    Adapter a;
    if( !a(*it).IsEndValid() && m_worker.GetZoneEnd( a(*it) ) < m_vd.zvStart ) return depth;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    const auto ty025 = round( ty * 0.25f );
    const auto ty05  = round( ty * 0.5f );
    const auto ty075 = round( ty * 0.75f );

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = a(*it);
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = std::max( ( end - ev.Start() ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto MinVisNs = MinVisSize * nspx;
            const auto color = GetThreadColor( tid, depth );
            int num = 0;
            const auto px0 = ( ev.Start() - m_vd.zvStart ) * pxns;
            auto px1ns = end - m_vd.zvStart;
            auto rend = end;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)a(l).End() < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                num += std::distance( prevIt, it );
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( a(*it) );
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                rend = nend;
                nextTime = nend + nspx;
            }
            const auto px1 = px1ns * pxns;
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
            {
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.Start(), rend, true };
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - ev.Start() ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) && rend - ev.Start() > 0 )
                    {
                        ZoomToRange( ev.Start(), rend );
                    }
                }
                else
                {
                    ZoneTooltip( ev );

                    if( IsMouseClicked( 2 ) && rend - ev.Start() > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( IsMouseClicked( 0 ) )
                    {
                        if( ImGui::GetIO().KeyCtrl )
                        {
                            auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
                            m_findZone.ShowZone( ev.SrcLoc(), m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
                        }
                        else
                        {
                            ShowZoneInfo( ev );
                        }
                    }

                    m_zoneSrcLocHighlight = ev.SrcLoc();
                    m_zoneHover = &ev;
                }
            }
            const auto tmp = RealToString( num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            const auto zoneColor = GetZoneColorData( ev, tid, depth );
            const char* zoneName = m_worker.GetZoneName( ev );

            if( ev.HasChildren() )
            {
                const auto d = DispatchZoneLevel( m_worker.GetZoneChildren( ev.Child() ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
                if( d > maxdepth ) maxdepth = d;
            }

            auto tsz = ImGui::CalcTextSize( zoneName );
            if( tsz.x > zsz )
            {
                zoneName = ShortenNamespace( zoneName );
                tsz = ImGui::CalcTextSize( zoneName );
            }

            const auto pr0 = ( ev.Start() - m_vd.zvStart ) * pxns;
            const auto pr1 = ( end - m_vd.zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), zoneColor.color );
            if( zoneColor.highlight )
            {
                draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), zoneColor.accentColor, 0.f, -1, zoneColor.thickness );
            }
            else
            {
                const auto darkColor = DarkenColor( zoneColor.color );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), zoneColor.accentColor, zoneColor.thickness );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, zoneColor.thickness );
            }
            if( dsz > MinVisSize )
            {
                const auto diff = dsz - MinVisSize;
                uint32_t color;
                if( diff < 1 )
                {
                    color = ( uint32_t( diff * 0x88 ) << 24 ) | 0x2222DD;
                }
                else
                {
                    color = 0x882222DD;
                }

                draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz, pr1 ), offset + tsz.y ), color );
                draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), color );
            }
            if( rsz > MinVisSize )
            {
                const auto diff = rsz - MinVisSize;
                uint32_t color;
                if( diff < 1 )
                {
                    color = ( uint32_t( diff * 0xAA ) << 24 ) | 0xFFFFFF;
                }
                else
                {
                    color = 0xAAFFFFFF;
                }

                DrawLine( draw, dpos + ImVec2( pr0 + rsz, offset + ty05  ), dpos + ImVec2( pr0 - rsz, offset + ty05  ), color );
                DrawLine( draw, dpos + ImVec2( pr0 + rsz, offset + ty025 ), dpos + ImVec2( pr0 + rsz, offset + ty075 ), color );
                DrawLine( draw, dpos + ImVec2( pr0 - rsz, offset + ty025 ), dpos + ImVec2( pr0 - rsz, offset + ty075 ), color );

                DrawLine( draw, dpos + ImVec2( pr1 + rsz, offset + ty05  ), dpos + ImVec2( pr1 - rsz, offset + ty05  ), color );
                DrawLine( draw, dpos + ImVec2( pr1 + rsz, offset + ty025 ), dpos + ImVec2( pr1 + rsz, offset + ty075 ), color );
                DrawLine( draw, dpos + ImVec2( pr1 - rsz, offset + ty025 ), dpos + ImVec2( pr1 - rsz, offset + ty075 ), color );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( ev.Start() - m_vd.zvStart ) * pxns + ( ( end - ev.Start() ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.Start() == ev.End() )
                {
                    DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), 0xFFFFFFFF, zoneName );
                }
                else
                {
                    DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFFFFFFFF, zoneName );
                }
            }
            else
            {
                ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                DrawTextContrast( draw, wpos + ImVec2( ( ev.Start() - m_vd.zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
            {
                ZoneTooltip( ev );
                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { ev.Start(), m_worker.GetZoneEnd( ev ), true };

                if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( IsMouseClicked( 0 ) )
                {
                    if( ImGui::GetIO().KeyCtrl )
                    {
                        auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
                        m_findZone.ShowZone( ev.SrcLoc(), m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
                    }
                    else
                    {
                        ShowZoneInfo( ev );
                    }
                }

                m_zoneSrcLocHighlight = ev.SrcLoc();
                m_zoneHover = &ev;
            }

            ++it;
        }
    }
    return maxdepth;
}

template<typename Adapter, typename V>
int View::SkipZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax, uint64_t tid )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart - delay ), [] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)a(l).End() < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_vd.zvEnd + resolution, [] ( const auto& l, const auto& r ) { Adapter a; return a(l).Start() < r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    Adapter a;
    while( it < zitend )
    {
        auto& ev = a(*it);
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = std::max( ( end - ev.Start() ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto MinVisNs = MinVisSize * nspx;
            auto px1ns = end - m_vd.zvStart;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)a(l).End() < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( a(*it) );
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                nextTime = nend + nspx;
            }
        }
        else
        {
            if( ev.HasChildren() )
            {
                const auto d = DispatchZoneLevel( m_worker.GetZoneChildren( ev.Child() ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax, tid );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }
    return maxdepth;
}

int View::DispatchGpuZoneLevel( const Vector<short_ptr<GpuEvent>>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        if( vec.is_magic() )
        {
            return DrawGpuZoneLevel<VectorAdapterDirect<GpuEvent>>( *(Vector<GpuEvent>*)&vec, hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
        }
        else
        {
            return DrawGpuZoneLevel<VectorAdapterPointer<GpuEvent>>( vec, hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
        }
    }
    else
    {
        if( vec.is_magic() )
        {
            return SkipGpuZoneLevel<VectorAdapterDirect<GpuEvent>>( *(Vector<GpuEvent>*)&vec, hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
        }
        else
        {
            return SkipGpuZoneLevel<VectorAdapterPointer<GpuEvent>>( vec, hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
        }
    }
}

template<typename Adapter, typename V>
int View::DrawGpuZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart - delay ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).GpuEnd(), begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), std::max<int64_t>( 0, m_vd.zvEnd + resolution ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).GpuStart(), begin, drift ) < (uint64_t)r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    depth++;
    int maxdepth = depth;

    Adapter a;
    while( it < zitend )
    {
        auto& ev = a(*it);
        auto end = m_worker.GetZoneEnd( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.GpuStart(), begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto color = GetZoneColor( ev );
            const auto MinVisNs = MinVisSize * nspx;
            int num = 0;
            const auto px0 = ( start - m_vd.zvStart ) * pxns;
            auto px1ns = end - m_vd.zvStart;
            auto rend = end;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, std::max<int64_t>( 0, nextTime ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).GpuEnd(), begin, drift ) < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                num += std::distance( prevIt, it );
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( a(*it) ), begin, drift );
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext < 0 || nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                rend = nend;
                nextTime = nend + nspx;
            }
            const auto px1 = px1ns * pxns;
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty + 1 ) ) )
            {
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - start ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToRange( start, rend );
                    }
                }
                else
                {
                    const auto zoneThread = thread != 0 ? thread : m_worker.DecompressThread( ev.Thread() );
                    ZoneTooltip( ev );

                    if( IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( IsMouseClicked( 0 ) )
                    {
                        ShowZoneInfo( ev, zoneThread );
                    }

                    m_gpuThread = zoneThread;
                    m_gpuStart = ev.CpuStart();
                    m_gpuEnd = ev.CpuEnd();
                }
            }
            const auto tmp = RealToString( num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            if( ev.Child() >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.Child() ), hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }

            const char* zoneName = m_worker.GetZoneName( ev );
            auto tsz = ImGui::CalcTextSize( zoneName );

            const auto pr0 = ( start - m_vd.zvStart ) * pxns;
            const auto pr1 = ( end - m_vd.zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            const auto zoneColor = GetZoneColorData( ev );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), zoneColor.color );
            if( zoneColor.highlight )
            {
                draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), zoneColor.accentColor, 0.f, -1, zoneColor.thickness );
            }
            else
            {
                const auto darkColor = DarkenColor( zoneColor.color );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), zoneColor.accentColor, zoneColor.thickness );
                DrawLine( draw, dpos + ImVec2( px0, offset + tsz.y ), dpos + ImVec2( px1-1, offset + tsz.y ), dpos + ImVec2( px1-1, offset ), darkColor, zoneColor.thickness );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( start - m_vd.zvStart ) * pxns + ( ( end - start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.GpuStart() == ev.GpuEnd() )
                {
                    DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset ), 0xFFFFFFFF, zoneName );
                }
                else
                {
                    DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFFFFFFFF, zoneName );
                }
            }
            else
            {
                ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                DrawTextContrast( draw, wpos + ImVec2( ( start - m_vd.zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y + 1 ) ) )
            {
                const auto zoneThread = thread != 0 ? thread : m_worker.DecompressThread( ev.Thread() );
                ZoneTooltip( ev );

                if( !m_zoomAnim.active && IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( IsMouseClicked( 0 ) )
                {
                    ShowZoneInfo( ev, zoneThread );
                }

                m_gpuThread = zoneThread;
                m_gpuStart = ev.CpuStart();
                m_gpuEnd = ev.CpuEnd();
            }

            ++it;
        }
    }
    return maxdepth;
}

template<typename Adapter, typename V>
int View::SkipGpuZoneLevel( const V& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart - delay ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).GpuEnd(), begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), std::max<int64_t>( 0, m_vd.zvEnd + resolution ), [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).GpuStart(), begin, drift ) < (uint64_t)r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    Adapter a;
    while( it < zitend )
    {
        auto& ev = a(*it);
        auto end = m_worker.GetZoneEnd( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.GpuStart(), begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            const auto MinVisNs = MinVisSize * nspx;
            auto px1ns = end - m_vd.zvStart;
            auto nextTime = end + MinVisNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [begin, drift] ( const auto& l, const auto& r ) { Adapter a; return (uint64_t)AdjustGpuTime( a(l).GpuEnd(), begin, drift ) < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( a(*it) ), begin, drift );
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinVisNs * 2 ) break;
                px1ns = nsnext;
                nextTime = nend + nspx;
            }
        }
        else
        {
            if( ev.Child() >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.Child() ), hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }
    return maxdepth;
}

enum class LockState
{
    Nothing,
    HasLock,            // green
    HasBlockingLock,    // yellow
    WaitLock            // red
};

static Vector<LockEventPtr>::const_iterator GetNextLockEvent( const Vector<LockEventPtr>::const_iterator& it, const Vector<LockEventPtr>::const_iterator& end, LockState& nextState, uint64_t threadBit )
{
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            if( next->lockCount != 0 )
            {
                if( GetThreadBit( next->lockingThread ) == threadBit )
                {
                    nextState = AreOtherWaiting( next->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                    break;
                }
                else if( IsThreadWaiting( next->waitList, threadBit ) )
                {
                    nextState = LockState::WaitLock;
                    break;
                }
            }
            next++;
        }
        break;
    case LockState::HasLock:
        while( next < end )
        {
            if( next->lockCount == 0 )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( next->waitList != 0 )
            {
                if( AreOtherWaiting( next->waitList, threadBit ) )
                {
                    nextState = LockState::HasBlockingLock;
                }
                break;
            }
            if( next->waitList != it->waitList || next->lockCount != it->lockCount )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::HasBlockingLock:
        while( next < end )
        {
            if( next->lockCount == 0 )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( next->waitList != it->waitList || next->lockCount != it->lockCount )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::WaitLock:
        while( next < end )
        {
            if( GetThreadBit( next->lockingThread ) == threadBit )
            {
                nextState = AreOtherWaiting( next->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( next->lockingThread != it->lockingThread )
            {
                break;
            }
            if( next->lockCount == 0 )
            {
                break;
            }
            next++;
        }
        break;
    default:
        assert( false );
        break;
    }

    return next;
}

static Vector<LockEventPtr>::const_iterator GetNextLockEventShared( const Vector<LockEventPtr>::const_iterator& it, const Vector<LockEventPtr>::const_iterator& end, LockState& nextState, uint64_t threadBit )
{
    const auto itptr = (const LockEventShared*)(const LockEvent*)it->ptr;
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)(const LockEvent*)next->ptr;
            if( next->lockCount != 0 )
            {
                const auto wait = next->waitList | ptr->waitShared;
                if( GetThreadBit( next->lockingThread ) == threadBit )
                {
                    nextState = AreOtherWaiting( wait, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                    break;
                }
                else if( IsThreadWaiting( wait, threadBit ) )
                {
                    nextState = LockState::WaitLock;
                    break;
                }
            }
            else if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = ( next->waitList != 0 ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            else if( ptr->sharedList != 0 && IsThreadWaiting( next->waitList, threadBit ) )
            {
                nextState = LockState::WaitLock;
                break;
            }
            next++;
        }
        break;
    case LockState::HasLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)(const LockEvent*)next->ptr;
            if( next->lockCount == 0 && !IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( next->waitList != 0 )
            {
                if( AreOtherWaiting( next->waitList, threadBit ) )
                {
                    nextState = LockState::HasBlockingLock;
                }
                break;
            }
            else if( !IsThreadWaiting( ptr->sharedList, threadBit ) && ptr->waitShared != 0 )
            {
                nextState = LockState::HasBlockingLock;
                break;
            }
            if( next->waitList != it->waitList || ptr->waitShared != itptr->waitShared || next->lockCount != it->lockCount || ptr->sharedList != itptr->sharedList )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::HasBlockingLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)(const LockEvent*)next->ptr;
            if( next->lockCount == 0 && !IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( next->waitList != it->waitList || ptr->waitShared != itptr->waitShared || next->lockCount != it->lockCount || ptr->sharedList != itptr->sharedList )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::WaitLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)(const LockEvent*)next->ptr;
            if( GetThreadBit( next->lockingThread ) == threadBit )
            {
                const auto wait = next->waitList | ptr->waitShared;
                nextState = AreOtherWaiting( wait, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = ( next->waitList != 0 ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( next->lockingThread != it->lockingThread )
            {
                break;
            }
            if( next->lockCount == 0 && !IsThreadWaiting( ptr->waitShared, threadBit ) )
            {
                break;
            }
            next++;
        }
        break;
    default:
        assert( false );
        break;
    }

    return next;
}

static LockState CombineLockState( LockState state, LockState next )
{
    return (LockState)std::max( (int)state, (int)next );
}

void View::DrawLockHeader( uint32_t id, const LockMap& lockmap, const SourceLocation& srcloc, bool hover, ImDrawList* draw, const ImVec2& wpos, float w, float ty, float offset, uint8_t tid )
{
    char buf[1024];
    if( lockmap.customName.Active() )
    {
        sprintf( buf, "%" PRIu32 ": %s", id, m_worker.GetString( lockmap.customName ) );
    }
    else
    {
        sprintf( buf, "%" PRIu32 ": %s", id, m_worker.GetString( srcloc.function ) );
    }
    DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty + 1 ) ) )
    {
        m_lockHoverHighlight = id;

        if( ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty + 1 ) ) )
        {
            const auto& range = lockmap.range[tid];
            const auto activity = range.end - range.start;
            const auto traceLen = m_worker.GetLastTime();

            int64_t timeAnnounce = lockmap.timeAnnounce;
            int64_t timeTerminate = lockmap.timeTerminate;
            if( !lockmap.timeline.empty() )
            {
                if( timeAnnounce <= 0 )
                {
                    timeAnnounce = lockmap.timeline.front().ptr->Time();
                }
                if( timeTerminate <= 0 )
                {
                    timeTerminate = lockmap.timeline.back().ptr->Time();
                }
            }
            const auto lockLen = timeTerminate - timeAnnounce;

            ImGui::BeginTooltip();
            switch( lockmap.type )
            {
            case LockType::Lockable:
                TextFocused( "Type:", "lockable" );
                break;
            case LockType::SharedLockable:
                TextFocused( "Type:", "shared lockable" );
                break;
            default:
                assert( false );
                break;
            }
            ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
            ImGui::Separator();
            TextFocused( ICON_FA_RANDOM " Appeared at", TimeToString( range.start ) );
            TextFocused( ICON_FA_RANDOM " Last event at", TimeToString( range.end ) );
            TextFocused( ICON_FA_RANDOM " Activity time:", TimeToString( activity ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of lock lifetime)", activity / double( lockLen ) * 100 );
            ImGui::Separator();
            TextFocused( "Announce time:", TimeToString( timeAnnounce ) );
            TextFocused( "Terminate time:", TimeToString( timeTerminate ) );
            TextFocused( "Lifetime:", TimeToString( lockLen ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of trace time)", lockLen / double( traceLen ) * 100 );
            ImGui::Separator();
            TextDisabledUnformatted( "Thread list:" );
            ImGui::Indent( ty );
            for( const auto& t : lockmap.threadList )
            {
                SmallColorBox( GetThreadColor( t, 0 ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( t ) );
            }
            ImGui::Unindent( ty );
            ImGui::Separator();
            TextFocused( "Lock events:", RealToString( lockmap.timeline.size() ) );
            ImGui::EndTooltip();

            if( IsMouseClicked( 0 ) )
            {
                m_lockInfoWindow = id;
            }
            if( IsMouseClicked( 2 ) )
            {
                ZoomToRange( range.start, range.end );
            }
        }
    }
}

int View::DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int _offset, LockHighlight& highlight, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    const auto ty025 = round( ty * 0.25f );
    const auto ty05  = round( ty * 0.5f );
    const auto ty075 = round( ty * 0.75f );

    int cnt = 0;
    for( const auto& v : m_worker.GetLockMap() )
    {
        const auto& lockmap = *v.second;
        if( !lockmap.valid || !Vis( &lockmap ).visible ) continue;
        if( m_vd.onlyContendedLocks && ( lockmap.threadList.size() == 1 || !lockmap.isContended ) && m_lockInfoWindow != v.first ) continue;

        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;

        const auto offset = _offset + ostep * cnt;

        const auto& range = lockmap.range[it->second];
        const auto& tl = lockmap.timeline;
        assert( !tl.empty() );
        if( range.start > m_vd.zvEnd || range.end < m_vd.zvStart )
        {
            if( m_lockInfoWindow == v.first )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x2288DD88 );
                draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x4488DD88 );
                DrawLockHeader( v.first, lockmap, m_worker.GetSourceLocation( lockmap.srcloc ), hover, draw, wpos, w, ty, offset, it->second );
                cnt++;
            }

            continue;
        }

        auto GetNextLockFunc = lockmap.type == LockType::Lockable ? GetNextLockEvent : GetNextLockEventShared;

        const auto thread = it->second;
        const auto threadBit = GetThreadBit( thread );

        auto vbegin = std::lower_bound( tl.begin(), tl.end(), std::max( range.start, m_vd.zvStart - delay ), [] ( const auto& l, const auto& r ) { return l.ptr->Time() < r; } );
        const auto vend = std::lower_bound( vbegin, tl.end(), std::min( range.end, m_vd.zvEnd + resolution ), [] ( const auto& l, const auto& r ) { return l.ptr->Time() < r; } );

        if( vbegin > tl.begin() ) vbegin--;

        LockState state = LockState::Nothing;
        if( lockmap.type == LockType::Lockable )
        {
            if( vbegin->lockCount != 0 )
            {
                if( vbegin->lockingThread == thread )
                {
                    state = AreOtherWaiting( vbegin->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                }
                else if( IsThreadWaiting( vbegin->waitList, threadBit ) )
                {
                    state = LockState::WaitLock;
                }
            }
        }
        else
        {
            auto ptr = (const LockEventShared*)(const LockEvent*)vbegin->ptr;
            if( vbegin->lockCount != 0 )
            {
                if( vbegin->lockingThread == thread )
                {
                    state = ( AreOtherWaiting( vbegin->waitList, threadBit ) || AreOtherWaiting( ptr->waitShared, threadBit ) ) ? LockState::HasBlockingLock : LockState::HasLock;
                }
                else if( IsThreadWaiting( vbegin->waitList, threadBit ) || IsThreadWaiting( ptr->waitShared, threadBit ) )
                {
                    state = LockState::WaitLock;
                }
            }
            else if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                state = vbegin->waitList != 0 ? LockState::HasBlockingLock : LockState::HasLock;
            }
            else if( ptr->sharedList != 0 && IsThreadWaiting( vbegin->waitList, threadBit ) )
            {
                state = LockState::WaitLock;
            }
        }

        const auto yPos = wpos.y + offset;
        if( yPos + ostep >= yMin && yPos <= yMax )
        {
            bool drawn = false;
            const auto& srcloc = m_worker.GetSourceLocation( lockmap.srcloc );

            double pxend = 0;
            for(;;)
            {
                if( m_vd.onlyContendedLocks )
                {
                    while( vbegin < vend && ( state == LockState::Nothing || state == LockState::HasLock ) )
                    {
                        vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
                    }
                }
                else
                {
                    while( vbegin < vend && state == LockState::Nothing )
                    {
                        vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
                    }
                }
                if( vbegin >= vend ) break;

                assert( state != LockState::Nothing && ( !m_vd.onlyContendedLocks || state != LockState::HasLock ) );
                drawn = true;

                LockState drawState = state;
                auto next = GetNextLockFunc( vbegin, vend, state, threadBit );

                const auto t0 = vbegin->ptr->Time();
                int64_t t1 = next == tl.end() ? m_worker.GetLastTime() : next->ptr->Time();
                const auto px0 = std::max( pxend, ( t0 - m_vd.zvStart ) * pxns );
                auto tx0 = px0;
                double px1 = ( t1 - m_vd.zvStart ) * pxns;
                uint64_t condensed = 0;

                if( m_vd.onlyContendedLocks )
                {
                    for(;;)
                    {
                        if( next >= vend || px1 - tx0 > MinVisSize ) break;
                        auto n = next;
                        auto ns = state;
                        while( n < vend && ( ns == LockState::Nothing || ns == LockState::HasLock ) )
                        {
                            n = GetNextLockFunc( n, vend, ns, threadBit );
                        }
                        if( n >= vend ) break;
                        if( n == next )
                        {
                            n = GetNextLockFunc( n, vend, ns, threadBit );
                        }
                        drawState = CombineLockState( drawState, state );
                        condensed++;
                        const auto t2 = n == tl.end() ? m_worker.GetLastTime() : n->ptr->Time();
                        const auto px2 = ( t2 - m_vd.zvStart ) * pxns;
                        if( px2 - px1 > MinVisSize ) break;
                        if( drawState != ns && px2 - px0 > MinVisSize && !( ns == LockState::Nothing || ns == LockState::HasLock ) ) break;
                        t1 = t2;
                        tx0 = px1;
                        px1 = px2;
                        next = n;
                        state = ns;
                    }
                }
                else
                {
                    for(;;)
                    {
                        if( next >= vend || px1 - tx0 > MinVisSize ) break;
                        auto n = next;
                        auto ns = state;
                        while( n < vend && ns == LockState::Nothing )
                        {
                            n = GetNextLockFunc( n, vend, ns, threadBit );
                        }
                        if( n >= vend ) break;
                        if( n == next )
                        {
                            n = GetNextLockFunc( n, vend, ns, threadBit );
                        }
                        drawState = CombineLockState( drawState, state );
                        condensed++;
                        const auto t2 = n == tl.end() ? m_worker.GetLastTime() : n->ptr->Time();
                        const auto px2 = ( t2 - m_vd.zvStart ) * pxns;
                        if( px2 - px1 > MinVisSize ) break;
                        if( drawState != ns && px2 - px0 > MinVisSize && ns != LockState::Nothing ) break;
                        t1 = t2;
                        tx0 = px1;
                        px1 = px2;
                        next = n;
                        state = ns;
                    }
                }

                pxend = std::max( { px1, px0+MinVisSize, px0 + pxns * 0.5 } );

                bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty + 1 ) );
                if( itemHovered )
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        m_lockInfoWindow = v.first;
                    }
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( t0, t1 );
                    }

                    if( condensed > 1 )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Multiple lock events:", RealToString( condensed ) );
                        ImGui::EndTooltip();
                    }
                    else
                    {
                        highlight.blocked = drawState == LockState::HasBlockingLock;
                        if( !highlight.blocked )
                        {
                            highlight.id = v.first;
                            highlight.begin = t0;
                            highlight.end = t1;
                            highlight.thread = thread;
                            highlight.blocked = false;
                        }
                        else
                        {
                            auto b = vbegin;
                            while( b != tl.begin() )
                            {
                                if( b->lockingThread != vbegin->lockingThread )
                                {
                                    break;
                                }
                                b--;
                            }
                            b++;
                            highlight.begin = b->ptr->Time();

                            auto e = next;
                            while( e != tl.end() )
                            {
                                if( e->lockingThread != next->lockingThread )
                                {
                                    highlight.id = v.first;
                                    highlight.end = e->ptr->Time();
                                    highlight.thread = thread;
                                    break;
                                }
                                e++;
                            }
                        }

                        ImGui::BeginTooltip();
                        if( v.second->customName.Active() )
                        {
                            ImGui::Text( "Lock #%" PRIu32 ": %s", v.first, m_worker.GetString( v.second->customName ) );
                        }
                        else
                        {
                            ImGui::Text( "Lock #%" PRIu32 ": %s", v.first, m_worker.GetString( srcloc.function ) );
                        }
                        ImGui::Separator();
                        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                        TextFocused( "Time:", TimeToString( t1 - t0 ) );
                        ImGui::Separator();

                        int16_t markloc = 0;
                        auto it = vbegin;
                        for(;;)
                        {
                            if( it->ptr->thread == thread )
                            {
                                if( ( it->lockingThread == thread || IsThreadWaiting( it->waitList, threadBit ) ) && it->ptr->SrcLoc() != 0 )
                                {
                                    markloc = it->ptr->SrcLoc();
                                    break;
                                }
                            }
                            if( it == tl.begin() ) break;
                            --it;
                        }
                        if( markloc != 0 )
                        {
                            const auto& marklocdata = m_worker.GetSourceLocation( markloc );
                            ImGui::TextUnformatted( "Lock event location:" );
                            ImGui::TextUnformatted( m_worker.GetString( marklocdata.function ) );
                            ImGui::TextUnformatted( LocationToString( m_worker.GetString( marklocdata.file ), marklocdata.line ) );
                            ImGui::Separator();
                        }

                        if( lockmap.type == LockType::Lockable )
                        {
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                if( vbegin->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadName( tid ), vbegin->lockCount );
                                }
                                if( vbegin->waitList != 0 )
                                {
                                    assert( !AreOtherWaiting( next->waitList, threadBit ) );
                                    ImGui::TextUnformatted( "Recursive lock acquire in thread." );
                                }
                                break;
                            case LockState::HasBlockingLock:
                            {
                                if( vbegin->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), TracyCountBits( vbegin->waitList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), vbegin->lockCount, TracyCountBits( vbegin->waitList ) );
                                }
                                auto waitList = vbegin->waitList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( waitList != 0 )
                                {
                                    if( waitList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                    }
                                    waitList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockState::WaitLock:
                            {
                                if( vbegin->lockCount > 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other thread:", m_worker.GetThreadName( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadName( tid ) );
                                }
                                ImGui::Indent( ty );
                                ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[vbegin->lockingThread] ) );
                                ImGui::Unindent( ty );
                                break;
                            }
                            default:
                                assert( false );
                                break;
                            }
                        }
                        else
                        {
                            const auto ptr = (const LockEventShared*)(const LockEvent*)vbegin->ptr;
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                assert( vbegin->waitList == 0 );
                                if( ptr->sharedList == 0 )
                                {
                                    assert( vbegin->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%" PRIu64 "):", TracyCountBits( ptr->sharedList ) - 1 );
                                    auto sharedList = ptr->sharedList;
                                    int t = 0;
                                    ImGui::Indent( ty );
                                    while( sharedList != 0 )
                                    {
                                        if( sharedList & 0x1 && t != thread )
                                        {
                                            ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                        }
                                        sharedList >>= 1;
                                        t++;
                                    }
                                    ImGui::Unindent( ty );
                                }
                                break;
                            case LockState::HasBlockingLock:
                            {
                                if( ptr->sharedList == 0 )
                                {
                                    assert( vbegin->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), TracyCountBits( vbegin->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), TracyCountBits( vbegin->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock.", m_worker.GetThreadName( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%" PRIu64 "):", TracyCountBits( ptr->sharedList ) - 1 );
                                    auto sharedList = ptr->sharedList;
                                    int t = 0;
                                    ImGui::Indent( ty );
                                    while( sharedList != 0 )
                                    {
                                        if( sharedList & 0x1 && t != thread )
                                        {
                                            ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                        }
                                        sharedList >>= 1;
                                        t++;
                                    }
                                    ImGui::Unindent( ty );
                                    ImGui::Text( "Blocked threads (%" PRIu64 "):", TracyCountBits( vbegin->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }

                                auto waitList = vbegin->waitList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( waitList != 0 )
                                {
                                    if( waitList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                    }
                                    waitList >>= 1;
                                    t++;
                                }
                                auto waitShared = ptr->waitShared;
                                t = 0;
                                while( waitShared != 0 )
                                {
                                    if( waitShared & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                    }
                                    waitShared >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockState::WaitLock:
                            {
                                assert( vbegin->lockCount == 0 || vbegin->lockCount == 1 );
                                if( vbegin->lockCount != 0 || ptr->sharedList != 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), vbegin->lockCount + TracyCountBits( ptr->sharedList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadName( tid ) );
                                }
                                ImGui::Indent( ty );
                                if( vbegin->lockCount != 0 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[vbegin->lockingThread] ) );
                                }
                                auto sharedList = ptr->sharedList;
                                int t = 0;
                                while( sharedList != 0 )
                                {
                                    if( sharedList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                    }
                                    sharedList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            default:
                                assert( false );
                                break;
                            }
                        }
                        ImGui::EndTooltip();
                    }
                }

                const auto cfilled  = drawState == LockState::HasLock ? 0xFF228A22 : ( drawState == LockState::HasBlockingLock ? 0xFF228A8A : 0xFF2222BD );
                draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), cfilled );
                if( m_lockHighlight.thread != thread && ( drawState == LockState::HasBlockingLock ) != m_lockHighlight.blocked && next != tl.end() && m_lockHighlight.id == int64_t( v.first ) && m_lockHighlight.begin <= vbegin->ptr->Time() && m_lockHighlight.end >= next->ptr->Time() )
                {
                    const auto t = uint8_t( ( sin( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count() * 0.01 ) * 0.5 + 0.5 ) * 255 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), 0x00FFFFFF | ( t << 24 ), 0.f, -1, 2.f );
                }
                else if( condensed == 0 )
                {
                    const auto coutline = drawState == LockState::HasLock ? 0xFF3BA33B : ( drawState == LockState::HasBlockingLock ? 0xFF3BA3A3 : 0xFF3B3BD6 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), coutline );
                }
                else if( condensed > 1 )
                {
                    DrawZigZag( draw, wpos + ImVec2( 0, offset + ty05 ), px0, pxend, ty025, DarkenColor( cfilled ) );
                }

                const auto rx0 = ( t0 - m_vd.zvStart ) * pxns;
                if( dsz >= MinVisSize )
                {
                    draw->AddRectFilled( wpos + ImVec2( rx0, offset ), wpos + ImVec2( std::min( rx0+dsz, px1 ), offset + ty ), 0x882222DD );
                }
                if( rsz >= MinVisSize )
                {
                    DrawLine( draw, dpos + ImVec2( rx0 + rsz, offset + ty05  ), dpos + ImVec2( rx0 - rsz, offset + ty05  ), 0xAAFFFFFF );
                    DrawLine( draw, dpos + ImVec2( rx0 + rsz, offset + ty025 ), dpos + ImVec2( rx0 + rsz, offset + ty075 ), 0xAAFFFFFF );
                    DrawLine( draw, dpos + ImVec2( rx0 - rsz, offset + ty025 ), dpos + ImVec2( rx0 - rsz, offset + ty075 ), 0xAAFFFFFF );

                    DrawLine( draw, dpos + ImVec2( px1 + rsz, offset + ty05  ), dpos + ImVec2( px1 - rsz, offset + ty05  ), 0xAAFFFFFF );
                    DrawLine( draw, dpos + ImVec2( px1 + rsz, offset + ty025 ), dpos + ImVec2( px1 + rsz, offset + ty075 ), 0xAAFFFFFF );
                    DrawLine( draw, dpos + ImVec2( px1 - rsz, offset + ty025 ), dpos + ImVec2( px1 - rsz, offset + ty075 ), 0xAAFFFFFF );
                }

                vbegin = next;
            }

            if( drawn || m_lockInfoWindow == v.first )
            {
                if( m_lockInfoWindow == v.first )
                {
                    draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x2288DD88 );
                    draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x4488DD88 );
                }
                else if( m_lockHoverHighlight == v.first )
                {
                    draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x228888DD );
                    draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x448888DD );
                }

                DrawLockHeader( v.first, lockmap, srcloc, hover, draw, wpos, w, ty, offset, it->second );
                cnt++;
            }
        }
        else
        {
            while( vbegin < vend && ( state == LockState::Nothing || ( m_vd.onlyContendedLocks && state == LockState::HasLock ) ) )
            {
                vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
            }
            if( vbegin < vend ) cnt++;
        }
    }
    return cnt;
}

int View::DrawCpuData( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    auto cpuData = m_worker.GetCpuData();
    const auto cpuCnt = m_worker.GetCpuDataCpuCount();
    if( cpuCnt == 0 ) return offset;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    const auto ostep = ty + 1;
    const auto nspxdbl = 1.0 / pxns;
    const auto nspx = int64_t( nspxdbl );
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    static int cpuDataVisStub;
    auto& vis = Vis( &cpuDataVisStub );
    bool& showFull = vis.showFull;

    const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
    const auto oldOffset = offset;
    ImGui::PushClipRect( wpos, wpos + ImVec2( w, offset + vis.height ), true );
    if( yPos + ty >= yMin && yPos <= yMax )
    {
        if( showFull )
        {
            draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFFDD88DD );
        }
        else
        {
            draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF6E446E, 2.0f );
        }

        float txtx = ImGui::CalcTextSize( "CPU data" ).x;
        DrawTextContrast( draw, wpos + ImVec2( ty, offset ), showFull ? 0xFFDD88DD : 0xFF6E446E, "CPU data" );
        DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0x66DD88DD );

        if( hover && IsMouseClicked( 0 ) && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtx, offset + ty ) ) )
        {
            showFull = !showFull;
        }
    }
    offset += ostep;

    if( showFull )
    {
#ifdef TRACY_NO_STATISTICS
        if( m_vd.drawCpuUsageGraph )
#else
        if( m_vd.drawCpuUsageGraph && m_worker.IsCpuUsageReady() )
#endif
        {
            const auto cpuUsageHeight = floor( 30.f * GetScale() );
            if( wpos.y + offset + cpuUsageHeight + 3 >= yMin && wpos.y + offset <= yMax )
            {
                const auto iw = (size_t)w;
                m_worker.GetCpuUsage( m_vd.zvStart, nspxdbl, iw, m_cpuUsageBuf );

                const float cpuCntRev = 1.f / cpuCnt;
                float pos = 0;
                auto usage = m_cpuUsageBuf.begin();
                while( pos < w )
                {
                    float base;
                    if( usage->first != 0 )
                    {
                        base = dpos.y + offset + ( 1.f - usage->first * cpuCntRev ) * cpuUsageHeight;
                        DrawLine( draw, ImVec2( dpos.x + pos, dpos.y + offset + cpuUsageHeight ), ImVec2( dpos.x + pos, base ), 0xFF55BB55 );
                    }
                    else
                    {
                        base = dpos.y + offset + cpuUsageHeight;
                    }
                    if( usage->second != 0 )
                    {
                        int usageTotal = usage->first + usage->second;
                        DrawLine( draw, ImVec2( dpos.x + pos, base ), ImVec2( dpos.x + pos, dpos.y + offset + ( 1.f - usageTotal * cpuCntRev ) * cpuUsageHeight ), 0xFF666666 );
                    }
                    pos++;
                    usage++;
                }
                DrawLine( draw, dpos + ImVec2( 0, offset+cpuUsageHeight+2 ), dpos + ImVec2( w, offset+cpuUsageHeight+2 ), 0x22DD88DD );

                if( hover && ImGui::IsMouseHoveringRect( ImVec2( wpos.x, wpos.y + offset ), ImVec2( wpos.x + w, wpos.y + offset + cpuUsageHeight ), true ) )
                {
                    const auto& usage = m_cpuUsageBuf[ImGui::GetIO().MousePos.x - wpos.x];
                    ImGui::BeginTooltip();
                    TextFocused( "Cores used by profiled program:", RealToString( usage.first ) );
                    ImGui::SameLine();
                    char buf[64];
                    PrintStringPercent( buf, usage.first * cpuCntRev * 100 );
                    TextDisabledUnformatted( buf );
                    TextFocused( "Cores used by other programs:", RealToString( usage.second ) );
                    ImGui::SameLine();
                    PrintStringPercent( buf, usage.second * cpuCntRev * 100 );
                    TextDisabledUnformatted( buf );
                    TextFocused( "Number of cores:", RealToString( cpuCnt ) );
                    if( usage.first + usage.second != 0 )
                    {
                        const auto mt = m_vd.zvStart + ( ImGui::GetIO().MousePos.x - wpos.x ) * nspxdbl;
                        ImGui::Separator();
                        for( int i=0; i<cpuCnt; i++ )
                        {
                            if( !cpuData[i].cs.empty() )
                            {
                                auto& cs = cpuData[i].cs;
                                auto it = std::lower_bound( cs.begin(), cs.end(), mt, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                                if( it != cs.end() && it->Start() <= mt && it->End() >= mt )
                                {
                                    auto tt = m_worker.GetThreadTopology( i );
                                    if( tt )
                                    {
                                        ImGui::TextDisabled( "[%i:%i] CPU %i:", tt->package, tt->core, i );
                                    }
                                    else
                                    {
                                        ImGui::TextDisabled( "CPU %i:", i );
                                    }
                                    ImGui::SameLine();
                                    const auto thread = m_worker.DecompressThreadExternal( it->Thread() );
                                    bool local, untracked;
                                    const char* txt;
                                    auto label = GetThreadContextData( thread, local, untracked, txt );
                                    if( local || untracked )
                                    {
                                        uint32_t color;
                                        if( m_vd.dynamicColors != 0 )
                                        {
                                            color = local ? GetThreadColor( thread, 0 ) : ( untracked ? 0xFF663333 : 0xFF444444 );
                                        }
                                        else
                                        {
                                            color = local ? 0xFF334488 : ( untracked ? 0xFF663333 : 0xFF444444 );
                                        }
                                        TextColoredUnformatted( HighlightColor<75>( color ), label );
                                        ImGui::SameLine();
                                        ImGui::TextDisabled( "(%s)", RealToString( thread ) );
                                    }
                                    else
                                    {
                                        TextDisabledUnformatted( label );
                                    }
                                }
                            }
                        }
                    }
                    ImGui::EndTooltip();
                }
            }
            offset += cpuUsageHeight + 3;
        }

        ImGui::PushFont( m_smallFont );
        const auto sty = round( ImGui::GetTextLineHeight() );
        const auto sstep = sty + 1;

        const auto origOffset = offset;
        for( int i=0; i<cpuCnt; i++ )
        {
            if( !cpuData[i].cs.empty() )
            {
                if( wpos.y + offset + sty >= yMin && wpos.y + offset <= yMax )
                {
                    DrawLine( draw, dpos + ImVec2( 0, offset+sty ), dpos + ImVec2( w, offset+sty ), 0x22DD88DD );

                    auto& cs = cpuData[i].cs;
                    auto tt = m_worker.GetThreadTopology( i );

                    auto it = std::lower_bound( cs.begin(), cs.end(), std::max<int64_t>( 0, m_vd.zvStart ), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                    if( it != cs.end() )
                    {
                        auto eit = std::lower_bound( it, cs.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
                        while( it < eit )
                        {
                            const auto start = it->Start();
                            const auto end = it->End();
                            const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
                            if( zsz < MinVisSize )
                            {
                                const auto MinVisNs = MinVisSize * nspx;
                                int num = 0;
                                const auto px0 = ( start - m_vd.zvStart ) * pxns;
                                auto px1ns = end - m_vd.zvStart;
                                auto rend = end;
                                auto nextTime = end + MinVisNs;
                                for(;;)
                                {
                                    const auto prevIt = it;
                                    it = std::lower_bound( it, eit, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                                    if( it == prevIt ) ++it;
                                    num += std::distance( prevIt, it );
                                    if( it == eit ) break;
                                    const auto nend = it->IsEndValid() ? it->End() : m_worker.GetLastTime();
                                    const auto nsnext = nend - m_vd.zvStart;
                                    if( nsnext - px1ns >= MinVisNs * 2 ) break;
                                    px1ns = nsnext;
                                    rend = nend;
                                    nextTime = nend + nspx;
                                }
                                const auto px1 = px1ns * pxns;
                                DrawZigZag( draw, wpos + ImVec2( 0, offset + sty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), sty/4, 0xFF888888 );

                                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset-1 ), wpos + ImVec2( std::max( px1, px0+MinVisSize ), offset + sty ) ) )
                                {
                                    ImGui::PopFont();
                                    ImGui::BeginTooltip();
                                    TextFocused( "CPU:", RealToString( i ) );
                                    if( tt )
                                    {
                                        ImGui::SameLine();
                                        ImGui::Spacing();
                                        ImGui::SameLine();
                                        TextFocused( "Package:", RealToString( tt->package ) );
                                        ImGui::SameLine();
                                        TextFocused( "Core:", RealToString( tt->core ) );
                                    }
                                    TextFocused( "Context switch regions:", RealToString( num ) );
                                    ImGui::Separator();
                                    TextFocused( "Start time:", TimeToString( start ) );
                                    TextFocused( "End time:", TimeToString( rend ) );
                                    TextFocused( "Activity time:", TimeToString( rend - start ) );
                                    ImGui::EndTooltip();
                                    ImGui::PushFont( m_smallFont );

                                    if( IsMouseClicked( 2 ) )
                                    {
                                        ZoomToRange( start, rend );
                                    }
                                }
                            }
                            else
                            {
                                const auto thread = m_worker.DecompressThreadExternal( it->Thread() );
                                bool local, untracked;
                                const char* txt;
                                auto label = GetThreadContextData( thread, local, untracked, txt );
                                const auto pr0 = ( start - m_vd.zvStart ) * pxns;
                                const auto pr1 = ( end - m_vd.zvStart ) * pxns;
                                const auto px0 = std::max( pr0, -10.0 );
                                const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );

                                uint32_t color;
                                if( m_vd.dynamicColors != 0 )
                                {
                                    color = local ? GetThreadColor( thread, 0 ) : ( untracked ? 0xFF663333 : 0xFF444444 );
                                }
                                else
                                {
                                    color = local ? 0xFF334488 : ( untracked ? 0xFF663333 : 0xFF444444 );
                                }

                                draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + sty ), color );
                                if( m_drawThreadHighlight == thread )
                                {
                                    draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + sty ), 0xFFFFFFFF );
                                }
                                else
                                {
                                    const auto accentColor = HighlightColor( color );
                                    const auto darkColor = DarkenColor( color );
                                    DrawLine( draw, dpos + ImVec2( px0, offset + sty ), dpos + ImVec2( px0, offset ), dpos + ImVec2( px1-1, offset ), accentColor, 1.f );
                                    DrawLine( draw, dpos + ImVec2( px0, offset + sty ), dpos + ImVec2( px1-1, offset + sty ), dpos + ImVec2( px1-1, offset ), darkColor, 1.f );
                                }

                                auto tsz = ImGui::CalcTextSize( label );
                                if( tsz.x < zsz )
                                {
                                    const auto x = ( start - m_vd.zvStart ) * pxns + ( ( end - start ) * pxns - tsz.x ) / 2;
                                    if( x < 0 || x > w - tsz.x )
                                    {
                                        ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                                        DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                        ImGui::PopClipRect();
                                    }
                                    else if( start == end )
                                    {
                                        DrawTextContrast( draw, wpos + ImVec2( px0 + ( px1 - px0 - tsz.x ) * 0.5, offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                    }
                                    else
                                    {
                                        DrawTextContrast( draw, wpos + ImVec2( x, offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                    }
                                }
                                else
                                {
                                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                                    DrawTextContrast( draw, wpos + ImVec2( ( start - m_vd.zvStart ) * pxns, offset-1 ), local ? 0xFFFFFFFF : 0xAAFFFFFF, label );
                                    ImGui::PopClipRect();
                                }

                                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset-1 ), wpos + ImVec2( px1, offset + sty ) ) )
                                {
                                    m_drawThreadHighlight = thread;
                                    ImGui::PopFont();
                                    ImGui::BeginTooltip();
                                    TextFocused( "CPU:", RealToString( i ) );
                                    if( tt )
                                    {
                                        ImGui::SameLine();
                                        ImGui::Spacing();
                                        ImGui::SameLine();
                                        TextFocused( "Package:", RealToString( tt->package ) );
                                        ImGui::SameLine();
                                        TextFocused( "Core:", RealToString( tt->core ) );
                                    }
                                    if( local )
                                    {
                                        TextFocused( "Program:", m_worker.GetCaptureProgram().c_str() );
                                        ImGui::SameLine();
                                        TextDisabledUnformatted( "(profiled program)" );
                                        SmallColorBox( GetThreadColor( thread, 0 ) );
                                        ImGui::SameLine();
                                        TextFocused( "Thread:", m_worker.GetThreadName( thread ) );
                                        ImGui::SameLine();
                                        ImGui::TextDisabled( "(%s)", RealToString( thread ) );
                                        m_drawThreadMigrations = thread;
                                        m_cpuDataThread = thread;
                                    }
                                    else
                                    {
                                        if( untracked )
                                        {
                                            TextFocused( "Program:", m_worker.GetCaptureProgram().c_str() );
                                        }
                                        else
                                        {
                                            TextFocused( "Program:", txt );
                                        }
                                        ImGui::SameLine();
                                        if( untracked )
                                        {
                                            TextDisabledUnformatted( "(untracked thread in profiled program)" );
                                        }
                                        else
                                        {
                                            TextDisabledUnformatted( "(external)" );
                                        }
                                        TextFocused( "Thread:", m_worker.GetExternalName( thread ).second );
                                        ImGui::SameLine();
                                        ImGui::TextDisabled( "(%s)", RealToString( thread ) );
                                    }
                                    ImGui::Separator();
                                    TextFocused( "Start time:", TimeToStringExact( start ) );
                                    TextFocused( "End time:", TimeToStringExact( end ) );
                                    TextFocused( "Activity time:", TimeToString( end - start ) );
                                    ImGui::EndTooltip();
                                    ImGui::PushFont( m_smallFont );

                                    if( IsMouseClicked( 2 ) )
                                    {
                                        ZoomToRange( start, end );
                                    }
                                }
                                ++it;
                            }
                        }
                    }

                    char buf[64];
                    if( tt )
                    {
                        sprintf( buf, "[%i:%i] CPU %i", tt->package, tt->core, i );
                    }
                    else
                    {
                        sprintf( buf, "CPU %i", i );
                    }
                    const auto txtx = ImGui::CalcTextSize( buf ).x;
                    DrawTextContrast( draw, wpos + ImVec2( ty, offset-1 ), 0xFFDD88DD, buf );
                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset-1 ), wpos + ImVec2( sty + txtx, offset + sty ) ) )
                    {
                        ImGui::PopFont();
                        ImGui::BeginTooltip();
                        TextFocused( "CPU:", RealToString( i ) );
                        if( tt )
                        {
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Package:", RealToString( tt->package ) );
                            ImGui::SameLine();
                            TextFocused( "Core:", RealToString( tt->core ) );
                        }
                        TextFocused( "Context switch regions:", RealToString( cs.size() ) );
                        ImGui::EndTooltip();
                        ImGui::PushFont( m_smallFont );
                    }
                }
                offset += sstep;
            }
        }

        if( m_drawThreadMigrations != 0 )
        {
            auto ctxSwitch = m_worker.GetContextSwitchData( m_drawThreadMigrations );
            if( ctxSwitch )
            {
                const auto color = HighlightColor( GetThreadColor( m_drawThreadMigrations, -8 ) );

                auto& v = ctxSwitch->v;
                auto it = std::lower_bound( v.begin(), v.end(), m_vd.zvStart, [] ( const auto& l, const auto& r ) { return l.End() < r; } );
                if( it != v.begin() ) --it;
                auto end = std::lower_bound( it, v.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
                if( end == v.end() ) --end;

                while( it < end )
                {
                    const auto t0 = it->End();
                    const auto cpu0 = it->Cpu();

                    ++it;

                    const auto t1 = it->Start();
                    const auto cpu1 = it->Cpu();

                    const auto px0 = ( t0 - m_vd.zvStart ) * pxns;
                    const auto px1 = ( t1 - m_vd.zvStart ) * pxns;

                    if( t1 - t0 < 2 * nspx )
                    {
                        DrawLine( draw, dpos + ImVec2( px0, origOffset + sty * 0.5f + cpu0 * sstep ), dpos + ImVec2( px1, origOffset + sty * 0.5f + cpu1 * sstep ), color );
                    }
                    else
                    {
                        DrawLine( draw, dpos + ImVec2( px0, origOffset + sty * 0.5f + cpu0 * sstep ), dpos + ImVec2( px1, origOffset + sty * 0.5f + cpu1 * sstep ), 0xFF000000, 4.f );
                        DrawLine( draw, dpos + ImVec2( px0, origOffset + sty * 0.5f + cpu0 * sstep ), dpos + ImVec2( px1, origOffset + sty * 0.5f + cpu1 * sstep ), color, 2.f );
                    }
                }
            }
        }

        ImGui::PopFont();
    }

    offset += ostep * 0.2f;
    AdjustThreadHeight( vis, oldOffset, offset );
    ImGui::PopClipRect();

    return offset;
}

void View::DrawMessages()
{
    const auto& msgs = m_worker.GetMessages();

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1200 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Messages", &m_showMessages );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( msgs.empty() )
    {
        ImGui::TextUnformatted( "No messages were collected." );
        ImGui::End();
        return;
    }

    size_t tsz = 0;
    for( const auto& t : m_threadOrder ) if( !t->messages.empty() ) tsz++;

    bool filterChanged = m_messageFilter.Draw( ICON_FA_FILTER " Filter messages", 200 );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_BACKSPACE " Clear" ) )
    {
        m_messageFilter.Clear();
        filterChanged = true;
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Total message count:", RealToString( msgs.size() ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Visible messages:", RealToString( m_visibleMessages ) );
    if( m_worker.GetFrameImageCount() != 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_IMAGE " Show frame images", &m_showMessageImages );
    }

    bool threadsChanged = false;
    auto expand = ImGui::TreeNode( ICON_FA_RANDOM " Visible threads:" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", tsz );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleMsgThread( t->id ) = true;
            }
            threadsChanged = true;
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleMsgThread( t->id ) = false;
            }
            threadsChanged = true;
        }

        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            if( t->messages.empty() ) continue;
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &VisibleMsgThread( t->id ) ) )
            {
                threadsChanged = true;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->messages.size() ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
            }
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        ImGui::TreePop();
    }

    const bool msgsChanged = msgs.size() != m_prevMessages;
    if( filterChanged || threadsChanged )
    {
        bool showCallstack = false;
        m_msgList.reserve( msgs.size() );
        m_msgList.clear();
        if( m_messageFilter.IsActive() )
        {
            for( size_t i=0; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    const auto text = m_worker.GetString( msgs[i]->ref );
                    if( m_messageFilter.PassFilter( text ) )
                    {
                        if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                        m_msgList.push_back_no_space_check( uint32_t( i ) );
                    }
                }
            }
        }
        else
        {
            for( size_t i=0; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                    m_msgList.push_back_no_space_check( uint32_t( i ) );
                }
            }
        }
        m_messagesShowCallstack = showCallstack;
        m_visibleMessages = m_msgList.size();
        if( msgsChanged ) m_prevMessages = msgs.size();
    }
    else if( msgsChanged )
    {
        assert( m_prevMessages < msgs.size() );
        bool showCallstack = m_messagesShowCallstack;
        m_msgList.reserve( msgs.size() );
        if( m_messageFilter.IsActive() )
        {
            for( size_t i=m_prevMessages; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    const auto text = m_worker.GetString( msgs[i]->ref );
                    if( m_messageFilter.PassFilter( text ) )
                    {
                        if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                        m_msgList.push_back_no_space_check( uint32_t( i ) );
                    }
                }
            }
        }
        else
        {
            for( size_t i=m_prevMessages; i<msgs.size(); i++ )
            {
                const auto& v = msgs[i];
                const auto tid = m_worker.DecompressThread( v->thread );
                if( VisibleMsgThread( tid ) )
                {
                    if( !showCallstack && msgs[i]->callstack.Val() != 0 ) showCallstack = true;
                    m_msgList.push_back_no_space_check( uint32_t( i ) );
                }
            }
        }
        m_messagesShowCallstack = showCallstack;
        m_visibleMessages = m_msgList.size();
        m_prevMessages = msgs.size();
    }

    bool hasCallstack = m_messagesShowCallstack;
    ImGui::Separator();
    ImGui::BeginChild( "##messages" );
    const int colNum = hasCallstack ? 4 : 3;
    if( ImGui::BeginTable( "##messages", colNum, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Hideable ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Thread" );
        ImGui::TableSetupColumn( "Message" );
        if( hasCallstack ) ImGui::TableSetupColumn( "Call stack" );
        ImGui::TableHeadersRow();

        int idx = 0;
        if( m_msgToFocus )
        {
            for( const auto& msgIdx : m_msgList )
            {
                DrawMessageLine( *msgs[msgIdx], hasCallstack, idx );
            }
        }
        else
        {
            ImGuiListClipper clipper;
            clipper.Begin( m_msgList.size() );
            while( clipper.Step() )
            {
                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                {
                    DrawMessageLine( *msgs[m_msgList[i]], hasCallstack, idx );
                }
            }
        }

        if( m_worker.IsConnected() && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() )
        {
            ImGui::SetScrollHereY( 1.f );
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::End();
}

void View::DrawMessageLine( const MessageData& msg, bool hasCallstack, int& idx )
{
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    const auto text = m_worker.GetString( msg.ref );
    const auto tid = m_worker.DecompressThread( msg.thread );
    ImGui::PushID( &msg );
    if( ImGui::Selectable( TimeToStringExact( msg.time ), m_msgHighlight == &msg, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowItemOverlap ) )
    {
        CenterAtTime( msg.time );
    }
    if( ImGui::IsItemHovered() )
    {
        m_msgHighlight = &msg;

        if( m_showMessageImages )
        {
            const auto frameIdx = m_worker.GetFrameRange( *m_frames, msg.time, msg.time ).first;
            auto fi = m_worker.GetFrameImage( *m_frames, frameIdx );
            if( fi )
            {
                ImGui::BeginTooltip();
                if( fi != m_frameTexturePtr )
                {
                    if( !m_frameTexture ) m_frameTexture = MakeTexture();
                    UpdateTexture( m_frameTexture, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );
                    m_frameTexturePtr = fi;
                }
                if( fi->flip )
                {
                    ImGui::Image( m_frameTexture, ImVec2( fi->w, fi->h ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
                }
                else
                {
                    ImGui::Image( m_frameTexture, ImVec2( fi->w, fi->h ) );
                }
                ImGui::EndTooltip();
            }
        }
    }
    if( m_msgToFocus == &msg )
    {
        ImGui::SetScrollHereY();
        m_msgToFocus.Decay( nullptr );
        m_messagesScrollBottom = false;
    }
    ImGui::PopID();
    ImGui::TableNextColumn();
    SmallColorBox( GetThreadColor( tid, 0 ) );
    ImGui::SameLine();
    if( m_worker.IsThreadFiber( tid ) )
    {
        TextColoredUnformatted( 0xFF88FF88, m_worker.GetThreadName( tid ) );
    }
    else
    {
        ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
    }
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
    ImGui::TableNextColumn();
    auto tend = text;
    while( *tend != '\0' && *tend != '\n' ) tend++;
    ImGui::PushStyleColor( ImGuiCol_Text, msg.color );
    const auto cw = ImGui::GetContentRegionAvail().x;
    const auto tw = ImGui::CalcTextSize( text, tend ).x;
    ImGui::TextUnformatted( text, tend );
    if( tw > cw && ImGui::IsItemHovered() )
    {
        ImGui::SetNextWindowSize( ImVec2( 1000 * GetScale(), 0 ) );
        ImGui::BeginTooltip();
        ImGui::TextWrapped( "%s", text );
        ImGui::EndTooltip();
    }
    ImGui::PopStyleColor();
    if( hasCallstack )
    {
        ImGui::TableNextColumn();
        const auto cs = msg.callstack.Val();
        if( cs != 0 )
        {
            SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
            ImGui::SameLine();
            DrawCallstackCalls( cs, 4 );
        }
    }
}

void View::DrawHistogramMinMaxLabel( ImDrawList* draw, int64_t tmin, int64_t tmax, ImVec2 wpos, float w, float ty )
{
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto ty15 = round( ty * 1.5f );
    const auto mintxt = TimeToString( tmin );
    const auto maxtxt = TimeToString( tmax );
    const auto maxsz = ImGui::CalcTextSize( maxtxt ).x;
    DrawLine( draw, dpos, dpos + ImVec2( 0, ty15 ), 0x66FFFFFF );
    DrawLine( draw, dpos + ImVec2( w-1, 0 ), dpos + ImVec2( w-1, ty15 ), 0x66FFFFFF );
    draw->AddText( wpos + ImVec2( 0, ty15 ), 0x66FFFFFF, mintxt );
    draw->AddText( wpos + ImVec2( w-1-maxsz, ty15 ), 0x66FFFFFF, maxtxt );

    char range[64];
    sprintf( range, ICON_FA_LONG_ARROW_ALT_LEFT " %s " ICON_FA_LONG_ARROW_ALT_RIGHT, TimeToString( tmax - tmin ) );

    const auto rsz = ImGui::CalcTextSize( range ).x;
    draw->AddText( wpos + ImVec2( round( (w-1-rsz) * 0.5 ), ty15 ), 0x66FFFFFF, range );
}

void View::DrawSamplesStatistics( Vector<SymList>& data, int64_t timeRange, AccumulationMode accumulationMode )
{
    static unordered_flat_map<uint64_t, SymList> inlineMap;
    assert( inlineMap.empty() );
    if( !m_statSeparateInlines )
    {
        static unordered_flat_map<uint64_t, SymList> baseMap;
        assert( baseMap.empty() );
        for( auto& v : data )
        {
            auto sym = m_worker.GetSymbolData( v.symAddr );
            const auto symAddr = ( sym && sym->isInline ) ? m_worker.GetSymbolForAddress( v.symAddr ) : v.symAddr;
            auto it = baseMap.find( symAddr );
            if( it == baseMap.end() )
            {
                baseMap.emplace( symAddr, SymList { symAddr, v.incl, v.excl, 0 } );
            }
            else
            {
                assert( symAddr == it->second.symAddr );
                it->second.incl += v.incl;
                it->second.excl += v.excl;
                it->second.count++;
            }
        }
        for( auto& v : data ) inlineMap.emplace( v.symAddr, SymList { v.symAddr, v.incl, v.excl, v.count } );
        data.clear();
        for( auto& v : baseMap )
        {
            data.push_back_no_space_check( v.second );
        }
        baseMap.clear();
    }

    if( data.empty() )
    {
        ImGui::TextUnformatted( "No entries to be displayed." );
    }
    else
    {
        const auto& symMap = m_worker.GetSymbolMap();

        if( accumulationMode == AccumulationMode::SelfOnly )
        {
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l.excl != r.excl ? l.excl > r.excl : l.symAddr < r.symAddr; } );
        }
        else
        {
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l.incl != r.incl ? l.incl > r.incl : l.symAddr < r.symAddr; } );
        }

        ImGui::BeginChild( "##statisticsSampling" );
        if( ImGui::BeginTable( "##statisticsSampling", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY ) )
        {
            ImGui::TableSetupScrollFreeze( 0, 1 );
            ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_NoHide );
            ImGui::TableSetupColumn( "Location", ImGuiTableColumnFlags_NoSort );
            ImGui::TableSetupColumn( "Image" );
            ImGui::TableSetupColumn( m_statSampleTime ? "Time" : "Count", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
            ImGui::TableSetupColumn( "Code size", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
            ImGui::TableHeadersRow();

            double revSampleCount100;
            if( m_statRange.active && m_worker.GetSamplingPeriod() != 0 )
            {
                const auto st = m_statRange.max - m_statRange.min;
                const auto cnt = st / m_worker.GetSamplingPeriod();
                revSampleCount100 = 100. / cnt;
            }
            else
            {
                revSampleCount100 = 100. / m_worker.GetCallstackSampleCount();
            }

            const bool showAll = m_showAllSymbols;
            const auto period = m_worker.GetSamplingPeriod();
            int idx = 0;
            for( auto& v : data )
            {
                const auto cnt = accumulationMode == AccumulationMode::SelfOnly ? v.excl : v.incl;
                if( cnt > 0 || showAll )
                {
                    const char* name = "[unknown]";
                    const char* file = "[unknown]";
                    const char* imageName = "[unknown]";
                    uint32_t line = 0;
                    bool isInline = false;
                    uint32_t symlen = 0;
                    auto codeAddr = v.symAddr;

                    auto sit = symMap.find( v.symAddr );
                    if( sit != symMap.end() )
                    {
                        name = m_worker.GetString( sit->second.name );
                        imageName = m_worker.GetString( sit->second.imageName );
                        isInline = sit->second.isInline;
                        switch( m_statSampleLocation )
                        {
                        case 0:
                            file = m_worker.GetString( sit->second.file );
                            line = sit->second.line;
                            break;
                        case 1:
                            file = m_worker.GetString( sit->second.callFile );
                            line = sit->second.callLine;
                            break;
                        case 2:
                            if( sit->second.isInline )
                            {
                                file = m_worker.GetString( sit->second.callFile );
                                line = sit->second.callLine;
                            }
                            else
                            {
                                file = m_worker.GetString( sit->second.file );
                                line = sit->second.line;
                            }
                            break;
                        default:
                            assert( false );
                            break;
                        }
                        if( m_statHideUnknown && file[0] == '[' ) continue;
                        symlen = sit->second.size.Val();
                    }
                    else if( m_statHideUnknown )
                    {
                        continue;
                    }

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();

                    const bool isKernel = v.symAddr >> 63 != 0;
                    const char* parentName = nullptr;
                    if( symlen == 0 && !isKernel )
                    {
                        const auto parentAddr = m_worker.GetSymbolForAddress( v.symAddr );
                        if( parentAddr != 0 )
                        {
                            auto pit = symMap.find( parentAddr );
                            if( pit != symMap.end() )
                            {
                                codeAddr = parentAddr;
                                symlen = pit->second.size.Val();
                                parentName = m_worker.GetString( pit->second.name );
                            }
                        }
                    }

                    bool expand = false;
                    if( !m_statSeparateInlines )
                    {
                        if( v.count > 0 && v.symAddr != 0 )
                        {
                            ImGui::PushID( v.symAddr );
                            expand = ImGui::TreeNodeEx( "", v.count == 0 ? ImGuiTreeNodeFlags_Leaf : 0 );
                            ImGui::PopID();
                            ImGui::SameLine();
                        }
                    }
                    else if( isInline )
                    {
                        TextDisabledUnformatted( ICON_FA_CARET_RIGHT );
                        ImGui::SameLine();
                    }
                    uint32_t excl;
                    if( m_statSeparateInlines )
                    {
                        excl = v.excl;
                    }
                    else
                    {
                        auto it = inlineMap.find( v.symAddr );
                        excl = it != inlineMap.end() ? it->second.excl : 0;
                    }
                    bool hasNoSamples = v.symAddr == 0 || excl == 0;
                    if( !m_statSeparateInlines && hasNoSamples && v.symAddr != 0 && v.count > 0 )
                    {
                        auto inSym = m_worker.GetInlineSymbolList( v.symAddr, symlen );
                        if( inSym )
                        {
                            const auto symEnd = v.symAddr + symlen;
                            while( *inSym < symEnd )
                            {
                                auto sit = inlineMap.find( *inSym );
                                if( sit != inlineMap.end() )
                                {
                                    if( sit->second.excl != 0 )
                                    {
                                        hasNoSamples = false;
                                        break;
                                    }
                                }
                                inSym++;
                            }
                        }
                    }
                    if( hasNoSamples )
                    {
                        if( isKernel )
                        {
                            TextColoredUnformatted( 0xFF8888FF, name );
                        }
                        else
                        {
                            ImGui::TextUnformatted( name );
                        }
                    }
                    else
                    {
                        ImGui::PushID( idx++ );
                        if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                        const auto clicked = ImGui::Selectable( name, m_sampleParents.withInlines && m_sampleParents.symAddr == v.symAddr, ImGuiSelectableFlags_SpanAllColumns );
                        if( isKernel ) ImGui::PopStyleColor();
                        if( clicked ) ShowSampleParents( v.symAddr, !m_statSeparateInlines );
                        ImGui::PopID();
                    }
                    if( parentName )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", parentName );
                    }
                    if( !m_statSeparateInlines && v.count > 0 && v.symAddr != 0 )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(+%s)", RealToString( v.count ) );
                    }
                    ImGui::TableNextColumn();
                    float indentVal = 0.f;
                    if( m_statBuzzAnim.Match( v.symAddr ) )
                    {
                        const auto time = m_statBuzzAnim.Time();
                        indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::Indent( indentVal );
                    }
                    if( m_statShowAddress )
                    {
                        ImGui::TextDisabled( "0x%" PRIx64, v.symAddr );
                    }
                    else
                    {
                        TextDisabledUnformatted( LocationToString( file, line ) );
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        DrawSourceTooltip( file, line );
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( SourceFileValid( file, m_worker.GetCaptureTime(), *this, m_worker ) )
                            {
                                ViewSymbol( file, line, codeAddr, v.symAddr );
                                if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( false );
                            }
                            else if( symlen != 0 )
                            {
                                uint32_t len;
                                if( m_worker.GetSymbolCode( codeAddr, len ) )
                                {
                                    ViewSymbol( nullptr, 0, codeAddr, v.symAddr );
                                    if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( false );
                                }
                                else
                                {
                                    m_statBuzzAnim.Enable( v.symAddr, 0.5f );
                                }
                            }
                            else
                            {
                                m_statBuzzAnim.Enable( v.symAddr, 0.5f );
                            }
                        }
                    }
                    if( indentVal != 0.f )
                    {
                        ImGui::Unindent( indentVal );
                    }
                    ImGui::TableNextColumn();
                    TextDisabledUnformatted( imageName );
                    ImGui::TableNextColumn();
                    if( cnt > 0 )
                    {
                        char buf[64];
                        if( m_statSampleTime )
                        {
                            const auto t = cnt * period;
                            ImGui::TextUnformatted( TimeToString( t ) );
                            PrintStringPercent( buf, 100. * t / timeRange );
                        }
                        else
                        {
                            ImGui::TextUnformatted( RealToString( cnt ) );
                            PrintStringPercent( buf, cnt * revSampleCount100 );
                        }
                        ImGui::SameLine();
                        TextDisabledUnformatted( buf );
                    }
                    ImGui::TableNextColumn();
                    if( symlen != 0 )
                    {
                        if( m_worker.HasSymbolCode( codeAddr ) )
                        {
                            TextDisabledUnformatted( ICON_FA_DATABASE );
                            ImGui::SameLine();
                        }
                        if( isInline )
                        {
                            TextDisabledUnformatted( "<" );
                            ImGui::SameLine();
                        }
                        TextDisabledUnformatted( MemSizeToString( symlen ) );
                    }

                    if( !m_statSeparateInlines && expand )
                    {
                        assert( v.count > 0 );
                        assert( symlen != 0 );
                        auto inSym = m_worker.GetInlineSymbolList( v.symAddr, symlen );
                        assert( inSym != nullptr );
                        const auto symEnd = v.symAddr + symlen;
                        Vector<SymList> inSymList;
                        while( *inSym < symEnd )
                        {
                            auto sit = inlineMap.find( *inSym );
                            if( sit != inlineMap.end() )
                            {
                                inSymList.push_back( SymList { *inSym, sit->second.incl, sit->second.excl } );
                            }
                            else
                            {
                                inSymList.push_back( SymList { *inSym, 0, 0 } );
                            }
                            inSym++;
                        }
                        auto statIt = inlineMap.find( v.symAddr );
                        if( statIt != inlineMap.end() )
                        {
                            inSymList.push_back( SymList { v.symAddr, statIt->second.incl, statIt->second.excl } );
                        }

                        if( accumulationMode == AccumulationMode::SelfOnly )
                        {
                            pdqsort_branchless( inSymList.begin(), inSymList.end(), []( const auto& l, const auto& r ) { return l.excl != r.excl ? l.excl > r.excl : l.symAddr < r.symAddr; } );
                        }
                        else
                        {
                            pdqsort_branchless( inSymList.begin(), inSymList.end(), []( const auto& l, const auto& r ) { return l.incl != l.incl ? l.incl > r.incl : l.symAddr < r.symAddr; } );
                        }

                        ImGui::Indent();
                        for( auto& iv : inSymList )
                        {
                            const auto cnt = accumulationMode == AccumulationMode::SelfOnly ? iv.excl : iv.incl;
                            if( cnt > 0 || showAll )
                            {
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                auto sit = symMap.find( iv.symAddr );
                                assert( sit != symMap.end() );
                                name = m_worker.GetString( sit->second.name );
                                switch( m_statSampleLocation )
                                {
                                case 0:
                                    file = m_worker.GetString( sit->second.file );
                                    line = sit->second.line;
                                    break;
                                case 1:
                                    file = m_worker.GetString( sit->second.callFile );
                                    line = sit->second.callLine;
                                    break;
                                case 2:
                                    if( sit->second.isInline )
                                    {
                                        file = m_worker.GetString( sit->second.callFile );
                                        line = sit->second.callLine;
                                    }
                                    else
                                    {
                                        file = m_worker.GetString( sit->second.file );
                                        line = sit->second.line;
                                    }
                                    break;
                                default:
                                    assert( false );
                                    break;
                                }

                                const auto sn = iv.symAddr == v.symAddr ? "[ - self - ]" : name;
                                if( iv.excl == 0 )
                                {
                                    ImGui::TextUnformatted( sn );
                                }
                                else
                                {
                                    ImGui::PushID( idx++ );
                                    if( ImGui::Selectable( sn, !m_sampleParents.withInlines && m_sampleParents.symAddr == iv.symAddr, ImGuiSelectableFlags_SpanAllColumns ) )
                                    {
                                        ShowSampleParents( iv.symAddr, false );
                                    }
                                    ImGui::PopID();
                                }
                                ImGui::TableNextColumn();
                                float indentVal = 0.f;
                                if( m_statBuzzAnim.Match( iv.symAddr ) )
                                {
                                    const auto time = m_statBuzzAnim.Time();
                                    indentVal = sin( time * 60.f ) * 10.f * time;
                                    ImGui::Indent( indentVal );
                                }
                                if( m_statShowAddress )
                                {
                                    ImGui::TextDisabled( "0x%" PRIx64, iv.symAddr );
                                }
                                else
                                {
                                    TextDisabledUnformatted( LocationToString( file, line ) );
                                }
                                if( ImGui::IsItemHovered() )
                                {
                                    DrawSourceTooltip( file, line );
                                    if( ImGui::IsItemClicked( 1 ) )
                                    {
                                        if( SourceFileValid( file, m_worker.GetCaptureTime(), *this, m_worker ) )
                                        {
                                            ViewSymbol( file, line, codeAddr, iv.symAddr );
                                            if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( true );
                                        }
                                        else if( symlen != 0 )
                                        {
                                            uint32_t len;
                                            if( m_worker.GetSymbolCode( codeAddr, len ) )
                                            {
                                                ViewSymbol( nullptr, 0, codeAddr, iv.symAddr );
                                                if( !m_statSeparateInlines ) m_sourceView->CalcInlineStats( true );
                                            }
                                            else
                                            {
                                                m_statBuzzAnim.Enable( iv.symAddr, 0.5f );
                                            }
                                        }
                                        else
                                        {
                                            m_statBuzzAnim.Enable( iv.symAddr, 0.5f );
                                        }
                                    }
                                }
                                if( indentVal != 0.f )
                                {
                                    ImGui::Unindent( indentVal );
                                }
                                ImGui::TableNextColumn();
                                ImGui::TableNextColumn();
                                if( cnt > 0 )
                                {
                                    char buf[64];
                                    if( m_statSampleTime )
                                    {
                                        const auto t = cnt * period;
                                        ImGui::TextUnformatted( TimeToString( t ) );
                                        PrintStringPercent( buf, 100. * t / timeRange );
                                    }
                                    else
                                    {
                                        ImGui::TextUnformatted( RealToString( cnt ) );
                                        PrintStringPercent( buf, cnt * revSampleCount100 );
                                    }
                                    ImGui::SameLine();
                                    TextDisabledUnformatted( buf );
                                }
                            }
                        }
                        ImGui::Unindent();
                        ImGui::TreePop();
                    }
                }
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();

        inlineMap.clear();
    }
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

void View::DrawLockInfoWindow()
{
    bool visible = true;
    ImGui::Begin( "Lock info", &visible, ImGuiWindowFlags_AlwaysAutoResize );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        auto it = m_worker.GetLockMap().find( m_lockInfoWindow );
        assert( it != m_worker.GetLockMap().end() );
        const auto& lock = *it->second;
        const auto& srcloc = m_worker.GetSourceLocation( lock.srcloc );
        auto fileName = m_worker.GetString( srcloc.file );

        int64_t timeAnnounce = lock.timeAnnounce;
        int64_t timeTerminate = lock.timeTerminate;
        if( !lock.timeline.empty() )
        {
            if( timeAnnounce <= 0 )
            {
                timeAnnounce = lock.timeline.front().ptr->Time();
            }
            if( timeTerminate <= 0 )
            {
                timeTerminate = lock.timeline.back().ptr->Time();
            }
        }

        bool waitState = false;
        bool holdState = false;
        int64_t waitStartTime = 0;
        int64_t holdStartTime = 0;
        int64_t waitTotalTime = 0;
        int64_t holdTotalTime = 0;
        uint32_t maxWaitingThreads = 0;
        for( auto& v : lock.timeline )
        {
            if( holdState )
            {
                if( v.lockCount == 0 )
                {
                    holdTotalTime += v.ptr->Time() - holdStartTime;
                    holdState = false;
                }
            }
            else
            {
                if( v.lockCount != 0 )
                {
                    holdStartTime = v.ptr->Time();
                    holdState = true;
                }
            }
            if( waitState )
            {
                if( v.waitList == 0 )
                {
                    waitTotalTime += v.ptr->Time() - waitStartTime;
                    waitState = false;
                }
                else
                {
                    maxWaitingThreads = std::max<uint32_t>( maxWaitingThreads, TracyCountBits( v.waitList ) );
                }
            }
            else
            {
                if( v.waitList != 0 )
                {
                    waitStartTime = v.ptr->Time();
                    waitState = true;
                    maxWaitingThreads = std::max<uint32_t>( maxWaitingThreads, TracyCountBits( v.waitList ) );
                }
            }
        }

        ImGui::PushFont( m_bigFont );
        if( lock.customName.Active() )
        {
            ImGui::Text( "Lock #%" PRIu32 ": %s", m_lockInfoWindow, m_worker.GetString( lock.customName ) );
        }
        else
        {
            ImGui::Text( "Lock #%" PRIu32 ": %s", m_lockInfoWindow, m_worker.GetString( srcloc.function ) );
        }
        ImGui::PopFont();
        if( lock.customName.Active() )
        {
            TextFocused( "Name:", m_worker.GetString( srcloc.function ) );
        }
        TextDisabledUnformatted( "Location:" );
        if( m_lockInfoAnim.Match( m_lockInfoWindow ) )
        {
            const auto time = m_lockInfoAnim.Time();
            const auto indentVal = sin( time * 60.f ) * 10.f * time;
            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
        }
        else
        {
            ImGui::SameLine();
        }
        ImGui::TextUnformatted( LocationToString( fileName, srcloc.line ) );
        if( ImGui::IsItemClicked( 1 ) )
        {
            if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
            {
                ViewSource( fileName, srcloc.line );
            }
            else
            {
                m_lockInfoAnim.Enable( m_lockInfoWindow, 0.5f );
            }
        }
        ImGui::Separator();

        switch( lock.type )
        {
        case LockType::Lockable:
            TextFocused( "Type:", "lockable" );
            break;
        case LockType::SharedLockable:
            TextFocused( "Type:", "shared lockable" );
            break;
        default:
            assert( false );
            break;
        }
        TextFocused( "Lock events:", RealToString( lock.timeline.size() ) );
        ImGui::Separator();

        const auto announce = timeAnnounce;
        const auto terminate = timeTerminate;
        const auto lifetime = timeTerminate - timeAnnounce;
        const auto traceLen = m_worker.GetLastTime();

        TextFocused( "Announce time:", TimeToString( announce ) );
        TextFocused( "Terminate time:", TimeToString( terminate ) );
        TextFocused( "Lifetime:", TimeToString( lifetime ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of trace time)", lifetime / double( traceLen ) * 100 );
        ImGui::Separator();

        TextFocused( "Lock hold time:", TimeToString( holdTotalTime ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of lock lifetime)", holdTotalTime / float( lifetime ) * 100.f );
        TextFocused( "Lock wait time:", TimeToString( waitTotalTime ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of lock lifetime)", waitTotalTime / float( lifetime ) * 100.f );
        TextFocused( "Max waiting threads:", RealToString( maxWaitingThreads ) );
        ImGui::Separator();

        const auto threadList = ImGui::TreeNode( "Thread list" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", lock.threadList.size() );
        if( threadList )
        {
            for( const auto& t : lock.threadList )
            {
                SmallColorBox( GetThreadColor( t, 0 ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( t ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( t ) );
            }
            ImGui::TreePop();
        }
    }
    ImGui::End();
    if( !visible ) m_lockInfoWindow = InvalidId;
}

void View::DrawSelectedAnnotation()
{
    assert( m_selectedAnnotation );
    bool show = true;
    ImGui::Begin( "Annotation", &show, ImGuiWindowFlags_AlwaysAutoResize );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to annotation" ) )
        {
            ZoomToRange( m_selectedAnnotation->range.min, m_selectedAnnotation->range.max );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_TRASH_ALT " Remove" ) )
        {
            for( auto it = m_annotations.begin(); it != m_annotations.end(); ++it )
            {
                if( it->get() == m_selectedAnnotation )
                {
                    m_annotations.erase( it );
                    break;
                }
            }
            ImGui::End();
            m_selectedAnnotation = nullptr;
            return;
        }
        ImGui::Separator();
        {
            const auto desc = m_selectedAnnotation->text.c_str();
            const auto descsz = std::min<size_t>( 1023, m_selectedAnnotation->text.size() );
            char buf[1024];
            buf[descsz] = '\0';
            memcpy( buf, desc, descsz );
            if( ImGui::InputTextWithHint( "##anndesc", "Describe annotation", buf, 256 ) )
            {
                m_selectedAnnotation->text.assign( buf );
            }
        }
        ImVec4 col = ImGui::ColorConvertU32ToFloat4( m_selectedAnnotation->color );
        ImGui::ColorEdit3( "Color", &col.x );
        m_selectedAnnotation->color = ImGui::ColorConvertFloat4ToU32( col );
        ImGui::Separator();
        TextFocused( "Annotation begin:", TimeToStringExact( m_selectedAnnotation->range.min ) );
        TextFocused( "Annotation end:", TimeToStringExact( m_selectedAnnotation->range.max ) );
        TextFocused( "Annotation length:", TimeToString( m_selectedAnnotation->range.max - m_selectedAnnotation->range.min ) );
    }
    ImGui::End();
    if( !show ) m_selectedAnnotation = nullptr;
}

void View::DrawAnnotationList()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 600 * scale, 300 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Annotation list", &m_showAnnotationList );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    if( ImGui::Button( ICON_FA_PLUS " Add annotation" ) )
    {
        AddAnnotation( m_vd.zvStart, m_vd.zvEnd );
    }

    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();

    if( m_annotations.empty() )
    {
        ImGui::TextWrapped( "No annotations." );
        ImGui::Separator();
        ImGui::End();
        return;
    }

    TextFocused( "Annotations:", RealToString( m_annotations.size() ) );
    ImGui::Separator();
    ImGui::BeginChild( "##annotationList" );
    const bool ctrl = ImGui::GetIO().KeyCtrl;
    int remove = -1;
    int idx = 0;
    for( auto& ann : m_annotations )
    {
        ImGui::PushID( idx );
        if( ImGui::Button( ICON_FA_EDIT ) )
        {
            m_selectedAnnotation = ann.get();
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_MICROSCOPE ) )
        {
            ZoomToRange( ann->range.min, ann->range.max );
        }
        ImGui::SameLine();
        if( ButtonDisablable( ICON_FA_TRASH_ALT, !ctrl ) )
        {
            remove = idx;
        }
        if( !ctrl ) TooltipIfHovered( "Press ctrl key to enable removal" );
        ImGui::SameLine();
        ImGui::ColorButton( "c", ImGui::ColorConvertU32ToFloat4( ann->color ), ImGuiColorEditFlags_NoTooltip );
        ImGui::SameLine();
        if( m_selectedAnnotation == ann.get() )
        {
            bool t = true;
            ImGui::Selectable( "##annSelectable", &t );
            ImGui::SameLine( 0, 0 );
        }
        if( ann->text.empty() )
        {
            TextDisabledUnformatted( "Empty annotation" );
        }
        else
        {
            ImGui::TextUnformatted( ann->text.c_str() );
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::TextDisabled( "%s - %s (%s)", TimeToStringExact( ann->range.min ), TimeToStringExact( ann->range.max ), TimeToString( ann->range.max - ann->range.min ) );
        ImGui::PopID();
        idx++;
    }
    if( remove >= 0 )
    {
        if( m_annotations[remove].get() == m_selectedAnnotation ) m_selectedAnnotation = nullptr;
        m_annotations.erase( m_annotations.begin() + remove );
    }
    ImGui::EndChild();
    ImGui::End();
}

void View::DrawSampleParents()
{
    bool show = true;
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Sample entry call stacks", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        auto ss = m_worker.GetSymbolStats( m_sampleParents.symAddr );
        auto excl = ss->excl;
        auto stats = ss->parents;

        const auto symbol = m_worker.GetSymbolData( m_sampleParents.symAddr );
        if( !symbol->isInline && m_sampleParents.withInlines )
        {
            const auto symlen = symbol->size.Val();
            auto inSym = m_worker.GetInlineSymbolList( m_sampleParents.symAddr, symlen );
            if( inSym )
            {
                const auto symEnd = m_sampleParents.symAddr + symlen;
                while( *inSym < symEnd )
                {
                    auto istat = m_worker.GetSymbolStats( *inSym++ );
                    if( !istat ) continue;
                    excl += istat->excl;
                    for( auto& v : istat->baseParents )
                    {
                        auto it = stats.find( v.first );
                        if( it == stats.end() )
                        {
                            stats.emplace( v.first, v.second );
                        }
                        else
                        {
                            it->second += v.second;
                        }
                    }
                }
            }
        }
        assert( !stats.empty() );

        ImGui::PushFont( m_bigFont );
        TextFocused( "Symbol:", m_worker.GetString( symbol->name ) );
        if( symbol->isInline )
        {
            ImGui::SameLine();
            TextDisabledUnformatted( "(inline)" );
        }
        else if( !m_sampleParents.withInlines )
        {
            ImGui::SameLine();
            TextDisabledUnformatted( "(without inlines)" );
        }
        ImGui::PopFont();
        TextDisabledUnformatted( "Location:" );
        ImGui::SameLine();
        const auto callFile = m_worker.GetString( symbol->callFile );
        ImGui::TextUnformatted( LocationToString( callFile, symbol->callLine ) );
        if( ImGui::IsItemClicked( 1 ) )
        {
            ViewDispatch( callFile, symbol->callLine, m_sampleParents.symAddr );
        }
        TextDisabledUnformatted( "Entry point:" );
        ImGui::SameLine();
        const auto file = m_worker.GetString( symbol->file );
        ImGui::TextUnformatted( LocationToString( file, symbol->line ) );
        if( ImGui::IsItemClicked( 1 ) )
        {
            ViewDispatch( file, symbol->line, m_sampleParents.symAddr );
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextDisabledUnformatted( m_worker.GetString( symbol->imageName ) );
        ImGui::Separator();
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
        if( ImGui::RadioButton( ICON_FA_TABLE " List", m_sampleParents.mode == 0 ) ) m_sampleParents.mode = 0;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( ImGui::RadioButton( ICON_FA_TREE " Bottom-up tree", m_sampleParents.mode == 1 ) ) m_sampleParents.mode = 1;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( ImGui::RadioButton( ICON_FA_TREE " Top-down tree", m_sampleParents.mode == 2 ) ) m_sampleParents.mode = 2;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_STOPWATCH " Show time", &m_statSampleTime );
        ImGui::PopStyleVar();
        ImGui::Separator();
        ImGui::BeginChild( "##sampleParents" );
        switch( m_sampleParents.mode )
        {
        case 0:
        {
            TextDisabledUnformatted( "Entry call stack:" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
            {
                m_sampleParents.sel = std::max( m_sampleParents.sel - 1, 0 );
            }
            ImGui::SameLine();
            ImGui::Text( "%s / %s", RealToString( m_sampleParents.sel + 1 ), RealToString( stats.size() ) );
            if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "EntryCallStackPopup" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
            {
                m_sampleParents.sel = std::min<int>( m_sampleParents.sel + 1, stats.size() - 1 );
            }
            if( ImGui::BeginPopup( "EntryCallStackPopup" ) )
            {
                int sel = m_sampleParents.sel + 1;
                ImGui::SetNextItemWidth( 120 * scale );
                const bool clicked = ImGui::InputInt( "##entryCallStack", &sel, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
                if( clicked ) m_sampleParents.sel = std::min( std::max( sel, 1 ), int( stats.size() ) ) - 1;
                ImGui::EndPopup();
            }
            Vector<decltype(stats.begin())> data;
            data.reserve( stats.size() );
            for( auto it = stats.begin(); it != stats.end(); ++it ) data.push_back( it );
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l->second > r->second; } );
            ImGui::SameLine();
            ImGui::TextUnformatted( m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * data[m_sampleParents.sel]->second ) : RealToString( data[m_sampleParents.sel]->second ) );
            ImGui::SameLine();
            char buf[64];
            PrintStringPercent( buf, 100. * data[m_sampleParents.sel]->second / excl );
            TextDisabledUnformatted( buf );
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
            ImGui::TextUnformatted( ICON_FA_AT " Frame location:" );
            ImGui::SameLine();
            ImGui::RadioButton( "Source code", &m_showCallstackFrameAddress, 0 );
            ImGui::SameLine();
            ImGui::RadioButton( "Entry point", &m_showCallstackFrameAddress, 3 );
            ImGui::SameLine();
            ImGui::RadioButton( "Return address", &m_showCallstackFrameAddress, 1 );
            ImGui::SameLine();
            ImGui::RadioButton( "Symbol address", &m_showCallstackFrameAddress, 2 );
            ImGui::PopStyleVar();

            auto& cs = m_worker.GetParentCallstack( data[m_sampleParents.sel]->first );
            ImGui::Separator();
            if( ImGui::BeginTable( "##callstack", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY ) )
            {
                ImGui::TableSetupScrollFreeze( 0, 1 );
                ImGui::TableSetupColumn( "Frame", ImGuiTableColumnFlags_NoHide | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableSetupColumn( "Function" );
                ImGui::TableSetupColumn( "Location" );
                ImGui::TableSetupColumn( "Image" );
                ImGui::TableHeadersRow();

                int fidx = 0;
                int bidx = 0;
                for( auto& entry : cs )
                {
                    auto frameData = entry.custom ? m_worker.GetParentCallstackFrame( entry ) : m_worker.GetCallstackFrame( entry );
                    assert( frameData );
                    const auto fsz = frameData->size;
                    for( uint8_t f=0; f<fsz; f++ )
                    {
                        const auto& frame = frameData->data[f];
                        auto txt = m_worker.GetString( frame.name );
                        bidx++;
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        if( f == fsz-1 )
                        {
                            ImGui::Text( "%i", fidx++ );
                        }
                        else
                        {
                            ImGui::PushFont( m_smallFont );
                            TextDisabledUnformatted( "inline" );
                            ImGui::PopFont();
                        }
                        ImGui::TableNextColumn();
                        {
                            ImGui::PushTextWrapPos( 0.0f );
                            if( txt[0] == '[' )
                            {
                                TextDisabledUnformatted( txt );
                            }
                            else if( m_worker.GetCanonicalPointer( entry ) >> 63 != 0 )
                            {
                                TextColoredUnformatted( 0xFF8888FF, txt );
                            }
                            else
                            {
                                ImGui::TextUnformatted( txt );
                            }
                            ImGui::PopTextWrapPos();
                        }
                        if( ImGui::IsItemClicked() )
                        {
                            ImGui::SetClipboardText( txt );
                        }
                        ImGui::TableNextColumn();
                        ImGui::PushTextWrapPos( 0.0f );
                        float indentVal = 0.f;
                        if( m_sampleParentBuzzAnim.Match( bidx ) )
                        {
                            const auto time = m_sampleParentBuzzAnim.Time();
                            indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::Indent( indentVal );
                        }
                        txt = m_worker.GetString( frame.file );
                        switch( m_showCallstackFrameAddress )
                        {
                        case 0:
                            TextDisabledUnformatted( LocationToString( txt, frame.line ) );
                            if( ImGui::IsItemClicked() )
                            {
                                ImGui::SetClipboardText( txt );
                            }
                            break;
                        case 1:
                            if( entry.custom == 0 )
                            {
                                const auto addr = m_worker.GetCanonicalPointer( entry );
                                ImGui::TextDisabled( "0x%" PRIx64, addr );
                                if( ImGui::IsItemClicked() )
                                {
                                    char tmp[32];
                                    sprintf( tmp, "0x%" PRIx64, addr );
                                    ImGui::SetClipboardText( tmp );
                                }
                            }
                            else
                            {
                                TextDisabledUnformatted( "unavailable" );
                            }
                            break;
                        case 2:
                            ImGui::TextDisabled( "0x%" PRIx64, frame.symAddr );
                            if( ImGui::IsItemClicked() )
                            {
                                char tmp[32];
                                sprintf( tmp, "0x%" PRIx64, frame.symAddr );
                                ImGui::SetClipboardText( tmp );
                            }
                            break;
                        case 3:
                        {
                            const auto sym = m_worker.GetSymbolData( frame.symAddr );
                            if( sym )
                            {
                                const auto symtxt = m_worker.GetString( sym->file );
                                TextDisabledUnformatted( LocationToString( symtxt, sym->line ) );
                                if( ImGui::IsItemClicked() )
                                {
                                    ImGui::SetClipboardText( symtxt );
                                }
                            }
                            else
                            {
                                TextDisabledUnformatted( "[unknown]" );
                            }
                            break;
                        }
                        default:
                            assert( false );
                            break;
                        }
                        if( ImGui::IsItemHovered() )
                        {
                            if( m_showCallstackFrameAddress == 3 )
                            {
                                const auto sym = m_worker.GetSymbolData( frame.symAddr );
                                if( sym )
                                {
                                    const auto symtxt = m_worker.GetString( sym->file );
                                    DrawSourceTooltip( symtxt, sym->line );
                                }
                            }
                            else
                            {
                                DrawSourceTooltip( txt, frame.line );
                            }
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( m_showCallstackFrameAddress == 3 )
                                {
                                    const auto sym = m_worker.GetSymbolData( frame.symAddr );
                                    if( sym )
                                    {
                                        const auto symtxt = m_worker.GetString( sym->file );
                                        if( !ViewDispatch( symtxt, sym->line, frame.symAddr ) )
                                        {
                                            m_sampleParentBuzzAnim.Enable( bidx, 0.5f );
                                        }
                                    }
                                    else
                                    {
                                        m_sampleParentBuzzAnim.Enable( bidx, 0.5f );
                                    }
                                }
                                else
                                {
                                    if( !ViewDispatch( txt, frame.line, frame.symAddr ) )
                                    {
                                        m_sampleParentBuzzAnim.Enable( bidx, 0.5f );
                                    }
                                }
                            }
                        }
                        if( indentVal != 0.f )
                        {
                            ImGui::Unindent( indentVal );
                        }
                        ImGui::PopTextWrapPos();
                        ImGui::TableNextColumn();
                        if( frameData->imageName.Active() )
                        {
                            TextDisabledUnformatted( m_worker.GetString( frameData->imageName ) );
                        }
                    }
                }
                ImGui::EndTable();
            }
            break;
        }
        case 1:
        {
            SmallCheckbox( "Group by function name", &m_sampleParents.groupBottomUp );
            auto tree = GetParentsCallstackFrameTreeBottomUp( stats, m_sampleParents.groupBottomUp );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawParentsFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }

            break;
        }
        case 2:
        {
            SmallCheckbox( "Group by function name", &m_sampleParents.groupTopDown );
            auto tree = GetParentsCallstackFrameTreeTopDown( stats, m_sampleParents.groupTopDown );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawParentsFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }
            break;
        }
        default:
            assert( false );
            break;
        }
        ImGui::EndChild();
    }
    ImGui::End();

    if( !show )
    {
        m_sampleParents.symAddr = 0;
    }
}

void View::DrawRanges()
{
    ImGui::Begin( "Time range limits", &m_showRanges, ImGuiWindowFlags_AlwaysAutoResize );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
    DrawRangeEntry( m_findZone.range, ICON_FA_SEARCH " Find zone", 0x4488DD88, "RangeFindZoneCopyFrom", 0 );
    ImGui::Separator();
    DrawRangeEntry( m_statRange, ICON_FA_SORT_AMOUNT_UP " Statistics", 0x448888EE, "RangeStatisticsCopyFrom", 1 );
    ImGui::Separator();
    DrawRangeEntry( m_waitStackRange, ICON_FA_HOURGLASS_HALF " Wait stacks", 0x44EEB588, "RangeWaitStackCopyFrom", 2 );
    ImGui::Separator();
    DrawRangeEntry( m_memInfo.range, ICON_FA_MEMORY " Memory", 0x4488EEE3, "RangeMemoryCopyFrom", 3 );
    ImGui::End();
}

void View::DrawRangeEntry( Range& range, const char* label, uint32_t color, const char* popupLabel, int id )
{
    SmallColorBox( color );
    ImGui::SameLine();
    if( SmallCheckbox( label, &range.active ) )
    {
        if( range.active && range.min == 0 && range.max == 0 )
        {
            range.min = m_vd.zvStart;
            range.max = m_vd.zvEnd;
        }
    }
    if( range.active )
    {
        ImGui::SameLine();
        if( ImGui::SmallButton( "Limit to view" ) )
        {
            range.min = m_vd.zvStart;
            range.max = m_vd.zvEnd;
        }
        TextFocused( "Time range:", TimeToStringExact( range.min ) );
        ImGui::SameLine();
        TextFocused( "-", TimeToStringExact( range.max ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", TimeToString( range.max - range.min ) );
        if( ImGui::SmallButton( ICON_FA_MICROSCOPE " Focus" ) ) ZoomToRange( range.min, range.max );
        ImGui::SameLine();
        if( SmallButtonDisablable( ICON_FA_STICKY_NOTE " Set from annotation", m_annotations.empty() ) ) ImGui::OpenPopup( popupLabel );
        if( ImGui::BeginPopup( popupLabel ) )
        {
            for( auto& v : m_annotations )
            {
                SmallColorBox( v->color );
                ImGui::SameLine();
                if( ImGui::Selectable( v->text.c_str() ) )
                {
                    range.min = v->range.min;
                    range.max = v->range.max;
                }
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::TextDisabled( "%s - %s (%s)", TimeToStringExact( v->range.min ), TimeToStringExact( v->range.max ), TimeToString( v->range.max - v->range.min ) );
            }
            ImGui::EndPopup();
        }
        if( id != 0 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_SEARCH " Copy from find zone", m_findZone.range.min == 0 && m_findZone.range.max == 0 ) ) range = m_findZone.range;
        }
        if( id != 1 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_SORT_AMOUNT_UP " Copy from statistics", m_statRange.min == 0 && m_statRange.max == 0 ) ) range = m_statRange;
        }
        if( id != 2 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_HOURGLASS_HALF " Copy from wait stacks", m_waitStackRange.min == 0 && m_waitStackRange.max == 0 ) ) range = m_waitStackRange;
        }
        if( id != 3 )
        {
            ImGui::SameLine();
            if( SmallButtonDisablable( ICON_FA_MEMORY " Copy from memory", m_memInfo.range.min == 0 && m_memInfo.range.max == 0 ) ) range = m_memInfo.range;
        }
    }
}

void View::DrawWaitStacks()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Wait stacks", &m_showWaitStacks );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable wait stacks." );
#else
    uint64_t totalCount = 0;
    unordered_flat_map<uint32_t, uint64_t> stacks;
    for( auto& t : m_threadOrder )
    {
        if( WaitStackThread( t->id ) )
        {
            auto it = t->ctxSwitchSamples.begin();
            auto end = t->ctxSwitchSamples.end();
            if( m_waitStackRange.active )
            {
                it = std::lower_bound( it, end, m_waitStackRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                end = std::lower_bound( it, end, m_waitStackRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
            }
            totalCount += std::distance( it, end );
            while( it != end )
            {
                auto cs = it->callstack.Val();
                auto cit = stacks.find( cs );
                if( cit == stacks.end() )
                {
                    stacks.emplace( cs, 1 );
                }
                else
                {
                    cit->second++;
                }
                ++it;
            }
        }
    }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    if( ImGui::RadioButton( ICON_FA_TABLE " List", m_waitStackMode == 0 ) ) m_waitStackMode = 0;
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::RadioButton( ICON_FA_TREE " Bottom-up tree", m_waitStackMode == 1 ) ) m_waitStackMode = 1;
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::RadioButton( ICON_FA_TREE " Top-down tree", m_waitStackMode == 2 ) ) m_waitStackMode = 2;
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Total wait stacks:", RealToString( m_worker.GetContextSwitchSampleCount() ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Selected:", RealToString( totalCount ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::Checkbox( "Limit range", &m_waitStackRange.active ) )
    {
        if( m_waitStackRange.active && m_waitStackRange.min == 0 && m_waitStackRange.max == 0 )
        {
            m_waitStackRange.min = m_vd.zvStart;
            m_waitStackRange.max = m_vd.zvEnd;
        }
    }
    if( m_waitStackRange.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }
    ImGui::PopStyleVar();

    bool threadsChanged = false;
    auto expand = ImGui::TreeNode( ICON_FA_RANDOM " Visible threads:" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_threadOrder.size() );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                WaitStackThread( t->id ) = true;
            }
            threadsChanged = true;
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                WaitStackThread( t->id ) = false;
            }
            threadsChanged = true;
        }

        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            if( t->ctxSwitchSamples.empty() ) continue;
            ImGui::PushID( idx++ );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            if( SmallCheckbox( m_worker.GetThreadName( t->id ), &WaitStackThread( t->id ) ) )
            {
                threadsChanged = true;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->ctxSwitchSamples.size() ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
            }
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
        }
        ImGui::TreePop();
    }
    if( threadsChanged ) m_waitStack = 0;

    ImGui::Separator();
    ImGui::BeginChild( "##waitstacks" );
    if( stacks.empty() )
    {
        ImGui::TextUnformatted( "No wait stacks to display." );
    }
    else
    {
        switch( m_waitStackMode )
        {
        case 0:
        {
            TextDisabledUnformatted( "Wait stack:" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
            {
                m_waitStack = std::max( m_waitStack - 1, 0 );
            }
            ImGui::SameLine();
            ImGui::Text( "%s / %s", RealToString( m_waitStack + 1 ), RealToString( stacks.size() ) );
            if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "WaitStacksPopup" );
            ImGui::SameLine();
            if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
            {
                m_waitStack = std::min<int>( m_waitStack + 1, stacks.size() - 1 );
            }
            if( ImGui::BeginPopup( "WaitStacksPopup" ) )
            {
                int sel = m_waitStack + 1;
                ImGui::SetNextItemWidth( 120 * scale );
                const bool clicked = ImGui::InputInt( "##waitStack", &sel, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
                if( clicked ) m_waitStack = std::min( std::max( sel, 1 ), int( stacks.size() ) ) - 1;
                ImGui::EndPopup();
            }
            ImGui::SameLine();
            ImGui::Spacing();
            ImGui::SameLine();
            Vector<decltype(stacks.begin())> data;
            data.reserve( stacks.size() );
            for( auto it = stacks.begin(); it != stacks.end(); ++it ) data.push_back( it );
            pdqsort_branchless( data.begin(), data.end(), []( const auto& l, const auto& r ) { return l->second > r->second; } );
            TextFocused( "Counts:", RealToString( data[m_waitStack]->second ) );
            ImGui::SameLine();
            char buf[64];
            PrintStringPercent( buf, 100. * data[m_waitStack]->second / totalCount );
            TextDisabledUnformatted( buf );
            ImGui::Separator();
            DrawCallstackTable( data[m_waitStack]->first, false );
            break;
        }
        case 1:
        {
            SmallCheckbox( "Group by function name", &m_groupWaitStackBottomUp );
            auto tree = GetCallstackFrameTreeBottomUp( stacks, m_groupCallstackTreeByNameBottomUp );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }
            break;
        }
        case 2:
        {
            SmallCheckbox( "Group by function name", &m_groupWaitStackTopDown );
            auto tree = GetCallstackFrameTreeTopDown( stacks, m_groupCallstackTreeByNameTopDown );
            if( !tree.empty() )
            {
                int idx = 0;
                DrawFrameTreeLevel( tree, idx );
            }
            else
            {
                TextDisabledUnformatted( "No call stacks to show" );
            }
            break;
        }
        default:
            assert( false );
            break;
        }
    }
#endif
    ImGui::EndChild();
    ImGui::End();
}

void View::DrawAllocList()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1100 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Allocations list", &m_memInfo.showAllocList );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    std::vector<const MemEvent*> data;
    auto basePtr = m_worker.GetMemoryNamed( m_memInfo.pool ).data.data();
    data.reserve( m_memInfo.allocList.size() );
    for( auto& idx : m_memInfo.allocList )
    {
        data.emplace_back( basePtr + idx );
    }

    TextFocused( "Number of allocations:", RealToString( m_memInfo.allocList.size() ) );
    ListMemData( data, []( auto v ) {
        ImGui::Text( "0x%" PRIx64, v->Ptr() );
    }, "##allocations", -1, m_memInfo.pool );
    ImGui::End();
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
