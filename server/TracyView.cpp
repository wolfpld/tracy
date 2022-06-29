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
#include <random>
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

#ifndef TRACY_NO_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

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

static double s_time = 0;

constexpr const char* GpuContextNames[] = {
    "Invalid",
    "OpenGL",
    "Vulkan",
    "OpenCL",
    "Direct3D 12",
    "Direct3D 11"
};


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

static tracy_force_inline void PrintStringPercent( char* buf, const char* string, double percent )
{
    const auto ssz = strlen( string );
    memcpy( buf, string, ssz );
    memcpy( buf+ssz, " (", 2 );
    auto end = PrintFloat( buf+ssz+2, buf+128, percent, 2 );
    memcpy( end, "%)", 3 );
}

static tracy_force_inline void PrintStringPercent( char* buf, double percent )
{
    memcpy( buf, "(", 2 );
    auto end = PrintFloat( buf+1, buf+64, percent, 2 );
    memcpy( end, "%)", 3 );
}

template<int V = 25>
static tracy_force_inline uint32_t HighlightColor( uint32_t color )
{
    return 0xFF000000 |
        ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + V ) ) << 16 ) |
        ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + V ) ) << 8  ) |
        ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + V ) )       );
}


enum { MinVisSize = 3 };
enum { MinCtxSize = 4 };
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

const char* View::ShortenNamespace( const char* name ) const
{
    if( m_namespace == Namespace::Full ) return name;
    if( m_namespace == Namespace::Short )
    {
        auto ptr = name;
        while( *ptr != '\0' ) ptr++;
        while( ptr > name && *ptr != ':' ) ptr--;
        if( *ptr == ':' ) ptr++;
        return ptr;
    }

    static char buf[1024];
    auto dst = buf;
    auto ptr = name;
    for(;;)
    {
        auto start = ptr;
        while( *ptr != '\0' && *ptr != ':' ) ptr++;
        if( *ptr == '\0' )
        {
            memcpy( dst, start, ptr - start + 1 );
            return buf;
        }
        *dst++ = *start;
        *dst++ = ':';
        while( *ptr == ':' ) ptr++;
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

void View::DrawNotificationArea()
{
    auto& io = ImGui::GetIO();
    const auto ty = ImGui::GetTextLineHeight();
    if( m_worker.IsConnected() )
    {
        size_t sqs;
        {
            std::shared_lock<std::shared_mutex> lock( m_worker.GetMbpsDataLock() );
            sqs = m_worker.GetSendQueueSize();
        }
        if( sqs != 0 )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), ICON_FA_SATELLITE_DISH );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                TextFocused( "Query backlog:", RealToString( sqs ) );
                ImGui::EndTooltip();
            }
        }
        else
        {
            const auto sif = m_worker.GetSendInFlight();
            if( sif != 0 )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1, 0.75f, 0, 1 ), ICON_FA_SATELLITE_DISH );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Queries in flight:", RealToString( sif ) );
                    ImGui::EndTooltip();
                }
            }
        }
    }
    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread != 0 )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), ICON_FA_SKULL );
        if( ImGui::IsItemHovered() )
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
    if( m_worker.AreSamplesInconsistent() )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EYE_DROPPER );
        TooltipIfHovered( "Sampling data and ghost zones may be displayed wrongly due to data inconsistency. Save and reload the trace to fix this." );
    }
    if( m_vd.drawEmptyLabels )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EXPAND );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Displaying empty labels." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawEmptyLabels = false;
        }
    }
    if( !m_vd.drawContextSwitches )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_HIKING );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Context switches are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawContextSwitches = true;
        }
    }
    if( !m_vd.drawCpuData )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_SLIDERS_H );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "CPU data is hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawCpuData = true;
        }
    }
    if( !m_vd.drawGpuZones )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_EYE );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "GPU zones are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawGpuZones = true;
        }
    }
    if( !m_vd.drawZones )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_MICROCHIP );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "CPU zones are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawZones = true;
        }
    }
#ifndef TRACY_NO_STATISTICS
    if( !m_vd.ghostZones )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_GHOST );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Ghost zones are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.ghostZones = true;
        }
    }
#endif
    if( !m_vd.drawLocks )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_LOCK );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Locks are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawLocks = true;
        }
    }
    if( !m_vd.drawPlots )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_SIGNATURE );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Plots are hidden." );
            ImGui::EndTooltip();
            if( IsMouseClicked( 0 ) ) m_vd.drawPlots = true;
        }
    }
    {
        bool hidden = false;
        for( auto& v : m_visData )
        {
            if( !v.second.visible )
            {
                hidden = true;
                break;
            }
        }
        if( hidden )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 1, 0.5, 0, 1 ), ICON_FA_LOW_VISION );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( "Some timeline entries are hidden." );
                ImGui::EndTooltip();
                if( IsMouseClicked( 0 ) ) m_showOptions = true;
            }
        }
    }
    if( !m_worker.IsBackgroundDone() )
    {
        ImGui::SameLine();
        TextDisabledUnformatted( ICON_FA_TASKS );
        ImGui::SameLine();
        const auto pos = ImGui::GetCursorPos();
        ImGui::TextUnformatted( "  " );
        ImGui::GetWindowDrawList()->AddCircleFilled( pos + ImVec2( 0, ty * 0.75f ), ty * ( 0.2f + ( sin( s_time * 8 ) + 1 ) * 0.125f ), 0xFF888888, 10 );
        auto rmin = ImGui::GetItemRectMin();
        rmin.x -= ty * 0.5f;
        const auto rmax = ImGui::GetItemRectMax();
        if( ImGui::IsMouseHoveringRect( rmin, rmax ) )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Processing background tasks" );
            ImGui::EndTooltip();
        }
    }
    if( m_saveThreadState.load( std::memory_order_relaxed ) == SaveThreadState::Saving )
    {
        ImGui::SameLine();
        ImGui::TextUnformatted( ICON_FA_SAVE " Saving trace..." );
        m_notificationTime = 0;
    }
    else if( m_notificationTime > 0 )
    {
        m_notificationTime -= std::min( io.DeltaTime, 0.25f );
        ImGui::SameLine();
        TextDisabledUnformatted( m_notificationText.c_str() );
    }

    ImGui::PushFont( m_smallFont );
    const auto wpos = ImGui::GetWindowPos();
    const auto w = ImGui::GetContentRegionAvail().x;
    const auto fps = RealToString( int( io.Framerate + 0.5f ) );
    const auto fpssz = ImGui::CalcTextSize( fps ).x;
    ImGui::GetWindowDrawList()->AddText( wpos + ImVec2( w-fpssz, 0 ), 0x88FFFFFF, fps );
    ImGui::PopFont();
}

bool View::DrawConnection()
{
    const auto scale = GetScale();
    const auto ty = ImGui::GetTextLineHeight();
    const auto cs = ty * 0.9f;
    const auto isConnected = m_worker.IsConnected();

    {
        std::shared_lock<std::shared_mutex> lock( m_worker.GetMbpsDataLock() );
        TextFocused( isConnected ? "Connected to:" : "Disconnected:", m_worker.GetAddr().c_str() );
        const auto& mbpsVector = m_worker.GetMbpsData();
        const auto mbps = mbpsVector.back();
        char buf[64];
        if( mbps < 0.1f )
        {
            sprintf( buf, "%6.2f Kbps", mbps * 1000.f );
        }
        else
        {
            sprintf( buf, "%6.2f Mbps", mbps );
        }
        ImGui::Dummy( ImVec2( cs, 0 ) );
        ImGui::SameLine();
        ImGui::PlotLines( buf, mbpsVector.data(), mbpsVector.size(), 0, nullptr, 0, std::numeric_limits<float>::max(), ImVec2( 150 * scale, 0 ) );
        TextDisabledUnformatted( "Ratio" );
        ImGui::SameLine();
        ImGui::Text( "%.1f%%", m_worker.GetCompRatio() * 100.f );
        ImGui::SameLine();
        TextDisabledUnformatted( "Real:" );
        ImGui::SameLine();
        ImGui::Text( "%6.2f Mbps", mbps / m_worker.GetCompRatio() );
        TextFocused( "Data transferred:", MemSizeToString( m_worker.GetDataTransferred() ) );
        TextFocused( "Query backlog:", RealToString( m_worker.GetSendQueueSize() ) );
    }

    const auto wpos = ImGui::GetWindowPos() + ImGui::GetWindowContentRegionMin();
    ImGui::GetWindowDrawList()->AddCircleFilled( wpos + ImVec2( 1 + cs * 0.5, 3 + ty * 1.75 ), cs * 0.5, isConnected ? 0xFF2222CC : 0xFF444444, 10 );

    {
        std::lock_guard<std::mutex> lock( m_worker.GetDataLock() );
        ImGui::SameLine();
        TextFocused( "+", RealToString( m_worker.GetSendInFlight() ) );
        const auto sz = m_worker.GetFrameCount( *m_frames );
        if( sz > 1 )
        {
            const auto dt = m_worker.GetFrameTime( *m_frames, sz - 2 );
            const auto fps = 1000000000.f / dt;
            TextDisabledUnformatted( "FPS:" );
            ImGui::SameLine();
            ImGui::Text( "%6.1f", fps );
            ImGui::SameLine();
            TextFocused( "Frame time:", TimeToString( dt ) );
        }
    }

    const auto& fis = m_worker.GetFrameImages();
    if( !fis.empty() )
    {
        const auto fiScale = scale * 0.5f;
        const auto& fi = fis.back();
        if( fi != m_frameTextureConnPtr )
        {
            if( !m_frameTextureConn ) m_frameTextureConn = MakeTexture();
            UpdateTexture( m_frameTextureConn, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );
            m_frameTextureConnPtr = fi;
        }
        ImGui::Separator();
        if( fi->flip )
        {
            ImGui::Image( m_frameTextureConn, ImVec2( fi->w * fiScale, fi->h * fiScale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
        }
        else
        {
            ImGui::Image( m_frameTextureConn, ImVec2( fi->w * fiScale, fi->h * fiScale ) );
        }
    }

    ImGui::Separator();
    if( ImGui::Button( ICON_FA_SAVE " Save trace" ) && m_saveThreadState.load( std::memory_order_relaxed ) == SaveThreadState::Inert )
    {
#ifndef TRACY_NO_FILESELECTOR
        nfdu8filteritem_t filter = { "Tracy Profiler trace file", "tracy" };
        nfdu8char_t* fn;
        auto res = NFD_SaveDialogU8( &fn, &filter, 1, nullptr, nullptr );
        if( res == NFD_OKAY )
#else
        const char* fn = "trace.tracy";
#endif
        {
            const auto sz = strlen( fn );
            if( sz < 7 || memcmp( fn + sz - 6, ".tracy", 6 ) != 0 )
            {
                char tmp[1024];
                sprintf( tmp, "%s.tracy", fn );
                m_filenameStaging = tmp;
            }
            else
            {
                m_filenameStaging = fn;
            }
#ifndef TRACY_NO_FILESELECTOR
            NFD_FreePathU8( fn );
#endif
        }
    }

    ImGui::SameLine( 0, 2 * ty );
    const char* stopStr = ICON_FA_PLUG " Stop";
    std::lock_guard<std::mutex> lock( m_worker.GetDataLock() );
    if( !m_disconnectIssued && m_worker.IsConnected() )
    {
        if( ImGui::Button( stopStr ) )
        {
            m_worker.Disconnect();
            m_disconnectIssued = true;
        }
    }
    else
    {
        ImGui::BeginDisabled();
        ImGui::Button( stopStr );
        ImGui::EndDisabled();
    }

    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_EXCLAMATION_TRIANGLE " Discard" ) )
    {
        ImGui::OpenPopup( "Confirm trace discard" );
    }

    if( ImGui::BeginPopupModal( "Confirm trace discard", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        ImGui::PushFont( m_bigFont );
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::PopFont();
        ImGui::TextUnformatted( "All unsaved profiling data will be lost!" );
        ImGui::TextUnformatted( "Are you sure you want to proceed?" );
        ImGui::Separator();
        if( ImGui::Button( "Yes" ) )
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
            m_reconnectRequested = true;
            return false;
        }
        ImGui::SameLine( 0, ty * 2 );
        if( ImGui::Button( "No", ImVec2( ty * 6, 0 ) ) )
        {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if( m_worker.IsConnected() )
    {
        const auto& params = m_worker.GetParameters();
        if( !params.empty() )
        {
            ImGui::Separator();
            if( ImGui::TreeNode( "Trace parameters" ) )
            {
                if( ImGui::BeginTable( "##traceparams", 2, ImGuiTableFlags_Borders ) )
                {
                    ImGui::TableSetupColumn( "Name" );
                    ImGui::TableSetupColumn( "Value", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                    ImGui::TableHeadersRow();
                    size_t idx = 0;
                    for( auto& p : params )
                    {
                        ImGui::TableNextRow();
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted( m_worker.GetString( p.name ) );
                        ImGui::TableNextColumn();
                        ImGui::PushID( idx );
                        if( p.isBool )
                        {
                            bool val = p.val;
                            if( ImGui::Checkbox( "", &val ) )
                            {
                                m_worker.SetParameter( idx, int32_t( val ) );
                            }
                        }
                        else
                        {
                            auto val = int( p.val );
                            if( ImGui::InputInt( "", &val, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue ) )
                            {
                                m_worker.SetParameter( idx, int32_t( val ) );
                            }
                        }
                        ImGui::PopID();
                        idx++;
                    }
                    ImGui::EndTable();
                }
                ImGui::TreePop();
            }
        }
    }

    return true;
}

enum { BestTime = 1000 * 1000 * 1000 / 143 };
enum { GoodTime = 1000 * 1000 * 1000 / 59 };
enum { BadTime = 1000 * 1000 * 1000 / 29 };

static ImU32 GetFrameColor( uint64_t frameTime )
{
    return frameTime > BadTime  ? 0xFF2222DD :
           frameTime > GoodTime ? 0xFF22DDDD :
           frameTime > BestTime ? 0xFF22DD22 : 0xFFDD9900;
}

static int GetFrameWidth( int frameScale )
{
    return frameScale == 0 ? 4 : ( frameScale < 0 ? 6 : 1 );
}

static int GetFrameGroup( int frameScale )
{
    return frameScale < 2 ? 1 : ( 1 << ( frameScale - 1 ) );
}

template<class T>
constexpr const T& clamp( const T& v, const T& lo, const T& hi )
{
    return v < lo ? lo : v > hi ? hi : v;
}

void View::DrawFrames()
{
    assert( m_worker.GetFrameCount( *m_frames ) != 0 );

    const auto scale = GetScale();
    const auto Height = 50 * scale;

    enum { MaxFrameTime = 50 * 1000 * 1000 };  // 50ms

    ImGuiWindow* window = ImGui::GetCurrentWindowRead();
    if( window->SkipItems ) return;

    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
    const auto wspace = ImGui::GetWindowContentRegionMax() - ImGui::GetWindowContentRegionMin();
    const auto w = wspace.x;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##frames", ImVec2( w, Height ) );
    bool hover = ImGui::IsItemHovered();

    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x33FFFFFF );
    const auto wheel = io.MouseWheel;
    const auto prevScale = m_vd.frameScale;
    if( hover )
    {
        if( wheel > 0 )
        {
            if( m_vd.frameScale >= 0 ) m_vd.frameScale--;
        }
        else if( wheel < 0 )
        {
            if( m_vd.frameScale < 10 ) m_vd.frameScale++;
        }
    }

    const int fwidth = GetFrameWidth( m_vd.frameScale );
    const int group = GetFrameGroup( m_vd.frameScale );
    const int total = m_worker.GetFrameCount( *m_frames );
    const int onScreen = ( w - 2 ) / fwidth;
    if( m_viewMode != ViewMode::Paused )
    {
        m_vd.frameStart = ( total < onScreen * group ) ? 0 : total - onScreen * group;
        if( m_viewMode == ViewMode::LastFrames )
        {
            SetViewToLastFrames();
        }
        else
        {
            assert( m_viewMode == ViewMode::LastRange );
            const auto delta = m_worker.GetLastTime() - m_vd.zvEnd;
            if( delta != 0 )
            {
                m_vd.zvStart += delta;
                m_vd.zvEnd += delta;
            }
        }
    }

    if( hover )
    {
        const auto hwheel_delta = io.MouseWheelH * 100.f;
        if( IsMouseDragging( 1 ) || hwheel_delta != 0 )
        {
            m_viewMode = ViewMode::Paused;
            m_viewModeHeuristicTry = false;
            auto delta = GetMouseDragDelta( 1 ).x;
            if( delta == 0 ) delta = hwheel_delta;
            if( abs( delta ) >= fwidth )
            {
                const auto d = (int)delta / fwidth;
                m_vd.frameStart = std::max( 0, m_vd.frameStart - d * group );
                io.MouseClickedPos[1].x = io.MousePos.x + d * fwidth - delta;
            }
        }

        const auto mx = io.MousePos.x;
        if( mx > wpos.x && mx < wpos.x + w - 1 )
        {
            const auto mo = mx - ( wpos.x + 1 );
            const auto off = mo * group / fwidth;

            const int sel = m_vd.frameStart + off;
            if( sel < total )
            {
                ImGui::BeginTooltip();
                if( group > 1 )
                {
                    auto f = m_worker.GetFrameTime( *m_frames, sel );
                    auto g = std::min( group, total - sel );
                    for( int j=1; j<g; j++ )
                    {
                        f = std::max( f, m_worker.GetFrameTime( *m_frames, sel + j ) );
                    }

                    TextDisabledUnformatted( "Frames:" );
                    ImGui::SameLine();
                    ImGui::Text( "%s - %s (%s)", RealToString( sel ), RealToString( sel + g - 1 ), RealToString( g ) );
                    ImGui::Separator();
                    TextFocused( "Max frame time:", TimeToString( f ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / f );

                    if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { m_worker.GetFrameTime( *m_frames, sel ), m_worker.GetFrameTime( *m_frames, sel + g - 1 ), true };
                }
                else
                {
                    const auto fnum = GetFrameNumber( *m_frames, sel, m_worker.GetFrameOffset() );
                    m_frameHover = sel;
                    if( m_frames->name == 0 )
                    {
                        const auto offset = m_worker.GetFrameOffset();
                        if( sel == 0 )
                        {
                            ImGui::TextUnformatted( "Tracy initialization" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                        else if( offset == 0 )
                        {
                            TextDisabledUnformatted( "Frame:" );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( RealToString( fnum ) );
                            ImGui::Separator();
                            const auto frameTime = m_worker.GetFrameTime( *m_frames, sel );
                            TextFocused( "Frame time:", TimeToString( frameTime ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / frameTime );
                        }
                        else if( sel == 1 )
                        {
                            ImGui::TextUnformatted( "Missed frames" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, 1 ) ) );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Frame:" );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( RealToString( fnum ) );
                            ImGui::Separator();
                            const auto frameTime = m_worker.GetFrameTime( *m_frames, sel );
                            TextFocused( "Frame time:", TimeToString( frameTime ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / frameTime );
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:", m_worker.GetString( m_frames->name ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( RealToString( fnum ) );
                        ImGui::Separator();
                        const auto frameTime = m_worker.GetFrameTime( *m_frames, sel );
                        TextFocused( "Frame time:", TimeToString( frameTime ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%.1f FPS)", 1000000000.0 / frameTime );
                    }
                }
                TextFocused( "Time from start of program:", TimeToStringExact( m_worker.GetFrameBegin( *m_frames, sel ) ) );
                auto fi = m_worker.GetFrameImage( *m_frames, sel );
                if( fi )
                {
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
                }
                ImGui::EndTooltip();

                if( io.KeyCtrl )
                {
                    if( fi && IsMouseDown( 0 ) )
                    {
                        m_showPlayback = true;
                        m_playback.pause = true;
                        SetPlaybackFrame( m_frames->frames[sel].frameImage );
                    }
                }
                else
                {
                    if( IsMouseClicked( 0 ) )
                    {
                        m_viewMode = ViewMode::Paused;
                        m_viewModeHeuristicTry = false;
                        m_zoomAnim.active = false;
                        if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;
                        m_vd.zvStart = m_worker.GetFrameBegin( *m_frames, sel );
                        m_vd.zvEnd = m_worker.GetFrameEnd( *m_frames, sel + group - 1 );
                        if( m_vd.zvStart == m_vd.zvEnd ) m_vd.zvStart--;
                    }
                    else if( IsMouseDragging( 0 ) )
                    {
                        const auto t0 = std::min( m_vd.zvStart, m_worker.GetFrameBegin( *m_frames, sel ) );
                        const auto t1 = std::max( m_vd.zvEnd, m_worker.GetFrameEnd( *m_frames, sel + group - 1 ) );
                        ZoomToRange( t0, t1 );
                    }
                }

                if( IsMouseClickReleased( 1 ) ) m_setRangePopup = RangeSlim { m_worker.GetFrameBegin( *m_frames, sel ), m_worker.GetFrameEnd( *m_frames, sel + group - 1 ), true };
            }

            if( ( !m_worker.IsConnected() || m_viewMode == ViewMode::Paused ) && wheel != 0 )
            {
                const int pfwidth = GetFrameWidth( prevScale );
                const int pgroup = GetFrameGroup( prevScale );

                const auto oldoff = mo * pgroup / pfwidth;
                m_vd.frameStart = std::min( total, std::max( 0, m_vd.frameStart - int( off - oldoff ) ) );
            }
        }
    }

    int i = 0, idx = 0;
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() && m_findZone.show && m_findZone.showZoneInFrames && !m_findZone.match.empty() )
    {
        auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
        zoneData.zones.ensure_sorted();
        auto begin = zoneData.zones.begin();
        while( i < onScreen && m_vd.frameStart + idx < total )
        {
            const auto f0 = m_worker.GetFrameBegin( *m_frames, m_vd.frameStart + idx );
            auto f1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx );
            auto f = f1 - f0;
            if( group > 1 )
            {
                const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                for( int j=1; j<g; j++ )
                {
                    f = std::max( f, m_worker.GetFrameTime( *m_frames, m_vd.frameStart + idx + j ) );
                }
                f1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx + g - 1 );
            }

            int64_t zoneTime = 0;
            // This search is not valid, as zones are sorted according to their start time, not end time.
            auto itStart = std::lower_bound( begin, zoneData.zones.end(), f0, [] ( const auto& l, const auto& r ) { return l.Zone()->End() < r; } );
            if( itStart != zoneData.zones.end() )
            {
                auto itEnd = std::lower_bound( itStart, zoneData.zones.end(), f1, [] ( const auto& l, const auto& r ) { return l.Zone()->Start() < r; } );
                if( m_frames->continuous )
                {
                    if( m_findZone.selfTime )
                    {
                        while( itStart != itEnd )
                        {
                            const auto t0 = clamp( itStart->Zone()->Start(), f0, f1 );
                            const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), f0, f1 );
                            zoneTime += t1 - t0 - GetZoneChildTimeFastClamped( *itStart->Zone(), t0, t1 );
                            itStart++;
                        }
                    }
                    else
                    {
                        while( itStart != itEnd )
                        {
                            const auto t0 = clamp( itStart->Zone()->Start(), f0, f1 );
                            const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), f0, f1 );
                            zoneTime += t1 - t0;
                            itStart++;
                        }
                    }
                }
                else
                {
                    if( m_findZone.selfTime )
                    {
                        while( itStart != itEnd )
                        {
                            const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                            for( int j=0; j<g; j++ )
                            {
                                const auto ft0 = m_worker.GetFrameBegin( *m_frames, m_vd.frameStart + idx + j );
                                const auto ft1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx + j );
                                const auto t0 = clamp( itStart->Zone()->Start(), ft0, ft1 );
                                const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), ft0, ft1 );
                                zoneTime += t1 - t0 - GetZoneChildTimeFastClamped( *itStart->Zone(), t0, t1 );
                            }
                            itStart++;
                        }
                    }
                    else
                    {
                        while( itStart != itEnd )
                        {
                            const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                            for( int j=0; j<g; j++ )
                            {
                                const auto ft0 = m_worker.GetFrameBegin( *m_frames, m_vd.frameStart + idx + j );
                                const auto ft1 = m_worker.GetFrameEnd( *m_frames, m_vd.frameStart + idx + j );
                                const auto t0 = clamp( itStart->Zone()->Start(), ft0, ft1 );
                                const auto t1 = clamp( m_worker.GetZoneEndDirect( *itStart->Zone() ), ft0, ft1 );
                                zoneTime += t1 - t0;
                            }
                            itStart++;
                        }
                    }
                }
            }
            else
            {
                begin = itStart;
            }

            zoneTime /= group;
            const auto h = std::max( 1.f, float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 ) );
            if( zoneTime == 0 )
            {
                if( fwidth != 1 )
                {
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), 0xFF888888 );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2 ), 0xFF888888 );
                }
            }
            else if( zoneTime <= f )
            {
                const auto zh = float( std::min<uint64_t>( MaxFrameTime, zoneTime ) ) / MaxFrameTime * ( Height - 2 );
                if( fwidth != 1 )
                {
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1-zh ), 0xFF888888 );
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-zh ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), 0xFFEEEEEE );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2-zh ), 0xFF888888 );
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-zh ), dpos + ImVec2( 1+i, Height-2 ), 0xFFEEEEEE );
                }
            }
            else
            {
                const auto zh = float( std::min<uint64_t>( MaxFrameTime, zoneTime ) ) / MaxFrameTime * ( Height - 2 );
                if( fwidth != 1 )
                {
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-zh ), wpos + ImVec2( fwidth + i*fwidth, Height-1-h ), 0xFF2222BB );
                    draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), 0xFFEEEEEE );
                }
                else
                {
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-zh ), dpos + ImVec2( 1+i, Height-2-h ), 0xFF2222BB );
                    DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2 ), 0xFFEEEEEE );
                }
            }

            i++;
            idx += group;
        }
    }
    else
#endif
    {
        while( i < onScreen && m_vd.frameStart + idx < total )
        {
            auto f = m_worker.GetFrameTime( *m_frames, m_vd.frameStart + idx );
            if( group > 1 )
            {
                const int g = std::min( group, total - ( m_vd.frameStart + idx ) );
                for( int j=1; j<g; j++ )
                {
                    f = std::max( f, m_worker.GetFrameTime( *m_frames, m_vd.frameStart + idx + j ) );
                }
            }

            const auto h = std::max( 1.f, float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 ) );
            if( fwidth != 1 )
            {
                draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), GetFrameColor( f ) );
            }
            else
            {
                DrawLine( draw, dpos + ImVec2( 1+i, Height-2-h ), dpos + ImVec2( 1+i, Height-2 ), GetFrameColor( f ) );
            }

            i++;
            idx += group;
        }
    }

    const auto zrange = m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvEnd );
    if( zrange.second > m_vd.frameStart && zrange.first < m_vd.frameStart + onScreen * group )
    {
        auto x1 = std::min( onScreen * fwidth, ( zrange.second - m_vd.frameStart ) * fwidth / group );
        auto x0 = std::max( 0, ( zrange.first - m_vd.frameStart ) * fwidth / group );

        if( x0 == x1 ) x1 = x0 + 1;
        if( x1 - x0 >= 3 )
        {
            draw->AddRectFilled( wpos + ImVec2( 2+x0, 0 ), wpos + ImVec2( x1, Height ), 0x55DD22DD );
            DrawLine( draw, dpos + ImVec2( 1+x0, -1 ), dpos + ImVec2( 1+x0, Height-1 ), 0x55FF55FF );
            DrawLine( draw, dpos + ImVec2( x1, -1 ), dpos + ImVec2( x1, Height-1 ), 0x55FF55FF );
        }
        else
        {
            draw->AddRectFilled( wpos + ImVec2( 1+x0, 0 ), wpos + ImVec2( 1+x1, Height ), 0x55FF55FF );
        }
    }

    DrawLine( draw, dpos + ImVec2( 0, round( Height - Height * BadTime / MaxFrameTime ) ),  dpos + ImVec2( w, round( Height - Height * BadTime / MaxFrameTime ) ),  0x4422DDDD );
    DrawLine( draw, dpos + ImVec2( 0, round( Height - Height * GoodTime / MaxFrameTime ) ), dpos + ImVec2( w, round( Height - Height * GoodTime / MaxFrameTime ) ), 0x4422DD22 );
    DrawLine( draw, dpos + ImVec2( 0, round( Height - Height * BestTime / MaxFrameTime ) ), dpos + ImVec2( w, round( Height - Height * BestTime / MaxFrameTime ) ), 0x44DD9900 );
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

uint64_t View::GetFrameNumber( const FrameData& fd, int i, uint64_t offset ) const
{
    if( fd.name == 0 )
    {
        if( offset == 0 )
        {
            return i;
        }
        else
        {
            return i + offset - 1;
        }
    }
    else
    {
        return i + 1;
    }
}

const char* View::GetFrameText( const FrameData& fd, int i, uint64_t ftime, uint64_t offset ) const
{
    const auto fnum = GetFrameNumber( fd, i, offset );
    static char buf[1024];
    if( fd.name == 0 )
    {
        if( i == 0 )
        {
            sprintf( buf, "Tracy init (%s)", TimeToString( ftime ) );
        }
        else if( offset == 0 )
        {
            sprintf( buf, "Frame %s (%s)", RealToString( fnum ), TimeToString( ftime ) );
        }
        else if( i == 1 )
        {
            sprintf( buf, "Missed frames (%s)", TimeToString( ftime ) );
        }
        else
        {
            sprintf( buf, "Frame %s (%s)", RealToString( fnum ), TimeToString( ftime ) );
        }
    }
    else
    {
        sprintf( buf, "%s %s (%s)", m_worker.GetString( fd.name ), RealToString( fnum ), TimeToString( ftime ) );
    }
    return buf;
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

static void DrawZigZag( ImDrawList* draw, const ImVec2& wpos, double start, double end, double h, uint32_t color, float thickness = 1.f )
{
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    const auto spanSz = end - start;
    if( spanSz <= h * 0.5 )
    {
        DrawLine( draw, dpos + ImVec2( start, 0 ), wpos + ImVec2( start + spanSz, round( -spanSz ) ), color, thickness );
        return;
    }

    const auto h05 = round( h * 0.5 );
    const auto h2 = h*2;
    int steps = int( ( end - start ) / h2 );

    auto path = (ImVec2*)alloca( sizeof( ImVec2 ) * ( 2 * steps + 4 ) );
    auto ptr = path;

    *ptr++ = dpos + ImVec2( start, 0 );
    *ptr++ = dpos + ImVec2( start + h05, -h05 );
    start += h05;

    while( steps-- )
    {
        *ptr++ = dpos + ImVec2( start + h,   h05 );
        *ptr++ = dpos + ImVec2( start + h2, -h05 );
        start += h2;
    }

    if( end - start <= h )
    {
        const auto span = end - start;
        *ptr++ = dpos + ImVec2( start + span, round( span - h*0.5 ) );
    }
    else
    {
        const auto span = end - start - h;
        *ptr++ = dpos + ImVec2( start + h, h05 );
        *ptr++ = dpos + ImVec2( start + h + span, round( h*0.5 - span ) );
    }

    draw->AddPolyline( path, ptr - path, color, 0, thickness );
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

static float AdjustThreadPosition( View::VisData& vis, float wy, int& offset )
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

static const char* DecodeContextSwitchReasonCode( uint8_t reason )
{
    switch( reason )
    {
    case 0: return "Executive";
    case 1: return "FreePage";
    case 2: return "PageIn";
    case 3: return "PoolAllocation";
    case 4: return "DelayExecution";
    case 5: return "Suspended";
    case 6: return "UserRequest";
    case 7: return "WrExecutive";
    case 8: return "WrFreePage";
    case 9: return "WrPageIn";
    case 10: return "WrPoolAllocation";
    case 11: return "WrDelayExecution";
    case 12: return "WrSuspended";
    case 13: return "WrUserRequest";
    case 14: return "WrEventPair";
    case 15: return "WrQueue";
    case 16: return "WrLpcReceive";
    case 17: return "WrLpcReply";
    case 18: return "WrVirtualMemory";
    case 19: return "WrPageOut";
    case 20: return "WrRendezvous";
    case 21: return "WrKeyedEvent";
    case 22: return "WrTerminated";
    case 23: return "WrProcessInSwap";
    case 24: return "WrCpuRateControl";
    case 25: return "WrCalloutStack";
    case 26: return "WrKernel";
    case 27: return "WrResource";
    case 28: return "WrPushLock";
    case 29: return "WrMutex";
    case 30: return "WrQuantumEnd";
    case 31: return "WrDispatchInt";
    case 32: return "WrPreempted";
    case 33: return "WrYieldExecution";
    case 34: return "WrFastMutex";
    case 35: return "WrGuardedMutex";
    case 36: return "WrRundown";
    case 37: return "WrAlertByThreadId";
    case 38: return "WrDeferredPreempt";
    case 39: return "WrPhysicalFault";
    case 40: return "MaximumWaitReason";
    default: return "unknown";
    }
}

static const char* DecodeContextSwitchReason( uint8_t reason )
{
    switch( reason )
    {
    case 0: return "(Thread is waiting for the scheduler)";
    case 1: return "(Thread is waiting for a free virtual memory page)";
    case 2: return "(Thread is waiting for a virtual memory page to arrive in memory)";
    case 4: return "(Thread execution is delayed)";
    case 5: return "(Thread execution is suspended)";
    case 6: return "(Thread is waiting on object - WaitForSingleObject, etc.)";
    case 7: return "(Thread is waiting for the scheduler)";
    case 8: return "(Thread is waiting for a free virtual memory page)";
    case 9: return "(Thread is waiting for a virtual memory page to arrive in memory)";
    case 11: return "(Thread execution is delayed)";
    case 12: return "(Thread execution is suspended)";
    case 13: return "(Thread is waiting for window messages)";
    case 15: return "(Thread is waiting on KQUEUE)";
    case 24: return "(CPU rate limiting)";
    case 34: return "(Waiting for a Fast Mutex)";
    default: return "";
    }
}

static const char* DecodeContextSwitchStateCode( uint8_t state )
{
    switch( state )
    {
    case 0: return "Initialized";
    case 1: return "Ready";
    case 2: return "Running";
    case 3: return "Standby";
    case 4: return "Terminated";
    case 5: return "Waiting";
    case 6: return "Transition";
    case 7: return "DeferredReady";
    case 101: return "D (disk sleep)";
    case 102: return "I (idle)";
    case 103: return "R (running)";
    case 104: return "S (sleeping)";
    case 105: return "T (stopped)";
    case 106: return "t (tracing stop)";
    case 107: return "W";
    case 108: return "X (dead)";
    case 109: return "Z (zombie)";
    case 110: return "P (parked)";
    default: return "unknown";
    }
}

static const char* DecodeContextSwitchState( uint8_t state )
{
    switch( state )
    {
    case 0: return "(Thread has been initialized, but has not yet started)";
    case 1: return "(Thread is waiting to use a processor because no processor is free. The thread is prepared to run on the next available processor)";
    case 2: return "(Thread is currently using a processor)";
    case 3: return "(Thread is about to use a processor)";
    case 4: return "(Thread has finished executing and has exited)";
    case 5: return "(Thread is not ready to use the processor because it is waiting for a peripheral operation to complete or a resource to become free)";
    case 6: return "(Thread is waiting for a resource, other than the processor, before it can execute)";
    case 7: return "(Thread has been selected to run on a specific processor but have not yet beed scheduled)";
    case 101: return "(Uninterruptible sleep, usually IO)";
    case 102: return "(Idle kernel thread)";
    case 103: return "(Running or on run queue)";
    case 104: return "(Interruptible sleep, waiting for an event to complete)";
    case 105: return "(Stopped by job control signal)";
    case 106: return "(Stopped by debugger during the tracing)";
    case 107: return "(Paging)";
    case 108: return "(Dead task is scheduling one last time)";
    case 109: return "(Zombie process)";
    case 110: return "(Parked)";
    default: return "";
    }
}

void View::DrawContextSwitches( const ContextSwitch* ctx, const Vector<SampleData>& sampleData, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int offset, int endOffset, bool isFiber )
{
    const auto lineSize = 2 * GetScale();

    auto& vec = ctx->v;
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, m_vd.zvStart ), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
    if( it == vec.end() ) return;
    if( it != vec.begin() ) --it;

    auto citend = std::lower_bound( it, vec.end(), m_vd.zvEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
    if( it == citend ) return;
    if( citend != vec.end() ) ++citend;

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = round( ImGui::GetTextLineHeight() * 0.75f );
    const auto ty05 = round( ty * 0.5f );
    auto draw = ImGui::GetWindowDrawList();
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    auto pit = citend;
    double minpx = -10.0;

    while( it < citend )
    {
        auto& ev = *it;
        if( pit != citend )
        {
            const bool migration = pit->Cpu() != ev.Cpu();
            const auto px0 = std::max( { ( pit->End() - m_vd.zvStart ) * pxns, -10.0, minpx } );
            const auto pxw = ( ev.WakeupVal() - m_vd.zvStart ) * pxns;
            const auto px1 = std::min( ( ev.Start() - m_vd.zvStart ) * pxns, w + 10.0 );
            const auto color = migration ? 0xFFEE7711 : 0xFF2222AA;
            if( m_vd.darkenContextSwitches )
            {
                draw->AddRectFilled( dpos + ImVec2( px0, offset + ty05 ), dpos + ImVec2( px1, endOffset ), 0x661C2321 );
            }
            DrawLine( draw, dpos + ImVec2( px0, offset + ty05 - 0.5f ), dpos + ImVec2( std::min( pxw, w+10.0 ), offset + ty05 - 0.5f ), color, lineSize );
            if( ev.WakeupVal() != ev.Start() )
            {
                DrawLine( draw, dpos + ImVec2( std::max( pxw, 10.0 ), offset + ty05 - 0.5f ), dpos + ImVec2( px1, offset + ty05 - 0.5f ), 0xFF2280A0, lineSize );
            }

            if( hover )
            {
                bool tooltip = false;
                if( ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( pxw, offset + ty ) ) )
                {
                    ImGui::BeginTooltip();
                    if( isFiber )
                    {
                        TextFocused( "Fiber is", "yielding" );
                        TextFocused( "Yield time:", TimeToString( ev.Start() - pit->End() ) );
                    }
                    else
                    {
                        TextFocused( "Thread is", migration ? "migrating CPUs" : "waiting" );
                        TextFocused( "Waiting time:", TimeToString( ev.WakeupVal() - pit->End() ) );
                        if( migration )
                        {
                            TextFocused( "CPU:", RealToString( pit->Cpu() ) );
                            ImGui::SameLine();
                            TextFocused( ICON_FA_LONG_ARROW_ALT_RIGHT, RealToString( ev.Cpu() ) );
                        }
                        else
                        {
                            TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                        }
                        if( pit->Reason() != 100 )
                        {
                            TextFocused( "Wait reason:", DecodeContextSwitchReasonCode( pit->Reason() ) );
                            ImGui::SameLine();
                            ImGui::PushFont( m_smallFont );
                            ImGui::AlignTextToFramePadding();
                            TextDisabledUnformatted( DecodeContextSwitchReason( pit->Reason() ) );
                            ImGui::PopFont();
                        }
                        TextFocused( "Wait state:", DecodeContextSwitchStateCode( pit->State() ) );
                        ImGui::SameLine();
                        ImGui::PushFont( m_smallFont );
                        ImGui::AlignTextToFramePadding();
                        TextDisabledUnformatted( DecodeContextSwitchState( pit->State() ) );
                        ImGui::PopFont();
                    }
                    tooltip = true;

                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( pit->End(), ev.WakeupVal() );
                    }
                }
                else if( ev.WakeupVal() != ev.Start() && ImGui::IsMouseHoveringRect( wpos + ImVec2( pxw, offset ), wpos + ImVec2( px1, offset + ty ) ) )
                {
                    assert( !isFiber );
                    ImGui::BeginTooltip();
                    TextFocused( "Thread is", "waking up" );
                    TextFocused( "Scheduling delay:", TimeToString( ev.Start() - ev.WakeupVal() ) );
                    TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( pit->End(), ev.WakeupVal() );
                    }
                    tooltip = true;
                }
                if( tooltip )
                {
                    if( !sampleData.empty() )
                    {
                        auto sdit = std::lower_bound( sampleData.begin(), sampleData.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                        bool found = sdit != sampleData.end() && sdit->time.Val() == ev.Start();
                        if( !found && it != vec.begin() )
                        {
                            auto eit = it;
                            --eit;
                            sdit = std::lower_bound( sampleData.begin(), sampleData.end(), eit->End(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                            found = sdit != sampleData.end() && sdit->time.Val() == eit->End();
                        }
                        if( found )
                        {
                            ImGui::Separator();
                            TextDisabledUnformatted( ICON_FA_HOURGLASS_HALF " Wait stack:" );
                            CallstackTooltipContents( sdit->callstack.Val() );
                            if( ImGui::IsMouseClicked( 0 ) )
                            {
                                m_callstackInfoWindow = sdit->callstack.Val();
                            }
                        }
                    }
                    ImGui::EndTooltip();
                }
            }
        }

        const auto end = ev.IsEndValid() ? ev.End() : m_worker.GetLastTime();
        const auto zsz = std::max( ( end - ev.Start() ) * pxns, pxns * 0.5 );
        if( zsz < MinCtxSize )
        {
            const auto MinCtxNs = MinCtxSize * nspx;
            int num = 0;
            const auto px0 = std::max( ( ev.Start() - m_vd.zvStart ) * pxns, -10.0 );
            auto px1ns = end - m_vd.zvStart;
            auto rend = end;
            auto nextTime = end + MinCtxNs;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, citend, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                num += std::distance( prevIt, it );
                if( it == citend ) break;
                const auto nend = it->IsEndValid() ? it->End() : m_worker.GetLastTime();
                const auto nsnext = nend - m_vd.zvStart;
                if( nsnext - px1ns >= MinCtxNs * 2 ) break;
                px1ns = nsnext;
                rend = nend;
                nextTime = nend + nspx;
            }
            minpx = std::min( std::max( px1ns * pxns, px0+MinCtxSize ), double( w + 10 ) );
            if( num == 1 )
            {
                DrawLine( draw, dpos + ImVec2( px0, offset + ty05 - 0.5f ), dpos + ImVec2( minpx, offset + ty05 - 0.5f ), 0xFF22DD22, lineSize );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( minpx, offset + ty + 1 ) ) )
                {
                    ImGui::BeginTooltip();
                    if( isFiber )
                    {
                        const auto tid = m_worker.DecompressThread( ev.Thread() );
                        TextFocused( "Fiber is", "running" );
                        TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                        TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                    }
                    else
                    {
                        TextFocused( "Thread is", "running" );
                        TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                        TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                    }
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.Start(), rend );
                    }
                }
            }
            else
            {
                DrawZigZag( draw, wpos + ImVec2( 0, offset + ty05 ), px0, minpx, ty/4, 0xFF888888, 1.5 );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( minpx, offset + ty + 1 ) ) )
                {
                    ImGui::BeginTooltip();
                    TextFocused( isFiber ? "Fiber is" : "Thread is", "changing activity multiple times" );
                    TextFocused( "Number of running regions:", RealToString( num ) );
                    TextFocused( "Time:", TimeToString( rend - ev.Start() ) );
                    ImGui::EndTooltip();

                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( ev.Start(), rend );
                    }
                }
            }
            pit = it-1;
        }
        else
        {
            const auto px0 = std::max( { ( ev.Start() - m_vd.zvStart ) * pxns, -10.0, minpx } );
            const auto px1 = std::min( ( end - m_vd.zvStart ) * pxns, w + 10.0 );
            DrawLine( draw, dpos + ImVec2( px0, offset + ty05 - 0.5f ), dpos + ImVec2( px1, offset + ty05 - 0.5f ), 0xFF22DD22, lineSize );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ty + 1 ) ) )
            {
                ImGui::BeginTooltip();
                if( isFiber )
                {
                    const auto tid = m_worker.DecompressThread( ev.Thread() );
                    TextFocused( "Fiber is", "running" );
                    TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                    TextFocused( "Thread:", m_worker.GetThreadName( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( tid ) );
                }
                else
                {
                    TextFocused( "Thread is", "running" );
                    TextFocused( "Activity time:", TimeToString( end - ev.Start() ) );
                    TextFocused( "CPU:", RealToString( ev.Cpu() ) );
                }
                ImGui::EndTooltip();

                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( ev.Start(), end );
                }
            }
            pit = it;
            ++it;
        }
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

static int64_t AdjustGpuTime( int64_t time, int64_t begin, int drift )
{
    if( time < 0 ) return time;
    const auto t = time - begin;
    return time + t / 1000000000 * drift;
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

const char* View::GetThreadContextData( uint64_t thread, bool& _local, bool& _untracked, const char*& program )
{
    static char buf[256];
    const auto local = m_worker.IsThreadLocal( thread );
    auto txt = local ? m_worker.GetThreadName( thread ) : m_worker.GetExternalName( thread ).first;
    auto label = txt;
    bool untracked = false;
    if( !local )
    {
        if( m_worker.GetPid() == 0 )
        {
            untracked = strcmp( txt, m_worker.GetCaptureProgram().c_str() ) == 0;
        }
        else
        {
            const auto pid = m_worker.GetPidFromTid( thread );
            untracked = pid == m_worker.GetPid();
            if( untracked )
            {
                label = txt = m_worker.GetExternalName( thread ).second;
            }
            else
            {
                const auto ttxt = m_worker.GetExternalName( thread ).second;
                if( strcmp( ttxt, "???" ) != 0 && strcmp( ttxt, txt ) != 0 )
                {
                    snprintf( buf, 256, "%s (%s)", txt, ttxt );
                    label = buf;
                }
            }
        }
    }
    _local = local;
    _untracked = untracked;
    program = txt;
    return label;
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

static const char* FormatPlotValue( double val, PlotValueFormatting format )
{
    static char buf[64];
    switch( format )
    {
    case PlotValueFormatting::Number:
        return RealToString( val );
        break;
    case PlotValueFormatting::Memory:
        return MemSizeToString( val );
        break;
    case PlotValueFormatting::Percentage:
        sprintf( buf, "%.2f%%", val );
        break;
    default:
        assert( false );
        break;
    }
    return buf;
}

int View::DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    const auto PlotHeight = 100 * GetScale();

    enum { MaxPoints = 128 };
    float tmpvec[MaxPoints*2];

    const auto w = ImGui::GetContentRegionAvail().x - 1;
    const auto ty = ImGui::GetTextLineHeight();
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto nspx = 1.0 / pxns;
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    for( const auto& v : m_worker.GetPlots() )
    {
        auto& vis = Vis( v );
        if( !vis.visible )
        {
            vis.height = 0;
            vis.offset = 0;
            continue;
        }
        if( v->data.empty() ) continue;
        bool& showFull = vis.showFull;

        float txtx = 0;
        const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
        const auto oldOffset = offset;
        ImGui::PushClipRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + vis.height ), true );
        if( yPos + ty >= yMin && yPos <= yMax )
        {
            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFF44DDDD );
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF226E6E, 2.0f );
            }
            const auto txt = GetPlotName( v );
            txtx = ImGui::CalcTextSize( txt ).x;
            DrawTextContrast( draw, wpos + ImVec2( ty, offset ), showFull ? 0xFF44DDDD : 0xFF226E6E, txt );
            DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtx, offset + ty ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Plot \"%s\"", txt );
                ImGui::Separator();

                const auto first = v->data.front().time.Val();
                const auto last = v->data.back().time.Val();
                const auto activity = last - first;
                const auto traceLen = m_worker.GetLastTime();

                TextFocused( "Appeared at", TimeToString( first ) );
                TextFocused( "Last event at", TimeToString( last ) );
                TextFocused( "Activity time:", TimeToString( activity ) );
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, activity / double( traceLen ) * 100 );
                TextDisabledUnformatted( buf );
                ImGui::Separator();
                TextFocused( "Data points:", RealToString( v->data.size() ) );
                TextFocused( "Data range:", FormatPlotValue( v->max - v->min, v->format ) );
                TextFocused( "Min value:", FormatPlotValue( v->min, v->format ) );
                TextFocused( "Max value:", FormatPlotValue( v->max, v->format ) );
                TextFocused( "Avg value:", FormatPlotValue( v->sum / v->data.size(), v->format ) );
                TextFocused( "Data/second:", RealToString( double( v->data.size() ) / activity * 1000000000ll ) );

                const auto it = std::lower_bound( v->data.begin(), v->data.end(), last - 1000000000ll * 10, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                const auto tr10 = last - it->time.Val();
                if( tr10 != 0 )
                {
                    TextFocused( "D/s (10s):", RealToString( double( std::distance( it, v->data.end() ) ) / tr10 * 1000000000ll ) );
                }
                ImGui::EndTooltip();

                if( IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( first, last );
                }
            }
        }

        offset += ty;

        if( showFull )
        {
            auto yPos = wpos.y + offset;
            if( yPos + PlotHeight >= yMin && yPos <= yMax )
            {
                auto& vec = v->data;
                vec.ensure_sorted();

                if( v->type == PlotType::Memory )
                {
                    auto& mem = m_worker.GetMemoryNamed( v->name );

                    if( m_memoryAllocInfoPool == v->name && m_memoryAllocInfoWindow >= 0 )
                    {
                        const auto& ev = mem.data[m_memoryAllocInfoWindow];

                        const auto tStart = ev.TimeAlloc();
                        const auto tEnd = ev.TimeFree() < 0 ? m_worker.GetLastTime() : ev.TimeFree();

                        const auto px0 = ( tStart - m_vd.zvStart ) * pxns;
                        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_vd.zvStart ) * pxns );
                        draw->AddRectFilled( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x2288DD88 );
                        draw->AddRect( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x4488DD88 );
                    }
                    if( m_memoryAllocHover >= 0 && m_memoryAllocHoverPool == v->name && ( m_memoryAllocInfoPool != v->name || m_memoryAllocHover != m_memoryAllocInfoWindow ) )
                    {
                        const auto& ev = mem.data[m_memoryAllocHover];

                        const auto tStart = ev.TimeAlloc();
                        const auto tEnd = ev.TimeFree() < 0 ? m_worker.GetLastTime() : ev.TimeFree();

                        const auto px0 = ( tStart - m_vd.zvStart ) * pxns;
                        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_vd.zvStart ) * pxns );
                        draw->AddRectFilled( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x228888DD );
                        draw->AddRect( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x448888DD );

                        if( m_memoryAllocHoverWait > 0 )
                        {
                            m_memoryAllocHoverWait--;
                        }
                        else
                        {
                            m_memoryAllocHover = -1;
                        }
                    }
                }

                auto it = std::lower_bound( vec.begin(), vec.end(), m_vd.zvStart - m_worker.GetDelay(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                auto end = std::lower_bound( it, vec.end(), m_vd.zvEnd + m_worker.GetResolution(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );

                if( end != vec.end() ) end++;
                if( it != vec.begin() ) it--;

                double min = it->val;
                double max = it->val;
                const auto num = std::distance( it, end );
                if( num > 1000000 )
                {
                    min = v->min;
                    max = v->max;
                }
                else
                {
                    auto tmp = it;
                    ++tmp;
                    const auto sz = end - tmp;
                    for( ptrdiff_t i=0; i<sz; i++ )
                    {
                        min = tmp[i].val < min ? tmp[i].val : min;
                        max = tmp[i].val > max ? tmp[i].val : max;
                    }
                }
                if( min == max )
                {
                    min--;
                    max++;
                }

                const auto rMin = min;
                const auto rMax = max;

                auto pvit = m_plotView.find( v );
                if( pvit == m_plotView.end() )
                {
                    pvit = m_plotView.emplace( v, PlotView { min, max } ).first;
                }
                auto& pv = pvit->second;
                if( pv.min != min || pv.max != max )
                {
                    const auto dt = ImGui::GetIO().DeltaTime;
                    const auto minDiff = min - pv.min;
                    const auto maxDiff = max - pv.max;

                    pv.min += minDiff * 15.0 * dt;
                    pv.max += maxDiff * 15.0 * dt;

                    const auto minDiffNew = min - pv.min;
                    const auto maxDiffNew = max - pv.max;

                    if( minDiff * minDiffNew < 0 ) pv.min = min;
                    if( maxDiff * maxDiffNew < 0 ) pv.max = max;

                    min = pv.min;
                    max = pv.max;
                }

                const auto revrange = 1.0 / ( max - min );

                if( it == vec.begin() )
                {
                    const auto x = ( it->time.Val() - m_vd.zvStart ) * pxns;
                    const auto y = PlotHeight - ( it->val - min ) * revrange * PlotHeight;
                    DrawPlotPoint( wpos, x, y, offset, 0xFF44DDDD, hover, false, it, 0, false, v->type, v->format, PlotHeight, v->name );
                }

                auto prevx = it;
                auto prevy = it;
                ++it;
                ptrdiff_t skip = 0;
                while( it < end )
                {
                    const auto x0 = ( prevx->time.Val() - m_vd.zvStart ) * pxns;
                    const auto x1 = ( it->time.Val() - m_vd.zvStart ) * pxns;
                    const auto y0 = PlotHeight - ( prevy->val - min ) * revrange * PlotHeight;
                    const auto y1 = PlotHeight - ( it->val - min ) * revrange * PlotHeight;

                    DrawLine( draw, dpos + ImVec2( x0, offset + y0 ), dpos + ImVec2( x1, offset + y1 ), 0xFF44DDDD );

                    const auto rx = skip == 0 ? 2.0 : ( skip == 1 ? 2.5 : 4.0 );

                    auto range = std::upper_bound( it, end, int64_t( it->time.Val() + nspx * rx ), [] ( const auto& l, const auto& r ) { return l < r.time.Val(); } );
                    assert( range > it );
                    const auto rsz = std::distance( it, range );
                    if( rsz == 1 )
                    {
                        DrawPlotPoint( wpos, x1, y1, offset, 0xFF44DDDD, hover, true, it, prevy->val, false, v->type, v->format, PlotHeight, v->name );
                        prevx = it;
                        prevy = it;
                        ++it;
                    }
                    else
                    {
                        prevx = it;

                        skip = rsz / MaxPoints;
                        const auto skip1 = std::max<ptrdiff_t>( 1, skip );
                        const auto sz = rsz / skip1 + 1;
                        assert( sz <= MaxPoints*2 );

                        auto dst = tmpvec;
                        const auto rsz = std::distance( it, range );
                        const auto ssz = rsz / skip1;
                        for( int64_t i=0; i<ssz; i++ )
                        {
                            *dst++ = float( it->val );
                            it += skip1;
                        }
                        pdqsort_branchless( tmpvec, dst );

                        if( rsz > MaxPoints )
                        {
                            DrawLine( draw, dpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), dpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD, 4.f );

                            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x1 - 2, offset ), wpos + ImVec2( x1 + 2, offset + PlotHeight ) ) )
                            {
                                ImGui::BeginTooltip();
                                TextFocused( "Number of values:", RealToString( rsz ) );
                                TextDisabledUnformatted( "Estimated range:" );
                                ImGui::SameLine();
                                ImGui::Text( "%s - %s", FormatPlotValue( tmpvec[0], v->format ), FormatPlotValue( dst[-1], v->format ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s)", FormatPlotValue( dst[-1] - tmpvec[0], v->format ) );
                                ImGui::EndTooltip();
                            }
                        }
                        else
                        {
                            DrawLine( draw, dpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), dpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD );

                            auto vit = tmpvec;
                            while( vit != dst )
                            {
                                auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                                assert( vrange > vit );
                                if( std::distance( vit, vrange ) == 1 )
                                {
                                    DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, false, v->format, PlotHeight );
                                }
                                else
                                {
                                    DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, true, v->format, PlotHeight );
                                }
                                vit = vrange;
                            }
                        }

                        prevy = it - 1;
                    }
                }

                if( yPos + ty >= yMin && yPos <= yMax )
                {
                    char tmp[64];
                    sprintf( tmp, "(y-range: %s, visible data points: %s)", FormatPlotValue( rMax - rMin, v->format ), RealToString( num ) );
                    draw->AddText( wpos + ImVec2( ty * 1.5f + txtx, offset - ty ), 0x8844DDDD, tmp );
                }
                auto tmp = FormatPlotValue( rMax, v->format );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
                offset += PlotHeight - ty;
                tmp = FormatPlotValue( rMin, v->format );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );

                DrawLine( draw, dpos + ImVec2( 0, offset + ty - 1 ), dpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );
                offset += ty;
            }
            else
            {
                offset += PlotHeight;
            }
        }
        offset += 0.2 * ty;
        AdjustThreadHeight( vis, oldOffset, offset );
        ImGui::PopClipRect();
    }

    return offset;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, PlotValueFormatting format, float PlotHeight )
{
    auto draw = ImGui::GetWindowDrawList();
    if( merged )
    {
        draw->AddRectFilled( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }
    else
    {
        draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        TextFocused( "Value:", FormatPlotValue( val, format ) );
        if( hasPrev )
        {
            TextFocused( "Change:", FormatPlotValue( val - prev, format ) );
        }
        ImGui::EndTooltip();
    }
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, PlotValueFormatting format, float PlotHeight, uint64_t name )
{
    auto draw = ImGui::GetWindowDrawList();
    if( merged )
    {
        draw->AddRectFilled( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }
    else
    {
        draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        TextFocused( "Time:", TimeToStringExact( item->time.Val() ) );
        if( type == PlotType::Memory )
        {
            TextDisabledUnformatted( "Value:" );
            ImGui::SameLine();
            if( item->val < 10000ll )
            {
                ImGui::TextUnformatted( MemSizeToString( item->val ) );
            }
            else
            {
                ImGui::TextUnformatted( MemSizeToString( item->val ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( item->val ) );
            }
        }
        else
        {
            TextFocused( "Value:", FormatPlotValue( item->val, format ) );
        }
        if( hasPrev )
        {
            const auto change = item->val - prev;
            TextFocused( "Change:", FormatPlotValue( change, format ) );

            if( type == PlotType::Memory )
            {
                auto& mem = m_worker.GetMemoryNamed( name );
                const MemEvent* ev = nullptr;
                if( change > 0 )
                {
                    auto it = std::lower_bound( mem.data.begin(), mem.data.end(), item->time.Val(), [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                    if( it != mem.data.end() && it->TimeAlloc() == item->time.Val() )
                    {
                        ev = it;
                    }
                }
                else
                {
                    const auto& data = mem.data;
                    auto it = std::lower_bound( mem.frees.begin(), mem.frees.end(), item->time.Val(), [&data] ( const auto& lhs, const auto& rhs ) { return data[lhs].TimeFree() < rhs; } );
                    if( it != mem.frees.end() && data[*it].TimeFree() == item->time.Val() )
                    {
                        ev = &data[*it];
                    }
                }
                if( ev )
                {
                    ImGui::Separator();
                    TextDisabledUnformatted( "Address:" );
                    ImGui::SameLine();
                    ImGui::Text( "0x%" PRIx64, ev->Ptr() );
                    TextFocused( "Appeared at", TimeToStringExact( ev->TimeAlloc() ) );
                    if( change > 0 )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(this event)" );
                    }
                    if( ev->TimeFree() < 0 )
                    {
                        ImGui::TextUnformatted( "Allocation still active" );
                    }
                    else
                    {
                        TextFocused( "Freed at", TimeToStringExact( ev->TimeFree() ) );
                        if( change < 0 )
                        {
                            ImGui::SameLine();
                            TextDisabledUnformatted( "(this event)" );
                        }
                        TextFocused( "Duration:", TimeToString( ev->TimeFree() - ev->TimeAlloc() ) );
                    }
                    uint64_t tid;
                    if( change > 0 )
                    {
                        tid = m_worker.DecompressThread( ev->ThreadAlloc() );
                    }
                    else
                    {
                        tid = m_worker.DecompressThread( ev->ThreadFree() );
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
                    m_memoryAllocHover = std::distance( mem.data.begin(), ev );
                    m_memoryAllocHoverWait = 2;
                    m_memoryAllocHoverPool = name;
                    if( IsMouseClicked( 0 ) )
                    {
                        m_memoryAllocInfoWindow = m_memoryAllocHover;
                        m_memoryAllocInfoPool = name;
                    }
                }
            }
        }
        ImGui::EndTooltip();
    }
}

void View::DrawInfoWindow()
{
    if( m_zoneInfoWindow )
    {
        DrawZoneInfoWindow();
    }
    else if( m_gpuInfoWindow )
    {
        DrawGpuInfoWindow();
    }
}

template<typename T>
static inline uint32_t GetZoneCallstack( const T& ev, const Worker& worker );

template<>
inline uint32_t GetZoneCallstack<ZoneEvent>( const ZoneEvent& ev, const Worker& worker )
{
    return worker.GetZoneExtra( ev ).callstack.Val();
}

template<>
inline uint32_t GetZoneCallstack<GpuEvent>( const GpuEvent& ev, const Worker& worker )
{
    return ev.callstack.Val();
}

template<typename T>
void DrawZoneTrace( T zone, const std::vector<T>& trace, const Worker& worker, BuzzAnim<const void*>& anim, View& view, bool& showUnknownFrames, std::function<void(T, int&)> showZone )
{
    bool expand = ImGui::TreeNode( "Zone trace" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( trace.size() ) );
    if( !expand ) return;

    ImGui::SameLine();
    SmallCheckbox( "Show unknown frames", &showUnknownFrames );

    int fidx = 1;
    TextDisabledUnformatted( "0." );
    ImGui::SameLine();
    TextDisabledUnformatted( "[this zone]" );

    if( !trace.empty() )
    {
        T prev = zone;
        const auto sz = trace.size();
        for( size_t i=0; i<sz; i++ )
        {
            auto curr = trace[i];
            const auto pcv = GetZoneCallstack( *prev, worker );
            const auto ccv = GetZoneCallstack( *curr, worker );
            if( pcv == 0 || ccv == 0 )
            {
                if( showUnknownFrames )
                {
                    ImGui::TextDisabled( "%i.", fidx++ );
                    ImGui::SameLine();
                    TextDisabledUnformatted( "[unknown frames]" );
                }
            }
            else if( pcv != ccv )
            {
                auto& prevCs = worker.GetCallstack( pcv );
                auto& currCs = worker.GetCallstack( ccv );

                const auto psz = int( prevCs.size() );
                int idx;
                for( idx=0; idx<psz; idx++ )
                {
                    auto pf = prevCs[idx];
                    bool found = false;
                    for( auto& cf : currCs )
                    {
                        if( cf.data == pf.data )
                        {
                            idx--;
                            found = true;
                            break;
                        }
                    }
                    if( found ) break;
                }
                for( int j=1; j<idx; j++ )
                {
                    auto frameData = worker.GetCallstackFrame( prevCs[j] );
                    auto frame = frameData->data + frameData->size - 1;
                    ImGui::TextDisabled( "%i.", fidx++ );
                    ImGui::SameLine();
                    TextDisabledUnformatted( worker.GetString( frame->name ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    if( anim.Match( frame ) )
                    {
                        const auto time = anim.Time();
                        const auto indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                    }
                    else
                    {
                        ImGui::SameLine();
                    }
                    const auto fileName = worker.GetString( frame->file );
                    TextDisabledUnformatted( LocationToString( fileName, frame->line ) );
                    if( ImGui::IsItemClicked( 1 ) )
                    {
                        if( !view.ViewDispatch( fileName, frame->line, frame->symAddr ) )
                        {
                            anim.Enable( frame, 0.5f );
                        }
                    }
                }
            }

            showZone( curr, fidx );
            prev = curr;
        }
    }

    auto last = trace.empty() ? zone : trace.back();
    const auto lcv = GetZoneCallstack( *last, worker );
    if( lcv == 0 )
    {
        if( showUnknownFrames )
        {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            TextDisabledUnformatted( "[unknown frames]" );
        }
    }
    else
    {
        auto& cs = worker.GetCallstack( lcv );
        const auto csz = cs.size();
        for( uint16_t i=1; i<csz; i++ )
        {
            auto frameData = worker.GetCallstackFrame( cs[i] );
            auto frame = frameData->data + frameData->size - 1;
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            TextDisabledUnformatted( worker.GetString( frame->name ) );
            ImGui::SameLine();
            ImGui::Spacing();
            if( anim.Match( frame ) )
            {
                const auto time = anim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const auto fileName = worker.GetString( frame->file );
            TextDisabledUnformatted( LocationToString( fileName, frame->line ) );
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( !view.ViewDispatch( fileName, frame->line, frame->symAddr ) )
                {
                    anim.Enable( frame, 0.5f );
                }
            }
        }
    }

    ImGui::TreePop();
}

void View::CalcZoneTimeData( unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    assert( zone.HasChildren() );
    const auto& children = m_worker.GetZoneChildren( zone.Child() );
    if( children.is_magic() )
    {
        CalcZoneTimeDataImpl<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &children ), data, ztime, zone );
    }
    else
    {
        CalcZoneTimeDataImpl<VectorAdapterPointer<ZoneEvent>>( children, data, ztime, zone );
    }
}

template<typename Adapter, typename V>
void View::CalcZoneTimeDataImpl( const V& children, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    Adapter a;
    if( m_timeDist.exclusiveTime )
    {
        int64_t zt = ztime;
        for( auto& child : children )
        {
            const auto t = m_worker.GetZoneEnd( a(child) ) - a(child).Start();
            zt -= t;
        }
        ztime = zt;
    }
    for( auto& child : children )
    {
        const auto srcloc = a(child).SrcLoc();
        const auto t = m_worker.GetZoneEnd( a(child) ) - a(child).Start();
        auto it = data.find( srcloc );
        if( it == data.end() )
        {
            it = data.emplace( srcloc, ZoneTimeData { t, 1 } ).first;
        }
        else
        {
            it->second.time += t;
            it->second.count++;
        }
        if( a(child).Child() >= 0 ) CalcZoneTimeData( data, it->second.time, a(child) );
    }
}

void View::CalcZoneTimeData( const ContextSwitch* ctx, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    assert( zone.HasChildren() );
    const auto& children = m_worker.GetZoneChildren( zone.Child() );
    if( children.is_magic() )
    {
        CalcZoneTimeDataImpl<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &children ), ctx, data, ztime, zone );
    }
    else
    {
        CalcZoneTimeDataImpl<VectorAdapterPointer<ZoneEvent>>( children, ctx, data, ztime, zone );
    }
}

template<typename Adapter, typename V>
void View::CalcZoneTimeDataImpl( const V& children, const ContextSwitch* ctx, unordered_flat_map<int16_t, ZoneTimeData>& data, int64_t& ztime, const ZoneEvent& zone )
{
    Adapter a;
    if( m_timeDist.exclusiveTime )
    {
        int64_t zt = ztime;
        for( auto& child : children )
        {
            int64_t t;
            uint64_t cnt;
            const auto res = GetZoneRunningTime( ctx, a(child), t, cnt );
            assert( res );
            zt -= t;
        }
        ztime = zt;
    }
    for( auto& child : children )
    {
        const auto srcloc = a(child).SrcLoc();
        int64_t t;
        uint64_t cnt;
        const auto res = GetZoneRunningTime( ctx, a(child), t, cnt );
        assert( res );
        auto it = data.find( srcloc );
        if( it == data.end() )
        {
            it = data.emplace( srcloc, ZoneTimeData { t, 1 } ).first;
        }
        else
        {
            it->second.time += t;
            it->second.count++;
        }
        if( a(child).HasChildren() ) CalcZoneTimeData( ctx, data, it->second.time, a(child) );
    }
}

void View::DrawZoneInfoWindow()
{
    auto& ev = *m_zoneInfoWindow;

    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 500 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    bool show = true;
    ImGui::Begin( "Zone info", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to zone" ) )
        {
            ZoomToZone( ev );
        }
        auto parent = GetZoneParent( ev );
        if( parent )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_UP " Go to parent" ) )
            {
                ShowZoneInfo( *parent );
            }
        }
#ifndef TRACY_NO_STATISTICS
        if( m_worker.AreSourceLocationZonesReady() )
        {
            const auto sl = ev.SrcLoc();
            const auto& slz = m_worker.GetZonesForSourceLocation( sl );
            if( !slz.zones.empty() )
            {
                ImGui::SameLine();
                if( ImGui::Button( ICON_FA_CHART_BAR " Statistics" ) )
                {
                    m_findZone.ShowZone( sl, m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
                }
            }
        }
#endif
        if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).callstack.Val() != 0 )
        {
            const auto& extra = m_worker.GetZoneExtra( ev );
            ImGui::SameLine();
            bool hilite = m_callstackInfoWindow == extra.callstack.Val();
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackInfoWindow = extra.callstack.Val();
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        const auto fileName = m_worker.GetString( srcloc.file );
        if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
        {
            ImGui::SameLine();
            bool hilite = m_sourceViewFile == fileName;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_FILE_ALT " Source" ) )
            {
                ViewSource( fileName, srcloc.line );
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        if( !m_zoneInfoStack.empty() )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_LEFT " Go back" ) )
            {
                m_zoneInfoWindow = m_zoneInfoStack.back_and_pop();
            }
        }

        ImGui::Separator();

        auto threadData = GetZoneThreadData( ev );
        assert( threadData );
        const auto tid = threadData->id;
        if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).name.Active() )
        {
            ImGui::PushFont( m_bigFont );
            TextFocused( "Zone name:", m_worker.GetString( m_worker.GetZoneExtra( ev ).name ) );
            ImGui::PopFont();
            if( srcloc.name.active )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", m_worker.GetString( srcloc.name ) );
            }
            ImGui::SameLine();
            if( ClipboardButton( 1 ) )
            {
                if( srcloc.name.active )
                {
                    char tmp[1024];
                    sprintf( tmp, "%s (%s)", m_worker.GetString( m_worker.GetZoneExtra( ev ).name ), m_worker.GetString( srcloc.name ) );
                    ImGui::SetClipboardText( tmp );
                }
                else
                {
                    ImGui::SetClipboardText( m_worker.GetString( m_worker.GetZoneExtra( ev ).name ) );
                }
            }
            TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
            ImGui::SameLine();
            if( ClipboardButton( 2 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        }
        else if( srcloc.name.active )
        {
            ImGui::PushFont( m_bigFont );
            TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
            ImGui::PopFont();
            ImGui::SameLine();
            if( ClipboardButton( 1 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.name ) );
            TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
            ImGui::SameLine();
            if( ClipboardButton( 2 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        }
        else
        {
            ImGui::PushFont( m_bigFont );
            TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
            ImGui::PopFont();
            ImGui::SameLine();
            if( ClipboardButton( 1 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        }
        SmallColorBox( GetSrcLocColor( m_worker.GetSourceLocation( ev.SrcLoc() ), 0 ) );
        ImGui::SameLine();
        TextDisabledUnformatted( "Location:" );
        ImGui::SameLine();
        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
        ImGui::SameLine();
        if( ClipboardButton( 3 ) )
        {
            ImGui::SetClipboardText( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
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
        if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).text.Active() )
        {
            TextFocused( "User text:", m_worker.GetString( m_worker.GetZoneExtra( ev ).text ) );
        }

        ImGui::Separator();
        ImGui::BeginChild( "##zoneinfo" );

        const auto end = m_worker.GetZoneEnd( ev );
        const auto ztime = end - ev.Start();
        const auto selftime = GetZoneSelfTime( ev );
        TextFocused( "Time from start of program:", TimeToStringExact( ev.Start() ) );
        TextFocused( "Execution time:", TimeToString( ztime ) );
#ifndef TRACY_NO_STATISTICS
        if( m_worker.AreSourceLocationZonesReady() )
        {
            auto& zoneData = m_worker.GetZonesForSourceLocation( ev.SrcLoc() );
            if( zoneData.total > 0 )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.2f%% of mean time)", float( ztime ) / zoneData.total * zoneData.zones.size() * 100 );
            }
        }
#endif
        TextFocused( "Self time:", TimeToString( selftime ) );
        if( ztime != 0 )
        {
            char buf[64];
            PrintStringPercent( buf, 100.f * selftime / ztime );
            ImGui::SameLine();
            TextDisabledUnformatted( buf );
        }
        const auto ctx = m_worker.GetContextSwitchData( tid );
        if( ctx )
        {
            auto it = std::lower_bound( ctx->v.begin(), ctx->v.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
            if( it != ctx->v.end() )
            {
                const auto end = m_worker.GetZoneEnd( ev );
                auto eit = std::upper_bound( it, ctx->v.end(), end, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                bool incomplete = eit == ctx->v.end() && !m_worker.IsThreadFiber( tid );
                uint64_t cnt = std::distance( it, eit );
                if( cnt == 1 )
                {
                    if( !incomplete )
                    {
                        TextFocused( "Running state time:", TimeToString( ztime ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "(100%)" );
                        ImGui::Separator();
                        TextFocused( "Running state regions:", "1" );
                        if( !threadData->isFiber ) TextFocused( "CPU:", RealToString( it->Cpu() ) );
                    }
                }
                else if( cnt > 1 )
                {
                    uint8_t cpus[256] = {};
                    auto bit = it;
                    int64_t running = it->End() - ev.Start();
                    cpus[it->Cpu()] = 1;
                    ++it;
                    for( uint64_t i=0; i<cnt-2; i++ )
                    {
                        running += it->End() - it->Start();
                        cpus[it->Cpu()] = 1;
                        ++it;
                    }
                    running += end - it->Start();
                    cpus[it->Cpu()] = 1;
                    TextFocused( "Running state time:", TimeToString( running ) );
                    if( ztime != 0 )
                    {
                        char buf[64];
                        PrintStringPercent( buf, 100.f * running / ztime );
                        ImGui::SameLine();
                        TextDisabledUnformatted( buf );
                    }
                    ImGui::Separator();
                    if( incomplete )
                    {
                        TextColoredUnformatted( ImVec4( 1, 0, 0, 1 ), "Incomplete context switch data!" );
                    }
                    TextFocused( "Running state regions:", RealToString( cnt ) );

                    if( !threadData->isFiber )
                    {
                        int numCpus = 0;
                        for( int i=0; i<256; i++ ) numCpus += cpus[i];
                        if( numCpus == 1 )
                        {
                            TextFocused( "CPU:", RealToString( it->Cpu() ) );
                        }
                        else
                        {
                            ImGui::TextDisabled( "CPUs (%i):", numCpus );
                            for( int i=0;; i++ )
                            {
                                if( cpus[i] != 0 )
                                {
                                    ImGui::SameLine();
                                    numCpus--;
                                    if( numCpus == 0 )
                                    {
                                        ImGui::Text( "%i", i );
                                        break;
                                    }
                                    else
                                    {
                                        int consecutive = 1;
                                        int remaining = numCpus;
                                        for(;;)
                                        {
                                            if( cpus[i+consecutive] == 0 ) break;
                                            consecutive++;
                                            if( --remaining == 0 ) break;
                                        }
                                        if( consecutive > 2 )
                                        {
                                            if( remaining == 0 )
                                            {
                                                ImGui::Text( "%i \xE2\x80\x93 %i", i, i+consecutive-1 );
                                                break;
                                            }
                                            else
                                            {
                                                ImGui::Text( "%i \xE2\x80\x93 %i,", i, i+consecutive-1 );
                                                i += consecutive - 1;
                                                numCpus = remaining;
                                            }
                                        }
                                        else
                                        {
                                            ImGui::Text( "%i,", i );
                                        }
                                    }
                                }
                            }
                        }
                    }

                    --eit;
                    if( ImGui::TreeNode( "Wait regions" ) )
                    {
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        SmallCheckbox( "Time relative to zone start", &m_ctxSwitchTimeRelativeToZone );
                        const int64_t adjust = m_ctxSwitchTimeRelativeToZone ? ev.Start() : 0;
                        const auto wrsz = eit - bit;

                        const auto numColumns = threadData->isFiber ? 4 : 6;
                        if( ImGui::BeginTable( "##waitregions", numColumns, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<int64_t>( 1+wrsz, 15 ) ) ) )
                        {
                            ImGui::TableSetupScrollFreeze( 0, 1 );
                            ImGui::TableSetupColumn( "Begin" );
                            ImGui::TableSetupColumn( "End" );
                            ImGui::TableSetupColumn( "Time" );
                            if( threadData->isFiber )
                            {
                                ImGui::TableSetupColumn( "Thread" );
                            }
                            else
                            {
                                ImGui::TableSetupColumn( "Wakeup" );
                                ImGui::TableSetupColumn( "CPU" );
                                ImGui::TableSetupColumn( "State" );
                            }
                            ImGui::TableHeadersRow();

                            ImGuiListClipper clipper;
                            clipper.Begin( wrsz );
                            while( clipper.Step() )
                            {
                                for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                                {
                                    const auto cend = bit[i].End();
                                    const auto cstart = bit[i+1].Start();
                                    const auto cwakeup = bit[i+1].WakeupVal();

                                    ImGui::PushID( i );
                                    ImGui::TableNextRow();
                                    ImGui::TableNextColumn();

                                    auto tt = adjust == 0 ? TimeToStringExact( cend ) : TimeToString( cend - adjust );
                                    if( ImGui::Selectable( tt ) )
                                    {
                                        CenterAtTime( cend );
                                    }
                                    ImGui::TableNextColumn();
                                    tt = adjust == 0 ? TimeToStringExact( cstart ) : TimeToString( cstart - adjust );
                                    if( ImGui::Selectable( tt ) )
                                    {
                                        CenterAtTime( cstart );
                                    }
                                    ImGui::TableNextColumn();
                                    if( ImGui::Selectable( TimeToString( cwakeup - cend ) ) )
                                    {
                                        ZoomToRange( cend, cwakeup );
                                    }
                                    ImGui::TableNextColumn();
                                    if( threadData->isFiber )
                                    {
                                        const auto ftid = m_worker.DecompressThread( bit[i].Thread() );
                                        ImGui::TextUnformatted( m_worker.GetThreadName( ftid ) );
                                        ImGui::SameLine();
                                        ImGui::TextDisabled( "(%s)", RealToString( ftid ) );
                                    }
                                    else
                                    {
                                        const auto cpu0 = bit[i].Cpu();
                                        const auto reason = bit[i].Reason();
                                        const auto state = bit[i].State();
                                        const auto cpu1 = bit[i+1].Cpu();

                                        if( cstart != cwakeup )
                                        {
                                            if( ImGui::Selectable( TimeToString( cstart - cwakeup ) ) )
                                            {
                                                ZoomToRange( cwakeup, cstart );
                                            }
                                        }
                                        else
                                        {
                                            ImGui::TextUnformatted( "-" );
                                        }
                                        ImGui::TableNextColumn();
                                        if( cpu0 == cpu1 )
                                        {
                                            ImGui::TextUnformatted( RealToString( cpu0 ) );
                                        }
                                        else
                                        {
                                            ImGui::Text( "%i " ICON_FA_LONG_ARROW_ALT_RIGHT " %i", cpu0, cpu1 );
                                            const auto tt0 = m_worker.GetThreadTopology( cpu0 );
                                            const auto tt1 = m_worker.GetThreadTopology( cpu1 );
                                            if( tt0 && tt1 )
                                            {
                                                if( tt0->package != tt1->package )
                                                {
                                                    ImGui::SameLine();
                                                    TextDisabledUnformatted( "P" );
                                                }
                                                else if( tt0->core != tt1->core )
                                                {
                                                    ImGui::SameLine();
                                                    TextDisabledUnformatted( "C" );
                                                }
                                            }
                                        }
                                        ImGui::TableNextColumn();
                                        const char* desc;
                                        if( reason == ContextSwitchData::NoState )
                                        {
                                            ImGui::TextUnformatted( DecodeContextSwitchStateCode( state ) );
                                            desc = DecodeContextSwitchState( state );
                                        }
                                        else
                                        {
                                            ImGui::TextUnformatted( DecodeContextSwitchReasonCode( reason ) );
                                            desc = DecodeContextSwitchReason( reason );
                                        }
                                        if( *desc ) TooltipIfHovered( desc );
                                    }
                                    ImGui::PopID();
                                }
                            }
                            ImGui::EndTable();
                        }
                        ImGui::TreePop();
                    }
                }
            }
        }

        ImGui::Separator();
        auto& memNameMap = m_worker.GetMemNameMap();
        if( memNameMap.size() > 1 )
        {
            ImGui::AlignTextToFramePadding();
            TextDisabledUnformatted( ICON_FA_ARCHIVE " Memory pool:" );
            ImGui::SameLine();
            if( ImGui::BeginCombo( "##memoryPool", m_zoneInfoMemPool == 0 ? "Default allocator" : m_worker.GetString( m_zoneInfoMemPool ) ) )
            {
                for( auto& v : memNameMap )
                {
                    if( ImGui::Selectable( v.first == 0 ? "Default allocator" : m_worker.GetString( v.first ) ) )
                    {
                        m_zoneInfoMemPool = v.first;
                    }
                }
                ImGui::EndCombo();
            }
        }
        auto& mem = m_worker.GetMemoryNamed( m_zoneInfoMemPool );
        if( mem.data.empty() )
        {
            TextDisabledUnformatted( "No memory events." );
        }
        else
        {
            if( !mem.plot )
            {
                ImGui::Text( "Please wait, computing data..." );
                DrawWaitingDots( s_time );
            }
            else
            {
                const auto thread = m_worker.CompressThread( tid );

                auto ait = std::lower_bound( mem.data.begin(), mem.data.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return l.TimeAlloc() < r; } );
                const auto aend = std::upper_bound( ait, mem.data.end(), end, [] ( const auto& l, const auto& r ) { return l < r.TimeAlloc(); } );

                auto fit = std::lower_bound( mem.frees.begin(), mem.frees.end(), ev.Start(), [&mem] ( const auto& l, const auto& r ) { return mem.data[l].TimeFree() < r; } );
                const auto fend = std::upper_bound( fit, mem.frees.end(), end, [&mem] ( const auto& l, const auto& r ) { return l < mem.data[r].TimeFree(); } );

                const auto aDist = std::distance( ait, aend );
                const auto fDist = std::distance( fit, fend );
                if( aDist == 0 && fDist == 0 )
                {
                    TextDisabledUnformatted( "No memory events." );
                }
                else
                {
                    int64_t cAlloc = 0;
                    int64_t cFree = 0;
                    int64_t nAlloc = 0;
                    int64_t nFree = 0;

                    auto ait2 = ait;
                    auto fit2 = fit;

                    while( ait != aend )
                    {
                        if( ait->ThreadAlloc() == thread )
                        {
                            cAlloc += ait->Size();
                            nAlloc++;
                        }
                        ait++;
                    }
                    while( fit != fend )
                    {
                        if( mem.data[*fit].ThreadFree() == thread )
                        {
                            cFree += mem.data[*fit].Size();
                            nFree++;
                        }
                        fit++;
                    }

                    if( nAlloc == 0 && nFree == 0 )
                    {
                        TextDisabledUnformatted( "No memory events." );
                    }
                    else
                    {
                        ImGui::TextUnformatted( RealToString( nAlloc + nFree ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "memory events." );
                        ImGui::TextUnformatted( RealToString( nAlloc ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "allocs," );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( RealToString( nFree ) );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "frees." );
                        TextFocused( "Memory allocated:", MemSizeToString( cAlloc ) );
                        TextFocused( "Memory freed:", MemSizeToString( cFree ) );
                        TextFocused( "Overall change:", MemSizeToString( cAlloc - cFree ) );

                        if( ImGui::TreeNode( "Allocations list" ) )
                        {
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            SmallCheckbox( "Time relative to zone start", &m_allocTimeRelativeToZone );

                            std::vector<const MemEvent*> v;
                            v.reserve( nAlloc + nFree );

                            auto it = ait2;
                            while( it != aend )
                            {
                                if( it->ThreadAlloc() == thread )
                                {
                                    v.emplace_back( it );
                                }
                                it++;
                            }
                            while( fit2 != fend )
                            {
                                const auto ptr = &mem.data[*fit2++];
                                if( ptr->ThreadFree() == thread )
                                {
                                    if( ptr < ait2 || ptr >= aend )
                                    {
                                        v.emplace_back( ptr );
                                    }
                                }
                            }
                            pdqsort_branchless( v.begin(), v.end(), [] ( const auto& l, const auto& r ) { return l->TimeAlloc() < r->TimeAlloc(); } );

                            ListMemData( v, []( auto v ) {
                                ImGui::Text( "0x%" PRIx64, v->Ptr() );
                            }, nullptr, m_allocTimeRelativeToZone ? ev.Start() : -1, m_zoneInfoMemPool );
                            ImGui::TreePop();
                        }
                    }
                }
            }
        }

        ImGui::Separator();
        {
            if( threadData->messages.empty() )
            {
                TextDisabledUnformatted( "No messages" );
            }
            else
            {
                auto msgit = std::lower_bound( threadData->messages.begin(), threadData->messages.end(), ev.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
                auto msgend = std::lower_bound( msgit, threadData->messages.end(), end+1, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

                const auto dist = std::distance( msgit, msgend );
                if( dist == 0 )
                {
                    TextDisabledUnformatted( "No messages" );
                }
                else
                {
                    bool expand = ImGui::TreeNode( "Messages" );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", RealToString( dist ) );
                    if( expand )
                    {
                        ImGui::SameLine();
                        SmallCheckbox( "Time relative to zone start", &m_messageTimeRelativeToZone );
                        if( ImGui::BeginTable( "##messages", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<int64_t>( msgend-msgit+1, 15 ) ) ) )
                        {
                            ImGui::TableSetupScrollFreeze( 0, 1 );
                            ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                            ImGui::TableSetupColumn( "Message" );
                            ImGui::TableHeadersRow();
                            do
                            {
                                ImGui::PushID( *msgit );
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn();
                                if( ImGui::Selectable( m_messageTimeRelativeToZone ? TimeToString( (*msgit)->time - ev.Start() ) : TimeToStringExact( (*msgit)->time ), m_msgHighlight == *msgit, ImGuiSelectableFlags_SpanAllColumns ) )
                                {
                                    CenterAtTime( (*msgit)->time );
                                }
                                if( ImGui::IsItemHovered() )
                                {
                                    m_msgHighlight = *msgit;
                                }
                                ImGui::PopID();
                                ImGui::TableNextColumn();
                                ImGui::PushStyleColor( ImGuiCol_Text, (*msgit)->color );
                                ImGui::TextWrapped( "%s", m_worker.GetString( (*msgit)->ref ) );
                                ImGui::PopStyleColor();
                            }
                            while( ++msgit != msgend );
                            ImGui::EndTable();
                        }
                        ImGui::TreePop();
                        ImGui::Spacing();
                    }
                }
            }
        }

        ImGui::Separator();

        std::vector<const ZoneEvent*> zoneTrace;
        while( parent )
        {
             zoneTrace.emplace_back( parent );
             parent = GetZoneParent( *parent );
        }
        int idx = 0;
        DrawZoneTrace<const ZoneEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, m_showUnknownFrames, [&idx, this] ( const ZoneEvent* v, int& fidx ) {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            const auto& srcloc = m_worker.GetSourceLocation( v->SrcLoc() );
            SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
            ImGui::SameLine();
            const auto txt = m_worker.GetZoneName( *v, srcloc );
            ImGui::PushID( idx++ );
            auto sel = ImGui::Selectable( txt, false );
            auto hover = ImGui::IsItemHovered();
            const auto fileName = m_worker.GetString( srcloc.file );
            if( m_zoneinfoBuzzAnim.Match( v ) )
            {
                const auto time = m_zoneinfoBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            ImGui::TextDisabled( "(%s) %s", TimeToString( m_worker.GetZoneEnd( *v ) - v->Start() ), LocationToString( fileName, srcloc.line ) );
            ImGui::PopID();
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                {
                    ViewSource( fileName, srcloc.line );
                }
                else
                {
                    m_zoneinfoBuzzAnim.Enable( v, 0.5f );
                }
            }
            if( sel )
            {
                ShowZoneInfo( *v );
            }
            if( hover )
            {
                m_zoneHighlight = v;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *v );
                }
                ZoneTooltip( *v );
            }
        } );

        if( ev.HasChildren() )
        {
            const auto& children = m_worker.GetZoneChildren( ev.Child() );
            bool expand = ImGui::TreeNode( "Child zones" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( children.size() ) );
            if( expand )
            {
                if( children.is_magic() )
                {
                    DrawZoneInfoChildren<VectorAdapterDirect<ZoneEvent>>( *(Vector<ZoneEvent>*)( &children ), ztime );
                }
                else
                {
                    DrawZoneInfoChildren<VectorAdapterPointer<ZoneEvent>>( children, ztime );
                }
                ImGui::TreePop();
            }

            expand = ImGui::TreeNode( "Time distribution" );
            if( expand )
            {
                ImGui::SameLine();
                if( SmallCheckbox( "Self time", &m_timeDist.exclusiveTime ) ) m_timeDist.dataValidFor = nullptr;
                if( ctx )
                {
                    ImGui::SameLine();
                    if( SmallCheckbox( "Running time", &m_timeDist.runningTime ) ) m_timeDist.dataValidFor = nullptr;
                }
                if( m_timeDist.dataValidFor != &ev )
                {
                    m_timeDist.data.clear();
                    if( ev.IsEndValid() ) m_timeDist.dataValidFor = &ev;

                    if( m_timeDist.runningTime )
                    {
                        assert( ctx );
                        int64_t time;
                        uint64_t cnt;
                        if( !GetZoneRunningTime( ctx, ev, time, cnt ) )
                        {
                            TextDisabledUnformatted( "Incomplete context switch data." );
                            m_timeDist.dataValidFor = nullptr;
                        }
                        else
                        {
                            auto it = m_timeDist.data.emplace( ev.SrcLoc(), ZoneTimeData{ time, 1 } ).first;
                            CalcZoneTimeData( ctx, m_timeDist.data, it->second.time, ev );
                        }
                        m_timeDist.fztime = 100.f / time;
                    }
                    else
                    {
                        auto it = m_timeDist.data.emplace( ev.SrcLoc(), ZoneTimeData{ ztime, 1 } ).first;
                        CalcZoneTimeData( m_timeDist.data, it->second.time, ev );
                        m_timeDist.fztime = 100.f / ztime;
                    }
                }
                if( !m_timeDist.data.empty() )
                {
                    std::vector<unordered_flat_map<int16_t, ZoneTimeData>::const_iterator> vec;
                    vec.reserve( m_timeDist.data.size() );
                    for( auto it = m_timeDist.data.cbegin(); it != m_timeDist.data.cend(); ++it ) vec.emplace_back( it );
                    if( ImGui::BeginTable( "##timedist", 3, ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV ) )
                    {
                        ImGui::TableSetupColumn( "Zone", ImGuiTableColumnFlags_PreferSortDescending );
                        ImGui::TableSetupColumn( "Time", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                        ImGui::TableSetupColumn( "MTPC", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                        ImGui::TableHeadersRow();
                        const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
                        switch( sortspec.ColumnIndex )
                        {
                        case 0:
                            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.count < rhs->second.count; } );
                            }
                            else
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.count > rhs->second.count; } );
                            }
                            break;
                        case 1:
                            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time < rhs->second.time; } );
                            }
                            else
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time > rhs->second.time; } );
                            }
                            break;
                        case 2:
                            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return float( lhs->second.time ) / lhs->second.count < float( rhs->second.time ) / rhs->second.count; } );
                            }
                            else
                            {
                                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return float( lhs->second.time ) / lhs->second.count > float( rhs->second.time ) / rhs->second.count; } );
                            }
                            break;
                        default:
                            assert( false );
                            break;
                        }
                        for( auto& v : vec )
                        {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            const auto& sl = m_worker.GetSourceLocation( v->first );
                            SmallColorBox( GetSrcLocColor( sl, 0 ) );
                            ImGui::SameLine();
                            const auto name = m_worker.GetZoneName( sl );
                            if( ImGui::Selectable( name, false, ImGuiSelectableFlags_SpanAllColumns ) )
                            {
                                m_findZone.ShowZone( v->first, name, ev.Start(), m_worker.GetZoneEnd( ev ) );
                            }
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( v->second.count ) );
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted( TimeToString( v->second.time ) );
                            ImGui::SameLine();
                            char buf[64];
                            PrintStringPercent( buf, v->second.time * m_timeDist.fztime );
                            TextDisabledUnformatted( buf );
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted( TimeToString( v->second.time / v->second.count ) );
                        }
                        ImGui::EndTable();
                    }
                }
                ImGui::TreePop();
            }
        }

        ImGui::EndChild();
    }
    ImGui::End();

    if( !show )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

template<typename Adapter, typename V>
void View::DrawZoneInfoChildren( const V& children, int64_t ztime )
{
    Adapter a;
    const auto rztime = 1.0 / ztime;
    const auto ty = ImGui::GetTextLineHeight();

    ImGui::SameLine();
    SmallCheckbox( "Group children locations", &m_groupChildrenLocations );

    if( m_groupChildrenLocations )
    {
        struct ChildGroup
        {
            int16_t srcloc;
            uint64_t t;
            Vector<uint32_t> v;
        };
        uint64_t ctime = 0;
        unordered_flat_map<int16_t, ChildGroup> cmap;
        cmap.reserve( 128 );
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.Start();
            const auto srcloc = child.SrcLoc();
            ctime += ct;

            auto it = cmap.find( srcloc );
            if( it == cmap.end() ) it = cmap.emplace( srcloc, ChildGroup { srcloc } ).first;

            it->second.t += ct;
            it->second.v.push_back( i );
        }

        auto msz = cmap.size();
        Vector<ChildGroup*> cgvec;
        cgvec.reserve_and_use( msz );
        size_t idx = 0;
        for( auto& it : cmap )
        {
            cgvec[idx++] = &it.second;
        }

        pdqsort_branchless( cgvec.begin(), cgvec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->t > rhs->t; } );

        ImGui::Columns( 2 );
        ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() * 2 );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() * 2 );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        for( size_t i=0; i<msz; i++ )
        {
            bool expandGroup = false;
            const auto& cgr = *cgvec[i];
            const auto& srcloc = m_worker.GetSourceLocation( cgr.srcloc );
            const auto txt = m_worker.GetZoneName( srcloc );
            if( cgr.v.size() == 1 )
            {
                auto& cev = a(children[cgr.v.front()]);
                const auto txt = m_worker.GetZoneName( cev );
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( (int)cgr.v.front() );
                ImGui::TreeNodeEx( txt, ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen );
                if( ImGui::IsItemClicked() )
                {
                    ShowZoneInfo( cev );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_zoneHighlight = &cev;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
            }
            else
            {
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( cgr.srcloc );
                expandGroup = ImGui::TreeNode( txt );
                ImGui::PopID();
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    if( srcloc.name.active )
                    {
                        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
                    }
                    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
                    ImGui::Separator();
                    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                    ImGui::EndTooltip();
                }
                ImGui::SameLine();
                ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( cgr.v.size() ) );
            }
            ImGui::NextColumn();
            const auto part = double( cgr.t ) * rztime;
            char buf[128];
            PrintStringPercent( buf, TimeToString( cgr.t ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            if( expandGroup )
            {
                auto ctt = std::make_unique<uint64_t[]>( cgr.v.size() );
                auto cti = std::make_unique<uint32_t[]>( cgr.v.size() );
                for( size_t i=0; i<cgr.v.size(); i++ )
                {
                    const auto& child = a(children[cgr.v[i]]);
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.Start();
                    ctt[i] = ct;
                    cti[i] = uint32_t( i );
                }

                pdqsort_branchless( cti.get(), cti.get() + cgr.v.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                ImGuiListClipper clipper;
                clipper.Begin( cgr.v.size() );
                while( clipper.Step() )
                {
                    for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
                    {
                        auto& cev = a(children[cgr.v[cti[i]]]);
                        const auto txt = m_worker.GetZoneName( cev );
                        bool b = false;
                        ImGui::Indent();
                        ImGui::PushID( (int)cgr.v[cti[i]] );
                        if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                        {
                            ShowZoneInfo( cev );
                        }
                        if( ImGui::IsItemHovered() )
                        {
                            m_zoneHighlight = &cev;
                            if( IsMouseClicked( 2 ) )
                            {
                                ZoomToZone( cev );
                            }
                            ZoneTooltip( cev );
                        }
                        ImGui::PopID();
                        ImGui::Unindent();
                        ImGui::NextColumn();
                        const auto part = double( ctt[cti[i]] ) * rztime;
                        char buf[128];
                        PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
                        ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                        ImGui::NextColumn();
                    }
                }
                ImGui::TreePop();
            }
        }
        ImGui::EndColumns();
    }
    else
    {
        auto ctt = std::make_unique<uint64_t[]>( children.size() );
        auto cti = std::make_unique<uint32_t[]>( children.size() );
        uint64_t ctime = 0;
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.Start();
            ctime += ct;
            ctt[i] = ct;
            cti[i] = uint32_t( i );
        }

        pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

        ImGui::Columns( 2 );
        ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        ImGuiListClipper clipper;
        clipper.Begin( children.size() );
        while( clipper.Step() )
        {
            for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
            {
                auto& cev = a(children[cti[i]]);
                const auto txt = m_worker.GetZoneName( cev );
                bool b = false;
                SmallColorBox( GetSrcLocColor( m_worker.GetSourceLocation( cev.SrcLoc() ), 0 ) );
                ImGui::SameLine();
                ImGui::PushID( (int)i );
                if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    ShowZoneInfo( cev );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_zoneHighlight = &cev;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
                ImGui::NextColumn();
                const auto part = double( ctt[cti[i]] ) * rztime;
                char buf[128];
                PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
                ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                ImGui::NextColumn();
            }
        }
        ImGui::EndColumns();
    }
}

void View::DrawGpuInfoWindow()
{
    auto& ev = *m_gpuInfoWindow;
    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 500 * scale, 600 * scale), ImGuiCond_FirstUseEver );
    bool show = true;
    ImGui::Begin( "Zone info", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to zone" ) )
        {
            ZoomToZone( ev );
        }
        auto parent = GetZoneParent( ev );
        if( parent )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_UP " Go to parent" ) )
            {
                ShowZoneInfo( *parent, m_gpuInfoWindowThread );
            }
        }
        if( ev.callstack.Val() != 0 )
        {
            ImGui::SameLine();
            bool hilite = m_callstackInfoWindow == ev.callstack.Val();
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
            {
                m_callstackInfoWindow = ev.callstack.Val();
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        const auto fileName = m_worker.GetString( srcloc.file );
        if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
        {
            ImGui::SameLine();
            bool hilite = m_sourceViewFile == fileName;
            if( hilite )
            {
                SetButtonHighlightColor();
            }
            if( ImGui::Button( ICON_FA_FILE_ALT " Source" ) )
            {
                ViewSource( fileName, srcloc.line );
            }
            if( hilite )
            {
                ImGui::PopStyleColor( 3 );
            }
        }
        if( !m_gpuInfoStack.empty() )
        {
            ImGui::SameLine();
            if( ImGui::Button( ICON_FA_ARROW_LEFT " Go back" ) )
            {
                m_gpuInfoWindow = m_gpuInfoStack.back_and_pop();
            }
        }

        ImGui::Separator();

        const auto tid = GetZoneThread( ev );
        ImGui::PushFont( m_bigFont );
        TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
        ImGui::PopFont();
        ImGui::SameLine();
        if( ClipboardButton( 1 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.name ) );
        TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
        ImGui::SameLine();
        if( ClipboardButton( 2 ) ) ImGui::SetClipboardText( m_worker.GetString( srcloc.function ) );
        SmallColorBox( GetZoneColor( ev ) );
        ImGui::SameLine();
        TextDisabledUnformatted( "Location:" );
        ImGui::SameLine();
        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
        ImGui::SameLine();
        if( ClipboardButton( 3 ) )
        {
            ImGui::SetClipboardText( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
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
        ImGui::Separator();
        ImGui::BeginChild( "##gpuinfo" );

        const auto end = m_worker.GetZoneEnd( ev );
        const auto ztime = end - ev.GpuStart();
        const auto selftime = GetZoneSelfTime( ev );
        TextFocused( "Time from start of program:", TimeToStringExact( ev.GpuStart() ) );
        TextFocused( "GPU execution time:", TimeToString( ztime ) );
        TextFocused( "GPU self time:", TimeToString( selftime ) );
        if( ztime != 0 )
        {
            char buf[64];
            PrintStringPercent( buf, 100.f * selftime / ztime );
            ImGui::SameLine();
            TextDisabledUnformatted( buf );
        }
        TextFocused( "CPU command setup time:", TimeToString( ev.CpuEnd() - ev.CpuStart() ) );
        auto ctx = GetZoneCtx( ev );
        if( !ctx )
        {
            TextFocused( "Delay to execution:", TimeToString( ev.GpuStart() - ev.CpuStart() ) );
        }
        else
        {
            const auto td = ctx->threadData.size() == 1 ? ctx->threadData.begin() : ctx->threadData.find( m_worker.DecompressThread( ev.Thread() ) );
            assert( td != ctx->threadData.end() );
            int64_t begin;
            if( td->second.timeline.is_magic() )
            {
                begin = ((Vector<GpuEvent>*)&td->second.timeline)->front().GpuStart();
            }
            else
            {
                begin = td->second.timeline.front()->GpuStart();
            }
            const auto drift = GpuDrift( ctx );
            TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.GpuStart(), begin, drift ) - ev.CpuStart() ) );
        }

        ImGui::Separator();

        std::vector<const GpuEvent*> zoneTrace;
        while( parent )
        {
            zoneTrace.emplace_back( parent );
            parent = GetZoneParent( *parent );
        }
        int idx = 0;
        DrawZoneTrace<const GpuEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, m_showUnknownFrames, [&idx, this] ( const GpuEvent* v, int& fidx ) {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            const auto& srcloc = m_worker.GetSourceLocation( v->SrcLoc() );
            const auto txt = m_worker.GetZoneName( *v, srcloc );
            ImGui::PushID( idx++ );
            auto sel = ImGui::Selectable( txt, false );
            auto hover = ImGui::IsItemHovered();
            const auto fileName = m_worker.GetString( srcloc.file );
            if( m_zoneinfoBuzzAnim.Match( v ) )
            {
                const auto time = m_zoneinfoBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            ImGui::TextDisabled( "(%s) %s", TimeToString( m_worker.GetZoneEnd( *v ) - v->GpuStart() ), LocationToString( fileName, srcloc.line ) );
            ImGui::PopID();
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                {
                    ViewSource( fileName, srcloc.line );
                }
                else
                {
                    m_zoneinfoBuzzAnim.Enable( v, 0.5f );
                }
            }
            if( sel )
            {
                ShowZoneInfo( *v, m_gpuInfoWindowThread );
            }
            if( hover )
            {
                m_gpuHighlight = v;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *v );
                }
                ZoneTooltip( *v );
            }
        } );

        if( ev.Child() >= 0 )
        {
            const auto& children = m_worker.GetGpuChildren( ev.Child() );
            bool expand = ImGui::TreeNode( "Child zones" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( children.size() ) );
            if( expand )
            {
                if( children.is_magic() )
                {
                    DrawGpuInfoChildren<VectorAdapterDirect<GpuEvent>>( *(Vector<GpuEvent>*)( &children ), ztime );
                }
                else
                {
                    DrawGpuInfoChildren<VectorAdapterPointer<GpuEvent>>( children, ztime );
                }
                ImGui::TreePop();
            }
        }

        ImGui::EndChild();
    }
    ImGui::End();

    if( !show )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

template<typename Adapter, typename V>
void View::DrawGpuInfoChildren( const V& children, int64_t ztime )
{
    Adapter a;
    const auto rztime = 1.0 / ztime;
    const auto ty = ImGui::GetTextLineHeight();

    ImGui::SameLine();
    SmallCheckbox( "Group children locations", &m_groupChildrenLocations );

    if( m_groupChildrenLocations )
    {
        struct ChildGroup
        {
            int16_t srcloc;
            uint64_t t;
            Vector<uint32_t> v;
        };
        uint64_t ctime = 0;
        unordered_flat_map<StringRef, ChildGroup, StringRefHasher, StringRefComparator> cmap;
        cmap.reserve( 128 );
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.GpuStart();
            const auto srcloc = child.SrcLoc();
            const auto name = m_worker.GetSourceLocation( srcloc ).name;
            ctime += ct;

            auto it = cmap.find( name );
            if( it == cmap.end() ) it = cmap.emplace( name, ChildGroup { srcloc } ).first;

            it->second.t += ct;
            it->second.v.push_back( i );
        }

        auto msz = cmap.size();
        Vector<ChildGroup*> cgvec;
        cgvec.reserve_and_use( msz );
        size_t idx = 0;
        for( auto& it : cmap )
        {
            cgvec[idx++] = &it.second;
        }

        pdqsort_branchless( cgvec.begin(), cgvec.end(), []( const auto& lhs, const auto& rhs ) { return lhs->t > rhs->t; } );

        ImGui::Columns( 2 );
        ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        for( size_t i=0; i<msz; i++ )
        {
            bool expandGroup = false;
            const auto& cgr = *cgvec[i];
            const auto& srcloc = m_worker.GetSourceLocation( cgr.srcloc );
            const auto txt = m_worker.GetZoneName( srcloc );
            if( cgr.v.size() == 1 )
            {
                auto& cev = a(children[cgr.v.front()]);
                const auto txt = m_worker.GetZoneName( cev );
                ImGui::PushID( (int)cgr.v.front() );
                ImGui::TreeNodeEx( txt, ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen );
                if( ImGui::IsItemClicked() )
                {
                    ShowZoneInfo( cev, m_gpuInfoWindowThread );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_gpuHighlight = &cev;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
            }
            else
            {
                ImGui::PushID( cgr.srcloc );
                expandGroup = ImGui::TreeNode( txt );
                ImGui::PopID();
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    if( srcloc.name.active )
                    {
                        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
                    }
                    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
                    ImGui::Separator();
                    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                    ImGui::EndTooltip();
                }
                ImGui::SameLine();
                ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( cgr.v.size() ) );
            }
            ImGui::NextColumn();
            const auto part = double( cgr.t ) * rztime;
            char buf[128];
            PrintStringPercent( buf, TimeToString( cgr.t ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            if( expandGroup )
            {
                auto ctt = std::make_unique<uint64_t[]>( cgr.v.size() );
                auto cti = std::make_unique<uint32_t[]>( cgr.v.size() );
                for( size_t i=0; i<cgr.v.size(); i++ )
                {
                    const auto& child = a(children[cgr.v[i]]);
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.GpuStart();
                    ctt[i] = ct;
                    cti[i] = uint32_t( i );
                }

                pdqsort_branchless( cti.get(), cti.get() + cgr.v.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                for( size_t i=0; i<cgr.v.size(); i++ )
                {
                    auto& cev = a(children[cgr.v[cti[i]]]);
                    const auto txt = m_worker.GetZoneName( cev );
                    bool b = false;
                    ImGui::Indent();
                    ImGui::PushID( (int)cgr.v[cti[i]] );
                    if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                    {
                        ShowZoneInfo( cev, m_gpuInfoWindowThread );
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        m_gpuHighlight = &cev;
                        if( IsMouseClicked( 2 ) )
                        {
                            ZoomToZone( cev );
                        }
                        ZoneTooltip( cev );
                    }
                    ImGui::PopID();
                    ImGui::Unindent();
                    ImGui::NextColumn();
                    const auto part = double( ctt[cti[i]] ) * rztime;
                    char buf[128];
                    PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
                    ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                    ImGui::NextColumn();
                }
                ImGui::TreePop();
            }
        }
        ImGui::EndColumns();
    }
    else
    {
        auto ctt = std::make_unique<uint64_t[]>( children.size() );
        auto cti = std::make_unique<uint32_t[]>( children.size() );
        uint64_t ctime = 0;
        for( size_t i=0; i<children.size(); i++ )
        {
            const auto& child = a(children[i]);
            const auto cend = m_worker.GetZoneEnd( child );
            const auto ct = cend - child.GpuStart();
            ctime += ct;
            ctt[i] = ct;
            cti[i] = uint32_t( i );
        }

        pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

        ImGui::Columns( 2 );
        TextColoredUnformatted( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
        ImGui::NextColumn();
        char buf[128];
        PrintStringPercent( buf, TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::ProgressBar( double( ztime - ctime ) / ztime, ImVec2( -1, ty ), buf );
        ImGui::NextColumn();
        for( size_t i=0; i<children.size(); i++ )
        {
            auto& cev = a(children[cti[i]]);
            bool b = false;
            ImGui::PushID( (int)i );
            if( ImGui::Selectable( m_worker.GetZoneName( cev ), &b, ImGuiSelectableFlags_SpanAllColumns ) )
            {
                ShowZoneInfo( cev, m_gpuInfoWindowThread );
            }
            if( ImGui::IsItemHovered() )
            {
                m_gpuHighlight = &cev;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( cev );
                }
                ZoneTooltip( cev );
            }
            ImGui::PopID();
            ImGui::NextColumn();
            const auto part = double( ctt[cti[i]] ) / ztime;
            char buf[128];
            PrintStringPercent( buf, TimeToString( ctt[cti[i]] ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
        }
        ImGui::EndColumns();
    }
}

void View::DrawOptions()
{
    ImGui::Begin( "Options", &m_showOptions, ImGuiWindowFlags_AlwaysAutoResize );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    const auto scale = GetScale();
    bool val = m_vd.drawEmptyLabels;
    ImGui::Checkbox( ICON_FA_EXPAND " Draw empty labels", &val );
    m_vd.drawEmptyLabels = val;
    val = m_vd.drawFrameTargets;
    ImGui::Checkbox( ICON_FA_FLAG_CHECKERED " Draw frame targets", &val );
    m_vd.drawFrameTargets = val;
    ImGui::Indent();
    int tmp = m_vd.frameTarget;
    ImGui::SetNextItemWidth( 90 * scale );
    if( ImGui::InputInt( "Target FPS", &tmp ) )
    {
        if( tmp < 1 ) tmp = 1;
        m_vd.frameTarget = tmp;
    }
    ImGui::SameLine();
    TextDisabledUnformatted( TimeToString( 1000*1000*1000 / tmp ) );
    ImGui::Unindent();
    if( m_worker.HasContextSwitches() )
    {
        ImGui::Separator();
        val = m_vd.drawContextSwitches;
        ImGui::Checkbox( ICON_FA_HIKING " Draw context switches", &val );
        m_vd.drawContextSwitches = val;
        ImGui::Indent();
        val = m_vd.darkenContextSwitches;
        SmallCheckbox( ICON_FA_MOON " Darken inactive threads", &val );
        m_vd.darkenContextSwitches = val;
        ImGui::Unindent();
        val = m_vd.drawCpuData;
        ImGui::Checkbox( ICON_FA_SLIDERS_H " Draw CPU data", &val );
        m_vd.drawCpuData = val;
        ImGui::Indent();
        val = m_vd.drawCpuUsageGraph;
        SmallCheckbox( ICON_FA_SIGNATURE " Draw CPU usage graph", &val );
        m_vd.drawCpuUsageGraph = val;
        ImGui::Unindent();
    }

    if( m_worker.GetCallstackSampleCount() != 0 )
    {
        val = m_vd.drawSamples;
        ImGui::Checkbox( ICON_FA_EYE_DROPPER " Draw stack samples", &val );
        m_vd.drawSamples = val;
    }

    const auto& gpuData = m_worker.GetGpuData();
    if( !gpuData.empty() )
    {
        ImGui::Separator();
        val = m_vd.drawGpuZones;
        ImGui::Checkbox( ICON_FA_EYE " Draw GPU zones", &val );
        m_vd.drawGpuZones = val;
        const auto expand = ImGui::TreeNode( "GPU zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", gpuData.size() );
        if( expand )
        {
            for( size_t i=0; i<gpuData.size(); i++ )
            {
                const auto& timeline = gpuData[i]->threadData.begin()->second.timeline;
                char buf[1024];
                sprintf( buf, "%s context %zu", GpuContextNames[(int)gpuData[i]->type], i );
                SmallCheckbox( buf, &Vis( gpuData[i] ).visible );
                ImGui::SameLine();
                if( gpuData[i]->threadData.size() == 1 )
                {
                    ImGui::TextDisabled( "%s top level zones", RealToString( timeline.size() ) );
                }
                else
                {
                    ImGui::TextDisabled( "%s threads", RealToString( gpuData[i]->threadData.size() ) );
                }
                if( gpuData[i]->name.Active() )
                {
                    ImGui::PushFont( m_smallFont );
                    TextFocused( "Name:", m_worker.GetString( gpuData[i]->name ) );
                    ImGui::PopFont();
                }
                if( !gpuData[i]->hasCalibration )
                {
                    ImGui::TreePush();
                    auto& drift = GpuDrift( gpuData[i] );
                    ImGui::SetNextItemWidth( 120 * scale );
                    ImGui::PushID( i );
                    ImGui::InputInt( "Drift (ns/s)", &drift );
                    ImGui::PopID();
                    if( timeline.size() > 1 )
                    {
                        ImGui::SameLine();
                        if( ImGui::Button( ICON_FA_ROBOT " Auto" ) )
                        {
                            size_t lastidx = 0;
                            if( timeline.is_magic() )
                            {
                                auto& tl = *((Vector<GpuEvent>*)&timeline);
                                for( size_t j=tl.size()-1; j > 0; j-- )
                                {
                                    if( tl[j].GpuEnd() >= 0 )
                                    {
                                        lastidx = j;
                                        break;
                                    }
                                }
                            }
                            else
                            {
                                for( size_t j=timeline.size()-1; j > 0; j-- )
                                {
                                    if( timeline[j]->GpuEnd() >= 0 )
                                    {
                                        lastidx = j;
                                        break;
                                    }
                                }
                            }

                            enum { NumSlopes = 10000 };
                            std::random_device rd;
                            std::default_random_engine gen( rd() );
                            std::uniform_int_distribution<size_t> dist( 0, lastidx - 1 );
                            float slopes[NumSlopes];
                            size_t idx = 0;
                            if( timeline.is_magic() )
                            {
                                auto& tl = *((Vector<GpuEvent>*)&timeline);
                                do
                                {
                                    const auto p0 = dist( gen );
                                    const auto p1 = dist( gen );
                                    if( p0 != p1 )
                                    {
                                        slopes[idx++] = float( 1.0 - double( tl[p1].GpuStart() - tl[p0].GpuStart() ) / double( tl[p1].CpuStart() - tl[p0].CpuStart() ) );
                                    }
                                }
                                while( idx < NumSlopes );
                            }
                            else
                            {
                                do
                                {
                                    const auto p0 = dist( gen );
                                    const auto p1 = dist( gen );
                                    if( p0 != p1 )
                                    {
                                        slopes[idx++] = float( 1.0 - double( timeline[p1]->GpuStart() - timeline[p0]->GpuStart() ) / double( timeline[p1]->CpuStart() - timeline[p0]->CpuStart() ) );
                                    }
                                }
                                while( idx < NumSlopes );
                            }
                            std::sort( slopes, slopes+NumSlopes );
                            drift = int( 1000000000 * -slopes[NumSlopes/2] );
                        }
                    }
                    ImGui::TreePop();
                }
            }
            ImGui::TreePop();
        }
    }

    ImGui::Separator();
    val = m_vd.drawZones;
    ImGui::Checkbox( ICON_FA_MICROCHIP " Draw CPU zones", &val );
    ImGui::Indent();
    m_vd.drawZones = val;

#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreGhostZonesReady() && m_worker.GetGhostZonesCount() != 0 )
    {
        val = m_vd.ghostZones;
        SmallCheckbox( ICON_FA_GHOST " Draw ghost zones", &val );
        m_vd.ghostZones = val;
    }
#endif

    int ival = m_vd.dynamicColors;
    ImGui::TextUnformatted( ICON_FA_PALETTE " Zone colors" );
    ImGui::SameLine();
    bool forceColors = m_vd.forceColors;
    if( SmallCheckbox( "Ignore custom", &forceColors ) ) m_vd.forceColors = forceColors;
    ImGui::Indent();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::RadioButton( "Static", &ival, 0 );
    ImGui::RadioButton( "Thread dynamic", &ival, 1 );
    ImGui::RadioButton( "Source location dynamic", &ival, 2 );
    ImGui::PopStyleVar();
    ImGui::Unindent();
    m_vd.dynamicColors = ival;
    ival = (int)m_namespace;
    ImGui::TextUnformatted( ICON_FA_BOX_OPEN " Namespaces" );
    ImGui::Indent();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::RadioButton( "Full", &ival, 0 );
    ImGui::RadioButton( "Shortened", &ival, 1 );
    ImGui::RadioButton( "None", &ival, 2 );
    ImGui::PopStyleVar();
    ImGui::Unindent();
    m_namespace = (Namespace)ival;
    ImGui::Unindent();

    if( !m_worker.GetLockMap().empty() )
    {
        size_t lockCnt = 0;
        size_t singleCnt = 0;
        size_t multiCntCont = 0;
        size_t multiCntUncont = 0;
        for( const auto& l : m_worker.GetLockMap() )
        {
            if( l.second->valid && !l.second->timeline.empty() )
            {
                lockCnt++;
                if( l.second->threadList.size() == 1 )
                {
                    singleCnt++;
                }
                else if( l.second->isContended )
                {
                    multiCntCont++;
                }
                else
                {
                    multiCntUncont++;
                }
            }
        }

        ImGui::Separator();
        val = m_vd.drawLocks;
        ImGui::Checkbox( ICON_FA_LOCK " Draw locks", &val );
        m_vd.drawLocks = val;
        ImGui::SameLine();
        val = m_vd.onlyContendedLocks;
        ImGui::Checkbox( "Only contended", &val );
        m_vd.onlyContendedLocks = val;
        const auto expand = ImGui::TreeNode( "Locks" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", lockCnt );
        TooltipIfHovered( "Locks with no recorded events are counted, but not listed." );
        if( expand )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Vis( l.second ).visible = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Vis( l.second ).visible = false;
                }
            }
            ImGui::SameLine();
            DrawHelpMarker( "Right click on lock name to open lock information window." );

            const bool multiExpand = ImGui::TreeNodeEx( "Contended locks present in multiple threads", ImGuiTreeNodeFlags_DefaultOpen );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", multiCntCont );
            if( multiExpand )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && l.second->isContended ) Vis( l.second ).visible = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && l.second->isContended ) Vis( l.second ).visible = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() != 1 && l.second->isContended )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        if( l.second->customName.Active() )
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( l.second->customName ) );
                        }
                        else
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        }
                        SmallCheckbox( buf, &Vis( l.second ).visible );
                        if( ImGui::IsItemHovered() )
                        {
                            m_lockHoverHighlight = l.first;

                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                m_lockInfoWindow = l.first;
                            }
                        }
                        if( m_optionsLockBuzzAnim.Match( l.second->srcloc ) )
                        {
                            const auto time = m_optionsLockBuzzAnim.Time();
                            const auto indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        }
                        else
                        {
                            ImGui::SameLine();
                        }
                        ImGui::TextDisabled( "(%s) %s", RealToString( l.second->timeline.size() ), LocationToString( fileName, sl.line ) );
                        if( ImGui::IsItemHovered() )
                        {
                            DrawSourceTooltip( fileName, sl.line, 1, 1 );
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                                {
                                    ViewSource( fileName, sl.line );
                                }
                                else
                                {
                                    m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                                }
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            const bool multiUncontExpand = ImGui::TreeNodeEx( "Uncontended locks present in multiple threads", 0 );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", multiCntUncont );
            if( multiUncontExpand )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && !l.second->isContended ) Vis( l.second ).visible = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 && !l.second->isContended ) Vis( l.second ).visible = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() != 1 && !l.second->isContended )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        if( l.second->customName.Active() )
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( l.second->customName ) );
                        }
                        else
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        }
                        SmallCheckbox( buf, &Vis( l.second ).visible );
                        if( ImGui::IsItemHovered() )
                        {
                            m_lockHoverHighlight = l.first;

                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                m_lockInfoWindow = l.first;
                            }
                        }
                        if( m_optionsLockBuzzAnim.Match( l.second->srcloc ) )
                        {
                            const auto time = m_optionsLockBuzzAnim.Time();
                            const auto indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        }
                        else
                        {
                            ImGui::SameLine();
                        }
                        ImGui::TextDisabled( "(%s) %s", RealToString( l.second->timeline.size() ), LocationToString( fileName, sl.line ) );
                        if( ImGui::IsItemHovered() )
                        {
                            DrawSourceTooltip( fileName, sl.line, 1, 1 );
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                                {
                                    ViewSource( fileName, sl.line );
                                }
                                else
                                {
                                    m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                                }
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            const auto singleExpand = ImGui::TreeNodeEx( "Locks present in a single thread", 0 );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", singleCnt );
            if( singleExpand )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() == 1 ) Vis( l.second ).visible = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() == 1 ) Vis( l.second ).visible = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() == 1 )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        if( l.second->customName.Active() )
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( l.second->customName ) );
                        }
                        else
                        {
                            sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        }
                        SmallCheckbox( buf, &Vis( l.second ).visible );
                        if( ImGui::IsItemHovered() )
                        {
                            m_lockHoverHighlight = l.first;

                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                m_lockInfoWindow = l.first;
                            }
                        }
                        if( m_optionsLockBuzzAnim.Match( l.second->srcloc ) )
                        {
                            const auto time = m_optionsLockBuzzAnim.Time();
                            const auto indentVal = sin( time * 60.f ) * 10.f * time;
                            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                        }
                        else
                        {
                            ImGui::SameLine();
                        }
                        ImGui::TextDisabled( "(%s) %s", RealToString( l.second->timeline.size() ), LocationToString( fileName, sl.line ) );
                        if( ImGui::IsItemHovered() )
                        {
                            DrawSourceTooltip( fileName, sl.line, 1, 1 );
                            if( ImGui::IsItemClicked( 1 ) )
                            {
                                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                                {
                                    ViewSource( fileName, sl.line );
                                }
                                else
                                {
                                    m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                                }
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            ImGui::TreePop();
        }
    }

    if( !m_worker.GetPlots().empty() )
    {
        ImGui::Separator();
        val = m_vd.drawPlots;
        ImGui::Checkbox( ICON_FA_SIGNATURE " Draw plots", &val );
        m_vd.drawPlots = val;
        const auto expand = ImGui::TreeNode( "Plots" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetPlots().size() );
        if( expand )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& p : m_worker.GetPlots() )
                {
                    Vis( p ).visible = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& p : m_worker.GetPlots() )
                {
                    Vis( p ).visible = false;
                }
            }

            for( const auto& p : m_worker.GetPlots() )
            {
                SmallCheckbox( GetPlotName( p ), &Vis( p ).visible );
                ImGui::SameLine();
                ImGui::TextDisabled( "%s data points", RealToString( p->data.size() ) );
            }
            ImGui::TreePop();
        }
    }

    ImGui::Separator();
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
                Vis( t ).visible = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                Vis( t ).visible = false;
            }
        }

        const auto wposx = ImGui::GetCursorScreenPos().x;
        m_threadDnd.clear();
        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            m_threadDnd.push_back( ImGui::GetCursorScreenPos().y );
            ImGui::PushID( idx );
            const auto threadName = m_worker.GetThreadName( t->id );
            const auto threadColor = GetThreadColor( t->id, 0 );
            SmallColorBox( threadColor );
            ImGui::SameLine();
            SmallCheckbox( threadName, &Vis( t ).visible );
            if( ImGui::BeginDragDropSource( ImGuiDragDropFlags_SourceNoHoldToOpenOthers ) )
            {
                ImGui::SetDragDropPayload( "ThreadOrder", &idx, sizeof(int) );
                ImGui::TextUnformatted( ICON_FA_RANDOM );
                ImGui::SameLine();
                SmallColorBox( threadColor );
                ImGui::SameLine();
                ImGui::TextUnformatted( threadName );
                ImGui::EndDragDropSource();
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->id ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( "Crashed" );
                    ImGui::EndTooltip();
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
            if( t->isFiber )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
            ImGui::SameLine();
            ImGui::TextDisabled( "%s top level zones", RealToString( t->timeline.size() ) );
            idx++;
        }
        if( m_threadDnd.size() > 1 )
        {
            const auto w = ImGui::GetContentRegionAvail().x;
            const auto dist = m_threadDnd[1] - m_threadDnd[0];
            const auto half = dist * 0.5f;
            m_threadDnd.push_back( m_threadDnd.back() + dist );

            int target = -1;
            int source;
            for( size_t i=0; i<m_threadDnd.size(); i++ )
            {
                if( ImGui::BeginDragDropTargetCustom( ImRect( wposx, m_threadDnd[i] - half, wposx + w, m_threadDnd[i] + half ), i+1 ) )
                {
                    auto draw = ImGui::GetWindowDrawList();
                    draw->AddLine( ImVec2( wposx, m_threadDnd[i] ), ImVec2( wposx + w, m_threadDnd[i] ), ImGui::GetColorU32(ImGuiCol_DragDropTarget), 2.f );
                    if( auto payload = ImGui::AcceptDragDropPayload( "ThreadOrder", ImGuiDragDropFlags_AcceptNoDrawDefaultRect ) )
                    {
                        target = (int)i;
                        source = *(int*)payload->Data;
                    }
                    ImGui::EndDragDropTarget();
                }
            }
            if( target >= 0 && target != source )
            {
                const auto srcval = m_threadOrder[source];
                if( target < source )
                {
                    assert( source < (int)m_threadOrder.size() );
                    m_threadOrder.erase( m_threadOrder.begin() + source );
                    m_threadOrder.insert( m_threadOrder.begin() + target, srcval );
                }
                else
                {
                    assert( target <= (int)m_threadOrder.size() );
                    m_threadOrder.insert( m_threadOrder.begin() + target, srcval );
                    m_threadOrder.erase( m_threadOrder.begin() + source );
                }
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    expand = ImGui::TreeNode( ICON_FA_IMAGES " Visible frame sets:" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_worker.GetFrames().size() );
    if( expand )
    {
        ImGui::SameLine();
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& fd : m_worker.GetFrames() )
            {
                Vis( fd ).visible = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& fd : m_worker.GetFrames() )
            {
                Vis( fd ).visible = false;
            }
        }

        int idx = 0;
        for( const auto& fd : m_worker.GetFrames() )
        {
            ImGui::PushID( idx++ );
            SmallCheckbox( fd->name == 0 ? "Frames" : m_worker.GetString( fd->name ), &Vis( fd ).visible );
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "%s %sframes", RealToString( fd->frames.size() ), fd->continuous ? "" : "discontinuous " );
        }
        ImGui::TreePop();
    }
    ImGui::End();
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

uint64_t View::GetSelectionTarget( const Worker::ZoneThreadData& ev, FindZone::GroupBy groupBy ) const
{
    switch( groupBy )
    {
    case FindZone::GroupBy::Thread:
        return ev.Thread();
    case FindZone::GroupBy::UserText:
    {
        const auto& zone = *ev.Zone();
        if( !m_worker.HasZoneExtra( zone ) ) return std::numeric_limits<uint64_t>::max();
        const auto& extra = m_worker.GetZoneExtra( zone );
        return extra.text.Active() ? extra.text.Idx() : std::numeric_limits<uint64_t>::max();
    }
    case FindZone::GroupBy::ZoneName:
    {
        const auto& zone = *ev.Zone();
        if( !m_worker.HasZoneExtra( zone ) ) return std::numeric_limits<uint64_t>::max();
        const auto& extra = m_worker.GetZoneExtra( zone );
        return extra.name.Active() ? extra.name.Idx() : std::numeric_limits<uint64_t>::max();
    }
    case FindZone::GroupBy::Callstack:
        return m_worker.GetZoneExtra( *ev.Zone() ).callstack.Val();
    case FindZone::GroupBy::Parent:
    {
        const auto parent = GetZoneParent( *ev.Zone(), m_worker.DecompressThread( ev.Thread() ) );
        return parent ? uint64_t( parent->SrcLoc() ) : 0;
    }
    case FindZone::GroupBy::NoGrouping:
        return 0;
    default:
        assert( false );
        return 0;
    }
}

static void DrawHistogramMinMaxLabel( ImDrawList* draw, int64_t tmin, int64_t tmax, ImVec2 wpos, float w, float ty )
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

void View::DrawFindZone()
{
    if( m_shortcut == ShortcutAction::OpenFind ) ImGui::SetNextWindowFocus();

    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 520 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Find zone", &m_findZone.show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable zone search." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

    bool findClicked = false;

    ImGui::PushItemWidth( -0.01f );
    if( m_shortcut == ShortcutAction::OpenFind )
    {
        ImGui::SetKeyboardFocusHere();
        m_shortcut = ShortcutAction::None;
    }
    else if( ImGui::IsWindowAppearing() )
    {
        ImGui::SetKeyboardFocusHere();
    }
    findClicked |= ImGui::InputTextWithHint( "###findzone", "Enter zone name to search for", m_findZone.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
    ImGui::PopItemWidth();

    findClicked |= ImGui::Button( ICON_FA_SEARCH " Find" );
    ImGui::SameLine();

    if( ImGui::Button( ICON_FA_BAN " Clear" ) )
    {
        m_findZone.Reset();
    }
    ImGui::SameLine();
    ImGui::Checkbox( "Ignore case", &m_findZone.ignoreCase );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( ImGui::Checkbox( "Limit range", &m_findZone.range.active ) )
    {
        if( m_findZone.range.active && m_findZone.range.min == 0 && m_findZone.range.max == 0 )
        {
            m_findZone.range.min = m_vd.zvStart;
            m_findZone.range.max = m_vd.zvEnd;
        }
    }
    if( m_findZone.range.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }

    if( m_findZone.rangeSlim != m_findZone.range )
    {
        m_findZone.ResetMatch();
        m_findZone.rangeSlim = m_findZone.range;
    }

    if( findClicked )
    {
        m_findZone.Reset();
        FindZones();
    }

    if( !m_findZone.match.empty() )
    {
        const auto rangeMin = m_findZone.range.min;
        const auto rangeMax = m_findZone.range.max;

        ImGui::Separator();
        ImGui::BeginChild( "##findzone" );
        bool expand = ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_findZone.match.size() );
        if( expand )
        {
            auto prev = m_findZone.selMatch;
            int idx = 0;
            for( auto& v : m_findZone.match )
            {
                auto& srcloc = m_worker.GetSourceLocation( v );
                auto& zones = m_worker.GetZonesForSourceLocation( v ).zones;
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( idx );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_findZone.selMatch, idx++ );
                ImGui::PopStyleVar();
                if( m_findZoneBuzzAnim.Match( idx ) )
                {
                    const auto time = m_findZoneBuzzAnim.Time();
                    const auto indentVal = sin( time * 60.f ) * 10.f * time;
                    ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
                }
                else
                {
                    ImGui::SameLine();
                }
                const auto fileName = m_worker.GetString( srcloc.file );
                ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s", RealToString( zones.size() ), LocationToString( fileName, srcloc.line ) );
                if( ImGui::IsItemHovered() )
                {
                    DrawSourceTooltip( fileName, srcloc.line );
                    if( ImGui::IsItemClicked( 1 ) )
                    {
                        if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                        {
                            ViewSource( fileName, srcloc.line );
                        }
                        else
                        {
                            m_findZoneBuzzAnim.Enable( idx, 0.5f );
                        }
                    }
                }
                ImGui::PopID();
            }
            ImGui::TreePop();

            if( m_findZone.selMatch != prev )
            {
                m_findZone.ResetMatch();
            }
        }
        if( m_findZone.scheduleResetMatch )
        {
            m_findZone.scheduleResetMatch = false;
            m_findZone.ResetMatch();
        }

        ImGui::Separator();

        auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
        auto& zones = zoneData.zones;
        zones.ensure_sorted();
        if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto ty = ImGui::GetTextLineHeight();

            int64_t tmin = m_findZone.tmin;
            int64_t tmax = m_findZone.tmax;
            int64_t total = m_findZone.total;
            const auto zsz = zones.size();
            if( m_findZone.sortedNum != zsz )
            {
                auto& vec = m_findZone.sorted;
                const auto vszorig = vec.size();
                vec.reserve( zsz );
                size_t i;
                if( m_findZone.runningTime )
                {
                    if( m_findZone.range.active )
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            if( end > rangeMax || zone.Start() < rangeMin ) continue;
                            const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                            if( !ctx ) break;
                            int64_t t;
                            uint64_t cnt;
                            if( !GetZoneRunningTime( ctx, zone, t, cnt ) ) break;
                            vec.push_back_no_space_check( t );
                            total += t;
                            if( t < tmin ) tmin = t;
                            else if( t > tmax ) tmax = t;
                        }
                    }
                    else
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                            if( !ctx ) break;
                            int64_t t;
                            uint64_t cnt;
                            if( !GetZoneRunningTime( ctx, zone, t, cnt ) ) break;
                            vec.push_back_no_space_check( t );
                            total += t;
                            if( t < tmin ) tmin = t;
                            else if( t > tmax ) tmax = t;
                        }
                    }
                }
                else if( m_findZone.selfTime )
                {
                    tmin = zoneData.selfMin;
                    tmax = zoneData.selfMax;
                    if( m_findZone.range.active )
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto start = zone.Start();
                            if( end > rangeMax || start < rangeMin ) continue;
                            const auto t = end - start - GetZoneChildTimeFast( zone );
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                    else
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto t = end - zone.Start() - GetZoneChildTimeFast( zone );
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                }
                else
                {
                    tmin = zoneData.min;
                    tmax = zoneData.max;
                    if( m_findZone.range.active )
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto start = zone.Start();
                            if( end > rangeMax || start < rangeMin ) continue;
                            const auto t = end - start;
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                    else
                    {
                        for( i=m_findZone.sortedNum; i<zsz; i++ )
                        {
                            auto& zone = *zones[i].Zone();
                            const auto end = zone.End();
                            const auto t = end - zone.Start();
                            vec.push_back_no_space_check( t );
                            total += t;
                        }
                    }
                }
                auto mid = vec.begin() + vszorig;
#ifdef NO_PARALLEL_SORT
                pdqsort_branchless( mid, vec.end() );
#else
                std::sort( std::execution::par_unseq, mid, vec.end() );
#endif
                std::inplace_merge( vec.begin(), mid, vec.end() );

                const auto vsz = vec.size();
                if( vsz != 0 )
                {
                    m_findZone.average = float( total ) / vsz;
                    m_findZone.median = vec[vsz/2];
                    m_findZone.total = total;
                    m_findZone.sortedNum = i;
                    m_findZone.tmin = tmin;
                    m_findZone.tmax = tmax;
                }
            }

            if( m_findZone.selGroup != m_findZone.Unselected )
            {
                if( m_findZone.selSortNum != m_findZone.sortedNum )
                {
                    const auto selGroup = m_findZone.selGroup;
                    const auto groupBy = m_findZone.groupBy;

                    auto& vec = m_findZone.selSort;
                    vec.reserve( zsz );
                    auto act = m_findZone.selSortActive;
                    int64_t total = m_findZone.selTotal;
                    if( m_findZone.runningTime )
                    {
                        if( m_findZone.range.active )
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( ev.Zone()->End() > rangeMax || ev.Zone()->Start() < rangeMin ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                                    int64_t t;
                                    uint64_t cnt;
                                    GetZoneRunningTime( ctx, *ev.Zone(), t, cnt );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                        else
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( zones[i].Thread() ) );
                                    int64_t t;
                                    uint64_t cnt;
                                    GetZoneRunningTime( ctx, *ev.Zone(), t, cnt );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                    }
                    else if( m_findZone.selfTime )
                    {
                        if( m_findZone.range.active )
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( ev.Zone()->End() > rangeMax || ev.Zone()->Start() < rangeMin ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start() - GetZoneChildTimeFast( *ev.Zone() );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                        else
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start() - GetZoneChildTimeFast( *ev.Zone() );
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                    }
                    else
                    {
                        if( m_findZone.range.active )
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( ev.Zone()->End() > rangeMax || ev.Zone()->Start() < rangeMin ) continue;
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start();
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                        else
                        {
                            for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                            {
                                auto& ev = zones[i];
                                if( selGroup == GetSelectionTarget( ev, groupBy ) )
                                {
                                    const auto t = ev.Zone()->End() - ev.Zone()->Start();
                                    vec.push_back_no_space_check( t );
                                    act++;
                                    total += t;
                                }
                            }
                        }
                    }
                    if( !vec.empty() )
                    {
                        auto mid = vec.begin() + m_findZone.selSortActive;
                        pdqsort_branchless( mid, vec.end() );
                        std::inplace_merge( vec.begin(), mid, vec.end() );

                        m_findZone.selAverage = float( total ) / act;
                        m_findZone.selMedian = vec[act/2];
                        m_findZone.selTotal = total;
                        m_findZone.selSortNum = m_findZone.sortedNum;
                        m_findZone.selSortActive = act;
                    }
                }
            }

            if( tmin != std::numeric_limits<int64_t>::max() && !m_findZone.sorted.empty() )
            {
                TextDisabledUnformatted( "Minimum values in bin:" );
                ImGui::SameLine();
                ImGui::SetNextItemWidth( ImGui::CalcTextSize( "123456890123456" ).x );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 1, 1 ) );
                ImGui::InputInt( "##minBinVal", &m_findZone.minBinVal );
                if( m_findZone.minBinVal < 1 ) m_findZone.minBinVal = 1;
                ImGui::SameLine();
                if( ImGui::Button( "Reset" ) ) m_findZone.minBinVal = 1;
                ImGui::PopStyleVar();

                SmallCheckbox( "Log values", &m_findZone.logVal );
                ImGui::SameLine();
                if( SmallCheckbox( "Log time", &m_findZone.logTime ) )
                {
                    m_findZone.binCache.numBins = -1;
                }
                ImGui::SameLine();
                SmallCheckbox( "Cumulate time", &m_findZone.cumulateTime );
                ImGui::SameLine();
                DrawHelpMarker( "Show total time taken by calls in each bin instead of call counts." );
                ImGui::SameLine();
                if( SmallCheckbox( "Self time", &m_findZone.selfTime ) )
                {
                    m_findZone.runningTime = false;
                    m_findZone.scheduleResetMatch = true;
                }
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, 100.f * zoneData.selfTotal / zoneData.total );
                TextDisabledUnformatted( buf );
                if( m_worker.HasContextSwitches() )
                {
                    ImGui::SameLine();
                    if( SmallCheckbox( "Running time", &m_findZone.runningTime ) )
                    {
                        m_findZone.selfTime = false;
                        m_findZone.scheduleResetMatch = true;
                    }
                }

                const auto cumulateTime = m_findZone.cumulateTime;

                if( tmax - tmin > 0 )
                {
                    const auto w = ImGui::GetContentRegionAvail().x;

                    const auto numBins = int64_t( w - 4 );
                    if( numBins > 1 )
                    {
                        const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                        const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                        const auto& sorted = m_findZone.sorted;

                        auto sortedBegin = sorted.begin();
                        auto sortedEnd = sorted.end();
                        while( sortedBegin != sortedEnd && *sortedBegin == 0 ) ++sortedBegin;

                        if( m_findZone.minBinVal > 1 || m_findZone.range.active )
                        {
                            if( m_findZone.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                int64_t i;
                                for( i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( sortedBegin, nit );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedBegin = nit;
                                }
                                for( int64_t j=numBins-1; j>i; j-- )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( j-1 ) * zmax ) );
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( nit, sortedEnd );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedEnd = nit;
                                }
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                int64_t i;
                                for( i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( sortedBegin, nit );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedBegin = nit;
                                }
                                for( int64_t j=numBins-1; j>i; j-- )
                                {
                                    const auto nextBinVal = tmin + ( j-1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( sortedBegin, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( nit, sortedEnd );
                                    if( distance >= m_findZone.minBinVal ) break;
                                    sortedEnd = nit;
                                }
                            }

                            if( sortedBegin != sorted.end() )
                            {
                                tmin = *sortedBegin;
                                tmax = *(sortedEnd-1);
                                total = 0;
                                for( auto ptr = sortedBegin; ptr != sortedEnd; ptr++ ) total += *ptr;
                            }
                        }

                        if( numBins > m_findZone.numBins )
                        {
                            m_findZone.numBins = numBins;
                            m_findZone.bins = std::make_unique<int64_t[]>( numBins );
                            m_findZone.binTime = std::make_unique<int64_t[]>( numBins );
                            m_findZone.selBin = std::make_unique<int64_t[]>( numBins );
                            m_findZone.binCache.numBins = -1;
                        }

                        const auto& bins = m_findZone.bins;
                        const auto& binTime = m_findZone.binTime;
                        const auto& selBin = m_findZone.selBin;

                        const auto distBegin = std::distance( sorted.begin(), sortedBegin );
                        const auto distEnd = std::distance( sorted.begin(), sortedEnd );
                        if( m_findZone.binCache.numBins != numBins ||
                            m_findZone.binCache.distBegin != distBegin ||
                            m_findZone.binCache.distEnd != distEnd )
                        {
                            m_findZone.binCache.numBins = numBins;
                            m_findZone.binCache.distBegin = distBegin;
                            m_findZone.binCache.distEnd = distEnd;

                            memset( bins.get(), 0, sizeof( int64_t ) * numBins );
                            memset( binTime.get(), 0, sizeof( int64_t ) * numBins );
                            memset( selBin.get(), 0, sizeof( int64_t ) * numBins );

                            int64_t selectionTime = 0;

                            if( m_findZone.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                {
                                    auto zit = sortedBegin;
                                    for( int64_t i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                        auto nit = std::lower_bound( zit, sortedEnd, nextBinVal );
                                        const auto distance = std::distance( zit, nit );
                                        const auto timeSum = std::accumulate( zit, nit, int64_t( 0 ) );
                                        bins[i] = distance;
                                        binTime[i] = timeSum;
                                        if( m_findZone.highlight.active )
                                        {
                                            auto end = nit == zit ? zit : nit-1;
                                            if( *zit >= s && *end <= e ) selectionTime += timeSum;
                                        }
                                        zit = nit;
                                    }
                                    const auto timeSum = std::accumulate( zit, sortedEnd, int64_t( 0 ) );
                                    bins[numBins-1] += std::distance( zit, sortedEnd );
                                    binTime[numBins-1] += timeSum;
                                    if( m_findZone.highlight.active && *zit >= s && *(sortedEnd-1) <= e ) selectionTime += timeSum;
                                }

                                if( m_findZone.selGroup != m_findZone.Unselected )
                                {
                                    auto zit = m_findZone.selSort.begin();
                                    while( zit != m_findZone.selSort.end() && *zit == 0 ) ++zit;
                                    for( int64_t i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                        auto nit = std::lower_bound( zit, m_findZone.selSort.end(), nextBinVal );
                                        if( cumulateTime )
                                        {
                                            selBin[i] = std::accumulate( zit, nit, int64_t( 0 ) );
                                        }
                                        else
                                        {
                                            selBin[i] = std::distance( zit, nit );
                                        }
                                        zit = nit;
                                    }
                                }
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                auto zit = sortedBegin;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( zit, sortedEnd, nextBinVal );
                                    const auto distance = std::distance( zit, nit );
                                    const auto timeSum = std::accumulate( zit, nit, int64_t( 0 ) );
                                    bins[i] = distance;
                                    binTime[i] = timeSum;
                                    if( m_findZone.highlight.active )
                                    {
                                        auto end = nit == zit ? zit : nit-1;
                                        if( *zit >= s && *end <= e ) selectionTime += timeSum;
                                    }
                                    zit = nit;
                                }
                                const auto timeSum = std::accumulate( zit, sortedEnd, int64_t( 0 ) );
                                bins[numBins-1] += std::distance( zit, sortedEnd );
                                binTime[numBins-1] += timeSum;
                                if( m_findZone.highlight.active && *zit >= s && *(sortedEnd-1) <= e ) selectionTime += timeSum;

                                if( m_findZone.selGroup != m_findZone.Unselected )
                                {
                                    auto zit = m_findZone.selSort.begin();
                                    while( zit != m_findZone.selSort.end() && *zit == 0 ) ++zit;
                                    for( int64_t i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                        auto nit = std::lower_bound( zit, m_findZone.selSort.end(), nextBinVal );
                                        if( cumulateTime )
                                        {
                                            selBin[i] = std::accumulate( zit, nit, int64_t( 0 ) );
                                        }
                                        else
                                        {
                                            selBin[i] = std::distance( zit, nit );
                                        }
                                        zit = nit;
                                    }
                                }
                            }

                            m_findZone.selTime = selectionTime;
                        }

                        int maxBin = 0;
                        int64_t maxVal;
                        if( cumulateTime )
                        {
                            maxVal = binTime[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                if( maxVal < binTime[i] )
                                {
                                    maxVal = binTime[i];
                                    maxBin = i;
                                }
                            }
                        }
                        else
                        {
                            maxVal = bins[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                if( maxVal < bins[i] )
                                {
                                    maxVal = bins[i];
                                    maxBin = i;
                                }
                            }
                        }

                        TextFocused( "Total time:", TimeToString( total ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( maxVal ) );
                        TextFocused( "Mean:", TimeToString( m_findZone.average ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Median:", TimeToString( m_findZone.median ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        {
                            int64_t t0, t1;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );
                                t0 = int64_t( pow( 10, ltmin + double( maxBin )   / numBins * ( ltmax - ltmin ) ) );
                                t1 = int64_t( pow( 10, ltmin + double( maxBin+1 ) / numBins * ( ltmax - ltmin ) ) );
                            }
                            else
                            {
                                t0 = int64_t( tmin + double( maxBin )   / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + double( maxBin+1 ) / numBins * ( tmax - tmin ) );
                            }
                            TextFocused( "Mode:", TimeToString( ( t0 + t1 ) / 2 ) );
                        }
                        if( !m_findZone.range.active && m_findZone.sorted.size() > 1 )
                        {
                            const auto sz = m_findZone.sorted.size();
                            const auto avg = m_findZone.average;
                            const auto ss = zoneData.sumSq - 2. * zoneData.total * avg + avg * avg * sz;
                            const auto sd = sqrt( ss / ( sz - 1 ) );

                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "\xcf\x83:", TimeToString( sd ) );
                            TooltipIfHovered( "Standard deviation" );
                        }

                        TextDisabledUnformatted( "Selection range:" );
                        ImGui::SameLine();
                        if( m_findZone.highlight.active )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
                            ImGui::Text( "%s - %s (%s)", TimeToString( s ), TimeToString( e ), TimeToString( e - s ) );
                        }
                        else
                        {
                            ImGui::TextUnformatted( "none" );
                        }
                        ImGui::SameLine();
                        DrawHelpMarker( "Left draw on histogram to select range. Right click to clear selection." );
                        if( m_findZone.highlight.active )
                        {
                            TextFocused( "Selection time:", TimeToString( m_findZone.selTime ) );
                        }
                        else
                        {
                            TextFocused( "Selection time:", "none" );
                        }
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            TextFocused( "Zone group time:", TimeToString( m_findZone.groups[m_findZone.selGroup].time ) );
                            TextFocused( "Group mean:", TimeToString( m_findZone.selAverage ) );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Group median:", TimeToString( m_findZone.selMedian ) );
                        }
                        else
                        {
                            TextFocused( "Zone group time:", "none" );
                            TextFocused( "Group mean:", "none" );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Group median:", "none" );
                        }

                        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                        ImGui::Checkbox( "###draw1", &m_findZone.drawAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c1", ImVec4( 0xFF/255.f, 0x44/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Mean time" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0xAA/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Median time" );
                        ImGui::Checkbox( "###draw2", &m_findZone.drawSelAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c3", ImVec4( 0xFF/255.f, 0xAA/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::TextUnformatted( "Group mean" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Group mean" );
                        }
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c4", ImVec4( 0x44/255.f, 0xDD/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::TextUnformatted( "Group median" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Group median" );
                        }
                        ImGui::PopStyleVar();

                        const auto Height = 200 * scale;
                        const auto wpos = ImGui::GetCursorScreenPos();
                        const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

                        ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 2.5 ) ) );
                        const bool hover = ImGui::IsItemHovered();

                        auto draw = ImGui::GetWindowDrawList();
                        draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                        draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                        if( m_findZone.logVal )
                        {
                            const auto hAdj = double( Height - 4 ) / log10( maxVal + 1 );
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val = cumulateTime ? binTime[i] : bins[i];
                                if( val > 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( selBin[i] + 1 ) * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }
                        else
                        {
                            const auto hAdj = double( Height - 4 ) / maxVal;
                            for( int i=0; i<numBins; i++ )
                            {
                                const auto val = cumulateTime ? binTime[i] : bins[i];
                                if( val > 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - selBin[i] * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }

                        const auto xoff = 2;
                        const auto yoff = Height + 1;

                        DrawHistogramMinMaxLabel( draw, tmin, tmax, wpos + ImVec2( 0, yoff ), w, ty );

                        const auto ty05 = round( ty * 0.5f );
                        const auto ty025 = round( ty * 0.25f );
                        if( m_findZone.logTime )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );
                            const auto start = int( floor( ltmin ) );
                            const auto end = int( ceil( ltmax ) );

                            const auto range = ltmax - ltmin;
                            const auto step = w / range;
                            auto offset = start - ltmin;
                            int tw = 0;
                            int tx = 0;

                            auto tt = int64_t( pow( 10, start ) );

                            static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                            for( int i=start; i<=end; i++ )
                            {
                                const auto x = ( i - start + offset ) * step;

                                if( x >= 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( x, yoff ), dpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF );
                                    if( tw == 0 || x > tx + tw + ty * 1.1 )
                                    {
                                        tx = x;
                                        auto txt = TimeToString( tt );
                                        draw->AddText( wpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }
                                }

                                for( int j=0; j<8; j++ )
                                {
                                    const auto xoff = x + logticks[j] * step;
                                    if( xoff >= 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( xoff, yoff ), dpos + ImVec2( xoff, yoff + ty025 ), 0x66FFFFFF );
                                    }
                                }

                                tt *= 10;
                            }
                        }
                        else
                        {
                            const auto pxns = numBins / double( tmax - tmin );
                            const auto nspx = 1.0 / pxns;
                            const auto scale = std::max<float>( 0.0f, round( log10( nspx ) + 2 ) );
                            const auto step = pow( 10, scale );

                            const auto dx = step * pxns;
                            double x = 0;
                            int tw = 0;
                            int tx = 0;

                            const auto sstep = step / 10.0;
                            const auto sdx = dx / 10.0;

                            static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                            int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                            const auto diff = tmin / sstep - int64_t( tmin / sstep );
                            const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                            int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                            while( x < numBins )
                            {
                                DrawLine( draw, dpos + ImVec2( xo + x, yoff ), dpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                {
                                    tx = x;
                                    auto txt = TimeToString( tt );
                                    draw->AddText( wpos + ImVec2( xo + x, yoff + ty05 ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }

                                iter = ( iter + 1 ) % 10;
                                x += sdx;
                                tt += sstep;
                            }
                        }

                        float ta, tm, tga, tgm;
                        if( m_findZone.logTime )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            ta = ( log10( m_findZone.average ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            tm = ( log10( m_findZone.median ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            tga = ( log10( m_findZone.selAverage ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            tgm = ( log10( m_findZone.selMedian ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                        }
                        else
                        {
                            ta = ( m_findZone.average - tmin ) / float( tmax - tmin ) * numBins;
                            tm = ( m_findZone.median - tmin ) / float( tmax - tmin ) * numBins;
                            tga = ( m_findZone.selAverage - tmin ) / float( tmax - tmin ) * numBins;
                            tgm = ( m_findZone.selMedian - tmin ) / float( tmax - tmin ) * numBins;
                        }
                        ta = round( ta );
                        tm = round( tm );
                        tga = round( tga );
                        tgm = round( tgm );

                        if( m_findZone.drawAvgMed )
                        {
                            if( ta == tm )
                            {
                                DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFFFF88FF );
                            }
                            else
                            {
                                DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFF4444FF );
                                DrawLine( draw, ImVec2( dpos.x + tm, dpos.y ), ImVec2( dpos.x + tm, dpos.y+Height-2 ), 0xFFFFAA44 );
                            }
                        }
                        if( m_findZone.drawSelAvgMed && m_findZone.selGroup != m_findZone.Unselected )
                        {
                            DrawLine( draw, ImVec2( dpos.x + tga, dpos.y ), ImVec2( dpos.x + tga, dpos.y+Height-2 ), 0xFF44AAFF );
                            DrawLine( draw, ImVec2( dpos.x + tgm, dpos.y ), ImVec2( dpos.x + tgm, dpos.y+Height-2 ), 0xFF44DD44 );
                        }

                        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            auto& io = ImGui::GetIO();
                            DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, dpos.y ), ImVec2( io.MousePos.x + 0.5f, dpos.y+Height-2 ), 0x33FFFFFF );

                            const auto bin = int64_t( io.MousePos.x - wpos.x - 2 );
                            int64_t t0, t1;
                            if( m_findZone.logTime )
                            {
                                t0 = int64_t( pow( 10, ltmin + double( bin ) / numBins * ( ltmax - ltmin ) ) );

                                // Hackfix for inability to select data in last bin.
                                // A proper solution would be nice.
                                if( bin+1 == numBins )
                                {
                                    t1 = tmax;
                                }
                                else
                                {
                                    t1 = int64_t( pow( 10, ltmin + double( bin+1 ) / numBins * ( ltmax - ltmin ) ) );
                                }
                            }
                            else
                            {
                                t0 = int64_t( tmin + double( bin )   / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + double( bin+1 ) / numBins * ( tmax - tmin ) );
                            }

                            int64_t tBefore = 0;
                            for( int i=0; i<bin; i++ )
                            {
                                tBefore += binTime[i];
                            }

                            int64_t tAfter = 0;
                            for( int i=bin+1; i<numBins; i++ )
                            {
                                tAfter += binTime[i];
                            }

                            ImGui::BeginTooltip();
                            TextDisabledUnformatted( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            TextFocused( "Count:", RealToString( bins[bin] ) );
                            TextFocused( "Time spent in bin:", TimeToString( binTime[bin] ) );
                            TextFocused( "Time spent in the left bins:", TimeToString( tBefore ) );
                            TextFocused( "Time spent in the right bins:", TimeToString( tAfter ) );
                            ImGui::EndTooltip();

                            if( IsMouseClicked( 1 ) )
                            {
                                m_findZone.highlight.active = false;
                                m_findZone.ResetGroups();
                            }
                            else if( IsMouseClicked( 0 ) )
                            {
                                m_findZone.highlight.active = true;
                                m_findZone.highlight.start = t0;
                                m_findZone.highlight.end = t1;
                                m_findZone.hlOrig_t0 = t0;
                                m_findZone.hlOrig_t1 = t1;
                            }
                            else if( IsMouseDragging( 0 ) )
                            {
                                if( t0 < m_findZone.hlOrig_t0 )
                                {
                                    m_findZone.highlight.start = t0;
                                    m_findZone.highlight.end = m_findZone.hlOrig_t1;
                                }
                                else
                                {
                                    m_findZone.highlight.start = m_findZone.hlOrig_t0;
                                    m_findZone.highlight.end = t1;
                                }
                                m_findZone.ResetGroups();
                            }
                        }

                        if( m_findZone.highlight.active && m_findZone.highlight.start != m_findZone.highlight.end )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                            float t0, t1;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );

                                t0 = ( log10( s ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                t1 = ( log10( e ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                            }
                            else
                            {
                                t0 = ( s - tmin ) / float( tmax - tmin ) * numBins;
                                t1 = ( e - tmin ) / float( tmax - tmin ) * numBins;
                            }

                            draw->PushClipRect( wpos, wpos + ImVec2( w, Height ), true );
                            draw->AddRectFilled( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x22DD8888 );
                            draw->AddRect( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x44DD8888 );
                            draw->PopClipRect();
                        }

                        if( ( m_zoneHover && m_findZone.match[m_findZone.selMatch] == m_zoneHover->SrcLoc() ) ||
                            ( m_zoneHover2 && m_findZone.match[m_findZone.selMatch] == m_zoneHover2->SrcLoc() ) )
                        {
                            const auto zoneTime = m_zoneHover ? ( m_worker.GetZoneEnd( *m_zoneHover ) - m_zoneHover->Start() ) : ( m_worker.GetZoneEnd( *m_zoneHover2 ) - m_zoneHover2->Start() );
                            float zonePos;
                            if( m_findZone.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );
                                zonePos = round( ( log10( zoneTime ) - ltmin ) / float( ltmax - ltmin ) * numBins );
                            }
                            else
                            {
                                zonePos = round( ( zoneTime - tmin ) / float( tmax - tmin ) * numBins );
                            }
                            const auto c = uint32_t( ( sin( s_time * 10 ) * 0.25 + 0.75 ) * 255 );
                            const auto color = 0xFF000000 | ( c << 16 ) | ( c << 8 ) | c;
                            DrawLine( draw, ImVec2( dpos.x + zonePos, dpos.y ), ImVec2( dpos.x + zonePos, dpos.y+Height-2 ), color );
                        }
                    }
                }
            }

            ImGui::TreePop();
        }

        ImGui::Separator();
        SmallCheckbox( "Show zone time in frames", &m_findZone.showZoneInFrames );
        ImGui::Separator();

        ImGui::TextUnformatted( "Found zones:" );
        ImGui::SameLine();
        DrawHelpMarker( "Left click to highlight entry." );
        if( m_findZone.selGroup != m_findZone.Unselected )
        {
            ImGui::SameLine();
            if( ImGui::SmallButton( ICON_FA_BACKSPACE " Clear" ) )
            {
                m_findZone.selGroup = m_findZone.Unselected;
                m_findZone.ResetSelection();
            }
        }

        bool groupChanged = false;
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        ImGui::TextUnformatted( "Group by:" );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Thread", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Thread );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "User text", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::UserText );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Zone name", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::ZoneName );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Call stacks", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Callstack );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Parent", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Parent );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "No grouping", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::NoGrouping );
        if( groupChanged )
        {
            m_findZone.selGroup = m_findZone.Unselected;
            m_findZone.ResetGroups();
        }

        ImGui::TextUnformatted( "Sort by:" );
        ImGui::SameLine();
        ImGui::RadioButton( "Order", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Order );
        ImGui::SameLine();
        ImGui::RadioButton( "Count", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Count );
        ImGui::SameLine();
        ImGui::RadioButton( "Time", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Time );
        ImGui::SameLine();
        ImGui::RadioButton( "MTPC", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Mtpc );
        ImGui::PopStyleVar();
        ImGui::SameLine();
        DrawHelpMarker( "Mean time per call" );

        const auto hmin = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto hmax = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto groupBy = m_findZone.groupBy;
        const auto highlightActive = m_findZone.highlight.active;
        const auto limitRange = m_findZone.range.active;
        FindZone::Group* group = nullptr;
        const uint64_t invalidGid = std::numeric_limits<uint64_t>::max() - 1;
        uint64_t lastGid = invalidGid;
        auto zptr = zones.data() + m_findZone.processed;
        const auto zend = zones.data() + zones.size();
        while( zptr < zend )
        {
            auto& ev = *zptr;
            const auto end = ev.Zone()->End();
            const auto start = ev.Zone()->Start();
            if( limitRange && ( start < rangeMin || end > rangeMax ) )
            {
                zptr++;
                continue;
            }
            auto timespan = end - start;
            assert( timespan != 0 );
            if( m_findZone.selfTime )
            {
                timespan -= GetZoneChildTimeFast( *ev.Zone() );
            }
            else if( m_findZone.runningTime )
            {
                const auto ctx = m_worker.GetContextSwitchData( m_worker.DecompressThread( ev.Thread() ) );
                if( !ctx ) break;
                int64_t t;
                uint64_t cnt;
                if( !GetZoneRunningTime( ctx, *ev.Zone(), t, cnt ) ) break;
                timespan = t;
            }

            if( highlightActive )
            {
                if( timespan < hmin || timespan > hmax )
                {
                    zptr++;
                    continue;
                }
            }

            zptr++;
            uint64_t gid = 0;
            switch( groupBy )
            {
            case FindZone::GroupBy::Thread:
                gid = ev.Thread();
                break;
            case FindZone::GroupBy::UserText:
            {
                const auto& zone = *ev.Zone();
                if( !m_worker.HasZoneExtra( zone ) )
                {
                    gid = std::numeric_limits<uint64_t>::max();
                }
                else
                {
                    const auto& extra = m_worker.GetZoneExtra( zone );
                    gid = extra.text.Active() ? extra.text.Idx() : std::numeric_limits<uint64_t>::max();
                }
                break;
            }
            case FindZone::GroupBy::ZoneName:
            {
                const auto& zone = *ev.Zone();
                if( !m_worker.HasZoneExtra( zone ) )
                {
                    gid = std::numeric_limits<uint64_t>::max();
                }
                else
                {
                    const auto& extra = m_worker.GetZoneExtra( zone );
                    gid = extra.name.Active() ? extra.name.Idx() : std::numeric_limits<uint64_t>::max();
                }
                break;
            }
            case FindZone::GroupBy::Callstack:
                gid = m_worker.GetZoneExtra( *ev.Zone() ).callstack.Val();
                break;
            case FindZone::GroupBy::Parent:
            {
                const auto parent = GetZoneParent( *ev.Zone(), m_worker.DecompressThread( ev.Thread() ) );
                if( parent ) gid = uint64_t( uint16_t( parent->SrcLoc() ) );
                break;
            }
            case FindZone::GroupBy::NoGrouping:
                break;
            default:
                assert( false );
                break;
            }
            if( lastGid != gid )
            {
                lastGid = gid;
                auto it = m_findZone.groups.find( gid );
                if( it == m_findZone.groups.end() )
                {
                    it = m_findZone.groups.emplace( gid, FindZone::Group { m_findZone.groupId++ } ).first;
                    it->second.zones.reserve( 1024 );
                    if( m_findZone.samples.enabled )
                        it->second.zonesTids.reserve( 1024 );
                }
                group = &it->second;
            }
            group->time += timespan;
            group->zones.push_back_non_empty( ev.Zone() );
            if( m_findZone.samples.enabled )
                group->zonesTids.push_back_non_empty( ev.Thread() );
        }
        m_findZone.processed = zptr - zones.data();

        const bool groupsUpdated = lastGid != invalidGid;
        if( m_findZone.samples.enabled && groupsUpdated )
        {
            m_findZone.samples.scheduleUpdate = true;
        }


        Vector<decltype( m_findZone.groups )::iterator> groups;
        groups.reserve_and_use( m_findZone.groups.size() );
        int idx = 0;
        for( auto it = m_findZone.groups.begin(); it != m_findZone.groups.end(); ++it )
        {
            groups[idx++] = it;
        }

        switch( m_findZone.sortBy )
        {
        case FindZone::SortBy::Order:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.id < rhs->second.id; } );
            break;
        case FindZone::SortBy::Count:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.zones.size() > rhs->second.zones.size(); } );
            break;
        case FindZone::SortBy::Time:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time > rhs->second.time; } );
            break;
        case FindZone::SortBy::Mtpc:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return double( lhs->second.time ) / lhs->second.zones.size() > double( rhs->second.time ) / rhs->second.zones.size(); } );
            break;
        default:
            assert( false );
            break;
        }

        int16_t changeZone = 0;

        if( groupBy == FindZone::GroupBy::Callstack )
        {
            const auto gsz = (int)groups.size();
            if( gsz > 0 )
            {
                if( m_findZone.selCs > gsz ) m_findZone.selCs = gsz;
                const auto group = groups[m_findZone.selCs];

                const bool selHilite = m_findZone.selGroup == group->first;
                if( selHilite ) SetButtonHighlightColor();
                if( ImGui::SmallButton( " " ICON_FA_CHECK " " ) )
                {
                    m_findZone.selGroup = group->first;
                    m_findZone.ResetSelection();
                }
                if( selHilite ) ImGui::PopStyleColor( 3 );
                ImGui::SameLine();
                if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
                {
                    m_findZone.selCs = std::max( m_findZone.selCs - 1, 0 );
                }
                ImGui::SameLine();
                ImGui::Text( "%s / %s", RealToString( m_findZone.selCs + 1 ), RealToString( gsz ) );
                if( ImGui::IsItemClicked() ) ImGui::OpenPopup( "FindZoneCallstackPopup" );
                ImGui::SameLine();
                if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
                {
                    m_findZone.selCs = std::min<int>( m_findZone.selCs + 1, gsz - 1 );
                }
                if( ImGui::BeginPopup( "FindZoneCallstackPopup" ) )
                {
                    int sel = m_findZone.selCs + 1;
                    ImGui::SetNextItemWidth( 120 * scale );
                    const bool clicked = ImGui::InputInt( "##findZoneCallstack", &sel, 1, 100, ImGuiInputTextFlags_EnterReturnsTrue );
                    if( clicked ) m_findZone.selCs = std::min( std::max( sel, 1 ), int( gsz ) ) - 1;
                    ImGui::EndPopup();
                }

                ImGui::SameLine();
                TextFocused( "Count:", RealToString( group->second.zones.size() ) );
                ImGui::SameLine();
                TextFocused( "Time:", TimeToString( group->second.time ) );
                ImGui::SameLine();
                char buf[64];
                PrintStringPercent( buf, group->second.time * 100.f / zoneData.total );
                TextDisabledUnformatted( buf );

                if( group->first != 0 )
                {
                    ImGui::SameLine();
                    int idx = 0;
                    SmallCallstackButton( " " ICON_FA_ALIGN_JUSTIFY " ", group->first, idx, false );

                    int fidx = 0;
                    ImGui::Spacing();
                    ImGui::Indent();
                    auto& csdata = m_worker.GetCallstack( group->first );
                    for( auto& entry : csdata )
                    {
                        auto frameData = m_worker.GetCallstackFrame( entry );
                        if( !frameData )
                        {
                            ImGui::TextDisabled( "%i.", fidx++ );
                            ImGui::SameLine();
                            ImGui::Text( "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
                        }
                        else
                        {
                            const auto fsz = frameData->size;
                            for( uint8_t f=0; f<fsz; f++ )
                            {
                                const auto& frame = frameData->data[f];
                                auto txt = m_worker.GetString( frame.name );

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
                                if( f == fsz-1 )
                                {
                                    ImGui::TextDisabled( "%i.", fidx++ );
                                }
                                else
                                {
                                    TextDisabledUnformatted( ICON_FA_CARET_RIGHT );
                                }
                                ImGui::SameLine();
                                ImGui::TextUnformatted( txt );
                            }
                        }
                    }
                    ImGui::Unindent();
                }
                else
                {
                    ImGui::Text( "No call stack" );
                }

                ImGui::Spacing();
                if( ImGui::TreeNodeEx( "Zone list" ) )
                {
                    DrawZoneList( group->second.id, group->second.zones );
                }
            }
        }
        else
        {
            for( auto& v : groups )
            {
                bool isFiber = false;
                const char* hdrString;
                switch( groupBy )
                {
                case FindZone::GroupBy::Thread:
                    {
                    const auto tid = m_worker.DecompressThread( v->first );
                    const auto threadColor = GetThreadColor( tid, 0 );
                    SmallColorBox( threadColor );
                    ImGui::SameLine();
                    hdrString = m_worker.GetThreadName( tid );
                    isFiber = m_worker.IsThreadFiber( tid );
                    break;
                    }
                case FindZone::GroupBy::UserText:
                    hdrString = v->first == std::numeric_limits<uint64_t>::max() ? "No user text" : m_worker.GetString( StringIdx( v->first ) );
                    break;
                case FindZone::GroupBy::ZoneName:
                    if( v->first == std::numeric_limits<uint64_t>::max() )
                    {
                        auto& srcloc = m_worker.GetSourceLocation( m_findZone.match[m_findZone.selMatch] );
                        hdrString = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                    }
                    else
                    {
                        hdrString = m_worker.GetString( StringIdx( v->first ) );
                    }
                    break;
                case FindZone::GroupBy::Callstack:
                    if( v->first == 0 )
                    {
                        hdrString = "No callstack";
                    }
                    else
                    {
                        auto& callstack = m_worker.GetCallstack( v->first );
                        auto& frameData = *m_worker.GetCallstackFrame( *callstack.begin() );
                        hdrString = m_worker.GetString( frameData.data[frameData.size-1].name );
                    }
                    break;
                case FindZone::GroupBy::Parent:
                    if( v->first == 0 )
                    {
                        hdrString = "<no parent>";
                        SmallColorBox( 0 );
                    }
                    else
                    {
                        auto& srcloc = m_worker.GetSourceLocation( int16_t( v->first ) );
                        hdrString = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                        SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                    }
                    ImGui::SameLine();
                    break;
                case FindZone::GroupBy::NoGrouping:
                    hdrString = "Zone list";
                    break;
                default:
                    hdrString = nullptr;
                    assert( false );
                    break;
                }
                ImGui::PushID( v->first );
                const bool expand = ImGui::TreeNodeEx( hdrString, ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick | ( v->first == m_findZone.selGroup ? ImGuiTreeNodeFlags_Selected : 0 ) );
                if( ImGui::IsItemClicked() )
                {
                    m_findZone.selGroup = v->first;
                    m_findZone.ResetSelection();
                }
                if( m_findZone.groupBy == FindZone::GroupBy::Parent && ImGui::IsItemClicked( 2 ) )
                {
                    changeZone = int16_t( v->first );
                }
                ImGui::PopID();
                if( isFiber )
                {
                    ImGui::SameLine();
                    TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
                }
                ImGui::SameLine();
                ImGui::TextColored( ImVec4( 0.5f, 0.5f, 0.5f, 1.0f ), "(%s) %s", RealToString( v->second.zones.size() ), TimeToString( v->second.time ) );
                if( expand )
                {
                    DrawZoneList( v->second.id, v->second.zones );
                }
            }
        }

        if( m_findZone.samples.enabled && m_findZone.samples.scheduleUpdate && !m_findZone.scheduleResetMatch )
        {
            m_findZone.samples.scheduleUpdate = false;

            const auto& symMap = m_worker.GetSymbolMap();
            m_findZone.samples.counts.clear();
            m_findZone.samples.counts.reserve( symMap.size() );

            struct GroupRange {
                const FindZone::Group* group;
                Vector<short_ptr<ZoneEvent>>::const_iterator begin;
                Vector<short_ptr<ZoneEvent>>::const_iterator end;
            };
            Vector<GroupRange> selectedGroups;
            selectedGroups.reserve( m_findZone.groups.size() );
            for( auto it = m_findZone.groups.begin(); it != m_findZone.groups.end(); ++it )
            {
                assert( it->second.zones.size() == it->second.zonesTids.size() );
                if( ( m_findZone.selGroup == m_findZone.Unselected || it->first == m_findZone.selGroup )
                    && !it->second.zones.empty() )
                {
                    selectedGroups.push_back_no_space_check( GroupRange{&it->second} );
                }
            }

            for( auto& v : symMap )
            {
                bool pass = ( m_statShowKernel || ( v.first >> 63 ) == 0 );
                if( !pass && v.second.size.Val() == 0 )
                {
                    const auto parentAddr = m_worker.GetSymbolForAddress( v.first );
                    if( parentAddr != 0 )
                    {
                        auto pit = symMap.find( parentAddr );
                        if( pit != symMap.end() )
                        {
                            pass = ( m_statShowKernel || ( parentAddr >> 63 ) == 0 );
                        }
                    }
                }
                if( !pass ) continue;

                auto samples = m_worker.GetSamplesForSymbol( v.first );
                if( !samples )  continue;

                auto samplesBegin = samples->begin();
                auto samplesEnd = samples->end();
                if( m_findZone.range.active )
                {
                    const auto rangeMin = m_findZone.range.min;
                    const auto rangeMax = m_findZone.range.max;
                    samplesBegin = std::lower_bound( samplesBegin, samplesEnd, rangeMin, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                    samplesEnd = std::lower_bound( samplesBegin, samplesEnd, rangeMax, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                }
                if( samplesBegin == samplesEnd )  continue;

                bool empty = true;
                const auto firstTime = samplesBegin->time.Val();
                const auto lastTime = samplesEnd->time.Val();
                for( auto& g: selectedGroups )
                {
                    const auto& zones = g.group->zones;
                    auto begin = std::lower_bound( zones.begin(), zones.end(), firstTime, [] ( const auto& l, const auto& r ) { return l->Start() < r; } );
                    auto end = std::upper_bound( begin, zones.end(), lastTime, [] ( const auto& l, const auto& r ) { return l <= r->Start(); } );
                    g.begin = begin;
                    g.end = end;
                    empty = empty && (begin == end);
                }
                if (empty) continue;

                uint32_t count = 0;
                for( auto it = samplesBegin; it != samplesEnd; ++it )
                {
                    const auto time = it->time.Val();
                    bool pass = false;
                    for( auto& g: selectedGroups )
                    {
                        while( g.begin != g.end && time > (*g.begin)->End() ) ++g.begin;
                        if( g.begin == g.end ) continue;
                        if( time < (*g.begin)->Start() ) continue;

                        const auto& tids = g.group->zonesTids;
                        const auto firstZone = g.group->zones.begin();
                        for (auto z = g.begin; z != g.end && (*z)->Start() <= time; ++z)
                        {
                            auto zoneIndex = z - firstZone;
                            if( (*z)->End() > time && it->thread == tids[zoneIndex] )
                            {
                                pass = true;
                                break;
                            }
                        }
                    }
                    if( pass ) count ++;
                }
                if( count > 0 )  m_findZone.samples.counts.push_back_no_space_check( SymList { v.first, 0, count } );
            }
        }

        ImGui::Separator();
        const bool hasSamples = m_worker.AreCallstackSamplesReady() && m_worker.GetCallstackSampleCount() > 0;
        if( hasSamples && ImGui::TreeNodeEx( ICON_FA_EYE_DROPPER " Samples", ImGuiTreeNodeFlags_None ) )
        {
            {
                ImGui::Checkbox( ICON_FA_STOPWATCH " Show time", &m_statSampleTime );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::Checkbox( ICON_FA_EYE_SLASH " Hide unknown", &m_statHideUnknown );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::Checkbox( ICON_FA_SITEMAP " Inlines", &m_statSeparateInlines );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                ImGui::Checkbox( ICON_FA_AT " Address", &m_statShowAddress );
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( ImGui::Checkbox( ICON_FA_HAT_WIZARD " Include kernel", &m_statShowKernel ))
                {
                    m_findZone.samples.scheduleUpdate = true;
                }
            }

            if( !m_findZone.samples.enabled )
            {
                m_findZone.samples.enabled = true;
                m_findZone.samples.scheduleUpdate = true;
                m_findZone.scheduleResetMatch = true;
            }

            Vector<SymList> data;
            data.reserve( m_findZone.samples.counts.size() );
            for( auto it: m_findZone.samples.counts ) data.push_back_no_space_check( it );
            int64_t timeRange = ( m_findZone.selGroup != m_findZone.Unselected ) ? m_findZone.selTotal : m_findZone.total;
            DrawSamplesStatistics( data, timeRange, AccumulationMode::SelfOnly );

            ImGui::TreePop();
        }
        else
        {
            if( m_findZone.samples.enabled )
            {
                m_findZone.samples.enabled = false;
                m_findZone.samples.scheduleUpdate = false;
                m_findZone.samples.counts = Vector<SymList>();
                for( auto& it: m_findZone.groups ) it.second.zonesTids.clear();
            }
        }

        ImGui::EndChild();

        if( changeZone != 0 )
        {
            auto& srcloc = m_worker.GetSourceLocation( changeZone );
            m_findZone.ShowZone( changeZone, m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
        }
    }
#endif

    ImGui::End();
}

void View::DrawZoneList( int id, const Vector<short_ptr<ZoneEvent>>& zones )
{
    const auto zsz = zones.size();
    char buf[32];
    sprintf( buf, "%i##zonelist", id );
    if( !ImGui::BeginTable( buf, 3, ImGuiTableFlags_NoSavedSettings | ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<size_t>( zsz + 1, 15 ) ) ) ) return;
    ImGui::TableSetupScrollFreeze( 0, 1 );
    ImGui::TableSetupColumn( "Time from start" );
    ImGui::TableSetupColumn( "Execution time", ImGuiTableColumnFlags_PreferSortDescending );
    ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_NoSort );
    ImGui::TableHeadersRow();

    const Vector<short_ptr<ZoneEvent>>* zonesToIterate = &zones;
    Vector<short_ptr<ZoneEvent>> sortedZones;

    const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
    if( sortspec.ColumnIndex != 0 || sortspec.SortDirection != ImGuiSortDirection_Ascending )
    {
        zonesToIterate = &sortedZones;
        sortedZones.reserve_and_use( zones.size() );
        memcpy( sortedZones.data(), zones.data(), zones.size() * sizeof( decltype( *zones.begin() ) ) );

        switch( sortspec.ColumnIndex )
        {
        case 0:
            assert( sortspec.SortDirection != ImGuiSortDirection_Descending );
            std::reverse( sortedZones.begin(), sortedZones.end() );
            break;
        case 1:
            if( m_findZone.selfTime )
            {
                if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() - this->GetZoneChildTimeFast( *lhs ) >
                               m_worker.GetZoneEndDirect( *rhs ) - rhs->Start() - this->GetZoneChildTimeFast( *rhs );
                    } );
                }
                else
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() - this->GetZoneChildTimeFast( *lhs ) <
                               m_worker.GetZoneEndDirect( *rhs ) - rhs->Start() - this->GetZoneChildTimeFast( *rhs );
                    } );
                }
            }
            else if( m_findZone.runningTime )
            {
                if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        const auto ctx0 = m_worker.GetContextSwitchData( GetZoneThread( *lhs ) );
                        const auto ctx1 = m_worker.GetContextSwitchData( GetZoneThread( *rhs ) );
                        int64_t t0, t1;
                        uint64_t c0, c1;
                        GetZoneRunningTime( ctx0, *lhs, t0, c0 );
                        GetZoneRunningTime( ctx1, *rhs, t1, c1 );
                        return t0 > t1;
                    } );
                }
                else
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        const auto ctx0 = m_worker.GetContextSwitchData( GetZoneThread( *lhs ) );
                        const auto ctx1 = m_worker.GetContextSwitchData( GetZoneThread( *rhs ) );
                        int64_t t0, t1;
                        uint64_t c0, c1;
                        GetZoneRunningTime( ctx0, *lhs, t0, c0 );
                        GetZoneRunningTime( ctx1, *rhs, t1, c1 );
                        return t0 < t1;
                    } );
                }
            }
            else
            {
                if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() > m_worker.GetZoneEndDirect( *rhs ) - rhs->Start();
                    } );
                }
                else
                {
                    pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                        return m_worker.GetZoneEndDirect( *lhs ) - lhs->Start() < m_worker.GetZoneEndDirect( *rhs ) - rhs->Start();
                    } );
                }
            }
            break;
        case 2:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                    const auto hle = m_worker.HasZoneExtra( *lhs );
                    const auto hre = m_worker.HasZoneExtra( *rhs );
                    if( !( hle & hre ) ) return hle > hre;
                    return strcmp( m_worker.GetString( m_worker.GetZoneExtra( *lhs ).name ), m_worker.GetString( m_worker.GetZoneExtra( *rhs ).name ) ) < 0;
                } );
            }
            else
            {
                pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                    const auto hle = m_worker.HasZoneExtra( *lhs );
                    const auto hre = m_worker.HasZoneExtra( *rhs );
                    if( !( hle & hre ) ) return hle < hre;
                    return strcmp( m_worker.GetString( m_worker.GetZoneExtra( *lhs ).name ), m_worker.GetString( m_worker.GetZoneExtra( *rhs ).name ) ) > 0;
                } );
            }
            break;
        default:
            assert( false );
            break;
        }
    }

    ImGuiListClipper clipper;
    clipper.Begin( zonesToIterate->size() );
    while( clipper.Step() )
    {
        for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            auto ev = (*zonesToIterate)[i].get();
            const auto end = m_worker.GetZoneEndDirect( *ev );
            int64_t timespan;
            if( m_findZone.runningTime )
            {
                const auto ctx = m_worker.GetContextSwitchData( GetZoneThread( *ev ) );
                uint64_t cnt;
                GetZoneRunningTime( ctx, *ev, timespan, cnt );
            }
            else
            {
                timespan = end - ev->Start();
                if( m_findZone.selfTime ) timespan -= GetZoneChildTimeFast( *ev );
            }

            ImGui::PushID( ev );
            if( m_zoneHover == ev ) ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0, 1, 0, 1 ) );
            if( ImGui::Selectable( TimeToStringExact( ev->Start() ), m_zoneInfoWindow == ev, ImGuiSelectableFlags_SpanAllColumns ) )
            {
                ShowZoneInfo( *ev );
            }
            if( ImGui::IsItemHovered() )
            {
                m_zoneHighlight = ev;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *ev );
                }
                ZoneTooltip( *ev );
                m_zoneHover2 = ev;
            }

            ImGui::TableNextColumn();
            ImGui::TextUnformatted( TimeToString( timespan ) );
            ImGui::TableNextColumn();
            if( m_worker.HasZoneExtra( *ev ) )
            {
                const auto& extra = m_worker.GetZoneExtra( *ev );
                if( extra.name.Active() )
                {
                    ImGui::TextUnformatted( m_worker.GetString( extra.name ) );
                }
            }
            if( m_zoneHover == ev ) ImGui::PopStyleColor();
            ImGui::PopID();
        }
    }
    ImGui::EndTable();
    ImGui::TreePop();
}

bool View::FindMatchingZone( int prev0, int prev1, int flags )
{
    int idx = 0;
    bool found = false;
    auto& srcloc0 = m_worker.GetSourceLocation( m_compare.match[0][m_compare.selMatch[0]] );
    auto& srcloc1 = m_compare.second->GetSourceLocation( m_compare.match[1][m_compare.selMatch[1]] );
    auto string0 = m_worker.GetString( srcloc0.name.active ? srcloc0.name : srcloc0.function );
    auto string1 = m_compare.second->GetString( srcloc1.name.active ? srcloc1.name : srcloc1.function );
    auto file0 = m_worker.GetString( srcloc0.file );
    auto file1 = m_compare.second->GetString( srcloc1.file );
    bool wrongFile = false;
    bool wrongLine = false;
    if( flags & FindMatchingZoneFlagSourceFile )
    {
        wrongFile = strcmp( file0, file1 ) != 0;
    }
    if( flags & FindMatchingZoneFlagLineNum )
    {
        wrongLine = srcloc0.line != srcloc1.line;
    }

    if( strcmp( string0, string1 ) != 0 || wrongFile || wrongLine )
    {
        if( prev0 != m_compare.selMatch[0] )
        {
            for( auto& v : m_compare.match[1] )
            {
                auto& srcloc = m_compare.second->GetSourceLocation( v );
                auto string = m_compare.second->GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                auto file = m_compare.second->GetString( srcloc.file );
                bool sameFile = true;
                bool sameLine = true;
                if( flags & FindMatchingZoneFlagSourceFile )
                {
                    sameFile = strcmp( file0, file ) == 0;
                }
                if( flags & FindMatchingZoneFlagLineNum )
                {
                    sameLine = srcloc0.line == srcloc.line;
                }
                if( strcmp( string0, string ) == 0 && sameFile && sameLine )
                {
                    m_compare.selMatch[1] = idx;
                    found = true;
                    break;
                }
                idx++;
            }
        }
        else
        {
            assert( prev1 != m_compare.selMatch[1] );
            for( auto& v : m_compare.match[0] )
            {
                auto& srcloc = m_worker.GetSourceLocation( v );
                auto string = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                auto file = m_worker.GetString( srcloc.file );
                bool sameFile = true;
                bool sameLine = true;
                if( flags & FindMatchingZoneFlagSourceFile )
                {
                    sameFile = strcmp( file1, file ) == 0;
                }
                if( flags & FindMatchingZoneFlagLineNum )
                {
                    sameLine = srcloc1.line == srcloc.line;
                }
                if( strcmp( string1, string ) == 0 && sameFile && sameLine )
                {
                    m_compare.selMatch[0] = idx;
                    found = true;
                    break;
                }
                idx++;
            }

        }
    }
    return found;
}

void View::DrawCompare()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 590 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Compare traces", &m_compare.show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable trace comparison." );
#elif defined TRACY_NO_FILESELECTOR
    ImGui::TextWrapped( "File selector is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_FILESELECTOR macro to enable trace comparison." );
#else
    if( !m_compare.second )
    {
        ImGui::TextWrapped( "Please load a second trace to compare results." );
        if( ImGui::Button( ICON_FA_FOLDER_OPEN " Open second trace" ) && !m_compare.loadThread.joinable() )
        {
            nfdu8filteritem_t filter = { "Tracy Profiler trace file", "tracy" };
            nfdu8char_t* fn;
            auto res = NFD_OpenDialogU8( &fn, &filter, 1, nullptr );
            if( res == NFD_OKAY )
            {
                try
                {
                    auto f = std::shared_ptr<tracy::FileRead>( tracy::FileRead::Open( fn ) );
                    if( f )
                    {
                        m_compare.loadThread = std::thread( [this, f] {
                            try
                            {
                                m_compare.second = std::make_unique<Worker>( *f, EventType::None );
                                m_compare.userData = std::make_unique<UserData>( m_compare.second->GetCaptureProgram().c_str(), m_compare.second->GetCaptureTime() );
                            }
                            catch( const tracy::UnsupportedVersion& e )
                            {
                                m_compare.badVer.state = BadVersionState::UnsupportedVersion;
                                m_compare.badVer.version = e.version;
                            }
                        } );
                    }
                }
                catch( const tracy::NotTracyDump& )
                {
                    m_compare.badVer.state = BadVersionState::BadFile;
                }
                catch( const tracy::FileReadError& )
                {
                    m_compare.badVer.state = BadVersionState::ReadError;
                }
                NFD_FreePathU8( fn );
            }
        }
        tracy::BadVersion( m_compare.badVer, m_bigFont );
        ImGui::End();
        return;
    }

    if( m_compare.loadThread.joinable() ) m_compare.loadThread.join();

    if( !m_worker.AreSourceLocationZonesReady() || !m_compare.second->AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

    TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
    ImGui::SameLine();
    TextDisabledUnformatted( "This trace:" );
    ImGui::SameLine();
    const auto& desc0 = m_userData.GetDescription();
    if( desc0.empty() )
    {
        ImGui::TextUnformatted( m_worker.GetCaptureName().c_str() );
    }
    else
    {
        ImGui::TextUnformatted( desc0.c_str() );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", m_worker.GetCaptureName().c_str() );
    }

    TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
    ImGui::SameLine();
    TextDisabledUnformatted( "External trace:" );
    ImGui::SameLine();
    const auto& desc1 = m_compare.userData->GetDescription();
    if( desc1.empty() )
    {
        ImGui::TextUnformatted( m_compare.second->GetCaptureName().c_str() );
    }
    else
    {
        ImGui::TextUnformatted( desc1.c_str() );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", m_compare.second->GetCaptureName().c_str() );
    }

    if( ImGui::Button( ICON_FA_TRASH_ALT " Unload" ) )
    {
        m_compare.Reset();
        m_compare.second.reset();
        m_compare.userData.reset();
        ImGui::End();
        return;
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::Text( "Compare mode: " );
    ImGui::SameLine();
    const auto oldMode = m_compare.compareMode;
    ImGui::RadioButton( "Zones", &m_compare.compareMode, 0 );
    ImGui::SameLine();
    ImGui::RadioButton( "Frames", &m_compare.compareMode, 1 );
    if( oldMode != m_compare.compareMode )
    {
        m_compare.Reset();
    }

    bool findClicked = false;

    if( m_compare.compareMode == 0 )
    {
        ImGui::PushItemWidth( -0.01f );
        findClicked |= ImGui::InputTextWithHint( "###compare", "Enter zone name to search for", m_compare.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
        ImGui::PopItemWidth();

        findClicked |= ImGui::Button( ICON_FA_SEARCH " Find" );
        ImGui::SameLine();

        if( ImGui::Button( ICON_FA_BAN " Clear" ) )
        {
            m_compare.Reset();
        }
        ImGui::SameLine();
        ImGui::Checkbox( "Ignore case", &m_compare.ignoreCase );

        if( findClicked )
        {
            m_compare.Reset();
            FindZonesCompare();
        }

        if( m_compare.match[0].empty() && m_compare.match[1].empty() )
        {
            ImGui::End();
            return;
        }

        ImGui::Separator();
        ImGui::BeginChild( "##compare" );

        if( ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            ImGui::SameLine();
            SmallCheckbox( "Link selection", &m_compare.link );

            ImGui::Separator();
            ImGui::Columns( 2 );
            TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
            ImGui::SameLine();
            ImGui::TextUnformatted( "This trace" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", m_compare.match[0].size() );
            ImGui::NextColumn();
            TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
            ImGui::SameLine();
            ImGui::TextUnformatted( "External trace" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", m_compare.match[1].size() );
            ImGui::Separator();
            ImGui::NextColumn();

            const auto prev0 = m_compare.selMatch[0];
            int idx = 0;
            for( auto& v : m_compare.match[0] )
            {
                auto& srcloc = m_worker.GetSourceLocation( v );
                auto& zones = m_worker.GetZonesForSourceLocation( v ).zones;
                SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                ImGui::SameLine();
                ImGui::PushID( idx );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[0], idx++ );
                ImGui::PopStyleVar();
                ImGui::SameLine();
                ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s", RealToString( zones.size() ), LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                ImGui::PopID();
            }
            ImGui::NextColumn();

            const auto prev1 = m_compare.selMatch[1];
            idx = 0;
            for( auto& v : m_compare.match[1] )
            {
                auto& srcloc = m_compare.second->GetSourceLocation( v );
                auto& zones = m_compare.second->GetZonesForSourceLocation( v ).zones;
                ImGui::PushID( -1 - idx );
                ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                ImGui::RadioButton( m_compare.second->GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[1], idx++ );
                ImGui::PopStyleVar();
                ImGui::SameLine();
                ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s", RealToString( zones.size() ), LocationToString( m_compare.second->GetString( srcloc.file ), srcloc.line ) );
                ImGui::PopID();
            }
            ImGui::NextColumn();
            ImGui::EndColumns();
            ImGui::TreePop();

            if( prev0 != m_compare.selMatch[0] || prev1 != m_compare.selMatch[1] )
            {
                m_compare.ResetSelection();

                if( m_compare.link )
                {
                    if( !FindMatchingZone( prev0, prev1, FindMatchingZoneFlagSourceFile | FindMatchingZoneFlagLineNum ) )
                    {
                        if( !FindMatchingZone( prev0, prev1, FindMatchingZoneFlagSourceFile ) )
                        {
                            FindMatchingZone( prev0, prev1, FindMatchingZoneFlagDefault );
                        }
                    }
                }
            }
        }

        if( m_compare.match[0].empty() || m_compare.match[1].empty() )
        {
            ImGui::Separator();
            ImGui::TextWrapped( "Both traces must have matches." );
            ImGui::End();
            return;
        }
    }
    else
    {
        assert( m_compare.compareMode == 1 );

        ImGui::Separator();
        ImGui::BeginChild( "##compare" );
        if( ImGui::TreeNodeEx( "Frame sets", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto& f0 = m_worker.GetFrames();
            const auto& f1 = m_compare.second->GetFrames();

            ImGui::SameLine();
            SmallCheckbox( "Link selection", &m_compare.link );

            ImGui::Separator();
            ImGui::Columns( 2 );
            TextColoredUnformatted( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
            ImGui::SameLine();
            ImGui::TextUnformatted( "This trace" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", f0.size() );
            ImGui::NextColumn();
            TextColoredUnformatted( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
            ImGui::SameLine();
            ImGui::TextUnformatted( "External trace" );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", f1.size() );
            ImGui::Separator();
            ImGui::NextColumn();

            const auto prev0 = m_compare.selMatch[0];
            int idx = 0;
            for( auto& v : f0 )
            {
                const auto name = m_worker.GetString( v->name );
                ImGui::PushID( -1 - idx );
                ImGui::RadioButton( name, &m_compare.selMatch[0], idx++ );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( v->frames.size() ) );
                ImGui::PopID();
            }
            ImGui::NextColumn();

            const auto prev1 = m_compare.selMatch[1];
            idx = 0;
            for( auto& v : f1 )
            {
                const auto name = m_compare.second->GetString( v->name );
                ImGui::PushID( idx );
                ImGui::RadioButton( name, &m_compare.selMatch[1], idx++ );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( v->frames.size() ) );
                ImGui::PopID();
            }
            ImGui::NextColumn();
            ImGui::EndColumns();
            ImGui::TreePop();

            if( prev0 != m_compare.selMatch[0] || prev1 != m_compare.selMatch[1] )
            {
                m_compare.ResetSelection();

                if( m_compare.link )
                {
                    auto string0 = m_worker.GetString( f0[m_compare.selMatch[0]]->name );
                    auto string1 = m_compare.second->GetString( f1[m_compare.selMatch[1]]->name );

                    if( strcmp( string0, string1 ) != 0 )
                    {
                        idx = 0;
                        if( prev0 != m_compare.selMatch[0] )
                        {
                            for( auto& v : f1 )
                            {
                                auto string = m_compare.second->GetString( v->name );
                                if( strcmp( string0, string ) == 0 )
                                {
                                    m_compare.selMatch[1] = idx;
                                    break;
                                }
                                idx++;
                            }
                        }
                        else
                        {
                            assert( prev1 != m_compare.selMatch[1] );
                            for( auto& v : f0 )
                            {
                                auto string = m_worker.GetString( v->name );
                                if( strcmp( string1, string ) == 0 )
                                {
                                    m_compare.selMatch[0] = idx;
                                    break;
                                }
                                idx++;
                            }
                        }
                    }
                }
            }
        }
    }

    ImGui::Separator();
    if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        const auto ty = ImGui::GetTextLineHeight();

        int64_t tmin, tmax;
        size_t size0, size1;
        int64_t total0, total1;
        double sumSq0, sumSq1;

        if( m_compare.compareMode == 0 )
        {
            auto& zoneData0 = m_worker.GetZonesForSourceLocation( m_compare.match[0][m_compare.selMatch[0]] );
            auto& zoneData1 = m_compare.second->GetZonesForSourceLocation( m_compare.match[1][m_compare.selMatch[1]] );
            auto& zones0 = zoneData0.zones;
            auto& zones1 = zoneData1.zones;
            zones0.ensure_sorted();
            zones1.ensure_sorted();

            tmin = std::min( zoneData0.min, zoneData1.min );
            tmax = std::max( zoneData0.max, zoneData1.max );

            size0 = zones0.size();
            size1 = zones1.size();
            total0 = zoneData0.total;
            total1 = zoneData1.total;
            sumSq0 = zoneData0.sumSq;
            sumSq1 = zoneData1.sumSq;

            const size_t zsz[2] = { size0, size1 };
            for( int k=0; k<2; k++ )
            {
                if( m_compare.sortedNum[k] != zsz[k] )
                {
                    auto& zones = k == 0 ? zones0 : zones1;
                    auto& vec = m_compare.sorted[k];
                    vec.reserve( zsz[k] );
                    int64_t total = m_compare.total[k];
                    size_t i;
                    for( i=m_compare.sortedNum[k]; i<zsz[k]; i++ )
                    {
                        auto& zone = *zones[i].Zone();
                        const auto t = zone.End() - zone.Start();
                        vec.emplace_back( t );
                        total += t;
                    }
                    auto mid = vec.begin() + m_compare.sortedNum[k];
                    pdqsort_branchless( mid, vec.end() );
                    std::inplace_merge( vec.begin(), mid, vec.end() );

                    m_compare.average[k] = float( total ) / i;
                    m_compare.median[k] = vec[i/2];
                    m_compare.total[k] = total;
                    m_compare.sortedNum[k] = i;
                }
            }
        }
        else
        {
            assert( m_compare.compareMode == 1 );

            const auto& f0 = m_worker.GetFrames()[m_compare.selMatch[0]];
            const auto& f1 = m_compare.second->GetFrames()[m_compare.selMatch[1]];

            tmin = std::min( f0->min, f1->min );
            tmax = std::max( f0->max, f1->max );

            size0 = f0->frames.size();
            size1 = f1->frames.size();
            total0 = f0->total;
            total1 = f1->total;
            sumSq0 = f0->sumSq;
            sumSq1 = f1->sumSq;

            const size_t zsz[2] = { size0, size1 };
            for( int k=0; k<2; k++ )
            {
                if( m_compare.sortedNum[k] != zsz[k] )
                {
                    auto& frameSet = k == 0 ? f0 : f1;
                    auto worker = k == 0 ? &m_worker : m_compare.second.get();
                    auto& vec = m_compare.sorted[k];
                    vec.reserve( zsz[k] );
                    int64_t total = m_compare.total[k];
                    size_t i;
                    for( i=m_compare.sortedNum[k]; i<zsz[k]; i++ )
                    {
                        if( worker->GetFrameEnd( *frameSet, i ) == worker->GetLastTime() ) break;
                        const auto t = worker->GetFrameTime( *frameSet, i );
                        vec.emplace_back( t );
                        total += t;
                    }
                    auto mid = vec.begin() + m_compare.sortedNum[k];
                    pdqsort_branchless( mid, vec.end() );
                    std::inplace_merge( vec.begin(), mid, vec.end() );

                    m_compare.average[k] = float( total ) / i;
                    m_compare.median[k] = vec[i/2];
                    m_compare.total[k] = total;
                    m_compare.sortedNum[k] = i;
                }
            }
        }

        if( tmin != std::numeric_limits<int64_t>::max() )
        {
            TextDisabledUnformatted( "Minimum values in bin:" );
            ImGui::SameLine();
            ImGui::SetNextItemWidth( ImGui::CalcTextSize( "123456890123456" ).x );
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 1, 1 ) );
            ImGui::InputInt( "##minBinVal", &m_compare.minBinVal );
            if( m_compare.minBinVal < 1 ) m_compare.minBinVal = 1;
            ImGui::SameLine();
            if( ImGui::Button( "Reset" ) ) m_compare.minBinVal = 1;
            ImGui::PopStyleVar();

            SmallCheckbox( "Log values", &m_compare.logVal );
            ImGui::SameLine();
            SmallCheckbox( "Log time", &m_compare.logTime );
            ImGui::SameLine();
            SmallCheckbox( "Cumulate time", &m_compare.cumulateTime );
            ImGui::SameLine();
            DrawHelpMarker( "Show total time taken by calls in each bin instead of call counts." );
            ImGui::SameLine();
            SmallCheckbox( "Normalize values", &m_compare.normalize );
            ImGui::SameLine();
            DrawHelpMarker( "Normalization will fudge reported data values!" );

            const auto cumulateTime = m_compare.cumulateTime;

            if( tmax - tmin > 0 )
            {
                const auto w = ImGui::GetContentRegionAvail().x;

                const auto numBins = int64_t( w - 4 );
                if( numBins > 1 )
                {
                    if( numBins > m_compare.numBins )
                    {
                        m_compare.numBins = numBins;
                        m_compare.bins = std::make_unique<CompVal[]>( numBins );
                        m_compare.binTime = std::make_unique<CompVal[]>( numBins );
                    }

                    const auto& bins = m_compare.bins;
                    const auto& binTime = m_compare.binTime;

                    memset( bins.get(), 0, sizeof( CompVal ) * numBins );
                    memset( binTime.get(), 0, sizeof( CompVal ) * numBins );

                    double adj0 = 1;
                    double adj1 = 1;
                    if( m_compare.normalize )
                    {
                        if( size0 > size1 )
                        {
                            adj1 = double( size0 ) / size1;
                        }
                        else
                        {
                            adj0 = double( size1 ) / size0;
                        }
                    }

                    const auto& sorted = m_compare.sorted;
                    auto sBegin0 = sorted[0].begin();
                    auto sBegin1 = sorted[1].begin();
                    auto sEnd0 = sorted[0].end();
                    auto sEnd1 = sorted[1].end();

                    if( m_compare.minBinVal > 1 )
                    {
                        if( m_compare.logTime )
                        {
                            const auto tMinLog = log10( tmin );
                            const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                            int64_t i;
                            for( i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                const auto distance0 = std::distance( sBegin0, nit0 );
                                const auto distance1 = std::distance( sBegin1, nit1 );
                                if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                sBegin0 = nit0;
                                sBegin1 = nit1;
                            }
                            for( int64_t j=numBins-1; j>i; j-- )
                            {
                                const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( j-1 ) * zmax ) );
                                auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                const auto distance0 = std::distance( nit0, sEnd0 );
                                const auto distance1 = std::distance( nit1, sEnd1 );
                                if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                sEnd0 = nit0;
                                sEnd1 = nit1;
                            }
                        }
                        else
                        {
                            const auto zmax = tmax - tmin;
                            int64_t i;
                            for( i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                const auto distance0 = std::distance( sBegin0, nit0 );
                                const auto distance1 = std::distance( sBegin1, nit1 );
                                if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                sBegin0 = nit0;
                                sBegin1 = nit1;
                            }
                            for( int64_t j=numBins-1; j>i; j-- )
                            {
                                const auto nextBinVal = tmin + ( j-1 ) * zmax / numBins;
                                auto nit0 = std::lower_bound( sBegin0, sEnd0, nextBinVal );
                                auto nit1 = std::lower_bound( sBegin1, sEnd1, nextBinVal );
                                const auto distance0 = std::distance( nit0, sEnd0 );
                                const auto distance1 = std::distance( nit1, sEnd1 );
                                if( distance0 >= m_compare.minBinVal || distance1 >= m_compare.minBinVal ) break;
                                sEnd0 = nit0;
                                sEnd1 = nit1;
                            }
                        }

                        tmin = std::min( *sBegin0, *sBegin1 );
                        tmax = std::max( *(sEnd0-1), *(sEnd1-1) );
                    }

                    auto zit0 = sBegin0;
                    auto zit1 = sBegin1;
                    if( m_compare.logTime )
                    {
                        const auto tMinLog = log10( tmin );
                        const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                        for( int64_t i=0; i<numBins; i++ )
                        {
                            const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                            auto nit0 = std::lower_bound( zit0, sEnd0, nextBinVal );
                            auto nit1 = std::lower_bound( zit1, sEnd1, nextBinVal );
                            bins[i].v0 += adj0 * std::distance( zit0, nit0 );
                            bins[i].v1 += adj1 * std::distance( zit1, nit1 );
                            binTime[i].v0 += adj0 * std::accumulate( zit0, nit0, int64_t( 0 ) );
                            binTime[i].v1 += adj1 * std::accumulate( zit1, nit1, int64_t( 0 ) );
                            zit0 = nit0;
                            zit1 = nit1;
                        }
                    }
                    else
                    {
                        const auto zmax = tmax - tmin;
                        for( int64_t i=0; i<numBins; i++ )
                        {
                            const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                            auto nit0 = std::lower_bound( zit0, sEnd0, nextBinVal );
                            auto nit1 = std::lower_bound( zit1, sEnd1, nextBinVal );
                            bins[i].v0 += adj0 * std::distance( zit0, nit0 );
                            bins[i].v1 += adj1 * std::distance( zit1, nit1 );
                            binTime[i].v0 += adj0 * std::accumulate( zit0, nit0, int64_t( 0 ) );
                            binTime[i].v1 += adj1 * std::accumulate( zit1, nit1, int64_t( 0 ) );
                            zit0 = nit0;
                            zit1 = nit1;
                        }
                    }

                    double maxVal;
                    if( cumulateTime )
                    {
                        maxVal = std::max( binTime[0].v0, binTime[0].v1 );
                        for( int i=1; i<numBins; i++ )
                        {
                            maxVal = std::max( { maxVal, binTime[i].v0, binTime[i].v1 } );
                        }
                    }
                    else
                    {
                        maxVal = std::max( bins[0].v0, bins[0].v1 );
                        for( int i=1; i<numBins; i++ )
                        {
                            maxVal = std::max( { maxVal, bins[i].v0, bins[i].v1 } );
                        }
                    }

                    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                    ImGui::SameLine();
                    TextFocused( "Total time (this):", TimeToString( total0 * adj0 ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                    ImGui::SameLine();
                    TextFocused( "Total time (ext.):", TimeToString( total1 * adj1 ) );
                    TextFocused( "Savings:", TimeToString( total1 * adj1 - total0 * adj0 ) );
                    ImGui::SameLine();
                    char buf[64];
                    PrintStringPercent( buf, ( total0 * adj0 ) / ( total1 * adj1 ) * 100 );
                    TextDisabledUnformatted( buf );
                    TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( floor( maxVal ) ) );

                    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                    ImGui::SameLine();
                    TextFocused( "Mean time (this):", TimeToString( m_compare.average[0] ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                    ImGui::SameLine();
                    TextFocused( "Median time (this):", TimeToString( m_compare.median[0] ) );
                    if( sorted[0].size() > 1 )
                    {
                        const auto sz = sorted[0].size();
                        const auto avg = m_compare.average[0];
                        const auto ss = sumSq0 - 2. * total0 * avg + avg * avg * sz;
                        const auto sd = sqrt( ss / ( sz - 1 ) );

                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
                        TextFocused( "\xcf\x83 (this):", TimeToString( sd ) );
                        TooltipIfHovered( "Standard deviation" );
                    }


                    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                    ImGui::SameLine();
                    TextFocused( "Mean time (ext.):", TimeToString( m_compare.average[1] ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
                    TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                    ImGui::SameLine();
                    TextFocused( "Median time (ext.):", TimeToString( m_compare.median[1] ) );
                    if( sorted[1].size() > 1 )
                    {
                        const auto sz = sorted[1].size();
                        const auto avg = m_compare.average[1];
                        const auto ss = sumSq1 - 2. * total1 * avg + avg * avg * sz;
                        const auto sd = sqrt( ss / ( sz - 1 ) );

                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
                        TextFocused( "\xcf\x83 (ext.):", TimeToString( sd ) );
                        TooltipIfHovered( "Standard deviation" );
                    }

                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                    ImGui::Button( ICON_FA_LEMON );
                    ImGui::PopStyleColor( 4 );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( "This trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                    ImGui::Button( ICON_FA_GEM );
                    ImGui::PopStyleColor( 4 );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( "External trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

                    ImGui::ColorButton( "c3", ImVec4( 0x44/255.f, 0xBB/255.f, 0xBB/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( "Overlap" );

                    const auto Height = 200 * scale;
                    const auto wpos = ImGui::GetCursorScreenPos();
                    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

                    ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 2.5 ) ) );
                    const bool hover = ImGui::IsItemHovered();

                    auto draw = ImGui::GetWindowDrawList();
                    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                    draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                    if( m_compare.logVal )
                    {
                        const auto hAdj = double( Height - 4 ) / log10( maxVal + 1 );
                        for( int i=0; i<numBins; i++ )
                        {
                            const auto val0 = cumulateTime ? binTime[i].v0 : bins[i].v0;
                            const auto val1 = cumulateTime ? binTime[i].v1 : bins[i].v1;
                            if( val0 > 0 || val1 > 0 )
                            {
                                const auto val = std::min( val0, val1 );
                                if( val > 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFFBBBB44 );
                                }
                                if( val1 == val )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), dpos + ImVec2( 2+i, Height-3 - log10( val0 + 1 ) * hAdj ), 0xFF22DDDD );
                                }
                                else
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), dpos + ImVec2( 2+i, Height-3 - log10( val1 + 1 ) * hAdj ), 0xFF2222DD );
                                }
                            }
                        }
                    }
                    else
                    {
                        const auto hAdj = double( Height - 4 ) / maxVal;
                        for( int i=0; i<numBins; i++ )
                        {
                            const auto val0 = cumulateTime ? binTime[i].v0 : bins[i].v0;
                            const auto val1 = cumulateTime ? binTime[i].v1 : bins[i].v1;
                            if( val0 > 0 || val1 > 0 )
                            {
                                const auto val = std::min( val0, val1 );
                                if( val > 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFFBBBB44 );
                                }
                                if( val1 == val )
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - val * hAdj ), dpos + ImVec2( 2+i, Height-3 - val0 * hAdj ), 0xFF22DDDD );
                                }
                                else
                                {
                                    DrawLine( draw, dpos + ImVec2( 2+i, Height-3 - val * hAdj ), dpos + ImVec2( 2+i, Height-3 - val1 * hAdj ), 0xFF2222DD );
                                }
                            }
                        }
                    }

                    const auto xoff = 2;
                    const auto yoff = Height + 1;

                    DrawHistogramMinMaxLabel( draw, tmin, tmax, wpos + ImVec2( 0, yoff ), w, ty );

                    const auto ty05 = round( ty * 0.5f );
                    const auto ty025 = round( ty * 0.25f );
                    if( m_compare.logTime )
                    {
                        const auto ltmin = log10( tmin );
                        const auto ltmax = log10( tmax );
                        const auto start = int( floor( ltmin ) );
                        const auto end = int( ceil( ltmax ) );

                        const auto range = ltmax - ltmin;
                        const auto step = w / range;
                        auto offset = start - ltmin;
                        int tw = 0;
                        int tx = 0;

                        auto tt = int64_t( pow( 10, start ) );

                        static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                        for( int i=start; i<=end; i++ )
                        {
                            const auto x = ( i - start + offset ) * step;

                            if( x >= 0 )
                            {
                                DrawLine( draw, dpos + ImVec2( x, yoff ), dpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF );
                                if( tw == 0 || x > tx + tw + ty * 1.1 )
                                {
                                    tx = x;
                                    auto txt = TimeToString( tt );
                                    draw->AddText( wpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }
                            }

                            for( int j=0; j<8; j++ )
                            {
                                const auto xoff = x + logticks[j] * step;
                                if( xoff >= 0 )
                                {
                                    DrawLine( draw, dpos + ImVec2( xoff, yoff ), dpos + ImVec2( xoff, yoff + ty025 ), 0x66FFFFFF );
                                }
                            }

                            tt *= 10;
                        }
                    }
                    else
                    {
                        const auto pxns = numBins / double( tmax - tmin );
                        const auto nspx = 1.0 / pxns;
                        const auto scale = std::max<float>( 0.0f, round( log10( nspx ) + 2 ) );
                        const auto step = pow( 10, scale );

                        const auto dx = step * pxns;
                        double x = 0;
                        int tw = 0;
                        int tx = 0;

                        const auto sstep = step / 10.0;
                        const auto sdx = dx / 10.0;

                        static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                        int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                        const auto diff = tmin / sstep - int64_t( tmin / sstep );
                        const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                        int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                        while( x < numBins )
                        {
                            DrawLine( draw, dpos + ImVec2( xo + x, yoff ), dpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                            if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                            {
                                tx = x;
                                auto txt = TimeToString( tt );
                                draw->AddText( wpos + ImVec2( xo + x, yoff + ty05 ), 0x66FFFFFF, txt );
                                tw = ImGui::CalcTextSize( txt ).x;
                            }

                            iter = ( iter + 1 ) % 10;
                            x += sdx;
                            tt += sstep;
                        }
                    }

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                    {
                        const auto ltmin = log10( tmin );
                        const auto ltmax = log10( tmax );

                        auto& io = ImGui::GetIO();
                        DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, dpos.y ), ImVec2( io.MousePos.x + 0.5f, dpos.y+Height-2 ), 0x33FFFFFF );

                        const auto bin = int64_t( io.MousePos.x - wpos.x - 2 );
                        int64_t t0, t1;
                        if( m_compare.logTime )
                        {
                            t0 = int64_t( pow( 10, ltmin + double( bin )   / numBins * ( ltmax - ltmin ) ) );
                            t1 = int64_t( pow( 10, ltmin + double( bin+1 ) / numBins * ( ltmax - ltmin ) ) );
                        }
                        else
                        {
                            t0 = int64_t( tmin + double( bin )   / numBins * ( tmax - tmin ) );
                            t1 = int64_t( tmin + double( bin+1 ) / numBins * ( tmax - tmin ) );
                        }

                        int64_t tBefore[2] = { 0, 0 };
                        for( int i=0; i<bin; i++ )
                        {
                            tBefore[0] += binTime[i].v0;
                            tBefore[1] += binTime[i].v1;
                        }

                        int64_t tAfter[2] = { 0, 0 };
                        for( int i=bin+1; i<numBins; i++ )
                        {
                            tAfter[0] += binTime[i].v0;
                            tAfter[1] += binTime[i].v1;
                        }

                        ImGui::BeginTooltip();
                        TextDisabledUnformatted( "Time range:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                        TextDisabledUnformatted( "Count:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", RealToString( floor( bins[bin].v0 ) ), RealToString( floor( bins[bin].v1 ) ) );
                        TextDisabledUnformatted( "Time spent in bin:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( binTime[bin].v0 ), TimeToString( binTime[bin].v1 ) );
                        TextDisabledUnformatted( "Time spent in the left bins:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( tBefore[0] ), TimeToString( tBefore[1] ) );
                        TextDisabledUnformatted( "Time spent in the right bins:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( tAfter[0] ), TimeToString( tAfter[1] ) );
                        TextDisabledUnformatted( "(Data is displayed as:" );
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "[this trace] /" );
                        ImGui::SameLine();
                        TextColoredUnformatted( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
                        TextDisabledUnformatted( "[external trace])" );
                        ImGui::EndTooltip();
                    }
                }
            }
        }
        ImGui::TreePop();
    }

    ImGui::EndChild();
#endif
    ImGui::End();
}

struct SrcLocZonesSlim
{
    int16_t srcloc;
    size_t numZones;
    int64_t total;
};

void View::AccumulationModeComboBox()
{
    ImGui::TextUnformatted( "Timing" );
    ImGui::SameLine();
    const char* accumulationModeTable = m_statMode == 1 ? "Self only\0With children\0" : "Self only\0With children\0Non-reentrant\0";
    ImGui::SetNextItemWidth( ImGui::CalcTextSize( "Non-reentrant" ).x + ImGui::GetTextLineHeight() * 2 );
    if( m_statMode == 1 && m_statAccumulationMode == AccumulationMode::NonReentrantChildren )
    {
        m_statAccumulationMode = AccumulationMode::SelfOnly;
    }
    int accumulationMode = static_cast<int>( m_statAccumulationMode );
    ImGui::Combo( "##accumulationMode", &accumulationMode, accumulationModeTable );
    m_statAccumulationMode = static_cast<AccumulationMode>( accumulationMode );
}

void View::DrawStatistics()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 600 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Statistics", &m_showStatistics, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable statistics view." );
#else
    if( !m_worker.AreSourceLocationZonesReady() && ( !m_worker.AreCallstackSamplesReady() || m_worker.GetCallstackSampleCount() == 0 ) )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    ImGui::RadioButton( ICON_FA_SYRINGE " Instrumentation", &m_statMode, 0 );
    if( m_worker.AreCallstackSamplesReady() )
    {
        ImGui::SameLine();
        if( m_worker.GetCallstackSampleCount() > 0 )
        {
            ImGui::Spacing();
            ImGui::SameLine();
            ImGui::RadioButton( ICON_FA_EYE_DROPPER " Sampling", &m_statMode, 1 );
        }
        else if( m_worker.GetSymbolsCount() > 0 )
        {
            ImGui::Spacing();
            ImGui::SameLine();
            ImGui::RadioButton( ICON_FA_PUZZLE_PIECE " Symbols", &m_statMode, 1 );
        }
    }
    if( m_worker.GetGpuZoneCount() > 0 )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::RadioButton( ICON_FA_EYE " GPU", &m_statMode, 2 );
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();


    Vector<SrcLocZonesSlim> srcloc;

    if( m_statMode == 0 )
    {
        if( !m_worker.AreSourceLocationZonesReady() )
        {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::PopStyleVar();
            ImGui::TextWrapped( "Please wait, computing data..." );
            DrawWaitingDots( s_time );
            ImGui::End();
            return;
        }

        const auto filterActive = m_statisticsFilter.IsActive();
        auto& slz = m_worker.GetSourceLocationZones();
        srcloc.reserve( slz.size() );
        uint32_t slzcnt = 0;
        if( m_statRange.active )
        {
            const auto min = m_statRange.min;
            const auto max = m_statRange.max;
            const auto st = max - min;
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 && it->second.min <= st )
                {
                    if( !filterActive )
                    {
                        auto cit = m_statCache.find( it->first );
                        if( cit != m_statCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                        {
                            if( cit->second.count != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                            }
                        }
                        else
                        {
                            size_t cnt = 0;
                            int64_t total = 0;
                            for( auto& v : it->second.zones )
                            {
                                auto& z = *v.Zone();
                                const auto start = z.Start();
                                const auto end = z.End();
                                if( start >= min && end <= max )
                                {
                                    const auto zt = end - start;
                                    if( m_statAccumulationMode == AccumulationMode::SelfOnly )
                                    {
                                        total += zt - GetZoneChildTimeFast( z );
                                        cnt++;
                                    }
                                    else if( m_statAccumulationMode == AccumulationMode::AllChildren || !IsZoneReentry( z ) )
                                    {
                                        total += zt;
                                        cnt++;
                                    }
                                }
                            }
                            if( cnt != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                            }
                            m_statCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                        }
                    }
                    else
                    {
                        slzcnt++;
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            auto cit = m_statCache.find( it->first );
                            if( cit != m_statCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                            {
                                if( cit->second.count != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                                }
                            }
                            else
                            {
                                size_t cnt = 0;
                                int64_t total = 0;
                                for( auto& v : it->second.zones )
                                {
                                    auto& z = *v.Zone();
                                    const auto start = z.Start();
                                    const auto end = z.End();
                                    if( start >= min && end <= max )
                                    {
                                        const auto zt = end - start;
                                        if( m_statAccumulationMode == AccumulationMode::SelfOnly )
                                        {
                                            total += zt - GetZoneChildTimeFast( z );
                                            cnt++;
                                        }
                                        else if( m_statAccumulationMode == AccumulationMode::AllChildren || !IsZoneReentry( z ) )
                                        {
                                            total += zt;
                                            cnt++;
                                        }
                                    }
                                }
                                if( cnt != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                                }
                                m_statCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                            }
                        }
                    }
                }
            }
        }
        else
        {
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 )
                {
                    slzcnt++;
                    size_t count;
                    int64_t total;
                    switch( m_statAccumulationMode )
                    {
                    case AccumulationMode::SelfOnly:
                        count = it->second.zones.size();
                        total = it->second.selfTotal;
                        break;
                    case AccumulationMode::AllChildren:
                        count = it->second.zones.size();
                        total = it->second.total;
                        break;
                    case AccumulationMode::NonReentrantChildren:
                        count = it->second.nonReentrantCount;
                        total = it->second.nonReentrantTotal;
                        break;
                    }
                    if( !filterActive )
                    {
                        srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                    }
                    else
                    {
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                        }
                    }
                }
            }
        }

        TextFocused( "Total zone count:", RealToString( slzcnt ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Visible zones:", RealToString( srcloc.size() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        AccumulationModeComboBox();
    }
    else if( m_statMode == 1 )
    {
        ImGui::Checkbox( ICON_FA_STOPWATCH " Show time", &m_statSampleTime );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( m_statRange.active )
        {
            ImGui::BeginDisabled();
            m_statAccumulationMode = AccumulationMode::SelfOnly;
            AccumulationModeComboBox();
            ImGui::EndDisabled();
        }
        else
        {
            AccumulationModeComboBox();
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_EYE_SLASH " Hide unknown", &m_statHideUnknown );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_PUZZLE_PIECE " Show all", &m_showAllSymbols );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_SITEMAP " Inlines", &m_statSeparateInlines );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_AT " Address", &m_statShowAddress );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::TextUnformatted( "Location:" );
        ImGui::SameLine();
        const char* locationTable = "Entry\0Sample\0Smart\0";
        ImGui::SetNextItemWidth( ImGui::CalcTextSize( "Sample" ).x + ImGui::GetTextLineHeight() * 2 );
        ImGui::Combo( "##location", &m_statSampleLocation, locationTable );
    }
    else
    {
        assert( m_statMode == 2 );
        if( !m_worker.AreGpuSourceLocationZonesReady() )
        {
            ImGui::Spacing();
            ImGui::Separator();
            ImGui::PopStyleVar();
            ImGui::TextWrapped( "Please wait, computing data..." );
            DrawWaitingDots( s_time );
            ImGui::End();
            return;
        }

        const auto filterActive = m_statisticsFilter.IsActive();
        auto& slz = m_worker.GetGpuSourceLocationZones();
        srcloc.reserve( slz.size() );
        uint32_t slzcnt = 0;
        if( m_statRange.active )
        {
            const auto min = m_statRange.min;
            const auto max = m_statRange.max;
            const auto st = max - min;
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 && it->second.min <= st )
                {
                    if( !filterActive )
                    {
                        auto cit = m_gpuStatCache.find( it->first );
                        if( cit != m_gpuStatCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                        {
                            if( cit->second.count != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                            }
                        }
                        else
                        {
                            size_t cnt = 0;
                            int64_t total = 0;
                            for( auto& v : it->second.zones )
                            {
                                auto& z = *v.Zone();
                                const auto start = z.GpuStart();
                                const auto end = z.GpuEnd();
                                if( start >= min && end <= max )
                                {
                                    const auto zt = end - start;
                                    total += zt;
                                    cnt++;
                                }
                            }
                            if( cnt != 0 )
                            {
                                slzcnt++;
                                srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                            }
                            m_gpuStatCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                        }
                    }
                    else
                    {
                        slzcnt++;
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            auto cit = m_gpuStatCache.find( it->first );
                            if( cit != m_gpuStatCache.end() && cit->second.range == m_statRange && cit->second.accumulationMode == m_statAccumulationMode && cit->second.sourceCount == it->second.zones.size() )
                            {
                                if( cit->second.count != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cit->second.count, cit->second.total } );
                                }
                            }
                            else
                            {
                                size_t cnt = 0;
                                int64_t total = 0;
                                for( auto& v : it->second.zones )
                                {
                                    auto& z = *v.Zone();
                                    const auto start = z.GpuStart();
                                    const auto end = z.GpuEnd();
                                    if( start >= min && end <= max )
                                    {
                                        const auto zt = end - start;
                                        total += zt;
                                        cnt++;
                                    }
                                }
                                if( cnt != 0 )
                                {
                                    srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, cnt, total } );
                                }
                                m_gpuStatCache[it->first] = StatisticsCache { RangeSlim { m_statRange.min, m_statRange.max, m_statRange.active }, m_statAccumulationMode, it->second.zones.size(), cnt, total };
                            }
                        }
                    }
                }
            }
        }
        else
        {
            for( auto it = slz.begin(); it != slz.end(); ++it )
            {
                if( it->second.total != 0 )
                {
                    slzcnt++;
                    size_t count = it->second.zones.size();
                    int64_t total = it->second.total;
                    if( !filterActive )
                    {
                        srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                    }
                    else
                    {
                        auto& sl = m_worker.GetSourceLocation( it->first );
                        auto name = m_worker.GetString( sl.name.active ? sl.name : sl.function );
                        if( m_statisticsFilter.PassFilter( name ) )
                        {
                            srcloc.push_back_no_space_check( SrcLocZonesSlim { it->first, count, total } );
                        }
                    }
                }
            }
        }

        TextFocused( "Total zone count:", RealToString( slzcnt ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Visible zones:", RealToString( srcloc.size() ) );
    }

    ImGui::Separator();
    ImGui::AlignTextToFramePadding();
    TextDisabledUnformatted( "Filter results" );
    ImGui::SameLine();
    m_statisticsFilter.Draw( ICON_FA_FILTER "###resultFilter", 200 );
    ImGui::SameLine();
    if( ImGui::Button( ICON_FA_BACKSPACE " Clear" ) )
    {
        m_statisticsFilter.Clear();
    }
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    if( m_statMode == 1 )
    {
        TextDisabledUnformatted( "Image name" );
        ImGui::SameLine();
        m_statisticsImageFilter.Draw( ICON_FA_FILTER "###imageFilter", 200 );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "###imageCombo", nullptr, ImGuiComboFlags_NoPreview | ImGuiComboFlags_HeightLarge ) )
        {
            unordered_flat_set<StringIdx, StringIdxHasher, StringIdxComparator> set;
            std::vector<const char*> imgNames;
            for( auto& v : m_worker.GetSymbolMap() )
            {
                auto it = set.find( v.second.imageName );
                if( it == set.end() )
                {
                    set.emplace( v.second.imageName );
                }
            }
            imgNames.reserve( set.size() );
            for( auto& img : set )
            {
                imgNames.emplace_back( m_worker.GetString( img ) );
            }
            std::sort( imgNames.begin(), imgNames.end(), [] ( const auto& lhs, const auto& rhs ) { return strcmp( lhs, rhs ) < 0; } );
            for( auto& img : imgNames )
            {
                bool sel = false;
                if( ImGui::Selectable( img, &sel ) )
                {
                    auto len = std::min<size_t>( 255, strlen( img ) );
                    memcpy( m_statisticsImageFilter.InputBuf, img, len );
                    m_statisticsImageFilter.InputBuf[len] = 0;
                    m_statisticsImageFilter.Build();
                }
            }
            ImGui::EndCombo();
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_BACKSPACE " Clear###image" ) )
        {
            m_statisticsImageFilter.Clear();
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        ImGui::Checkbox( ICON_FA_HAT_WIZARD " Include kernel", &m_statShowKernel );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
    }
    if( m_statMode == 1 && !m_worker.AreSymbolSamplesReady() )
    {
        m_statRange.active = false;
        bool val = false;
        ImGui::PushItemFlag( ImGuiItemFlags_Disabled, true );
        ImGui::PushStyleVar( ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f );
        ImGui::Checkbox( "Limit range", &val );
        ImGui::PopItemFlag();
        ImGui::PopStyleVar();
        TooltipIfHovered( "Waiting for background tasks to finish" );
    }
    else
    {
        if( ImGui::Checkbox( "Limit range", &m_statRange.active ) )
        {
            if( m_statRange.active && m_statRange.min == 0 && m_statRange.max == 0 )
            {
                m_statRange.min = m_vd.zvStart;
                m_statRange.max = m_vd.zvEnd;
            }
        }
        if( m_statRange.active )
        {
            ImGui::SameLine();
            TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
            ImGui::SameLine();
            ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
        }
    }

    ImGui::Separator();
    ImGui::PopStyleVar();

    int64_t timeRange;
    if( m_statRange.active )
    {
        const auto st = m_statRange.max - m_statRange.min;
        timeRange = st == 0 ? 1 : st;
    }
    else
    {
        timeRange = m_worker.GetLastTime();
    }

    if( m_statMode == 0 || m_statMode == 2 )
    {
        if( srcloc.empty() )
        {
            ImGui::TextUnformatted( "No entries to be displayed." );
        }
        else
        {
            ImGui::BeginChild( "##statistics" );
            if( ImGui::BeginTable( "##statistics", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY ) )
            {
                ImGui::TableSetupScrollFreeze( 0, 1 );
                ImGui::TableSetupColumn( "Name", ImGuiTableColumnFlags_NoHide );
                ImGui::TableSetupColumn( "Location", ImGuiTableColumnFlags_NoSort );
                ImGui::TableSetupColumn( "Total time", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableSetupColumn( "Counts", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableSetupColumn( "MTPC", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
                ImGui::TableHeadersRow();

                const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
                switch( sortspec.ColumnIndex )
                {
                case 0:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), [this]( const auto& lhs, const auto& rhs ) { return strcmp( m_worker.GetZoneName( m_worker.GetSourceLocation( lhs.srcloc ) ), m_worker.GetZoneName( m_worker.GetSourceLocation( rhs.srcloc ) ) ) < 0; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), [this]( const auto& lhs, const auto& rhs ) { return strcmp( m_worker.GetZoneName( m_worker.GetSourceLocation( lhs.srcloc ) ), m_worker.GetZoneName( m_worker.GetSourceLocation( rhs.srcloc ) ) ) > 0; } );
                    }
                    break;
                case 2:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total < rhs.total; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total > rhs.total; } );
                    }
                    break;
                case 3:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.numZones < rhs.numZones; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.numZones > rhs.numZones; } );
                    }
                    break;
                case 4:
                    if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total / lhs.numZones < rhs.total / rhs.numZones; } );
                    }
                    else
                    {
                        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs.total / lhs.numZones > rhs.total / rhs.numZones; } );
                    }
                    break;
                default:
                    assert( false );
                    break;
                }

                for( auto& v : srcloc )
                {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();

                    ImGui::PushID( v.srcloc );
                    auto& srcloc = m_worker.GetSourceLocation( v.srcloc );
                    auto name = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
                    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
                    ImGui::SameLine();
                    if( m_statMode == 0 )
                    {
                        if( ImGui::Selectable( name, m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == v.srcloc, ImGuiSelectableFlags_SpanAllColumns ) )
                        {
                            m_findZone.ShowZone( v.srcloc, name );
                        }
                    }
                    else
                    {
                        ImGui::TextUnformatted( name );
                    }
                    ImGui::TableNextColumn();
                    float indentVal = 0.f;
                    if( m_statBuzzAnim.Match( v.srcloc ) )
                    {
                        const auto time = m_statBuzzAnim.Time();
                        indentVal = sin( time * 60.f ) * 10.f * time;
                        ImGui::Indent( indentVal );
                    }
                    const auto file = m_worker.GetString( srcloc.file );

                    TextDisabledUnformatted( LocationToString( file, srcloc.line ) );
                    if( ImGui::IsItemHovered() )
                    {
                        DrawSourceTooltip( file, srcloc.line );
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( SourceFileValid( file, m_worker.GetCaptureTime(), *this, m_worker ) )
                            {
                                ViewSource( file, srcloc.line );
                            }
                            else
                            {
                                m_statBuzzAnim.Enable( v.srcloc, 0.5f );
                            }
                        }
                    }
                    if( indentVal != 0.f )
                    {
                        ImGui::Unindent( indentVal );
                    }
                    ImGui::TableNextColumn();
                    const auto time = v.total;
                    ImGui::TextUnformatted( TimeToString( time ) );
                    ImGui::SameLine();
                    char buf[64];
                    PrintStringPercent( buf, 100. * time / timeRange );
                    TextDisabledUnformatted( buf );
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted( RealToString( v.numZones ) );
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted( TimeToString( time / v.numZones ) );
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();
        }
    }
    else
    {
        assert( m_statMode == 1 );
        const auto& symMap = m_worker.GetSymbolMap();
        const auto& symStat = m_worker.GetSymbolStats();

        Vector<SymList> data;
        if( m_showAllSymbols )
        {
            data.reserve( symMap.size() );
            if( m_statisticsFilter.IsActive() || m_statisticsImageFilter.IsActive() || !m_statShowKernel )
            {
                for( auto& v : symMap )
                {
                    const auto name = m_worker.GetString( v.second.name );
                    const auto image = m_worker.GetString( v.second.imageName );
                    bool pass = ( m_statShowKernel || ( v.first >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( name ) && m_statisticsImageFilter.PassFilter( image );
                    if( !pass && v.second.size.Val() == 0 )
                    {
                        const auto parentAddr = m_worker.GetSymbolForAddress( v.first );
                        if( parentAddr != 0 )
                        {
                            auto pit = symMap.find( parentAddr );
                            if( pit != symMap.end() )
                            {
                                const auto parentName = m_worker.GetString( pit->second.name );
                                pass = ( m_statShowKernel || ( parentAddr >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( parentName ) && m_statisticsImageFilter.PassFilter( image );
                            }
                        }
                    }
                    if( pass )
                    {
                        auto it = symStat.find( v.first );
                        if( it == symStat.end() )
                        {
                            data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                        }
                        else
                        {
                            if( m_statRange.active )
                            {
                                auto samples = m_worker.GetSamplesForSymbol( v.first );
                                if( samples )
                                {
                                    auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                    if( it != samples->end() )
                                    {
                                        auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                        const auto count = uint32_t( end - it );
                                        data.push_back_no_space_check( SymList { v.first, 0, count } );
                                    }
                                    else
                                    {
                                        data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                                    }
                                }
                                else
                                {
                                    data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                                }
                            }
                            else
                            {
                                data.push_back_no_space_check( SymList { v.first, it->second.incl, it->second.excl } );
                            }
                        }
                    }
                }
            }
            else
            {
                for( auto& v : symMap )
                {
                    auto it = symStat.find( v.first );
                    if( it == symStat.end() )
                    {
                        data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                    }
                    else
                    {
                        if( m_statRange.active )
                        {
                            auto samples = m_worker.GetSamplesForSymbol( v.first );
                            if( samples )
                            {
                                auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                if( it != samples->end() )
                                {
                                    auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                    const auto count = uint32_t( end - it );
                                    data.push_back_no_space_check( SymList { v.first, 0, count } );
                                }
                                else
                                {
                                    data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                                }
                            }
                            else
                            {
                                data.push_back_no_space_check( SymList { v.first, 0, 0 } );
                            }
                        }
                        else
                        {
                            data.push_back_no_space_check( SymList { v.first, it->second.incl, it->second.excl } );
                        }
                    }
                }
            }
        }
        else
        {
            data.reserve( symStat.size() );
            if( m_statisticsFilter.IsActive() || m_statisticsImageFilter.IsActive() || !m_statShowKernel )
            {
                for( auto& v : symStat )
                {
                    auto sit = symMap.find( v.first );
                    if( sit != symMap.end() )
                    {
                        const auto name = m_worker.GetString( sit->second.name );
                        const auto image = m_worker.GetString( sit->second.imageName );
                        bool pass = ( m_statShowKernel || ( v.first >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( name ) && m_statisticsImageFilter.PassFilter( image );
                        if( !pass && sit->second.size.Val() == 0 )
                        {
                            const auto parentAddr = m_worker.GetSymbolForAddress( v.first );
                            if( parentAddr != 0 )
                            {
                                auto pit = symMap.find( parentAddr );
                                if( pit != symMap.end() )
                                {
                                    const auto parentName = m_worker.GetString( pit->second.name );
                                    pass = ( m_statShowKernel || ( parentAddr >> 63 ) == 0 ) && m_statisticsFilter.PassFilter( parentName ) && m_statisticsImageFilter.PassFilter( image );
                                }
                            }
                        }
                        if( pass )
                        {
                            if( m_statRange.active )
                            {
                                auto samples = m_worker.GetSamplesForSymbol( v.first );
                                if( samples )
                                {
                                    auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                    if( it != samples->end() )
                                    {
                                        auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                        const auto count = uint32_t( end - it );
                                        data.push_back_no_space_check( SymList { v.first, 0, count } );
                                    }
                                }
                            }
                            else
                            {
                                data.push_back_no_space_check( SymList { v.first, v.second.incl, v.second.excl } );
                            }
                        }
                    }
                }
            }
            else
            {
                if( m_statRange.active )
                {
                    for( auto& v : symStat )
                    {
                        auto samples = m_worker.GetSamplesForSymbol( v.first );
                        if( samples )
                        {
                            auto it = std::lower_bound( samples->begin(), samples->end(), m_statRange.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                            if( it != samples->end() )
                            {
                                auto end = std::lower_bound( it, samples->end(), m_statRange.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
                                const auto count = uint32_t( end - it );
                                data.push_back_no_space_check( SymList { v.first, 0, count } );
                            }
                        }
                    }
                }
                else
                {
                    for( auto& v : symStat )
                    {
                        data.push_back_no_space_check( SymList { v.first, v.second.incl, v.second.excl } );
                    }
                }
            }
        }

        DrawSamplesStatistics(data, timeRange, m_statAccumulationMode);
    }
#endif
    ImGui::End();
}


void View::DrawSamplesStatistics(Vector<SymList>& data, int64_t timeRange, AccumulationMode accumulationMode)
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

void View::DrawCallstackWindow()
{
    bool show = true;
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Call stack", &show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        DrawCallstackTable( m_callstackInfoWindow, true );
    }
    ImGui::End();
    if( !show ) m_callstackInfoWindow = 0;
}

void View::DrawCallstackTable( uint32_t callstack, bool globalEntriesButton )
{
    auto& cs = m_worker.GetCallstack( callstack );
    if( ClipboardButton() )
    {
        std::ostringstream s;
        int fidx = 0;
        int bidx = 0;
        for( auto& entry : cs )
        {
            char buf[64*1024];
            auto frameData = m_worker.GetCallstackFrame( entry );
            if( !frameData )
            {
                sprintf( buf, "%3i. %p\n", fidx++, (void*)m_worker.GetCanonicalPointer( entry ) );
            }
            else
            {
                auto ptr = buf;
                const auto fsz = frameData->size;
                for( uint8_t f=0; f<fsz; f++ )
                {
                    const auto& frame = frameData->data[f];
                    auto txt = m_worker.GetString( frame.name );

                    if( fidx == 0 && f != fsz-1 )
                    {
                        auto test = tracy::s_tracyStackFrames;
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

                    if( f == fsz-1 )
                    {
                        ptr += sprintf( ptr, "%3i. ", fidx++ );
                    }
                    else
                    {
                        ptr += sprintf( ptr, "inl. " );
                    }
                    ptr += sprintf( ptr, "%s  ", txt );
                    txt = m_worker.GetString( frame.file );
                    if( frame.line == 0 )
                    {
                        ptr += sprintf( ptr, "(%s)", txt );
                    }
                    else
                    {
                        ptr += sprintf( ptr, "(%s:%" PRIu32 ")", txt, frame.line );
                    }
                    if( frameData->imageName.Active() )
                    {
                        ptr += sprintf( ptr, " %s\n", m_worker.GetString( frameData->imageName ) );
                    }
                    else
                    {
                        ptr += sprintf( ptr, "\n" );
                    }
                }
            }
            s << buf;
        }
        ImGui::SetClipboardText( s.str().c_str() );
    }
    ImGui::SameLine();
    ImGui::TextUnformatted( ICON_FA_AT " Frame location:" );
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::RadioButton( "Source code", &m_showCallstackFrameAddress, 0 );
    ImGui::SameLine();
    ImGui::RadioButton( "Entry point", &m_showCallstackFrameAddress, 3 );
    ImGui::SameLine();
    ImGui::RadioButton( "Return address", &m_showCallstackFrameAddress, 1 );
    ImGui::SameLine();
    ImGui::RadioButton( "Symbol address", &m_showCallstackFrameAddress, 2 );

    if( globalEntriesButton && m_worker.AreCallstackSamplesReady() )
    {
        auto frame = m_worker.GetCallstackFrame( *cs.begin() );
        if( frame && frame->data[0].symAddr != 0 )
        {
            auto sym = m_worker.GetSymbolStats( frame->data[0].symAddr );
            if( sym && !sym->parents.empty() )
            {
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( ImGui::Button( ICON_FA_DOOR_OPEN " Global entry statistics" ) )
                {
                    ShowSampleParents( frame->data[0].symAddr, true );
                }
            }
        }
    }
    ImGui::PopStyleVar();

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
            auto frameData = m_worker.GetCallstackFrame( entry );
            if( !frameData )
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::Text( "%i", fidx++ );
                ImGui::TableNextColumn();
                char buf[32];
                sprintf( buf, "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
                ImGui::TextUnformatted( buf );
                if( ImGui::IsItemClicked() )
                {
                    ImGui::SetClipboardText( buf );
                }
            }
            else
            {
                const auto fsz = frameData->size;
                for( uint8_t f=0; f<fsz; f++ )
                {
                    const auto& frame = frameData->data[f];
                    auto txt = m_worker.GetString( frame.name );

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

                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    bidx++;
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
                    if( m_callstackBuzzAnim.Match( bidx ) )
                    {
                        const auto time = m_callstackBuzzAnim.Time();
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
                            ImGui::SetClipboardText( LocationToString( txt, frame.line ) );
                        }
                        break;
                    case 1:
                        if( entry.sel == 0 )
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
                            ImGui::TextDisabled( "Custom #%" PRIu64, entry.idx );
                        }
                        break;
                    case 2:
                        if( entry.sel == 0 )
                        {
                            ImGui::TextDisabled( "0x%" PRIx64, frame.symAddr );
                            if( ImGui::IsItemClicked() )
                            {
                                char tmp[32];
                                sprintf( tmp, "0x%" PRIx64, frame.symAddr );
                                ImGui::SetClipboardText( tmp );
                            }
                        }
                        else
                        {
                            ImGui::TextDisabled( "Custom #%" PRIu64, entry.idx );
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
                                        m_callstackBuzzAnim.Enable( bidx, 0.5f );
                                    }
                                }
                                else
                                {
                                    m_callstackBuzzAnim.Enable( bidx, 0.5f );
                                }
                            }
                            else
                            {
                                if( !ViewDispatch( txt, frame.line, frame.symAddr ) )
                                {
                                    m_callstackBuzzAnim.Enable( bidx, 0.5f );
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
        }
        ImGui::EndTable();
    }
}

void View::DrawMemoryAllocWindow()
{
    bool show = true;
    ImGui::Begin( "Memory allocation", &show, ImGuiWindowFlags_AlwaysAutoResize );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        const auto& mem = m_worker.GetMemoryNamed( m_memoryAllocInfoPool );
        const auto& ev = mem.data[m_memoryAllocInfoWindow];
        const auto tidAlloc = m_worker.DecompressThread( ev.ThreadAlloc() );
        const auto tidFree = m_worker.DecompressThread( ev.ThreadFree() );
        int idx = 0;

        if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to allocation" ) )
        {
            ZoomToRange( ev.TimeAlloc(), ev.TimeFree() >= 0 ? ev.TimeFree() : m_worker.GetLastTime() );
        }

        if( m_worker.GetMemNameMap().size() > 1 )
        {
            TextFocused( ICON_FA_ARCHIVE " Pool:", m_memoryAllocInfoPool == 0 ? "Default allocator" : m_worker.GetString( m_memoryAllocInfoPool ) );
        }
        char buf[64];
        sprintf( buf, "0x%" PRIx64, ev.Ptr() );
        TextFocused( "Address:", buf );
        TextFocused( "Size:", MemSizeToString( ev.Size() ) );
        if( ev.Size() >= 10000ll )
        {
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s bytes)", RealToString( ev.Size() ) );
        }
        ImGui::Separator();
        TextFocused( "Appeared at", TimeToStringExact( ev.TimeAlloc() ) );
        if( ImGui::IsItemClicked() ) CenterAtTime( ev.TimeAlloc() );
        ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
        SmallColorBox( GetThreadColor( tidAlloc, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( tidAlloc ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( tidAlloc ) );
        if( m_worker.IsThreadFiber( tidAlloc ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        if( ev.CsAlloc() != 0 )
        {
            const auto cs = ev.CsAlloc();
            SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
            ImGui::SameLine();
            DrawCallstackCalls( cs, 2 );
        }
        if( ev.TimeFree() < 0 )
        {
            TextDisabledUnformatted( "Allocation still active" );
        }
        else
        {
            TextFocused( "Freed at", TimeToStringExact( ev.TimeFree() ) );
            if( ImGui::IsItemClicked() ) CenterAtTime( ev.TimeFree() );
            ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
            SmallColorBox( GetThreadColor( tidFree, 0 ) );
            ImGui::SameLine();
            TextFocused( "Thread:", m_worker.GetThreadName( tidFree ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( tidFree ) );
            if( m_worker.IsThreadFiber( tidFree ) )
            {
                ImGui::SameLine();
                TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
            }
            if( ev.csFree.Val() != 0 )
            {
                const auto cs = ev.csFree.Val();
                SmallCallstackButton( ICON_FA_ALIGN_JUSTIFY, cs, idx );
                ImGui::SameLine();
                DrawCallstackCalls( cs, 2 );
            }
            TextFocused( "Duration:", TimeToString( ev.TimeFree() - ev.TimeAlloc() ) );
        }

        bool sep = false;
        auto zoneAlloc = FindZoneAtTime( tidAlloc, ev.TimeAlloc() );
        if( zoneAlloc )
        {
            ImGui::Separator();
            sep = true;
            const auto& srcloc = m_worker.GetSourceLocation( zoneAlloc->SrcLoc() );
            const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
            ImGui::PushID( idx++ );
            TextFocused( "Zone alloc:", txt );
            auto hover = ImGui::IsItemHovered();
            ImGui::PopID();
            if( ImGui::IsItemClicked() )
            {
                ShowZoneInfo( *zoneAlloc );
            }
            if( hover )
            {
                m_zoneHighlight = zoneAlloc;
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *zoneAlloc );
                }
                ZoneTooltip( *zoneAlloc );
            }
        }

        if( ev.TimeFree() >= 0 )
        {
            auto zoneFree = FindZoneAtTime( tidFree, ev.TimeFree() );
            if( zoneFree )
            {
                if( !sep ) ImGui::Separator();
                const auto& srcloc = m_worker.GetSourceLocation( zoneFree->SrcLoc() );
                const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                TextFocused( "Zone free:", txt );
                auto hover = ImGui::IsItemHovered();
                if( ImGui::IsItemClicked() )
                {
                    ShowZoneInfo( *zoneFree );
                }
                if( hover )
                {
                    m_zoneHighlight = zoneFree;
                    if( IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( *zoneFree );
                    }
                    ZoneTooltip( *zoneFree );
                }
                if( zoneAlloc != 0 && zoneAlloc == zoneFree )
                {
                    ImGui::SameLine();
                    TextDisabledUnformatted( "(same zone)" );
                }
            }
        }
    }
    ImGui::End();
    if( !show ) m_memoryAllocInfoWindow = -1;
}

void View::DrawInfo()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 400 * scale, 650 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Trace information", &m_showInfo, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }
    ImGui::PushFont( m_bigFont );
    TextFocused( "Program:", m_worker.GetCaptureProgram().c_str() );
    ImGui::PopFont();
    const auto exectime = m_worker.GetExecutableTime();
    if( exectime != 0 )
    {
        char etmp[64];
        time_t et = exectime;
        auto elt = localtime( &et );
        strftime( etmp, 64, "%F %T", elt );
        TextFocused( "Build time:", etmp );
    }
    {
        char dtmp[64];
        time_t date = m_worker.GetCaptureTime();
        auto lt = localtime( &date );
        strftime( dtmp, 64, "%F %T", lt );
        TextFocused( "Capture time:", dtmp );
    }
    if( !m_filename.empty() )
    {
        TextFocused( "File:", m_filename.c_str() );
        if( m_userData.Valid() )
        {
            const auto save = m_userData.GetConfigLocation();
            if( save )
            {
                ImGui::SameLine();
                if( ImGui::SmallButton( ICON_FA_FOLDER ) )
                {
                    ImGui::SetClipboardText( save );
                }
                TooltipIfHovered( "Copy user settings location to clipboard." );
            }
        }
    }
    {
        const auto& desc = m_userData.GetDescription();
        const auto descsz = std::min<size_t>( 255, desc.size() );
        char buf[256];
        buf[descsz] = '\0';
        memcpy( buf, desc.c_str(), descsz );
        ImGui::SetNextItemWidth( -1 );
        if( ImGui::InputTextWithHint( "##traceDesc", "Enter description of the trace", buf, 256 ) )
        {
            m_userData.SetDescription( buf );
        }
    }

    ImGui::Separator();
    ImGui::BeginChild( "##info" );

    const auto ficnt = m_worker.GetFrameImageCount();
    if( ImGui::TreeNode( "Trace statistics" ) )
    {
        ImGui::TextDisabled( "Trace version:" );
        ImGui::SameLine();
        const auto version = m_worker.GetTraceVersion();
        ImGui::Text( "%i.%i.%i", version >> 16, ( version >> 8 ) & 0xFF, version & 0xFF );
        TextFocused( "Queue delay:", TimeToString( m_worker.GetDelay() ) );
        TextFocused( "Timer resolution:", TimeToString( m_worker.GetResolution() ) );
        TextFocused( "CPU zones:", RealToString( m_worker.GetZoneCount() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Extra data:", RealToString( m_worker.GetZoneExtraCount() ) );
        TooltipIfHovered( "Count of zones containing any of the following: call stack trace, custom name, user text" );
        TextFocused( "GPU zones:", RealToString( m_worker.GetGpuZoneCount() ) );
        TextFocused( "Lock events:", RealToString( m_worker.GetLockCount() ) );
        TextFocused( "Plot data points:", RealToString( m_worker.GetPlotCount() ) );
        TooltipIfHovered( "User plots" );
        ImGui::SameLine();
        TextFocused( "+", RealToString( m_worker.GetTracyPlotCount() ) );
        TooltipIfHovered( "Automated Tracy plots" );
        auto& memNameMap = m_worker.GetMemNameMap();
        TextFocused( "Memory pools:", RealToString( memNameMap.size() ) );
        uint64_t memTotalCnt = 0;
        for( auto v : memNameMap ) memTotalCnt += v.second->data.size();
        TextFocused( "Memory allocations:", RealToString( memTotalCnt ) );
        TextFocused( "Source locations:", RealToString( m_worker.GetSrcLocCount() ) );
        TextFocused( "Strings:", RealToString( m_worker.GetStringsCount() ) );
        TextFocused( "Symbols:", RealToString( m_worker.GetSymbolsCount() ) );
        TextFocused( "Symbol code fragments:", RealToString( m_worker.GetSymbolCodeCount() ) );
        TooltipIfHovered( MemSizeToString( m_worker.GetSymbolCodeSize() ) );
        TextFocused( "Code locations:", RealToString( m_worker.GetCodeLocationsSize() ) );
        TextFocused( "Call stacks:", RealToString( m_worker.GetCallstackPayloadCount() ) );
        if( m_worker.AreCallstackSamplesReady() )
        {
            ImGui::SameLine();
            TextFocused( "+", RealToString( m_worker.GetCallstackParentPayloadCount() ) );
            TooltipIfHovered( "Parent call stacks for stack samples" );
        }
        TextFocused( "Call stack frames:", RealToString( m_worker.GetCallstackFrameCount() ) );
        if( m_worker.AreCallstackSamplesReady() )
        {
            ImGui::SameLine();
            TextFocused( "+", RealToString( m_worker.GetCallstackParentFrameCount() ) );
            TooltipIfHovered( "Parent call stack frames for stack samples" );
        }
        TextFocused( "Call stack samples:", RealToString( m_worker.GetCallstackSampleCount() ) );
        TextFocused( "Ghost zones:", RealToString( m_worker.GetGhostZonesCount() ) );
#ifndef TRACY_NO_STATISTICS
        TextFocused( "Child sample symbols:", RealToString( m_worker.GetChildSamplesCountSyms() ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Child samples:", RealToString( m_worker.GetChildSamplesCountFull() ) );
            ImGui::EndTooltip();
        }
        TextFocused( "Context switch samples:", RealToString( m_worker.GetContextSwitchSampleCount() ) );
#endif
        TextFocused( "Hardware samples:", RealToString( m_worker.GetHwSampleCount() ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Unique addresses:", RealToString( m_worker.GetHwSampleCountAddress() ) );
            ImGui::EndTooltip();
        }
        TextFocused( "Frame images:", RealToString( ficnt ) );
        if( ficnt != 0 && ImGui::IsItemHovered() )
        {
            const auto bytes = m_worker.GetTextureCompressionBytes();
            ImGui::BeginTooltip();
            TextFocused( "Input data:", MemSizeToString( bytes.first ) );
            TextFocused( "Compressed:", MemSizeToString( bytes.second ) );
            char buf[64];
            auto ptr = PrintFloat( buf, buf+62, 100. * bytes.second / bytes.first, 2 );
            memcpy( ptr, "%", 2 );
            TextFocused( "Ratio:", buf );
            ImGui::EndTooltip();
        }
        TextFocused( "Context switch regions:", RealToString( m_worker.GetContextSwitchCount() ) );
        TooltipIfHovered( "Detailed context switch data regarding application threads" );
        ImGui::SameLine();
        TextFocused( "+", RealToString( m_worker.GetContextSwitchPerCpuCount() ) );
        TooltipIfHovered( "Coarse CPU core context switch data" );
        if( m_worker.GetSourceFileCacheCount() == 0 )
        {
            TextFocused( "Source file cache:", "0" );
        }
        else
        {
            ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
            const bool expand = ImGui::TreeNode( "Source file cache:" );
            ImGui::PopStyleColor();
            ImGui::SameLine();
            ImGui::TextUnformatted( RealToString( m_worker.GetSourceFileCacheCount() ) );
            TooltipIfHovered( MemSizeToString( m_worker.GetSourceFileCacheSize() ) );
            if( expand )
            {
                auto& cache = m_worker.GetSourceFileCache();
                std::vector<decltype(cache.begin())> vec;
                vec.reserve( cache.size() );
                for( auto it = cache.begin(); it != cache.end(); ++it ) vec.emplace_back( it );
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& lhs, const auto& rhs ) { return strcmp( lhs->first, rhs->first ) < 0; } );
                for( auto& v : vec )
                {
                    ImGui::BulletText( "%s", v->first );
                    if( ImGui::IsItemClicked() ) ViewSource( v->first, 0 );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%s)", MemSizeToString( v->second.len ) );
                }
                ImGui::TreePop();
            }
        }
        ImGui::TreePop();
    }

    if( ImGui::TreeNode( "Frame statistics" ) )
    {
        auto fsz = m_worker.GetFullFrameCount( *m_frames );
        if( fsz != 0 )
        {
            TextFocused( "Frame set:", m_frames->name == 0 ? "Frames" : m_worker.GetString( m_frames->name ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", m_frames->continuous ? "continuous" : "discontinuous" );
            ImGui::SameLine();
            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
            if( ImGui::BeginCombo( "##frameCombo", nullptr, ImGuiComboFlags_NoPreview ) )
            {
                auto& frames = m_worker.GetFrames();
                for( auto& fd : frames )
                {
                    bool isSelected = m_frames == fd;
                    if( ImGui::Selectable( fd->name == 0 ? "Frames" : m_worker.GetString( fd->name ), isSelected ) )
                    {
                        m_frames = fd;
                        fsz = m_worker.GetFullFrameCount( *m_frames );
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
            ImGui::PopStyleVar();
            ImGui::SameLine();
            SmallCheckbox( "Limit to view", &m_frameSortData.limitToView );
            if( m_frameSortData.limitToView )
            {
                ImGui::SameLine();
                TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
            }

            const auto frameRange = m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvEnd );
            if( m_frameSortData.frameSet != m_frames || ( m_frameSortData.limitToView && m_frameSortData.limitRange != frameRange ) || ( !m_frameSortData.limitToView && m_frameSortData.limitRange.first != -1 ) )
            {
                m_frameSortData.frameSet = m_frames;
                m_frameSortData.frameNum = 0;
                m_frameSortData.data.clear();
                m_frameSortData.total = 0;
            }
            bool recalc = false;
            int64_t total = 0;
            if( !m_frameSortData.limitToView )
            {
                if( m_frameSortData.frameNum != fsz || m_frameSortData.limitRange.first != -1 )
                {
                    auto& vec = m_frameSortData.data;
                    vec.reserve( fsz );
                    const auto midSz = vec.size();
                    total = m_frameSortData.total;
                    for( size_t i=m_frameSortData.frameNum; i<fsz; i++ )
                    {
                        const auto t = m_worker.GetFrameTime( *m_frames, i );
                        if( t > 0 )
                        {
                            vec.emplace_back( t );
                            total += t;
                        }
                    }
                    auto mid = vec.begin() + midSz;
                    pdqsort_branchless( mid, vec.end() );
                    std::inplace_merge( vec.begin(), mid, vec.end() );
                    recalc = true;
                    m_frameSortData.limitRange.first = -1;
                }
            }
            else
            {
                if( m_frameSortData.limitRange != frameRange )
                {
                    auto& vec = m_frameSortData.data;
                    assert( vec.empty() );
                    vec.reserve( frameRange.second - frameRange.first );
                    for( int i=frameRange.first; i<frameRange.second; i++ )
                    {
                        const auto t = m_worker.GetFrameTime( *m_frames, i );
                        if( t > 0 )
                        {
                            vec.emplace_back( t );
                            total += t;
                        }
                    }
                    pdqsort_branchless( vec.begin(), vec.end() );
                    recalc = true;
                    m_frameSortData.limitRange = frameRange;
                }
            }
            if( recalc )
            {
                auto& vec = m_frameSortData.data;
                const auto vsz = vec.size();
                m_frameSortData.average = float( total ) / vsz;
                m_frameSortData.median = vec[vsz/2];
                m_frameSortData.total = total;
                m_frameSortData.frameNum = fsz;
            }

            const auto profileSpan = m_worker.GetLastTime();
            TextFocused( "Count:", RealToString( fsz ) );
            TextFocused( "Total time:", TimeToString( m_frameSortData.total ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of profile time span)", m_frameSortData.total / float( profileSpan ) * 100.f );
            TextFocused( "Mean frame time:", TimeToString( m_frameSortData.average ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.average ) ) );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.average ) );
                ImGui::EndTooltip();
            }
            TextFocused( "Median frame time:", TimeToString( m_frameSortData.median ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.median ) ) );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.median ) );
                ImGui::EndTooltip();
            }

            if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
            {
                const auto ty = ImGui::GetTextLineHeight();

                auto& frames = m_frameSortData.data;
                auto tmin = frames.front();
                auto tmax = frames.back();

                if( tmin != std::numeric_limits<int64_t>::max() )
                {
                    TextDisabledUnformatted( "Minimum values in bin:" );
                    ImGui::SameLine();
                    ImGui::SetNextItemWidth( ImGui::CalcTextSize( "123456890123456" ).x );
                    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 1, 1 ) );
                    ImGui::InputInt( "##minBinVal", &m_frameSortData.minBinVal );
                    if( m_frameSortData.minBinVal < 1 ) m_frameSortData.minBinVal = 1;
                    ImGui::SameLine();
                    if( ImGui::Button( "Reset" ) ) m_frameSortData.minBinVal = 1;
                    ImGui::PopStyleVar();

                    SmallCheckbox( "Log values", &m_frameSortData.logVal );
                    ImGui::SameLine();
                    SmallCheckbox( "Log time", &m_frameSortData.logTime );

                    TextDisabledUnformatted( "FPS range:" );
                    ImGui::SameLine();
                    ImGui::Text( "%s FPS - %s FPS", RealToString( round( 1000000000.0 / tmin ) ), RealToString( round( 1000000000.0 / tmax ) ) );

                    if( tmax - tmin > 0 )
                    {
                        const auto w = ImGui::GetContentRegionAvail().x;

                        const auto numBins = int64_t( w - 4 );
                        if( numBins > 1 )
                        {
                            if( numBins > m_frameSortData.numBins )
                            {
                                m_frameSortData.numBins = numBins;
                                m_frameSortData.bins = std::make_unique<int64_t[]>( numBins );
                            }

                            const auto& bins = m_frameSortData.bins;

                            memset( bins.get(), 0, sizeof( int64_t ) * numBins );

                            auto framesBegin = frames.begin();
                            auto framesEnd = frames.end();
                            while( framesBegin != framesEnd && *framesBegin == 0 ) ++framesBegin;

                            if( m_frameSortData.minBinVal > 1 )
                            {
                                if( m_frameSortData.logTime )
                                {
                                    const auto tMinLog = log10( tmin );
                                    const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                    int64_t i;
                                    for( i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( framesBegin, nit );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesBegin = nit;
                                    }
                                    for( int64_t j=numBins-1; j>i; j-- )
                                    {
                                        const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( j-1 ) * zmax ) );
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( nit, framesEnd );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesEnd = nit;
                                    }
                                }
                                else
                                {
                                    const auto zmax = tmax - tmin;
                                    int64_t i;
                                    for( i=0; i<numBins; i++ )
                                    {
                                        const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( framesBegin, nit );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesBegin = nit;
                                    }
                                    for( int64_t j=numBins-1; j>i; j-- )
                                    {
                                        const auto nextBinVal = tmin + ( j-1 ) * zmax / numBins;
                                        auto nit = std::lower_bound( framesBegin, framesEnd, nextBinVal );
                                        const auto distance = std::distance( nit, framesEnd );
                                        if( distance >= m_frameSortData.minBinVal ) break;
                                        framesEnd = nit;
                                    }
                                }

                                tmin = *framesBegin;
                                tmax = *(framesEnd-1);
                            }

                            if( m_frameSortData.logTime )
                            {
                                const auto tMinLog = log10( tmin );
                                const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                                auto fit = framesBegin;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                    auto nit = std::lower_bound( fit, framesEnd, nextBinVal );
                                    bins[i] = std::distance( fit, nit );
                                    fit = nit;
                                }
                                bins[numBins-1] += std::distance( fit, framesEnd );
                            }
                            else
                            {
                                const auto zmax = tmax - tmin;
                                auto fit = framesBegin;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
                                    auto nit = std::lower_bound( fit, framesEnd, nextBinVal );
                                    bins[i] = std::distance( fit, nit );
                                    fit = nit;
                                }
                                bins[numBins-1] += std::distance( fit, framesEnd );
                            }

                            int64_t maxVal = bins[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( maxVal, bins[i] );
                            }

                            TextFocused( "Max counts:", RealToString( maxVal ) );

                            ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
                            ImGui::Checkbox( "###draw1", &m_frameSortData.drawAvgMed );
                            ImGui::SameLine();
                            ImGui::ColorButton( "c1", ImVec4( 0xFF/255.f, 0x44/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( "Mean time" );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0x88/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( "Median time" );
                            ImGui::PopStyleVar();

                            const auto Height = 200 * scale;
                            const auto wpos = ImGui::GetCursorScreenPos();
                            const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

                            ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 2.5 ) ) );
                            const bool hover = ImGui::IsItemHovered();

                            auto draw = ImGui::GetWindowDrawList();
                            draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x22FFFFFF );
                            draw->AddRect( wpos, wpos + ImVec2( w, Height ), 0x88FFFFFF );

                            if( m_frameSortData.logVal )
                            {
                                const auto hAdj = double( Height - 4 ) / log10( maxVal + 1 );
                                for( int i=0; i<numBins; i++ )
                                {
                                    const auto val = bins[i];
                                    if( val > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFF22DDDD );
                                    }
                                }
                            }
                            else
                            {
                                const auto hAdj = double( Height - 4 ) / maxVal;
                                for( int i=0; i<numBins; i++ )
                                {
                                    const auto val = bins[i];
                                    if( val > 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( 2+i, Height-3 ), dpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                    }
                                }
                            }

                            const auto xoff = 2;
                            const auto yoff = Height + 1;

                            DrawHistogramMinMaxLabel( draw, tmin, tmax, wpos + ImVec2( 0, yoff ), w, ty );

                            const auto ty05 = round( ty * 0.5f );
                            const auto ty025 = round( ty * 0.25f );
                            if( m_frameSortData.logTime )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );
                                const auto start = int( floor( ltmin ) );
                                const auto end = int( ceil( ltmax ) );

                                const auto range = ltmax - ltmin;
                                const auto step = w / range;
                                auto offset = start - ltmin;
                                int tw = 0;
                                int tx = 0;

                                auto tt = int64_t( pow( 10, start ) );

                                static const double logticks[] = { log10( 2 ), log10( 3 ), log10( 4 ), log10( 5 ), log10( 6 ), log10( 7 ), log10( 8 ), log10( 9 ) };

                                for( int i=start; i<=end; i++ )
                                {
                                    const auto x = ( i - start + offset ) * step;

                                    if( x >= 0 )
                                    {
                                        DrawLine( draw, dpos + ImVec2( x, yoff ), dpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF );
                                        if( tw == 0 || x > tx + tw + ty * 1.1 )
                                        {
                                            tx = x;
                                            auto txt = TimeToString( tt );
                                            draw->AddText( wpos + ImVec2( x, yoff + ty05 ), 0x66FFFFFF, txt );
                                            tw = ImGui::CalcTextSize( txt ).x;
                                        }
                                    }

                                    for( int j=0; j<8; j++ )
                                    {
                                        const auto xoff = x + logticks[j] * step;
                                        if( xoff >= 0 )
                                        {
                                            DrawLine( draw, dpos + ImVec2( xoff, yoff ), dpos + ImVec2( xoff, yoff + ty025 ), 0x66FFFFFF );
                                        }
                                    }

                                    tt *= 10;
                                }
                            }
                            else
                            {
                                const auto pxns = numBins / double( tmax - tmin );
                                const auto nspx = 1.0 / pxns;
                                const auto scale = std::max<float>( 0.0f, round( log10( nspx ) + 2 ) );
                                const auto step = pow( 10, scale );

                                const auto dx = step * pxns;
                                double x = 0;
                                int tw = 0;
                                int tx = 0;

                                const auto sstep = step / 10.0;
                                const auto sdx = dx / 10.0;

                                static const double linelen[] = { 0.5, 0.25, 0.25, 0.25, 0.25, 0.375, 0.25, 0.25, 0.25, 0.25 };

                                int64_t tt = int64_t( ceil( tmin / sstep ) * sstep );
                                const auto diff = tmin / sstep - int64_t( tmin / sstep );
                                const auto xo = ( diff == 0 ? 0 : ( ( 1 - diff ) * sstep * pxns ) ) + xoff;
                                int iter = int( ceil( ( tmin - int64_t( tmin / step ) * step ) / sstep ) );

                                while( x < numBins )
                                {
                                    DrawLine( draw, dpos + ImVec2( xo + x, yoff ), dpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                    if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                    {
                                        tx = x;
                                        auto txt = TimeToString( tt );
                                        draw->AddText( wpos + ImVec2( xo + x, yoff + ty05 ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }

                                    iter = ( iter + 1 ) % 10;
                                    x += sdx;
                                    tt += sstep;
                                }
                            }

                            if( m_frameSortData.drawAvgMed )
                            {
                                float ta, tm;
                                if( m_frameSortData.logTime )
                                {
                                    const auto ltmin = log10( tmin );
                                    const auto ltmax = log10( tmax );

                                    ta = ( log10( m_frameSortData.average ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                    tm = ( log10( m_frameSortData.median ) - ltmin ) / float( ltmax - ltmin ) * numBins;
                                }
                                else
                                {
                                    ta = ( m_frameSortData.average - tmin ) / float( tmax - tmin ) * numBins;
                                    tm = ( m_frameSortData.median - tmin ) / float( tmax - tmin ) * numBins;
                                }
                                ta = round( ta );
                                tm = round( tm );

                                if( ta == tm )
                                {
                                    DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFFFF88FF );
                                }
                                else
                                {
                                    DrawLine( draw, ImVec2( dpos.x + ta, dpos.y ), ImVec2( dpos.x + ta, dpos.y+Height-2 ), 0xFF4444FF );
                                    DrawLine( draw, ImVec2( dpos.x + tm, dpos.y ), ImVec2( dpos.x + tm, dpos.y+Height-2 ), 0xFFFF8844 );
                                }
                            }

                            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                            {
                                const auto ltmin = log10( tmin );
                                const auto ltmax = log10( tmax );

                                auto& io = ImGui::GetIO();
                                DrawLine( draw, ImVec2( io.MousePos.x + 0.5f, dpos.y ), ImVec2( io.MousePos.x + 0.5f, dpos.y+Height-2 ), 0x33FFFFFF );

                                const auto bin = int64_t( io.MousePos.x - wpos.x - 2 );
                                int64_t t0, t1;
                                if( m_frameSortData.logTime )
                                {
                                    t0 = int64_t( pow( 10, ltmin + double( bin ) / numBins * ( ltmax - ltmin ) ) );

                                    // Hackfix for inability to select data in last bin.
                                    // A proper solution would be nice.
                                    if( bin+1 == numBins )
                                    {
                                        t1 = tmax;
                                    }
                                    else
                                    {
                                        t1 = int64_t( pow( 10, ltmin + double( bin+1 ) / numBins * ( ltmax - ltmin ) ) );
                                    }
                                }
                                else
                                {
                                    t0 = int64_t( tmin + double( bin )   / numBins * ( tmax - tmin ) );
                                    t1 = int64_t( tmin + double( bin+1 ) / numBins * ( tmax - tmin ) );
                                }

                                ImGui::BeginTooltip();
                                TextDisabledUnformatted( "Time range:" );
                                ImGui::SameLine();
                                ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s FPS - %s FPS)", RealToString( round( 1000000000.0 / t0 ) ), RealToString( round( 1000000000.0 / t1 ) ) );
                                TextFocused( "Count:", RealToString( bins[bin] ) );
                                ImGui::EndTooltip();
                            }

                            if( m_frameHover != -1 )
                            {
                                const auto frameTime = m_worker.GetFrameTime( *m_frames, m_frameHover );
                                float framePos;
                                if( m_frameSortData.logTime )
                                {
                                    const auto ltmin = log10( tmin );
                                    const auto ltmax = log10( tmax );
                                    framePos = round( ( log10( frameTime ) - ltmin ) / float( ltmax - ltmin ) * numBins );
                                }
                                else
                                {
                                    framePos = round( ( frameTime - tmin ) / float( tmax - tmin ) * numBins );
                                }
                                const auto c = uint32_t( ( sin( s_time * 10 ) * 0.25 + 0.75 ) * 255 );
                                const auto color = 0xFF000000 | ( c << 16 ) | ( c << 8 ) | c;
                                DrawLine( draw, ImVec2( dpos.x + framePos, dpos.y ), ImVec2( dpos.x + framePos, dpos.y+Height-2 ), color );
                            }
                        }
                    }
                }

                ImGui::TreePop();
            }
        }
        ImGui::TreePop();
    }

    auto& topology = m_worker.GetCpuTopology();
    if( !topology.empty() )
    {
        if( ImGui::TreeNode( "CPU topology" ) )
        {
            char buf[128];

            const auto ty = ImGui::GetFontSize();
            ImGui::PushFont( m_smallFont );
            const auto sty = ImGui::GetFontSize();
            ImGui::PopFont();
            const float margin = round( ty * 0.5 );
            const float small = round( sty * 0.5 );

            std::vector<int> maxthreads( topology.size() );

            float ptsz = 0;
            float ctsz = 0;
            float ttsz = 0;
            for( auto& package : topology )
            {
                sprintf( buf, ICON_FA_BOX " Package %" PRIu32, package.first );
                ImGui::PushFont( m_smallFont );
                const auto psz = ImGui::CalcTextSize( buf ).x;
                if( psz > ptsz ) ptsz = psz;
                ImGui::PopFont();

                size_t mt = 0;
                for( auto& core : package.second )
                {
                    sprintf( buf, ICON_FA_MICROCHIP "%" PRIu32, core.first );
                    const auto csz = ImGui::CalcTextSize( buf ).x;
                    if( csz > ctsz ) ctsz = csz;

                    const auto tnum = core.second.size();
                    if( tnum > mt ) mt = tnum;

                    for( auto& thread : core.second )
                    {
                        sprintf( buf, ICON_FA_RANDOM "%" PRIu32, thread );
                        const auto tsz = ImGui::CalcTextSize( buf ).x;
                        if( tsz > ttsz ) ttsz = tsz;
                    }
                }
                maxthreads[package.first] = (int)mt;
            }

            const auto remainingWidth = ImGui::GetContentRegionAvail().x;
            auto dpos = ImGui::GetCursorScreenPos() + ImVec2( margin, 0 );
            const auto draw = ImGui::GetWindowDrawList();

            float width = 0;
            float origy = dpos.y;

            std::vector<decltype(topology.begin())> tsort;
            tsort.reserve( topology.size() );
            for( auto it = topology.begin(); it != topology.end(); ++it ) tsort.emplace_back( it );
            std::sort( tsort.begin(), tsort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
            for( auto& package : tsort )
            {
                if( package->first != 0 ) dpos.y += ty;
                sprintf( buf, ICON_FA_BOX " Package %" PRIu32, package->first );
                draw->AddText( dpos, 0xFFFFFFFF, buf );
                dpos.y += ty;

                const auto inCoreWidth = ( ttsz + margin ) * maxthreads[package->first];
                const auto coreWidth = inCoreWidth + 2 * margin;
                const auto inCoreHeight = margin + 2 * small + ty;
                const auto coreHeight = inCoreHeight + ty;
                const auto cpl = std::max( 1, (int)floor( ( remainingWidth - 2 * margin ) / coreWidth ) );
                const auto cl = ( package->second.size() + cpl - 1 ) / cpl;
                const auto pw = cpl * coreWidth + 2 * margin;
                const auto ph = margin + cl * coreHeight;
                if( pw > width ) width = pw;

                draw->AddRect( dpos, dpos + ImVec2( margin + coreWidth * std::min<size_t>( cpl, package->second.size() ), ph ), 0xFFFFFFFF );

                std::vector<decltype(package->second.begin())> csort;
                csort.reserve( package->second.size() );
                for( auto it = package->second.begin(); it != package->second.end(); ++it ) csort.emplace_back( it );
                std::sort( csort.begin(), csort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
                auto cpos = dpos + ImVec2( margin, margin );
                int ll = cpl;
                for( auto& core : csort )
                {
                    sprintf( buf, ICON_FA_MICROCHIP "%" PRIu32, core->first );
                    draw->AddText( cpos, 0xFFFFFFFF, buf );
                    draw->AddRect( cpos + ImVec2( 0, ty ), cpos + ImVec2( inCoreWidth + small, inCoreHeight + small ), 0xFFFFFFFF );

                    for( int i=0; i<core->second.size(); i++ )
                    {
                        sprintf( buf, ICON_FA_RANDOM "%" PRIu32, core->second[i] );
                        draw->AddText( cpos + ImVec2( margin + i * ( margin + ttsz ), ty + small ), 0xFFFFFFFF, buf );
                    }

                    if( --ll == 0 )
                    {
                        ll = cpl;
                        cpos.x -= (cpl-1) * coreWidth;
                        cpos.y += coreHeight;
                    }
                    else
                    {
                        cpos.x += coreWidth;
                    }
                }
                dpos.y += ph;
            }
            ImGui::ItemSize( ImVec2( width, dpos.y - origy ) );
            ImGui::TreePop();
        }
    }

    if( ImGui::TreeNode( "Source location substitutions" ) )
    {
        static char test[1024] = {};
        ImGui::SetNextItemWidth( -1 );
        ImGui::InputTextWithHint( "##srcSubstTest", "Enter example source location to test substitutions", test, 1024 );
        if( m_sourceRegexValid )
        {
            TextFocused( "Result:", SourceSubstitution( test ) );
        }
        else
        {
            ImGui::TextColored( ImVec4( 255, 0, 0, 255 ), "Error in regular expression" );
        }
        if( ImGui::SmallButton( "Add new substitution" ) ) m_sourceSubstitutions.emplace_back( SourceRegex {} );
        int idx = 0, remove = -1;
        bool changed = false;
        ImGui::Columns( 2, nullptr, false );
        for( auto& v : m_sourceSubstitutions )
        {
            ImGui::PushID( idx );
            if( ImGui::Button( ICON_FA_TRASH_ALT ) ) remove = idx;
            ImGui::SameLine();
            char tmp[1024];
            strncpy( tmp, v.pattern.c_str(), 1024 );
            ImGui::SetNextItemWidth( -1 );
            if( ImGui::InputTextWithHint( "##pattern", "Regex pattern", tmp, 1024 ) )
            {
                v.pattern.assign( tmp );
                changed = true;
            }
            ImGui::NextColumn();
            strncpy( tmp, v.target.c_str(), 1024 );
            ImGui::SetNextItemWidth( -1 );
            if( ImGui::InputTextWithHint( "##replacement", "Regex replacement", tmp, 1024 ) ) v.target.assign( tmp );
            ImGui::PopID();
            ImGui::NextColumn();
            idx++;
        }
        ImGui::EndColumns();
        if( remove != -1 )
        {
            m_sourceSubstitutions.erase( m_sourceSubstitutions.begin() + remove );
            changed = true;
        }

        if( changed )
        {
            bool regexValid = true;
            for( auto& v : m_sourceSubstitutions )
            {
                try
                {
                    v.regex.assign( v.pattern );
                }
                catch( std::regex_error& err )
                {
                    regexValid = false;
                    break;
                }
            }
            m_sourceRegexValid = regexValid;
        }

        ImGui::TreePop();
    }

    ImGui::Separator();
    TextFocused( "PID:", RealToString( m_worker.GetPid() ) );
    TextFocused( "Host info:", m_worker.GetHostInfo().c_str() );

    const auto cpuId = m_worker.GetCpuId();
    if( cpuId != 0 )
    {
        const auto stepping = cpuId & 0xF;
        const auto baseModel = ( cpuId >> 4 ) & 0xF;
        const auto baseFamily = ( cpuId >> 8 ) & 0xF;
        const auto extModel = ( cpuId >> 12 ) & 0xF;
        const auto extFamily = ( cpuId >> 16 );

        const uint32_t model = ( baseFamily == 6 || baseFamily == 15 ) ? ( ( extModel << 4 ) | baseModel ) : baseModel;
        const uint32_t family = baseFamily == 15 ? baseFamily + extFamily : baseFamily;

        TextFocused( "CPU:", m_worker.GetCpuManufacturer() );
        ImGui::SameLine();
        TextFocused( "Family", RealToString( family ) );
        ImGui::SameLine();
        TextFocused( "Model", RealToString( model ) );
        ImGui::SameLine();
        TextFocused( "Stepping", RealToString( stepping ) );
    }

    auto& appInfo = m_worker.GetAppInfo();
    if( !appInfo.empty() )
    {
        ImGui::Separator();
        TextDisabledUnformatted( "Application info:" );
        for( auto& v : appInfo )
        {
            ImGui::TextUnformatted( m_worker.GetString( v ) );
        }
    }

    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread != 0 )
    {
        ImGui::Separator();
        TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Application has crashed. " ICON_FA_SKULL );
        TextFocused( "Time of crash:", TimeToString( crash.time ) );
        SmallColorBox( GetThreadColor( crash.thread, 0 ) );
        ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadName( crash.thread ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( crash.thread ) );
        if( m_worker.IsThreadFiber( crash.thread ) )
        {
            ImGui::SameLine();
            TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
        }
        TextDisabledUnformatted( "Reason:" );
        ImGui::SameLine();
        ImGui::TextWrapped( "%s", m_worker.GetString( crash.message ) );
        if( ImGui::Button( ICON_FA_MICROSCOPE " Focus" ) )
        {
            CenterAtTime( crash.time );
        }
        if( crash.callstack != 0 )
        {
            ImGui::SameLine();
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
    }

    ImGui::EndChild();
    ImGui::End();
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

void View::SetPlaybackFrame( uint32_t idx )
{
    const auto frameSet = m_worker.GetFramesBase();
    const auto& frameImages = m_worker.GetFrameImages();
    assert( idx < frameImages.size() );

    m_playback.frame = idx;

    if( idx == frameImages.size() - 1 )
    {
        m_playback.pause = true;
    }
    else
    {
        const auto t0 = m_worker.GetFrameBegin( *frameSet, frameImages[idx]->frameRef );
        const auto t1 = m_worker.GetFrameBegin( *frameSet, frameImages[idx+1]->frameRef );
        m_playback.timeLeft = ( t1 - t0 ) / 1000000000.f;
    }
}

static const char* PlaybackWindowButtons[] = {
    ICON_FA_PLAY " Play",
    ICON_FA_PAUSE " Pause",
};

enum { PlaybackWindowButtonsCount = sizeof( PlaybackWindowButtons ) / sizeof( *PlaybackWindowButtons ) };

void View::DrawPlayback()
{
    ImGui::Begin( "Playback", &m_showPlayback, ImGuiWindowFlags_AlwaysAutoResize );
    if( !m_showPlayback ) m_playback.pause = true;
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    const auto scale = GetScale();
    const auto frameSet = m_worker.GetFramesBase();
    const auto& frameImages = m_worker.GetFrameImages();
    const auto& fi = frameImages[m_playback.frame];
    const auto ficnt = m_worker.GetFrameImageCount();

    const auto tstart = m_worker.GetFrameBegin( *frameSet, fi->frameRef );

    if( !m_playback.texture )
    {
        m_playback.texture = MakeTexture();
    }
    if( m_playback.currFrame != m_playback.frame )
    {
        m_playback.currFrame = m_playback.frame;
        UpdateTexture( m_playback.texture, m_worker.UnpackFrameImage( *fi ), fi->w, fi->h );

        if( m_playback.sync )
        {
            const auto end = m_worker.GetFrameEnd( *frameSet, fi->frameRef );
            m_zoomAnim.active = false;
            m_vd.zvStart = tstart;
            m_vd.zvEnd = end;
            m_viewMode = ViewMode::Paused;
            m_viewModeHeuristicTry = false;
        }
    }

    if( !m_playback.pause )
    {
        auto time = ImGui::GetIO().DeltaTime * m_playback.speed;
        while( !m_playback.pause && time > 0 )
        {
            const auto dt = std::min( time, m_playback.timeLeft );
            time -= dt;
            m_playback.timeLeft -= dt;
            if( m_playback.timeLeft == 0 )
            {
                SetPlaybackFrame( m_playback.frame + 1 );
            }
        }
    }

    if( m_playback.zoom )
    {
        if( fi->flip )
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * 2 * scale, fi->h * 2 * scale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
        }
        else
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * 2 * scale, fi->h * 2 * scale ) );
        }
    }
    else
    {
        if( fi->flip )
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * scale, fi->h * scale ), ImVec2( 0, 1 ), ImVec2( 1, 0 ) );
        }
        else
        {
            ImGui::Image( m_playback.texture, ImVec2( fi->w * scale, fi->h * scale ) );
        }
    }
    const auto wheel = ImGui::GetIO().MouseWheel;
    bool changed = false;
    int tmp = m_playback.frame + 1;
    if( wheel && ImGui::IsItemHovered() )
    {
        tmp -= (int)wheel;
        changed = true;
    }
    changed |= ImGui::SliderInt( "Frame image", &tmp, 1, ficnt, "%d" );
    ImGui::SetItemUsingMouseWheel();
    if( wheel && ImGui::IsItemHovered() )
    {
        if( ImGui::IsItemActive() )
        {
            ImGui::ClearActiveID();
        }
        else
        {
            tmp -= (int)wheel;
            changed = true;
        }
    }
    if( changed )
    {
        if( tmp < 1 ) tmp = 1;
        else if( (uint32_t)tmp > ficnt ) tmp = ficnt;
        SetPlaybackFrame( uint32_t( tmp - 1 ) );
        m_playback.pause = true;
    }
    ImGui::SliderFloat( "Playback speed", &m_playback.speed, 0.1f, 4, "%.2f" );

    const auto th = ImGui::GetTextLineHeight();
    float bw = 0;
    for( int i=0; i<PlaybackWindowButtonsCount; i++ )
    {
        bw = std::max( bw, ImGui::CalcTextSize( PlaybackWindowButtons[i] ).x );
    }
    bw += th;

    if( ImGui::Button( " " ICON_FA_CARET_LEFT " " ) )
    {
        if( m_playback.frame > 0 )
        {
            SetPlaybackFrame( m_playback.frame - 1 );
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( ImGui::Button( " " ICON_FA_CARET_RIGHT " " ) )
    {
        if( m_playback.frame < ficnt - 1 )
        {
            SetPlaybackFrame( m_playback.frame + 1 );
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( m_playback.pause )
    {
        if( ImGui::Button( PlaybackWindowButtons[0], ImVec2( bw, 0 ) ) && m_playback.frame != frameImages.size() - 1 )
        {
            m_playback.pause = false;
        }
    }
    else
    {
        if( ImGui::Button( PlaybackWindowButtons[1], ImVec2( bw, 0 ) ) )
        {
            m_playback.pause = true;
        }
    }
    ImGui::SameLine();
    if( ImGui::Checkbox( "Sync timeline", &m_playback.sync ) )
    {
        if( m_playback.sync )
        {
            m_vd.zvStart = m_worker.GetFrameBegin( *frameSet, fi->frameRef );
            m_vd.zvEnd = m_worker.GetFrameEnd( *frameSet, fi->frameRef );
            m_zoomAnim.active = false;
            m_viewMode = ViewMode::Paused;
            m_viewModeHeuristicTry = false;
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox( "Zoom 2\xc3\x97", &m_playback.zoom );
    TextFocused( "Timestamp:", TimeToString( tstart ) );
    TooltipIfHovered( TimeToStringExact( tstart ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    TextFocused( "Frame:", RealToString( GetFrameNumber( *frameSet, fi->frameRef, m_worker.GetFrameOffset() ) ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    char buf[64];
    auto ptr = PrintFloat( buf, buf+62, 4.f * fi->csz / ( size_t( fi->w ) * size_t( fi->h ) / 2 ), 2 );
    memcpy( ptr, " bpp", 5 );
    TextFocused( "Ratio:", buf );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ptr = PrintFloat( buf, buf+62, 100.f * fi->csz / ( size_t( fi->w ) * size_t( fi->h ) / 2 ), 2 );
        memcpy( ptr, "%", 2 );
        ImGui::TextUnformatted( buf );
        ImGui::EndTooltip();
    }
    ImGui::End();
}

void View::DrawCpuDataWindow()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 700 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "CPU data", &m_showCpuDataWindow );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    struct PidData
    {
        std::vector<uint64_t> tids;
        CpuThreadData data;
    };

    const auto& ctd = m_worker.GetCpuThreadData();
    unordered_flat_map<uint64_t, PidData> pids;
    for( auto& v : ctd )
    {
        uint64_t pid = m_worker.GetPidFromTid( v.first );
        auto it = pids.find( pid );
        if( it == pids.end() )
        {
            it = pids.emplace( pid, PidData {} ).first;
        }
        it->second.tids.emplace_back( v.first );
        it->second.data.runningTime += v.second.runningTime;
        it->second.data.runningRegions += v.second.runningRegions;
        it->second.data.migrations += v.second.migrations;
    }

    TextFocused( "Tracked threads:", RealToString( ctd.size() ) );
    ImGui::SameLine();
    TextFocused( "Tracked processes:", RealToString( pids.size() ) );
    ImGui::Separator();
    ImGui::BeginChild( "##cpudata" );
    if( ImGui::BeginTable( "##cpudata", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "PID/TID", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "Name" );
        ImGui::TableSetupColumn( "Running time", ImGuiTableColumnFlags_PreferSortDescending );
        ImGui::TableSetupColumn( "Running regions", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableSetupColumn( "CPU migrations", ImGuiTableColumnFlags_PreferSortDescending | ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_NoResize );
        ImGui::TableHeadersRow();

        std::vector<unordered_flat_map<uint64_t, PidData>::iterator> psort;
        psort.reserve( pids.size() );
        for( auto it = pids.begin(); it != pids.end(); ++it ) psort.emplace_back( it );
        const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
        switch( sortspec.ColumnIndex )
        {
        case 0:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->first > r->first; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->first < r->first; } );
            }
            break;
        case 1:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l->second.tids[0] ).first, m_worker.GetExternalName( r->second.tids[0] ).first ) > 0; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l->second.tids[0] ).first, m_worker.GetExternalName( r->second.tids[0] ).first ) < 0; } );
            }
            break;
        case 2:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningTime > r->second.data.runningTime; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningTime < r->second.data.runningTime; } );
            }
            break;
        case 3:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningRegions > r->second.data.runningRegions; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.runningRegions < r->second.data.runningRegions; } );
            }
            break;
        case 4:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.migrations > r->second.data.migrations; } );
            }
            else
            {
                pdqsort_branchless( psort.begin(), psort.end(), [] ( const auto& l, const auto& r ) { return l->second.data.migrations < r->second.data.migrations; } );
            }
            break;
        default:
            assert( false );
            break;
        }

        const auto thisPid = m_worker.GetPid();
        const auto rtimespan = 1.0 / m_worker.GetLastTime();
        const auto ty = ImGui::GetTextLineHeight();

        auto& style = ImGui::GetStyle();
        const auto framePaddingY = style.FramePadding.y;
        for( auto& pidit : psort )
        {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();

            char buf[128];
            auto& pid = *pidit;
            const auto pidMatch = thisPid != 0 && thisPid == pid.first;
            auto name = m_worker.GetExternalName( pid.second.tids[0] ).first;
            if( pidMatch )
            {
                name = m_worker.GetCaptureProgram().c_str();
                ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0.2f, 1.0f, 0.2f, 1.0f ) );
            }
            const auto pidtxt = pid.first == 0 ? "Unknown" : RealToString( pid.first );
            const auto expand = ImGui::TreeNode( pidtxt );
            if( ImGui::IsItemHovered() )
            {
                if( pidMatch )
                {
                    m_drawThreadMigrations = pid.first;
                    m_cpuDataThread = pid.first;
                }
                m_drawThreadHighlight = pid.first;
            }
            const auto tsz = pid.second.tids.size();
            if( tsz > 1 )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( tsz ) );
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted( pid.first == 0 ? "???" : name );
            if( ImGui::IsItemHovered() )
            {
                if( pidMatch )
                {
                    m_drawThreadMigrations = pid.first;
                    m_cpuDataThread = pid.first;
                }
                m_drawThreadHighlight = pid.first;
            }
            ImGui::TableNextColumn();
            PrintStringPercent( buf, TimeToString( pid.second.data.runningTime ), double( pid.second.data.runningTime ) * rtimespan * 100 );
            style.FramePadding.y = 0;
            ImGui::ProgressBar( double( pid.second.data.runningTime ) * rtimespan, ImVec2( -1, ty ), buf );
            style.FramePadding.y = framePaddingY;
            ImGui::TableNextColumn();
            ImGui::TextUnformatted( RealToString( pid.second.data.runningRegions ) );
            ImGui::TableNextColumn();
            ImGui::TextUnformatted( RealToString( pid.second.data.migrations ) );
            ImGui::SameLine();
            PrintStringPercent( buf, double( pid.second.data.migrations ) / pid.second.data.runningRegions * 100 );
            TextDisabledUnformatted( buf );
            if( expand )
            {
                ImGui::Separator();
                switch( sortspec.ColumnIndex )
                {
                case 0:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), []( const auto& l, const auto& r ) { return l > r; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end() );
                    }
                    break;
                case 1:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l ).second, m_worker.GetExternalName( r ).second ) > 0; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [this] ( const auto& l, const auto& r ) { return strcmp( m_worker.GetExternalName( l ).second, m_worker.GetExternalName( r ).second ) < 0; } );
                    }
                    break;
                case 2:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningTime > ctd.find( r )->second.runningTime; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningTime < ctd.find( r )->second.runningTime; } );
                    }
                    break;
                case 3:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningRegions > ctd.find( r )->second.runningRegions; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.runningRegions < ctd.find( r )->second.runningRegions; } );
                    }
                    break;
                case 4:
                    if( sortspec.SortDirection == ImGuiSortDirection_Descending )
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.migrations > ctd.find( r )->second.migrations; } );
                    }
                    else
                    {
                        pdqsort_branchless( pid.second.tids.begin(), pid.second.tids.end(), [&ctd] ( const auto& l, const auto& r ) { return ctd.find( l )->second.migrations < ctd.find( r )->second.migrations; } );
                    }
                    break;
                default:
                    assert( false );
                    break;
                }
                for( auto& tid : pid.second.tids )
                {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();

                    const auto tidMatch = pidMatch && m_worker.IsThreadLocal( tid );
                    const char* tname;
                    if( tidMatch )
                    {
                        tname = m_worker.GetThreadName( tid );
                        ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.0f, 1.0f, 0.2f, 1.0f ) );
                    }
                    else
                    {
                        tname = m_worker.GetExternalName( tid ).second;
                    }
                    const auto& tit = ctd.find( tid );
                    assert( tit != ctd.end() );
                    ImGui::TextUnformatted( RealToString( tid ) );
                    if( ImGui::IsItemHovered() )
                    {
                        if( tidMatch )
                        {
                            m_drawThreadMigrations = tid;
                            m_cpuDataThread = tid;
                        }
                        m_drawThreadHighlight = tid;
                    }
                    ImGui::TableNextColumn();
                    if( tidMatch )
                    {
                        SmallColorBox( GetThreadColor( tid, 0 ) );
                        ImGui::SameLine();
                    }
                    ImGui::TextUnformatted( tname );
                    if( ImGui::IsItemHovered() )
                    {
                        if( tidMatch )
                        {
                            m_drawThreadMigrations = tid;
                            m_cpuDataThread = tid;
                        }
                        m_drawThreadHighlight = tid;
                    }
                    ImGui::TableNextColumn();
                    PrintStringPercent( buf, TimeToString( tit->second.runningTime ), double( tit->second.runningTime ) * rtimespan * 100 );
                    style.FramePadding.y = 0;
                    ImGui::ProgressBar( double( tit->second.runningTime ) * rtimespan, ImVec2( -1, ty ), buf );
                    style.FramePadding.y = framePaddingY;
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted( RealToString( tit->second.runningRegions ) );
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted( RealToString( tit->second.migrations ) );
                    ImGui::SameLine();
                    PrintStringPercent( buf, double( tit->second.migrations ) / tit->second.runningRegions * 100 );
                    TextDisabledUnformatted( buf );
                    if( tidMatch )
                    {
                        ImGui::PopStyleColor();
                    }
                }
                ImGui::TreePop();
                ImGui::Separator();
            }
            if( pidMatch )
            {
                ImGui::PopStyleColor();
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::End();
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

void View::ListMemData( std::vector<const MemEvent*>& vec, std::function<void(const MemEvent*)> DrawAddress, const char* id, int64_t startTime, uint64_t pool )
{
    if( startTime == -1 ) startTime = 0;
    if( ImGui::BeginTable( "##mem", 8, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY, ImVec2( 0, ImGui::GetTextLineHeightWithSpacing() * std::min<int64_t>( 1+vec.size(), 15 ) ) ) )
    {
        ImGui::TableSetupScrollFreeze( 0, 1 );
        ImGui::TableSetupColumn( "Address", ImGuiTableColumnFlags_NoHide );
        ImGui::TableSetupColumn( "Size", ImGuiTableColumnFlags_PreferSortDescending );
        ImGui::TableSetupColumn( "Appeared at", ImGuiTableColumnFlags_DefaultSort );
        ImGui::TableSetupColumn( "Duration", ImGuiTableColumnFlags_PreferSortDescending );
        ImGui::TableSetupColumn( "Thread", ImGuiTableColumnFlags_NoSort );
        ImGui::TableSetupColumn( "Zone alloc", ImGuiTableColumnFlags_NoSort );
        ImGui::TableSetupColumn( "Zone free", ImGuiTableColumnFlags_NoSort );
        ImGui::TableSetupColumn( "Call stack", ImGuiTableColumnFlags_NoSort );
        ImGui::TableHeadersRow();

        const auto& mem = m_worker.GetMemoryNamed( pool );
        const auto& sortspec = *ImGui::TableGetSortSpecs()->Specs;
        switch( sortspec.ColumnIndex )
        {
        case 0:
            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Ptr() < r->Ptr(); } );
            }
            else
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Ptr() > r->Ptr(); } );
            }
            break;
        case 1:
            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Size() < r->Size(); } );
            }
            else
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return l->Size() > r->Size(); } );
            }
            break;
        case 2:
            if( sortspec.SortDirection == ImGuiSortDirection_Descending )
            {
                std::reverse( vec.begin(), vec.end() );
            }
            break;
        case 3:
            if( sortspec.SortDirection == ImGuiSortDirection_Ascending )
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return ( l->TimeFree() - l->TimeAlloc() ) < ( r->TimeFree() - r->TimeAlloc() ); } );
            }
            else
            {
                pdqsort_branchless( vec.begin(), vec.end(), []( const auto& l, const auto& r ) { return ( l->TimeFree() - l->TimeAlloc() ) > ( r->TimeFree() - r->TimeAlloc() ); } );
            }
            break;
        default:
            assert( false );
            break;
        }

        int idx = 0;
        ImGuiListClipper clipper;
        clipper.Begin( vec.end() - vec.begin() );
        while( clipper.Step() )
        {
            for( auto i=clipper.DisplayStart; i<clipper.DisplayEnd; i++ )
            {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();

                auto v = vec[i];
                const auto arrIdx = std::distance( mem.data.begin(), v );

                if( m_memoryAllocInfoPool == pool && m_memoryAllocInfoWindow == arrIdx )
                {
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 0.f, 0.f, 1.f ) );
                    DrawAddress( v );
                    ImGui::PopStyleColor();
                }
                else
                {
                    DrawAddress( v );
                    if( ImGui::IsItemClicked() )
                    {
                        m_memoryAllocInfoWindow = arrIdx;
                        m_memoryAllocInfoPool = pool;
                    }
                }
                if( ImGui::IsItemClicked( 2 ) )
                {
                    ZoomToRange( v->TimeAlloc(), v->TimeFree() >= 0 ? v->TimeFree() : m_worker.GetLastTime() );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_memoryAllocHover = arrIdx;
                    m_memoryAllocHoverWait = 2;
                    m_memoryAllocHoverPool = pool;
                }
                ImGui::TableNextColumn();
                ImGui::TextUnformatted( MemSizeToString( v->Size() ) );
                ImGui::TableNextColumn();
                ImGui::PushID( idx++ );
                if( ImGui::Selectable( TimeToStringExact( v->TimeAlloc() - startTime ) ) )
                {
                    CenterAtTime( v->TimeAlloc() );
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                if( v->TimeFree() < 0 )
                {
                    TextColoredUnformatted( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), TimeToString( m_worker.GetLastTime() - v->TimeAlloc() ) );
                    ImGui::TableNextColumn();
                    const auto tid = m_worker.DecompressThread( v->ThreadAlloc() );
                    SmallColorBox( GetThreadColor( tid, 0 ) );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
                }
                else
                {
                    ImGui::PushID( idx++ );
                    if( ImGui::Selectable( TimeToString( v->TimeFree() - v->TimeAlloc() ) ) )
                    {
                        CenterAtTime( v->TimeFree() );
                    }
                    ImGui::PopID();
                    ImGui::TableNextColumn();
                    if( v->ThreadAlloc() == v->ThreadFree() )
                    {
                        const auto tid = m_worker.DecompressThread( v->ThreadAlloc() );
                        SmallColorBox( GetThreadColor( tid, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( tid ) );
                    }
                    else
                    {
                        const auto tidAlloc = m_worker.DecompressThread( v->ThreadAlloc() );
                        const auto tidFree = m_worker.DecompressThread( v->ThreadFree() );
                        SmallColorBox( GetThreadColor( tidAlloc, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( tidAlloc ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "/" );
                        ImGui::SameLine();
                        SmallColorBox( GetThreadColor( tidFree, 0 ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( m_worker.GetThreadName( tidFree ) );
                    }
                }
                ImGui::TableNextColumn();
                auto zone = FindZoneAtTime( m_worker.DecompressThread( v->ThreadAlloc() ), v->TimeAlloc() );
                if( !zone )
                {
                    ImGui::TextUnformatted( "-" );
                }
                else
                {
                    const auto& srcloc = m_worker.GetSourceLocation( zone->SrcLoc() );
                    const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                    ImGui::PushID( idx++ );
                    auto sel = ImGui::Selectable( txt, m_zoneInfoWindow == zone );
                    auto hover = ImGui::IsItemHovered();
                    ImGui::PopID();
                    if( sel )
                    {
                        ShowZoneInfo( *zone );
                    }
                    if( hover )
                    {
                        m_zoneHighlight = zone;
                        if( IsMouseClicked( 2 ) )
                        {
                            ZoomToZone( *zone );
                        }
                        ZoneTooltip( *zone );
                    }
                }
                ImGui::TableNextColumn();
                if( v->TimeFree() < 0 )
                {
                    TextColoredUnformatted( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "active" );
                }
                else
                {
                    auto zoneFree = FindZoneAtTime( m_worker.DecompressThread( v->ThreadFree() ), v->TimeFree() );
                    if( !zoneFree )
                    {
                        ImGui::TextUnformatted( "-" );
                    }
                    else
                    {
                        const auto& srcloc = m_worker.GetSourceLocation( zoneFree->SrcLoc() );
                        const auto txt = srcloc.name.active ? m_worker.GetString( srcloc.name ) : m_worker.GetString( srcloc.function );
                        ImGui::PushID( idx++ );
                        bool sel;
                        if( zoneFree == zone )
                        {
                            ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 1.f, 0.6f, 1.f ) );
                            sel = ImGui::Selectable( txt, m_zoneInfoWindow == zoneFree );
                            ImGui::PopStyleColor( 1 );
                        }
                        else
                        {
                            sel = ImGui::Selectable( txt, m_zoneInfoWindow == zoneFree );
                        }
                        auto hover = ImGui::IsItemHovered();
                        ImGui::PopID();
                        if( sel )
                        {
                            ShowZoneInfo( *zoneFree );
                        }
                        if( hover )
                        {
                            m_zoneHighlight = zoneFree;
                            if( IsMouseClicked( 2 ) )
                            {
                                ZoomToZone( *zoneFree );
                            }
                            ZoneTooltip( *zoneFree );
                        }
                    }
                }
                ImGui::TableNextColumn();
                if( v->CsAlloc() == 0 )
                {
                    TextDisabledUnformatted( "[alloc]" );
                }
                else
                {
                    SmallCallstackButton( "alloc", v->CsAlloc(), idx );
                }
                ImGui::SameLine();
                ImGui::Spacing();
                ImGui::SameLine();
                if( v->csFree.Val() == 0 )
                {
                    TextDisabledUnformatted( "[free]" );
                }
                else
                {
                    SmallCallstackButton( "free", v->csFree.Val(), idx );
                }
            }
        }
        ImGui::EndTable();
    }
}

template<class T>
static tracy_force_inline T* GetFrameTreeItemNoGroup( unordered_flat_map<uint64_t, T>& tree, CallstackFrameId idx, const Worker& worker )
{
    auto it = tree.find( idx.data );
    if( it == tree.end() )
    {
        it = tree.emplace( idx.data, T( idx ) ).first;
    }
    return &it->second;
}

template<class T>
static tracy_force_inline T* GetFrameTreeItemGroup( unordered_flat_map<uint64_t, T>& tree, CallstackFrameId idx, const Worker& worker )
{
    auto frameDataPtr = worker.GetCallstackFrame( idx );
    if( !frameDataPtr ) return nullptr;

    auto& frameData = *frameDataPtr;
    auto& frame = frameData.data[frameData.size-1];
    auto fidx = frame.name.Idx();

    auto it = tree.find( fidx );
    if( it == tree.end() )
    {
        it = tree.emplace( fidx, T( idx ) ).first;
    }
    return &it->second;
}

template<class T>
static tracy_force_inline T* GetParentFrameTreeItemGroup( unordered_flat_map<uint64_t, T>& tree, CallstackFrameId idx, const Worker& worker )
{
    auto frameDataPtr = idx.custom ? worker.GetParentCallstackFrame( idx ) : worker.GetCallstackFrame( idx );
    if( !frameDataPtr ) return nullptr;

    auto& frameData = *frameDataPtr;
    auto& frame = frameData.data[frameData.size-1];
    auto fidx = frame.name.Idx();

    auto it = tree.find( fidx );
    if( it == tree.end() )
    {
        it = tree.emplace( fidx, T( idx ) ).first;
    }
    return &it->second;
}


unordered_flat_map<uint32_t, View::MemPathData> View::GetCallstackPaths( const MemData& mem, MemRange memRange ) const
{
    unordered_flat_map<uint32_t, MemPathData> pathSum;
    pathSum.reserve( m_worker.GetCallstackPayloadCount() );

    if( m_memInfo.range.active )
    {
        auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
        if( it != mem.data.end() )
        {
            auto end = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.max, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
            if( memRange != MemRange::Full )
            {
                while( it != end )
                {
                    auto& ev = *it++;
                    if( ev.CsAlloc() == 0 ) continue;
                    if( ( memRange == MemRange::Inactive ) == ( ev.TimeFree() >= 0 && ev.TimeFree() < m_memInfo.range.max ) ) continue;
                    auto pit = pathSum.find( ev.CsAlloc() );
                    if( pit == pathSum.end() )
                    {
                        pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                    }
                    else
                    {
                        pit->second.cnt++;
                        pit->second.mem += ev.Size();
                    }
                }
            }
            else
            {
                while( it != end )
                {
                    auto& ev = *it++;
                    if( ev.CsAlloc() == 0 ) continue;
                    auto pit = pathSum.find( ev.CsAlloc() );
                    if( pit == pathSum.end() )
                    {
                        pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                    }
                    else
                    {
                        pit->second.cnt++;
                        pit->second.mem += ev.Size();
                    }
                }
            }
        }
    }
    else
    {
        if( memRange != MemRange::Full )
        {
            for( auto& ev : mem.data )
            {
                if( ev.CsAlloc() == 0 ) continue;
                if( ( memRange == MemRange::Inactive ) == ( ev.TimeFree() >= 0 ) ) continue;
                auto it = pathSum.find( ev.CsAlloc() );
                if( it == pathSum.end() )
                {
                    pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                }
                else
                {
                    it->second.cnt++;
                    it->second.mem += ev.Size();
                }
            }
        }
        else
        {
            for( auto& ev : mem.data )
            {
                if( ev.CsAlloc() == 0 ) continue;
                auto it = pathSum.find( ev.CsAlloc() );
                if( it == pathSum.end() )
                {
                    pathSum.emplace( ev.CsAlloc(), MemPathData { 1, ev.Size() } );
                }
                else
                {
                    it->second.cnt++;
                    it->second.mem += ev.Size();
                }
            }
        }
    }
    return pathSum;
}

unordered_flat_map<uint64_t, MemCallstackFrameTree> View::GetCallstackFrameTreeBottomUp( const MemData& mem ) const
{
    unordered_flat_map<uint64_t, MemCallstackFrameTree> root;
    auto pathSum = GetCallstackPaths( mem, m_memRangeBottomUp );
    if( m_groupCallstackTreeByNameBottomUp )
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
                for( int i = int( cs.size() ) - 2; i >= 0; i-- )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second.cnt;
                    treePtr->alloc += path.second.mem;
                    treePtr->callstacks.emplace( path.first );
                }
            }
        }
    }
    else
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemNoGroup( root, base, m_worker );
            treePtr->count += path.second.cnt;
            treePtr->alloc += path.second.mem;
            treePtr->callstacks.emplace( path.first );
            for( int i = int( cs.size() ) - 2; i >= 0; i-- )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i], m_worker );
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetCallstackFrameTreeBottomUp( const unordered_flat_map<uint32_t, uint64_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( int i = int( cs.size() ) - 2; i >= 0; i-- )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemNoGroup( root, base, m_worker );
            treePtr->count += path.second;
            for( int i = int( cs.size() ) - 2; i >= 0; i-- )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i], m_worker );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetParentsCallstackFrameTreeBottomUp( const unordered_flat_map<uint32_t, uint32_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetParentFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( int i = int( cs.size() ) - 2; i >= 0; i-- )
                {
                    treePtr = GetParentFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.back();
            auto treePtr = GetFrameTreeItemNoGroup( root, base, m_worker );
            treePtr->count += path.second;
            for( int i = int( cs.size() ) - 2; i >= 0; i-- )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i], m_worker );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}


unordered_flat_map<uint64_t, MemCallstackFrameTree> View::GetCallstackFrameTreeTopDown( const MemData& mem ) const
{
    unordered_flat_map<uint64_t, MemCallstackFrameTree> root;
    auto pathSum = GetCallstackPaths( mem, m_memRangeTopDown );
    if( m_groupCallstackTreeByNameTopDown )
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
                for( uint16_t i = 1; i < cs.size(); i++ )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second.cnt;
                    treePtr->alloc += path.second.mem;
                    treePtr->callstacks.emplace( path.first );
                }
            }
        }
    }
    else
    {
        for( auto& path : pathSum )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemNoGroup( root, base, m_worker );
            treePtr->count += path.second.cnt;
            treePtr->alloc += path.second.mem;
            treePtr->callstacks.emplace( path.first );
            for( uint16_t i = 1; i < cs.size(); i++ )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i], m_worker );
                treePtr->count += path.second.cnt;
                treePtr->alloc += path.second.mem;
                treePtr->callstacks.emplace( path.first );
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetCallstackFrameTreeTopDown( const unordered_flat_map<uint32_t, uint64_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( uint16_t i = 1; i < cs.size(); i++ )
                {
                    treePtr = GetFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemNoGroup( root, base, m_worker );
            treePtr->count += path.second;
            for( uint16_t i = 1; i < cs.size(); i++ )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i], m_worker );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}

unordered_flat_map<uint64_t, CallstackFrameTree> View::GetParentsCallstackFrameTreeTopDown( const unordered_flat_map<uint32_t, uint32_t>& stacks, bool group ) const
{
    unordered_flat_map<uint64_t, CallstackFrameTree> root;
    if( group )
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetParentFrameTreeItemGroup( root, base, m_worker );
            if( treePtr )
            {
                treePtr->count += path.second;
                for( uint16_t i = 1; i < cs.size(); i++ )
                {
                    treePtr = GetParentFrameTreeItemGroup( treePtr->children, cs[i], m_worker );
                    if( !treePtr ) break;
                    treePtr->count += path.second;
                }
            }
        }
    }
    else
    {
        for( auto& path : stacks )
        {
            auto& cs = m_worker.GetParentCallstack( path.first );
            auto base = cs.front();
            auto treePtr = GetFrameTreeItemNoGroup( root, base, m_worker );
            treePtr->count += path.second;
            for( uint16_t i = 1; i < cs.size(); i++ )
            {
                treePtr = GetFrameTreeItemNoGroup( treePtr->children, cs[i], m_worker );
                treePtr->count += path.second;
            }
        }
    }
    return root;
}


enum { ChunkBits = 10 };
enum { PageBits = 10 };
enum { PageSize = 1 << PageBits };
enum { PageChunkBits = ChunkBits + PageBits };
enum { PageChunkSize = 1 << PageChunkBits };

uint32_t MemDecayColor[256] = {
    0x0, 0xFF077F07, 0xFF078007, 0xFF078207, 0xFF078307, 0xFF078507, 0xFF078707, 0xFF078807,
    0xFF078A07, 0xFF078B07, 0xFF078D07, 0xFF078F07, 0xFF079007, 0xFF089208, 0xFF089308, 0xFF089508,
    0xFF089708, 0xFF089808, 0xFF089A08, 0xFF089B08, 0xFF089D08, 0xFF089F08, 0xFF08A008, 0xFF08A208,
    0xFF09A309, 0xFF09A509, 0xFF09A709, 0xFF09A809, 0xFF09AA09, 0xFF09AB09, 0xFF09AD09, 0xFF09AF09,
    0xFF09B009, 0xFF09B209, 0xFF09B309, 0xFF09B509, 0xFF0AB70A, 0xFF0AB80A, 0xFF0ABA0A, 0xFF0ABB0A,
    0xFF0ABD0A, 0xFF0ABF0A, 0xFF0AC00A, 0xFF0AC20A, 0xFF0AC30A, 0xFF0AC50A, 0xFF0AC70A, 0xFF0BC80B,
    0xFF0BCA0B, 0xFF0BCB0B, 0xFF0BCD0B, 0xFF0BCF0B, 0xFF0BD00B, 0xFF0BD20B, 0xFF0BD30B, 0xFF0BD50B,
    0xFF0BD70B, 0xFF0BD80B, 0xFF0BDA0B, 0xFF0CDB0C, 0xFF0CDD0C, 0xFF0CDF0C, 0xFF0CE00C, 0xFF0CE20C,
    0xFF0CE30C, 0xFF0CE50C, 0xFF0CE70C, 0xFF0CE80C, 0xFF0CEA0C, 0xFF0CEB0C, 0xFF0DED0D, 0xFF0DEF0D,
    0xFF0DF00D, 0xFF0DF20D, 0xFF0DF30D, 0xFF0DF50D, 0xFF0DF70D, 0xFF0DF80D, 0xFF0DFA0D, 0xFF0DFB0D,
    0xFF0DFD0D, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E,
    0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0EFF0E, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F,
    0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F, 0xFF0FFF0F,
    0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10,
    0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF10FF10, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11,
    0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF11FF11, 0xFF12FF12,
    0x0, 0xFF1212FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF,
    0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1111FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF,
    0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF, 0xFF1010FF,
    0xFF1010FF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF,
    0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0F0FFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF,
    0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF, 0xFF0E0EFF,
    0xFF0D0DFD, 0xFF0D0DFB, 0xFF0D0DFA, 0xFF0D0DF8, 0xFF0D0DF7, 0xFF0D0DF5, 0xFF0D0DF3, 0xFF0D0DF2,
    0xFF0D0DF0, 0xFF0D0DEF, 0xFF0D0DED, 0xFF0C0CEB, 0xFF0C0CEA, 0xFF0C0CE8, 0xFF0C0CE7, 0xFF0C0CE5,
    0xFF0C0CE3, 0xFF0C0CE2, 0xFF0C0CE0, 0xFF0C0CDF, 0xFF0C0CDD, 0xFF0C0CDB, 0xFF0B0BDA, 0xFF0B0BD8,
    0xFF0B0BD7, 0xFF0B0BD5, 0xFF0B0BD3, 0xFF0B0BD2, 0xFF0B0BD0, 0xFF0B0BCF, 0xFF0B0BCD, 0xFF0B0BCB,
    0xFF0B0BCA, 0xFF0B0BC8, 0xFF0A0AC7, 0xFF0A0AC5, 0xFF0A0AC3, 0xFF0A0AC2, 0xFF0A0AC0, 0xFF0A0ABF,
    0xFF0A0ABD, 0xFF0A0ABB, 0xFF0A0ABA, 0xFF0A0AB8, 0xFF0A0AB7, 0xFF0909B5, 0xFF0909B3, 0xFF0909B2,
    0xFF0909B0, 0xFF0909AF, 0xFF0909AD, 0xFF0909AB, 0xFF0909AA, 0xFF0909A8, 0xFF0909A7, 0xFF0909A5,
    0xFF0909A3, 0xFF0808A2, 0xFF0808A0, 0xFF08089F, 0xFF08089D, 0xFF08089B, 0xFF08089A, 0xFF080898,
    0xFF080897, 0xFF080895, 0xFF080893, 0xFF080892, 0xFF070790, 0xFF07078F, 0xFF07078D, 0xFF07078B,
    0xFF07078A, 0xFF070788, 0xFF070787, 0xFF070785, 0xFF070783, 0xFF070782, 0xFF070780, 0xFF07077F,
};

struct MemoryPage
{
    uint64_t page;
    int8_t data[PageSize];
};

static tracy_force_inline MemoryPage& GetPage( unordered_flat_map<uint64_t, MemoryPage>& memmap, uint64_t page )
{
    auto it = memmap.find( page );
    if( it == memmap.end() )
    {
        it = memmap.emplace( page, MemoryPage { page, {} } ).first;
    }
    return it->second;
}

static tracy_force_inline void FillPages( unordered_flat_map<uint64_t, MemoryPage>& memmap, uint64_t c0, uint64_t c1, int8_t val )
{
    auto p0 = c0 >> PageBits;
    const auto p1 = c1 >> PageBits;

    if( p0 == p1 )
    {
        const auto a0 = c0 & ( PageSize - 1 );
        const auto a1 = c1 & ( PageSize - 1 );

        auto& page = GetPage( memmap, p0 );
        if( a0 == a1 )
        {
            page.data[a0] = val;
        }
        else
        {
            memset( page.data + a0, val, a1 - a0 + 1 );
        }
    }
    else
    {
        {
            const auto a0 = c0 & ( PageSize - 1 );
            auto& page = GetPage( memmap, p0 );
            memset( page.data + a0, val, PageSize - a0 );
        }
        while( ++p0 < p1 )
        {
            auto& page = GetPage( memmap, p0 );
            memset( page.data, val, PageSize );
        }
        {
            const auto a1 = c1 & ( PageSize - 1 );
            auto& page = GetPage( memmap, p1 );
            memset( page.data, val, a1 + 1 );
        }
    }
}

std::vector<MemoryPage> View::GetMemoryPages() const
{
    std::vector<MemoryPage> ret;

    static unordered_flat_map<uint64_t, MemoryPage> memmap;

    const auto& mem = m_worker.GetMemoryNamed( m_memInfo.pool );
    const auto memlow = mem.low;

    if( m_memInfo.range.active )
    {
        auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
        if( it != mem.data.end() )
        {
            auto end = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.max, []( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
            while( it != end )
            {
                auto& alloc = *it++;

                const auto a0 = alloc.Ptr() - memlow;
                const auto a1 = a0 + alloc.Size();
                int8_t val = alloc.TimeFree() < 0 ?
                    int8_t( std::max( int64_t( 1 ), 127 - ( ( m_memInfo.range.max - alloc.TimeAlloc() ) >> 24 ) ) ) :
                    ( alloc.TimeFree() > m_memInfo.range.max ?
                        int8_t( std::max( int64_t( 1 ), 127 - ( ( m_memInfo.range.max - alloc.TimeAlloc() ) >> 24 ) ) ) :
                        int8_t( -std::max( int64_t( 1 ), 127 - ( ( m_memInfo.range.max - alloc.TimeFree() ) >> 24 ) ) ) );

                const auto c0 = a0 >> ChunkBits;
                const auto c1 = a1 >> ChunkBits;

                FillPages( memmap, c0, c1, val );
            }
        }
    }
    else
    {
        const auto lastTime = m_worker.GetLastTime();
        for( auto& alloc : mem.data )
        {
            const auto a0 = alloc.Ptr() - memlow;
            const auto a1 = a0 + alloc.Size();
            const int8_t val = alloc.TimeFree() < 0 ?
                int8_t( std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.TimeAlloc() ) ) >> 24 ) ) ) :
                int8_t( -std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.TimeFree() ) ) >> 24 ) ) );

            const auto c0 = a0 >> ChunkBits;
            const auto c1 = a1 >> ChunkBits;

            FillPages( memmap, c0, c1, val );
        }
    }

    std::vector<unordered_flat_map<uint64_t, MemoryPage>::const_iterator> itmap;
    itmap.reserve( memmap.size() );
    ret.reserve( memmap.size() );
    for( auto it = memmap.begin(); it != memmap.end(); ++it ) itmap.emplace_back( it );
    pdqsort_branchless( itmap.begin(), itmap.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.page < rhs->second.page; } );
    for( auto& v : itmap ) ret.emplace_back( v->second );

    memmap.clear();
    return ret;
}

void View::DrawMemory()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1100 * scale, 500 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Memory", &m_memInfo.show, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    if( ImGui::GetCurrentWindowRead()->SkipItems ) { ImGui::End(); return; }

    auto& memNameMap = m_worker.GetMemNameMap();
    if( memNameMap.size() > 1 )
    {
        TextDisabledUnformatted( ICON_FA_ARCHIVE " Memory pool:" );
        ImGui::SameLine();
        if( ImGui::BeginCombo( "##memoryPool", m_memInfo.pool == 0 ? "Default allocator" : m_worker.GetString( m_memInfo.pool ) ) )
        {
            for( auto& v : memNameMap )
            {
                if( ImGui::Selectable( v.first == 0 ? "Default allocator" : m_worker.GetString( v.first ) ) )
                {
                    m_memInfo.pool = v.first;
                    m_memInfo.showAllocList = false;
                }
            }
            ImGui::EndCombo();
        }
        ImGui::Separator();
    }

    auto& mem = m_worker.GetMemoryNamed( m_memInfo.pool );
    if( mem.data.empty() )
    {
        ImGui::TextWrapped( "No memory data collected." );
        ImGui::End();
        return;
    }

    TextDisabledUnformatted( "Total allocations:" );
    ImGui::SameLine();
    ImGui::Text( "%-15s", RealToString( mem.data.size() ) );
    ImGui::SameLine();
    TextDisabledUnformatted( "Active allocations:" );
    ImGui::SameLine();
    ImGui::Text( "%-15s", RealToString( mem.active.size() ) );
    ImGui::SameLine();
    TextDisabledUnformatted( "Memory usage:" );
    ImGui::SameLine();
    ImGui::Text( "%-15s", MemSizeToString( mem.usage ) );
    ImGui::SameLine();
    TextFocused( "Memory span:", MemSizeToString( mem.high - mem.low ) );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    DrawHelpMarker(
        "Click on address to display memory allocation info window. Middle click to zoom to allocation range.\n"
        "Active allocations are displayed using green color.\n"
        "A single thread is displayed if alloc and free was performed on the same thread. Otherwise two threads are displayed in order: alloc, free.\n"
        "If alloc and free is performed in the same zone, the free zone is displayed in yellow color." );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::SeparatorEx( ImGuiSeparatorFlags_Vertical );
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 2, 2 ) );
    if( ImGui::Checkbox( "Limit range", &m_memInfo.range.active ) )
    {
        if( m_memInfo.range.active && m_memInfo.range.min == 0 && m_memInfo.range.max == 0 )
        {
            m_memInfo.range.min = m_vd.zvStart;
            m_memInfo.range.max = m_vd.zvEnd;
        }
    }
    if( m_memInfo.range.active )
    {
        ImGui::SameLine();
        TextColoredUnformatted( 0xFF00FFFF, ICON_FA_EXCLAMATION_TRIANGLE );
        ImGui::SameLine();
        ToggleButton( ICON_FA_RULER " Limits", m_showRanges );
    }
    ImGui::PopStyleVar();

    ImGui::Separator();
    ImGui::BeginChild( "##memory" );
    if( ImGui::TreeNode( ICON_FA_AT " Allocations" ) )
    {
        bool findClicked =  ImGui::InputTextWithHint( "###address", "Enter memory address to search for", m_memInfo.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
        ImGui::SameLine();
        findClicked |= ImGui::Button( ICON_FA_SEARCH " Find" );
        if( findClicked )
        {
            m_memInfo.ptrFind = strtoull( m_memInfo.pattern, nullptr, 0 );
        }
        ImGui::SameLine();
        if( ImGui::Button( ICON_FA_BACKSPACE " Clear" ) )
        {
            m_memInfo.ptrFind = 0;
            m_memInfo.pattern[0] = '\0';
        }

        if( m_memInfo.ptrFind != 0 )
        {
            std::vector<const MemEvent*> match;
            match.reserve( mem.active.size() );     // heuristic
            if( m_memInfo.range.active )
            {
                auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                if( it != mem.data.end() )
                {
                    auto end = std::lower_bound( it, mem.data.end(), m_memInfo.range.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                    while( it != end )
                    {
                        if( it->Ptr() <= m_memInfo.ptrFind && it->Ptr() + it->Size() > m_memInfo.ptrFind )
                        {
                            match.emplace_back( it );
                        }
                        ++it;
                    }
                }
            }
            else
            {
                for( auto& v : mem.data )
                {
                    if( v.Ptr() <= m_memInfo.ptrFind && v.Ptr() + v.Size() > m_memInfo.ptrFind )
                    {
                        match.emplace_back( &v );
                    }
                }
            }

            if( match.empty() )
            {
                ImGui::TextUnformatted( "Found no allocations at given address" );
            }
            else
            {
                ListMemData( match, [this]( auto v ) {
                    if( v->Ptr() == m_memInfo.ptrFind )
                    {
                        ImGui::Text( "0x%" PRIx64, m_memInfo.ptrFind );
                    }
                    else
                    {
                        ImGui::Text( "0x%" PRIx64 "+%" PRIu64, v->Ptr(), m_memInfo.ptrFind - v->Ptr() );
                    }
                }, "##allocations", -1, m_memInfo.pool );
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_HEARTBEAT " Active allocations" ) )
    {
        uint64_t total = 0;
        std::vector<const MemEvent*> items;
        items.reserve( mem.active.size() );
        if( m_memInfo.range.active )
        {
            auto it = std::lower_bound( mem.data.begin(), mem.data.end(), m_memInfo.range.min, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
            if( it != mem.data.end() )
            {
                auto end = std::lower_bound( it, mem.data.end(), m_memInfo.range.max, [] ( const auto& lhs, const auto& rhs ) { return lhs.TimeAlloc() < rhs; } );
                while( it != end )
                {
                    const auto tf = it->TimeFree();
                    if( tf < 0 || tf >= m_memInfo.range.max )
                    {
                        items.emplace_back( it );
                        total += it->Size();
                    }
                    ++it;
                }
            }
        }
        else
        {
            auto ptr = mem.data.data();
            for( auto& v : mem.active ) items.emplace_back( ptr + v.second );
            pdqsort_branchless( items.begin(), items.end(), []( const auto& lhs, const auto& rhs ) { return lhs->TimeAlloc() < rhs->TimeAlloc(); } );
            total = mem.usage;
        }

        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( items.size() ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Memory usage:", MemSizeToString( total ) );

        if( !items.empty() )
        {
            ListMemData( items, []( auto v ) {
                ImGui::Text( "0x%" PRIx64, v->Ptr() );
            }, "##activeMem", -1, m_memInfo.pool );
        }
        else
        {
            TextDisabledUnformatted( "No active allocations" );
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_MAP " Memory map" ) )
    {
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Single pixel:", MemSizeToString( 1 << ChunkBits ) );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        TextFocused( "Single line:", MemSizeToString( PageChunkSize ) );

        auto pages = GetMemoryPages();
        const size_t lines = pages.size();

        ImGui::BeginChild( "##memMap", ImVec2( PageSize + 2, lines + 2 ), false );
        auto draw = ImGui::GetWindowDrawList();
        const auto wpos = ImGui::GetCursorScreenPos() + ImVec2( 1, 1 );
        const auto dpos = wpos + ImVec2( 0.5f, 0.5f );
        draw->AddRect( wpos - ImVec2( 1, 1 ), wpos + ImVec2( PageSize + 1, lines + 1 ), 0xFF666666 );
        draw->AddRectFilled( wpos, wpos + ImVec2( PageSize, lines ), 0xFF444444 );

        size_t line = 0;
        for( auto& page : pages )
        {
            size_t idx = 0;
            while( idx < PageSize )
            {
                if( page.data[idx] == 0 )
                {
                    do
                    {
                        idx++;
                    }
                    while( idx < PageSize && page.data[idx] == 0 );
                }
                else
                {
                    auto val = page.data[idx];
                    const auto i0 = idx;
                    do
                    {
                        idx++;
                    }
                    while( idx < PageSize && page.data[idx] == val );
                    DrawLine( draw, dpos + ImVec2( i0, line ), dpos + ImVec2( idx, line ), MemDecayColor[(uint8_t)val] );
                }
            }
            line++;
        }

        ImGui::EndChild();
        ImGui::TreePop();
    }

    ImGui::PushID( m_memInfo.pool );
    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_TREE " Bottom-up call stack tree" ) )
    {
        ImGui::SameLine();
        DrawHelpMarker( "Press ctrl key to display allocation info tooltip. Right click on function name to display allocations list." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( "Group by function name", &m_groupCallstackTreeByNameBottomUp );
        ImGui::SameLine();
        DrawHelpMarker( "If enabled, only one source location will be displayed (which may be incorrect)." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool activeOnlyBottomUp = m_memRangeBottomUp == MemRange::Active;
        if( SmallCheckbox( "Only active allocations", &activeOnlyBottomUp ) )
            m_memRangeBottomUp = activeOnlyBottomUp ? MemRange::Active : MemRange::Full;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool inactiveOnlyBottomUp = m_memRangeBottomUp == MemRange::Inactive;
        if( SmallCheckbox( "Only inactive allocations", &inactiveOnlyBottomUp ) )
            m_memRangeBottomUp = inactiveOnlyBottomUp ? MemRange::Inactive : MemRange::Full;

        auto tree = GetCallstackFrameTreeBottomUp( mem );
        if( !tree.empty() )
        {
            int idx = 0;
            DrawFrameTreeLevel( tree, idx );
        }
        else
        {
            TextDisabledUnformatted( "No call stack data collected" );
        }

        ImGui::TreePop();
    }

    ImGui::Separator();
    if( ImGui::TreeNode( ICON_FA_TREE " Top-down call stack tree" ) )
    {
        ImGui::SameLine();
        DrawHelpMarker( "Press ctrl key to display allocation info tooltip. Right click on function name to display allocations list." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        SmallCheckbox( "Group by function name", &m_groupCallstackTreeByNameTopDown );
        ImGui::SameLine();
        DrawHelpMarker( "If enabled, only one source location will be displayed (which may be incorrect)." );
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool activeOnlyTopDown = m_memRangeTopDown == MemRange::Active;
        if( SmallCheckbox( "Only active allocations", &activeOnlyTopDown ) )
            m_memRangeTopDown = activeOnlyTopDown ? MemRange::Active : MemRange::Full;
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        bool inactiveOnlyTopDown = m_memRangeTopDown == MemRange::Inactive;
        if( SmallCheckbox( "Only inactive allocations", &inactiveOnlyTopDown ) )
            m_memRangeTopDown = inactiveOnlyTopDown ? MemRange::Inactive : MemRange::Full;

        auto tree = GetCallstackFrameTreeTopDown( mem );
        if( !tree.empty() )
        {
            int idx = 0;
            DrawFrameTreeLevel( tree, idx );
        }
        else
        {
            TextDisabledUnformatted( "No call stack data collected" );
        }

        ImGui::TreePop();
    }
    ImGui::PopID();

    ImGui::EndChild();
    ImGui::End();
}

void View::DrawFrameTreeLevel( const unordered_flat_map<uint64_t, MemCallstackFrameTree>& tree, int& idx )
{
    auto& io = ImGui::GetIO();

    std::vector<unordered_flat_map<uint64_t, MemCallstackFrameTree>::const_iterator> sorted;
    sorted.reserve( tree.size() );
    for( auto it = tree.begin(); it != tree.end(); ++it )
    {
        sorted.emplace_back( it );
    }
    pdqsort_branchless( sorted.begin(), sorted.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs->second.alloc > rhs->second.alloc; } );

    int lidx = 0;
    for( auto& _v : sorted )
    {
        auto& v = _v->second;
        const auto isKernel = ( m_worker.GetCanonicalPointer( v.frame ) >> 63 ) != 0;
        idx++;
        auto frameDataPtr = m_worker.GetCallstackFrame( v.frame );
        if( frameDataPtr )
        {
            auto& frameData = *frameDataPtr;
            auto frame = frameData.data[frameData.size-1];
            bool expand = false;

            const auto frameName = m_worker.GetString( frame.name );
            if( v.children.empty() )
            {
                ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
                if( frameName[0] == '[' )
                {
                    TextDisabledUnformatted( frameName );
                }
                else if( isKernel )
                {
                    TextColoredUnformatted( 0xFF8888FF, frameName );
                }
                else
                {
                    ImGui::TextUnformatted( frameName );
                }
                ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
            }
            else
            {
                ImGui::PushID( lidx++ );
                if( frameName[0] == '[' ) ImGui::PushStyleColor( ImGuiCol_Text, 0x88FFFFFF );
                else if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                if( tree.size() == 1 )
                {
                    expand = ImGui::TreeNodeEx( frameName, ImGuiTreeNodeFlags_DefaultOpen );
                }
                else
                {
                    expand = ImGui::TreeNode( frameName );
                }
                if( isKernel || frameName[0] == '[' ) ImGui::PopStyleColor();
                ImGui::PopID();
            }

            if( ImGui::IsItemClicked( 1 ) )
            {
                auto& mem = m_worker.GetMemoryNamed( m_memInfo.pool ).data;
                const auto sz = mem.size();
                m_memInfo.showAllocList = true;
                m_memInfo.allocList.clear();
                for( size_t i=0; i<sz; i++ )
                {
                    if( v.callstacks.find( mem[i].CsAlloc() ) != v.callstacks.end() )
                    {
                        m_memInfo.allocList.emplace_back( i );
                    }
                }
            }

            if( io.KeyCtrl && ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                TextFocused( "Allocations size:", MemSizeToString( v.alloc ) );
                TextFocused( "Allocations count:", RealToString( v.count ) );
                TextFocused( "Mean allocation size:", MemSizeToString( v.alloc / v.count ) );
                ImGui::SameLine();
                ImGui::EndTooltip();
            }

            if( m_callstackTreeBuzzAnim.Match( idx ) )
            {
                const auto time = m_callstackTreeBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const char* fileName = nullptr;
            if( frame.line == 0 )
            {
                if( frameDataPtr->imageName.Active() ) TextDisabledUnformatted( m_worker.GetString( frameDataPtr->imageName ) );
            }
            else
            {
                fileName = m_worker.GetString( frame.file );
                ImGui::TextDisabled( "%s:%i", fileName, frame.line );
            }
            if( ImGui::IsItemHovered() )
            {
                DrawSourceTooltip( fileName, frame.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( !ViewDispatch( fileName, frame.line, frame.symAddr ) )
                    {
                        m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
                    }
                }
            }

            ImGui::SameLine();
            if( v.children.empty() )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s (%s)", MemSizeToString( v.alloc ), RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node" );
            }
            else
            {
                uint32_t childCost = 0;
                uint64_t childAlloc = 0;
                for( auto& c : v.children )
                {
                    childCost += c.second.count;
                    childAlloc += c.second.alloc;
                }
                const auto rc = v.count - childCost;
                if( rc != 0 )
                {
                    ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s (%s)", MemSizeToString( v.alloc - childAlloc ), RealToString( rc ) );
                    TooltipIfHovered( "Cost only in this node" );
                    ImGui::SameLine();
                }
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s (%s)", MemSizeToString( v.alloc ), RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node and children" );
            }

            if( expand )
            {
                DrawFrameTreeLevel( v.children, idx );
                ImGui::TreePop();
            }
        }
    }
}

void View::DrawFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx )
{
    std::vector<unordered_flat_map<uint64_t, CallstackFrameTree>::const_iterator> sorted;
    sorted.reserve( tree.size() );
    for( auto it = tree.begin(); it != tree.end(); ++it )
    {
        sorted.emplace_back( it );
    }
    pdqsort_branchless( sorted.begin(), sorted.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs->second.count > rhs->second.count; } );

    int lidx = 0;
    for( auto& _v : sorted )
    {
        auto& v = _v->second;
        const auto isKernel = ( m_worker.GetCanonicalPointer( v.frame ) >> 63 ) != 0;
        idx++;
        auto frameDataPtr = m_worker.GetCallstackFrame( v.frame );
        if( frameDataPtr )
        {
            auto& frameData = *frameDataPtr;
            auto frame = frameData.data[frameData.size-1];
            bool expand = false;

            const auto frameName = m_worker.GetString( frame.name );
            if( v.children.empty() )
            {
                ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
                if( frameName[0] == '[' )
                {
                    TextDisabledUnformatted( frameName );
                }
                else if( isKernel )
                {
                    TextColoredUnformatted( 0xFF8888FF, frameName );
                }
                else
                {
                    ImGui::TextUnformatted( frameName );
                }
                ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
            }
            else
            {
                ImGui::PushID( lidx++ );
                if( frameName[0] == '[' ) ImGui::PushStyleColor( ImGuiCol_Text, 0x88FFFFFF );
                else if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                if( tree.size() == 1 )
                {
                    expand = ImGui::TreeNodeEx( frameName, ImGuiTreeNodeFlags_DefaultOpen );
                }
                else
                {
                    expand = ImGui::TreeNode( frameName );
                }
                if( isKernel || frameName[0] == '[' ) ImGui::PopStyleColor();
                ImGui::PopID();
            }

            if( m_callstackTreeBuzzAnim.Match( idx ) )
            {
                const auto time = m_callstackTreeBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const char* fileName = nullptr;
            if( frame.line == 0 )
            {
                TextDisabledUnformatted( m_worker.GetString( frameDataPtr->imageName ) );
            }
            else
            {
                fileName = m_worker.GetString( frame.file );
                ImGui::TextDisabled( "%s:%i", fileName, frame.line );
            }
            if( ImGui::IsItemHovered() )
            {
                DrawSourceTooltip( fileName, frame.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( !ViewDispatch( fileName, frame.line, frame.symAddr ) )
                    {
                        m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
                    }
                }
            }

            ImGui::SameLine();
            if( v.children.empty() )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node" );
            }
            else
            {
                uint32_t childCost = 0;
                for( auto& c : v.children ) childCost += c.second.count;
                const auto r = v.count - childCost;
                if( r != 0 )
                {
                    ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", RealToString( r ) );
                    TooltipIfHovered( "Cost only in this node" );
                    ImGui::SameLine();
                }
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "(%s)", RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node and children" );
            }

            if( expand )
            {
                DrawFrameTreeLevel( v.children, idx );
                ImGui::TreePop();
            }
        }
    }
}

void View::DrawParentsFrameTreeLevel( const unordered_flat_map<uint64_t, CallstackFrameTree>& tree, int& idx )
{
    std::vector<unordered_flat_map<uint64_t, CallstackFrameTree>::const_iterator> sorted;
    sorted.reserve( tree.size() );
    for( auto it = tree.begin(); it != tree.end(); ++it )
    {
        sorted.emplace_back( it );
    }
    pdqsort_branchless( sorted.begin(), sorted.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs->second.count > rhs->second.count; } );

    int lidx = 0;
    for( auto& _v : sorted )
    {
        auto& v = _v->second;
        const auto isKernel = ( m_worker.GetCanonicalPointer( v.frame ) >> 63 ) != 0;
        idx++;
        auto frameDataPtr = v.frame.custom ? m_worker.GetParentCallstackFrame( v.frame ) : m_worker.GetCallstackFrame( v.frame );
        if( frameDataPtr )
        {
            auto& frameData = *frameDataPtr;
            auto frame = frameData.data[frameData.size-1];
            bool expand = false;

            const auto frameName = m_worker.GetString( frame.name );
            if( v.children.empty() )
            {
                ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
                if( frameName[0] == '[' )
                {
                    TextDisabledUnformatted( frameName );
                }
                else if( isKernel )
                {
                    TextColoredUnformatted( 0xFF8888FF, frameName );
                }
                else
                {
                    ImGui::TextUnformatted( frameName );
                }
                ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
            }
            else
            {
                ImGui::PushID( lidx++ );
                if( frameName[0] == '[' ) ImGui::PushStyleColor( ImGuiCol_Text, 0x88FFFFFF );
                else if( isKernel ) ImGui::PushStyleColor( ImGuiCol_Text, 0xFF8888FF );
                if( tree.size() == 1 )
                {
                    expand = ImGui::TreeNodeEx( frameName, ImGuiTreeNodeFlags_DefaultOpen );
                }
                else
                {
                    expand = ImGui::TreeNode( frameName );
                }
                if( isKernel || frameName[0] == '[' ) ImGui::PopStyleColor();
                ImGui::PopID();
            }

            if( m_callstackTreeBuzzAnim.Match( idx ) )
            {
                const auto time = m_callstackTreeBuzzAnim.Time();
                const auto indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
            }
            else
            {
                ImGui::SameLine();
            }
            const char* fileName = nullptr;
            if( frame.line == 0 )
            {
                TextDisabledUnformatted( m_worker.GetString( frameDataPtr->imageName ) );
            }
            else
            {
                fileName = m_worker.GetString( frame.file );
                ImGui::TextDisabled( "%s:%i", fileName, frame.line );
            }
            if( ImGui::IsItemHovered() )
            {
                DrawSourceTooltip( fileName, frame.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( !ViewDispatch( fileName, frame.line, frame.symAddr ) )
                    {
                        m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
                    }
                }
            }

            ImGui::SameLine();
            if( v.children.empty() )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * v.count ) : RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node" );
            }
            else
            {
                uint32_t childCost = 0;
                for( auto& c : v.children ) childCost += c.second.count;
                const auto r = v.count - childCost;
                if( r != 0 )
                {
                    ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "(%s)", m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * r ) : RealToString( r ) );
                    TooltipIfHovered( "Cost only in this node" );
                    ImGui::SameLine();
                }
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "(%s)", m_statSampleTime ? TimeToString( m_worker.GetSamplingPeriod() * v.count ) : RealToString( v.count ) );
                TooltipIfHovered( "Cost in this node and children" );
            }

            if( expand )
            {
                DrawParentsFrameTreeLevel( v.children, idx );
                ImGui::TreePop();
            }
        }
    }
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

const char* View::GetPlotName( const PlotData* plot ) const
{
    static char tmp[1024];
    switch( plot->type )
    {
    case PlotType::User:
        return m_worker.GetString( plot->name );
    case PlotType::Memory:
        if( plot->name == 0 )
        {
            return ICON_FA_MEMORY " Memory usage";
        }
        else
        {
            sprintf( tmp, ICON_FA_MEMORY " %s", m_worker.GetString( plot->name ) );
            return tmp;
        }
    case PlotType::SysTime:
        return ICON_FA_TACHOMETER_ALT " CPU usage";
    default:
        assert( false );
        return nullptr;
    }
}

uint32_t View::GetThreadColor( uint64_t thread, int depth )
{
    if( m_vd.dynamicColors == 0 ) return 0xFFCC5555;
    return GetHsvColor( thread, depth );
}

uint32_t View::GetRawSrcLocColor( const SourceLocation& srcloc, int depth )
{
    auto namehash = srcloc.namehash;
    if( namehash == 0 && srcloc.function.active )
    {
        const auto f = m_worker.GetString( srcloc.function );
        namehash = charutil::hash( f );
        if( namehash == 0 ) namehash++;
        srcloc.namehash = namehash;
    }
    if( namehash == 0 )
    {
        return GetHsvColor( uint64_t( &srcloc ), depth );
    }
    else
    {
        return GetHsvColor( namehash, depth );
    }
}

uint32_t View::GetSrcLocColor( const SourceLocation& srcloc, int depth )
{
    const auto color = srcloc.color;
    if( color != 0 && !m_vd.forceColors ) return color | 0xFF000000;
    if( m_vd.dynamicColors == 0 ) return 0xFFCC5555;
    return GetRawSrcLocColor( srcloc, depth );
}

uint32_t View::GetZoneColor( const ZoneEvent& ev, uint64_t thread, int depth )
{
    const auto sl = ev.SrcLoc();
    const auto& srcloc = m_worker.GetSourceLocation( sl );
    if( !m_vd.forceColors )
    {
        if( m_worker.HasZoneExtra( ev ) )
        {
            const auto custom_color = m_worker.GetZoneExtra( ev ).color.Val();
            if( custom_color != 0 ) return custom_color | 0xFF000000;
        }
        const auto color = srcloc.color;
        if( color != 0 ) return color | 0xFF000000;
    }
    switch( m_vd.dynamicColors )
    {
    case 0:
        return 0xFFCC5555;
    case 1:
        return GetHsvColor( thread, depth );
    case 2:
        return GetRawSrcLocColor( srcloc, depth );
    default:
        assert( false );
        return 0;
    }
}

uint32_t View::GetZoneColor( const GpuEvent& ev )
{
    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
    const auto color = srcloc.color;
    return color != 0 ? ( color | 0xFF000000 ) : 0xFF222288;
}

View::ZoneColorData View::GetZoneColorData( const ZoneEvent& ev, uint64_t thread, int depth )
{
    ZoneColorData ret;
    const auto& srcloc = ev.SrcLoc();
    if( m_zoneInfoWindow == &ev )
    {
        ret.color = GetZoneColor( ev, thread, depth );
        ret.accentColor = 0xFF44DD44;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else if( m_zoneHighlight == &ev )
    {
        ret.color = GetZoneColor( ev, thread, depth );
        ret.accentColor = 0xFF4444FF;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else if( m_zoneSrcLocHighlight == srcloc )
    {
        ret.color = GetZoneColor( ev, thread, depth );
        ret.accentColor = 0xFFEEEEEE;
        ret.thickness = 1.f;
        ret.highlight = true;
    }
    else if( m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == srcloc )
    {
        uint32_t color = 0xFF229999;
        if( m_findZone.highlight.active )
        {
            const auto zt = m_worker.GetZoneEnd( ev ) - ev.Start();
            if( zt >= m_findZone.highlight.start && zt <= m_findZone.highlight.end )
            {
                color = 0xFFFFCC66;
            }
        }
        ret.color = color;
        ret.accentColor = HighlightColor( color );
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else
    {
        const auto color = GetZoneColor( ev, thread, depth );
        ret.color = color;
        ret.accentColor = HighlightColor( color );
        ret.thickness = 1.f;
        ret.highlight = false;
    }
    return ret;
}

View::ZoneColorData View::GetZoneColorData( const GpuEvent& ev )
{
    ZoneColorData ret;
    const auto color = GetZoneColor( ev );
    ret.color = color;
    if( m_gpuInfoWindow == &ev )
    {
        ret.accentColor = 0xFF44DD44;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else if( m_gpuHighlight == &ev )
    {
        ret.accentColor = 0xFF4444FF;
        ret.thickness = 3.f;
        ret.highlight = true;
    }
    else
    {
        ret.accentColor = HighlightColor( color );
        ret.thickness = 1.f;
        ret.highlight = false;
    }
    return ret;
}

void View::ZoomToZone( const ZoneEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.Start() <= 0 ) return;
    ZoomToRange( ev.Start(), end );
}

void View::ZoomToZone( const GpuEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.GpuStart() <= 0 ) return;
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        ZoomToRange( ev.GpuStart(), end );
    }
    else
    {
        const auto td = ctx->threadData.size() == 1 ? ctx->threadData.begin() : ctx->threadData.find( m_worker.DecompressThread( ev.Thread() ) );
        assert( td != ctx->threadData.end() );
        int64_t begin;
        if( td->second.timeline.is_magic() )
        {
            begin = ((Vector<GpuEvent>*)&td->second.timeline)->front().GpuStart();
        }
        else
        {
            begin = td->second.timeline.front()->GpuStart();
        }
        const auto drift = GpuDrift( ctx );
        ZoomToRange( AdjustGpuTime( ev.GpuStart(), begin, drift ), AdjustGpuTime( end, begin, drift ) );
    }
}

void View::ZoomToRange( int64_t start, int64_t end, bool pause )
{
    if( start == end )
    {
        end = start + 1;
    }

    if( pause )
    {
        m_viewMode = ViewMode::Paused;
        m_viewModeHeuristicTry = false;
    }
    m_highlightZoom.active = false;
    if( !m_playback.pause && m_playback.sync ) m_playback.pause = true;

    m_zoomAnim.active = true;
    if( m_viewMode == ViewMode::LastRange )
    {
        const auto rangeCurr = m_vd.zvEnd - m_vd.zvStart;
        const auto rangeDest = end - start;
        m_zoomAnim.start0 = m_vd.zvStart;
        m_zoomAnim.start1 = m_vd.zvStart - ( rangeDest - rangeCurr );
        m_zoomAnim.end0 = m_vd.zvEnd;
        m_zoomAnim.end1 = m_vd.zvEnd;
    }
    else
    {
        m_zoomAnim.start0 = m_vd.zvStart;
        m_zoomAnim.start1 = start;
        m_zoomAnim.end0 = m_vd.zvEnd;
        m_zoomAnim.end1 = end;
    }
    m_zoomAnim.progress = 0;
}

void View::ZoomToPrevFrame()
{
    if( m_vd.zvStart >= m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        size_t frame;
        if( m_frames->continuous )
        {
            frame = (size_t)m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvStart ).first;
        }
        else
        {
            frame = (size_t)m_worker.GetFrameRange( *m_frames, m_vd.zvStart, m_vd.zvStart ).second;
        }

        if( frame > 0 )
        {
            frame--;
            const auto fbegin = m_worker.GetFrameBegin( *m_frames, frame );
            const auto fend = m_worker.GetFrameEnd( *m_frames, frame );
            ZoomToRange( fbegin, fend );
        }
    }
}

void View::ZoomToNextFrame()
{
    int64_t start;
    if( m_zoomAnim.active )
    {
        start = m_zoomAnim.start1;
    }
    else
    {
        start = m_vd.zvStart;
    }

    size_t frame;
    if( start < m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        frame = 0;
    }
    else
    {
        frame = (size_t)m_worker.GetFrameRange( *m_frames, start, start ).first + 1;
    }
    if( frame >= m_worker.GetFrameCount( *m_frames ) ) return;

    const auto fbegin = m_worker.GetFrameBegin( *m_frames, frame );
    const auto fend = m_worker.GetFrameEnd( *m_frames, frame );
    ZoomToRange( fbegin, fend );
}

void View::CenterAtTime( int64_t t )
{
    const auto hr = std::max<uint64_t>( 1, ( m_vd.zvEnd - m_vd.zvStart ) / 2 );
    ZoomToRange( t - hr, t + hr );
}

void View::ShowZoneInfo( const ZoneEvent& ev )
{
    if( m_zoneInfoWindow && m_zoneInfoWindow != &ev )
    {
        m_zoneInfoStack.push_back( m_zoneInfoWindow );
    }
    m_zoneInfoWindow = &ev;

    if( m_gpuInfoWindow )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

void View::ShowZoneInfo( const GpuEvent& ev, uint64_t thread )
{
    if( m_gpuInfoWindow && m_gpuInfoWindow != &ev )
    {
        m_gpuInfoStack.push_back( m_gpuInfoWindow );
    }
    m_gpuInfoWindow = &ev;
    m_gpuInfoWindowThread = thread;

    if( m_zoneInfoWindow )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

void View::ZoneTooltip( const ZoneEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.Start();
    const auto selftime = GetZoneSelfTime( ev );

    ImGui::BeginTooltip();
    if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).name.Active() )
    {
        ImGui::TextUnformatted( m_worker.GetString( m_worker.GetZoneExtra( ev ).name ) );
    }
    if( srcloc.name.active )
    {
        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
    }
    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
    ImGui::SameLine();
    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
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
    ImGui::Separator();
    TextFocused( "Execution time:", TimeToString( ztime ) );
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& zoneData = m_worker.GetZonesForSourceLocation( ev.SrcLoc() );
        if( zoneData.total > 0 )
        {
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of mean time)", float( ztime ) / zoneData.total * zoneData.zones.size() * 100 );
        }
    }
#endif
    TextFocused( "Self time:", TimeToString( selftime ) );
    if( ztime != 0 )
    {
        char buf[64];
        PrintStringPercent( buf, 100.f * selftime / ztime );
        ImGui::SameLine();
        TextDisabledUnformatted( buf );
    }
    const auto ctx = m_worker.GetContextSwitchData( tid );
    if( ctx )
    {
        int64_t time;
        uint64_t cnt;
        if( GetZoneRunningTime( ctx, ev, time, cnt ) )
        {
            TextFocused( "Running state time:", TimeToString( time ) );
            if( ztime != 0 )
            {
                char buf[64];
                PrintStringPercent( buf, 100.f * time / ztime );
                ImGui::SameLine();
                TextDisabledUnformatted( buf );
            }
            TextFocused( "Running state regions:", RealToString( cnt ) );
        }
    }
    if( m_worker.HasZoneExtra( ev ) && m_worker.GetZoneExtra( ev ).text.Active() )
    {
        ImGui::NewLine();
        TextColoredUnformatted( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), m_worker.GetString( m_worker.GetZoneExtra( ev ).text ) );
    }
    ImGui::EndTooltip();
}

void View::ZoneTooltip( const GpuEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    const auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.GpuStart();
    const auto selftime = GetZoneSelfTime( ev );

    ImGui::BeginTooltip();
    ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    SmallColorBox( GetSrcLocColor( srcloc, 0 ) );
    ImGui::SameLine();
    ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
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
    ImGui::Separator();
    TextFocused( "GPU execution time:", TimeToString( ztime ) );
    TextFocused( "GPU self time:", TimeToString( selftime ) );
    if( ztime != 0 )
    {
        char buf[64];
        PrintStringPercent( buf, 100.f * selftime / ztime );
        ImGui::SameLine();
        TextDisabledUnformatted( buf );
    }
    TextFocused( "CPU command setup time:", TimeToString( ev.CpuEnd() - ev.CpuStart() ) );
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        TextFocused( "Delay to execution:", TimeToString( ev.GpuStart() - ev.CpuStart() ) );
    }
    else
    {
        const auto td = ctx->threadData.size() == 1 ? ctx->threadData.begin() : ctx->threadData.find( m_worker.DecompressThread( ev.Thread() ) );
        assert( td != ctx->threadData.end() );
        int64_t begin;
        if( td->second.timeline.is_magic() )
        {
            begin = ((Vector<GpuEvent>*)&td->second.timeline)->front().GpuStart();
        }
        else
        {
            begin = td->second.timeline.front()->GpuStart();
        }
        const auto drift = GpuDrift( ctx );
        TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.GpuStart(), begin, drift ) - ev.CpuStart() ) );
    }

    ImGui::EndTooltip();
}

void View::CallstackTooltip( uint32_t idx )
{
    ImGui::BeginTooltip();
    CallstackTooltipContents( idx );
    ImGui::EndTooltip();
}

void View::CallstackTooltipContents( uint32_t idx )
{
    auto& cs = m_worker.GetCallstack( idx );
    int fidx = 0;
    for( auto& entry : cs )
    {
        auto frameData = m_worker.GetCallstackFrame( entry );
        if( !frameData )
        {
            ImGui::TextDisabled( "%i.", fidx++ );
            ImGui::SameLine();
            ImGui::Text( "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
        }
        else
        {
            const auto fsz = frameData->size;
            for( uint8_t f=0; f<fsz; f++ )
            {
                const auto& frame = frameData->data[f];
                auto txt = m_worker.GetString( frame.name );

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
                if( f == fsz-1 )
                {
                    ImGui::TextDisabled( "%i.", fidx++ );
                }
                else
                {
                    TextDisabledUnformatted( ICON_FA_CARET_RIGHT );
                }
                ImGui::SameLine();
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
                if( frameData->imageName.Active() )
                {
                    ImGui::SameLine();
                    ImGui::PushFont( m_smallFont );
                    ImGui::AlignTextToFramePadding();
                    TextDisabledUnformatted( m_worker.GetString( frameData->imageName ) );
                    ImGui::PopFont();
                }
            }
        }
    }
}

void View::CrashTooltip()
{
    auto& crash = m_worker.GetCrashEvent();
    ImGui::BeginTooltip();
    TextFocused( "Time:", TimeToString( crash.time ) );
    TextFocused( "Reason:", m_worker.GetString( crash.message ) );
    ImGui::EndTooltip();
}

const ZoneEvent* View::GetZoneParent( const ZoneEvent& zone ) const
{
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& slz = m_worker.GetZonesForSourceLocation( zone.SrcLoc() );
        if( !slz.zones.empty() && slz.zones.is_sorted() )
        {
            auto it = std::lower_bound( slz.zones.begin(), slz.zones.end(), zone.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs.Zone()->Start() < rhs; } );
            if( it != slz.zones.end() && it->Zone() == &zone )
            {
                return GetZoneParent( zone, m_worker.DecompressThread( it->Thread() ) );
            }
        }
    }
#endif

    for( const auto& thread : m_worker.GetThreadData() )
    {
        const ZoneEvent* parent = nullptr;
        const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            if( timeline->is_magic() )
            {
                auto vec = (Vector<ZoneEvent>*)timeline;
                auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                if( it != vec->begin() ) --it;
                if( zone.IsEndValid() && it->Start() > zone.End() ) break;
                if( it == &zone ) return parent;
                if( !it->HasChildren() ) break;
                parent = it;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
            else
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
                if( it != timeline->begin() ) --it;
                if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
                if( *it == &zone ) return parent;
                if( !(*it)->HasChildren() ) break;
                parent = *it;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
        }
    }
    return nullptr;
}

const ZoneEvent* View::GetZoneParent( const ZoneEvent& zone, uint64_t tid ) const
{
    const auto thread = m_worker.GetThreadData( tid );
    const ZoneEvent* parent = nullptr;
    const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
    if( timeline->empty() ) return nullptr;
    for(;;)
    {
        if( timeline->is_magic() )
        {
            auto vec = (Vector<ZoneEvent>*)timeline;
            auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
            if( it != vec->begin() ) --it;
            if( zone.IsEndValid() && it->Start() > zone.End() ) break;
            if( it == &zone ) return parent;
            if( !it->HasChildren() ) break;
            parent = it;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
        else
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
            if( it != timeline->begin() ) --it;
            if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
            if( *it == &zone ) return parent;
            if( !(*it)->HasChildren() ) break;
            parent = *it;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
    }
    return nullptr;
}

bool View::IsZoneReentry( const ZoneEvent& zone ) const
{
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& slz = m_worker.GetZonesForSourceLocation( zone.SrcLoc() );
        if( !slz.zones.empty() && slz.zones.is_sorted() )
        {
            auto it = std::lower_bound( slz.zones.begin(), slz.zones.end(), zone.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs.Zone()->Start() < rhs; } );
            if( it != slz.zones.end() && it->Zone() == &zone )
            {
                return IsZoneReentry( zone, m_worker.DecompressThread( it->Thread() ) );
            }
        }
    }
#endif

    for( const auto& thread : m_worker.GetThreadData() )
    {
        const ZoneEvent* parent = nullptr;
        const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            if( timeline->is_magic() )
            {
                auto vec = (Vector<ZoneEvent>*)timeline;
                auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                if( it != vec->begin() ) --it;
                if( zone.IsEndValid() && it->Start() > zone.End() ) break;
                if( it == &zone ) return false;
                if( !it->HasChildren() ) break;
                parent = it;
                if (parent->SrcLoc() == zone.SrcLoc() ) return true;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
            else
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
                if( it != timeline->begin() ) --it;
                if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
                if( *it == &zone ) return false;
                if( !(*it)->HasChildren() ) break;
                parent = *it;
                if (parent->SrcLoc() == zone.SrcLoc() ) return true;
                timeline = &m_worker.GetZoneChildren( parent->Child() );
            }
        }
    }
    return false;
}

bool View::IsZoneReentry( const ZoneEvent& zone, uint64_t tid ) const
{
    const auto thread = m_worker.GetThreadData( tid );
    const ZoneEvent* parent = nullptr;
    const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
    if( timeline->empty() ) return false;
    for(;;)
    {
        if( timeline->is_magic() )
        {
            auto vec = (Vector<ZoneEvent>*)timeline;
            auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
            if( it != vec->begin() ) --it;
            if( zone.IsEndValid() && it->Start() > zone.End() ) break;
            if( it == &zone ) return false;
            if( !it->HasChildren() ) break;
            parent = it;
            if (parent->SrcLoc() == zone.SrcLoc() ) return true;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
        else
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
            if( it != timeline->begin() ) --it;
            if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
            if( *it == &zone ) return false;
            if( !(*it)->HasChildren() ) break;
            parent = *it;
            if (parent->SrcLoc() == zone.SrcLoc() ) return true;
            timeline = &m_worker.GetZoneChildren( parent->Child() );
        }
    }
    return false;
}

const GpuEvent* View::GetZoneParent( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        for( const auto& td : ctx->threadData )
        {
            const GpuEvent* parent = nullptr;
            const Vector<short_ptr<GpuEvent>>* timeline = &td.second.timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                if( timeline->is_magic() )
                {
                    auto vec = (Vector<GpuEvent>*)timeline;
                    auto it = std::upper_bound( vec->begin(), vec->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r.GpuStart(); } );
                    if( it != vec->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && it->GpuStart() > zone.GpuEnd() ) break;
                    if( it == &zone ) return parent;
                    if( it->Child() < 0 ) break;
                    parent = it;
                    timeline = &m_worker.GetGpuChildren( parent->Child() );
                }
                else
                {
                    auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r->GpuStart(); } );
                    if( it != timeline->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && (*it)->GpuStart() > zone.GpuEnd() ) break;
                    if( *it == &zone ) return parent;
                    if( (*it)->Child() < 0 ) break;
                    parent = *it;
                    timeline = &m_worker.GetGpuChildren( parent->Child() );
                }
            }
        }
    }
    return nullptr;
}

const ThreadData* View::GetZoneThreadData( const ZoneEvent& zone ) const
{
#ifndef TRACY_NO_STATISTICS
    if( m_worker.AreSourceLocationZonesReady() )
    {
        auto& slz = m_worker.GetZonesForSourceLocation( zone.SrcLoc() );
        if( !slz.zones.empty() && slz.zones.is_sorted() )
        {
            auto it = std::lower_bound( slz.zones.begin(), slz.zones.end(), zone.Start(), [] ( const auto& lhs, const auto& rhs ) { return lhs.Zone()->Start() < rhs; } );
            if( it != slz.zones.end() && it->Zone() == &zone )
            {
                return m_worker.GetThreadData( m_worker.DecompressThread( it->Thread() ) );
            }
        }
    }
#endif

    for( const auto& thread : m_worker.GetThreadData() )
    {
        const Vector<short_ptr<ZoneEvent>>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            if( timeline->is_magic() )
            {
                auto vec = (Vector<ZoneEvent>*)timeline;
                auto it = std::upper_bound( vec->begin(), vec->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
                if( it != vec->begin() ) --it;
                if( zone.IsEndValid() && it->Start() > zone.End() ) break;
                if( it == &zone ) return thread;
                if( !it->HasChildren() ) break;
                timeline = &m_worker.GetZoneChildren( it->Child() );
            }
            else
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.Start(), [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
                if( it != timeline->begin() ) --it;
                if( zone.IsEndValid() && (*it)->Start() > zone.End() ) break;
                if( *it == &zone ) return thread;
                if( !(*it)->HasChildren() ) break;
                timeline = &m_worker.GetZoneChildren( (*it)->Child() );
            }
        }
    }
    return nullptr;
}

uint64_t View::GetZoneThread( const ZoneEvent& zone ) const
{
    auto threadData = GetZoneThreadData( zone );
    return threadData ? threadData->id : 0;
}

uint64_t View::GetZoneThread( const GpuEvent& zone ) const
{
    if( zone.Thread() == 0 )
    {
        for( const auto& ctx : m_worker.GetGpuData() )
        {
            if ( ctx->threadData.size() != 1 ) continue;
            const Vector<short_ptr<GpuEvent>>* timeline = &ctx->threadData.begin()->second.timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                if( timeline->is_magic() )
                {
                    auto vec = (Vector<GpuEvent>*)timeline;
                    auto it = std::upper_bound( vec->begin(), vec->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r.GpuStart(); } );
                    if( it != vec->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && it->GpuStart() > zone.GpuEnd() ) break;
                    if( it == &zone ) return ctx->thread;
                    if( it->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( it->Child() );
                }
                else
                {
                    auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r->GpuStart(); } );
                    if( it != timeline->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && (*it)->GpuStart() > zone.GpuEnd() ) break;
                    if( *it == &zone ) return ctx->thread;
                    if( (*it)->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( (*it)->Child() );
                }
            }
        }
        return 0;
    }
    else
    {
        return m_worker.DecompressThread( zone.Thread() );
    }
}

const GpuCtxData* View::GetZoneCtx( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        for( const auto& td : ctx->threadData )
        {
            const Vector<short_ptr<GpuEvent>>* timeline = &td.second.timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                if( timeline->is_magic() )
                {
                    auto vec = (Vector<GpuEvent>*)timeline;
                    auto it = std::upper_bound( vec->begin(), vec->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r.GpuStart(); } );
                    if( it != vec->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && it->GpuStart() > zone.GpuEnd() ) break;
                    if( it == &zone ) return ctx;
                    if( it->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( it->Child() );
                }
                else
                {
                    auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.GpuStart(), [] ( const auto& l, const auto& r ) { return (uint64_t)l < (uint64_t)r->GpuStart(); } );
                    if( it != timeline->begin() ) --it;
                    if( zone.GpuEnd() >= 0 && (*it)->GpuStart() > zone.GpuEnd() ) break;
                    if( *it == &zone ) return ctx;
                    if( (*it)->Child() < 0 ) break;
                    timeline = &m_worker.GetGpuChildren( (*it)->Child() );
                }
            }
        }
    }
    return nullptr;
}

const ZoneEvent* View::FindZoneAtTime( uint64_t thread, int64_t time ) const
{
    // TODO add thread rev-map
    ThreadData* td = nullptr;
    for( const auto& t : m_worker.GetThreadData() )
    {
        if( t->id == thread )
        {
            td = t;
            break;
        }
    }
    if( !td ) return nullptr;

    const Vector<short_ptr<ZoneEvent>>* timeline = &td->timeline;
    if( timeline->empty() ) return nullptr;
    const ZoneEvent* ret = nullptr;
    for(;;)
    {
        if( timeline->is_magic() )
        {
            auto vec = (Vector<ZoneEvent>*)timeline;
            auto it = std::upper_bound( vec->begin(), vec->end(), time, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
            if( it != vec->begin() ) --it;
            if( it->Start() > time || ( it->IsEndValid() && it->End() < time ) ) return ret;
            ret = it;
            if( !it->HasChildren() ) return ret;
            timeline = &m_worker.GetZoneChildren( it->Child() );
        }
        else
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), time, [] ( const auto& l, const auto& r ) { return l < r->Start(); } );
            if( it != timeline->begin() ) --it;
            if( (*it)->Start() > time || ( (*it)->IsEndValid() && (*it)->End() < time ) ) return ret;
            ret = *it;
            if( !(*it)->HasChildren() ) return ret;
            timeline = &m_worker.GetZoneChildren( (*it)->Child() );
        }
    }
}

#ifndef TRACY_NO_STATISTICS
void View::FindZones()
{
    m_findZone.match = m_worker.GetMatchingSourceLocation( m_findZone.pattern, m_findZone.ignoreCase );
    if( m_findZone.match.empty() ) return;

    auto it = m_findZone.match.begin();
    while( it != m_findZone.match.end() )
    {
        if( m_worker.GetZonesForSourceLocation( *it ).zones.empty() )
        {
            it = m_findZone.match.erase( it );
        }
        else
        {
            ++it;
        }
    }
}

void View::FindZonesCompare()
{
    m_compare.match[0] = m_worker.GetMatchingSourceLocation( m_compare.pattern, m_compare.ignoreCase );
    if( !m_compare.match[0].empty() )
    {
        auto it = m_compare.match[0].begin();
        while( it != m_compare.match[0].end() )
        {
            if( m_worker.GetZonesForSourceLocation( *it ).zones.empty() )
            {
                it = m_compare.match[0].erase( it );
            }
            else
            {
                ++it;
            }
        }
    }

    m_compare.match[1] = m_compare.second->GetMatchingSourceLocation( m_compare.pattern, m_compare.ignoreCase );
    if( !m_compare.match[1].empty() )
    {
        auto it = m_compare.match[1].begin();
        while( it != m_compare.match[1].end() )
        {
            if( m_compare.second->GetZonesForSourceLocation( *it ).zones.empty() )
            {
                it = m_compare.match[1].erase( it );
            }
            else
            {
                ++it;
            }
        }
    }
}
#endif

void View::SmallCallstackButton( const char* name, uint32_t callstack, int& idx, bool tooltip )
{
    bool hilite = m_callstackInfoWindow == callstack;
    if( hilite )
    {
        SetButtonHighlightColor();
    }
    ImGui::PushID( idx++ );
    if( ImGui::SmallButton( name ) )
    {
        m_callstackInfoWindow = callstack;
    }
    ImGui::PopID();
    if( hilite )
    {
        ImGui::PopStyleColor( 3 );
    }
    if( tooltip && ImGui::IsItemHovered() )
    {
        CallstackTooltip( callstack );
    }
}

void View::DrawCallstackCalls( uint32_t callstack, uint16_t limit ) const
{
    const auto& csdata = m_worker.GetCallstack( callstack );
    const auto cssz = std::min( csdata.size(), limit );
    bool first = true;
    for( uint16_t i=0; i<cssz; i++ )
    {
        const auto frameData = m_worker.GetCallstackFrame( csdata[i] );
        if( !frameData ) break;
        if( first )
        {
            first = false;
        }
        else
        {
            ImGui::SameLine();
            TextDisabledUnformatted( ICON_FA_LONG_ARROW_ALT_LEFT );
            ImGui::SameLine();
        }
        const auto& frame = frameData->data[frameData->size - 1];
        auto txt = m_worker.GetString( frame.name );
        if( txt[0] == '[' )
        {
            TextDisabledUnformatted( txt );
        }
        else
        {
            ImGui::TextUnformatted( txt );
        }
    }
}

void View::SetViewToLastFrames()
{
    const int total = m_worker.GetFrameCount( *m_frames );

    m_vd.zvStart = m_worker.GetFrameBegin( *m_frames, std::max( 0, total - 4 ) );
    if( total == 1 )
    {
        m_vd.zvEnd = m_worker.GetLastTime();
    }
    else
    {
        m_vd.zvEnd = m_worker.GetFrameBegin( *m_frames, total - 1 );
    }
    if( m_vd.zvEnd == m_vd.zvStart )
    {
        m_vd.zvEnd = m_worker.GetLastTime();
    }
}

int64_t View::GetZoneChildTime( const ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = m_worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<ZoneEvent>*)&children;
            for( auto& v : vec )
            {
                const auto childSpan = std::max( int64_t( 0 ), v.End() - v.Start() );
                time += childSpan;
            }
        }
        else
        {
            for( auto& v : children )
            {
                const auto childSpan = std::max( int64_t( 0 ), v->End() - v->Start() );
                time += childSpan;
            }
        }
    }
    return time;
}

int64_t View::GetZoneChildTime( const GpuEvent& zone )
{
    int64_t time = 0;
    if( zone.Child() >= 0 )
    {
        auto& children = m_worker.GetGpuChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<GpuEvent>*)&children;
            for( auto& v : vec )
            {
                const auto childSpan = std::max( int64_t( 0 ), v.GpuEnd() - v.GpuStart() );
                time += childSpan;
            }
        }
        else
        {
            for( auto& v : children )
            {
                const auto childSpan = std::max( int64_t( 0 ), v->GpuEnd() - v->GpuStart() );
                time += childSpan;
            }
        }
    }
    return time;
}

int64_t View::GetZoneChildTimeFast( const ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = m_worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<ZoneEvent>*)&children;
            for( auto& v : vec )
            {
                assert( v.IsEndValid() );
                time += v.End() - v.Start();
            }
        }
        else
        {
            for( auto& v : children )
            {
                assert( v->IsEndValid() );
                time += v->End() - v->Start();
            }
        }
    }
    return time;
}

int64_t View::GetZoneChildTimeFastClamped( const ZoneEvent& zone, int64_t t0, int64_t t1 )
{
    int64_t time = 0;
    if( zone.HasChildren() )
    {
        auto& children = m_worker.GetZoneChildren( zone.Child() );
        if( children.is_magic() )
        {
            auto& vec = *(Vector<ZoneEvent>*)&children;
            auto it = std::lower_bound( vec.begin(), vec.end(), t0, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
            if( it == vec.end() ) return 0;
            const auto zitend = std::lower_bound( it, vec.end(), t1, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
            if( it == zitend ) return 0;
            while( it < zitend )
            {
                const auto c0 = std::max<int64_t>( it->Start(), t0 );
                const auto c1 = std::min<int64_t>( it->End(), t1 );
                time += c1 - c0;
                ++it;
            }
        }
        else
        {
            auto it = std::lower_bound( children.begin(), children.end(), t0, [] ( const auto& l, const auto& r ) { return (uint64_t)l->End() < (uint64_t)r; } );
            if( it == children.end() ) return 0;
            const auto zitend = std::lower_bound( it, children.end(), t1, [] ( const auto& l, const auto& r ) { return l->Start() < r; } );
            if( it == zitend ) return 0;
            while( it < zitend )
            {
                const auto c0 = std::max<int64_t>( (*it)->Start(), t0 );
                const auto c1 = std::min<int64_t>( (*it)->End(), t1 );
                time += c1 - c0;
                ++it;
            }
        }
    }
    return time;
}

int64_t View::GetZoneSelfTime( const ZoneEvent& zone )
{
    if( m_cache.zoneSelfTime.first == &zone ) return m_cache.zoneSelfTime.second;
    if( m_cache.zoneSelfTime2.first == &zone ) return m_cache.zoneSelfTime2.second;
    const auto ztime = m_worker.GetZoneEnd( zone ) - zone.Start();
    const auto selftime = ztime - GetZoneChildTime( zone );
    if( zone.IsEndValid() )
    {
        m_cache.zoneSelfTime2 = m_cache.zoneSelfTime;
        m_cache.zoneSelfTime = std::make_pair( &zone, selftime );
    }
    return selftime;
}

int64_t View::GetZoneSelfTime( const GpuEvent& zone )
{
    if( m_cache.gpuSelfTime.first == &zone ) return m_cache.gpuSelfTime.second;
    if( m_cache.gpuSelfTime2.first == &zone ) return m_cache.gpuSelfTime2.second;
    const auto ztime = m_worker.GetZoneEnd( zone ) - zone.GpuStart();
    const auto selftime = ztime - GetZoneChildTime( zone );
    if( zone.GpuEnd() >= 0 )
    {
        m_cache.gpuSelfTime2 = m_cache.gpuSelfTime;
        m_cache.gpuSelfTime = std::make_pair( &zone, selftime );
    }
    return selftime;
}

bool View::GetZoneRunningTime( const ContextSwitch* ctx, const ZoneEvent& ev, int64_t& time, uint64_t& cnt )
{
    auto it = std::lower_bound( ctx->v.begin(), ctx->v.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
    if( it == ctx->v.end() ) return false;
    const auto end = m_worker.GetZoneEnd( ev );
    const auto eit = std::upper_bound( it, ctx->v.end(), end, [] ( const auto& l, const auto& r ) { return l < r.Start(); } );
    if( eit == ctx->v.end() ) return false;
    cnt = std::distance( it, eit );
    if( cnt == 0 ) return false;
    if( cnt == 1 )
    {
        time = end - ev.Start();
    }
    else
    {
        int64_t running = it->End() - ev.Start();
        ++it;
        for( uint64_t i=0; i<cnt-2; i++ )
        {
            running += it->End() - it->Start();
            ++it;
        }
        running += end - it->Start();
        time = running;
    }
    return true;
}

const char* View::SourceSubstitution( const char* srcFile ) const
{
    if( !m_sourceRegexValid || m_sourceSubstitutions.empty() ) return srcFile;
    static std::string res, tmp;
    res.assign( srcFile );
    for( auto& v : m_sourceSubstitutions )
    {
        tmp = std::regex_replace( res, v.regex, v.target );
        std::swap( tmp, res );
    }
    return res.c_str();
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
