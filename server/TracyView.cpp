#include <algorithm>
#include <assert.h>
#include <chrono>
#include <inttypes.h>
#include <limits>
#include <math.h>
#include <mutex>
#include <numeric>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

#include "../common/TracyMutex.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySystem.hpp"
#include "tracy_pdqsort.h"
#include "TracyBadVersion.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyPopcnt.hpp"
#include "TracyView.hpp"

#include "../imguicolortextedit/TextEditor.h"

#ifdef TRACY_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

#ifdef TRACY_EXTENDED_FONT
#  include "IconsFontAwesome5.h"
#endif

#ifndef M_PI_2
#define M_PI_2 1.57079632679489661923
#endif

namespace tracy
{

static const char* TimeToString( int64_t ns )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const char* sign = "";
    if( ns < 0 )
    {
        sign = "-";
        ns = -ns;
    }

    if( ns < 1000 )
    {
        sprintf( buf, "%s%" PRIi64 " ns", sign, ns );
    }
    else if( ns < 1000ll * 1000 )
    {
#ifdef TRACY_EXTENDED_FONT
        sprintf( buf, "%s%.2f \xce\xbcs", sign, ns / 1000. );
#else
        sprintf( buf, "%s%.2f us", sign, ns / 1000. );
#endif
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        sprintf( buf, "%s%.2f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.2f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 )
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) ) / ( 1000. * 1000. * 1000. );
        sprintf( buf, "%s%" PRIi64 ":%04.1f", sign, m, s );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 * 24 )
    {
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - h * ( 60 * 60 ) - m * 60 );
        sprintf( buf, "%s%" PRIi64 ":%02" PRIi64 ":%02" PRIi64, sign, h, m, s );
    }
    else
    {
        const auto d = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 * 24 ) );
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) - d * 24 );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - d * ( 60 * 24 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - d * ( 60 * 60 * 24 ) - h * ( 60 * 60 ) - m * 60 );
        sprintf( buf, "%s%" PRIi64 "d%02" PRIi64 ":%02" PRIi64 ":%02" PRIi64, sign, d, h, m, s );
    }
    return buf;
}

static const char* TimeToStringInteger( int64_t ns )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const char* sign = "";
    if( ns < 0 )
    {
        sign = "-";
        ns = -ns;
    }

    if( ns < 1000 )
    {
        sprintf( buf, "%s%" PRIi64 " ns", sign, ns );
    }
    else if( ns < 1000ll * 1000 )
    {
#ifdef TRACY_EXTENDED_FONT
        sprintf( buf, "%s%.0f \xce\xbcs", sign, ns / 1000. );
#else
        sprintf( buf, "%s%.0f us", sign, ns / 1000. );
#endif
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        sprintf( buf, "%s%.0f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.0f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) );
        sprintf( buf, "%s%" PRIi64 ":%02.0f", sign, m, s / ( 1000. * 1000. * 1000. ) );
    }
    return buf;
}

static const char* RealToString( double val, bool separator )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    sprintf( buf, "%f", val );
    auto ptr = buf;
    if( *ptr == '-' ) ptr++;

    const auto vbegin = ptr;

    if( separator )
    {
        while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;
        auto end = ptr;
        while( *end != '\0' ) end++;
        auto sz = end - ptr;

        while( ptr - vbegin > 3 )
        {
            ptr -= 3;
            memmove( ptr+1, ptr, sz );
            *ptr = ',';
            sz += 4;
        }
    }

    while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;

    if( *ptr == '\0' ) return buf;
    while( *ptr != '\0' ) ptr++;
    ptr--;
    while( *ptr == '0' && *ptr != ',' && *ptr != '.' ) ptr--;
    if( *ptr != '.' && *ptr != ',' ) ptr++;
    *ptr = '\0';
    return buf;
}

static const char* MemSizeToString( int64_t val )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const auto aval = abs( val );

    if( aval < 10000ll )
    {
        sprintf( buf, "%" PRIi64 " bytes", val );
        return buf;
    }

    enum class Unit
    {
        Kilobyte,
        Megabyte,
        Gigabyte,
        Terabyte
    };
    Unit unit;

    if( aval < 10000ll * 1024 )
    {
        sprintf( buf, "%.2f", val / 1024. );
        unit = Unit::Kilobyte;
    }
    else if( aval < 10000ll * 1024 * 1024 )
    {
        sprintf( buf, "%.2f", val / ( 1024. * 1024 ) );
        unit = Unit::Megabyte;
    }
    else if( aval < 10000ll * 1024 * 1024 * 1024 )
    {
        sprintf( buf, "%.2f", val / ( 1024. * 1024 * 1024 ) );
        unit = Unit::Gigabyte;
    }
    else
    {
        sprintf( buf, "%.2f", val / ( 1024. * 1024 * 1024 * 1024 ) );
        unit = Unit::Terabyte;
    }

    auto ptr = buf;
    while( *ptr ) ptr++;
    ptr--;
    while( ptr >= buf && *ptr == '0' ) ptr--;
    if( *ptr != '.' ) ptr++;

    *ptr++ = ' ';
    switch( unit )
    {
    case Unit::Kilobyte:
        *ptr++ = 'K';
        break;
    case Unit::Megabyte:
        *ptr++ = 'M';
        break;
    case Unit::Gigabyte:
        *ptr++ = 'G';
        break;
    case Unit::Terabyte:
        *ptr++ = 'T';
        break;
    default:
        assert( false );
        break;
    }
    *ptr++ = 'B';
    *ptr++ = '\0';

    return buf;
}

static void TextFocused( const char* label, const char* value )
{
    ImGui::TextDisabled( "%s", label );
    ImGui::SameLine();
    ImGui::Text( "%s", value );
}

enum { MinVisSize = 3 };
enum { MinFrameSize = 5 };

static View* s_instance = nullptr;

View::View( const char* addr, ImFont* fixedWidth, SetTitleCallback stcb )
    : m_worker( addr )
    , m_staticView( false )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zvHeight( 0 )
    , m_zvScroll( 0 )
    , m_zoneInfoWindow( nullptr )
    , m_zoneSrcLocHighlight( 0 )
    , m_lockHighlight { -1 }
    , m_msgHighlight( nullptr )
    , m_msgToFocus( nullptr )
    , m_gpuInfoWindow( nullptr )
    , m_callstackInfoWindow( 0 )
    , m_memoryAllocInfoWindow( -1 )
    , m_memoryAllocHover( -1 )
    , m_memoryAllocHoverWait( 0 )
    , m_frames( nullptr )
    , m_gpuThread( 0 )
    , m_gpuStart( 0 )
    , m_gpuEnd( 0 )
    , m_showOptions( false )
    , m_showMessages( false )
    , m_showStatistics( false )
    , m_showInfo( false )
    , m_drawGpuZones( true )
    , m_drawZones( true )
    , m_drawLocks( true )
    , m_drawPlots( true )
    , m_onlyContendedLocks( true )
    , m_statSort( 0 )
    , m_statSelf( false )
    , m_showCallstackFrameAddress( false )
    , m_namespace( Namespace::Full )
    , m_textEditorFont( fixedWidth )
    , m_stcb( stcb )
    , m_titleSet( false )
{
    assert( s_instance == nullptr );
    s_instance = this;

    InitTextEditor();
}

View::View( FileRead& f, ImFont* fixedWidth, SetTitleCallback stcb )
    : m_worker( f )
    , m_staticView( true )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zvHeight( 0 )
    , m_zvScroll( 0 )
    , m_zoneInfoWindow( nullptr )
    , m_zoneSrcLocHighlight( 0 )
    , m_msgHighlight( nullptr )
    , m_msgToFocus( nullptr )
    , m_gpuInfoWindow( nullptr )
    , m_callstackInfoWindow( 0 )
    , m_memoryAllocInfoWindow( -1 )
    , m_memoryAllocHover( -1 )
    , m_memoryAllocHoverWait( 0 )
    , m_frames( m_worker.GetFramesBase() )
    , m_gpuThread( 0 )
    , m_gpuStart( 0 )
    , m_gpuEnd( 0 )
    , m_showOptions( false )
    , m_showMessages( false )
    , m_showStatistics( false )
    , m_showInfo( false )
    , m_drawGpuZones( true )
    , m_drawZones( true )
    , m_drawLocks( true )
    , m_drawPlots( true )
    , m_onlyContendedLocks( true )
    , m_statSort( 0 )
    , m_statSelf( false )
    , m_showCallstackFrameAddress( false )
    , m_namespace( Namespace::Full )
    , m_textEditorFont( fixedWidth )
    , m_stcb( stcb )
    , m_titleSet( false )
{
    assert( s_instance == nullptr );
    s_instance = this;

    InitTextEditor();
}

View::~View()
{
    m_worker.Shutdown();

    if( m_compare.loadThread.joinable() ) m_compare.loadThread.join();

    assert( s_instance != nullptr );
    s_instance = nullptr;
}

void View::InitTextEditor()
{
    m_textEditor = std::make_unique<TextEditor>();
    m_textEditor->SetReadOnly( true );
    m_textEditor->SetLanguageDefinition( TextEditor::LanguageDefinition::CPlusPlus() );

    m_textEditorFile = nullptr;
}

void View::SetTextEditorFile( const char* fileName, int line )
{
    if( !m_textEditorFile || strcmp( m_textEditorFile, fileName ) != 0 )
    {
        FILE* f = fopen( fileName, "rb" );
        fseek( f, 0, SEEK_END );
        const auto sz = ftell( f );
        fseek( f, 0, SEEK_SET );
        auto data = new char[sz];
        fread( data, 1, sz, f );
        fclose( f );
        m_textEditor->SetText( data );
        delete[] data;
    }

    m_textEditor->SetCursorPosition( TextEditor::Coordinates( line-1, 0 ) );

    m_textEditorFile = fileName;
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
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos( 450.0f );
        ImGui::TextUnformatted( desc );
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

void View::DrawTextContrast( ImDrawList* draw, const ImVec2& pos, uint32_t color, const char* text )
{
    draw->AddText( pos + ImVec2( 1, 1 ), 0x88000000, text );
    draw->AddText( pos, color, text );
}

bool View::Draw()
{
    HandshakeStatus status = (HandshakeStatus)s_instance->m_worker.GetHandshakeStatus();
    if( status == HandshakeProtocolMismatch )
    {
        ImGui::OpenPopup( "Protocol mismatch" );
    }
    else if( status == HandshakeNotAvailable )
    {
        ImGui::OpenPopup( "Client not ready" );
    }

    if( ImGui::BeginPopupModal( "Protocol mismatch", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
#endif
        ImGui::Text( "The client you are trying to connect to uses incompatible protocol version.\nMake sure you are using the same Tracy version on both client and server." );
        ImGui::Separator();
        if( ImGui::Button( "My bad" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::EndPopup();
    }

    if( ImGui::BeginPopupModal( "Client not ready", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_LIGHTBULB );
#endif
        ImGui::Text( "The client you are trying to connect to is no longer able to sent profiling data,\nbecause another server was already connected to it.\nYou can do the following:\n\n  1. Restart the client application.\n  2. Rebuild the client application with on-demand mode enabled." );
        ImGui::Separator();
        if( ImGui::Button( "I understand" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::EndPopup();
    }

    return s_instance->DrawImpl();
}

static const char* MainWindowButtons[] = {
#ifdef TRACY_EXTENDED_FONT
    ICON_FA_PLAY " Resume",
    ICON_FA_PAUSE " Pause"
#else
    "Resume",
    "Pause"
#endif
};

enum { MainWindowButtonsCount = sizeof( MainWindowButtons ) / sizeof( *MainWindowButtons ) };

bool View::DrawImpl()
{
    if( !m_worker.HasData() )
    {
        char tmp[2048];
        sprintf( tmp, "%s###Connection", m_worker.GetAddr().c_str() );
        ImGui::Begin( tmp, nullptr, ImGuiWindowFlags_AlwaysAutoResize );
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_WIFI );
#endif
        ImGui::Text( "Waiting for connection..." );
        ImGui::End();
        return true;
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
    if( !m_staticView )
    {
        DrawConnection();
    }
    else
    {
        keepOpenPtr = &keepOpen;
    }

#ifdef TRACY_ROOT_WINDOW
    if( !m_titleSet && m_stcb )
    {
        m_titleSet = true;
        m_stcb( m_worker.GetCaptureName().c_str() );
    }

    auto& style = ImGui::GetStyle();
    const auto wrPrev = style.WindowRounding;
    const auto wbsPrev = style.WindowBorderSize;
    const auto wpPrev = style.WindowPadding;
    style.WindowRounding = 0.f;
    style.WindowBorderSize = 0.f;
    style.WindowPadding = ImVec2( 4.f, 4.f );

    ImGui::SetNextWindowPos( ImVec2( 0, 0 ) );
    ImGui::SetNextWindowSize( ImVec2( m_rootWidth, m_rootHeight ) );
    ImGui::Begin( "Timeline view###Profiler", nullptr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoMove );

    style.WindowRounding = wrPrev;
    style.WindowBorderSize = wbsPrev;
    style.WindowPadding = wpPrev;
#else
    char tmp[2048];
    sprintf( tmp, "%s###Profiler", m_worker.GetCaptureName().c_str() );
    ImGui::SetNextWindowSize( ImVec2( 1550, 800 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( tmp, keepOpenPtr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus );
#endif

    std::lock_guard<TracyMutex> lock( m_worker.GetDataLock() );
    if( !m_worker.IsDataStatic() )
    {
        if( ImGui::Button( m_pause ? MainWindowButtons[0] : MainWindowButtons[1], ImVec2( bw, 0 ) ) ) m_pause = !m_pause;
    }
    else
    {
        ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f) );
        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f) );
        ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f) );
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_POWER_OFF ) ) keepOpen = false;
#else
        if( ImGui::Button( "Close" ) ) keepOpen = false;
#endif
        ImGui::PopStyleColor( 3 );
    }
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_COG " Options" ) ) m_showOptions = true;
#else
    if( ImGui::Button( "Options" ) ) m_showOptions = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_TAGS " Messages" ) ) m_showMessages = true;
#else
    if( ImGui::Button( "Messages" ) ) m_showMessages = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_SEARCH " Find zone" ) ) m_findZone.show = true;
#else
    if( ImGui::Button( "Find zone" ) ) m_findZone.show = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_SORT_AMOUNT_UP " Statistics" ) ) m_showStatistics = true;
#else
    if( ImGui::Button( "Statistics" ) ) m_showStatistics = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_MEMORY " Memory" ) ) m_memInfo.show = true;
#else
    if( ImGui::Button( "Memory" ) ) m_memInfo.show = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_BALANCE_SCALE " Compare" ) ) m_compare.show = true;
#else
    if( ImGui::Button( "Compare" ) ) m_compare.show = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_FINGERPRINT " Info" ) ) m_showInfo = true;
#else
    if( ImGui::Button( "Info" ) ) m_showInfo = true;
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::SmallButton( ICON_FA_CARET_LEFT ) ) ZoomToPrevFrame();
#else
    if( ImGui::SmallButton( "<" ) ) ZoomToPrevFrame();
#endif
    ImGui::SameLine();
    {
        const auto vis = Visible( m_frames );
        if( !vis )
        {
            ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
        }
        ImGui::Text( "%s: %s", m_frames->name == 0 ? "Frames" : m_worker.GetString( m_frames->name ), RealToString( m_worker.GetFrameCount( *m_frames ), true ) );
        if( !vis )
        {
            ImGui::PopStyleColor();
        }
    }
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::SmallButton( ICON_FA_CARET_RIGHT ) ) ZoomToNextFrame();
#else
    if( ImGui::SmallButton( ">" ) ) ZoomToNextFrame();
#endif
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
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
    ImGui::Text( "Time span: %-10s View span: %-10s Zones: %-13s Queue delay: %s  Timer resolution: %s", TimeToString( m_worker.GetLastTime() - m_worker.GetTimeBegin() ), TimeToString( m_zvEnd - m_zvStart ), RealToString( m_worker.GetZoneCount(), true ), TimeToString( m_worker.GetDelay() ), TimeToString( m_worker.GetResolution() ) );
    DrawFrames();
    DrawZones();
    ImGui::End();

    m_zoneHighlight = nullptr;
    m_gpuHighlight = nullptr;

    DrawInfoWindow();

    if( m_showOptions ) DrawOptions();
    if( m_showMessages ) DrawMessages();
    if( m_findZone.show ) DrawFindZone();
    if( m_showStatistics ) DrawStatistics();
    if( m_memInfo.show ) DrawMemory();
    if( m_compare.show ) DrawCompare();
    if( m_callstackInfoWindow != 0 ) DrawCallstackWindow();
    if( m_memoryAllocInfoWindow >= 0 ) DrawMemoryAllocWindow();
    if( m_showInfo ) DrawInfo();
    if( m_textEditorFile ) DrawTextEditor();

    const auto& io = ImGui::GetIO();
    if( m_zoomAnim.active )
    {
        m_zoomAnim.progress += io.DeltaTime * m_zoomAnim.lenMod;
        if( m_zoomAnim.progress >= 1.f )
        {
            m_zoomAnim.active = false;
            m_zvStart = m_zoomAnim.start1;
            m_zvEnd = m_zoomAnim.end1;
        }
        else
        {
            const auto v = sqrt( sin( M_PI_2 * m_zoomAnim.progress ) );
            m_zvStart = int64_t( m_zoomAnim.start0 + ( m_zoomAnim.start1 - m_zoomAnim.start0 ) * v );
            m_zvEnd = int64_t( m_zoomAnim.end0 + ( m_zoomAnim.end1 - m_zoomAnim.end0 ) * v );
        }
    }

    m_callstackBuzzAnim.Update( io.DeltaTime );
    m_callstackTreeBuzzAnim.Update( io.DeltaTime );
    m_zoneinfoBuzzAnim.Update( io.DeltaTime );
    m_findZoneBuzzAnim.Update( io.DeltaTime );

    return keepOpen;
}

void View::DrawConnection()
{
    const auto ty = ImGui::GetFontSize();
    const auto cs = ty * 0.9f;

    {
        std::lock_guard<TracyMutex> lock( m_worker.GetMbpsDataLock() );
        char tmp[2048];
        sprintf( tmp, "%s###Connection", m_worker.GetAddr().c_str() );
        ImGui::Begin( tmp, nullptr, ImGuiWindowFlags_AlwaysAutoResize );
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
        ImGui::PlotLines( buf, mbpsVector.data(), mbpsVector.size(), 0, nullptr, 0, std::numeric_limits<float>::max(), ImVec2( 150, 0 ) );
        ImGui::Text( "Ratio %.1f%%  Real: %6.2f Mbps", m_worker.GetCompRatio() * 100.f, mbps / m_worker.GetCompRatio() );
    }

    ImGui::Text( "Memory usage: %s", MemSizeToString( memUsage.load( std::memory_order_relaxed ) ) );

    const auto wpos = ImGui::GetWindowPos() + ImGui::GetWindowContentRegionMin();
    ImGui::GetWindowDrawList()->AddCircleFilled( wpos + ImVec2( 1 + cs * 0.5, 3 + ty * 0.5 ), cs * 0.5, m_worker.IsConnected() ? 0xFF2222CC : 0xFF444444, 10 );

    std::lock_guard<TracyMutex> lock( m_worker.GetDataLock() );
    {
        const auto sz = m_worker.GetFrameCount( *m_frames );
        if( sz > 1 )
        {
            const auto dt = m_worker.GetFrameTime( *m_frames, sz - 2 );
            const auto dtm = dt / 1000000.f;
            const auto fps = 1000.f / dtm;
            ImGui::Text( "FPS: %6.1f  Frame time: %.2f ms", fps, dtm );
        }
    }

#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_SAVE " Save trace" ) )
#else
    if( ImGui::Button( "Save trace" ) )
#endif
    {
#ifdef TRACY_FILESELECTOR
        nfdchar_t* fn;
        auto res = NFD_SaveDialog( "tracy", nullptr, &fn );
        if( res == NFD_OKAY )
#else
        const char* fn = "trace.tracy";
#endif
        {
            std::unique_ptr<FileWrite> f;
            const auto sz = strlen( fn );
            if( sz < 7 || memcmp( fn + sz - 6, ".tracy", 6 ) != 0 )
            {
                char tmp[1024];
                sprintf( tmp, "%s.tracy", fn );
                f.reset( FileWrite::Open( tmp ) );
            }
            else
            {
                f.reset( FileWrite::Open( fn ) );
            }
            if( f )
            {
                m_worker.Write( *f );
            }
        }
    }

    ImGui::End();
}

static ImU32 GetFrameColor( uint64_t frameTime )
{
    enum { BestTime = 1000 * 1000 * 1000 / 143 };
    enum { GoodTime = 1000 * 1000 * 1000 / 59 };
    enum { BadTime = 1000 * 1000 * 1000 / 29 };

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

void View::DrawFrames()
{
    assert( m_worker.GetFrameCount( *m_frames ) != 0 );

    const auto Height = 40 * ImGui::GetTextLineHeight() / 15.f;

    enum { MaxFrameTime = 50 * 1000 * 1000 };  // 50ms

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto wspace = ImGui::GetWindowContentRegionMax() - ImGui::GetWindowContentRegionMin();
    const auto w = wspace.x;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##frames", ImVec2( w, Height ) );
    bool hover = ImGui::IsItemHovered();

    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x33FFFFFF );
    const auto wheel = io.MouseWheel;
    const auto prevScale = m_frameScale;
    if( hover )
    {
        if( wheel > 0 )
        {
            if( m_frameScale >= 0 ) m_frameScale--;
        }
        else if( wheel < 0 )
        {
            if( m_frameScale < 10 ) m_frameScale++;
        }
    }

    const int fwidth = GetFrameWidth( m_frameScale );
    const int group = GetFrameGroup( m_frameScale );
    const int total = m_worker.GetFrameCount( *m_frames );
    const int onScreen = ( w - 2 ) / fwidth;
    if( !m_pause )
    {
        m_frameStart = ( total < onScreen * group ) ? 0 : total - onScreen * group;
        m_zvStart = m_worker.GetFrameBegin( *m_frames, std::max( 0, total - 4 ) );
        if( total == 1 )
        {
            m_zvEnd = m_worker.GetLastTime();
        }
        else
        {
            m_zvEnd = m_worker.GetFrameBegin( *m_frames, total - 1 );
        }
    }

    if( hover )
    {
        if( ImGui::IsMouseDragging( 1, 0 ) )
        {
            m_pause = true;
            const auto delta = ImGui::GetMouseDragDelta( 1, 0 ).x;
            if( abs( delta ) >= fwidth )
            {
                const auto d = (int)delta / fwidth;
                m_frameStart = std::max( 0, m_frameStart - d * group );
                io.MouseClickedPos[1].x = io.MousePos.x + d * fwidth - delta;
            }
        }

        const auto mx = io.MousePos.x;
        if( mx > wpos.x && mx < wpos.x + w - 1 )
        {
            const auto mo = mx - ( wpos.x + 1 );
            const auto off = mo * group / fwidth;

            const int sel = m_frameStart + off;
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

                    ImGui::TextDisabled( "Frames:" );
                    ImGui::SameLine();
                    ImGui::Text( "%s - %s (%s)", RealToString( sel, true ), RealToString( sel + g - 1, true ), RealToString( g, true ) );
                    ImGui::Separator();
                    TextFocused( "Max frame time:", TimeToString( f ) );
                }
                else
                {
                    if( m_frames->name == 0 )
                    {
                        const auto offset = m_worker.GetFrameOffset();
                        if( sel == 0 )
                        {
                            ImGui::Text( "Tracy initialization" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                        else if( offset == 0 )
                        {
                            ImGui::TextDisabled( "Frame:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s", RealToString( sel, true ) );
                            ImGui::Separator();
                            TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                        else if( sel == 1 )
                        {
                            ImGui::Text( "Missed frames" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, 1 ) ) );
                        }
                        else
                        {
                            ImGui::TextDisabled( "Frame:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s", RealToString( sel + offset - 1, true ) );
                            ImGui::Separator();
                            TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:", m_worker.GetString( m_frames->name ) );
                        ImGui::SameLine();
                        ImGui::Text( "%s", RealToString( sel + 1, true ) );
                        ImGui::Separator();
                        TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                    }
                }
                TextFocused( "Time from start of program:", TimeToString( m_worker.GetFrameBegin( *m_frames, sel ) - m_worker.GetTimeBegin() ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_pause = true;
                    m_zvStart = m_worker.GetFrameBegin( *m_frames, sel );
                    m_zvEnd = m_worker.GetFrameEnd( *m_frames, sel + group - 1 );
                    if( m_zvStart == m_zvEnd ) m_zvStart--;
                }
                else if( ImGui::IsMouseDragging( 0 ) )
                {
                    m_zvStart = std::min( m_zvStart, m_worker.GetFrameBegin( *m_frames, sel ) );
                    m_zvEnd = std::max( m_zvEnd, m_worker.GetFrameEnd( *m_frames, sel + group - 1 ) );
                }
            }

            if( m_pause && wheel != 0 )
            {
                const int pfwidth = GetFrameWidth( prevScale );
                const int pgroup = GetFrameGroup( prevScale );

                const auto oldoff = mo * pgroup / pfwidth;
                m_frameStart = std::min( total, std::max( 0, m_frameStart - int( off - oldoff ) ) );
            }
        }
    }

    int i = 0, idx = 0;
    while( i < onScreen && m_frameStart + idx < total )
    {
        auto f = m_worker.GetFrameTime( *m_frames, m_frameStart + idx );
        int g;
        if( group > 1 )
        {
            g = std::min( group, total - ( m_frameStart + idx ) );
            for( int j=1; j<g; j++ )
            {
                f = std::max( f, m_worker.GetFrameTime( *m_frames, m_frameStart + idx + j ) );
            }
        }

        const auto h = float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 );
        if( fwidth != 1 )
        {
            draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), GetFrameColor( f ) );
        }
        else
        {
            draw->AddLine( wpos + ImVec2( 1+i, Height-2-h ), wpos + ImVec2( 1+i, Height-2 ), GetFrameColor( f ) );
        }

        i++;
        idx += group;
    }

    const std::pair <int, int> zrange = m_worker.GetFrameRange( *m_frames, m_zvStart, m_zvEnd );

    if( zrange.second > m_frameStart && zrange.first < m_frameStart + onScreen * group )
    {
        auto x1 = std::min( onScreen * fwidth, ( zrange.second - m_frameStart ) * fwidth / group );
        auto x0 = std::max( 0, ( zrange.first - m_frameStart ) * fwidth / group );

        if( x0 == x1 ) x1 = x0 + 1;

        draw->AddRectFilled( wpos + ImVec2( 1+x0, 0 ), wpos + ImVec2( 1+x1, Height ), 0x55DD22DD );
    }
}

void View::HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns )
{
    assert( timespan > 0 );
    auto& io = ImGui::GetIO();

    const auto nspx = double( timespan ) / w;

    if( ImGui::IsMouseClicked( 0 ) )
    {
        m_highlight.active = true;
        m_highlight.start = m_highlight.end = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( ImGui::IsMouseDragging( 0, 0 ) )
    {
        m_highlight.end = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else
    {
        m_highlight.active = false;
    }

    if( ImGui::IsMouseClicked( 2 ) )
    {
        m_highlightZoom.active = true;
        m_highlightZoom.start = m_highlightZoom.end = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( ImGui::IsMouseDragging( 2, 0 ) )
    {
        m_highlightZoom.end = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
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
                const auto tsOld = m_zvEnd - m_zvStart;
                const auto tsNew = e - s;
                const auto mul = double( tsOld ) / tsNew;
                const auto left = s - m_zvStart;
                const auto right = m_zvEnd - e;

                ZoomToRange( m_zvStart - left * mul, m_zvEnd + right * mul );
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

    if( ImGui::IsMouseDragging( 1, 0 ) )
    {
        m_zoomAnim.active = false;
        m_pause = true;
        const auto delta = ImGui::GetMouseDragDelta( 1, 0 );
        const auto dpx = int64_t( delta.x * nspx );
        if( dpx != 0 )
        {
            m_zvStart -= dpx;
            m_zvEnd -= dpx;
            io.MouseClickedPos[1].x = io.MousePos.x;
        }
        if( delta.y != 0 )
        {
            auto y = ImGui::GetScrollY();
            ImGui::SetScrollY( y - delta.y );
            io.MouseClickedPos[1].y = io.MousePos.y;
        }
    }

    const auto wheel = io.MouseWheel;
    if( wheel != 0 )
    {
        m_zoomAnim.active = false;
        m_pause = true;
        const double mouse = io.MousePos.x - wpos.x;
        const auto p = mouse / w;
        const auto p1 = timespan * p;
        const auto p2 = timespan - p1;
        if( wheel > 0 )
        {
            m_zvStart += int64_t( p1 * 0.25 );
            m_zvEnd -= int64_t( p2 * 0.25 );
        }
        else if( timespan < 1000ll * 1000 * 1000 * 60 * 60 )
        {
            m_zvStart -= std::max( int64_t( 1 ), int64_t( p1 * 0.25 ) );
            m_zvEnd += std::max( int64_t( 1 ), int64_t( p2 * 0.25 ) );
        }
        timespan = m_zvEnd - m_zvStart;
        pxns = w / double( timespan );
    }
}

const char* View::GetFrameText( const FrameData& fd, int i, uint64_t ftime, uint64_t offset ) const
{
    static char buf[1024];
    if( fd.name == 0 )
    {
        if( i == 0 )
        {
            sprintf( buf, "Tracy init (%s)", TimeToString( ftime ) );
        }
        else if( offset == 0 )
        {
            sprintf( buf, "Frame %s (%s)", RealToString( i, true ), TimeToString( ftime ) );
        }
        else if( i == 1 )
        {
            sprintf( buf, "Missed frames (%s)", TimeToString( ftime ) );
        }
        else
        {
            sprintf( buf, "Frame %s (%s)", RealToString( i + offset - 1, true ), TimeToString( ftime ) );
        }
    }
    else
    {
        sprintf( buf, "%s %s (%s)", m_worker.GetString( fd.name ), RealToString( i + 1, true ), TimeToString( ftime ) );
    }
    return buf;
}

bool View::DrawZoneFramesHeader()
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - ImGui::GetStyle().ScrollbarSize;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetFontSize();

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty * 1.5 ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover ) HandleZoneViewMouse( timespan, wpos, w, pxns );

    {
        const auto nspx = 1.0 / pxns;
        const auto scale = std::max( 0.0, round( log10( nspx ) + 2 ) );
        const auto step = pow( 10, scale );

        const auto dx = step * pxns;
        double x = 0;
        int tw = 0;
        int tx = 0;
        int64_t tt = 0;
        while( x < w )
        {
            draw->AddLine( wpos + ImVec2( x, 0 ), wpos + ImVec2( x, round( ty * 0.5 ) ), 0x66FFFFFF );
            if( tw == 0 )
            {
                char buf[128];
                const auto t = m_zvStart - m_worker.GetTimeBegin();
                auto txt = TimeToString( t );
                if( t >= 0 )
                {
                    sprintf( buf, "+%s", txt );
                    txt = buf;
                }
                draw->AddText( wpos + ImVec2( x, round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                tw = ImGui::CalcTextSize( txt ).x;
            }
            else if( x > tx + tw + ty * 2 )
            {
                tx = x;
                auto txt = TimeToString( tt );
                draw->AddText( wpos + ImVec2( x, round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                tw = ImGui::CalcTextSize( txt ).x;
            }

            for( int i=1; i<5; i++ )
            {
                draw->AddLine( wpos + ImVec2( x + i * dx / 10, 0 ), wpos + ImVec2( x + i * dx / 10, round( ty * 0.25 ) ), 0x33FFFFFF );
            }
            draw->AddLine( wpos + ImVec2( x + 5 * dx / 10, 0 ), wpos + ImVec2( x + 5 * dx / 10, round( ty * 0.375 ) ), 0x33FFFFFF );
            for( int i=6; i<10; i++ )
            {
                draw->AddLine( wpos + ImVec2( x + i * dx / 10, 0 ), wpos + ImVec2( x + i * dx / 10, round( ty * 0.25 ) ), 0x33FFFFFF );
            }

            x += dx;
            tt += step;
        }
    }

    return hover;
}

static uint32_t DarkenColor( uint32_t color )
{
    return 0xFF000000 |
        ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) * 2 / 3 ) ) << 16 ) |
        ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) * 2 / 3 ) ) << 8  ) |
        ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) * 2 / 3 ) )       );
}

static void DrawZigZag( ImDrawList* draw, const ImVec2& wpos, double start, double end, double h, uint32_t color )
{
    int mode = 0;
    while( start < end )
    {
        double step = std::min( end - start, mode == 0 ? h/2 : h );
        switch( mode )
        {
        case 0:
            draw->AddLine( wpos + ImVec2( start, 0 ), wpos + ImVec2( start + step, round( -step ) ), color );
            mode = 1;
            break;
        case 1:
            draw->AddLine( wpos + ImVec2( start, round( -h/2 ) ), wpos + ImVec2( start + step, round( step - h/2 ) ), color );
            mode = 2;
            break;
        case 2:
            draw->AddLine( wpos + ImVec2( start, round( h/2 ) ), wpos + ImVec2( start + step, round( h/2 - step ) ), color );
            mode = 1;
            break;
        default:
            assert( false );
            break;
        };
        start += step;
    }
}

bool View::DrawZoneFrames( const FrameData& frames )
{
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - ImGui::GetStyle().ScrollbarSize;
    const auto wh = ImGui::GetContentRegionAvail().y;
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetFontSize();

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, ty ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover ) HandleZoneViewMouse( timespan, wpos, w, pxns );

    const auto nspx = 1.0 / pxns;

    const std::pair <int, int> zrange = m_worker.GetFrameRange( frames, m_zvStart, m_zvEnd );
    if( zrange.first < 0 ) return hover;

    int64_t prev = -1;
    int64_t prevEnd = -1;
    bool tooltipDisplayed = false;

    for( int i = zrange.first; i < zrange.second; i++ )
    {
        const auto ftime = m_worker.GetFrameTime( frames, i );
        const auto fbegin = m_worker.GetFrameBegin( frames, i );
        const auto fend = m_worker.GetFrameEnd( frames, i );
        const auto fsz = pxns * ftime;

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, ty ) ) )
        {
            tooltipDisplayed = true;

            ImGui::BeginTooltip();
            ImGui::Text( "%s", GetFrameText( frames, i, ftime, m_worker.GetFrameOffset() ) );
            ImGui::Separator();
            TextFocused( "Time from start of program:", TimeToString( m_worker.GetFrameBegin( frames, i ) - m_worker.GetTimeBegin() ) );
            ImGui::EndTooltip();

            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToRange( fbegin, fend );
            }
        }

        if( fsz < MinFrameSize )
        {
            if( !frames.continuous && prev != -1 )
            {
                if( ( fbegin - prevEnd ) * pxns >= MinFrameSize )
                {
                    DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( prevEnd - m_zvStart ) * pxns, ty / 4, 0xFF888888 );
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

            continue;
        }

        if( prev != -1 )
        {
            if( frames.continuous )
            {
                DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( fbegin - m_zvStart ) * pxns, ty / 4, 0xFF888888 );
            }
            else
            {
                DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( prevEnd - m_zvStart ) * pxns, ty / 4, 0xFF888888 );
            }
            prev = -1;
        }

        if( m_frames == &frames )
        {
            if( fbegin >= m_zvStart )
            {
                draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            if( !frames.continuous && fend <= m_zvEnd )
            {
                draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
        }

        auto buf = GetFrameText( frames, i, ftime, m_worker.GetFrameOffset() );
        auto tx = ImGui::CalcTextSize( buf ).x;
        uint32_t color = ( frames.name == 0 && i == 0 ) ? 0xFF4444FF : 0xFFFFFFFF;

        if( fsz - 5 <= tx )
        {
            buf = TimeToString( ftime );
            tx = ImGui::CalcTextSize( buf ).x;
        }

        if( fbegin >= m_zvStart )
        {
            draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, 1 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, ty - 1 ), color );
        }
        if( fend <= m_zvEnd )
        {
            draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, 1 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, ty - 1 ), color );
        }
        if( fsz - 5 > tx )
        {
            const auto part = ( fsz - 5 - tx ) / 2;
            draw->AddLine( wpos + ImVec2( std::max( -10.0, ( fbegin - m_zvStart ) * pxns + 2 ), round( ty / 2 ) ), wpos + ImVec2( std::min( w + 20.0, ( fbegin - m_zvStart ) * pxns + part ), round( ty / 2 ) ), color );
            draw->AddText( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2 + part, 0 ), color, buf );
            draw->AddLine( wpos + ImVec2( std::max( -10.0, ( fbegin - m_zvStart ) * pxns + 2 + part + tx ), round( ty / 2 ) ), wpos + ImVec2( std::min( w + 20.0, ( fend - m_zvStart ) * pxns - 2 ), round( ty / 2 ) ), color );
        }
        else
        {
            draw->AddLine( wpos + ImVec2( std::max( -10.0, ( fbegin - m_zvStart ) * pxns + 2 ), round( ty / 2 ) ), wpos + ImVec2( std::min( w + 20.0, ( fend - m_zvStart ) * pxns - 2 ), round( ty / 2 ) ), color );
        }
    }

    if( prev != -1 )
    {
        DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_zvStart ) * pxns, ty / 4, 0xFF888888 );
        prev = -1;
    }

    const auto fend = m_worker.GetFrameEnd( frames, zrange.second-1 );
    if( fend == m_zvEnd )
    {
        draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
    }

    if( hover && !tooltipDisplayed )
    {
        ImGui::BeginTooltip();
        ImGui::TextDisabled( "Frame set:" );
        ImGui::SameLine();
        ImGui::Text( "%s", frames.name == 0 ? "Frames" : m_worker.GetString( frames.name ) );
        ImGui::EndTooltip();
    }

    return hover;
}

void View::DrawZones()
{
    m_msgHighlight.Decay( nullptr );
    m_zoneSrcLocHighlight.Decay( 0 );

    if( m_zvStart == m_zvEnd ) return;
    assert( m_zvStart < m_zvEnd );

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    m_gpuThread = 0;
    m_gpuStart = 0;
    m_gpuEnd = 0;

    const auto linepos = ImGui::GetCursorScreenPos();
    const auto lineh = ImGui::GetContentRegionAvail().y;

    bool drawMouseLine = DrawZoneFramesHeader();
    auto& frames = m_worker.GetFrames();
    for( auto fd : frames )
    {
        if( Visible( fd ) )
        {
            drawMouseLine |= DrawZoneFrames( *fd );
        }
    }

    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetWindowContentRegionWidth(), ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    window = ImGui::GetCurrentWindow();
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto h = std::max<float>( m_zvHeight, ImGui::GetContentRegionAvail().y - 4 );    // magic border value
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();

    const auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover )
    {
        drawMouseLine = true;
        HandleZoneViewMouse( timespan, wpos, w, pxns );
    }

    const auto nspx = 1.0 / pxns;

    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    int offset = 0;
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;

    const auto yMin = linepos.y;
    const auto yMax = yMin + lineh;

    // gpu zones
    if( m_drawGpuZones )
    {
        for( size_t i=0; i<m_worker.GetGpuData().size(); i++ )
        {
            const auto& v = m_worker.GetGpuData()[i];
            if( !Visible( v ) ) continue;
            bool& showFull = ShowFull( v );

            const auto yPos = wpos.y + offset;
            if( yPos + ostep >= yMin && yPos <= yMax )
            {
                draw->AddLine( wpos + ImVec2( 0, offset + ostep - 1 ), wpos + ImVec2( w, offset + ostep - 1 ), 0x33FFFFFF );

                if( showFull )
                {
                    draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFFFFAAAA );
                }
                else
                {
                    draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF886666 );
                }
                const bool isVulkan = v->thread == 0;
                char buf[64];
                if( isVulkan )
                {
                    sprintf( buf, "Vulkan context %zu", i );
                }
                else
                {
                    sprintf( buf, "OpenGL context %zu", i );
                }
                draw->AddText( wpos + ImVec2( ty, offset ), showFull ? 0xFFFFAAAA : 0xFF886666, buf );

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty ) ) )
                {
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        showFull = !showFull;
                    }

                    ImGui::BeginTooltip();
                    ImGui::Text( "%s", buf );
                    ImGui::Separator();
                    if( !isVulkan )
                    {
                        TextFocused( "Thread:", m_worker.GetThreadString( v->thread ) );
                    }
                    if( !v->timeline.empty() )
                    {
                        const auto t = v->timeline.front()->gpuStart;
                        if( t != std::numeric_limits<int64_t>::max() )
                        {
                            TextFocused( "Appeared at", TimeToString( t - m_worker.GetTimeBegin() ) );
                        }
                    }
                    TextFocused( "Zone count:", RealToString( v->count, true ) );
                    TextFocused( "Top-level zones:", RealToString( v->timeline.size(), true ) );
                    if( isVulkan )
                    {
                        TextFocused( "Timestamp accuracy:", TimeToString( v->period ) );
                    }
                    else
                    {
                        ImGui::TextDisabled( "Query accuracy bits:" );
                        ImGui::SameLine();
                        ImGui::Text( "%i", v->accuracyBits );
                    }
                    ImGui::EndTooltip();
                }
            }

            offset += ostep;
            if( showFull && !v->timeline.empty() && v->timeline.front()->gpuStart != std::numeric_limits<int64_t>::max() )
            {
                const auto begin = v->timeline.front()->gpuStart;
                const auto drift = GpuDrift( v );
                const auto depth = DispatchGpuZoneLevel( v->timeline, hover, pxns, wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                offset += ostep * depth;
            }
            offset += ostep * 0.2f;
        }
    }

    auto& crash = m_worker.GetCrashEvent();
    // zones
    LockHighlight nextLockHighlight { -1 };
    for( const auto& v : m_worker.GetThreadData() )
    {
        if( !Visible( v ) ) continue;
        bool& showFull = ShowFull( v );

        const auto yPos = wpos.y + offset;
        if( yPos + ostep >= yMin && yPos <= yMax )
        {
            draw->AddLine( wpos + ImVec2( 0, offset + ostep - 1 ), wpos + ImVec2( w, offset + ostep - 1 ), 0x33FFFFFF );

            const auto labelColor = crash.thread == v->id ? ( showFull ? 0xFF2222FF : 0xFF111188 ) : ( showFull ? 0xFFFFFFFF : 0xFF888888 );

            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), labelColor );

                auto it = std::lower_bound( v->messages.begin(), v->messages.end(), m_zvStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
                auto end = std::lower_bound( it, v->messages.end(), m_zvEnd, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

                while( it < end )
                {
                    const auto next = std::upper_bound( it, v->messages.end(), (*it)->time + MinVisSize * nspx, [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs->time; } );
                    const auto dist = std::distance( it, next );

                    const auto px = ( (*it)->time - m_zvStart ) * pxns;
                    if( dist > 1 )
                    {
                        draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.5, offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, offset + to ), wpos + ImVec2( px, offset + to + th ), 0xFFDDDDDD );
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, offset + to ), wpos + ImVec2( px, offset + to + th ), 0xFFDDDDDD );
                    }
                    else
                    {
                        const auto color = ( m_msgHighlight == *it ) ? 0xFF4444FF : 0xFFDDDDDD;
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, offset + to ), wpos + ImVec2( px, offset + to + th ), color );
                    }
                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, offset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, offset + ty ) ) )
                    {
                        ImGui::BeginTooltip();
                        if( dist > 1 )
                        {
                            ImGui::Text( "%i messages", (int)dist );
                        }
                        else
                        {
                            ImGui::Text( "%s", TimeToString( (*it)->time - m_worker.GetTimeBegin() ) );
                            ImGui::Separator();
                            ImGui::Text( "Message text:" );
                            ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", m_worker.GetString( (*it)->ref ) );
                        }
                        ImGui::EndTooltip();
                        m_msgHighlight = *it;

                        if( ImGui::IsMouseClicked( 0 ) )
                        {
                            m_showMessages = true;
                            m_msgToFocus = *it;
                        }
                        if( ImGui::IsMouseClicked( 2 ) )
                        {
                            CenterAtTime( (*it)->time );
                        }
                    }
                    it = next;
                }

                if( crash.thread == v->id && crash.time >= m_zvStart && crash.time <= m_zvEnd )
                {
                    const auto px = ( crash.time - m_zvStart ) * pxns;

                    draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px, offset + to + th ), 0xFF2222FF );
                    draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, offset + to + th * 0.5f ), wpos + ImVec2( px, offset + to + th ), 0xFF2222FF );

#ifdef TRACY_EXTENDED_FONT
                    const auto crashText = ICON_FA_SKULL " crash " ICON_FA_SKULL;
#else
                    const auto crashText = "crash";
#endif

                    auto ctw = ImGui::CalcTextSize( crashText ).x;
                    draw->AddText( wpos + ImVec2( px - ctw * 0.5f, offset + to + th * 0.5f - ty ), 0xFF2222FF, crashText );

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, offset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, offset + ty ) ) )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Time:", TimeToString( crash.time - m_worker.GetTimeBegin() ) );
                        TextFocused( "Reason:", m_worker.GetString( crash.message ) );
                        ImGui::EndTooltip();

                        if( ImGui::IsMouseClicked( 0 ) )
                        {
                            m_showInfo = true;
                        }
                    }
                }
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), labelColor );
            }
            const auto txt = m_worker.GetThreadString( v->id );
            const auto txtsz = ImGui::CalcTextSize( txt );
            if( m_gpuThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x448888DD );
                draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x888888DD );
            }
            if( m_gpuInfoWindow && m_gpuInfoWindowThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x4488DD88 );
                draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x + 4, offset + ty ), 0x8888DD88 );
            }
            draw->AddText( wpos + ImVec2( ty, offset ), labelColor, txt );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtsz.x, offset + ty ) ) )
            {
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }

                ImGui::BeginTooltip();
                ImGui::Text( "%s", m_worker.GetThreadString( v->id ) );
                if( crash.thread == v->id )
                {
                    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
#else
                    ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), "Crashed" );
#endif
                }
                if( !v->timeline.empty() )
                {
                    ImGui::Separator();
                    TextFocused( "Appeared at", TimeToString( v->timeline.front()->start - m_worker.GetTimeBegin() ) );
                    TextFocused( "Zone count:", RealToString( v->count, true ) );
                    TextFocused( "Top-level zones:", RealToString( v->timeline.size(), true ) );
                }
                ImGui::EndTooltip();
            }
        }

        offset += ostep;

        if( showFull )
        {
            m_lastCpu = -1;
            if( m_drawZones )
            {
                const auto depth = DispatchZoneLevel( v->timeline, hover, pxns, wpos, offset, 0, yMin, yMax );
                offset += ostep * depth;
            }

            if( m_drawLocks )
            {
                const auto depth = DrawLocks( v->id, hover, pxns, wpos, offset, nextLockHighlight, yMin, yMax );
                offset += ostep * depth;
            }
        }
        offset += ostep * 0.2f;
    }
    m_lockHighlight = nextLockHighlight;

    if( m_drawPlots )
    {
        offset = DrawPlots( offset, pxns, wpos, hover, yMin, yMax );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( scrollPos == 0 && m_zvScroll != 0 )
    {
        m_zvHeight = 0;
    }
    else
    {
        if( offset > m_zvHeight ) m_zvHeight = offset;
    }
    m_zvScroll = scrollPos;

    ImGui::EndChild();

    if( m_gpuStart != 0 && m_gpuEnd != 0 )
    {
        const auto px0 = ( m_gpuStart - m_zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuEnd - m_zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x228888DD );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x448888DD );
    }
    if( m_gpuInfoWindow )
    {
        const auto px0 = ( m_gpuInfoWindow->cpuStart - m_zvStart ) * pxns;
        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( m_gpuInfoWindow->cpuEnd - m_zvStart ) * pxns );
        draw->AddRectFilled( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x2288DD88 );
        draw->AddRect( ImVec2( wpos.x + px0, linepos.y ), ImVec2( wpos.x + px1, linepos.y + lineh ), 0x4488DD88 );
    }

    if( m_highlight.active && m_highlight.start != m_highlight.end )
    {
        const auto s = std::min( m_highlight.start, m_highlight.end );
        const auto e = std::max( m_highlight.start, m_highlight.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x22DD8888 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x44DD8888 );

        ImGui::BeginTooltip();
        ImGui::Text( "%s", TimeToString( e - s ) );
        ImGui::EndTooltip();
    }
    else if( drawMouseLine )
    {
        auto& io = ImGui::GetIO();
        draw->AddLine( ImVec2( io.MousePos.x, linepos.y ), ImVec2( io.MousePos.x, linepos.y + lineh ), 0x33FFFFFF );
    }

    if( m_highlightZoom.active && m_highlightZoom.start != m_highlightZoom.end )
    {
        const auto s = std::min( m_highlightZoom.start, m_highlightZoom.end );
        const auto e = std::max( m_highlightZoom.start, m_highlightZoom.end );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x1688DD88 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x2C88DD88 );
    }

    if( m_memInfo.show && m_memInfo.restrictTime )
    {
        const auto zvMid = ( m_zvEnd - m_zvStart ) / 2;
        draw->AddLine( ImVec2( wpos.x + zvMid * pxns, linepos.y ), ImVec2( wpos.x + zvMid * pxns, linepos.y + lineh ), 0x88FF44FF );
    }
}

int View::DispatchZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        return DrawZoneLevel( vec, hover, pxns, wpos, _offset, depth, yMin, yMax );
    }
    else
    {
        return SkipZoneLevel( vec, hover, pxns, wpos, _offset, depth, yMin, yMax );
    }
}

int View::DrawZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        const auto color = GetZoneColor( ev );
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = std::max( ( end - ev.start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            int num = 1;
            const auto px0 = ( ev.start - m_zvStart ) * pxns;
            auto px1 = ( end - m_zvStart ) * pxns;
            auto rend = end;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                num++;
            }
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ) ) )
            {
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num, true ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - ev.start ) );
                    ImGui::EndTooltip();

                    if( ImGui::IsMouseClicked( 2 ) && rend - ev.start > 0 )
                    {
                        ZoomToRange( ev.start, rend );
                    }
                }
                else
                {
                    ZoneTooltip( ev );

                    if( ImGui::IsMouseClicked( 2 ) && rend - ev.start > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        ShowZoneInfo( ev );
                    }

                    m_zoneSrcLocHighlight = ev.srcloc;
                }
            }
            char tmp[64];
            sprintf( tmp, "%s", RealToString( num, true ) );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            const char* zoneName = m_worker.GetZoneName( ev );
            int dmul = ev.text.active ? 2 : 1;

            bool migration = false;
            if( m_lastCpu != ev.cpu_start )
            {
                if( m_lastCpu >= 0 )
                {
                    migration = true;
                }
                m_lastCpu = ev.cpu_start;
            }

            if( ev.child >= 0 )
            {
                const auto d = DispatchZoneLevel( m_worker.GetZoneChildren( ev.child ), hover, pxns, wpos, _offset, depth, yMin, yMax );
                if( d > maxdepth ) maxdepth = d;
            }

            if( ev.end >= 0 && m_lastCpu != ev.cpu_end )
            {
                m_lastCpu = ev.cpu_end;
                migration = true;
            }

            auto tsz = ImGui::CalcTextSize( zoneName );
            if( tsz.x > zsz )
            {
                zoneName = ShortenNamespace( zoneName );
                tsz = ImGui::CalcTextSize( zoneName );
            }

            const auto pr0 = ( ev.start - m_zvStart ) * pxns;
            const auto pr1 = ( end - m_zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), color );
            draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), GetZoneHighlight( ev, migration ), 0.f, -1, GetZoneThickness( ev ) );
            if( dsz * dmul >= MinVisSize )
            {
                draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz*dmul, pr1 ), offset + tsz.y ), 0x882222DD );
                draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), 0x882222DD );
            }
            if( rsz >= MinVisSize )
            {
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );

                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( ev.start - m_zvStart ) * pxns + ( ( end - ev.start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.start == ev.end )
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
                DrawTextContrast( draw, wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ) ) )
            {
                ZoneTooltip( ev );

                if( !m_zoomAnim.active && ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    ShowZoneInfo( ev );
                }

                m_zoneSrcLocHighlight = ev.srcloc;
            }

            ++it;
        }
    }
    return maxdepth;
}

int View::SkipZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = std::max( ( end - ev.start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            auto px1 = ( end - m_zvStart ) * pxns;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
            }
        }
        else
        {
            m_lastCpu = ev.cpu_start;

            if( ev.child >= 0 )
            {
                const auto d = DispatchZoneLevel( m_worker.GetZoneChildren( ev.child ), hover, pxns, wpos, _offset, depth, yMin, yMax );
                if( d > maxdepth ) maxdepth = d;
            }

            if( ev.end >= 0 && m_lastCpu != ev.cpu_end )
            {
                m_lastCpu = ev.cpu_end;
            }

            ++it;
        }
    }
    return maxdepth;
}

int View::DispatchGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        return DrawGpuZoneLevel( vec, hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
    }
    else
    {
        return SkipGpuZoneLevel( vec, hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
    }
}

static int64_t AdjustGpuTime( int64_t time, int64_t begin, int drift )
{
    const auto t = time - begin;
    return time + t / 1000000000 * drift;
}

int View::DrawGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [begin, drift] ( const auto& l, const auto& r ) { return (uint64_t)AdjustGpuTime( l->gpuEnd, begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [begin, drift] ( const auto& l, const auto& r ) { return AdjustGpuTime( l->gpuStart, begin, drift ) < r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        const auto color = GetZoneColor( ev );
        auto end = m_worker.GetZoneEnd( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.gpuStart, begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            int num = 1;
            const auto px0 = ( start - m_zvStart ) * pxns;
            auto px1 = ( end - m_zvStart ) * pxns;
            auto rend = end;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( **it ), begin, drift );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                num++;
            }
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ), color );
            DrawZigZag( draw, wpos + ImVec2( 0, offset + ty/2 ), std::max( px0, -10.0 ), std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), ty/4, DarkenColor( color ) );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( std::max( px1, px0+MinVisSize ), double( w + 10 ) ), offset + ty ) ) )
            {
                if( num > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Zones too small to display:", RealToString( num, true ) );
                    ImGui::Separator();
                    TextFocused( "Execution time:", TimeToString( rend - start ) );
                    ImGui::EndTooltip();

                    if( ImGui::IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToRange( start, rend );
                    }
                }
                else
                {
                    ZoneTooltip( ev );

                    if( ImGui::IsMouseClicked( 2 ) && rend - start > 0 )
                    {
                        ZoomToZone( ev );
                    }
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        ShowZoneInfo( ev, thread );
                    }

                    m_gpuThread = thread;
                    m_gpuStart = ev.cpuStart;
                    m_gpuEnd = ev.cpuEnd;
                }
            }
            char tmp[64];
            sprintf( tmp, "%s", RealToString( num, true ) );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                DrawTextContrast( draw, wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            if( ev.child >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.child ), hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }

            const char* zoneName = m_worker.GetZoneName( ev );
            auto tsz = ImGui::CalcTextSize( zoneName );

            const auto pr0 = ( start - m_zvStart ) * pxns;
            const auto pr1 = ( end - m_zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::max( { std::min( pr1, double( w + 10 ) ), px0 + pxns * 0.5, px0 + MinVisSize } );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), color );
            draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), GetZoneHighlight( ev ), 0.f, -1, GetZoneThickness( ev ) );
            if( dsz >= MinVisSize )
            {
                draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz, pr1 ), offset + tsz.y ), 0x882222DD );
                draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), 0x882222DD );
            }
            if( rsz >= MinVisSize )
            {
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr0 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );

                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/2 ) ), wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/2 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 + rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 - rsz, offset + round( tsz.y/4 ) ), wpos + ImVec2( pr1 - rsz, offset + round( 3*tsz.y/4 ) ), 0xAAFFFFFF );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( start - m_zvStart ) * pxns + ( ( end - start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    DrawTextContrast( draw, wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else if( ev.gpuStart == ev.gpuEnd )
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
                DrawTextContrast( draw, wpos + ImVec2( ( start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ) ) )
            {
                ZoneTooltip( ev );

                if( !m_zoomAnim.active && ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    ShowZoneInfo( ev, thread );
                }

                m_gpuThread = thread;
                m_gpuStart = ev.cpuStart;
                m_gpuEnd = ev.cpuEnd;
            }

            ++it;
        }
    }
    return maxdepth;
}

int View::SkipGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [begin, drift] ( const auto& l, const auto& r ) { return (uint64_t)AdjustGpuTime( l->gpuEnd, begin, drift ) < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [begin, drift] ( const auto& l, const auto& r ) { return AdjustGpuTime( l->gpuStart, begin, drift ) < r; } );
    if( it == zitend ) return depth;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        auto end = m_worker.GetZoneEnd( ev );
        if( end == std::numeric_limits<int64_t>::max() ) break;
        const auto start = AdjustGpuTime( ev.gpuStart, begin, drift );
        end = AdjustGpuTime( end, begin, drift );
        const auto zsz = std::max( ( end - start ) * pxns, pxns * 0.5 );
        if( zsz < MinVisSize )
        {
            auto px1 = ( end - m_zvStart ) * pxns;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( **it ), begin, drift );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
            }
        }
        else
        {
            if( ev.child >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.child ), hover, pxns, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
                if( d > maxdepth ) maxdepth = d;
            }
            ++it;
        }
    }
    return maxdepth;
}

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

enum class LockState
{
    Nothing,
    HasLock,            // green
    HasBlockingLock,    // yellow
    WaitLock            // red
};

static Vector<LockEvent*>::const_iterator GetNextLockEvent( const Vector<LockEvent*>::const_iterator& it, const Vector<LockEvent*>::const_iterator& end, LockState& nextState, uint64_t threadBit )
{
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            if( (*next)->lockCount != 0 )
            {
                if( GetThreadBit( (*next)->lockingThread ) == threadBit )
                {
                    nextState = AreOtherWaiting( (*next)->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                    break;
                }
                else if( IsThreadWaiting( (*next)->waitList, threadBit ) )
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
            if( (*next)->lockCount == 0 )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( (*next)->waitList != 0 )
            {
                if( AreOtherWaiting( (*next)->waitList, threadBit ) )
                {
                    nextState = LockState::HasBlockingLock;
                }
                break;
            }
            if( (*next)->waitList != (*it)->waitList || (*next)->lockCount != (*it)->lockCount )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::HasBlockingLock:
        while( next < end )
        {
            if( (*next)->lockCount == 0 )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( (*next)->waitList != (*it)->waitList || (*next)->lockCount != (*it)->lockCount )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::WaitLock:
        while( next < end )
        {
            if( GetThreadBit( (*next)->lockingThread ) == threadBit )
            {
                nextState = AreOtherWaiting( (*next)->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( (*next)->lockingThread != (*it)->lockingThread )
            {
                break;
            }
            if( (*next)->lockCount == 0 )
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

static Vector<LockEvent*>::const_iterator GetNextLockEventShared( const Vector<LockEvent*>::const_iterator& it, const Vector<LockEvent*>::const_iterator& end, LockState& nextState, uint64_t threadBit )
{
    const auto itptr = (const LockEventShared*)*it;
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( ptr->lockCount != 0 )
            {
                const auto wait = ptr->waitList | ptr->waitShared;
                if( GetThreadBit( ptr->lockingThread ) == threadBit )
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
                nextState = ( ptr->waitList != 0 ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            else if( ptr->sharedList != 0 && IsThreadWaiting( ptr->waitList, threadBit ) )
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
            const auto ptr = (const LockEventShared*)*next;
            if( ptr->lockCount == 0 && !IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( ptr->waitList != 0 )
            {
                if( AreOtherWaiting( ptr->waitList, threadBit ) )
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
            if( ptr->waitList != itptr->waitList || ptr->waitShared != itptr->waitShared || ptr->lockCount != itptr->lockCount || ptr->sharedList != itptr->sharedList )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::HasBlockingLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( ptr->lockCount == 0 && !IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = LockState::Nothing;
                break;
            }
            if( ptr->waitList != itptr->waitList || ptr->waitShared != itptr->waitShared || ptr->lockCount != itptr->lockCount || ptr->sharedList != itptr->sharedList )
            {
                break;
            }
            next++;
        }
        break;
    case LockState::WaitLock:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)*next;
            if( GetThreadBit( ptr->lockingThread ) == threadBit )
            {
                const auto wait = ptr->waitList | ptr->waitShared;
                nextState = AreOtherWaiting( wait, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                nextState = ( ptr->waitList != 0 ) ? LockState::HasBlockingLock : LockState::HasLock;
                break;
            }
            if( ptr->lockingThread != itptr->lockingThread )
            {
                break;
            }
            if( ptr->lockCount == 0 && !IsThreadWaiting( ptr->waitShared, threadBit ) )
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

int View::DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int _offset, LockHighlight& highlight, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    const auto w = ImGui::GetWindowContentRegionWidth();
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    int cnt = 0;
    for( const auto& v : m_worker.GetLockMap() )
    {
        const auto& lockmap = v.second;
        if( !lockmap.valid || !Visible( &lockmap ) ) continue;

        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;

        const auto& tl = lockmap.timeline;
        assert( !tl.empty() );
        if( tl.back()->time < m_zvStart ) continue;

        auto GetNextLockFunc = lockmap.type == LockType::Lockable ? GetNextLockEvent : GetNextLockEventShared;

        const auto thread = it->second;
        const auto threadBit = GetThreadBit( thread );

        auto vbegin = std::lower_bound( tl.begin(), tl.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return l->time < r; } );
        const auto vend = std::lower_bound( vbegin, tl.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->time < r; } );

        if( vbegin > tl.begin() ) vbegin--;

        const auto offset = _offset + ostep * cnt;

        LockState state = LockState::Nothing;
        if( lockmap.type == LockType::Lockable )
        {
            if( (*vbegin)->lockCount != 0 )
            {
                if( (*vbegin)->lockingThread == thread )
                {
                    state = AreOtherWaiting( (*vbegin)->waitList, threadBit ) ? LockState::HasBlockingLock : LockState::HasLock;
                }
                else if( IsThreadWaiting( (*vbegin)->waitList, threadBit ) )
                {
                    state = LockState::WaitLock;
                }
            }
        }
        else
        {
            const auto ptr = (LockEventShared*)*vbegin;
            if( ptr->lockCount != 0 )
            {
                if( ptr->lockingThread == thread )
                {
                    state = ( AreOtherWaiting( ptr->waitList, threadBit ) || AreOtherWaiting( ptr->waitShared, threadBit ) ) ? LockState::HasBlockingLock : LockState::HasLock;
                }
                else if( IsThreadWaiting( ptr->waitList, threadBit ) || IsThreadWaiting( ptr->waitShared, threadBit ) )
                {
                    state = LockState::WaitLock;
                }
            }
            else if( IsThreadWaiting( ptr->sharedList, threadBit ) )
            {
                state = ptr->waitList != 0 ? LockState::HasBlockingLock : LockState::HasLock;
            }
            else if( ptr->sharedList != 0 && IsThreadWaiting( ptr->waitList, threadBit ) )
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
                while( vbegin < vend && ( state == LockState::Nothing || ( m_onlyContendedLocks && state == LockState::HasLock ) ) )
                {
                    vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
                }
                if( vbegin >= vend ) break;

                assert( state != LockState::Nothing && ( !m_onlyContendedLocks || state != LockState::HasLock ) );
                drawn = true;

                LockState drawState = state;
                auto next = GetNextLockFunc( vbegin, vend, state, threadBit );

                const auto t0 = (*vbegin)->time;
                int64_t t1 = next == tl.end() ? m_lastTime : (*next)->time;
                const auto px0 = std::max( pxend, ( t0 - m_zvStart ) * pxns );
                auto tx0 = px0;
                double px1 = ( t1 - m_zvStart ) * pxns;
                uint64_t condensed = 0;

                for(;;)
                {
                    if( next >= vend || px1 - tx0 > MinVisSize ) break;
                    auto n = next;
                    auto ns = state;
                    while( n < vend && ( ns == LockState::Nothing || ( m_onlyContendedLocks && ns == LockState::HasLock ) ) )
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
                    const auto t2 = n == tl.end() ? m_lastTime : (*n)->time;
                    const auto px2 = ( t2 - m_zvStart ) * pxns;
                    if( px2 - px1 > MinVisSize ) break;
                    if( drawState != ns && px2 - px0 > MinVisSize && !( ns == LockState::Nothing || ( m_onlyContendedLocks && ns == LockState::HasLock ) ) ) break;
                    t1 = t2;
                    tx0 = px1;
                    px1 = px2;
                    next = n;
                    state = ns;
                }

                pxend = std::max( { px1, px0+MinVisSize, px0 + pxns * 0.5 } );

                bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ) );
                if( itemHovered )
                {
                    if( condensed > 1 )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Multiple lock events:", RealToString( condensed, true ) );
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
                                if( (*b)->lockingThread != (*vbegin)->lockingThread )
                                {
                                    break;
                                }
                                b--;
                            }
                            b++;
                            highlight.begin = (*b)->time;

                            auto e = next;
                            while( e != tl.end() )
                            {
                                if( (*e)->lockingThread != (*next)->lockingThread )
                                {
                                    highlight.id = v.first;
                                    highlight.end = (*e)->time;
                                    highlight.thread = thread;
                                    break;
                                }
                                e++;
                            }
                        }

                        ImGui::BeginTooltip();
                        ImGui::Text( "Lock #%" PRIu32 ": %s", v.first, m_worker.GetString( srcloc.function ) );
                        ImGui::Separator();
                        ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
                        TextFocused( "Time:", TimeToString( t1 - t0 ) );
                        ImGui::Separator();

                        uint32_t markloc = 0;
                        auto it = vbegin;
                        for(;;)
                        {
                            if( (*it)->thread == thread )
                            {
                                if( ( (*it)->lockingThread == thread || IsThreadWaiting( (*it)->waitList, threadBit ) ) && (*it)->srcloc != 0 )
                                {
                                    markloc = (*it)->srcloc;
                                    break;
                                }
                            }
                            if( it == tl.begin() ) break;
                            --it;
                        }
                        if( markloc != 0 )
                        {
                            const auto& marklocdata = m_worker.GetSourceLocation( markloc );
                            ImGui::Text( "Lock event location:" );
                            ImGui::Text( "%s", m_worker.GetString( marklocdata.function ) );
                            ImGui::Text( "%s:%i", m_worker.GetString( marklocdata.file ), marklocdata.line );
                            ImGui::Separator();
                        }

                        if( v.second.type == LockType::Lockable )
                        {
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                if( (*vbegin)->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadString( tid ), (*vbegin)->lockCount );
                                }
                                if( (*vbegin)->waitList != 0 )
                                {
                                    assert( !AreOtherWaiting( (*next)->waitList, threadBit ) );
                                    ImGui::Text( "Recursive lock acquire in thread." );
                                }
                                break;
                            case LockState::HasBlockingLock:
                            {
                                if( (*vbegin)->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( (*vbegin)->waitList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%i):", m_worker.GetThreadString( tid ), (*vbegin)->lockCount, TracyCountBits( (*vbegin)->waitList ) );
                                }
                                auto waitList = (*vbegin)->waitList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( waitList != 0 )
                                {
                                    if( waitList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                    }
                                    waitList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockState::WaitLock:
                            {
                                if( (*vbegin)->lockCount > 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other thread:", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadString( tid ) );
                                }
                                ImGui::Indent( ty );
                                ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[(*vbegin)->lockingThread] ) );
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
                            const auto ptr = (const LockEventShared*)*vbegin;
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                assert( ptr->waitList == 0 );
                                if( ptr->sharedList == 0 )
                                {
                                    assert( ptr->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%i):", TracyCountBits( ptr->sharedList ) - 1 );
                                    auto sharedList = ptr->sharedList;
                                    int t = 0;
                                    ImGui::Indent( ty );
                                    while( sharedList != 0 )
                                    {
                                        if( sharedList & 0x1 && t != thread )
                                        {
                                            ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
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
                                    assert( ptr->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock.", m_worker.GetThreadString( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%i):", TracyCountBits( ptr->sharedList ) - 1 );
                                    auto sharedList = ptr->sharedList;
                                    int t = 0;
                                    ImGui::Indent( ty );
                                    while( sharedList != 0 )
                                    {
                                        if( sharedList & 0x1 && t != thread )
                                        {
                                            ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                        }
                                        sharedList >>= 1;
                                        t++;
                                    }
                                    ImGui::Unindent( ty );
                                    ImGui::Text( "Blocked threads (%i):", TracyCountBits( ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }

                                auto waitList = ptr->waitList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( waitList != 0 )
                                {
                                    if( waitList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
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
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
                                    }
                                    waitShared >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockState::WaitLock:
                            {
                                assert( ptr->lockCount == 0 || ptr->lockCount == 1 );
                                if( ptr->lockCount != 0 || ptr->sharedList != 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other threads (%i):", m_worker.GetThreadString( tid ), ptr->lockCount + TracyCountBits( ptr->sharedList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadString( tid ) );
                                }
                                ImGui::Indent( ty );
                                if( ptr->lockCount != 0 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[ptr->lockingThread] ) );
                                }
                                auto sharedList = ptr->sharedList;
                                int t = 0;
                                while( sharedList != 0 )
                                {
                                    if( sharedList & 0x1 )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[t] ) );
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
                if( m_lockHighlight.thread != thread && ( drawState == LockState::HasBlockingLock ) != m_lockHighlight.blocked && next != tl.end() && m_lockHighlight.id == int64_t( v.first ) && m_lockHighlight.begin <= (*vbegin)->time && m_lockHighlight.end >= (*next)->time )
                {
                    const auto t = uint8_t( ( sin( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count() * 0.01 ) * 0.5 + 0.5 ) * 255 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), 0x00FFFFFF | ( t << 24 ), 0.f, -1, 2.f );
                }
                else if( condensed == 0 )
                {
                    const auto coutline = drawState == LockState::HasLock ? 0xFF3BA33B : ( drawState == LockState::HasBlockingLock ? 0xFF3BA3A3 : 0xFF3B3BD6 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ), coutline );
                }

                const auto rx0 = ( t0 - m_zvStart ) * pxns;
                if( dsz >= MinVisSize )
                {
                    draw->AddRectFilled( wpos + ImVec2( rx0, offset ), wpos + ImVec2( std::min( rx0+dsz, px1 ), offset + ty ), 0x882222DD );
                }
                if( rsz >= MinVisSize )
                {
                    draw->AddLine( wpos + ImVec2( rx0 + rsz, offset + round( ty/2 ) ), wpos + ImVec2( rx0 - rsz, offset + round( ty/2 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( rx0 + rsz, offset + round( ty/4 ) ), wpos + ImVec2( rx0 + rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( rx0 - rsz, offset + round( ty/4 ) ), wpos + ImVec2( rx0 - rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );

                    draw->AddLine( wpos + ImVec2( px1 + rsz, offset + round( ty/2 ) ), wpos + ImVec2( px1 - rsz, offset + round( ty/2 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px1 + rsz, offset + round( ty/4 ) ), wpos + ImVec2( px1 + rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px1 - rsz, offset + round( ty/4 ) ), wpos + ImVec2( px1 - rsz, offset + round( 3*ty/4 ) ), 0xAAFFFFFF );
                }

                vbegin = next;
            }

            if( drawn )
            {
                char buf[1024];
                sprintf( buf, "%" PRIu32 ": %s", v.first, m_worker.GetString( srcloc.function ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty ) ) )
                {
                    ImGui::BeginTooltip();
                    switch( v.second.type )
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
                    ImGui::Text( "Thread list:" );
                    ImGui::Separator();
                    ImGui::Indent( ty );
                    for( const auto& t : v.second.threadList )
                    {
                        ImGui::Text( "%s", m_worker.GetThreadString( t ) );
                    }
                    ImGui::Unindent( ty );
                    ImGui::Separator();
                    TextFocused( "Lock events:", RealToString( v.second.timeline.size(), true ) );
                    ImGui::EndTooltip();
                }
                cnt++;
            }
        }
        else
        {
            while( vbegin < vend && ( state == LockState::Nothing || ( m_onlyContendedLocks && state == LockState::HasLock ) ) )
            {
                vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
            }
            if( vbegin < vend ) cnt++;
        }
    }
    return cnt;
}

int View::DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    const auto PlotHeight = 100 * ImGui::GetTextLineHeight() / 15.f;

    enum { MaxPoints = 512 };
    float tmpvec[MaxPoints*2];

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto nspx = 1.0 / pxns;

    for( const auto& v : m_worker.GetPlots() )
    {
        if( !Visible( v ) ) continue;
        assert( !v->data.empty() );
        bool& showFull = ShowFull( v );

        float txtx;
        auto yPos = wpos.y + offset;
        if( yPos + ty >= yMin && yPos <= yMax )
        {
            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFF44DDDD );
            }
            else
            {
                draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF226E6E );
            }
            const auto txt = GetPlotName( v );
            txtx = ImGui::CalcTextSize( txt ).x;
            draw->AddText( wpos + ImVec2( ty, offset ), showFull ? 0xFF44DDDD : 0xFF226E6E, txt );
            draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtx, offset + ty ) ) )
            {
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }

                const auto tr = v->data.back().time - v->data.front().time;

                ImGui::BeginTooltip();
                ImGui::Text( "Plot \"%s\"", txt );
                ImGui::Separator();
                TextFocused( "Data points:", RealToString( v->data.size(), true ) );
                TextFocused( "Data range:", RealToString( v->max - v->min, true ) );
                TextFocused( "Min value:", RealToString( v->min, true ) );
                TextFocused( "Max value:", RealToString( v->max, true ) );
                TextFocused( "Time range:", TimeToString( tr ) );
                TextFocused( "Data/second:", RealToString( double( v->data.size() ) / tr * 1000000000ll, true ) );

                const auto it = std::lower_bound( v->data.begin(), v->data.end(), v->data.back().time - 1000000000ll * 10, [] ( const auto& l, const auto& r ) { return l.time < r; } );
                const auto tr10 = v->data.back().time - it->time;
                if( tr10 != 0 )
                {
                    TextFocused( "D/s (10s):", RealToString( double( std::distance( it, v->data.end() ) ) / tr10 * 1000000000ll, true ) );
                }

                ImGui::EndTooltip();
            }
        }

        offset += ty;

        if( showFull )
        {
            auto yPos = wpos.y + offset;
            if( yPos + PlotHeight >= yMin && yPos <= yMax )
            {
                const auto& vec = v->data;

                if( v->type == PlotType::Memory )
                {
                    const auto& mem = m_worker.GetMemData();

                    if( m_memoryAllocInfoWindow >= 0 )
                    {
                        const auto& ev = mem.data[m_memoryAllocInfoWindow];

                        const auto tStart = ev.timeAlloc;
                        const auto tEnd = ev.timeFree < 0 ? m_worker.GetLastTime() : ev.timeFree;

                        const auto px0 = ( tStart - m_zvStart ) * pxns;
                        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_zvStart ) * pxns );
                        draw->AddRectFilled( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x2288DD88 );
                        draw->AddRect( ImVec2( wpos.x + px0, yPos ), ImVec2( wpos.x + px1, yPos + PlotHeight ), 0x4488DD88 );
                    }
                    if( m_memoryAllocHover >= 0 && m_memoryAllocHover != m_memoryAllocInfoWindow )
                    {
                        const auto& ev = mem.data[m_memoryAllocHover];

                        const auto tStart = ev.timeAlloc;
                        const auto tEnd = ev.timeFree < 0 ? m_worker.GetLastTime() : ev.timeFree;

                        const auto px0 = ( tStart - m_zvStart ) * pxns;
                        const auto px1 = std::max( px0 + std::max( 1.0, pxns * 0.5 ), ( tEnd - m_zvStart ) * pxns );
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

                auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - m_worker.GetDelay(), [] ( const auto& l, const auto& r ) { return l.time < r; } );
                auto end = std::lower_bound( it, vec.end(), m_zvEnd + m_worker.GetResolution(), [] ( const auto& l, const auto& r ) { return l.time < r; } );

                if( end != vec.end() ) end++;
                if( it != vec.begin() ) it--;

                double min = it->val;
                double max = it->val;
                if( std::distance( it, end ) > 1000000 )
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
                    tmp += sz;
                }

                const auto revrange = 1.0 / ( max - min );

                if( it == vec.begin() )
                {
                    const auto x = ( it->time - m_zvStart ) * pxns;
                    const auto y = PlotHeight - ( it->val - min ) * revrange * PlotHeight;
                    DrawPlotPoint( wpos, x, y, offset, 0xFF44DDDD, hover, false, it, 0, false, v->type, PlotHeight );
                }

                auto prevx = it;
                auto prevy = it;
                ++it;
                ptrdiff_t skip = 0;
                while( it < end )
                {
                    const auto x0 = ( prevx->time - m_zvStart ) * pxns;
                    const auto x1 = ( it->time - m_zvStart ) * pxns;
                    const auto y0 = PlotHeight - ( prevy->val - min ) * revrange * PlotHeight;
                    const auto y1 = PlotHeight - ( it->val - min ) * revrange * PlotHeight;

                    draw->AddLine( wpos + ImVec2( x0, offset + y0 ), wpos + ImVec2( x1, offset + y1 ), 0xFF44DDDD );

                    const auto rx = skip == 0 ? 2.0 : ( skip == 1 ? 2.5 : 4.0 );

                    auto range = std::upper_bound( it, end, int64_t( it->time + nspx * rx ), [] ( const auto& l, const auto& r ) { return l < r.time; } );
                    assert( range > it );
                    const auto rsz = std::distance( it, range );
                    if( rsz == 1 )
                    {
                        DrawPlotPoint( wpos, x1, y1, offset, 0xFF44DDDD, hover, true, it, prevy->val, false, v->type, PlotHeight );
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
                        for(;;)
                        {
                            *dst++ = float( it->val );
                            if( std::distance( it, range ) > skip1 )
                            {
                                it += skip1;
                            }
                            else
                            {
                                break;
                            }
                        }
                        pdqsort_branchless( tmpvec, dst );

                        draw->AddLine( wpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), wpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD );

                        auto vit = tmpvec;
                        while( vit != dst )
                        {
                            auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                            assert( vrange > vit );
                            if( std::distance( vit, vrange ) == 1 )
                            {
                                DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, false, PlotHeight );
                            }
                            else
                            {
                                DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, true, PlotHeight );
                            }
                            vit = vrange;
                        }

                        prevy = it - 1;
                    }
                }

                char tmp[64];
                if( yPos + ty >= yMin && yPos <= yMax )
                {
                    sprintf( tmp, "(y-range: %s)", v->type == PlotType::Memory ? MemSizeToString( max - min ) : RealToString( max - min, true ) );
                    draw->AddText( wpos + ImVec2( ty * 1.5f + txtx, offset - ty ), 0x8844DDDD, tmp );
                }
                sprintf( tmp, "%s", v->type == PlotType::Memory ? MemSizeToString( max ) : RealToString( max, true ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
                offset += PlotHeight - ty;
                sprintf( tmp, "%s", v->type == PlotType::Memory ? MemSizeToString( min ) : RealToString( min, true ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );

                draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );
                offset += ty;
            }
            else
            {
                offset += PlotHeight;
            }
        }
        offset += 0.2 * ty;
    }

    return offset;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, float PlotHeight )
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
        TextFocused( "Value:", RealToString( val, true ) );
        if( hasPrev )
        {
            TextFocused( "Change:", RealToString( val - prev, true ) );
        }
        ImGui::EndTooltip();
    }
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, const PlotItem* item, double prev, bool merged, PlotType type, float PlotHeight )
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
        if( type == PlotType::Memory )
        {
            ImGui::TextDisabled( "Value:" );
            ImGui::SameLine();
            if( item->val < 10000ll )
            {
                ImGui::Text( "%s", MemSizeToString( item->val ) );
            }
            else
            {
                ImGui::Text( "%s (%s)", MemSizeToString( item->val ), RealToString( item->val, true ) );
            }
        }
        else
        {
            TextFocused( "Value:", RealToString( item->val, true ) );
        }
        if( hasPrev )
        {
            const auto change = item->val - prev;
            TextFocused( "Change:", type == PlotType::Memory ? MemSizeToString( change ) : RealToString( change, true ) );

            if( type == PlotType::Memory )
            {
                auto& mem = m_worker.GetMemData();
                const MemEvent* ev = nullptr;
                if( change > 0 )
                {
                    auto it = std::lower_bound( mem.data.begin(), mem.data.end(), item->time, [] ( const auto& lhs, const auto& rhs ) { return lhs.timeAlloc < rhs; } );
                    if( it != mem.data.end() && it->timeAlloc == item->time )
                    {
                        ev = it;
                    }
                }
                else
                {
                    const auto& data = mem.data;
                    auto it = std::lower_bound( mem.frees.begin(), mem.frees.end(), item->time, [&data] ( const auto& lhs, const auto& rhs ) { return data[lhs].timeFree < rhs; } );
                    if( it != mem.frees.end() && data[*it].timeFree == item->time )
                    {
                        ev = &data[*it];
                    }
                }
                if( ev )
                {
                    ImGui::Separator();
                    ImGui::TextDisabled( "Address:" );
                    ImGui::SameLine();
                    ImGui::Text( "0x%" PRIx64, ev->ptr );
                    TextFocused( "Appeared at", TimeToString( ev->timeAlloc - m_worker.GetTimeBegin() ) );
                    if( change > 0 )
                    {
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(this event)" );
                    }
                    if( ev->timeFree < 0 )
                    {
                        ImGui::Text( "Allocation still active" );
                    }
                    else
                    {
                        TextFocused( "Freed at", TimeToString( ev->timeFree - m_worker.GetTimeBegin() ) );
                        if( change < 0 )
                        {
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(this event)" );
                        }
                        TextFocused( "Duration:", TimeToString( ev->timeFree - ev->timeAlloc ) );
                    }
                    uint64_t tid;
                    if( change > 0 )
                    {
                        tid = m_worker.DecompressThread( ev->threadAlloc );
                    }
                    else
                    {
                        tid = m_worker.DecompressThread( ev->threadFree );
                    }
                    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );

                    m_memoryAllocHover = std::distance( mem.data.begin(), ev );
                    m_memoryAllocHoverWait = 2;
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        m_memoryAllocInfoWindow = m_memoryAllocHover;
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
void DrawZoneTrace( T zone, const std::vector<T>& trace, const Worker& worker, BuzzAnim<const void*>& anim, View& view, std::function<void(T)> showZone )
{
    bool expand = ImGui::TreeNode( "Zone trace" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( trace.size(), true ) );
    if( !expand ) return;

    if( !trace.empty() )
    {
        T prev = zone;
        const auto sz = trace.size();
        for( size_t i=0; i<sz; i++ )
        {
            auto curr = trace[i];
            if( prev->callstack == 0 || curr->callstack == 0 )
            {
                ImGui::TextDisabled( "[unknown frames]" );
            }
            else if( prev->callstack != curr->callstack )
            {
                auto& prevCs = worker.GetCallstack( prev->callstack );
                auto& currCs = worker.GetCallstack( curr->callstack );

                const auto psz = int8_t( prevCs.size() );
                int8_t idx;
                for( idx=0; idx<psz; idx++ )
                {
                    auto pf = prevCs[idx];
                    bool found = false;
                    for( auto& cf : currCs )
                    {
                        if( cf == pf )
                        {
                            idx--;
                            found = true;
                            break;
                        }
                    }
                    if( found ) break;
                }
                for( int8_t j=1; j<idx; j++ )
                {
                    auto frame = worker.GetCallstackFrame( prevCs[j] );
                    ImGui::TextDisabled( "%s", worker.GetString( frame->name ) );
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
                    if( frame->line == 0 )
                    {
                        ImGui::TextDisabled( "%s", fileName );
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:%i", fileName, frame->line );
                    }
                    if( ImGui::IsItemClicked( 1 ) )
                    {
                        if( frame->line != 0 && FileExists( fileName ) )
                        {
                            view.SetTextEditorFile( fileName, frame->line );
                        }
                        else
                        {
                            anim.Enable( frame, 0.5f );
                        }
                    }
                }
            }

            showZone( curr );
            prev = curr;
        }
    }

    auto last = trace.empty() ? zone : trace.back();
    if( last->callstack == 0 )
    {
        ImGui::TextDisabled( "[unknown frames]" );
    }
    else
    {
        auto& cs = worker.GetCallstack( last->callstack );
        const auto csz = cs.size();
        for( uint8_t i=1; i<csz; i++ )
        {
            auto frame = worker.GetCallstackFrame( cs[i] );
            ImGui::TextDisabled( "%s", worker.GetString( frame->name ) );
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
            if( frame->line == 0 )
            {
                ImGui::TextDisabled( "%s", fileName );
            }
            else
            {
                ImGui::TextDisabled( "%s:%i", fileName, frame->line );
            }
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( frame->line != 0 && FileExists( fileName ) )
                {
                    view.SetTextEditorFile( fileName, frame->line );
                }
                else
                {
                    anim.Enable( frame, 0.5f );
                }
            }
        }
    }

    ImGui::TreePop();
}

void View::DrawZoneInfoWindow()
{
    auto& ev = *m_zoneInfoWindow;
    int dmul = 1;

    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );

    bool show = true;
    ImGui::Begin( "Zone info", &show );

#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to zone" ) )
#else
    if( ImGui::Button( "Zoom to zone" ) )
#endif
    {
        ZoomToZone( ev );
    }
    auto parent = GetZoneParent( ev );
    if( parent )
    {
        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_ARROW_UP " Go to parent" ) )
#else
        if( ImGui::Button( "Go to parent" ) )
#endif
        {
            ShowZoneInfo( *parent );
        }
    }
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_CHART_BAR " Statistics" ) )
#else
    if( ImGui::Button( "Statistics" ) )
#endif
    {
        m_findZone.ShowZone( ev.srcloc, m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ) );
    }
    if( ev.callstack != 0 )
    {
        ImGui::SameLine();
        bool hilite = m_callstackInfoWindow == ev.callstack;
        if( hilite )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
        }
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
#else
        if( ImGui::Button( "Call stack" ) )
#endif
        {
            m_callstackInfoWindow = ev.callstack;
        }
        if( hilite )
        {
            ImGui::PopStyleColor( 3 );
        }
    }
    const auto fileName = m_worker.GetString( srcloc.file );
    if( FileExists( fileName ) )
    {
        ImGui::SameLine();
        bool hilite = m_textEditorFile == fileName;
        if( hilite )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
        }
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_FILE_ALT " Source" ) )
#else
        if( ImGui::Button( "Source" ) )
#endif
        {
            SetTextEditorFile( fileName, srcloc.line );
        }
        if( hilite )
        {
            ImGui::PopStyleColor( 3 );
        }
    }
    if( !m_zoneInfoStack.empty() )
    {
        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_ARROW_LEFT " Go back" ) )
#else
        if( ImGui::Button( "Go back" ) )
#endif
        {
            m_zoneInfoWindow = m_zoneInfoStack.back_and_pop();
        }
    }

    ImGui::Separator();

    const auto tid = GetZoneThread( ev );
    if( ev.name.active )
    {
        TextFocused( "Zone name:", m_worker.GetString( ev.name ) );
    }
    if( srcloc.name.active )
    {
        TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
    }
    TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
    ImGui::TextDisabled( "Location:" );
    ImGui::SameLine();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(id)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "0x%" PRIX64, tid );
        ImGui::EndTooltip();
    }
    if( ev.text.active )
    {
        TextFocused( "User text:", m_worker.GetString( ev.text ) );
        dmul++;
    }

    ImGui::Separator();

    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.start;
    TextFocused( "Time from start of program:", TimeToString( ev.start - m_worker.GetTimeBegin() ) );
    TextFocused( "Execution time:", TimeToString( ztime ) );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        TextFocused( "Without profiling:", TimeToString( ztime - m_worker.GetDelay() * dmul ) );
        ImGui::EndTooltip();
    }

    auto& mem = m_worker.GetMemData();
    if( mem.plot )
    {
        ImGui::Separator();

        const auto thread = m_worker.CompressThread( tid );

        auto ait = std::lower_bound( mem.data.begin(), mem.data.end(), ev.start, [] ( const auto& l, const auto& r ) { return l.timeAlloc < r; } );
        const auto aend = std::upper_bound( mem.data.begin(), mem.data.end(), end, [] ( const auto& l, const auto& r ) { return l < r.timeAlloc; } );

        auto fit = std::lower_bound( mem.frees.begin(), mem.frees.end(), ev.start, [&mem] ( const auto& l, const auto& r ) { return mem.data[l].timeFree < r; } );
        const auto fend = std::upper_bound( mem.frees.begin(), mem.frees.end(), end, [&mem] ( const auto& l, const auto& r ) { return l < mem.data[r].timeFree; } );

        const auto aDist = std::distance( ait, aend );
        const auto fDist = std::distance( fit, fend );
        if( aDist == 0 && fDist == 0 )
        {
            ImGui::Text( "No memory events." );
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
                if( ait->threadAlloc == thread )
                {
                    cAlloc += ait->size;
                    nAlloc++;
                }
                ait++;
            }
            while( fit != fend )
            {
                if( mem.data[*fit].threadFree == thread )
                {
                    cFree += mem.data[*fit].size;
                    nFree++;
                }
                fit++;
            }

            if( nAlloc == 0 && nFree == 0 )
            {
                ImGui::Text( "No memory events." );
            }
            else
            {
                ImGui::Text( "%s", RealToString( nAlloc + nFree, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "memory events." );
                ImGui::Text( "%s", RealToString( nAlloc, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "allocs," );
                ImGui::SameLine();
                ImGui::Text( "%s", RealToString( nFree, true ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "frees." );
                TextFocused( "Memory allocated:", MemSizeToString( cAlloc ) );
                TextFocused( "Memory freed:", MemSizeToString( cFree ) );
                TextFocused( "Overall change:", MemSizeToString( cAlloc - cFree ) );

                if( ImGui::TreeNode( "Allocations list" ) )
                {
                    std::vector<const MemEvent*> v;
                    v.reserve( nAlloc + nFree );

                    auto it = ait2;
                    while( it != aend )
                    {
                        if( it->threadAlloc == thread )
                        {
                            v.emplace_back( it );
                        }
                        it++;
                    }
                    while( fit2 != fend )
                    {
                        const auto ptr = &mem.data[*fit2++];
                        if( ptr->threadFree == thread )
                        {
                            if( ptr < ait2 || ptr >= aend )
                            {
                                v.emplace_back( ptr );
                            }
                        }
                    }
                    pdqsort_branchless( v.begin(), v.end(), [] ( const auto& l, const auto& r ) { return l->timeAlloc < r->timeAlloc; } );

                    ListMemData<decltype( v.begin() )>( v.begin(), v.end(), []( auto& v ) {
                        ImGui::Text( "0x%" PRIx64, (*v)->ptr );
                    } );
                    ImGui::TreePop();
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
    DrawZoneTrace<const ZoneEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, [&idx, this] ( const ZoneEvent* v ) {
        const auto& srcloc = m_worker.GetSourceLocation( v->srcloc );
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
        ImGui::TextDisabled( "(%s) %s:%i", TimeToString( m_worker.GetZoneEnd( *v ) - v->start ), fileName, srcloc.line );
        ImGui::PopID();
        if( ImGui::IsItemClicked( 1 ) )
        {
            if( FileExists( fileName ) )
            {
                SetTextEditorFile( fileName, srcloc.line );
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
            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToZone( *v );
            }
            ZoneTooltip( *v );
        }
    } );

    if( ev.child >= 0 )
    {
        const auto& children = m_worker.GetZoneChildren( ev.child );
        bool expand = ImGui::TreeNode( "Child zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( children.size(), true ) );
        if( expand )
        {
            auto ctt = std::make_unique<uint64_t[]>( children.size() );
            auto cti = std::make_unique<uint32_t[]>( children.size() );
            uint64_t ctime = 0;
            for( size_t i=0; i<children.size(); i++ )
            {
                const auto cend = m_worker.GetZoneEnd( *children[i] );
                const auto ct = cend - children[i]->start;
                ctime += ct;
                ctt[i] = ct;
                cti[i] = uint32_t( i );
            }

            pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

            const auto ty = ImGui::GetTextLineHeight();
            ImGui::Columns( 2 );
            ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
            ImGui::NextColumn();
            char buf[128];
            sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
            ImGui::ProgressBar( double( ztime - ctime ) / ztime, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            for( size_t i=0; i<children.size(); i++ )
            {
                auto& cev = *children[cti[i]];
                const auto txt = m_worker.GetZoneName( cev );
                bool b = false;
                ImGui::PushID( (int)i );
                if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    ShowZoneInfo( cev );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_zoneHighlight = &cev;
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
                ImGui::NextColumn();
                const auto part = double( ctt[cti[i]] ) / ztime;
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
                ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                ImGui::NextColumn();
            }
            ImGui::EndColumns();
            ImGui::TreePop();
        }
    }

    ImGui::End();

    if( !show )
    {
        m_zoneInfoWindow = nullptr;
        m_zoneInfoStack.clear();
    }
}

void View::DrawGpuInfoWindow()
{
    auto& ev = *m_gpuInfoWindow;
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );

    bool show = true;
    ImGui::Begin( "Zone info", &show );

#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to zone" ) )
#else
    if( ImGui::Button( "Zoom to zone" ) )
#endif
    {
        ZoomToZone( ev );
    }
    auto parent = GetZoneParent( ev );
    if( parent )
    {
        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_ARROW_UP " Go to parent" ) )
#else
        if( ImGui::Button( "Go to parent" ) )
#endif
        {
            ShowZoneInfo( *parent, m_gpuInfoWindowThread );
        }
    }
    if( ev.callstack != 0 )
    {
        ImGui::SameLine();
        bool hilite = m_callstackInfoWindow == ev.callstack;
        if( hilite )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
        }
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
#else
        if( ImGui::Button( "Call stack" ) )
#endif
        {
            m_callstackInfoWindow = ev.callstack;
        }
        if( hilite )
        {
            ImGui::PopStyleColor( 3 );
        }
    }
    const auto fileName = m_worker.GetString( srcloc.file );
    if( FileExists( fileName ) )
    {
        ImGui::SameLine();
        bool hilite = m_textEditorFile == fileName;
        if( hilite )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
            ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
        }
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_FILE_ALT " Source" ) )
#else
        if( ImGui::Button( "Source" ) )
#endif
        {
            SetTextEditorFile( fileName, srcloc.line );
        }
        if( hilite )
        {
            ImGui::PopStyleColor( 3 );
        }
    }
    if( !m_gpuInfoStack.empty() )
    {
        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_ARROW_LEFT " Go back" ) )
#else
        if( ImGui::Button( "Go back" ) )
#endif
        {
            m_gpuInfoWindow = m_gpuInfoStack.back_and_pop();
        }
    }

    ImGui::Separator();

    const auto tid = GetZoneThread( ev );
    TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
    TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
    ImGui::TextDisabled( "Location:" );
    ImGui::SameLine();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(id)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "0x%" PRIX64, tid );
        ImGui::EndTooltip();
    }

    ImGui::Separator();

    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.gpuStart;
    TextFocused( "Time from start of program:", TimeToString( ev.gpuStart - m_worker.GetTimeBegin() ) );
    TextFocused( "GPU execution time:", TimeToString( ztime ) );
    TextFocused( "CPU command setup time:", TimeToString( ev.cpuEnd - ev.cpuStart ) );
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        TextFocused( "Delay to execution:", TimeToString( ev.gpuStart - ev.cpuStart ) );
    }
    else
    {
        const auto begin = ctx->timeline.front()->gpuStart;
        const auto drift = GpuDrift( ctx );
        TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.gpuStart, begin, drift ) - ev.cpuStart ) );
    }

    ImGui::Separator();

    std::vector<const GpuEvent*> zoneTrace;
    while( parent )
    {
        zoneTrace.emplace_back( parent );
        parent = GetZoneParent( *parent );
    }
    int idx = 0;
    DrawZoneTrace<const GpuEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, [&idx, this] ( const GpuEvent* v ) {
        const auto& srcloc = m_worker.GetSourceLocation( v->srcloc );
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
        ImGui::TextDisabled( "(%s) %s:%i", TimeToString( m_worker.GetZoneEnd( *v ) - v->gpuStart ), fileName, srcloc.line );
        ImGui::PopID();
        if( ImGui::IsItemClicked( 1 ) )
        {
            if( FileExists( fileName ) )
            {
                SetTextEditorFile( fileName, srcloc.line );
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
            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToZone( *v );
            }
            ZoneTooltip( *v );
        }
    } );

    if( ev.child >= 0 )
    {
        const auto& children = m_worker.GetGpuChildren( ev.child );
        bool expand = ImGui::TreeNode( "Child zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( children.size(), true ) );
        if( expand )
        {
            auto ctt = std::make_unique<uint64_t[]>( children.size() );
            auto cti = std::make_unique<uint32_t[]>( children.size() );
            uint64_t ctime = 0;
            for( size_t i=0; i<children.size(); i++ )
            {
                const auto cend = m_worker.GetZoneEnd( *children[i] );
                const auto ct = cend - children[i]->gpuStart;
                ctime += ct;
                ctt[i] = ct;
                cti[i] = uint32_t( i );
            }

            pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

            const auto ty = ImGui::GetTextLineHeight();
            ImGui::Columns( 2 );
            ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
            ImGui::NextColumn();
            char buf[128];
            sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
            ImGui::ProgressBar( double( ztime - ctime ) / ztime, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
            for( size_t i=0; i<children.size(); i++ )
            {
                auto& cev = *children[cti[i]];
                bool b = false;
                ImGui::PushID( (int)i );
                if( ImGui::Selectable( m_worker.GetZoneName( cev ), &b, ImGuiSelectableFlags_SpanAllColumns ) )
                {
                    ShowZoneInfo( cev, m_gpuInfoWindowThread );
                }
                if( ImGui::IsItemHovered() )
                {
                    m_gpuHighlight = &cev;
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( cev );
                    }
                    ZoneTooltip( cev );
                }
                ImGui::PopID();
                ImGui::NextColumn();
                const auto part = double( ctt[cti[i]] ) / ztime;
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
                ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                ImGui::NextColumn();
            }
            ImGui::EndColumns();
            ImGui::TreePop();
        }
    }

    ImGui::End();

    if( !show )
    {
        m_gpuInfoWindow = nullptr;
        m_gpuInfoStack.clear();
    }
}

void View::DrawOptions()
{
    ImGui::Begin( "Options", &m_showOptions, ImGuiWindowFlags_AlwaysAutoResize );

    const auto& gpuData = m_worker.GetGpuData();
    if( !gpuData.empty() )
    {
#ifdef TRACY_EXTENDED_FONT
        ImGui::Checkbox( ICON_FA_EYE " Draw GPU zones", &m_drawGpuZones );
#else
        ImGui::Checkbox( "Draw GPU zones", &m_drawGpuZones );
#endif
        const auto expand = ImGui::TreeNode( "GPU zones" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", gpuData.size() );
        if( expand )
        {
            for( size_t i=0; i<gpuData.size(); i++ )
            {
                const bool isVulkan = gpuData[i]->thread == 0;
                char buf[1024];
                if( isVulkan )
                {
                    sprintf( buf, "Vulkan context %zu", i );
                }
                else
                {
                    sprintf( buf, "OpenGL context %zu", i );
                }
                ImGui::Checkbox( buf, &Visible( gpuData[i] ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "%s top level zones", RealToString( gpuData[i]->timeline.size(), true ) );
                ImGui::TreePush();
                auto& drift = GpuDrift( gpuData[i] );
                ImGui::InputInt( "Drift (ns/s)", &drift );
                ImGui::TreePop();
            }
            ImGui::TreePop();
        }
    }

#ifdef TRACY_EXTENDED_FONT
    ImGui::Checkbox( ICON_FA_MICROCHIP " Draw CPU zones", &m_drawZones );
#else
    ImGui::Checkbox( "Draw CPU zones", &m_drawZones );
#endif
    int ns = (int)m_namespace;
    ImGui::Combo( "Namespaces", &ns, "Full\0Shortened\0None\0" );
    m_namespace = (Namespace)ns;

    if( !m_worker.GetLockMap().empty() )
    {
        ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
        ImGui::Checkbox( ICON_FA_LOCK " Draw locks", &m_drawLocks );
#else
        ImGui::Checkbox( "Draw locks", &m_drawLocks );
#endif
        ImGui::SameLine();
        ImGui::Checkbox( "Only contended", &m_onlyContendedLocks );
        const auto expand = ImGui::TreeNode( "Locks" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetLockMap().size() );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "Locks with no recorded events are counted, but not listed." );
            ImGui::EndTooltip();
        }
        if( expand )
        {
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Visible( &l.second ) = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& l : m_worker.GetLockMap() )
                {
                    Visible( &l.second ) = false;
                }
            }

            for( const auto& l : m_worker.GetLockMap() )
            {
                if( l.second.valid )
                {
                    char buf[1024];
                    sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second.srcloc ).function ) );
                    ImGui::Checkbox( buf, &Visible( &l.second ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "%s events", RealToString( l.second.timeline.size(), true ) );
                }
            }
            ImGui::TreePop();
        }
    }

    if( !m_worker.GetPlots().empty() )
    {
        ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
        ImGui::Checkbox( ICON_FA_SIGNATURE " Draw plots", &m_drawPlots );
#else
        ImGui::Checkbox( "Draw plots", &m_drawPlots );
#endif
        const auto expand = ImGui::TreeNode( "Plots" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_worker.GetPlots().size() );
        if( expand )
        {
            if( ImGui::SmallButton( "Select all" ) )
            {
                for( const auto& p : m_worker.GetPlots() )
                {
                    Visible( p ) = true;
                }
            }
            ImGui::SameLine();
            if( ImGui::SmallButton( "Unselect all" ) )
            {
                for( const auto& p : m_worker.GetPlots() )
                {
                    Visible( p ) = false;
                }
            }

            for( const auto& p : m_worker.GetPlots() )
            {
                ImGui::Checkbox( GetPlotName( p ), &Visible( p ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "%s data points", RealToString( p->data.size(), true ) );
            }
            ImGui::TreePop();
        }
    }

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    auto expand = ImGui::TreeNode( ICON_FA_RANDOM " Visible threads:" );
#else
    auto expand = ImGui::TreeNode( "Visible threads:" );
#endif
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_worker.GetThreadData().size() );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_worker.GetThreadData() )
            {
                Visible( t ) = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_worker.GetThreadData() )
            {
                Visible( t ) = false;
            }
        }

        int idx = 0;
        for( const auto& t : m_worker.GetThreadData() )
        {
            ImGui::PushID( idx++ );
            ImGui::Checkbox( m_worker.GetThreadString( t->id ), &Visible( t ) );
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "%s top level zones", RealToString( t->timeline.size(), true ) );
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
#else
                ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), "Crashed" );
#endif
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    expand = ImGui::TreeNode( ICON_FA_IMAGES " Visible frame sets:" );
#else
    expand = ImGui::TreeNode( "Visible frame sets:" );
#endif
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_worker.GetFrames().size() );
    if( expand )
    {
        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& fd : m_worker.GetFrames() )
            {
                Visible( fd ) = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& fd : m_worker.GetFrames() )
            {
                Visible( fd ) = false;
            }
        }

        int idx = 0;
        for( const auto& fd : m_worker.GetFrames() )
        {
            ImGui::PushID( idx++ );
            ImGui::Checkbox( fd->name == 0 ? "Frames" : m_worker.GetString( fd->name ), &Visible( fd ) );
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "%s %sframes", RealToString( fd->frames.size(), true ), fd->continuous ? "" : "discontinuous " );
        }
        ImGui::TreePop();
    }
    ImGui::End();
}

void View::DrawMessages()
{
    ImGui::Begin( "Messages", &m_showMessages );

#ifdef TRACY_EXTENDED_FONT
    auto expand = ImGui::TreeNode( ICON_FA_RANDOM " Visible threads:" );
#else
    auto expand = ImGui::TreeNode( "Visible threads:" );
#endif
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", m_worker.GetThreadData().size() );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_worker.GetThreadData() )
            {
                VisibleMsgThread( t->id ) = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_worker.GetThreadData() )
            {
                VisibleMsgThread( t->id ) = false;
            }
        }

        int idx = 0;
        for( const auto& t : m_worker.GetThreadData() )
        {
            ImGui::PushID( idx++ );
            ImGui::Checkbox( m_worker.GetThreadString( t->id ), &VisibleMsgThread( t->id ) );
            ImGui::PopID();
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
#else
                ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), "Crashed" );
#endif
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
    ImGui::Columns( 3 );
    ImGui::Text( "Time" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on message to center timeline on it." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Thread" );
    ImGui::NextColumn();
    ImGui::Text( "Message" );
    ImGui::NextColumn();
    ImGui::Separator();

    for( const auto& v : m_worker.GetMessages() )
    {
        if( VisibleMsgThread( v->thread ) )
        {
            ImGui::PushID( v );
            if( ImGui::Selectable( TimeToString( v->time - m_worker.GetTimeBegin() ), m_msgHighlight == v, ImGuiSelectableFlags_SpanAllColumns ) )
            {
                CenterAtTime( v->time );
            }
            if( ImGui::IsItemHovered() )
            {
                m_msgHighlight = v;
            }
            if( m_msgToFocus == v )
            {
                ImGui::SetScrollHere();
                m_msgToFocus = nullptr;
            }
            ImGui::PopID();
            ImGui::NextColumn();
            ImGui::Text( "%s", m_worker.GetThreadString( v->thread ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(0x%" PRIX64 ")", v->thread );
            ImGui::NextColumn();
            ImGui::TextWrapped( "%s", m_worker.GetString( v->ref ) );
            ImGui::NextColumn();
        }
    }
    ImGui::EndColumns();
    ImGui::End();
}

uint64_t View::GetSelectionTarget( const Worker::ZoneThreadData& ev, FindZone::GroupBy groupBy ) const
{
    switch( groupBy )
    {
    case FindZone::GroupBy::Thread:
        return ev.thread;
    case FindZone::GroupBy::UserText:
        return ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max();
    case FindZone::GroupBy::Callstack:
        return ev.zone->callstack;
    default:
        assert( false );
        return 0;
    }
}

void View::DrawFindZone()
{
    ImGui::Begin( "Find zone", &m_findZone.show );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable zone search." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        ImGui::End();
        return;
    }

    ImGui::InputText( "", m_findZone.pattern, 1024 );
    ImGui::SameLine();

#ifdef TRACY_EXTENDED_FONT
    const bool findClicked = ImGui::Button( ICON_FA_SEARCH " Find" );
#else
    const bool findClicked = ImGui::Button( "Find" );
#endif
    ImGui::SameLine();

#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_BAN " Clear" ) )
#else
    if( ImGui::Button( "Clear" ) )
#endif
    {
        m_findZone.Reset();
    }

    if( findClicked )
    {
        m_findZone.Reset();
        FindZones();
    }

    if( !m_findZone.match.empty() )
    {
        ImGui::Separator();
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
                ImGui::PushID( idx );
                ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_findZone.selMatch, idx++ );
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
                ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s:%i", RealToString( zones.size(), true ), fileName, srcloc.line );
                if( ImGui::IsItemClicked( 1 ) )
                {
                    if( FileExists( fileName ) )
                    {
                        SetTextEditorFile( fileName, srcloc.line );
                    }
                    else
                    {
                        m_findZoneBuzzAnim.Enable( idx, 0.5f );
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

        ImGui::Separator();

        if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto ty = ImGui::GetFontSize();

            auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
            auto& zones = zoneData.zones;
            const auto tmin = zoneData.min;
            const auto tmax = zoneData.max;
            const auto timeTotal = zoneData.total;

            const auto zsz = zones.size();
            if( m_findZone.sortedNum != zsz )
            {
                auto& vec = m_findZone.sorted;
                vec.reserve( zsz );
                int64_t total = m_findZone.total;
                size_t i;
                for( i=m_findZone.sortedNum; i<zsz; i++ )
                {
                    auto& zone = *zones[i].zone;
                    if( zone.end < 0 ) break;
                    const auto t = zone.end - zone.start;
                    vec.emplace_back( t );
                    total += t;
                }
                auto mid = vec.begin() + m_findZone.sortedNum;
                pdqsort_branchless( mid, vec.end() );
                std::inplace_merge( vec.begin(), mid, vec.end() );

                m_findZone.average = float( total ) / i;
                m_findZone.median = vec[i/2];
                m_findZone.total = total;
                m_findZone.sortedNum = i;
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
                    size_t i;
                    for( i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                    {
                        auto& ev = zones[i];
                        if( selGroup == GetSelectionTarget( ev, groupBy ) )
                        {
                            const auto t = ev.zone->end - ev.zone->start;
                            vec.emplace_back( t );
                            act++;
                            total += t;
                        }
                    }
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

            if( tmin != std::numeric_limits<int64_t>::max() )
            {
                ImGui::Checkbox( "Log values", &m_findZone.logVal );
                ImGui::SameLine();
                ImGui::Checkbox( "Log time", &m_findZone.logTime );
                ImGui::SameLine();
                ImGui::Checkbox( "Cumulate time", &m_findZone.cumulateTime );
                ImGui::SameLine();
                ImGui::TextDisabled( "(?)" );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( "Show total time taken by calls in each bin instead of call counts." );
                    ImGui::EndTooltip();
                }

                ImGui::TextDisabled( "Time range:" );
                ImGui::SameLine();
                ImGui::Text( "%s - %s (%s)", TimeToString( tmin ), TimeToString( tmax ), TimeToString( tmax - tmin ) );

                const auto dt = double( tmax - tmin );
                const auto cumulateTime = m_findZone.cumulateTime;

                if( dt > 0 )
                {
                    const auto w = ImGui::GetContentRegionAvail().x;

                    const auto numBins = int64_t( w - 4 );
                    if( numBins > 1 )
                    {
                        if( numBins != m_findZone.numBins )
                        {
                            m_findZone.numBins = numBins;
                            m_findZone.bins = std::make_unique<int64_t[]>( numBins );
                            m_findZone.binTime = std::make_unique<int64_t[]>( numBins );
                            m_findZone.selBin = std::make_unique<int64_t[]>( numBins );
                        }

                        const auto& bins = m_findZone.bins;
                        const auto& binTime = m_findZone.binTime;
                        const auto& selBin = m_findZone.selBin;

                        memset( bins.get(), 0, sizeof( int64_t ) * numBins );
                        memset( binTime.get(), 0, sizeof( int64_t ) * numBins );
                        memset( selBin.get(), 0, sizeof( int64_t ) * numBins );

                        int64_t selectionTime = 0;
                        const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                        const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );

                        const auto& sorted = m_findZone.sorted;

                        if( m_findZone.logTime )
                        {
                            const auto tMinLog = log10( tmin );
                            const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                            {
                                auto zit = sorted.begin();
                                while( zit != sorted.end() && *zit == 0 ) zit++;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                    auto nit = std::lower_bound( zit, sorted.end(), nextBinVal );
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
                                const auto timeSum = std::accumulate( zit, sorted.end(), int64_t( 0 ) );
                                bins[numBins-1] += std::distance( zit, sorted.end() );
                                binTime[numBins-1] += timeSum;
                                if( m_findZone.highlight.active && *zit >= s && *(sorted.end()-1) <= e ) selectionTime += timeSum;
                            }

                            if( m_findZone.selGroup != m_findZone.Unselected )
                            {
                                auto zit = m_findZone.selSort.begin();
                                while( zit != m_findZone.selSort.end() && *zit == 0 ) zit++;
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
                            auto zit = sorted.begin();
                            while( zit != sorted.end() && *zit == 0 ) zit++;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = ( i+1 ) * zmax / numBins;
                                auto nit = std::lower_bound( zit, sorted.end(), nextBinVal );
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
                            const auto timeSum = std::accumulate( zit, sorted.end(), int64_t( 0 ) );
                            bins[numBins-1] += std::distance( zit, sorted.end() );
                            binTime[numBins-1] += timeSum;
                            if( m_findZone.highlight.active && *zit >= s && *(sorted.end()-1) <= e ) selectionTime += timeSum;

                            if( m_findZone.selGroup != m_findZone.Unselected )
                            {
                                auto zit = m_findZone.selSort.begin();
                                while( zit != m_findZone.selSort.end() && *zit == 0 ) zit++;
                                for( int64_t i=0; i<numBins; i++ )
                                {
                                    const auto nextBinVal = ( i+1 ) * zmax / numBins;
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

                        int64_t maxVal;
                        if( cumulateTime )
                        {
                            maxVal = binTime[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( maxVal, binTime[i] );
                            }
                        }
                        else
                        {
                            maxVal = bins[0];
                            for( int i=1; i<numBins; i++ )
                            {
                                maxVal = std::max( maxVal, bins[i] );
                            }
                        }

                        TextFocused( "Total time:", TimeToString( timeTotal ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( maxVal, true ) );
                        TextFocused( "Average time:", TimeToString( m_findZone.average ) );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        TextFocused( "Median time:", TimeToString( m_findZone.median ) );

                        ImGui::TextDisabled( "Selection range:" );
                        ImGui::SameLine();
                        if( m_findZone.highlight.active )
                        {
                            const auto s = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
                            const auto e = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
                            ImGui::Text( "%s - %s (%s)", TimeToString( s ), TimeToString( e ), TimeToString( e - s ) );
                        }
                        else
                        {
                            ImGui::Text( "none" );
                        }
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(?)" );
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            ImGui::Text( "Left draw on histogram to select range. Right click to clear selection." );
                            ImGui::EndTooltip();
                        }
                        if( m_findZone.highlight.active )
                        {
                            TextFocused( "Selection time:", TimeToString( selectionTime ) );
                        }
                        else
                        {
                            TextFocused( "Selection time:", "none" );
                        }
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            TextFocused( "Zone group time:", TimeToString( m_findZone.groups[m_findZone.selGroup].time ) );
                            TextFocused( "Group average:", TimeToString( m_findZone.selAverage ) );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Group median:", TimeToString( m_findZone.selMedian ) );
                        }
                        else
                        {
                            TextFocused( "Zone group time:", "none" );
                            TextFocused( "Group average:", "none" );
                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
                            TextFocused( "Group median:", "none" );
                        }

                        ImGui::Checkbox( "###draw1", &m_findZone.drawAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c1", ImVec4( 0xFF/255.f, 0x44/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        ImGui::Text( "Average time" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0xAA/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        ImGui::Text( "Median time" );
                        ImGui::Checkbox( "###draw2", &m_findZone.drawSelAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c3", ImVec4( 0xFF/255.f, 0xAA/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::Text( "Group average" );
                        }
                        else
                        {
                            ImGui::TextDisabled( "Group average" );
                        }
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c4", ImVec4( 0x44/255.f, 0xDD/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::Text( "Group median" );
                        }
                        else
                        {
                            ImGui::TextDisabled( "Group median" );
                        }

                        const auto Height = 200 * ImGui::GetTextLineHeight() / 15.f;
                        const auto wpos = ImGui::GetCursorScreenPos();

                        ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 1.5 ) ) );
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
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10( selBin[i] + 1 ) * hAdj ), 0xFFDD7777 );
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
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                    if( selBin[i] > 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - selBin[i] * hAdj ), 0xFFDD7777 );
                                    }
                                }
                            }
                        }

                        const auto xoff = 2;
                        const auto yoff = Height + 1;

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
                                    draw->AddLine( wpos + ImVec2( x, yoff ), wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF );
                                    if( tw == 0 || x > tx + tw + ty * 1.1 )
                                    {
                                        tx = x;
                                        auto txt = TimeToStringInteger( tt );
                                        draw->AddText( wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }
                                }

                                for( int j=0; j<8; j++ )
                                {
                                    const auto xoff = x + logticks[j] * step;
                                    if( xoff >= 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( xoff, yoff ), wpos + ImVec2( xoff, yoff + round( ty * 0.25 ) ), 0x66FFFFFF );
                                    }
                                }

                                tt *= 10;
                            }
                        }
                        else
                        {
                            const auto pxns = numBins / dt;
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
                                draw->AddLine( wpos + ImVec2( xo + x, yoff ), wpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                {
                                    tx = x;
                                    auto txt = TimeToStringInteger( tt );
                                    draw->AddText( wpos + ImVec2( xo + x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
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
                                draw->AddLine( ImVec2( wpos.x + ta, wpos.y ), ImVec2( wpos.x + ta, wpos.y+Height-2 ), 0xFFFF88FF );
                            }
                            else
                            {
                                draw->AddLine( ImVec2( wpos.x + ta, wpos.y ), ImVec2( wpos.x + ta, wpos.y+Height-2 ), 0xFF4444FF );
                                draw->AddLine( ImVec2( wpos.x + tm, wpos.y ), ImVec2( wpos.x + tm, wpos.y+Height-2 ), 0xFFFFAA44 );
                            }
                        }
                        if( m_findZone.drawSelAvgMed && m_findZone.selGroup != m_findZone.Unselected )
                        {
                            draw->AddLine( ImVec2( wpos.x + tga, wpos.y ), ImVec2( wpos.x + tga, wpos.y+Height-2 ), 0xFF44AAFF );
                            draw->AddLine( ImVec2( wpos.x + tgm, wpos.y ), ImVec2( wpos.x + tgm, wpos.y+Height-2 ), 0xFF44DD44 );
                        }

                        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            auto& io = ImGui::GetIO();
                            draw->AddLine( ImVec2( io.MousePos.x, wpos.y ), ImVec2( io.MousePos.x, wpos.y+Height-2 ), 0x33FFFFFF );

                            const auto bin = double( io.MousePos.x - wpos.x - 2 );
                            int64_t t0, t1;
                            if( m_findZone.logTime )
                            {
                                t0 = int64_t( pow( 10, ltmin +  bin    / numBins * ( ltmax - ltmin ) ) );

                                // Hackfix for inability to select data in last bin.
                                // A proper solution would be nice.
                                if( bin+1 == numBins )
                                {
                                    t1 = tmax;
                                }
                                else
                                {
                                    t1 = int64_t( pow( 10, ltmin + (bin+1) / numBins * ( ltmax - ltmin ) ) );
                                }
                            }
                            else
                            {
                                t0 = int64_t( tmin +  bin    / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + (bin+1) / numBins * ( tmax - tmin ) );
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
                            ImGui::TextDisabled( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            ImGui::TextDisabled( "Count:" );
                            ImGui::SameLine();
                            ImGui::Text( "%" PRIu64, bins[bin] );
                            TextFocused( "Time spent in bin:", TimeToString( binTime[bin] ) );
                            TextFocused( "Time spent in the left bins:", TimeToString( tBefore ) );
                            TextFocused( "Time spent in the right bins:", TimeToString( tAfter ) );
                            ImGui::EndTooltip();

                            if( ImGui::IsMouseClicked( 1 ) )
                            {
                                m_findZone.highlight.active = false;
                                m_findZone.ResetGroups();
                            }
                            else if( ImGui::IsMouseClicked( 0 ) )
                            {
                                m_findZone.highlight.active = true;
                                m_findZone.highlight.start = t0;
                                m_findZone.highlight.end = t1;
                                m_findZone.hlOrig_t0 = t0;
                                m_findZone.hlOrig_t1 = t1;
                            }
                            else if( ImGui::IsMouseDragging( 0, 0 ) )
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

                            draw->AddRectFilled( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x22DD8888 );
                            draw->AddRect( wpos + ImVec2( 2 + t0, 1 ), wpos + ImVec2( 2 + t1, Height-1 ), 0x44DD8888 );
                        }
                    }
                }
            }

            ImGui::TreePop();
        }

        ImGui::Separator();
        ImGui::Text( "Found zones:" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(?)" );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "Left click to highlight entry. Right click to clear selection." );
            ImGui::EndTooltip();
        }

        bool groupChanged = false;
        ImGui::Text( "Group by:" );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Thread", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Thread );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "User text", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::UserText );
        ImGui::SameLine();
        groupChanged |= ImGui::RadioButton( "Call stacks", (int*)( &m_findZone.groupBy ), (int)FindZone::GroupBy::Callstack );
        if( groupChanged )
        {
            m_findZone.selGroup = m_findZone.Unselected;
            m_findZone.ResetGroups();
        }

        ImGui::Text( "Sort by:" );
        ImGui::SameLine();
        ImGui::RadioButton( "Order", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Order );
        ImGui::SameLine();
        ImGui::RadioButton( "Count", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Count );
        ImGui::SameLine();
        ImGui::RadioButton( "Time", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Time );

        auto& zones = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] ).zones;
        auto sz = zones.size();
        auto processed = m_findZone.processed;
        const auto hmin = std::min( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto hmax = std::max( m_findZone.highlight.start, m_findZone.highlight.end );
        const auto groupBy = m_findZone.groupBy;
        const auto highlightActive = m_findZone.highlight.active;
        while( processed < sz )
        {
            auto& ev = zones[processed];
            if( ev.zone->end < 0 ) break;

            const auto end = m_worker.GetZoneEndDirect( *ev.zone );
            const auto timespan = end - ev.zone->start;
            if( timespan == 0 )
            {
                processed++;
                continue;
            }

            if( highlightActive )
            {
                if( timespan < hmin || timespan > hmax )
                {
                    processed++;
                    continue;
                }
            }

            processed++;
            FindZone::Group* group;
            switch( groupBy )
            {
            case FindZone::GroupBy::Thread:
                group = &m_findZone.groups[ev.thread];
                break;
            case FindZone::GroupBy::UserText:
                group = &m_findZone.groups[ev.zone->text.active ? ev.zone->text.idx : std::numeric_limits<uint64_t>::max()];
                break;
            case FindZone::GroupBy::Callstack:
                group = &m_findZone.groups[ev.zone->callstack];
                break;
            default:
                group = nullptr;
                assert( false );
                break;
            }
            group->time += timespan;
            group->zones.push_back( ev.zone );
        }
        m_findZone.processed = processed;

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
            break;
        case FindZone::SortBy::Count:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.zones.size() > rhs->second.zones.size(); } );
            break;
        case FindZone::SortBy::Time:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.time > rhs->second.time; } );
            break;
        default:
            assert( false );
            break;
        }

        ImGui::BeginChild( "##zonesScroll", ImVec2( ImGui::GetWindowContentRegionWidth(), std::max( 200.f, ImGui::GetContentRegionAvail().y ) ) );
        idx = 0;
        for( auto& v : groups )
        {
            const char* hdrString;
            switch( groupBy )
            {
            case FindZone::GroupBy::Thread:
                hdrString = m_worker.GetThreadString( m_worker.DecompressThread( v->first ) );
                break;
            case FindZone::GroupBy::UserText:
                hdrString = v->first == std::numeric_limits<uint64_t>::max() ? "No user text" : m_worker.GetString( StringIdx( v->first ) );
                break;
            case FindZone::GroupBy::Callstack:
                if( v->first == 0 )
                {
                    hdrString = "No callstack";
                }
                else
                {
                    auto& callstack = m_worker.GetCallstack( v->first );
                    hdrString = m_worker.GetString( m_worker.GetCallstackFrame( *callstack.begin() )->name );
                }
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
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.5f, 0.5f, 0.5f, 1.0f ), "(%s) %s", RealToString( v->second.zones.size(), true ), TimeToString( v->second.time ) );
            if( groupBy == FindZone::GroupBy::Callstack && v->first != 0 )
            {
                ImGui::SameLine();
                SmallCallstackButton( "callstack", v->first, idx );
            }

            if( expand )
            {
                ImGui::Columns( 3, hdrString );
                ImGui::Separator();
                ImGui::Text( "Time from start" );
                ImGui::NextColumn();
                ImGui::Text( "Execution time" );
                ImGui::NextColumn();
                ImGui::Text( "Name" );
                ImGui::SameLine();
                ImGui::TextDisabled( "(?)" );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( "Only displayed if custom zone name is set." );
                    ImGui::EndTooltip();
                }
                ImGui::NextColumn();
                ImGui::Separator();

                for( auto& ev : v->second.zones )
                {
                    const auto end = m_worker.GetZoneEndDirect( *ev );
                    const auto timespan = end - ev->start;

                    ImGui::PushID( ev );
                    if( ImGui::Selectable( TimeToString( ev->start - m_worker.GetTimeBegin() ), m_zoneInfoWindow == ev, ImGuiSelectableFlags_SpanAllColumns ) )
                    {
                        ShowZoneInfo( *ev );
                    }
                    if( ImGui::IsItemHovered() )
                    {
                        m_zoneHighlight = ev;
                        if( ImGui::IsMouseClicked( 2 ) )
                        {
                            ZoomToZone( *ev );
                        }
                        ZoneTooltip( *ev );
                    }

                    ImGui::NextColumn();
                    ImGui::Text( "%s", TimeToString( timespan ) );
                    ImGui::NextColumn();
                    if( ev->name.active )
                    {
                        ImGui::Text( "%s", m_worker.GetString( ev->name ) );
                    }
                    ImGui::NextColumn();

                    ImGui::PopID();
                }
                ImGui::Columns( 1 );
                ImGui::Separator();
                ImGui::TreePop();
            }
        }
        ImGui::EndChild();
        if( ImGui::IsItemHovered() && ImGui::IsMouseClicked( 1 ) )
        {
            m_findZone.selGroup = m_findZone.Unselected;
            m_findZone.ResetSelection();
        }
    }
#endif

    ImGui::End();
}

void View::DrawCompare()
{
    ImGui::Begin( "Compare traces", &m_compare.show );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable trace comparison." );
#elif !defined TRACY_FILESELECTOR
    ImGui::TextWrapped( "File selector is disabled in this build." );
    ImGui::TextWrapped( "Rebuild with the TRACY_FILESELECTOR macro to enable trace comparison." );
#else
    if( !m_compare.second )
    {
        ImGui::TextWrapped( "Please load a second trace to compare results." );
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_FOLDER_OPEN " Open second trace" ) && !m_compare.loadThread.joinable() )
#else
        if( ImGui::Button( "Open second trace" ) && !m_compare.loadThread.joinable() )
#endif
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
                        m_compare.loadThread = std::thread( [this, f] {
                            try
                            {
                                m_compare.second = std::make_unique<Worker>( *f, EventType::None );
                            }
                            catch( const tracy::UnsupportedVersion& e )
                            {
                                m_compare.badVer = e.version;
                            }
                        } );
                    }
                }
                catch( const tracy::NotTracyDump& e )
                {
                    m_compare.badVer = -1;
                }
            }
        }
        tracy::BadVersion( m_compare.badVer );
        ImGui::End();
        return;
    }

    if( m_compare.loadThread.joinable() ) m_compare.loadThread.join();

    if( !m_worker.AreSourceLocationZonesReady() || !m_compare.second->AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        ImGui::End();
        return;
    }

#ifdef TRACY_EXTENDED_FONT
    ImGui::TextColored( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
    ImGui::SameLine();
#endif
    ImGui::TextDisabled( "This trace:" );
    ImGui::SameLine();
    ImGui::Text( "%s", m_worker.GetCaptureName().c_str() );

#ifdef TRACY_EXTENDED_FONT
    ImGui::TextColored( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
    ImGui::SameLine();
#endif
    ImGui::TextDisabled( "External trace:" );
    ImGui::SameLine();
    ImGui::Text( "%s", m_compare.second->GetCaptureName().c_str() );
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::SmallButton( ICON_FA_TRASH_ALT " Unload" ) )
#else
    if( ImGui::SmallButton( "Unload" ) )
#endif
    {
        m_compare.Reset();
        m_compare.second.reset();
        ImGui::End();
        return;
    }

    ImGui::InputText( "", m_compare.pattern, 1024 );
    ImGui::SameLine();

#ifdef TRACY_EXTENDED_FONT
    const bool findClicked = ImGui::Button( ICON_FA_SEARCH " Find" );
#else
    const bool findClicked = ImGui::Button( "Find" );
#endif
    ImGui::SameLine();

#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_BAN " Clear" ) )
#else
    if( ImGui::Button( "Clear" ) )
#endif
    {
        m_compare.Reset();
    }

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

    if( ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        ImGui::Separator();
        ImGui::Columns( 2 );
#ifdef TRACY_EXTENDED_FONT
        ImGui::TextColored( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
        ImGui::SameLine();
#endif
        ImGui::Text( "This trace" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_compare.match[0].size() );
        ImGui::NextColumn();
#ifdef TRACY_EXTENDED_FONT
        ImGui::TextColored( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
        ImGui::SameLine();
#endif
        ImGui::Text( "External trace" );
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
            ImGui::PushID( idx );
            ImGui::RadioButton( m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[0], idx++ );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s:%i", RealToString( zones.size(), true ), m_worker.GetString( srcloc.file ), srcloc.line );
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
            ImGui::RadioButton( m_compare.second->GetString( srcloc.name.active ? srcloc.name : srcloc.function ), &m_compare.selMatch[1], idx++ );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.5, 0.5, 0.5, 1 ), "(%s) %s:%i", RealToString( zones.size(), true ), m_compare.second->GetString( srcloc.file ), srcloc.line );
            ImGui::PopID();
        }
        ImGui::NextColumn();
        ImGui::EndColumns();
        ImGui::TreePop();

        if( prev0 != m_compare.selMatch[0] || prev1 != m_compare.selMatch[1] )
        {
            m_compare.ResetSelection();
        }
    }

    ImGui::Separator();

    if( m_compare.match[0].empty() || m_compare.match[1].empty() )
    {
        ImGui::TextWrapped( "Both traces must have matches." );
        ImGui::End();
        return;
    }

    if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        const auto ty = ImGui::GetFontSize();

        auto& zoneData0 = m_worker.GetZonesForSourceLocation( m_compare.match[0][m_compare.selMatch[0]] );
        auto& zoneData1 = m_compare.second->GetZonesForSourceLocation( m_compare.match[1][m_compare.selMatch[1]] );
        auto& zones0 = zoneData0.zones;
        auto& zones1 = zoneData1.zones;

        auto tmin = std::min( zoneData0.min, zoneData1.min );
        auto tmax = std::max( zoneData0.max, zoneData1.max );;

        const size_t zsz[2] = { zones0.size(), zones1.size() };
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
                    auto& zone = *zones[i].zone;
                    if( zone.end < 0 ) break;
                    const auto t = zone.end - zone.start;
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

        if( tmin != std::numeric_limits<int64_t>::max() )
        {
            ImGui::Checkbox( "Log values", &m_compare.logVal );
            ImGui::SameLine();
            ImGui::Checkbox( "Log time", &m_compare.logTime );
            ImGui::SameLine();
            ImGui::Checkbox( "Cumulate time", &m_compare.cumulateTime );
            ImGui::SameLine();
            ImGui::TextDisabled( "(?)" );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Show total time taken by calls in each bin instead of call counts." );
                ImGui::EndTooltip();
            }
            ImGui::SameLine();
            ImGui::Checkbox( "Normalize values", &m_compare.normalize );
            ImGui::SameLine();
            ImGui::TextDisabled( "(?)" );
            if( ImGui::IsItemHovered() )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Normalization will fudge reported data values!" );
                ImGui::EndTooltip();
            }

            ImGui::TextDisabled( "Time range:" );
            ImGui::SameLine();
            ImGui::Text( "%s - %s (%s)", TimeToString( tmin ), TimeToString( tmax ), TimeToString( tmax - tmin ) );

            const auto dt = double( tmax - tmin );
            const auto cumulateTime = m_compare.cumulateTime;

            if( dt > 0 )
            {
                const auto w = ImGui::GetContentRegionAvail().x;

                const auto numBins = int64_t( w - 4 );
                if( numBins > 1 )
                {
                    if( numBins != m_compare.numBins )
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
                        if( zones0.size() > zones1.size() )
                        {
                            adj1 = double( zones0.size() ) / zones1.size();
                        }
                        else
                        {
                            adj0 = double( zones1.size() ) / zones0.size();
                        }
                    }

                    const auto& sorted = m_compare.sorted;
                    auto zit0 = sorted[0].begin();
                    auto zit1 = sorted[1].begin();
                    if( m_compare.logTime )
                    {
                        const auto tMinLog = log10( tmin );
                        const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                        for( int64_t i=0; i<numBins; i++ )
                        {
                            const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                            auto nit0 = std::lower_bound( zit0, sorted[0].end(), nextBinVal );
                            auto nit1 = std::lower_bound( zit1, sorted[1].end(), nextBinVal );
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
                            const auto nextBinVal = ( i+1 ) * zmax / numBins;
                            auto nit0 = std::lower_bound( zit0, sorted[0].end(), nextBinVal );
                            auto nit1 = std::lower_bound( zit1, sorted[1].end(), nextBinVal );
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

#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                    ImGui::SameLine();
#endif
                    TextFocused( "Total time (this):", TimeToString( zoneData0.total * adj0 ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                    ImGui::SameLine();
#endif
                    TextFocused( "Total time (ext.):", TimeToString( zoneData1.total * adj1 ) );
                    TextFocused( "Savings:", TimeToString( zoneData1.total * adj1 - zoneData0.total * adj0 ) );
                    TextFocused( "Max counts:", cumulateTime ? TimeToString( maxVal ) : RealToString( floor( maxVal ), true ) );

#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                    ImGui::SameLine();
#endif
                    TextFocused( "Average time (this):", TimeToString( m_compare.average[0] ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                    ImGui::SameLine();
#endif
                    TextFocused( "Median time (this):", TimeToString( m_compare.median[0] ) );

#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                    ImGui::SameLine();
#endif
                    TextFocused( "Average time (ext.):", TimeToString( m_compare.average[1] ) );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                    ImGui::SameLine();
#endif
                    TextFocused( "Median time (ext.):", TimeToString( m_compare.median[1] ) );

#ifdef TRACY_EXTENDED_FONT
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ) );
                    ImGui::Button( ICON_FA_LEMON );
                    ImGui::PopStyleColor( 4 );
#else
                    ImGui::ColorButton( "c1", ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
#endif
                    ImGui::SameLine();
                    ImGui::Text( "This trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

#ifdef TRACY_EXTENDED_FONT
                    ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                    ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ) );
                    ImGui::Button( ICON_FA_GEM );
                    ImGui::PopStyleColor( 4 );
#else
                    ImGui::ColorButton( "c2", ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
#endif
                    ImGui::SameLine();
                    ImGui::Text( "External trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

                    ImGui::ColorButton( "c3", ImVec4( 0x44/255.f, 0xBB/255.f, 0xBB/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                    ImGui::SameLine();
                    ImGui::Text( "Overlap" );

                    const auto Height = 200 * ImGui::GetTextLineHeight() / 15.f;
                    const auto wpos = ImGui::GetCursorScreenPos();

                    ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 1.5 ) ) );
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
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFFBBBB44 );
                                }
                                if( val1 == val )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), wpos + ImVec2( 2+i, Height-3 - log10( val0 + 1 ) * hAdj ), 0xFF22DDDD );
                                }
                                else
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), wpos + ImVec2( 2+i, Height-3 - log10( val1 + 1 ) * hAdj ), 0xFF2222DD );
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
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFFBBBB44 );
                                }
                                if( val1 == val )
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - val * hAdj ), wpos + ImVec2( 2+i, Height-3 - val0 * hAdj ), 0xFF22DDDD );
                                }
                                else
                                {
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 - val * hAdj ), wpos + ImVec2( 2+i, Height-3 - val1 * hAdj ), 0xFF2222DD );
                                }
                            }
                        }
                    }

                    const auto xoff = 2;
                    const auto yoff = Height + 1;

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
                                draw->AddLine( wpos + ImVec2( x, yoff ), wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF );
                                if( tw == 0 || x > tx + tw + ty * 1.1 )
                                {
                                    tx = x;
                                    auto txt = TimeToStringInteger( tt );
                                    draw->AddText( wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                    tw = ImGui::CalcTextSize( txt ).x;
                                }
                            }

                            for( int j=0; j<8; j++ )
                            {
                                const auto xoff = x + logticks[j] * step;
                                if( xoff >= 0 )
                                {
                                    draw->AddLine( wpos + ImVec2( xoff, yoff ), wpos + ImVec2( xoff, yoff + round( ty * 0.25 ) ), 0x66FFFFFF );
                                }
                            }

                            tt *= 10;
                        }
                    }
                    else
                    {
                        const auto pxns = numBins / dt;
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
                            draw->AddLine( wpos + ImVec2( xo + x, yoff ), wpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                            if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                            {
                                tx = x;
                                auto txt = TimeToStringInteger( tt );
                                draw->AddText( wpos + ImVec2( xo + x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
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
                        draw->AddLine( ImVec2( io.MousePos.x, wpos.y ), ImVec2( io.MousePos.x, wpos.y+Height-2 ), 0x33FFFFFF );

                        const auto bin = double( io.MousePos.x - wpos.x - 2 );
                        int64_t t0, t1;
                        if( m_compare.logTime )
                        {
                            t0 = int64_t( pow( 10, ltmin +  bin    / numBins * ( ltmax - ltmin ) ) );
                            t1 = int64_t( pow( 10, ltmin + (bin+1) / numBins * ( ltmax - ltmin ) ) );
                        }
                        else
                        {
                            t0 = int64_t( tmin +  bin    / numBins * ( tmax - tmin ) );
                            t1 = int64_t( tmin + (bin+1) / numBins * ( tmax - tmin ) );
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
                        ImGui::TextDisabled( "Time range:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                        ImGui::TextDisabled( "Count:" );
                        ImGui::SameLine();
                        ImGui::Text( "%g / %g", floor( bins[bin].v0 ), floor( bins[bin].v1 ) );
                        ImGui::TextDisabled( "Time spent in bin:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( binTime[bin].v0 ), TimeToString( binTime[bin].v1 ) );
                        ImGui::TextDisabled( "Time spent in the left bins:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( tBefore[0] ), TimeToString( tBefore[1] ) );
                        ImGui::TextDisabled( "Time spent in the right bins:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", TimeToString( tAfter[0] ), TimeToString( tAfter[1] ) );
                        ImGui::TextDisabled( "(Data is displayed as:" );
                        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                        ImGui::TextColored( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
#endif
                        ImGui::TextDisabled( "[this trace] /" );
                        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                        ImGui::TextColored( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
#endif
                        ImGui::TextDisabled( "[external trace])" );
                        ImGui::EndTooltip();
                    }
                }
            }
        }
        ImGui::TreePop();
    }

#endif
    ImGui::End();
}

void View::DrawStatistics()
{
    ImGui::Begin( "Statistics", &m_showStatistics );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable statistics view." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        ImGui::End();
        return;
    }

#ifdef TRACY_EXTENDED_FONT
    ImGui::Checkbox( ICON_FA_CLOCK " Show self times", &m_statSelf );
#else
    ImGui::Checkbox( "Show self times", &m_statSelf );
#endif

    auto& slz = m_worker.GetSourceLocationZones();
    Vector<decltype(slz.begin())> srcloc;
    srcloc.reserve( slz.size() );
    for( auto it = slz.begin(); it != slz.end(); ++it )
    {
        if( it->second.total != 0 )
        {
            srcloc.push_back_no_space_check( it );
        }
    }

    switch( m_statSort )
    {
    case 0:
        if( m_statSelf )
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.selfTotal > rhs->second.selfTotal; } );
        }
        else
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.total > rhs->second.total; } );
        }
        break;
    case 1:
        pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.zones.size() > rhs->second.zones.size(); } );
        break;
    case 2:
        if( m_statSelf )
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.selfTotal / lhs->second.zones.size() > rhs->second.selfTotal / rhs->second.zones.size(); } );
        }
        else
        {
            pdqsort_branchless( srcloc.begin(), srcloc.end(), []( const auto& lhs, const auto& rhs ) { return lhs->second.total / lhs->second.zones.size() > rhs->second.total / rhs->second.zones.size(); } );
        }
        break;
    default:
        assert( false );
        break;
    }

    TextFocused( "Recorded source locations:", RealToString( srcloc.size(), true ) );

    ImGui::Columns( 5 );
    ImGui::Separator();
    ImGui::Text( "Name" );
    ImGui::NextColumn();
    ImGui::Text( "Location" );
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Total time" ) ) m_statSort = 0;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Counts" ) ) m_statSort = 1;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "MTPC" ) ) m_statSort = 2;
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Mean time per call" );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Separator();

    for( auto& v : srcloc )
    {
        ImGui::PushID( v->first );

        auto& srcloc = m_worker.GetSourceLocation( v->first );
        auto name = m_worker.GetString( srcloc.name.active ? srcloc.name : srcloc.function );
        if( ImGui::Selectable( name, m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == v->first, ImGuiSelectableFlags_SpanAllColumns ) )
        {
            m_findZone.ShowZone( v->first, name );
        }
        ImGui::NextColumn();
        ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
        ImGui::NextColumn();
        ImGui::Text( "%s", TimeToString( m_statSelf ? v->second.selfTotal : v->second.total ) );
        ImGui::NextColumn();
        ImGui::Text( "%s", RealToString( v->second.zones.size(), true ) );
        ImGui::NextColumn();
        ImGui::Text( "%s", TimeToString( ( m_statSelf ? v->second.selfTotal : v->second.total ) / v->second.zones.size() ) );
        ImGui::NextColumn();

        ImGui::PopID();
    }
    ImGui::EndColumns();
#endif
    ImGui::End();
}

void View::DrawCallstackWindow()
{
    bool show = true;
    ImGui::Begin( "Call stack", &show );

#ifdef TRACY_EXTENDED_FONT
    ImGui::Checkbox( ICON_FA_AT " Show frame addresses", &m_showCallstackFrameAddress );
#else
    ImGui::Checkbox( "Show frame addresses", &m_showCallstackFrameAddress );
#endif

    auto& cs = m_worker.GetCallstack( m_callstackInfoWindow );

    ImGui::Columns( 3 );
    ImGui::Text( "Frame" );
    ImGui::NextColumn();
    ImGui::Text( "Function" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on entry to copy it to clipboard." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Location" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on entry to copy it to clipboard." );
        ImGui::Text( "Right click on entry to try to open source file." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();

    int fidx = 0;
    for( auto& entry : cs )
    {
        ImGui::Separator();
        ImGui::Text( "%i", fidx++ );
        ImGui::NextColumn();

        auto frame = m_worker.GetCallstackFrame( entry );
        if( !frame )
        {
            char buf[32];
            sprintf( buf, "%p", (void*)entry );
            ImGui::Text( "%s", buf );
            if( ImGui::IsItemClicked() )
            {
                ImGui::SetClipboardText( buf );
            }
            ImGui::NextColumn();
            ImGui::NextColumn();
        }
        else
        {
            auto txt = m_worker.GetString( frame->name );
            ImGui::TextWrapped( "%s", txt );
            if( ImGui::IsItemClicked() )
            {
                ImGui::SetClipboardText( txt );
            }
            ImGui::NextColumn();
            ImGui::PushTextWrapPos( 0.0f );
            float indentVal = 0.f;
            if( m_callstackBuzzAnim.Match( fidx ) )
            {
                const auto time = m_callstackBuzzAnim.Time();
                indentVal = sin( time * 60.f ) * 10.f * time;
                ImGui::Indent( indentVal );
            }
            txt = m_worker.GetString( frame->file );
            if( m_showCallstackFrameAddress )
            {
                ImGui::TextDisabled( "0x%" PRIx64, entry );
                if( ImGui::IsItemClicked() )
                {
                    char tmp[32];
                    sprintf( tmp, "0x%" PRIx64, entry );
                    ImGui::SetClipboardText( tmp );
                }
            }
            else
            {
                if( frame->line == 0 )
                {
                    ImGui::TextDisabled( "%s", txt );
                }
                else
                {
                    ImGui::TextDisabled( "%s:%i", txt, frame->line );
                }
                if( ImGui::IsItemClicked() )
                {
                    ImGui::SetClipboardText( txt );
                }
            }
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( FileExists( txt ) )
                {
                    SetTextEditorFile( txt, frame->line );
                }
                else
                {
                    m_callstackBuzzAnim.Enable( fidx, 0.5f );
                }
            }
            if( indentVal != 0.f )
            {
                ImGui::Unindent( indentVal );
            }
            ImGui::PopTextWrapPos();
            ImGui::NextColumn();
        }
    }

    ImGui::EndColumns();
    ImGui::End();

    if( !show )
    {
        m_callstackInfoWindow = 0;
    }
}

void View::DrawMemoryAllocWindow()
{
    bool show = true;
    ImGui::Begin( "Memory allocation", &show );

    const auto& mem = m_worker.GetMemData();
    const auto& ev = mem.data[m_memoryAllocInfoWindow];
    const auto tidAlloc = m_worker.DecompressThread( ev.threadAlloc );
    const auto tidFree = m_worker.DecompressThread( ev.threadFree );
    int idx = 0;

    char buf[64];
    sprintf( buf, "0x%" PRIx64, ev.ptr );
    TextFocused( "Address:", buf );
    TextFocused( "Size:", MemSizeToString( ev.size ) );
    if( ev.size >= 10000ll )
    {
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s bytes)", RealToString( ev.size, true ) );
    }
    ImGui::Separator();
    TextFocused( "Appeared at", TimeToString( ev.timeAlloc - m_worker.GetTimeBegin() ) );
    if( ImGui::IsItemClicked() ) CenterAtTime( ev.timeAlloc );
    ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
    TextFocused( "Thread:", m_worker.GetThreadString( tidAlloc ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tidAlloc );
    if( ev.csAlloc != 0 )
    {
        ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
        SmallCallstackButton( "Call stack", ev.csAlloc, idx );
    }
    if( ev.timeFree < 0 )
    {
        ImGui::TextDisabled( "Allocation still active" );
    }
    else
    {
        TextFocused( "Freed at", TimeToString( ev.timeFree - m_worker.GetTimeBegin() ) );
        if( ImGui::IsItemClicked() ) CenterAtTime( ev.timeFree );
        ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
        TextFocused( "Thread:", m_worker.GetThreadString( tidFree ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(0x%" PRIX64 ")", tidFree );
        if( ev.csFree != 0 )
        {
            ImGui::SameLine(); ImGui::Spacing(); ImGui::SameLine();
            SmallCallstackButton( "Call stack", ev.csFree, idx );
        }
        TextFocused( "Duration:", TimeToString( ev.timeFree - ev.timeAlloc ) );
    }

    ImGui::Separator();

    auto zoneAlloc = FindZoneAtTime( tidAlloc, ev.timeAlloc );
    if( zoneAlloc )
    {
        const auto& srcloc = m_worker.GetSourceLocation( zoneAlloc->srcloc );
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
            if( ImGui::IsMouseClicked( 2 ) )
            {
                ZoomToZone( *zoneAlloc );
            }
            ZoneTooltip( *zoneAlloc );
        }
    }

    if( ev.timeFree >= 0 )
    {
        auto zoneFree = FindZoneAtTime( tidFree, ev.timeFree );
        if( zoneFree )
        {
            const auto& srcloc = m_worker.GetSourceLocation( zoneFree->srcloc );
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
                if( ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *zoneFree );
                }
                ZoneTooltip( *zoneFree );
            }
        }

        if( zoneAlloc != 0 && zoneAlloc == zoneFree )
        {
            ImGui::SameLine();
            ImGui::TextDisabled( "(same zone)" );
        }
    }

    ImGui::End();
    if( !show ) m_memoryAllocInfoWindow = -1;
}

void View::DrawInfo()
{
    char dtmp[64];
    time_t date = m_worker.GetCaptureTime();
    auto lt = localtime( &date );
    strftime( dtmp, 64, "%F %T", lt );

    const auto& io = ImGui::GetIO();

    ImGui::Begin( "Trace information", &m_showInfo );
    TextFocused( "Profiler memory usage:", MemSizeToString( memUsage.load( std::memory_order_relaxed ) ) );
    TextFocused( "Profiler FPS:", RealToString( int( io.Framerate ), true ) );
    ImGui::Separator();
    TextFocused( "Captured program:", m_worker.GetCaptureProgram().c_str() );
    TextFocused( "Capture time:", dtmp );
    ImGui::Separator();
    TextFocused( "Queue delay:", TimeToString( m_worker.GetDelay() ) );
    TextFocused( "Timer resolution:", TimeToString( m_worker.GetResolution() ) );
    ImGui::Separator();
    TextFocused( "Zones:", RealToString( m_worker.GetZoneCount(), true ) );
    TextFocused( "Lock events:", RealToString( m_worker.GetLockCount(), true ) );
    TextFocused( "Plot data points:", RealToString( m_worker.GetPlotCount(), true ) );
    TextFocused( "Memory allocations:", RealToString( m_worker.GetMemData().data.size(), true ) );
    TextFocused( "Source locations:", RealToString( m_worker.GetSrcLocCount(), true ) );
    TextFocused( "Call stacks:", RealToString( m_worker.GetCallstackPayloadCount(), true ) );
    TextFocused( "Call stack frames:", RealToString( m_worker.GetCallstackFrameCount(), true ) );

    const auto fsz = m_worker.GetFullFrameCount( *m_frames );
    if( fsz != 0 )
    {
        if( m_frameSortData.frameSet != m_frames )
        {
            m_frameSortData.frameSet = m_frames;
            m_frameSortData.frameNum = 0;
            m_frameSortData.data.clear();
            m_frameSortData.total = 0;
        }
        if( m_frameSortData.frameNum != fsz )
        {
            auto& vec = m_frameSortData.data;
            vec.reserve( fsz );
            int64_t total = m_frameSortData.total;
            for( size_t i=m_frameSortData.frameNum; i<fsz; i++ )
            {
                const auto t = m_worker.GetFrameTime( *m_frames, i );
                if( t > 0 )
                {
                    vec.emplace_back( t );
                    total += t;
                }
            }
            auto mid = vec.begin() + m_frameSortData.frameNum;
            pdqsort_branchless( mid, m_frameSortData.data.end() );
            std::inplace_merge( vec.begin(), mid, vec.end() );

            m_frameSortData.average = float( total ) / fsz;
            m_frameSortData.median = vec[fsz/2];
            m_frameSortData.total = total;
            m_frameSortData.frameNum = fsz;
        }

        const auto profileSpan = m_worker.GetLastTime() - m_worker.GetTimeBegin();

        ImGui::Separator();
        TextFocused( "Frame set:", m_frames->name == 0 ? "Frames" : m_worker.GetString( m_frames->name ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", m_frames->continuous ? "continuous" : "discontinuous" );
        TextFocused( "Count:", RealToString( fsz, true ) );
        TextFocused( "Total time:", TimeToString( m_frameSortData.total ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of profile time span)", m_frameSortData.total / float( profileSpan ) * 100.f );
        TextFocused( "Average frame time:", TimeToString( m_frameSortData.average ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.average ), true ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.average, true ) );
            ImGui::EndTooltip();
        }
        TextFocused( "Median frame time:", TimeToString( m_frameSortData.median ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%s FPS)", RealToString( round( 1000000000.0 / m_frameSortData.median ), true ) );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::Text( "%s FPS", RealToString( 1000000000.0 / m_frameSortData.median, true ) );
            ImGui::EndTooltip();
        }

        if( ImGui::TreeNode( "Histogram" ) )
        {
            const auto ty = ImGui::GetFontSize();

            auto& frames = m_frameSortData.data;
            const auto tmin = frames.front();
            const auto tmax = frames.back();
            const auto timeTotal = m_frameSortData.total;

            if( tmin != std::numeric_limits<int64_t>::max() )
            {
                ImGui::Checkbox( "Log values", &m_frameSortData.logVal );
                ImGui::SameLine();
                ImGui::Checkbox( "Log time", &m_frameSortData.logTime );

                ImGui::TextDisabled( "Time range:" );
                ImGui::SameLine();
                ImGui::Text( "%s - %s (%s)", TimeToString( tmin ), TimeToString( tmax ), TimeToString( tmax - tmin ) );

                ImGui::TextDisabled( "FPS range:" );
                ImGui::SameLine();
                ImGui::Text( "%s FPS - %s FPS", RealToString( round( 1000000000.0 / tmin ), true ), RealToString( round( 1000000000.0 / tmax ), true ) );

                const auto dt = double( tmax - tmin );
                if( dt > 0 )
                {
                    const auto w = ImGui::GetContentRegionAvail().x;

                    const auto numBins = int64_t( w - 4 );
                    if( numBins > 1 )
                    {
                        if( numBins != m_frameSortData.numBins )
                        {
                            m_frameSortData.numBins = numBins;
                            m_frameSortData.bins = std::make_unique<int64_t[]>( numBins );
                        }

                        const auto& bins = m_frameSortData.bins;

                        memset( bins.get(), 0, sizeof( int64_t ) * numBins );

                        if( m_frameSortData.logTime )
                        {
                            const auto tMinLog = log10( tmin );
                            const auto zmax = ( log10( tmax ) - tMinLog ) / numBins;
                            auto fit = frames.begin();
                            while( fit != frames.end() && *fit == 0 ) fit++;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = int64_t( pow( 10.0, tMinLog + ( i+1 ) * zmax ) );
                                auto nit = std::lower_bound( fit, frames.end(), nextBinVal );
                                bins[i] = std::distance( fit, nit );
                                fit = nit;
                            }
                            bins[numBins-1] += std::distance( fit, frames.end() );
                        }
                        else
                        {
                            const auto zmax = tmax - tmin;
                            auto fit = frames.begin();
                            while( fit != frames.end() && *fit == 0 ) fit++;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = ( i+1 ) * zmax / numBins;
                                auto nit = std::lower_bound( fit, frames.end(), nextBinVal );
                                bins[i] = std::distance( fit, nit );
                                fit = nit;
                            }
                            bins[numBins-1] += std::distance( fit, frames.end() );
                        }

                        int64_t maxVal = bins[0];
                        for( int i=1; i<numBins; i++ )
                        {
                            maxVal = std::max( maxVal, bins[i] );
                        }

                        TextFocused( "Max counts:", RealToString( maxVal, true ) );

                        ImGui::Checkbox( "###draw1", &m_frameSortData.drawAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c1", ImVec4( 0xFF/255.f, 0x44/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        ImGui::Text( "Average time" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0x88/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        ImGui::Text( "Median time" );

                        const auto Height = 200 * ImGui::GetTextLineHeight() / 15.f;
                        const auto wpos = ImGui::GetCursorScreenPos();

                        ImGui::InvisibleButton( "##histogram", ImVec2( w, Height + round( ty * 1.5 ) ) );
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
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - log10( val + 1 ) * hAdj ), 0xFF22DDDD );
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
                                    draw->AddLine( wpos + ImVec2( 2+i, Height-3 ), wpos + ImVec2( 2+i, Height-3 - val * hAdj ), 0xFF22DDDD );
                                }
                            }
                        }

                        const auto xoff = 2;
                        const auto yoff = Height + 1;

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
                                    draw->AddLine( wpos + ImVec2( x, yoff ), wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF );
                                    if( tw == 0 || x > tx + tw + ty * 1.1 )
                                    {
                                        tx = x;
                                        auto txt = TimeToStringInteger( tt );
                                        draw->AddText( wpos + ImVec2( x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
                                        tw = ImGui::CalcTextSize( txt ).x;
                                    }
                                }

                                for( int j=0; j<8; j++ )
                                {
                                    const auto xoff = x + logticks[j] * step;
                                    if( xoff >= 0 )
                                    {
                                        draw->AddLine( wpos + ImVec2( xoff, yoff ), wpos + ImVec2( xoff, yoff + round( ty * 0.25 ) ), 0x66FFFFFF );
                                    }
                                }

                                tt *= 10;
                            }
                        }
                        else
                        {
                            const auto pxns = numBins / dt;
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
                                draw->AddLine( wpos + ImVec2( xo + x, yoff ), wpos + ImVec2( xo + x, yoff + round( ty * linelen[iter] ) ), 0x66FFFFFF );
                                if( iter == 0 && ( tw == 0 || x > tx + tw + ty * 1.1 ) )
                                {
                                    tx = x;
                                    auto txt = TimeToStringInteger( tt );
                                    draw->AddText( wpos + ImVec2( xo + x, yoff + round( ty * 0.5 ) ), 0x66FFFFFF, txt );
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
                                draw->AddLine( ImVec2( wpos.x + ta, wpos.y ), ImVec2( wpos.x + ta, wpos.y+Height-2 ), 0xFFFF88FF );
                            }
                            else
                            {
                                draw->AddLine( ImVec2( wpos.x + ta, wpos.y ), ImVec2( wpos.x + ta, wpos.y+Height-2 ), 0xFF4444FF );
                                draw->AddLine( ImVec2( wpos.x + tm, wpos.y ), ImVec2( wpos.x + tm, wpos.y+Height-2 ), 0xFFFF8844 );
                            }
                        }

                        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 2, 2 ), wpos + ImVec2( w-2, Height + round( ty * 1.5 ) ) ) )
                        {
                            const auto ltmin = log10( tmin );
                            const auto ltmax = log10( tmax );

                            auto& io = ImGui::GetIO();
                            draw->AddLine( ImVec2( io.MousePos.x, wpos.y ), ImVec2( io.MousePos.x, wpos.y+Height-2 ), 0x33FFFFFF );

                            const auto bin = double( io.MousePos.x - wpos.x - 2 );
                            int64_t t0, t1;
                            if( m_frameSortData.logTime )
                            {
                                t0 = int64_t( pow( 10, ltmin +  bin    / numBins * ( ltmax - ltmin ) ) );

                                // Hackfix for inability to select data in last bin.
                                // A proper solution would be nice.
                                if( bin+1 == numBins )
                                {
                                    t1 = tmax;
                                }
                                else
                                {
                                    t1 = int64_t( pow( 10, ltmin + (bin+1) / numBins * ( ltmax - ltmin ) ) );
                                }
                            }
                            else
                            {
                                t0 = int64_t( tmin +  bin    / numBins * ( tmax - tmin ) );
                                t1 = int64_t( tmin + (bin+1) / numBins * ( tmax - tmin ) );
                            }

                            ImGui::BeginTooltip();
                            ImGui::TextDisabled( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%s FPS - %s FPS)", RealToString( round( 1000000000.0 / t0 ), true ), RealToString( round( 1000000000.0 / t1 ), true ) );
                            ImGui::TextDisabled( "Count:" );
                            ImGui::SameLine();
                            ImGui::Text( "%" PRIu64, bins[bin] );
                            ImGui::EndTooltip();
                        }
                    }
                }
            }

            ImGui::TreePop();
        }
    }
    ImGui::Separator();
    TextFocused( "Host info:", m_worker.GetHostInfo().c_str() );
    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread != 0 )
    {
        ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
        ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Application has crashed. " ICON_FA_SKULL );
#else
        ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), "Application has crashed." );
#endif
        TextFocused( "Time of crash:", TimeToString( crash.time - m_worker.GetTimeBegin() ) );
        TextFocused( "Thread:", m_worker.GetThreadString( crash.thread ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(0x%" PRIX64 ")", crash.thread );
        ImGui::TextDisabled( "Reason:" );
        ImGui::SameLine();
        ImGui::TextWrapped( "%s", m_worker.GetString( crash.message ) );
        if( crash.callstack != 0 )
        {
            bool hilite = m_callstackInfoWindow == crash.callstack;
            if( hilite )
            {
                ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
                ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
                ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
            }
#ifdef TRACY_EXTENDED_FONT
            if( ImGui::Button( ICON_FA_ALIGN_JUSTIFY " Call stack" ) )
#else
            if( ImGui::Button( "Call stack" ) )
#endif
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
    ImGui::End();
}

void View::DrawTextEditor()
{
    bool show = true;
    ImGui::Begin( "Source view", &show );
#ifdef TRACY_EXTENDED_FONT
    ImGui::TextColored( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
#else
    ImGui::TextColored( ImVec4( 1.f, 1.f, 0.2f, 1.f ), "/!\\" );
#endif
    ImGui::SameLine();
    ImGui::TextColored( ImVec4( 1.f, 0.3f, 0.3f, 1.f ), "The source file contents might not reflect the actual profiled code!" );
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ImGui::TextColored( ImVec4( 1.f, 1.f, 0.2f, 1.f ), ICON_FA_EXCLAMATION_TRIANGLE );
#else
    ImGui::TextColored( ImVec4( 1.f, 1.f, 0.2f, 1.f ), "/!\\" );
#endif
    TextFocused( "File:", m_textEditorFile );
    if( m_textEditorFont ) ImGui::PushFont( m_textEditorFont );
    m_textEditor->Render( m_textEditorFile, ImVec2(), true );
    if( m_textEditorFont ) ImGui::PopFont();
    ImGui::End();
    if( !show ) m_textEditorFile = nullptr;
}

template<class T>
void View::ListMemData( T ptr, T end, std::function<void(T&)> DrawAddress, const char* id )
{
    const auto& style = ImGui::GetStyle();
    const auto dist = std::distance( ptr, end ) + 1;
    const auto ty = ImGui::GetTextLineHeight() + style.ItemSpacing.y;

    ImGui::BeginChild( id ? id : "##memScroll", ImVec2( 0, std::max( ty * std::min<int64_t>( dist, 5 ), std::min( ty * dist, ImGui::GetContentRegionAvail().y ) ) ) );
    ImGui::Columns( 8 );
    ImGui::Text( "Address" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on address to display memory allocation info window." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Size" );
    ImGui::NextColumn();
    ImGui::Text( "Appeared at" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Click on entry to center timeline at the memory allocation time." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Duration" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Active allocations are displayed using green color." );
        ImGui::Text( "Click on entry to center timeline at the memory release time." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Thread" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Shows one thread if alloc and free was performed on the same thread." );
        ImGui::Text( "Otherwise two threads are displayed in order: alloc, free." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Zone alloc" );
    ImGui::NextColumn();
    ImGui::Text( "Zone free" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "If alloc and free is performed in the same zone, it is displayed in yellow color." );
        ImGui::EndTooltip();
    }
    ImGui::NextColumn();
    ImGui::Text( "Call stack" );
    ImGui::NextColumn();
    ImGui::Separator();

    const auto& mem = m_worker.GetMemData();

    int idx = 0;
    while( ptr != end )
    {
        auto v = *ptr;
        const auto arrIdx = std::distance( mem.data.begin(), v );

        if( m_memoryAllocInfoWindow == arrIdx )
        {
            ImGui::PushStyleColor( ImGuiCol_Text, ImVec4( 1.f, 0.f, 0.f, 1.f ) );
            DrawAddress( ptr );
            ImGui::PopStyleColor();
        }
        else
        {
            DrawAddress( ptr );
            if( ImGui::IsItemClicked() )
            {
                m_memoryAllocInfoWindow = arrIdx;
            }
        }
        if( ImGui::IsItemHovered() )
        {
            m_memoryAllocHover = arrIdx;
            m_memoryAllocHoverWait = 2;
        }
        ImGui::NextColumn();
        ImGui::Text( "%s", MemSizeToString( v->size ) );
        ImGui::NextColumn();
        ImGui::PushID( idx++ );
        if( ImGui::Selectable( TimeToString( v->timeAlloc - m_worker.GetTimeBegin() ) ) )
        {
            CenterAtTime( v->timeAlloc );
        }
        ImGui::PopID();
        ImGui::NextColumn();
        if( v->timeFree < 0 )
        {
            ImGui::TextColored( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "%s", TimeToString( m_worker.GetLastTime() - v->timeAlloc ) );
            ImGui::NextColumn();
            ImGui::Text( "%s", m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ) );
        }
        else
        {
            ImGui::PushID( idx++ );
            if( ImGui::Selectable( TimeToString( v->timeFree - v->timeAlloc ) ) )
            {
                CenterAtTime( v->timeFree );
            }
            ImGui::PopID();
            ImGui::NextColumn();
            if( v->threadAlloc == v->threadFree )
            {
                ImGui::Text( "%s", m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ) );
            }
            else
            {
                ImGui::Text( "%s / %s", m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ), m_worker.GetThreadString( m_worker.DecompressThread( v->threadFree ) ) );
            }
        }
        ImGui::NextColumn();
        auto zone = FindZoneAtTime( m_worker.DecompressThread( v->threadAlloc ), v->timeAlloc );
        if( !zone )
        {
            ImGui::Text( "-" );
        }
        else
        {
            const auto& srcloc = m_worker.GetSourceLocation( zone->srcloc );
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
                if( ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( *zone );
                }
                ZoneTooltip( *zone );
            }
        }
        ImGui::NextColumn();
        if( v->timeFree < 0 )
        {
            ImGui::TextColored( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "active" );
        }
        else
        {
            auto zoneFree = FindZoneAtTime( m_worker.DecompressThread( v->threadFree ), v->timeFree );
            if( !zoneFree )
            {
                ImGui::Text( "-" );
            }
            else
            {
                const auto& srcloc = m_worker.GetSourceLocation( zoneFree->srcloc );
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
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToZone( *zoneFree );
                    }
                    ZoneTooltip( *zoneFree );
                }
            }
        }
        ImGui::NextColumn();
        if( v->csAlloc == 0 )
        {
            ImGui::TextDisabled( "[alloc]" );
        }
        else
        {
            SmallCallstackButton( "alloc", v->csAlloc, idx );
        }
        ImGui::SameLine();
        ImGui::Spacing();
        ImGui::SameLine();
        if( v->csFree == 0 )
        {
            ImGui::TextDisabled( "[free]" );
        }
        else
        {
            SmallCallstackButton( "free", v->csFree, idx );
        }
        ImGui::NextColumn();
        ptr++;
    }
    ImGui::EndColumns();
    ImGui::EndChild();
}

static tracy_force_inline CallstackFrameTree* GetFrameTreeItem( std::vector<CallstackFrameTree>& tree, uint64_t idx )
{
    auto it = std::find_if( tree.begin(), tree.end(), [idx] ( const auto& v ) { return v.frame == idx; } );
    if( it == tree.end() )
    {
        tree.emplace_back( CallstackFrameTree { idx } );
        return &tree.back();
    }
    else
    {
        return &*it;
    }
}

std::vector<CallstackFrameTree> View::GetCallstackFrameTree( const MemData& mem ) const
{
    struct PathData
    {
        uint32_t cnt;
        uint64_t mem;
    };

    std::vector<CallstackFrameTree> root;
    flat_hash_map<uint32_t, PathData, nohash<uint32_t>> pathSum;
    pathSum.reserve( m_worker.GetCallstackPayloadCount() );

    const auto zvMid = m_zvStart + ( m_zvEnd - m_zvStart ) / 2;

    for( auto& ev : mem.data )
    {
        if( ev.csAlloc == 0 ) continue;
        if( m_memInfo.restrictTime && ev.timeAlloc >= zvMid ) continue;

        auto it = pathSum.find( ev.csAlloc );
        if( it == pathSum.end() )
        {
            pathSum.emplace( ev.csAlloc, PathData { 1, ev.size } );
        }
        else
        {
            it->second.cnt++;
            it->second.mem += ev.size;
        }
    }

    for( auto& path : pathSum )
    {
        auto& cs = m_worker.GetCallstack( path.first );

        auto base = cs.back();
        auto treePtr = GetFrameTreeItem( root, base );
        treePtr->countInclusive += path.second.cnt;
        treePtr->allocInclusive += path.second.mem;

        for( int i = int( cs.size() ) - 2; i >= 0; i-- )
        {
            treePtr = GetFrameTreeItem( treePtr->children, cs[i] );
            treePtr->countInclusive += path.second.cnt;
            treePtr->allocInclusive += path.second.mem;
        }

        treePtr->countExclusive += path.second.cnt;
        treePtr->allocExclusive += path.second.mem;
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

void View::DrawMemory()
{
    auto& mem = m_worker.GetMemData();

    ImGui::Begin( "Memory", &m_memInfo.show );

    if( mem.data.empty() )
    {
        ImGui::TextWrapped( "No memory data collected." );
        ImGui::End();
        return;
    }

    ImGui::Text( "Total allocations: %-15s Active allocations: %-15s Memory usage: %-15s Memory span: %s",
        RealToString( mem.data.size(), true ),
        RealToString( mem.active.size(), true ),
        MemSizeToString( mem.usage ),
        MemSizeToString( mem.high - mem.low ) );

#ifdef TRACY_EXTENDED_FONT
    ImGui::Checkbox( ICON_FA_HISTORY " Restrict time", &m_memInfo.restrictTime );
#else
    ImGui::Checkbox( "Restrict time", &m_memInfo.restrictTime );
#endif
    ImGui::SameLine();
    ImGui::TextDisabled( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Don't show allocations beyond the middle of timeline" );
        ImGui::Text( "display (it is indicated by purple line)." );
        ImGui::EndTooltip();
    }

    const auto zvMid = m_zvStart + ( m_zvEnd - m_zvStart ) / 2;

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::TreeNode( ICON_FA_AT " Allocations" ) )
#else
    if( ImGui::TreeNode( "Allocations" ) )
#endif
    {
        ImGui::InputText( "###address", m_memInfo.pattern, 1024 );
        ImGui::SameLine();

#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_SEARCH " Find" ) )
#else
        if( ImGui::Button( "Find" ) )
#endif
        {
            m_memInfo.ptrFind = strtoull( m_memInfo.pattern, nullptr, 0 );
        }
        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_BAN " Clear" ) )
#else
        if( ImGui::Button( "Clear" ) )
#endif
        {
            m_memInfo.ptrFind = 0;
            m_memInfo.pattern[0] = '\0';
        }

        if( m_memInfo.ptrFind != 0 )
        {
            std::vector<const MemEvent*> match;
            match.reserve( mem.active.size() );     // heuristic
            if( m_memInfo.restrictTime )
            {
                for( auto& v : mem.data )
                {
                    if( v.ptr <= m_memInfo.ptrFind && v.ptr + v.size > m_memInfo.ptrFind && v.timeAlloc < zvMid )
                    {
                        match.emplace_back( &v );
                    }
                }
            }
            else
            {
                for( auto& v : mem.data )
                {
                    if( v.ptr <= m_memInfo.ptrFind && v.ptr + v.size > m_memInfo.ptrFind )
                    {
                        match.emplace_back( &v );
                    }
                }
            }

            if( match.empty() )
            {
                ImGui::Text( "Found no allocations at given address" );
            }
            else
            {
                ListMemData<decltype( match.begin() )>( match.begin(), match.end(), [this]( auto& it ) {
                    auto& v = *it;
                    if( v->ptr == m_memInfo.ptrFind )
                    {
                        ImGui::Text( "0x%" PRIx64, m_memInfo.ptrFind );
                    }
                    else
                    {
                        ImGui::Text( "0x%" PRIx64 "+%" PRIu64, v->ptr, m_memInfo.ptrFind - v->ptr );
                    }
                }, "##allocations" );
            }
        }
        ImGui::TreePop();
    }

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::TreeNode( ICON_FA_HEARTBEAT " Active allocations" ) )
#else
    if( ImGui::TreeNode( "Active allocations" ) )
#endif
    {
        uint64_t total = 0;
        std::vector<const MemEvent*> items;
        items.reserve( mem.active.size() );
        if( m_memInfo.restrictTime )
        {
            for( auto& v : mem.data )
            {
                if( v.timeAlloc < zvMid && ( v.timeFree > zvMid || v.timeFree < 0 ) )
                {
                    items.emplace_back( &v );
                    total += v.size;
                }
            }
        }
        else
        {
            auto ptr = mem.data.data();
            for( auto& v : mem.active )
            {
                items.emplace_back( ptr + v.second );
            }
            pdqsort_branchless( items.begin(), items.end(), []( const auto& lhs, const auto& rhs ) { return lhs->timeAlloc < rhs->timeAlloc; } );
            total = mem.usage;
        }

        ImGui::SameLine();
        ImGui::TextDisabled( "(%s)", RealToString( items.size(), true ) );
        ImGui::Text( "Memory usage: %s", MemSizeToString( total ) );

        ListMemData<decltype( items.begin() )>( items.begin(), items.end(), []( auto& v ) {
            ImGui::Text( "0x%" PRIx64, (*v)->ptr );
        }, "##activeMem" );
        ImGui::TreePop();
    }

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::TreeNode( ICON_FA_MAP " Memory map" ) )
#else
    if( ImGui::TreeNode( "Memory map" ) )
#endif
    {
        ImGui::Text( "Single pixel: %s   Single line: %s", MemSizeToString( 1 << ChunkBits ), MemSizeToString( PageChunkSize ) );

        auto pages = GetMemoryPages();

        const int8_t empty[PageSize] = {};
        const auto sz = pages.second / PageSize;
        auto pgptr = pages.first;
        const auto end = pgptr + sz * PageSize;
        size_t lines = sz;
        while( pgptr != end )
        {
            if( memcmp( empty, pgptr, PageSize ) == 0 )
            {
                pgptr += PageSize;
                while( pgptr != end && memcmp( empty, pgptr, PageSize ) == 0 )
                {
                    lines--;
                    pgptr += PageSize;
                }
            }
            else
            {
                pgptr += PageSize;
            }
        }

        ImGui::BeginChild( "##memMap", ImVec2( PageSize + 2, lines + 2 ), false );
        auto draw = ImGui::GetWindowDrawList();
        const auto wpos = ImGui::GetCursorScreenPos() + ImVec2( 1, 1 );
        draw->AddRect( wpos - ImVec2( 1, 1 ), wpos + ImVec2( PageSize + 1, lines + 1 ), 0xFF666666 );
        draw->AddRectFilled( wpos, wpos + ImVec2( PageSize, lines ), 0xFF444444 );

        size_t line = 0;
        pgptr = pages.first;
        while( pgptr != end )
        {
            if( memcmp( empty, pgptr, PageSize ) == 0 )
            {
                pgptr += PageSize;
                draw->AddLine( wpos + ImVec2( 0, line ), wpos + ImVec2( PageSize, line ), 0x11000000 );
                line++;
                while( pgptr != end && memcmp( empty, pgptr, PageSize ) == 0 ) pgptr += PageSize;
            }
            else
            {
                size_t idx = 0;
                while( idx < PageSize )
                {
                    if( pgptr[idx] == 0 )
                    {
                        do
                        {
                            idx++;
                        }
                        while( idx < PageSize && pgptr[idx] == 0 );
                    }
                    else
                    {
                        auto val = pgptr[idx];
                        const auto i0 = idx;
                        do
                        {
                            idx++;
                        }
                        while( idx < PageSize && pgptr[idx] == val );
                        draw->AddLine( wpos + ImVec2( i0, line ), wpos + ImVec2( idx, line ), MemDecayColor[(uint8_t)val] );
                    }
                }
                line++;
                pgptr += PageSize;
            }
        }

        delete[] pages.first;

        ImGui::EndChild();
        ImGui::TreePop();
    }

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::TreeNode( ICON_FA_ALIGN_JUSTIFY " Call stack tree" ) )
#else
    if( ImGui::TreeNode( "Call stack tree" ) )
#endif
    {
        ImGui::TextDisabled( "Press ctrl key to display allocation info tooltip." );
        ImGui::TextDisabled( "Right click on file name to open source file." );

        auto& mem = m_worker.GetMemData();
        auto tree = GetCallstackFrameTree( mem );

        int idx = 0;
        DrawFrameTreeLevel( tree, idx );

        ImGui::TreePop();
    }

    ImGui::End();
}

void View::DrawFrameTreeLevel( std::vector<CallstackFrameTree>& tree, int& idx )
{
    auto& io = ImGui::GetIO();

    int lidx = 0;
    pdqsort_branchless( tree.begin(), tree.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs.allocInclusive > rhs.allocInclusive; } );
    for( auto& v : tree )
    {
        idx++;
        auto frame = m_worker.GetCallstackFrame( v.frame );
        bool expand = false;
        if( v.children.empty() )
        {
            ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
            ImGui::Text( "%s", m_worker.GetString( frame->name ) );
            ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
        }
        else
        {
            ImGui::PushID( lidx++ );
            if( tree.size() == 1 )
            {
                expand = ImGui::TreeNodeEx( m_worker.GetString( frame->name ), ImGuiTreeNodeFlags_DefaultOpen );
            }
            else
            {
                expand = ImGui::TreeNode( m_worker.GetString( frame->name ) );
            }
            ImGui::PopID();
        }

        if( io.KeyCtrl && ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();

            ImGui::TextColored( ImVec4( 0.4, 0.4, 0.1, 1.0 ), "Inclusive alloc size:" );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s", MemSizeToString( v.allocInclusive ) );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.4, 0.4, 0.1, 1.0 ), "count:" );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s", RealToString( v.countInclusive, true ) );
            ImGui::TextColored( ImVec4( 0.4, 0.4, 0.1, 1.0 ), "Average inclusive alloc size:" );
            ImGui::SameLine();
            if( v.countInclusive != 0 )
            {
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s", MemSizeToString( v.allocInclusive / v.countInclusive ) );
            }
            else
            {
                ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "-" );
            }

            ImGui::TextColored( ImVec4( 0.1, 0.4, 0.4, 1.0 ), "Exclusive alloc size:" );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s", MemSizeToString( v.allocExclusive ) );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.1, 0.4, 0.4, 1.0 ), "count:" );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s", RealToString( v.countExclusive, true ) );
            ImGui::TextColored( ImVec4( 0.1, 0.4, 0.4, 1.0 ), "Average exclusive alloc size:" );
            ImGui::SameLine();
            if( v.countExclusive != 0 )
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s", MemSizeToString( v.allocExclusive / v.countExclusive ) );
            }
            else
            {
                ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "-" );
            }

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
        const auto fileName = m_worker.GetString( frame->file );
        ImGui::TextDisabled( "%s:%i", fileName, frame->line );
        if( ImGui::IsItemClicked( 1 ) )
        {
            if( FileExists( fileName ) )
            {
                SetTextEditorFile( fileName, frame->line );
            }
            else
            {
                m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
            }
        }

        if( v.allocExclusive != v.allocInclusive )
        {
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.4, 0.4, 0.1, 1.0 ), "I:" );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s (%s)", MemSizeToString( v.allocInclusive ), RealToString( v.countInclusive, true ) );
        }
        if( v.allocExclusive != 0 )
        {
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.1, 0.4, 0.4, 1.0 ), "E:" );
            ImGui::SameLine();
            ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s (%s)", MemSizeToString( v.allocExclusive ), RealToString( v.countExclusive, true ) );
        }

        if( expand )
        {
            DrawFrameTreeLevel( v.children, idx );
            ImGui::TreePop();
        }
    }
}

std::pair<int8_t*, size_t> View::GetMemoryPages() const
{
    const auto& mem = m_worker.GetMemData();
    const auto span = mem.high - mem.low;
    const auto pages = ( span / PageChunkSize ) + 1;

    const auto datasz = pages * PageSize;
    int8_t* data = new int8_t[datasz];
    auto pgptr = data;
    memset( pgptr, 0, pages * PageSize );

    const auto memlow = mem.low;

    if( m_memInfo.restrictTime )
    {
        const auto zvMid = m_zvStart + ( m_zvEnd - m_zvStart ) / 2;
        for( auto& alloc : mem.data )
        {
            if( m_memInfo.restrictTime && alloc.timeAlloc > zvMid ) break;

            const auto a0 = alloc.ptr - memlow;
            const auto a1 = a0 + alloc.size;
            int8_t val = alloc.timeFree < 0 ?
                int8_t( std::max( int64_t( 1 ), 127 - ( ( zvMid - alloc.timeAlloc ) >> 24 ) ) ) :
                ( alloc.timeFree > zvMid ?
                    int8_t( std::max( int64_t( 1 ), 127 - ( ( zvMid - alloc.timeAlloc ) >> 24 ) ) ) :
                    int8_t( -std::max( int64_t( 1 ), 127 - ( ( zvMid - alloc.timeFree ) >> 24 ) ) ) );

            const auto c0 = a0 >> ChunkBits;
            const auto c1 = a1 >> ChunkBits;

            if( c0 == c1 )
            {
                pgptr[c0] = val;
            }
            else
            {
                memset( pgptr + c0, val, c1 - c0 + 1 );
            }
        }
    }
    else
    {
        const auto lastTime = m_worker.GetLastTime();
        for( auto& alloc : mem.data )
        {
            const auto a0 = alloc.ptr - memlow;
            const auto a1 = a0 + alloc.size;
            const int8_t val = alloc.timeFree < 0 ?
                int8_t( std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.timeAlloc ) ) >> 24 ) ) ) :
                int8_t( -std::max( int64_t( 1 ), 127 - ( ( lastTime - std::min( lastTime, alloc.timeFree ) ) >> 24 ) ) );

            const auto c0 = a0 >> ChunkBits;
            const auto c1 = a1 >> ChunkBits;

            if( c0 == c1 )
            {
                pgptr[c0] = val;
            }
            else
            {
                memset( pgptr + c0, val, c1 - c0 + 1 );
            }
        }
    }

    return std::make_pair( data, datasz );
}

const char* View::GetPlotName( const PlotData* plot ) const
{
    switch( plot->type )
    {
    case PlotType::User:
        return m_worker.GetString( plot->name );
    case PlotType::Memory:
#ifdef TRACY_EXTENDED_FONT
        return ICON_FA_MEMORY " Memory usage";
#else
        return "Memory usage";
#endif
    default:
        assert( false );
        return nullptr;
    }
}

uint32_t View::GetZoneColor( const ZoneEvent& ev )
{
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto color = srcloc.color;
    return color != 0 ? ( color | 0xFF000000 ) : 0xFFCC5555;
}

uint32_t View::GetZoneColor( const GpuEvent& ev )
{
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto color = srcloc.color;
    return color != 0 ? ( color | 0xFF000000 ) : 0xFF222288;
}

uint32_t View::GetZoneHighlight( const ZoneEvent& ev, bool migration )
{
    if( m_zoneInfoWindow == &ev )
    {
        return 0xFF44DD44;
    }
    else if( m_zoneHighlight == &ev )
    {
        return 0xFF4444FF;
    }
    else if( m_zoneSrcLocHighlight == ev.srcloc )
    {
        return 0xFFEEEEEE;
    }
    else if( migration )
    {
        return 0xFFDD22DD;
    }
    else
    {
        const auto color = GetZoneColor( ev );
        return 0xFF000000 |
            ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + 25 ) ) << 16 ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + 25 ) ) << 8  ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + 25 ) )       );
    }
}

uint32_t View::GetZoneHighlight( const GpuEvent& ev )
{
    if( m_gpuInfoWindow == &ev )
    {
        return 0xFF44DD44;
    }
    else if( m_gpuHighlight == &ev )
    {
        return 0xFF4444FF;
    }
    else
    {
        const auto color = GetZoneColor( ev );
        return 0xFF000000 |
            ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + 25 ) ) << 16 ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + 25 ) ) << 8  ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + 25 ) )       );
    }
}

float View::GetZoneThickness( const ZoneEvent& ev )
{
    if( m_zoneInfoWindow == &ev || m_zoneHighlight == &ev )
    {
        return 3.f;
    }
    else
    {
        return 1.f;
    }
}

float View::GetZoneThickness( const GpuEvent& ev )
{
    if( m_gpuInfoWindow == &ev || m_gpuHighlight == &ev )
    {
        return 3.f;
    }
    else
    {
        return 1.f;
    }
}

void View::ZoomToZone( const ZoneEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.start <= 0 ) return;
    ZoomToRange( ev.start, end );
}

void View::ZoomToZone( const GpuEvent& ev )
{
    const auto end = m_worker.GetZoneEnd( ev );
    if( end - ev.gpuStart <= 0 ) return;
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        ZoomToRange( ev.gpuStart, end );
    }
    else
    {
        const auto begin = ctx->timeline.front()->gpuStart;
        const auto drift = GpuDrift( ctx );
        ZoomToRange( AdjustGpuTime( ev.gpuStart, begin, drift ), AdjustGpuTime( end, begin, drift ) );
    }
}

void View::ZoomToRange( int64_t start, int64_t end )
{
    if( start == end )
    {
        end = start + 1;
    }

    m_pause = true;
    m_highlightZoom.active = false;
    m_zoomAnim.active = true;
    m_zoomAnim.start0 = m_zvStart;
    m_zoomAnim.start1 = start;
    m_zoomAnim.end0 = m_zvEnd;
    m_zoomAnim.end1 = end;
    m_zoomAnim.progress = 0;

    const auto d0 = double( m_zoomAnim.end0 - m_zoomAnim.start0 );
    const auto d1 = double( m_zoomAnim.end1 - m_zoomAnim.start1 );
    const auto diff = d0>d1 ? d0/d1 : d1/d0;
    m_zoomAnim.lenMod = 10.0 / log10( diff );
}

void View::ZoomToPrevFrame()
{
    if( m_zvStart >= m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        int frame;
        if( m_frames->continuous )
        {
            frame = m_worker.GetFrameRange( *m_frames, m_zvStart, m_zvStart ).first;
        }
        else
        {
            frame = m_worker.GetFrameRange( *m_frames, m_zvStart, m_zvStart ).second;
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
    int frame;
    if( m_zvStart < m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        frame = -1;
    }
    else
    {
        frame = m_worker.GetFrameRange( *m_frames, m_zvStart, m_zvStart ).first;
    }
    frame++;
    if( frame >= m_worker.GetFrameCount( *m_frames ) ) return;

    const auto fbegin = m_worker.GetFrameBegin( *m_frames, frame );
    const auto fend = m_worker.GetFrameEnd( *m_frames, frame );
    ZoomToRange( fbegin, fend );
}

void View::CenterAtTime( int64_t t )
{
    const auto hr = std::max<uint64_t>( 1, ( m_zvEnd - m_zvStart ) / 2 );
    ZoomToRange( t - hr, t + hr );
}

void View::ShowZoneInfo( const ZoneEvent& ev )
{
    if( m_zoneInfoWindow )
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
    if( m_gpuInfoWindow )
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
    auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto end = m_worker.GetZoneEnd( ev );

    ImGui::BeginTooltip();
    if( ev.name.active )
    {
        ImGui::Text( "%s", m_worker.GetString( ev.name ) );
    }
    if( srcloc.name.active )
    {
        ImGui::Text( "%s", m_worker.GetString( srcloc.name ) );
    }
    ImGui::Text( "%s", m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    ImGui::Separator();
    TextFocused( "Execution time:", TimeToString( end - ev.start ) );
    if( ev.cpu_start >= 0 )
    {
        ImGui::TextDisabled( "CPU:" );
        ImGui::SameLine();
        if( ev.end < 0 || ev.cpu_start == ev.cpu_end )
        {
            ImGui::Text( "%i", ev.cpu_start );
        }
        else
        {
            ImGui::Text( "%i -> %i", ev.cpu_start, ev.cpu_end );
        }
    }
    if( ev.text.active )
    {
        ImGui::NewLine();
        ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", m_worker.GetString( ev.text ) );
    }
    ImGui::EndTooltip();
}

void View::ZoneTooltip( const GpuEvent& ev )
{
    const auto tid = GetZoneThread( ev );
    const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto end = m_worker.GetZoneEnd( ev );

    ImGui::BeginTooltip();
    ImGui::Text( "%s", m_worker.GetString( srcloc.name ) );
    ImGui::Text( "%s", m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    ImGui::Separator();
    TextFocused( "GPU execution time:", TimeToString( end - ev.gpuStart ) );
    TextFocused( "CPU command setup time:", TimeToString( ev.cpuEnd - ev.cpuStart ) );
    auto ctx = GetZoneCtx( ev );
    if( !ctx )
    {
        TextFocused( "Delay to execution:", TimeToString( ev.gpuStart - ev.cpuStart ) );
    }
    else
    {
        const auto begin = ctx->timeline.front()->gpuStart;
        const auto drift = GpuDrift( ctx );
        TextFocused( "Delay to execution:", TimeToString( AdjustGpuTime( ev.gpuStart, begin, drift ) - ev.cpuStart ) );
    }

    ImGui::EndTooltip();
}

void View::CallstackTooltip( uint32_t idx )
{
    auto& cs = m_worker.GetCallstack( idx );

    ImGui::BeginTooltip();
    int fidx = 0;
    for( auto& entry : cs )
    {
        ImGui::TextDisabled( "%i.", fidx++ );
        ImGui::SameLine();
        auto frame = m_worker.GetCallstackFrame( entry );
        if( !frame )
        {
            ImGui::Text( "0x%" PRIX64, entry );
        }
        else
        {
            ImGui::Text( "%s", m_worker.GetString( frame->name ) );
        }
    }
    ImGui::EndTooltip();
}

const ZoneEvent* View::GetZoneParent( const ZoneEvent& zone ) const
{
    for( const auto& thread : m_worker.GetThreadData() )
    {
        const ZoneEvent* parent = nullptr;
        const Vector<ZoneEvent*>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.start, [] ( const auto& l, const auto& r ) { return l < r->start; } );
            if( it != timeline->begin() ) --it;
            if( zone.end >= 0 && (*it)->start > zone.end ) break;
            if( *it == &zone ) return parent;
            if( (*it)->child < 0 ) break;
            parent = *it;
            timeline = &m_worker.GetZoneChildren( parent->child );
        }
    }
    return nullptr;
}

const GpuEvent* View::GetZoneParent( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        const GpuEvent* parent = nullptr;
        const Vector<GpuEvent*>* timeline = &ctx->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.gpuStart, [] ( const auto& l, const auto& r ) { return l < r->gpuStart; } );
            if( it != timeline->begin() ) --it;
            if( zone.gpuEnd >= 0 && (*it)->gpuStart > zone.gpuEnd ) break;
            if( *it == &zone ) return parent;
            if( (*it)->child < 0 ) break;
            parent = *it;
            timeline = &m_worker.GetGpuChildren( parent->child );
        }
    }
    return nullptr;
}

uint64_t View::GetZoneThread( const ZoneEvent& zone ) const
{
    for( const auto& thread : m_worker.GetThreadData() )
    {
        const Vector<ZoneEvent*>* timeline = &thread->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.start, [] ( const auto& l, const auto& r ) { return l < r->start; } );
            if( it != timeline->begin() ) --it;
            if( zone.end >= 0 && (*it)->start > zone.end ) break;
            if( *it == &zone ) return thread->id;
            if( (*it)->child < 0 ) break;
            timeline = &m_worker.GetZoneChildren( (*it)->child );
        }
    }
    return 0;
}

uint64_t View::GetZoneThread( const GpuEvent& zone ) const
{
    if( zone.thread == 0 )
    {
        for( const auto& ctx : m_worker.GetGpuData() )
        {
            const Vector<GpuEvent*>* timeline = &ctx->timeline;
            if( timeline->empty() ) continue;
            for(;;)
            {
                auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.gpuStart, [] ( const auto& l, const auto& r ) { return l < r->gpuStart; } );
                if( it != timeline->begin() ) --it;
                if( zone.gpuEnd >= 0 && (*it)->gpuStart > zone.gpuEnd ) break;
                if( *it == &zone ) return ctx->thread;
                if( (*it)->child < 0 ) break;
                timeline = &m_worker.GetGpuChildren( (*it)->child );
            }
        }
        return 0;
    }
    else
    {
        return m_worker.DecompressThread( zone.thread );
    }
}

const GpuCtxData* View::GetZoneCtx( const GpuEvent& zone ) const
{
    for( const auto& ctx : m_worker.GetGpuData() )
    {
        const Vector<GpuEvent*>* timeline = &ctx->timeline;
        if( timeline->empty() ) continue;
        for(;;)
        {
            auto it = std::upper_bound( timeline->begin(), timeline->end(), zone.gpuStart, [] ( const auto& l, const auto& r ) { return l < r->gpuStart; } );
            if( it != timeline->begin() ) --it;
            if( zone.gpuEnd >= 0 && (*it)->gpuStart > zone.gpuEnd ) break;
            if( *it == &zone ) return ctx;
            if( (*it)->child < 0 ) break;
            timeline = &m_worker.GetGpuChildren( (*it)->child );
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

    const Vector<ZoneEvent*>* timeline = &td->timeline;
    if( timeline->empty() ) return nullptr;
    ZoneEvent* ret = nullptr;
    for(;;)
    {
        auto it = std::upper_bound( timeline->begin(), timeline->end(), time, [] ( const auto& l, const auto& r ) { return l < r->start; } );
        if( it != timeline->begin() ) --it;
        if( (*it)->start > time || ( (*it)->end >= 0 && (*it)->end < time ) ) return ret;
        ret = *it;
        if( (*it)->child < 0 ) return ret;
        timeline = &m_worker.GetZoneChildren( (*it)->child );
    }
}

#ifndef TRACY_NO_STATISTICS
void View::FindZones()
{
    m_findZone.match = m_worker.GetMatchingSourceLocation( m_findZone.pattern );
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
    m_compare.match[0] = m_worker.GetMatchingSourceLocation( m_compare.pattern );
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

    m_compare.match[1] = m_compare.second->GetMatchingSourceLocation( m_compare.pattern );
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

void View::SmallCallstackButton( const char* name, uint32_t callstack, int& idx )
{
    bool hilite = m_callstackInfoWindow == callstack;
    if( hilite )
    {
        ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.f, 0.6f, 0.6f ) );
        ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.f, 0.7f, 0.7f ) );
        ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.f, 0.8f, 0.8f ) );
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
    if( ImGui::IsItemHovered() )
    {
        CallstackTooltip( callstack );
    }
}

}
