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

static double s_time = 0;

static const char* s_tracyStackFrames[] = {
    "tracy::Callstack",
    "tracy::GpuCtxScope::{ctor}",
    "tracy::Profiler::SendCallstack",
    "tracy::Profiler::SendCallstack(int, unsigned long)",
    "tracy::Profiler::MemAllocCallstack",
    "tracy::Profiler::MemAllocCallstack(void const*, unsigned long, int)",
    "tracy::Profiler::MemFreeCallstack",
    "tracy::Profiler::MemFreeCallstack(void const*, int)",
    "tracy::ScopedZone::{ctor}",
    "tracy::ScopedZone::ScopedZone(tracy::SourceLocationData const*, int, bool)",
    nullptr
};

static const char* IntTable100 =
"00010203040506070809"
"10111213141516171819"
"20212223242526272829"
"30313233343536373839"
"40414243444546474849"
"50515253545556575859"
"60616263646566676869"
"70717273747576777879"
"80818283848586878889"
"90919293949596979899";

static inline void PrintTinyInt( char*& buf, uint64_t v )
{
    if( v >= 10 )
    {
        *buf++ = '0' + v/10;
    }
    *buf++ = '0' + v%10;
}

static inline void PrintTinyInt0( char*& buf, uint64_t v )
{
    if( v >= 10 )
    {
        *buf++ = '0' + v/10;
    }
    else
    {
        *buf++ = '0';
    }
    *buf++ = '0' + v%10;
}

static inline void PrintSmallInt( char*& buf, uint64_t v )
{
    if( v >= 100 )
    {
        memcpy( buf, IntTable100 + v/10*2, 2 );
        buf += 2;
    }
    else if( v >= 10 )
    {
        *buf++ = '0' + v/10;
    }
    *buf++ = '0' + v%10;
}

static inline void PrintFrac00( char*& buf, uint64_t v )
{
    *buf++ = '.';
    v += 5;
    if( v/10%10 == 0 )
    {
        *buf++ = '0' + v/100;
    }
    else
    {
        memcpy( buf, IntTable100 + v/10*2, 2 );
        buf += 2;
    }
}

static inline void PrintFrac0( char*& buf, uint64_t v )
{
    *buf++ = '.';
    *buf++ = '0' + (v+50)/100;
}

static inline void PrintSmallIntFrac( char*& buf, uint64_t v )
{
    uint64_t in = v / 1000;
    uint64_t fr = v % 1000;
    if( fr >= 995 )
    {
        PrintSmallInt( buf, in+1 );
    }
    else
    {
        PrintSmallInt( buf, in );
        if( fr > 5 )
        {
            PrintFrac00( buf, fr );
        }
    }
}

static inline void PrintSecondsFrac( char*& buf, uint64_t v )
{
    uint64_t in = v / 1000;
    uint64_t fr = v % 1000;
    if( fr >= 950 )
    {
        PrintTinyInt0( buf, in+1 );
    }
    else
    {
        PrintTinyInt0( buf, in );
        if( fr > 50 )
        {
            PrintFrac0( buf, fr );
        }
    }
}

static const char* TimeToString( int64_t _ns )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    char* bufstart = buf;
    bufsel = ( bufsel + 1 ) % Pool;

    uint64_t ns;
    if( _ns < 0 )
    {
        *buf = '-';
        buf++;
        ns = -_ns;
    }
    else
    {
        ns = _ns;
    }

    if( ns < 1000 )
    {
        PrintSmallInt( buf, ns );
        memcpy( buf, " ns", 4 );
    }
    else if( ns < 1000ll * 1000 )
    {
        PrintSmallIntFrac( buf, ns );
#ifdef TRACY_EXTENDED_FONT
        memcpy( buf, " \xce\xbcs", 5 );
#else
        memcpy( buf, " us", 4 );
#endif
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        PrintSmallIntFrac( buf, ns / 1000 );
        memcpy( buf, " ms", 4 );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        PrintSmallIntFrac( buf, ns / ( 1000ll * 1000 ) );
        memcpy( buf, " s", 3 );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 )
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) ) / ( 1000ll * 1000 );
        PrintTinyInt( buf, m );
        *buf++ = ':';
        PrintSecondsFrac( buf, s );
        *buf++ = '\0';
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 * 24 )
    {
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - h * ( 60 * 60 ) - m * 60 );
        PrintTinyInt( buf, h );
        *buf++ = ':';
        PrintTinyInt0( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        *buf++ = '\0';
    }
    else
    {
        const auto d = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 * 24 ) );
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) - d * 24 );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - d * ( 60 * 24 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - d * ( 60 * 60 * 24 ) - h * ( 60 * 60 ) - m * 60 );
        if( d < 1000 )
        {
            PrintSmallInt( buf, d );
            *buf++ = 'd';
        }
        else
        {
            buf += sprintf( buf, "%" PRIi64 "d", d );
        }
        PrintTinyInt0( buf, h );
        *buf++ = ':';
        PrintTinyInt0( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        *buf++ = '\0';
    }
    return bufstart;
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
    while( *ptr == '0' ) ptr--;
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

static void TextDisabledUnformatted( const char* begin, const char* end = nullptr )
{
    ImGui::PushStyleColor(ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled]);
    ImGui::TextUnformatted( begin, end );
    ImGui::PopStyleColor();
}

static void TextFocused( const char* label, const char* value )
{
    TextDisabledUnformatted( label );
    ImGui::SameLine();
    ImGui::TextUnformatted( value );
}

static void SetButtonHighlightColor()
{
    ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.35f, 0.6f, 0.6f ) );
    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.35f, 0.8f, 0.8f ) );
    ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.35f, 0.7f, 0.7f ) );
}

static void ToggleButton( const char* label, bool& toggle )
{
    const auto active = toggle;
    if( active ) SetButtonHighlightColor();
    if( ImGui::Button( label ) ) toggle = !toggle;
    if( active ) ImGui::PopStyleColor( 3 );
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


enum { MinVisSize = 3 };
enum { MinFrameSize = 5 };

static View* s_instance = nullptr;

View::View( const char* addr, ImFont* fixedWidth, SetTitleCallback stcb )
    : m_worker( addr )
    , m_staticView( false )
    , m_pause( false )
    , m_frames( nullptr )
    , m_textEditorFont( fixedWidth )
    , m_stcb( stcb )
{
    assert( s_instance == nullptr );
    s_instance = this;

    InitTextEditor();
}

View::View( FileRead& f, ImFont* fixedWidth, SetTitleCallback stcb )
    : m_worker( f )
    , m_staticView( true )
    , m_pause( true )
    , m_frames( m_worker.GetFramesBase() )
    , m_textEditorFont( fixedWidth )
    , m_stcb( stcb )
{
    assert( s_instance == nullptr );
    s_instance = this;

    m_notificationTime = 4;
    m_notificationText = std::string( "Trace loaded in " ) + TimeToString( m_worker.GetLoadTime() );

    InitTextEditor();
    SetViewToLastFrames();
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
        auto data = new char[sz+1];
        fread( data, 1, sz, f );
        fclose( f );
        data[sz] = '\0';
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
    TextDisabledUnformatted( "(?)" );
    if( ImGui::IsItemHovered() )
    {
        const auto ty = ImGui::GetFontSize();
        ImGui::BeginTooltip();
        ImGui::PushTextWrapPos( 450.0f * ty / 15.f );
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
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
#endif
        ImGui::TextUnformatted( "The client you are trying to connect to uses incompatible protocol version.\nMake sure you are using the same Tracy version on both client and server." );
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
        ImGui::TextUnformatted( "The client you are trying to connect to is no longer able to sent profiling data,\nbecause another server was already connected to it.\nYou can do the following:\n\n  1. Restart the client application.\n  2. Rebuild the client application with on-demand mode enabled." );
        ImGui::Separator();
        if( ImGui::Button( "I understand" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::EndPopup();
    }

    if( ImGui::BeginPopupModal( "Client disconnected", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_HANDSHAKE );
#endif
        ImGui::TextUnformatted( "The client you are trying to connect to has disconnected during the initial\nconnection handshake. Please check your network configuration." );
        ImGui::Separator();
        if( ImGui::Button( "Will do" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            return false;
        }
        ImGui::EndPopup();
    }

    if( ImGui::BeginPopupModal( "Instrumentation failure", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
        const auto& data = s_instance->m_worker.GetFailureData();

#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_SKULL );
#endif
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
            ImGui::Text( "%s:%i", s_instance->m_worker.GetString( srcloc.file ), srcloc.line );
        }
        if( data.thread != 0 )
        {
            TextFocused( "Thread:", s_instance->m_worker.GetThreadString( data.thread ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(0x%" PRIX64 ")", data.thread );
        }
        ImGui::Separator();
        if( ImGui::Button( "I understand" ) )
        {
            ImGui::CloseCurrentPopup();
            s_instance->m_worker.ClearFailure();
        }
        ImGui::EndPopup();
    }

    s_time += ImGui::GetIO().DeltaTime;
    return s_instance->DrawImpl();
}

static const char* MainWindowButtons[] = {
#ifdef TRACY_EXTENDED_FONT
    ICON_FA_PLAY " Resume",
    ICON_FA_PAUSE " Pause",
    ICON_FA_SQUARE " Stopped"
#else
    "Resume",
    "Pause",
    "Stopped"
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
        ImGui::TextUnformatted( "Waiting for connection..." );
        DrawWaitingDots( s_time );
        ImGui::Spacing();
        ImGui::Separator();
        bool wasCancelled = ImGui::Button( "Cancel" );
        ImGui::End();
        return !wasCancelled;
    }

    const auto& io = ImGui::GetIO();

    assert( m_shortcut == ShortcutAction::None );
    if( io.KeyCtrl )
    {
        if( ImGui::IsKeyPressed( 'F' ) )
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
    if( !m_staticView )
    {
        if( !DrawConnection() ) return false;
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
    style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.129f, 0.137f, 0.11f, 1.f );

    ImGui::SetNextWindowPos( ImVec2( 0, 0 ) );
    ImGui::SetNextWindowSize( ImVec2( m_rootWidth, m_rootHeight ) );
    ImGui::Begin( "Timeline view###Profiler", nullptr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoMove );

    style.WindowRounding = wrPrev;
    style.WindowBorderSize = wbsPrev;
    style.WindowPadding = wpPrev;
    style.Colors[ImGuiCol_WindowBg] = ImVec4( 0.11f, 0.11f, 0.08f, 1.f );
#else
    char tmp[2048];
    sprintf( tmp, "%s###Profiler", m_worker.GetCaptureName().c_str() );
    ImGui::SetNextWindowSize( ImVec2( 1550, 800 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( tmp, keepOpenPtr, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoBringToFrontOnFocus );
#endif

    std::lock_guard<TracyMutex> lock( m_worker.GetDataLock() );
    if( !m_worker.IsDataStatic() )
    {
        if( m_worker.IsConnected() )
        {
            if( ImGui::Button( m_pause ? MainWindowButtons[0] : MainWindowButtons[1], ImVec2( bw, 0 ) ) ) m_pause = !m_pause;
        }
        else
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor( 0.3f, 0.3f, 0.3f, 1.0f ) );
            ImGui::ButtonEx( MainWindowButtons[2], ImVec2( bw, 0 ), ImGuiButtonFlags_Disabled );
            ImGui::PopStyleColor( 1 );
        }
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
    ToggleButton( ICON_FA_COG " Options", m_showOptions );
#else
    ToggleButton( "Options", m_showOptions );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_TAGS " Messages", m_showMessages );
#else
    ToggleButton( "Messages", m_showMessages );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_SEARCH " Find zone", m_findZone.show );
#else
    ToggleButton( "Find zone", m_findZone.show );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_SORT_AMOUNT_UP " Statistics", m_showStatistics );
#else
    ToggleButton( "Statistics", m_showStatistics );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_MEMORY " Memory", m_memInfo.show );
#else
    ToggleButton( "Memory", m_memInfo.show );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_BALANCE_SCALE " Compare", m_compare.show );
#else
    ToggleButton( "Compare", m_compare.show );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_FINGERPRINT " Info", m_showInfo );
#else
    ToggleButton( "Info", m_showInfo );
#endif
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) ) ZoomToPrevFrame();
#else
    if( ImGui::SmallButton( " < " ) ) ZoomToPrevFrame();
#endif
    ImGui::SameLine();
    {
        const auto vis = Vis( m_frames ).visible;
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
    if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) ) ZoomToNextFrame();
#else
    if( ImGui::SmallButton( " > " ) ) ZoomToNextFrame();
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
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( fd->frames.size(), true ) );
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ToggleButton( ICON_FA_CROSSHAIRS, m_goToFrame );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::TextUnformatted( "Go to frame" );
        ImGui::EndTooltip();
    }
#else
    ToggleButton( "Go to", m_goToFrame );
#endif
    ImGui::SameLine();
    ImGui::Spacing();
    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    ImGui::Text( ICON_FA_EYE " %-10s", TimeToString( m_zvEnd - m_zvStart ) );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "View span" );
        ImGui::EndTooltip();
    }
    ImGui::SameLine();
    ImGui::Text( ICON_FA_DATABASE " %-10s", TimeToString( m_worker.GetLastTime() - m_worker.GetTimeBegin() ) );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Time span" );
        ImGui::EndTooltip();
    }
#else
    ImGui::Text( "View span: %-10s Time span: %-10s ", TimeToString( m_zvEnd - m_zvStart ), TimeToString( m_worker.GetLastTime() - m_worker.GetTimeBegin() ) );
#endif
    if( m_notificationTime > 0 )
    {
        m_notificationTime -= io.DeltaTime;
        ImGui::SameLine();
        TextDisabledUnformatted( m_notificationText.c_str() );
    }
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
    if( m_memInfo.showAllocList ) DrawAllocList();
    if( m_compare.show ) DrawCompare();
    if( m_callstackInfoWindow != 0 ) DrawCallstackWindow();
    if( m_memoryAllocInfoWindow >= 0 ) DrawMemoryAllocWindow();
    if( m_showInfo ) DrawInfo();
    if( m_textEditorFile ) DrawTextEditor();
    if( m_goToFrame ) DrawGoToFrame();
    if( m_lockInfoWindow != InvalidId ) DrawLockInfoWindow();

    if( m_zoomAnim.active )
    {
        m_zoomAnim.progress += io.DeltaTime * 3.33f;
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
    m_optionsLockBuzzAnim.Update( io.DeltaTime );
    m_lockInfoAnim.Update( io.DeltaTime );
    m_statBuzzAnim.Update( io.DeltaTime );

    return keepOpen;
}

bool View::DrawConnection()
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
        ImGui::Text( "Query backlog: %s", RealToString( m_worker.GetSendQueueSize(), true ) );
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

    ImGui::SameLine( 0, 2 * ty );
#ifdef TRACY_EXTENDED_FONT
    const char* stopStr = ICON_FA_PLUG " Stop";
#else
    const char* stopStr = "Stop";
#endif
    if( m_worker.IsConnected() )
    {
        if( ImGui::Button( stopStr ) )
        {
            m_worker.Disconnect();
        }
    }
    else
    {
        ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor( 0.3f, 0.3f, 0.3f, 1.0f ) );
        ImGui::ButtonEx( stopStr, ImVec2( 0, 0 ), ImGuiButtonFlags_Disabled );
        ImGui::PopStyleColor( 1 );
    }

    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_EXCLAMATION_TRIANGLE " Discard" ) )
#else
    if( ImGui::Button( "Discard" ) )
#endif
    {
        ImGui::OpenPopup( "Confirm trace discard" );
    }

    if( ImGui::BeginPopupModal( "Confirm trace discard", nullptr, ImGuiWindowFlags_AlwaysAutoResize ) )
    {
#ifdef TRACY_EXTENDED_FONT
        TextCentered( ICON_FA_EXCLAMATION_TRIANGLE );
#endif
        ImGui::TextUnformatted( "All unsaved profiling data will be lost!" );
        ImGui::TextUnformatted( "Are you sure you want to proceed?" );
        ImGui::Separator();
        if( ImGui::Button( "Yes" ) )
        {
            ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
            ImGui::End();
            return false;
        }
        ImGui::SameLine( 0, ty * 2 );
        if( ImGui::Button( "No", ImVec2( ty * 8, 0 ) ) )
        {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    ImGui::End();
    return true;
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
        SetViewToLastFrames();
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

                    TextDisabledUnformatted( "Frames:" );
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
                            ImGui::TextUnformatted( "Tracy initialization" );
                            ImGui::Separator();
                            TextFocused( "Time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                        else if( offset == 0 )
                        {
                            TextDisabledUnformatted( "Frame:" );
                            ImGui::SameLine();
                            ImGui::TextUnformatted( RealToString( sel, true ) );
                            ImGui::Separator();
                            TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
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
                            ImGui::TextUnformatted( RealToString( sel + offset - 1, true ) );
                            ImGui::Separator();
                            TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:", m_worker.GetString( m_frames->name ) );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( RealToString( sel + 1, true ) );
                        ImGui::Separator();
                        TextFocused( "Frame time:", TimeToString( m_worker.GetFrameTime( *m_frames, sel ) ) );
                    }
                }
                TextFocused( "Time from start of program:", TimeToString( m_worker.GetFrameBegin( *m_frames, sel ) - m_worker.GetTimeBegin() ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_pause = true;
                    m_zoomAnim.active = false;
                    m_zvStart = m_worker.GetFrameBegin( *m_frames, sel );
                    m_zvEnd = m_worker.GetFrameEnd( *m_frames, sel + group - 1 );
                    if( m_zvStart == m_zvEnd ) m_zvStart--;
                }
                else if( ImGui::IsMouseDragging( 0 ) )
                {
                    const auto t0 = std::min( m_zvStart, m_worker.GetFrameBegin( *m_frames, sel ) );
                    const auto t1 = std::max( m_zvEnd, m_worker.GetFrameEnd( *m_frames, sel + group - 1 ) );
                    ZoomToRange( t0, t1 );
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
            t0 = m_zvStart;
            t1 = m_zvEnd;
        }
        const auto zoomSpan = t1 - t0;
        const auto p1 = zoomSpan * p;
        const auto p2 = zoomSpan - p1;
        if( wheel > 0 )
        {
            t0 += int64_t( p1 * 0.25 );
            t1 -= int64_t( p2 * 0.25 );
        }
        else if( zoomSpan < 1000ll * 1000 * 1000 * 60 * 60 )
        {
            t0 -= std::max( int64_t( 1 ), int64_t( p1 * 0.25 ) );
            t1 += std::max( int64_t( 1 ), int64_t( p2 * 0.25 ) );
        }
        ZoomToRange( t0, t1 );
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

            if( scale != 0 )
            {
                for( int i=1; i<5; i++ )
                {
                    draw->AddLine( wpos + ImVec2( x + i * dx / 10, 0 ), wpos + ImVec2( x + i * dx / 10, round( ty * 0.25 ) ), 0x33FFFFFF );
                }
                draw->AddLine( wpos + ImVec2( x + 5 * dx / 10, 0 ), wpos + ImVec2( x + 5 * dx / 10, round( ty * 0.375 ) ), 0x33FFFFFF );
                for( int i=6; i<10; i++ )
                {
                    draw->AddLine( wpos + ImVec2( x + i * dx / 10, 0 ), wpos + ImVec2( x + i * dx / 10, round( ty * 0.25 ) ), 0x33FFFFFF );
                }
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
    int64_t endPos = -1;
    bool tooltipDisplayed = false;
    const auto activeFrameSet = m_frames == &frames;

    const auto inactiveColor = GetColorMuted( 0x888888, activeFrameSet );
    const auto activeColor = GetColorMuted( 0xFFFFFF, activeFrameSet );
    const auto redColor = GetColorMuted( 0x4444FF, activeFrameSet );

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
            ImGui::TextUnformatted( GetFrameText( frames, i, ftime, m_worker.GetFrameOffset() ) );
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
                    DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( prevEnd - m_zvStart ) * pxns, ty / 4, inactiveColor );
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
                DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( fbegin - m_zvStart ) * pxns, ty / 4, inactiveColor );
            }
            else
            {
                DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( prevEnd - m_zvStart ) * pxns, ty / 4, inactiveColor );
            }
            prev = -1;
        }

        if( activeFrameSet )
        {
            if( fbegin >= m_zvStart && endPos != fbegin )
            {
                draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            if( fend <= m_zvEnd )
            {
                draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
            }
            endPos = fend;
        }

        auto buf = GetFrameText( frames, i, ftime, m_worker.GetFrameOffset() );
        auto tx = ImGui::CalcTextSize( buf ).x;
        uint32_t color = ( frames.name == 0 && i == 0 ) ? redColor : activeColor;

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
        if( frames.continuous )
        {
            DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), ( prev - m_zvStart ) * pxns, ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_zvStart ) * pxns, ty / 4, inactiveColor );
        }
        else
        {
            const auto begin = ( prev - m_zvStart ) * pxns;
            const auto end = ( m_worker.GetFrameBegin( frames, zrange.second-1 ) - m_zvStart ) * pxns;
            DrawZigZag( draw, wpos + ImVec2( 0, round( ty / 2 ) ), begin, std::max( begin + MinFrameSize, end ), ty / 4, inactiveColor );
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
        if( ImGui::IsMouseClicked( 0 ) )
        {
            m_frames = &frames;
        }
    }

    return hover;
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

static void AdjustThreadHeight( View::VisData& vis, int oldOffset, int& offset )
{
    const auto h = offset - oldOffset;
    if( vis.height > h )
    {
        vis.height = h;
        offset = oldOffset + vis.height;
    }
    else if( vis.height < h )
    {
        const auto diff = h - vis.height;
        const auto move = std::max( 2.0, diff * 10.0 * ImGui::GetIO().DeltaTime );
        vis.height = int( std::min<double>( vis.height + move, h ) );
        offset = oldOffset + vis.height;
    }
}

void View::DrawZones()
{
    m_msgHighlight.Decay( nullptr );
    m_zoneSrcLocHighlight.Decay( 0 );
    m_lockHoverHighlight.Decay( InvalidId );

    if( m_zvStart == m_zvEnd ) return;
    assert( m_zvStart < m_zvEnd );

    if( ImGui::GetCurrentWindow()->SkipItems ) return;

    m_gpuThread = 0;
    m_gpuStart = 0;
    m_gpuEnd = 0;

    const auto linepos = ImGui::GetCursorScreenPos();
    const auto lineh = ImGui::GetContentRegionAvail().y;

    auto draw = ImGui::GetWindowDrawList();
    const auto w = ImGui::GetWindowContentRegionWidth() - ImGui::GetStyle().ScrollbarSize;
    const auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );
    {
        const auto tbegin = m_worker.GetTimeBegin();
        const auto tend = m_worker.GetLastTime();
        if( tbegin > m_zvStart )
        {
            draw->AddRectFilled( linepos, linepos + ImVec2( ( tbegin - m_zvStart ) * pxns, lineh ), 0x44000000 );
        }
        if( tend < m_zvEnd )
        {
            draw->AddRectFilled( linepos + ImVec2( ( tend - m_zvStart ) * pxns, 0 ), linepos + ImVec2( w, lineh ), 0x44000000 );
        }
    }

    bool drawMouseLine = DrawZoneFramesHeader();
    auto& frames = m_worker.GetFrames();
    for( auto fd : frames )
    {
        if( Vis( fd ).visible )
        {
            drawMouseLine |= DrawZoneFrames( *fd );
        }
    }

    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetWindowContentRegionWidth(), ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto h = std::max<float>( m_zvHeight, ImGui::GetContentRegionAvail().y - 4 );    // magic border value

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();

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

            int depth = 0;
            offset += ostep;
            if( showFull && !v->timeline.empty() && v->timeline.front()->gpuStart != std::numeric_limits<int64_t>::max() )
            {
                const auto begin = v->timeline.front()->gpuStart;
                const auto drift = GpuDrift( v );
                depth = DispatchGpuZoneLevel( v->timeline, hover, pxns, int64_t( nspx ), wpos, offset, 0, v->thread, yMin, yMax, begin, drift );
                offset += ostep * depth;
            }
            offset += ostep * 0.2f;

            if( !m_drawEmptyLabels && showFull && depth == 0 )
            {
                vis.height = 0;
                vis.offset = 0;
                offset = oldOffset;
            }
            else if( yPos + ostep >= yMin && yPos <= yMax )
            {
                draw->AddLine( wpos + ImVec2( 0, oldOffset + ostep - 1 ), wpos + ImVec2( w, oldOffset + ostep - 1 ), 0x33FFFFFF );

                if( showFull )
                {
                    draw->AddTriangleFilled( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( ty - to/2, oldOffset + to/2 ), wpos + ImVec2( ty * 0.5, oldOffset + to/2 + th ), 0xFFFFAAAA );
                }
                else
                {
                    draw->AddTriangle( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( to/2, oldOffset + ty - to/2 ), wpos + ImVec2( to/2 + th, oldOffset + ty * 0.5 ), 0xFF886666, 2.0f );
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
                draw->AddText( wpos + ImVec2( ty, oldOffset ), showFull ? 0xFFFFAAAA : 0xFF886666, buf );

                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, oldOffset + ty ) ) )
                {
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        showFull = !showFull;
                    }
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        const auto t0 = v->timeline.front()->gpuStart;
                        if( t0 != std::numeric_limits<int64_t>::max() )
                        {
                            // FIXME
                            const auto t1 = std::min( m_worker.GetLastTime(), m_worker.GetZoneEnd( *v->timeline.back() ) );
                            ZoomToRange( t0, t1 );
                        }
                    }

                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( buf );
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
                        TextDisabledUnformatted( "Query accuracy bits:" );
                        ImGui::SameLine();
                        ImGui::Text( "%i", v->accuracyBits );
                    }
                    ImGui::EndTooltip();
                }
            }

            AdjustThreadHeight( vis, oldOffset, offset );
            ImGui::PopClipRect();
        }
    }

    // zones
    const auto& threadData = m_worker.GetThreadData();
    if( threadData.size() != m_threadOrder.size() )
    {
        m_threadOrder.reserve( threadData.size() );
        for( int i=m_threadOrder.size(); i<threadData.size(); i++ )
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
        bool& showFull = vis.showFull;

        const auto yPos = AdjustThreadPosition( vis, wpos.y, offset );
        const auto oldOffset = offset;
        ImGui::PushClipRect( wpos, wpos + ImVec2( w, offset + vis.height ), true );

        int depth = 0;
        offset += ostep;
        if( showFull )
        {
            m_lastCpu = -1;
            if( m_drawZones )
            {
                depth = DispatchZoneLevel( v->timeline, hover, pxns, int64_t( nspx ), wpos, offset, 0, yMin, yMax );
                offset += ostep * depth;
            }

            if( m_drawLocks )
            {
                const auto lockDepth = DrawLocks( v->id, hover, pxns, wpos, offset, nextLockHighlight, yMin, yMax );
                offset += ostep * lockDepth;
                depth += lockDepth;
            }
        }
        offset += ostep * 0.2f;

        auto msgit = std::lower_bound( v->messages.begin(), v->messages.end(), m_zvStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        auto msgend = std::lower_bound( msgit, v->messages.end(), m_zvEnd+1, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

        if( !m_drawEmptyLabels && showFull && depth == 0 && msgit == msgend && crash.thread != v->id )
        {
            vis.height = 0;
            vis.offset = 0;
            offset = oldOffset;
        }
        else if( yPos + ostep >= yMin && yPos <= yMax )
        {
            draw->AddLine( wpos + ImVec2( 0, oldOffset + ostep - 1 ), wpos + ImVec2( w, oldOffset + ostep - 1 ), 0x33FFFFFF );

            const auto labelColor = crash.thread == v->id ? ( showFull ? 0xFF2222FF : 0xFF111188 ) : ( showFull ? 0xFFFFFFFF : 0xFF888888 );

            if( showFull )
            {
                draw->AddTriangleFilled( wpos + ImVec2( to/2, oldOffset + to/2 ), wpos + ImVec2( ty - to/2, oldOffset + to/2 ), wpos + ImVec2( ty * 0.5, oldOffset + to/2 + th ), labelColor );

                while( msgit < msgend )
                {
                    const auto next = std::upper_bound( msgit, v->messages.end(), (*msgit)->time + MinVisSize * nspx, [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs->time; } );
                    const auto dist = std::distance( msgit, next );

                    const auto px = ( (*msgit)->time - m_zvStart ) * pxns;
                    if( dist > 1 )
                    {
                        unsigned int color = 0xFFDDDDDD;
                        if( m_msgHighlight && m_msgHighlight->thread == v->id )
                        {
                            const auto hTime = m_msgHighlight->time;
                            if( (*msgit)->time <= hTime && ( next == v->messages.end() || (*next)->time > hTime ) )
                            {
                                color = 0xFF4444FF;
                            }
                        }
                        draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.5, oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, oldOffset + to ), wpos + ImVec2( px, oldOffset + to + th ), color );
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, oldOffset + to ), wpos + ImVec2( px, oldOffset + to + th ), color, 2.0f );
                    }
                    else
                    {
                        const auto color = ( m_msgHighlight == *msgit ) ? 0xFF4444FF : 0xFFDDDDDD;
                        draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, oldOffset + to ), wpos + ImVec2( px + (ty - to) * 0.5, oldOffset + to ), wpos + ImVec2( px, oldOffset + to + th ), color, 2.0f );
                    }
                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, oldOffset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, oldOffset + ty ) ) )
                    {
                        ImGui::BeginTooltip();
                        if( dist > 1 )
                        {
                            ImGui::Text( "%i messages", (int)dist );
                        }
                        else
                        {
                            ImGui::TextUnformatted( TimeToString( (*msgit)->time - m_worker.GetTimeBegin() ) );
                            ImGui::Separator();
                            ImGui::TextUnformatted( "Message text:" );
                            ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", m_worker.GetString( (*msgit)->ref ) );
                        }
                        ImGui::EndTooltip();
                        m_msgHighlight = *msgit;

                        if( ImGui::IsMouseClicked( 0 ) )
                        {
                            m_showMessages = true;
                            m_msgToFocus = *msgit;
                        }
                        if( ImGui::IsMouseClicked( 2 ) )
                        {
                            CenterAtTime( (*msgit)->time );
                        }
                    }
                    msgit = next;
                }

                if( crash.thread == v->id && crash.time >= m_zvStart && crash.time <= m_zvEnd )
                {
                    const auto px = ( crash.time - m_zvStart ) * pxns;

                    draw->AddTriangleFilled( wpos + ImVec2( px - (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px, oldOffset + to + th ), 0xFF2222FF );
                    draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px + (ty - to) * 0.25f, oldOffset + to + th * 0.5f ), wpos + ImVec2( px, oldOffset + to + th ), 0xFF2222FF, 2.0f );

#ifdef TRACY_EXTENDED_FONT
                    const auto crashText = ICON_FA_SKULL " crash " ICON_FA_SKULL;
#else
                    const auto crashText = "crash";
#endif

                    auto ctw = ImGui::CalcTextSize( crashText ).x;
                    draw->AddText( wpos + ImVec2( px - ctw * 0.5f, oldOffset + to + th * 0.5f - ty ), 0xFF2222FF, crashText );

                    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, oldOffset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, oldOffset + ty ) ) )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Time:", TimeToString( crash.time - m_worker.GetTimeBegin() ) );
                        TextFocused( "Reason:", m_worker.GetString( crash.message ) );
                        ImGui::EndTooltip();

                        if( ImGui::IsMouseClicked( 0 ) )
                        {
                            m_showInfo = true;
                        }
                        if( ImGui::IsMouseClicked( 2 ) )
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
            const auto txt = m_worker.GetThreadString( v->id );
            const auto txtsz = ImGui::CalcTextSize( txt );
            if( m_gpuThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x + 4, oldOffset + ty ), 0x448888DD );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x + 4, oldOffset + ty ), 0x888888DD );
            }
            if( m_gpuInfoWindow && m_gpuInfoWindowThread == v->id )
            {
                draw->AddRectFilled( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x + 4, oldOffset + ty ), 0x4488DD88 );
                draw->AddRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x + 4, oldOffset + ty ), 0x8888DD88 );
            }
            draw->AddText( wpos + ImVec2( ty, oldOffset ), labelColor, txt );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, oldOffset ), wpos + ImVec2( ty + txtsz.x, oldOffset + ty ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::TextUnformatted( m_worker.GetThreadString( v->id ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(0x%" PRIx64 ")", v->id );
                if( crash.thread == v->id )
                {
                    ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                    ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
#else
                    ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), "Crashed" );
#endif
                }

                ImGui::Separator();
                int64_t first = std::numeric_limits<int64_t>::max();
                int64_t last = -1;
                if( !v->timeline.empty() )
                {
                    first = v->timeline.front()->start;
                    last = m_worker.GetZoneEnd( *v->timeline.back() );
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
                    if( lptr->ptr->time < first ) first = lptr->ptr->time;
                    while( eptr->ptr->thread != thread ) eptr--;
                    if( eptr->ptr->time > last ) last = eptr->ptr->time;
                }

                if( last >= 0 )
                {
                    const auto activity = last - first;
                    const auto traceLen = m_worker.GetLastTime() - m_worker.GetTimeBegin();

                    TextFocused( "Appeared at", TimeToString( first - m_worker.GetTimeBegin() ) );
                    TextFocused( "Last event at", TimeToString( last - m_worker.GetTimeBegin() ) );
                    TextFocused( "Activity time:", TimeToString( activity ) );
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%.2f%%)", activity / double( traceLen ) * 100 );
                }

                ImGui::Separator();
                if( !v->timeline.empty() )
                {
                    TextFocused( "Zone count:", RealToString( v->count, true ) );
                    TextFocused( "Top-level zones:", RealToString( v->timeline.size(), true ) );
                }
                if( !v->messages.empty() )
                {
                    TextFocused( "Messages:", RealToString( v->messages.size(), true ) );
                }
                if( lockCnt != 0 )
                {
                    TextFocused( "Locks:", RealToString( lockCnt, true ) );
                }
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }
                if( last >= 0 && ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToRange( first, last );
                }
            }
        }

        AdjustThreadHeight( vis, oldOffset, offset );
        ImGui::PopClipRect();
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
        ImGui::TextUnformatted( TimeToString( e - s ) );
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

int View::DispatchZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        return DrawZoneLevel( vec, hover, pxns, nspx, wpos, _offset, depth, yMin, yMax );
    }
    else
    {
        return SkipZoneLevel( vec, hover, pxns, nspx, wpos, _offset, depth, yMin, yMax );
    }
}

int View::DrawZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
{
    const auto delay = m_worker.GetDelay();
    const auto resolution = m_worker.GetResolution();
    // cast to uint64_t, so that unended zones (end = -1) are still drawn
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - delay, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), m_zvEnd + resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    if( it == zitend ) return depth;
    if( (*it)->end < 0 && m_worker.GetZoneEnd( **it ) < m_zvStart ) return depth;

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
            int num = 0;
            const auto px0 = ( ev.start - m_zvStart ) * pxns;
            auto px1 = ( end - m_zvStart ) * pxns;
            auto rend = end;
            auto nextTime = end + MinVisSize;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                num += std::distance( prevIt, it );
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                nextTime = nend + nspx;
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
                const auto d = DispatchZoneLevel( m_worker.GetZoneChildren( ev.child ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax );
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

int View::SkipZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, float yMin, float yMax )
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
            auto nextTime = end + MinVisSize;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l->end < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = m_worker.GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                nextTime = nend + nspx;
            }
        }
        else
        {
            m_lastCpu = ev.cpu_start;

            if( ev.child >= 0 )
            {
                const auto d = DispatchZoneLevel( m_worker.GetZoneChildren( ev.child ), hover, pxns, nspx, wpos, _offset, depth, yMin, yMax );
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

int View::DispatchGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
{
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;

    const auto yPos = wpos.y + offset;
    if( yPos + ostep >= yMin && yPos <= yMax )
    {
        return DrawGpuZoneLevel( vec, hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
    }
    else
    {
        return SkipGpuZoneLevel( vec, hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
    }
}

static int64_t AdjustGpuTime( int64_t time, int64_t begin, int drift )
{
    const auto t = time - begin;
    return time + t / 1000000000 * drift;
}

int View::DrawGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
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
            int num = 0;
            const auto px0 = ( start - m_zvStart ) * pxns;
            auto px1 = ( end - m_zvStart ) * pxns;
            auto rend = end;
            auto nextTime = end + MinVisSize;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l->gpuEnd < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                num += std::distance( prevIt, it );
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( **it ), begin, drift );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                nextTime = nend + nspx;
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
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.child ), hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
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

int View::SkipGpuZoneLevel( const Vector<GpuEvent*>& vec, bool hover, double pxns, int64_t nspx, const ImVec2& wpos, int _offset, int depth, uint64_t thread, float yMin, float yMax, int64_t begin, int drift )
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
            auto nextTime = end;
            for(;;)
            {
                const auto prevIt = it;
                it = std::lower_bound( it, zitend, nextTime, [] ( const auto& l, const auto& r ) { return (uint64_t)l->gpuEnd < (uint64_t)r; } );
                if( it == prevIt ) ++it;
                if( it == zitend ) break;
                const auto nend = AdjustGpuTime( m_worker.GetZoneEnd( **it ), begin, drift );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                nextTime = nend + nspx;
            }
        }
        else
        {
            if( ev.child >= 0 )
            {
                const auto d = DispatchGpuZoneLevel( m_worker.GetGpuChildren( ev.child ), hover, pxns, nspx, wpos, _offset, depth, thread, yMin, yMax, begin, drift );
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
    const auto itptr = (const LockEventShared*)it->ptr;
    auto next = it;
    next++;

    switch( nextState )
    {
    case LockState::Nothing:
        while( next < end )
        {
            const auto ptr = (const LockEventShared*)next->ptr;
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
            const auto ptr = (const LockEventShared*)next->ptr;
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
            const auto ptr = (const LockEventShared*)next->ptr;
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
            const auto ptr = (const LockEventShared*)next->ptr;
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
    sprintf( buf, "%" PRIu32 ": %s", id, m_worker.GetString( srcloc.function ) );
    DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ) ) )
    {
        m_lockHoverHighlight = id;

        if( ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty ) ) )
        {
            const auto& range = lockmap.range[tid];
            const auto activity = range.end - range.start;
            const auto traceLen = m_worker.GetLastTime() - m_worker.GetTimeBegin();

            int64_t timeAnnounce = lockmap.timeAnnounce;
            int64_t timeTerminate = lockmap.timeTerminate;
            if( !lockmap.timeline.empty() )
            {
                if( timeAnnounce == 0 )
                {
                    timeAnnounce = lockmap.timeline.front().ptr->time;
                }
                if( timeTerminate == 0 )
                {
                    timeTerminate = lockmap.timeline.back().ptr->time;
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
            ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
            ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
            TextFocused( ICON_FA_RANDOM " Appeared at", TimeToString( range.start - m_worker.GetTimeBegin() ) );
            TextFocused( ICON_FA_RANDOM " Last event at", TimeToString( range.end - m_worker.GetTimeBegin() ) );
            TextFocused( ICON_FA_RANDOM " Activity time:", TimeToString( activity ) );
#else
            ImGui::TextUnformatted( "This thread" );
            TextFocused( "Appeared at", TimeToString( range.start - m_worker.GetTimeBegin() ) );
            TextFocused( "Last event at", TimeToString( range.end - m_worker.GetTimeBegin() ) );
            TextFocused( "Activity time:", TimeToString( activity ) );
#endif
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of lock lifetime)", activity / double( lockLen ) * 100 );
            ImGui::Separator();
            TextFocused( "Announce time:", TimeToString( timeAnnounce - m_worker.GetTimeBegin() ) );
            TextFocused( "Terminate time:", TimeToString( timeTerminate - m_worker.GetTimeBegin() ) );
            TextFocused( "Lifetime:", TimeToString( lockLen ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of trace time)", lockLen / double( traceLen ) * 100 );
            ImGui::Separator();
            TextDisabledUnformatted( "Thread list:" );
            ImGui::Indent( ty );
            for( const auto& t : lockmap.threadList )
            {
                ImGui::TextUnformatted( m_worker.GetThreadString( t ) );
            }
            ImGui::Unindent( ty );
            ImGui::Separator();
            TextFocused( "Lock events:", RealToString( lockmap.timeline.size(), true ) );
            ImGui::EndTooltip();

            if( ImGui::IsMouseClicked( 0 ) )
            {
                m_lockInfoWindow = id;
            }
            if( ImGui::IsMouseClicked( 2 ) )
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
    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = delay * pxns;
    const auto rsz = resolution * pxns;

    int cnt = 0;
    for( const auto& v : m_worker.GetLockMap() )
    {
        const auto& lockmap = *v.second;
        if( !lockmap.valid || !Vis( &lockmap ).visible ) continue;
        if( m_onlyContendedLocks && lockmap.threadList.size() == 1 && m_lockInfoWindow != v.first ) continue;

        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;

        const auto offset = _offset + ostep * cnt;

        const auto& range = lockmap.range[it->second];
        const auto& tl = lockmap.timeline;
        assert( !tl.empty() );
        if( range.start > m_zvEnd || range.end < m_zvStart )
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

        auto vbegin = std::lower_bound( tl.begin(), tl.end(), std::max( range.start, m_zvStart - delay ), [] ( const auto& l, const auto& r ) { return l.ptr->time < r; } );
        const auto vend = std::lower_bound( vbegin, tl.end(), std::min( range.end, m_zvEnd + resolution ), [] ( const auto& l, const auto& r ) { return l.ptr->time < r; } );

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
            auto ptr = (const LockEventShared*)vbegin->ptr;
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
                if( m_onlyContendedLocks )
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

                assert( state != LockState::Nothing && ( !m_onlyContendedLocks || state != LockState::HasLock ) );
                drawn = true;

                LockState drawState = state;
                auto next = GetNextLockFunc( vbegin, vend, state, threadBit );

                const auto t0 = vbegin->ptr->time;
                int64_t t1 = next == tl.end() ? m_worker.GetLastTime() : next->ptr->time;
                const auto px0 = std::max( pxend, ( t0 - m_zvStart ) * pxns );
                auto tx0 = px0;
                double px1 = ( t1 - m_zvStart ) * pxns;
                uint64_t condensed = 0;

                if( m_onlyContendedLocks )
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
                        const auto t2 = n == tl.end() ? m_worker.GetLastTime() : n->ptr->time;
                        const auto px2 = ( t2 - m_zvStart ) * pxns;
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
                        const auto t2 = n == tl.end() ? m_worker.GetLastTime() : n->ptr->time;
                        const auto px2 = ( t2 - m_zvStart ) * pxns;
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

                bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( pxend, double( w + 10 ) ), offset + ty ) );
                if( itemHovered )
                {
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        m_lockInfoWindow = v.first;
                    }
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        ZoomToRange( t0, t1 );
                    }

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
                                if( b->lockingThread != vbegin->lockingThread )
                                {
                                    break;
                                }
                                b--;
                            }
                            b++;
                            highlight.begin = b->ptr->time;

                            auto e = next;
                            while( e != tl.end() )
                            {
                                if( e->lockingThread != next->lockingThread )
                                {
                                    highlight.id = v.first;
                                    highlight.end = e->ptr->time;
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
                            if( it->ptr->thread == thread )
                            {
                                if( ( it->lockingThread == thread || IsThreadWaiting( it->waitList, threadBit ) ) && it->ptr->srcloc != 0 )
                                {
                                    markloc = it->ptr->srcloc;
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
                            ImGui::Text( "%s:%i", m_worker.GetString( marklocdata.file ), marklocdata.line );
                            ImGui::Separator();
                        }

                        if( lockmap.type == LockType::Lockable )
                        {
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                if( vbegin->lockCount == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadString( tid ), vbegin->lockCount );
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
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( vbegin->waitList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%i):", m_worker.GetThreadString( tid ), vbegin->lockCount, TracyCountBits( vbegin->waitList ) );
                                }
                                auto waitList = vbegin->waitList;
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
                                if( vbegin->lockCount > 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other thread:", m_worker.GetThreadString( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadString( tid ) );
                                }
                                ImGui::Indent( ty );
                                ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[vbegin->lockingThread] ) );
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
                            const auto ptr = (const LockEventShared*)vbegin->ptr;
                            switch( drawState )
                            {
                            case LockState::HasLock:
                                assert( vbegin->waitList == 0 );
                                if( ptr->sharedList == 0 )
                                {
                                    assert( vbegin->lockCount == 1 );
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
                                    assert( vbegin->lockCount == 1 );
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( vbegin->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }
                                else if( TracyCountBits( ptr->sharedList ) == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. Blocked threads (%i):", m_worker.GetThreadString( tid ), TracyCountBits( vbegin->waitList ) + TracyCountBits( ptr->waitShared ) );
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
                                    ImGui::Text( "Blocked threads (%i):", TracyCountBits( vbegin->waitList ) + TracyCountBits( ptr->waitShared ) );
                                }

                                auto waitList = vbegin->waitList;
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
                                assert( vbegin->lockCount == 0 || vbegin->lockCount == 1 );
                                if( vbegin->lockCount != 0 || ptr->sharedList != 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other threads (%i):", m_worker.GetThreadString( tid ), vbegin->lockCount + TracyCountBits( ptr->sharedList ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadString( tid ) );
                                }
                                ImGui::Indent( ty );
                                if( vbegin->lockCount != 0 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadString( lockmap.threadList[vbegin->lockingThread] ) );
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
                if( m_lockHighlight.thread != thread && ( drawState == LockState::HasBlockingLock ) != m_lockHighlight.blocked && next != tl.end() && m_lockHighlight.id == int64_t( v.first ) && m_lockHighlight.begin <= vbegin->ptr->time && m_lockHighlight.end >= next->ptr->time )
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
                    DrawZigZag( draw, wpos + ImVec2( 0, offset + round( ty / 2 ) ), px0, pxend, ty / 4, DarkenColor( cfilled ) );
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
            while( vbegin < vend && ( state == LockState::Nothing || ( m_onlyContendedLocks && state == LockState::HasLock ) ) )
            {
                vbegin = GetNextLockFunc( vbegin, vend, state, threadBit );
            }
            if( vbegin < vend ) cnt++;
        }
    }
    return cnt;
}

static const char* FormatPlotValue( double val, PlotType type )
{
    static char buf[64];
    switch( type )
    {
    case PlotType::User:
        return RealToString( val, true );
        break;
    case PlotType::Memory:
        return MemSizeToString( val );
        break;
    case PlotType::SysTime:
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
    const auto PlotHeight = 100 * ImGui::GetTextLineHeight() / 15.f;

    enum { MaxPoints = 128 };
    float tmpvec[MaxPoints*2];

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto nspx = 1.0 / pxns;

    for( const auto& v : m_worker.GetPlots() )
    {
        auto& vis = Vis( v );
        if( !vis.visible )
        {
            vis.height = 0;
            vis.offset = 0;
            continue;
        }
        assert( !v->data.empty() );
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
            draw->AddText( wpos + ImVec2( ty, offset ), showFull ? 0xFF44DDDD : 0xFF226E6E, txt );
            draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + txtx, offset + ty ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Plot \"%s\"", txt );
                ImGui::Separator();

                const auto first = v->data.front().time;
                const auto last = v->data.back().time;
                const auto activity = last - first;
                const auto traceLen = m_worker.GetLastTime() - m_worker.GetTimeBegin();

                TextFocused( "Appeared at", TimeToString( first - m_worker.GetTimeBegin() ) );
                TextFocused( "Last event at", TimeToString( last - m_worker.GetTimeBegin() ) );
                TextFocused( "Activity time:", TimeToString( activity ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.2f%%)", activity / double( traceLen ) * 100 );
                ImGui::Separator();
                TextFocused( "Data points:", RealToString( v->data.size(), true ) );
                TextFocused( "Data range:", FormatPlotValue( v->max - v->min, v->type ) );
                TextFocused( "Min value:", FormatPlotValue( v->min, v->type ) );
                TextFocused( "Max value:", FormatPlotValue( v->max, v->type ) );
                TextFocused( "Data/second:", RealToString( double( v->data.size() ) / activity * 1000000000ll, true ) );

                const auto it = std::lower_bound( v->data.begin(), v->data.end(), last - 1000000000ll * 10, [] ( const auto& l, const auto& r ) { return l.time < r; } );
                const auto tr10 = last - it->time;
                if( tr10 != 0 )
                {
                    TextFocused( "D/s (10s):", RealToString( double( std::distance( it, v->data.end() ) ) / tr10 * 1000000000ll, true ) );
                }
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    showFull = !showFull;
                }
                if( ImGui::IsMouseClicked( 2 ) )
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
                }

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

                        if( rsz > MaxPoints )
                        {
                            draw->AddLine( wpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), wpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD, 4.f );

                            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x1 - 2, offset ), wpos + ImVec2( x1 + 2, offset + PlotHeight ) ) )
                            {
                                ImGui::BeginTooltip();
                                TextFocused( "Number of values:", RealToString( rsz, true ) );
                                TextDisabledUnformatted( "Estimated range:" );
                                ImGui::SameLine();
                                ImGui::Text( "%s - %s", FormatPlotValue( tmpvec[0], v->type ), FormatPlotValue( dst[-1], v->type ) );
                                ImGui::SameLine();
                                ImGui::TextDisabled( "(%s)", FormatPlotValue( dst[-1] - tmpvec[0], v->type ) );
                                ImGui::EndTooltip();
                            }
                        }
                        else
                        {
                            draw->AddLine( wpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), wpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD );

                            auto vit = tmpvec;
                            while( vit != dst )
                            {
                                auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                                assert( vrange > vit );
                                if( std::distance( vit, vrange ) == 1 )
                                {
                                    DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, false, v->type, PlotHeight );
                                }
                                else
                                {
                                    DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, true, v->type, PlotHeight );
                                }
                                vit = vrange;
                            }
                        }

                        prevy = it - 1;
                    }
                }

                char tmp[64];
                if( yPos + ty >= yMin && yPos <= yMax )
                {
                    sprintf( tmp, "(y-range: %s)", FormatPlotValue( max - min, v->type ) );
                    draw->AddText( wpos + ImVec2( ty * 1.5f + txtx, offset - ty ), 0x8844DDDD, tmp );
                }
                sprintf( tmp, "%s", FormatPlotValue( max, v->type ) );
                DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
                offset += PlotHeight - ty;
                sprintf( tmp, "%s", FormatPlotValue( min, v->type ) );
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
        AdjustThreadHeight( vis, oldOffset, offset );
        ImGui::PopClipRect();
    }

    return offset;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged, PlotType type, float PlotHeight )
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
        TextFocused( "Value:", FormatPlotValue( val, type ) );
        if( hasPrev )
        {
            TextFocused( "Change:", FormatPlotValue( val - prev, type ) );
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
            TextDisabledUnformatted( "Value:" );
            ImGui::SameLine();
            if( item->val < 10000ll )
            {
                ImGui::TextUnformatted( MemSizeToString( item->val ) );
            }
            else
            {
                ImGui::Text( "%s (%s)", MemSizeToString( item->val ), RealToString( item->val, true ) );
            }
        }
        else
        {
            TextFocused( "Value:", FormatPlotValue( item->val, type ) );
        }
        if( hasPrev )
        {
            const auto change = item->val - prev;
            TextFocused( "Change:", FormatPlotValue( change, type ) );

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
                    TextDisabledUnformatted( "Address:" );
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
                        ImGui::TextUnformatted( "Allocation still active" );
                    }
                    else
                    {
                        TextFocused( "Freed at", TimeToString( ev->timeFree - m_worker.GetTimeBegin() ) );
                        if( change < 0 )
                        {
                            ImGui::SameLine();
                            TextDisabledUnformatted( "(this event)" );
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
void DrawZoneTrace( T zone, const std::vector<T>& trace, const Worker& worker, BuzzAnim<const void*>& anim, View& view, bool& showUnknownFrames, std::function<void(T, int&)> showZone )
{
    bool expand = ImGui::TreeNode( "Zone trace" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( trace.size(), true ) );
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
            if( prev->callstack == 0 || curr->callstack == 0 )
            {
                if( showUnknownFrames )
                {
                    ImGui::TextDisabled( "%i.", fidx++ );
                    ImGui::SameLine();
                    TextDisabledUnformatted( "[unknown frames]" );
                }
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
                        if( cf.data == pf.data )
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
                    if( frame->line == 0 )
                    {
                        TextDisabledUnformatted( fileName );
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

            showZone( curr, fidx );
            prev = curr;
        }
    }

    auto last = trace.empty() ? zone : trace.back();
    if( last->callstack == 0 )
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
        auto& cs = worker.GetCallstack( last->callstack );
        const auto csz = cs.size();
        for( uint8_t i=1; i<csz; i++ )
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
            if( frame->line == 0 )
            {
                TextDisabledUnformatted( fileName );
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
            SetButtonHighlightColor();
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
            SetButtonHighlightColor();
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

    auto threadData = GetZoneThreadData( ev );
    assert( threadData );
    const auto tid = threadData->id;
    if( ev.name.active )
    {
        TextFocused( "Zone name:", m_worker.GetString( ev.name ) );
    }
    if( srcloc.name.active )
    {
        TextFocused( "Zone name:", m_worker.GetString( srcloc.name ) );
    }
    TextFocused( "Function:", m_worker.GetString( srcloc.function ) );
    TextDisabledUnformatted( "Location:" );
    ImGui::SameLine();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    if( ev.text.active )
    {
        TextFocused( "User text:", m_worker.GetString( ev.text ) );
        dmul++;
    }

    ImGui::Separator();

    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.start;
    const auto selftime = GetZoneSelfTime( ev );
    TextFocused( "Time from start of program:", TimeToString( ev.start - m_worker.GetTimeBegin() ) );
    TextFocused( "Execution time:", TimeToString( ztime ) );
    if( ImGui::IsItemHovered() )
    {
        ImGui::BeginTooltip();
        TextFocused( "Without profiling:", TimeToString( ztime - m_worker.GetDelay() * dmul ) );
        ImGui::EndTooltip();
    }
    TextFocused( "Self time:", TimeToString( selftime ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%.2f%%)", 100.f * selftime / ztime );

    auto& mem = m_worker.GetMemData();
    if( !mem.data.empty() )
    {
        ImGui::Separator();

        if( !mem.plot )
        {
            ImGui::Text( "Please wait, computing data..." );
            DrawWaitingDots( s_time );
        }
        else
        {
            const auto thread = m_worker.CompressThread( tid );

            auto ait = std::lower_bound( mem.data.begin(), mem.data.end(), ev.start, [] ( const auto& l, const auto& r ) { return l.timeAlloc < r; } );
            const auto aend = std::upper_bound( mem.data.begin(), mem.data.end(), end, [] ( const auto& l, const auto& r ) { return l < r.timeAlloc; } );

            auto fit = std::lower_bound( mem.frees.begin(), mem.frees.end(), ev.start, [&mem] ( const auto& l, const auto& r ) { return mem.data[l].timeFree < r; } );
            const auto fend = std::upper_bound( mem.frees.begin(), mem.frees.end(), end, [&mem] ( const auto& l, const auto& r ) { return l < mem.data[r].timeFree; } );

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
                    TextDisabledUnformatted( "No memory events." );
                }
                else
                {
                    ImGui::TextUnformatted( RealToString( nAlloc + nFree, true ) );
                    ImGui::SameLine();
                    TextDisabledUnformatted( "memory events." );
                    ImGui::TextUnformatted( RealToString( nAlloc, true ) );
                    ImGui::SameLine();
                    TextDisabledUnformatted( "allocs," );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( RealToString( nFree, true ) );
                    ImGui::SameLine();
                    TextDisabledUnformatted( "frees." );
                    TextFocused( "Memory allocated:", MemSizeToString( cAlloc ) );
                    TextFocused( "Memory freed:", MemSizeToString( cFree ) );
                    TextFocused( "Overall change:", MemSizeToString( cAlloc - cFree ) );

                    if( ImGui::TreeNode( "Allocations list" ) )
                    {
                        SmallCheckbox( "Allocation times relative to zone start", &m_allocTimeRelativeToZone );

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
                        }, nullptr, m_allocTimeRelativeToZone ? ev.start : -1 );
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
            auto msgit = std::lower_bound( threadData->messages.begin(), threadData->messages.end(), ev.start, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
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
                ImGui::TextDisabled( "(%s)", RealToString( dist, true ) );
                if( expand )
                {
                    static bool widthSet = false;
                    ImGui::Columns( 2 );
                    if( !widthSet )
                    {
                        widthSet = true;
                        const auto w = ImGui::GetWindowWidth();
                        ImGui::SetColumnWidth( 0, w * 0.2f );
                        ImGui::SetColumnWidth( 1, w * 0.8f );
                    }
                    TextDisabledUnformatted( "Time" );
                    ImGui::NextColumn();
                    TextDisabledUnformatted( "Message" );
                    ImGui::NextColumn();
                    ImGui::Separator();
                    do
                    {
                        ImGui::PushID( *msgit );
                        if( ImGui::Selectable( TimeToString( (*msgit)->time - ev.start ), m_msgHighlight == *msgit, ImGuiSelectableFlags_SpanAllColumns ) )
                        {
                            CenterAtTime( (*msgit)->time );
                        }
                        if( ImGui::IsItemHovered() )
                        {
                            m_msgHighlight = *msgit;
                        }
                        ImGui::PopID();
                        ImGui::NextColumn();
                        ImGui::TextWrapped( "%s", m_worker.GetString( (*msgit)->ref ) );
                        ImGui::NextColumn();
                    }
                    while( ++msgit != msgend );
                    ImGui::EndColumns();
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
            const auto rztime = 1.0 / ztime;
            const auto ty = ImGui::GetTextLineHeight();

            ImGui::SameLine();
            SmallCheckbox( "Group children locations", &m_groupChildrenLocations );

            if( m_groupChildrenLocations )
            {
                struct ChildGroup
                {
                    int32_t srcloc;
                    uint64_t t;
                    Vector<uint32_t> v;
                };
                uint64_t ctime = 0;
                flat_hash_map<int32_t, ChildGroup, nohash<int32_t>> cmap;
                cmap.reserve( 128 );
                for( size_t i=0; i<children.size(); i++ )
                {
                    const auto& child = *children[i];
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.start;
                    const auto srcloc = child.srcloc;
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
                ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
                ImGui::NextColumn();
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
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
                        auto& cev = *children[cgr.v.front()];
                        const auto txt = m_worker.GetZoneName( cev );
                        bool b = false;
                        ImGui::PushID( (int)cgr.v.front() );
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
                            ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
                            ImGui::EndTooltip();
                        }
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( cgr.v.size(), true ) );
                    }
                    ImGui::NextColumn();
                    const auto part = double( cgr.t ) * rztime;
                    char buf[128];
                    sprintf( buf, "%s (%.2f%%)", TimeToString( cgr.t ), part * 100 );
                    ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                    ImGui::NextColumn();
                    if( expandGroup )
                    {
                        auto ctt = std::make_unique<uint64_t[]>( cgr.v.size() );
                        auto cti = std::make_unique<uint32_t[]>( cgr.v.size() );
                        for( size_t i=0; i<cgr.v.size(); i++ )
                        {
                            const auto& child = *children[cgr.v[i]];
                            const auto cend = m_worker.GetZoneEnd( child );
                            const auto ct = cend - child.start;
                            ctt[i] = ct;
                            cti[i] = uint32_t( i );
                        }

                        pdqsort_branchless( cti.get(), cti.get() + cgr.v.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                        for( size_t i=0; i<cgr.v.size(); i++ )
                        {
                            auto& cev = *children[cgr.v[cti[i]]];
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
                                if( ImGui::IsMouseClicked( 2 ) )
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
                            sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
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
                    const auto& child = *children[i];
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.start;
                    ctime += ct;
                    ctt[i] = ct;
                    cti[i] = uint32_t( i );
                }

                pdqsort_branchless( cti.get(), cti.get() + children.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                ImGui::Columns( 2 );
                ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
                ImGui::NextColumn();
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
                ImGui::ProgressBar( double( ztime - ctime ) * rztime, ImVec2( -1, ty ), buf );
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
                    const auto part = double( ctt[cti[i]] ) * rztime;
                    char buf[128];
                    sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
                    ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                    ImGui::NextColumn();
                }
                ImGui::EndColumns();
            }
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
            SetButtonHighlightColor();
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
            SetButtonHighlightColor();
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
    TextDisabledUnformatted( "Location:" );
    ImGui::SameLine();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );

    ImGui::Separator();

    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.gpuStart;
    const auto selftime = GetZoneSelfTime( ev );
    TextFocused( "Time from start of program:", TimeToString( ev.gpuStart - m_worker.GetTimeBegin() ) );
    TextFocused( "GPU execution time:", TimeToString( ztime ) );
    TextFocused( "GPU self time:", TimeToString( selftime ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%.2f%%)", 100.f * selftime / ztime );
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
    DrawZoneTrace<const GpuEvent*>( &ev, zoneTrace, m_worker, m_zoneinfoBuzzAnim, *this, m_showUnknownFrames, [&idx, this] ( const GpuEvent* v, int& fidx ) {
        ImGui::TextDisabled( "%i.", fidx++ );
        ImGui::SameLine();
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
            const auto rztime = 1.0 / ztime;
            const auto ty = ImGui::GetTextLineHeight();

            ImGui::SameLine();
            SmallCheckbox( "Group children locations", &m_groupChildrenLocations );

            if( m_groupChildrenLocations )
            {
                struct ChildGroup
                {
                    int32_t srcloc;
                    uint64_t t;
                    Vector<uint32_t> v;
                };
                uint64_t ctime = 0;
                flat_hash_map<int32_t, ChildGroup, nohash<int32_t>> cmap;
                cmap.reserve( 128 );
                for( size_t i=0; i<children.size(); i++ )
                {
                    const auto& child = *children[i];
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.gpuStart;
                    const auto srcloc = child.srcloc;
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
                ImGui::TextColored( ImVec4( 1.0f, 1.0f, 0.4f, 1.0f ), "Self time" );
                ImGui::NextColumn();
                char buf[128];
                sprintf( buf, "%s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
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
                        auto& cev = *children[cgr.v.front()];
                        const auto txt = m_worker.GetZoneName( cev );
                        bool b = false;
                        ImGui::PushID( (int)cgr.v.front() );
                        if( ImGui::Selectable( txt, &b, ImGuiSelectableFlags_SpanAllColumns ) )
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
                            ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
                            ImGui::EndTooltip();
                        }
                        ImGui::SameLine();
                        ImGui::TextDisabled( "(\xc3\x97%s)", RealToString( cgr.v.size(), true ) );
                    }
                    ImGui::NextColumn();
                    const auto part = double( cgr.t ) * rztime;
                    char buf[128];
                    sprintf( buf, "%s (%.2f%%)", TimeToString( cgr.t ), part * 100 );
                    ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
                    ImGui::NextColumn();
                    if( expandGroup )
                    {
                        auto ctt = std::make_unique<uint64_t[]>( cgr.v.size() );
                        auto cti = std::make_unique<uint32_t[]>( cgr.v.size() );
                        for( size_t i=0; i<cgr.v.size(); i++ )
                        {
                            const auto& child = *children[cgr.v[i]];
                            const auto cend = m_worker.GetZoneEnd( child );
                            const auto ct = cend - child.gpuStart;
                            ctt[i] = ct;
                            cti[i] = uint32_t( i );
                        }

                        pdqsort_branchless( cti.get(), cti.get() + cgr.v.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

                        for( size_t i=0; i<cgr.v.size(); i++ )
                        {
                            auto& cev = *children[cgr.v[cti[i]]];
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
                                if( ImGui::IsMouseClicked( 2 ) )
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
                            sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
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
                    const auto& child = *children[i];
                    const auto cend = m_worker.GetZoneEnd( child );
                    const auto ct = cend - child.gpuStart;
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

#ifdef TRACY_EXTENDED_FONT
    ImGui::Checkbox( ICON_FA_EXPAND " Draw empty labels", &m_drawEmptyLabels );
#else
    ImGui::Checkbox( "Draw empty labels", &m_drawEmptyLabels );
#endif
    ImGui::Separator();

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
                ImGui::Checkbox( buf, &Vis( gpuData[i] ).visible );
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
        size_t lockCnt = 0;
        size_t singleCnt = 0;
        size_t multiCnt = 0;
        for( const auto& l : m_worker.GetLockMap() )
        {
            if( l.second->valid && !l.second->timeline.empty() )
            {
                lockCnt++;
                if( l.second->threadList.size() == 1 )
                {
                    singleCnt++;
                }
                else
                {
                    multiCnt++;
                }
            }
        }

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
        ImGui::TextDisabled( "(%zu)", lockCnt );
        if( ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            ImGui::TextUnformatted( "Locks with no recorded events are counted, but not listed." );
            ImGui::EndTooltip();
        }
        if( expand )
        {
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

            const bool multiExpand = ImGui::TreeNodeEx( "Locks present in multiple threads", ImGuiTreeNodeFlags_DefaultOpen );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", multiCnt );
            if( multiExpand )
            {
                if( ImGui::SmallButton( "Select all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 ) Vis( l.second ).visible = true;
                    }
                }
                ImGui::SameLine();
                if( ImGui::SmallButton( "Unselect all" ) )
                {
                    for( const auto& l : m_worker.GetLockMap() )
                    {
                        if( l.second->threadList.size() != 1 ) Vis( l.second ).visible = false;
                    }
                }

                for( const auto& l : m_worker.GetLockMap() )
                {
                    if( l.second->valid && !l.second->timeline.empty() && l.second->threadList.size() != 1 )
                    {
                        auto& sl = m_worker.GetSourceLocation( l.second->srcloc );
                        auto fileName = m_worker.GetString( sl.file );

                        char buf[1024];
                        sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        ImGui::Checkbox( buf, &Vis( l.second ).visible );
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
                        ImGui::TextDisabled( "(%s) %s:%i", RealToString( l.second->timeline.size(), true ), fileName, sl.line );
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( FileExists( fileName ) )
                            {
                                SetTextEditorFile( fileName, sl.line );
                            }
                            else
                            {
                                m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
                            }
                        }
                    }
                }
                ImGui::TreePop();
            }
            const auto singleExpand = ImGui::TreeNodeEx( "Locks present in a single thread", ImGuiTreeNodeFlags_DefaultOpen );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%zu)", singleCnt );
            if( singleExpand )
            {
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
                        sprintf( buf, "%" PRIu32 ": %s", l.first, m_worker.GetString( m_worker.GetSourceLocation( l.second->srcloc ).function ) );
                        ImGui::Checkbox( buf, &Vis( l.second ).visible );
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
                        ImGui::TextDisabled( "(%s) %s:%i", RealToString( l.second->timeline.size(), true ), fileName, sl.line );
                        if( ImGui::IsItemClicked( 1 ) )
                        {
                            if( FileExists( fileName ) )
                            {
                                SetTextEditorFile( fileName, sl.line );
                            }
                            else
                            {
                                m_optionsLockBuzzAnim.Enable( l.second->srcloc, 0.5f );
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
                ImGui::Checkbox( GetPlotName( p ), &Vis( p ).visible );
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
    ImGui::TextDisabled( "(%zu)", m_threadOrder.size() );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

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

        const auto th = 18.f * ImGui::GetTextLineHeight() / 15.f;
        int idIdx = 0;
        int idx = 0;
        int upIdx = -1;
        int downIdx = -1;
        for( const auto& t : m_threadOrder )
        {
            ImGui::PushID( idIdx++ );
#ifdef TRACY_EXTENDED_FONT
            if( ImGui::Button( ICON_FA_CARET_UP, ImVec2( th, 0 ) ) )
#else
            if( ImGui::Button( "^", ImVec2( th, 0 ) ) )
#endif
            {
                upIdx = idx;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::PushID( idIdx++ );
#ifdef TRACY_EXTENDED_FONT
            if( ImGui::Button( ICON_FA_CARET_DOWN, ImVec2( th, 0 ) ) )
#else
            if( ImGui::Button( "v", ImVec2( th, 0 ) ) )
#endif
            {
                downIdx = idx;
            }
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::PushID( idIdx++ );
            ImGui::Checkbox( m_worker.GetThreadString( t->id ), &Vis( t ).visible );
            ImGui::PopID();
            if( crash.thread == t->id )
            {
                ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL );
                if( ImGui::IsItemHovered() )
                {
                    ImGui::BeginTooltip();
                    ImGui::TextUnformatted( "Crashed" );
                    ImGui::EndTooltip();
                    if( ImGui::IsMouseClicked( 0 ) )
                    {
                        m_showInfo = true;
                    }
                    if( ImGui::IsMouseClicked( 2 ) )
                    {
                        CenterAtTime( crash.time );
                    }
                }
#else
                ImGui::TextColored( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), "Crashed" );
#endif
            }
            ImGui::SameLine();
            ImGui::TextDisabled( "%s top level zones", RealToString( t->timeline.size(), true ) );
            idx++;
        }
        if( upIdx > 0 )
        {
            std::swap( m_threadOrder[upIdx], m_threadOrder[upIdx-1] );
        }
        if( downIdx >= 0 && downIdx < m_threadOrder.size() - 1 )
        {
            std::swap( m_threadOrder[downIdx], m_threadOrder[downIdx+1] );
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
            ImGui::Checkbox( fd->name == 0 ? "Frames" : m_worker.GetString( fd->name ), &Vis( fd ).visible );
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
    ImGui::SetNextWindowSize( ImVec2( 1200, 600 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Messages", &m_showMessages );

    size_t tsz = 0;
    for( const auto& t : m_threadOrder ) if( !t->messages.empty() ) tsz++;

#ifdef TRACY_EXTENDED_FONT
    auto expand = ImGui::TreeNode( ICON_FA_RANDOM " Visible threads:" );
#else
    auto expand = ImGui::TreeNode( "Visible threads:" );
#endif
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", tsz );
    if( expand )
    {
        auto& crash = m_worker.GetCrashEvent();

        if( ImGui::SmallButton( "Select all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleMsgThread( t->id ) = true;
            }
        }
        ImGui::SameLine();
        if( ImGui::SmallButton( "Unselect all" ) )
        {
            for( const auto& t : m_threadOrder )
            {
                VisibleMsgThread( t->id ) = false;
            }
        }

        int idx = 0;
        for( const auto& t : m_threadOrder )
        {
            if( t->messages.empty() ) continue;
            ImGui::PushID( idx++ );
            ImGui::Checkbox( m_worker.GetThreadString( t->id ), &VisibleMsgThread( t->id ) );
            ImGui::PopID();
            ImGui::SameLine();
            ImGui::TextDisabled( "(%s)", RealToString( t->messages.size(), true ) );
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
    const auto w = ImGui::GetWindowWidth();
    static bool widthSet = false;
    ImGui::Columns( 3 );
    if( !widthSet )
    {
        widthSet = true;
        ImGui::SetColumnWidth( 0, w * 0.07f );
        ImGui::SetColumnWidth( 1, w * 0.13f );
        ImGui::SetColumnWidth( 2, w * 0.8f );
    }
    ImGui::TextUnformatted( "Time" );
    ImGui::SameLine();
    DrawHelpMarker( "Click on message to center timeline on it." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Thread" );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Message" );
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
                ImGui::SetScrollHereY();
                m_msgToFocus = nullptr;
            }
            ImGui::PopID();
            ImGui::NextColumn();
            ImGui::TextUnformatted( m_worker.GetThreadString( v->thread ) );
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
    if( m_shortcut == ShortcutAction::OpenFind ) ImGui::SetNextWindowFocus();

    ImGui::Begin( "Find zone", &m_findZone.show );
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
    findClicked |= ImGui::InputTextWithHint( "###findzone", "Enter zone name to search for", m_findZone.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
    ImGui::PopItemWidth();

#ifdef TRACY_EXTENDED_FONT
    findClicked |= ImGui::Button( ICON_FA_SEARCH " Find" );
#else
    findClicked |= ImGui::Button( "Find" );
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
    ImGui::SameLine();

    ImGui::Checkbox( "Ignore case", &m_findZone.ignoreCase );

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
        if( m_findZone.scheduleResetMatch )
        {
            m_findZone.scheduleResetMatch = false;
            m_findZone.ResetMatch();
        }

        ImGui::Separator();

        auto& zoneData = m_worker.GetZonesForSourceLocation( m_findZone.match[m_findZone.selMatch] );
        if( ImGui::TreeNodeEx( "Histogram", ImGuiTreeNodeFlags_DefaultOpen ) )
        {
            const auto ty = ImGui::GetFontSize();

            auto& zones = zoneData.zones;
            const auto tmin = m_findZone.selfTime ? zoneData.selfMin : zoneData.min;
            const auto tmax = m_findZone.selfTime ? zoneData.selfMax : zoneData.max;
            const auto timeTotal = m_findZone.selfTime ? zoneData.selfTotal : zoneData.total;

            const auto zsz = zones.size();
            if( m_findZone.sortedNum != zsz )
            {
                auto& vec = m_findZone.sorted;
                vec.reserve( zsz );
                int64_t total = m_findZone.total;
                size_t i;
                if( m_findZone.selfTime )
                {
                    for( i=m_findZone.sortedNum; i<zsz; i++ )
                    {
                        auto& zone = *zones[i].zone;
                        if( zone.end < 0 ) break;
                        const auto t = zone.end - zone.start - GetZoneChildTimeFast( zone );
                        vec.emplace_back( t );
                        total += t;
                    }
                }
                else
                {
                    for( i=m_findZone.sortedNum; i<zsz; i++ )
                    {
                        auto& zone = *zones[i].zone;
                        if( zone.end < 0 ) break;
                        const auto t = zone.end - zone.start;
                        vec.emplace_back( t );
                        total += t;
                    }
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
                    if( m_findZone.selfTime )
                    {
                        for( size_t i=m_findZone.selSortNum; i<m_findZone.sortedNum; i++ )
                        {
                            auto& ev = zones[i];
                            if( selGroup == GetSelectionTarget( ev, groupBy ) )
                            {
                                const auto t = ev.zone->end - ev.zone->start - GetZoneChildTimeFast( *ev.zone );
                                vec.emplace_back( t );
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
                                const auto t = ev.zone->end - ev.zone->start;
                                vec.emplace_back( t );
                                act++;
                                total += t;
                            }
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
                DrawHelpMarker( "Show total time taken by calls in each bin instead of call counts." );
                ImGui::SameLine();
                if( ImGui::Checkbox( "Self time", &m_findZone.selfTime ) )
                {
                    m_findZone.scheduleResetMatch = true;
                }
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.2f%%)", 100.f * zoneData.selfTotal / zoneData.total );

                TextDisabledUnformatted( "Time range:" );
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
                                while( zit != sorted.end() && *zit == 0 ) ++zit;
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
                            auto zit = sorted.begin();
                            while( zit != sorted.end() && *zit == 0 ) ++zit;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
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
                        if( m_findZone.sorted.size() > 1 )
                        {
                            const auto sz = m_findZone.sorted.size();
                            const auto avg = m_findZone.average;
                            const auto ss = zoneData.sumSq - 2. * zoneData.total * avg + avg * avg * sz;
                            const auto sd = sqrt( ss / ( sz - 1 ) );

                            ImGui::SameLine();
                            ImGui::Spacing();
                            ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                            TextFocused( "\xcf\x83:", TimeToString( sd ) );
#else
                            TextFocused( "s:", TimeToString( sd ) );
#endif
                            if( ImGui::IsItemHovered() )
                            {
                                ImGui::BeginTooltip();
                                ImGui::Text( "Standard deviation" );
                                ImGui::EndTooltip();
                            }
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
                        ImGui::TextUnformatted( "Average time" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0xAA/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Median time" );
                        ImGui::Checkbox( "###draw2", &m_findZone.drawSelAvgMed );
                        ImGui::SameLine();
                        ImGui::ColorButton( "c3", ImVec4( 0xFF/255.f, 0xAA/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::TextUnformatted( "Group average" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Group average" );
                        }
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c4", ImVec4( 0x44/255.f, 0xDD/255.f, 0x44/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        if( m_findZone.selGroup != m_findZone.Unselected )
                        {
                            ImGui::TextUnformatted( "Group median" );
                        }
                        else
                        {
                            TextDisabledUnformatted( "Group median" );
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
                                        auto txt = TimeToString( tt );
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
                                    auto txt = TimeToString( tt );
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
                            TextDisabledUnformatted( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            TextFocused( "Count:", RealToString( bins[bin], true ) );
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
        ImGui::TextUnformatted( "Found zones:" );
        ImGui::SameLine();
        DrawHelpMarker( "Left click to highlight entry. Right click to clear selection." );

        bool groupChanged = false;
        ImGui::TextUnformatted( "Group by:" );
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

        ImGui::TextUnformatted( "Sort by:" );
        ImGui::SameLine();
        ImGui::RadioButton( "Order", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Order );
        ImGui::SameLine();
        ImGui::RadioButton( "Count", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Count );
        ImGui::SameLine();
        ImGui::RadioButton( "Time", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Time );
        ImGui::SameLine();
        ImGui::RadioButton( "MTPC", (int*)( &m_findZone.sortBy ), (int)FindZone::SortBy::Mtpc );
        ImGui::SameLine();
        DrawHelpMarker( "Mean time per call" );

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
            auto timespan = end - ev.zone->start;
            if( timespan == 0 )
            {
                processed++;
                continue;
            }
            if( m_findZone.selfTime ) timespan -= GetZoneChildTimeFast( *ev.zone );

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
        case FindZone::SortBy::Mtpc:
            pdqsort_branchless( groups.begin(), groups.end(), []( const auto& lhs, const auto& rhs ) { return double( lhs->second.time ) / lhs->second.zones.size() > double( rhs->second.time ) / rhs->second.zones.size(); } );
            break;
        default:
            assert( false );
            break;
        }

        ImGui::BeginChild( "##zonesScroll", ImVec2( ImGui::GetWindowContentRegionWidth(), std::max( 200.f, ImGui::GetContentRegionAvail().y ) ) );
        idx = 0;
        if( groupBy == FindZone::GroupBy::Callstack )
        {
            const auto gsz = groups.size();
            if( gsz > 0 )
            {
                if( m_findZone.selCs > gsz ) m_findZone.selCs = gsz;
                const auto group = groups[m_findZone.selCs];

                const bool selHilite = m_findZone.selGroup == group->first;
                if( selHilite ) SetButtonHighlightColor();
#ifdef TRACY_EXTENDED_FONT
                if( ImGui::SmallButton( " " ICON_FA_CHECK " " ) )
#else
                if( ImGui::SmallButton( "Select" ) )
#endif
                {
                    m_findZone.selGroup = group->first;
                    m_findZone.ResetSelection();
                }
                if( selHilite ) ImGui::PopStyleColor( 3 );
                ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                if( ImGui::SmallButton( " " ICON_FA_CARET_LEFT " " ) )
#else
                if( ImGui::SmallButton( " < " ) )
#endif
                {
                    m_findZone.selCs = std::max( m_findZone.selCs - 1, 0 );
                }
                ImGui::SameLine();
                ImGui::Text( "%s / %s", RealToString( m_findZone.selCs + 1, true ), RealToString( gsz, true ) );
                ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                if( ImGui::SmallButton( " " ICON_FA_CARET_RIGHT " " ) )
#else
                if( ImGui::SmallButton( " > " ) )
#endif
                {
                    m_findZone.selCs = std::min<int>( m_findZone.selCs + 1, gsz - 1 );
                }

                ImGui::SameLine();
                TextFocused( "Count:", RealToString( group->second.zones.size(), true ) );
                ImGui::SameLine();
                TextFocused( "Time:", TimeToString( group->second.time ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%.2f%%)", group->second.time * 100.f / zoneData.total );

                if( group->first != 0 )
                {
                    ImGui::SameLine();
                    int idx = 0;
#ifdef TRACY_EXTENDED_FONT
                    SmallCallstackButton( " " ICON_FA_ALIGN_JUSTIFY " ", group->first, idx, false );
#else
                    SmallCallstackButton( "Call stack", group->first, idx, false );
#endif

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
                                    TextDisabledUnformatted( "--" );
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
                    DrawZoneList( group->second.zones );
                }
            }
        }
        else
        {
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
                        auto& frameData = *m_worker.GetCallstackFrame( *callstack.begin() );
                        hdrString = m_worker.GetString( frameData.data[frameData.size-1].name );
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
                if( expand )
                {
                    DrawZoneList( v->second.zones );
                }
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

void View::DrawZoneList( const Vector<ZoneEvent*>& zones )
{
    ImGui::Columns( 3 );
    ImGui::Separator();
    if( ImGui::SmallButton( "Time from start" ) ) m_findZone.tableSortBy = FindZone::TableSortBy::Starttime;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Execution time" ) )  m_findZone.tableSortBy = FindZone::TableSortBy::Runtime;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Name" ) )  m_findZone.tableSortBy = FindZone::TableSortBy::Name;
    ImGui::SameLine();
    DrawHelpMarker( "Only displayed if custom zone name is set." );
    ImGui::NextColumn();
    ImGui::Separator();

    const Vector<ZoneEvent*>* zonesToIterate = &zones;
    Vector<ZoneEvent*> sortedZones;

    if( m_findZone.tableSortBy != FindZone::TableSortBy::Starttime )
    {
        zonesToIterate = &sortedZones;
        sortedZones.reserve_and_use( zones.size() );
        memcpy( sortedZones.data(), zones.data(), zones.size() * sizeof( ZoneEvent* ) );

        switch( m_findZone.tableSortBy )
        {
        case FindZone::TableSortBy::Runtime:
            if( m_findZone.selfTime )
            {
                pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                    return m_worker.GetZoneEndDirect( *lhs ) - lhs->start - this->GetZoneChildTimeFast( *lhs ) >
                        m_worker.GetZoneEndDirect( *rhs ) - rhs->start - this->GetZoneChildTimeFast( *rhs );
                } );
            }
            else
            {
                pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                    return m_worker.GetZoneEndDirect( *lhs ) - lhs->start > m_worker.GetZoneEndDirect( *rhs ) - rhs->start;
                } );
            }
            break;
        case FindZone::TableSortBy::Name:
            pdqsort_branchless( sortedZones.begin(), sortedZones.end(), [this]( const auto& lhs, const auto& rhs ) {
                if( lhs->name.active != rhs->name.active ) return lhs->name.active > rhs->name.active;
                return strcmp( m_worker.GetString( lhs->name ), m_worker.GetString( rhs->name ) ) < 0;
            } );
            break;
        default:
            assert( false );
            break;
        }
    }

    for( auto& ev : *zonesToIterate )
    {
        const auto end = m_worker.GetZoneEndDirect( *ev );
        auto timespan = end - ev->start;
        if( m_findZone.selfTime ) timespan -= GetZoneChildTimeFast( *ev );

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
        ImGui::TextUnformatted( TimeToString( timespan ) );
        ImGui::NextColumn();
        if( ev->name.active )
        {
            ImGui::TextUnformatted( m_worker.GetString( ev->name ) );
        }
        ImGui::NextColumn();

        ImGui::PopID();
    }
    ImGui::Columns( 1 );
    ImGui::Separator();
    ImGui::TreePop();
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
        DrawWaitingDots( s_time );
        ImGui::End();
        return;
    }

#ifdef TRACY_EXTENDED_FONT
    ImGui::TextColored( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
    ImGui::SameLine();
#endif
    TextDisabledUnformatted( "This trace:" );
    ImGui::SameLine();
    ImGui::TextUnformatted( m_worker.GetCaptureName().c_str() );

#ifdef TRACY_EXTENDED_FONT
    ImGui::TextColored( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
    ImGui::SameLine();
#endif
    TextDisabledUnformatted( "External trace:" );
    ImGui::SameLine();
    ImGui::TextUnformatted( m_compare.second->GetCaptureName().c_str() );
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

    bool findClicked = false;

    ImGui::PushItemWidth( -0.01f );
    findClicked |= ImGui::InputTextWithHint( "###compare", "Enter zone name to search for", m_compare.pattern, 1024, ImGuiInputTextFlags_EnterReturnsTrue );
    ImGui::PopItemWidth();

#ifdef TRACY_EXTENDED_FONT
    findClicked |= ImGui::Button( ICON_FA_SEARCH " Find" );
#else
    findClicked |= ImGui::Button( "Find" );
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

    if( ImGui::TreeNodeEx( "Matched source locations", ImGuiTreeNodeFlags_DefaultOpen ) )
    {
        ImGui::Separator();
        ImGui::Columns( 2 );
#ifdef TRACY_EXTENDED_FONT
        ImGui::TextColored( ImVec4( 0xDD/255.f, 0xDD/255.f, 0x22/255.f, 1.f ), ICON_FA_LEMON );
        ImGui::SameLine();
#endif
        ImGui::TextUnformatted( "This trace" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", m_compare.match[0].size() );
        ImGui::NextColumn();
#ifdef TRACY_EXTENDED_FONT
        ImGui::TextColored( ImVec4( 0xDD/255.f, 0x22/255.f, 0x22/255.f, 1.f ), ICON_FA_GEM );
        ImGui::SameLine();
#endif
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
            DrawHelpMarker( "Show total time taken by calls in each bin instead of call counts." );
            ImGui::SameLine();
            ImGui::Checkbox( "Normalize values", &m_compare.normalize );
            ImGui::SameLine();
            DrawHelpMarker( "Normalization will fudge reported data values!" );

            TextDisabledUnformatted( "Time range:" );
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
                            const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
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
                    ImGui::SameLine();
                    ImGui::TextDisabled( "(%.2f%%)", ( zoneData0.total * adj0 ) / ( zoneData1.total * adj1 ) * 100 );
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
                    if( sorted[0].size() > 1 )
                    {
                        const auto sz = sorted[0].size();
                        const auto avg = m_compare.average[0];
                        const auto ss = zoneData0.sumSq - 2. * zoneData0.total * avg + avg * avg * sz;
                        const auto sd = sqrt( ss / ( sz - 1 ) );

                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                        ImGui::TextColored( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
                        TextFocused( "\xcf\x83 (this):", TimeToString( sd ) );
#else
                        TextFocused( "s (this):", TimeToString( sd ) );
#endif
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            ImGui::Text( "Standard deviation" );
                            ImGui::EndTooltip();
                        }
                    }


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
                    if( sorted[1].size() > 1 )
                    {
                        const auto sz = sorted[1].size();
                        const auto avg = m_compare.average[1];
                        const auto ss = zoneData1.sumSq - 2. * zoneData1.total * avg + avg * avg * sz;
                        const auto sd = sqrt( ss / ( sz - 1 ) );

                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                        ImGui::TextColored( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
                        TextFocused( "\xcf\x83 (ext.):", TimeToString( sd ) );
#else
                        TextFocused( "s (ext.):", TimeToString( sd ) );
#endif
                        if( ImGui::IsItemHovered() )
                        {
                            ImGui::BeginTooltip();
                            ImGui::Text( "Standard deviation" );
                            ImGui::EndTooltip();
                        }
                    }

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
                    ImGui::TextUnformatted( "This trace" );
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
                    ImGui::TextUnformatted( "External trace" );
                    ImGui::SameLine();
                    ImGui::Spacing();
                    ImGui::SameLine();

                    ImGui::ColorButton( "c3", ImVec4( 0x44/255.f, 0xBB/255.f, 0xBB/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                    ImGui::SameLine();
                    ImGui::TextUnformatted( "Overlap" );

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
                                    auto txt = TimeToString( tt );
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
                                auto txt = TimeToString( tt );
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
                        TextDisabledUnformatted( "Time range:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                        TextDisabledUnformatted( "Count:" );
                        ImGui::SameLine();
                        ImGui::Text( "%s / %s", RealToString( floor( bins[bin].v0 ), true ), RealToString( floor( bins[bin].v1 ), true ) );
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
#ifdef TRACY_EXTENDED_FONT
                        ImGui::TextColored( ImVec4( 0xDD/511.f, 0xDD/511.f, 0x22/511.f, 1.f ), ICON_FA_LEMON );
                        ImGui::SameLine();
#endif
                        TextDisabledUnformatted( "[this trace] /" );
                        ImGui::SameLine();
#ifdef TRACY_EXTENDED_FONT
                        ImGui::TextColored( ImVec4( 0xDD/511.f, 0x22/511.f, 0x22/511.f, 1.f ), ICON_FA_GEM );
                        ImGui::SameLine();
#endif
                        TextDisabledUnformatted( "[external trace])" );
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
    ImGui::SetNextWindowSize( ImVec2( 1000, 600 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Statistics", &m_showStatistics );
#ifdef TRACY_NO_STATISTICS
    ImGui::TextWrapped( "Collection of statistical data is disabled in this build." );
    ImGui::TextWrapped( "Rebuild without the TRACY_NO_STATISTICS macro to enable statistics view." );
#else
    if( !m_worker.AreSourceLocationZonesReady() )
    {
        ImGui::TextWrapped( "Please wait, computing data..." );
        DrawWaitingDots( s_time );
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

    const auto w = ImGui::GetWindowWidth();
    static bool widthSet = false;
    ImGui::Columns( 5 );
    if( !widthSet )
    {
        widthSet = true;
        ImGui::SetColumnWidth( 0, w * 0.3f );
        ImGui::SetColumnWidth( 1, w * 0.4f );
        ImGui::SetColumnWidth( 2, w * 0.1f );
        ImGui::SetColumnWidth( 3, w * 0.1f );
        ImGui::SetColumnWidth( 4, w * 0.1f );
    }
    ImGui::Separator();
    ImGui::TextUnformatted( "Name" );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Location" );
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Total time" ) ) m_statSort = 0;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "Counts" ) ) m_statSort = 1;
    ImGui::NextColumn();
    if( ImGui::SmallButton( "MTPC" ) ) m_statSort = 2;
    ImGui::SameLine();
    DrawHelpMarker( "Mean time per call" );
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
        float indentVal = 0.f;
        if( m_statBuzzAnim.Match( v->first ) )
        {
            const auto time = m_statBuzzAnim.Time();
            indentVal = sin( time * 60.f ) * 10.f * time;
            ImGui::Indent( indentVal );
        }
        const auto file = m_worker.GetString( srcloc.file );
        ImGui::TextDisabled( "%s:%i", file, srcloc.line );
        if( ImGui::IsItemClicked( 1 ) )
        {
            if( FileExists( file ) )
            {
                SetTextEditorFile( file, srcloc.line );
            }
            else
            {
                m_statBuzzAnim.Enable( v->first, 0.5f );
            }
        }
        if( indentVal != 0.f )
        {
            ImGui::Unindent( indentVal );
        }
        ImGui::NextColumn();
        ImGui::TextUnformatted( TimeToString( m_statSelf ? v->second.selfTotal : v->second.total ) );
        ImGui::NextColumn();
        ImGui::TextUnformatted( RealToString( v->second.zones.size(), true ) );
        ImGui::NextColumn();
        ImGui::TextUnformatted( TimeToString( ( m_statSelf ? v->second.selfTotal : v->second.total ) / v->second.zones.size() ) );
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
    ImGui::SetNextWindowSize( ImVec2( 1200, 500 ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Call stack", &show );

#ifdef TRACY_EXTENDED_FONT
    ImGui::Checkbox( ICON_FA_AT " Show frame addresses", &m_showCallstackFrameAddress );
#else
    ImGui::Checkbox( "Show frame addresses", &m_showCallstackFrameAddress );
#endif

    auto& cs = m_worker.GetCallstack( m_callstackInfoWindow );

    const auto w = ImGui::GetWindowWidth();
    static bool widthSet = false;
    ImGui::Columns( 3 );
    if( !widthSet )
    {
        widthSet = true;
        ImGui::SetColumnWidth( 0, w * 0.05f );
        ImGui::SetColumnWidth( 1, w * 0.475f );
        ImGui::SetColumnWidth( 2, w * 0.475f );
    }
    ImGui::TextUnformatted( "Frame" );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Function" );
    ImGui::SameLine();
    DrawHelpMarker( "Click on entry to copy it to clipboard." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Location" );
    ImGui::SameLine();
    DrawHelpMarker( "Click on entry to copy it to clipboard.\nRight click on entry to try to open source file." );
    ImGui::NextColumn();

    int fidx = 0;
    int bidx = 0;
    for( auto& entry : cs )
    {
        auto frameData = m_worker.GetCallstackFrame( entry );
        if( !frameData )
        {
            ImGui::Separator();
            ImGui::Text( "%i", fidx++ );
            ImGui::NextColumn();
            char buf[32];
            sprintf( buf, "%p", (void*)m_worker.GetCanonicalPointer( entry ) );
            ImGui::TextUnformatted( buf );
            if( ImGui::IsItemClicked() )
            {
                ImGui::SetClipboardText( buf );
            }
            ImGui::NextColumn();
            ImGui::NextColumn();
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

                bidx++;

                ImGui::Separator();
                if( f == fsz-1 )
                {
                    ImGui::Text( "%i", fidx++ );
                }
                else
                {
                    TextDisabledUnformatted( "inline" );
                }
                ImGui::NextColumn();

                ImGui::TextWrapped( "%s", txt );
                if( ImGui::IsItemClicked() )
                {
                    ImGui::SetClipboardText( txt );
                }
                ImGui::NextColumn();
                ImGui::PushTextWrapPos( 0.0f );
                float indentVal = 0.f;
                if( m_callstackBuzzAnim.Match( bidx ) )
                {
                    const auto time = m_callstackBuzzAnim.Time();
                    indentVal = sin( time * 60.f ) * 10.f * time;
                    ImGui::Indent( indentVal );
                }
                txt = m_worker.GetString( frame.file );
                if( m_showCallstackFrameAddress )
                {
                    if( entry.sel == 0 )
                    {
                        ImGui::TextDisabled( "0x%" PRIx64, entry.idx );
                        if( ImGui::IsItemClicked() )
                        {
                            char tmp[32];
                            sprintf( tmp, "0x%" PRIx64, entry.idx );
                            ImGui::SetClipboardText( tmp );
                        }
                    }
                    else
                    {
                        ImGui::TextDisabled( "Custom #%" PRIu64, entry.idx );
                    }
                }
                else
                {
                    if( frame.line == 0 )
                    {
                        TextDisabledUnformatted( txt );
                    }
                    else
                    {
                        ImGui::TextDisabled( "%s:%i", txt, frame.line );
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
                        SetTextEditorFile( txt, frame.line );
                    }
                    else
                    {
                        m_callstackBuzzAnim.Enable( bidx, 0.5f );
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
    ImGui::Begin( "Memory allocation", &show, ImGuiWindowFlags_AlwaysAutoResize );

    const auto& mem = m_worker.GetMemData();
    const auto& ev = mem.data[m_memoryAllocInfoWindow];
    const auto tidAlloc = m_worker.DecompressThread( ev.threadAlloc );
    const auto tidFree = m_worker.DecompressThread( ev.threadFree );
    int idx = 0;

#ifdef TRACY_EXTENDED_FONT
    if( ImGui::Button( ICON_FA_MICROSCOPE " Zoom to allocation" ) )
#else
    if( ImGui::Button( "Zoom to allocation" ) )
#endif
    {
        ZoomToRange( ev.timeAlloc, ev.timeFree >= 0 ? ev.timeFree : m_worker.GetLastTime() );
    }

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
        TextDisabledUnformatted( "Allocation still active" );
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
            TextDisabledUnformatted( "(same zone)" );
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
    ImGui::TextDisabled( "Trace version:" );
    ImGui::SameLine();
    const auto version = m_worker.GetTraceVersion();
    ImGui::Text( "%i.%i.%i", version >> 16, ( version >> 8 ) & 0xFF, version & 0xFF );
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
            const auto midSz = vec.size();
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
            auto mid = vec.begin() + midSz;
            pdqsort_branchless( mid, m_frameSortData.data.end() );
            std::inplace_merge( vec.begin(), mid, vec.end() );

            const auto vsz = vec.size();
            m_frameSortData.average = float( total ) / vsz;
            m_frameSortData.median = vec[vsz/2];
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

            if( tmin != std::numeric_limits<int64_t>::max() )
            {
                ImGui::Checkbox( "Log values", &m_frameSortData.logVal );
                ImGui::SameLine();
                ImGui::Checkbox( "Log time", &m_frameSortData.logTime );

                TextDisabledUnformatted( "Time range:" );
                ImGui::SameLine();
                ImGui::Text( "%s - %s (%s)", TimeToString( tmin ), TimeToString( tmax ), TimeToString( tmax - tmin ) );

                TextDisabledUnformatted( "FPS range:" );
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
                            while( fit != frames.end() && *fit == 0 ) ++fit;
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
                            while( fit != frames.end() && *fit == 0 ) ++fit;
                            for( int64_t i=0; i<numBins; i++ )
                            {
                                const auto nextBinVal = tmin + ( i+1 ) * zmax / numBins;
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
                        ImGui::TextUnformatted( "Average time" );
                        ImGui::SameLine();
                        ImGui::Spacing();
                        ImGui::SameLine();
                        ImGui::ColorButton( "c2", ImVec4( 0x44/255.f, 0x88/255.f, 0xFF/255.f, 1.f ), ImGuiColorEditFlags_NoTooltip );
                        ImGui::SameLine();
                        ImGui::TextUnformatted( "Median time" );

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
                                        auto txt = TimeToString( tt );
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
                                    auto txt = TimeToString( tt );
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
                            TextDisabledUnformatted( "Time range:" );
                            ImGui::SameLine();
                            ImGui::Text( "%s - %s", TimeToString( t0 ), TimeToString( t1 ) );
                            ImGui::SameLine();
                            ImGui::TextDisabled( "(%s FPS - %s FPS)", RealToString( round( 1000000000.0 / t0 ), true ), RealToString( round( 1000000000.0 / t1 ), true ) );
                            TextFocused( "Count:", RealToString( bins[bin], true ) );
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
        TextDisabledUnformatted( "Reason:" );
        ImGui::SameLine();
        ImGui::TextWrapped( "%s", m_worker.GetString( crash.message ) );
#ifdef TRACY_EXTENDED_FONT
        if( ImGui::Button( ICON_FA_MICROSCOPE " Focus" ) )
#else
        if( ImGui::Button( "Focus" ) )
#endif
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

void View::DrawGoToFrame()
{
    static int frameNum = 1;

    const bool mainFrameSet = m_frames->name == 0;
    const auto numFrames = mainFrameSet ? m_frames->frames.size() - 1 : m_frames->frames.size();
    const auto frameOffset = mainFrameSet ? 0 : 1;

    ImGui::Begin( "Go to frame", &m_goToFrame, ImGuiWindowFlags_AlwaysAutoResize );
    ImGui::InputInt( "Frame", &frameNum );
    frameNum = std::min( std::max( frameNum, 1 ), int( numFrames ) );
    if( ImGui::Button( "Go to" ) )
    {
        ZoomToRange( m_worker.GetFrameBegin( *m_frames, frameNum - frameOffset ), m_worker.GetFrameEnd( *m_frames, frameNum - frameOffset ) );
    }
    ImGui::End();
}

void View::DrawLockInfoWindow()
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
        if( timeAnnounce == 0 )
        {
            timeAnnounce = lock.timeline.front().ptr->time;
        }
        if( timeTerminate == 0 )
        {
            timeTerminate = lock.timeline.back().ptr->time;
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
                holdTotalTime += v.ptr->time - holdStartTime;
                holdState = false;
            }
        }
        else
        {
            if( v.lockCount != 0 )
            {
                holdStartTime = v.ptr->time;
                holdState = true;
            }
        }
        if( waitState )
        {
            if( v.waitList == 0 )
            {
                waitTotalTime += v.ptr->time - waitStartTime;
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
                waitStartTime = v.ptr->time;
                waitState = true;
                maxWaitingThreads = std::max<uint32_t>( maxWaitingThreads, TracyCountBits( v.waitList ) );
            }
        }
    }

    bool visible = true;
    ImGui::Begin( "Lock info", &visible, ImGuiWindowFlags_AlwaysAutoResize );
    ImGui::Text( "Lock #%" PRIu32 ": %s", m_lockInfoWindow, m_worker.GetString( srcloc.function ) );
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
    ImGui::Text( "%s:%i", fileName, srcloc.line );
    if( ImGui::IsItemClicked( 1 ) )
    {
        if( FileExists( fileName ) )
        {
            SetTextEditorFile( fileName, srcloc.line );
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
    TextFocused( "Lock events:", RealToString( lock.timeline.size(), true ) );
    ImGui::Separator();

    const auto announce = timeAnnounce - m_worker.GetTimeBegin();
    const auto terminate = timeTerminate - m_worker.GetTimeBegin();
    const auto lifetime = timeTerminate - timeAnnounce;
    const auto traceLen = m_worker.GetLastTime() - m_worker.GetTimeBegin();

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
    TextFocused( "Max waiting threads:", RealToString( maxWaitingThreads, true ) );
    ImGui::Separator();

    const auto threadList = ImGui::TreeNode( "Thread list" );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%zu)", lock.threadList.size() );
    if( threadList )
    {
        for( const auto& t : lock.threadList )
        {
            ImGui::TextUnformatted( m_worker.GetThreadString( t ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(0x%" PRIX64 ")", t );
        }
        ImGui::TreePop();
    }
    ImGui::End();
    if( !visible ) m_lockInfoWindow = InvalidId;
}

template<class T>
void View::ListMemData( T ptr, T end, std::function<void(T&)> DrawAddress, const char* id, int64_t startTime )
{
    if( startTime == -1 ) startTime = m_worker.GetTimeBegin();

    const auto& style = ImGui::GetStyle();
    const auto dist = std::distance( ptr, end ) + 1;
    const auto ty = ImGui::GetTextLineHeight() + style.ItemSpacing.y;

    ImGui::BeginChild( id ? id : "##memScroll", ImVec2( 0, std::max( ty * std::min<int64_t>( dist, 5 ), std::min( ty * dist, ImGui::GetContentRegionAvail().y ) ) ) );
    ImGui::Columns( 8 );
    ImGui::TextUnformatted( "Address" );
    ImGui::SameLine();
    DrawHelpMarker( "Click on address to display memory allocation info window.\nMiddle click to zoom to allocation range." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Size" );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Appeared at" );
    ImGui::SameLine();
    DrawHelpMarker( "Click on entry to center timeline at the memory allocation time." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Duration" );
    ImGui::SameLine();
    DrawHelpMarker( "Active allocations are displayed using green color.\nClick on entry to center timeline at the memory release time." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Thread" );
    ImGui::SameLine();
    DrawHelpMarker( "Shows one thread if alloc and free was performed on the same thread.\nOtherwise two threads are displayed in order: alloc, free." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Zone alloc" );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Zone free" );
    ImGui::SameLine();
    DrawHelpMarker( "If alloc and free is performed in the same zone, it is displayed in yellow color." );
    ImGui::NextColumn();
    ImGui::TextUnformatted( "Call stack" );
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
        if( ImGui::IsItemClicked( 2 ) )
        {
            ZoomToRange( v->timeAlloc, v->timeFree >= 0 ? v->timeFree : m_worker.GetLastTime() );
        }
        if( ImGui::IsItemHovered() )
        {
            m_memoryAllocHover = arrIdx;
            m_memoryAllocHoverWait = 2;
        }
        ImGui::NextColumn();
        ImGui::TextUnformatted( MemSizeToString( v->size ) );
        ImGui::NextColumn();
        ImGui::PushID( idx++ );
        if( ImGui::Selectable( TimeToString( v->timeAlloc - startTime ) ) )
        {
            CenterAtTime( v->timeAlloc );
        }
        ImGui::PopID();
        ImGui::NextColumn();
        if( v->timeFree < 0 )
        {
            ImGui::TextColored( ImVec4( 0.6f, 1.f, 0.6f, 1.f ), "%s", TimeToString( m_worker.GetLastTime() - v->timeAlloc ) );
            ImGui::NextColumn();
            ImGui::TextUnformatted( m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ) );
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
                ImGui::TextUnformatted( m_worker.GetThreadString( m_worker.DecompressThread( v->threadAlloc ) ) );
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
            ImGui::TextUnformatted( "-" );
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
                ImGui::TextUnformatted( "-" );
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
            TextDisabledUnformatted( "[alloc]" );
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
            TextDisabledUnformatted( "[free]" );
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

static tracy_force_inline CallstackFrameTree* GetFrameTreeItem( std::vector<CallstackFrameTree>& tree, CallstackFrameId idx, const Worker& worker, bool groupByName )
{
    std::vector<CallstackFrameTree>::iterator it;
    if( groupByName )
    {
        auto& frameData = *worker.GetCallstackFrame( idx );
        auto& frame = frameData.data[frameData.size-1];
        auto fidx = frame.name.idx;

        it = std::find_if( tree.begin(), tree.end(), [&worker, fidx] ( const auto& v ) {
            auto& frameData = *worker.GetCallstackFrame( v.frame );
            auto& frame = frameData.data[frameData.size-1];
            return frame.name.idx == fidx;
        } );
    }
    else
    {
        it = std::find_if( tree.begin(), tree.end(), [idx] ( const auto& v ) { return v.frame.data == idx.data; } );
    }
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

flat_hash_map<uint32_t, View::PathData, nohash<uint32_t>> View::GetCallstackPaths( const MemData& mem ) const
{
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
    return pathSum;
}

std::vector<CallstackFrameTree> View::GetCallstackFrameTreeBottomUp( const MemData& mem ) const
{
    std::vector<CallstackFrameTree> root;
    auto pathSum = GetCallstackPaths( mem );
    for( auto& path : pathSum )
    {
        auto& cs = m_worker.GetCallstack( path.first );

        auto base = cs.back();
        auto treePtr = GetFrameTreeItem( root, base, m_worker, m_groupCallstackTreeByNameBottomUp );
        treePtr->count += path.second.cnt;
        treePtr->alloc += path.second.mem;
        treePtr->callstacks.emplace( path.first );

        for( int i = int( cs.size() ) - 2; i >= 0; i-- )
        {
            treePtr = GetFrameTreeItem( treePtr->children, cs[i], m_worker, m_groupCallstackTreeByNameBottomUp );
            treePtr->count += path.second.cnt;
            treePtr->alloc += path.second.mem;
            treePtr->callstacks.emplace( path.first );
        }
    }
    return root;
}

std::vector<CallstackFrameTree> View::GetCallstackFrameTreeTopDown( const MemData& mem ) const
{
    std::vector<CallstackFrameTree> root;
    auto pathSum = GetCallstackPaths( mem );
    for( auto& path : pathSum )
    {
        auto& cs = m_worker.GetCallstack( path.first );

        auto base = cs.front();
        auto treePtr = GetFrameTreeItem( root, base, m_worker, m_groupCallstackTreeByNameTopDown );
        treePtr->count += path.second.cnt;
        treePtr->alloc += path.second.mem;
        treePtr->callstacks.emplace( path.first );

        for( int i = 1; i < cs.size(); i++ )
        {
            treePtr = GetFrameTreeItem( treePtr->children, cs[i], m_worker, m_groupCallstackTreeByNameTopDown );
            treePtr->count += path.second.cnt;
            treePtr->alloc += path.second.mem;
            treePtr->callstacks.emplace( path.first );
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
    DrawHelpMarker( "Don't show allocations beyond the middle of timeline display (it is indicated by purple line)." );

    const auto zvMid = m_zvStart + ( m_zvEnd - m_zvStart ) / 2;

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::TreeNode( ICON_FA_AT " Allocations" ) )
#else
    if( ImGui::TreeNode( "Allocations" ) )
#endif
    {
        ImGui::InputTextWithHint( "###address", "Enter memory address to search for", m_memInfo.pattern, 1024 );
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
                ImGui::TextUnformatted( "Found no allocations at given address" );
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
    if( ImGui::TreeNode( ICON_FA_ALIGN_JUSTIFY " Bottom-up call stack tree" ) )
#else
    if( ImGui::TreeNode( "Bottom-up call stack tree" ) )
#endif
    {
        ImGui::Checkbox( "Group by function name", &m_groupCallstackTreeByNameBottomUp );
        ImGui::SameLine();
        DrawHelpMarker( "If enabled, only one source location will be displayed (which may be incorrect)." );
        TextDisabledUnformatted( "Press ctrl key to display allocation info tooltip." );
        TextDisabledUnformatted( "Right click on function name to display allocations list. Right click on file name to open source file." );

        auto& mem = m_worker.GetMemData();
        auto tree = GetCallstackFrameTreeBottomUp( mem );

        int idx = 0;
        DrawFrameTreeLevel( tree, idx );

        ImGui::TreePop();
    }

    ImGui::Separator();
#ifdef TRACY_EXTENDED_FONT
    if( ImGui::TreeNode( ICON_FA_ALIGN_JUSTIFY " Top-down call stack tree" ) )
#else
    if( ImGui::TreeNode( "Top-down call stack tree" ) )
#endif
    {
        ImGui::Checkbox( "Group by function name", &m_groupCallstackTreeByNameTopDown );
        ImGui::SameLine();
        DrawHelpMarker( "If enabled, only one source location will be displayed (which may be incorrect)." );
        TextDisabledUnformatted( "Press ctrl key to display allocation info tooltip." );
        TextDisabledUnformatted( "Right click on function name to display allocations list. Right click on file name to open source file." );

        auto& mem = m_worker.GetMemData();
        auto tree = GetCallstackFrameTreeTopDown( mem );

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
    pdqsort_branchless( tree.begin(), tree.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs.alloc > rhs.alloc; } );
    for( auto& v : tree )
    {
        idx++;
        auto& frameData = *m_worker.GetCallstackFrame( v.frame );
        auto frame = frameData.data[frameData.size-1];
        bool expand = false;
        if( v.children.empty() )
        {
            ImGui::Indent( ImGui::GetTreeNodeToLabelSpacing() );
            ImGui::TextUnformatted( m_worker.GetString( frame.name ) );
            ImGui::Unindent( ImGui::GetTreeNodeToLabelSpacing() );
        }
        else
        {
            ImGui::PushID( lidx++ );
            if( tree.size() == 1 )
            {
                expand = ImGui::TreeNodeEx( m_worker.GetString( frame.name ), ImGuiTreeNodeFlags_DefaultOpen );
            }
            else
            {
                expand = ImGui::TreeNode( m_worker.GetString( frame.name ) );
            }
            ImGui::PopID();
        }

        if( ImGui::IsItemClicked( 1 ) )
        {
            auto& mem = m_worker.GetMemData().data;
            const auto sz = mem.size();
            m_memInfo.showAllocList = true;
            m_memInfo.allocList.clear();
            for( size_t i=0; i<sz; i++ )
            {
                if( v.callstacks.find( mem[i].csAlloc ) != v.callstacks.end() )
                {
                    m_memInfo.allocList.emplace_back( i );
                }
            }
        }

        if( io.KeyCtrl && ImGui::IsItemHovered() )
        {
            ImGui::BeginTooltip();
            TextFocused( "Allocations size:", MemSizeToString( v.alloc ) );
            TextFocused( "Allocations count:", RealToString( v.count, true ) );
            TextFocused( "Average allocation size:", MemSizeToString( v.alloc / v.count ) );
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
        const auto fileName = m_worker.GetString( frame.file );
        ImGui::TextDisabled( "%s:%i", fileName, frame.line );
        if( ImGui::IsItemClicked( 1 ) )
        {
            if( FileExists( fileName ) )
            {
                SetTextEditorFile( fileName, frame.line );
            }
            else
            {
                m_callstackTreeBuzzAnim.Enable( idx, 0.5f );
            }
        }

        ImGui::SameLine();
        if( v.children.empty() )
        {
            ImGui::TextColored( ImVec4( 0.2, 0.8, 0.8, 1.0 ), "%s (%s)", MemSizeToString( v.alloc ), RealToString( v.count, true ) );
        }
        else
        {
            ImGui::TextColored( ImVec4( 0.8, 0.8, 0.2, 1.0 ), "%s (%s)", MemSizeToString( v.alloc ), RealToString( v.count, true ) );
        }

        if( expand )
        {
            DrawFrameTreeLevel( v.children, idx );
            ImGui::TreePop();
        }
    }
}

void View::DrawAllocList()
{
    std::vector<const MemEvent*> data;
    auto basePtr = m_worker.GetMemData().data.data();
    data.reserve( m_memInfo.allocList.size() );
    for( auto& idx : m_memInfo.allocList )
    {
        data.emplace_back( basePtr + idx );
    }

    ImGui::Begin( "Allocations list", &m_memInfo.showAllocList );
    TextFocused( "Number of allocations:", RealToString( m_memInfo.allocList.size(), true ) );
    ListMemData<decltype( data.begin() )>( data.begin(), data.end(), []( auto& v ) {
        ImGui::Text( "0x%" PRIx64, (*v)->ptr );
    }, "##allocations" );
    ImGui::End();
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
    case PlotType::SysTime:
#ifdef TRACY_EXTENDED_FONT
        return ICON_FA_TACHOMETER_ALT " CPU usage";
#else
        return "CPU usage";
#endif
    default:
        assert( false );
        return nullptr;
    }
}

uint32_t View::GetZoneColor( const ZoneEvent& ev )
{
    if( m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == ev.srcloc )
    {
        return 0xFF229999;
    }
    else
    {
        const auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
        const auto color = srcloc.color;
        return color != 0 ? ( color | 0xFF000000 ) : 0xFFCC5555;
    }
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
    if( m_zoneInfoWindow == &ev || m_zoneHighlight == &ev || ( m_findZone.show && !m_findZone.match.empty() && m_findZone.match[m_findZone.selMatch] == ev.srcloc ) )
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
    int64_t start;
    if( m_zoomAnim.active )
    {
        start = m_zoomAnim.start1;
    }
    else
    {
        start = m_zvStart;
    }

    int frame;
    if( start < m_worker.GetFrameBegin( *m_frames, 0 ) )
    {
        frame = -1;
    }
    else
    {
        frame = m_worker.GetFrameRange( *m_frames, start, start ).first;
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
    auto& srcloc = m_worker.GetSourceLocation( ev.srcloc );
    const auto end = m_worker.GetZoneEnd( ev );
    const auto ztime = end - ev.start;
    const auto selftime = GetZoneSelfTime( ev );

    ImGui::BeginTooltip();
    if( ev.name.active )
    {
        ImGui::TextUnformatted( m_worker.GetString( ev.name ) );
    }
    if( srcloc.name.active )
    {
        ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
    }
    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    ImGui::Separator();
    TextFocused( "Execution time:", TimeToString( ztime ) );
    TextFocused( "Self time:", TimeToString( selftime ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%.2f%%)", 100.f * selftime / ztime );
    if( ev.cpu_start >= 0 )
    {
        TextDisabledUnformatted( "CPU:" );
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
    const auto ztime = end - ev.gpuStart;
    const auto selftime = GetZoneSelfTime( ev );

    ImGui::BeginTooltip();
    ImGui::TextUnformatted( m_worker.GetString( srcloc.name ) );
    ImGui::TextUnformatted( m_worker.GetString( srcloc.function ) );
    ImGui::Separator();
    ImGui::Text( "%s:%i", m_worker.GetString( srcloc.file ), srcloc.line );
    TextFocused( "Thread:", m_worker.GetThreadString( tid ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(0x%" PRIX64 ")", tid );
    ImGui::Separator();
    TextFocused( "GPU execution time:", TimeToString( ztime ) );
    TextFocused( "GPU self time:", TimeToString( selftime ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%.2f%%)", 100.f * selftime / ztime );
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
                    TextDisabledUnformatted( "--" );
                }
                ImGui::SameLine();
                ImGui::TextUnformatted( txt );
            }
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

const ThreadData* View::GetZoneThreadData( const ZoneEvent& zone ) const
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
            if( *it == &zone ) return thread;
            if( (*it)->child < 0 ) break;
            timeline = &m_worker.GetZoneChildren( (*it)->child );
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

void View::SetViewToLastFrames()
{
    const int total = m_worker.GetFrameCount( *m_frames );

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

int64_t View::GetZoneChildTime( const ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.child >= 0 )
    {
        for( auto& v : m_worker.GetZoneChildren( zone.child ) )
        {
            const auto childSpan = std::max( int64_t( 0 ), v->end - v->start );
            time += childSpan;
        }
    }
    return time;
}

int64_t View::GetZoneChildTime( const GpuEvent& zone )
{
    int64_t time = 0;
    if( zone.child >= 0 )
    {
        for( auto& v : m_worker.GetGpuChildren( zone.child ) )
        {
            const auto childSpan = std::max( int64_t( 0 ), v->gpuEnd - v->gpuStart );
            time += childSpan;
        }
    }
    return time;
}

int64_t View::GetZoneChildTimeFast( const ZoneEvent& zone )
{
    int64_t time = 0;
    if( zone.child >= 0 )
    {
        for( auto& v : m_worker.GetZoneChildren( zone.child ) )
        {
            assert( v->end >= 0 );
            time += v->end - v->start;
        }
    }
    return time;
}

int64_t View::GetZoneSelfTime( const ZoneEvent& zone )
{
    if( m_cache.zoneSelfTime.first == &zone ) return m_cache.zoneSelfTime.second;
    if( m_cache.zoneSelfTime2.first == &zone ) return m_cache.zoneSelfTime2.second;
    const auto ztime = m_worker.GetZoneEnd( zone ) - zone.start;
    const auto selftime = ztime - GetZoneChildTime( zone );
    if( zone.end >= 0 )
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
    const auto ztime = m_worker.GetZoneEnd( zone ) - zone.gpuStart;
    const auto selftime = ztime - GetZoneChildTime( zone );
    if( zone.gpuEnd >= 0 )
    {
        m_cache.gpuSelfTime2 = m_cache.gpuSelfTime;
        m_cache.gpuSelfTime = std::make_pair( &zone, selftime );
    }
    return selftime;
}

}
