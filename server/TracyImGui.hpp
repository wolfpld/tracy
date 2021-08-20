#ifndef __TRACYIMGUI_HPP__
#define __TRACYIMGUI_HPP__

#ifdef _MSC_VER
#  pragma warning( disable: 4244 )  // conversion from don't care to whatever, possible loss of data
#endif

#include <algorithm>
#include <assert.h>
#include <stdint.h>

#include "imgui.h"
#include "imgui_internal.h"

#include "../common/TracyForceInline.hpp"
#include "IconsFontAwesome5.h"

#if !IMGUI_DEFINE_MATH_OPERATORS
static inline ImVec2 operator+( const ImVec2& l, const ImVec2& r ) { return ImVec2( l.x + r.x, l.y + r.y ); }
static inline ImVec2 operator-( const ImVec2& l, const ImVec2& r ) { return ImVec2( l.x - r.x, l.y - r.y ); }
#endif

namespace tracy
{

static const ImVec4 SyntaxColors[] = {
    { 0.7f,  0.7f,  0.7f,  1 },    // default
    { 0.45f, 0.68f, 0.32f, 1 },    // comment
    { 0.72f, 0.37f, 0.12f, 1 },    // preprocessor
    { 0.64f, 0.64f, 1,     1 },    // string
    { 0.64f, 0.82f, 1,     1 },    // char literal
    { 1,     0.91f, 0.53f, 1 },    // keyword
    { 0.81f, 0.6f,  0.91f, 1 },    // number
    { 0.9f,  0.9f,  0.9f,  1 },    // punctuation
    { 0.78f, 0.46f, 0.75f, 1 },    // type
    { 0.21f, 0.69f, 0.89f, 1 },    // special
};

static const ImVec4 SyntaxColorsDimmed[] = {
    { 0.7f,  0.7f,  0.7f,  0.6f },    // default
    { 0.45f, 0.68f, 0.32f, 0.6f },    // comment
    { 0.72f, 0.37f, 0.12f, 0.6f },    // preprocessor
    { 0.64f, 0.64f, 1,     0.6f },    // string
    { 0.64f, 0.82f, 1,     0.6f },    // char literal
    { 1,     0.91f, 0.53f, 0.6f },    // keyword
    { 0.81f, 0.6f,  0.91f, 0.6f },    // number
    { 0.9f,  0.9f,  0.9f,  0.6f },    // punctuation
    { 0.78f, 0.46f, 0.75f, 0.6f },    // type
    { 0.21f, 0.69f, 0.89f, 0.6f },    // special
};

[[maybe_unused]] static inline void TextCentered( const char* text )
{
    const auto tw = ImGui::CalcTextSize( text ).x;
    ImGui::SetCursorPosX( ( ImGui::GetWindowWidth() - tw ) * 0.5f );
    ImGui::TextUnformatted( text );
}

[[maybe_unused]] static inline void TextColoredUnformatted( uint32_t col, const char* text, const char* end = nullptr )
{
    ImGui::PushStyleColor( ImGuiCol_Text, col );
    ImGui::TextUnformatted( text, end );
    ImGui::PopStyleColor();
}

[[maybe_unused]] static inline void TextColoredUnformatted( const ImVec4& col, const char* text, const char* end = nullptr )
{
    ImGui::PushStyleColor( ImGuiCol_Text, col );
    ImGui::TextUnformatted( text, end );
    ImGui::PopStyleColor();
}

[[maybe_unused]] static inline void TextDisabledUnformatted( const char* begin, const char* end = nullptr )
{
    ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
    ImGui::TextUnformatted( begin, end );
    ImGui::PopStyleColor();
}

[[maybe_unused]] static inline void TextFocused( const char* label, const char* value )
{
    TextDisabledUnformatted( label );
    ImGui::SameLine();
    ImGui::TextUnformatted( value );
}

[[maybe_unused]] static inline void DrawWaitingDots( double time )
{
    ImGui::TextUnformatted( "" );
    auto draw = ImGui::GetWindowDrawList();
    const auto wpos = ImGui::GetWindowPos();
    const auto ty = ImGui::GetFontSize();
    const auto h = ImGui::GetCursorPosY() - ty * 0.5f;
    const auto w = ImGui::GetWindowWidth();
    draw->AddCircleFilled( wpos + ImVec2( w * 0.5f - ty, h ), ty * ( 0.15f + 0.2f * ( pow( cos( time * 3.5f + 0.3f ), 16.f ) ) ), 0xFFBBBBBB, 12 );
    draw->AddCircleFilled( wpos + ImVec2( w * 0.5f     , h ), ty * ( 0.15f + 0.2f * ( pow( cos( time * 3.5f        ), 16.f ) ) ), 0xFFBBBBBB, 12 );
    draw->AddCircleFilled( wpos + ImVec2( w * 0.5f + ty, h ), ty * ( 0.15f + 0.2f * ( pow( cos( time * 3.5f - 0.3f ), 16.f ) ) ), 0xFFBBBBBB, 12 );
}

[[maybe_unused]] static inline bool SmallCheckbox( const char* label, bool* var )
{
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    auto ret = ImGui::Checkbox( label, var );
    ImGui::PopStyleVar();
    return ret;
}

[[maybe_unused]] static inline void SmallColorBox( uint32_t color )
{
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    ImGui::ColorButton( "c1", ImVec4( (color & 0xFF) / 255.f, ((color>>8) & 0xFF ) / 255.f, ((color>>16) & 0xFF ) / 255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
    ImGui::PopStyleVar();
}

[[maybe_unused]] static inline bool ButtonDisablable( const char* label, bool disabled )
{
    if( disabled )
    {
        ImGui::BeginDisabled();
        ImGui::Button( label );
        ImGui::EndDisabled();
        return false;
    }
    else
    {
        return ImGui::Button( label );
    }
}

[[maybe_unused]] static inline bool SmallButtonDisablable( const char* label, bool disabled )
{
    if( disabled )
    {
        ImGui::BeginDisabled();
        ImGui::SmallButton( label );
        ImGui::EndDisabled();
        return false;
    }
    else
    {
        return ImGui::SmallButton( label );
    }
}

[[maybe_unused]] static inline void DrawTextContrast( ImDrawList* draw, const ImVec2& pos, uint32_t color, const char* text )
{
    draw->AddText( pos + ImVec2( 1, 1 ), 0xAA000000, text );
    draw->AddText( pos, color, text );
}

[[maybe_unused]] static void SetButtonHighlightColor()
{
    ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor::HSV( 0.35f, 0.6f, 0.6f ) );
    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, (ImVec4)ImColor::HSV( 0.35f, 0.8f, 0.8f ) );
    ImGui::PushStyleColor( ImGuiCol_ButtonActive, (ImVec4)ImColor::HSV( 0.35f, 0.7f, 0.7f ) );
}

[[maybe_unused]] static void ToggleButton( const char* label, bool& toggle )
{
    const auto active = toggle;
    if( active ) SetButtonHighlightColor();
    if( ImGui::Button( label ) ) toggle = !toggle;
    if( active ) ImGui::PopStyleColor( 3 );
}

[[maybe_unused]] static void SmallToggleButton( const char* label, bool& toggle )
{
    const auto active = toggle;
    if( active ) SetButtonHighlightColor();
    ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
    if( ImGui::Button( label ) ) toggle = !toggle;
    ImGui::PopStyleVar( 1 );
    if( active ) ImGui::PopStyleColor( 3 );
}

[[maybe_unused]] static bool ClipboardButton( int id = 0 )
{
    ImGui::PushStyleColor( ImGuiCol_Border, ImVec4( 0.43f, 0.43f, 0.50f, 0.25f ) );
    ImGui::PushStyleColor( ImGuiCol_Button, ImVec4( 0.26f, 0.59f, 0.98f, 0.20f ) );
    ImGui::PushStyleColor( ImGuiCol_ButtonHovered, ImVec4( 0.26f, 0.59f, 0.98f, 0.5f ) );
    ImGui::PushStyleColor( ImGuiCol_ButtonActive, ImVec4( 0.06f, 0.53f, 0.98f, 0.5f ) );
    ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
    ImGui::PushID( id );
    const auto res = ImGui::SmallButton( ICON_FA_CLIPBOARD );
    ImGui::PopID();
    ImGui::PopStyleColor( 5 );
    return res;
}

[[maybe_unused]] static void DrawStripedRect( ImDrawList* draw, double x0, double y0, double x1, double y1, double sw, uint32_t color, bool fix_stripes_in_screen_space, bool inverted )
{
    assert( x1 >= x0 );
    assert( y1 >= y0 );
    assert( sw > 0 );

    const auto ww = ImGui::GetItemRectSize().x;
    if( x0 > ww || x1 < 0 ) return;

    if( x1 - x0 > ww )
    {
        x0 = std::max<double>( 0, x0 );
        x1 = std::min<double>( ww, x1 );
    }

    ImGui::PushClipRect( ImVec2( x0, y0 ), ImVec2( x1, y1 ), true );

    const auto rw = x1 - x0;
    const auto rh = y1 - y0;
    const auto cnt = int( ( rh + rw + sw*2 ) / ( sw*2 ) );
    auto v0 = ImVec2( x0, y0 - rw );

    if ( fix_stripes_in_screen_space )
    {
        const auto window_height = double( ImGui::GetWindowHeight() );
        const auto flipped_v0y = window_height - v0.y; //we transform into a y-is-up coordinate space to achieve upper-left to lower-right stripes. If we didn't, we would calculate values for lower-left to upper-right

        const auto manhatten_distance = x0 + flipped_v0y;
        const auto in_multiples_of_2_times_sw = int( manhatten_distance / ( sw*2 ) );

        const auto floored_manhatten_distance = double( in_multiples_of_2_times_sw*sw*2 ); //floor in terms of 2 * stripe width

        const auto corrected_flipped_v0y = ( floored_manhatten_distance - x0 ); //the corrected (floored) y respects the position of the stripes
        v0.y = window_height - corrected_flipped_v0y - double( inverted*sw ); //transform back into y-is-down imgui space
    }

    for( int i=0; i<cnt; i++ )
    {
        draw->PathLineTo( v0 + ImVec2( 0, i*sw*2 ) );
        draw->PathLineTo( v0 + ImVec2( rw, i*sw*2 + rw ) );
        draw->PathLineTo( v0 + ImVec2( rw, i*sw*2 + rw + sw ) );
        draw->PathLineTo( v0 + ImVec2( 0, i*sw*2 + sw ) );
        draw->PathFillConvex( color );
    }

    ImGui::PopClipRect();
}

[[maybe_unused]] static tracy_force_inline void DrawLine( ImDrawList* draw, const ImVec2& v1, const ImVec2& v2, uint32_t col, float thickness = 1.0f )
{
    const ImVec2 data[2] = { v1, v2 };
    draw->AddPolyline( data, 2, col, 0, thickness );
}

[[maybe_unused]] static tracy_force_inline void DrawLine( ImDrawList* draw, const ImVec2& v1, const ImVec2& v2, const ImVec2& v3, uint32_t col, float thickness = 1.0f )
{
    const ImVec2 data[3] = { v1, v2, v3 };
    draw->AddPolyline( data, 3, col, 0, thickness );
}

}

#endif
