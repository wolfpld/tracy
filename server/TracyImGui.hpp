#ifndef __TRACYIMGUI_HPP__
#define __TRACYIMGUI_HPP__

#ifdef _MSC_VER
#  pragma warning( disable: 4244 )  // conversion from don't care to whatever, possible loss of data 
#endif

#include <algorithm>
#include <stdint.h>

#include "../imgui/imgui.h"
#include "../imgui/imgui_internal.h"

#if !IMGUI_DEFINE_MATH_OPERATORS
static inline ImVec2 operator+( const ImVec2& l, const ImVec2& r ) { return ImVec2( l.x + r.x, l.y + r.y ); }
static inline ImVec2 operator-( const ImVec2& l, const ImVec2& r ) { return ImVec2( l.x - r.x, l.y - r.y ); }
#endif

namespace tracy
{

    static inline void TextCentered( const char* text )
    {
        const auto tw = ImGui::CalcTextSize( text ).x;
        ImGui::SetCursorPosX( ( ImGui::GetWindowWidth() - tw ) * 0.5f );
        ImGui::TextUnformatted( text );
    }

    static inline void TextColoredUnformatted( const ImVec4& col, const char* text )
    {
        ImGui::PushStyleColor( ImGuiCol_Text, col );
        ImGui::TextUnformatted( text );
        ImGui::PopStyleColor();
    }

    static inline void TextDisabledUnformatted( const char* begin, const char* end = nullptr )
    {
        ImGui::PushStyleColor( ImGuiCol_Text, GImGui->Style.Colors[ImGuiCol_TextDisabled] );
        ImGui::TextUnformatted( begin, end );
        ImGui::PopStyleColor();
    }

    static inline void TextFocused( const char* label, const char* value )
    {
        TextDisabledUnformatted( label );
        ImGui::SameLine();
        ImGui::TextUnformatted( value );
    }

    static inline void DrawWaitingDots( double time )
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

    static inline bool SmallCheckbox( const char* label, bool* var )
    {
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        auto ret = ImGui::Checkbox( label, var );
        ImGui::PopStyleVar();
        return ret;
    }

    static inline void LineVertical( struct ImDrawList* draw, float x, float y0, float y1, uint32_t c0, uint32_t c1 )
    {
        draw->AddRectFilledMultiColor( ImVec2( x, y0 ), ImVec2( x+1, y1 ), c0, c0, c1, c1 );
    }

    static inline uint8_t lerp( uint8_t v0, uint8_t v1, float t )
    {
        return uint8_t( v0 + t * ( v1 - v0 ) );
    }

    static inline void LineVerticalShaded( struct ImDrawList* draw, float x, float y0, float y1, uint32_t c0, uint32_t c1, float maxHeight )
    {
        const auto dy = y1 - y0;
        const auto t = std::min( 1.f, dy / maxHeight );
        const auto ct = 0xFF000000 |
            ( lerp( ( c0 & 0x00FF0000 ) >> 16, ( c1 & 0x00FF0000 ) >> 16, t ) << 16 ) |
            ( lerp( ( c0 & 0x0000FF00 ) >>  8, ( c1 & 0x0000FF00 ) >>  8, t ) <<  8 ) |
            ( lerp( ( c0 & 0x000000FF )      , ( c1 & 0x000000FF )      , t )       );
        LineVertical( draw, x, y0, y1, c0, ct );
    }

}

#endif
