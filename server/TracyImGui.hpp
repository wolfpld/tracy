#ifndef __TRACYIMGUI_HPP__
#define __TRACYIMGUI_HPP__

#ifdef _MSC_VER
#  pragma warning( disable: 4244 )  // conversion from don't care to whatever, possible loss of data 
#endif

#include <stdint.h>

#include "../imgui/imgui.h"
#include "../imgui/imgui_internal.h"

#include "IconsFontAwesome5.h"

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

    static inline void TextColoredUnformatted( uint32_t col, const char* text, const char* end = nullptr )
    {
        ImGui::PushStyleColor( ImGuiCol_Text, col );
        ImGui::TextUnformatted( text, end );
        ImGui::PopStyleColor();
    }

    static inline void TextColoredUnformatted( const ImVec4& col, const char* text, const char* end = nullptr )
    {
        ImGui::PushStyleColor( ImGuiCol_Text, col );
        ImGui::TextUnformatted( text, end );
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

    static inline void SmallColorBox( uint32_t color )
    {
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        ImGui::ColorButton( "c1", ImVec4( (color & 0xFF) / 255.f, ((color>>8) & 0xFF ) / 255.f, ((color>>16) & 0xFF ) / 255.f, 1.f ), ImGuiColorEditFlags_NoTooltip | ImGuiColorEditFlags_NoDragDrop );
        ImGui::PopStyleVar();
    }

    static inline bool ButtonDisablable( const char* label, bool disabled )
    {
        if( disabled )
        {
            ImGui::PushStyleColor( ImGuiCol_Button, (ImVec4)ImColor( 0.3f, 0.3f, 0.3f, 1.0f ) );
            ImGui::ButtonEx( label, ImVec2( 0, 0 ), ImGuiButtonFlags_Disabled );
            ImGui::PopStyleColor( 1 );
            return false;
        }
        else
        {
            return ImGui::Button( label );
        }
    }

    static inline void DrawTextContrast( ImDrawList* draw, const ImVec2& pos, uint32_t color, const char* text )
    {
        draw->AddText( pos + ImVec2( 1, 1 ), 0xAA000000, text );
        draw->AddText( pos, color, text );
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

    static void SmallToggleButton( const char* label, bool& toggle )
    {
        const auto active = toggle;
        if( active ) SetButtonHighlightColor();
        ImGui::PushStyleVar( ImGuiStyleVar_FramePadding, ImVec2( 0, 0 ) );
        if( ImGui::Button( label ) ) toggle = !toggle;
        ImGui::PopStyleVar( 1 );
        if( active ) ImGui::PopStyleColor( 3 );
    }

    static bool ClipboardButton( int id = 0 )
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

}

#endif
