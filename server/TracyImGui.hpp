#ifndef __TRACYIMGUI_HPP__
#define __TRACYIMGUI_HPP__

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
        ImGui::Text( "%s", text );
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

}

#endif
