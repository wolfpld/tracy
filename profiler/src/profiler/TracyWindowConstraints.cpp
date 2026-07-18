#include <algorithm>
#include <imgui_internal.h>

#include "TracyWindowConstraints.hpp"

namespace tracy
{

static int GetChildDepth()
{
    int depth = 0;
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    while( window->Flags & ImGuiWindowFlags_ChildWindow )
    {
        window = window->ParentWindow;
        depth++;
    }
    return depth;
}

void WindowConstraints::Reset()
{
    m_minWidth = 0;
}

void WindowConstraints::Constrain() const
{
    ImGui::SetNextWindowSizeConstraints( ImVec2( m_minWidth, 0 ), ImVec2( FLT_MAX, FLT_MAX ) );
}

void WindowConstraints::MarkMinWidth()
{
    ImGui::SameLine();
    const auto& style = ImGui::GetStyle();
    const auto depth = GetChildDepth();
    const auto pos = ImGui::GetCursorPosX() + depth * ( style.WindowPadding.x + style.ScrollbarSize );
    m_minWidth = std::max( m_minWidth, pos );
    ImGui::NewLine();
}

}
