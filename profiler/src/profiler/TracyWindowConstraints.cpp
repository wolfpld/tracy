#include <algorithm>
#include <imgui.h>

#include "TracyWindowConstraints.hpp"

namespace tracy
{

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
    m_minWidth = std::max( m_minWidth, ImGui::GetCursorPosX() );
    ImGui::NewLine();
}

}
