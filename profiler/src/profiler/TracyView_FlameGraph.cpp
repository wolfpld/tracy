#include "TracyView.hpp"

namespace tracy
{

void View::DrawFlameGraph()
{
    const auto scale = GetScale();
    ImGui::SetNextWindowSize( ImVec2( 1400 * scale, 800 * scale ), ImGuiCond_FirstUseEver );
    ImGui::Begin( "Flame graph", &m_showFlameGraph, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse );
    ImGui::End();
}

}
