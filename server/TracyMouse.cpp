#include "TracyMouse.hpp"

namespace tracy
{

bool IsMouseDown( ImGuiMouseButton button )
{
    return ImGui::IsMouseDown( button );
}

bool IsMouseClicked( ImGuiMouseButton button )
{
    return ImGui::IsMouseClicked( button );
}

bool IsMouseDragging( ImGuiMouseButton button, float lock_threshold )
{
    return ImGui::IsMouseDragging( button, lock_threshold );
}

ImVec2 GetMouseDragDelta( ImGuiMouseButton button, float lock_threshold )
{
    return ImGui::GetMouseDragDelta( button, lock_threshold );
}

}
