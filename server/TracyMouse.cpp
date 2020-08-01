#include "TracyMouse.hpp"

#include "../imgui/imgui_internal.h"

namespace tracy
{

static constexpr int MouseButtons = IM_ARRAYSIZE( ImGuiContext::IO.MouseDown );

struct Mouse
{
    bool mouseDown[MouseButtons];
    bool mouseClicked[MouseButtons];
    bool mouseDragging[MouseButtons];
    ImVec2 mouseDragDelta[MouseButtons];
};

static Mouse s_mouse;

void MouseFrame()
{
    for( int i=0; i<MouseButtons; i++ )
    {
        s_mouse.mouseDown[i] = ImGui::IsMouseDown( i );
        s_mouse.mouseClicked[i] = ImGui::IsMouseClicked( i );
        s_mouse.mouseDragging[i] = ImGui::IsMouseDragging( i, 0 );
        s_mouse.mouseDragDelta[i] = ImGui::GetMouseDragDelta( i, 0 );
    }
}

bool IsMouseDown( ImGuiMouseButton button )
{
    return s_mouse.mouseDown[button];
}

bool IsMouseClicked( ImGuiMouseButton button )
{
    return s_mouse.mouseClicked[button];
}

bool IsMouseDragging( ImGuiMouseButton button )
{
    return s_mouse.mouseDragging[button];
}

ImVec2 GetMouseDragDelta( ImGuiMouseButton button )
{
    return s_mouse.mouseDragDelta[button];
}

}
