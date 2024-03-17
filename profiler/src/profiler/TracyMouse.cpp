#include <cmath>

#include "TracyMouse.hpp"

#include "imgui_internal.h"

namespace tracy
{

static constexpr int MouseButtons = IM_ARRAYSIZE( ImGuiContext::IO.MouseDown );
static constexpr float MouseDragThreshold = 2;

struct Mouse
{
    bool mouseDown[MouseButtons];
    bool mouseClicked[MouseButtons];
    bool mouseReleased[MouseButtons];
    bool mouseDragging[MouseButtons];
    ImVec2 mouseDragDelta[MouseButtons];
    bool mousePotentialClickRelease[MouseButtons];
};

static Mouse s_mouse = {};

void MouseFrame()
{
    for( int i=0; i<MouseButtons; i++ )
    {
        s_mouse.mouseDown[i] = ImGui::IsMouseDown( i );
        s_mouse.mouseClicked[i] = ImGui::IsMouseClicked( i );
        s_mouse.mouseReleased[i] = ImGui::IsMouseReleased( i );
        s_mouse.mouseDragging[i] = ImGui::IsMouseDragging( i, 0 );
        s_mouse.mouseDragDelta[i] = ImGui::GetMouseDragDelta( i, 0 );

        if( s_mouse.mouseDragging[i] )
        {
            if( s_mouse.mouseClicked[i] || s_mouse.mousePotentialClickRelease[i] )
            {
                if( std::abs( s_mouse.mouseDragDelta[i].x ) < MouseDragThreshold && std::abs( s_mouse.mouseDragDelta[i].y ) < MouseDragThreshold )
                {
                    s_mouse.mouseDragging[i] = false;
                }
                else
                {
                    s_mouse.mousePotentialClickRelease[i] = false;
                }
            }
        }
        else if( !s_mouse.mouseDown[i] && !s_mouse.mouseReleased[i] )
        {
            s_mouse.mousePotentialClickRelease[i] = false;
        }
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

void ConsumeMouseEvents( ImGuiMouseButton button )
{
    s_mouse.mouseDown[button] = false;
    s_mouse.mouseClicked[button] = false;
    s_mouse.mouseDragging[button] = false;
}

bool IsMouseClickReleased( ImGuiMouseButton button )
{
    if( s_mouse.mouseReleased[button] && s_mouse.mousePotentialClickRelease[button] ) return true;
    if( s_mouse.mouseClicked[button] ) s_mouse.mousePotentialClickRelease[button] = true;
    return false;
}

}
