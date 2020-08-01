#ifndef __TRACYMOUSE_HPP__
#define __TRACYMOUSE_HPP__

#include "../imgui/imgui.h"

namespace tracy
{

bool IsMouseDown( ImGuiMouseButton button );
bool IsMouseClicked( ImGuiMouseButton button );
bool IsMouseDragging( ImGuiMouseButton button, float lock_threshold = -1.f );
ImVec2 GetMouseDragDelta( ImGuiMouseButton button, float lock_threshold = -1.f );

}

#endif
