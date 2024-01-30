#include <linux/input-event-codes.h>

#include "../../imgui/imgui.h"

#include "WaylandMethod.hpp"
#include "WaylandPointer.hpp"

WaylandPointer::WaylandPointer( wl_pointer* pointer, int32_t& scale, std::function<void(wl_pointer*, uint32_t)> setCursor )
    : m_pointer( pointer )
    , m_wheel( false )
    , m_wheelX( 0 )
    , m_wheelY( 0 )
    , m_scale( scale )
    , m_setCursor( std::move( setCursor ) )
{
    static constexpr wl_pointer_listener listener = {
        .enter = Method( Enter ),
        .leave = Method( Leave ),
        .motion = Method( Motion ),
        .button = Method( Button ),
        .axis = Method( Axis ),
        .frame = Method( Frame ),
        .axis_source = Method( AxisSource ),
        .axis_stop = Method( AxisStop ),
        .axis_discrete = Method( AxisDiscrete ),
        .axis_value120 = Method( AxisValue120 ),
        .axis_relative_direction = Method( AxisRelativeDirection )
    };

    wl_pointer_add_listener( m_pointer, &listener, this );
}

WaylandPointer::~WaylandPointer()
{
    wl_pointer_destroy( m_pointer );
}

void WaylandPointer::Enter( wl_pointer* pointer, uint32_t serial, wl_surface* surf, wl_fixed_t sx, wl_fixed_t sy )
{
    m_setCursor( pointer, serial );
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( wl_fixed_to_double( sx * m_scale ), wl_fixed_to_double( sy * m_scale ) );
}

void WaylandPointer::Leave( wl_pointer* pointer, uint32_t serial, wl_surface* surf )
{
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( -FLT_MAX, -FLT_MAX );
}

void WaylandPointer::Motion( wl_pointer* pointer, uint32_t time, wl_fixed_t sx, wl_fixed_t sy )
{
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( wl_fixed_to_double( sx * m_scale ), wl_fixed_to_double( sy * m_scale ) );
}

void WaylandPointer::Button( wl_pointer* pointer, uint32_t serial, uint32_t time, uint32_t button, uint32_t state )
{
    int b;
    switch( button )
    {
    case BTN_LEFT: b = 0; break;
    case BTN_MIDDLE: b = 2; break;
    case BTN_RIGHT: b = 1; break;
    default: return;
    }
    ImGuiIO& io = ImGui::GetIO();
    io.AddMouseButtonEvent( b, state == WL_POINTER_BUTTON_STATE_PRESSED );
}

void WaylandPointer::Axis( wl_pointer* pointer, uint32_t time, uint32_t axis, wl_fixed_t value )
{
    m_wheel = true;
    if( axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL )
    {
        m_wheelX -= value;
    }
    else
    {
        m_wheelY -= value;
    }
}

void WaylandPointer::Frame( wl_pointer* pointer )
{
    if( m_wheel )
    {
        m_wheel = false;
        m_wheelX /= 8;
        m_wheelY /= 8;
        ImGuiIO& io = ImGui::GetIO();
        io.AddMouseWheelEvent( wl_fixed_to_double( m_wheelX ), wl_fixed_to_double( m_wheelY ) );
        m_wheelX = m_wheelY = 0;
    }
}

void WaylandPointer::AxisSource( wl_pointer* pointer, uint32_t source )
{
}

void WaylandPointer::AxisStop( wl_pointer* pointer, uint32_t time, uint32_t axis )
{
}

void WaylandPointer::AxisDiscrete( wl_pointer* pointer, uint32_t axis, int32_t discrete )
{
}

void WaylandPointer::AxisValue120( wl_pointer* pointer, uint32_t axis, int32_t value120 )
{
}

void WaylandPointer::AxisRelativeDirection( wl_pointer* pointer, uint32_t axis, uint32_t direction )
{
}
