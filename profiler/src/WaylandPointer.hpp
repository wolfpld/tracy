#ifndef __WAYLANDPOINTER_HPP__
#define __WAYLANDPOINTER_HPP__

#include <functional>
#include <wayland-client.h>

class WaylandPointer
{
public:
    WaylandPointer( wl_pointer* pointer, int32_t& scale, std::function<void(wl_pointer*, uint32_t)> setCursor );
    ~WaylandPointer();

    [[nodiscard]] wl_pointer* GetPointer() const { return m_pointer; }

private:
    void Enter( wl_pointer* pointer, uint32_t serial, wl_surface* surf, wl_fixed_t sx, wl_fixed_t sy );
    void Leave( wl_pointer* pointer, uint32_t serial, wl_surface* surf );
    void Motion( wl_pointer* pointer, uint32_t time, wl_fixed_t sx, wl_fixed_t sy );
    void Button( wl_pointer* pointer, uint32_t serial, uint32_t time, uint32_t button, uint32_t state );
    void Axis( wl_pointer* pointer, uint32_t time, uint32_t axis, wl_fixed_t value );
    void Frame( wl_pointer* pointer );
    void AxisSource( wl_pointer* pointer, uint32_t source );
    void AxisStop( wl_pointer* pointer, uint32_t time, uint32_t axis );
    void AxisDiscrete( wl_pointer* pointer, uint32_t axis, int32_t discrete );
    void AxisValue120( wl_pointer* pointer, uint32_t axis, int32_t value120 );
    void AxisRelativeDirection( wl_pointer* pointer, uint32_t axis, uint32_t direction );

    wl_pointer* m_pointer;

    bool m_wheel;
    wl_fixed_t m_wheelX;
    wl_fixed_t m_wheelY;

    int32_t& m_scale;
    std::function<void(wl_pointer*, uint32_t)> m_setCursor;
};

#endif
