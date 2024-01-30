#ifndef __WAYLANDOUTPUT_HPP__
#define __WAYLANDOUTPUT_HPP__

#include <wayland-client.h>

class WaylandOutput
{
public:
    WaylandOutput( wl_output* output );
    ~WaylandOutput();

    int32_t Scale() const { return m_scale; }
    wl_output* Output() const { return m_output; }

private:
    void Geometry( wl_output* output, int32_t x, int32_t y, int32_t phys_w, int32_t phys_h, int32_t subpixel, const char* make, const char* model, int32_t transform );
    void Mode( wl_output* output, uint32_t flags, int32_t width, int32_t height, int32_t refresh );
    void Done( wl_output* output );
    void Scale( wl_output* output, int32_t scale );
    void Name( wl_output* output, const char* name );
    void Description( wl_output* output, const char* description );

    wl_output* m_output;
    int32_t m_scale;
};

#endif
