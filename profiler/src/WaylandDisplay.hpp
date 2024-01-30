#ifndef __WAYLANDDISPLAY_HPP__
#define __WAYLANDDISPLAY_HPP__

#include <functional>
#include <memory>
#include <wayland-client.h>
#include <unordered_map>

#include "wayland/xdg-activation.h"
#include "wayland/xdg-decoration.h"
#include "wayland/xdg-shell.h"

#include "WaylandKeyboard.hpp"
#include "WaylandOutput.hpp"
#include "WaylandPointer.hpp"

class WaylandDisplay
{
public:
    WaylandDisplay( int32_t& scale, std::function<void(wl_pointer*, uint32_t)> setCursor );
    ~WaylandDisplay();

    [[nodiscard]] wl_display* GetDisplay() const { return m_dpy; }
    [[nodiscard]] wl_compositor* GetCompositor() const { return m_compositor; }
    [[nodiscard]] wl_shm* GetShm() const { return m_shm; }
    [[nodiscard]] xdg_wm_base* GetWmBase() const { return m_wmBase; }
    [[nodiscard]] zxdg_decoration_manager_v1* GetDecorationManager() const { return m_decorationManager; }
    [[nodiscard]] xdg_activation_v1* GetActivation() const { return m_activation; }
    [[nodiscard]] wl_pointer* GetPointer() const { return m_pointer ? m_pointer->GetPointer() : nullptr; }

    [[nodiscard]] WaylandOutput* GetOutput( wl_output* output, uint32_t& id );
    [[nodiscard]] WaylandOutput* GetOutput( uint32_t id );

private:
    void RegistryGlobal( wl_registry* reg, uint32_t name, const char* interface, uint32_t version );
    void RegistryGlobalRemove( wl_registry* reg, uint32_t name );

    void XdgWmPing( xdg_wm_base* shell, uint32_t serial );

    void SeatCapabilities( wl_seat* seat, uint32_t caps );
    void SeatName( wl_seat* seat, const char* name );

    wl_display* m_dpy;
    wl_compositor* m_compositor;
    wl_shm* m_shm;
    xdg_wm_base* m_wmBase;
    wl_seat* m_seat;
    zxdg_decoration_manager_v1* m_decorationManager;
    xdg_activation_v1* m_activation;

    std::unique_ptr<WaylandKeyboard> m_keyboard;
    std::unique_ptr<WaylandPointer> m_pointer;

    std::unordered_map<uint32_t, std::unique_ptr<WaylandOutput>> m_outputs;

    int32_t& m_scale;

    std::function<void(wl_pointer*, uint32_t)> m_setCursor;
};

#endif
