#ifndef __WAYLANDKEYBOARD_HPP__
#define __WAYLANDKEYBOARD_HPP__

#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-compose.h>
#include <wayland-client.h>

class WaylandKeyboard
{
public:
    WaylandKeyboard( wl_keyboard* keyboard );
    ~WaylandKeyboard();

private:
    void Keymap( wl_keyboard* kbd, uint32_t format, int32_t fd, uint32_t size );
    void Enter( wl_keyboard* kbd, uint32_t serial, wl_surface* surf, wl_array* keys );
    void Leave( wl_keyboard* kbd, uint32_t serial, wl_surface* surf );
    void Key( wl_keyboard* kbd, uint32_t serial, uint32_t time, uint32_t key, uint32_t state );
    void Modifiers( wl_keyboard* kbd, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group );
    void RepeatInfo( wl_keyboard* kbd, int32_t rate, int32_t delay );

    xkb_keysym_t Compose( xkb_keysym_t sym );

    wl_keyboard* m_keyboard;

    xkb_context* m_xkbCtx;
    xkb_keymap* m_keymap;
    xkb_state* m_state;
    xkb_compose_table* m_composeTable;
    xkb_compose_state* m_composeState;

    xkb_mod_index_t m_modCtrl;
    xkb_mod_index_t m_modAlt;
    xkb_mod_index_t m_modShift;
    xkb_mod_index_t m_modSuper;
};

#endif
