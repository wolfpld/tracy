#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../../imgui/imgui.h"

#include "WaylandKeyboard.hpp"
#include "WaylandMethod.hpp"

constexpr ImGuiKey s_keyTable[] = {
    /*   0 */ ImGuiKey_None,
    /*   1 */ ImGuiKey_Escape,
    /*   2 */ ImGuiKey_1,
    /*   3 */ ImGuiKey_2,
    /*   4 */ ImGuiKey_3,
    /*   5 */ ImGuiKey_4,
    /*   6 */ ImGuiKey_5,
    /*   7 */ ImGuiKey_6,
    /*   8 */ ImGuiKey_7,
    /*   9 */ ImGuiKey_8,
    /*  10 */ ImGuiKey_9,
    /*  11 */ ImGuiKey_0,
    /*  12 */ ImGuiKey_Minus,
    /*  13 */ ImGuiKey_Equal,
    /*  14 */ ImGuiKey_Backspace,
    /*  15 */ ImGuiKey_Tab,
    /*  16 */ ImGuiKey_Q,
    /*  17 */ ImGuiKey_W,
    /*  18 */ ImGuiKey_E,
    /*  19 */ ImGuiKey_R,
    /*  20 */ ImGuiKey_T,
    /*  21 */ ImGuiKey_Y,
    /*  22 */ ImGuiKey_U,
    /*  23 */ ImGuiKey_I,
    /*  24 */ ImGuiKey_O,
    /*  25 */ ImGuiKey_P,
    /*  26 */ ImGuiKey_LeftBracket,
    /*  27 */ ImGuiKey_RightBracket,
    /*  28 */ ImGuiKey_Enter,
    /*  29 */ ImGuiKey_LeftCtrl,
    /*  30 */ ImGuiKey_A,
    /*  31 */ ImGuiKey_S,
    /*  32 */ ImGuiKey_D,
    /*  33 */ ImGuiKey_F,
    /*  34 */ ImGuiKey_G,
    /*  35 */ ImGuiKey_H,
    /*  36 */ ImGuiKey_J,
    /*  37 */ ImGuiKey_K,
    /*  38 */ ImGuiKey_L,
    /*  39 */ ImGuiKey_Semicolon,
    /*  40 */ ImGuiKey_Apostrophe,
    /*  41 */ ImGuiKey_GraveAccent,
    /*  42 */ ImGuiKey_LeftShift,
    /*  43 */ ImGuiKey_Backslash,
    /*  44 */ ImGuiKey_Z,
    /*  45 */ ImGuiKey_X,
    /*  46 */ ImGuiKey_C,
    /*  47 */ ImGuiKey_V,
    /*  48 */ ImGuiKey_B,
    /*  49 */ ImGuiKey_N,
    /*  50 */ ImGuiKey_M,
    /*  51 */ ImGuiKey_Comma,
    /*  52 */ ImGuiKey_Period,
    /*  53 */ ImGuiKey_Slash,
    /*  54 */ ImGuiKey_RightShift,
    /*  55 */ ImGuiKey_KeypadMultiply,
    /*  56 */ ImGuiKey_LeftAlt,
    /*  57 */ ImGuiKey_Space,
    /*  58 */ ImGuiKey_CapsLock,
    /*  59 */ ImGuiKey_F1,
    /*  60 */ ImGuiKey_F2,
    /*  61 */ ImGuiKey_F3,
    /*  62 */ ImGuiKey_F4,
    /*  63 */ ImGuiKey_F5,
    /*  64 */ ImGuiKey_F6,
    /*  65 */ ImGuiKey_F7,
    /*  66 */ ImGuiKey_F8,
    /*  67 */ ImGuiKey_F9,
    /*  68 */ ImGuiKey_F10,
    /*  69 */ ImGuiKey_NumLock,
    /*  70 */ ImGuiKey_ScrollLock,
    /*  71 */ ImGuiKey_Keypad7,
    /*  72 */ ImGuiKey_Keypad8,
    /*  73 */ ImGuiKey_Keypad9,
    /*  74 */ ImGuiKey_KeypadSubtract,
    /*  75 */ ImGuiKey_Keypad4,
    /*  76 */ ImGuiKey_Keypad5,
    /*  77 */ ImGuiKey_Keypad6,
    /*  78 */ ImGuiKey_KeypadAdd,
    /*  79 */ ImGuiKey_Keypad1,
    /*  80 */ ImGuiKey_Keypad2,
    /*  81 */ ImGuiKey_Keypad3,
    /*  82 */ ImGuiKey_Keypad0,
    /*  83 */ ImGuiKey_KeypadDecimal,
    /*  84 */ ImGuiKey_RightAlt,
    /*  85 */ ImGuiKey_None,
    /*  86 */ ImGuiKey_Backslash,
    /*  87 */ ImGuiKey_F11,
    /*  88 */ ImGuiKey_F12,
    /*  89 */ ImGuiKey_None,
    /*  90 */ ImGuiKey_None,
    /*  91 */ ImGuiKey_None,
    /*  92 */ ImGuiKey_None,
    /*  93 */ ImGuiKey_None,
    /*  94 */ ImGuiKey_None,
    /*  95 */ ImGuiKey_None,
    /*  96 */ ImGuiKey_KeypadEnter,
    /*  97 */ ImGuiKey_RightCtrl,
    /*  98 */ ImGuiKey_KeypadDivide,
    /*  99 */ ImGuiKey_PrintScreen,
    /* 100 */ ImGuiKey_RightAlt,
    /* 101 */ ImGuiKey_None,
    /* 102 */ ImGuiKey_Home,
    /* 103 */ ImGuiKey_UpArrow,
    /* 104 */ ImGuiKey_PageUp,
    /* 105 */ ImGuiKey_LeftArrow,
    /* 106 */ ImGuiKey_RightArrow,
    /* 107 */ ImGuiKey_End,
    /* 108 */ ImGuiKey_DownArrow,
    /* 109 */ ImGuiKey_PageDown,
    /* 110 */ ImGuiKey_Insert,
    /* 111 */ ImGuiKey_Delete,
    /* 112 */ ImGuiKey_None,
    /* 113 */ ImGuiKey_None,
    /* 114 */ ImGuiKey_None,
    /* 115 */ ImGuiKey_None,
    /* 116 */ ImGuiKey_None,
    /* 117 */ ImGuiKey_KeypadEqual,
    /* 118 */ ImGuiKey_None,
    /* 119 */ ImGuiKey_Pause,
    /* 120 */ ImGuiKey_None,
    /* 121 */ ImGuiKey_KeypadDecimal,
    /* 122 */ ImGuiKey_None,
    /* 123 */ ImGuiKey_None,
    /* 124 */ ImGuiKey_None,
    /* 125 */ ImGuiKey_LeftSuper,
    /* 126 */ ImGuiKey_RightSuper,
    /* 127 */ ImGuiKey_Menu,
};

WaylandKeyboard::WaylandKeyboard( wl_keyboard* keyboard )
    : m_keyboard( keyboard )
    , m_keymap( nullptr )
    , m_state( nullptr )
    , m_composeTable( nullptr )
    , m_composeState( nullptr )
{
    m_xkbCtx = xkb_context_new( XKB_CONTEXT_NO_FLAGS );

    static constexpr wl_keyboard_listener listener = {
        .keymap = Method( Keymap ),
        .enter = Method( Enter ),
        .leave = Method( Leave ),
        .key = Method( Key ),
        .modifiers = Method( Modifiers ),
        .repeat_info = Method( RepeatInfo ),
    };

    wl_keyboard_add_listener( m_keyboard, &listener, this );
}

WaylandKeyboard::~WaylandKeyboard()
{
    if( m_composeState ) xkb_compose_state_unref( m_composeState );
    if( m_composeTable ) xkb_compose_table_unref( m_composeTable );
    if( m_state ) xkb_state_unref( m_state );
    if( m_keymap ) xkb_keymap_unref( m_keymap );
    xkb_context_unref( m_xkbCtx );
    wl_keyboard_destroy( m_keyboard );
}

void WaylandKeyboard::Keymap( wl_keyboard* kbd, uint32_t format, int32_t fd, uint32_t size )
{
    if( format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 )
    {
        close( fd );
        return;
    }

    auto map = (char*)mmap( nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0 );
    close( fd );
    if( map == MAP_FAILED ) return;

    if( m_keymap ) xkb_keymap_unref( m_keymap );
    m_keymap = xkb_keymap_new_from_string( m_xkbCtx, map, XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS );
    munmap( map, size );
    if( !m_keymap ) return;

    if( m_state ) xkb_state_unref( m_state );
    m_state = xkb_state_new( m_keymap );

    const char* locale = getenv( "LC_ALL" );
    if( !locale )
    {
        locale = getenv( "LC_CTYPE" );
        if( !locale )
        {
            locale = getenv( "LANG" );
            if( !locale )
            {
                locale = "C";
            }
        }
    }

    if( m_composeTable ) xkb_compose_table_unref( m_composeTable );
    m_composeTable = xkb_compose_table_new_from_locale( m_xkbCtx, locale, XKB_COMPOSE_COMPILE_NO_FLAGS );

    if( m_composeState ) xkb_compose_state_unref( m_composeState );
    m_composeState = xkb_compose_state_new( m_composeTable, XKB_COMPOSE_STATE_NO_FLAGS );

    m_modCtrl = xkb_keymap_mod_get_index( m_keymap, XKB_MOD_NAME_CTRL );
    m_modAlt = xkb_keymap_mod_get_index( m_keymap, XKB_MOD_NAME_ALT );
    m_modShift = xkb_keymap_mod_get_index( m_keymap, XKB_MOD_NAME_SHIFT );
    m_modSuper = xkb_keymap_mod_get_index( m_keymap, XKB_MOD_NAME_LOGO );
}

void WaylandKeyboard::Enter( wl_keyboard* kbd, uint32_t serial, wl_surface* surf, wl_array* keys )
{
    ImGui::GetIO().AddFocusEvent( true );
}

void WaylandKeyboard::Leave( wl_keyboard* kbd, uint32_t serial, wl_surface* surf )
{
    ImGui::GetIO().AddFocusEvent( false );
}

void WaylandKeyboard::Key( wl_keyboard* kbd, uint32_t serial, uint32_t time, uint32_t key, uint32_t state )
{
    auto& io = ImGui::GetIO();
    if( key < ( sizeof( s_keyTable ) / sizeof( *s_keyTable ) ) )
    {
        io.AddKeyEvent( s_keyTable[key], state == WL_KEYBOARD_KEY_STATE_PRESSED );
    }

    if( state == WL_KEYBOARD_KEY_STATE_PRESSED )
    {
        const xkb_keysym_t* keysyms;
        if( xkb_state_key_get_syms( m_state, key + 8, &keysyms ) == 1 )
        {
            const auto sym = Compose( keysyms[0] );
            char txt[8];
            if( xkb_keysym_to_utf8( sym, txt, sizeof( txt ) ) > 0 )
            {
                ImGui::GetIO().AddInputCharactersUTF8( txt );
            }
        }
    }
}

void WaylandKeyboard::Modifiers( wl_keyboard* kbd, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group )
{
    xkb_state_update_mask( m_state, mods_depressed, mods_latched, mods_locked, 0, 0, group );

    auto& io = ImGui::GetIO();

    io.AddKeyEvent( ImGuiMod_Ctrl, xkb_state_mod_index_is_active( m_state, m_modCtrl, XKB_STATE_MODS_EFFECTIVE ) );
    io.AddKeyEvent( ImGuiMod_Shift, xkb_state_mod_index_is_active( m_state, m_modShift, XKB_STATE_MODS_EFFECTIVE ) );
    io.AddKeyEvent( ImGuiMod_Alt, xkb_state_mod_index_is_active( m_state, m_modAlt, XKB_STATE_MODS_EFFECTIVE ) );
    io.AddKeyEvent( ImGuiMod_Super, xkb_state_mod_index_is_active( m_state, m_modSuper, XKB_STATE_MODS_EFFECTIVE ) );
}

void WaylandKeyboard::RepeatInfo( wl_keyboard* kbd, int32_t rate, int32_t delay )
{
}

xkb_keysym_t WaylandKeyboard::Compose( xkb_keysym_t sym )
{
    if( sym == XKB_KEY_NoSymbol ) return sym;
    if( xkb_compose_state_feed( m_composeState, sym ) != XKB_COMPOSE_FEED_ACCEPTED ) return sym;
    switch( xkb_compose_state_get_status( m_composeState ) )
    {
    case XKB_COMPOSE_COMPOSED:
        return xkb_compose_state_get_one_sym( m_composeState );
    case XKB_COMPOSE_COMPOSING:
    case XKB_COMPOSE_CANCELLED:
        return XKB_KEY_NoSymbol;
    case XKB_COMPOSE_NOTHING:
    default:
        return sym;
    }
}
