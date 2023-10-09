#include <EGL/egl.h>
#include <EGL/eglext.h>

#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_opengl3_loader.h"

#include <chrono>
#include <linux/input-event-codes.h>
#include <memory>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <unordered_map>
#include <xkbcommon/xkbcommon.h>
#include <xkbcommon/xkbcommon-compose.h>
#include <wayland-client.h>
#include <wayland-cursor.h>
#include <wayland-egl.h>

#include "wayland/xdg-activation.h"
#include "wayland/xdg-decoration.h"
#include "wayland/xdg-shell.h"

#include "../../server/TracyImGui.hpp"

#include "Backend.hpp"
#include "RunQueue.hpp"

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

static std::function<void()> s_redraw;
static RunQueue* s_mainThreadTasks;

static struct wl_display* s_dpy;
static struct wl_compositor* s_comp;
static struct wl_surface* s_surf;
static struct wl_egl_window* s_eglWin;
static struct wl_shm* s_shm;
static struct xdg_wm_base* s_wm;
static EGLDisplay s_eglDpy;
static EGLContext s_eglCtx;
static EGLSurface s_eglSurf;
static struct xdg_surface* s_xdgSurf;
static struct xdg_toplevel* s_toplevel;
static struct wl_seat* s_seat;
static struct wl_pointer* s_pointer;
static struct wl_cursor_theme* s_cursorTheme;
static struct wl_surface* s_cursorSurf;
static int32_t s_cursorX, s_cursorY;
static struct xdg_activation_v1* s_activation;
static struct xdg_activation_token_v1* s_actToken;
static struct zxdg_decoration_manager_v1* s_decoration;
static struct zxdg_toplevel_decoration_v1* s_tldec;
static struct wl_keyboard* s_keyboard;
static struct xkb_context* s_xkbCtx;
static struct xkb_keymap* s_xkbKeymap;
static struct xkb_state* s_xkbState;
static struct xkb_compose_table* s_xkbComposeTable;
static struct xkb_compose_state* s_xkbComposeState;
static xkb_mod_index_t s_xkbCtrl, s_xkbAlt, s_xkbShift, s_xkbSuper;

struct Output
{
    int32_t scale;
    wl_output* obj;
};
static std::unordered_map<uint32_t, std::unique_ptr<Output>> s_output;
static int s_maxScale = 1;
static int s_prevScale = 1;

static bool s_running = true;
static int s_w, s_h;
static bool s_maximized;
static uint64_t s_time;

static wl_fixed_t s_wheelAxisX, s_wheelAxisY;
static bool s_wheel;

static void PointerEnter( void*, struct wl_pointer* pointer, uint32_t serial, struct wl_surface* surf, wl_fixed_t sx, wl_fixed_t sy )
{
    wl_pointer_set_cursor( pointer, serial, s_cursorSurf, s_cursorX, s_cursorY );
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( wl_fixed_to_double( sx * s_maxScale ), wl_fixed_to_double( sy * s_maxScale ) );
}

static void PointerLeave( void*, struct wl_pointer* pointer, uint32_t serial, struct wl_surface* surf )
{
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( -FLT_MAX, -FLT_MAX );
}

static void PointerMotion( void*, struct wl_pointer* pointer, uint32_t time, wl_fixed_t sx, wl_fixed_t sy )
{
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent( wl_fixed_to_double( sx * s_maxScale ), wl_fixed_to_double( sy * s_maxScale ) );
}

static void PointerButton( void*, struct wl_pointer* pointer, uint32_t serial, uint32_t time, uint32_t button, uint32_t state )
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

static void PointerAxis( void*, struct wl_pointer* pointer, uint32_t time, uint32_t axis, wl_fixed_t value )
{
    s_wheel = true;
    if( axis == WL_POINTER_AXIS_HORIZONTAL_SCROLL )
    {
        s_wheelAxisX -= value;
    }
    else
    {
        s_wheelAxisY -= value;
    }
}

static void PointerAxisSource( void*, struct wl_pointer* pointer, uint32_t source )
{
}

static void PointerAxisStop( void*, struct wl_pointer* pointer, uint32_t time, uint32_t axis )
{
}

static void PointerAxisDiscrete( void*, struct wl_pointer* pointer, uint32_t axis, int32_t type )
{
}

static void PointerFrame( void*, struct wl_pointer* pointer )
{
    if( s_wheel )
    {
        s_wheel = false;
        s_wheelAxisX /= 8;
        s_wheelAxisY /= 8;
        ImGuiIO& io = ImGui::GetIO();
        io.AddMouseWheelEvent( wl_fixed_to_double( s_wheelAxisX ), wl_fixed_to_double( s_wheelAxisY ) );
        s_wheelAxisX = s_wheelAxisY = 0;
    }
}

constexpr struct wl_pointer_listener pointerListener = {
    .enter = PointerEnter,
    .leave = PointerLeave,
    .motion = PointerMotion,
    .button = PointerButton,
    .axis = PointerAxis,
    .frame = PointerFrame,
    .axis_source = PointerAxisSource,
    .axis_stop = PointerAxisStop,
    .axis_discrete = PointerAxisDiscrete
};


static void KeyboardKeymap( void*, struct wl_keyboard* kbd, uint32_t format, int32_t fd, uint32_t size )
{
    if( format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1 )
    {
        close( fd );
        return;
    }

    auto map = (char*)mmap( nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0 );
    close( fd );
    if( map == MAP_FAILED ) return;

    if( s_xkbKeymap ) xkb_keymap_unref( s_xkbKeymap );
    s_xkbKeymap = xkb_keymap_new_from_string( s_xkbCtx, map, XKB_KEYMAP_FORMAT_TEXT_V1, XKB_KEYMAP_COMPILE_NO_FLAGS );
    munmap( map, size );
    if( !s_xkbKeymap ) return;

    if( s_xkbState ) xkb_state_unref( s_xkbState );
    s_xkbState = xkb_state_new( s_xkbKeymap );

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

    if( s_xkbComposeTable ) xkb_compose_table_unref( s_xkbComposeTable );
    s_xkbComposeTable = xkb_compose_table_new_from_locale( s_xkbCtx, locale, XKB_COMPOSE_COMPILE_NO_FLAGS );

    if( s_xkbComposeState ) xkb_compose_state_unref( s_xkbComposeState );
    s_xkbComposeState = xkb_compose_state_new( s_xkbComposeTable, XKB_COMPOSE_STATE_NO_FLAGS );

    s_xkbCtrl = xkb_keymap_mod_get_index( s_xkbKeymap, "Control" );
    s_xkbAlt = xkb_keymap_mod_get_index( s_xkbKeymap, "Mod1" );
    s_xkbShift = xkb_keymap_mod_get_index( s_xkbKeymap, "Shift" );
    s_xkbSuper = xkb_keymap_mod_get_index( s_xkbKeymap, "Mod4" );
}

static void KeyboardEnter( void*, struct wl_keyboard* kbd, uint32_t serial, struct wl_surface* surf, struct wl_array* keys )
{
    ImGui::GetIO().AddFocusEvent( true );
}

static void KeyboardLeave( void*, struct wl_keyboard* kbd, uint32_t serial, struct wl_surface* surf )
{
    ImGui::GetIO().AddFocusEvent( false );
}

static xkb_keysym_t Compose( const xkb_keysym_t sym )
{
    if( sym == XKB_KEY_NoSymbol ) return sym;
    if( xkb_compose_state_feed( s_xkbComposeState, sym ) != XKB_COMPOSE_FEED_ACCEPTED ) return sym;
    switch( xkb_compose_state_get_status( s_xkbComposeState ) )
    {
    case XKB_COMPOSE_COMPOSED:
        return xkb_compose_state_get_one_sym( s_xkbComposeState );
    case XKB_COMPOSE_COMPOSING:
    case XKB_COMPOSE_CANCELLED:
        return XKB_KEY_NoSymbol;
    case XKB_COMPOSE_NOTHING:
    default:
        return sym;
    }
}

static void KeyboardKey( void*, struct wl_keyboard* kbd, uint32_t serial, uint32_t time, uint32_t key, uint32_t state )
{
    auto& io = ImGui::GetIO();
    if( key < ( sizeof( s_keyTable ) / sizeof( *s_keyTable ) ) )
    {
        io.AddKeyEvent( s_keyTable[key], state == WL_KEYBOARD_KEY_STATE_PRESSED );
    }

    if( state == WL_KEYBOARD_KEY_STATE_PRESSED )
    {
        const xkb_keysym_t* keysyms;
        if( xkb_state_key_get_syms( s_xkbState, key + 8, &keysyms ) == 1 )
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

static void KeyboardModifiers( void*, struct wl_keyboard* kbd, uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched, uint32_t mods_locked, uint32_t group )
{
    xkb_state_update_mask( s_xkbState, mods_depressed, mods_latched, mods_locked, 0, 0, group );

    auto& io = ImGui::GetIO();

    io.AddKeyEvent( ImGuiMod_Ctrl, xkb_state_mod_index_is_active( s_xkbState, s_xkbCtrl, XKB_STATE_MODS_EFFECTIVE ) );
    io.AddKeyEvent( ImGuiMod_Shift, xkb_state_mod_index_is_active( s_xkbState, s_xkbShift, XKB_STATE_MODS_EFFECTIVE ) );
    io.AddKeyEvent( ImGuiMod_Alt, xkb_state_mod_index_is_active( s_xkbState, s_xkbAlt, XKB_STATE_MODS_EFFECTIVE ) );
    io.AddKeyEvent( ImGuiMod_Super, xkb_state_mod_index_is_active( s_xkbState, s_xkbSuper, XKB_STATE_MODS_EFFECTIVE ) );
}

static void KeyboardRepeatInfo( void*, struct wl_keyboard* kbd, int32_t rate, int32_t delay )
{
}

constexpr struct wl_keyboard_listener keyboardListener = {
    .keymap = KeyboardKeymap,
    .enter = KeyboardEnter,
    .leave = KeyboardLeave,
    .key = KeyboardKey,
    .modifiers = KeyboardModifiers,
    .repeat_info = KeyboardRepeatInfo
};


static void SeatCapabilities( void*, struct wl_seat* seat, uint32_t caps )
{
    const bool hasPointer = caps & WL_SEAT_CAPABILITY_POINTER;
    const bool hasKeyboard = caps & WL_SEAT_CAPABILITY_KEYBOARD;

    if( hasPointer && !s_pointer )
    {
        s_pointer = wl_seat_get_pointer( s_seat );
        wl_pointer_add_listener( s_pointer, &pointerListener, nullptr );
    }
    else if( !hasPointer && s_pointer )
    {
        wl_pointer_release( s_pointer );
        s_pointer = nullptr;
    }

    if( hasKeyboard && !s_keyboard )
    {
        s_keyboard = wl_seat_get_keyboard( s_seat );
        wl_keyboard_add_listener( s_keyboard, &keyboardListener, nullptr );
    }
    else if( !hasKeyboard && s_keyboard )
    {
        wl_keyboard_release( s_keyboard );
        s_keyboard = nullptr;
    }
}

static void SeatName( void*, struct wl_seat* seat, const char* name )
{
}

constexpr struct wl_seat_listener seatListener = {
    .capabilities = SeatCapabilities,
    .name = SeatName
};


static void WmPing( void*, struct xdg_wm_base* shell, uint32_t serial )
{
    xdg_wm_base_pong( shell, serial );
}

constexpr struct xdg_wm_base_listener wmListener = {
    .ping = WmPing
};


static void OutputGeometry( void*, struct wl_output* output, int32_t x, int32_t y, int32_t phys_w, int32_t phys_h, int32_t subpixel, const char* make, const char* model, int32_t transform )
{
}

static void OutputMode( void*, struct wl_output* output, uint32_t flags, int32_t w, int32_t h, int32_t refresh )
{
}

static void OutputDone( void*, struct wl_output* output )
{
    int max = 1;
    for( auto& out : s_output )
    {
        if( out.second->scale > max ) max = out.second->scale;
    }
    s_maxScale = max;
}

static void OutputScale( void* data, struct wl_output* output, int32_t scale )
{
    auto out = (Output*)data;
    out->scale = scale;
}

constexpr struct wl_output_listener outputListener = {
    .geometry = OutputGeometry,
    .mode = OutputMode,
    .done = OutputDone,
    .scale = OutputScale
};


static void DecorationConfigure( void*, struct zxdg_toplevel_decoration_v1* tldec, uint32_t mode )
{
}

constexpr struct zxdg_toplevel_decoration_v1_listener decorationListener = {
    .configure = DecorationConfigure
};


static void RegistryGlobal( void*, struct wl_registry* reg, uint32_t name, const char* interface, uint32_t version )
{
    if( strcmp( interface, wl_compositor_interface.name ) == 0 )
    {
        s_comp = (wl_compositor*)wl_registry_bind( reg, name, &wl_compositor_interface, 4 );
    }
    else if( strcmp( interface, wl_shm_interface.name ) == 0 )
    {
        s_shm = (wl_shm*)wl_registry_bind( reg, name, &wl_shm_interface, 1 );
    }
    else if( strcmp( interface, xdg_wm_base_interface.name ) == 0 )
    {
        s_wm = (xdg_wm_base*)wl_registry_bind( reg, name, &xdg_wm_base_interface, 1 );
        xdg_wm_base_add_listener( s_wm, &wmListener, nullptr );
    }
    else if( strcmp( interface, wl_seat_interface.name ) == 0 )
    {
        s_seat = (wl_seat*)wl_registry_bind( reg, name, &wl_seat_interface, 5 );
        wl_seat_add_listener( s_seat, &seatListener, nullptr );
    }
    else if( strcmp( interface, xdg_activation_v1_interface.name ) == 0 )
    {
        s_activation = (xdg_activation_v1*)wl_registry_bind( reg, name, &xdg_activation_v1_interface, 1 );
    }
    else if( strcmp( interface, wl_output_interface.name ) == 0 )
    {
        auto output = (wl_output*)wl_registry_bind( reg, name, &wl_output_interface, 2 );
        auto ptr = std::make_unique<Output>( Output { 1, output } );
        wl_output_add_listener( output, &outputListener, ptr.get() );
        s_output.emplace( name, std::move( ptr ) );
    }
    else if( strcmp( interface, zxdg_decoration_manager_v1_interface.name ) == 0 )
    {
        s_decoration = (zxdg_decoration_manager_v1*)wl_registry_bind( reg, name, &zxdg_decoration_manager_v1_interface, 1 );
    }
}

static void RegistryGlobalRemove( void*, struct wl_registry* reg, uint32_t name )
{
    auto it = s_output.find( name );
    if( it == s_output.end() ) return;
    wl_output_destroy( it->second->obj );
    s_output.erase( it );
}

constexpr struct wl_registry_listener registryListener = {
    .global = RegistryGlobal,
    .global_remove = RegistryGlobalRemove
};


static void XdgSurfaceConfigure( void*, struct xdg_surface* surf, uint32_t serial )
{
    tracy::s_wasActive = true;
    xdg_surface_ack_configure( surf, serial );
}

constexpr struct xdg_surface_listener xdgSurfaceListener = {
    .configure = XdgSurfaceConfigure
};


static void XdgToplevelConfigure( void*, struct xdg_toplevel* toplevel, int32_t width, int32_t height, struct wl_array* states )
{
    if( width == 0 || height == 0 ) return;

    bool max = false;
    auto data = (uint32_t*)states->data;
    for( size_t i = 0; i < states->size / sizeof(uint32_t); i++ )
    {
        if( data[i] == XDG_TOPLEVEL_STATE_MAXIMIZED )
        {
            max = true;
            break;
        }
    }
    s_maximized = max;

    width *= s_maxScale;
    height *= s_maxScale;

    if( s_w != width || s_h != height )
    {
        s_w = width;
        s_h = height;

        wl_egl_window_resize( s_eglWin, width, height, 0, 0 );
        wl_surface_commit( s_surf );
    }
}

static void XdgToplevelClose( void*, struct xdg_toplevel* toplevel )
{
    s_running = false;
}

constexpr struct xdg_toplevel_listener toplevelListener = {
    .configure = XdgToplevelConfigure,
    .close = XdgToplevelClose
};

static void SetupCursor()
{
    auto env_xcursor_theme = getenv( "XCURSOR_THEME" );
    auto env_xcursor_size = getenv( "XCURSOR_SIZE" );

    int size = env_xcursor_size ? atoi( env_xcursor_size ) : 24;
    size *= s_maxScale;

    if( s_cursorSurf ) wl_surface_destroy( s_cursorSurf );
    if( s_cursorTheme ) wl_cursor_theme_destroy( s_cursorTheme );

    s_cursorTheme = wl_cursor_theme_load( env_xcursor_theme, size, s_shm );
    auto cursor = wl_cursor_theme_get_cursor( s_cursorTheme, "left_ptr" );
    s_cursorSurf = wl_compositor_create_surface( s_comp );
    if( s_maxScale != 1 ) wl_surface_set_buffer_scale( s_cursorSurf, s_maxScale );
    wl_surface_attach( s_cursorSurf, wl_cursor_image_get_buffer( cursor->images[0] ), 0, 0 );
    wl_surface_commit( s_cursorSurf );
    s_cursorX = cursor->images[0]->hotspot_x / s_maxScale;
    s_cursorY = cursor->images[0]->hotspot_y / s_maxScale;
}

Backend::Backend( const char* title, const std::function<void()>& redraw, RunQueue* mainThreadTasks )
{
    s_redraw = redraw;
    s_mainThreadTasks = mainThreadTasks;
    s_w = m_winPos.w;
    s_h = m_winPos.h;
    s_maximized = m_winPos.maximize;

    s_dpy = wl_display_connect( nullptr );
    if( !s_dpy ) { fprintf( stderr, "Cannot establish wayland display connection!\n" ); exit( 1 ); }

    wl_registry_add_listener( wl_display_get_registry( s_dpy ), &registryListener, nullptr );
    s_xkbCtx = xkb_context_new( XKB_CONTEXT_NO_FLAGS );
    wl_display_roundtrip( s_dpy );

    if( !s_comp ) { fprintf( stderr, "No wayland compositor!\n" ); exit( 1 ); }
    if( !s_shm ) { fprintf( stderr, "No wayland shared memory!\n" ); exit( 1 ); }
    if( !s_wm ) { fprintf( stderr, "No wayland window manager!\n" ); exit( 1 ); }
    if( !s_seat ) { fprintf( stderr, "No wayland seat!\n" ); exit( 1 ); }

    s_surf = wl_compositor_create_surface( s_comp );
    s_eglWin = wl_egl_window_create( s_surf, m_winPos.w, m_winPos.h );
    s_xdgSurf = xdg_wm_base_get_xdg_surface( s_wm, s_surf );
    xdg_surface_add_listener( s_xdgSurf, &xdgSurfaceListener, nullptr );

    SetupCursor();

    constexpr EGLint eglConfigAttrib[] = {
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
        EGL_RED_SIZE, 8,
        EGL_GREEN_SIZE, 8,
        EGL_BLUE_SIZE, 8,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_NONE
    };

    s_eglDpy = eglGetPlatformDisplay( EGL_PLATFORM_WAYLAND_KHR, s_dpy, nullptr );
    EGLBoolean res;
    res = eglInitialize( s_eglDpy, nullptr, nullptr );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot initialize EGL!\n" ); exit( 1 ); }

    EGLint count;
    EGLConfig eglConfig;
    res = eglChooseConfig( s_eglDpy, eglConfigAttrib, &eglConfig, 1, &count );
    if( res != EGL_TRUE || count != 1 ) { fprintf( stderr, "No suitable EGL config found!\n" ); exit( 1 ); }

    res = eglBindAPI( EGL_OPENGL_API );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot use OpenGL through EGL!\n" ); exit( 1 ); }

    s_eglSurf = eglCreatePlatformWindowSurface( s_eglDpy, eglConfig, s_eglWin, nullptr );

    constexpr EGLint eglCtxAttrib[] = {
        EGL_CONTEXT_MAJOR_VERSION, 3,
        EGL_CONTEXT_MINOR_VERSION, 2,
        EGL_CONTEXT_OPENGL_PROFILE_MASK,  EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT,
        EGL_NONE
    };

    s_eglCtx = eglCreateContext( s_eglDpy, eglConfig, EGL_NO_CONTEXT, eglCtxAttrib );
    if( !s_eglCtx ) { fprintf( stderr, "Cannot create OpenGL 3.2 Core Profile context!\n" ); exit( 1 ); }
    res = eglMakeCurrent( s_eglDpy, s_eglSurf, s_eglSurf, s_eglCtx );
    if( res != EGL_TRUE ) { fprintf( stderr, "Cannot make EGL context current!\n" ); exit( 1 ); }

    ImGui_ImplOpenGL3_Init( "#version 150" );

    wl_display_roundtrip( s_dpy );
    s_toplevel = xdg_surface_get_toplevel( s_xdgSurf );
    xdg_toplevel_add_listener( s_toplevel, &toplevelListener, nullptr );
    xdg_toplevel_set_title( s_toplevel, title );
    xdg_toplevel_set_app_id( s_toplevel, "tracy" );

    if( s_decoration )
    {
        s_tldec = zxdg_decoration_manager_v1_get_toplevel_decoration( s_decoration, s_toplevel );
        zxdg_toplevel_decoration_v1_add_listener( s_tldec, &decorationListener, nullptr );
        zxdg_toplevel_decoration_v1_set_mode( s_tldec, ZXDG_TOPLEVEL_DECORATION_V1_MODE_SERVER_SIDE );
        wl_display_roundtrip( s_dpy );
    }

    ImGuiIO& io = ImGui::GetIO();
    io.BackendPlatformName = "wayland (tracy profiler)";
    s_time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
}

Backend::~Backend()
{
    if( s_tldec ) zxdg_toplevel_decoration_v1_destroy( s_tldec );
    if( s_decoration ) zxdg_decoration_manager_v1_destroy( s_decoration );
    if( s_actToken ) xdg_activation_token_v1_destroy( s_actToken );
    if( s_activation ) xdg_activation_v1_destroy( s_activation );
    if( s_keyboard ) wl_keyboard_destroy( s_keyboard );
    if( s_pointer ) wl_pointer_destroy( s_pointer );
    eglMakeCurrent( s_eglDpy, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT );
    eglDestroySurface( s_eglDpy, s_eglSurf );
    eglDestroyContext( s_eglDpy, s_eglCtx );
    eglTerminate( s_eglDpy );
    xdg_toplevel_destroy( s_toplevel );
    wl_surface_destroy( s_cursorSurf );
    wl_cursor_theme_destroy( s_cursorTheme );
    xdg_surface_destroy( s_xdgSurf );
    wl_egl_window_destroy( s_eglWin );
    wl_surface_destroy( s_surf );
    for( auto& v : s_output ) wl_output_destroy( v.second->obj );
    s_output.clear();
    wl_seat_destroy( s_seat );
    xdg_wm_base_destroy( s_wm );
    wl_shm_destroy( s_shm );
    wl_compositor_destroy( s_comp );
    if( s_xkbComposeState ) xkb_compose_state_unref( s_xkbComposeState );
    if( s_xkbComposeTable ) xkb_compose_table_unref( s_xkbComposeTable );
    if( s_xkbState ) xkb_state_unref( s_xkbState );
    if( s_xkbKeymap ) xkb_keymap_unref( s_xkbKeymap );
    xkb_context_unref( s_xkbCtx );
    wl_display_disconnect( s_dpy );
}

void Backend::Show()
{
    wl_surface_commit( s_surf );
}

void Backend::Run()
{
    while( s_running && wl_display_dispatch( s_dpy ) != -1 )
    {
        s_redraw();
        s_mainThreadTasks->Run();
    }
}


static void TokenDone( void*, xdg_activation_token_v1* token, const char* str )
{
    xdg_activation_v1_activate( s_activation, str, s_surf );
    xdg_activation_token_v1_destroy( token );
    s_actToken = nullptr;
}

constexpr struct xdg_activation_token_v1_listener tokenListener = {
    .done = TokenDone
}; 


void Backend::Attention()
{
    if( !s_activation ) return;
    if( s_actToken ) return;
    s_actToken = xdg_activation_v1_get_activation_token( s_activation );
    xdg_activation_token_v1_set_surface( s_actToken, s_surf );
    xdg_activation_token_v1_commit( s_actToken );
    xdg_activation_token_v1_add_listener( s_actToken, &tokenListener, nullptr );
}

void Backend::NewFrame( int& w, int& h )
{
    if( s_prevScale != s_maxScale )
    {
        SetupCursor();
        wl_surface_set_buffer_scale( s_surf, s_maxScale );
        s_prevScale = s_maxScale;
    }

    m_winPos.maximize = s_maximized;
    if( !s_maximized )
    {
        m_winPos.w = s_w;
        m_winPos.h = s_h;
    }

    w = s_w;
    h = s_h;

    ImGuiIO& io = ImGui::GetIO();
    io.DisplaySize = ImVec2( w, h );
    io.DisplayFramebufferScale = ImVec2( 1, 1 );

    ImGui_ImplOpenGL3_NewFrame();

    uint64_t time = std::chrono::duration_cast<std::chrono::microseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
    io.DeltaTime = std::min( 0.1f, ( time - s_time ) / 1000000.f );
    s_time = time;
}

void Backend::EndFrame()
{
    const ImVec4 clear_color = ImColor( 114, 144, 154 );

    ImGui::Render();
    glViewport( 0, 0, s_w, s_h );
    glClearColor( clear_color.x, clear_color.y, clear_color.z, clear_color.w );
    glClear( GL_COLOR_BUFFER_BIT );
    ImGui_ImplOpenGL3_RenderDrawData( ImGui::GetDrawData() );

    eglSwapBuffers( s_eglDpy, s_eglSurf );
}

void Backend::SetIcon( uint8_t* data, int w, int h )
{
}

void Backend::SetTitle( const char* title )
{
    xdg_toplevel_set_title( s_toplevel, title );
}

float Backend::GetDpiScale()
{
    return s_maxScale;
}
