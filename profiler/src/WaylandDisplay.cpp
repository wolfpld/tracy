#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "WaylandDisplay.hpp"
#include "WaylandMethod.hpp"
#include "WaylandOutput.hpp"
#include "WaylandRegistry.hpp"

namespace {
void Check( bool condition, const char* msg )
{
    if( !condition )
    {
        fprintf( stderr, "%s\n", msg );
        abort();
    }
}
}

WaylandDisplay::WaylandDisplay( int32_t& scale, std::function<void(wl_pointer*, uint32_t)> setCursor )
    : m_dpy( wl_display_connect( nullptr ) )
    , m_decorationManager( nullptr )
    , m_activation( nullptr )
    , m_scale( scale )
    , m_setCursor( std::move( setCursor ) )
{
    Check( m_dpy, "Failed to connect to Wayland display" );

    static constexpr wl_registry_listener listener = {
        .global = Method( RegistryGlobal ),
        .global_remove = Method( RegistryGlobalRemove ),
    };

    wl_registry_add_listener( wl_display_get_registry( m_dpy ), &listener, this );
    wl_display_roundtrip( m_dpy );

    Check( m_compositor, "Wayland compositor not found" );
    Check( m_shm, "Wayland shared memory not found" );
    Check( m_wmBase, "Wayland window manager not found" );
    Check( m_seat, "Wayland seat not found" );
}

WaylandDisplay::~WaylandDisplay()
{
    if( m_decorationManager ) zxdg_decoration_manager_v1_destroy( m_decorationManager );
    if( m_activation ) xdg_activation_v1_destroy( m_activation );
    m_outputs.clear();
    m_keyboard.reset();
    m_pointer.reset();
    wl_seat_destroy( m_seat );
    xdg_wm_base_destroy( m_wmBase );
    wl_shm_destroy( m_shm );
    wl_compositor_destroy( m_compositor );
    wl_display_disconnect( m_dpy );
}

WaylandOutput* WaylandDisplay::GetOutput( wl_output* output, uint32_t& id )
{
    auto it = std::find_if( m_outputs.begin(), m_outputs.end(), [output]( const auto& pair ) { return pair.second->Output() == output; } );
    if( it == m_outputs.end() ) return nullptr;
    id = it->first;
    return it->second.get();
}

WaylandOutput* WaylandDisplay::GetOutput( uint32_t id )
{
    auto it = m_outputs.find( id );
    if( it == m_outputs.end() ) return nullptr;
    return it->second.get();
}

void WaylandDisplay::RegistryGlobal( wl_registry* reg, uint32_t name, const char* interface, uint32_t version )
{
    if( strcmp( interface, wl_compositor_interface.name ) == 0 )
    {
        m_compositor = RegistryBind( wl_compositor, 3, 4 );
    }
    else if ( strcmp( interface, wl_shm_interface.name ) == 0 )
    {
        m_shm = RegistryBind( wl_shm );
    }
    else if( strcmp( interface, xdg_wm_base_interface.name ) == 0 )
    {
        static constexpr xdg_wm_base_listener listener = {
            .ping = Method( XdgWmPing )
        };

        m_wmBase = RegistryBind( xdg_wm_base );
        xdg_wm_base_add_listener( m_wmBase, &listener, this );
    }
    else if( strcmp( interface, wl_seat_interface.name ) == 0 )
    {
        static constexpr wl_seat_listener listener = {
            .capabilities = Method( SeatCapabilities ),
            .name = Method( SeatName )
        };

        m_seat = RegistryBind( wl_seat, 5, 9 );
        wl_seat_add_listener( m_seat, &listener, this );
    }
    else if( strcmp( interface, wl_output_interface.name ) == 0 )
    {
        auto output = RegistryBind( wl_output, 3, 4 );
        m_outputs.emplace( name, std::make_unique<WaylandOutput>( output ) );
    }
    else if( strcmp( interface, zxdg_decoration_manager_v1_interface.name ) == 0 )
    {
        m_decorationManager = RegistryBind( zxdg_decoration_manager_v1 );
    }
    else if( strcmp( interface, xdg_activation_v1_interface.name ) == 0 )
    {
        m_activation = RegistryBind( xdg_activation_v1 );
    }
}

void WaylandDisplay::RegistryGlobalRemove( wl_registry* reg, uint32_t name )
{
    auto it = m_outputs.find( name );
    if( it != m_outputs.end() ) m_outputs.erase( it );
}

void WaylandDisplay::XdgWmPing( xdg_wm_base* shell, uint32_t serial )
{
    xdg_wm_base_pong( shell, serial );
}

void WaylandDisplay::SeatCapabilities( wl_seat* seat, uint32_t caps )
{
    const bool hasPointer = caps & WL_SEAT_CAPABILITY_POINTER;
    const bool hasKeyboard = caps & WL_SEAT_CAPABILITY_KEYBOARD;

    if( hasPointer && !m_pointer )
    {
        m_pointer = std::make_unique<WaylandPointer>( wl_seat_get_pointer( seat ), m_scale, m_setCursor );
    }
    else if( !hasPointer && m_pointer )
    {
        m_pointer.reset();
    }

    if( hasKeyboard && !m_keyboard )
    {
        m_keyboard = std::make_unique<WaylandKeyboard>( wl_seat_get_keyboard( seat ) );
    }
    else if( !hasKeyboard && m_keyboard )
    {
        m_keyboard.reset();
    }
}

void WaylandDisplay::SeatName( wl_seat* seat, const char* name )
{
}
