#include "player.hpp"

#include "gfx.hpp"
#include "map.hpp"
#include "texture.hpp"
#include "timer.hpp"
#include "world.hpp"

#include <tracy/Tracy.hpp>

namespace dyna
{

Player::Player( int gx, int gy )
{
    x = gx * 64;
    y = gy * 64;
    set_action( Action::wait );
    queue = Action::wait;
}

void Player::tick( World& world )
{
    ZoneScoped;
    Map& map = world.map();

    delta += Timer::delta;

    while( delta > t )
    {
        delta -= t;

        if( left > 0 )
        {
            left--;

            switch( action )
            {
            case Action::down: y++; break;
            case Action::up: y--; break;
            case Action::left: x--; break;
            case Action::right: x++; break;
            case Action::place_bomb:
                if( left == 0 )
                    map.place_bomb( x / 64, y / 64 );
                break;
            default:
                break;
            }
        }
        else
        {
            if( action == Action::death )
            {
                die( world );
                return;
            }
            if( map.at( x / 64, y / 64 ).kind == Field::Kind::vortex )
            {
                world.next_level = true;
                return;
            }
            if( !can_move( queue, map ) )
                queue = Action::wait;

            if( action != queue )
                set_action( queue );

            if( action != Action::wait )
                left = 64;
            if( action == Action::place_bomb )
                left = 32;
        }

        if( action != Action::death && killed( map ) )
        {
            set_action( Action::death );
            left = 1140 / t;
        }
    }
}

void Player::draw()
{
    ZoneScoped;
    const AnimTexture* tex = nullptr;

    switch( action )
    {
    case Action::wait: tex = &Textures::p_wait; break;
    case Action::up: tex = &Textures::p_u; break;
    case Action::down: tex = &Textures::p_d; break;
    case Action::left: tex = &Textures::p_l; break;
    case Action::right: tex = &Textures::p_r; break;
    case Action::death: tex = &Textures::p_death; break;
    case Action::place_bomb: tex = &Textures::p_wait; break;
    default:
        return;
    }

    int frame = static_cast<int>( Timer::get_timestamp() - action_start );
    frame /= ( action == Action::death ) ? 60 : 40;
    tex->bind( frame );

    Gfx::draw_sprite( x, y );
}

void Player::move( Action a )
{
    queue = a;
}

void Player::die( World& world )
{
    world.killed = true;
}

bool Player::killed( const Map& map ) const
{
    if( Entity::killed( map ) )
        return true;
    if( map.monster_collide( x, y ) )
        return true;
    return false;
}

}
