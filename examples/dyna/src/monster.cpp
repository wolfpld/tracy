#include "monster.hpp"

#include "gfx.hpp"
#include "map.hpp"
#include "texture.hpp"
#include "timer.hpp"
#include "world.hpp"

#include <tracy/Tracy.hpp>

namespace dyna
{

namespace
{

bool is_opposite( Action a, Action b )
{
    return ( a == Action::up && b == Action::down ) ||
           ( a == Action::down && b == Action::up ) ||
           ( a == Action::left && b == Action::right ) ||
           ( a == Action::right && b == Action::left );
}

} // namespace

Monster::Monster( int type, int gx, int gy )
    : mtype( type )
    , t( type == 1 ? 14 : type == 2 ? 11
                                    : 7 )
{
    x = gx * 64;
    y = gy * 64;
}

void Monster::set_action( Action a )
{
    Entity::set_action( a );
    if( action == Action::appear )
        left = 200;
}

std::vector<Action> Monster::possible_dirs( const Map& map ) const
{
    std::vector<Action> dirs;

    if( x > 0 && !map.at( x / 64 - 1, y / 64 ).solid() )
        dirs.push_back( Action::left );
    if( x / 64 < map.getx() - 1 && !map.at( x / 64 + 1, y / 64 ).solid() )
        dirs.push_back( Action::right );
    if( y > 0 && !map.at( x / 64, y / 64 - 1 ).solid() )
        dirs.push_back( Action::up );
    if( y / 64 < map.gety() - 1 && !map.at( x / 64, y / 64 + 1 ).solid() )
        dirs.push_back( Action::down );

    return dirs;
}

bool Monster::straight( const std::vector<Action>& dirs )
{
    return is_opposite( dirs[0], dirs[1] );
}

Action Monster::any_dir( const Map& map )
{
    std::vector<Action> dirs = possible_dirs( map );
    if( dirs.empty() )
        return Action::wait;
    return dirs[RNG::next( static_cast<int>( dirs.size() ) )];
}

Action Monster::rand_dir( const Map& map )
{
    Action tmp = any_dir( map );
    if( is_opposite( action, tmp ) )
        tmp = any_dir( map );
    return tmp;
}

void Monster::think( const Map& map )
{
    ZoneScoped;
    if( action == Action::wait || action == Action::appear )
    {
        set_action( rand_dir( map ) );
        return;
    }

    std::vector<Action> dirs = possible_dirs( map );

    if( dirs.size() == 2 && straight( dirs ) )
    {
        left = 64;
    }
    else
    {
        Action tmp = rand_dir( map );

        if( tmp == action )
        {
            left = 64;
        }
        else
        {
            set_action( tmp );
            if( tmp != Action::wait )
                left = 64;
        }
    }
}

void Monster::tick( World& world )
{
    ZoneScoped;
    Map& map = world.map();

    delta += Timer::delta;

    while( delta > t )
    {
        delta -= t;

        if( action == Action::wait )
        {
            think( map );
        }
        else if( left > 0 )
        {
            left--;

            switch( action )
            {
            case Action::down: y++; break;
            case Action::up: y--; break;
            case Action::left: x--; break;
            case Action::right: x++; break;
            default: break;
            }
        }
        else
        {
            if( action == Action::death )
                die( world );
            else
                think( map );
        }

        if( action != Action::death && killed( map ) )
        {
            set_action( Action::death );
            left = 790 / t;
        }
    }
}

void Monster::die( World& )
{
    dead = true;
}

const AnimTexture& Monster::texture_for( Action a ) const
{
    struct Set
    {
        const AnimTexture* wait;
        const AnimTexture* up;
        const AnimTexture* down;
        const AnimTexture* left;
        const AnimTexture* right;
        const AnimTexture* death;
    };

    Set s;
    if( mtype == 1 )
        s = { &Textures::m1_d, &Textures::m1_u, &Textures::m1_d, &Textures::m1_l, &Textures::m1_r, &Textures::m1_death };
    else if( mtype == 2 )
        s = { &Textures::m2_d, &Textures::m2_u, &Textures::m2_d, &Textures::m2_l, &Textures::m2_r, &Textures::m2_death };
    else
        s = { &Textures::m3_d, &Textures::m3_u, &Textures::m3_d, &Textures::m3_l, &Textures::m3_r, &Textures::m3_death };

    switch( a )
    {
    case Action::up: return *s.up;
    case Action::down: return *s.down;
    case Action::left: return *s.left;
    case Action::right: return *s.right;
    case Action::death: return *s.death;
    case Action::wait:
    case Action::appear:
    default: return *s.wait;   // wait/appear use the "down" sprite
    }
}

void Monster::draw()
{
    ZoneScoped;
    // The original returns without drawing for unexpected actions; monsters only
    // ever hold the actions handled by texture_for, so always draw.
    generic_draw( texture_for( action ) );
}

void Monster::generic_draw( const AnimTexture& tex )
{
    int frame;

    if( action == Action::wait )
    {
        frame = 0;
    }
    else if( action == Action::appear )
    {
        frame = 0;
        Gfx::alpha( static_cast<float>( 200 - left ) / 200.0f );
    }
    else
    {
        frame = static_cast<int>( ( Timer::get_timestamp() - action_start ) / 40 );
    }

    tex.bind( frame );
    Gfx::draw_sprite( x, y );

    if( action == Action::appear )
        Gfx::alpha( 1.0f );
}

}
