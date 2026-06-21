#include "bonus.hpp"

#include "gfx.hpp"
#include "texture.hpp"
#include "timer.hpp"

#include <tracy/Tracy.hpp>

namespace dyna
{

Vortex::Vortex( int gx, int gy )
{
    x = gx;   // stored in grid units, drawn via draw_square
    y = gy;
    set_action( Action::appear );
    left = 79;
}

void Vortex::draw()
{
    ZoneScoped;
    int frame = static_cast<int>( ( Timer::get_timestamp() - action_start ) / 40 );

    switch( action )
    {
    case Action::appear:
        Textures::vortex_appear.bind( frame );
        break;
    case Action::wait:
        Textures::vortex.bind( frame );
        break;
    default:
        break;
    }

    Gfx::draw_square( x, y );
}

void Vortex::tick( World& )
{
    ZoneScoped;
    delta += Timer::delta;

    while( delta > 10 )
    {
        delta -= 10;

        if( left > 0 )
            left--;
        else if( action == Action::appear )
            set_action( Action::wait );
    }
}

void Vortex::die( World& ) {}

}
