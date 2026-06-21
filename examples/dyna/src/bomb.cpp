#include "bomb.hpp"

#include "gfx.hpp"
#include "map.hpp"
#include "texture.hpp"
#include "timer.hpp"
#include "world.hpp"

#include <tracy/Tracy.hpp>

namespace dyna
{

Bomb::Bomb( int x_, int y_ )
    : x( x_ )
    , y( y_ )
    , left( 9 )
{
}

void Bomb::draw()
{
    ZoneScoped;
    if( stage == Stage::exploding )
        return;

    if( stage == Stage::appear )
    {
        Textures::bomb_appear.bind( 9 - left );
    }
    else
    {
        int frame = static_cast<int>( ( time - left ) / static_cast<float>( time ) * 8 );
        if( Timer::get_timestamp() / 100 % 2 == 0 )
            frame++;
        Textures::bomb.bind( frame );
    }

    Gfx::draw_square( x, y );
}

void Bomb::tick( World& world )
{
    ZoneScoped;
    delta += Timer::delta;

    while( delta > 10 )
    {
        delta -= 10;

        if( stage == Stage::appear )
        {
            if( left > 0 )
            {
                delta -= 10;   // the fade-in advances at double speed
                left--;
            }
            else
            {
                stage = Stage::ticking;
                left = time;
            }
        }
        else if( left > 0 )
        {
            left--;
        }
        else if( stage == Stage::ticking )
        {
            explode( world );
        }
        else
        {
            die( world );
        }
    }
}

void Bomb::explode( World& world )
{
    ZoneScoped;
    stage = Stage::exploding;
    left = 200;

    Map& map = world.map();
    map.at( x, y ) = Field::explosion( Field::ExplosionType::center );

    struct Dir
    {
        int dx, dy;
        Field::ExplosionType through, tip;
    };
    const Dir dirs[4] = {
        { -1, 0, Field::ExplosionType::horizontal, Field::ExplosionType::left },
        { 1, 0, Field::ExplosionType::horizontal, Field::ExplosionType::right },
        { 0, -1, Field::ExplosionType::vertical, Field::ExplosionType::up },
        { 0, 1, Field::ExplosionType::vertical, Field::ExplosionType::down },
    };

    for( const Dir& d : dirs )
    {
        for( int i = 1; i <= maxrange; i++ )
        {
            int tx = x + d.dx * i;
            int ty = y + d.dy * i;

            if( tx < 0 || tx > map.getx() - 1 || ty < 0 || ty > map.gety() - 1 )
                break;

            Destruction destr = map.at( tx, ty ).destructible();
            if( destr == Destruction::none )
                break;

            etiles.emplace_back( tx, ty );

            if( map.at( tx, ty ).kind == Field::Kind::crate )
                world.crates_left--;

            if( i == maxrange || destr == Destruction::single )
            {
                map.at( tx, ty ) = Field::explosion( d.tip );
                break;
            }
            else
            {
                map.at( tx, ty ) = Field::explosion( d.through );
            }
        }
    }
}

void Bomb::die( World& world )
{
    ZoneScoped;
    dead = true;

    Map& map = world.map();
    map.at( x, y ) = Field::floor();
    for( const auto& [tx, ty] : etiles )
        map.at( tx, ty ) = Field::floor();
}

}
