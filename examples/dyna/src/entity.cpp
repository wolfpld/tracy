#include "entity.hpp"

#include "map.hpp"
#include "timer.hpp"

namespace dyna
{

void Entity::set_action( Action a )
{
    action = a;
    action_start = Timer::get_timestamp();
}

bool Entity::can_move( Action a, const Map& map ) const
{
    switch( a )
    {
    case Action::up:
        return y > 0 && !map.at( x / 64, y / 64 - 1 ).solid();
    case Action::down:
        return y / 64 < map.gety() - 1 && !map.at( x / 64, y / 64 + 1 ).solid();
    case Action::left:
        return x > 0 && !map.at( x / 64 - 1, y / 64 ).solid();
    case Action::right:
        return x / 64 < map.getx() - 1 && !map.at( x / 64 + 1, y / 64 ).solid();
    default:
        return true;
    }
}

bool Entity::killed( const Map& map ) const
{
    int tx = ( x + 32 ) / 64;
    int ty = ( y + 32 ) / 64;
    return map.at( tx, ty ).kind == Field::Kind::explosion;
}

}
