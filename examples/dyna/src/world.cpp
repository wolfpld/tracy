#include "world.hpp"

#include "map.hpp"
#include "player.hpp"

namespace dyna
{

World::World( const std::string& level_fn, bool with_player )
    : map_( std::make_unique<Map>( level_fn ) )
    , name_( level_fn.substr( level_fn.rfind( '/' ) + 1 ) )
{
    if( with_player )
    {
        player_ = map_->create_player();
        crates_left = map_->get_crates();
    }
    else
    {
        crates_left = -1;   // the menu never opens an exit portal
    }
}

World::~World() = default;

void World::tick()
{
    map_->tick( *this );
    if( player_ )
        player_->tick( *this );
}

void World::draw()
{
    map_->draw();
    if( player_ )
        player_->draw();
}

}
