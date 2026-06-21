#include "map.hpp"

#include "bomb.hpp"
#include "bonus.hpp"
#include "gfx.hpp"
#include "monster.hpp"
#include "player.hpp"
#include "texture.hpp"
#include "timer.hpp"
#include "world.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <tracy/Tracy.hpp>

namespace dyna
{

// ---- Field --------------------------------------------------------------

Field Field::explosion( ExplosionType t )
{
    Field f;
    f.kind = Kind::explosion;
    f.etype = t;
    f.tstart = Timer::get_timestamp();
    return f;
}

bool Field::solid() const
{
    switch( kind )
    {
    case Kind::wall:
    case Kind::crate:
    case Kind::bomb:
        return true;
    default:
        return false;
    }
}

Destruction Field::destructible() const
{
    switch( kind )
    {
    case Kind::floor:
        return Destruction::multi;
    case Kind::crate:
        return Destruction::single;
    default:
        return Destruction::none;
    }
}

void Field::draw( int x, int y ) const
{
    switch( kind )
    {
    case Kind::wall:
        Textures::wall.bind();
        Gfx::draw_square( x, y );
        break;

    case Kind::crate:
        Textures::sand.bind();
        Gfx::draw_square( x, y );
        Textures::crate.bind();
        Gfx::draw_square( x, y );
        break;

    case Kind::explosion: {
        Textures::sand.bind();
        Gfx::draw_square( x, y );

        int frame = static_cast<int>( ( Timer::get_timestamp() - tstart ) / 40 % 8 );
        if( frame > 4 ) frame = 8 - frame;

        switch( etype )
        {
        case ExplosionType::center: Textures::e_c.bind( frame ); break;
        case ExplosionType::vertical: Textures::e_v.bind( frame ); break;
        case ExplosionType::horizontal: Textures::e_h.bind( frame ); break;
        case ExplosionType::left: Textures::e_le.bind( frame ); break;
        case ExplosionType::right: Textures::e_re.bind( frame ); break;
        case ExplosionType::up: Textures::e_ue.bind( frame ); break;
        case ExplosionType::down: Textures::e_de.bind( frame ); break;
        }
        Gfx::draw_square( x, y );
        break;
    }

        // floor, bomb and vortex tiles all show plain sand; the bomb and vortex
        // sprites themselves are drawn by their entities.
    case Kind::floor:
    case Kind::bomb:
    case Kind::vortex:
    default:
        Textures::sand.bind();
        Gfx::draw_square( x, y );
        break;
    }
}

// ---- Map ----------------------------------------------------------------

Map::Map( const std::string& fn )
{
    ZoneScoped;
    ZoneText( fn.c_str(), fn.size() );

    load( fn );
    generate_destructibles();
    populate_map();
}

Map::~Map() = default;

void Map::load( const std::string& fn )
{
    ZoneScoped;
    std::ifstream f( fn );
    if( !f )
    {
        std::fprintf( stderr, "Cannot open level %s\n", fn.c_str() );
        grid.assign( X * Y, Field::floor() );
        return;
    }

    std::stringstream buf;
    buf << f.rdbuf();
    std::string content = buf.str();

    size_t nl = content.find( '\n' );
    std::string header = ( nl == std::string::npos ) ? content : content.substr( 0, nl );
    std::sscanf( header.c_str(), "%d %d %d %d", &destructibles, &m1, &m2, &m3 );

    grid.assign( X * Y, Field::floor() );
    px = -1;

    size_t p = ( nl == std::string::npos ) ? content.size() : nl + 1;
    for( int ry = 0; ry < Y; ry++ )
    {
        for( int rx = 0; rx < X; rx++ )
        {
            char c = ( p < content.size() ) ? content[p++] : '\0';
            switch( c )
            {
            case '.':
                at( rx, ry ) = Field::floor();
                break;
            case '#':
                at( rx, ry ) = Field::wall();
                break;
            case '@':
                at( rx, ry ) = Field::floor();
                px = rx;
                py = ry;
                break;
            case '\n':
                rx--;   // newlines don't consume a grid cell
                break;
            default:
                break;
            }
        }
    }
}

bool Map::monster_ok( int rx, int ry, int pxx, int pyy, int r ) const
{
    const Field& f = at( rx, ry );
    return f.is_floor_family() && f.kind != Field::Kind::crate &&
           ( std::abs( rx - pxx ) > r || std::abs( ry - pyy ) > r );
}

void Map::generate_destructibles()
{
    ZoneScoped;
    int i = destructibles;
    while( i != 0 )
    {
        int rx = RNG::next( X );
        int ry = RNG::next( Y );
        if( monster_ok( rx, ry, px, py, 1 ) )
        {
            at( rx, ry ) = Field::crate();
            i--;
        }
    }
}

void Map::populate_map()
{
    ZoneScoped;
    for( int type = 1; type <= 3; type++ )
    {
        int count = ( type == 1 ) ? m1 : ( type == 2 ) ? m2
                                                       : m3;
        while( count != 0 )
        {
            int rx = RNG::next( X );
            int ry = RNG::next( Y );
            if( monster_ok( rx, ry, px, py, 2 ) )
            {
                monsters.push_back( std::make_unique<Monster>( type, rx, ry ) );
                count--;
            }
        }
    }
}

void Map::draw()
{
    ZoneScoped;
    for( int ry = 0; ry < Y; ry++ )
        for( int rx = 0; rx < X; rx++ )
            at( rx, ry ).draw( rx, ry );

    for( auto& b : bombs ) b->draw();
    for( auto& e : monsters ) e->draw();
    for( auto& e : bonuses ) e->draw();
}

void Map::tick( World& world )
{
    ZoneScoped;
    // Bombs.
    for( auto& b : bombs ) b->tick( world );
    bombs.erase( std::remove_if( bombs.begin(), bombs.end(),
                                 []( const std::unique_ptr<Bomb>& b ) { return b->is_dead(); } ),
                 bombs.end() );

    // Monsters: tick, then retire the dead and queue their respawn timers.
    for( auto& e : monsters ) e->tick( world );
    for( auto& e : monsters )
    {
        if( e->is_dead() )
        {
            int delay = ( e->type() == 1 ) ? 10000 : ( e->type() == 2 ) ? 20000
                                                                        : 30000;
            mwait.push_back( { e->type(), Timer::get_timestamp() + delay } );
        }
    }
    monsters.erase( std::remove_if( monsters.begin(), monsters.end(),
                                    []( const std::unique_ptr<Monster>& e ) { return e->is_dead(); } ),
                    monsters.end() );

    // The respawn and exit-portal placement below need the player's position;
    // they only fire during gameplay (a monster died, or every crate is gone),
    // never on the player-less menu screen.
    Player* player = world.player();

    // Respawn monsters whose wait has elapsed.
    std::int64_t now = Timer::get_timestamp();
    std::vector<MWait> still_waiting;
    for( const MWait& m : mwait )
    {
        if( m.time < now && player )
        {
            int rx = 0, ry = 0;
            bool ok = false;
            while( !ok )
            {
                rx = RNG::next( X );
                ry = RNG::next( Y );
                if( monster_ok( rx, ry, player->getx() / 64, player->gety() / 64, 3 ) )
                    ok = true;
            }
            auto monster = std::make_unique<Monster>( m.type, rx, ry );
            monster->set_action( Action::appear );
            monsters.push_back( std::move( monster ) );
        }
        else
        {
            still_waiting.push_back( m );
        }
    }
    mwait = std::move( still_waiting );

    // Bonuses.
    for( auto& e : bonuses ) e->tick( world );

    // Once every crate is gone, open the exit portal somewhere clear.
    if( world.crates_left == 0 && player )
    {
        world.crates_left--;

        int rx = 0, ry = 0;
        bool ok = false;
        while( !ok )
        {
            rx = RNG::next( X );
            ry = RNG::next( Y );
            if( monster_ok( rx, ry, player->getx() / 64, player->gety() / 64, 4 ) )
                ok = true;
        }

        at( rx, ry ) = Field::vortex();
        bonuses.push_back( std::make_unique<Vortex>( rx, ry ) );
    }
}

std::unique_ptr<Player> Map::create_player() const
{
    return std::make_unique<Player>( px, py );
}

void Map::place_bomb( int x, int y )
{
    Field& f = at( x, y );
    if( f.is_floor_family() && f.kind != Field::Kind::bomb )
    {
        f = Field::bomb();
        bombs.push_back( std::make_unique<Bomb>( x, y ) );
    }
}

bool Map::monster_collide( int tx, int ty ) const
{
    for( const auto& e : monsters )
    {
        if( ( e->getx() + 32 ) / 64 == ( tx + 32 ) / 64 &&
            ( e->gety() + 32 ) / 64 == ( ty + 32 ) / 64 )
            return true;
    }
    return false;
}

}
