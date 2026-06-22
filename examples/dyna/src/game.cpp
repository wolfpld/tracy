#include "game.hpp"

#include "datapath.hpp"
#include "gfx.hpp"
#include "map.hpp"
#include "player.hpp"
#include "timer.hpp"
#include "world.hpp"

#include <SDL3/SDL.h>
#include <tracy/Tracy.hpp>

#include <string>

namespace dyna
{

namespace Game
{

namespace
{

struct TracySection
{
    explicit TracySection( const char* name ) { Enter( name ); }
    ~TracySection() { Leave(); }

    void Enter( const char* name )
    {
        idx = TracySectionEnter( "%s", name );
    }

    void Leave()
    {
        if( idx > 0 )
        {
            TracySectionLeave( idx );
            idx = 0;
        }
    }

private:
    uint32_t idx;
};

SDL_Keycode key = 0;   // most recently pressed movement key
bool help = false;

// Run one level to completion. Returns true if the player asked to quit the
// whole application (window close), false if the level simply ended (death,
// escape, or reaching the exit) and control should return to the caller.
bool level_loop( World& world )
{
    TracySection section( ( std::string( "Level " ) + world.name() ).c_str() );

    Player* p = world.player();

    for( ;; )
    {
        SDL_Event ev;
        while( SDL_PollEvent( &ev ) )
        {
            if( ev.type == SDL_EVENT_QUIT )
                return true;

            if( ev.type == SDL_EVENT_KEY_DOWN && !ev.key.repeat )
            {
                switch( ev.key.key )
                {
                case SDLK_ESCAPE:
                    world.killed = true;
                    return false;
                case SDLK_LEFT:
                    key = SDLK_LEFT;
                    p->move( Action::left );
                    break;
                case SDLK_RIGHT:
                    key = SDLK_RIGHT;
                    p->move( Action::right );
                    break;
                case SDLK_UP:
                    key = SDLK_UP;
                    p->move( Action::up );
                    break;
                case SDLK_DOWN:
                    key = SDLK_DOWN;
                    p->move( Action::down );
                    break;
                case SDLK_SPACE:
                    world.map().place_bomb( ( p->getx() + 32 ) / 64, ( p->gety() + 32 ) / 64 );
                    break;
                default:
                    break;
                }
            }

            if( ev.type == SDL_EVENT_KEY_UP )
            {
                switch( ev.key.key )
                {
                case SDLK_LEFT:
                    if( key == SDLK_LEFT ) p->move( Action::wait );
                    break;
                case SDLK_RIGHT:
                    if( key == SDLK_RIGHT ) p->move( Action::wait );
                    break;
                case SDLK_UP:
                    if( key == SDLK_UP ) p->move( Action::wait );
                    break;
                case SDLK_DOWN:
                    if( key == SDLK_DOWN ) p->move( Action::wait );
                    break;
                default:
                    break;
                }
            }
        }

        Gfx::clear();

        Timer::tick();

        world.tick();
        world.draw();

        Gfx::swap();

        if( world.killed || world.next_level )
            return false;
    }
}

// Play through the levels in order. Returns true if the application should quit.
bool new_game()
{
    TracySection section( "In-game" );

    int level = 1;

    for( ;; )
    {
        World world( data_path( "data/levels/" + std::to_string( level ) ), true );

        if( level_loop( world ) )
            return true;   // window closed

        if( world.killed )
            return false;   // died or escaped to the menu
        if( ++level >= 10 )
            return false;   // cleared the last level
    }
}

} // namespace

void menu_loop()
{
    constexpr const char* sectionName = "Main menu";
    TracySection section( sectionName );

    World world( data_path( "data/levels/menu" ), false );

    for( ;; )
    {
        SDL_Event ev;
        while( SDL_PollEvent( &ev ) )
        {
            if( ev.type == SDL_EVENT_QUIT )
                return;

            if( ev.type == SDL_EVENT_KEY_DOWN && !ev.key.repeat )
            {
                switch( ev.key.key )
                {
                case SDLK_ESCAPE:
                    return;
                case SDLK_SPACE:
                    section.Leave();
                    if( new_game() )
                        return;   // window closed during play
                    section.Enter( sectionName );
                    break;
                case SDLK_H:
                    help = !help;
                    break;
                default:
                    break;
                }
            }
        }

        Gfx::clear();

        Timer::tick();
        world.tick();
        world.draw();

        if( help )
            Gfx::show_help();
        else
            Gfx::show_menu();

        Gfx::swap();
    }
}

} // namespace Game

}
