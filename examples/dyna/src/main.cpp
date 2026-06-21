#include "game.hpp"
#include "gfx.hpp"

#include <SDL3/SDL_main.h>
#include <tracy/Tracy.hpp>

int main( int /*argc*/, char* /*argv*/[] )
{
    TracyNoop;

    if( !dyna::Init::all() )
        return 1;

    dyna::Game::menu_loop();

    dyna::Init::shutdown();
    return 0;
}
