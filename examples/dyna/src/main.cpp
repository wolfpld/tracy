#include "game.hpp"
#include "gfx.hpp"

#include <SDL3/SDL_main.h>

int main( int /*argc*/, char* /*argv*/[] )
{
    if( !dyna::Init::all() )
        return 1;

    dyna::Game::menu_loop();

    dyna::Init::shutdown();
    return 0;
}
