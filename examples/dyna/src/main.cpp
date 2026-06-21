#include "game.hpp"
#include "gfx.hpp"

#include <SDL3/SDL_main.h>
#include <tracy/Tracy.hpp>

#include <cstdlib>
#include <new>

// Route every heap allocation through Tracy so the profiler can track memory
// usage. The default array forms (operator new[]/delete[]) and the nothrow
// forms forward to these, so overriding the scalar operators covers them too.
void* operator new( std::size_t count )
{
    void* ptr = std::malloc( count );
    if( !ptr ) throw std::bad_alloc();
    TracyAlloc( ptr, count );
    return ptr;
}

void operator delete( void* ptr ) noexcept
{
    TracyFree( ptr );
    std::free( ptr );
}

int main( int /*argc*/, char* /*argv*/[] )
{
    TracyNoop;

    if( !dyna::Init::all() )
        return 1;

    dyna::Game::menu_loop();

    dyna::Init::shutdown();
    return 0;
}
