#include "timer.hpp"

#include <SDL3/SDL.h>

#include <random>

namespace dyna
{

namespace Timer
{
int delta = 0;
static std::int64_t timestamp = 0;

void reset()
{
    delta = 0;
    timestamp = static_cast<std::int64_t>( SDL_GetTicks() );
}

int tick()
{
    std::int64_t tmp = timestamp;
    timestamp = static_cast<std::int64_t>( SDL_GetTicks() );
    delta = static_cast<int>( timestamp - tmp );
    return delta;
}

std::int64_t get_timestamp()
{
    return timestamp;
}
}

namespace RNG
{
static std::mt19937& engine()
{
    static std::mt19937 e{ std::random_device{}() };
    return e;
}

int next( int n )
{
    if( n <= 0 ) return 0;
    std::uniform_int_distribution<int> dist( 0, n - 1 );
    return dist( engine() );
}
}

}
