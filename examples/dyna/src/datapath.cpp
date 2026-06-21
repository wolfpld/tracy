#include "datapath.hpp"

#include <SDL3/SDL.h>

namespace dyna
{

std::string data_path( const std::string& rel )
{
    // SDL_GetBasePath returns the executable's directory (with a trailing
    // separator) and is owned by SDL, so cache it for the program's lifetime.
    static const std::string base = []
    {
        const char* p = SDL_GetBasePath();
        return std::string( p ? p : "" );
    }();
    return base + rel;
}

}
