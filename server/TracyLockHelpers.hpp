#ifndef __TRACYLOCKHELPERS_HPP__
#define __TRACYLOCKHELPERS_HPP__

#include <stdint.h>

#include "../public/common/TracyForceInline.hpp"

namespace tracy
{

static tracy_force_inline uint64_t GetThreadBit( uint8_t thread )
{
    return uint64_t( 1 ) << thread;
}

static tracy_force_inline bool IsThreadWaiting( uint64_t bitlist, uint64_t threadBit )
{
    return ( bitlist & threadBit ) != 0;
}

static tracy_force_inline bool AreOtherWaiting( uint64_t bitlist, uint64_t threadBit )
{
    return ( bitlist & ~threadBit ) != 0;
}

}

#endif
