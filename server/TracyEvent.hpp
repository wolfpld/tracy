#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include "TracyVector.hpp"

namespace tracy
{

struct Event
{
    int64_t start;
    int64_t end;

    Vector<Event*> child;
};

enum { EventSize = sizeof( Event ) };

}

#endif
