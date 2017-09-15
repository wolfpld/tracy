#ifndef __TRACYEVENT_HPP__
#define __TRACYEVENT_HPP__

#include <vector>

namespace tracy
{

struct Event
{
    int64_t start;
    int64_t end;

    std::vector<Event*> child;
};

enum { EventSize = sizeof( Event ) };

}

#endif
