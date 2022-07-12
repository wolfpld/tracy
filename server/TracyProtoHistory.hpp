#ifndef __TRACYPROTOHISTORY_HPP__
#define __TRACYPROTOHISTORY_HPP__

#include <stdint.h>

namespace tracy
{

struct ProtocolHistory_t
{
    uint32_t protocol;
    uint32_t minVer;
    uint32_t maxVer;
};

extern const ProtocolHistory_t* ProtocolHistory;

}

#endif
