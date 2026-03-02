#ifndef __TRACYBROADCAST_HPP__
#define __TRACYBROADCAST_HPP__

#include "TracyProtocol.hpp"
#include "TracySocket.hpp"
#include <optional>

namespace tracy
{

std::optional<BroadcastMessage> ParseBroadcastMessage( const char* msg, size_t msgLen );
uint64_t ClientUniqueID( const IpAddress& addr, uint16_t port );

}

#endif
