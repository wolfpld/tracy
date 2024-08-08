// server-side functions supporting the protocol
#ifndef __TRACYPROTOCOLSERVER_HPP__
#define __TRACYPROTOCOLSERVER_HPP__

#include "TracyProtocol.hpp"
#include "TracySocket.hpp"
#include <optional>

namespace tracy
{
// create the latest version of broadcast message, migrating older versions if possible
std::optional<tracy::BroadcastMessage> ParseBroadcastMessage( const char* msg, size_t msgLen );
// internal unique ID for a client
uint64_t ClientUniqueID( tracy::IpAddress const& addr, uint16_t port );
}

#endif
