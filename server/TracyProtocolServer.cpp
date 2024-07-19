#include "TracyProtocolServer.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

namespace tracy
{
std::optional<tracy::BroadcastMessage> ParseBroadcastMessage(const char* msg, size_t msgLen)
{
    if (msgLen < sizeof(uint16_t))
    {
        std::cout << "Received too short broadcast message" << std::endl;
        return std::nullopt;
    }
    uint16_t broadcastVersion;
    memcpy(&broadcastVersion, msg, sizeof(uint16_t));
    if (broadcastVersion > tracy::BroadcastVersion)
    {
        std::cout << "Received broadcast message with unsupported version: " << broadcastVersion << std::endl;
        return std::nullopt;
    }
    switch (broadcastVersion)
    {
        case 3:
        {
            if (msgLen > sizeof(tracy::BroadcastMessage))
            {
                std::cout << "Received unexpected size broadcast v3 message" << std::endl;
                return std::nullopt;
            }
            tracy::BroadcastMessage bm;
            memcpy(&bm, msg, msgLen);
            return bm;
            break;
        }
        case 2:
        {
            if (msgLen > sizeof(tracy::BroadcastMessage_v2))
            {
                std::cout << "Received unexpected size broadcast v2 message" << std::endl;
                return std::nullopt;
            }
            tracy::BroadcastMessage_v2 bm;
            memcpy(&bm, msg, msgLen);

            tracy::BroadcastMessage out;
            out.broadcastVersion = broadcastVersion;
            out.protocolVersion  = bm.protocolVersion;
            out.activeTime       = bm.activeTime;
            out.listenPort       = bm.listenPort;
            strcpy(out.programName, bm.programName);
            out.pid = 0;
            return out;
            break;
        }
        case 1:
        {
            if (msgLen > sizeof(tracy::BroadcastMessage_v1))
            {
                std::cout << "Received unexpected size broadcast v1 message" << std::endl;
                return std::nullopt;
            }
            tracy::BroadcastMessage_v1 bm;
            memcpy(&bm, msg, msgLen);

            tracy::BroadcastMessage out;
            out.broadcastVersion = broadcastVersion;
            out.protocolVersion  = bm.protocolVersion;
            out.activeTime       = bm.activeTime;
            out.listenPort       = bm.listenPort;
            strcpy(out.programName, bm.programName);
            out.pid = 0;
            return out;
            break;
        }
        case 0:
        {
            if (msgLen > sizeof(tracy::BroadcastMessage_v0))
            {
                std::cout << "Received unexpected size broadcast v0 message" << std::endl;
                return std::nullopt;
            }
            tracy::BroadcastMessage_v0 bm;
            memcpy(&bm, msg, msgLen);

            tracy::BroadcastMessage out;
            out.broadcastVersion = broadcastVersion;
            out.protocolVersion  = bm.protocolVersion;
            out.activeTime       = bm.activeTime;
            out.listenPort       = tracy::DEFAULT_CLIENT_DATA_TCP_PORT;
            strcpy(out.programName, bm.programName);
            out.pid = 0;
            return out;
            break;
        }
        default:
            assert(false);
            break;
    }
    return std::nullopt;
}

uint64_t ClientUniqueID(tracy::IpAddress const& addr, uint16_t port)
{
    return uint64_t(addr.GetNumber()) | (uint64_t(port) << 32);
}
}
