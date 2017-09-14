#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../common/TracySocket.hpp"
#include "../common/TracyQueue.hpp"
#include "TracyEvent.hpp"

namespace tracy
{

struct QueueItem;

class View
{
public:
    View() : View( "127.0.0.1" ) {}
    View( const char* addr );
    ~View();

    static bool ShouldExit();

private:
    void Worker();

    void DispatchProcess( const QueueItem& ev );
    void DispatchProcess( const QueueItem& ev, const char*& ptr );

    void Process( const QueueItem& ev );
    void ProcessZoneBegin( uint64_t id, const QueueZoneBegin& ev );
    void ProcessZoneEnd( uint64_t id, const QueueZoneEnd& ev );

    void CheckString( uint64_t ptr );
    void AddString( uint64_t ptr, std::string&& str );

    std::string m_addr;

    Socket m_sock;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;

    int64_t m_timeBegin;

    // this block must be locked
    std::mutex m_lock;
    std::vector<Event> m_data;
    std::vector<uint64_t> m_timeline;
    std::unordered_map<uint64_t, std::string> m_strings;

    // not used for vis - no need to lock
    std::unordered_map<uint64_t, QueueZoneEnd> m_pendingEndZone;
    std::unordered_map<uint64_t, uint64_t> m_openZones;
    std::unordered_set<uint64_t> m_pendingStrings;
};

}

#endif
