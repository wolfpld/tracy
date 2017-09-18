#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../common/tracy_lz4.hpp"
#include "../common/TracySocket.hpp"
#include "../common/TracyQueue.hpp"
#include "TracyEvent.hpp"
#include "TracySlab.hpp"
#include "TracyVector.hpp"

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
    static void Draw();

private:
    void Worker();

    void DispatchProcess( const QueueItem& ev );
    void DispatchProcess( const QueueItem& ev, const char*& ptr );

    void Process( const QueueItem& ev );
    void ProcessZoneBegin( uint64_t id, const QueueZoneBegin& ev );
    void ProcessZoneEnd( uint64_t id, const QueueZoneEnd& ev );
    void ProcessFrameMark( uint64_t id );

    void CheckString( uint64_t ptr );
    void AddString( uint64_t ptr, std::string&& str );

    void NewZone( Event* zone );
    void UpdateZone( Event* zone );

    uint64_t GetFrameTime( size_t idx ) const;
    uint64_t GetLastTime() const;
    const char* TimeToString( uint64_t ns ) const;

    void DrawImpl();
    void DrawFrames();

    std::string m_addr;

    Socket m_sock;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::atomic<bool> m_connected;

    // this block must be locked
    std::mutex m_lock;
    Vector<Event*> m_timeline;
    Vector<uint64_t> m_frames;
    std::unordered_map<uint64_t, std::string> m_strings;

    std::mutex m_mbpslock;
    std::vector<float> m_mbps;

    // not used for vis - no need to lock
    std::unordered_map<uint64_t, QueueZoneEnd> m_pendingEndZone;
    std::unordered_map<uint64_t, Event*> m_openZones;
    std::unordered_set<uint64_t> m_pendingStrings;

    Slab<EventSize*1024*1024> m_slab;

    LZ4_streamDecode_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;

    int m_frameScale;
};

}

#endif
