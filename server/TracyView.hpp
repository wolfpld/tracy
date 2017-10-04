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
#include "TracyCharUtil.hpp"
#include "TracyEvent.hpp"
#include "TracySlab.hpp"
#include "TracyVector.hpp"

struct ImVec2;

namespace tracy
{

struct QueueItem;
class FileRead;
class FileWrite;

class View
{
public:
    View() : View( "127.0.0.1" ) {}
    View( const char* addr );
    View( FileRead& f );
    ~View();

    static bool ShouldExit();
    static void Draw();

private:
    struct ThreadData
    {
        uint64_t id;
        Vector<Event*> timeline;
    };

    struct LockMap
    {
        uint64_t id;
        uint64_t srcloc;
        Vector<LockEvent*> timeline;
    };

    void Worker();

    void DispatchProcess( const QueueItem& ev );
    void DispatchProcess( const QueueItem& ev, const char*& ptr );

    void ServerQuery( uint8_t type, uint64_t data );

    void Process( const QueueItem& ev );
    void ProcessZoneBegin( const QueueZoneBegin& ev );
    void ProcessZoneEnd( const QueueZoneEnd& ev );
    void ProcessFrameMark( const QueueFrameMark& ev );
    void ProcessZoneText( const QueueZoneText& ev );
    void ProcessZoneName( const QueueZoneName& ev );
    void ProcessLockAnnounce( const QueueLockAnnounce& ev );
    void ProcessLockWait( const QueueLockWait& ev );
    void ProcessLockObtain( const QueueLockObtain& ev );
    void ProcessLockRelease( const QueueLockRelease& ev );

    void CheckString( uint64_t ptr );
    void CheckThreadString( uint64_t id );
    void CheckCustomString( uint64_t ptr, Event* dst );
    void CheckSourceLocation( uint64_t ptr );

    void AddString( uint64_t ptr, std::string&& str );
    void AddThreadString( uint64_t id, std::string&& str );
    void AddCustomString( uint64_t ptr, std::string&& str );
    void AddSourceLocation( const QueueSourceLocation& srcloc );

    void NewZone( Event* zone, uint64_t thread );
    void UpdateZone( Event* zone );

    void InsertZone( Event* zone, Event* parent, Vector<Event*>& vec );

    void InsertLockEvent( Vector<LockEvent*>& timeline, LockEvent* lev );
    void UpdateLockCount( Vector<LockEvent*>& timeline, size_t pos );

    uint64_t GetFrameTime( size_t idx ) const;
    uint64_t GetFrameBegin( size_t idx ) const;
    uint64_t GetFrameEnd( size_t idx ) const;
    uint64_t GetLastTime() const;
    int64_t GetZoneEnd( const Event& ev ) const;
    Vector<Event*>& GetParentVector( const Event& ev );
    const char* TimeToString( int64_t ns ) const;
    const char* GetString( uint64_t ptr ) const;
    const char* GetThreadString( uint64_t id ) const;
    const QueueSourceLocation& GetSourceLocation( uint64_t srcloc ) const;

    void DrawImpl();
    void DrawConnection();
    void DrawFrames();
    void DrawZones();
    int DrawZoneLevel( const Vector<Event*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth );
    void DrawZoneInfoWindow();

    uint32_t GetZoneColor( const Event& ev );
    uint32_t GetZoneColor( const QueueSourceLocation& srcloc );
    uint32_t GetZoneHighlight( const Event& ev, bool migration );
    float GetZoneThickness( const Event& ev );

    void ZoomToZone( const Event& ev );
    void ZoneTooltip( const Event& ev );

    void Write( FileWrite& f );
    void WriteTimeline( FileWrite& f, const Vector<Event*>& vec );
    void ReadTimeline( FileRead& f, Vector<Event*>& vec, Event* parent, const std::unordered_map<uint64_t, const char*>& stringMap );

    std::string m_addr;

    Socket m_sock;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_hasData;
    bool m_staticView;

    // this block must be locked
    std::mutex m_lock;
    Vector<uint64_t> m_frames;
    Vector<ThreadData*> m_threads;
    std::unordered_map<uint64_t, std::string> m_strings;
    std::unordered_map<uint64_t, std::string> m_threadNames;
    std::unordered_set<const char*, charutil::Hasher, charutil::Comparator> m_customStrings;
    std::unordered_map<uint64_t, QueueSourceLocation> m_sourceLocation;
    std::unordered_map<uint64_t, LockMap> m_lockMap;
    uint64_t m_zonesCnt;

    std::mutex m_mbpslock;
    std::vector<float> m_mbps;

    // not used for vis - no need to lock
    std::unordered_map<uint64_t, std::vector<Event*>> m_zoneStack;
    std::unordered_set<uint64_t> m_pendingStrings;
    std::unordered_set<uint64_t> m_pendingThreads;
    std::unordered_set<uint64_t> m_pendingSourceLocation;
    std::unordered_map<uint64_t, Event*> m_pendingCustomStrings;
    std::unordered_map<uint64_t, uint32_t> m_threadMap;
    std::unordered_map<uint64_t, std::vector<LockEvent*>> m_pendingLocks;

    Slab<EventSize*1024*1024> m_slab;

    LZ4_streamDecode_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;

    int m_frameScale;
    bool m_pause;
    int m_frameStart;

    int64_t m_zvStart;
    int64_t m_zvEnd;

    int64_t m_zvStartNext;
    int64_t m_zvEndNext;

    uint64_t m_delay;
    uint64_t m_resolution;
    double m_timerMul;
    std::string m_captureName;

    int8_t m_lastCpu;

    const Event* m_zoneInfoWindow;
    const Event* m_zoneHighlight;
};

}

#endif
