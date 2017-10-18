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
    struct MessagePending
    {
        int64_t time;
        uint64_t thread;
    };

    struct MessageData
    {
        int64_t time;
        const char* txt;
    };

    struct ThreadData
    {
        uint64_t id;
        bool enabled;
        Vector<Event*> timeline;
        Vector<MessageData*> messages;
    };

    struct LockMap
    {
        uint64_t srcloc;
        Vector<LockEvent*> timeline;
        std::unordered_map<uint64_t, uint8_t> threadMap;
        std::vector<uint64_t> threadList;
    };

    struct LockHighlight
    {
        int64_t id;
        uint64_t begin;
        uint64_t end;
        uint8_t thread;
        bool blocked;
    };

    struct PlotItem
    {
        int64_t time;
        double val;
    };

    struct PlotData
    {
        uint64_t name;
        double min;
        double max;
        bool enabled;
        std::vector<PlotItem> data;
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
    void ProcessLockWait( const QueueLockWait& ev );
    void ProcessLockObtain( const QueueLockObtain& ev );
    void ProcessLockRelease( const QueueLockRelease& ev );
    void ProcessLockMark( const QueueLockMark& ev );
    void ProcessPlotData( const QueuePlotData& ev );
    void ProcessMessage( const QueueMessage& ev, bool literal );

    void CheckString( uint64_t ptr );
    void CheckThreadString( uint64_t id );
    void CheckCustomString( uint64_t ptr, Event* dst );
    void CheckSourceLocation( uint64_t ptr );

    void AddString( uint64_t ptr, std::string&& str );
    void AddThreadString( uint64_t id, std::string&& str );
    void AddCustomString( uint64_t ptr, std::string&& str );
    void AddSourceLocation( const QueueSourceLocation& srcloc );
    void AddMessageData( uint64_t ptr, const char* str, size_t sz );

    void NewZone( Event* zone, uint64_t thread );
    void UpdateZone( Event* zone );

    void InsertZone( Event* zone, Event* parent, Vector<Event*>& vec );

    void InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread );
    void UpdateLockCount( LockMap& lockmap, size_t pos );

    void InsertPlot( PlotData* plot, int64_t time, double val );
    void HandlePlotName( uint64_t name, std::string&& str );

    uint64_t GetFrameTime( size_t idx ) const;
    uint64_t GetFrameBegin( size_t idx ) const;
    uint64_t GetFrameEnd( size_t idx ) const;
    int64_t GetLastTime() const;
    int64_t GetZoneEnd( const Event& ev ) const;
    Vector<Event*>& GetParentVector( const Event& ev );
    const char* TimeToString( int64_t ns ) const;
    const char* GetString( uint64_t ptr ) const;
    const char* GetThreadString( uint64_t id ) const;
    const QueueSourceLocation& GetSourceLocation( uint64_t srcloc ) const;

    void DrawImpl();
    void DrawConnection();
    void DrawFrames();
    bool DrawZoneFrames();
    void DrawZones();
    int DrawZoneLevel( const Vector<Event*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth );
    int DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int offset, LockHighlight& highlight );
    void DrawZoneInfoWindow();
    int DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev );
    void DrawOptions();
    void DrawMessages();

    void HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns );

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
    Vector<PlotData*> m_plots;
    Vector<MessageData*> m_messages;
    std::unordered_map<uint64_t, std::string> m_strings;
    std::unordered_map<uint64_t, std::string> m_threadNames;
    std::unordered_set<const char*, charutil::Hasher, charutil::Comparator> m_customStrings;
    std::unordered_map<uint64_t, QueueSourceLocation> m_sourceLocation;
    std::unordered_map<uint32_t, LockMap> m_lockMap;
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
    std::unordered_map<uint64_t, uint32_t> m_plotMap;
    std::unordered_map<std::string, uint32_t> m_plotRev;
    std::unordered_map<uint64_t, PlotData*> m_pendingPlots;
    std::unordered_map<uint64_t, MessagePending> m_pendingMessages;

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

    uint64_t m_zvHeight;
    uint64_t m_zvScroll;

    const Event* m_zoneInfoWindow;
    const Event* m_zoneHighlight;
    LockHighlight m_lockHighlight;
    const MessageData* m_msgHighlight;

    bool m_drawRegion;
    uint64_t m_regionStart;
    uint64_t m_regionEnd;

    bool m_showOptions;
    bool m_showMessages;
    bool m_drawZones;
    bool m_drawLocks;
    bool m_drawPlots;

    bool m_terminate;
};

}

#endif
