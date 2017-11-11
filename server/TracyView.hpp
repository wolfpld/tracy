#ifndef __TRACYVIEW_HPP__
#define __TRACYVIEW_HPP__

#include <atomic>
#include <map>
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
    enum class Namespace : uint8_t
    {
        Full,
        Mid,
        Short
    };

    struct MessageData
    {
        int64_t time;
        StringRef ref;
    };

    struct ThreadData
    {
        uint64_t id;
        bool showFull;
        bool visible;
        Vector<ZoneEvent*> timeline;
        Vector<MessageData*> messages;
    };

    struct LockMap
    {
        uint32_t srcloc;
        Vector<LockEvent*> timeline;
        std::unordered_map<uint64_t, uint8_t> threadMap;
        std::vector<uint64_t> threadList;
        bool visible;
    };

    struct LockHighlight
    {
        int64_t id;
        int64_t begin;
        int64_t end;
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
        bool showFull;
        bool visible;
        Vector<PlotItem*> data;
        Vector<PlotItem*> postpone;
        uint64_t postponeTime;
    };

    struct StringLocation
    {
        const char* ptr;
        uint32_t idx;
    };

    struct SourceLocationHasher
    {
        size_t operator()( const SourceLocation* ptr ) const
        {
            return charutil::hash( (const char*)ptr, sizeof( SourceLocation ) );
        }
    };

    struct SourceLocationComparator
    {
        bool operator()( const SourceLocation* lhs, const SourceLocation* rhs ) const
        {
            return memcmp( lhs, rhs, sizeof( SourceLocation ) ) == 0;
        }
    };

    void Worker();

    void DispatchProcess( const QueueItem& ev, char*& ptr );

    void ServerQuery( uint8_t type, uint64_t data );

    void Process( const QueueItem& ev );
    void ProcessZoneBegin( const QueueZoneBegin& ev );
    void ProcessZoneBeginAllocSrcLoc( const QueueZoneBegin& ev );
    void ProcessZoneEnd( const QueueZoneEnd& ev );
    void ProcessFrameMark( const QueueFrameMark& ev );
    void ProcessZoneText( const QueueZoneText& ev );
    void ProcessZoneName( const QueueZoneName& ev );
    void ProcessLockWait( const QueueLockWait& ev );
    void ProcessLockObtain( const QueueLockObtain& ev );
    void ProcessLockRelease( const QueueLockRelease& ev );
    void ProcessLockMark( const QueueLockMark& ev );
    void ProcessPlotData( const QueuePlotData& ev );
    void ProcessMessage( const QueueMessage& ev );
    void ProcessMessageLiteral( const QueueMessage& ev );

    void CheckString( uint64_t ptr );
    void CheckThreadString( uint64_t id );
    void CheckSourceLocation( uint64_t ptr );

    void AddString( uint64_t ptr, char* str, size_t sz );
    void AddThreadString( uint64_t id, char* str, size_t sz );
    void AddCustomString( uint64_t ptr, char* str, size_t sz );
    void AddSourceLocation( const QueueSourceLocation& srcloc );
    void AddSourceLocationPayload( uint64_t ptr, char* data, size_t sz );

    StringLocation StoreString( char* str, size_t sz );

    uint32_t ShrinkSourceLocation( uint64_t srcloc );

    void InsertMessageData( MessageData* msg, uint64_t thread );

    ThreadData* NoticeThread( uint64_t thread );

    void NewZone( ZoneEvent* zone, uint64_t thread );
    void UpdateZone( ZoneEvent* zone );

    void InsertZone( ZoneEvent* zone, Vector<ZoneEvent*>& vec );

    void InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread );
    void UpdateLockCount( LockMap& lockmap, size_t pos );

    void InsertPlot( PlotData* plot, int64_t time, double val );
    void InsertPlot( PlotData* plot, PlotItem* item );
    void HandlePlotName( uint64_t name, char* str, size_t sz );
    void HandlePostponedPlots();

    int64_t GetFrameTime( size_t idx ) const;
    int64_t GetFrameBegin( size_t idx ) const;
    int64_t GetFrameEnd( size_t idx ) const;
    int64_t GetLastTime() const;
    int64_t GetZoneEnd( const ZoneEvent& ev ) const;
    const char* GetString( uint64_t ptr ) const;
    const char* GetString( const StringRef& ref ) const;
    const char* GetThreadString( uint64_t id ) const;
    const SourceLocation& GetSourceLocation( int32_t srcloc ) const;

    const char* ShortenNamespace( const char* name ) const;

    void DrawImpl();
    void DrawConnection();
    void DrawFrames();
    bool DrawZoneFrames();
    void DrawZones();
    int DrawZoneLevel( const Vector<ZoneEvent*>& vec, bool hover, double pxns, const ImVec2& wpos, int offset, int depth );
    int DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int offset, LockHighlight& highlight );
    void DrawZoneInfoWindow();
    int DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover );
    void DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged );
    void DrawOptions();
    void DrawMessages();

    void HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns );

    uint32_t GetZoneColor( const ZoneEvent& ev );
    uint32_t GetZoneColor( const SourceLocation& srcloc );
    uint32_t GetZoneHighlight( const ZoneEvent& ev, bool migration );
    float GetZoneThickness( const ZoneEvent& ev );

    void ZoomToZone( const ZoneEvent& ev );
    void ZoneTooltip( const ZoneEvent& ev );
    const ZoneEvent* GetZoneParent( const ZoneEvent& zone ) const;

    TextData* GetTextData( ZoneEvent& zone );
    const TextData* GetTextData( const ZoneEvent& zone ) const;

    void Write( FileWrite& f );
    void WriteTimeline( FileWrite& f, const Vector<ZoneEvent*>& vec );
    void ReadTimeline( FileRead& f, Vector<ZoneEvent*>& vec );

    std::string m_addr;

    Socket m_sock;
    std::thread m_thread;
    std::atomic<bool> m_shutdown;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_hasData;
    bool m_staticView;

    // this block must be locked
    std::mutex m_lock;
    Vector<int64_t> m_frames;
    Vector<ThreadData*> m_threads;
    Vector<PlotData*> m_plots;
    Vector<MessageData*> m_messages;
    Vector<TextData*> m_textData;
    std::unordered_map<uint64_t, const char*> m_strings;
    std::unordered_map<uint64_t, const char*> m_threadNames;
    std::unordered_map<uint64_t, SourceLocation> m_sourceLocation;
    std::vector<uint64_t> m_sourceLocationExpand;
    std::map<uint32_t, LockMap> m_lockMap;
    uint64_t m_zonesCnt;

    Vector<const char*> m_stringData;
    std::unordered_map<const char*, uint32_t, charutil::Hasher, charutil::Comparator> m_stringMap;

    Vector<SourceLocation*> m_sourceLocationPayload;
    std::unordered_map<SourceLocation*, uint32_t, SourceLocationHasher, SourceLocationComparator> m_sourceLocationPayloadMap;

    std::mutex m_mbpslock;
    std::vector<float> m_mbps;

    // not used for vis - no need to lock
    std::unordered_map<uint64_t, std::vector<ZoneEvent*>> m_zoneStack;
    std::unordered_set<uint64_t> m_pendingStrings;
    std::unordered_set<uint64_t> m_pendingThreads;
    std::unordered_set<uint64_t> m_pendingSourceLocation;
    std::unordered_map<uint64_t, StringLocation> m_pendingCustomStrings;
    std::unordered_map<uint64_t, uint32_t> m_threadMap;
    std::unordered_map<uint64_t, uint32_t> m_plotMap;
    std::unordered_map<const char*, uint32_t, charutil::Hasher, charutil::Comparator> m_plotRev;
    std::unordered_map<uint64_t, PlotData*> m_pendingPlots;
    std::unordered_map<uint64_t, uint32_t> m_sourceLocationShrink;
    std::unordered_map<uint64_t, int32_t> m_pendingSourceLocationPayload;

    Slab<64*1024*1024> m_slab;

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

    int64_t m_delay;
    int64_t m_resolution;
    double m_timerMul;
    std::string m_captureName;

    int8_t m_lastCpu;

    int m_zvHeight;
    int m_zvScroll;

    const ZoneEvent* m_zoneInfoWindow;
    const ZoneEvent* m_zoneHighlight;
    LockHighlight m_lockHighlight;
    const MessageData* m_msgHighlight;

    bool m_drawRegion;
    int64_t m_regionStart;
    int64_t m_regionEnd;

    bool m_showOptions;
    bool m_showMessages;
    bool m_drawZones;
    bool m_drawLocks;
    bool m_drawPlots;
    bool m_onlyContendedLocks;

    Namespace m_namespace;

    bool m_terminate;
};

}

#endif
