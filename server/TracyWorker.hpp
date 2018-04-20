#ifndef __TRACYWORKER_HPP__
#define __TRACYWORKER_HPP__

#include <atomic>
#include <limits>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include "../common/tracy_benaphore.h"
#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"
#include "../common/TracyQueue.hpp"
#include "../common/TracySocket.hpp"
#include "tracy_flat_hash_map.hpp"
#include "TracyEvent.hpp"
#include "TracySlab.hpp"

namespace tracy
{

class FileRead;
class FileWrite;

namespace EventType
{
    enum Type : uint32_t
    {
        Locks       = 1 << 0,
        Messages    = 1 << 1,
        Plots       = 1 << 2,
        Memory      = 1 << 3,

        None        = 0,
        All         = std::numeric_limits<uint32_t>::max()
    };
}

class Worker
{
#pragma pack( 1 )
    struct ZoneThreadData
    {
        ZoneEvent* zone;
        uint16_t thread;
    };
#pragma pack()

    struct SourceLocationZones
    {
        SourceLocationZones()
            : min( std::numeric_limits<int64_t>::max() )
            , max( std::numeric_limits<int64_t>::min() )
            , total( 0 )
        {}

        Vector<ZoneThreadData> zones;
        int64_t min;
        int64_t max;
        int64_t total;
    };

    struct DataBlock
    {
        DataBlock() : zonesCnt( 0 ), lastTime( 0 ) {}

        NonRecursiveBenaphore lock;
        Vector<int64_t> frames;
        Vector<GpuCtxData*> gpuData;
        Vector<MessageData*> messages;
        Vector<PlotData*> plots;
        Vector<ThreadData*> threads;
        MemData memory;
        uint64_t zonesCnt;
        int64_t lastTime;

        flat_hash_map<uint64_t, const char*, nohash<uint64_t>> strings;
        Vector<const char*> stringData;
        flat_hash_map<const char*, uint32_t, charutil::HasherPOT, charutil::Comparator> stringMap;
        flat_hash_map<uint64_t, const char*, nohash<uint64_t>> threadNames;

        flat_hash_map<uint64_t, SourceLocation, nohash<uint64_t>> sourceLocation;
        Vector<SourceLocation*> sourceLocationPayload;
        flat_hash_map<SourceLocation*, uint32_t, SourceLocationHasher, SourceLocationComparator> sourceLocationPayloadMap;
        Vector<uint64_t> sourceLocationExpand;
#ifndef TRACY_NO_STATISTICS
        flat_hash_map<int32_t, SourceLocationZones, nohash<int32_t>> sourceLocationZones;
#endif

        std::map<uint32_t, LockMap> lockMap;

        flat_hash_map<uint64_t, uint16_t, nohash<uint64_t>> threadMap;
        Vector<uint64_t> threadExpand;
    };

    struct MbpsBlock
    {
        MbpsBlock() : mbps( 64 ), compRatio( 1.0 ) {}

        NonRecursiveBenaphore lock;
        std::vector<float> mbps;
        float compRatio;
    };

public:
    Worker( const char* addr );
    Worker( FileRead& f, EventType::Type eventMask = EventType::All );
    ~Worker();

    const std::string& GetAddr() const { return m_addr; }
    const std::string& GetCaptureName() const { return m_captureName; }
    int64_t GetDelay() const { return m_delay; }
    int64_t GetResolution() const { return m_resolution; }

    NonRecursiveBenaphore& GetDataLock() { return m_data.lock; }
    size_t GetFrameCount() const { return m_data.frames.size(); }
    int64_t GetLastTime() const { return m_data.lastTime; }
    uint64_t GetZoneCount() const { return m_data.zonesCnt; }

    int64_t GetFrameTime( size_t idx ) const;
    int64_t GetFrameBegin( size_t idx ) const;
    int64_t GetFrameEnd( size_t idx ) const;
    std::pair <int, int> GetFrameRange( int64_t from, int64_t to );

    const std::map<uint32_t, LockMap>& GetLockMap() const { return m_data.lockMap; }
    const Vector<MessageData*>& GetMessages() const { return m_data.messages; }
    const Vector<GpuCtxData*>& GetGpuData() const { return m_data.gpuData; }
    const Vector<PlotData*>& GetPlots() const { return m_data.plots; }
    const Vector<ThreadData*>& GetThreadData() const { return m_data.threads; }
    const MemData& GetMemData() const { return m_data.memory; }

    // Some zones may have incomplete timing data (only start time is available, end hasn't arrived yet).
    // GetZoneEnd() will try to infer the end time by looking at child zones (parent zone can't end
    //     before its children have ended).
    // GetZoneEndDirect() will only return zone's direct timing data, without looking at children.
    static int64_t GetZoneEnd( const ZoneEvent& ev );
    static int64_t GetZoneEnd( const GpuEvent& ev );
    static tracy_force_inline int64_t GetZoneEndDirect( const ZoneEvent& ev ) { return ev.end >= 0 ? ev.end : ev.start; }
    static tracy_force_inline int64_t GetZoneEndDirect( const GpuEvent& ev ) { return ev.gpuEnd >= 0 ? ev.gpuEnd : ev.gpuStart; }

    const char* GetString( uint64_t ptr ) const;
    const char* GetString( const StringRef& ref ) const;
    const char* GetString( const StringIdx& idx ) const;
    const char* GetThreadString( uint64_t id ) const;
    const SourceLocation& GetSourceLocation( int32_t srcloc ) const;

    std::vector<int32_t> GetMatchingSourceLocation( const char* query ) const;

#ifndef TRACY_NO_STATISTICS
    const SourceLocationZones& GetZonesForSourceLocation( int32_t srcloc ) const;
    const flat_hash_map<int32_t, SourceLocationZones, nohash<int32_t>>& GetSourceLocationZones() const { return m_data.sourceLocationZones; }
#endif

    tracy_force_inline uint16_t CompressThread( uint64_t thread );
    tracy_force_inline uint64_t DecompressThread( uint16_t thread ) const { assert( thread < m_data.threadExpand.size() ); return m_data.threadExpand[thread]; }

    NonRecursiveBenaphore& GetMbpsDataLock() { return m_mbpsData.lock; }
    const std::vector<float>& GetMbpsData() const { return m_mbpsData.mbps; }
    float GetCompRatio() const { return m_mbpsData.compRatio; }

    bool HasData() const { return m_hasData.load( std::memory_order_acquire ); }
    bool IsConnected() const { return m_connected.load( std::memory_order_relaxed ); }
    bool IsDataStatic() const { return !m_thread.joinable(); }
    void Shutdown() { m_shutdown.store( true, std::memory_order_relaxed ); }

    void Write( FileWrite& f );

private:
    void Exec();
    void ServerQuery( uint8_t type, uint64_t data );

    tracy_force_inline void DispatchProcess( const QueueItem& ev, char*& ptr );
    tracy_force_inline void Process( const QueueItem& ev );
    tracy_force_inline void ProcessZoneBegin( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLoc( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneEnd( const QueueZoneEnd& ev );
    tracy_force_inline void ProcessFrameMark( const QueueFrameMark& ev );
    tracy_force_inline void ProcessZoneText( const QueueZoneText& ev );
    tracy_force_inline void ProcessLockAnnounce( const QueueLockAnnounce& ev );
    tracy_force_inline void ProcessLockWait( const QueueLockWait& ev );
    tracy_force_inline void ProcessLockObtain( const QueueLockObtain& ev );
    tracy_force_inline void ProcessLockRelease( const QueueLockRelease& ev );
    tracy_force_inline void ProcessLockSharedWait( const QueueLockWait& ev );
    tracy_force_inline void ProcessLockSharedObtain( const QueueLockObtain& ev );
    tracy_force_inline void ProcessLockSharedRelease( const QueueLockRelease& ev );
    tracy_force_inline void ProcessLockMark( const QueueLockMark& ev );
    tracy_force_inline void ProcessPlotData( const QueuePlotData& ev );
    tracy_force_inline void ProcessMessage( const QueueMessage& ev );
    tracy_force_inline void ProcessMessageLiteral( const QueueMessage& ev );
    tracy_force_inline void ProcessGpuNewContext( const QueueGpuNewContext& ev );
    tracy_force_inline void ProcessGpuZoneBegin( const QueueGpuZoneBegin& ev );
    tracy_force_inline void ProcessGpuZoneEnd( const QueueGpuZoneEnd& ev );
    tracy_force_inline void ProcessGpuTime( const QueueGpuTime& ev );
    tracy_force_inline void ProcessGpuResync( const QueueGpuResync& ev );
    tracy_force_inline void ProcessMemAlloc( const QueueMemAlloc& ev );
    tracy_force_inline void ProcessMemFree( const QueueMemFree& ev );

    tracy_force_inline void CheckSourceLocation( uint64_t ptr );
    void NewSourceLocation( uint64_t ptr );
    tracy_force_inline uint32_t ShrinkSourceLocation( uint64_t srcloc );
    uint32_t NewShrinkedSourceLocation( uint64_t srcloc );

    void InsertMessageData( MessageData* msg, uint64_t thread );

    ThreadData* NewThread( uint64_t thread );
    ThreadData* NoticeThread( uint64_t thread );

    tracy_force_inline void NewZone( ZoneEvent* zone, uint64_t thread );

    void InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread );

    void CheckString( uint64_t ptr );
    void CheckThreadString( uint64_t id );

    void AddSourceLocation( const QueueSourceLocation& srcloc );
    void AddSourceLocationPayload( uint64_t ptr, char* data, size_t sz );

    void AddString( uint64_t ptr, char* str, size_t sz );
    void AddThreadString( uint64_t id, char* str, size_t sz );
    void AddCustomString( uint64_t ptr, char* str, size_t sz );

    void InsertPlot( PlotData* plot, int64_t time, double val );
    void HandlePlotName( uint64_t name, char* str, size_t sz );

    void HandlePostponedPlots();

    StringLocation StoreString( char* str, size_t sz );
    uint16_t CompressThreadNew( uint64_t thread );

    tracy_force_inline void ReadTimeline( FileRead& f, Vector<ZoneEvent*>& vec, uint16_t thread );
    tracy_force_inline void ReadTimeline( FileRead& f, Vector<GpuEvent*>& vec );

    void ReadTimeline( FileRead& f, Vector<ZoneEvent*>& vec, uint16_t thread, uint64_t size );
    void ReadTimeline( FileRead& f, Vector<GpuEvent*>& vec, uint64_t size );

    void WriteTimeline( FileWrite& f, const Vector<ZoneEvent*>& vec );
    void WriteTimeline( FileWrite& f, const Vector<GpuEvent*>& vec );

    int64_t TscTime( int64_t tsc ) { return int64_t( tsc * m_timerMul ); }
    int64_t TscTime( uint64_t tsc ) { return int64_t( tsc * m_timerMul ); }

    Socket m_sock;
    std::string m_addr;

    std::thread m_thread;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_hasData;
    std::atomic<bool> m_shutdown;

    int64_t m_delay;
    int64_t m_resolution;
    double m_timerMul;
    std::string m_captureName;
    bool m_terminate;
    LZ4_streamDecode_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;

    flat_hash_map<uint16_t, GpuCtxData*, nohash<uint16_t>> m_gpuCtxMap;
    flat_hash_map<uint64_t, StringLocation, nohash<uint64_t>> m_pendingCustomStrings;
    flat_hash_map<uint64_t, PlotData*, nohash<uint64_t>> m_pendingPlots;
    flat_hash_map<uint64_t, PlotData*, nohash<uint64_t>> m_plotMap;
    flat_hash_map<const char*, PlotData*, charutil::HasherPOT, charutil::Comparator> m_plotRev;
    flat_hash_map<uint64_t, int32_t, nohash<uint64_t>> m_pendingSourceLocationPayload;
    Vector<uint64_t> m_sourceLocationQueue;
    flat_hash_map<uint64_t, uint32_t, nohash<uint64_t>> m_sourceLocationShrink;
    flat_hash_map<uint64_t, ThreadData*, nohash<uint64_t>> m_threadMap;

    uint32_t m_pendingStrings;
    uint32_t m_pendingThreads;
    uint32_t m_pendingSourceLocation;

    Slab<64*1024*1024> m_slab;

    DataBlock m_data;
    MbpsBlock m_mbpsData;
};

}

#endif
