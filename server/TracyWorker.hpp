#ifndef __TRACYWORKER_HPP__
#define __TRACYWORKER_HPP__

#include <atomic>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "../common/tracy_lz4.hpp"
#include "../common/TracyForceInline.hpp"
#include "../common/TracyMutex.hpp"
#include "../common/TracyQueue.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "tracy_flat_hash_map.hpp"
#include "TracyEvent.hpp"
#include "TracySlab.hpp"
#include "TracyStringDiscovery.hpp"
#include "TracyVarArray.hpp"

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

struct UnsupportedVersion : public std::exception
{
    UnsupportedVersion( int version ) : version( version ) {}
    int version;
};

struct LoadProgress
{
    enum Stage
    {
        Initialization,
        Locks,
        Messages,
        Zones,
        GpuZones,
        Plots,
        Memory,
        CallStacks
    };

    LoadProgress() : total( 0 ), progress( 0 ), subTotal( 0 ), subProgress( 0 ) {}

    std::atomic<uint64_t> total;
    std::atomic<uint64_t> progress;
    std::atomic<uint64_t> subTotal;
    std::atomic<uint64_t> subProgress;
};

class Worker
{
public:
#pragma pack( 1 )
    struct ZoneThreadData
    {
        ZoneEvent* zone;
        uint16_t thread;
    };
#pragma pack()

private:
    struct SourceLocationZones
    {
        Vector<ZoneThreadData> zones;
        int64_t min = std::numeric_limits<int64_t>::max();
        int64_t max = std::numeric_limits<int64_t>::min();
        int64_t total = 0;
        double sumSq = 0;
        int64_t selfMin = std::numeric_limits<int64_t>::max();
        int64_t selfMax = std::numeric_limits<int64_t>::min();
        int64_t selfTotal = 0;
    };

    struct CallstackFrameIdHash
    {
        size_t operator()( const CallstackFrameId& id ) const { return id.data; }
        typedef tracy::power_of_two_hash_policy hash_policy;
    };

    struct CallstackFrameIdCompare
    {
        bool operator()( const CallstackFrameId& lhs, const CallstackFrameId& rhs ) const { return lhs.data == rhs.data; }
    };

    struct RevFrameHash
    {
        size_t operator()( const CallstackFrameData* data ) const
        {
            size_t hash = data->size;
            for( uint8_t i=0; i<data->size; i++ )
            {
                const auto& v = data->data[i];
                hash = ( ( hash << 5 ) + hash ) ^ size_t( v.line );
                hash = ( ( hash << 5 ) + hash ) ^ size_t( v.file.__data );
                hash = ( ( hash << 5 ) + hash ) ^ size_t( v.name.__data );
            }
            return hash;
        }
        typedef tracy::power_of_two_hash_policy hash_policy;
    };

    struct RevFrameComp
    {
        bool operator()( const CallstackFrameData* lhs, const CallstackFrameData* rhs ) const
        {
            if( lhs->size != rhs->size ) return false;
            for( uint8_t i=0; i<lhs->size; i++ )
            {
                if( memcmp( lhs->data + i, rhs->data + i, sizeof( CallstackFrame ) ) != 0 ) return false;
            }
            return true;
        }
    };

    struct DataBlock
    {
        DataBlock() : zonesCnt( 0 ), lastTime( 0 ), frameOffset( 0 ), threadLast( std::numeric_limits<uint64_t>::max(), 0 ) {}

        TracyMutex lock;
        StringDiscovery<FrameData*> frames;
        FrameData* framesBase;
        Vector<GpuCtxData*> gpuData;
        Vector<MessageData*> messages;
        StringDiscovery<PlotData*> plots;
        Vector<ThreadData*> threads;
        MemData memory;
        uint64_t zonesCnt;
        int64_t lastTime;
        uint64_t frameOffset;

        flat_hash_map<uint64_t, const char*, nohash<uint64_t>> strings;
        Vector<const char*> stringData;
        flat_hash_map<charutil::StringKey, uint32_t, charutil::StringKey::HasherPOT, charutil::StringKey::Comparator> stringMap;
        flat_hash_map<uint64_t, const char*, nohash<uint64_t>> threadNames;

        flat_hash_map<uint64_t, SourceLocation, nohash<uint64_t>> sourceLocation;
        Vector<SourceLocation*> sourceLocationPayload;
        flat_hash_map<SourceLocation*, uint32_t, SourceLocationHasher, SourceLocationComparator> sourceLocationPayloadMap;
        Vector<uint64_t> sourceLocationExpand;
#ifndef TRACY_NO_STATISTICS
        flat_hash_map<int32_t, SourceLocationZones, nohash<int32_t>> sourceLocationZones;
        bool sourceLocationZonesReady;
#else
        flat_hash_map<int32_t, uint64_t> sourceLocationZonesCnt;
#endif

        flat_hash_map<VarArray<CallstackFrameId>*, uint32_t, VarArrayHasherPOT<CallstackFrameId>, VarArrayComparator<CallstackFrameId>> callstackMap;
        Vector<VarArray<CallstackFrameId>*> callstackPayload;
        flat_hash_map<CallstackFrameId, CallstackFrameData*, CallstackFrameIdHash, CallstackFrameIdCompare> callstackFrameMap;
        flat_hash_map<CallstackFrameData*, CallstackFrameId, RevFrameHash, RevFrameComp> revFrameMap;

        flat_hash_map<uint32_t, LockMap*, nohash<uint32_t>> lockMap;

        flat_hash_map<uint64_t, uint16_t, nohash<uint64_t>> threadMap;
        Vector<uint64_t> threadExpand;
        std::pair<uint64_t, uint16_t> threadLast;

        Vector<Vector<ZoneEvent*>> zoneChildren;
        Vector<Vector<GpuEvent*>> gpuChildren;

        Vector<Vector<ZoneEvent*>> zoneVectorCache;

        CrashEvent crashEvent;
    };

    struct MbpsBlock
    {
        MbpsBlock() : mbps( 64 ), compRatio( 1.0 ), queue( 0 ) {}

        TracyMutex lock;
        std::vector<float> mbps;
        float compRatio;
        size_t queue;
    };

    enum class NextCallstackType
    {
        Zone,
        Gpu,
        Crash
    };

    struct NextCallstack
    {
        NextCallstackType type;
        union
        {
            ZoneEvent* zone;
            GpuEvent* gpu;
        };
    };

    struct FailureData
    {
        uint64_t thread;
        int32_t srcloc;
    };

public:
    enum class Failure
    {
        None,
        ZoneStack,
        ZoneEnd,
        ZoneText,
        ZoneName,
        MemFree,
        FrameEnd,

        NUM_FAILURES
    };

    Worker( const char* addr );
    Worker( FileRead& f, EventType::Type eventMask = EventType::All );
    ~Worker();

    const std::string& GetAddr() const { return m_addr; }
    const std::string& GetCaptureName() const { return m_captureName; }
    const std::string& GetCaptureProgram() const { return m_captureProgram; }
    uint64_t GetCaptureTime() const { return m_captureTime; }
    const std::string& GetHostInfo() const { return m_hostInfo; }
    int64_t GetDelay() const { return m_delay; }
    int64_t GetResolution() const { return m_resolution; }

    TracyMutex& GetDataLock() { return m_data.lock; }
    size_t GetFrameCount( const FrameData& fd ) const { return fd.frames.size(); }
    size_t GetFullFrameCount( const FrameData& fd ) const;
    int64_t GetTimeBegin() const { return GetFrameBegin( *m_data.framesBase, 0 ); }
    int64_t GetLastTime() const { return m_data.lastTime; }
    uint64_t GetZoneCount() const { return m_data.zonesCnt; }
    uint64_t GetLockCount() const;
    uint64_t GetPlotCount() const;
    uint64_t GetSrcLocCount() const { return m_data.sourceLocationPayload.size() + m_data.sourceLocation.size(); }
    uint64_t GetCallstackPayloadCount() const { return m_data.callstackPayload.size() - 1; }
    uint64_t GetCallstackFrameCount() const { return m_data.callstackFrameMap.size(); }
    uint64_t GetFrameOffset() const { return m_data.frameOffset; }
    const FrameData* GetFramesBase() const { return m_data.framesBase; }
    const Vector<FrameData*>& GetFrames() const { return m_data.frames.Data(); }

    int64_t GetFrameTime( const FrameData& fd, size_t idx ) const;
    int64_t GetFrameBegin( const FrameData& fd, size_t idx ) const;
    int64_t GetFrameEnd( const FrameData& fd, size_t idx ) const;
    std::pair <int, int> GetFrameRange( const FrameData& fd, int64_t from, int64_t to );

    const flat_hash_map<uint32_t, LockMap*, nohash<uint32_t>>& GetLockMap() const { return m_data.lockMap; }
    const Vector<MessageData*>& GetMessages() const { return m_data.messages; }
    const Vector<GpuCtxData*>& GetGpuData() const { return m_data.gpuData; }
    const Vector<PlotData*>& GetPlots() const { return m_data.plots.Data(); }
    const Vector<ThreadData*>& GetThreadData() const { return m_data.threads; }
    const MemData& GetMemData() const { return m_data.memory; }

    const VarArray<CallstackFrameId>& GetCallstack( uint32_t idx ) const { return *m_data.callstackPayload[idx]; }
    const CallstackFrameData* GetCallstackFrame( const CallstackFrameId& ptr ) const;
    uint64_t GetCanonicalPointer( const CallstackFrameId& id ) const;

    const CrashEvent& GetCrashEvent() const { return m_data.crashEvent; }

    // Some zones may have incomplete timing data (only start time is available, end hasn't arrived yet).
    // GetZoneEnd() will try to infer the end time by looking at child zones (parent zone can't end
    //     before its children have ended).
    // GetZoneEndDirect() will only return zone's direct timing data, without looking at children.
    int64_t GetZoneEnd( const ZoneEvent& ev );
    int64_t GetZoneEnd( const GpuEvent& ev );
    static tracy_force_inline int64_t GetZoneEndDirect( const ZoneEvent& ev ) { return ev.end >= 0 ? ev.end : ev.start; }
    static tracy_force_inline int64_t GetZoneEndDirect( const GpuEvent& ev ) { return ev.gpuEnd >= 0 ? ev.gpuEnd : ev.gpuStart; }

    const char* GetString( uint64_t ptr ) const;
    const char* GetString( const StringRef& ref ) const;
    const char* GetString( const StringIdx& idx ) const;
    const char* GetThreadString( uint64_t id ) const;
    const SourceLocation& GetSourceLocation( int32_t srcloc ) const;

    const char* GetZoneName( const SourceLocation& srcloc ) const;
    const char* GetZoneName( const ZoneEvent& ev ) const;
    const char* GetZoneName( const ZoneEvent& ev, const SourceLocation& srcloc ) const;
    const char* GetZoneName( const GpuEvent& ev ) const;
    const char* GetZoneName( const GpuEvent& ev, const SourceLocation& srcloc ) const;

    tracy_force_inline const Vector<ZoneEvent*>& GetZoneChildren( int32_t idx ) const { return m_data.zoneChildren[idx]; }
    tracy_force_inline const Vector<GpuEvent*>& GetGpuChildren( int32_t idx ) const { return m_data.gpuChildren[idx]; }

    std::vector<int32_t> GetMatchingSourceLocation( const char* query, bool ignoreCase ) const;

#ifndef TRACY_NO_STATISTICS
    const SourceLocationZones& GetZonesForSourceLocation( int32_t srcloc ) const;
    const flat_hash_map<int32_t, SourceLocationZones, nohash<int32_t>>& GetSourceLocationZones() const { return m_data.sourceLocationZones; }
    bool AreSourceLocationZonesReady() const { return m_data.sourceLocationZonesReady; }
#endif

    tracy_force_inline uint16_t CompressThread( uint64_t thread )
    {
        if( m_data.threadLast.first == thread ) return m_data.threadLast.second;
        return CompressThreadReal( thread );
    }
    tracy_force_inline uint64_t DecompressThread( uint16_t thread ) const { assert( thread < m_data.threadExpand.size() ); return m_data.threadExpand[thread]; }

    TracyMutex& GetMbpsDataLock() { return m_mbpsData.lock; }
    const std::vector<float>& GetMbpsData() const { return m_mbpsData.mbps; }
    float GetCompRatio() const { return m_mbpsData.compRatio; }
    size_t GetSendQueueSize() const { return m_mbpsData.queue; }

    bool HasData() const { return m_hasData.load( std::memory_order_acquire ); }
    bool IsConnected() const { return m_connected.load( std::memory_order_relaxed ); }
    bool IsDataStatic() const { return !m_thread.joinable(); }
    void Shutdown() { m_shutdown.store( true, std::memory_order_relaxed ); }
    void Disconnect() { Shutdown(); }   // TODO: Needs proper implementation.

    void Write( FileWrite& f );
    int GetTraceVersion() const { return m_traceVersion; }
    uint8_t GetHandshakeStatus() const { return m_handshake.load( std::memory_order_relaxed ); }

    static const LoadProgress& GetLoadProgress() { return s_loadProgress; }
    int64_t GetLoadTime() const { return m_loadTime; }

    void ClearFailure() { m_failure = Failure::None; }
    Failure GetFailureType() const { return m_failure; }
    const FailureData& GetFailureData() const { return m_failureData; }
    static const char* GetFailureString( Failure failure );

private:
    void Exec();
    void Query( ServerQuery type, uint64_t data );

    tracy_force_inline bool DispatchProcess( const QueueItem& ev, char*& ptr );
    tracy_force_inline bool Process( const QueueItem& ev );
    tracy_force_inline void ProcessZoneBegin( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginCallstack( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLoc( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLocCallstack( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneEnd( const QueueZoneEnd& ev );
    tracy_force_inline void ProcessZoneValidation( const QueueZoneValidation& ev );
    tracy_force_inline void ProcessFrameMark( const QueueFrameMark& ev );
    tracy_force_inline void ProcessFrameMarkStart( const QueueFrameMark& ev );
    tracy_force_inline void ProcessFrameMarkEnd( const QueueFrameMark& ev );
    tracy_force_inline void ProcessZoneText( const QueueZoneText& ev );
    tracy_force_inline void ProcessZoneName( const QueueZoneText& ev );
    tracy_force_inline void ProcessLockAnnounce( const QueueLockAnnounce& ev );
    tracy_force_inline void ProcessLockTerminate( const QueueLockTerminate& ev );
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
    tracy_force_inline void ProcessGpuZoneBeginCallstack( const QueueGpuZoneBegin& ev );
    tracy_force_inline void ProcessGpuZoneEnd( const QueueGpuZoneEnd& ev );
    tracy_force_inline void ProcessGpuTime( const QueueGpuTime& ev );
    tracy_force_inline void ProcessMemAlloc( const QueueMemAlloc& ev );
    tracy_force_inline bool ProcessMemFree( const QueueMemFree& ev );
    tracy_force_inline void ProcessMemAllocCallstack( const QueueMemAlloc& ev );
    tracy_force_inline void ProcessMemFreeCallstack( const QueueMemFree& ev );
    tracy_force_inline void ProcessCallstackMemory( const QueueCallstackMemory& ev );
    tracy_force_inline void ProcessCallstack( const QueueCallstack& ev );
    tracy_force_inline void ProcessCallstackAlloc( const QueueCallstackAlloc& ev );
    tracy_force_inline void ProcessCallstackFrameSize( const QueueCallstackFrameSize& ev );
    tracy_force_inline void ProcessCallstackFrame( const QueueCallstackFrame& ev );
    tracy_force_inline void ProcessCrashReport( const QueueCrashReport& ev );
    tracy_force_inline void ProcessSysTime( const QueueSysTime& ev );

    tracy_force_inline void ProcessZoneBeginImpl( ZoneEvent* zone, const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLocImpl( ZoneEvent* zone, const QueueZoneBegin& ev );
    tracy_force_inline void ProcessGpuZoneBeginImpl( GpuEvent* zone, const QueueGpuZoneBegin& ev );

    void ZoneStackFailure( uint64_t thread, const ZoneEvent* ev );
    void ZoneEndFailure( uint64_t thread );
    void ZoneTextFailure( uint64_t thread );
    void ZoneNameFailure( uint64_t thread );
    void MemFreeFailure( uint64_t thread );
    void FrameEndFailure();

    tracy_force_inline void CheckSourceLocation( uint64_t ptr );
    void NewSourceLocation( uint64_t ptr );
    tracy_force_inline uint32_t ShrinkSourceLocation( uint64_t srcloc );
    uint32_t NewShrinkedSourceLocation( uint64_t srcloc );

    tracy_force_inline void MemAllocChanged( int64_t time );
    void CreateMemAllocPlot();
    void ReconstructMemAllocPlot();

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

    tracy_force_inline void AddCallstackPayload( uint64_t ptr, char* data, size_t sz );
    tracy_force_inline void AddCallstackAllocPayload( uint64_t ptr, char* data, size_t sz );

    void InsertPlot( PlotData* plot, int64_t time, double val );
    void HandlePlotName( uint64_t name, char* str, size_t sz );
    void HandleFrameName( uint64_t name, char* str, size_t sz );

    void HandlePostponedPlots();

    StringLocation StoreString( char* str, size_t sz );
    uint16_t CompressThreadReal( uint64_t thread );
    uint16_t CompressThreadNew( uint64_t thread );

    tracy_force_inline void ReadTimeline( FileRead& f, ZoneEvent* zone, uint16_t thread, int64_t& refTime );
    tracy_force_inline void ReadTimelinePre042( FileRead& f, ZoneEvent* zone, uint16_t thread, int fileVer );
    tracy_force_inline void ReadTimeline( FileRead& f, GpuEvent* zone, int64_t& refTime, int64_t& refGpuTime );
    tracy_force_inline void ReadTimelinePre044( FileRead& f, GpuEvent* zone, int64_t& refTime, int64_t& refGpuTime, int fileVer );

    tracy_force_inline void ReadTimelineUpdateStatistics( ZoneEvent* zone, uint16_t thread );

    void ReadTimeline( FileRead& f, Vector<ZoneEvent*>& vec, uint16_t thread, uint64_t size, int64_t& refTime );
    void ReadTimelinePre042( FileRead& f, Vector<ZoneEvent*>& vec, uint16_t thread, uint64_t size, int fileVer );
    void ReadTimeline( FileRead& f, Vector<GpuEvent*>& vec, uint64_t size, int64_t& refTime, int64_t& refGpuTime );
    void ReadTimelinePre044( FileRead& f, Vector<GpuEvent*>& vec, uint64_t size, int64_t& refTime, int64_t& refGpuTime, int fileVer );

    void WriteTimeline( FileWrite& f, const Vector<ZoneEvent*>& vec, int64_t& refTime );
    void WriteTimeline( FileWrite& f, const Vector<GpuEvent*>& vec, int64_t& refTime, int64_t& refGpuTime );

    int64_t TscTime( int64_t tsc ) { return int64_t( tsc * m_timerMul ); }
    int64_t TscTime( uint64_t tsc ) { return int64_t( tsc * m_timerMul ); }

    Socket m_sock;
    std::string m_addr;

    std::thread m_thread;
    std::atomic<bool> m_connected = { false };
    std::atomic<bool> m_hasData;
    std::atomic<bool> m_shutdown = { false };

    std::thread m_threadBackground;

    int64_t m_delay;
    int64_t m_resolution;
    double m_timerMul;
    std::string m_captureName;
    std::string m_captureProgram;
    uint64_t m_captureTime;
    std::string m_hostInfo;
    bool m_terminate = false;
    bool m_crashed = false;
    LZ4_streamDecode_t* m_stream;
    char* m_buffer;
    int m_bufferOffset;
    bool m_onDemand;

    GpuCtxData* m_gpuCtxMap[256];
    flat_hash_map<uint64_t, StringLocation, nohash<uint64_t>> m_pendingCustomStrings;
    uint64_t m_pendingCallstackPtr = 0;
    uint32_t m_pendingCallstackId;
    flat_hash_map<uint64_t, int32_t, nohash<uint64_t>> m_pendingSourceLocationPayload;
    Vector<uint64_t> m_sourceLocationQueue;
    flat_hash_map<uint64_t, uint32_t, nohash<uint64_t>> m_sourceLocationShrink;
    flat_hash_map<uint64_t, ThreadData*, nohash<uint64_t>> m_threadMap;
    flat_hash_map<uint64_t, NextCallstack, nohash<uint64_t>> m_nextCallstack;

    uint32_t m_pendingStrings;
    uint32_t m_pendingThreads;
    uint32_t m_pendingSourceLocation;
    uint32_t m_pendingCallstackFrames;
    uint8_t m_pendingCallstackSubframes;

    CallstackFrameData* m_callstackFrameStaging;
    uint64_t m_callstackFrameStagingPtr;
    uint64_t m_callstackAllocNextIdx = 0;

    uint64_t m_lastMemActionCallstack;
    bool m_lastMemActionWasAlloc;

    Slab<64*1024*1024> m_slab;

    DataBlock m_data;
    MbpsBlock m_mbpsData;

    int m_traceVersion;
    std::atomic<uint8_t> m_handshake = { 0 };

    static LoadProgress s_loadProgress;
    int64_t m_loadTime;

    Failure m_failure = Failure::None;
    FailureData m_failureData;

    PlotData* m_sysTimePlot = nullptr;

    Vector<ServerQueryPacket> m_serverQueryQueue;
    size_t m_serverQuerySpaceLeft;
};

}

#endif
