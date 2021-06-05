#ifndef __TRACYWORKER_HPP__
#define __TRACYWORKER_HPP__

#include <atomic>
#include <condition_variable>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>
#include <string.h>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../common/TracyForceInline.hpp"
#include "../common/TracyQueue.hpp"
#include "../common/TracyProtocol.hpp"
#include "../common/TracySocket.hpp"
#include "tracy_robin_hood.h"
#include "TracyEvent.hpp"
#include "TracyShortPtr.hpp"
#include "TracySlab.hpp"
#include "TracyStringDiscovery.hpp"
#include "TracyTextureCompression.hpp"
#include "TracyThreadCompress.hpp"
#include "TracyVarArray.hpp"


namespace tracy
{

class FileRead;
class FileWrite;

namespace EventType
{
    enum Type : uint32_t
    {
        Locks           = 1 << 0,
        Messages        = 1 << 1,
        Plots           = 1 << 2,
        Memory          = 1 << 3,
        FrameImages     = 1 << 4,
        ContextSwitches = 1 << 5,
        Samples         = 1 << 6,
        SymbolCode      = 1 << 7,
        SourceCache     = 1 << 8,

        None            = 0,
        All             = std::numeric_limits<uint32_t>::max()
    };
}

struct UnsupportedVersion : public std::exception
{
    UnsupportedVersion( int version ) : version( version ) {}
    int version;
};

struct LegacyVersion : public std::exception
{
    LegacyVersion( int version ) : version ( version ) {}
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
        CallStacks,
        FrameImages,
        ContextSwitches,
        ContextSwitchesPerCpu
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
    struct ImportEventTimeline
    {
        uint64_t tid;
        uint64_t timestamp;
        std::string name;
        std::string text;
        bool isEnd;
        std::string locFile;
        uint32_t locLine;
    };

    struct ImportEventMessages
    {
        uint64_t tid;
        uint64_t timestamp;
        std::string message;
    };

    struct ImportEventPlots
    {
        std::string name;
        PlotValueFormatting format;
        std::vector<std::pair<int64_t, double>> data;
    };

    struct ZoneThreadData
    {
        tracy_force_inline ZoneEvent* Zone() const { return (ZoneEvent*)( _zone_thread >> 16 ); }
        tracy_force_inline void SetZone( ZoneEvent* zone ) { assert( ( uint64_t( zone ) & 0xFFFF000000000000 ) == 0 ); memcpy( ((char*)&_zone_thread)+2, &zone, 4 ); memcpy( ((char*)&_zone_thread)+6, ((char*)&zone)+4, 2 ); }
        tracy_force_inline uint16_t Thread() const { return uint16_t( _zone_thread & 0xFFFF ); }
        tracy_force_inline void SetThread( uint16_t thread ) { memcpy( &_zone_thread, &thread, 2 ); }

        uint64_t _zone_thread;
    };
    enum { ZoneThreadDataSize = sizeof( ZoneThreadData ) };

    struct CpuThreadTopology
    {
        uint32_t package;
        uint32_t core;
    };

    struct MemoryBlock
    {
        const char* data;
        uint32_t len;
    };

    struct InlineStackData
    {
        uint64_t symAddr;
        CallstackFrameId frame;
        uint8_t inlineFrame;
    };

#pragma pack( 1 )
    struct GhostKey
    {
        CallstackFrameId frame;
        uint8_t inlineFrame;
    };
#pragma pack()

    struct GhostKeyHasher
    {
        size_t operator()( const GhostKey& key ) const
        {
            return charutil::hash( (const char*)&key, sizeof( GhostKey ) );
        }
    };

    struct GhostKeyComparator
    {
        bool operator()( const GhostKey& lhs, const GhostKey& rhs ) const
        {
            return memcmp( &lhs, &rhs, sizeof( GhostKey ) ) == 0;
        }
    };

private:
    struct SourceLocationZones
    {
        struct ZtdSort { bool operator()( const ZoneThreadData& lhs, const ZoneThreadData& rhs ) { return lhs.Zone()->Start() < rhs.Zone()->Start(); } };

        SortedVector<ZoneThreadData, ZtdSort> zones;
        int64_t min = std::numeric_limits<int64_t>::max();
        int64_t max = std::numeric_limits<int64_t>::min();
        int64_t total = 0;
        double sumSq = 0;
        int64_t selfMin = std::numeric_limits<int64_t>::max();
        int64_t selfMax = std::numeric_limits<int64_t>::min();
        int64_t selfTotal = 0;
        size_t nonReentrantCount = 0;
        int64_t nonReentrantMin = std::numeric_limits<int64_t>::max();
        int64_t nonReentrantMax = std::numeric_limits<int64_t>::min();
        int64_t nonReentrantTotal = 0;
    };

    struct CallstackFrameIdHash
    {
        size_t operator()( const CallstackFrameId& id ) const { return id.data; }
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
                hash = ( ( hash << 5 ) + hash ) ^ size_t( v.file.Idx() );
                hash = ( ( hash << 5 ) + hash ) ^ size_t( v.name.Idx() );
            }
            return hash;
        }
    };

    struct RevFrameComp
    {
        bool operator()( const CallstackFrameData* lhs, const CallstackFrameData* rhs ) const
        {
            if( lhs->size != rhs->size ) return false;
            for( uint8_t i=0; i<lhs->size; i++ )
            {
                if( memcmp( lhs->data + i, rhs->data + i, sizeof( CallstackFrameBasic ) ) != 0 ) return false;
            }
            return true;
        }
    };

    struct SymbolPending
    {
        StringIdx name;
        StringIdx imageName;
        StringIdx file;
        uint32_t line;
        uint32_t size;
        bool isInline;
    };

    struct DataBlock
    {
        std::mutex lock;
        StringDiscovery<FrameData*> frames;
        FrameData* framesBase;
        Vector<GpuCtxData*> gpuData;
        Vector<short_ptr<MessageData>> messages;
        StringDiscovery<PlotData*> plots;
        Vector<ThreadData*> threads;
        Vector<ZoneExtra> zoneExtra;
        MemData* memory;
        unordered_flat_map<uint64_t, MemData*> memNameMap;
        uint64_t zonesCnt = 0;
        uint64_t gpuCnt = 0;
        uint64_t samplesCnt = 0;
        uint64_t ghostCnt = 0;
        int64_t baseTime = 0;
        int64_t lastTime = 0;
        uint64_t frameOffset = 0;
        CpuArchitecture cpuArch = CpuArchUnknown;
        uint32_t cpuId = 0;
        char cpuManufacturer[13];

        unordered_flat_map<uint64_t, const char*> strings;
        Vector<const char*> stringData;
        unordered_flat_map<charutil::StringKey, uint32_t, charutil::StringKey::Hasher, charutil::StringKey::Comparator> stringMap;
        unordered_flat_map<uint64_t, const char*> threadNames;
        unordered_flat_map<uint64_t, std::pair<const char*, const char*>> externalNames;

        unordered_flat_map<uint64_t, SourceLocation> sourceLocation;
        Vector<short_ptr<SourceLocation>> sourceLocationPayload;
        unordered_flat_map<const SourceLocation*, int16_t, SourceLocationHasher, SourceLocationComparator> sourceLocationPayloadMap;
        Vector<uint64_t> sourceLocationExpand;
#ifndef TRACY_NO_STATISTICS
        unordered_flat_map<int16_t, SourceLocationZones> sourceLocationZones;
        bool sourceLocationZonesReady = false;
#else
        unordered_flat_map<int16_t, uint64_t> sourceLocationZonesCnt;
#endif

        unordered_flat_map<VarArray<CallstackFrameId>*, uint32_t, VarArrayHasher<CallstackFrameId>, VarArrayComparator<CallstackFrameId>> callstackMap;
        Vector<short_ptr<VarArray<CallstackFrameId>>> callstackPayload;
        unordered_flat_map<CallstackFrameId, CallstackFrameData*, CallstackFrameIdHash, CallstackFrameIdCompare> callstackFrameMap;
        unordered_flat_map<CallstackFrameData*, CallstackFrameId, RevFrameHash, RevFrameComp> revFrameMap;
        unordered_flat_map<uint64_t, SymbolData> symbolMap;
        unordered_flat_map<uint64_t, SymbolStats> symbolStats;
        Vector<SymbolLocation> symbolLoc;
        Vector<uint64_t> symbolLocInline;
        int64_t newSymbolsIndex = -1;
        int64_t newInlineSymbolsIndex = -1;
        unordered_flat_map<uint64_t, uint64_t> codeSymbolMap;

#ifndef TRACY_NO_STATISTICS
        unordered_flat_map<VarArray<CallstackFrameId>*, uint32_t, VarArrayHasher<CallstackFrameId>, VarArrayComparator<CallstackFrameId>> parentCallstackMap;
        Vector<short_ptr<VarArray<CallstackFrameId>>> parentCallstackPayload;
        unordered_flat_map<CallstackFrameId, CallstackFrameData*, CallstackFrameIdHash, CallstackFrameIdCompare> parentCallstackFrameMap;
        unordered_flat_map<CallstackFrameData*, CallstackFrameId, RevFrameHash, RevFrameComp> revParentFrameMap;
        unordered_flat_map<uint32_t, uint32_t> postponedSamples;
        unordered_flat_map<CallstackFrameId, uint32_t, CallstackFrameIdHash, CallstackFrameIdCompare> pendingInstructionPointers;
        unordered_flat_map<uint64_t, unordered_flat_map<CallstackFrameId, uint32_t, CallstackFrameIdHash, CallstackFrameIdCompare>> instructionPointersMap;
        unordered_flat_map<uint64_t, Vector<SampleDataRange>> symbolSamples;
        unordered_flat_map<CallstackFrameId, Vector<SampleDataRange>, CallstackFrameIdHash, CallstackFrameIdCompare> pendingSymbolSamples;
        unordered_flat_map<uint64_t, Vector<Int48>> childSamples;
        bool newFramesWereReceived = false;
        bool callstackSamplesReady = false;
        bool ghostZonesReady = false;
        bool ghostZonesPostponed = false;
        bool symbolSamplesReady = false;
#endif

        unordered_flat_map<uint32_t, LockMap*> lockMap;

        ThreadCompress localThreadCompress;
        ThreadCompress externalThreadCompress;

        Vector<Vector<short_ptr<ZoneEvent>>> zoneChildren;
        Vector<Vector<short_ptr<GpuEvent>>> gpuChildren;
#ifndef TRACY_NO_STATISTICS
        Vector<Vector<GhostZone>> ghostChildren;
        Vector<GhostKey> ghostFrames;
        unordered_flat_map<GhostKey, uint32_t, GhostKeyHasher, GhostKeyComparator> ghostFramesMap;
#endif

        Vector<Vector<short_ptr<ZoneEvent>>> zoneVectorCache;

        Vector<short_ptr<FrameImage>> frameImage;
        Vector<StringRef> appInfo;

        CrashEvent crashEvent;

        unordered_flat_map<uint64_t, ContextSwitch*> ctxSwitch;

        CpuData cpuData[256];
        int cpuDataCount = 0;
        unordered_flat_map<uint64_t, uint64_t> tidToPid;
        unordered_flat_map<uint64_t, CpuThreadData> cpuThreadData;

        std::pair<uint64_t, ThreadData*> threadDataLast = std::make_pair( std::numeric_limits<uint64_t>::max(), nullptr );
        std::pair<uint64_t, ContextSwitch*> ctxSwitchLast = std::make_pair( std::numeric_limits<uint64_t>::max(), nullptr );
        uint64_t checkSrclocLast = 0;
        std::pair<uint64_t, uint16_t> shrinkSrclocLast = std::make_pair( std::numeric_limits<uint64_t>::max(), 0 );
#ifndef TRACY_NO_STATISTICS
        std::pair<uint16_t, SourceLocationZones*> srclocZonesLast = std::make_pair( 0, nullptr );
#else
        std::pair<uint16_t, uint64_t*> srclocCntLast = std::make_pair( 0, nullptr );
#endif

#ifndef TRACY_NO_STATISTICS
        Vector<ContextSwitchUsage> ctxUsage;
        bool ctxUsageReady = false;
#endif

        unordered_flat_map<uint32_t, unordered_flat_map<uint32_t, std::vector<uint32_t>>> cpuTopology;
        unordered_flat_map<uint32_t, CpuThreadTopology> cpuTopologyMap;

        unordered_flat_map<uint64_t, MemoryBlock> symbolCode;
        uint64_t symbolCodeSize = 0;

        unordered_flat_map<uint64_t, uint64_t> codeAddressToLocation;
        unordered_flat_map<uint64_t, Vector<uint64_t>> locationCodeAddressList;

        unordered_flat_map<const char*, MemoryBlock, charutil::Hasher, charutil::Comparator> sourceFileCache;

        unordered_flat_map<uint64_t, HwSampleData> hwSamples;
    };

    struct MbpsBlock
    {
        MbpsBlock() : mbps( 64 ), compRatio( 1.0 ), queue( 0 ), transferred( 0 ) {}

        std::shared_mutex lock;
        std::vector<float> mbps;
        float compRatio;
        size_t queue;
        uint64_t transferred;
    };

    struct FailureData
    {
        uint64_t thread;
        int16_t srcloc;
        uint32_t callstack;
    };

    struct FrameImagePending
    {
        const char* image;
        uint32_t csz;
    };

public:
    enum class Failure
    {
        None,
        ZoneStack,
        ZoneDoubleEnd,
        ZoneText,
        ZoneColor,
        ZoneName,
        MemFree,
        MemAllocTwice,
        FrameEnd,
        FrameImageIndex,
        FrameImageTwice,

        NUM_FAILURES
    };

    Worker( const char* addr, uint16_t port );
    Worker( const char* name, const char* program, const std::vector<ImportEventTimeline>& timeline, const std::vector<ImportEventMessages>& messages, const std::vector<ImportEventPlots>& plots, const std::unordered_map<uint64_t, std::string>& threadNames );
    Worker( FileRead& f, EventType::Type eventMask = EventType::All, bool bgTasks = true );
    ~Worker();

    const std::string& GetAddr() const { return m_addr; }
    uint16_t GetPort() const { return m_port; }
    const std::string& GetCaptureName() const { return m_captureName; }
    const std::string& GetCaptureProgram() const { return m_captureProgram; }
    uint64_t GetCaptureTime() const { return m_captureTime; }
    uint64_t GetExecutableTime() const { return m_executableTime; }
    const std::string& GetHostInfo() const { return m_hostInfo; }
    int64_t GetDelay() const { return m_delay; }
    int64_t GetResolution() const { return m_resolution; }
    uint64_t GetPid() const { return m_pid; };
    CpuArchitecture GetCpuArch() const { return m_data.cpuArch; }
    uint32_t GetCpuId() const { return m_data.cpuId; }
    const char* GetCpuManufacturer() const { return m_data.cpuManufacturer; }

    std::mutex& GetDataLock() { return m_data.lock; }
    size_t GetFrameCount( const FrameData& fd ) const { return fd.frames.size(); }
    size_t GetFullFrameCount( const FrameData& fd ) const;
    int64_t GetLastTime() const { return m_data.lastTime; }
    uint64_t GetZoneCount() const { return m_data.zonesCnt; }
    uint64_t GetZoneExtraCount() const { return m_data.zoneExtra.size() - 1; }
    uint64_t GetGpuZoneCount() const { return m_data.gpuCnt; }
    uint64_t GetLockCount() const;
    uint64_t GetPlotCount() const;
    uint64_t GetTracyPlotCount() const;
    uint64_t GetContextSwitchCount() const;
    uint64_t GetContextSwitchPerCpuCount() const;
    bool HasContextSwitches() const { return !m_data.ctxSwitch.empty(); }
    uint64_t GetSrcLocCount() const { return m_data.sourceLocationPayload.size() + m_data.sourceLocation.size(); }
    uint64_t GetCallstackPayloadCount() const { return m_data.callstackPayload.size() - 1; }
#ifndef TRACY_NO_STATISTICS
    uint64_t GetCallstackParentPayloadCount() const { return m_data.parentCallstackPayload.size(); }
    uint64_t GetCallstackParentFrameCount() const { return m_callstackParentNextIdx; }
#endif
    uint64_t GetCallstackFrameCount() const { return m_data.callstackFrameMap.size(); }
    uint64_t GetCallstackSampleCount() const { return m_data.samplesCnt; }
    uint64_t GetSymbolsCount() const { return m_data.symbolMap.size(); }
    uint64_t GetSymbolCodeCount() const { return m_data.symbolCode.size(); }
    uint64_t GetSymbolCodeSize() const { return m_data.symbolCodeSize; }
    uint64_t GetCodeLocationsSize() const { return m_data.codeAddressToLocation.size(); }
    uint64_t GetGhostZonesCount() const { return m_data.ghostCnt; }
    uint32_t GetFrameImageCount() const { return (uint32_t)m_data.frameImage.size(); }
    uint64_t GetStringsCount() const { return m_data.strings.size() + m_data.stringData.size(); }
    uint64_t GetHwSampleCountAddress() const { return m_data.hwSamples.size(); }
    uint64_t GetHwSampleCount() const;
#ifndef TRACY_NO_STATISTICS
    uint64_t GetChildSamplesCountSyms() const { return m_data.childSamples.size(); }
    uint64_t GetChildSamplesCountFull() const;
#endif
    uint64_t GetFrameOffset() const { return m_data.frameOffset; }
    const FrameData* GetFramesBase() const { return m_data.framesBase; }
    const Vector<FrameData*>& GetFrames() const { return m_data.frames.Data(); }
    const ContextSwitch* const GetContextSwitchData( uint64_t thread )
    {
        if( m_data.ctxSwitchLast.first == thread ) return m_data.ctxSwitchLast.second;
        return GetContextSwitchDataImpl( thread );
    }
    const CpuData* GetCpuData() const { return m_data.cpuData; }
    int GetCpuDataCpuCount() const { return m_data.cpuDataCount; }
    uint64_t GetPidFromTid( uint64_t tid ) const;
    const unordered_flat_map<uint64_t, CpuThreadData>& GetCpuThreadData() const { return m_data.cpuThreadData; }
    void GetCpuUsage( int64_t t0, double tstep, size_t num, std::vector<std::pair<int, int>>& out );
    const unordered_flat_map<const char*, MemoryBlock, charutil::Hasher, charutil::Comparator>& GetSourceFileCache() const { return m_data.sourceFileCache; }
    uint64_t GetSourceFileCacheCount() const { return m_data.sourceFileCache.size(); }
    uint64_t GetSourceFileCacheSize() const;
    MemoryBlock GetSourceFileFromCache( const char* file ) const;
    HwSampleData* GetHwSampleData( uint64_t addr );

    int64_t GetFrameTime( const FrameData& fd, size_t idx ) const;
    int64_t GetFrameBegin( const FrameData& fd, size_t idx ) const;
    int64_t GetFrameEnd( const FrameData& fd, size_t idx ) const;
    const FrameImage* GetFrameImage( const FrameData& fd, size_t idx ) const;
    std::pair<int, int> GetFrameRange( const FrameData& fd, int64_t from, int64_t to );

    const unordered_flat_map<uint32_t, LockMap*>& GetLockMap() const { return m_data.lockMap; }
    const Vector<short_ptr<MessageData>>& GetMessages() const { return m_data.messages; }
    const Vector<GpuCtxData*>& GetGpuData() const { return m_data.gpuData; }
    const Vector<PlotData*>& GetPlots() const { return m_data.plots.Data(); }
    const Vector<ThreadData*>& GetThreadData() const { return m_data.threads; }
    const ThreadData* GetThreadData( uint64_t tid ) const;
    const MemData& GetMemoryNamed( uint64_t name ) const;
    const MemData& GetMemoryDefault() const { return *m_data.memory; }
    const unordered_flat_map<uint64_t, MemData*>& GetMemNameMap() const { return m_data.memNameMap; }
    const Vector<short_ptr<FrameImage>>& GetFrameImages() const { return m_data.frameImage; }
    const Vector<StringRef>& GetAppInfo() const { return m_data.appInfo; }

    const VarArray<CallstackFrameId>& GetCallstack( uint32_t idx ) const { return *m_data.callstackPayload[idx]; }
    const CallstackFrameData* GetCallstackFrame( const CallstackFrameId& ptr ) const;
    CallstackFrameId PackPointer( uint64_t ptr ) const;
    uint64_t GetCanonicalPointer( const CallstackFrameId& id ) const;
    const SymbolData* GetSymbolData( uint64_t sym ) const;
    bool HasSymbolCode( uint64_t sym ) const;
    const char* GetSymbolCode( uint64_t sym, uint32_t& len ) const;
    uint64_t GetSymbolForAddress( uint64_t address ) const;
    uint64_t GetSymbolForAddress( uint64_t address, uint32_t& offset ) const;
    uint64_t GetInlineSymbolForAddress( uint64_t address ) const;
    bool HasInlineSymbolAddresses() const { return !m_data.codeSymbolMap.empty(); }
    StringIdx GetLocationForAddress( uint64_t address, uint32_t& line ) const;
    const Vector<uint64_t>* GetAddressesForLocation( uint32_t fileStringIdx, uint32_t line ) const;
    const uint64_t* GetInlineSymbolList( uint64_t sym, uint32_t len ) const;

#ifndef TRACY_NO_STATISTICS
    const VarArray<CallstackFrameId>& GetParentCallstack( uint32_t idx ) const { return *m_data.parentCallstackPayload[idx]; }
    const CallstackFrameData* GetParentCallstackFrame( const CallstackFrameId& ptr ) const;
    const Vector<SampleDataRange>* GetSamplesForSymbol( uint64_t symAddr ) const;
    const Vector<Int48>* GetChildSamples( uint64_t addr ) const;
#endif

    const CrashEvent& GetCrashEvent() const { return m_data.crashEvent; }

    // Some zones may have incomplete timing data (only start time is available, end hasn't arrived yet).
    // GetZoneEnd() will try to infer the end time by looking at child zones (parent zone can't end
    //     before its children have ended).
    // GetZoneEndDirect() will only return zone's direct timing data, without looking at children.
    int64_t GetZoneEnd( const ZoneEvent& ev );
    int64_t GetZoneEnd( const GpuEvent& ev );
    static tracy_force_inline int64_t GetZoneEndDirect( const ZoneEvent& ev ) { return ev.IsEndValid() ? ev.End() : ev.Start(); }
    static tracy_force_inline int64_t GetZoneEndDirect( const GpuEvent& ev ) { return ev.GpuEnd() >= 0 ? ev.GpuEnd() : ev.GpuStart(); }

    uint32_t FindStringIdx( const char* str ) const;
    const char* GetString( uint64_t ptr ) const;
    const char* GetString( const StringRef& ref ) const;
    const char* GetString( const StringIdx& idx ) const;
    const char* GetThreadName( uint64_t id ) const;
    bool IsThreadLocal( uint64_t id );
    const SourceLocation& GetSourceLocation( int16_t srcloc ) const;
    std::pair<const char*, const char*> GetExternalName( uint64_t id ) const;

    const char* GetZoneName( const SourceLocation& srcloc ) const;
    const char* GetZoneName( const ZoneEvent& ev ) const;
    const char* GetZoneName( const ZoneEvent& ev, const SourceLocation& srcloc ) const;
    const char* GetZoneName( const GpuEvent& ev ) const;
    const char* GetZoneName( const GpuEvent& ev, const SourceLocation& srcloc ) const;

    tracy_force_inline const Vector<short_ptr<ZoneEvent>>& GetZoneChildren( int32_t idx ) const { return m_data.zoneChildren[idx]; }
    tracy_force_inline const Vector<short_ptr<GpuEvent>>& GetGpuChildren( int32_t idx ) const { return m_data.gpuChildren[idx]; }
#ifndef TRACY_NO_STATISTICS
    tracy_force_inline const Vector<GhostZone>& GetGhostChildren( int32_t idx ) const { return m_data.ghostChildren[idx]; }
    tracy_force_inline const GhostKey& GetGhostFrame( const Int24& frame ) const { return m_data.ghostFrames[frame.Val()]; }
#endif

    tracy_force_inline const bool HasZoneExtra( const ZoneEvent& ev ) const { return ev.extra != 0; }
    tracy_force_inline const ZoneExtra& GetZoneExtra( const ZoneEvent& ev ) const { return m_data.zoneExtra[ev.extra]; }

    std::vector<int16_t> GetMatchingSourceLocation( const char* query, bool ignoreCase ) const;

#ifndef TRACY_NO_STATISTICS
    const SourceLocationZones& GetZonesForSourceLocation( int16_t srcloc ) const;
    const unordered_flat_map<int16_t, SourceLocationZones>& GetSourceLocationZones() const { return m_data.sourceLocationZones; }
    bool AreSourceLocationZonesReady() const { return m_data.sourceLocationZonesReady; }
    bool IsCpuUsageReady() const { return m_data.ctxUsageReady; }

    const unordered_flat_map<uint64_t, SymbolData>& GetSymbolMap() const { return m_data.symbolMap; }
    const unordered_flat_map<uint64_t, SymbolStats>& GetSymbolStats() const { return m_data.symbolStats; }
    const SymbolStats* GetSymbolStats( uint64_t symAddr ) const;
    const unordered_flat_map<CallstackFrameId, uint32_t, CallstackFrameIdHash, CallstackFrameIdCompare>* GetSymbolInstructionPointers( uint64_t symAddr ) const;
    bool AreCallstackSamplesReady() const { return m_data.callstackSamplesReady; }
    bool AreGhostZonesReady() const { return m_data.ghostZonesReady; }
    bool AreSymbolSamplesReady() const { return m_data.symbolSamplesReady; }
#endif

    tracy_force_inline uint16_t CompressThread( uint64_t thread ) { return m_data.localThreadCompress.CompressThread( thread ); }
    tracy_force_inline uint64_t DecompressThread( uint16_t thread ) const { return m_data.localThreadCompress.DecompressThread( thread ); }
    tracy_force_inline uint64_t DecompressThreadExternal( uint16_t thread ) const { return m_data.externalThreadCompress.DecompressThread( thread ); }

    std::shared_mutex& GetMbpsDataLock() { return m_mbpsData.lock; }
    const std::vector<float>& GetMbpsData() const { return m_mbpsData.mbps; }
    float GetCompRatio() const { return m_mbpsData.compRatio; }
    size_t GetSendQueueSize() const { return m_mbpsData.queue; }
    size_t GetSendInFlight() const { return m_serverQuerySpaceBase - m_serverQuerySpaceLeft; }
    uint64_t GetDataTransferred() const { return m_mbpsData.transferred; }

    bool HasData() const { return m_hasData.load( std::memory_order_acquire ); }
    bool IsConnected() const { return m_connected.load( std::memory_order_relaxed ); }
    bool IsDataStatic() const { return !m_thread.joinable(); }
    bool IsBackgroundDone() const { return m_backgroundDone.load( std::memory_order_relaxed ); }
    void Shutdown() { m_shutdown.store( true, std::memory_order_relaxed ); }
    void Disconnect();
    bool WasDisconnectIssued() const { return m_disconnect; }

    void Write( FileWrite& f, bool fiDict );
    int GetTraceVersion() const { return m_traceVersion; }
    uint8_t GetHandshakeStatus() const { return m_handshake.load( std::memory_order_relaxed ); }
    int64_t GetSamplingPeriod() const { return m_samplingPeriod; }

    static const LoadProgress& GetLoadProgress() { return s_loadProgress; }
    int64_t GetLoadTime() const { return m_loadTime; }

    void ClearFailure() { m_failure = Failure::None; }
    Failure GetFailureType() const { return m_failure; }
    const FailureData& GetFailureData() const { return m_failureData; }
    static const char* GetFailureString( Failure failure );

    const char* UnpackFrameImage( const FrameImage& image ) { return m_texcomp.Unpack( image ); }

    const Vector<Parameter>& GetParameters() const { return m_params; }
    void SetParameter( size_t paramIdx, int32_t val );

    const decltype(DataBlock::cpuTopology)& GetCpuTopology() const { return m_data.cpuTopology; }
    const CpuThreadTopology* GetThreadTopology( uint32_t cpuThread ) const;

    std::pair<uint64_t, uint64_t> GetTextureCompressionBytes() const { return std::make_pair( m_texcomp.GetInputBytesCount(), m_texcomp.GetOutputBytesCount() ); }

    void DoPostponedWork();

private:
    void Network();
    void Exec();
    void Query( ServerQuery type, uint64_t data, uint32_t extra = 0 );
    void QueryTerminate();
    void QuerySourceFile( const char* fn );
    void QueryDataTransfer( const void* ptr, size_t size );

    tracy_force_inline bool DispatchProcess( const QueueItem& ev, const char*& ptr );
    tracy_force_inline bool Process( const QueueItem& ev );
    tracy_force_inline void ProcessThreadContext( const QueueThreadContext& ev );
    tracy_force_inline void ProcessZoneBegin( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginCallstack( const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLoc( const QueueZoneBeginLean& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLocCallstack( const QueueZoneBeginLean& ev );
    tracy_force_inline void ProcessZoneEnd( const QueueZoneEnd& ev );
    tracy_force_inline void ProcessZoneValidation( const QueueZoneValidation& ev );
    tracy_force_inline void ProcessFrameMark( const QueueFrameMark& ev );
    tracy_force_inline void ProcessFrameMarkStart( const QueueFrameMark& ev );
    tracy_force_inline void ProcessFrameMarkEnd( const QueueFrameMark& ev );
    tracy_force_inline void ProcessFrameImage( const QueueFrameImage& ev );
    tracy_force_inline void ProcessZoneText();
    tracy_force_inline void ProcessZoneName();
    tracy_force_inline void ProcessZoneColor( const QueueZoneColor& ev );
    tracy_force_inline void ProcessZoneValue( const QueueZoneValue& ev );
    tracy_force_inline void ProcessLockAnnounce( const QueueLockAnnounce& ev );
    tracy_force_inline void ProcessLockTerminate( const QueueLockTerminate& ev );
    tracy_force_inline void ProcessLockWait( const QueueLockWait& ev );
    tracy_force_inline void ProcessLockObtain( const QueueLockObtain& ev );
    tracy_force_inline void ProcessLockRelease( const QueueLockRelease& ev );
    tracy_force_inline void ProcessLockSharedWait( const QueueLockWait& ev );
    tracy_force_inline void ProcessLockSharedObtain( const QueueLockObtain& ev );
    tracy_force_inline void ProcessLockSharedRelease( const QueueLockRelease& ev );
    tracy_force_inline void ProcessLockMark( const QueueLockMark& ev );
    tracy_force_inline void ProcessLockName( const QueueLockName& ev );
    tracy_force_inline void ProcessPlotData( const QueuePlotData& ev );
    tracy_force_inline void ProcessPlotConfig( const QueuePlotConfig& ev );
    tracy_force_inline void ProcessMessage( const QueueMessage& ev );
    tracy_force_inline void ProcessMessageLiteral( const QueueMessageLiteral& ev );
    tracy_force_inline void ProcessMessageColor( const QueueMessageColor& ev );
    tracy_force_inline void ProcessMessageLiteralColor( const QueueMessageColorLiteral& ev );
    tracy_force_inline void ProcessMessageCallstack( const QueueMessage& ev );
    tracy_force_inline void ProcessMessageLiteralCallstack( const QueueMessageLiteral& ev );
    tracy_force_inline void ProcessMessageColorCallstack( const QueueMessageColor& ev );
    tracy_force_inline void ProcessMessageLiteralColorCallstack( const QueueMessageColorLiteral& ev );
    tracy_force_inline void ProcessMessageAppInfo( const QueueMessage& ev );
    tracy_force_inline void ProcessGpuNewContext( const QueueGpuNewContext& ev );
    tracy_force_inline void ProcessGpuZoneBegin( const QueueGpuZoneBegin& ev, bool serial );
    tracy_force_inline void ProcessGpuZoneBeginCallstack( const QueueGpuZoneBegin& ev, bool serial );
    tracy_force_inline void ProcessGpuZoneBeginAllocSrcLoc( const QueueGpuZoneBeginLean& ev, bool serial );
    tracy_force_inline void ProcessGpuZoneBeginAllocSrcLocCallstack( const QueueGpuZoneBeginLean& ev, bool serial );
    tracy_force_inline void ProcessGpuZoneEnd( const QueueGpuZoneEnd& ev, bool serial );
    tracy_force_inline void ProcessGpuTime( const QueueGpuTime& ev );
    tracy_force_inline void ProcessGpuCalibration( const QueueGpuCalibration& ev );
    tracy_force_inline void ProcessGpuContextName( const QueueGpuContextName& ev );
    tracy_force_inline MemEvent* ProcessMemAlloc( const QueueMemAlloc& ev );
    tracy_force_inline MemEvent* ProcessMemAllocNamed( const QueueMemAlloc& ev );
    tracy_force_inline MemEvent* ProcessMemFree( const QueueMemFree& ev );
    tracy_force_inline MemEvent* ProcessMemFreeNamed( const QueueMemFree& ev );
    tracy_force_inline void ProcessMemAllocCallstack( const QueueMemAlloc& ev );
    tracy_force_inline void ProcessMemAllocCallstackNamed( const QueueMemAlloc& ev );
    tracy_force_inline void ProcessMemFreeCallstack( const QueueMemFree& ev );
    tracy_force_inline void ProcessMemFreeCallstackNamed( const QueueMemFree& ev );
    tracy_force_inline void ProcessCallstackSerial();
    tracy_force_inline void ProcessCallstack();
    tracy_force_inline void ProcessCallstackSample( const QueueCallstackSample& ev );
    tracy_force_inline void ProcessCallstackFrameSize( const QueueCallstackFrameSize& ev );
    tracy_force_inline void ProcessCallstackFrame( const QueueCallstackFrame& ev, bool querySymbols );
    tracy_force_inline void ProcessSymbolInformation( const QueueSymbolInformation& ev );
    tracy_force_inline void ProcessCodeInformation( const QueueCodeInformation& ev );
    tracy_force_inline void ProcessCrashReport( const QueueCrashReport& ev );
    tracy_force_inline void ProcessSysTime( const QueueSysTime& ev );
    tracy_force_inline void ProcessContextSwitch( const QueueContextSwitch& ev );
    tracy_force_inline void ProcessThreadWakeup( const QueueThreadWakeup& ev );
    tracy_force_inline void ProcessTidToPid( const QueueTidToPid& ev );
    tracy_force_inline void ProcessHwSampleCpuCycle( const QueueHwSample& ev );
    tracy_force_inline void ProcessHwSampleInstructionRetired( const QueueHwSample& ev );
    tracy_force_inline void ProcessHwSampleCacheReference( const QueueHwSample& ev );
    tracy_force_inline void ProcessHwSampleCacheMiss( const QueueHwSample& ev );
    tracy_force_inline void ProcessHwSampleBranchRetired( const QueueHwSample& ev );
    tracy_force_inline void ProcessHwSampleBranchMiss( const QueueHwSample& ev );
    tracy_force_inline void ProcessParamSetup( const QueueParamSetup& ev );
    tracy_force_inline void ProcessCpuTopology( const QueueCpuTopology& ev );
    tracy_force_inline void ProcessMemNamePayload( const QueueMemNamePayload& ev );

    tracy_force_inline ZoneEvent* AllocZoneEvent();
    tracy_force_inline void ProcessZoneBeginImpl( ZoneEvent* zone, const QueueZoneBegin& ev );
    tracy_force_inline void ProcessZoneBeginAllocSrcLocImpl( ZoneEvent* zone, const QueueZoneBeginLean& ev );
    tracy_force_inline void ProcessGpuZoneBeginImpl( GpuEvent* zone, const QueueGpuZoneBegin& ev, bool serial );
    tracy_force_inline void ProcessGpuZoneBeginAllocSrcLocImpl( GpuEvent* zone, const QueueGpuZoneBeginLean& ev, bool serial );
    tracy_force_inline void ProcessGpuZoneBeginImplCommon( GpuEvent* zone, const QueueGpuZoneBeginLean& ev, bool serial );
    tracy_force_inline MemEvent* ProcessMemAllocImpl( uint64_t memname, MemData& memdata, const QueueMemAlloc& ev );
    tracy_force_inline MemEvent* ProcessMemFreeImpl( uint64_t memname, MemData& memdata, const QueueMemFree& ev );
    tracy_force_inline void ProcessCallstackSampleImpl( const SampleData& sd, ThreadData& td, int64_t t, uint32_t callstack );

    void ZoneStackFailure( uint64_t thread, const ZoneEvent* ev );
    void ZoneDoubleEndFailure( uint64_t thread, const ZoneEvent* ev );
    void ZoneTextFailure( uint64_t thread );
    void ZoneColorFailure( uint64_t thread );
    void ZoneNameFailure( uint64_t thread );
    void MemFreeFailure( uint64_t thread );
    void MemAllocTwiceFailure( uint64_t thread );
    void FrameEndFailure();
    void FrameImageIndexFailure();
    void FrameImageTwiceFailure();

    tracy_force_inline void CheckSourceLocation( uint64_t ptr );
    void NewSourceLocation( uint64_t ptr );
    tracy_force_inline int16_t ShrinkSourceLocation( uint64_t srcloc )
    {
        if( m_data.shrinkSrclocLast.first == srcloc ) return m_data.shrinkSrclocLast.second;
        return ShrinkSourceLocationReal( srcloc );
    }
    int16_t ShrinkSourceLocationReal( uint64_t srcloc );
    int16_t NewShrinkedSourceLocation( uint64_t srcloc );

    tracy_force_inline void MemAllocChanged( uint64_t memname, MemData& memdata, int64_t time );
    void CreateMemAllocPlot( MemData& memdata );
    void ReconstructMemAllocPlot( MemData& memdata );

    void InsertMessageData( MessageData* msg );

    ThreadData* NoticeThreadReal( uint64_t thread );
    ThreadData* NewThread( uint64_t thread );
    tracy_force_inline ThreadData* NoticeThread( uint64_t thread )
    {
        if( m_data.threadDataLast.first == thread ) return m_data.threadDataLast.second;
        return NoticeThreadReal( thread );
    }
    ThreadData* RetrieveThreadReal( uint64_t thread );
    tracy_force_inline ThreadData* RetrieveThread( uint64_t thread )
    {
        if( m_data.threadDataLast.first == thread ) return m_data.threadDataLast.second;
        return RetrieveThreadReal( thread );
    }

#ifndef TRACY_NO_STATISTICS
    SourceLocationZones* GetSourceLocationZones( uint16_t srcloc )
    {
        if( m_data.srclocZonesLast.first == srcloc ) return m_data.srclocZonesLast.second;
        return GetSourceLocationZonesReal( srcloc );
    }
    SourceLocationZones* GetSourceLocationZonesReal( uint16_t srcloc );
#else
    uint64_t* GetSourceLocationZonesCnt( uint16_t srcloc )
    {
        if( m_data.srclocCntLast.first == srcloc ) return m_data.srclocCntLast.second;
        return GetSourceLocationZonesCntReal( srcloc );
    }
    uint64_t* GetSourceLocationZonesCntReal( uint16_t srcloc );
#endif

    tracy_force_inline void NewZone( ZoneEvent* zone, uint64_t thread );

    void InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread, int64_t time );

    bool CheckString( uint64_t ptr );
    void CheckThreadString( uint64_t id );
    void CheckExternalName( uint64_t id );

    void AddSourceLocation( const QueueSourceLocation& srcloc );
    void AddSourceLocationPayload( uint64_t ptr, const char* data, size_t sz );

    void AddString( uint64_t ptr, const char* str, size_t sz );
    void AddThreadString( uint64_t id, const char* str, size_t sz );
    void AddSingleString( const char* str, size_t sz );
    void AddSingleStringFailure( const char* str, size_t sz );
    void AddSecondString( const char* str, size_t sz );
    void AddExternalName( uint64_t ptr, const char* str, size_t sz );
    void AddExternalThreadName( uint64_t ptr, const char* str, size_t sz );
    void AddFrameImageData( uint64_t ptr, const char* data, size_t sz );
    void AddSymbolCode( uint64_t ptr, const char* data, size_t sz );
    void AddSourceCode( const char* data, size_t sz );

    tracy_force_inline void AddCallstackPayload( uint64_t ptr, const char* data, size_t sz );
    tracy_force_inline void AddCallstackAllocPayload( uint64_t ptr, const char* data, size_t sz );

    void InsertPlot( PlotData* plot, int64_t time, double val );
    void HandlePlotName( uint64_t name, const char* str, size_t sz );
    void HandleFrameName( uint64_t name, const char* str, size_t sz );

    void HandlePostponedSamples();
    void HandlePostponedGhostZones();

    bool IsThreadStringRetrieved( uint64_t id );
    bool IsSourceLocationRetrieved( int16_t srcloc );
    bool IsCallstackRetrieved( uint32_t callstack );
    bool HasAllFailureData();
    void HandleFailure( const char* ptr, const char* end );
    void DispatchFailure( const QueueItem& ev, const char*& ptr );

    uint32_t GetSingleStringIdx();
    uint32_t GetSecondStringIdx();
    StringLocation StoreString( const char* str, size_t sz );
    const ContextSwitch* const GetContextSwitchDataImpl( uint64_t thread );

    void CacheSource( const StringRef& str );

    tracy_force_inline Vector<short_ptr<ZoneEvent>>& GetZoneChildrenMutable( int32_t idx ) { return m_data.zoneChildren[idx]; }
#ifndef TRACY_NO_STATISTICS
    tracy_force_inline Vector<GhostZone>& GetGhostChildrenMutable( int32_t idx ) { return m_data.ghostChildren[idx]; }
#endif

#ifndef TRACY_NO_STATISTICS
    void ReconstructContextSwitchUsage();
    bool UpdateSampleStatistics( uint32_t callstack, uint32_t count, bool canPostpone );
    void UpdateSampleStatisticsPostponed( decltype(Worker::DataBlock::postponedSamples.begin())& it );
    void UpdateSampleStatisticsImpl( const CallstackFrameData** frames, uint16_t framesCount, uint32_t count, const VarArray<CallstackFrameId>& cs );
    tracy_force_inline void GetStackWithInlines( Vector<InlineStackData>& ret, const VarArray<CallstackFrameId>& cs );
    tracy_force_inline int AddGhostZone( const VarArray<CallstackFrameId>& cs, Vector<GhostZone>* vec, uint64_t t );
#endif

    tracy_force_inline int64_t ReadTimeline( FileRead& f, ZoneEvent* zone, int64_t refTime, int32_t& childIdx );
    tracy_force_inline int64_t ReadTimelineHaveSize( FileRead& f, ZoneEvent* zone, int64_t refTime, int32_t& childIdx, uint32_t sz );
    tracy_force_inline void ReadTimelinePre063( FileRead& f, ZoneEvent* zone, int64_t& refTime, int32_t& childIdx, int fileVer );
    tracy_force_inline void ReadTimeline( FileRead& f, GpuEvent* zone, int64_t& refTime, int64_t& refGpuTime, int32_t& childIdx );
    tracy_force_inline void ReadTimelineHaveSize( FileRead& f, GpuEvent* zone, int64_t& refTime, int64_t& refGpuTime, int32_t& childIdx, uint64_t sz );

#ifndef TRACY_NO_STATISTICS
    tracy_force_inline void ReconstructZoneStatistics( SrcLocCountMap& countMap, ZoneEvent& zone, uint16_t thread );
#else
    tracy_force_inline void CountZoneStatistics( ZoneEvent* zone );
#endif

    tracy_force_inline ZoneExtra& GetZoneExtraMutable( const ZoneEvent& ev ) { return m_data.zoneExtra[ev.extra]; }
    tracy_force_inline ZoneExtra& AllocZoneExtra( ZoneEvent& ev );
    tracy_force_inline ZoneExtra& RequestZoneExtra( ZoneEvent& ev );

    void UpdateMbps( int64_t td );

    int64_t ReadTimeline( FileRead& f, Vector<short_ptr<ZoneEvent>>& vec, uint32_t size, int64_t refTime, int32_t& childIdx );
    void ReadTimelinePre063( FileRead& f, Vector<short_ptr<ZoneEvent>>& vec, uint64_t size, int64_t& refTime, int32_t& childIdx, int fileVer );
    void ReadTimeline( FileRead& f, Vector<short_ptr<GpuEvent>>& vec, uint64_t size, int64_t& refTime, int64_t& refGpuTime, int32_t& childIdx );

    tracy_force_inline void WriteTimeline( FileWrite& f, const Vector<short_ptr<ZoneEvent>>& vec, int64_t& refTime );
    tracy_force_inline void WriteTimeline( FileWrite& f, const Vector<short_ptr<GpuEvent>>& vec, int64_t& refTime, int64_t& refGpuTime );
    template<typename Adapter, typename V>
    void WriteTimelineImpl( FileWrite& f, const V& vec, int64_t& refTime );
    template<typename Adapter, typename V>
    void WriteTimelineImpl( FileWrite& f, const V& vec, int64_t& refTime, int64_t& refGpuTime );

    int64_t TscTime( int64_t tsc ) { return int64_t( tsc * m_timerMul ); }
    int64_t TscTime( uint64_t tsc ) { return int64_t( tsc * m_timerMul ); }

    Socket m_sock;
    std::string m_addr;
    uint16_t m_port;

    std::thread m_thread;
    std::thread m_threadNet;
    std::atomic<bool> m_connected { false };
    std::atomic<bool> m_hasData;
    std::atomic<bool> m_shutdown { false };

    std::atomic<bool> m_backgroundDone { true };
    std::thread m_threadBackground;

    int64_t m_delay;
    int64_t m_resolution;
    double m_timerMul;
    std::string m_captureName;
    std::string m_captureProgram;
    uint64_t m_captureTime;
    uint64_t m_executableTime;
    std::string m_hostInfo;
    uint64_t m_pid;
    int64_t m_samplingPeriod;
    bool m_terminate = false;
    bool m_crashed = false;
    bool m_disconnect = false;
    void* m_stream;     // LZ4_streamDecode_t*
    char* m_buffer;
    int m_bufferOffset;
    bool m_onDemand;
    bool m_ignoreMemFreeFaults;
    bool m_codeTransfer;
    bool m_combineSamples;

    short_ptr<GpuCtxData> m_gpuCtxMap[256];
    uint32_t m_pendingCallstackId = 0;
    int16_t m_pendingSourceLocationPayload = 0;
    Vector<uint64_t> m_sourceLocationQueue;
    unordered_flat_map<uint64_t, int16_t> m_sourceLocationShrink;
    unordered_flat_map<uint64_t, ThreadData*> m_threadMap;
    FrameImagePending m_pendingFrameImageData = {};
    unordered_flat_map<uint64_t, SymbolPending> m_pendingSymbols;
    unordered_flat_set<uint64_t> m_pendingSymbolCode;
    unordered_flat_set<StringRef, StringRefHasher, StringRefComparator> m_pendingFileStrings;
    unordered_flat_set<StringRef, StringRefHasher, StringRefComparator> m_checkedFileStrings;
    StringLocation m_pendingSingleString = {};
    StringLocation m_pendingSecondString = {};

    uint32_t m_pendingStrings;
    uint32_t m_pendingThreads;
    uint32_t m_pendingExternalNames;
    uint32_t m_pendingSourceLocation;
    uint32_t m_pendingCallstackFrames;
    uint8_t m_pendingCallstackSubframes;
    uint32_t m_pendingCodeInformation;

    CallstackFrameData* m_callstackFrameStaging;
    uint64_t m_callstackFrameStagingPtr;
    uint64_t m_callstackAllocNextIdx = 0;
    uint64_t m_callstackParentNextIdx = 0;

    uint32_t m_serialNextCallstack = 0;
    uint64_t m_memNamePayload = 0;

    Slab<64*1024*1024> m_slab;

    DataBlock m_data;
    MbpsBlock m_mbpsData;

    int m_traceVersion;
    std::atomic<uint8_t> m_handshake { 0 };

    static LoadProgress s_loadProgress;
    int64_t m_loadTime;

    Failure m_failure = Failure::None;
    FailureData m_failureData = {};

    PlotData* m_sysTimePlot = nullptr;

    Vector<ServerQueryPacket> m_serverQueryQueue;
    size_t m_serverQuerySpaceLeft, m_serverQuerySpaceBase;

    unordered_flat_map<uint64_t, int32_t> m_frameImageStaging;
    char* m_frameImageBuffer = nullptr;
    size_t m_frameImageBufferSize = 0;
    TextureCompression m_texcomp;

    uint64_t m_threadCtx = 0;
    ThreadData* m_threadCtxData = nullptr;
    int64_t m_refTimeThread = 0;
    int64_t m_refTimeSerial = 0;
    int64_t m_refTimeCtx = 0;
    int64_t m_refTimeGpu = 0;

    std::atomic<uint64_t> m_bytes { 0 };
    std::atomic<uint64_t> m_decBytes { 0 };

    struct NetBuffer
    {
        int bufferOffset;
        int size;
    };

    std::vector<NetBuffer> m_netRead;
    std::mutex m_netReadLock;
    std::condition_variable m_netReadCv;

    int m_netWriteCnt = 0;
    std::mutex m_netWriteLock;
    std::condition_variable m_netWriteCv;

#ifdef TRACY_NO_STATISTICS
    Vector<ZoneEvent*> m_zoneEventPool;
#endif

    Vector<Parameter> m_params;

    char* m_tmpBuf = nullptr;
    size_t m_tmpBufSize = 0;

    unordered_flat_map<uint64_t, uint32_t> m_nextCallstack;
    std::vector<const char*> m_sourceCodeQuery;
};

}

#endif
