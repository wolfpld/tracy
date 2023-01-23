#ifdef _MSC_VER
#  pragma warning( disable: 4244 4267 )  // conversion from don't care to whatever, possible loss of data
#endif

#ifdef _WIN32
#  include <malloc.h>
#else
#  include <alloca.h>
#endif

#include <cctype>
#include <chrono>
#include <math.h>
#include <string.h>

#ifdef __MINGW32__
#  define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <sys/stat.h>

#include <capstone.h>

#define ZDICT_STATIC_LINKING_ONLY
#include "../zstd/zdict.h"

#include "../public/common/TracyProtocol.hpp"
#include "../public/common/TracySystem.hpp"
#include "../public/common/TracyYield.hpp"
#include "../public/common/TracyStackFrames.hpp"
#include "../public/common/TracyVersion.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracySort.hpp"
#include "TracyTaskDispatch.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

static tracy_force_inline uint32_t UnpackFileLine( uint64_t packed, uint32_t& line )
{
    line = packed & 0xFFFFFFFF;
    return packed >> 32;
}

static bool SourceFileValid( const char* fn, uint64_t olderThan )
{
    struct stat buf;
    if( stat( fn, &buf ) == 0 && ( buf.st_mode & S_IFREG ) != 0 )
    {
        return (uint64_t)buf.st_mtime < olderThan;
    }
    return false;
}


static const uint8_t FileHeader[8] { 't', 'r', 'a', 'c', 'y', Version::Major, Version::Minor, Version::Patch };
enum { FileHeaderMagic = 5 };
static const int CurrentVersion = FileVersion( Version::Major, Version::Minor, Version::Patch );
static const int MinSupportedVersion = FileVersion( 0, 8, 0 );


static void UpdateLockCountLockable( LockMap& lockmap, size_t pos )
{
    auto& timeline = lockmap.timeline;
    bool isContended = lockmap.isContended;
    uint8_t lockingThread;
    uint8_t lockCount;
    uint64_t waitList;

    if( pos == 0 )
    {
        lockingThread = 0;
        lockCount = 0;
        waitList = 0;
    }
    else
    {
        const auto& tl = timeline[pos-1];
        lockingThread = tl.lockingThread;
        lockCount = tl.lockCount;
        waitList = tl.waitList;
    }
    const auto end = timeline.size();

    while( pos != end )
    {
        auto& tl = timeline[pos];
        const auto tbit = uint64_t( 1 ) << tl.ptr->thread;
        switch( (LockEvent::Type)tl.ptr->type )
        {
        case LockEvent::Type::Wait:
            waitList |= tbit;
            break;
        case LockEvent::Type::Obtain:
            assert( lockCount < std::numeric_limits<uint8_t>::max() );
            assert( ( waitList & tbit ) != 0 );
            waitList &= ~tbit;
            lockingThread = tl.ptr->thread;
            lockCount++;
            break;
        case LockEvent::Type::Release:
            assert( lockCount > 0 );
            lockCount--;
            break;
        default:
            break;
        }
        tl.lockingThread = lockingThread;
        tl.waitList = waitList;
        tl.lockCount = lockCount;
        if( !isContended ) isContended = lockCount != 0 && waitList != 0;
        pos++;
    }

    lockmap.isContended = isContended;
}

static void UpdateLockCountSharedLockable( LockMap& lockmap, size_t pos )
{
    auto& timeline = lockmap.timeline;
    bool isContended = lockmap.isContended;
    uint8_t lockingThread;
    uint8_t lockCount;
    uint64_t waitShared;
    uint64_t waitList;
    uint64_t sharedList;

    if( pos == 0 )
    {
        lockingThread = 0;
        lockCount = 0;
        waitShared = 0;
        waitList = 0;
        sharedList = 0;
    }
    else
    {
        const auto& tl = timeline[pos-1];
        const auto tlp = (const LockEventShared*)(const LockEvent*)tl.ptr;
        lockingThread = tl.lockingThread;
        lockCount = tl.lockCount;
        waitShared = tlp->waitShared;
        waitList = tl.waitList;
        sharedList = tlp->sharedList;
    }
    const auto end = timeline.size();

    // ObtainShared and ReleaseShared should assert on lockCount == 0, but
    // due to the async retrieval of data from threads that's not possible.
    while( pos != end )
    {
        auto& tl = timeline[pos];
        const auto tlp = (LockEventShared*)(LockEvent*)tl.ptr;
        const auto tbit = uint64_t( 1 ) << tlp->thread;
        switch( (LockEvent::Type)tlp->type )
        {
        case LockEvent::Type::Wait:
            waitList |= tbit;
            break;
        case LockEvent::Type::WaitShared:
            waitShared |= tbit;
            break;
        case LockEvent::Type::Obtain:
            assert( lockCount < std::numeric_limits<uint8_t>::max() );
            assert( ( waitList & tbit ) != 0 );
            waitList &= ~tbit;
            lockingThread = tlp->thread;
            lockCount++;
            break;
        case LockEvent::Type::Release:
            assert( lockCount > 0 );
            lockCount--;
            break;
        case LockEvent::Type::ObtainShared:
            assert( ( waitShared & tbit ) != 0 );
            assert( ( sharedList & tbit ) == 0 );
            waitShared &= ~tbit;
            sharedList |= tbit;
            break;
        case LockEvent::Type::ReleaseShared:
            assert( ( sharedList & tbit ) != 0 );
            sharedList &= ~tbit;
            break;
        default:
            break;
        }
        tl.lockingThread = lockingThread;
        tlp->waitShared = waitShared;
        tl.waitList = waitList;
        tlp->sharedList = sharedList;
        tl.lockCount = lockCount;
        if( !isContended ) isContended = ( lockCount != 0 && ( waitList != 0 || waitShared != 0 ) ) || ( sharedList != 0 && waitList != 0 );
        pos++;
    }

    lockmap.isContended = isContended;
}

static inline void UpdateLockCount( LockMap& lockmap, size_t pos )
{
    if( lockmap.type == LockType::Lockable )
    {
        UpdateLockCountLockable( lockmap, pos );
    }
    else
    {
        UpdateLockCountSharedLockable( lockmap, pos );
    }
}

static tracy_force_inline void WriteTimeOffset( FileWrite& f, int64_t& refTime, int64_t time )
{
    int64_t timeOffset = time - refTime;
    refTime += timeOffset;
    f.Write( &timeOffset, sizeof( timeOffset ) );
}

static tracy_force_inline int64_t ReadTimeOffset( FileRead& f, int64_t& refTime )
{
    int64_t timeOffset;
    f.Read( timeOffset );
    refTime += timeOffset;
    return refTime;
}

static tracy_force_inline void UpdateLockRange( LockMap& lockmap, const LockEvent& ev, int64_t lt )
{
    auto& range = lockmap.range[ev.thread];
    if( range.start > lt ) range.start = lt;
    if( range.end < lt ) range.end = lt;
}

template<size_t U>
static uint64_t ReadHwSampleVec( FileRead& f, SortedVector<Int48, Int48Sort>& vec, Slab<U>& slab )
{
    uint64_t sz;
    f.Read( sz );
    if( sz != 0 )
    {
        int64_t refTime = 0;
        vec.reserve_exact( sz, slab );
        for( uint64_t i=0; i<sz; i++ )
        {
            vec[i] = ReadTimeOffset( f, refTime );
        }
    }
    return sz;
}

static bool IsQueryPrio( ServerQuery type )
{
    return type < ServerQuery::ServerQueryDisconnect;
}


LoadProgress Worker::s_loadProgress;

Worker::Worker( const char* addr, uint16_t port )
    : m_addr( addr )
    , m_port( port )
    , m_hasData( false )
    , m_stream( LZ4_createStreamDecode() )
    , m_buffer( new char[TargetFrameSize*3 + 1] )
    , m_bufferOffset( 0 )
    , m_inconsistentSamples( false )
    , m_pendingStrings( 0 )
    , m_pendingThreads( 0 )
    , m_pendingFibers( 0 )
    , m_pendingExternalNames( 0 )
    , m_pendingSourceLocation( 0 )
    , m_pendingCallstackFrames( 0 )
    , m_pendingCallstackSubframes( 0 )
    , m_pendingSymbolCode( 0 )
    , m_callstackFrameStaging( nullptr )
    , m_traceVersion( CurrentVersion )
    , m_loadTime( 0 )
{
    m_data.sourceLocationExpand.push_back( 0 );
    m_data.localThreadCompress.InitZero();
    m_data.callstackPayload.push_back( nullptr );
    m_data.zoneExtra.push_back( ZoneExtra {} );
    m_data.symbolLocInline.push_back( std::numeric_limits<uint64_t>::max() );
    m_data.memory = m_slab.AllocInit<MemData>();
    m_data.memNameMap.emplace( 0, m_data.memory );

    memset( (char*)m_gpuCtxMap, 0, sizeof( m_gpuCtxMap ) );

#ifndef TRACY_NO_STATISTICS
    m_data.sourceLocationZonesReady = true;
    m_data.gpuSourceLocationZonesReady = true;
    m_data.callstackSamplesReady = true;
    m_data.ghostZonesReady = true;
    m_data.ctxUsageReady = true;
    m_data.symbolSamplesReady = true;
#endif

    m_thread = std::thread( [this] { SetThreadName( "Tracy Worker" ); Exec(); } );
    m_threadNet = std::thread( [this] { SetThreadName( "Tracy Network" ); Network(); } );
}

Worker::Worker( const char* name, const char* program, const std::vector<ImportEventTimeline>& timeline, const std::vector<ImportEventMessages>& messages, const std::vector<ImportEventPlots>& plots, const std::unordered_map<uint64_t, std::string>& threadNames )
    : m_hasData( true )
    , m_delay( 0 )
    , m_resolution( 0 )
    , m_captureName( name )
    , m_captureProgram( program )
    , m_captureTime( 0 )
    , m_executableTime( 0 )
    , m_pid( 0 )
    , m_samplingPeriod( 0 )
    , m_stream( nullptr )
    , m_buffer( nullptr )
    , m_inconsistentSamples( false )
    , m_traceVersion( CurrentVersion )
{
    m_data.sourceLocationExpand.push_back( 0 );
    m_data.localThreadCompress.InitZero();
    m_data.callstackPayload.push_back( nullptr );
    m_data.zoneExtra.push_back( ZoneExtra {} );
    m_data.symbolLocInline.push_back( std::numeric_limits<uint64_t>::max() );
    m_data.memory = m_slab.AllocInit<MemData>();
    m_data.memNameMap.emplace( 0, m_data.memory );

    m_data.lastTime = 0;
    if( !timeline.empty() )
    {
        m_data.lastTime = timeline.back().timestamp;
    }
    if( !messages.empty() )
    {
        if( m_data.lastTime < (int64_t)messages.back().timestamp ) m_data.lastTime = messages.back().timestamp;
    }
    if( !plots.empty() )
    {
        for( auto& v : plots )
        {
            if( m_data.lastTime < v.data.back().first ) m_data.lastTime = v.data.back().first;
        }
    }

    for( auto& v : timeline )
    {
        if( !v.isEnd )
        {
            SourceLocation srcloc {{
                StringRef(),
                StringRef( StringRef::Idx, StoreString( v.name.c_str(), v.name.size() ).idx ),
                StringRef( StringRef::Idx, StoreString( v.locFile.c_str(), v.locFile.size() ).idx ),
                v.locLine,
                0
            }};
            int key;
            auto it = m_data.sourceLocationPayloadMap.find( &srcloc );
            if( it == m_data.sourceLocationPayloadMap.end() )
            {
                auto slptr = m_slab.Alloc<SourceLocation>();
                memcpy( slptr, &srcloc, sizeof( srcloc ) );
                uint32_t idx = m_data.sourceLocationPayload.size();
                m_data.sourceLocationPayloadMap.emplace( slptr, idx );
                m_data.sourceLocationPayload.push_back( slptr );
                key = -int16_t( idx + 1 );
#ifndef TRACY_NO_STATISTICS
                auto res = m_data.sourceLocationZones.emplace( key, SourceLocationZones() );
                m_data.srclocZonesLast.first = key;
                m_data.srclocZonesLast.second = &res.first->second;

#else
                auto res = m_data.sourceLocationZonesCnt.emplace( key, 0 );
                m_data.srclocCntLast.first = key;
                m_data.srclocCntLast.second = &res.first->second;
#endif
            }
            else
            {
                key = -int16_t( it->second + 1 );
            }

            auto zone = AllocZoneEvent();
            zone->SetStartSrcLoc( v.timestamp, key );
            zone->SetEnd( -1 );
            zone->SetChild( -1 );

            if( !v.text.empty() )
            {
                auto& extra = RequestZoneExtra( *zone );
                extra.text = StringIdx( StoreString( v.text.c_str(), v.text.size() ).idx );
            }

            if( m_threadCtx != v.tid )
            {
                m_threadCtx = v.tid;
                m_threadCtxData = NoticeThread( v.tid );
            }
            NewZone( zone );
        }
        else
        {
            auto td = NoticeThread( v.tid );
            if( td->zoneIdStack.empty() ) continue;
            td->zoneIdStack.pop_back();
            auto& stack = td->stack;
            auto zone = stack.back_and_pop();
            td->DecStackCount( zone->SrcLoc() );
            zone->SetEnd( v.timestamp );

#ifndef TRACY_NO_STATISTICS
            ZoneThreadData ztd;
            ztd.SetZone( zone );
            ztd.SetThread( CompressThread( v.tid ) );
            auto slz = GetSourceLocationZones( zone->SrcLoc() );
            slz->zones.push_back( ztd );
#else
            CountZoneStatistics( zone );
#endif
        }
    }

    std::unordered_map<std::string, uint64_t> frameNames;

    for( auto& v : messages )
    {
        // There is no specific chrome-tracing type for frame events. We use messages that contain the word "frame"
        std::string lower( v.message );
        std::transform( lower.begin(), lower.end(), lower.begin(), []( char c ) { return char( std::tolower( c ) ); } );
        if( lower.find( "frame" ) != std::string::npos )
        {
            // Reserve 0 as the default FrameSet, since it replaces the name with "Frame" and we want to keep our custom names.
            auto result = frameNames.emplace( v.message, frameNames.size() + 1 );
            auto fd = m_data.frames.Retrieve( result.first->second, [&] ( uint64_t name ) {
                auto fd = m_slab.AllocInit<FrameData>();
                fd->name = name;
                fd->continuous = 1;
                return fd;
            }, [&] ( uint64_t name ) {
                HandleFrameName( name, v.message.c_str(), v.message.length() );
            });

            int64_t time = v.timestamp;
            fd->frames.push_back( FrameEvent{ time, -1, -1 } );
            if ( m_data.lastTime < time ) m_data.lastTime = time;
        }
        else
        {
            auto msg = m_slab.Alloc<MessageData>();
            msg->time = v.timestamp;
            msg->ref = StringRef( StringRef::Type::Idx, StoreString( v.message.c_str(), v.message.size() ).idx );
            msg->thread = CompressThread( v.tid );
            msg->color = 0xFFFFFFFF;
            msg->callstack.SetVal( 0 );

            if( m_threadCtx != v.tid )
            {
                m_threadCtx = v.tid;
                m_threadCtxData = nullptr;
            }
            InsertMessageData( msg );
        }
    }

    for( auto& v : plots )
    {
        uint64_t nptr = (uint64_t)&v.name;
        auto it = m_data.strings.find( nptr );
        if( it == m_data.strings.end() )
        {
            const auto sl = StoreString( v.name.c_str(), v.name.size() );
            m_data.strings.emplace( nptr, sl.ptr );
        }

        auto plot = m_slab.AllocInit<PlotData>();
        plot->name = nptr;
        plot->type = PlotType::User;
        plot->format = v.format;
        plot->showSteps = false;
        plot->fill = true;
        plot->color = 0;

        double sum = 0;
        double min = v.data.begin()->second;
        double max = v.data.begin()->second;
        plot->data.reserve_exact( v.data.size(), m_slab );
        size_t idx = 0;
        for( auto& p : v.data )
        {
            plot->data[idx].time.SetVal( p.first );
            plot->data[idx].val = p.second;
            idx++;
            if( min > p.second ) min = p.second;
            else if( max < p.second ) max = p.second;
            sum += p.second;
        }
        plot->min = min;
        plot->max = max;
        plot->sum = sum;

        m_data.plots.Data().push_back( plot );
    }

    for( auto& t : m_threadMap )
    {
        auto name = threadNames.find(t.first);
        if( name != threadNames.end() )
        {
            char buf[128];
            int len;
            if( t.first <= std::numeric_limits<uint32_t>::max() )
            {
                len = snprintf( buf, sizeof( buf ), "(%" PRIu64 ") %s", t.first, name->second.c_str() );
            }
            else
            {
                len = snprintf( buf, sizeof( buf ), "(PID %" PRIu64 " TID %" PRIu64 ") %s", t.first >> 32, t.first & 0xFFFFFFFF, name->second.c_str() );
            }
            AddThreadString( t.first, buf, len );
        }
        else
        {
            char buf[64];
            int len;
            if( t.first <= std::numeric_limits<uint32_t>::max() )
            {
                len = sprintf( buf, "%" PRIu64, t.first );
            }
            else
            {
                len = sprintf( buf, "PID %" PRIu64 " TID %" PRIu64, t.first >> 32, t.first & 0xFFFFFFFF );
            }
            AddThreadString( t.first, buf, len );
        }
    }

    // Add a default frame if we didn't have any framesets
    if( frameNames.empty() )
    {
        m_data.framesBase = m_data.frames.Retrieve( 0, [this] ( uint64_t name ) {
            auto fd = m_slab.AllocInit<FrameData>();
            fd->name = name;
            fd->continuous = 1;
            return fd;
        }, [this] ( uint64_t name ) {
            assert( name == 0 );
            char tmp[6] = "Frame";
            HandleFrameName( name, tmp, 5 );
        } );

        m_data.framesBase->frames.push_back( FrameEvent{ 0, -1, -1 } );
        m_data.framesBase->frames.push_back( FrameEvent{ 0, -1, -1 } );
    }
}

Worker::Worker( FileRead& f, EventType::Type eventMask, bool bgTasks )
    : m_hasData( true )
    , m_stream( nullptr )
    , m_buffer( nullptr )
    , m_inconsistentSamples( false )
{
    auto loadStart = std::chrono::high_resolution_clock::now();

    int fileVer = 0;

    uint8_t hdr[8];
    f.Read( hdr, sizeof( hdr ) );
    if( memcmp( FileHeader, hdr, FileHeaderMagic ) == 0 )
    {
        fileVer = FileVersion( hdr[FileHeaderMagic], hdr[FileHeaderMagic+1], hdr[FileHeaderMagic+2] );
        if( fileVer > CurrentVersion )
        {
            throw UnsupportedVersion( fileVer );
        }
        if( fileVer < MinSupportedVersion )
        {
            throw LegacyVersion( fileVer );
        }

        f.Read( m_delay );
    }
    else
    {
        throw LegacyVersion( FileVersion( 0, 2, 0 ) );
    }
    m_traceVersion = fileVer;

    s_loadProgress.total.store( 11, std::memory_order_relaxed );
    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::Initialization, std::memory_order_relaxed );
    f.Read8( m_resolution, m_timerMul, m_data.lastTime, m_data.frameOffset, m_pid, m_samplingPeriod, m_data.cpuArch, m_data.cpuId );
    f.Read( m_data.cpuManufacturer, 12 );
    m_data.cpuManufacturer[12] = '\0';

    uint64_t sz;
    {
        f.Read( sz );
        assert( sz < 1024 );
        char tmp[1024];
        f.Read( tmp, sz );
        m_captureName = std::string( tmp, tmp+sz );
        if( m_captureName.empty() ) m_captureName = f.GetFilename();
    }
    {
        f.Read( sz );
        assert( sz < 1024 );
        char tmp[1024];
        f.Read( tmp, sz );
        m_captureProgram = std::string( tmp, tmp+sz );
        f.Read( m_captureTime );
    }

    f.Read( m_executableTime );

    {
        f.Read( sz );
        assert( sz < 1024 );
        char tmp[1024];
        f.Read( tmp, sz );
        m_hostInfo = std::string( tmp, tmp+sz );
    }

    f.Read( sz );
    m_data.cpuTopology.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint32_t packageId;
        uint64_t psz;
        f.Read2( packageId, psz );
        auto& package = *m_data.cpuTopology.emplace( packageId, unordered_flat_map<uint32_t, std::vector<uint32_t>> {} ).first;
        package.second.reserve( psz );
        for( uint64_t j=0; j<psz; j++ )
        {
            uint32_t coreId;
            uint64_t csz;
            f.Read2( coreId, csz );
            auto& core = *package.second.emplace( coreId, std::vector<uint32_t> {} ).first;
            core.second.reserve( csz );
            for( uint64_t k=0; k<csz; k++ )
            {
                uint32_t thread;
                f.Read( thread );
                core.second.emplace_back( thread );

                m_data.cpuTopologyMap.emplace( thread, CpuThreadTopology { packageId, coreId } );
            }
        }
    }

    f.Read( &m_data.crashEvent, sizeof( m_data.crashEvent ) );

    f.Read( sz );
    m_data.frames.Data().reserve_exact( sz, m_slab );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto ptr = m_slab.AllocInit<FrameData>();
        uint64_t fsz;
        f.Read3( ptr->name, ptr->continuous, fsz );
        ptr->frames.reserve_exact( fsz, m_slab );
        int64_t refTime = 0;
        if( ptr->continuous )
        {
            for( uint64_t j=0; j<fsz; j++ )
            {
                ptr->frames[j].start = ReadTimeOffset( f, refTime );
                ptr->frames[j].end = -1;
                f.Read( &ptr->frames[j].frameImage, sizeof( int32_t ) );
            }
        }
        else
        {
            for( uint64_t j=0; j<fsz; j++ )
            {
                ptr->frames[j].start = ReadTimeOffset( f, refTime );
                ptr->frames[j].end = ReadTimeOffset( f, refTime );
                f.Read( &ptr->frames[j].frameImage, sizeof( int32_t ) );
            }
        }
        for( uint64_t j=0; j<fsz; j++ )
        {
            const auto timeSpan = GetFrameTime( *ptr, j );
            if( timeSpan > 0 )
            {
                ptr->min = std::min( ptr->min, timeSpan );
                ptr->max = std::max( ptr->max, timeSpan );
                ptr->total += timeSpan;
                ptr->sumSq += double( timeSpan ) * timeSpan;
            }
        }
        m_data.frames.Data()[i] = ptr;
    }
    m_data.framesBase = m_data.frames.Data()[0];
    assert( m_data.framesBase->name == 0 );

    unordered_flat_map<uint64_t, const char*> pointerMap;

    f.Read( sz );
    m_data.stringMap.reserve( sz );
    m_data.stringData.reserve_exact( sz, m_slab );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr, ssz;
        f.Read2( ptr, ssz );
        auto dst = m_slab.Alloc<char>( ssz+1 );
        f.Read( dst, ssz );
        dst[ssz] = '\0';
        m_data.stringMap.emplace( charutil::StringKey { dst, size_t( ssz ) }, i );
        m_data.stringData[i] = ( dst );
        pointerMap.emplace( ptr, dst );
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t id, ptr;
        f.Read2( id, ptr );
        auto it = pointerMap.find( ptr );
        if( it != pointerMap.end() )
        {
            m_data.strings.emplace( id, it->second );
        }
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t id, ptr;
        f.Read2( id, ptr );
        auto it = pointerMap.find( ptr );
        if( it != pointerMap.end() )
        {
            m_data.threadNames.emplace( id, it->second );
        }
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t id, ptr, ptr2;
        f.Read3( id, ptr, ptr2 );
        auto it = pointerMap.find( ptr );
        auto it2 = pointerMap.find( ptr2 );
        if( it != pointerMap.end() && it2 != pointerMap.end() )
        {
            m_data.externalNames.emplace( id, std::make_pair( it->second, it2->second ) );
        }
    }

    m_data.localThreadCompress.Load( f, fileVer );
    m_data.externalThreadCompress.Load( f, fileVer );

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( ptr );
        SourceLocation srcloc;
        f.Read( &srcloc, sizeof( SourceLocationBase ) );
        srcloc.namehash = 0;
        m_data.sourceLocation.emplace( ptr, srcloc );
    }

    f.Read( sz );
    m_data.sourceLocationExpand.reserve_exact( sz, m_slab );
    f.Read( m_data.sourceLocationExpand.data(), sizeof( uint64_t ) * sz );
    const auto sle = sz;

    f.Read( sz );
    m_data.sourceLocationPayload.reserve_exact( sz, m_slab );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto srcloc = m_slab.Alloc<SourceLocation>();
        f.Read( srcloc, sizeof( SourceLocationBase ) );
        srcloc->namehash = 0;
        m_data.sourceLocationPayload[i] = srcloc;
        m_data.sourceLocationPayloadMap.emplace( srcloc, int16_t( i ) );
    }

#ifndef TRACY_NO_STATISTICS
    m_data.sourceLocationZones.reserve( sle + sz );

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        int16_t id;
        uint64_t cnt;
        f.Read2( id, cnt );
        auto status = m_data.sourceLocationZones.emplace( id, SourceLocationZones() );
        assert( status.second );
        status.first->second.zones.reserve( cnt );
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        int16_t id;
        uint64_t cnt;
        f.Read2( id, cnt );
        auto status = m_data.gpuSourceLocationZones.emplace( id, GpuSourceLocationZones() );
        assert( status.second );
        status.first->second.zones.reserve( cnt );
    }
#else
    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        int16_t id;
        f.Read( id );
        f.Skip( sizeof( uint64_t ) );
        m_data.sourceLocationZonesCnt.emplace( id, 0 );
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        int16_t id;
        f.Read( id );
        f.Skip( sizeof( uint64_t ) );
        m_data.gpuSourceLocationZonesCnt.emplace( id, 0 );
    }
#endif

    s_loadProgress.progress.store( LoadProgress::Locks, std::memory_order_relaxed );
    f.Read( sz );
    if( eventMask & EventType::Locks )
    {
        s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
        for( uint64_t i=0; i<sz; i++ )
        {
            s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
            auto lockmapPtr = m_slab.AllocInit<LockMap>();
            auto& lockmap = *lockmapPtr;
            uint32_t id;
            uint64_t tsz;
            f.Read8( id, lockmap.customName, lockmap.srcloc, lockmap.type, lockmap.valid, lockmap.timeAnnounce, lockmap.timeTerminate, tsz );
            lockmap.isContended = false;
            lockmap.threadMap.reserve( tsz );
            lockmap.threadList.reserve( tsz );
            for( uint64_t i=0; i<tsz; i++ )
            {
                uint64_t t;
                f.Read( t );
                lockmap.threadMap.emplace( t, i );
                lockmap.threadList.emplace_back( t );
            }
            f.Read( tsz );
            lockmap.timeline.reserve_exact( tsz, m_slab );
            auto ptr = lockmap.timeline.data();
            int64_t refTime = lockmap.timeAnnounce;
            if( lockmap.type == LockType::Lockable )
            {
                for( uint64_t i=0; i<tsz; i++ )
                {
                    auto lev = m_slab.Alloc<LockEvent>();
                    const auto lt = ReadTimeOffset( f, refTime );
                    lev->SetTime( lt );
                    int16_t srcloc;
                    f.Read( srcloc );
                    lev->SetSrcLoc( srcloc );
                    f.Read( &lev->thread, sizeof( LockEvent::thread ) + sizeof( LockEvent::type ) );
                    *ptr++ = { lev };
                    UpdateLockRange( lockmap, *lev, lt );
                }
            }
            else
            {
                for( uint64_t i=0; i<tsz; i++ )
                {
                    auto lev = m_slab.Alloc<LockEventShared>();
                    const auto lt = ReadTimeOffset( f, refTime );
                    lev->SetTime( lt );
                    int16_t srcloc;
                    f.Read( srcloc );
                    lev->SetSrcLoc( srcloc );
                    f.Read( &lev->thread, sizeof( LockEventShared::thread ) + sizeof( LockEventShared::type ) );
                    *ptr++ = { lev };
                    UpdateLockRange( lockmap, *lev, lt );
                }
            }
            UpdateLockCount( lockmap, 0 );
            m_data.lockMap.emplace( id, lockmapPtr );
        }
    }
    else
    {
        for( uint64_t i=0; i<sz; i++ )
        {
            LockType type;
            uint64_t tsz;
            f.Skip( sizeof( LockMap::customName ) + sizeof( uint32_t ) + sizeof( LockMap::srcloc ) );
            f.Read( type );
            f.Skip( sizeof( LockMap::valid ) + sizeof( LockMap::timeAnnounce ) + sizeof( LockMap::timeTerminate ) );
            f.Read( tsz );
            f.Skip( tsz * sizeof( uint64_t ) );
            f.Read( tsz );
            f.Skip( tsz * ( sizeof( int64_t ) + sizeof( int16_t ) + sizeof( LockEvent::thread ) + sizeof( LockEvent::type ) ) );
        }
    }

    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::Messages, std::memory_order_relaxed );
    unordered_flat_map<uint64_t, MessageData*> msgMap;
    f.Read( sz );
    if( eventMask & EventType::Messages )
    {
        m_data.messages.reserve_exact( sz, m_slab );
        int64_t refTime = 0;
        for( uint64_t i=0; i<sz; i++ )
        {
            uint64_t ptr;
            f.Read( ptr );
            auto msgdata = m_slab.Alloc<MessageData>();
            msgdata->time = ReadTimeOffset( f, refTime );
            f.Read3( msgdata->ref, msgdata->color, msgdata->callstack );
            m_data.messages[i] = msgdata;
            msgMap.emplace( ptr, msgdata );
        }
    }
    else
    {
        f.Skip( sz * ( sizeof( uint64_t ) + sizeof( MessageData::time ) + sizeof( MessageData::ref ) + sizeof( MessageData::color ) + sizeof( MessageData::callstack ) ) );
    }

    f.Read( sz );
    assert( sz != 0 );
    m_data.zoneExtra.reserve_exact( sz, m_slab );
    f.Read( m_data.zoneExtra.data(), sz * sizeof( ZoneExtra ) );

    s_loadProgress.progress.store( LoadProgress::Zones, std::memory_order_relaxed );
    f.Read( sz );
    s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
    s_loadProgress.subProgress.store( 0, std::memory_order_relaxed );
    f.Read( sz );
    m_data.zoneChildren.reserve_exact( sz, m_slab );
    memset( (char*)m_data.zoneChildren.data(), 0, sizeof( Vector<short_ptr<ZoneEvent>> ) * sz );
    int32_t childIdx = 0;
    f.Read( sz );
    m_data.threads.reserve_exact( sz, m_slab );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto td = m_slab.AllocInit<ThreadData>();
        uint64_t tid;
        f.Read4( tid, td->count, td->kernelSampleCnt, td->isFiber );
        td->id = tid;
        m_data.zonesCnt += td->count;
        uint32_t tsz;
        f.Read( tsz );
        if( tsz != 0 )
        {
            ReadTimeline( f, td->timeline, tsz, 0, childIdx );
        }
        uint64_t msz;
        f.Read( msz );
        if( eventMask & EventType::Messages )
        {
            const auto ctid = CompressThread( tid );
            td->messages.reserve_exact( msz, m_slab );
            for( uint64_t j=0; j<msz; j++ )
            {
                uint64_t ptr;
                f.Read( ptr );
                auto md = msgMap[ptr];
                td->messages[j] = md;
                md->thread = ctid;
            }
        }
        else
        {
            f.Skip( msz * sizeof( uint64_t ) );
        }
        uint64_t ssz;
        f.Read( ssz );
        if( ssz != 0 )
        {
            if( eventMask & EventType::Samples )
            {
                int64_t refTime = 0;
                td->ctxSwitchSamples.reserve_exact( ssz, m_slab );
                auto ptr = td->ctxSwitchSamples.data();
                for( uint64_t j=0; j<ssz; j++ )
                {
                    ptr->time.SetVal( ReadTimeOffset( f, refTime ) );
                    f.Read( &ptr->callstack, sizeof( ptr->callstack ) );
                    ptr++;
                }
            }
            else
            {
                f.Skip( ssz * ( 8 + 3 ) );
            }
        }
        f.Read( ssz );
        if( ssz != 0 )
        {
            if( eventMask & EventType::Samples )
            {
                m_data.samplesCnt += ssz;
                int64_t refTime = 0;
                td->samples.reserve_exact( ssz, m_slab );
                auto ptr = td->samples.data();
                for( uint64_t j=0; j<ssz; j++ )
                {
                    ptr->time.SetVal( ReadTimeOffset( f, refTime ) );
                    f.Read( &ptr->callstack, sizeof( ptr->callstack ) );
                    ptr++;
                }
            }
            else
            {
                f.Skip( ssz * ( 8 + 3 ) );
            }
        }
        m_data.threads[i] = td;
        m_threadMap.emplace( tid, td );
    }

    s_loadProgress.progress.store( LoadProgress::GpuZones, std::memory_order_relaxed );
    f.Read( sz );
    s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
    s_loadProgress.subProgress.store( 0, std::memory_order_relaxed );
    f.Read( sz );
    m_data.gpuChildren.reserve_exact( sz, m_slab );
    memset( (char*)m_data.gpuChildren.data(), 0, sizeof( Vector<short_ptr<GpuEvent>> ) * sz );
    childIdx = 0;
    f.Read( sz );
    m_data.gpuData.reserve_exact( sz, m_slab );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto ctx = m_slab.AllocInit<GpuCtxData>();
        uint8_t calibration;
        f.Read7( ctx->thread, calibration, ctx->count, ctx->period, ctx->type, ctx->name, ctx->overflow );
        ctx->hasCalibration = calibration;
        ctx->hasPeriod = ctx->period != 1.f;
        m_data.gpuCnt += ctx->count;
        uint64_t tdsz;
        f.Read( tdsz );
        for( uint64_t j=0; j<tdsz; j++ )
        {
            uint64_t tid, tsz;
            f.Read2( tid, tsz );
            if( tsz != 0 )
            {
                int64_t refTime = 0;
                int64_t refGpuTime = 0;
                auto td = ctx->threadData.emplace( tid, GpuCtxThreadData {} ).first;
                ReadTimeline( f, td->second.timeline, tsz, refTime, refGpuTime, childIdx );
            }
        }
        m_data.gpuData[i] = ctx;
    }

    s_loadProgress.progress.store( LoadProgress::Plots, std::memory_order_relaxed );
    f.Read( sz );
    if( eventMask & EventType::Plots )
    {
        m_data.plots.Data().reserve( sz );
        s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
        if( fileVer >= FileVersion( 0, 8, 3 ) )
        {
            for( uint64_t i=0; i<sz; i++ )
            {
                s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
                auto pd = m_slab.AllocInit<PlotData>();
                uint64_t psz;
                f.Read10( pd->type, pd->format, pd->showSteps, pd->fill, pd->color, pd->name, pd->min, pd->max, pd->sum, psz );
                pd->data.reserve_exact( psz, m_slab );
                auto ptr = pd->data.data();
                int64_t refTime = 0;
                for( uint64_t j=0; j<psz; j++ )
                {
                    int64_t t;
                    f.Read2( t, ptr->val );
                    refTime += t;
                    ptr->time = refTime;
                    ptr++;
                }
                m_data.plots.Data().push_back_no_space_check( pd );
            }
        }
        else
        {
            for( uint64_t i=0; i<sz; i++ )
            {
                s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
                auto pd = m_slab.AllocInit<PlotData>();
                uint64_t psz;
                f.Read7( pd->type, pd->format, pd->name, pd->min, pd->max, pd->sum, psz );
                pd->showSteps = false;
                pd->fill = true;
                pd->color = 0;
                pd->data.reserve_exact( psz, m_slab );
                auto ptr = pd->data.data();
                int64_t refTime = 0;
                for( uint64_t j=0; j<psz; j++ )
                {
                    int64_t t;
                    f.Read2( t, ptr->val );
                    refTime += t;
                    ptr->time = refTime;
                    ptr++;
                }
                m_data.plots.Data().push_back_no_space_check( pd );
            }
        }
    }
    else
    {
        if( fileVer >= FileVersion( 0, 8, 3 ) )
        {
            for( uint64_t i=0; i<sz; i++ )
            {
                f.Skip( sizeof( PlotData::name ) + sizeof( PlotData::min ) + sizeof( PlotData::max ) + sizeof( PlotData::sum ) + sizeof( PlotData::type ) + sizeof( PlotData::format ) + sizeof( PlotData::showSteps ) + sizeof( PlotData::fill ) + sizeof( PlotData::color ) );
                uint64_t psz;
                f.Read( psz );
                f.Skip( psz * ( sizeof( uint64_t ) + sizeof( double ) ) );
            }

        }
        else
        {
            for( uint64_t i=0; i<sz; i++ )
            {
                f.Skip( sizeof( PlotData::name ) + sizeof( PlotData::min ) + sizeof( PlotData::max ) + sizeof( PlotData::sum ) + sizeof( PlotData::type ) + sizeof( PlotData::format ) );
                uint64_t psz;
                f.Read( psz );
                f.Skip( psz * ( sizeof( uint64_t ) + sizeof( double ) ) );
            }
        }
    }

    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::Memory, std::memory_order_relaxed );

    uint64_t memcount, memtarget, memload = 0;
    f.Read2( memcount, memtarget );
    s_loadProgress.subTotal.store( memtarget, std::memory_order_relaxed );

    for( uint64_t k=0; k<memcount; k++ )
    {
        uint64_t memname;
        f.Read2( memname, sz );
        if( eventMask & EventType::Memory )
        {
            auto mit = m_data.memNameMap.emplace( memname, m_slab.AllocInit<MemData>() );
            if( memname == 0 ) m_data.memory = mit.first->second;
            auto& memdata = *mit.first->second;
            memdata.data.reserve_exact( sz, m_slab );
            uint64_t activeSz, freesSz;
            f.Read2( activeSz, freesSz );
            memdata.active.reserve( activeSz );
            memdata.frees.reserve_exact( freesSz, m_slab );
            auto mem = memdata.data.data();
            s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
            size_t fidx = 0;
            int64_t refTime = 0;
            auto& frees = memdata.frees;
            auto& active = memdata.active;

            for( uint64_t i=0; i<sz; i++ )
            {
                s_loadProgress.subProgress.store( memload+i, std::memory_order_relaxed );
                uint64_t ptr, size;
                Int24 csAlloc;
                int64_t timeAlloc, timeFree;
                uint16_t threadAlloc, threadFree;
                f.Read8( ptr, size, csAlloc, mem->csFree, timeAlloc, timeFree, threadAlloc, threadFree );
                mem->SetPtr( ptr );
                mem->SetSize( size );
                mem->SetCsAlloc( csAlloc.Val() );
                refTime += timeAlloc;
                mem->SetTimeThreadAlloc( refTime, threadAlloc );
                if( timeFree >= 0 )
                {
                    mem->SetTimeThreadFree( timeFree + refTime, threadFree );
                    frees[fidx++] = i;
                }
                else
                {
                    mem->SetTimeThreadFree( timeFree, threadFree );
                    active.emplace( ptr, i );
                }
                mem++;
            }
            memload += sz;
            f.Read4( memdata.high, memdata.low, memdata.usage, memdata.name );

            if( sz != 0 )
            {
                memdata.reconstruct = true;
            }
        }
        else
        {
            f.Skip( 2 * sizeof( uint64_t ) );
            f.Skip( sz * ( sizeof( uint64_t ) + sizeof( uint64_t ) + sizeof( Int24 ) + sizeof( Int24 ) + sizeof( int64_t ) * 2 + sizeof( uint16_t ) * 2 ) );
            f.Skip( sizeof( MemData::high ) + sizeof( MemData::low ) + sizeof( MemData::usage ) + sizeof( MemData::name ) );
        }
    }

    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::CallStacks, std::memory_order_relaxed );
    f.Read( sz );
    m_data.callstackPayload.reserve_exact( sz+1, m_slab );
    m_data.callstackPayload[0] = nullptr;
    for( uint64_t i=0; i<sz; i++ )
    {
        uint16_t csz;
        f.Read( csz );

        const auto memsize = sizeof( VarArray<CallstackFrameId> ) + csz * sizeof( CallstackFrameId );
        auto mem = (char*)m_slab.AllocRaw( memsize );

        auto data = (CallstackFrameId*)mem;
        f.Read( data, csz * sizeof( CallstackFrameId ) );

        auto arr = (VarArray<CallstackFrameId>*)( mem + csz * sizeof( CallstackFrameId ) );
        new(arr) VarArray<CallstackFrameId>( csz, data );

        m_data.callstackPayload[i+1] = arr;
    }

    f.Read( sz );
    m_data.callstackFrameMap.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        CallstackFrameId id;
        auto frameData = m_slab.Alloc<CallstackFrameData>();
        f.Read3( id, frameData->size, frameData->imageName );

        frameData->data = m_slab.Alloc<CallstackFrame>( frameData->size );
        f.Read( frameData->data, sizeof( CallstackFrame ) * frameData->size );

        m_data.callstackFrameMap.emplace( id, frameData );
    }

    f.Read( sz );
    if( sz > 0 )
    {
        m_data.appInfo.reserve_exact( sz, m_slab );
        f.Read( m_data.appInfo.data(), sizeof( m_data.appInfo[0] ) * sz );
    }

    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::FrameImages, std::memory_order_relaxed );

    if( eventMask & EventType::FrameImages )
    {
        ZSTD_CDict* cdict = nullptr;
        uint32_t dsz;
        f.Read( dsz );
        auto dict = new char[dsz];
        f.Read( dict, dsz );
        cdict = ZSTD_createCDict( dict, dsz, 3 );
        m_texcomp.SetDict( ZSTD_createDDict( dict, dsz ) );
        delete[] dict;

        f.Read( sz );
        m_data.frameImage.reserve_exact( sz, m_slab );
        s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
        if( sz != 0 )
        {
            struct JobData
            {
                enum State : int { InProgress, Available, DataReady };
                FrameImage* fi;
                char* buf = nullptr;
                size_t bufsz = 0;
                char* outbuf = nullptr;
                size_t outsz = 0;
                ZSTD_CCtx* ctx = ZSTD_createCCtx();
                alignas(64) std::atomic<State> state = Available;
            };

#ifdef __EMSCRIPTEN__
            const int jobs = 1;
#else
            // Leave one thread for file reader, second thread for dispatch (this thread)
            // Minimum 2 threads to have at least two buffers (one in use, second one filling up)
            const auto jobs = std::max<int>( std::thread::hardware_concurrency() - 2, 2 );
#endif
            auto td = std::make_unique<TaskDispatch>( jobs );
            auto data = std::make_unique<JobData[]>( jobs );

            for( uint64_t i=0; i<sz; i++ )
            {
                s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
                auto fi = m_slab.Alloc<FrameImage>();
                f.Read3( fi->w, fi->h, fi->flip );
                const auto sz = size_t( fi->w * fi->h / 2 );

                int idx = -1;
                for(;;)
                {
                    for( int j=0; j<jobs; j++ )
                    {
                        const auto state = data[j].state.load( std::memory_order_acquire );
                        if( state != JobData::InProgress )
                        {
                            if( state == JobData::DataReady )
                            {
                                char* tmp = (char*)m_slab.AllocBig( data[j].fi->csz );
                                memcpy( tmp, data[j].outbuf, data[j].fi->csz );
                                data[j].fi->ptr = tmp;
                            }
                            idx = j;
                            break;
                        }
                    }
                    if( idx >= 0 ) break;
                    YieldThread();
                }

                if( data[idx].bufsz < sz )
                {
                    data[idx].bufsz = sz;
                    delete[] data[idx].buf;
                    data[idx].buf = new char[sz];
                }
                f.Read( data[idx].buf, sz );
                data[idx].fi = fi;

                data[idx].state.store( JobData::InProgress, std::memory_order_release );
                td->Queue( [this, &data, idx, fi, cdict] {
                    if( cdict )
                    {
                        fi->csz = m_texcomp.Pack( data[idx].ctx, cdict, data[idx].outbuf, data[idx].outsz, data[idx].buf, fi->w * fi->h / 2 );
                    }
                    else
                    {
                        fi->csz = m_texcomp.Pack( data[idx].ctx, data[idx].outbuf, data[idx].outsz, data[idx].buf, fi->w * fi->h / 2 );
                    }
                    data[idx].state.store( JobData::DataReady, std::memory_order_release );
                } );

                m_data.frameImage[i] = fi;
            }
            td->Sync();
            td.reset();
            for( int i=0; i<jobs; i++ )
            {
                if( data[i].state.load( std::memory_order_acquire ) == JobData::DataReady )
                {
                    char* tmp = (char*)m_slab.AllocBig( data[i].fi->csz );
                    memcpy( tmp, data[i].outbuf, data[i].fi->csz );
                    data[i].fi->ptr = tmp;
                }
                ZSTD_freeCCtx( data[i].ctx );
                delete[] data[i].buf;
                delete[] data[i].outbuf;
            }

            const auto& frames = GetFramesBase()->frames;
            const auto fsz = uint32_t( frames.size() );
            for( uint32_t i=0; i<fsz; i++ )
            {
                const auto& f = frames[i];
                if( f.frameImage != -1 )
                {
                    m_data.frameImage[f.frameImage]->frameRef = i;
                }
            }
        }

        ZSTD_freeCDict( cdict );
    }
    else
    {
        uint32_t dsz;
        f.Read( dsz );
        f.Skip( dsz );
        f.Read( sz );
        s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
        for( uint64_t i=0; i<sz; i++ )
        {
            s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
            uint16_t w, h;
            f.Read2( w, h );
            const auto fisz = w * h / 2;
            f.Skip( fisz + sizeof( FrameImage::flip ) );
        }
        for( auto& v : m_data.framesBase->frames )
        {
            v.frameImage = -1;
        }
    }

    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::ContextSwitches, std::memory_order_relaxed );

    if( eventMask & EventType::ContextSwitches )
    {
        f.Read( sz );
        s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
        m_data.ctxSwitch.reserve( sz );
        for( uint64_t i=0; i<sz; i++ )
        {
            s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
            uint64_t thread, csz;
            f.Read2( thread, csz );
            auto data = m_slab.AllocInit<ContextSwitch>();
            data->v.reserve_exact( csz, m_slab );
            int64_t runningTime = 0;
            int64_t refTime = 0;
            auto ptr = data->v.data();
            for( uint64_t j=0; j<csz; j++ )
            {
                int64_t deltaWakeup, deltaStart, diff, thread;
                uint8_t cpu;
                int8_t reason, state;
                f.Read7( deltaWakeup, deltaStart, diff, cpu, reason, state, thread );
                refTime += deltaWakeup;
                ptr->SetWakeup( refTime );
                refTime += deltaStart;
                ptr->SetStartCpu( refTime, cpu );
                if( diff > 0 ) runningTime += diff;
                refTime += diff;
                ptr->SetEndReasonState( refTime, reason, state );
                ptr->SetThread( CompressThread( thread ) );
                ptr++;
            }
            data->runningTime = runningTime;
            m_data.ctxSwitch.emplace( thread, data );
        }
    }
    else
    {
        f.Read( sz );
        s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
        for( uint64_t i=0; i<sz; i++ )
        {
            s_loadProgress.subProgress.store( i, std::memory_order_relaxed );
            f.Skip( sizeof( uint64_t ) );
            uint64_t csz;
            f.Read( csz );
            f.Skip( csz * ( sizeof( int64_t ) * 4 + sizeof( int8_t ) * 3 ) );
        }
    }

    s_loadProgress.subTotal.store( 0, std::memory_order_relaxed );
    s_loadProgress.progress.store( LoadProgress::ContextSwitchesPerCpu, std::memory_order_relaxed );
    f.Read( sz );
    s_loadProgress.subTotal.store( sz, std::memory_order_relaxed );
    if( eventMask & EventType::ContextSwitches )
    {
        uint64_t cnt = 0;
        for( int i=0; i<256; i++ )
        {
            int64_t refTime = 0;
            f.Read( sz );
            if( sz != 0 )
            {
                m_data.cpuDataCount = i+1;
                m_data.cpuData[i].cs.reserve_exact( sz, m_slab );
                auto ptr = m_data.cpuData[i].cs.data();
                for( uint64_t j=0; j<sz; j++ )
                {
                    int64_t deltaStart, deltaEnd;
                    uint16_t thread;
                    f.Read3( deltaStart, deltaEnd, thread );
                    refTime += deltaStart;
                    ptr->SetStartThread( refTime, thread );
                    refTime += deltaEnd;
                    ptr->SetEnd( refTime );
                    ptr++;
                }
                cnt += sz;
            }
            s_loadProgress.subProgress.store( cnt, std::memory_order_relaxed );
        }
    }
    else
    {
        for( int i=0; i<256; i++ )
        {
            f.Read( sz );
            f.Skip( sz * ( sizeof( int64_t ) * 2 + sizeof( uint16_t ) ) );
        }
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t tid, pid;
        f.Read2( tid, pid );
        m_data.tidToPid.emplace( tid, pid );
    }

    f.Read( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t tid;
        CpuThreadData data;
        f.Read2( tid, data );
        m_data.cpuThreadData.emplace( tid, data );
    }

    f.Read( sz );
    m_data.symbolLoc.reserve_exact( sz, m_slab );
    f.Read( sz );
    m_data.symbolLocInline.reserve_exact( sz, m_slab );
    f.Read( sz );
    m_data.symbolMap.reserve( sz );
    int symIdx = 0;
    int symInlineIdx = 0;
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t symAddr;
        StringIdx name, file, imageName, callFile;
        uint32_t line, callLine;
        uint8_t isInline;
        Int24 size;
        f.Read9( symAddr, name, file, line, imageName, callFile, callLine, isInline, size );
        m_data.symbolMap.emplace( symAddr, SymbolData { { name, file, line }, imageName, callFile, callLine, isInline, size } );
        if( isInline )
        {
            m_data.symbolLocInline[symInlineIdx++] = symAddr;
        }
        else
        {
            m_data.symbolLoc[symIdx++] = SymbolLocation { symAddr, size.Val() };
        }
    }
#ifdef NO_PARALLEL_SORT
    pdqsort_branchless( m_data.symbolLoc.begin(), m_data.symbolLoc.end(), [] ( const auto& l, const auto& r ) { return l.addr < r.addr; } );
    pdqsort_branchless( m_data.symbolLocInline.begin(), m_data.symbolLocInline.end() );
#else
    std::sort( std::execution::par_unseq, m_data.symbolLoc.begin(), m_data.symbolLoc.end(), [] ( const auto& l, const auto& r ) { return l.addr < r.addr; } );
    std::sort( std::execution::par_unseq, m_data.symbolLocInline.begin(), m_data.symbolLocInline.end() );
#endif

    f.Read( sz );
    if( eventMask & EventType::SymbolCode )
    {
        uint64_t ssz = 0;
        m_data.symbolCode.reserve( sz );
        for( uint64_t i=0; i<sz; i++ )
        {
            uint64_t symAddr;
            uint32_t len;
            f.Read2( symAddr, len );
            ssz += len;
            auto ptr = (char*)m_slab.AllocBig( len );
            f.Read( ptr, len );
            m_data.symbolCode.emplace( symAddr, MemoryBlock { ptr, len } );
        }
        m_data.symbolCodeSize = ssz;
    }
    else
    {
        for( uint64_t i=0; i<sz; i++ )
        {
            uint64_t symAddr;
            uint32_t len;
            f.Read2( symAddr, len );
            f.Skip( len );
        }
    }

    if( fileVer <= FileVersion( 0, 8, 4 ) )
    {
        f.Read( sz );
        for( uint64_t i=0; i<sz; i++ )
        {
            uint64_t packed;
            uint16_t lsz;
            f.Read2( packed, lsz );
            uint32_t line;
            const auto fidx = UnpackFileLine( packed, line );
            uint64_t ref = 0;
            for( uint16_t j=0; j<lsz; j++ )
            {
                uint64_t diff;
                f.Read( diff );
                ref += diff;
                auto frameId = PackPointer( ref );
                if( m_data.callstackFrameMap.find( frameId ) == m_data.callstackFrameMap.end() )
                {
                    auto cs = m_slab.AllocInit<CallstackFrameData>();
                    cs->size = 1;
                    cs->data = m_slab.AllocInit<CallstackFrame>( 1 );
                    cs->data->file = StringIdx( fidx );
                    cs->data->line = line;
                    cs->data->symAddr = 0;
                    m_data.callstackFrameMap.emplace( frameId, cs );
                }
            }
        }
    }

    f.Read( sz );
    m_data.codeSymbolMap.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t v1, v2;
        f.Read2( v1, v2 );
        m_data.codeSymbolMap.emplace( v1, v2 );
    }

    f.Read( sz );
    m_data.hwSamples.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t addr;
        f.Read( addr );
        auto& data = m_data.hwSamples.emplace( addr, HwSampleData {} ).first->second;
        ReadHwSampleVec( f, data.cycles, m_slab );
        ReadHwSampleVec( f, data.retired, m_slab );
        ReadHwSampleVec( f, data.cacheRef, m_slab );
        ReadHwSampleVec( f, data.cacheMiss, m_slab );
        if( ReadHwSampleVec( f, data.branchRetired, m_slab ) != 0 ) m_data.hasBranchRetirement = true;
        ReadHwSampleVec( f, data.branchMiss, m_slab );
    }

    f.Read( sz );
    if( eventMask & EventType::SourceCache )
    {
        m_data.sourceFileCache.reserve( sz );
        for( uint64_t i=0; i<sz; i++ )
        {
            uint32_t len;
            f.Read( len );
            auto key = m_slab.Alloc<char>( len+1 );
            f.Read( key, len );
            key[len] = '\0';
            f.Read( len );
            auto data = (char*)m_slab.AllocBig( len );
            f.Read( data, len );
            m_data.sourceFileCache.emplace( key, MemoryBlock { data, len } );
        }
    }
    else
    {
        for( uint64_t i=0; i<sz; i++ )
        {
            uint32_t s32;
            f.Read( s32 );
            f.Skip( s32 );
            f.Read( s32 );
            f.Skip( s32 );
        }
    }

    s_loadProgress.total.store( 0, std::memory_order_relaxed );
    m_loadTime = std::chrono::duration_cast<std::chrono::nanoseconds>( std::chrono::high_resolution_clock::now() - loadStart ).count();

    if( !bgTasks )
    {
        m_backgroundDone.store( true, std::memory_order_relaxed );
    }
    else
    {
        m_backgroundDone.store( false, std::memory_order_relaxed );
#ifndef TRACY_NO_STATISTICS
        m_threadBackground = std::thread( [this, eventMask] {
            std::vector<std::thread> jobs;

            if( !m_data.ctxSwitch.empty() && m_data.cpuDataCount != 0 )
            {
                jobs.emplace_back( std::thread( [this] { ReconstructContextSwitchUsage(); } ) );
            }

            for( auto& mem : m_data.memNameMap )
            {
                if( mem.second->reconstruct ) jobs.emplace_back( std::thread( [this, mem = mem.second] { ReconstructMemAllocPlot( *mem ); } ) );
            }

            std::function<void(uint8_t*, Vector<short_ptr<ZoneEvent>>&, uint16_t)> ProcessTimeline;
            ProcessTimeline = [this, &ProcessTimeline] ( uint8_t* countMap, Vector<short_ptr<ZoneEvent>>& _vec, uint16_t thread )
            {
                if( m_shutdown.load( std::memory_order_relaxed ) ) return;
                assert( _vec.is_magic() );
                auto& vec = *(Vector<ZoneEvent>*)( &_vec );
                for( auto& zone : vec )
                {
                    if( zone.IsEndValid() ) ReconstructZoneStatistics( countMap, zone, thread );
                    if( zone.HasChildren() )
                    {
                        countMap[uint16_t(zone.SrcLoc())]++;
                        ProcessTimeline( countMap, GetZoneChildrenMutable( zone.Child() ), thread );
                        countMap[uint16_t(zone.SrcLoc())]--;
                    }
                }
            };

            jobs.emplace_back( std::thread( [this, ProcessTimeline] {
                for( auto& t : m_data.threads )
                {
                    if( m_shutdown.load( std::memory_order_relaxed ) ) return;
                    if( !t->timeline.empty() )
                    {
                        uint8_t countMap[64*1024];
                        // Don't touch thread compression cache in a thread.
                        ProcessTimeline( countMap, t->timeline, m_data.localThreadCompress.DecompressMustRaw( t->id ) );
                    }
                }
                std::lock_guard<std::mutex> lock( m_data.lock );
                m_data.sourceLocationZonesReady = true;
            } ) );

            std::function<void(Vector<short_ptr<GpuEvent>>&, uint16_t)> ProcessTimelineGpu;
            ProcessTimelineGpu = [this, &ProcessTimelineGpu] ( Vector<short_ptr<GpuEvent>>& _vec, uint16_t thread )
            {
                if( m_shutdown.load( std::memory_order_relaxed ) ) return;
                assert( _vec.is_magic() );
                auto& vec = *(Vector<GpuEvent>*)( &_vec );
                for( auto& zone : vec )
                {
                    if( zone.GpuEnd() >= 0 ) ReconstructZoneStatistics( zone, thread );
                    if( zone.Child() >= 0 )
                    {
                        ProcessTimelineGpu( GetGpuChildrenMutable( zone.Child() ), thread );
                    }
                }
            };

            jobs.emplace_back( std::thread( [this, ProcessTimelineGpu] {
                for( auto& t : m_data.gpuData )
                {
                    for( auto& td : t->threadData )
                    {
                        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
                        if( !td.second.timeline.empty() )
                        {
                            ProcessTimelineGpu( td.second.timeline, td.first );
                        }
                    }
                }
                std::lock_guard<std::mutex> lock( m_data.lock );
                m_data.gpuSourceLocationZonesReady = true;
            } ) );

            if( eventMask & EventType::Samples )
            {
                jobs.emplace_back( std::thread( [this] {
                    unordered_flat_map<uint32_t, uint32_t> counts;
                    uint32_t total = 0;
                    for( auto& t : m_data.threads ) total += t->samples.size();
                    if( total != 0 )
                    {
                        for( auto& t : m_data.threads )
                        {
                            if( m_shutdown.load( std::memory_order_relaxed ) ) return;
                            auto cit = t->ctxSwitchSamples.begin();
                            for( auto& sd : t->samples )
                            {
                                bool isCtxSwitch = false;
                                if( cit != t->ctxSwitchSamples.end() )
                                {
                                    const auto sdt = sd.time.Val();
                                    cit = std::lower_bound( cit, t->ctxSwitchSamples.end(), sdt, []( const auto& l, const auto& r ) { return (uint64_t)l.time.Val() < (uint64_t)r; } );
                                    isCtxSwitch = cit != t->ctxSwitchSamples.end() && cit->time.Val() == sdt;
                                }
                                if( !isCtxSwitch )
                                {
                                    const auto cs = sd.callstack.Val();
                                    auto it = counts.find( cs );
                                    if( it == counts.end() )
                                    {
                                        counts.emplace( cs, 1 );
                                    }
                                    else
                                    {
                                        it->second++;
                                    }

                                    const auto& callstack = GetCallstack( cs );
                                    auto& ip = callstack[0];
                                    auto frame = GetCallstackFrame( ip );
                                    if( frame )
                                    {
                                        const auto symAddr = frame->data[0].symAddr;
                                        auto it = m_data.instructionPointersMap.find( symAddr );
                                        if( it == m_data.instructionPointersMap.end() )
                                        {
                                            m_data.instructionPointersMap.emplace( symAddr, unordered_flat_map<CallstackFrameId, uint32_t, CallstackFrameIdHash, CallstackFrameIdCompare> { { ip, 1 } } );
                                        }
                                        else
                                        {
                                            auto fit = it->second.find( ip );
                                            if( fit == it->second.end() )
                                            {
                                                it->second.emplace( ip, 1 );
                                            }
                                            else
                                            {
                                                fit->second++;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        for( auto& v : counts ) UpdateSampleStatistics( v.first, v.second, false );
                    }
                    std::lock_guard<std::mutex> lock( m_data.lock );
                    m_data.callstackSamplesReady = true;
                } ) );

                jobs.emplace_back( std::thread( [this] {
                    uint32_t gcnt = 0;
                    for( auto& t : m_data.threads )
                    {
                        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
                        if( !t->samples.empty() )
                        {
                            if( t->samples[0].time.Val() != 0 )
                            {
                                for( auto& sd : t->samples )
                                {
                                    gcnt += AddGhostZone( GetCallstack( sd.callstack.Val() ), &t->ghostZones, sd.time.Val() );
                                }
                            }
                            else
                            {
                                for( auto& sd : t->samples )
                                {
                                    const auto st = sd.time.Val();
                                    if( st != 0 ) gcnt += AddGhostZone( GetCallstack( sd.callstack.Val() ), &t->ghostZones, st );
                                }
                            }
                        }
                    }
                    std::lock_guard<std::mutex> lock( m_data.lock );
                    m_data.ghostZonesReady = true;
                    m_data.ghostCnt = gcnt;
                } ) );

                jobs.emplace_back( std::thread( [this] {
                    for( auto& t : m_data.threads )
                    {
                        uint16_t tid = CompressThread( t->id );
                        for( auto& v : t->samples )
                        {
                            const auto& time = v.time;
                            const auto cs = v.callstack.Val();
                            const auto& callstack = GetCallstack( cs );
                            auto& ip = callstack[0];
                            auto frame = GetCallstackFrame( ip );
                            if( frame )
                            {
                                const auto symAddr = frame->data[0].symAddr;
                                auto it = m_data.symbolSamples.find( symAddr );
                                if( it == m_data.symbolSamples.end() )
                                {
                                    m_data.symbolSamples.emplace( symAddr, Vector<SampleDataRange>( SampleDataRange { time, tid, ip } ) );
                                }
                                else
                                {
                                    it->second.push_back_non_empty( SampleDataRange { time, tid, ip } );
                                }
                            }
                            auto childAddr = GetCanonicalPointer( callstack[0] );
                            for( uint16_t i=1; i<callstack.size(); i++ )
                            {
                                auto addr = GetCanonicalPointer( callstack[i] );
                                auto it = m_data.childSamples.find( addr );
                                if( it == m_data.childSamples.end() )
                                {
                                    m_data.childSamples.emplace( addr, Vector<ChildSample>( ChildSample { time, childAddr } ) );
                                }
                                else
                                {
                                    it->second.push_back_non_empty( ChildSample { time, childAddr } );
                                }
                                childAddr = addr;
                            }
                        }
                    }
                    for( auto& v : m_data.symbolSamples )
                    {
                        pdqsort_branchless( v.second.begin(), v.second.end(), []( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs.time.Val(); } );
                    }
                    for( auto& v : m_data.childSamples )
                    {
                        pdqsort_branchless( v.second.begin(), v.second.end(), []( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs.time.Val(); } );
                    }
                    std::lock_guard<std::mutex> lock( m_data.lock );
                    m_data.symbolSamplesReady = true;
                } ) );
            }

            for( auto& job : jobs ) job.join();
            m_backgroundDone.store( true, std::memory_order_relaxed );
        } );
#else
        m_backgroundDone.store( true, std::memory_order_relaxed );
#endif
    }
}

Worker::~Worker()
{
    Shutdown();

    if( m_threadNet.joinable() ) m_threadNet.join();
    if( m_thread.joinable() ) m_thread.join();
    if( m_threadBackground.joinable() ) m_threadBackground.join();

    delete[] m_buffer;
    LZ4_freeStreamDecode( (LZ4_streamDecode_t*)m_stream );

    delete[] m_frameImageBuffer;
    delete[] m_tmpBuf;

    for( auto& v : m_data.threads )
    {
        v->timeline.~Vector();
        v->stack.~Vector();
        v->messages.~Vector();
        v->zoneIdStack.~Vector();
        v->samples.~Vector();
#ifndef TRACY_NO_STATISTICS
        v->childTimeStack.~Vector();
        v->ghostZones.~Vector();
#endif
    }
    for( auto& v : m_data.gpuData )
    {
        for( auto& vt : v->threadData )
        {
            vt.second.timeline.~Vector();
            vt.second.stack.~Vector();
        }
    }
    for( auto& v : m_data.plots.Data() )
    {
        v->~PlotData();
    }
    for( auto& v : m_data.frames.Data() )
    {
        v->~FrameData();
    }
    for( auto& v : m_data.lockMap )
    {
        v.second->~LockMap();
    }
    for( auto& v : m_data.zoneChildren )
    {
        v.~Vector();
    }
    for( auto& v : m_data.memNameMap )
    {
        v.second->~MemData();
    }
    for( auto& v : m_data.ctxSwitch )
    {
        v.second->v.~Vector();
    }
    for( auto& v : m_data.gpuChildren )
    {
        v.~Vector();
    }
#ifndef TRACY_NO_STATISTICS
    for( auto& v : m_data.ghostChildren )
    {
        v.~Vector();
    }
#endif
}

uint64_t Worker::GetLockCount() const
{
    uint64_t cnt = 0;
    for( auto& l : m_data.lockMap )
    {
        cnt += l.second->timeline.size();
    }
    return cnt;
}

uint64_t Worker::GetPlotCount() const
{
    uint64_t cnt = 0;
    for( auto& p : m_data.plots.Data() )
    {
        if( p->type == PlotType::User )
        {
            cnt += p->data.size();
        }
    }
    return cnt;
}

uint64_t Worker::GetTracyPlotCount() const
{
    uint64_t cnt = 0;
    for( auto& p : m_data.plots.Data() )
    {
        if( p->type != PlotType::User )
        {
            cnt += p->data.size();
        }
    }
    return cnt;
}

uint64_t Worker::GetContextSwitchCount() const
{
    uint64_t cnt = 0;
    for( auto& v : m_data.ctxSwitch )
    {
        cnt += v.second->v.size();
    }
    return cnt;
}

uint64_t Worker::GetContextSwitchPerCpuCount() const
{
    uint64_t cnt = 0;
    for( int i=0; i<m_data.cpuDataCount; i++ )
    {
        cnt += m_data.cpuData[i].cs.size();
    }
    return cnt;
}

#ifndef TRACY_NO_STATISTICS
uint64_t Worker::GetChildSamplesCountFull() const
{
    uint64_t cnt = 0;
    for( auto& v : m_data.childSamples )
    {
        cnt += v.second.size();
    }
    return cnt;
}

uint64_t Worker::GetContextSwitchSampleCount() const
{
    uint64_t cnt = 0;
    for( auto& v : m_data.threads )
    {
        cnt += v->ctxSwitchSamples.size();
    }
    return cnt;
}
#endif

uint64_t Worker::GetPidFromTid( uint64_t tid ) const
{
    auto it = m_data.tidToPid.find( tid );
    if( it == m_data.tidToPid.end() ) return 0;
    return it->second;
}

void Worker::GetCpuUsage( int64_t t0, double tstep, size_t num, std::vector<std::pair<int, int>>& out )
{
    if( out.size() < num ) out.resize( num );

    if( t0 > m_data.lastTime || int64_t( t0 + tstep * num ) < 0 )
    {
        memset( out.data(), 0, sizeof( int ) * 2 * num );
        return;
    }

#ifndef TRACY_NO_STATISTICS
    if( !m_data.ctxUsage.empty() )
    {
        auto ptr = out.data();
        auto itBegin = m_data.ctxUsage.begin();
        for( size_t i=0; i<num; i++ )
        {
            const auto time = int64_t( t0 + tstep * i );
            if( time < 0 || time > m_data.lastTime )
            {
                ptr->first = 0;
                ptr->second = 0;
            }
            else
            {
                const auto test = ( time << 16 ) | 0xFFFF;
                auto it = std::upper_bound( itBegin, m_data.ctxUsage.end(), test, [] ( const auto& l, const auto& r ) { return l < r._time_other_own; } );
                if( it == m_data.ctxUsage.begin() || it == m_data.ctxUsage.end() )
                {
                    ptr->first = 0;
                    ptr->second = 0;
                }
                else
                {
                    --it;
                    ptr->first = it->Own();
                    ptr->second = it->Other();
                }
                itBegin = it;
            }
            ptr++;
        }
    }
    else
#endif
    {
        memset( out.data(), 0, sizeof( int ) * 2 * num );
        for( int i=0; i<m_data.cpuDataCount; i++ )
        {
            auto& cs = m_data.cpuData[i].cs;
            if( !cs.empty() )
            {
                auto itBegin = cs.begin();
                auto ptr = out.data();
                for( size_t i=0; i<num; i++ )
                {
                    const auto time = int64_t( t0 + tstep * i );
                    if( time > m_data.lastTime ) break;
                    if( time >= 0 )
                    {
                        auto it = std::lower_bound( itBegin, cs.end(), time, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                        if( it == cs.end() ) break;
                        if( it->IsEndValid() && it->Start() <= time  )
                        {
                            if( GetPidFromTid( DecompressThreadExternal( it->Thread() ) ) == m_pid )
                            {
                                ptr->first++;
                            }
                            else
                            {
                                ptr->second++;
                            }
                        }
                        itBegin = it;
                    }
                    ptr++;
                }
            }
        }
    }
}

const ContextSwitch* const Worker::GetContextSwitchDataImpl( uint64_t thread )
{
    auto it = m_data.ctxSwitch.find( thread );
    if( it != m_data.ctxSwitch.end() )
    {
        m_data.ctxSwitchLast.first = thread;
        m_data.ctxSwitchLast.second = it->second;
        return it->second;
    }
    else
    {
        return nullptr;
    }
}

size_t Worker::GetFullFrameCount( const FrameData& fd ) const
{
    const auto sz = fd.frames.size();
    assert( sz != 0 );

    if( fd.continuous )
    {
        if( IsConnected() )
        {
            return sz - 1;
        }
        else
        {
            return sz;
        }
    }
    else
    {
        const auto& last = fd.frames.back();
        if( last.end >= 0 )
        {
            return sz;
        }
        else
        {
            return sz - 1;
        }
    }
}

bool Worker::AreFramesUsed() const
{
    if( m_data.frames.Data().size() > 1 ) return true;
    return m_data.framesBase->frames.size() > 2;
}

int64_t Worker::GetFrameTime( const FrameData& fd, size_t idx ) const
{
    if( fd.continuous )
    {
        if( idx < fd.frames.size() - 1 )
        {
            return fd.frames[idx+1].start - fd.frames[idx].start;
        }
        else
        {
            assert( m_data.lastTime != 0 );
            return m_data.lastTime - fd.frames.back().start;
        }
    }
    else
    {
        const auto& frame = fd.frames[idx];
        if( frame.end >= 0 )
        {
            return frame.end - frame.start;
        }
        else
        {
            return m_data.lastTime - fd.frames.back().start;
        }
    }
}

int64_t Worker::GetFrameBegin( const FrameData& fd, size_t idx ) const
{
    assert( idx < fd.frames.size() );
    return fd.frames[idx].start;
}

int64_t Worker::GetFrameEnd( const FrameData& fd, size_t idx ) const
{
    if( fd.continuous )
    {
        if( idx < fd.frames.size() - 1 )
        {
            return fd.frames[idx+1].start;
        }
        else
        {
            return m_data.lastTime;
        }
    }
    else
    {
        if( fd.frames[idx].end >= 0 )
        {
            return fd.frames[idx].end;
        }
        else
        {
            return m_data.lastTime;
        }
    }
}

const FrameImage* Worker::GetFrameImage( const FrameData& fd, size_t idx ) const
{
    assert( idx < fd.frames.size() );
    const auto& v = fd.frames[idx].frameImage;
    if( v < 0 ) return nullptr;
    return m_data.frameImage[v];
}

std::pair<int, int> Worker::GetFrameRange( const FrameData& fd, int64_t from, int64_t to )
{
    auto zitbegin = std::lower_bound( fd.frames.begin(), fd.frames.end(), from, [] ( const auto& lhs, const auto& rhs ) { return lhs.start < rhs; } );
    if( zitbegin == fd.frames.end() ) zitbegin--;

    const auto zitend = std::lower_bound( zitbegin, fd.frames.end(), to, [] ( const auto& lhs, const auto& rhs ) { return lhs.start < rhs; } );

    int zbegin = std::distance( fd.frames.begin(), zitbegin );
    if( zbegin > 0 && zitbegin->start != from ) --zbegin;
    const int zend = std::distance( fd.frames.begin(), zitend );

    return std::make_pair( zbegin, zend );
}

const CallstackFrameData* Worker::GetCallstackFrame( const CallstackFrameId& ptr ) const
{
    assert( ptr.custom == 0 );
    auto it = m_data.callstackFrameMap.find( ptr );
    if( it == m_data.callstackFrameMap.end() )
    {
        return nullptr;
    }
    else
    {
        return it->second;
    }
}

#ifndef TRACY_NO_STATISTICS
const CallstackFrameData* Worker::GetParentCallstackFrame( const CallstackFrameId& ptr ) const
{
    assert( ptr.custom == 1 );
    auto it = m_data.parentCallstackFrameMap.find( ptr );
    if( it == m_data.parentCallstackFrameMap.end() )
    {
        return nullptr;
    }
    else
    {
        return it->second;
    }
}

const Vector<SampleDataRange>* Worker::GetSamplesForSymbol( uint64_t symAddr ) const
{
    assert( m_data.symbolSamplesReady );
    auto it = m_data.symbolSamples.find( symAddr );
    if( it == m_data.symbolSamples.end() ) return nullptr;
    return &it->second;
}

const Vector<ChildSample>* Worker::GetChildSamples( uint64_t addr ) const
{
    assert( m_data.symbolSamplesReady );
    auto it = m_data.childSamples.find( addr );
    if( it == m_data.childSamples.end() ) return nullptr;
    return &it->second;
}
#endif

const SymbolData* Worker::GetSymbolData( uint64_t sym ) const
{
    auto it = m_data.symbolMap.find( sym );
    if( it == m_data.symbolMap.end() )
    {
        return nullptr;
    }
    else
    {
        return &it->second;
    }
}

bool Worker::HasSymbolCode( uint64_t sym ) const
{
    return m_data.symbolCode.find( sym ) != m_data.symbolCode.end();
}

const char* Worker::GetSymbolCode( uint64_t sym, uint32_t& len ) const
{
    auto it = m_data.symbolCode.find( sym );
    if( it == m_data.symbolCode.end() ) return nullptr;
    len = it->second.len;
    return it->second.data;
}

uint64_t Worker::GetSymbolForAddress( uint64_t address )
{
    DoPostponedSymbols();
    auto it = std::lower_bound( m_data.symbolLoc.begin(), m_data.symbolLoc.end(), address, [] ( const auto& l, const auto& r ) { return l.addr + l.len < r; } );
    if( it == m_data.symbolLoc.end() || address < it->addr ) return 0;
    return it->addr;
}

uint64_t Worker::GetSymbolForAddress( uint64_t address, uint32_t& offset )
{
    DoPostponedSymbols();
    auto it = std::lower_bound( m_data.symbolLoc.begin(), m_data.symbolLoc.end(), address, [] ( const auto& l, const auto& r ) { return l.addr + l.len < r; } );
    if( it == m_data.symbolLoc.end() || address < it->addr ) return 0;
    offset = address - it->addr;
    return it->addr;
}

uint64_t Worker::GetInlineSymbolForAddress( uint64_t address ) const
{
    auto it = m_data.codeSymbolMap.find( address );
    if( it == m_data.codeSymbolMap.end() ) return 0;
    return it->second;
}

StringIdx Worker::GetLocationForAddress( uint64_t address, uint32_t& line ) const
{
    auto frame = GetCallstackFrame( PackPointer( address ) );
    if( !frame )
    {
        line = 0;
        return StringIdx();
    }
    else
    {
        auto subFrame = frame->data[0];
        line = subFrame.line;
        return subFrame.file;
    }
}

const uint64_t* Worker::GetInlineSymbolList( uint64_t sym, uint32_t len )
{
    DoPostponedInlineSymbols();
    auto it = std::lower_bound( m_data.symbolLocInline.begin(), m_data.symbolLocInline.end(), sym );
    if( it == m_data.symbolLocInline.end() ) return nullptr;
    if( *it >= sym + len ) return nullptr;
    return it;
}

int64_t Worker::GetZoneEnd( const ZoneEvent& ev )
{
    auto ptr = &ev;
    for(;;)
    {
        if( ptr->IsEndValid() ) return ptr->End();
        if( !ptr->HasChildren() ) return ptr->Start();
        auto& children = GetZoneChildren( ptr->Child() );
        if( children.is_magic() )
        {
            auto& c = *(Vector<ZoneEvent>*)&children;
            ptr = &c.back();
        }
        else
        {
            ptr = children.back();
        }
    }
}

int64_t Worker::GetZoneEnd( const GpuEvent& ev )
{
    auto ptr = &ev;
    for(;;)
    {
        if( ptr->GpuEnd() >= 0 ) return ptr->GpuEnd();
        if( ptr->Child() < 0 ) return ptr->GpuStart() >= 0 ? ptr->GpuStart() : m_data.lastTime;
        auto& children = GetGpuChildren( ptr->Child() );
        if( children.is_magic() )
        {
            auto& c = *(Vector<GpuEvent>*)&children;
            ptr = &c.back();
        }
        else
        {
            ptr = children.back();
        }
    }
}

uint32_t Worker::FindStringIdx( const char* str ) const
{
    if( !str ) return 0;
    charutil::StringKey key = { str, strlen( str ) };
    auto sit = m_data.stringMap.find( key );
    if( sit == m_data.stringMap.end() )
    {
        return 0;
    }
    else
    {
        return sit->second;
    }
}

const char* Worker::GetString( uint64_t ptr ) const
{
    const auto it = m_data.strings.find( ptr );
    if( it == m_data.strings.end() || it->second == nullptr )
    {
        return "???";
    }
    else
    {
        return it->second;
    }
}

const char* Worker::GetString( const StringRef& ref ) const
{
    if( ref.isidx )
    {
        assert( ref.active );
        return m_data.stringData[ref.str];
    }
    else
    {
        if( ref.active )
        {
            return GetString( ref.str );
        }
        else
        {
            return "???";
        }
    }
}

const char* Worker::GetString( const StringIdx& idx ) const
{
    assert( idx.Active() );
    return m_data.stringData[idx.Idx()];
}

static const char* BadExternalThreadNames[] = {
    "ntdll.dll",
    "???",
    nullptr
};

const char* Worker::GetThreadName( uint64_t id ) const
{
    const auto it = m_data.threadNames.find( id );
    if( it == m_data.threadNames.end() )
    {
        const auto eit = m_data.externalNames.find( id );
        if( eit == m_data.externalNames.end() )
        {
            return "???";
        }
        else
        {
            return eit->second.second;
        }
    }
    else
    {
        // Client should send additional information about thread name, to make this check unnecessary
        const auto txt = it->second;
        if( txt[0] >= '0' && txt[0] <= '9' && (uint64_t)atoi( txt ) == id )
        {
            const auto eit = m_data.externalNames.find( id );
            if( eit != m_data.externalNames.end() )
            {
                const char* ext = eit->second.second;
                const char** ptr = BadExternalThreadNames;
                while( *ptr )
                {
                    if( strcmp( *ptr, ext ) == 0 ) return txt;
                    ptr++;
                }
                return ext;
            }
        }
        return txt;
    }
}

bool Worker::IsThreadLocal( uint64_t id )
{
    auto td = RetrieveThread( id );
    return td && ( td->count > 0 || !td->samples.empty() );
}

bool Worker::IsThreadFiber( uint64_t id )
{
    auto td = RetrieveThread( id );
    return td && ( td->isFiber );
}

const SourceLocation& Worker::GetSourceLocation( int16_t srcloc ) const
{
    if( srcloc < 0 )
    {
        return *m_data.sourceLocationPayload[-srcloc-1];
    }
    else
    {
        const auto it = m_data.sourceLocation.find( m_data.sourceLocationExpand[srcloc] );
        assert( it != m_data.sourceLocation.end() );
        return it->second;
    }
}

std::pair<const char*, const char*> Worker::GetExternalName( uint64_t id ) const
{
    const auto it = m_data.externalNames.find( id );
    if( it == m_data.externalNames.end() )
    {
        return std::make_pair( "???", "???" );
    }
    else
    {
        return it->second;
    }
}

const char* Worker::GetZoneName( const SourceLocation& srcloc ) const
{
    if( srcloc.name.active )
    {
        return GetString( srcloc.name );
    }
    else
    {
        return GetString( srcloc.function );
    }
}

const char* Worker::GetZoneName( const ZoneEvent& ev ) const
{
    auto& srcloc = GetSourceLocation( ev.SrcLoc() );
    return GetZoneName( ev, srcloc );
}

const char* Worker::GetZoneName( const ZoneEvent& ev, const SourceLocation& srcloc ) const
{
    if( HasZoneExtra( ev ) && GetZoneExtra( ev ).name.Active() )
    {
        return GetString( GetZoneExtra( ev ).name );
    }
    else if( srcloc.name.active )
    {
        return GetString( srcloc.name );
    }
    else
    {
        return GetString( srcloc.function );
    }
}

const char* Worker::GetZoneName( const GpuEvent& ev ) const
{
    auto& srcloc = GetSourceLocation( ev.SrcLoc() );
    return GetZoneName( ev, srcloc );
}

const char* Worker::GetZoneName( const GpuEvent& ev, const SourceLocation& srcloc ) const
{
    if( srcloc.name.active )
    {
        return GetString( srcloc.name );
    }
    else
    {
        return GetString( srcloc.function );
    }
}

static bool strstr_nocase( const char* l, const char* r )
{
    const auto lsz = strlen( l );
    const auto rsz = strlen( r );
    auto ll = (char*)alloca( lsz + 1 );
    auto rl = (char*)alloca( rsz + 1 );
    for( size_t i=0; i<lsz; i++ )
    {
        ll[i] = tolower( l[i] );
    }
    ll[lsz] = '\0';
    for( size_t i=0; i<rsz; i++ )
    {
        rl[i] = tolower( r[i] );
    }
    rl[rsz] = '\0';
    return strstr( ll, rl ) != nullptr;
}

std::vector<int16_t> Worker::GetMatchingSourceLocation( const char* query, bool ignoreCase ) const
{
    std::vector<int16_t> match;

    const auto sz = m_data.sourceLocationExpand.size();
    for( size_t i=1; i<sz; i++ )
    {
        const auto it = m_data.sourceLocation.find( m_data.sourceLocationExpand[i] );
        assert( it != m_data.sourceLocation.end() );
        const auto& srcloc = it->second;
        const auto str = GetString( srcloc.name.active ? srcloc.name : srcloc.function );
        bool found = false;
        if( ignoreCase )
        {
            found = strstr_nocase( str, query );
        }
        else
        {
            found = strstr( str, query ) != nullptr;
        }
        if( found )
        {
            match.push_back( (int16_t)i );
        }
    }

    for( auto& srcloc : m_data.sourceLocationPayload )
    {
        const auto str = GetString( srcloc->name.active ? srcloc->name : srcloc->function );
        bool found = false;
        if( ignoreCase )
        {
            found = strstr_nocase( str, query );
        }
        else
        {
            found = strstr( str, query ) != nullptr;
        }
        if( found )
        {
            auto it = m_data.sourceLocationPayloadMap.find( (const SourceLocation*)srcloc );
            assert( it != m_data.sourceLocationPayloadMap.end() );
            match.push_back( -int16_t( it->second + 1 ) );
        }
    }

    return match;
}

#ifndef TRACY_NO_STATISTICS
Worker::SourceLocationZones& Worker::GetZonesForSourceLocation( int16_t srcloc )
{
    assert( AreSourceLocationZonesReady() );
    static SourceLocationZones empty;
    auto it = m_data.sourceLocationZones.find( srcloc );
    return it != m_data.sourceLocationZones.end() ? it->second : empty;
}

const Worker::SourceLocationZones& Worker::GetZonesForSourceLocation( int16_t srcloc ) const
{
    assert( AreSourceLocationZonesReady() );
    static const SourceLocationZones empty;
    auto it = m_data.sourceLocationZones.find( srcloc );
    return it != m_data.sourceLocationZones.end() ? it->second : empty;
}

const SymbolStats* Worker::GetSymbolStats( uint64_t symAddr ) const
{
    assert( AreCallstackSamplesReady() );
    auto it = m_data.symbolStats.find( symAddr );
    if( it == m_data.symbolStats.end() )
    {
        return nullptr;
    }
    else
    {
        return &it->second;
    }
}

const unordered_flat_map<CallstackFrameId, uint32_t, Worker::CallstackFrameIdHash, Worker::CallstackFrameIdCompare>* Worker::GetSymbolInstructionPointers( uint64_t symAddr ) const
{
    assert( AreCallstackSamplesReady() );
    auto it = m_data.instructionPointersMap.find( symAddr );
    if( it == m_data.instructionPointersMap.end() )
    {
        return nullptr;
    }
    else
    {
        return &it->second;
    }
}
#endif

void Worker::Network()
{
    auto ShouldExit = [this] { return m_shutdown.load( std::memory_order_relaxed ); };
    auto lz4buf = std::unique_ptr<char[]>( new char[LZ4Size] );

    for(;;)
    {
        {
            std::unique_lock<std::mutex> lock( m_netWriteLock );
            m_netWriteCv.wait( lock, [this] { return m_netWriteCnt > 0 || m_shutdown.load( std::memory_order_relaxed ); } );
            if( m_shutdown.load( std::memory_order_relaxed ) ) goto close;
            m_netWriteCnt--;
        }

        auto buf = m_buffer + m_bufferOffset;
        lz4sz_t lz4sz;
        if( !m_sock.Read( &lz4sz, sizeof( lz4sz ), 10, ShouldExit ) ) goto close;
        if( !m_sock.Read( lz4buf.get(), lz4sz, 10, ShouldExit ) ) goto close;
        auto bb = m_bytes.load( std::memory_order_relaxed );
        m_bytes.store( bb + sizeof( lz4sz ) + lz4sz, std::memory_order_relaxed );

        auto sz = LZ4_decompress_safe_continue( (LZ4_streamDecode_t*)m_stream, lz4buf.get(), buf, lz4sz, TargetFrameSize );
        assert( sz >= 0 );
        bb = m_decBytes.load( std::memory_order_relaxed );
        m_decBytes.store( bb + sz, std::memory_order_relaxed );

        {
            std::lock_guard<std::mutex> lock( m_netReadLock );
            m_netRead.push_back( NetBuffer { m_bufferOffset, sz } );
            m_netReadCv.notify_one();
        }

        m_bufferOffset += sz;
        if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
    }

close:
    std::lock_guard<std::mutex> lock( m_netReadLock );
    m_netRead.push_back( NetBuffer { -1 } );
    m_netReadCv.notify_one();
}

void Worker::Exec()
{
    auto ShouldExit = [this] { return m_shutdown.load( std::memory_order_relaxed ); };

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) { m_netWriteCv.notify_one(); return; };
        if( m_sock.Connect( m_addr.c_str(), m_port ) ) break;
        std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
    }

    std::chrono::time_point<std::chrono::high_resolution_clock> t0;

    m_sock.Send( HandshakeShibboleth, HandshakeShibbolethSize );
    uint32_t protocolVersion = ProtocolVersion;
    m_sock.Send( &protocolVersion, sizeof( protocolVersion ) );
    HandshakeStatus handshake;
    if( !m_sock.Read( &handshake, sizeof( handshake ), 10, ShouldExit ) )
    {
        m_handshake.store( HandshakeDropped, std::memory_order_relaxed );
        goto close;
    }
    m_handshake.store( handshake, std::memory_order_relaxed );
    switch( handshake )
    {
    case HandshakeWelcome:
        break;
    case HandshakeProtocolMismatch:
    case HandshakeNotAvailable:
    default:
        goto close;
    }

    m_data.framesBase = m_data.frames.Retrieve( 0, [this] ( uint64_t name ) {
        auto fd = m_slab.AllocInit<FrameData>();
        fd->name = name;
        fd->continuous = 1;
        return fd;
    }, [this] ( uint64_t name ) {
        assert( name == 0 );
        char tmp[6] = "Frame";
        HandleFrameName( name, tmp, 5 );
    } );

    {
        WelcomeMessage welcome;
        if( !m_sock.Read( &welcome, sizeof( welcome ), 10, ShouldExit ) )
        {
            m_handshake.store( HandshakeDropped, std::memory_order_relaxed );
            goto close;
        }
        m_timerMul = welcome.timerMul;
        m_data.baseTime = welcome.initBegin;
        const auto initEnd = TscTime( welcome.initEnd );
        m_data.framesBase->frames.push_back( FrameEvent{ 0, -1, -1 } );
        m_data.framesBase->frames.push_back( FrameEvent{ initEnd, -1, -1 } );
        m_data.lastTime = initEnd;
        m_delay = TscPeriod( welcome.delay );
        m_resolution = TscPeriod( welcome.resolution );
        m_pid = welcome.pid;
        m_samplingPeriod = welcome.samplingPeriod;
        m_onDemand = welcome.flags & WelcomeFlag::OnDemand;
        m_captureProgram = welcome.programName;
        m_captureTime = welcome.epoch;
        m_executableTime = welcome.exectime;
        m_ignoreMemFreeFaults = ( welcome.flags & WelcomeFlag::OnDemand ) || ( welcome.flags & WelcomeFlag::IsApple );
        m_data.cpuArch = (CpuArchitecture)welcome.cpuArch;
        m_codeTransfer = welcome.flags & WelcomeFlag::CodeTransfer;
        m_combineSamples = welcome.flags & WelcomeFlag::CombineSamples;
        m_identifySamples = welcome.flags & WelcomeFlag::IdentifySamples;
        m_data.cpuId = welcome.cpuId;
        memcpy( m_data.cpuManufacturer, welcome.cpuManufacturer, 12 );
        m_data.cpuManufacturer[12] = '\0';

        char dtmp[64];
        time_t date = welcome.epoch;
        auto lt = localtime( &date );
        strftime( dtmp, 64, "%F %T", lt );
        char tmp[1024];
        sprintf( tmp, "%s @ %s", welcome.programName, dtmp );
        m_captureName = tmp;

        m_hostInfo = welcome.hostInfo;

        if( m_onDemand )
        {
            OnDemandPayloadMessage onDemand;
            if( !m_sock.Read( &onDemand, sizeof( onDemand ), 10, ShouldExit ) )
            {
                m_handshake.store( HandshakeDropped, std::memory_order_relaxed );
                goto close;
            }
            m_data.frameOffset = onDemand.frames;
            m_data.framesBase->frames.push_back( FrameEvent{ TscTime( onDemand.currentTime ), -1, -1 } );
        }
    }

    m_serverQuerySpaceBase = m_serverQuerySpaceLeft = std::min( ( m_sock.GetSendBufSize() / ServerQueryPacketSize ), 8*1024 ) - 4;   // leave space for terminate request
    m_hasData.store( true, std::memory_order_release );

    LZ4_setStreamDecode( (LZ4_streamDecode_t*)m_stream, nullptr, 0 );
    m_connected.store( true, std::memory_order_relaxed );
    {
        std::lock_guard<std::mutex> lock( m_netWriteLock );
        m_netWriteCnt = 2;
        m_netWriteCv.notify_one();
    }

    t0 = std::chrono::high_resolution_clock::now();

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) )
        {
            QueryTerminate();
            goto close;
        }

        NetBuffer netbuf;
        {
            std::unique_lock<std::mutex> lock( m_netReadLock );
            m_netReadCv.wait( lock, [this] { return !m_netRead.empty(); } );
            netbuf = m_netRead.front();
            m_netRead.erase( m_netRead.begin() );
        }
        if( netbuf.bufferOffset < 0 ) goto close;

        const char* ptr = m_buffer + netbuf.bufferOffset;
        const char* end = ptr + netbuf.size;

        {
            std::lock_guard<std::mutex> lock( m_data.lock );
            while( ptr < end )
            {
                auto ev = (const QueueItem*)ptr;
                if( !DispatchProcess( *ev, ptr ) )
                {
                    if( m_failure != Failure::None ) HandleFailure( ptr, end );
                    QueryTerminate();
                    goto close;
                }
            }

            {
                std::lock_guard<std::mutex> lock( m_netWriteLock );
                m_netWriteCnt++;
                m_netWriteCv.notify_one();
            }

            if( m_serverQuerySpaceLeft > 0 && !m_serverQueryQueuePrio.empty() )
            {
                const auto toSend = std::min( m_serverQuerySpaceLeft, m_serverQueryQueuePrio.size() );
                m_sock.Send( m_serverQueryQueuePrio.data(), toSend * ServerQueryPacketSize );
                m_serverQuerySpaceLeft -= toSend;
                if( toSend == m_serverQueryQueuePrio.size() )
                {
                    m_serverQueryQueuePrio.clear();
                }
                else
                {
                    m_serverQueryQueuePrio.erase( m_serverQueryQueuePrio.begin(), m_serverQueryQueuePrio.begin() + toSend );
                }
            }
            if( m_serverQuerySpaceLeft > 0 && !m_serverQueryQueue.empty() )
            {
                const auto toSend = std::min( m_serverQuerySpaceLeft, m_serverQueryQueue.size() );
                m_sock.Send( m_serverQueryQueue.data(), toSend * ServerQueryPacketSize );
                m_serverQuerySpaceLeft -= toSend;
                if( toSend == m_serverQueryQueue.size() )
                {
                    m_serverQueryQueue.clear();
                }
                else
                {
                    m_serverQueryQueue.erase( m_serverQueryQueue.begin(), m_serverQueryQueue.begin() + toSend );
                }
            }
        }

        auto t1 = std::chrono::high_resolution_clock::now();
        auto td = std::chrono::duration_cast<std::chrono::milliseconds>( t1 - t0 ).count();
        enum { MbpsUpdateTime = 200 };
        if( td > MbpsUpdateTime )
        {
            UpdateMbps( td );
            t0 = t1;
        }

        if( m_terminate )
        {
            if( m_pendingStrings != 0 || m_pendingThreads != 0 || m_pendingSourceLocation != 0 || m_pendingCallstackFrames != 0 ||
                m_data.plots.IsPending() || m_pendingCallstackId != 0 || m_pendingExternalNames != 0 ||
                m_pendingCallstackSubframes != 0 || m_pendingFrameImageData.image != nullptr || !m_pendingSymbols.empty() ||
                m_pendingSymbolCode != 0 || !m_serverQueryQueue.empty() || !m_serverQueryQueuePrio.empty() ||
                m_pendingSourceLocationPayload != 0 || m_pendingSingleString.ptr != nullptr || m_pendingSecondString.ptr != nullptr ||
                !m_sourceCodeQuery.empty() || m_pendingFibers != 0 )
            {
                continue;
            }
            if( !m_crashed && !m_disconnect )
            {
                bool done = true;
                for( auto& v : m_data.threads )
                {
                    if( !v->stack.empty() )
                    {
                        done = false;
                        break;
                    }
                }
                if( !done ) continue;
            }
            QueryTerminate();
            UpdateMbps( 0 );
            break;
        }
    }

close:
    Shutdown();
    m_netWriteCv.notify_one();
    m_sock.Close();
    m_connected.store( false, std::memory_order_relaxed );
}

void Worker::UpdateMbps( int64_t td )
{
    const auto bytes = m_bytes.exchange( 0, std::memory_order_relaxed );
    const auto decBytes = m_decBytes.exchange( 0, std::memory_order_relaxed );
    std::lock_guard<std::shared_mutex> lock( m_mbpsData.lock );
    if( td != 0 )
    {
        m_mbpsData.mbps.erase( m_mbpsData.mbps.begin() );
        m_mbpsData.mbps.emplace_back( bytes / ( td * 125.f ) );
    }
    m_mbpsData.compRatio = decBytes == 0 ? 1 : float( bytes ) / decBytes;
    m_mbpsData.queue = m_serverQueryQueue.size() + m_serverQueryQueuePrio.size();
    m_mbpsData.transferred += bytes;
}

bool Worker::IsThreadStringRetrieved( uint64_t id )
{
    const auto name = GetThreadName( m_failureData.thread );
    return strcmp( name, "???" ) != 0;
}

bool Worker::IsCallstackRetrieved( uint32_t callstack )
{
    auto& cs = GetCallstack( callstack );
    for( auto& v : cs )
    {
        auto frameData = GetCallstackFrame( v );
        if( !frameData ) return false;
    }
    return true;
}

bool Worker::IsSourceLocationRetrieved( int16_t srcloc )
{
    auto& sl = GetSourceLocation( srcloc );
    auto func = GetString( sl.function );
    auto file = GetString( sl.file );
    return strcmp( func, "???" ) != 0 && strcmp( file, "???" ) != 0;
}

bool Worker::HasAllFailureData()
{
    if( m_failureData.thread != 0 && !IsThreadStringRetrieved( m_failureData.thread ) ) return false;
    if( m_failureData.srcloc != 0 && !IsSourceLocationRetrieved( m_failureData.srcloc ) ) return false;
    if( m_failureData.callstack != 0 && !IsCallstackRetrieved( m_failureData.callstack ) ) return false;
    return true;
}

void Worker::HandleFailure( const char* ptr, const char* end )
{
    if( HasAllFailureData() ) return;
    for(;;)
    {
        while( ptr < end )
        {
            auto ev = (const QueueItem*)ptr;
            DispatchFailure( *ev, ptr );
        }
        if( HasAllFailureData() ) return;

        {
            std::lock_guard<std::mutex> lock( m_netWriteLock );
            m_netWriteCnt++;
            m_netWriteCv.notify_one();
        }

        if( m_serverQuerySpaceLeft > 0 && !m_serverQueryQueuePrio.empty() )
        {
            const auto toSend = std::min( m_serverQuerySpaceLeft, m_serverQueryQueuePrio.size() );
            m_sock.Send( m_serverQueryQueuePrio.data(), toSend * ServerQueryPacketSize );
            m_serverQuerySpaceLeft -= toSend;
            if( toSend == m_serverQueryQueuePrio.size() )
            {
                m_serverQueryQueuePrio.clear();
            }
            else
            {
                m_serverQueryQueuePrio.erase( m_serverQueryQueuePrio.begin(), m_serverQueryQueuePrio.begin() + toSend );
            }
        }
        if( m_serverQuerySpaceLeft > 0 && !m_serverQueryQueue.empty() )
        {
            const auto toSend = std::min( m_serverQuerySpaceLeft, m_serverQueryQueue.size() );
            m_sock.Send( m_serverQueryQueue.data(), toSend * ServerQueryPacketSize );
            m_serverQuerySpaceLeft -= toSend;
            if( toSend == m_serverQueryQueue.size() )
            {
                m_serverQueryQueue.clear();
            }
            else
            {
                m_serverQueryQueue.erase( m_serverQueryQueue.begin(), m_serverQueryQueue.begin() + toSend );
            }
        }

        if( m_shutdown.load( std::memory_order_relaxed ) ) return;

        NetBuffer netbuf;
        {
            std::unique_lock<std::mutex> lock( m_netReadLock );
            m_netReadCv.wait( lock, [this] { return !m_netRead.empty(); } );
            netbuf = m_netRead.front();
            m_netRead.erase( m_netRead.begin() );
        }
        if( netbuf.bufferOffset < 0 ) return;

        ptr = m_buffer + netbuf.bufferOffset;
        end = ptr + netbuf.size;
    }
}

void Worker::DispatchFailure( const QueueItem& ev, const char*& ptr )
{
    if( ev.hdr.idx >= (int)QueueType::StringData )
    {
        ptr += sizeof( QueueHeader ) + sizeof( QueueStringTransfer );
        if( ev.hdr.type == QueueType::FrameImageData ||
            ev.hdr.type == QueueType::SymbolCode ||
            ev.hdr.type == QueueType::SourceCode )
        {
            if( ev.hdr.type == QueueType::SymbolCode || ev.hdr.type == QueueType::SourceCode )
            {
                m_serverQuerySpaceLeft++;
            }
            uint32_t sz;
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz ) + sz;
        }
        else
        {
            uint16_t sz;
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            switch( ev.hdr.type )
            {
            case QueueType::StringData:
                AddString( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::ThreadName:
                AddThreadString( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::FiberName:
                AddFiberName( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::PlotName:
            case QueueType::FrameName:
            case QueueType::ExternalName:
                m_serverQuerySpaceLeft++;
                break;
            default:
                break;
            }
            ptr += sz;
        }
    }
    else
    {
        uint16_t sz;
        switch( ev.hdr.type )
        {
        case QueueType::SingleStringData:
            ptr += sizeof( QueueHeader );
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            AddSingleStringFailure( ptr, sz );
            ptr += sz;
            break;
        case QueueType::SecondStringData:
            ptr += sizeof( QueueHeader );
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            AddSecondString( ptr, sz );
            ptr += sz;
            break;
        default:
            ptr += QueueDataSize[ev.hdr.idx];
            switch( ev.hdr.type )
            {
            case QueueType::SourceLocation:
                AddSourceLocation( ev.srcloc );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::CallstackFrameSize:
                ProcessCallstackFrameSize( ev.callstackFrameSize );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::CallstackFrame:
                ProcessCallstackFrame( ev.callstackFrame, false );
                break;
            case QueueType::SymbolInformation:
            case QueueType::AckServerQueryNoop:
            case QueueType::AckSourceCodeNotAvailable:
            case QueueType::AckSymbolCodeNotAvailable:
                m_serverQuerySpaceLeft++;
                break;
            default:
                break;
            }
        }
    }
}

void Worker::Query( ServerQuery type, uint64_t data, uint32_t extra )
{
    ServerQueryPacket query { type, data, extra };
    if( m_serverQuerySpaceLeft > 0 && m_serverQueryQueuePrio.empty() && m_serverQueryQueue.empty() )
    {
        m_serverQuerySpaceLeft--;
        m_sock.Send( &query, ServerQueryPacketSize );
    }
    else if( IsQueryPrio( type ) )
    {
        m_serverQueryQueuePrio.push_back( query );
    }
    else
    {
        m_serverQueryQueue.push_back( query );
    }
}

void Worker::QueryTerminate()
{
    ServerQueryPacket query { ServerQueryTerminate, 0, 0 };
    m_sock.Send( &query, ServerQueryPacketSize );
}

void Worker::QuerySourceFile( const char* fn, const char* image )
{
    if( image ) QueryDataTransfer( image, strlen( image ) + 1 );
    QueryDataTransfer( fn, strlen( fn ) + 1 );
    m_sourceCodeQuery.emplace( m_nextSourceCodeQuery, fn );
    Query( ServerQuerySourceCode, m_nextSourceCodeQuery );
    m_nextSourceCodeQuery++;
}

void Worker::QueryDataTransfer( const void* ptr, size_t size )
{
    Query( ServerQueryDataTransfer, size );
    auto data = (const char*)ptr;
    while( size > 0 )
    {
        uint64_t d8;
        uint32_t d4;
        if( size >= 12 )
        {
            memcpy( &d8, data, 8 );
            memcpy( &d4, data+8, 4 );
            data += 12;
            size -= 12;
        }
        else if( size > 8 )
        {
            memcpy( &d8, data, 8 );
            memset( &d4, 0, 4 );
            memcpy( &d4, data+8, size-8 );
            size = 0;
        }
        else
        {
            memset( &d8, 0, 8 );
            memset( &d4, 0, 4 );
            memcpy( &d8, data, size );
            size = 0;
        }
        Query( ServerQueryDataTransferPart, d8, d4 );
    }
}

bool Worker::DispatchProcess( const QueueItem& ev, const char*& ptr )
{
    if( ev.hdr.idx >= (int)QueueType::StringData )
    {
        ptr += sizeof( QueueHeader ) + sizeof( QueueStringTransfer );
        if( ev.hdr.type == QueueType::FrameImageData ||
            ev.hdr.type == QueueType::SymbolCode ||
            ev.hdr.type == QueueType::SourceCode )
        {
            uint32_t sz;
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            switch( ev.hdr.type )
            {
            case QueueType::FrameImageData:
                AddFrameImageData( ev.stringTransfer.ptr, ptr, sz );
                break;
            case QueueType::SymbolCode:
                AddSymbolCode( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::SourceCode:
                AddSourceCode( (uint32_t)ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            default:
                assert( false );
                break;
            }
            ptr += sz;
        }
        else
        {
            uint16_t sz;
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            switch( ev.hdr.type )
            {
            case QueueType::StringData:
                AddString( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::ThreadName:
                AddThreadString( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::FiberName:
                AddFiberName( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::PlotName:
                HandlePlotName( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::SourceLocationPayload:
                AddSourceLocationPayload( ev.stringTransfer.ptr, ptr, sz );
                break;
            case QueueType::CallstackPayload:
                AddCallstackPayload( ev.stringTransfer.ptr, ptr, sz );
                break;
            case QueueType::FrameName:
                HandleFrameName( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::CallstackAllocPayload:
                AddCallstackAllocPayload( ev.stringTransfer.ptr, ptr, sz );
                break;
            case QueueType::ExternalName:
                AddExternalName( ev.stringTransfer.ptr, ptr, sz );
                m_serverQuerySpaceLeft++;
                break;
            case QueueType::ExternalThreadName:
                AddExternalThreadName( ev.stringTransfer.ptr, ptr, sz );
                break;
            default:
                assert( false );
                break;
            }
            ptr += sz;
        }
        return true;
    }
    else
    {
        uint16_t sz;
        switch( ev.hdr.type )
        {
        case QueueType::SingleStringData:
            ptr += sizeof( QueueHeader );
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            AddSingleString( ptr, sz );
            ptr += sz;
            return true;
        case QueueType::SecondStringData:
            ptr += sizeof( QueueHeader );
            memcpy( &sz, ptr, sizeof( sz ) );
            ptr += sizeof( sz );
            AddSecondString( ptr, sz );
            ptr += sz;
            return true;
        default:
            ptr += QueueDataSize[ev.hdr.idx];
            return Process( ev );
        }
    }
}

void Worker::CheckSourceLocation( uint64_t ptr )
{
    if( m_data.checkSrclocLast != ptr )
    {
        m_data.checkSrclocLast = ptr;
        if( m_data.sourceLocation.find( ptr ) == m_data.sourceLocation.end() )
        {
            NewSourceLocation( ptr );
        }
    }
}

void Worker::NewSourceLocation( uint64_t ptr )
{
    static const SourceLocation emptySourceLocation = {};

    m_data.sourceLocation.emplace( ptr, emptySourceLocation );
    m_pendingSourceLocation++;
    m_sourceLocationQueue.push_back( ptr );

    Query( ServerQuerySourceLocation, ptr );
}

int16_t Worker::ShrinkSourceLocationReal( uint64_t srcloc )
{
    auto it = m_sourceLocationShrink.find( srcloc );
    if( it != m_sourceLocationShrink.end() )
    {
        m_data.shrinkSrclocLast.first = srcloc;
        m_data.shrinkSrclocLast.second = it->second;
        return it->second;
    }
    else
    {
        return NewShrinkedSourceLocation( srcloc );
    }
}

int16_t Worker::NewShrinkedSourceLocation( uint64_t srcloc )
{
    assert( m_data.sourceLocationExpand.size() < std::numeric_limits<int16_t>::max() );
    const auto sz = int16_t( m_data.sourceLocationExpand.size() );
    m_data.sourceLocationExpand.push_back( srcloc );
#ifndef TRACY_NO_STATISTICS
    auto res = m_data.sourceLocationZones.emplace( sz, SourceLocationZones() );
    m_data.srclocZonesLast.first = sz;
    m_data.srclocZonesLast.second = &res.first->second;
#else
    auto res = m_data.sourceLocationZonesCnt.emplace( sz, 0 );
    m_data.srclocCntLast.first = sz;
    m_data.srclocCntLast.second = &res.first->second;
#endif
    m_sourceLocationShrink.emplace( srcloc, sz );
    m_data.shrinkSrclocLast.first = srcloc;
    m_data.shrinkSrclocLast.second = sz;
    return sz;
}

void Worker::InsertMessageData( MessageData* msg )
{
    if( m_data.messages.empty() )
    {
        m_data.messages.push_back( msg );
    }
    else if( m_data.messages.back()->time < msg->time )
    {
        m_data.messages.push_back_non_empty( msg );
    }
    else
    {
        auto mit = std::lower_bound( m_data.messages.begin(), m_data.messages.end(), msg->time, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        m_data.messages.insert( mit, msg );
    }

    auto td = GetCurrentThreadData();
    auto vec = &td->messages;
    if( vec->empty() )
    {
        vec->push_back( msg );
    }
    else if( vec->back()->time < msg->time )
    {
        vec->push_back_non_empty( msg );
    }
    else
    {
        auto tmit = std::lower_bound( vec->begin(), vec->end(), msg->time, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        vec->insert( tmit, msg );
    }
}

ThreadData* Worker::NoticeThreadReal( uint64_t thread )
{
    auto it = m_threadMap.find( thread );
    if( it != m_threadMap.end() )
    {
        m_data.threadDataLast.first = thread;
        m_data.threadDataLast.second = it->second;
        return it->second;
    }
    else
    {
        CheckThreadString( thread );
        return NewThread( thread, false );
    }
}

ThreadData* Worker::RetrieveThreadReal( uint64_t thread )
{
    auto it = m_threadMap.find( thread );
    if( it != m_threadMap.end() )
    {
        m_data.threadDataLast.first = thread;
        m_data.threadDataLast.second = it->second;
        return it->second;
    }
    else
    {
        return nullptr;
    }
}

ThreadData* Worker::GetCurrentThreadData()
{
    auto td = m_threadCtxData;
    if( !td ) td = m_threadCtxData = NoticeThread( m_threadCtx );
    if( td->fiber ) td = td->fiber;
    return td;
}

#ifndef TRACY_NO_STATISTICS
Worker::SourceLocationZones* Worker::GetSourceLocationZonesReal( uint16_t srcloc )
{
    auto it = m_data.sourceLocationZones.find( srcloc );
    assert( it != m_data.sourceLocationZones.end() );
    m_data.srclocZonesLast.first = srcloc;
    m_data.srclocZonesLast.second = &it->second;
    return &it->second;
}

Worker::GpuSourceLocationZones* Worker::GetGpuSourceLocationZonesReal( uint16_t srcloc )
{
    auto it = m_data.gpuSourceLocationZones.find( srcloc );
    if( it == m_data.gpuSourceLocationZones.end() )
    {
        it = m_data.gpuSourceLocationZones.emplace( srcloc, GpuSourceLocationZones() ).first;
    }
    m_data.gpuZonesLast.first = srcloc;
    m_data.gpuZonesLast.second = &it->second;
    return &it->second;
}
#else
uint64_t* Worker::GetSourceLocationZonesCntReal( uint16_t srcloc )
{
    auto it = m_data.sourceLocationZonesCnt.find( srcloc );
    assert( it != m_data.sourceLocationZonesCnt.end() );
    m_data.srclocCntLast.first = srcloc;
    m_data.srclocCntLast.second = &it->second;
    return &it->second;
}

uint64_t* Worker::GetGpuSourceLocationZonesCntReal( uint16_t srcloc )
{
    auto it = m_data.gpuSourceLocationZonesCnt.find( srcloc );
    assert( it != m_data.gpuSourceLocationZonesCnt.end() );
    m_data.gpuCntLast.first = srcloc;
    m_data.gpuCntLast.second = &it->second;
    return &it->second;
}
#endif

const ThreadData* Worker::GetThreadData( uint64_t tid ) const
{
    auto it = m_threadMap.find( tid );
    if( it == m_threadMap.end() ) return nullptr;
    return it->second;
}

const MemData& Worker::GetMemoryNamed( uint64_t name ) const
{
    auto it = m_data.memNameMap.find( name );
    assert( it != m_data.memNameMap.end() );
    return *it->second;
}

ThreadData* Worker::NewThread( uint64_t thread, bool fiber )
{
    auto td = m_slab.AllocInit<ThreadData>();
    td->id = thread;
    td->count = 0;
    td->nextZoneId = 0;
#ifndef TRACY_NO_STATISTICS
    td->ghostIdx = 0;
#endif
    td->kernelSampleCnt = 0;
    td->pendingSample.time.Clear();
    td->isFiber = fiber;
    td->fiber = nullptr;
    td->stackCount = (uint8_t*)m_slab.AllocBig( sizeof( uint8_t ) * 64*1024 );
    memset( td->stackCount, 0, sizeof( uint8_t ) * 64*1024 );
    m_data.threads.push_back( td );
    m_threadMap.emplace( thread, td );
    m_data.threadDataLast.first = thread;
    m_data.threadDataLast.second = td;
    return td;
}

void Worker::NewZone( ZoneEvent* zone )
{
    m_data.zonesCnt++;

    auto td = GetCurrentThreadData();
    td->count++;
    td->IncStackCount( zone->SrcLoc() );
    const auto ssz = td->stack.size();
    if( ssz == 0 )
    {
        td->stack.push_back( zone );
        td->timeline.push_back( zone );
    }
    else
    {
        auto& back = td->stack.data()[ssz-1];
        if( !back->HasChildren() )
        {
            back->SetChild( int32_t( m_data.zoneChildren.size() ) );
            if( m_data.zoneVectorCache.empty() )
            {
                m_data.zoneChildren.push_back( Vector<short_ptr<ZoneEvent>>( zone ) );
            }
            else
            {
                Vector<short_ptr<ZoneEvent>> vze = std::move( m_data.zoneVectorCache.back_and_pop() );
                assert( !vze.empty() );
                vze.clear();
                vze.push_back_non_empty( zone );
                m_data.zoneChildren.push_back( std::move( vze ) );
            }
        }
        else
        {
            const auto backChild = back->Child();
            assert( !m_data.zoneChildren[backChild].empty() );
            m_data.zoneChildren[backChild].push_back_non_empty( zone );
        }
        td->stack.push_back_non_empty( zone );
    }

    td->zoneIdStack.push_back( td->nextZoneId );
    td->nextZoneId = 0;

#ifndef TRACY_NO_STATISTICS
    td->childTimeStack.push_back( 0 );
#endif
}

void Worker::InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread, int64_t time )
{
    if( m_data.lastTime < time ) m_data.lastTime = time;

    NoticeThread( thread );

    auto it = lockmap.threadMap.find( thread );
    if( it == lockmap.threadMap.end() )
    {
        assert( lockmap.threadList.size() < MaxLockThreads );
        it = lockmap.threadMap.emplace( thread, lockmap.threadList.size() ).first;
        lockmap.threadList.emplace_back( thread );
    }
    lev->thread = it->second;
    assert( lev->thread == it->second );
    auto& timeline = lockmap.timeline;
    if( timeline.empty() )
    {
        timeline.push_back( { lev } );
        UpdateLockCount( lockmap, timeline.size() - 1 );
    }
    else
    {
        assert( timeline.back().ptr->Time() <= time );
        timeline.push_back_non_empty( { lev } );
        UpdateLockCount( lockmap, timeline.size() - 1 );
    }

    auto& range = lockmap.range[it->second];
    if( range.start > time ) range.start = time;
    if( range.end < time ) range.end = time;
}

bool Worker::CheckString( uint64_t ptr )
{
    if( ptr == 0 ) return true;
    if( m_data.strings.find( ptr ) != m_data.strings.end() ) return true;

    m_data.strings.emplace( ptr, "???" );
    m_pendingStrings++;

    Query( ServerQueryString, ptr );
    return false;
}

void Worker::CheckThreadString( uint64_t id )
{
    if( m_data.threadNames.find( id ) != m_data.threadNames.end() ) return;

    m_data.threadNames.emplace( id, "???" );
    m_pendingThreads++;

    if( m_sock.IsValid() ) Query( ServerQueryThreadString, id );
}

void Worker::CheckFiberName( uint64_t id, uint64_t tid )
{
    if( m_data.threadNames.find( tid ) != m_data.threadNames.end() ) return;

    m_data.threadNames.emplace( tid, "???" );
    m_pendingFibers++;

    if( m_sock.IsValid() ) Query( ServerQueryFiberName, id );
}

void Worker::CheckExternalName( uint64_t id )
{
    if( m_data.externalNames.find( id ) != m_data.externalNames.end() ) return;

    m_data.externalNames.emplace( id, std::make_pair( "???", "???" ) );
    m_pendingExternalNames += 2;

    Query( ServerQueryExternalName, id );
}

void Worker::AddSourceLocation( const QueueSourceLocation& srcloc )
{
    assert( m_pendingSourceLocation > 0 );
    m_pendingSourceLocation--;

    const auto ptr = m_sourceLocationQueue.front();
    m_sourceLocationQueue.erase( m_sourceLocationQueue.begin() );

    auto it = m_data.sourceLocation.find( ptr );
    assert( it != m_data.sourceLocation.end() );
    CheckString( srcloc.name );
    if( CheckString( srcloc.file ) )
    {
        StringRef ref( StringRef::Ptr, srcloc.file );
        if( srcloc.file != 0 && m_checkedFileStrings.find( ref ) == m_checkedFileStrings.end() && m_pendingFileStrings.find( ref ) == m_pendingFileStrings.end() )
        {
            CacheSource( ref );
        }
    }
    else
    {
        StringRef ref( StringRef::Ptr, srcloc.file );
        assert( m_checkedFileStrings.find( ref ) == m_checkedFileStrings.end() );
        if( m_pendingFileStrings.find( ref ) == m_pendingFileStrings.end() )
        {
            m_pendingFileStrings.emplace( ref );
        }
    }
    CheckString( srcloc.function );
    const uint32_t color = ( srcloc.b << 16 ) | ( srcloc.g << 8 ) | srcloc.r;
    it->second = SourceLocation {{ srcloc.name == 0 ? StringRef() : StringRef( StringRef::Ptr, srcloc.name ), StringRef( StringRef::Ptr, srcloc.function ), StringRef( StringRef::Ptr, srcloc.file ), srcloc.line, color }};
}

void Worker::AddSourceLocationPayload( uint64_t ptr, const char* data, size_t sz )
{
    const auto start = data;

    assert( m_pendingSourceLocationPayload == 0 );

    uint32_t color, line;
    memcpy( &color, data, 4 );
    memcpy( &line, data + 4, 4 );
    data += 8;
    auto end = data;

    while( *end ) end++;
    const auto func = StoreString( data, end - data );
    end++;

    data = end;
    while( *end ) end++;
    const auto source = StoreString( data, end - data );
    end++;

    const auto nsz = sz - ( end - start );

    color = ( ( color & 0x00FF0000 ) >> 16 ) |
            ( ( color & 0x0000FF00 )       ) |
            ( ( color & 0x000000FF ) << 16 );

    SourceLocation srcloc {{ nsz == 0 ? StringRef() : StringRef( StringRef::Idx, StoreString( end, nsz ).idx ), StringRef( StringRef::Idx, func.idx ), StringRef( StringRef::Idx, source.idx ), line, color }};
    auto it = m_data.sourceLocationPayloadMap.find( &srcloc );
    if( it == m_data.sourceLocationPayloadMap.end() )
    {
        auto slptr = m_slab.Alloc<SourceLocation>();
        memcpy( slptr, &srcloc, sizeof( srcloc ) );
        uint32_t idx = m_data.sourceLocationPayload.size();
        m_data.sourceLocationPayloadMap.emplace( slptr, idx );
        m_pendingSourceLocationPayload = -int16_t( idx + 1 );
        m_data.sourceLocationPayload.push_back( slptr );
        if( m_checkedFileStrings.find( srcloc.file ) == m_checkedFileStrings.end() )
        {
            CacheSource( srcloc.file );
        }
        const auto key = -int16_t( idx + 1 );
#ifndef TRACY_NO_STATISTICS
        auto res = m_data.sourceLocationZones.emplace( key, SourceLocationZones() );
        m_data.srclocZonesLast.first = key;
        m_data.srclocZonesLast.second = &res.first->second;
#else
        auto res = m_data.sourceLocationZonesCnt.emplace( key, 0 );
        m_data.srclocCntLast.first = key;
        m_data.srclocCntLast.second = &res.first->second;
#endif
    }
    else
    {
        m_pendingSourceLocationPayload = -int16_t( it->second + 1 );
    }
}

void Worker::AddString( uint64_t ptr, const char* str, size_t sz )
{
    assert( m_pendingStrings > 0 );
    m_pendingStrings--;
    auto it = m_data.strings.find( ptr );
    assert( it != m_data.strings.end() && strcmp( it->second, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    it->second = sl.ptr;

    StringRef ref( StringRef::Ptr, ptr );
    auto sit = m_pendingFileStrings.find( ref );
    if( sit != m_pendingFileStrings.end() )
    {
        m_pendingFileStrings.erase( sit );
        CacheSource( ref );
    }
}

void Worker::AddThreadString( uint64_t id, const char* str, size_t sz )
{
    assert( m_pendingThreads > 0 );
    m_pendingThreads--;
    auto it = m_data.threadNames.find( id );
    assert( it != m_data.threadNames.end() && strcmp( it->second, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    it->second = sl.ptr;
}

void Worker::AddFiberName( uint64_t id, const char* str, size_t sz )
{
    assert( m_pendingFibers > 0 );
    m_pendingFibers--;
    auto it = m_data.fiberToThreadMap.find( id );
    assert( it != m_data.fiberToThreadMap.end() );
    auto tit = m_data.threadNames.find( it->second );
    assert( tit != m_data.threadNames.end() && strcmp( tit->second, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    tit->second = sl.ptr;
}

void Worker::AddSingleString( const char* str, size_t sz )
{
    assert( m_pendingSingleString.ptr == nullptr );
    m_pendingSingleString = StoreString( str, sz );
}

void Worker::AddSingleStringFailure( const char* str, size_t sz )
{
    // During failure dispatch processing of most events is ignored, but string data
    // is still send. Just ignore anything that was already in the staging area.
    m_pendingSingleString = StoreString( str, sz );
}

void Worker::AddSecondString( const char* str, size_t sz )
{
    assert( m_pendingSecondString.ptr == nullptr );
    m_pendingSecondString = StoreString( str, sz );
}

void Worker::AddExternalName( uint64_t ptr, const char* str, size_t sz )
{
    assert( m_pendingExternalNames > 0 );
    m_pendingExternalNames--;
    auto it = m_data.externalNames.find( ptr );
    assert( it != m_data.externalNames.end() && strcmp( it->second.first, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    it->second.first = sl.ptr;
}

void Worker::AddExternalThreadName( uint64_t ptr, const char* str, size_t sz )
{
    assert( m_pendingExternalNames > 0 );
    m_pendingExternalNames--;
    auto it = m_data.externalNames.find( ptr );
    assert( it != m_data.externalNames.end() && strcmp( it->second.second, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    it->second.second = sl.ptr;
}

void Worker::AddFrameImageData( uint64_t ptr, const char* data, size_t sz )
{
    assert( m_pendingFrameImageData.image == nullptr );
    assert( sz % 8 == 0 );
    // Input data buffer cannot be changed, as it is used as LZ4 dictionary.
    if( m_frameImageBufferSize < sz )
    {
        m_frameImageBufferSize = sz;
        delete[] m_frameImageBuffer;
        m_frameImageBuffer = new char[sz];
    }
    auto src = (uint8_t*)data;
    auto dst = (uint8_t*)m_frameImageBuffer;
    memcpy( dst, src, sz );
    m_texcomp.FixOrder( (char*)dst, sz/8 );
    m_texcomp.Rdo( (char*)dst, sz/8 );
    m_pendingFrameImageData.image = m_texcomp.Pack( m_frameImageBuffer, sz, m_pendingFrameImageData.csz, m_slab );
}

void Worker::AddSymbolCode( uint64_t ptr, const char* data, size_t sz )
{
    assert( m_pendingSymbolCode > 0 );
    m_pendingSymbolCode--;

    auto code = (char*)m_slab.AllocBig( sz );
    memcpy( code, data, sz );
    m_data.symbolCode.emplace( ptr, MemoryBlock{ code, uint32_t( sz ) } );
    m_data.symbolCodeSize += sz;

    if( m_data.cpuArch == CpuArchUnknown ) return;
    csh handle;
    cs_err rval = CS_ERR_ARCH;
    switch( m_data.cpuArch )
    {
    case CpuArchX86:
        rval = cs_open( CS_ARCH_X86, CS_MODE_32, &handle );
        break;
    case CpuArchX64:
        rval = cs_open( CS_ARCH_X86, CS_MODE_64, &handle );
        break;
    case CpuArchArm32:
        rval = cs_open( CS_ARCH_ARM, CS_MODE_ARM, &handle );
        break;
    case CpuArchArm64:
        rval = cs_open( CS_ARCH_ARM64, CS_MODE_ARM, &handle );
        break;
    default:
        assert( false );
        break;
    }
    if( rval != CS_ERR_OK ) return;
    cs_option( handle, CS_OPT_DETAIL, CS_OPT_ON );
    cs_insn* insn;
    size_t cnt = cs_disasm( handle, (const uint8_t*)code, sz, ptr, 0, &insn );
    if( cnt > 0 )
    {
        for( size_t i=0; i<cnt; i++ )
        {
            const auto& op = insn[i];
            const auto addr = op.address;
            if( m_data.callstackFrameMap.find( PackPointer( addr ) ) == m_data.callstackFrameMap.end() )
            {
                m_pendingCallstackFrames++;
                Query( ServerQueryCallstackFrame, addr );
            }

            uint64_t callAddr = 0;
            const auto& detail = *op.detail;
            for( auto j=0; j<detail.groups_count; j++ )
            {
                if( detail.groups[j] == CS_GRP_JUMP || detail.groups[j] == CS_GRP_CALL )
                {
                    switch( GetCpuArch() )
                    {
                    case CpuArchX86:
                    case CpuArchX64:
                        if( detail.x86.op_count == 1 && detail.x86.operands[0].type == X86_OP_IMM )
                        {
                            callAddr = (uint64_t)detail.x86.operands[0].imm;
                        }
                        break;
                    case CpuArchArm32:
                        if( detail.arm.op_count == 1 && detail.arm.operands[0].type == ARM_OP_IMM )
                        {
                            callAddr = (uint64_t)detail.arm.operands[0].imm;
                        }
                        break;
                    case CpuArchArm64:
                        if( detail.arm64.op_count == 1 && detail.arm64.operands[0].type == ARM64_OP_IMM )
                        {
                            callAddr = (uint64_t)detail.arm64.operands[0].imm;
                        }
                        break;
                    default:
                        assert( false );
                        break;
                    }
                    if( callAddr != 0 ) break;
                }
            }
            if( callAddr != 0 && m_data.callstackFrameMap.find( PackPointer( callAddr ) ) == m_data.callstackFrameMap.end() )
            {
                m_pendingCallstackFrames++;
                Query( ServerQueryCallstackFrame, callAddr );
            }
        }
        cs_free( insn, cnt );
    }
    cs_close( &handle );
}


void Worker::AddSourceCode( uint32_t id, const char* data, size_t sz )
{
    auto it = m_sourceCodeQuery.find( id );
    assert( it != m_sourceCodeQuery.end() );
    auto file = it->second;
    m_sourceCodeQuery.erase( it );
    if( m_data.sourceFileCache.find( file ) != m_data.sourceFileCache.end() ) return;
    auto src = (char*)m_slab.AllocBig( sz );
    memcpy( src, data, sz );
    m_data.sourceFileCache.emplace( file, MemoryBlock{ src, uint32_t( sz ) } );
}

CallstackFrameId Worker::PackPointer( uint64_t ptr ) const
{
    assert( ( ( ptr & 0x3000000000000000 ) << 2 ) == ( ptr & 0xC000000000000000 ) );
    CallstackFrameId id;
    id.idx = ptr;
    id.sel = 0;
    id.custom = 0;
    return id;
}

uint64_t Worker::GetCanonicalPointer( const CallstackFrameId& id ) const
{
    assert( id.sel == 0 );
    return ( id.idx & 0x3FFFFFFFFFFFFFFF ) | ( ( id.idx & 0x3000000000000000 ) << 2 );
}

void Worker::AddCallstackPayload( uint64_t ptr, const char* _data, size_t _sz )
{
    assert( m_pendingCallstackId == 0 );

    const auto sz = _sz / sizeof( uint64_t );
    const auto memsize = sizeof( VarArray<CallstackFrameId> ) + sz * sizeof( CallstackFrameId );
    auto mem = (char*)m_slab.AllocRaw( memsize );

    auto data = (CallstackFrameId*)mem;
    auto dst = data;
    auto src = (uint64_t*)_data;
    for( size_t i=0; i<sz; i++ )
    {
        *dst++ = PackPointer( *src++ );
    }

    auto arr = (VarArray<CallstackFrameId>*)( mem + sz * sizeof( CallstackFrameId ) );
    new(arr) VarArray<CallstackFrameId>( sz, data );

    uint32_t idx;
    auto it = m_data.callstackMap.find( arr );
    if( it == m_data.callstackMap.end() )
    {
        idx = m_data.callstackPayload.size();
        m_data.callstackMap.emplace( arr, idx );
        m_data.callstackPayload.push_back( arr );

        for( auto& frame : *arr )
        {
            auto fit = m_data.callstackFrameMap.find( frame );
            if( fit == m_data.callstackFrameMap.end() )
            {
                m_pendingCallstackFrames++;
                Query( ServerQueryCallstackFrame, GetCanonicalPointer( frame ) );
            }
        }
    }
    else
    {
        idx = it->second;
        m_slab.Unalloc( memsize );
    }

    m_pendingCallstackId = idx;
}

void Worker::AddCallstackAllocPayload( uint64_t ptr, const char* data, size_t _sz )
{
    CallstackFrameId stack[64];
    uint8_t sz;
    memcpy( &sz, data, 1 ); data++;
    assert( sz <= 64 );
    for( uint8_t i=0; i<sz; i++ )
    {
        uint16_t sz;
        CallstackFrame cf;
        memcpy( &cf.line, data, 4 ); data += 4;
        memcpy( &sz, data, 2 ); data += 2;
        cf.name = StoreString( data, sz ).idx; data += sz;
        memcpy( &sz, data, 2 ); data += 2;
        cf.file = StoreString( data, sz ).idx; data += sz;
        cf.symAddr = 0;
        CallstackFrameData cfd = { &cf, 1 };

        CallstackFrameId id;
        auto it = m_data.revFrameMap.find( &cfd );
        if( it == m_data.revFrameMap.end() )
        {
            auto frame = m_slab.Alloc<CallstackFrame>();
            memcpy( frame, &cf, sizeof( CallstackFrame ) );
            auto frameData = m_slab.AllocInit<CallstackFrameData>();
            frameData->data = frame;
            frameData->size = 1;
            id.idx = m_callstackAllocNextIdx++;
            id.sel = 1;
            id.custom = 0;
            m_data.callstackFrameMap.emplace( id, frameData );
            m_data.revFrameMap.emplace( frameData, id );
        }
        else
        {
            id = it->second;
        }
        stack[i] = id;
    }

    VarArray<CallstackFrameId>* arr;
    size_t memsize;
    if( m_pendingCallstackId != 0 )
    {
        const auto nativeCs = m_data.callstackPayload[m_pendingCallstackId];
        const auto nsz = nativeCs->size();
        const auto tsz = sz + nsz;

        memsize = sizeof( VarArray<CallstackFrameId> ) + tsz * sizeof( CallstackFrameId );
        auto mem = (char*)m_slab.AllocRaw( memsize );
        memcpy( mem, stack, sizeof( CallstackFrameId ) * sz );
        memcpy( mem + sizeof( CallstackFrameId ) * sz, nativeCs->data(), sizeof( CallstackFrameId ) * nsz );

        arr = (VarArray<CallstackFrameId>*)( mem + tsz * sizeof( CallstackFrameId ) );
        new(arr) VarArray<CallstackFrameId>( tsz, (CallstackFrameId*)mem );
    }
    else
    {
        memsize = sizeof( VarArray<CallstackFrameId> ) + sz * sizeof( CallstackFrameId );
        auto mem = (char*)m_slab.AllocRaw( memsize );
        memcpy( mem, stack, sizeof( CallstackFrameId ) * sz );

        arr = (VarArray<CallstackFrameId>*)( mem + sz * sizeof( CallstackFrameId ) );
        new(arr) VarArray<CallstackFrameId>( sz, (CallstackFrameId*)mem );
    }

    uint32_t idx;
    auto it = m_data.callstackMap.find( arr );
    if( it == m_data.callstackMap.end() )
    {
        idx = m_data.callstackPayload.size();
        m_data.callstackMap.emplace( arr, idx );
        m_data.callstackPayload.push_back( arr );

        for( auto& frame : *arr )
        {
            auto fit = m_data.callstackFrameMap.find( frame );
            if( fit == m_data.callstackFrameMap.end() )
            {
                m_pendingCallstackFrames++;
                Query( ServerQueryCallstackFrame, GetCanonicalPointer( frame ) );
            }
        }
    }
    else
    {
        idx = it->second;
        m_slab.Unalloc( memsize );
    }

    m_pendingCallstackId = idx;
}

uint32_t Worker::MergeCallstacks( uint32_t first, uint32_t second )
{
    const auto& cs1 = GetCallstack( first );
    const auto& cs2 = GetCallstack( second );

    const auto sz1 = cs1.size();
    const auto sz2 = cs2.size();
    const auto tsz = sz1 + sz2;

    size_t memsize = sizeof( VarArray<CallstackFrameId> ) + tsz * sizeof( CallstackFrameId );
    auto mem = (char*)m_slab.AllocRaw( memsize );
    memcpy( mem, cs1.data(), sizeof( CallstackFrameId ) * sz1 );
    memcpy( mem + sizeof( CallstackFrameId ) * sz1, cs2.data(), sizeof( CallstackFrameId ) * sz2 );

    VarArray<CallstackFrameId>* arr = (VarArray<CallstackFrameId>*)( mem + tsz * sizeof( CallstackFrameId ) );
    new(arr) VarArray<CallstackFrameId>( tsz, (CallstackFrameId*)mem );

    uint32_t idx;
    auto it = m_data.callstackMap.find( arr );
    if( it == m_data.callstackMap.end() )
    {
        idx = m_data.callstackPayload.size();
        m_data.callstackMap.emplace( arr, idx );
        m_data.callstackPayload.push_back( arr );
    }
    else
    {
        idx = it->second;
        m_slab.Unalloc( memsize );
    }
    return idx;
}

void Worker::InsertPlot( PlotData* plot, int64_t time, double val )
{
    if( plot->data.empty() )
    {
        plot->min = val;
        plot->max = val;
        plot->sum = val;
        plot->data.push_back( { Int48( time ), val } );
    }
    else
    {
        if( plot->min > val ) plot->min = val;
        else if( plot->max < val ) plot->max = val;
        plot->sum += val;
        plot->data.push_back( { Int48( time ), val } );
    }
}

void Worker::HandlePlotName( uint64_t name, const char* str, size_t sz )
{
    const auto sl = StoreString( str, sz );
    m_data.plots.StringDiscovered( name, sl, m_data.strings, [this] ( PlotData* dst, PlotData* src ) {
        for( auto& v : src->data )
        {
            InsertPlot( dst, v.time.Val(), v.val );
        }
    } );
}

void Worker::HandleFrameName( uint64_t name, const char* str, size_t sz )
{
    const auto sl = StoreString( str, sz );
    m_data.frames.StringDiscovered( name, sl, m_data.strings, [] ( FrameData* dst, FrameData* src ) {
        auto sz = dst->frames.size();
        dst->frames.insert( dst->frames.end(), src->frames.begin(), src->frames.end() );
        std::inplace_merge( dst->frames.begin(), dst->frames.begin() + sz, dst->frames.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs.start < rhs.start; } );
    } );
}

void Worker::DoPostponedSymbols()
{
    if( m_data.newSymbolsIndex >= 0 )
    {
#ifdef NO_PARALLEL_SORT
        pdqsort_branchless( m_data.symbolLoc.begin() + m_data.newSymbolsIndex, m_data.symbolLoc.end(), [] ( const auto& l, const auto& r ) { return l.addr < r.addr; } );
#else
        std::sort( std::execution::par_unseq, m_data.symbolLoc.begin() + m_data.newSymbolsIndex, m_data.symbolLoc.end(), [] ( const auto& l, const auto& r ) { return l.addr < r.addr; } );
#endif
        const auto ms = std::lower_bound( m_data.symbolLoc.begin(), m_data.symbolLoc.begin() + m_data.newSymbolsIndex, m_data.symbolLoc[m_data.newSymbolsIndex], [] ( const auto& l, const auto& r ) { return l.addr < r.addr; } );
        std::inplace_merge( ms, m_data.symbolLoc.begin() + m_data.newSymbolsIndex, m_data.symbolLoc.end(), [] ( const auto& l, const auto& r ) { return l.addr < r.addr; } );
        m_data.newSymbolsIndex = -1;
    }
}

void Worker::DoPostponedInlineSymbols()
{
    if( m_data.newInlineSymbolsIndex >= 0 )
    {
#ifdef NO_PARALLEL_SORT
        pdqsort_branchless( m_data.symbolLocInline.begin() + m_data.newInlineSymbolsIndex, m_data.symbolLocInline.end() );
#else
        std::sort( std::execution::par_unseq, m_data.symbolLocInline.begin() + m_data.newInlineSymbolsIndex, m_data.symbolLocInline.end() );
#endif
        const auto ms = std::lower_bound( m_data.symbolLocInline.begin(), m_data.symbolLocInline.begin() + m_data.newInlineSymbolsIndex, m_data.symbolLocInline[m_data.newInlineSymbolsIndex] );
        std::inplace_merge( ms, m_data.symbolLocInline.begin() + m_data.newInlineSymbolsIndex, m_data.symbolLocInline.end() );
        m_data.newInlineSymbolsIndex = -1;
    }
}

void Worker::DoPostponedWorkAll()
{
    DoPostponedWork();
    DoPostponedSymbols();
    DoPostponedInlineSymbols();

    for( auto& plot : m_data.plots.Data() )
    {
        if( !plot->data.is_sorted() ) plot->data.sort();
    }
}

void Worker::DoPostponedWork()
{
#ifndef TRACY_NO_STATISTICS
    if( m_data.newFramesWereReceived )
    {
        HandlePostponedSamples();
        HandlePostponedGhostZones();
        m_data.newFramesWereReceived = false;
    }

    if( m_identifySamples && m_data.newContextSwitchesReceived )
    {
        for( auto& td : m_data.threads )
        {
            if( !td->postponedSamples.empty() )
            {
                auto ctx = GetContextSwitchData( td->id );
                if( ctx )
                {
                    td->postponedSamples.ensure_sorted();
                    auto sit = td->postponedSamples.begin();
                    auto cit = std::lower_bound( ctx->v.begin(), ctx->v.end(), sit->time.Val(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                    if( cit != ctx->v.end() )
                    {
                        do
                        {
                            if( sit->time.Val() == cit->Start() )
                            {
                                td->ctxSwitchSamples.push_back( *sit );
                            }
                            else
                            {
                                ProcessCallstackSampleImplStats( *sit, *td );
                            }
                            if( ++sit == td->postponedSamples.end() ) break;
                            cit = std::lower_bound( cit, ctx->v.end(), sit->time.Val(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                        }
                        while( cit != ctx->v.end() );
                        if( sit == td->postponedSamples.end() )
                        {
                            td->postponedSamples.clear();
                        }
                        else
                        {
                            td->postponedSamples.erase( td->postponedSamples.begin(), sit );
                        }
                    }
                }
            }
        }
        m_data.newContextSwitchesReceived = false;
    }
#endif
}

#ifndef TRACY_NO_STATISTICS
void Worker::HandlePostponedSamples()
{
    assert( m_data.newFramesWereReceived );
    if( m_data.postponedSamples.empty() ) return;
    auto it = m_data.postponedSamples.begin();
    do
    {
        UpdateSampleStatisticsPostponed( it );
    }
    while( it != m_data.postponedSamples.end() );
}

void Worker::GetStackWithInlines( Vector<InlineStackData>& ret, const VarArray<CallstackFrameId>& cs )
{
    ret.clear();
    int idx = cs.size() - 1;
    do
    {
        auto& entry = cs[idx];
        const auto frame = GetCallstackFrame( entry );
        if( frame )
        {
            uint8_t i = frame->size;
            do
            {
                i--;
                ret.push_back( InlineStackData { frame->data[i].symAddr, entry, i } );
            }
            while( i != 0 );
        }
        else
        {
            ret.push_back( InlineStackData{ GetCanonicalPointer( entry ), entry, 0 } );
        }
    }
    while( idx-- > 0 );
}

int Worker::AddGhostZone( const VarArray<CallstackFrameId>& cs, Vector<GhostZone>* vec, uint64_t t )
{
    static Vector<InlineStackData> stack;
    GetStackWithInlines( stack, cs );

    if( !vec->empty() && vec->back().end.Val() > (int64_t)t )
    {
        const auto refBackTime = vec->back().end.Val();
        auto tmp = vec;
        for(;;)
        {
            auto& back = tmp->back();
            if( back.end.Val() != refBackTime ) break;
            back.end.SetVal( t );
            if( back.child < 0 ) break;
            tmp = &m_data.ghostChildren[back.child];
        }
    }
    const int64_t refBackTime = vec->empty() ? 0 : vec->back().end.Val();
    int gcnt = 0;
    size_t idx = 0;
    while( !vec->empty() && idx < stack.size() )
    {
        auto& back = vec->back();
        const auto& backKey = m_data.ghostFrames[back.frame.Val()];
        const auto backFrame = GetCallstackFrame( backKey.frame );
        if( !backFrame ) break;
        const auto& inlineFrame = backFrame->data[backKey.inlineFrame];
        if( inlineFrame.symAddr != stack[idx].symAddr ) break;
        if( back.end.Val() != refBackTime ) break;
        back.end.SetVal( t + m_samplingPeriod );
        if( ++idx == stack.size() ) break;
        if( back.child < 0 )
        {
            back.child = m_data.ghostChildren.size();
            vec = &m_data.ghostChildren.push_next();
        }
        else
        {
            vec = &m_data.ghostChildren[back.child];
        }
    }
    while( idx < stack.size() )
    {
        gcnt++;
        uint32_t fid;
        GhostKey key { stack[idx].frame, stack[idx].inlineFrame };
        auto it = m_data.ghostFramesMap.find( key );
        if( it == m_data.ghostFramesMap.end() )
        {
            fid = uint32_t( m_data.ghostFrames.size() );
            m_data.ghostFrames.push_back( key );
            m_data.ghostFramesMap.emplace( key, fid );
        }
        else
        {
            fid = it->second;
        }
        auto& zone = vec->push_next();
        zone.start.SetVal( t );
        zone.end.SetVal( t + m_samplingPeriod );
        zone.frame.SetVal( fid );
        if( ++idx == stack.size() )
        {
            zone.child = -1;
        }
        else
        {
            zone.child = m_data.ghostChildren.size();
            vec = &m_data.ghostChildren.push_next();
        }
    }
    return gcnt;
}

void Worker::HandlePostponedGhostZones()
{
    assert( m_data.newFramesWereReceived );
    if( !m_data.ghostZonesPostponed ) return;
    bool postponed = false;
    for( auto& td : m_data.threads )
    {
        while( td->ghostIdx != td->samples.size() )
        {
            const auto& sample = td->samples[td->ghostIdx];
            const auto& cs = GetCallstack( sample.callstack.Val() );
            const auto cssz = cs.size();

            uint16_t i;
            for( i=0; i<cssz; i++ ) if( !GetCallstackFrame( cs[i] ) ) break;
            if( i != cssz )
            {
                postponed = true;
                break;
            }

            td->ghostIdx++;
            m_data.ghostCnt += AddGhostZone( cs, &td->ghostZones, sample.time.Val() );
        }
    }
    m_data.ghostZonesPostponed = postponed;
}
#endif

uint32_t Worker::GetSingleStringIdx()
{
    assert( m_pendingSingleString.ptr != nullptr );
    const auto idx = m_pendingSingleString.idx;
    m_pendingSingleString.ptr = nullptr;
    return idx;
}

uint32_t Worker::GetSecondStringIdx()
{
    assert( m_pendingSecondString.ptr != nullptr );
    const auto idx = m_pendingSecondString.idx;
    m_pendingSecondString.ptr = nullptr;
    return idx;
}

StringLocation Worker::StoreString( const char* str, size_t sz )
{
    StringLocation ret;
    charutil::StringKey key = { str, sz };
    auto sit = m_data.stringMap.find( key );
    if( sit == m_data.stringMap.end() )
    {
        auto ptr = m_slab.Alloc<char>( sz+1 );
        memcpy( ptr, str, sz );
        ptr[sz] = '\0';
        ret.ptr = ptr;
        ret.idx = m_data.stringData.size();
        m_data.stringMap.emplace( charutil::StringKey { ptr, sz }, m_data.stringData.size() );
        m_data.stringData.push_back( ptr );
    }
    else
    {
        ret.ptr = sit->first.ptr;
        ret.idx = sit->second;
    }
    return ret;
}

bool Worker::Process( const QueueItem& ev )
{
    switch( ev.hdr.type )
    {
    case QueueType::ThreadContext:
        ProcessThreadContext( ev.threadCtx );
        break;
    case QueueType::ZoneBegin:
        ProcessZoneBegin( ev.zoneBegin );
        break;
    case QueueType::ZoneBeginCallstack:
        ProcessZoneBeginCallstack( ev.zoneBegin );
        break;
    case QueueType::ZoneBeginAllocSrcLoc:
        ProcessZoneBeginAllocSrcLoc( ev.zoneBeginLean );
        break;
    case QueueType::ZoneBeginAllocSrcLocCallstack:
        ProcessZoneBeginAllocSrcLocCallstack( ev.zoneBeginLean );
        break;
    case QueueType::ZoneEnd:
        ProcessZoneEnd( ev.zoneEnd );
        break;
    case QueueType::ZoneValidation:
        ProcessZoneValidation( ev.zoneValidation );
        break;
    case QueueType::FrameMarkMsg:
        ProcessFrameMark( ev.frameMark );
        break;
    case QueueType::FrameMarkMsgStart:
        ProcessFrameMarkStart( ev.frameMark );
        break;
    case QueueType::FrameMarkMsgEnd:
        ProcessFrameMarkEnd( ev.frameMark );
        break;
    case QueueType::FrameVsync:
        ProcessFrameVsync( ev.frameVsync );
        break;
    case QueueType::FrameImage:
        ProcessFrameImage( ev.frameImage );
        break;
    case QueueType::SourceLocation:
        AddSourceLocation( ev.srcloc );
        m_serverQuerySpaceLeft++;
        break;
    case QueueType::ZoneText:
        ProcessZoneText();
        break;
    case QueueType::ZoneName:
        ProcessZoneName();
        break;
    case QueueType::ZoneColor:
        ProcessZoneColor( ev.zoneColor );
        break;
    case QueueType::ZoneValue:
        ProcessZoneValue( ev.zoneValue );
        break;
    case QueueType::LockAnnounce:
        ProcessLockAnnounce( ev.lockAnnounce );
        break;
    case QueueType::LockTerminate:
        ProcessLockTerminate( ev.lockTerminate );
        break;
    case QueueType::LockWait:
        ProcessLockWait( ev.lockWait );
        break;
    case QueueType::LockObtain:
        ProcessLockObtain( ev.lockObtain );
        break;
    case QueueType::LockRelease:
        ProcessLockRelease( ev.lockRelease );
        break;
    case QueueType::LockSharedWait:
        ProcessLockSharedWait( ev.lockWait );
        break;
    case QueueType::LockSharedObtain:
        ProcessLockSharedObtain( ev.lockObtain );
        break;
    case QueueType::LockSharedRelease:
        ProcessLockSharedRelease( ev.lockReleaseShared );
        break;
    case QueueType::LockMark:
        ProcessLockMark( ev.lockMark );
        break;
    case QueueType::LockName:
        ProcessLockName( ev.lockName );
        break;
    case QueueType::PlotDataInt:
        ProcessPlotDataInt( ev.plotDataInt );
        break;
    case QueueType::PlotDataFloat:
        ProcessPlotDataFloat( ev.plotDataFloat );
        break;
    case QueueType::PlotDataDouble:
        ProcessPlotDataDouble( ev.plotDataDouble );
        break;
    case QueueType::PlotConfig:
        ProcessPlotConfig( ev.plotConfig );
        break;
    case QueueType::Message:
        ProcessMessage( ev.message );
        break;
    case QueueType::MessageLiteral:
        ProcessMessageLiteral( ev.messageLiteral );
        break;
    case QueueType::MessageColor:
        ProcessMessageColor( ev.messageColor );
        break;
    case QueueType::MessageLiteralColor:
        ProcessMessageLiteralColor( ev.messageColorLiteral );
        break;
    case QueueType::MessageCallstack:
        ProcessMessageCallstack( ev.message );
        break;
    case QueueType::MessageLiteralCallstack:
        ProcessMessageLiteralCallstack( ev.messageLiteral );
        break;
    case QueueType::MessageColorCallstack:
        ProcessMessageColorCallstack( ev.messageColor );
        break;
    case QueueType::MessageLiteralColorCallstack:
        ProcessMessageLiteralColorCallstack( ev.messageColorLiteral );
        break;
    case QueueType::MessageAppInfo:
        ProcessMessageAppInfo( ev.message );
        break;
    case QueueType::GpuNewContext:
        ProcessGpuNewContext( ev.gpuNewContext );
        break;
    case QueueType::GpuZoneBegin:
        ProcessGpuZoneBegin( ev.gpuZoneBegin, false );
        break;
    case QueueType::GpuZoneBeginCallstack:
        ProcessGpuZoneBeginCallstack( ev.gpuZoneBegin, false );
        break;
    case QueueType::GpuZoneBeginAllocSrcLoc:
        ProcessGpuZoneBeginAllocSrcLoc( ev.gpuZoneBeginLean, false );
        break;
    case QueueType::GpuZoneBeginAllocSrcLocCallstack:
        ProcessGpuZoneBeginAllocSrcLocCallstack( ev.gpuZoneBeginLean, false );
        break;
    case QueueType::GpuZoneEnd:
        ProcessGpuZoneEnd( ev.gpuZoneEnd, false );
        break;
    case QueueType::GpuZoneBeginSerial:
        ProcessGpuZoneBegin( ev.gpuZoneBegin, true );
        break;
    case QueueType::GpuZoneBeginCallstackSerial:
        ProcessGpuZoneBeginCallstack( ev.gpuZoneBegin, true );
        break;
    case QueueType::GpuZoneBeginAllocSrcLocSerial:
        ProcessGpuZoneBeginAllocSrcLoc( ev.gpuZoneBeginLean, true );
        break;
    case QueueType::GpuZoneBeginAllocSrcLocCallstackSerial:
        ProcessGpuZoneBeginAllocSrcLocCallstack( ev.gpuZoneBeginLean, true );
        break;
    case QueueType::GpuZoneEndSerial:
        ProcessGpuZoneEnd( ev.gpuZoneEnd, true );
        break;
    case QueueType::GpuTime:
        ProcessGpuTime( ev.gpuTime );
        break;
    case QueueType::GpuCalibration:
        ProcessGpuCalibration( ev.gpuCalibration );
        break;
    case QueueType::GpuContextName:
        ProcessGpuContextName( ev.gpuContextName );
        break;
    case QueueType::MemAlloc:
        ProcessMemAlloc( ev.memAlloc );
        break;
    case QueueType::MemAllocNamed:
        ProcessMemAllocNamed( ev.memAlloc );
        break;
    case QueueType::MemFree:
        ProcessMemFree( ev.memFree );
        break;
    case QueueType::MemFreeNamed:
        ProcessMemFreeNamed( ev.memFree );
        break;
    case QueueType::MemAllocCallstack:
        ProcessMemAllocCallstack( ev.memAlloc );
        break;
    case QueueType::MemAllocCallstackNamed:
        ProcessMemAllocCallstackNamed( ev.memAlloc );
        break;
    case QueueType::MemFreeCallstack:
        ProcessMemFreeCallstack( ev.memFree );
        break;
    case QueueType::MemFreeCallstackNamed:
        ProcessMemFreeCallstackNamed( ev.memFree );
        break;
    case QueueType::CallstackSerial:
        ProcessCallstackSerial();
        break;
    case QueueType::Callstack:
    case QueueType::CallstackAlloc:
        ProcessCallstack();
        break;
    case QueueType::CallstackSample:
        ProcessCallstackSample( ev.callstackSample );
        break;
    case QueueType::CallstackSampleContextSwitch:
        ProcessCallstackSampleContextSwitch( ev.callstackSample );
        break;
    case QueueType::CallstackFrameSize:
        ProcessCallstackFrameSize( ev.callstackFrameSize );
        m_serverQuerySpaceLeft++;
        break;
    case QueueType::CallstackFrame:
        ProcessCallstackFrame( ev.callstackFrame, true );
        break;
    case QueueType::SymbolInformation:
        ProcessSymbolInformation( ev.symbolInformation );
        m_serverQuerySpaceLeft++;
        break;
    case QueueType::Terminate:
        m_terminate = true;
        break;
    case QueueType::KeepAlive:
        break;
    case QueueType::Crash:
        m_crashed = true;
        break;
    case QueueType::CrashReport:
        ProcessCrashReport( ev.crashReport );
        break;
    case QueueType::SysTimeReport:
        ProcessSysTime( ev.sysTime );
        break;
    case QueueType::ContextSwitch:
        ProcessContextSwitch( ev.contextSwitch );
        break;
    case QueueType::ThreadWakeup:
        ProcessThreadWakeup( ev.threadWakeup );
        break;
    case QueueType::TidToPid:
        ProcessTidToPid( ev.tidToPid );
        break;
    case QueueType::HwSampleCpuCycle:
        ProcessHwSampleCpuCycle( ev.hwSample );
        break;
    case QueueType::HwSampleInstructionRetired:
        ProcessHwSampleInstructionRetired( ev.hwSample );
        break;
    case QueueType::HwSampleCacheReference:
        ProcessHwSampleCacheReference( ev.hwSample );
        break;
    case QueueType::HwSampleCacheMiss:
        ProcessHwSampleCacheMiss( ev.hwSample );
        break;
    case QueueType::HwSampleBranchRetired:
        ProcessHwSampleBranchRetired( ev.hwSample );
        break;
    case QueueType::HwSampleBranchMiss:
        ProcessHwSampleBranchMiss( ev.hwSample );
        break;
    case QueueType::ParamSetup:
        ProcessParamSetup( ev.paramSetup );
        break;
    case QueueType::AckServerQueryNoop:
        m_serverQuerySpaceLeft++;
        break;
    case QueueType::AckSourceCodeNotAvailable:
        ProcessSourceCodeNotAvailable( ev.sourceCodeNotAvailable );
        m_serverQuerySpaceLeft++;
        break;
    case QueueType::AckSymbolCodeNotAvailable:
        m_pendingSymbolCode--;
        m_serverQuerySpaceLeft++;
        break;
    case QueueType::CpuTopology:
        ProcessCpuTopology( ev.cpuTopology );
        break;
    case QueueType::MemNamePayload:
        ProcessMemNamePayload( ev.memName );
        break;
    case QueueType::FiberEnter:
        ProcessFiberEnter( ev.fiberEnter );
        break;
    case QueueType::FiberLeave:
        ProcessFiberLeave( ev.fiberLeave );
        break;
    default:
        assert( false );
        break;
    }

    return m_failure == Failure::None;
}

void Worker::ProcessThreadContext( const QueueThreadContext& ev )
{
    m_refTimeThread = 0;
    if( m_threadCtx != ev.thread )
    {
        m_threadCtx = ev.thread;
        m_threadCtxData = RetrieveThread( ev.thread );
    }
}

static tracy_force_inline int64_t RefTime( int64_t& reference, int64_t delta )
{
    const auto refTime = reference + delta;
    reference = refTime;
    return refTime;
}

void Worker::ProcessZoneBeginImpl( ZoneEvent* zone, const QueueZoneBegin& ev )
{
    CheckSourceLocation( ev.srcloc );

    const auto start = TscTime( RefTime( m_refTimeThread, ev.time ) );
    zone->SetStartSrcLoc( start, ShrinkSourceLocation( ev.srcloc ) );
    zone->SetEnd( -1 );
    zone->SetChild( -1 );

    if( m_data.lastTime < start ) m_data.lastTime = start;

    NewZone( zone );
}

void Worker::ProcessZoneBeginAllocSrcLocImpl( ZoneEvent* zone, const QueueZoneBeginLean& ev )
{
    assert( m_pendingSourceLocationPayload != 0 );

    const auto start = TscTime( RefTime( m_refTimeThread, ev.time ) );
    zone->SetStartSrcLoc( start, m_pendingSourceLocationPayload );
    zone->SetEnd( -1 );
    zone->SetChild( -1 );

    if( m_data.lastTime < start ) m_data.lastTime = start;

    NewZone( zone );

    m_pendingSourceLocationPayload = 0;
}

ZoneEvent* Worker::AllocZoneEvent()
{
    ZoneEvent* ret;
#ifndef TRACY_NO_STATISTICS
    ret = m_slab.Alloc<ZoneEvent>();
#else
    if( m_zoneEventPool.empty() )
    {
        ret = m_slab.Alloc<ZoneEvent>();
    }
    else
    {
        ret = m_zoneEventPool.back_and_pop();
    }
#endif
    ret->extra = 0;
    return ret;
}

void Worker::ProcessZoneBegin( const QueueZoneBegin& ev )
{
    auto zone = AllocZoneEvent();
    ProcessZoneBeginImpl( zone, ev );
}

void Worker::ProcessZoneBeginCallstack( const QueueZoneBegin& ev )
{
    auto zone = AllocZoneEvent();
    ProcessZoneBeginImpl( zone, ev );
    auto td = GetCurrentThreadData();
    auto it = m_nextCallstack.find( td->id );
    assert( it != m_nextCallstack.end() );
    auto& extra = RequestZoneExtra( *zone );
    extra.callstack.SetVal( it->second );
    it->second = 0;
}

void Worker::ProcessZoneBeginAllocSrcLoc( const QueueZoneBeginLean& ev )
{
    auto zone = AllocZoneEvent();
    ProcessZoneBeginAllocSrcLocImpl( zone, ev );
}

void Worker::ProcessZoneBeginAllocSrcLocCallstack( const QueueZoneBeginLean& ev )
{
    auto zone = AllocZoneEvent();
    ProcessZoneBeginAllocSrcLocImpl( zone, ev );
    auto td = GetCurrentThreadData();
    auto it = m_nextCallstack.find( td->id );
    assert( it != m_nextCallstack.end() );
    auto& extra = RequestZoneExtra( *zone );
    extra.callstack.SetVal( it->second );
    it->second = 0;
}

void Worker::ProcessZoneEnd( const QueueZoneEnd& ev )
{
    auto td = GetCurrentThreadData();
    if( td->zoneIdStack.empty() )
    {
        ZoneDoubleEndFailure( td->id, td->timeline.empty() ? nullptr : td->timeline.back() );
        return;
    }
    auto zoneId = td->zoneIdStack.back_and_pop();
    if( zoneId != td->nextZoneId )
    {
        ZoneStackFailure( td->id, td->stack.back() );
        return;
    }
    td->nextZoneId = 0;

    auto& stack = td->stack;
    assert( !stack.empty() );
    auto zone = stack.back_and_pop();
    assert( zone->End() == -1 );
    const auto isReentry = td->DecStackCount( zone->SrcLoc() );
    const auto timeEnd = TscTime( RefTime( m_refTimeThread, ev.time ) );
    zone->SetEnd( timeEnd );
    assert( timeEnd >= zone->Start() );

    if( m_data.lastTime < timeEnd ) m_data.lastTime = timeEnd;

    if( zone->HasChildren() )
    {
        auto& childVec = m_data.zoneChildren[zone->Child()];
        const auto sz = childVec.size();
        if( sz <= 8 * 1024 )
        {
            Vector<short_ptr<ZoneEvent>> fitVec;
#ifndef TRACY_NO_STATISTICS
            fitVec.reserve_exact( sz, m_slab );
            memcpy( fitVec.data(), childVec.data(), sz * sizeof( short_ptr<ZoneEvent> ) );
#else
            fitVec.set_magic();
            auto& fv = *((Vector<ZoneEvent>*)&fitVec);
            fv.reserve_exact( sz, m_slab );
            auto dst = fv.data();
            for( auto& ze : childVec )
            {
                ZoneEvent* src = ze;
                memcpy( dst++, src, sizeof( ZoneEvent ) );
                m_zoneEventPool.push_back( src );
            }
#endif
            fitVec.swap( childVec );
            m_data.zoneVectorCache.push_back( std::move( fitVec ) );
        }
    }

#ifndef TRACY_NO_STATISTICS
    assert( !td->childTimeStack.empty() );
    const auto timeSpan = timeEnd - zone->Start();
    if( timeSpan > 0 )
    {
        ZoneThreadData ztd;
        ztd.SetZone( zone );
        ztd.SetThread( CompressThread( td->id ) );
        auto slz = GetSourceLocationZones( zone->SrcLoc() );
        slz->zones.push_back( ztd );
        if( slz->min > timeSpan ) slz->min = timeSpan;
        if( slz->max < timeSpan ) slz->max = timeSpan;
        slz->total += timeSpan;
        slz->sumSq += double( timeSpan ) * timeSpan;
        const auto selfSpan = timeSpan - td->childTimeStack.back_and_pop();
        if( slz->selfMin > selfSpan ) slz->selfMin = selfSpan;
        if( slz->selfMax < selfSpan ) slz->selfMax = selfSpan;
        slz->selfTotal += selfSpan;
        if( !isReentry )
        {
            slz->nonReentrantCount++;
            if( slz->nonReentrantMin > timeSpan ) slz->nonReentrantMin = timeSpan;
            if( slz->nonReentrantMax < timeSpan ) slz->nonReentrantMax = timeSpan;
            slz->nonReentrantTotal += timeSpan;
        }
        if( !td->childTimeStack.empty() )
        {
            td->childTimeStack.back() += timeSpan;
        }
    }
    else
    {
        td->childTimeStack.pop_back();
    }
#else
    CountZoneStatistics( zone );
#endif
}

void Worker::ZoneStackFailure( uint64_t thread, const ZoneEvent* ev )
{
    m_failure = Failure::ZoneStack;
    m_failureData.thread = thread;
    m_failureData.srcloc = ev->SrcLoc();
}

void Worker::ZoneDoubleEndFailure( uint64_t thread, const ZoneEvent* ev )
{
    m_failure = Failure::ZoneDoubleEnd;
    m_failureData.thread = thread;
    m_failureData.srcloc = ev ? ev->SrcLoc() : 0;
}

void Worker::ZoneTextFailure( uint64_t thread, const char* text )
{
    m_failure = Failure::ZoneText;
    m_failureData.thread = thread;
    m_failureData.message = text;
}

void Worker::ZoneValueFailure( uint64_t thread, uint64_t value )
{
    char buf[128];
    if( (int64_t)value < 0 )
    {
        sprintf( buf, "Zone value was: %" PRIu64 " (unsigned), %" PRIi64 " (signed)", value, (int64_t)value );
    }
    else
    {
        sprintf( buf, "Zone value was: %" PRIu64, value );
    }

    m_failure = Failure::ZoneValue;
    m_failureData.thread = thread;
    m_failureData.message = buf;
}

void Worker::ZoneColorFailure( uint64_t thread )
{
    m_failure = Failure::ZoneColor;
    m_failureData.thread = thread;
}

void Worker::ZoneNameFailure( uint64_t thread )
{
    m_failure = Failure::ZoneName;
    m_failureData.thread = thread;
}

void Worker::MemFreeFailure( uint64_t thread )
{
    m_failure = Failure::MemFree;
    m_failureData.thread = thread;
    m_failureData.callstack = m_serialNextCallstack;
}

void Worker::MemAllocTwiceFailure( uint64_t thread )
{
    m_failure = Failure::MemAllocTwice;
    m_failureData.thread = thread;
    m_failureData.callstack = m_serialNextCallstack;
}

void Worker::FrameEndFailure()
{
    m_failure = Failure::FrameEnd;
}

void Worker::FrameImageIndexFailure()
{
    m_failure = Failure::FrameImageIndex;
}

void Worker::FrameImageTwiceFailure()
{
    m_failure = Failure::FrameImageTwice;
}

void Worker::FiberLeaveFailure()
{
    m_failure = Failure::FiberLeave;
}

void Worker::ProcessZoneValidation( const QueueZoneValidation& ev )
{
    auto td = GetCurrentThreadData();
    td->nextZoneId = ev.id;
}

void Worker::ProcessFrameMark( const QueueFrameMark& ev )
{
    auto fd = m_data.frames.Retrieve( ev.name, [this] ( uint64_t name ) {
        auto fd = m_slab.AllocInit<FrameData>();
        fd->name = name;
        fd->continuous = 1;
        return fd;
    }, [this] ( uint64_t name ) {
        Query( ServerQueryFrameName, name );
    } );

    int32_t frameImage = -1;
    if( ev.name == 0 )
    {
        auto fis = m_frameImageStaging.find( fd->frames.size() );
        if( fis != m_frameImageStaging.end() )
        {
            frameImage = fis->second;
            m_frameImageStaging.erase( fis );
        }
    }

    assert( fd->continuous == 1 );
    const auto time = TscTime( ev.time );
    assert( fd->frames.empty() || fd->frames.back().start <= time );
    fd->frames.push_back( FrameEvent{ time, -1, frameImage } );
    if( m_data.lastTime < time ) m_data.lastTime = time;

#ifndef TRACY_NO_STATISTICS
    const auto timeSpan = GetFrameTime( *fd, fd->frames.size() - 1 );
    if( timeSpan > 0 )
    {
        fd->min = std::min( fd->min, timeSpan );
        fd->max = std::max( fd->max, timeSpan );
        fd->total += timeSpan;
        fd->sumSq += double( timeSpan ) * timeSpan;
    }
#endif
}

void Worker::ProcessFrameMarkStart( const QueueFrameMark& ev )
{
    auto fd = m_data.frames.Retrieve( ev.name, [this] ( uint64_t name ) {
        auto fd = m_slab.AllocInit<FrameData>();
        fd->name = name;
        fd->continuous = 0;
        return fd;
    }, [this] ( uint64_t name ) {
        Query( ServerQueryFrameName, name );
    } );

    assert( fd->continuous == 0 );
    const auto time = TscTime( ev.time );
    assert( fd->frames.empty() || ( fd->frames.back().end <= time && fd->frames.back().end != -1 ) );
    fd->frames.push_back( FrameEvent{ time, -1, -1 } );
    if( m_data.lastTime < time ) m_data.lastTime = time;
}

void Worker::ProcessFrameMarkEnd( const QueueFrameMark& ev )
{
    auto fd = m_data.frames.Retrieve( ev.name, [this] ( uint64_t name ) {
        auto fd = m_slab.AllocInit<FrameData>();
        fd->name = name;
        fd->continuous = 0;
        return fd;
    }, [this] ( uint64_t name ) {
        Query( ServerQueryFrameName, name );
    } );

    assert( fd->continuous == 0 );
    const auto time = TscTime( ev.time );
    if( fd->frames.empty() )
    {
        FrameEndFailure();
        return;
    }
    assert( fd->frames.back().end == -1 );
    fd->frames.back().end = time;
    if( m_data.lastTime < time ) m_data.lastTime = time;

#ifndef TRACY_NO_STATISTICS
    const auto timeSpan = GetFrameTime( *fd, fd->frames.size() - 1 );
    if( timeSpan > 0 )
    {
        fd->min = std::min( fd->min, timeSpan );
        fd->max = std::max( fd->max, timeSpan );
        fd->total += timeSpan;
        fd->sumSq += double( timeSpan ) * timeSpan;
    }
#endif
}

void Worker::ProcessFrameVsync( const QueueFrameVsync& ev )
{
    auto it = m_vsyncFrameMap.find( ev.id );
    if( it == m_vsyncFrameMap.end() )
    {
        auto fd = m_slab.AllocInit<FrameData>();
        // Hackfix workaround to maintain backwards compatibility.
        // Frame name pointers won't be in kernel space. Exploit that to store custom IDs.
        fd->name = uint64_t( m_vsyncFrameMap.size() ) | 0x8000000000000000;
        fd->continuous = 1;
        m_data.frames.AddExternal( fd );
        it = m_vsyncFrameMap.emplace( ev.id, fd ).first;
    }
    auto fd = it->second;
    assert( fd->continuous == 1 );
    const auto time = TscTime( ev.time );
    assert( fd->frames.empty() || fd->frames.back().start <= time );
    fd->frames.push_back( FrameEvent{ time, -1, -1 } );
    if( m_data.lastTime < time ) m_data.lastTime = time;

#ifndef TRACY_NO_STATISTICS
    const auto timeSpan = GetFrameTime( *fd, fd->frames.size() - 1 );
    if( timeSpan > 0 )
    {
        fd->min = std::min( fd->min, timeSpan );
        fd->max = std::max( fd->max, timeSpan );
        fd->total += timeSpan;
        fd->sumSq += double( timeSpan ) * timeSpan;
    }
#endif
}

void Worker::ProcessFrameImage( const QueueFrameImage& ev )
{
    assert( m_pendingFrameImageData.image != nullptr );

    auto& frames = m_data.framesBase->frames;
    const auto fidx = int64_t( ev.frame ) - int64_t( m_data.frameOffset ) + 1;
    if( m_onDemand && fidx <= 1 )
    {
        m_pendingFrameImageData.image = nullptr;
        return;
    }
    else if( fidx <= 0 )
    {
        FrameImageIndexFailure();
        return;
    }

    auto fi = m_slab.Alloc<FrameImage>();
    fi->ptr = m_pendingFrameImageData.image;
    fi->csz = m_pendingFrameImageData.csz;
    fi->w = ev.w;
    fi->h = ev.h;
    fi->frameRef = uint32_t( fidx );
    fi->flip = ev.flip;

    const auto idx = m_data.frameImage.size();
    m_data.frameImage.push_back( fi );
    m_pendingFrameImageData.image = nullptr;

    if( fidx >= (int64_t)frames.size() )
    {
        if( m_frameImageStaging.find( fidx ) != m_frameImageStaging.end() )
        {
            FrameImageTwiceFailure();
            return;
        }
        m_frameImageStaging.emplace( fidx, idx );
    }
    else if( frames[fidx].frameImage >= 0 )
    {
        FrameImageTwiceFailure();
    }
    else
    {
        frames[fidx].frameImage = idx;
    }
}

void Worker::ProcessZoneText()
{
    auto td = RetrieveThread( m_threadCtx );
    if( !td )
    {
        ZoneTextFailure( m_threadCtx, m_pendingSingleString.ptr );
        return;
    }
    if( td->fiber ) td = td->fiber;
    if( td->stack.empty() || td->nextZoneId != td->zoneIdStack.back() )
    {
        ZoneTextFailure( td->id, m_pendingSingleString.ptr );
        return;
    }

    const auto ptr = m_pendingSingleString.ptr;
    const auto idx = GetSingleStringIdx();

    td->nextZoneId = 0;
    auto& stack = td->stack;
    auto zone = stack.back();
    auto& extra = RequestZoneExtra( *zone );
    if( !extra.text.Active() )
    {
        extra.text = StringIdx( idx );
    }
    else
    {
        const auto str0 = GetString( extra.text );
        const auto str1 = ptr;
        const auto len0 = strlen( str0 );
        const auto len1 = strlen( str1 );
        const auto bsz = len0+len1+1;
        if( m_tmpBufSize < bsz )
        {
            delete[] m_tmpBuf;
            m_tmpBuf = new char[bsz];
            m_tmpBufSize = bsz;
        }
        char* buf = m_tmpBuf;
        memcpy( buf, str0, len0 );
        buf[len0] = '\n';
        memcpy( buf+len0+1, str1, len1 );
        extra.text = StringIdx( StoreString( buf, bsz ).idx );
    }
}

void Worker::ProcessZoneName()
{
    auto td = RetrieveThread( m_threadCtx );
    if( !td )
    {
        ZoneNameFailure( m_threadCtx );
        return;
    }
    if( td->fiber ) td = td->fiber;
    if( td->stack.empty() || td->nextZoneId != td->zoneIdStack.back() )
    {
        ZoneNameFailure( td->id );
        return;
    }

    td->nextZoneId = 0;
    auto& stack = td->stack;
    auto zone = stack.back();
    auto& extra = RequestZoneExtra( *zone );
    extra.name = StringIdx( GetSingleStringIdx() );
}

void Worker::ProcessZoneColor( const QueueZoneColor& ev )
{
    auto td = RetrieveThread( m_threadCtx );
    if( !td )
    {
        ZoneColorFailure( m_threadCtx );
        return;
    }
    if( td->fiber ) td = td->fiber;
    if( td->stack.empty() || td->nextZoneId != td->zoneIdStack.back() )
    {
        ZoneColorFailure( td->id );
        return;
    }

    td->nextZoneId = 0;
    auto& stack = td->stack;
    auto zone = stack.back();
    auto& extra = RequestZoneExtra( *zone );
    const uint32_t color = ( ev.b << 16 ) | ( ev.g << 8 ) | ev.r;
    extra.color = color;
}

void Worker::ProcessZoneValue( const QueueZoneValue& ev )
{
    char tmp[32];
    const auto tsz = sprintf( tmp, "%" PRIu64, ev.value );

    auto td = RetrieveThread( m_threadCtx );
    if( !td )
    {
        ZoneValueFailure( m_threadCtx, ev.value );
        return;
    }
    if( td->fiber ) td = td->fiber;
    if( td->stack.empty() || td->nextZoneId != td->zoneIdStack.back() )
    {
        ZoneValueFailure( td->id, ev.value );
        return;
    }

    td->nextZoneId = 0;
    auto& stack = td->stack;
    auto zone = stack.back();
    auto& extra = RequestZoneExtra( *zone );
    if( !extra.text.Active() )
    {
        extra.text = StringIdx( StoreString( tmp, tsz ).idx );
    }
    else
    {
        const auto str0 = GetString( extra.text );
        const auto len0 = strlen( str0 );
        const auto bsz = len0+tsz+1;
        if( m_tmpBufSize < bsz )
        {
            delete[] m_tmpBuf;
            m_tmpBuf = new char[bsz];
            m_tmpBufSize = bsz;
        }
        char* buf = m_tmpBuf;
        memcpy( buf, str0, len0 );
        buf[len0] = '\n';
        memcpy( buf+len0+1, tmp, tsz );
        extra.text = StringIdx( StoreString( buf, bsz ).idx );
    }
}

void Worker::ProcessLockAnnounce( const QueueLockAnnounce& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it == m_data.lockMap.end() );
    auto lm = m_slab.AllocInit<LockMap>();
    lm->srcloc = ShrinkSourceLocation( ev.lckloc );
    lm->type = ev.type;
    lm->timeAnnounce = TscTime( ev.time );
    lm->timeTerminate = 0;
    lm->valid = true;
    lm->isContended = false;
    lm->lockingThread = 0;
    m_data.lockMap.emplace( ev.id, lm );
    CheckSourceLocation( ev.lckloc );
}

void Worker::ProcessLockTerminate( const QueueLockTerminate& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    it->second->timeTerminate = TscTime( ev.time );
}

void Worker::ProcessLockWait( const QueueLockWait& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    auto& lock = *it->second;

    auto lev = lock.type == LockType::Lockable ? m_slab.Alloc<LockEvent>() : m_slab.Alloc<LockEventShared>();
    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    lev->SetTime( time );
    lev->SetSrcLoc( 0 );
    lev->type = LockEvent::Type::Wait;

    InsertLockEvent( lock, lev, ev.thread, time );
}

void Worker::ProcessLockObtain( const QueueLockObtain& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    auto& lock = *it->second;

    auto lev = lock.type == LockType::Lockable ? m_slab.Alloc<LockEvent>() : m_slab.Alloc<LockEventShared>();
    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    lev->SetTime( time );
    lev->SetSrcLoc( 0 );
    lev->type = LockEvent::Type::Obtain;

    InsertLockEvent( lock, lev, ev.thread, time );
    lock.lockingThread = ev.thread;
}

void Worker::ProcessLockRelease( const QueueLockRelease& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    auto& lock = *it->second;

    auto lev = lock.type == LockType::Lockable ? m_slab.Alloc<LockEvent>() : m_slab.Alloc<LockEventShared>();
    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    lev->SetTime( time );
    lev->SetSrcLoc( 0 );
    lev->type = LockEvent::Type::Release;

    InsertLockEvent( lock, lev, lock.lockingThread, time );
}

void Worker::ProcessLockSharedWait( const QueueLockWait& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    auto& lock = *it->second;

    assert( lock.type == LockType::SharedLockable );
    auto lev = m_slab.Alloc<LockEventShared>();
    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    lev->SetTime( time );
    lev->SetSrcLoc( 0 );
    lev->type = LockEvent::Type::WaitShared;

    InsertLockEvent( lock, lev, ev.thread, time );
}

void Worker::ProcessLockSharedObtain( const QueueLockObtain& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    auto& lock = *it->second;

    assert( lock.type == LockType::SharedLockable );
    auto lev = m_slab.Alloc<LockEventShared>();
    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    lev->SetTime( time );
    lev->SetSrcLoc( 0 );
    lev->type = LockEvent::Type::ObtainShared;

    InsertLockEvent( lock, lev, ev.thread, time );
}

void Worker::ProcessLockSharedRelease( const QueueLockReleaseShared& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    assert( it != m_data.lockMap.end() );
    auto& lock = *it->second;

    assert( lock.type == LockType::SharedLockable );
    auto lev = m_slab.Alloc<LockEventShared>();
    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    lev->SetTime( time );
    lev->SetSrcLoc( 0 );
    lev->type = LockEvent::Type::ReleaseShared;

    InsertLockEvent( lock, lev, ev.thread, time );
}

void Worker::ProcessLockMark( const QueueLockMark& ev )
{
    CheckSourceLocation( ev.srcloc );
    auto lit = m_data.lockMap.find( ev.id );
    assert( lit != m_data.lockMap.end() );
    auto& lockmap = *lit->second;
    auto tid = lockmap.threadMap.find( ev.thread );
    assert( tid != lockmap.threadMap.end() );
    const auto thread = tid->second;
    auto it = lockmap.timeline.end();
    for(;;)
    {
        --it;
        if( it->ptr->thread == thread )
        {
            switch( it->ptr->type )
            {
            case LockEvent::Type::Obtain:
            case LockEvent::Type::ObtainShared:
            case LockEvent::Type::Wait:
            case LockEvent::Type::WaitShared:
                it->ptr->SetSrcLoc( ShrinkSourceLocation( ev.srcloc ) );
                return;
            default:
                break;
            }
        }
    }
}

void Worker::ProcessLockName( const QueueLockName& ev )
{
    auto lit = m_data.lockMap.find( ev.id );
    assert( lit != m_data.lockMap.end() );
    lit->second->customName = StringIdx( GetSingleStringIdx() );
}

void Worker::ProcessPlotDataInt( const QueuePlotDataInt& ev )
{
    ProcessPlotDataImpl( ev.name, ev.time, (double)ev.val );
}

void Worker::ProcessPlotDataFloat( const QueuePlotDataFloat& ev )
{
    if( !isfinite( ev.val ) ) return;
    ProcessPlotDataImpl( ev.name, ev.time, (double)ev.val );
}

void Worker::ProcessPlotDataDouble( const QueuePlotDataDouble& ev )
{
    if( !isfinite( ev.val ) ) return;
    ProcessPlotDataImpl( ev.name, ev.time, ev.val );
}

void Worker::ProcessPlotDataImpl( uint64_t name, int64_t evTime, double val )
{
    PlotData* plot = m_data.plots.Retrieve( name, [this] ( uint64_t name ) {
        auto plot = m_slab.AllocInit<PlotData>();
        plot->name = name;
        plot->type = PlotType::User;
        plot->format = PlotValueFormatting::Number;
        plot->showSteps = false;
        plot->fill = true;
        plot->color = 0;
        return plot;
    }, [this]( uint64_t name ) {
        Query( ServerQueryPlotName, name );
    } );

    const auto time = TscTime( RefTime( m_refTimeThread, evTime ) );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    InsertPlot( plot, time, val );
}

void Worker::ProcessPlotConfig( const QueuePlotConfig& ev )
{
    PlotData* plot = m_data.plots.Retrieve( ev.name, [this] ( uint64_t name ) {
        auto plot = m_slab.AllocInit<PlotData>();
        plot->name = name;
        plot->type = PlotType::User;
        return plot;
    }, [this]( uint64_t name ) {
        Query( ServerQueryPlotName, name );
    } );

    plot->format = (PlotValueFormatting)ev.type;
    plot->showSteps = ev.step;
    plot->fill = ev.fill;
    plot->color = ev.color & 0xFFFFFF;
}

void Worker::ProcessMessage( const QueueMessage& ev )
{
    auto td = GetCurrentThreadData();
    auto msg = m_slab.Alloc<MessageData>();
    const auto time = TscTime( ev.time );
    msg->time = time;
    msg->ref = StringRef( StringRef::Type::Idx, GetSingleStringIdx() );
    msg->thread = CompressThread( td->id );
    msg->color = 0xFFFFFFFF;
    msg->callstack.SetVal( 0 );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    InsertMessageData( msg );
}

void Worker::ProcessMessageLiteral( const QueueMessageLiteral& ev )
{
    auto td = GetCurrentThreadData();
    CheckString( ev.text );
    auto msg = m_slab.Alloc<MessageData>();
    const auto time = TscTime( ev.time );
    msg->time = time;
    msg->ref = StringRef( StringRef::Type::Ptr, ev.text );
    msg->thread = CompressThread( td->id );
    msg->color = 0xFFFFFFFF;
    msg->callstack.SetVal( 0 );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    InsertMessageData( msg );
}

void Worker::ProcessMessageColor( const QueueMessageColor& ev )
{
    auto td = GetCurrentThreadData();
    auto msg = m_slab.Alloc<MessageData>();
    const auto time = TscTime( ev.time );
    msg->time = time;
    msg->ref = StringRef( StringRef::Type::Idx, GetSingleStringIdx() );
    msg->thread = CompressThread( td->id );
    msg->color = 0xFF000000 | ( ev.b << 16 ) | ( ev.g << 8 ) | ev.r;
    msg->callstack.SetVal( 0 );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    InsertMessageData( msg );
}

void Worker::ProcessMessageLiteralColor( const QueueMessageColorLiteral& ev )
{
    auto td = GetCurrentThreadData();
    CheckString( ev.text );
    auto msg = m_slab.Alloc<MessageData>();
    const auto time = TscTime( ev.time );
    msg->time = time;
    msg->ref = StringRef( StringRef::Type::Ptr, ev.text );
    msg->thread = CompressThread( td->id );
    msg->color = 0xFF000000 | ( ev.b << 16 ) | ( ev.g << 8 ) | ev.r;
    msg->callstack.SetVal( 0 );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    InsertMessageData( msg );
}

void Worker::ProcessMessageCallstack( const QueueMessage& ev )
{
    auto td = GetCurrentThreadData();
    ProcessMessage( ev );
    auto it = m_nextCallstack.find( td->id );
    assert( it != m_nextCallstack.end() );
    td->messages.back()->callstack.SetVal( it->second );
    it->second = 0;
}

void Worker::ProcessMessageLiteralCallstack( const QueueMessageLiteral& ev )
{
    auto td = GetCurrentThreadData();
    ProcessMessageLiteral( ev );
    auto it = m_nextCallstack.find( td->id );
    assert( it != m_nextCallstack.end() );
    td->messages.back()->callstack.SetVal( it->second );
    it->second = 0;
}

void Worker::ProcessMessageColorCallstack( const QueueMessageColor& ev )
{
    auto td = GetCurrentThreadData();
    ProcessMessageColor( ev );
    auto it = m_nextCallstack.find( td->id );
    assert( it != m_nextCallstack.end() );
    td->messages.back()->callstack.SetVal( it->second );
    it->second = 0;
}

void Worker::ProcessMessageLiteralColorCallstack( const QueueMessageColorLiteral& ev )
{
    auto td = GetCurrentThreadData();
    ProcessMessageLiteralColor( ev );
    auto it = m_nextCallstack.find( td->id );
    assert( it != m_nextCallstack.end() );
    td->messages.back()->callstack.SetVal( it->second );
    it->second = 0;
}

void Worker::ProcessMessageAppInfo( const QueueMessage& ev )
{
    m_data.appInfo.push_back( StringRef( StringRef::Type::Idx, GetSingleStringIdx() ) );
    const auto time = TscTime( ev.time );
    if( m_data.lastTime < time ) m_data.lastTime = time;
}

void Worker::ProcessGpuNewContext( const QueueGpuNewContext& ev )
{
    assert( !m_gpuCtxMap[ev.context] );
    assert( ev.type != GpuContextType::Invalid );

    int64_t gpuTime;
    if( ev.period == 1.f )
    {
        gpuTime = ev.gpuTime;
    }
    else
    {
        gpuTime = int64_t( double( ev.period ) * ev.gpuTime );      // precision loss
    }

    const auto cpuTime = TscTime( ev.cpuTime );
    auto gpu = m_slab.AllocInit<GpuCtxData>();
    memset( (char*)gpu->query, 0, sizeof( gpu->query ) );
    gpu->timeDiff = cpuTime - gpuTime;
    gpu->thread = ev.thread;
    gpu->period = ev.period;
    gpu->count = 0;
    gpu->type = ev.type;
    gpu->hasPeriod = ev.period != 1.f;
    gpu->hasCalibration = ev.flags & GpuContextCalibration;
    gpu->calibratedGpuTime = gpuTime;
    gpu->calibratedCpuTime = cpuTime;
    gpu->calibrationMod = 1.;
    gpu->lastGpuTime = 0;
    gpu->overflow = 0;
    gpu->overflowMul = 0;
    m_data.gpuData.push_back( gpu );
    m_gpuCtxMap[ev.context] = gpu;
}

void Worker::ProcessGpuZoneBeginImpl( GpuEvent* zone, const QueueGpuZoneBegin& ev, bool serial )
{
    CheckSourceLocation( ev.srcloc );
    zone->SetSrcLoc( ShrinkSourceLocation( ev.srcloc ) );
    ProcessGpuZoneBeginImplCommon( zone, ev, serial );
}

void Worker::ProcessGpuZoneBeginAllocSrcLocImpl( GpuEvent* zone, const QueueGpuZoneBeginLean& ev, bool serial )
{
    assert( m_pendingSourceLocationPayload != 0 );
    zone->SetSrcLoc( m_pendingSourceLocationPayload );
    ProcessGpuZoneBeginImplCommon( zone, ev, serial );
    m_pendingSourceLocationPayload = 0;
}

void Worker::ProcessGpuZoneBeginImplCommon( GpuEvent* zone, const QueueGpuZoneBeginLean& ev, bool serial )
{
    m_data.gpuCnt++;

    auto ctx = m_gpuCtxMap[ev.context].get();
    assert( ctx );

    int64_t cpuTime;
    if( serial )
    {
        cpuTime = RefTime( m_refTimeSerial, ev.cpuTime );
    }
    else
    {
        cpuTime = RefTime( m_refTimeThread, ev.cpuTime );
    }
    const auto time = TscTime( cpuTime );
    zone->SetCpuStart( time );
    zone->SetCpuEnd( -1 );
    zone->SetGpuStart( -1 );
    zone->SetGpuEnd( -1 );
    zone->callstack.SetVal( 0 );
    zone->SetChild( -1 );

    uint64_t ztid;
    if( ctx->thread == 0 )
    {
        // Vulkan, OpenCL and Direct3D 12 contexts are not bound to any single thread.
        zone->SetThread( CompressThread( ev.thread ) );
        ztid = ev.thread;
    }
    else
    {
        // OpenGL and Direct3D11 doesn't need per-zone thread id. It still can be sent,
        // because it may be needed for callstack collection purposes.
        zone->SetThread( 0 );
        ztid = 0;
    }

    if( m_data.lastTime < time ) m_data.lastTime = time;

    auto td = ctx->threadData.find( ztid );
    if( td == ctx->threadData.end() )
    {
        td = ctx->threadData.emplace( ztid, GpuCtxThreadData {} ).first;
    }
    auto timeline = &td->second.timeline;
    auto& stack = td->second.stack;
    if( !stack.empty() )
    {
        auto back = stack.back();
        if( back->Child() < 0 )
        {
            back->SetChild( int32_t( m_data.gpuChildren.size() ) );
            m_data.gpuChildren.push_back( Vector<short_ptr<GpuEvent>>() );
        }
        timeline = &m_data.gpuChildren[back->Child()];
    }

    timeline->push_back( zone );
    stack.push_back( zone );

    assert( !ctx->query[ev.queryId] );
    ctx->query[ev.queryId] = zone;
}

void Worker::ProcessGpuZoneBegin( const QueueGpuZoneBegin& ev, bool serial )
{
    auto zone = m_slab.Alloc<GpuEvent>();
    ProcessGpuZoneBeginImpl( zone, ev, serial );
}

void Worker::ProcessGpuZoneBeginCallstack( const QueueGpuZoneBegin& ev, bool serial )
{
    auto zone = m_slab.Alloc<GpuEvent>();
    ProcessGpuZoneBeginImpl( zone, ev, serial );
    if( serial )
    {
        assert( m_serialNextCallstack != 0 );
        zone->callstack.SetVal( m_serialNextCallstack );
        m_serialNextCallstack = 0;
    }
    else
    {
        auto td = GetCurrentThreadData();
        auto it = m_nextCallstack.find( td->id );
        assert( it != m_nextCallstack.end() );
        zone->callstack.SetVal( it->second );
        it->second = 0;
    }
}

void Worker::ProcessGpuZoneBeginAllocSrcLoc( const QueueGpuZoneBeginLean& ev, bool serial )
{
    auto zone = m_slab.Alloc<GpuEvent>();
    ProcessGpuZoneBeginAllocSrcLocImpl( zone, ev, serial );
}

void Worker::ProcessGpuZoneBeginAllocSrcLocCallstack( const QueueGpuZoneBeginLean& ev, bool serial )
{
    auto zone = m_slab.Alloc<GpuEvent>();
    ProcessGpuZoneBeginAllocSrcLocImpl( zone, ev, serial );
    if( serial )
    {
        assert( m_serialNextCallstack != 0 );
        zone->callstack.SetVal( m_serialNextCallstack );
        m_serialNextCallstack = 0;
    }
    else
    {
        auto td = GetCurrentThreadData();
        auto it = m_nextCallstack.find( td->id );
        assert( it != m_nextCallstack.end() );
        zone->callstack.SetVal( it->second );
        it->second = 0;
    }
}

void Worker::ProcessGpuZoneEnd( const QueueGpuZoneEnd& ev, bool serial )
{
    auto ctx = m_gpuCtxMap[ev.context];
    assert( ctx );

    auto td = ctx->threadData.find( ev.thread );
    assert( td != ctx->threadData.end() );

    assert( !td->second.stack.empty() );
    auto zone = td->second.stack.back_and_pop();

    assert( !ctx->query[ev.queryId] );
    ctx->query[ev.queryId] = zone;

    int64_t cpuTime;
    if( serial )
    {
        cpuTime = RefTime( m_refTimeSerial, ev.cpuTime );
    }
    else
    {
        cpuTime = RefTime( m_refTimeThread, ev.cpuTime );
    }
    const auto time = TscTime( cpuTime );
    zone->SetCpuEnd( time );
    if( m_data.lastTime < time ) m_data.lastTime = time;
}

void Worker::ProcessGpuTime( const QueueGpuTime& ev )
{
    auto ctx = m_gpuCtxMap[ev.context];
    assert( ctx );

    int64_t tgpu = RefTime( m_refTimeGpu, ev.gpuTime );
    if( tgpu < ctx->lastGpuTime - ( 1u << 31 ) )
    {
        if( ctx->overflow == 0 )
        {
            ctx->overflow = uint64_t( 1 ) << ( 64 - TracyLzcnt( ctx->lastGpuTime ) );
        }
        ctx->overflowMul++;
    }
    ctx->lastGpuTime = tgpu;
    if( ctx->overflow != 0 )
    {
        tgpu += ctx->overflow * ctx->overflowMul;
    }

    int64_t gpuTime;
    if( !ctx->hasPeriod )
    {
        if( !ctx->hasCalibration )
        {
            gpuTime = tgpu + ctx->timeDiff;
        }
        else
        {
            gpuTime = int64_t( ( tgpu - ctx->calibratedGpuTime ) * ctx->calibrationMod + ctx->calibratedCpuTime );
        }
    }
    else
    {
        if( !ctx->hasCalibration )
        {
            gpuTime = int64_t( double( ctx->period ) * tgpu ) + ctx->timeDiff;      // precision loss
        }
        else
        {
            gpuTime = int64_t( ( double( ctx->period ) * tgpu - ctx->calibratedGpuTime ) * ctx->calibrationMod + ctx->calibratedCpuTime );
        }
    }

    auto zone = ctx->query[ev.queryId];
    assert( zone );
    ctx->query[ev.queryId] = nullptr;

    if( zone->GpuStart() < 0 )
    {
        zone->SetGpuStart( gpuTime );
        ctx->count++;
    }
    else
    {
        zone->SetGpuEnd( gpuTime );
#ifndef TRACY_NO_STATISTICS
        const auto gpuStart = zone->GpuStart();
        const auto timeSpan = gpuTime - gpuStart;
        if( timeSpan > 0 )
        {
            GpuZoneThreadData ztd;
            ztd.SetZone( zone );
            ztd.SetThread( zone->Thread() );
            auto slz = GetGpuSourceLocationZones( zone->SrcLoc() );
            slz->zones.push_back( ztd );
            if( slz->min > timeSpan ) slz->min = timeSpan;
            if( slz->max < timeSpan ) slz->max = timeSpan;
            slz->total += timeSpan;
            slz->sumSq += double( timeSpan ) * timeSpan;
        }
#else
        CountZoneStatistics( zone );
#endif
    }
    if( m_data.lastTime < gpuTime ) m_data.lastTime = gpuTime;
}

void Worker::ProcessGpuCalibration( const QueueGpuCalibration& ev )
{
    auto ctx = m_gpuCtxMap[ev.context];
    assert( ctx );
    assert( ctx->hasCalibration );

    int64_t gpuTime;
    if( !ctx->hasPeriod )
    {
        gpuTime = ev.gpuTime;
    }
    else
    {
        gpuTime = int64_t( double( ctx->period ) * ev.gpuTime );      // precision loss
    }

    const auto cpuDelta = ev.cpuDelta;
    const auto gpuDelta = gpuTime - ctx->calibratedGpuTime;
    ctx->calibrationMod = double( cpuDelta ) / gpuDelta;
    ctx->calibratedGpuTime = gpuTime;
    ctx->calibratedCpuTime = TscTime( ev.cpuTime );
}

void Worker::ProcessGpuContextName( const QueueGpuContextName& ev )
{
    auto ctx = m_gpuCtxMap[ev.context];
    assert( ctx );
    const auto idx = GetSingleStringIdx();
    ctx->name = StringIdx( idx );
}

MemEvent* Worker::ProcessMemAllocImpl( uint64_t memname, MemData& memdata, const QueueMemAlloc& ev )
{
    if( memdata.active.find( ev.ptr ) != memdata.active.end() )
    {
        MemAllocTwiceFailure( ev.thread );
        return nullptr;
    }

    const auto time = TscTime( RefTime( m_refTimeSerial, ev.time ) );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    NoticeThread( ev.thread );

    assert( memdata.data.empty() || memdata.data.back().TimeAlloc() <= time );

    memdata.active.emplace( ev.ptr, memdata.data.size() );

    const auto ptr = ev.ptr;
    uint32_t lo;
    uint16_t hi;
    memcpy( &lo, ev.size, 4 );
    memcpy( &hi, ev.size+4, 2 );
    const uint64_t size = lo | ( uint64_t( hi ) << 32 );

    auto& mem = memdata.data.push_next();
    mem.SetPtr( ptr );
    mem.SetSize( size );
    mem.SetTimeThreadAlloc( time, CompressThread( ev.thread ) );
    mem.SetTimeThreadFree( -1, 0 );
    mem.SetCsAlloc( 0 );
    mem.csFree.SetVal( 0 );

    const auto low = memdata.low;
    const auto high = memdata.high;
    const auto ptrend = ptr + size;

    memdata.low = std::min( low, ptr );
    memdata.high = std::max( high, ptrend );
    memdata.usage += size;

    MemAllocChanged( memname, memdata, time );
    return &mem;
}

MemEvent* Worker::ProcessMemFreeImpl( uint64_t memname, MemData& memdata, const QueueMemFree& ev )
{
    const auto refTime = RefTime( m_refTimeSerial, ev.time );

    auto it = memdata.active.find( ev.ptr );
    if( it == memdata.active.end() )
    {
        if( ev.ptr == 0 ) return nullptr;

        if( !m_ignoreMemFreeFaults )
        {
            CheckThreadString( ev.thread );
            MemFreeFailure( ev.thread );
        }
        return nullptr;
    }

    const auto time = TscTime( refTime );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    NoticeThread( ev.thread );

    memdata.frees.push_back( it->second );
    auto& mem = memdata.data[it->second];
    mem.SetTimeThreadFree( time, CompressThread( ev.thread ) );
    memdata.usage -= mem.Size();
    memdata.active.erase( it );

    MemAllocChanged( memname, memdata, time );
    return &mem;
}

MemEvent* Worker::ProcessMemAlloc( const QueueMemAlloc& ev )
{
    assert( m_memNamePayload == 0 );
    return ProcessMemAllocImpl( 0, *m_data.memory, ev );
}

MemEvent* Worker::ProcessMemAllocNamed( const QueueMemAlloc& ev )
{
    assert( m_memNamePayload != 0 );
    auto memname = m_memNamePayload;
    m_memNamePayload = 0;
    auto it = m_data.memNameMap.find( memname );
    if( it == m_data.memNameMap.end() )
    {
        CheckString( memname );
        it = m_data.memNameMap.emplace( memname, m_slab.AllocInit<MemData>() ).first;
        it->second->name = memname;
    }
    return ProcessMemAllocImpl( memname, *it->second, ev );
}

MemEvent* Worker::ProcessMemFree( const QueueMemFree& ev )
{
    assert( m_memNamePayload == 0 );
    return ProcessMemFreeImpl( 0, *m_data.memory, ev );
}

MemEvent* Worker::ProcessMemFreeNamed( const QueueMemFree& ev )
{
    assert( m_memNamePayload != 0 );
    auto memname = m_memNamePayload;
    m_memNamePayload = 0;
    auto it = m_data.memNameMap.find( memname );
    if( it == m_data.memNameMap.end() )
    {
        CheckString( memname );
        it = m_data.memNameMap.emplace( memname, m_slab.AllocInit<MemData>() ).first;
        it->second->name = memname;
    }
    return ProcessMemFreeImpl( memname, *it->second, ev );
}

void Worker::ProcessMemAllocCallstack( const QueueMemAlloc& ev )
{
    auto mem = ProcessMemAlloc( ev );
    assert( m_serialNextCallstack != 0 );
    if( mem ) mem->SetCsAlloc( m_serialNextCallstack );
    m_serialNextCallstack = 0;
}

void Worker::ProcessMemAllocCallstackNamed( const QueueMemAlloc& ev )
{
    assert( m_memNamePayload != 0 );
    auto memname = m_memNamePayload;
    m_memNamePayload = 0;
    auto it = m_data.memNameMap.find( memname );
    if( it == m_data.memNameMap.end() )
    {
        CheckString( memname );
        it = m_data.memNameMap.emplace( memname, m_slab.AllocInit<MemData>() ).first;
        it->second->name = memname;
    }
    auto mem = ProcessMemAllocImpl( memname, *it->second, ev );
    assert( m_serialNextCallstack != 0 );
    if( mem ) mem->SetCsAlloc( m_serialNextCallstack );
    m_serialNextCallstack = 0;
}

void Worker::ProcessMemFreeCallstack( const QueueMemFree& ev )
{
    auto mem = ProcessMemFree( ev );
    assert( m_serialNextCallstack != 0 );
    if( mem ) mem->csFree.SetVal( m_serialNextCallstack );
    m_serialNextCallstack = 0;
}

void Worker::ProcessMemFreeCallstackNamed( const QueueMemFree& ev )
{
    assert( m_memNamePayload != 0 );
    auto memname = m_memNamePayload;
    m_memNamePayload = 0;
    auto it = m_data.memNameMap.find( memname );
    if( it == m_data.memNameMap.end() )
    {
        CheckString( memname );
        it = m_data.memNameMap.emplace( memname, m_slab.AllocInit<MemData>() ).first;
        it->second->name = memname;
    }
    auto mem = ProcessMemFreeImpl( memname, *it->second, ev );
    assert( m_serialNextCallstack != 0 );
    if( mem ) mem->csFree.SetVal( m_serialNextCallstack );
    m_serialNextCallstack = 0;
}

void Worker::ProcessCallstackSerial()
{
    assert( m_pendingCallstackId != 0 );
    assert( m_serialNextCallstack == 0 );
    m_serialNextCallstack = m_pendingCallstackId;
    m_pendingCallstackId = 0;
}

void Worker::ProcessCallstack()
{
    assert( m_pendingCallstackId != 0 );
    auto td = GetCurrentThreadData();
    auto it = m_nextCallstack.find( td->id );
    if( it == m_nextCallstack.end() ) it = m_nextCallstack.emplace( td->id, 0 ).first;
    assert( it->second == 0 );
    it->second = m_pendingCallstackId;
    m_pendingCallstackId = 0;
}

void Worker::ProcessCallstackSampleInsertSample( const SampleData& sd, ThreadData& td )
{
    const auto t = sd.time.Val();
    if( td.samples.empty() )
    {
        td.samples.push_back( sd );
    }
    else if( t != 0 && td.samples.back().time.Val() >= t )
    {
        m_inconsistentSamples = true;
        auto it = std::lower_bound( td.samples.begin(), td.samples.end(), t, []( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs; } );
        assert( it != td.samples.end() );
        if( it->time.Val() != t )
        {
            td.samples.push_back_non_empty( sd );
        }
        else
        {
            const auto mcs = MergeCallstacks( it->callstack.Val(), sd.callstack.Val() );
            it->callstack.SetVal( mcs );

            // This is a fixup of an already processed sample. Fixing stats is non-trivial, so just exit here.
            return;
        }
    }
    else
    {
        td.samples.push_back_non_empty( sd );
    }

    const auto callstack = sd.callstack.Val();
    const auto& cs = GetCallstack( callstack );
    const auto& ip = cs[0];
    if( GetCanonicalPointer( ip ) >> 63 != 0 ) td.kernelSampleCnt++;
    m_data.samplesCnt++;
}

void Worker::ProcessCallstackSampleImpl( const SampleData& sd, ThreadData& td )
{
    ProcessCallstackSampleInsertSample( sd, td );

#ifndef TRACY_NO_STATISTICS
    const auto t = sd.time.Val();
    if( t == 0 || !m_identifySamples )
    {
        ProcessCallstackSampleImplStats( sd, td );
    }
    else
    {
        bool postpone = false;
        auto ctx = GetContextSwitchData( td.id );
        if( !ctx )
        {
            postpone = true;
        }
        else
        {
            auto it = std::lower_bound( ctx->v.begin(), ctx->v.end(), sd.time.Val(), [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
            if( it == ctx->v.end() )
            {
                postpone = true;
            }
            else if( sd.time.Val() == it->Start() )
            {
                td.ctxSwitchSamples.push_back( sd );
            }
            else
            {
                ProcessCallstackSampleImplStats( sd, td );
            }
        }
        if( postpone )
        {
            td.postponedSamples.push_back( sd );
        }
    }
#endif
}

#ifndef TRACY_NO_STATISTICS
void Worker::ProcessCallstackSampleImplStats( const SampleData& sd, ThreadData& td )
{
    const auto t = sd.time.Val();
    const auto callstack = sd.callstack.Val();
    const auto& cs = GetCallstack( callstack );
    const auto& ip = cs[0];

    uint16_t tid = CompressThread( td.id );

    auto frame = GetCallstackFrame( ip );
    if( frame )
    {
        const auto symAddr = frame->data[0].symAddr;
        auto it = m_data.instructionPointersMap.find( symAddr );
        if( it == m_data.instructionPointersMap.end() )
        {
            m_data.instructionPointersMap.emplace( symAddr, unordered_flat_map<CallstackFrameId, uint32_t, CallstackFrameIdHash, CallstackFrameIdCompare> { { ip, 1 } } );
        }
        else
        {
            auto fit = it->second.find( ip );
            if( fit == it->second.end() )
            {
                it->second.emplace( ip, 1 );
            }
            else
            {
                fit->second++;
            }
        }
        auto sit = m_data.symbolSamples.find( symAddr );
        if( sit == m_data.symbolSamples.end() )
        {
            m_data.symbolSamples.emplace( symAddr, Vector<SampleDataRange>( SampleDataRange { sd.time, tid, ip } ) );
        }
        else
        {
            if( sit->second.back().time.Val() <= sd.time.Val() )
            {
                sit->second.push_back_non_empty( SampleDataRange { sd.time, tid, ip } );
            }
            else
            {
                auto iit = std::upper_bound( sit->second.begin(), sit->second.end(), sd.time.Val(), [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs.time.Val(); } );
                sit->second.insert( iit, SampleDataRange { sd.time, tid, ip } );
            }
        }
    }
    else
    {
        auto it = m_data.pendingInstructionPointers.find( ip );
        if( it == m_data.pendingInstructionPointers.end() )
        {
            m_data.pendingInstructionPointers.emplace( ip, 1 );
        }
        else
        {
            it->second++;
        }
        auto sit = m_data.pendingSymbolSamples.find( ip );
        if( sit == m_data.pendingSymbolSamples.end() )
        {
            m_data.pendingSymbolSamples.emplace( ip, Vector<SampleDataRange>( SampleDataRange { sd.time, tid,  ip } ) );
        }
        else
        {
            sit->second.push_back_non_empty( SampleDataRange { sd.time, tid, ip } );
        }
    }

    auto childAddr = GetCanonicalPointer( cs[0] );
    for( uint16_t i=1; i<cs.size(); i++ )
    {
        auto addr = GetCanonicalPointer( cs[i] );
        auto it = m_data.childSamples.find( addr );
        if( it == m_data.childSamples.end() )
        {
            m_data.childSamples.emplace( addr, Vector<ChildSample>( ChildSample { sd.time, childAddr } ) );
        }
        else
        {
            it->second.push_back_non_empty( ChildSample { sd.time, childAddr } );
        }
        childAddr = addr;
    }

    const auto framesKnown = UpdateSampleStatistics( callstack, 1, true );

    if( t != 0 )
    {
        assert( td.samples.size() > td.ghostIdx );
        if( framesKnown && td.ghostIdx + 1 == td.samples.size() )
        {
            td.ghostIdx++;
            m_data.ghostCnt += AddGhostZone( cs, &td.ghostZones, t );
        }
        else
        {
            m_data.ghostZonesPostponed = true;
        }
    }
}
#endif

void Worker::ProcessCallstackSample( const QueueCallstackSample& ev )
{
    assert( m_pendingCallstackId != 0 );
    const auto callstack = m_pendingCallstackId;
    m_pendingCallstackId = 0;

    const auto refTime = RefTime( m_refTimeCtx, ev.time );
    const auto t = refTime == 0 ? 0 : TscTime( refTime );

    auto& td = *NoticeThread( ev.thread );

    SampleData sd;
    sd.time.SetVal( t );
    sd.callstack.SetVal( callstack );

    if( m_combineSamples && t != 0 )
    {
        const auto pendingTime = td.pendingSample.time.Val();
        if( pendingTime == 0 )
        {
            td.pendingSample = sd;
        }
        else
        {
            if( pendingTime == t )
            {
                const auto mcs = MergeCallstacks( td.pendingSample.callstack.Val(), callstack );
                sd.callstack.SetVal( mcs );
                ProcessCallstackSampleImpl( sd, td );
                td.pendingSample.time.Clear();
            }
            else
            {
                ProcessCallstackSampleImpl( td.pendingSample, td );
                td.pendingSample = sd;
            }
        }
    }
    else
    {
        ProcessCallstackSampleImpl( sd, td );
    }
}

void Worker::ProcessCallstackSampleContextSwitch( const QueueCallstackSample& ev )
{
    assert( m_pendingCallstackId != 0 );
    const auto callstack = m_pendingCallstackId;
    m_pendingCallstackId = 0;

    const auto refTime = RefTime( m_refTimeCtx, ev.time );
    const auto t = refTime == 0 ? 0 : TscTime( refTime );

    auto& td = *NoticeThread( ev.thread );

    SampleData sd;
    sd.time.SetVal( t );
    sd.callstack.SetVal( callstack );

    ProcessCallstackSampleInsertSample( sd, td );

    td.ctxSwitchSamples.push_back( sd );
}

void Worker::ProcessCallstackFrameSize( const QueueCallstackFrameSize& ev )
{
    assert( !m_callstackFrameStaging );
    assert( m_pendingCallstackSubframes == 0 );
    assert( m_pendingCallstackFrames > 0 );
    m_pendingCallstackFrames--;
    m_pendingCallstackSubframes = ev.size;
#ifndef TRACY_NO_STATISTICS
    m_data.newFramesWereReceived = true;
#endif

    const auto idx = GetSingleStringIdx();

    // Frames may be duplicated due to recursion
    auto fmit = m_data.callstackFrameMap.find( PackPointer( ev.ptr ) );
    if( fmit == m_data.callstackFrameMap.end() )
    {
        m_callstackFrameStaging = m_slab.Alloc<CallstackFrameData>();
        m_callstackFrameStaging->size = ev.size;
        m_callstackFrameStaging->data = m_slab.Alloc<CallstackFrame>( ev.size );
        m_callstackFrameStaging->imageName = StringIdx( idx );

        m_callstackFrameStagingPtr = ev.ptr;
    }
}

void Worker::ProcessCallstackFrame( const QueueCallstackFrame& ev, bool querySymbols )
{
    assert( m_pendingCallstackSubframes > 0 );

    const auto nitidx = GetSingleStringIdx();
    const auto fitidx = GetSecondStringIdx();

    if( m_callstackFrameStaging )
    {
        const auto idx = m_callstackFrameStaging->size - m_pendingCallstackSubframes;
        const auto file = StringIdx( fitidx );

        if( m_pendingCallstackSubframes > 1 && idx == 0 )
        {
            auto fstr = GetString( file );
            auto flen = strlen( fstr );
            if( flen >= s_tracySkipSubframesMinLen )
            {
                auto ptr = s_tracySkipSubframes;
                do
                {
                    if( flen >= ptr->len && memcmp( fstr + flen - ptr->len, ptr->str, ptr->len ) == 0 )
                    {
                        m_pendingCallstackSubframes--;
                        m_callstackFrameStaging->size--;
                        return;
                    }
                    ptr++;
                }
                while( ptr->str );
            }
        }

        const auto name = StringIdx( nitidx );
        m_callstackFrameStaging->data[idx].name = name;
        m_callstackFrameStaging->data[idx].file = file;
        m_callstackFrameStaging->data[idx].line = ev.line;
        m_callstackFrameStaging->data[idx].symAddr = ev.symAddr;

        if( querySymbols && ev.symAddr != 0 && m_data.symbolMap.find( ev.symAddr ) == m_data.symbolMap.end() && m_pendingSymbols.find( ev.symAddr ) == m_pendingSymbols.end() )
        {
            m_pendingSymbols.emplace( ev.symAddr, SymbolPending { name, m_callstackFrameStaging->imageName, file, ev.line, ev.symLen, idx < m_callstackFrameStaging->size - 1 } );
            Query( ServerQuerySymbol, ev.symAddr );
        }

        StringRef ref( StringRef::Idx, fitidx );
        auto cit = m_checkedFileStrings.find( ref );
        if( cit == m_checkedFileStrings.end() ) CacheSource( ref, m_callstackFrameStaging->imageName );

        const auto frameId = PackPointer( m_callstackFrameStagingPtr );
#ifndef TRACY_NO_STATISTICS
        auto it = m_data.pendingInstructionPointers.find( frameId );
        if( it != m_data.pendingInstructionPointers.end() )
        {
            if( ev.symAddr != 0 )
            {
                auto sit = m_data.instructionPointersMap.find( ev.symAddr );
                if( sit == m_data.instructionPointersMap.end() )
                {
                    m_data.instructionPointersMap.emplace( ev.symAddr, unordered_flat_map<CallstackFrameId, uint32_t, CallstackFrameIdHash, CallstackFrameIdCompare> { { it->first, it->second } } );
                }
                else
                {
                    assert( sit->second.find( it->first ) == sit->second.end() );
                    sit->second.emplace( it->first, it->second );
                }
            }
            m_data.pendingInstructionPointers.erase( it );
        }
        auto pit = m_data.pendingSymbolSamples.find( frameId );
        if( pit != m_data.pendingSymbolSamples.end() )
        {
            if( ev.symAddr != 0 )
            {
                auto sit = m_data.symbolSamples.find( ev.symAddr );
                if( sit == m_data.symbolSamples.end() )
                {
                    pdqsort_branchless( pit->second.begin(), pit->second.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs.time.Val(); } );
                    m_data.symbolSamples.emplace( ev.symAddr, std::move( pit->second ) );
                }
                else
                {
                    for( auto& v : pit->second )
                    {
                        if( sit->second.back().time.Val() <= v.time.Val() )
                        {
                            sit->second.push_back_non_empty( v );
                        }
                        else
                        {
                            auto iit = std::upper_bound( sit->second.begin(), sit->second.end(), v.time.Val(), [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs.time.Val(); } );
                            sit->second.insert( iit, v );
                        }
                    }
                }
            }
            m_data.pendingSymbolSamples.erase( pit );
        }
#endif

        if( --m_pendingCallstackSubframes == 0 )
        {
            assert( m_data.callstackFrameMap.find( frameId ) == m_data.callstackFrameMap.end() );
            m_data.callstackFrameMap.emplace( frameId, m_callstackFrameStaging );
            m_data.codeSymbolMap.emplace( m_callstackFrameStagingPtr, m_callstackFrameStaging->data[0].symAddr );
            m_callstackFrameStaging = nullptr;
        }
    }
    else
    {
        m_pendingCallstackSubframes--;
    }
}

void Worker::ProcessSymbolInformation( const QueueSymbolInformation& ev )
{
    auto it = m_pendingSymbols.find( ev.symAddr );
    assert( it != m_pendingSymbols.end() );

    const auto idx = GetSingleStringIdx();

    SymbolData sd;
    sd.name = it->second.name;
    sd.file = StringIdx( idx );
    sd.line = ev.line;
    sd.imageName = it->second.imageName;
    sd.callFile = it->second.file;
    sd.callLine = it->second.line;
    sd.isInline = it->second.isInline;
    sd.size.SetVal( it->second.size );
    m_data.symbolMap.emplace( ev.symAddr, std::move( sd ) );

    if( m_codeTransfer && it->second.size > 0 && it->second.size <= 128*1024 )
    {
        m_pendingSymbolCode++;
        Query( ServerQuerySymbolCode, ev.symAddr, it->second.size );
    }

    if( !it->second.isInline )
    {
        if( m_data.newSymbolsIndex < 0 ) m_data.newSymbolsIndex = int64_t( m_data.symbolLoc.size() );
        m_data.symbolLoc.push_back( SymbolLocation { ev.symAddr, it->second.size } );
    }
    else
    {
        if( m_data.newInlineSymbolsIndex < 0 ) m_data.newInlineSymbolsIndex = int64_t( m_data.symbolLocInline.size() );
        m_data.symbolLocInline.push_back( ev.symAddr );
    }

    StringRef ref( StringRef::Idx, idx );
    auto cit = m_checkedFileStrings.find( ref );
    if( cit == m_checkedFileStrings.end() ) CacheSource( ref, it->second.imageName );

    m_pendingSymbols.erase( it );
}

void Worker::ProcessCrashReport( const QueueCrashReport& ev )
{
    CheckString( ev.text );

    auto td = GetCurrentThreadData();
    m_data.crashEvent.thread = td->id;
    m_data.crashEvent.time = TscTime( ev.time );
    m_data.crashEvent.message = ev.text;

    auto it = m_nextCallstack.find( td->id );
    if( it != m_nextCallstack.end() && it->second != 0 )
    {
        m_data.crashEvent.callstack = it->second;
        it->second = 0;
    }
    else
    {
        m_data.crashEvent.callstack = 0;
    }
}

void Worker::ProcessSysTime( const QueueSysTime& ev )
{
    const auto time = TscTime( ev.time );
    if( m_data.lastTime < time ) m_data.lastTime = time;
    const auto val = ev.sysTime;
    if( !m_sysTimePlot )
    {
        m_sysTimePlot = m_slab.AllocInit<PlotData>();
        m_sysTimePlot->name = 0;
        m_sysTimePlot->type = PlotType::SysTime;
        m_sysTimePlot->format = PlotValueFormatting::Percentage;
        m_sysTimePlot->showSteps = false;
        m_sysTimePlot->fill = true;
        m_sysTimePlot->color = 0;
        m_sysTimePlot->min = val;
        m_sysTimePlot->max = val;
        m_sysTimePlot->sum = val;
        m_sysTimePlot->data.push_back( { time, val } );
        m_data.plots.Data().push_back( m_sysTimePlot );
    }
    else
    {
        assert( !m_sysTimePlot->data.empty() );
        assert( m_sysTimePlot->data.back().time.Val() <= time );
        if( m_sysTimePlot->min > val ) m_sysTimePlot->min = val;
        else if( m_sysTimePlot->max < val ) m_sysTimePlot->max = val;
        m_sysTimePlot->sum += val;
        m_sysTimePlot->data.push_back( { time, val } );
    }
}

void Worker::ProcessContextSwitch( const QueueContextSwitch& ev )
{
#ifndef TRACY_NO_STATISTICS
    m_data.newContextSwitchesReceived = true;
#endif

    const auto time = TscTime( RefTime( m_refTimeCtx, ev.time ) );
    if( m_data.lastTime < time ) m_data.lastTime = time;

    if( ev.cpu >= m_data.cpuDataCount ) m_data.cpuDataCount = ev.cpu + 1;
    auto& cs = m_data.cpuData[ev.cpu].cs;
    if( ev.oldThread != 0 )
    {
        auto it = m_data.ctxSwitch.find( ev.oldThread );
        if( it != m_data.ctxSwitch.end() )
        {
            auto& data = it->second->v;
            assert( !data.empty() );
            auto& item = data.back();
            assert( item.Start() <= time );
            assert( item.End() == -1 );
            item.SetEnd( time );
            item.SetReason( ev.reason );
            item.SetState( ev.state );

            const auto dt = time - item.Start();
            it->second->runningTime += dt;

            auto tdit = m_data.cpuThreadData.find( ev.oldThread );
            if( tdit == m_data.cpuThreadData.end() )
            {
                tdit = m_data.cpuThreadData.emplace( ev.oldThread, CpuThreadData {} ).first;
            }
            tdit->second.runningRegions++;
            tdit->second.runningTime += dt;
        }
        if( !cs.empty() )
        {
            auto& cx = cs.back();
            assert( m_data.externalThreadCompress.DecompressThread( cx.Thread() ) == ev.oldThread );
            cx.SetEnd( time );
        }
    }
    if( ev.newThread != 0 )
    {
        auto it = m_data.ctxSwitch.find( ev.newThread );
        if( it == m_data.ctxSwitch.end() )
        {
            auto ctx = m_slab.AllocInit<ContextSwitch>();
            it = m_data.ctxSwitch.emplace( ev.newThread, ctx ).first;
        }
        auto& data = it->second->v;
        ContextSwitchData* item = nullptr;
        bool migration = false;
        if( !data.empty() && data.back().Reason() == ContextSwitchData::Wakeup )
        {
            item = &data.back();
            if( data.size() > 1 )
            {
                migration = data[data.size()-2].Cpu() != ev.cpu;
            }
        }
        else
        {
            assert( data.empty() || (uint64_t)data.back().End() <= (uint64_t)time );
            if( !data.empty() )
            {
                migration = data.back().Cpu() != ev.cpu;
            }
            item = &data.push_next();
            item->SetWakeup( time );
        }
        item->SetStart( time );
        item->SetEnd( -1 );
        item->SetCpu( ev.cpu );
        item->SetReason( -1 );
        item->SetState( -1 );
        item->SetThread( 0 );

        auto& cx = cs.push_next();
        cx.SetStart( time );
        cx.SetEnd( -1 );
        cx.SetThread( m_data.externalThreadCompress.CompressThread( ev.newThread ) );

        CheckExternalName( ev.newThread );

        if( migration )
        {
            auto tdit = m_data.cpuThreadData.find( ev.newThread );
            if( tdit == m_data.cpuThreadData.end() )
            {
                tdit = m_data.cpuThreadData.emplace( ev.newThread, CpuThreadData {} ).first;
            }
            tdit->second.migrations++;
        }
    }
}

void Worker::ProcessThreadWakeup( const QueueThreadWakeup& ev )
{
    const auto time = TscTime( RefTime( m_refTimeCtx, ev.time ) );
    if( m_data.lastTime < time ) m_data.lastTime = time;

    auto it = m_data.ctxSwitch.find( ev.thread );
    if( it == m_data.ctxSwitch.end() )
    {
        auto ctx = m_slab.AllocInit<ContextSwitch>();
        it = m_data.ctxSwitch.emplace( ev.thread, ctx ).first;
    }
    auto& data = it->second->v;
    if( !data.empty() && !data.back().IsEndValid() ) return;        // wakeup of a running thread
    auto& item = data.push_next();
    item.SetWakeup( time );
    item.SetStart( time );
    item.SetEnd( -1 );
    item.SetCpu( 0 );
    item.SetReason( ContextSwitchData::Wakeup );
    item.SetState( -1 );
    item.SetThread( 0 );
}

void Worker::ProcessTidToPid( const QueueTidToPid& ev )
{
    if( m_data.tidToPid.find( ev.tid ) == m_data.tidToPid.end() ) m_data.tidToPid.emplace( ev.tid, ev.pid );
}

void Worker::ProcessHwSampleCpuCycle( const QueueHwSample& ev )
{
    const auto time = ev.time == 0 ? 0 : TscTime( ev.time );
    auto it = m_data.hwSamples.find( ev.ip );
    if( it == m_data.hwSamples.end() ) it = m_data.hwSamples.emplace( ev.ip, HwSampleData {} ).first;
    it->second.cycles.push_back( time );
}

void Worker::ProcessHwSampleInstructionRetired( const QueueHwSample& ev )
{
    const auto time = ev.time == 0 ? 0 : TscTime( ev.time );
    auto it = m_data.hwSamples.find( ev.ip );
    if( it == m_data.hwSamples.end() ) it = m_data.hwSamples.emplace( ev.ip, HwSampleData {} ).first;
    it->second.retired.push_back( time );
}

void Worker::ProcessHwSampleCacheReference( const QueueHwSample& ev )
{
    const auto time = ev.time == 0 ? 0 : TscTime( ev.time );
    auto it = m_data.hwSamples.find( ev.ip );
    if( it == m_data.hwSamples.end() ) it = m_data.hwSamples.emplace( ev.ip, HwSampleData {} ).first;
    it->second.cacheRef.push_back( time );
}

void Worker::ProcessHwSampleCacheMiss( const QueueHwSample& ev )
{
    const auto time = ev.time == 0 ? 0 : TscTime( ev.time );
    auto it = m_data.hwSamples.find( ev.ip );
    if( it == m_data.hwSamples.end() ) it = m_data.hwSamples.emplace( ev.ip, HwSampleData {} ).first;
    it->second.cacheMiss.push_back( time );
}

void Worker::ProcessHwSampleBranchRetired( const QueueHwSample& ev )
{
    const auto time = ev.time == 0 ? 0 : TscTime( ev.time );
    auto it = m_data.hwSamples.find( ev.ip );
    if( it == m_data.hwSamples.end() ) it = m_data.hwSamples.emplace( ev.ip, HwSampleData {} ).first;
    it->second.branchRetired.push_back( time );
    m_data.hasBranchRetirement = true;
}

void Worker::ProcessHwSampleBranchMiss( const QueueHwSample& ev )
{
    const auto time = ev.time == 0 ? 0 : TscTime( ev.time );
    auto it = m_data.hwSamples.find( ev.ip );
    if( it == m_data.hwSamples.end() ) it = m_data.hwSamples.emplace( ev.ip, HwSampleData {} ).first;
    it->second.branchMiss.push_back( time );
}

void Worker::ProcessParamSetup( const QueueParamSetup& ev )
{
    CheckString( ev.name );
    m_params.push_back( Parameter { ev.idx, StringRef( StringRef::Ptr, ev.name ), bool( ev.isBool ), ev.val } );
}

void Worker::ProcessSourceCodeNotAvailable( const QueueSourceCodeNotAvailable& ev )
{
    auto it = m_sourceCodeQuery.find( ev.id );
    assert( it != m_sourceCodeQuery.end() );
    m_sourceCodeQuery.erase( it );
}

void Worker::ProcessCpuTopology( const QueueCpuTopology& ev )
{
    auto package = m_data.cpuTopology.find( ev.package );
    if( package == m_data.cpuTopology.end() ) package = m_data.cpuTopology.emplace( ev.package, unordered_flat_map<uint32_t, std::vector<uint32_t>> {} ).first;
    auto core = package->second.find( ev.core );
    if( core == package->second.end() ) core = package->second.emplace( ev.core, std::vector<uint32_t> {} ).first;
    core->second.emplace_back( ev.thread );

    assert( m_data.cpuTopologyMap.find( ev.thread ) == m_data.cpuTopologyMap.end() );
    m_data.cpuTopologyMap.emplace( ev.thread, CpuThreadTopology { ev.package, ev.core } );
}

void Worker::ProcessMemNamePayload( const QueueMemNamePayload& ev )
{
    assert( m_memNamePayload == 0 );
    m_memNamePayload = ev.name;
}

void Worker::ProcessFiberEnter( const QueueFiberEnter& ev )
{
    const auto t = TscTime( RefTime( m_refTimeThread, ev.time ) );
    if( m_data.lastTime < t ) m_data.lastTime = t;

    uint64_t tid;
    auto it = m_data.fiberToThreadMap.find( ev.fiber );
    if( it == m_data.fiberToThreadMap.end() )
    {
        tid = ( uint64_t(1) << 32 ) | m_data.fiberToThreadMap.size();
        m_data.fiberToThreadMap.emplace( ev.fiber, tid );
        NewThread( tid, true );
        CheckFiberName( ev.fiber, tid );
    }
    else
    {
        tid = it->second;
    }

    auto td = NoticeThread( ev.thread );
    if( td->fiber )
    {
        auto cit = m_data.ctxSwitch.find( td->fiber->id );
        assert( cit != m_data.ctxSwitch.end() );
        auto& data = cit->second->v;
        assert( !data.empty() );
        auto& item = data.back();
        item.SetEnd( t );
    }
    td->fiber = RetrieveThread( tid );
    assert( td->fiber );

    auto cit = m_data.ctxSwitch.find( tid );
    if( cit == m_data.ctxSwitch.end() )
    {
        auto ctx = m_slab.AllocInit<ContextSwitch>();
        cit = m_data.ctxSwitch.emplace( tid, ctx ).first;
    }
    auto& data = cit->second->v;
    auto& item = data.push_next();
    item.SetStartCpu( t, 0 );
    item.SetWakeup( t );
    item.SetEndReasonState( -1, ContextSwitchData::Fiber, -1 );
    item.SetThread( CompressThread( ev.thread ) );
}

void Worker::ProcessFiberLeave( const QueueFiberLeave& ev )
{
    const auto t = TscTime( RefTime( m_refTimeThread, ev.time ) );
    if( m_data.lastTime < t ) m_data.lastTime = t;

    auto td = RetrieveThread( ev.thread );
    if( !td->fiber )
    {
        FiberLeaveFailure();
        return;
    }

    auto cit = m_data.ctxSwitch.find( td->fiber->id );
    assert( cit != m_data.ctxSwitch.end() );
    auto& data = cit->second->v;
    assert( !data.empty() );
    auto& item = data.back();
    item.SetEnd( t );

    const auto dt = t - item.Start();
    cit->second->runningTime += dt;

    td->fiber = nullptr;
}

void Worker::MemAllocChanged( uint64_t memname, MemData& memdata, int64_t time )
{
    const auto val = (double)memdata.usage;
    if( !memdata.plot )
    {
        CreateMemAllocPlot( memdata );
        memdata.plot->min = val;
        memdata.plot->max = val;
        memdata.plot->sum = val;
        memdata.plot->data.push_back( { time, val } );
    }
    else
    {
        assert( !memdata.plot->data.empty() );
        assert( memdata.plot->data.back().time.Val() <= time );
        if( memdata.plot->min > val ) memdata.plot->min = val;
        else if( memdata.plot->max < val ) memdata.plot->max = val;
        memdata.plot->sum += val;
        memdata.plot->data.push_back( { time, val } );
    }
}

void Worker::CreateMemAllocPlot( MemData& memdata )
{
    assert( !memdata.plot );
    memdata.plot = m_slab.AllocInit<PlotData>();
    memdata.plot->name = memdata.name;
    memdata.plot->type = PlotType::Memory;
    memdata.plot->format = PlotValueFormatting::Memory;
    memdata.plot->showSteps = true;
    memdata.plot->fill = true;
    memdata.plot->color = 0;
    memdata.plot->data.push_back( { GetFrameBegin( *m_data.framesBase, 0 ), 0. } );
    m_data.plots.Data().push_back( memdata.plot );
}

void Worker::ReconstructMemAllocPlot( MemData& mem )
{
#ifdef NO_PARALLEL_SORT
    pdqsort_branchless( mem.frees.begin(), mem.frees.end(), [&mem] ( const auto& lhs, const auto& rhs ) { return mem.data[lhs].TimeFree() < mem.data[rhs].TimeFree(); } );
#else
    std::sort( std::execution::par_unseq, mem.frees.begin(), mem.frees.end(), [&mem] ( const auto& lhs, const auto& rhs ) { return mem.data[lhs].TimeFree() < mem.data[rhs].TimeFree(); } );
#endif

    const auto psz = mem.data.size() + mem.frees.size() + 1;

    PlotData* plot;
    {
        std::lock_guard<std::mutex> lock( m_data.lock );
        plot = m_slab.AllocInit<PlotData>();
        plot->data.reserve_exact( psz, m_slab );
    }

    plot->name = mem.name;
    plot->type = PlotType::Memory;
    plot->format = PlotValueFormatting::Memory;
    plot->showSteps = true;
    plot->fill = true;
    plot->color = 0;

    auto aptr = mem.data.begin();
    auto aend = mem.data.end();
    auto fptr = mem.frees.begin();
    auto fend = mem.frees.end();

    double sum = 0;
    double max = 0;
    double usage = 0;

    auto ptr = plot->data.data();
    ptr->time = GetFrameBegin( *m_data.framesBase, 0 );
    ptr->val = 0;
    ptr++;

    if( aptr != aend && fptr != fend )
    {
        auto atime = aptr->TimeAlloc();
        auto ftime = mem.data[*fptr].TimeFree();

        for(;;)
        {
            if( atime < ftime )
            {
                usage += int64_t( aptr->Size() );
                assert( usage >= 0 );
                if( max < usage ) max = usage;
                sum += usage;
                ptr->time = atime;
                ptr->val = usage;
                ptr++;
                aptr++;
                if( aptr == aend ) break;
                atime = aptr->TimeAlloc();
            }
            else
            {
                usage -= int64_t( mem.data[*fptr].Size() );
                assert( usage >= 0 );
                if( max < usage ) max = usage;
                sum += usage;
                ptr->time = ftime;
                ptr->val = usage;
                ptr++;
                fptr++;
                if( fptr == fend ) break;
                ftime = mem.data[*fptr].TimeFree();
            }
        }
    }

    while( aptr != aend )
    {
        assert( aptr->TimeFree() < 0 );
        int64_t time = aptr->TimeAlloc();
        usage += int64_t( aptr->Size() );
        assert( usage >= 0 );
        if( max < usage ) max = usage;
        sum += usage;
        ptr->time = time;
        ptr->val = usage;
        ptr++;
        aptr++;
    }
    while( fptr != fend )
    {
        const auto& memData = mem.data[*fptr];
        int64_t time = memData.TimeFree();
        usage -= int64_t( memData.Size() );
        assert( usage >= 0 );
        assert( max >= usage );
        sum += usage;
        ptr->time = time;
        ptr->val = usage;
        ptr++;
        fptr++;
    }

    plot->min = 0;
    plot->max = max;
    plot->sum = sum;

    std::lock_guard<std::mutex> lock( m_data.lock );
    m_data.plots.Data().insert( m_data.plots.Data().begin(), plot );
    mem.plot = plot;
}

#ifndef TRACY_NO_STATISTICS
void Worker::ReconstructContextSwitchUsage()
{
    assert( m_data.cpuDataCount != 0 );
    const auto cpucnt = m_data.cpuDataCount;

    auto& vec = m_data.ctxUsage;
    vec.push_back( ContextSwitchUsage( 0, 0, 0 ) );

    struct Cpu
    {
        bool startDone;
        Vector<ContextSwitchCpu>::iterator it;
        Vector<ContextSwitchCpu>::iterator end;
    };
    std::vector<Cpu> cpus;
    cpus.reserve( cpucnt );
    for( int i=0; i<cpucnt; i++ )
    {
        cpus.emplace_back( Cpu { false, m_data.cpuData[i].cs.begin(), m_data.cpuData[i].cs.end() } );
    }

    uint8_t other = 0;
    uint8_t own = 0;
    for(;;)
    {
        int64_t nextTime = std::numeric_limits<int64_t>::max();
        bool atEnd = true;
        for( int i=0; i<cpucnt; i++ )
        {
            if( cpus[i].it != cpus[i].end )
            {
                atEnd = false;
                const auto ct = !cpus[i].startDone ? cpus[i].it->Start() : cpus[i].it->End();
                if( ct < nextTime ) nextTime = ct;
            }
        }
        if( atEnd ) break;
        for( int i=0; i<cpucnt; i++ )
        {
            while( cpus[i].it != cpus[i].end )
            {
                const auto ct = !cpus[i].startDone ? cpus[i].it->Start() : cpus[i].it->End();
                if( nextTime != ct ) break;
                const auto isOwn = GetPidFromTid( DecompressThreadExternal( cpus[i].it->Thread() ) ) == m_pid;
                if( !cpus[i].startDone )
                {
                    if( isOwn )
                    {
                        own++;
                        assert( own <= cpucnt );
                    }
                    else
                    {
                        other++;
                        assert( other <= cpucnt );
                    }
                    if( !cpus[i].it->IsEndValid() )
                    {
                        cpus[i].it++;
                        assert( cpus[i].it = cpus[i].end );
                    }
                    else
                    {
                        cpus[i].startDone = true;
                    }
                }
                else
                {
                    if( isOwn )
                    {
                        assert( own > 0 );
                        own--;
                    }
                    else
                    {
                        assert( other > 0 );
                        other--;
                    }
                    cpus[i].startDone = false;
                    cpus[i].it++;
                }
            }
        }
        const auto& back = vec.back();
        if( back.Other() != other || back.Own() != own )
        {
            vec.push_back( ContextSwitchUsage( nextTime, other, own ) );
        }
    }

    std::lock_guard<std::mutex> lock( m_data.lock );
    m_data.ctxUsageReady = true;
}

bool Worker::UpdateSampleStatistics( uint32_t callstack, uint32_t count, bool canPostpone )
{
    const auto& cs = GetCallstack( callstack );
    const auto cssz = cs.size();

    auto frames = (const CallstackFrameData**)alloca( cssz * sizeof( CallstackFrameData* ) );
    for( uint16_t i=0; i<cssz; i++ )
    {
        auto frame = GetCallstackFrame( cs[i] );
        if( !frame )
        {
            if( canPostpone )
            {
                auto it = m_data.postponedSamples.find( callstack );
                if( it == m_data.postponedSamples.end() )
                {
                    m_data.postponedSamples.emplace( callstack, count );
                }
                else
                {
                    it->second += count;
                }
            }
            return false;
        }
        else
        {
            frames[i] = frame;
        }
    }

    if( canPostpone )
    {
        auto it = m_data.postponedSamples.find( callstack );
        if( it != m_data.postponedSamples.end() )
        {
            count += it->second;
            m_data.postponedSamples.erase( it );
        }
    }

    UpdateSampleStatisticsImpl( frames, cssz, count, cs );
    return true;
}

void Worker::UpdateSampleStatisticsPostponed( decltype(Worker::DataBlock::postponedSamples.begin())& it )
{
    const auto& cs = GetCallstack( it->first );
    const auto cssz = cs.size();

    auto frames = (const CallstackFrameData**)alloca( cssz * sizeof( CallstackFrameData* ) );
    for( uint16_t i=0; i<cssz; i++ )
    {
        auto frame = GetCallstackFrame( cs[i] );
        if( !frame )
        {
            ++it;
            return;
        }
        frames[i] = frame;
    }

    UpdateSampleStatisticsImpl( frames, cssz, it->second, cs );
    it = m_data.postponedSamples.erase( it );
}

void Worker::UpdateSampleStatisticsImpl( const CallstackFrameData** frames, uint16_t framesCount, uint32_t count, const VarArray<CallstackFrameId>& cs )
{
    const auto fexcl = frames[0];
    const auto fxsz = fexcl->size;
    const auto& frame0 = fexcl->data[0];
    auto sym0 = m_data.symbolStats.find( frame0.symAddr );
    if( sym0 == m_data.symbolStats.end() ) sym0 = m_data.symbolStats.emplace( frame0.symAddr, SymbolStats { 0, 0 } ).first;
    sym0->second.excl += count;
    for( uint8_t f=1; f<fxsz; f++ )
    {
        const auto& frame = fexcl->data[f];
        auto sym = m_data.symbolStats.find( frame.symAddr );
        if( sym == m_data.symbolStats.end() ) sym = m_data.symbolStats.emplace( frame.symAddr, SymbolStats { 0, 0 } ).first;
        sym->second.incl += count;
    }
    for( uint16_t c=1; c<framesCount; c++ )
    {
        const auto fincl = frames[c];
        const auto fsz = fincl->size;
        for( uint8_t f=0; f<fsz; f++ )
        {
            const auto& frame = fincl->data[f];
            auto sym = m_data.symbolStats.find( frame.symAddr );
            if( sym == m_data.symbolStats.end() ) sym = m_data.symbolStats.emplace( frame.symAddr, SymbolStats { 0, 0 } ).first;
            sym->second.incl += count;
        }
    }

    CallstackFrameId parentFrameId;
    if( fxsz != 1 )
    {
        auto cfdata = (CallstackFrame*)alloca( uint8_t( fxsz-1 ) * sizeof( CallstackFrame ) );
        for( int i=0; i<fxsz-1; i++ )
        {
            cfdata[i] = fexcl->data[i+1];
        }
        CallstackFrameData cfd;
        cfd.data = cfdata;
        cfd.size = fxsz-1;
        cfd.imageName = fexcl->imageName;

        auto it = m_data.revParentFrameMap.find( &cfd );
        if( it == m_data.revParentFrameMap.end() )
        {
            auto frame = m_slab.Alloc<CallstackFrame>( fxsz-1 );
            memcpy( frame, cfdata, ( fxsz-1 ) * sizeof( CallstackFrame ) );
            auto frameData = m_slab.AllocInit<CallstackFrameData>();
            frameData->data = frame;
            frameData->size = fxsz - 1;
            frameData->imageName = fexcl->imageName;
            parentFrameId.idx = m_callstackParentNextIdx++;
            parentFrameId.sel = 0;
            parentFrameId.custom = 1;
            m_data.parentCallstackFrameMap.emplace( parentFrameId, frameData );
            m_data.revParentFrameMap.emplace( frameData, parentFrameId );
        }
        else
        {
            parentFrameId = it->second;
        }
    }

    uint32_t parentIdx;
    {
        const auto sz = framesCount - ( fxsz == 1 );
        const auto memsize = sizeof( VarArray<CallstackFrameId> ) + sz * sizeof( CallstackFrameId );
        auto mem = (char*)m_slab.AllocRaw( memsize );

        auto data = (CallstackFrameId*)mem;
        auto dst = data;
        if( fxsz == 1 )
        {
            for( int i=0; i<sz; i++ )
            {
                *dst++ = cs[i+1];
            }
        }
        else
        {
            *dst++ = parentFrameId;
            for( int i=1; i<sz; i++ )
            {
                *dst++ = cs[i];
            }
        }

        auto arr = (VarArray<CallstackFrameId>*)( mem + sz * sizeof( CallstackFrameId ) );
        new(arr) VarArray<CallstackFrameId>( sz, data );

        auto it = m_data.parentCallstackMap.find( arr );
        if( it == m_data.parentCallstackMap.end() )
        {
            parentIdx = m_data.parentCallstackPayload.size();
            m_data.parentCallstackMap.emplace( arr, parentIdx );
            m_data.parentCallstackPayload.push_back( arr );
        }
        else
        {
            parentIdx = it->second;
            m_slab.Unalloc( memsize );
        }
    }

    sym0 = m_data.symbolStats.find( frame0.symAddr );
    auto sit = sym0->second.parents.find( parentIdx );
    if( sit == sym0->second.parents.end() )
    {
        sym0->second.parents.emplace( parentIdx, count );
    }
    else
    {
        sit->second += count;
    }

    uint32_t baseParentIdx;
    {
        const auto sz = framesCount - 1;
        const auto memsize = sizeof( VarArray<CallstackFrameId> ) + sz * sizeof( CallstackFrameId );
        auto mem = (char*)m_slab.AllocRaw( memsize );

        auto data = (CallstackFrameId*)mem;
        auto dst = data;
        for( int i=0; i<sz; i++ )
        {
            *dst++ = cs[i+1];
        }

        auto arr = (VarArray<CallstackFrameId>*)( mem + sz * sizeof( CallstackFrameId ) );
        new(arr) VarArray<CallstackFrameId>( sz, data );

        auto it = m_data.parentCallstackMap.find( arr );
        if( it == m_data.parentCallstackMap.end() )
        {
            baseParentIdx = m_data.parentCallstackPayload.size();
            m_data.parentCallstackMap.emplace( arr, baseParentIdx );
            m_data.parentCallstackPayload.push_back( arr );
        }
        else
        {
            baseParentIdx = it->second;
            m_slab.Unalloc( memsize );
        }
    }

    auto bit = sym0->second.baseParents.find( baseParentIdx );
    if( bit == sym0->second.baseParents.end() )
    {
        sym0->second.baseParents.emplace( baseParentIdx, count );
    }
    else
    {
        bit->second += count;
    }
}
#endif

int64_t Worker::ReadTimeline( FileRead& f, ZoneEvent* zone, int64_t refTime, int32_t& childIdx )
{
    uint32_t sz;
    f.Read( sz );
    return ReadTimelineHaveSize( f, zone, refTime, childIdx, sz );
}

int64_t Worker::ReadTimelineHaveSize( FileRead& f, ZoneEvent* zone, int64_t refTime, int32_t& childIdx, uint32_t sz )
{
    if( sz == 0 )
    {
        zone->SetChild( -1 );
        return refTime;
    }
    else
    {
        const auto idx = childIdx;
        childIdx++;
        zone->SetChild( idx );
        return ReadTimeline( f, m_data.zoneChildren[idx], sz, refTime, childIdx );
    }
}

void Worker::ReadTimeline( FileRead& f, GpuEvent* zone, int64_t& refTime, int64_t& refGpuTime, int32_t& childIdx )
{
    uint64_t sz;
    f.Read( sz );
    ReadTimelineHaveSize( f, zone, refTime, refGpuTime, childIdx, sz );
}

void Worker::ReadTimelineHaveSize( FileRead& f, GpuEvent* zone, int64_t& refTime, int64_t& refGpuTime, int32_t& childIdx, uint64_t sz )
{
    if( sz == 0 )
    {
        zone->SetChild( -1 );
    }
    else
    {
        const auto idx = childIdx;
        childIdx++;
        zone->SetChild( idx );
        ReadTimeline( f, m_data.gpuChildren[idx], sz, refTime, refGpuTime, childIdx );
    }
}

#ifndef TRACY_NO_STATISTICS
void Worker::ReconstructZoneStatistics( uint8_t* countMap, ZoneEvent& zone, uint16_t thread )
{
    assert( zone.IsEndValid() );
    auto timeSpan = zone.End() - zone.Start();
    if( timeSpan > 0 )
    {
        auto it = m_data.sourceLocationZones.find( zone.SrcLoc() );
        assert( it != m_data.sourceLocationZones.end() );
        ZoneThreadData ztd;
        ztd.SetZone( &zone );
        ztd.SetThread( thread );
        auto& slz = it->second;
        slz.zones.push_back( ztd );
        if( slz.min > timeSpan ) slz.min = timeSpan;
        if( slz.max < timeSpan ) slz.max = timeSpan;
        slz.total += timeSpan;
        slz.sumSq += double( timeSpan ) * timeSpan;
        if( countMap[uint16_t(zone.SrcLoc())] == 0 )
        {
            slz.nonReentrantCount++;
            if( slz.nonReentrantMin > timeSpan ) slz.nonReentrantMin = timeSpan;
            if( slz.nonReentrantMax < timeSpan ) slz.nonReentrantMax = timeSpan;
            slz.nonReentrantTotal += timeSpan;
        }
        if( zone.HasChildren() )
        {
            auto& children = GetZoneChildren( zone.Child() );
            assert( children.is_magic() );
            auto& c = *(Vector<ZoneEvent>*)( &children );
            for( auto& v : c )
            {
                const auto childSpan = std::max( int64_t( 0 ), v.End() - v.Start() );
                timeSpan -= childSpan;
            }
        }
        if( slz.selfMin > timeSpan ) slz.selfMin = timeSpan;
        if( slz.selfMax < timeSpan ) slz.selfMax = timeSpan;
        slz.selfTotal += timeSpan;
    }
}

void Worker::ReconstructZoneStatistics( GpuEvent& zone, uint16_t thread )
{
    assert( zone.GpuEnd() >= 0 );
    auto timeSpan = zone.GpuEnd() - zone.GpuStart();
    if( timeSpan > 0 )
    {
        auto it = m_data.gpuSourceLocationZones.find( zone.SrcLoc() );
        if( it == m_data.gpuSourceLocationZones.end() )
        {
            it = m_data.gpuSourceLocationZones.emplace( zone.SrcLoc(), GpuSourceLocationZones {} ).first;
        }
        GpuZoneThreadData ztd;
        ztd.SetZone( &zone );
        ztd.SetThread( thread );
        auto& slz = it->second;
        slz.zones.push_back( ztd );
        if( slz.min > timeSpan ) slz.min = timeSpan;
        if( slz.max < timeSpan ) slz.max = timeSpan;
        slz.total += timeSpan;
        slz.sumSq += double( timeSpan ) * timeSpan;
    }
}
#else
void Worker::CountZoneStatistics( ZoneEvent* zone )
{
    auto cnt = GetSourceLocationZonesCnt( zone->SrcLoc() );
    (*cnt)++;
}

void Worker::CountZoneStatistics( GpuEvent* zone )
{
    auto cnt = GetGpuSourceLocationZonesCnt( zone->SrcLoc() );
    (*cnt)++;
}
#endif

int64_t Worker::ReadTimeline( FileRead& f, Vector<short_ptr<ZoneEvent>>& _vec, uint32_t size, int64_t refTime, int32_t& childIdx )
{
    assert( size != 0 );
    const auto lp = s_loadProgress.subProgress.load( std::memory_order_relaxed );
    s_loadProgress.subProgress.store( lp + size, std::memory_order_relaxed );
    auto& vec = *(Vector<ZoneEvent>*)( &_vec );
    vec.set_magic();
    vec.reserve_exact( size, m_slab );
    auto zone = vec.begin();
    auto end = vec.end() - 1;

    int16_t srcloc;
    int64_t tstart, tend;
    uint32_t childSz, extra;
    f.Read4( srcloc, tstart, extra, childSz );

    while( zone != end )
    {
        refTime += tstart;
        zone->SetStartSrcLoc( refTime, srcloc );
        zone->extra = extra;
        refTime = ReadTimelineHaveSize( f, zone, refTime, childIdx, childSz );
        f.Read5( tend, srcloc, tstart, extra, childSz );
        refTime += tend;
        zone->SetEnd( refTime );
#ifdef TRACY_NO_STATISTICS
        CountZoneStatistics( zone );
#endif
        zone++;
    }

    refTime += tstart;
    zone->SetStartSrcLoc( refTime, srcloc );
    zone->extra = extra;
    refTime = ReadTimelineHaveSize( f, zone, refTime, childIdx, childSz );
    f.Read( tend );
    refTime += tend;
    zone->SetEnd( refTime );
#ifdef TRACY_NO_STATISTICS
    CountZoneStatistics( zone );
#endif

    return refTime;
}

void Worker::ReadTimeline( FileRead& f, Vector<short_ptr<GpuEvent>>& _vec, uint64_t size, int64_t& refTime, int64_t& refGpuTime, int32_t& childIdx )
{
    assert( size != 0 );
    const auto lp = s_loadProgress.subProgress.load( std::memory_order_relaxed );
    s_loadProgress.subProgress.store( lp + size, std::memory_order_relaxed );
    auto& vec = *(Vector<GpuEvent>*)( &_vec );
    vec.set_magic();
    vec.reserve_exact( size, m_slab );
    auto zone = vec.begin();
    auto end = vec.end();
    do
    {
        int64_t tcpu, tgpu;
        int16_t srcloc;
        uint16_t thread;
        uint64_t childSz;
        f.Read6( tcpu, tgpu, srcloc, zone->callstack, thread, childSz );
        zone->SetSrcLoc( srcloc );
        zone->SetThread( thread );
        refTime += tcpu;
        refGpuTime += tgpu;
        zone->SetCpuStart( refTime );
        zone->SetGpuStart( refGpuTime );

        ReadTimelineHaveSize( f, zone, refTime, refGpuTime, childIdx, childSz );

        f.Read2( tcpu, tgpu );
        refTime += tcpu;
        refGpuTime += tgpu;
        zone->SetCpuEnd( refTime );
        zone->SetGpuEnd( refGpuTime );
    }
    while( ++zone != end );
}

void Worker::Disconnect()
{
    //Query( ServerQueryDisconnect, 0 );
    Shutdown();
    m_disconnect = true;
}

static void WriteHwSampleVec( FileWrite& f, SortedVector<Int48, Int48Sort>& vec )
{
    uint64_t sz = vec.size();
    f.Write( &sz, sizeof( sz ) );
    if( sz != 0 )
    {
        if( !vec.is_sorted() ) vec.sort();
        int64_t refTime = 0;
        for( auto& v : vec )
        {
            WriteTimeOffset( f, refTime, v.Val() );
        }
    }
}

void Worker::Write( FileWrite& f, bool fiDict )
{
    DoPostponedWorkAll();

    f.Write( FileHeader, sizeof( FileHeader ) );

    f.Write( &m_delay, sizeof( m_delay ) );
    f.Write( &m_resolution, sizeof( m_resolution ) );
    f.Write( &m_timerMul, sizeof( m_timerMul ) );
    f.Write( &m_data.lastTime, sizeof( m_data.lastTime ) );
    f.Write( &m_data.frameOffset, sizeof( m_data.frameOffset ) );
    f.Write( &m_pid, sizeof( m_pid ) );
    f.Write( &m_samplingPeriod, sizeof( m_samplingPeriod ) );
    f.Write( &m_data.cpuArch, sizeof( m_data.cpuArch ) );
    f.Write( &m_data.cpuId, sizeof( m_data.cpuId ) );
    f.Write( m_data.cpuManufacturer, 12 );

    uint64_t sz = m_captureName.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_captureName.c_str(), sz );

    sz = m_captureProgram.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_captureProgram.c_str(), sz );

    f.Write( &m_captureTime, sizeof( m_captureTime ) );
    f.Write( &m_executableTime, sizeof( m_executableTime ) );

    sz = m_hostInfo.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_hostInfo.c_str(), sz );

    sz = m_data.cpuTopology.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& package : m_data.cpuTopology )
    {
        sz = package.second.size();
        f.Write( &package.first, sizeof( package.first ) );
        f.Write( &sz, sizeof( sz ) );
        for( auto& core : package.second )
        {
            sz = core.second.size();
            f.Write( &core.first, sizeof( core.first ) );
            f.Write( &sz, sizeof( sz ) );
            for( auto& thread : core.second )
            {
                f.Write( &thread, sizeof( thread ) );
            }
        }
    }

    f.Write( &m_data.crashEvent, sizeof( m_data.crashEvent ) );

    sz = m_data.frames.Data().size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& fd : m_data.frames.Data() )
    {
        int64_t refTime = 0;
        f.Write( &fd->name, sizeof( fd->name ) );
        f.Write( &fd->continuous, sizeof( fd->continuous ) );
        sz = fd->frames.size();
        f.Write( &sz, sizeof( sz ) );
        if( fd->continuous )
        {
            for( auto& fe : fd->frames )
            {
                WriteTimeOffset( f, refTime, fe.start );
                f.Write( &fe.frameImage, sizeof( fe.frameImage ) );
            }
        }
        else
        {
            for( auto& fe : fd->frames )
            {
                WriteTimeOffset( f, refTime, fe.start );
                WriteTimeOffset( f, refTime, fe.end );
                f.Write( &fe.frameImage, sizeof( fe.frameImage ) );
            }
        }
    }

    sz = m_data.stringData.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.stringData )
    {
        uint64_t ptr = (uint64_t)v;
        f.Write( &ptr, sizeof( ptr ) );
        sz = strlen( v );
        f.Write( &sz, sizeof( sz ) );
        f.Write( v, sz );
    }

    sz = m_data.strings.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.strings )
    {
        f.Write( &v.first, sizeof( v.first ) );
        uint64_t ptr = (uint64_t)v.second;
        f.Write( &ptr, sizeof( ptr ) );
    }

    sz = m_data.threadNames.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.threadNames )
    {
        f.Write( &v.first, sizeof( v.first ) );
        uint64_t ptr = (uint64_t)v.second;
        f.Write( &ptr, sizeof( ptr ) );
    }

    sz = m_data.externalNames.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.externalNames )
    {
        f.Write( &v.first, sizeof( v.first ) );
        uint64_t ptr = (uint64_t)v.second.first;
        f.Write( &ptr, sizeof( ptr ) );
        ptr = (uint64_t)v.second.second;
        f.Write( &ptr, sizeof( ptr ) );
    }

    m_data.localThreadCompress.Save( f );
    m_data.externalThreadCompress.Save( f );

    sz = m_data.sourceLocation.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceLocation )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( SourceLocationBase ) );
    }

    sz = m_data.sourceLocationExpand.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceLocationExpand )
    {
        f.Write( &v, sizeof( v ) );
    }

    sz = m_data.sourceLocationPayload.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceLocationPayload )
    {
        f.Write( v, sizeof( SourceLocationBase ) );
    }

#ifndef TRACY_NO_STATISTICS
    sz = m_data.sourceLocationZones.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceLocationZones )
    {
        int16_t id = v.first;
        uint64_t cnt = v.second.zones.size();
        f.Write( &id, sizeof( id ) );
        f.Write( &cnt, sizeof( cnt ) );
    }

    sz = m_data.gpuSourceLocationZones.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.gpuSourceLocationZones )
    {
        int16_t id = v.first;
        uint64_t cnt = v.second.zones.size();
        f.Write( &id, sizeof( id ) );
        f.Write( &cnt, sizeof( cnt ) );
    }
#else
    sz = m_data.sourceLocationZonesCnt.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceLocationZonesCnt )
    {
        int16_t id = v.first;
        uint64_t cnt = v.second;
        f.Write( &id, sizeof( id ) );
        f.Write( &cnt, sizeof( cnt ) );
    }

    sz = m_data.gpuSourceLocationZonesCnt.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.gpuSourceLocationZonesCnt )
    {
        int16_t id = v.first;
        uint64_t cnt = v.second;
        f.Write( &id, sizeof( id ) );
        f.Write( &cnt, sizeof( cnt ) );
    }
#endif

    sz = m_data.lockMap.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.lockMap )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second->customName, sizeof( v.second->customName ) );
        f.Write( &v.second->srcloc, sizeof( v.second->srcloc ) );
        f.Write( &v.second->type, sizeof( v.second->type ) );
        f.Write( &v.second->valid, sizeof( v.second->valid ) );
        f.Write( &v.second->timeAnnounce, sizeof( v.second->timeAnnounce ) );
        f.Write( &v.second->timeTerminate, sizeof( v.second->timeTerminate ) );
        sz = v.second->threadList.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& t : v.second->threadList )
        {
            f.Write( &t, sizeof( t ) );
        }
        int64_t refTime = v.second->timeAnnounce;
        sz = v.second->timeline.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& lev : v.second->timeline )
        {
            WriteTimeOffset( f, refTime, lev.ptr->Time() );
            const int16_t srcloc = lev.ptr->SrcLoc();
            f.Write( &srcloc, sizeof( srcloc ) );
            f.Write( &lev.ptr->thread, sizeof( lev.ptr->thread ) );
            f.Write( &lev.ptr->type, sizeof( lev.ptr->type ) );
        }
    }

    {
        int64_t refTime = 0;
        sz = m_data.messages.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& v : m_data.messages )
        {
            const auto ptr = (uint64_t)(MessageData*)v;
            f.Write( &ptr, sizeof( ptr ) );
            WriteTimeOffset( f, refTime, v->time );
            f.Write( &v->ref, sizeof( v->ref ) );
            f.Write( &v->color, sizeof( v->color ) );
            f.Write( &v->callstack, sizeof( v->callstack ) );
        }
    }

    sz = m_data.zoneExtra.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_data.zoneExtra.data(), sz * sizeof( ZoneExtra ) );

    sz = 0;
    for( auto& v : m_data.threads ) sz += v->count;
    f.Write( &sz, sizeof( sz ) );
    sz = m_data.zoneChildren.size();
    f.Write( &sz, sizeof( sz ) );
    sz = m_data.threads.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& thread : m_data.threads )
    {
        int64_t refTime = 0;
        f.Write( &thread->id, sizeof( thread->id ) );
        f.Write( &thread->count, sizeof( thread->count ) );
        f.Write( &thread->kernelSampleCnt, sizeof( thread->kernelSampleCnt ) );
        f.Write( &thread->isFiber, sizeof( thread->isFiber ) );
        WriteTimeline( f, thread->timeline, refTime );
        sz = thread->messages.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& v : thread->messages )
        {
            auto ptr = uint64_t( (MessageData*)v );
            f.Write( &ptr, sizeof( ptr ) );
        }
        sz = thread->ctxSwitchSamples.size();
        f.Write( &sz, sizeof( sz ) );
        refTime = 0;
        for( auto& v : thread->ctxSwitchSamples )
        {
            WriteTimeOffset( f, refTime, v.time.Val() );
            f.Write( &v.callstack, sizeof( v.callstack ) );
        }
        if( m_inconsistentSamples )
        {
#ifdef NO_PARALLEL_SORT
            pdqsort_branchless( thread->samples.begin(), thread->samples.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs.time.Val(); } );
#else
            std::sort( std::execution::par_unseq, thread->samples.begin(), thread->samples.end(), [] ( const auto& lhs, const auto& rhs ) { return lhs.time.Val() < rhs.time.Val(); } );
#endif
        }
        sz = thread->samples.size();
        f.Write( &sz, sizeof( sz ) );
        refTime = 0;
        for( auto& v : thread->samples )
        {
            WriteTimeOffset( f, refTime, v.time.Val() );
            f.Write( &v.callstack, sizeof( v.callstack ) );
        }
    }

    sz = 0;
    for( auto& v : m_data.gpuData ) sz += v->count;
    f.Write( &sz, sizeof( sz ) );
    sz = m_data.gpuChildren.size();
    f.Write( &sz, sizeof( sz ) );
    sz = m_data.gpuData.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& ctx : m_data.gpuData )
    {
        f.Write( &ctx->thread, sizeof( ctx->thread ) );
        uint8_t calibration = ctx->hasCalibration;
        f.Write( &calibration, sizeof( calibration ) );
        f.Write( &ctx->count, sizeof( ctx->count ) );
        f.Write( &ctx->period, sizeof( ctx->period ) );
        f.Write( &ctx->type, sizeof( ctx->type ) );
        f.Write( &ctx->name, sizeof( ctx->name ) );
        f.Write( &ctx->overflow, sizeof( ctx->overflow ) );
        sz = ctx->threadData.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& td : ctx->threadData )
        {
            int64_t refTime = 0;
            int64_t refGpuTime = 0;
            uint64_t tid = td.first;
            f.Write( &tid, sizeof( tid ) );
            WriteTimeline( f, td.second.timeline, refTime, refGpuTime );
        }
    }

    sz = m_data.plots.Data().size();
    for( auto& plot : m_data.plots.Data() ) { if( plot->type == PlotType::Memory ) sz--; }
    f.Write( &sz, sizeof( sz ) );
    for( auto& plot : m_data.plots.Data() )
    {
        if( plot->type == PlotType::Memory ) continue;
        f.Write( &plot->type, sizeof( plot->type ) );
        f.Write( &plot->format, sizeof( plot->format ) );
        f.Write( &plot->showSteps, sizeof( plot->showSteps ) );
        f.Write( &plot->fill, sizeof( plot->fill ) );
        f.Write( &plot->color, sizeof( plot->color ) );
        f.Write( &plot->name, sizeof( plot->name ) );
        f.Write( &plot->min, sizeof( plot->min ) );
        f.Write( &plot->max, sizeof( plot->max ) );
        f.Write( &plot->sum, sizeof( plot->sum ) );
        int64_t refTime = 0;
        sz = plot->data.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& v : plot->data )
        {
            WriteTimeOffset( f, refTime, v.time.Val() );
            f.Write( &v.val, sizeof( v.val ) );
        }
    }

    sz = m_data.memNameMap.size();
    f.Write( &sz, sizeof( sz ) );
    sz = 0;
    for( auto& memory : m_data.memNameMap )
    {
        sz += memory.second->data.size();
    }
    f.Write( &sz, sizeof( sz ) );
    for( auto& memory : m_data.memNameMap )
    {
        uint64_t name = memory.first;
        f.Write( &name, sizeof( name ) );

        auto& memdata = *memory.second;
        int64_t refTime = 0;
        sz = memdata.data.size();
        f.Write( &sz, sizeof( sz ) );
        sz = memdata.active.size();
        f.Write( &sz, sizeof( sz ) );
        sz = memdata.frees.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& mem : memdata.data )
        {
            const auto ptr = mem.Ptr();
            const auto size = mem.Size();
            const Int24 csAlloc = mem.CsAlloc();
            f.Write( &ptr, sizeof( ptr ) );
            f.Write( &size, sizeof( size ) );
            f.Write( &csAlloc, sizeof( csAlloc ) );
            f.Write( &mem.csFree, sizeof( mem.csFree ) );

            int64_t timeAlloc = mem.TimeAlloc();
            uint16_t threadAlloc = mem.ThreadAlloc();
            int64_t timeFree = mem.TimeFree();
            uint16_t threadFree = mem.ThreadFree();
            WriteTimeOffset( f, refTime, timeAlloc );
            int64_t freeOffset = timeFree < 0 ? timeFree : timeFree - timeAlloc;
            f.Write( &freeOffset, sizeof( freeOffset ) );
            f.Write( &threadAlloc, sizeof( threadAlloc ) );
            f.Write( &threadFree, sizeof( threadFree ) );
        }
        f.Write( &memdata.high, sizeof( memdata.high ) );
        f.Write( &memdata.low, sizeof( memdata.low ) );
        f.Write( &memdata.usage, sizeof( memdata.usage ) );
        f.Write( &memdata.name, sizeof( memdata.name ) );
    }

    sz = m_data.callstackPayload.size() - 1;
    f.Write( &sz, sizeof( sz ) );
    for( size_t i=1; i<=sz; i++ )
    {
        auto& cs = m_data.callstackPayload[i];
        uint16_t csz = cs->size();
        f.Write( &csz, sizeof( csz ) );
        f.Write( cs->data(), sizeof( CallstackFrameId ) * csz );
    }

    sz = m_data.callstackFrameMap.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& frame : m_data.callstackFrameMap )
    {
        f.Write( &frame.first, sizeof( CallstackFrameId ) );
        f.Write( &frame.second->size, sizeof( frame.second->size ) );
        f.Write( &frame.second->imageName, sizeof( frame.second->imageName ) );
        f.Write( frame.second->data, sizeof( CallstackFrame ) * frame.second->size );
    }

    sz = m_data.appInfo.size();
    f.Write( &sz, sizeof( sz ) );
    if( sz != 0 ) f.Write( m_data.appInfo.data(), sizeof( m_data.appInfo[0] ) * sz );

    {
        sz = m_data.frameImage.size();
        if( fiDict )
        {
            enum : uint32_t { DictSize = 4*1024*1024 };
            enum : uint32_t { SamplesLimit = 1U << 31 };
            uint32_t sNum = 0;
            uint32_t sSize = 0;
            for( auto& fi : m_data.frameImage )
            {
                const auto fisz = fi->w * fi->h / 2;
                if( sSize + fisz > SamplesLimit ) break;
                sSize += fisz;
                sNum++;
            }

            uint32_t offset = 0;
            auto sdata = new char[sSize];
            auto ssize = new size_t[sSize];
            for( uint32_t i=0; i<sNum; i++ )
            {
                const auto& fi = m_data.frameImage[i];
                const auto fisz = fi->w * fi->h / 2;
                const auto image = m_texcomp.Unpack( *fi );
                memcpy( sdata+offset, image, fisz );
                ssize[i] = fisz;
                offset += fisz;
            }
            assert( offset == sSize );

            ZDICT_fastCover_params_t params = {};
            params.d = 6;
            params.k = 50;
            params.f = 30;
            params.nbThreads = std::thread::hardware_concurrency();
            params.zParams.compressionLevel = 3;

            auto dict = new char[DictSize];
            const auto dictret = ZDICT_optimizeTrainFromBuffer_fastCover( dict, DictSize, sdata, ssize, sNum, &params );
            if( dictret <= DictSize )
            {
                const auto finalDictSize = uint32_t( dictret );
                auto zdict = ZSTD_createCDict( dict, finalDictSize, 3 );

                f.Write( &finalDictSize, sizeof( finalDictSize ) );
                f.Write( dict, finalDictSize );

                ZSTD_freeCDict( zdict );
            }
            else
            {
                uint32_t zero = 0;
                f.Write( &zero, sizeof( zero ) );
            }

            delete[] dict;
            delete[] ssize;
            delete[] sdata;
        }
        else
        {
            uint32_t zero = 0;
            f.Write( &zero, sizeof( zero ) );
        }
        f.Write( &sz, sizeof( sz ) );
        for( auto& fi : m_data.frameImage )
        {
            f.Write( &fi->w, sizeof( fi->w ) );
            f.Write( &fi->h, sizeof( fi->h ) );
            f.Write( &fi->flip, sizeof( fi->flip ) );
            const auto image = m_texcomp.Unpack( *fi );
            f.Write( image, fi->w * fi->h / 2 );
        }
    }

    // Only save context switches relevant to active threads.
    std::vector<unordered_flat_map<uint64_t, ContextSwitch*>::const_iterator> ctxValid;
    ctxValid.reserve( m_data.ctxSwitch.size() );
    for( auto it = m_data.ctxSwitch.begin(); it != m_data.ctxSwitch.end(); ++it )
    {
        auto td = RetrieveThread( it->first );
        if( td && ( td->count > 0 || !td->samples.empty() ) )
        {
            ctxValid.emplace_back( it );
        }
    }
    sz = ctxValid.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& ctx : ctxValid )
    {
        f.Write( &ctx->first, sizeof( ctx->first ) );
        sz = ctx->second->v.size();
        f.Write( &sz, sizeof( sz ) );
        int64_t refTime = 0;
        for( auto& cs : ctx->second->v )
        {
            WriteTimeOffset( f, refTime, cs.WakeupVal() );
            WriteTimeOffset( f, refTime, cs.Start() );
            WriteTimeOffset( f, refTime, cs.End() );
            uint8_t cpu = cs.Cpu();
            int8_t reason = cs.Reason();
            int8_t state = cs.State();
            uint64_t thread = DecompressThread( cs.Thread() );
            f.Write( &cpu, sizeof( cpu ) );
            f.Write( &reason, sizeof( reason ) );
            f.Write( &state, sizeof( state ) );
            f.Write( &thread, sizeof( thread ) );
        }
    }

    sz = GetContextSwitchPerCpuCount();
    f.Write( &sz, sizeof( sz ) );
    for( int i=0; i<256; i++ )
    {
        sz = m_data.cpuData[i].cs.size();
        f.Write( &sz, sizeof( sz ) );
        int64_t refTime = 0;
        for( auto& cx : m_data.cpuData[i].cs )
        {
            WriteTimeOffset( f, refTime, cx.Start() );
            WriteTimeOffset( f, refTime, cx.End() );
            uint16_t thread = cx.Thread();
            f.Write( &thread, sizeof( thread ) );
        }
    }

    sz = m_data.tidToPid.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.tidToPid )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
    }

    sz = m_data.cpuThreadData.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.cpuThreadData )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
    }

    sz = m_data.symbolLoc.size();
    f.Write( &sz, sizeof( sz ) );
    sz = m_data.symbolLocInline.size();
    f.Write( &sz, sizeof( sz ) );
    sz = m_data.symbolMap.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.symbolMap )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
    }

    sz = m_data.symbolCode.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.symbolCode )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second.len, sizeof( v.second.len ) );
        f.Write( v.second.data, v.second.len );
    }

    sz = m_data.codeSymbolMap.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.codeSymbolMap )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
    }

    sz = m_data.hwSamples.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.hwSamples )
    {
        f.Write( &v.first, sizeof( v.first ) );
        WriteHwSampleVec( f, v.second.cycles );
        WriteHwSampleVec( f, v.second.retired );
        WriteHwSampleVec( f, v.second.cacheRef );
        WriteHwSampleVec( f, v.second.cacheMiss );
        WriteHwSampleVec( f, v.second.branchRetired );
        WriteHwSampleVec( f, v.second.branchMiss );
    }

    sz = m_data.sourceFileCache.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceFileCache )
    {
        uint32_t s32 = strlen( v.first );
        f.Write( &s32, sizeof( s32 ) );
        f.Write( v.first, s32 );
        f.Write( &v.second.len, sizeof( v.second.len ) );
        f.Write( v.second.data, v.second.len );
    }
}

void Worker::WriteTimeline( FileWrite& f, const Vector<short_ptr<ZoneEvent>>& vec, int64_t& refTime )
{
    uint32_t sz = uint32_t( vec.size() );
    f.Write( &sz, sizeof( sz ) );
    if( vec.is_magic() )
    {
        WriteTimelineImpl<VectorAdapterDirect<ZoneEvent>>( f, *(Vector<ZoneEvent>*)( &vec ), refTime );
    }
    else
    {
        WriteTimelineImpl<VectorAdapterPointer<ZoneEvent>>( f, vec, refTime );
    }
}

template<typename Adapter, typename V>
void Worker::WriteTimelineImpl( FileWrite& f, const V& vec, int64_t& refTime )
{
    Adapter a;
    for( auto& val : vec )
    {
        auto& v = a(val);
        int16_t srcloc = v.SrcLoc();
        f.Write( &srcloc, sizeof( srcloc ) );
        int64_t start = v.Start();
        WriteTimeOffset( f, refTime, start );
        f.Write( &v.extra, sizeof( v.extra ) );
        if( !v.HasChildren() )
        {
            const uint32_t sz = 0;
            f.Write( &sz, sizeof( sz ) );
        }
        else
        {
            WriteTimeline( f, GetZoneChildren( v.Child() ), refTime );
        }
        WriteTimeOffset( f, refTime, v.End() );
    }
}

void Worker::WriteTimeline( FileWrite& f, const Vector<short_ptr<GpuEvent>>& vec, int64_t& refTime, int64_t& refGpuTime )
{
    uint64_t sz = vec.size();
    f.Write( &sz, sizeof( sz ) );
    if( vec.is_magic() )
    {
        WriteTimelineImpl<VectorAdapterDirect<GpuEvent>>( f, *(Vector<GpuEvent>*)( &vec ), refTime, refGpuTime );
    }
    else
    {
        WriteTimelineImpl<VectorAdapterPointer<GpuEvent>>( f, vec, refTime, refGpuTime );
    }
}

template<typename Adapter, typename V>
void Worker::WriteTimelineImpl( FileWrite& f, const V& vec, int64_t& refTime, int64_t& refGpuTime )
{
    Adapter a;
    for( auto& val : vec )
    {
        auto& v = a(val);
        WriteTimeOffset( f, refTime, v.CpuStart() );
        WriteTimeOffset( f, refGpuTime, v.GpuStart() );
        const int16_t srcloc = v.SrcLoc();
        f.Write( &srcloc, sizeof( srcloc ) );
        f.Write( &v.callstack, sizeof( v.callstack ) );
        const uint16_t thread = v.Thread();
        f.Write( &thread, sizeof( thread ) );

        if( v.Child() < 0 )
        {
            const uint64_t sz = 0;
            f.Write( &sz, sizeof( sz ) );
        }
        else
        {
            WriteTimeline( f, GetGpuChildren( v.Child() ), refTime, refGpuTime );
        }

        WriteTimeOffset( f, refTime, v.CpuEnd() );
        WriteTimeOffset( f, refGpuTime, v.GpuEnd() );
    }
}

static const char* s_failureReasons[] = {
    "<unknown reason>",
    "Invalid order of zone begin and end events.",
    "Zone is ended twice.",
    "Zone text transfer destination doesn't match active zone.",
    "Zone value transfer destination doesn't match active zone.",
    "Zone color transfer destination doesn't match active zone.",
    "Zone name transfer destination doesn't match active zone.",
    "Memory free event without a matching allocation.",
    "Memory allocation event was reported for an address that is already tracked and not freed.",
    "Discontinuous frame begin/end mismatch.",
    "Frame image offset is invalid.",
    "Multiple frame images were sent for a single frame.",
    "Fiber execution stopped on a thread which is not executing a fiber.",
};

static_assert( sizeof( s_failureReasons ) / sizeof( *s_failureReasons ) == (int)Worker::Failure::NUM_FAILURES, "Missing failure reason description." );

const char* Worker::GetFailureString( Worker::Failure failure )
{
    return s_failureReasons[(int)failure];
}

void Worker::SetParameter( size_t paramIdx, int32_t val )
{
    assert( paramIdx < m_params.size() );
    m_params[paramIdx].val = val;
    const auto idx = uint64_t( m_params[paramIdx].idx );
    const auto v = uint64_t( uint32_t( val ) );
    Query( ServerQueryParameter, ( idx << 32 ) | v );
}

const Worker::CpuThreadTopology* Worker::GetThreadTopology( uint32_t cpuThread ) const
{
    auto it = m_data.cpuTopologyMap.find( cpuThread );
    if( it == m_data.cpuTopologyMap.end() ) return nullptr;
    return &it->second;
}

ZoneExtra& Worker::AllocZoneExtra( ZoneEvent& ev )
{
    assert( ev.extra == 0 );
    ev.extra = uint32_t( m_data.zoneExtra.size() );
    auto& extra = m_data.zoneExtra.push_next();
    memset( (char*)&extra, 0, sizeof( extra ) );
    return extra;
}

ZoneExtra& Worker::RequestZoneExtra( ZoneEvent& ev )
{
    if( !HasZoneExtra( ev ) )
    {
        return AllocZoneExtra( ev );
    }
    else
    {
        return GetZoneExtraMutable( ev );
    }
}

void Worker::CacheSource( const StringRef& str, const StringIdx& image )
{
    assert( str.active );
    assert( m_checkedFileStrings.find( str ) == m_checkedFileStrings.end() );
    m_checkedFileStrings.emplace( str );
    auto file = GetString( str );
    // Possible duplication of pointer and index strings
    if( m_data.sourceFileCache.find( file ) != m_data.sourceFileCache.end() ) return;
    const auto execTime = GetExecutableTime();
    if( SourceFileValid( file, execTime != 0 ? execTime : GetCaptureTime() ) )
    {
        CacheSourceFromFile( file );
    }
    else if( execTime != 0 )
    {
        QuerySourceFile( file, image.Active() ? GetString( image ) : nullptr );
    }
}

void Worker::CacheSourceFromFile( const char* fn )
{
    FILE* f = fopen( fn, "rb" );
    fseek( f, 0, SEEK_END );
    const auto sz = ftell( f );
    fseek( f, 0, SEEK_SET );
    auto src = (char*)m_slab.AllocBig( sz );
    fread( src, 1, sz, f );
    fclose( f );
    m_data.sourceFileCache.emplace( fn, MemoryBlock{ src, uint32_t( sz ) } );
}

uint64_t Worker::GetSourceFileCacheSize() const
{
    uint64_t cnt = 0;
    for( auto& v : m_data.sourceFileCache )
    {
        cnt += v.second.len;
    }
    return cnt;
}

Worker::MemoryBlock Worker::GetSourceFileFromCache( const char* file ) const
{
    auto it = m_data.sourceFileCache.find( file );
    if( it == m_data.sourceFileCache.end() ) return MemoryBlock {};
    return it->second;
}

HwSampleData* Worker::GetHwSampleData( uint64_t addr )
{
    auto it = m_data.hwSamples.find( addr );
    if( it == m_data.hwSamples.end() ) return nullptr;
    return &it->second;
}

uint64_t Worker::GetHwSampleCount() const
{
    uint64_t cnt = 0;
    for( auto& v : m_data.hwSamples )
    {
        cnt += v.second.cycles.size();
        cnt += v.second.retired.size();
        cnt += v.second.cacheRef.size();
        cnt += v.second.cacheMiss.size();
        cnt += v.second.branchRetired.size();
        cnt += v.second.branchMiss.size();
    }
    return cnt;
}

void Worker::CacheSourceFiles()
{
    const auto execTime = GetExecutableTime();

    for( auto& sl : m_data.sourceLocationPayload )
    {
        const char* file = GetString( sl->file );
        if( m_data.sourceFileCache.find( file ) == m_data.sourceFileCache.end() )
        {
            if( SourceFileValid( file, execTime != 0 ? execTime : GetCaptureTime() ) ) CacheSourceFromFile( file );
        }
    }

    for( auto& sl : m_data.sourceLocation )
    {
        const char* file = GetString( sl.second.file );
        if( m_data.sourceFileCache.find( file ) == m_data.sourceFileCache.end() )
        {
            if( SourceFileValid( file, execTime != 0 ? execTime : GetCaptureTime() ) ) CacheSourceFromFile( file );
        }
    }

    for( auto& sym : m_data.symbolMap )
    {
        const char* file = GetString( sym.second.file );
        if( m_data.sourceFileCache.find( file ) == m_data.sourceFileCache.end() )
        {
            if( SourceFileValid( file, execTime != 0 ? execTime : GetCaptureTime() ) ) CacheSourceFromFile( file );
        }
    }
}

}
