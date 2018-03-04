#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <chrono>
#include <mutex>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySystem.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

Worker::Worker( const char* addr )
    : m_addr( addr )
    , m_connected( false )
    , m_hasData( false )
    , m_shutdown( false )
    , m_terminate( false )
    , m_stream( LZ4_createStreamDecode() )
    , m_buffer( new char[TargetFrameSize*3 + 1] )
    , m_bufferOffset( 0 )
    , m_pendingStrings( 0 )
    , m_pendingThreads( 0 )
    , m_pendingSourceLocation( 0 )
{
    m_data.sourceLocationExpand.push_back( 0 );

    m_thread = std::thread( [this] { Exec(); } );
    SetThreadName( m_thread, "Tracy Worker" );
}

Worker::Worker( FileRead& f )
    : m_connected( false )
    , m_hasData( true )
    , m_shutdown( false )
    , m_terminate( false )
    , m_stream( nullptr )
    , m_buffer( nullptr )
{
    f.Read( &m_delay, sizeof( m_delay ) );
    f.Read( &m_resolution, sizeof( m_resolution ) );
    f.Read( &m_timerMul, sizeof( m_timerMul ) );
    f.Read( &m_data.lastTime, sizeof( m_data.lastTime ) );

    uint64_t sz;
    {
        f.Read( &sz, sizeof( sz ) );
        assert( sz < 1024 );
        char tmp[1024];
        f.Read( tmp, sz );
        m_captureName = std::string( tmp, tmp+sz );
    }

    f.Read( &sz, sizeof( sz ) );
    m_data.frames.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t v;
        f.Read( &v, sizeof( v ) );
        m_data.frames.push_back( v );
    }

    std::unordered_map<uint64_t, const char*> pointerMap;

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        uint64_t ssz;
        f.Read( &ssz, sizeof( ssz ) );
        auto dst = m_slab.Alloc<char>( ssz+1 );
        f.Read( dst, ssz );
        dst[ssz] = '\0';
        m_data.stringData.push_back( dst );
        pointerMap.emplace( ptr, dst );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t id, ptr;
        f.Read( &id, sizeof( id ) );
        f.Read( &ptr, sizeof( ptr ) );
        m_data.strings.emplace( id, pointerMap.find( ptr )->second );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t id, ptr;
        f.Read( &id, sizeof( id ) );
        f.Read( &ptr, sizeof( ptr ) );
        m_data.threadNames.emplace( id, pointerMap.find( ptr )->second );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        SourceLocation srcloc;
        f.Read( &srcloc, sizeof( srcloc ) );
        m_data.sourceLocation.emplace( ptr, srcloc );
    }

    f.Read( &sz, sizeof( sz ) );
    m_data.sourceLocationExpand.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t v;
        f.Read( &v, sizeof( v ) );
        m_data.sourceLocationExpand.push_back( v );
    }

    f.Read( &sz, sizeof( sz ) );
    m_data.sourceLocationPayload.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto srcloc = m_slab.Alloc<SourceLocation>();
        f.Read( srcloc, sizeof( *srcloc ) );
        m_data.sourceLocationPayload.push_back( srcloc );
        m_data.sourceLocationPayloadMap.emplace( srcloc, uint32_t( i ) );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        LockMap lockmap;
        uint32_t id;
        uint64_t tsz;
        f.Read( &id, sizeof( id ) );
        f.Read( &lockmap.srcloc, sizeof( lockmap.srcloc ) );
        f.Read( &lockmap.type, sizeof( lockmap.type ) );
        f.Read( &lockmap.valid, sizeof( lockmap.valid ) );
        f.Read( &tsz, sizeof( tsz ) );
        for( uint64_t i=0; i<tsz; i++ )
        {
            uint64_t t;
            f.Read( &t, sizeof( t ) );
            lockmap.threadMap.emplace( t, lockmap.threadList.size() );
            lockmap.threadList.emplace_back( t );
        }
        f.Read( &tsz, sizeof( tsz ) );
        lockmap.timeline.reserve( tsz );
        if( lockmap.type == LockType::Lockable )
        {
            for( uint64_t i=0; i<tsz; i++ )
            {
                auto lev = m_slab.Alloc<LockEvent>();
                f.Read( lev, sizeof( LockEvent ) );
                lockmap.timeline.push_back( lev );
            }
        }
        else
        {
            for( uint64_t i=0; i<tsz; i++ )
            {
                auto lev = m_slab.Alloc<LockEventShared>();
                f.Read( lev, sizeof( LockEventShared ) );
                lockmap.timeline.push_back( lev );
            }
        }
        m_data.lockMap.emplace( id, std::move( lockmap ) );
    }

    std::unordered_map<uint64_t, MessageData*> msgMap;
    f.Read( &sz, sizeof( sz ) );
    m_data.messages.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        auto msgdata = m_slab.Alloc<MessageData>();
        f.Read( msgdata, sizeof( *msgdata ) );
        m_data.messages.push_back( msgdata );
        msgMap.emplace( ptr, msgdata );
    }

    f.Read( &sz, sizeof( sz ) );
    m_data.threads.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto td = m_slab.AllocInit<ThreadData>();
        f.Read( &td->id, sizeof( td->id ) );
        f.Read( &td->count, sizeof( td->count ) );
        ReadTimeline( f, td->timeline );
        uint64_t msz;
        f.Read( &msz, sizeof( msz ) );
        td->messages.reserve( msz );
        for( uint64_t j=0; j<msz; j++ )
        {
            uint64_t ptr;
            f.Read( &ptr, sizeof( ptr ) );
            td->messages.push_back( msgMap[ptr] );
        }
        m_data.threads.push_back( td );
    }

    f.Read( &sz, sizeof( sz ) );
    m_data.gpuData.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto ctx = m_slab.AllocInit<GpuCtxData>();
        f.Read( &ctx->thread, sizeof( ctx->thread ) );
        f.Read( &ctx->accuracyBits, sizeof( ctx->accuracyBits ) );
        f.Read( &ctx->count, sizeof( ctx->count ) );
        ReadTimeline( f, ctx->timeline );
        m_data.gpuData.push_back( ctx );
    }

    f.Read( &sz, sizeof( sz ) );
    m_data.plots.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto pd = m_slab.AllocInit<PlotData>();
        f.Read( &pd->name, sizeof( pd->name ) );
        f.Read( &pd->min, sizeof( pd->min ) );
        f.Read( &pd->max, sizeof( pd->max ) );
        uint64_t psz;
        f.Read( &psz, sizeof( psz ) );
        pd->data.reserve_and_use( psz );
        f.Read( pd->data.data(), psz * sizeof( PlotItem ) );
        m_data.plots.push_back( pd );
    }
}

Worker::~Worker()
{
    Shutdown();
    if ( m_thread.joinable() )
    {
        m_thread.join();
    }
    delete [] m_buffer;
    LZ4_freeStreamDecode( m_stream );
}

int64_t Worker::GetFrameTime( size_t idx ) const
{
    if( idx < m_data.frames.size() - 1 )
    {
        return m_data.frames[idx+1] - m_data.frames[idx];
    }
    else
    {
        return m_data.lastTime == 0 ? 0 : m_data.lastTime - m_data.frames.back();
    }
}

int64_t Worker::GetFrameBegin( size_t idx ) const
{
    assert( idx < m_data.frames.size() );
    return m_data.frames[idx];
}

int64_t Worker::GetFrameEnd( size_t idx ) const
{
    if( idx < m_data.frames.size() - 1 )
    {
        return m_data.frames[idx+1];
    }
    else
    {
        return m_data.lastTime;
    }
}

std::pair <int, int> Worker::GetFrameRange( int64_t from, int64_t to )
{
    const auto zitbegin = std::lower_bound( m_data.frames.begin(), m_data.frames.end(), from );
    if( zitbegin == m_data.frames.end() ) return std::make_pair( -1, -1 );
    const auto zitend = std::lower_bound( zitbegin, m_data.frames.end(), to );

    int zbegin = std::distance( m_data.frames.begin(), zitbegin );
    if( zbegin > 0 && *zitbegin != from) --zbegin;
    const int zend = std::distance( m_data.frames.begin(), zitend );

    return std::make_pair( zbegin, zend );
}

int64_t Worker::GetZoneEnd( const ZoneEvent& ev ) const
{
    auto ptr = &ev;
    for(;;)
    {
        if( ptr->end != -1 ) return ptr->end;
        if( ptr->child.empty() ) return ptr->start;
        ptr = ptr->child.back();
    }
}

int64_t Worker::GetZoneEnd( const GpuEvent& ev ) const
{
    auto ptr = &ev;
    for(;;)
    {
        if( ptr->gpuEnd != -1 ) return ptr->gpuEnd;
        if( ptr->child.empty() ) return ptr->gpuStart;
        ptr = ptr->child.back();
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
    assert( idx.active );
    return m_data.stringData[idx.idx];
}

const char* Worker::GetThreadString( uint64_t id ) const
{
    const auto it = m_data.threadNames.find( id );
    if( it == m_data.threadNames.end() )
    {
        return "???";
    }
    else
    {
        return it->second;
    }
}

const SourceLocation& Worker::GetSourceLocation( int32_t srcloc ) const
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

std::vector<int32_t> Worker::GetMatchingSourceLocation( const char* query ) const
{
    std::vector<int32_t> match;

    const auto sz = m_data.sourceLocationExpand.size();
    for( size_t i=1; i<sz; i++ )
    {
        const auto it = m_data.sourceLocation.find( m_data.sourceLocationExpand[i] );
        assert( it != m_data.sourceLocation.end() );
        const auto& srcloc = it->second;
        const auto str = GetString( srcloc.name.active ? srcloc.name : srcloc.function );
        if( strstr( str, query ) != nullptr )
        {
            match.push_back( (int32_t)i );
        }
    }

    for( auto& srcloc : m_data.sourceLocationPayload )
    {
        const auto str = GetString( srcloc->name.active ? srcloc->name : srcloc->function );
        if( strstr( str, query ) != nullptr )
        {
            auto it = m_data.sourceLocationPayloadMap.find( srcloc );
            assert( it != m_data.sourceLocationPayloadMap.end() );
            match.push_back( -int32_t( it->second + 1 ) );
        }
    }

    return match;
}

void Worker::Exec()
{
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    auto ShouldExit = [this]
    {
        return m_shutdown.load( std::memory_order_relaxed );
    };

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
        if( !m_sock.Connect( m_addr.c_str(), "8086" ) ) continue;

        std::chrono::time_point<std::chrono::high_resolution_clock> t0;

        uint64_t bytes = 0;
        uint64_t decBytes = 0;

        {
            WelcomeMessage welcome;
            if( !m_sock.Read( &welcome, sizeof( welcome ), &tv, ShouldExit ) ) goto close;
            m_timerMul = welcome.timerMul;
            m_data.frames.push_back( TscTime( welcome.initBegin ) );
            m_data.frames.push_back( TscTime( welcome.initEnd ) );
            m_data.lastTime = m_data.frames.back();
            m_delay = TscTime( welcome.delay );
            m_resolution = TscTime( welcome.resolution );

            char dtmp[64];
            time_t date = welcome.epoch;
            auto lt = localtime( &date );
            strftime( dtmp, 64, "%F %T", lt );
            char tmp[1024];
            sprintf( tmp, "%s @ %s###Profiler", welcome.programName, dtmp );
            m_captureName = tmp;
        }

        m_hasData.store( true, std::memory_order_release );

        LZ4_setStreamDecode( m_stream, nullptr, 0 );
        m_connected.store( true, std::memory_order_relaxed );

        t0 = std::chrono::high_resolution_clock::now();

        for(;;)
        {
            if( m_shutdown.load( std::memory_order_relaxed ) ) return;

            auto buf = m_buffer + m_bufferOffset;
            char lz4buf[LZ4Size];
            lz4sz_t lz4sz;
            if( !m_sock.Read( &lz4sz, sizeof( lz4sz ), &tv, ShouldExit ) ) goto close;
            if( !m_sock.Read( lz4buf, lz4sz, &tv, ShouldExit ) ) goto close;
            bytes += sizeof( lz4sz ) + lz4sz;

            auto sz = LZ4_decompress_safe_continue( m_stream, lz4buf, buf, lz4sz, TargetFrameSize );
            assert( sz >= 0 );
            decBytes += sz;

            char* ptr = buf;
            const char* end = buf + sz;

            {
                std::lock_guard<NonRecursiveBenaphore> lock( m_data.lock );
                while( ptr < end )
                {
                    auto ev = (const QueueItem*)ptr;
                    DispatchProcess( *ev, ptr );
                }

                m_bufferOffset += sz;
                if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;

                HandlePostponedPlots();
            }

            auto t1 = std::chrono::high_resolution_clock::now();
            auto td = std::chrono::duration_cast<std::chrono::milliseconds>( t1 - t0 ).count();
            enum { MbpsUpdateTime = 200 };
            if( td > MbpsUpdateTime )
            {
                std::lock_guard<NonRecursiveBenaphore> lock( m_mbpsData.lock );
                m_mbpsData.mbps.erase( m_mbpsData.mbps.begin() );
                m_mbpsData.mbps.emplace_back( bytes / ( td * 125.f ) );
                m_mbpsData.compRatio = float( bytes ) / decBytes;
                t0 = t1;
                bytes = 0;
                decBytes = 0;
            }

            if( m_terminate )
            {
                if( m_pendingStrings != 0 || m_pendingThreads != 0 || m_pendingSourceLocation != 0 ||
                    !m_pendingCustomStrings.empty() || !m_pendingPlots.empty() )
                {
                    continue;
                }
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
                ServerQuery( ServerQueryTerminate, 0 );
                break;
            }
        }

close:
        m_sock.Close();
        m_connected.store( false, std::memory_order_relaxed );
    }
}

void Worker::ServerQuery( uint8_t type, uint64_t data )
{
    enum { DataSize = sizeof( type ) + sizeof( data ) };
    char tmp[DataSize];
    memcpy( tmp, &type, sizeof( type ) );
    memcpy( tmp + sizeof( type ), &data, sizeof( data ) );
    m_sock.Send( tmp, DataSize );
}

void Worker::DispatchProcess( const QueueItem& ev, char*& ptr )
{
    if( ev.hdr.type == QueueType::CustomStringData || ev.hdr.type == QueueType::StringData
        || ev.hdr.type == QueueType::ThreadName || ev.hdr.type == QueueType::PlotName || ev.hdr.type == QueueType::SourceLocationPayload )
    {
        ptr += sizeof( QueueHeader ) + sizeof( QueueStringTransfer );
        uint16_t sz;
        memcpy( &sz, ptr, sizeof( sz ) );
        ptr += sizeof( sz );
        switch( ev.hdr.type )
        {
        case QueueType::CustomStringData:
            AddCustomString( ev.stringTransfer.ptr, ptr, sz );
            break;
        case QueueType::StringData:
            AddString( ev.stringTransfer.ptr, ptr, sz );
            break;
        case QueueType::ThreadName:
            AddThreadString( ev.stringTransfer.ptr, ptr, sz );
            break;
        case QueueType::PlotName:
            HandlePlotName( ev.stringTransfer.ptr, ptr, sz );
            break;
        case QueueType::SourceLocationPayload:
            AddSourceLocationPayload( ev.stringTransfer.ptr, ptr, sz );
            break;
        default:
            assert( false );
            break;
        }
        ptr += sz;
    }
    else
    {
        ptr += QueueDataSize[ev.hdr.idx];
        Process( ev );
    }
}

void Worker::CheckSourceLocation( uint64_t ptr )
{
    if( m_data.sourceLocation.find( ptr ) == m_data.sourceLocation.end() )
    {
        NewSourceLocation( ptr );
    }
}

void Worker::NewSourceLocation( uint64_t ptr )
{
    static const SourceLocation emptySourceLocation = {};

    m_data.sourceLocation.emplace( ptr, emptySourceLocation );
    m_pendingSourceLocation++;
    m_sourceLocationQueue.push_back( ptr );

    ServerQuery( ServerQuerySourceLocation, ptr );
}

uint32_t Worker::ShrinkSourceLocation( uint64_t srcloc )
{
    auto it = m_sourceLocationShrink.find( srcloc );
    if( it != m_sourceLocationShrink.end() )
    {
        return it->second;
    }
    else
    {
        return NewShrinkedSourceLocation( srcloc );
    }
}

uint32_t Worker::NewShrinkedSourceLocation( uint64_t srcloc )
{
    const auto sz = m_data.sourceLocationExpand.size();
    m_data.sourceLocationExpand.push_back( srcloc );
    m_sourceLocationShrink.emplace( srcloc, sz );
    return sz;
}

void Worker::InsertMessageData( MessageData* msg, uint64_t thread )
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

    auto vec = &NoticeThread( thread )->messages;
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

ThreadData* Worker::NoticeThread( uint64_t thread )
{
    auto it = m_threadMap.find( thread );
    if( it != m_threadMap.end() )
    {
        return it->second;
    }
    else
    {
        return NewThread( thread );
    }
}

ThreadData* Worker::NewThread( uint64_t thread )
{
    CheckThreadString( thread );
    auto td = m_slab.AllocInit<ThreadData>();
    td->id = thread;
    td->count = 0;
    m_data.threads.push_back( td );
    m_threadMap.emplace( thread, td );
    return td;
}

void Worker::NewZone( ZoneEvent* zone, uint64_t thread )
{
    m_data.zonesCnt++;
    auto td = NoticeThread( thread );
    td->count++;
    if( td->stack.empty() )
    {
        td->stack.push_back( zone );
        td->timeline.push_back( zone );
    }
    else
    {
        td->stack.back()->child.push_back( zone );
        td->stack.push_back_non_empty( zone );
    }
}

static void UpdateLockCountLockable( LockMap& lockmap, size_t pos )
{
    auto& timeline = lockmap.timeline;
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
        const auto tl = timeline[pos-1];
        lockingThread = tl->lockingThread;
        lockCount = tl->lockCount;
        waitList = tl->waitList;
    }
    const auto end = timeline.size();

    while( pos != end )
    {
        const auto tl = timeline[pos];
        const auto tbit = uint64_t( 1 ) << tl->thread;
        switch( (LockEvent::Type)tl->type )
        {
        case LockEvent::Type::Wait:
            waitList |= tbit;
            break;
        case LockEvent::Type::Obtain:
            assert( lockCount < std::numeric_limits<uint8_t>::max() );
            assert( ( waitList & tbit ) != 0 );
            waitList &= ~tbit;
            lockingThread = tl->thread;
            lockCount++;
            break;
        case LockEvent::Type::Release:
            assert( lockCount > 0 );
            lockCount--;
            break;
        default:
            break;
        }
        tl->lockingThread = lockingThread;
        tl->waitList = waitList;
        tl->lockCount = lockCount;
        assert( tl->lockingThread == lockingThread );
        pos++;
    }
}

static void UpdateLockCountSharedLockable( LockMap& lockmap, size_t pos )
{
    auto& timeline = lockmap.timeline;
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
        const auto tl = (LockEventShared*)timeline[pos-1];
        lockingThread = tl->lockingThread;
        lockCount = tl->lockCount;
        waitShared = tl->waitShared;
        waitList = tl->waitList;
        sharedList = tl->sharedList;
    }
    const auto end = timeline.size();

    // ObtainShared and ReleaseShared should assert on lockCount == 0, but
    // due to the async retrieval of data from threads that not possible.
    while( pos != end )
    {
        const auto tl = (LockEventShared*)timeline[pos];
        const auto tbit = uint64_t( 1 ) << tl->thread;
        switch( (LockEvent::Type)tl->type )
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
            lockingThread = tl->thread;
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
        tl->lockingThread = lockingThread;
        tl->waitShared = waitShared;
        tl->waitList = waitList;
        tl->sharedList = sharedList;
        tl->lockCount = lockCount;
        assert( tl->lockingThread == lockingThread );
        pos++;
    }
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

void Worker::InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread )
{
    m_data.lastTime = std::max( m_data.lastTime, lev->time );

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
        timeline.push_back( lev );
        UpdateLockCount( lockmap, timeline.size() - 1 );
    }
    else if( timeline.back()->time < lev->time )
    {
        timeline.push_back_non_empty( lev );
        UpdateLockCount( lockmap, timeline.size() - 1 );
    }
    else
    {
        auto it = std::lower_bound( timeline.begin(), timeline.end(), lev->time, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        it = timeline.insert( it, lev );
        UpdateLockCount( lockmap, std::distance( timeline.begin(), it ) );
    }
}

void Worker::CheckString( uint64_t ptr )
{
    if( ptr == 0 ) return;
    if( m_data.strings.find( ptr ) != m_data.strings.end() ) return;

    m_data.strings.emplace( ptr, "???" );
    m_pendingStrings++;

    ServerQuery( ServerQueryString, ptr );
}

void Worker::CheckThreadString( uint64_t id )
{
    if( m_data.threadNames.find( id ) != m_data.threadNames.end() ) return;

    m_data.threadNames.emplace( id, "???" );
    m_pendingThreads++;

    ServerQuery( ServerQueryThreadString, id );
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
    CheckString( srcloc.file );
    CheckString( srcloc.function );
    uint32_t color = ( srcloc.r << 16 ) | ( srcloc.g << 8 ) | srcloc.b;
    it->second = SourceLocation { srcloc.name == 0 ? StringRef() : StringRef( StringRef::Ptr, srcloc.name ), StringRef( StringRef::Ptr, srcloc.function ), StringRef( StringRef::Ptr, srcloc.file ), srcloc.line, color };
}

void Worker::AddSourceLocationPayload( uint64_t ptr, char* data, size_t sz )
{
    const auto start = data;

    assert( m_pendingSourceLocationPayload.find( ptr ) == m_pendingSourceLocationPayload.end() );

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

    SourceLocation srcloc { nsz == 0 ? StringRef() : StringRef( StringRef::Idx, StoreString( end, nsz ).idx ), StringRef( StringRef::Idx, func.idx ), StringRef( StringRef::Idx, source.idx ), line, color };
    auto it = m_data.sourceLocationPayloadMap.find( &srcloc );
    if( it == m_data.sourceLocationPayloadMap.end() )
    {
        auto slptr = m_slab.Alloc<SourceLocation>();
        memcpy( slptr, &srcloc, sizeof( srcloc ) );
        uint32_t idx = m_data.sourceLocationPayload.size();
        m_data.sourceLocationPayloadMap.emplace( slptr, idx );
        m_pendingSourceLocationPayload.emplace( ptr, -int32_t( idx + 1 ) );
        m_data.sourceLocationPayload.push_back( slptr );
    }
    else
    {
        m_pendingSourceLocationPayload.emplace( ptr, -int32_t( it->second + 1 ) );
    }
}

void Worker::AddString( uint64_t ptr, char* str, size_t sz )
{
    assert( m_pendingStrings > 0 );
    m_pendingStrings--;
    auto it = m_data.strings.find( ptr );
    assert( it != m_data.strings.end() && strcmp( it->second, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    it->second = sl.ptr;
}

void Worker::AddThreadString( uint64_t id, char* str, size_t sz )
{
    assert( m_pendingThreads > 0 );
    m_pendingThreads--;
    auto it = m_data.threadNames.find( id );
    assert( it != m_data.threadNames.end() && strcmp( it->second, "???" ) == 0 );
    const auto sl = StoreString( str, sz );
    it->second = sl.ptr;
}

void Worker::AddCustomString( uint64_t ptr, char* str, size_t sz )
{
    assert( m_pendingCustomStrings.find( ptr ) == m_pendingCustomStrings.end() );
    m_pendingCustomStrings.emplace( ptr, StoreString( str, sz ) );
}

void Worker::InsertPlot( PlotData* plot, int64_t time, double val )
{
    if( plot->data.empty() )
    {
        plot->min = val;
        plot->max = val;
        plot->data.push_back( { time, val } );
    }
    else if( plot->data.back().time < time )
    {
        if( plot->min > val ) plot->min = val;
        else if( plot->max < val ) plot->max = val;
        plot->data.push_back_non_empty( { time, val } );
    }
    else
    {
        if( plot->min > val ) plot->min = val;
        else if( plot->max < val ) plot->max = val;
        if( plot->postpone.empty() )
        {
            plot->postponeTime = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
            plot->postpone.push_back( { time, val } );
        }
        else
        {
            plot->postpone.push_back_non_empty( { time, val } );
        }
    }
}

void Worker::HandlePlotName( uint64_t name, char* str, size_t sz )
{
    auto pit = m_pendingPlots.find( name );
    assert( pit != m_pendingPlots.end() );

    const auto sl = StoreString( str, sz );

    auto it = m_plotRev.find( sl.ptr );
    if( it == m_plotRev.end() )
    {
        m_plotMap.emplace( name, pit->second );
        m_plotRev.emplace( sl.ptr, pit->second );
        m_data.plots.push_back( pit->second );
        m_data.strings.emplace( name, sl.ptr );
    }
    else
    {
        auto plot = it->second;
        m_plotMap.emplace( name, plot );
        const auto& pp = pit->second->data;
        for( auto& v : pp )
        {
            InsertPlot( plot, v.time, v.val );
        }
        // TODO what happens with the source data here?
    }

    m_pendingPlots.erase( pit );
}

void Worker::HandlePostponedPlots()
{
    for( auto& plot : m_data.plots )
    {
        auto& src = plot->postpone;
        if( src.empty() ) continue;
        if( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count() - plot->postponeTime < 100 ) continue;
        auto& dst = plot->data;
        std::sort( src.begin(), src.end(), [] ( const auto& l, const auto& r ) { return l.time < r.time; } );
        const auto ds = std::lower_bound( dst.begin(), dst.end(), src.front().time, [] ( const auto& l, const auto& r ) { return l.time < r; } );
        const auto dsd = std::distance( dst.begin(), ds ) ;
        const auto de = std::lower_bound( ds, dst.end(), src.back().time, [] ( const auto& l, const auto& r ) { return l.time < r; } );
        const auto ded = std::distance( dst.begin(), de );
        dst.insert( de, src.begin(), src.end() );
        std::inplace_merge( dst.begin() + dsd, dst.begin() + ded, dst.begin() + ded + src.size(), [] ( const auto& l, const auto& r ) { return l.time < r.time; } );
        src.clear();
    }
}

StringLocation Worker::StoreString( char* str, size_t sz )
{
    StringLocation ret;
    const char backup = str[sz];
    str[sz] = '\0';
    auto sit = m_data.stringMap.find( str );
    if( sit == m_data.stringMap.end() )
    {
        auto ptr = m_slab.Alloc<char>( sz+1 );
        memcpy( ptr, str, sz+1 );
        ret.ptr = ptr;
        ret.idx = m_data.stringData.size();
        m_data.stringMap.emplace( ptr, m_data.stringData.size() );
        m_data.stringData.push_back( ptr );
    }
    else
    {
        ret.ptr = sit->first;
        ret.idx = sit->second;
    }
    str[sz] = backup;
    return ret;
}

void Worker::Process( const QueueItem& ev )
{
    switch( ev.hdr.type )
    {
    case QueueType::ZoneBegin:
        ProcessZoneBegin( ev.zoneBegin );
        break;
    case QueueType::ZoneBeginAllocSrcLoc:
        ProcessZoneBeginAllocSrcLoc( ev.zoneBegin );
        break;
    case QueueType::ZoneEnd:
        ProcessZoneEnd( ev.zoneEnd );
        break;
    case QueueType::FrameMarkMsg:
        ProcessFrameMark( ev.frameMark );
        break;
    case QueueType::SourceLocation:
        AddSourceLocation( ev.srcloc );
        break;
    case QueueType::ZoneText:
        ProcessZoneText( ev.zoneText );
        break;
    case QueueType::LockAnnounce:
        ProcessLockAnnounce( ev.lockAnnounce );
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
        ProcessLockSharedRelease( ev.lockRelease );
        break;
    case QueueType::LockMark:
        ProcessLockMark( ev.lockMark );
        break;
    case QueueType::PlotData:
        ProcessPlotData( ev.plotData );
        break;
    case QueueType::Message:
        ProcessMessage( ev.message );
        break;
    case QueueType::MessageLiteral:
        ProcessMessageLiteral( ev.message );
        break;
    case QueueType::GpuNewContext:
        ProcessGpuNewContext( ev.gpuNewContext );
        break;
    case QueueType::GpuZoneBegin:
        ProcessGpuZoneBegin( ev.gpuZoneBegin );
        break;
    case QueueType::GpuZoneEnd:
        ProcessGpuZoneEnd( ev.gpuZoneEnd );
        break;
    case QueueType::GpuTime:
        ProcessGpuTime( ev.gpuTime );
        break;
    case QueueType::GpuResync:
        ProcessGpuResync( ev.gpuResync );
        break;
    case QueueType::Terminate:
        m_terminate = true;
        break;
    default:
        assert( false );
        break;
    }
}

void Worker::ProcessZoneBegin( const QueueZoneBegin& ev )
{
    auto zone = m_slab.AllocInit<ZoneEvent>();

    CheckSourceLocation( ev.srcloc );

    zone->start = TscTime( ev.time );
    zone->end = -1;
    zone->srcloc = ShrinkSourceLocation( ev.srcloc );
    assert( ev.cpu == 0xFFFFFFFF || ev.cpu <= std::numeric_limits<int8_t>::max() );
    zone->cpu_start = ev.cpu == 0xFFFFFFFF ? -1 : (int8_t)ev.cpu;

    m_data.lastTime = std::max( m_data.lastTime, zone->start );

    NewZone( zone, ev.thread );
}

void Worker::ProcessZoneBeginAllocSrcLoc( const QueueZoneBegin& ev )
{
    auto it = m_pendingSourceLocationPayload.find( ev.srcloc );
    assert( it != m_pendingSourceLocationPayload.end() );

    auto zone = m_slab.AllocInit<ZoneEvent>();

    zone->start = TscTime( ev.time );
    zone->end = -1;
    zone->srcloc = it->second;
    assert( ev.cpu == 0xFFFFFFFF || ev.cpu <= std::numeric_limits<int8_t>::max() );
    zone->cpu_start = ev.cpu == 0xFFFFFFFF ? -1 : (int8_t)ev.cpu;

    m_data.lastTime = std::max( m_data.lastTime, zone->start );

    NewZone( zone, ev.thread );

    m_pendingSourceLocationPayload.erase( it );
}

void Worker::ProcessZoneEnd( const QueueZoneEnd& ev )
{
    auto tit = m_threadMap.find( ev.thread );
    assert( tit != m_threadMap.end() );

    auto td = tit->second;
    auto& stack = td->stack;
    assert( !stack.empty() );
    auto zone = stack.back_and_pop();
    assert( zone->end == -1 );
    zone->end = TscTime( ev.time );
    assert( ev.cpu == 0xFFFFFFFF || ev.cpu <= std::numeric_limits<int8_t>::max() );
    zone->cpu_end = ev.cpu == 0xFFFFFFFF ? -1 : (int8_t)ev.cpu;
    assert( zone->end >= zone->start );

    m_data.lastTime = std::max( m_data.lastTime, zone->end );
}

void Worker::ProcessFrameMark( const QueueFrameMark& ev )
{
    assert( !m_data.frames.empty() );
    const auto lastframe = m_data.frames.back();
    const auto time = TscTime( ev.time );
    assert( lastframe < time );
    m_data.frames.push_back_non_empty( time );
    m_data.lastTime = std::max( m_data.lastTime, time );
}

void Worker::ProcessZoneText( const QueueZoneText& ev )
{
    auto tit = m_threadMap.find( ev.thread );
    assert( tit != m_threadMap.end() );

    auto td = tit->second;
    auto& stack = td->stack;
    assert( !stack.empty() );
    auto zone = stack.back();
    auto it = m_pendingCustomStrings.find( ev.text );
    assert( it != m_pendingCustomStrings.end() );
    zone->text = StringIdx( it->second.idx );
    m_pendingCustomStrings.erase( it );
}

void Worker::ProcessLockAnnounce( const QueueLockAnnounce& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    if( it == m_data.lockMap.end() )
    {
        LockMap lm;
        lm.srcloc = ShrinkSourceLocation( ev.lckloc );
        lm.type = ev.type;
        m_data.lockMap.emplace( ev.id, std::move( lm ) );
    }
    else
    {
        it->second.srcloc = ShrinkSourceLocation( ev.lckloc );
        assert( it->second.type == ev.type );
        it->second.valid = true;
    }
    CheckSourceLocation( ev.lckloc );
}

void Worker::ProcessLockWait( const QueueLockWait& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    if( it == m_data.lockMap.end() )
    {
        LockMap lm;
        lm.valid = false;
        lm.type = ev.type;
        it = m_data.lockMap.emplace( ev.id, std::move( lm ) ).first;
    }

    auto lev = ev.type == LockType::Lockable ? m_slab.Alloc<LockEvent>() : m_slab.Alloc<LockEventShared>();
    lev->time = TscTime( ev.time );
    lev->type = LockEvent::Type::Wait;
    lev->srcloc = 0;

    InsertLockEvent( it->second, lev, ev.thread );
}

void Worker::ProcessLockObtain( const QueueLockObtain& ev )
{
    assert( m_data.lockMap.find( ev.id ) != m_data.lockMap.end() );
    auto& lock = m_data.lockMap[ev.id];

    auto lev = lock.type == LockType::Lockable ? m_slab.Alloc<LockEvent>() : m_slab.Alloc<LockEventShared>();
    lev->time = TscTime( ev.time );
    lev->type = LockEvent::Type::Obtain;
    lev->srcloc = 0;

    InsertLockEvent( lock, lev, ev.thread );
}

void Worker::ProcessLockRelease( const QueueLockRelease& ev )
{
    assert( m_data.lockMap.find( ev.id ) != m_data.lockMap.end() );
    auto& lock = m_data.lockMap[ev.id];

    auto lev = lock.type == LockType::Lockable ? m_slab.Alloc<LockEvent>() : m_slab.Alloc<LockEventShared>();
    lev->time = TscTime( ev.time );
    lev->type = LockEvent::Type::Release;
    lev->srcloc = 0;

    InsertLockEvent( lock, lev, ev.thread );
}

void Worker::ProcessLockSharedWait( const QueueLockWait& ev )
{
    auto it = m_data.lockMap.find( ev.id );
    if( it == m_data.lockMap.end() )
    {
        LockMap lm;
        lm.valid = false;
        lm.type = ev.type;
        it = m_data.lockMap.emplace( ev.id, std::move( lm ) ).first;
    }

    assert( ev.type == LockType::SharedLockable );
    auto lev = m_slab.Alloc<LockEventShared>();
    lev->time = TscTime( ev.time );
    lev->type = LockEvent::Type::WaitShared;
    lev->srcloc = 0;

    InsertLockEvent( it->second, lev, ev.thread );
}

void Worker::ProcessLockSharedObtain( const QueueLockObtain& ev )
{
    assert( m_data.lockMap.find( ev.id ) != m_data.lockMap.end() );
    auto& lock = m_data.lockMap[ev.id];

    assert( lock.type == LockType::SharedLockable );
    auto lev = m_slab.Alloc<LockEventShared>();
    lev->time = TscTime( ev.time );
    lev->type = LockEvent::Type::ObtainShared;
    lev->srcloc = 0;

    InsertLockEvent( lock, lev, ev.thread );
}

void Worker::ProcessLockSharedRelease( const QueueLockRelease& ev )
{
    assert( m_data.lockMap.find( ev.id ) != m_data.lockMap.end() );
    auto& lock = m_data.lockMap[ev.id];

    assert( lock.type == LockType::SharedLockable );
    auto lev = m_slab.Alloc<LockEventShared>();
    lev->time = TscTime( ev.time );
    lev->type = LockEvent::Type::ReleaseShared;
    lev->srcloc = 0;

    InsertLockEvent( lock, lev, ev.thread );
}

void Worker::ProcessLockMark( const QueueLockMark& ev )
{
    CheckSourceLocation( ev.srcloc );
    auto lit = m_data.lockMap.find( ev.id );
    assert( lit != m_data.lockMap.end() );
    auto& lockmap = lit->second;
    auto tid = lockmap.threadMap.find( ev.thread );
    assert( tid != lockmap.threadMap.end() );
    const auto thread = tid->second;
    auto it = lockmap.timeline.end();
    for(;;)
    {
        --it;
        if( (*it)->thread == thread )
        {
            switch( (*it)->type )
            {
            case LockEvent::Type::Obtain:
            case LockEvent::Type::ObtainShared:
            case LockEvent::Type::Wait:
            case LockEvent::Type::WaitShared:
                (*it)->srcloc = ShrinkSourceLocation( ev.srcloc );
                return;
            default:
                break;
            }
        }
    }
}

void Worker::ProcessPlotData( const QueuePlotData& ev )
{
    PlotData* plot;
    auto it = m_plotMap.find( ev.name );
    if( it == m_plotMap.end() )
    {
        auto pit = m_pendingPlots.find( ev.name );
        if( pit == m_pendingPlots.end() )
        {
            plot = m_slab.AllocInit<PlotData>();
            plot->name = ev.name;
            m_pendingPlots.emplace( ev.name, plot );
            ServerQuery( ServerQueryPlotName, ev.name );
        }
        else
        {
            plot = pit->second;
        }
    }
    else
    {
        plot = it->second;
    }

    const auto time = TscTime( ev.time );
    m_data.lastTime = std::max( m_data.lastTime, time );
    switch( ev.type )
    {
    case PlotDataType::Double:
        InsertPlot( plot, time, ev.data.d );
        break;
    case PlotDataType::Float:
        InsertPlot( plot, time, (double)ev.data.f );
        break;
    case PlotDataType::Int:
        InsertPlot( plot, time, (double)ev.data.i );
        break;
    default:
        assert( false );
        break;
    }
}

void Worker::ProcessMessage( const QueueMessage& ev )
{
    auto it = m_pendingCustomStrings.find( ev.text );
    assert( it != m_pendingCustomStrings.end() );
    auto msg = m_slab.Alloc<MessageData>();
    msg->time = TscTime( ev.time );
    msg->ref = StringRef( StringRef::Type::Idx, it->second.idx );
    m_data.lastTime = std::max( m_data.lastTime, msg->time );
    InsertMessageData( msg, ev.thread );
    m_pendingCustomStrings.erase( it );
}

void Worker::ProcessMessageLiteral( const QueueMessage& ev )
{
    CheckString( ev.text );
    auto msg = m_slab.Alloc<MessageData>();
    msg->time = TscTime( ev.time );
    msg->ref = StringRef( StringRef::Type::Ptr, ev.text );
    m_data.lastTime = std::max( m_data.lastTime, msg->time );
    InsertMessageData( msg, ev.thread );
}

void Worker::ProcessGpuNewContext( const QueueGpuNewContext& ev )
{
    assert( m_gpuCtxMap.find( ev.context ) == m_gpuCtxMap.end() );

    auto gpu = m_slab.AllocInit<GpuCtxData>();
    gpu->timeDiff = TscTime( ev.cpuTime ) - ev.gpuTime;
    gpu->thread = ev.thread;
    gpu->accuracyBits = ev.accuracyBits;
    gpu->count = 0;
    m_data.gpuData.push_back( gpu );
    m_gpuCtxMap.emplace( ev.context, gpu );
}

void Worker::ProcessGpuZoneBegin( const QueueGpuZoneBegin& ev )
{
    auto it = m_gpuCtxMap.find( ev.context );
    assert( it != m_gpuCtxMap.end() );
    auto ctx = it->second;

    CheckSourceLocation( ev.srcloc );

    auto zone = m_slab.AllocInit<GpuEvent>();

    zone->cpuStart = TscTime( ev.cpuTime );
    zone->cpuEnd = -1;
    zone->gpuStart = std::numeric_limits<int64_t>::max();
    zone->gpuEnd = -1;
    zone->srcloc = ShrinkSourceLocation( ev.srcloc );

    m_data.lastTime = std::max( m_data.lastTime, zone->cpuStart );

    auto timeline = &ctx->timeline;
    if( !ctx->stack.empty() )
    {
        timeline = &ctx->stack.back()->child;
    }

    timeline->push_back( zone );

    ctx->stack.push_back( zone );
    ctx->queue.push_back( zone );
}

void Worker::ProcessGpuZoneEnd( const QueueGpuZoneEnd& ev )
{
    auto it = m_gpuCtxMap.find( ev.context );
    assert( it != m_gpuCtxMap.end() );
    auto ctx = it->second;

    assert( !ctx->stack.empty() );
    auto zone = ctx->stack.back_and_pop();
    ctx->queue.push_back( zone );

    zone->cpuEnd = TscTime( ev.cpuTime );
    m_data.lastTime = std::max( m_data.lastTime, zone->cpuEnd );
}

void Worker::ProcessGpuTime( const QueueGpuTime& ev )
{
    auto it = m_gpuCtxMap.find( ev.context );
    assert( it != m_gpuCtxMap.end() );
    auto ctx = it->second;

    auto zone = ctx->queue.front();
    if( zone->gpuStart == std::numeric_limits<int64_t>::max() )
    {
        zone->gpuStart = ctx->timeDiff + ev.gpuTime;
        m_data.lastTime = std::max( m_data.lastTime, zone->gpuStart );
        ctx->count++;
    }
    else
    {
        zone->gpuEnd = ctx->timeDiff + ev.gpuTime;
        m_data.lastTime = std::max( m_data.lastTime, zone->gpuEnd );
    }

    ctx->queue.erase( ctx->queue.begin() );
    if( !ctx->resync.empty() )
    {
        auto& resync = ctx->resync.front();
        assert( resync.events > 0 );
        resync.events--;
        if( resync.events == 0 )
        {
            ctx->timeDiff = resync.timeDiff;
            ctx->resync.erase( ctx->resync.begin() );
        }
    }
}

void Worker::ProcessGpuResync( const QueueGpuResync& ev )
{
    auto it = m_gpuCtxMap.find( ev.context );
    assert( it != m_gpuCtxMap.end() );
    auto ctx = it->second;

    const auto timeDiff = TscTime( ev.cpuTime ) - ev.gpuTime;

    if( ctx->queue.empty() )
    {
        assert( ctx->resync.empty() );
        ctx->timeDiff = timeDiff;
    }
    else
    {
        if( ctx->resync.empty() )
        {
            ctx->resync.push_back( { timeDiff, uint16_t( ctx->queue.size() ) } );
        }
        else
        {
            const auto last = ctx->resync.back().events;
            ctx->resync.push_back( { timeDiff, uint16_t( ctx->queue.size() - last ) } );
        }
    }
}

void Worker::ReadTimeline( FileRead& f, Vector<ZoneEvent*>& vec )
{
    uint64_t sz;
    f.Read( &sz, sizeof( sz ) );
    vec.reserve( sz );

    for( uint64_t i=0; i<sz; i++ )
    {
        auto zone = m_slab.AllocInit<ZoneEvent>();

        m_data.zonesCnt++;
        vec.push_back( zone );

        f.Read( &zone->start, sizeof( zone->start ) );
        f.Read( &zone->end, sizeof( zone->end ) );
        f.Read( &zone->srcloc, sizeof( zone->srcloc ) );
        f.Read( &zone->cpu_start, sizeof( zone->cpu_start ) );
        f.Read( &zone->cpu_end, sizeof( zone->cpu_end ) );
        f.Read( &zone->text, sizeof( zone->text ) );
        ReadTimeline( f, zone->child );
    }
}

void Worker::ReadTimeline( FileRead& f, Vector<GpuEvent*>& vec )
{
    uint64_t sz;
    f.Read( &sz, sizeof( sz ) );
    vec.reserve( sz );

    for( uint64_t i=0; i<sz; i++ )
    {
        auto zone = m_slab.AllocInit<GpuEvent>();

        vec.push_back( zone );

        f.Read( &zone->cpuStart, sizeof( zone->cpuStart ) );
        f.Read( &zone->cpuEnd, sizeof( zone->cpuEnd ) );
        f.Read( &zone->gpuStart, sizeof( zone->gpuStart ) );
        f.Read( &zone->gpuEnd, sizeof( zone->gpuEnd ) );
        f.Read( &zone->srcloc, sizeof( zone->srcloc ) );
        ReadTimeline( f, zone->child );
    }
}

void Worker::Write( FileWrite& f )
{
    f.Write( &m_delay, sizeof( m_delay ) );
    f.Write( &m_resolution, sizeof( m_resolution ) );
    f.Write( &m_timerMul, sizeof( m_timerMul ) );
    f.Write( &m_data.lastTime, sizeof( m_data.lastTime ) );

    uint64_t sz = m_captureName.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_captureName.c_str(), sz );

    sz = m_data.frames.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_data.frames.data(), sizeof( uint64_t ) * sz );

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

    sz = m_data.sourceLocation.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.sourceLocation )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
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
        f.Write( v, sizeof( *v ) );
    }

    sz = m_data.lockMap.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.lockMap )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second.srcloc, sizeof( v.second.srcloc ) );
        f.Write( &v.second.type, sizeof( v.second.type ) );
        f.Write( &v.second.valid, sizeof( v.second.valid ) );
        sz = v.second.threadList.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& t : v.second.threadList )
        {
            f.Write( &t, sizeof( t ) );
        }
        sz = v.second.timeline.size();
        f.Write( &sz, sizeof( sz ) );
        if( v.second.type == LockType::Lockable )
        {
            for( auto& lev : v.second.timeline )
            {
                f.Write( lev, sizeof( LockEvent ) );
            }
        }
        else
        {
            for( auto& lev : v.second.timeline )
            {
                f.Write( lev, sizeof( LockEventShared ) );
            }
        }
    }

    sz = m_data.messages.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_data.messages )
    {
        const auto ptr = (uint64_t)v;
        f.Write( &ptr, sizeof( ptr ) );
        f.Write( v, sizeof( *v ) );
    }

    sz = m_data.threads.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& thread : m_data.threads )
    {
        f.Write( &thread->id, sizeof( thread->id ) );
        f.Write( &thread->count, sizeof( thread->count ) );
        WriteTimeline( f, thread->timeline );
        sz = thread->messages.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& v : thread->messages )
        {
            auto ptr = uint64_t( v );
            f.Write( &ptr, sizeof( ptr ) );
        }
    }

    sz = m_data.gpuData.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& ctx : m_data.gpuData )
    {
        f.Write( &ctx->thread, sizeof( ctx->thread ) );
        f.Write( &ctx->accuracyBits, sizeof( ctx->accuracyBits ) );
        f.Write( &ctx->count, sizeof( ctx->count ) );
        WriteTimeline( f, ctx->timeline );
    }

    sz = m_data.plots.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& plot : m_data.plots )
    {
        f.Write( &plot->name, sizeof( plot->name ) );
        f.Write( &plot->min, sizeof( plot->min ) );
        f.Write( &plot->max, sizeof( plot->max ) );
        sz = plot->data.size();
        f.Write( &sz, sizeof( sz ) );
        f.Write( plot->data.data(), sizeof( PlotItem ) * sz );
    }
}

void Worker::WriteTimeline( FileWrite& f, const Vector<ZoneEvent*>& vec )
{
    uint64_t sz = vec.size();
    f.Write( &sz, sizeof( sz ) );

    for( auto& v : vec )
    {
        f.Write( &v->start, sizeof( v->start ) );
        f.Write( &v->end, sizeof( v->end ) );
        f.Write( &v->srcloc, sizeof( v->srcloc ) );
        f.Write( &v->cpu_start, sizeof( v->cpu_start ) );
        f.Write( &v->cpu_end, sizeof( v->cpu_end ) );
        f.Write( &v->text, sizeof( v->text ) );
        WriteTimeline( f, v->child );
    }
}

void Worker::WriteTimeline( FileWrite& f, const Vector<GpuEvent*>& vec )
{
    uint64_t sz = vec.size();
    f.Write( &sz, sizeof( sz ) );

    for( auto& v : vec )
    {
        f.Write( &v->cpuStart, sizeof( v->cpuStart ) );
        f.Write( &v->cpuEnd, sizeof( v->cpuEnd ) );
        f.Write( &v->gpuStart, sizeof( v->gpuStart ) );
        f.Write( &v->gpuEnd, sizeof( v->gpuEnd ) );
        f.Write( &v->srcloc, sizeof( v->srcloc ) );
        WriteTimeline( f, v->child );
    }
}

}
