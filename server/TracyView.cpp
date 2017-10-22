#ifdef _MSC_VER
#  include <winsock2.h>
#else
#  include <sys/time.h>
#endif

#include <algorithm>
#include <assert.h>
#include <chrono>
#include <inttypes.h>
#include <limits>
#include <math.h>
#include <stdlib.h>
#include <time.h>

#include "../common/TracyProtocol.hpp"
#include "../common/TracySystem.hpp"
#include "../common/TracyQueue.hpp"
#include "TracyFileRead.hpp"
#include "TracyFileWrite.hpp"
#include "TracyImGui.hpp"
#include "TracyView.hpp"

#ifdef TRACY_FILESELECTOR
#  include "../nfd/nfd.h"
#endif

#ifdef _MSC_VER
#  include <intrin.h>
#  define CountBits __popcnt64
#else
static int CountBits( uint64_t i )
{
    i = i - ( (i >> 1) & 0x5555555555555555 );
    i = ( i & 0x3333333333333333 ) + ( (i >> 2) & 0x3333333333333333 );
    i = ( (i + (i >> 4) ) & 0x0F0F0F0F0F0F0F0F );
    return ( i * (0x0101010101010101) ) >> 56;
}
#endif

namespace tracy
{

enum { MinVisSize = 3 };

static View* s_instance = nullptr;

View::View( const char* addr )
    : m_addr( addr )
    , m_shutdown( false )
    , m_connected( false )
    , m_hasData( false )
    , m_staticView( false )
    , m_zonesCnt( 0 )
    , m_mbps( 64 )
    , m_stream( LZ4_createStreamDecode() )
    , m_buffer( new char[TargetFrameSize*3] )
    , m_bufferOffset( 0 )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zvHeight( 0 )
    , m_zvScroll( 0 )
    , m_zoneInfoWindow( nullptr )
    , m_lockHighlight { -1 }
    , m_drawRegion( false )
    , m_showOptions( false )
    , m_showMessages( false )
    , m_drawZones( true )
    , m_drawLocks( true )
    , m_drawPlots( true )
    , m_onlyContendedLocks( false )
    , m_namespace( Namespace::Full )
    , m_terminate( false )
{
    assert( s_instance == nullptr );
    s_instance = this;

    ImGuiStyle& style = ImGui::GetStyle();
    style.FrameRounding = 2.f;

    m_thread = std::thread( [this] { Worker(); } );
    SetThreadName( m_thread, "Tracy View" );
}

View::View( FileRead& f )
    : m_shutdown( false )
    , m_connected( false )
    , m_hasData( true )
    , m_staticView( true )
    , m_zonesCnt( 0 )
    , m_stream( nullptr )
    , m_buffer( nullptr )
    , m_frameScale( 0 )
    , m_pause( false )
    , m_frameStart( 0 )
    , m_zvStart( 0 )
    , m_zvEnd( 0 )
    , m_zvHeight( 0 )
    , m_zvScroll( 0 )
    , m_zoneInfoWindow( nullptr )
    , m_drawRegion( false )
    , m_showOptions( false )
    , m_showMessages( false )
    , m_drawZones( true )
    , m_drawLocks( true )
    , m_drawPlots( true )
    , m_onlyContendedLocks( false )
    , m_namespace( Namespace::Full )
    , m_terminate( false )
{
    assert( s_instance == nullptr );
    s_instance = this;

    f.Read( &m_delay, sizeof( m_delay ) );
    f.Read( &m_resolution, sizeof( m_resolution ) );
    f.Read( &m_timerMul, sizeof( m_timerMul ) );

    uint64_t sz;
    {
        f.Read( &sz, sizeof( sz ) );
        assert( sz < 1024 );
        char tmp[1024];
        f.Read( tmp, sz );
        m_captureName = std::string( tmp, tmp+sz );
    }

    f.Read( &sz, sizeof( sz ) );
    m_frames.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t v;
        f.Read( &v, sizeof( v ) );
        m_frames.push_back( v );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        uint64_t ssz;
        f.Read( &ssz, sizeof( ssz ) );
        char tmp[16*1024];
        f.Read( tmp, ssz );
        m_strings.emplace( ptr, std::string( tmp, tmp+ssz ) );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        uint64_t ssz;
        f.Read( &ssz, sizeof( ssz ) );
        char tmp[16*1024];
        f.Read( tmp, ssz );
        m_threadNames.emplace( ptr, std::string( tmp, tmp+ssz ) );
    }

    std::unordered_map<uint64_t, const char*> stringMap;

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
        m_customStrings.emplace( dst );
        stringMap.emplace( ptr, dst );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr;
        f.Read( &ptr, sizeof( ptr ) );
        QueueSourceLocation srcloc;
        f.Read( &srcloc, sizeof( srcloc ) );
        m_sourceLocation.emplace( ptr, srcloc );
    }

    f.Read( &sz, sizeof( sz ) );
    for( uint64_t i=0; i<sz; i++ )
    {
        LockMap lockmap;
        uint32_t id;
        uint64_t tsz;
        f.Read( &id, sizeof( id ) );
        f.Read( &lockmap.srcloc, sizeof( lockmap.srcloc ) );
        f.Read( &tsz, sizeof( tsz ) );
        for( uint64_t i=0; i<tsz; i++ )
        {
            uint64_t t;
            f.Read( &t, sizeof( t ) );
            lockmap.threadMap.emplace( t, lockmap.threadList.size() );
            lockmap.threadList.emplace_back( t );
        }
        f.Read( &tsz, sizeof( tsz ) );
        for( uint64_t i=0; i<tsz; i++ )
        {
            auto lev = m_slab.Alloc<LockEvent>();
            f.Read( lev, sizeof( LockEvent ) );
            lockmap.timeline.push_back( lev );
        }
        lockmap.visible = true;
        m_lockMap.emplace( id, std::move( lockmap ) );
    }

    std::unordered_map<uint64_t, MessageData*> msgMap;
    f.Read( &sz, sizeof( sz ) );
    m_messages.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        uint64_t ptr, tsz;
        f.Read( &ptr, sizeof( ptr ) );
        auto msgdata = m_slab.Alloc<MessageData>();
        f.Read( &msgdata->_time_literal, sizeof( msgdata->_time_literal ) );
        if( msgdata->literal )
        {
            f.Read( &msgdata->str, sizeof( msgdata->str ) );
        }
        else
        {
            f.Read( &tsz, sizeof( tsz ) );
            auto txt = m_slab.Alloc<char>( tsz+1 );
            f.Read( txt, tsz );
            txt[tsz] = '\0';
            msgdata->txt = txt;
        }
        m_messages.push_back( msgdata );
        msgMap.emplace( ptr, msgdata );
    }

    f.Read( &sz, sizeof( sz ) );
    m_threads.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto td = m_slab.AllocInit<ThreadData>();
        f.Read( &td->id, sizeof( td->id ) );
        ReadTimeline( f, td->timeline, nullptr, stringMap );
        uint64_t msz;
        f.Read( &msz, sizeof( msz ) );
        td->messages.reserve( msz );
        for( uint64_t j=0; j<msz; j++ )
        {
            uint64_t ptr;
            f.Read( &ptr, sizeof( ptr ) );
            td->messages.push_back( msgMap[ptr] );
        }
        td->showFull = true;
        td->visible = true;
        m_threads.push_back( td );
    }

    f.Read( &sz, sizeof( sz ) );
    m_plots.reserve( sz );
    for( uint64_t i=0; i<sz; i++ )
    {
        auto pd = m_slab.AllocInit<PlotData>();
        f.Read( &pd->name, sizeof( pd->name ) );
        f.Read( &pd->min, sizeof( pd->min ) );
        f.Read( &pd->max, sizeof( pd->max ) );
        pd->showFull = true;
        pd->visible = true;
        uint64_t psz;
        f.Read( &psz, sizeof( psz ) );
        pd->data.reserve( psz );
        for( uint64_t j=0; j<psz; j++ )
        {
            auto item = m_slab.Alloc<PlotItem>();
            f.Read( item, sizeof( PlotItem ) );
            pd->data.push_back( item );
        }
        m_plots.push_back( pd );
    }
}

View::~View()
{
    m_shutdown.store( true, std::memory_order_relaxed );
    if( !m_staticView )
    {
        m_thread.join();
    }

    delete[] m_buffer;
    LZ4_freeStreamDecode( m_stream );

    assert( s_instance != nullptr );
    s_instance = nullptr;
}

bool View::ShouldExit()
{
    return s_instance->m_shutdown.load( std::memory_order_relaxed );
}

void View::Worker()
{
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    for(;;)
    {
        if( m_shutdown.load( std::memory_order_relaxed ) ) return;
        if( !m_sock.Connect( m_addr.c_str(), "8086" ) ) continue;

        std::chrono::time_point<std::chrono::high_resolution_clock> t0;

        uint8_t lz4;
        uint64_t bytes = 0;

        {
            WelcomeMessage welcome;
            if( !m_sock.Read( &welcome, sizeof( welcome ), &tv, ShouldExit ) ) goto close;
            lz4 = welcome.lz4;
            m_timerMul = welcome.timerMul;
            m_frames.push_back( welcome.initBegin * m_timerMul );
            m_frames.push_back( welcome.initEnd * m_timerMul );
            m_delay = welcome.delay * m_timerMul;
            m_resolution = welcome.resolution * m_timerMul;

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

            if( lz4 )
            {
                auto buf = m_buffer + m_bufferOffset;
                char lz4buf[LZ4Size];
                lz4sz_t lz4sz;
                if( !m_sock.Read( &lz4sz, sizeof( lz4sz ), &tv, ShouldExit ) ) goto close;
                if( !m_sock.Read( lz4buf, lz4sz, &tv, ShouldExit ) ) goto close;
                bytes += sizeof( lz4sz ) + lz4sz;

                auto sz = LZ4_decompress_safe_continue( m_stream, lz4buf, buf, lz4sz, TargetFrameSize );
                assert( sz >= 0 );

                const char* ptr = buf;
                const char* end = buf + sz;
                while( ptr < end )
                {
                    auto ev = (QueueItem*)ptr;
                    DispatchProcess( *ev, ptr );
                }

                m_bufferOffset += sz;
                if( m_bufferOffset > TargetFrameSize * 2 ) m_bufferOffset = 0;
            }
            else
            {
                QueueItem ev;
                if( !m_sock.Read( &ev.hdr, sizeof( QueueHeader ), &tv, ShouldExit ) ) goto close;
                const auto payload = QueueDataSize[ev.hdr.idx] - sizeof( QueueHeader );
                if( payload > 0 )
                {
                    if( !m_sock.Read( ((char*)&ev) + sizeof( QueueHeader ), payload, &tv, ShouldExit ) ) goto close;
                }
                bytes += sizeof( QueueHeader ) + payload;   // ignores string transfer
                DispatchProcess( ev );
            }

            HandlePostponedPlots();

            auto t1 = std::chrono::high_resolution_clock::now();
            auto td = std::chrono::duration_cast<std::chrono::milliseconds>( t1 - t0 ).count();
            enum { MbpsUpdateTime = 200 };
            if( td > MbpsUpdateTime )
            {
                std::lock_guard<std::mutex> lock( m_mbpslock );
                m_mbps.erase( m_mbps.begin() );
                m_mbps.emplace_back( bytes / ( td * 125.f ) );
                t0 = t1;
                bytes = 0;
            }

            if( m_terminate )
            {
                if( !m_pendingStrings.empty() || !m_pendingThreads.empty() || !m_pendingSourceLocation.empty() ||
                    !m_pendingCustomStrings.empty() || !m_pendingPlots.empty() || !m_pendingMessages.empty() )
                {
                    continue;
                }
                bool done = true;
                for( auto& v : m_zoneStack )
                {
                    if( !v.second.empty() )
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

void View::DispatchProcess( const QueueItem& ev )
{
    if( ev.hdr.type == QueueType::CustomStringData || ev.hdr.type == QueueType::StringData || ev.hdr.type == QueueType::ThreadName || ev.hdr.type == QueueType::PlotName || ev.hdr.type == QueueType::MessageData )
    {
        timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 10000;

        char buf[TargetFrameSize];
        uint16_t sz;
        m_sock.Read( &sz, sizeof( sz ), &tv, ShouldExit );
        m_sock.Read( buf, sz, &tv, ShouldExit );
        if( ev.hdr.type == QueueType::CustomStringData )
        {
            AddCustomString( ev.stringTransfer.ptr, std::string( buf, buf+sz ) );
        }
        else if( ev.hdr.type == QueueType::StringData )
        {
            AddString( ev.stringTransfer.ptr, std::string( buf, buf+sz ) );
        }
        else if( ev.hdr.type == QueueType::ThreadName )
        {
            AddThreadString( ev.stringTransfer.ptr, std::string( buf, buf+sz ) );
        }
        else if( ev.hdr.type == QueueType::PlotName )
        {
            HandlePlotName( ev.stringTransfer.ptr, std::string( buf, buf+sz ) );
        }
        else
        {
            AddMessageData( ev.stringTransfer.ptr, buf, sz );
        }
    }
    else
    {
        Process( ev );
    }
}

void View::DispatchProcess( const QueueItem& ev, const char*& ptr )
{
    ptr += QueueDataSize[ev.hdr.idx];
    if( ev.hdr.type == QueueType::CustomStringData || ev.hdr.type == QueueType::StringData || ev.hdr.type == QueueType::ThreadName || ev.hdr.type == QueueType::PlotName || ev.hdr.type == QueueType::MessageData )
    {
        uint16_t sz;
        memcpy( &sz, ptr, sizeof( sz ) );
        ptr += sizeof( sz );
        if( ev.hdr.type == QueueType::CustomStringData )
        {
            AddCustomString( ev.stringTransfer.ptr, std::string( ptr, ptr+sz ) );
        }
        else if( ev.hdr.type == QueueType::StringData )
        {
            AddString( ev.stringTransfer.ptr, std::string( ptr, ptr+sz ) );
        }
        else if( ev.hdr.type == QueueType::ThreadName )
        {
            AddThreadString( ev.stringTransfer.ptr, std::string( ptr, ptr+sz ) );
        }
        else if( ev.hdr.type == QueueType::PlotName )
        {
            HandlePlotName( ev.stringTransfer.ptr, std::string( ptr, ptr+sz ) );
        }
        else
        {
            AddMessageData( ev.stringTransfer.ptr, ptr, sz );
        }
        ptr += sz;
    }
    else
    {
        Process( ev );
    }
}

void View::ServerQuery( uint8_t type, uint64_t data )
{
    enum { DataSize = sizeof( type ) + sizeof( data ) };
    char tmp[DataSize];
    memcpy( tmp, &type, sizeof( type ) );
    memcpy( tmp + sizeof( type ), &data, sizeof( data ) );
    m_sock.Send( tmp, DataSize );
}

void View::Process( const QueueItem& ev )
{
    switch( ev.hdr.type )
    {
    case QueueType::ZoneBegin:
        ProcessZoneBegin( ev.zoneBegin );
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
    case QueueType::ZoneName:
        ProcessZoneName( ev.zoneName );
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
    case QueueType::Terminate:
        m_terminate = true;
        break;
    default:
        assert( false );
        break;
    }
}

void View::ProcessZoneBegin( const QueueZoneBegin& ev )
{
    auto zone = m_slab.AllocInit<Event>();

    CheckSourceLocation( ev.srcloc );

    zone->start = ev.time * m_timerMul;
    zone->end = -1;
    zone->srcloc = ev.srcloc;
    assert( ev.cpu == 0xFFFFFFFF || ev.cpu <= std::numeric_limits<int8_t>::max() );
    zone->cpu_start = ev.cpu == 0xFFFFFFFF ? -1 : (int8_t)ev.cpu;
    zone->text = nullptr;

    std::unique_lock<std::mutex> lock( m_lock );
    NewZone( zone, ev.thread );
    lock.unlock();
    m_zoneStack[ev.thread].push_back( zone );
}

void View::ProcessZoneEnd( const QueueZoneEnd& ev )
{
    auto& stack = m_zoneStack[ev.thread];
    assert( !stack.empty() );
    auto zone = stack.back();
    stack.pop_back();
    assert( zone->end == -1 );
    std::unique_lock<std::mutex> lock( m_lock );
    zone->end = ev.time * m_timerMul;
    assert( ev.cpu == 0xFFFFFFFF || ev.cpu <= std::numeric_limits<int8_t>::max() );
    zone->cpu_end = ev.cpu == 0xFFFFFFFF ? -1 : (int8_t)ev.cpu;
    lock.unlock();
    assert( zone->end >= zone->start );
    UpdateZone( zone );
}

void View::ProcessFrameMark( const QueueFrameMark& ev )
{
    assert( !m_frames.empty() );
    const auto lastframe = m_frames.back();
    const auto time = ev.time * m_timerMul;
    assert( lastframe < time );
    std::lock_guard<std::mutex> lock( m_lock );
    m_frames.push_back( time );
}

void View::ProcessZoneText( const QueueZoneText& ev )
{
    auto& stack = m_zoneStack[ev.thread];
    assert( !stack.empty() );
    auto zone = stack.back();
    CheckCustomString( ev.text, zone );
}

void View::ProcessZoneName( const QueueZoneName& ev )
{
    auto& stack = m_zoneStack[ev.thread];
    assert( !stack.empty() );
    auto zone = stack.back();
    CheckString( ev.name );
    std::lock_guard<std::mutex> lock( m_lock );
    GetTextData( *zone )->zoneName = ev.name;
}

void View::ProcessLockWait( const QueueLockWait& ev )
{
    auto lev = m_slab.Alloc<LockEvent>();
    lev->time = ev.time * m_timerMul;
    lev->type = LockEvent::Type::Wait;
    lev->srcloc = 0;

    auto it = m_lockMap.find( ev.id );
    std::lock_guard<std::mutex> lock( m_lock );
    if( it == m_lockMap.end() )
    {
        LockMap lm;
        lm.srcloc = ev.lckloc;
        lm.visible = true;
        it = m_lockMap.emplace( ev.id, std::move( lm ) ).first;
        CheckSourceLocation( ev.lckloc );
    }
    else if( it->second.srcloc == 0 )
    {
        it->second.srcloc = ev.lckloc;
        CheckSourceLocation( ev.lckloc );
    }
    InsertLockEvent( it->second, lev, ev.thread );
}

void View::ProcessLockObtain( const QueueLockObtain& ev )
{
    auto lev = m_slab.Alloc<LockEvent>();
    lev->time = ev.time * m_timerMul;
    lev->type = LockEvent::Type::Obtain;
    lev->srcloc = 0;

    std::lock_guard<std::mutex> lock( m_lock );
    InsertLockEvent( m_lockMap[ev.id], lev, ev.thread );
}

void View::ProcessLockRelease( const QueueLockRelease& ev )
{
    auto lev = m_slab.Alloc<LockEvent>();
    lev->time = ev.time * m_timerMul;
    lev->type = LockEvent::Type::Release;
    lev->srcloc = 0;

    std::lock_guard<std::mutex> lock( m_lock );
    InsertLockEvent( m_lockMap[ev.id], lev, ev.thread );
}

void View::ProcessLockMark( const QueueLockMark& ev )
{
    CheckSourceLocation( ev.srcloc );
    auto lit = m_lockMap.find( ev.id );
    assert( lit != m_lockMap.end() );
    std::lock_guard<std::mutex> lock( m_lock );
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
                (*it)->srcloc = ev.srcloc;
                break;
            case LockEvent::Type::Wait:
                (*it)->srcloc = ev.srcloc;
                return;
            default:
                break;
            }
        }
    }
}

void View::ProcessPlotData( const QueuePlotData& ev )
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
            plot->showFull = true;
            plot->visible = true;
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
        plot = m_plots[it->second];
    }

    const auto time = int64_t( ev.time * m_timerMul );
    std::lock_guard<std::mutex> lock( m_lock );
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

void View::ProcessMessage( const QueueMessage& ev )
{
    m_pendingMessages.emplace( ev.text, MessagePending { int64_t( ev.time * m_timerMul ), ev.thread } );
    ServerQuery( ServerQueryMessage, ev.text );
}

void View::ProcessMessageLiteral( const QueueMessage& ev )
{
    CheckString( ev.text );
    auto msg = m_slab.Alloc<MessageData>();
    msg->time = int64_t( ev.time * m_timerMul );
    msg->literal = true;
    msg->str = ev.text;
    InsertMessageData( msg, ev.thread );
}

void View::CheckString( uint64_t ptr )
{
    if( m_strings.find( ptr ) != m_strings.end() ) return;
    if( m_pendingStrings.find( ptr ) != m_pendingStrings.end() ) return;

    m_pendingStrings.emplace( ptr );

    ServerQuery( ServerQueryString, ptr );
}

void View::CheckThreadString( uint64_t id )
{
    if( m_threadNames.find( id ) != m_threadNames.end() ) return;
    if( m_pendingThreads.find( id ) != m_pendingThreads.end() ) return;

    m_pendingThreads.emplace( id );

    ServerQuery( ServerQueryThreadString, id );
}

void View::CheckCustomString( uint64_t ptr, Event* dst )
{
    assert( m_pendingCustomStrings.find( ptr ) == m_pendingCustomStrings.end() );
    m_pendingCustomStrings.emplace( ptr, dst );

    ServerQuery( ServerQueryCustomString, ptr );
}

void View::CheckSourceLocation( uint64_t ptr )
{
    if( m_sourceLocation.find( ptr ) != m_sourceLocation.end() ) return;
    if( m_pendingSourceLocation.find( ptr ) != m_pendingSourceLocation.end() ) return;

    m_pendingSourceLocation.emplace( ptr );

    ServerQuery( ServerQuerySourceLocation, ptr );
}

void View::AddString( uint64_t ptr, std::string&& str )
{
    assert( m_strings.find( ptr ) == m_strings.end() );
    auto it = m_pendingStrings.find( ptr );
    assert( it != m_pendingStrings.end() );
    m_pendingStrings.erase( it );
    std::lock_guard<std::mutex> lock( m_lock );
    m_strings.emplace( ptr, std::move( str ) );
}

void View::AddThreadString( uint64_t id, std::string&& str )
{
    assert( m_threadNames.find( id ) == m_threadNames.end() );
    auto it = m_pendingThreads.find( id );
    assert( it != m_pendingThreads.end() );
    m_pendingThreads.erase( it );
    std::lock_guard<std::mutex> lock( m_lock );
    m_threadNames.emplace( id, std::move( str ) );
}

void View::AddCustomString( uint64_t ptr, std::string&& str )
{
    auto pit = m_pendingCustomStrings.find( ptr );
    assert( pit != m_pendingCustomStrings.end() );
    std::unique_lock<std::mutex> lock( m_lock );
    auto sit = m_customStrings.find( str.c_str() );
    if( sit == m_customStrings.end() )
    {
        const auto sz = str.size();
        auto ptr = m_slab.Alloc<char>( sz+1 );
        memcpy( ptr, str.c_str(), sz );
        ptr[sz] = '\0';
        GetTextData( *pit->second )->userText = ptr;
        m_customStrings.emplace( ptr );
    }
    else
    {
        GetTextData( *pit->second )->userText = *sit;
    }
    lock.unlock();
    m_pendingCustomStrings.erase( pit );
}

void View::AddSourceLocation( const QueueSourceLocation& srcloc )
{
    assert( m_sourceLocation.find( srcloc.ptr ) == m_sourceLocation.end() );
    auto it = m_pendingSourceLocation.find( srcloc.ptr );
    assert( it != m_pendingSourceLocation.end() );
    m_pendingSourceLocation.erase( it );
    CheckString( srcloc.file );
    CheckString( srcloc.function );
    std::lock_guard<std::mutex> lock( m_lock );
    m_sourceLocation.emplace( srcloc.ptr, srcloc );
}

void View::AddMessageData( uint64_t ptr, const char* str, size_t sz )
{
    auto txt = m_slab.Alloc<char>( sz+1 );
    memcpy( txt, str, sz );
    txt[sz] = '\0';

    auto it = m_pendingMessages.find( ptr );
    assert( it != m_pendingMessages.end() );
    auto msg = m_slab.Alloc<MessageData>();
    msg->time = it->second.time;
    msg->literal = false;
    msg->txt = txt;
    InsertMessageData( msg, it->second.thread );
    m_pendingMessages.erase( it );
}

void View::InsertMessageData( MessageData* msg, uint64_t thread )
{
    std::lock_guard<std::mutex> lock( m_lock );
    if( m_messages.empty() || m_messages.back()->time < msg->time )
    {
        m_messages.push_back( msg );
    }
    else
    {
        auto mit = std::lower_bound( m_messages.begin(), m_messages.end(), msg->time, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        m_messages.insert( mit, msg );
    }

    Vector<MessageData*>* vec = &NoticeThread( thread )->messages;
    if( vec->empty() || vec->back()->time < msg->time )
    {
        vec->push_back( msg );
    }
    else
    {
        auto tmit = std::lower_bound( vec->begin(), vec->end(), msg->time, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        vec->insert( tmit, msg );
    }
}

View::ThreadData* View::NoticeThread( uint64_t thread )
{
    auto it = m_threadMap.find( thread );
    if( it == m_threadMap.end() )
    {
        CheckThreadString( thread );
        m_threadMap.emplace( thread, (uint32_t)m_threads.size() );
        auto td = m_slab.AllocInit<ThreadData>();
        td->id = thread;
        td->showFull = true;
        td->visible = true;
        m_threads.push_back( td );
        return m_threads.back();
    }
    else
    {
        return m_threads[it->second];
    }
}

void View::NewZone( Event* zone, uint64_t thread )
{
    m_zonesCnt++;
    Vector<Event*>* timeline = &NoticeThread( thread )->timeline;
    InsertZone( zone, nullptr, *timeline );
}

void View::UpdateZone( Event* zone )
{
    assert( zone->end != -1 );
    assert( std::upper_bound( zone->child.begin(), zone->child.end(), zone->end, [] ( const auto& l, const auto& r ) { return l < r->start; } ) == zone->child.end() );
}

void View::InsertZone( Event* zone, Event* parent, Vector<Event*>& vec )
{
    if( !vec.empty() )
    {
        const auto lastend = vec.back()->end;
        if( lastend != -1 && lastend <= zone->start )
        {
            zone->parent = parent;
            vec.push_back( zone );
        }
        else
        {
            assert( std::upper_bound( vec.begin(), vec.end(), zone->start, [] ( const auto& l, const auto& r ) { return l < r->start; } ) == vec.end() );
            assert( vec.back()->end == -1 || vec.back()->end >= zone->end );
            InsertZone( zone, vec.back(), vec.back()->child );
        }
    }
    else
    {
        zone->parent = parent;
        vec.push_back( zone );
    }
}

void View::InsertLockEvent( LockMap& lockmap, LockEvent* lev, uint64_t thread )
{
    NoticeThread( thread );

    auto it = lockmap.threadMap.find( thread );
    if( it == lockmap.threadMap.end() )
    {
        assert( lockmap.threadList.size() < MaxLockThreads );
        it = lockmap.threadMap.emplace( thread, lockmap.threadList.size() ).first;
        lockmap.threadList.emplace_back( thread );
    }
    lev->thread = it->second;
    auto& timeline = lockmap.timeline;
    if( timeline.empty() || timeline.back()->time < lev->time )
    {
        timeline.push_back( lev );
        UpdateLockCount( lockmap, timeline.size() - 1 );
    }
    else
    {
        auto it = std::lower_bound( timeline.begin(), timeline.end(), lev->time, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
        it = timeline.insert( it, lev );
        UpdateLockCount( lockmap, std::distance( timeline.begin(), it ) );
    }
}

void View::UpdateLockCount( LockMap& lockmap, size_t pos )
{
    auto& timeline = lockmap.timeline;
    uint8_t lockingThread = pos == 0 ? 0 : timeline[pos-1]->lockingThread;
    uint8_t lockCount = pos == 0 ? 0 : timeline[pos-1]->lockCount;
    uint64_t waitList = pos == 0 ? 0 : timeline[pos-1]->waitList;
    const auto end = timeline.size();

    while( pos != end )
    {
        const auto tbit = 1 << timeline[pos]->thread;
        switch( timeline[pos]->type )
        {
        case LockEvent::Type::Wait:
            waitList |= tbit;
            break;
        case LockEvent::Type::Obtain:
            assert( lockCount < std::numeric_limits<uint8_t>::max() );
            assert( waitList | tbit != 0 );
            waitList &= ~tbit;
            lockingThread = timeline[pos]->thread;
            lockCount++;
            break;
        case LockEvent::Type::Release:
            assert( lockCount > 0 );
            lockCount--;
            break;
        default:
            break;
        }
        timeline[pos]->lockingThread = lockingThread;
        timeline[pos]->waitList = waitList;
        timeline[pos]->lockCount = lockCount;
        pos++;
    }
}

void View::InsertPlot( PlotData* plot, int64_t time, double val )
{
    auto item = m_slab.Alloc<PlotItem>();
    item->time = time;
    item->val = val;
    InsertPlot( plot, item );
}

void View::InsertPlot( PlotData* plot, PlotItem* item )
{
    const auto& time = item->time;
    const auto& val = item->val;

    if( plot->data.empty() || plot->data.back()->time < time )
    {
        if( plot->data.empty() )
        {
            plot->min = val;
            plot->max = val;
        }
        else
        {
            if( plot->min > val ) plot->min = val;
            else if( plot->max < val ) plot->max = val;
        }
        plot->data.push_back( item );
    }
    else
    {
        if( plot->min > val ) plot->min = val;
        else if( plot->max < val ) plot->max = val;
        if( plot->postpone.empty() ) plot->postponeTime = std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count();
        plot->postpone.push_back( item );
    }
}

void View::HandlePlotName( uint64_t name, std::string&& str )
{
    auto pit = m_pendingPlots.find( name );
    assert( pit != m_pendingPlots.end() );

    auto it = m_plotRev.find( str );
    if( it == m_plotRev.end() )
    {
        const auto idx = m_plots.size();
        m_plotMap.emplace( name, idx );
        m_plotRev.emplace( str, idx );
        std::lock_guard<std::mutex> lock( m_lock );
        m_plots.push_back( pit->second );
        m_strings.emplace( name, std::move( str ) );
    }
    else
    {
        std::lock_guard<std::mutex> lock( m_lock );
        m_plotMap.emplace( name, it->second );
        const auto& pp = pit->second->data;
        auto plot = m_plots[it->second];
        for( auto& v : pp )
        {
            InsertPlot( plot, v );
        }
    }

    m_pendingPlots.erase( pit );
}

void View::HandlePostponedPlots()
{
    for( auto& plot : m_plots )
    {
        auto& src = plot->postpone;
        if( src.empty() ) continue;
        if( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::high_resolution_clock::now().time_since_epoch() ).count() - plot->postponeTime < 100 ) continue;
        auto& dst = plot->data;
        std::sort( src.begin(), src.end(), [] ( const auto& l, const auto& r ) { return l->time < r->time; } );
        const auto ds = std::lower_bound( dst.begin(), dst.end(), src.front()->time, [] ( const auto& l, const auto& r ) { return l->time < r; } );
        const auto dsd = std::distance( dst.begin(), ds ) ;
        const auto de = std::lower_bound( ds, dst.end(), src.back()->time, [] ( const auto& l, const auto& r ) { return l->time < r; } );
        const auto ded = std::distance( dst.begin(), de );
        std::unique_lock<std::mutex> lock( m_lock );
        dst.insert( de, src.begin(), src.end() );
        std::inplace_merge( dst.begin() + dsd, dst.begin() + ded, dst.begin() + ded + src.size(), [] ( const auto& l, const auto& r ) { return l->time < r->time; } );
        lock.unlock();
        src.clear();
    }
}

uint64_t View::GetFrameTime( size_t idx ) const
{
    if( idx < m_frames.size() - 1 )
    {
        return m_frames[idx+1] - m_frames[idx];
    }
    else
    {
        const auto last = GetLastTime();
        return last == 0 ? 0 : last - m_frames.back();
    }
}

uint64_t View::GetFrameBegin( size_t idx ) const
{
    assert( idx < m_frames.size() );
    return m_frames[idx];
}

uint64_t View::GetFrameEnd( size_t idx ) const
{
    if( idx < m_frames.size() - 1 )
    {
        return m_frames[idx+1];
    }
    else
    {
        return GetLastTime();
    }
}

int64_t View::GetLastTime() const
{
    int64_t last = 0;
    if( !m_frames.empty() ) last = m_frames.back();
    for( auto& v : m_threads )
    {
        if( !v->timeline.empty() )
        {
            auto ev = v->timeline.back();
            if( ev->end == -1 )
            {
                if( ev->start > last ) last = ev->start;
            }
            else if( ev->end > last )
            {
                last = ev->end;
            }
        }
    }
    return last;
}

int64_t View::GetZoneEnd( const Event& ev ) const
{
    auto ptr = &ev;
    for(;;)
    {
        if( ptr->end != -1 ) return ptr->end;
        if( ptr->child.empty() ) return ptr->start;
        ptr = ptr->child.back();
    }
}

Vector<Event*>& View::GetParentVector( const Event& ev )
{
    if( ev.parent )
    {
        return ev.parent->child;
    }
    else
    {
        for( auto& t : m_threads )
        {
            auto it = std::lower_bound( t->timeline.begin(), t->timeline.end(), ev.start, [] ( const auto& l, const auto& r ) { return l->start < r; } );
            if( it != t->timeline.end() && *it == &ev ) return t->timeline;
        }
        assert( false );
        static Vector<Event*> empty;
        return empty;
    }
}

const char* View::TimeToString( int64_t ns ) const
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const char* sign = "";
    if( ns < 0 )
    {
        sign = "-";
        ns = -ns;
    }

    if( ns < 1000 )
    {
        sprintf( buf, "%s%" PRIu64 " ns", sign, ns );
    }
    else if( ns < 1000ull * 1000 )
    {
        sprintf( buf, "%s%.2f us", sign, ns / 1000. );
    }
    else if( ns < 1000ull * 1000 * 1000 )
    {
        sprintf( buf, "%s%.2f ms", sign, ns / ( 1000. * 1000. ) );
    }
    else if( ns < 1000ull * 1000 * 1000 * 60 )
    {
        sprintf( buf, "%s%.2f s", sign, ns / ( 1000. * 1000. * 1000. ) );
    }
    else
    {
        const auto m = ns / ( 1000ull * 1000 * 1000 * 60 );
        const auto s = ns - m * ( 1000ull * 1000 * 1000 * 60 );
        sprintf( buf, "%s%" PRIu64 ":%04.1f", sign, m, s / ( 1000. * 1000. * 1000. ) );
    }
    return buf;
}

const char* View::RealToString( double val, bool separator ) const
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    sprintf( buf, "%f", val );
    auto ptr = buf;
    if( *ptr == '-' ) ptr++;

    const auto vbegin = ptr;

    if( separator )
    {
        while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;
        auto end = ptr;
        while( *end != '\0' ) end++;
        auto sz = end - ptr;

        while( ptr - vbegin > 3 )
        {
            ptr -= 3;
            memmove( ptr+1, ptr, sz );
            *ptr = ',';
            sz += 4;
        }
    }

    while( *ptr != '\0' && *ptr != ',' && *ptr != '.' ) ptr++;

    if( *ptr == '\0' ) return buf;
    while( *ptr != '\0' ) ptr++;
    ptr--;
    while( *ptr == '0' && *ptr != ',' && *ptr != '.' ) ptr--;
    if( *ptr != '.' && *ptr != ',' ) ptr++;
    *ptr = '\0';
    return buf;
}

const char* View::GetString( uint64_t ptr ) const
{
    const auto it = m_strings.find( ptr );
    if( it == m_strings.end() )
    {
        return "???";
    }
    else
    {
        return it->second.c_str();
    }
}

const char* View::GetThreadString( uint64_t id ) const
{
    const auto it = m_threadNames.find( id );
    if( it == m_threadNames.end() )
    {
        return "???";
    }
    else
    {
        return it->second.c_str();
    }
}

const QueueSourceLocation& View::GetSourceLocation( uint64_t srcloc ) const
{
    static const QueueSourceLocation empty = {};
    const auto it = m_sourceLocation.find( srcloc );
    if( it == m_sourceLocation.end() ) return empty;
    return it->second;
}

const char* View::ShortenNamespace( const char* name ) const
{
    if( m_namespace == Namespace::Full ) return name;
    if( m_namespace == Namespace::Short )
    {
        auto ptr = name;
        while( *ptr != '\0' ) ptr++;
        while( ptr > name && *ptr != ':' ) ptr--;
        if( *ptr == ':' ) ptr++;
        return ptr;
    }

    static char buf[1024];
    auto dst = buf;
    auto ptr = name;
    for(;;)
    {
        auto start = ptr;
        while( *ptr != '\0' && *ptr != ':' ) ptr++;
        if( *ptr == '\0' )
        {
            memcpy( dst, start, ptr - start + 1 );
            return buf;
        }
        *dst++ = *start;
        *dst++ = ':';
        while( *ptr == ':' ) ptr++;
    }
}

void View::Draw()
{
    s_instance->DrawImpl();
}

void View::DrawImpl()
{
    if( !m_hasData.load( std::memory_order_acquire ) )
    {
        ImGui::Begin( m_addr.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_ShowBorders );
        ImGui::Text( "Waiting for connection..." );
        ImGui::End();
        return;
    }

    if( !m_staticView )
    {
        DrawConnection();
    }

    std::lock_guard<std::mutex> lock( m_lock );
    ImGui::Begin( m_captureName.c_str(), nullptr, ImGuiWindowFlags_ShowBorders | ImGuiWindowFlags_NoScrollbar );
    if( ImGui::Button( m_pause ? "Resume" : "Pause", ImVec2( 70, 0 ) ) ) m_pause = !m_pause;
    ImGui::SameLine();
    if( ImGui::Button( "Options", ImVec2( 70, 0 ) ) ) m_showOptions = true;
    ImGui::SameLine();
    if( ImGui::Button( "Messages", ImVec2( 70, 0 ) ) ) m_showMessages = true;
    ImGui::SameLine();
    ImGui::Text( "Frames: %-7" PRIu64 " Time span: %-10s View span: %-10s Zones: %-13s Queue delay: %s  Timer resolution: %s", m_frames.size(), TimeToString( GetLastTime() - m_frames[0] ), TimeToString( m_zvEnd - m_zvStart ), RealToString( m_zonesCnt, true ), TimeToString( m_delay ), TimeToString( m_resolution ) );
    DrawFrames();
    DrawZones();
    ImGui::End();

    m_zoneHighlight = nullptr;
    DrawZoneInfoWindow();
    if( m_showOptions ) DrawOptions();
    if( m_showMessages ) DrawMessages();

    if( m_zvStartNext != 0 )
    {
        m_zvStart = m_zvStartNext;
        m_zvEnd = m_zvEndNext;
        m_pause = true;
    }
}

void View::DrawConnection()
{
    const auto ty = ImGui::GetFontSize();
    const auto cs = ty * 0.9f;

    ImGui::Begin( m_addr.c_str(), nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_ShowBorders );
    {
        std::lock_guard<std::mutex> lock( m_mbpslock );
        const auto mbps = m_mbps.back();
        char buf[64];
        if( mbps < 0.1f )
        {
            sprintf( buf, "%6.2f Kbps", mbps * 1000.f );
        }
        else
        {
            sprintf( buf, "%6.2f Mbps", mbps );
        }
        ImGui::Dummy( ImVec2( cs, 0 ) );
        ImGui::SameLine();
        ImGui::PlotLines( buf, m_mbps.data(), m_mbps.size(), 0, nullptr, 0, std::numeric_limits<float>::max(), ImVec2( 150, 0 ) );
    }

    ImGui::Text( "Memory usage: %.2f MB", memUsage.load( std::memory_order_relaxed ) / ( 1024.f * 1024.f ) );

    const auto wpos = ImGui::GetWindowPos() + ImGui::GetWindowContentRegionMin();
    ImGui::GetWindowDrawList()->AddCircleFilled( wpos + ImVec2( 1 + cs * 0.5, 3 + ty * 0.5 ), cs * 0.5, m_connected.load( std::memory_order_relaxed ) ? 0xFF2222CC : 0xFF444444, 10 );

    std::lock_guard<std::mutex> lock( m_lock );
    {
        const auto sz = m_frames.size();
        if( sz > 1 )
        {
            const auto dt = m_frames[sz-1] - m_frames[sz-2];
            const auto dtm = dt / 1000000.f;
            const auto fps = 1000.f / dtm;
            ImGui::Text( "FPS: %6.1f  Frame time: %.2f ms", fps, dtm );
        }
    }

    if( ImGui::Button( "Save trace" ) )
    {
#ifdef TRACY_FILESELECTOR
        nfdchar_t* fn;
        auto res = NFD_SaveDialog( "tracy", nullptr, &fn );
        if( res == NFD_OKAY )
#else
        const char* fn = "trace.tracy";
#endif
        {
            std::unique_ptr<FileWrite> f;
            const auto sz = strlen( fn );
            if( sz < 7 || memcmp( fn + sz - 6, ".tracy", 6 ) != 0 )
            {
                char tmp[1024];
                sprintf( tmp, "%s.tracy", fn );
                f.reset( FileWrite::Open( tmp ) );
            }
            else
            {
                f.reset( FileWrite::Open( fn ) );
            }
            if( f )
            {
                Write( *f );
            }
        }
    }

    ImGui::End();
}

static ImU32 GetFrameColor( uint64_t frameTime )
{
    enum { BestTime = 1000 * 1000 * 1000 / 143 };
    enum { GoodTime = 1000 * 1000 * 1000 / 59 };
    enum { BadTime = 1000 * 1000 * 1000 / 29 };

    return frameTime > BadTime  ? 0xFF2222DD :
           frameTime > GoodTime ? 0xFF22DDDD :
           frameTime > BestTime ? 0xFF22DD22 : 0xFFDD9900;
}

static int GetFrameWidth( int frameScale )
{
    return frameScale == 0 ? 4 : ( frameScale == -1 ? 6 : 1 );
}

static int GetFrameGroup( int frameScale )
{
    return frameScale < 2 ? 1 : ( 1 << ( frameScale - 1 ) );
}

void View::DrawFrames()
{
    assert( !m_frames.empty() );

    enum { Height = 40 };
    enum { MaxFrameTime = 50 * 1000 * 1000 };  // 50ms

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto wspace = ImGui::GetWindowContentRegionMax() - ImGui::GetWindowContentRegionMin();
    const auto w = wspace.x;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##frames", ImVec2( w, Height ) );
    bool hover = ImGui::IsItemHovered();

    draw->AddRectFilled( wpos, wpos + ImVec2( w, Height ), 0x33FFFFFF );
    const auto wheel = io.MouseWheel;
    const auto prevScale = m_frameScale;
    if( hover )
    {
        if( wheel > 0 )
        {
            if( m_frameScale > -1 ) m_frameScale--;
        }
        else if( wheel < 0 )
        {
            if( m_frameScale < 10 ) m_frameScale++;
        }
    }

    const int fwidth = GetFrameWidth( m_frameScale );
    const int group = GetFrameGroup( m_frameScale );
    const int total = m_frames.size();
    const int onScreen = ( w - 2 ) / fwidth;
    if( !m_pause )
    {
        m_frameStart = ( total < onScreen * group ) ? 0 : total - onScreen * group;
        m_zvStart = m_frames[std::max( 0, (int)m_frames.size() - 4 )];
        if( m_frames.size() == 1 )
        {
            m_zvEnd = GetLastTime();
        }
        else
        {
            m_zvEnd = m_frames.back();
        }
    }

    if( hover )
    {
        if( ImGui::IsMouseDragging( 1, 0 ) )
        {
            m_pause = true;
            const auto delta = ImGui::GetMouseDragDelta( 1, 0 ).x;
            if( abs( delta ) >= fwidth )
            {
                const auto d = (int)delta / fwidth;
                m_frameStart = std::max( 0, m_frameStart - d * group );
                io.MouseClickedPos[1].x = io.MousePos.x + d * fwidth - delta;
            }
        }

        const auto mx = io.MousePos.x;
        if( mx > wpos.x && mx < wpos.x + w - 1 )
        {
            const auto mo = mx - ( wpos.x + 1 );
            const auto off = mo * group / fwidth;

            const int sel = m_frameStart + off;
            if( sel < total )
            {
                ImGui::BeginTooltip();
                if( group > 1 )
                {
                    uint64_t f = GetFrameTime( sel );
                    auto g = std::min( group, total - sel );
                    for( int j=1; j<g; j++ )
                    {
                        f = std::max( f, GetFrameTime( sel + j ) );
                    }

                    ImGui::Text( "Frames: %i - %i (%i)", sel, sel + g - 1, g );
                    ImGui::Text( "Max frame time: %s", TimeToString( f ) );
                }
                else
                {
                    if( sel == 0 )
                    {
                        ImGui::Text( "Tracy initialization", sel );
                        ImGui::Text( "Time: %s", TimeToString( GetFrameTime( sel ) ) );
                    }
                    else
                    {
                        ImGui::Text( "Frame: %i", sel );
                        ImGui::Text( "Frame time: %s", TimeToString( GetFrameTime( sel ) ) );
                    }
                }
                ImGui::Text( "Time from start of program: %s", TimeToString( m_frames[sel] - m_frames[0] ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_pause = true;
                    m_zvStart = GetFrameBegin( sel );
                    m_zvEnd = GetFrameEnd( sel + group - 1 );
                    if( m_zvStart == m_zvEnd ) m_zvStart--;
                }
                else if( ImGui::IsMouseDragging( 0 ) )
                {
                    m_zvStart = std::min( m_zvStart, (int64_t)GetFrameBegin( sel ) );
                    m_zvEnd = std::max( m_zvEnd, (int64_t)GetFrameEnd( sel + group - 1 ) );
                }
            }

            if( m_pause && wheel != 0 )
            {
                const int pfwidth = GetFrameWidth( prevScale );
                const int pgroup = GetFrameGroup( prevScale );

                const auto oldoff = mo * pgroup / pfwidth;
                m_frameStart = std::min( total, std::max( 0, m_frameStart - int( off - oldoff ) ) );
            }
        }
    }

    int i = 0, idx = 0;
    while( i < onScreen && m_frameStart + idx < total )
    {
        uint64_t f = GetFrameTime( m_frameStart + idx );
        int g;
        if( group > 1 )
        {
            g = std::min( group, total - ( m_frameStart + idx ) );
            for( int j=1; j<g; j++ )
            {
                f = std::max( f, GetFrameTime( m_frameStart + idx + j ) );
            }
        }

        const auto h = float( std::min<uint64_t>( MaxFrameTime, f ) ) / MaxFrameTime * ( Height - 2 );
        if( fwidth != 1 )
        {
            draw->AddRectFilled( wpos + ImVec2( 1 + i*fwidth, Height-1-h ), wpos + ImVec2( fwidth + i*fwidth, Height-1 ), GetFrameColor( f ) );
        }
        else
        {
            draw->AddLine( wpos + ImVec2( 1+i, Height-2-h ), wpos + ImVec2( 1+i, Height-2 ), GetFrameColor( f ) );
        }

        i++;
        idx += group;
    }

    const auto zitbegin = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvStart );
    if( zitbegin == m_frames.end() ) return;
    const auto zitend = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvEnd );

    auto zbegin = (int)std::distance( m_frames.begin(), zitbegin );
    if( zbegin > 0 && *zitbegin != m_zvStart ) zbegin--;
    const auto zend = (int)std::distance( m_frames.begin(), zitend );

    if( zend > m_frameStart && zbegin < m_frameStart + onScreen * group )
    {
        auto x0 = std::max( 0, ( zbegin - m_frameStart ) * fwidth / group );
        auto x1 = std::min( onScreen * fwidth, ( zend - m_frameStart ) * fwidth / group );

        if( x0 == x1 ) x1 = x0 + 1;

        draw->AddRectFilled( wpos + ImVec2( 1+x0, 0 ), wpos + ImVec2( 1+x1, Height ), 0x55DD22DD );
    }
}

void View::HandleZoneViewMouse( int64_t timespan, const ImVec2& wpos, float w, double& pxns )
{
    assert( timespan > 0 );
    auto& io = ImGui::GetIO();

    const auto nspx = double( timespan ) / w;

    if( ImGui::IsMouseClicked( 0 ) )
    {
        m_drawRegion = true;
        m_regionEnd = m_regionStart = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else if( ImGui::IsMouseDragging( 0, 0 ) )
    {
        m_regionEnd = m_zvStart + ( io.MousePos.x - wpos.x ) * nspx;
    }
    else
    {
        m_drawRegion = false;
    }

    if( ImGui::IsMouseDragging( 1, 0 ) )
    {
        m_pause = true;
        const auto delta = ImGui::GetMouseDragDelta( 1, 0 );
        const auto dpx = int64_t( delta.x * nspx );
        if( dpx != 0 )
        {
            m_zvStart -= dpx;
            m_zvEnd -= dpx;
            io.MouseClickedPos[1].x = io.MousePos.x;
        }
        if( delta.y != 0 )
        {
            auto y = ImGui::GetScrollY();
            ImGui::SetScrollY( y - delta.y );
            io.MouseClickedPos[1].y = io.MousePos.y;
        }
    }

    const auto wheel = io.MouseWheel;
    if( wheel != 0 )
    {
        m_pause = true;
        const double mouse = io.MousePos.x - wpos.x;
        const auto p = mouse / w;
        const auto p1 = timespan * p;
        const auto p2 = timespan - p1;
        if( wheel > 0 )
        {
            m_zvStart += int64_t( p1 * 0.2f );
            m_zvEnd -= int64_t( p2 * 0.2f );
        }
        else if( timespan < 1000ull * 1000 * 1000 * 60 )
        {
            m_zvStart -= std::max( int64_t( 1 ), int64_t( p1 * 0.2f ) );
            m_zvEnd += std::max( int64_t( 1 ), int64_t( p2 * 0.2f ) );
        }
        timespan = m_zvEnd - m_zvStart;
        pxns = w / double( timespan );
    }
}

bool View::DrawZoneFrames()
{
    auto& io = ImGui::GetIO();

    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - ImGui::GetStyle().ScrollbarSize;
    const auto h = ImGui::GetFontSize();
    const auto wh = ImGui::GetContentRegionAvail().y;
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##zoneFrames", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover ) HandleZoneViewMouse( timespan, wpos, w, pxns );

    m_zvStartNext = 0;

    // frames
    do
    {
        const auto zitbegin = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvStart );
        if( zitbegin == m_frames.end() ) break;
        const auto zitend = std::lower_bound( m_frames.begin(), m_frames.end(), m_zvEnd );

        auto zbegin = (int)std::distance( m_frames.begin(), zitbegin );
        if( zbegin > 0 && *zitbegin != m_zvStart ) zbegin--;
        const auto zend = (int)std::distance( m_frames.begin(), zitend );

        for( int i=zbegin; i<zend; i++ )
        {
            const auto ftime = GetFrameTime( i );
            const auto fbegin = (int64_t)GetFrameBegin( i );
            const auto fend = (int64_t)GetFrameEnd( i );

            uint32_t color;
            char buf[128];
            if( i == 0 )
            {
                sprintf( buf, "Tracy init (%s)", TimeToString( ftime ) );
                color = 0xFF4444FF;
            }
            else
            {
                sprintf( buf, "Frame %i (%s)", i, TimeToString( ftime ) );
                color = 0xFFFFFFFF;
            }
            const auto tsz = ImGui::CalcTextSize( buf );
            const auto fsz = pxns * ftime;

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, tsz.y ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "%s", buf );
                ImGui::Text( "Time from start of program: %s", TimeToString( m_frames[i] - m_frames[0] ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 2 ) )
                {
                    m_zvStartNext = fbegin;
                    m_zvEndNext = fend;
                    m_pause = true;
                }
            }

            if( fbegin >= m_zvStart && fsz > 4 )
            {
                draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
            }

            if( fsz >= 5 )
            {
                if( fbegin >= m_zvStart )
                {
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, 1 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, tsz.y - 1 ), color );
                }
                if( fend <= m_zvEnd )
                {
                    draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, 1 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, tsz.y - 1 ), color );
                }
                if( fsz - 5 > tsz.x )
                {
                    const auto part = ( fsz - 5 - tsz.x ) / 2;
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, tsz.y / 2 ), wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + part, tsz.y / 2 ), color );
                    draw->AddText( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2 + part, 0 ), color, buf );
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2 + part + tsz.x, tsz.y / 2 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, tsz.y / 2 ), color );
                }
                else
                {
                    draw->AddLine( wpos + ImVec2( ( fbegin - m_zvStart ) * pxns + 2, tsz.y / 2 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns - 2, tsz.y / 2 ), color );
                }
            }
        }

        const auto fend = GetFrameEnd( zend-1 );
        if( fend == m_zvEnd )
        {
            draw->AddLine( wpos + ImVec2( ( fend - m_zvStart ) * pxns, 0 ), wpos + ImVec2( ( fend - m_zvStart ) * pxns, wh ), 0x22FFFFFF );
        }
    }
    while( false );

    return hover;
}

void View::DrawZones()
{
    m_msgHighlight = nullptr;

    if( m_zvStart == m_zvEnd ) return;
    assert( m_zvStart < m_zvEnd );

    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if( window->SkipItems ) return;

    const auto linepos = ImGui::GetCursorScreenPos();
    const auto lineh = ImGui::GetContentRegionAvail().y;

    auto drawMouseLine = DrawZoneFrames();

    ImGui::BeginChild( "##zoneWin", ImVec2( ImGui::GetWindowContentRegionWidth(), ImGui::GetContentRegionAvail().y ), false, ImGuiWindowFlags_AlwaysVerticalScrollbar | ImGuiWindowFlags_NoScrollWithMouse );

    window = ImGui::GetCurrentWindow();
    const auto wpos = ImGui::GetCursorScreenPos();
    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto h = std::max<float>( m_zvHeight, ImGui::GetContentRegionAvail().y - 4 );    // magic border value
    auto draw = ImGui::GetWindowDrawList();

    ImGui::InvisibleButton( "##zones", ImVec2( w, h ) );
    bool hover = ImGui::IsItemHovered();

    auto timespan = m_zvEnd - m_zvStart;
    auto pxns = w / double( timespan );

    if( hover )
    {
        drawMouseLine = true;
        HandleZoneViewMouse( timespan, wpos, w, pxns );
    }

    // zones
    LockHighlight nextLockHighlight { -1 };
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    int offset = 0;
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    for( auto& v : m_threads )
    {
        if( !v->visible ) continue;

        draw->AddLine( wpos + ImVec2( 0, offset + ostep - 1 ), wpos + ImVec2( w, offset + ostep - 1 ), 0x33FFFFFF );

        if( v->showFull )
        {
            draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFFFFFFFF );

            auto it = std::lower_bound( v->messages.begin(), v->messages.end(), m_zvStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
            auto end = std::lower_bound( v->messages.begin(), v->messages.end(), m_zvEnd, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );

            while( it < end )
            {
                const auto px = ( (*it)->time - m_zvStart ) * pxns;
                draw->AddTriangle( wpos + ImVec2( px - (ty - to) * 0.5, offset + to ), wpos + ImVec2( px + (ty - to) * 0.5, offset + to ), wpos + ImVec2( px, offset + to + th ), 0xFFDDDDDD );
                if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px - (ty - to) * 0.5 - 1, offset ), wpos + ImVec2( px + (ty - to) * 0.5 + 1, offset + ty ) ) )
                {
                    ImGui::BeginTooltip();
                    ImGui::Text( "%s", TimeToString( (*it)->time - m_frames[0] ) );
                    ImGui::Text( "%s", (*it)->literal ? GetString( (*it)->str ) : (*it)->txt );
                    ImGui::EndTooltip();
                    m_msgHighlight = *it;
                }
                ++it;
            }
        }
        else
        {
            draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF888888 );
        }
        const auto txt = GetThreadString( v->id );
        draw->AddText( wpos + ImVec2( ty, offset ), v->showFull ? 0xFFFFFFFF : 0xFF888888, txt );

        if( hover && ImGui::IsMouseClicked( 0 ) && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( txt ).x, offset + ty ) ) )
        {
            v->showFull = !v->showFull;
        }

        offset += ostep;

        if( v->showFull )
        {
            m_lastCpu = -1;
            if( m_drawZones )
            {
                const auto depth = DrawZoneLevel( v->timeline, hover, pxns, wpos, offset, 0 );
                offset += ostep * depth;
            }

            if( m_drawLocks )
            {
                const auto depth = DrawLocks( v->id, hover, pxns, wpos, offset, nextLockHighlight );
                offset += ostep * depth;
            }
        }
        offset += ostep * 0.2f;
    }
    m_lockHighlight = nextLockHighlight;

    if( m_drawPlots )
    {
        offset = DrawPlots( offset, pxns, wpos, hover );
    }

    const auto scrollPos = ImGui::GetScrollY();
    if( scrollPos == 0 && m_zvScroll != 0 )
    {
        m_zvHeight = 0;
    }
    else
    {
        if( offset > m_zvHeight ) m_zvHeight = offset;
    }
    m_zvScroll = scrollPos;

    ImGui::EndChild();

    if( m_drawRegion && m_regionStart != m_regionEnd )
    {
        const auto s = std::min( m_regionStart, m_regionEnd );
        const auto e = std::max( m_regionStart, m_regionEnd );
        draw->AddRectFilled( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x22DD8888 );
        draw->AddRect( ImVec2( wpos.x + ( s - m_zvStart ) * pxns, linepos.y ), ImVec2( wpos.x + ( e - m_zvStart ) * pxns, linepos.y + lineh ), 0x44DD8888 );

        ImGui::BeginTooltip();
        ImGui::Text( "%s", TimeToString( e - s ) );
        ImGui::EndTooltip();
    }
    else if( drawMouseLine )
    {
        auto& io = ImGui::GetIO();
        draw->AddLine( ImVec2( io.MousePos.x, linepos.y ), ImVec2( io.MousePos.x, linepos.y + lineh ), 0x33FFFFFF );
    }
}

int View::DrawZoneLevel( const Vector<Event*>& vec, bool hover, double pxns, const ImVec2& wpos, int _offset, int depth )
{
    auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - m_delay, [] ( const auto& l, const auto& r ) { return l->end < r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( vec.begin(), vec.end(), m_zvEnd + m_resolution, [] ( const auto& l, const auto& r ) { return l->start < r; } );
    if( it == zitend ) return depth;

    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    const auto ostep = ty + 1;
    const auto offset = _offset + ostep * depth;
    auto draw = ImGui::GetWindowDrawList();
    const auto dsz = m_delay * pxns;
    const auto rsz = m_resolution * pxns;

    depth++;
    int maxdepth = depth;

    while( it < zitend )
    {
        auto& ev = **it;
        auto& srcloc = GetSourceLocation( ev.srcloc );
        const auto color = GetZoneColor( srcloc );
        const auto end = GetZoneEnd( ev );
        const auto zsz = ( end - ev.start ) * pxns;
        if( zsz < MinVisSize )
        {
            int num = 1;
            const auto px0 = ( ev.start - m_zvStart ) * pxns;
            auto px1 = ( end - m_zvStart ) * pxns;
            auto rend = end;
            for(;;)
            {
                ++it;
                if( it == zitend ) break;
                auto& srcloc2 = GetSourceLocation( (*it)->srcloc );
                if( srcloc.r != srcloc2.r || srcloc.g != srcloc2.g || srcloc.b != srcloc2.b ) break;
                const auto nend = GetZoneEnd( **it );
                const auto pxnext = ( nend - m_zvStart ) * pxns;
                if( pxnext - px1 >= MinVisSize * 2 ) break;
                px1 = pxnext;
                rend = nend;
                num++;
            }
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), color, 2.f );
            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ) ) )
            {
                ImGui::BeginTooltip();
                ImGui::Text( "Zones too small to display: %i", num );
                ImGui::Text( "Execution time: %s", TimeToString( rend - ev.start ) );
                ImGui::EndTooltip();

                if( ImGui::IsMouseClicked( 2 ) && rend - ev.start > 0 )
                {
                    m_zvStartNext = ev.start;
                    m_zvEndNext = rend;
                }
            }
            char tmp[32];
            sprintf( tmp, "%i", num );
            const auto tsz = ImGui::CalcTextSize( tmp );
            if( tsz.x < px1 - px0 )
            {
                const auto x = px0 + ( px1 - px0 - tsz.x ) / 2;
                draw->AddText( wpos + ImVec2( x, offset ), 0xFF4488DD, tmp );
            }
        }
        else
        {
            const char* zoneName;
            if( ev.text && ev.text->zoneName )
            {
                zoneName = GetString( ev.text->zoneName );
            }
            else
            {
                zoneName = GetString( srcloc.function );
            }

            int dmul = 1;
            if( ev.text )
            {
                if( ev.text->zoneName ) dmul++;
                if( ev.text->userText ) dmul++;
            }

            bool migration = false;
            if( m_lastCpu != ev.cpu_start )
            {
                if( m_lastCpu != -1 )
                {
                    migration = true;
                }
                m_lastCpu = ev.cpu_start;
            }

            if( !ev.child.empty() )
            {
                const auto d = DrawZoneLevel( ev.child, hover, pxns, wpos, _offset, depth );
                if( d > maxdepth ) maxdepth = d;
            }

            if( ev.end != -1 && m_lastCpu != ev.cpu_end )
            {
                m_lastCpu = ev.cpu_end;
                migration = true;
            }

            auto tsz = ImGui::CalcTextSize( zoneName );
            if( tsz.x > zsz )
            {
                zoneName = ShortenNamespace( zoneName );
                tsz = ImGui::CalcTextSize( zoneName );
            }

            const auto pr0 = ( ev.start - m_zvStart ) * pxns;
            const auto pr1 = ( end - m_zvStart ) * pxns;
            const auto px0 = std::max( pr0, -10.0 );
            const auto px1 = std::min( pr1, double( w + 10 ) );
            draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), color, 2.f );
            draw->AddRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ), GetZoneHighlight( ev, migration ), 2.f, -1, GetZoneThickness( ev ) );
            if( dsz * dmul >= MinVisSize )
            {
                draw->AddRectFilled( wpos + ImVec2( pr0, offset ), wpos + ImVec2( std::min( pr0+dsz*dmul, pr1 ), offset + tsz.y ), 0x882222DD, 2.f );
                draw->AddRectFilled( wpos + ImVec2( pr1, offset ), wpos + ImVec2( pr1+dsz, offset + tsz.y ), 0x882222DD, 2.f );
            }
            if( rsz >= MinVisSize )
            {
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + tsz.y/2 ), wpos + ImVec2( pr0 - rsz, offset + tsz.y/2 ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 + rsz, offset + tsz.y/4 ), wpos + ImVec2( pr0 + rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr0 - rsz, offset + tsz.y/4 ), wpos + ImVec2( pr0 - rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );

                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + tsz.y/2 ), wpos + ImVec2( pr1 - rsz, offset + tsz.y/2 ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 + rsz, offset + tsz.y/4 ), wpos + ImVec2( pr1 + rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );
                draw->AddLine( wpos + ImVec2( pr1 - rsz, offset + tsz.y/4 ), wpos + ImVec2( pr1 - rsz, offset + 3*tsz.y/4 ), 0xAAFFFFFF );
            }
            if( tsz.x < zsz )
            {
                const auto x = ( ev.start - m_zvStart ) * pxns + ( ( end - ev.start ) * pxns - tsz.x ) / 2;
                if( x < 0 || x > w - tsz.x )
                {
                    ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                    draw->AddText( wpos + ImVec2( std::max( std::max( 0., px0 ), std::min( double( w - tsz.x ), x ) ), offset ), 0xFFFFFFFF, zoneName );
                    ImGui::PopClipRect();
                }
                else
                {
                    draw->AddText( wpos + ImVec2( x, offset ), 0xFFFFFFFF, zoneName );
                }
            }
            else
            {
                ImGui::PushClipRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y * 2 ), true );
                draw->AddText( wpos + ImVec2( ( ev.start - m_zvStart ) * pxns, offset ), 0xFFFFFFFF, zoneName );
                ImGui::PopClipRect();
            }

            if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + tsz.y ) ) )
            {
                ZoneTooltip( ev );

                if( m_zvStartNext == 0 && ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( ev );
                }
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_zoneInfoWindow = &ev;
                }
            }

            ++it;
        }
    }
    return maxdepth;
}

static inline bool IsThreadWaiting( uint64_t bitlist, uint8_t thread )
{
    return ( bitlist & ( 1 << thread ) ) != 0;
}

int View::DrawLocks( uint64_t tid, bool hover, double pxns, const ImVec2& wpos, int _offset, LockHighlight& highlight )
{
    enum class State
    {
        Nothing,
        HasLock,
        HasBlockingLock,
        WaitLock
    };

    int cnt = 0;
    for( auto& v : m_lockMap )
    {
        auto& lockmap = v.second;
        if( !lockmap.visible ) continue;

        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;

        auto& tl = lockmap.timeline;
        assert( !tl.empty() );
        if( tl.back()->time < m_zvStart ) continue;

        const auto thread = it->second;

        auto vbegin = std::lower_bound( tl.begin(), tl.end(), m_zvStart - m_delay, [] ( const auto& l, const auto& r ) { return l->time < r; } );
        const auto vend = std::lower_bound( tl.begin(), tl.end(), m_zvEnd + m_resolution, [] ( const auto& l, const auto& r ) { return l->time < r; } );
        auto vendn = tl.end();

        if( vbegin > tl.begin() ) vbegin--;

        bool drawn = false;
        const auto w = ImGui::GetWindowContentRegionWidth();
        const auto ty = ImGui::GetFontSize();
        const auto ostep = ty + 1;
        const auto offset = _offset + ostep * cnt;
        auto draw = ImGui::GetWindowDrawList();
        auto& srcloc = GetSourceLocation( lockmap.srcloc );
        const auto dsz = m_delay * pxns;
        const auto rsz = m_resolution * pxns;

        State state = State::Nothing;
        if( (*vbegin)->lockCount != 0 )
        {
            if( (*vbegin)->lockingThread == thread )
            {
                if( (*vbegin)->waitList == 0 )
                {
                    state = State::HasLock;
                }
                else
                {
                    state = State::HasBlockingLock;
                }
            }
            else if( IsThreadWaiting( (*vbegin)->waitList, thread ) )
            {
                state = State::WaitLock;
            }
        }

        while( vbegin < vend )
        {
            State nextState = State::Nothing;
            auto next = vbegin;
            next++;

            switch( state )
            {
            case State::Nothing:
                while( next < vendn )
                {
                    if( (*next)->lockCount != 0 )
                    {
                        if( (*next)->lockingThread == thread )
                        {
                            if( (*next)->waitList == 0 )
                            {
                                nextState = State::HasLock;
                                break;
                            }
                            else
                            {
                                nextState = State::HasBlockingLock;
                                break;
                            }
                        }
                        else if( IsThreadWaiting( (*next)->waitList, thread ) )
                        {
                            nextState = State::WaitLock;
                            break;
                        }
                    }
                    next++;
                }
                break;
            case State::HasLock:
                nextState = State::HasLock;
                while( next < vendn )
                {
                    if( (*next)->lockCount == 0 )
                    {
                        nextState = State::Nothing;
                        break;
                    }
                    if( (*next)->waitList != 0 )
                    {
                        nextState = State::HasBlockingLock;
                        break;
                    }
                    next++;
                }
                break;
            case State::HasBlockingLock:
                nextState = State::HasBlockingLock;
                while( next < vendn )
                {
                    if( (*next)->lockCount == 0 )
                    {
                        nextState = State::Nothing;
                        break;
                    }
                    if( (*next)->waitList != (*vbegin)->waitList )
                    {
                        break;
                    }
                    next++;
                }
                break;
            case State::WaitLock:
                nextState = State::WaitLock;
                while( next < vendn )
                {
                    if( (*next)->lockingThread == thread )
                    {
                        if( (*next)->waitList == 0 )
                        {
                            nextState = State::HasLock;
                            break;
                        }
                        else
                        {
                            nextState = State::HasBlockingLock;
                            break;
                        }
                    }
                    if( (*next)->lockingThread != (*vbegin)->lockingThread )
                    {
                        break;
                    }
                    if( (*next)->lockCount == 0 )
                    {
                        break;
                    }
                    next++;
                }
                break;
            default:
                assert( false );
                break;
            }

            if( state != State::Nothing && ( !m_onlyContendedLocks || state != State::HasLock ) )
            {
                drawn = true;
                const auto t0 = (*vbegin)->time;
                const auto t1 = next == tl.end() ? GetLastTime() : (*next)->time;
                const auto px0 = ( t0 - m_zvStart ) * pxns;
                const auto px1 = ( t1 - m_zvStart ) * pxns;

                bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ) );
                if( itemHovered )
                {
                    highlight.blocked = state == State::HasBlockingLock;
                    if( !highlight.blocked )
                    {
                        highlight.id = v.first;
                        highlight.begin = (*vbegin)->time;
                        highlight.end = (*next)->time;
                        highlight.thread = thread;
                        highlight.blocked = false;
                    }
                    else
                    {
                        auto b = vbegin;
                        while( b != tl.begin() )
                        {
                            if( (*b)->lockingThread != (*vbegin)->lockingThread )
                            {
                                break;
                            }
                            b--;
                        }
                        b++;
                        highlight.begin = (*b)->time;

                        auto e = next;
                        while( e != tl.end() )
                        {
                            if( (*e)->lockingThread != (*next)->lockingThread )
                            {
                                highlight.id = v.first;
                                highlight.end = (*e)->time;
                                highlight.thread = thread;
                                break;
                            }
                            e++;
                        }
                    }

                    ImGui::BeginTooltip();
                    ImGui::Text( "Lock #%" PRIu64, v.first );
                    ImGui::Text( "%s", GetString( srcloc.function ) );
                    ImGui::Text( "%s:%i", GetString( srcloc.file ), srcloc.line );
                    ImGui::Text( "Time: %s", TimeToString( t1 - t0 ) );
                    ImGui::Separator();

                    uint64_t markloc = 0;
                    auto it = vbegin;
                    for(;;)
                    {
                        if( (*it)->thread == thread )
                        {
                            if( ( (*it)->lockingThread == thread || IsThreadWaiting( (*it)->waitList, thread ) ) && (*it)->srcloc != 0 )
                            {
                                markloc = (*it)->srcloc;
                                break;
                            }
                        }
                        if( it == tl.begin() ) break;
                        --it;
                    }
                    if( markloc != 0 )
                    {
                        auto& marklocdata = GetSourceLocation( markloc );
                        ImGui::Text( "Lock event location:" );
                        ImGui::Text( "%s", GetString( marklocdata.function ) );
                        ImGui::Text( "%s:%i", GetString( marklocdata.file ), marklocdata.line );
                        ImGui::Separator();
                    }

                    switch( state )
                    {
                    case State::HasLock:
                        ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", GetThreadString( tid ) );
                        break;
                    case State::HasBlockingLock:
                    {
                        ImGui::Text( "Thread \"%s\" has lock. Other threads are blocked:", GetThreadString( tid ) );
                        auto waitList = (*vbegin)->waitList;
                        int t = 0;
                        while( waitList != 0 )
                        {
                            if( waitList & 0x1 )
                            {
                                ImGui::Text( "\"%s\"", GetThreadString( lockmap.threadList[t] ) );
                            }
                            waitList >>= 1;
                            t++;
                        }
                        break;
                    }
                    case State::WaitLock:
                    {
                        ImGui::Text( "Thread \"%s\" is blocked by other thread:", GetThreadString( tid ) );
                        ImGui::Text( "\"%s\"", GetThreadString( lockmap.threadList[(*vbegin)->lockingThread] ) );
                        break;
                    }
                    default:
                        assert( false );
                        break;
                    }
                    ImGui::EndTooltip();
                }

                const auto cfilled  = state == State::HasLock ? 0xFF228A22 : ( state == State::HasBlockingLock ? 0xFF228A8A : 0xFF2222BD );
                draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), cfilled, 2.f );
                if( m_lockHighlight.thread != thread && ( state == State::HasBlockingLock ) != m_lockHighlight.blocked && next != tl.end() && m_lockHighlight.id == v.first && m_lockHighlight.begin <= (*vbegin)->time && m_lockHighlight.end >= (*next)->time )
                {
                    const auto t = uint8_t( ( sin( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count() * 0.01 ) * 0.5 + 0.5 ) * 255 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), 0x00FFFFFF | ( t << 24 ), 2.f, -1, 2.f );
                }
                else
                {
                    const auto coutline = state == State::HasLock ? 0xFF3BA33B : ( state == State::HasBlockingLock ? 0xFF3BA3A3 : 0xFF3B3BD6 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), coutline, 2.f );
                }
                if( dsz >= MinVisSize )
                {
                    draw->AddRectFilled( wpos + ImVec2( px0, offset ), wpos + ImVec2( std::min( px0+dsz, px1 ), offset + ty ), 0x882222DD, 2.f );
                }
                if( rsz >= MinVisSize )
                {
                    draw->AddLine( wpos + ImVec2( px0 + rsz, offset + ty/2 ), wpos + ImVec2( px0 - rsz, offset + ty/2 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px0 + rsz, offset + ty/4 ), wpos + ImVec2( px0 + rsz, offset + 3*ty/4 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px0 - rsz, offset + ty/4 ), wpos + ImVec2( px0 - rsz, offset + 3*ty/4 ), 0xAAFFFFFF );

                    draw->AddLine( wpos + ImVec2( px1 + rsz, offset + ty/2 ), wpos + ImVec2( px1 - rsz, offset + ty/2 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px1 + rsz, offset + ty/4 ), wpos + ImVec2( px1 + rsz, offset + 3*ty/4 ), 0xAAFFFFFF );
                    draw->AddLine( wpos + ImVec2( px1 - rsz, offset + ty/4 ), wpos + ImVec2( px1 - rsz, offset + 3*ty/4 ), 0xAAFFFFFF );
                }
            }

            vbegin = next;
            state = nextState;
        }

        if( drawn )
        {
            char buf[1024];
            sprintf( buf, "%" PRIu64 ": %s", v.first, GetString( srcloc.function ) );
            draw->AddText( wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
            cnt++;
        }
    }
    return cnt;
}

enum { PlotHeight = 100 };

int View::DrawPlots( int offset, double pxns, const ImVec2& wpos, bool hover )
{
    const auto w = ImGui::GetWindowContentRegionWidth() - 1;
    const auto ty = ImGui::GetFontSize();
    auto draw = ImGui::GetWindowDrawList();
    const auto to = 9.f;
    const auto th = ( ty - to ) * sqrt( 3 ) * 0.5;
    const auto nspx = 1.0 / pxns;

    for( auto& v : m_plots )
    {
        if( !v->visible ) continue;

        assert( !v->data.empty() );

        if( v->showFull )
        {
            draw->AddTriangleFilled( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( ty - to/2, offset + to/2 ), wpos + ImVec2( ty * 0.5, offset + to/2 + th ), 0xFF44DDDD );
        }
        else
        {
            draw->AddTriangle( wpos + ImVec2( to/2, offset + to/2 ), wpos + ImVec2( to/2, offset + ty - to/2 ), wpos + ImVec2( to/2 + th, offset + ty * 0.5 ), 0xFF226E6E );
        }
        const auto txt = GetString( v->name );
        draw->AddText( wpos + ImVec2( ty, offset ), v->showFull ? 0xFF44DDDD : 0xFF226E6E, txt );
        draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( txt ).x, offset + ty ) ) )
        {
            if( ImGui::IsMouseClicked( 0 ) )
            {
                v->showFull = !v->showFull;
            }

            const auto tr = v->data.back()->time - v->data.front()->time;

            ImGui::BeginTooltip();
            ImGui::Text( "Plot \"%s\"", txt );
            ImGui::Text( "Data points: %s", RealToString( v->data.size(), true ) );
            ImGui::Text( "Data range: %s", RealToString( v->max - v->min, true ) );
            ImGui::Text( "Min value: %s", RealToString( v->min, true ) );
            ImGui::Text( "Max value: %s", RealToString( v->max, true ) );
            ImGui::Text( "Time range: %s", TimeToString( tr ) );
            ImGui::Text( "Data/second: %s", RealToString( double( v->data.size() ) / tr * 1000000000ull, true ) );

            const auto it = std::lower_bound( v->data.begin(), v->data.end(), v->data.back()->time - 1000000000ull * 10, [] ( const auto& l, const auto& r ) { return l->time < r; } );
            const auto tr10 = v->data.back()->time - (*it)->time;
            if( tr10 != 0 )
            {
                ImGui::Text( "D/s (10s): %s", RealToString( double( std::distance( it, v->data.end() ) ) / tr10 * 1000000000ull, true ) );
            }

            ImGui::EndTooltip();
        }

        offset += ty;

        if( v->showFull )
        {
            auto& vec = v->data;
            auto it = std::lower_bound( vec.begin(), vec.end(), m_zvStart - m_delay, [] ( const auto& l, const auto& r ) { return l->time < r; } );
            auto end = std::lower_bound( vec.begin(), vec.end(), m_zvEnd + m_resolution, [] ( const auto& l, const auto& r ) { return l->time < r; } );

            if( end != vec.end() ) end++;
            if( it != vec.begin() ) it--;

            double min = (*it)->val;
            double max = (*it)->val;
            if( std::distance( it, end ) > 1000000 )
            {
                min = v->min;
                max = v->max;
            }
            else
            {
                auto tmp = it;
                ++tmp;
                while( tmp != end )
                {
                    if( (*tmp)->val < min ) min = (*tmp)->val;
                    else if( (*tmp)->val > max ) max = (*tmp)->val;
                    ++tmp;
                }
            }

            {
                char tmp[64];
                sprintf( tmp, "%s", RealToString( max, true ) );
                draw->AddText( wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
            }

            const auto revrange = 1.0 / ( max - min );

            if( it == vec.begin() )
            {
                const auto x = ( (*it)->time - m_zvStart ) * pxns;
                const auto y = PlotHeight - ( (*it)->val - min ) * revrange * PlotHeight;
                DrawPlotPoint( wpos, x, y, offset, 0xFF44DDDD, hover, false, (*it)->val, 0, false );
            }

            auto prevx = it;
            auto prevy = it;
            ++it;
            ptrdiff_t skip = 0;
            while( it < end )
            {
                const auto x0 = ( (*prevx)->time - m_zvStart ) * pxns;
                const auto x1 = ( (*it)->time - m_zvStart ) * pxns;
                const auto y0 = PlotHeight - ( (*prevy)->val - min ) * revrange * PlotHeight;
                const auto y1 = PlotHeight - ( (*it)->val - min ) * revrange * PlotHeight;

                draw->AddLine( wpos + ImVec2( x0, offset + y0 ), wpos + ImVec2( x1, offset + y1 ), 0xFF44DDDD );

                const auto rx = skip == 0 ? 2.0 : ( skip == 1 ? 2.5 : 4.0 );

                auto range = std::upper_bound( it, end, int64_t( (*it)->time + nspx * rx ), [] ( const auto& l, const auto& r ) { return l < r->time; } );
                assert( range > it );
                const auto rsz = std::distance( it, range );
                if( rsz == 1 )
                {
                    DrawPlotPoint( wpos, x1, y1, offset, 0xFF44DDDD, hover, true, (*it)->val, (*prevy)->val, false );
                    prevx = it;
                    prevy = it;
                    ++it;
                }
                else
                {
                    prevx = it;

                    enum { MaxPoints = 512 };
                    skip = rsz / MaxPoints;
                    const auto skip1 = std::max<ptrdiff_t>( 1, skip );
                    const auto sz = rsz / skip1 + 1;
                    assert( sz <= MaxPoints*2 );
                    float tmpvec[MaxPoints*2];

                    auto dst = tmpvec;
                    for(;;)
                    {
                        *dst++ = float( (*it)->val );
                        if( std::distance( it, range ) > skip1 )
                        {
                            it += skip1;
                        }
                        else
                        {
                            break;
                        }
                    }
                    std::sort( tmpvec, dst, [] ( const auto& l, const auto& r ) { return l < r; } );

                    draw->AddLine( wpos + ImVec2( x1, offset + PlotHeight - ( tmpvec[0] - min ) * revrange * PlotHeight ), wpos + ImVec2( x1, offset + PlotHeight - ( dst[-1] - min ) * revrange * PlotHeight ), 0xFF44DDDD );

                    auto vit = tmpvec;
                    while( vit != dst )
                    {
                        auto vrange = std::upper_bound( vit, dst, *vit + 3.0 / ( revrange * PlotHeight ), [] ( const auto& l, const auto& r ) { return l < r; } );
                        assert( vrange > vit );
                        if( std::distance( vit, vrange ) == 1 )
                        {
                            DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, false );
                        }
                        else
                        {
                            DrawPlotPoint( wpos, x1, PlotHeight - ( *vit - min ) * revrange * PlotHeight, offset, 0xFF44DDDD, hover, false, *vit, 0, true );
                        }
                        vit = vrange;
                    }

                    prevy = it - 1;
                }
            }

            offset += PlotHeight - ty;
            {
                char tmp[64];
                sprintf( tmp, "%s", RealToString( min, true ) );
                draw->AddText( wpos + ImVec2( 0, offset ), 0x8844DDDD, tmp );
            }
            draw->AddLine( wpos + ImVec2( 0, offset + ty - 1 ), wpos + ImVec2( w, offset + ty - 1 ), 0x8844DDDD );
            offset += ty;
        }
        offset += 0.2 * ty;
    }

    return offset;
}

void View::DrawPlotPoint( const ImVec2& wpos, float x, float y, int offset, uint32_t color, bool hover, bool hasPrev, double val, double prev, bool merged )
{
    auto draw = ImGui::GetWindowDrawList();
    if( merged )
    {
        draw->AddRectFilled( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }
    else
    {
        draw->AddRect( wpos + ImVec2( x - 1.5f, offset + y - 1.5f ), wpos + ImVec2( x + 2.5f, offset + y + 2.5f ), color );
    }

    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( x - 2, offset ), wpos + ImVec2( x + 2, offset + PlotHeight ) ) )
    {
        ImGui::BeginTooltip();
        ImGui::Text( "Value: %s", RealToString( val, true ) );
        if( hasPrev )
        {
            ImGui::Text( "Change: %s", RealToString( val - prev, true ) );
        }
        ImGui::EndTooltip();
    }
}

void View::DrawZoneInfoWindow()
{
    if( !m_zoneInfoWindow ) return;

    auto& ev = *m_zoneInfoWindow;
    int dmul = 1;

    bool show = true;
    ImGui::Begin( "Zone info", &show, ImGuiWindowFlags_ShowBorders );

    if( ImGui::Button( "Zoom to zone" ) )
    {
        ZoomToZone( ev );
    }
    ImGui::SameLine();
    if( ImGui::Button( "Go to parent" ) )
    {
        if( ev.parent )
        {
            m_zoneInfoWindow = ev.parent;
        }
    }

    ImGui::Separator();

    if( ev.text && ev.text->zoneName )
    {
        ImGui::Text( "Zone name: %s", GetString( ev.text->zoneName ) );
        dmul++;
    }
    auto& srcloc = GetSourceLocation( ev.srcloc );
    ImGui::Text( "Function: %s", GetString( srcloc.function ) );
    ImGui::Text( "Location: %s:%i", GetString( srcloc.file ), srcloc.line );
    if( ev.text && ev.text->userText )
    {
        ImGui::Text( "User text: %s", ev.text->userText );
        dmul++;
    }

    ImGui::Separator();

    const auto end = GetZoneEnd( ev );
    const auto ztime = end - ev.start;
    ImGui::Text( "Time from start of program: %s", TimeToString( ev.start - m_frames[0] ) );
    ImGui::Text( "Execution time: %s", TimeToString( ztime ) );
    ImGui::Text( "Without profiling: %s", TimeToString( ztime - m_delay * dmul ) );

    auto ctt = std::make_unique<uint64_t[]>( ev.child.size() );
    auto cti = std::make_unique<uint32_t[]>( ev.child.size() );
    uint64_t ctime = 0;
    for( int i=0; i<ev.child.size(); i++ )
    {
        const auto cend = GetZoneEnd( *ev.child[i] );
        const auto ct = cend - ev.child[i]->start;
        ctime += ct;
        ctt[i] = ct;
        cti[i] = i;
    }

    std::sort( cti.get(), cti.get() + ev.child.size(), [&ctt] ( const auto& lhs, const auto& rhs ) { return ctt[lhs] > ctt[rhs]; } );

    if( !ev.child.empty() )
    {
        const auto ty = ImGui::GetTextLineHeight();
        ImGui::Columns( 2 );
        ImGui::Separator();
        ImGui::Text( "Child zones: %" PRIu64, ev.child.size() );
        ImGui::NextColumn();
        ImGui::Text( "Exclusive time: %s (%.2f%%)", TimeToString( ztime - ctime ), double( ztime - ctime ) / ztime * 100 );
        ImGui::NextColumn();
        ImGui::Separator();
        for( int i=0; i<ev.child.size(); i++ )
        {
            auto& cev = *ev.child[cti[i]];
            if( cev.text && cev.text->zoneName )
            {
                ImGui::Text( "%s", GetString( cev.text->zoneName ) );
            }
            else
            {
                auto& srcloc = GetSourceLocation( cev.srcloc );
                ImGui::Text( "%s", GetString( srcloc.function ) );
            }
            if( ImGui::IsItemHovered() )
            {
                m_zoneHighlight = &cev;
                if( ImGui::IsMouseClicked( 0 ) )
                {
                    m_zoneInfoWindow = &cev;
                }
                if( ImGui::IsMouseClicked( 2 ) )
                {
                    ZoomToZone( cev );
                }
                ZoneTooltip( cev );
            }
            ImGui::NextColumn();
            const auto part = double( ctt[cti[i]] ) / ztime;
            char buf[128];
            sprintf( buf, "%s (%.2f%%)", TimeToString( ctt[cti[i]] ), part * 100 );
            ImGui::ProgressBar( part, ImVec2( -1, ty ), buf );
            ImGui::NextColumn();
        }
        ImGui::EndColumns();
    }

    ImGui::End();

    if( !show ) m_zoneInfoWindow = nullptr;
}

void View::DrawOptions()
{
    const auto tw = ImGui::GetFontSize();
    ImGui::Begin( "Options", &m_showOptions, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_ShowBorders );
    ImGui::Checkbox( "Draw zones", &m_drawZones );
    int ns = (int)m_namespace;
    ImGui::Combo( "Namespaces", &ns, "Full\0Shortened\0None" );
    m_namespace = (Namespace)ns;
    ImGui::Separator();
    ImGui::Checkbox( "Draw locks", &m_drawLocks );
    ImGui::SameLine();
    ImGui::Checkbox( "Only contended", &m_onlyContendedLocks );
    ImGui::Indent( tw );
    for( auto& l : m_lockMap )
    {
        ImGui::Checkbox( GetString( GetSourceLocation( l.second.srcloc ).function ), &l.second.visible );
    }
    ImGui::Unindent( tw );
    ImGui::Separator();
    ImGui::Checkbox( "Draw plots", &m_drawPlots );
    ImGui::Indent( tw );
    for( auto& p : m_plots )
    {
        ImGui::Checkbox( GetString( p->name ), &p->visible );
    }
    ImGui::Unindent( tw );
    ImGui::Separator();
    ImGui::Text( "Visible threads:" );
    ImGui::Indent( tw );
    for( auto& t : m_threads )
    {
        ImGui::Checkbox( GetThreadString( t->id ), &t->visible );
    }
    ImGui::Unindent( tw );
    ImGui::End();
}

void View::DrawMessages()
{
    ImGui::Begin( "Messages", &m_showMessages, ImGuiWindowFlags_ShowBorders );
    for( auto& v : m_messages )
    {
        char tmp[64 * 1024];
        sprintf( tmp, "%10s | %s", TimeToString( v->time - m_frames[0] ), v->literal ? GetString( v->str ) : v->txt );
        if( m_msgHighlight == v )
        {
            ImGui::TextColored( ImVec4( 0xDD / 255.f, 0x22 / 255.f, 0x22 / 255.f, 1.f ), "%s", tmp );
        }
        else
        {
            ImGui::Text( "%s", tmp );
        }
        if( ImGui::IsItemClicked() )
        {
            m_pause = true;
            const auto hr = std::max<uint64_t>( 1, ( m_zvEnd - m_zvStart ) / 2 );
            m_zvStart = v->time - hr;
            m_zvEnd = v->time + hr;
        }
    }
    ImGui::End();
}

uint32_t View::GetZoneColor( const Event& ev )
{
    return GetZoneColor( GetSourceLocation( ev.srcloc ) );
}

uint32_t View::GetZoneColor( const QueueSourceLocation& srcloc )
{
    const auto color = srcloc.r | ( srcloc.g << 8 ) | ( srcloc.b << 16 );
    return color != 0 ? ( color | 0xFF000000 ) : 0xFFCC5555;
}

uint32_t View::GetZoneHighlight( const Event& ev, bool migration )
{
    if( m_zoneInfoWindow == &ev )
    {
        return 0xFF44DD44;
    }
    else if( m_zoneHighlight == &ev )
    {
        return 0xFF4444FF;
    }
    else if( migration )
    {
        return 0xFFDD22DD;
    }
    else
    {
        const auto color = GetZoneColor( ev );
        return 0xFF000000 |
            ( std::min<int>( 0xFF, ( ( ( color & 0x00FF0000 ) >> 16 ) + 25 ) ) << 16 ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x0000FF00 ) >> 8  ) + 25 ) ) << 8  ) |
            ( std::min<int>( 0xFF, ( ( ( color & 0x000000FF )       ) + 25 ) )       );
    }
}

float View::GetZoneThickness( const Event& ev )
{
    if( m_zoneInfoWindow == &ev || m_zoneHighlight == &ev )
    {
        return 3.f;
    }
    else
    {
        return 1.f;
    }
}

void View::ZoomToZone( const Event& ev )
{
    const auto end = GetZoneEnd( ev );
    if( end - ev.start <= 0 ) return;
    m_zvStartNext = ev.start;
    m_zvEndNext = end;
}

void View::ZoneTooltip( const Event& ev )
{
    int dmul = 1;
    if( ev.text )
    {
        if( ev.text->zoneName ) dmul++;
        if( ev.text->userText ) dmul++;
    }

    auto& srcloc = GetSourceLocation( ev.srcloc );

    const auto filename = GetString( srcloc.file );
    const auto line = srcloc.line;

    const char* func;
    const char* zoneName;
    if( ev.text && ev.text->zoneName )
    {
        zoneName = GetString( ev.text->zoneName );
        func = GetString( srcloc.function );
    }
    else
    {
        func = zoneName = GetString( srcloc.function );
    }

    const auto end = GetZoneEnd( ev );

    ImGui::BeginTooltip();
    ImGui::Text( "%s", func );
    ImGui::Text( "%s:%i", filename, line );
    ImGui::Text( "Execution time: %s", TimeToString( end - ev.start ) );
    ImGui::Text( "Without profiling: %s", TimeToString( end - ev.start - m_delay * dmul ) );
    if( ev.cpu_start != -1 )
    {
        if( ev.end == -1 || ev.cpu_start == ev.cpu_end )
        {
            ImGui::Text( "CPU: %i", ev.cpu_start );
        }
        else
        {
            ImGui::Text( "CPU: %i -> %i", ev.cpu_start, ev.cpu_end );
        }
    }
    if( ev.text && ev.text->userText )
    {
        ImGui::Text( "" );
        ImGui::TextColored( ImVec4( 0xCC / 255.f, 0xCC / 255.f, 0x22 / 255.f, 1.f ), "%s", ev.text->userText );
    }
    ImGui::EndTooltip();
}

TextData* View::GetTextData( Event& zone )
{
    if( !zone.text )
    {
        zone.text = m_slab.Alloc<TextData>();
        zone.text->userText = nullptr;
        zone.text->zoneName = 0;
    }
    return zone.text;
}

void View::Write( FileWrite& f )
{
    f.Write( &m_delay, sizeof( m_delay ) );
    f.Write( &m_resolution, sizeof( m_resolution ) );
    f.Write( &m_timerMul, sizeof( m_timerMul ) );

    uint64_t sz = m_captureName.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_captureName.c_str(), sz );

    sz = m_frames.size();
    f.Write( &sz, sizeof( sz ) );
    f.Write( m_frames.data(), sizeof( uint64_t ) * sz );

    sz = m_strings.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_strings )
    {
        f.Write( &v.first, sizeof( v.first ) );
        sz = v.second.size();
        f.Write( &sz, sizeof( sz ) );
        f.Write( v.second.c_str(), v.second.size() );
    }

    sz = m_threadNames.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_threadNames )
    {
        f.Write( &v.first, sizeof( v.first ) );
        sz = v.second.size();
        f.Write( &sz, sizeof( sz ) );
        f.Write( v.second.c_str(), v.second.size() );
    }

    sz = m_customStrings.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_customStrings )
    {
        uint64_t ptr = (uint64_t)v;
        f.Write( &ptr, sizeof( ptr ) );
        sz = strlen( v );
        f.Write( &sz, sizeof( sz ) );
        f.Write( v, sz );
    }

    sz = m_sourceLocation.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_sourceLocation )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second, sizeof( v.second ) );
    }

    sz = m_lockMap.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_lockMap )
    {
        f.Write( &v.first, sizeof( v.first ) );
        f.Write( &v.second.srcloc, sizeof( v.second.srcloc ) );
        sz = v.second.threadList.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& t : v.second.threadList )
        {
            f.Write( &t, sizeof( t ) );
        }
        sz = v.second.timeline.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& lev : v.second.timeline )
        {
            f.Write( lev, sizeof( LockEvent ) );
        }
    }

    sz = m_messages.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& v : m_messages )
    {
        const auto ptr = (uint64_t)v;
        f.Write( &ptr, sizeof( ptr ) );
        f.Write( &v->_time_literal, sizeof( v->_time_literal ) );
        if( v->literal )
        {
            f.Write( &v->str, sizeof( v->str ) );
        }
        else
        {
            sz = strlen( v->txt );
            f.Write( &sz, sizeof( sz ) );
            f.Write( v->txt, sz );
        }
    }

    sz = m_threads.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& thread : m_threads )
    {
        f.Write( &thread->id, sizeof( thread->id ) );
        WriteTimeline( f, thread->timeline );
        sz = thread->messages.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& v : thread->messages )
        {
            auto ptr = uint64_t( v );
            f.Write( &ptr, sizeof( ptr ) );
        }
    }

    sz = m_plots.size();
    f.Write( &sz, sizeof( sz ) );
    for( auto& plot : m_plots )
    {
        f.Write( &plot->name, sizeof( plot->name ) );
        f.Write( &plot->min, sizeof( plot->min ) );
        f.Write( &plot->max, sizeof( plot->max ) );
        sz = plot->data.size();
        f.Write( &sz, sizeof( sz ) );
        for( auto& item : plot->data )
        {
            f.Write( item, sizeof( PlotItem ) );
        }
    }
}

void View::WriteTimeline( FileWrite& f, const Vector<Event*>& vec )
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

        if( v->text )
        {
            uint8_t flag = 1;
            f.Write( &flag, sizeof( flag ) );
            f.Write( &v->text->userText, sizeof( v->text->userText ) );
            f.Write( &v->text->zoneName, sizeof( v->text->zoneName ) );
        }
        else
        {
            uint8_t flag = 0;
            f.Write( &flag, sizeof( flag ) );
        }

        WriteTimeline( f, v->child );
    }
}

void View::ReadTimeline( FileRead& f, Vector<Event*>& vec, Event* parent, const std::unordered_map<uint64_t, const char*>& stringMap )
{
    uint64_t sz;
    f.Read( &sz, sizeof( sz ) );
    vec.reserve( sz );

    for( uint64_t i=0; i<sz; i++ )
    {
        auto zone = m_slab.AllocInit<Event>();
        m_zonesCnt++;
        vec.push_back( zone );

        f.Read( &zone->start, sizeof( zone->start ) );
        f.Read( &zone->end, sizeof( zone->end ) );
        f.Read( &zone->srcloc, sizeof( zone->srcloc ) );
        f.Read( &zone->cpu_start, sizeof( zone->cpu_start ) );
        f.Read( &zone->cpu_end, sizeof( zone->cpu_end ) );

        uint8_t flag;
        f.Read( &flag, sizeof( flag ) );
        if( flag )
        {
            zone->text = m_slab.Alloc<TextData>();
            uint64_t ptr;
            f.Read( &ptr, sizeof( ptr ) );
            zone->text->userText = ptr == 0 ? nullptr : stringMap.find( ptr )->second;
            f.Read( &zone->text->zoneName, sizeof( zone->text->zoneName ) );
        }
        else
        {
            zone->text = nullptr;
        }

        zone->parent = parent;

        ReadTimeline( f, zone->child, zone, stringMap );
    }
}

}
