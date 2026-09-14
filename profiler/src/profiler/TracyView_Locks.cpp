#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyView.hpp"
#include "../Fonts.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;

template<typename F>
static void ForEachRoleAt( const LockMap& lockmap, uint32_t at, uint8_t flag, F&& fn )
{
    for( size_t slot=0; slot < lockmap.threads.size(); slot++ )
    {
        const auto& segs = lockmap.threads[slot].segments;
        auto it = std::upper_bound( segs.begin(), segs.end(), at, [] ( uint32_t v, const LockSegment& s ) { return v < s.evStart; } );
        if( it == segs.begin() ) continue;
        --it;
        if( ( it->nextEv == LockEvent::NoEvent || it->nextEv > at ) && ( it->flags & flag ) != 0 ) fn( ( uint16_t )slot );
    }
}


static size_t CountRoleAt( const LockMap& lockmap, uint32_t at, uint8_t flag )
{
    size_t cnt = 0;
    ForEachRoleAt( lockmap, at, flag, [ &cnt ] ( uint16_t ) { cnt++; } );
    return cnt;
}

// A shared hold ends only at the owning thread's ReleaseShared; segments split by
// other events within a hold keep their SharedHolding flag and must stay merged.
static bool SharedHoldEnded( const LockMap& lockmap, uint16_t slot, const LockSegment& seg )
{
    if( seg.nextEv == LockEvent::NoEvent ) return false;
    const auto& ev = lockmap.timeline[ seg.nextEv ];
    return ev.thread == slot && ( LockEvent::Type )ev.type == LockEvent::Type::ReleaseShared;
}

void View::DrawLockHeader( uint32_t id, const LockMap& lockmap, const SourceLocation& srcloc, bool hover, ImDrawList* draw, const ImVec2& wpos, float w, float ty, float offset, uint16_t tid )
{
    char buf[1024];
    if( lockmap.customName.Active() )
    {
        sprintf( buf, "%" PRIu32 ": %s", id, m_worker.GetString( lockmap.customName ) );
    }
    else
    {
        sprintf( buf, "%" PRIu32 ": %s", id, m_worker.GetString( srcloc.function ) );
    }
    ImGui::PushFont( g_fonts.normal, FontSmall );
    DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
    ImGui::PopFont();
    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty + 1 ) ) )
    {
        m_lockHoverHighlight = id;

        if( ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty + 1 ) ) )
        {
            const auto& tinfo = lockmap.threads[tid];
            const auto activity = tinfo.lastTime - tinfo.firstTime;
            const auto traceLen = m_worker.GetLastTime();

            int64_t timeAnnounce = lockmap.timeAnnounce;
            int64_t timeTerminate = lockmap.timeTerminate;
            if( !lockmap.timeline.empty() )
            {
                if( timeAnnounce <= 0 )
                {
                    timeAnnounce = lockmap.timeline.front().Time();
                }
                if( timeTerminate <= 0 )
                {
                    timeTerminate = lockmap.timeline.back().Time();
                }
            }
            const auto lockLen = timeTerminate - timeAnnounce;

            ImGui::BeginTooltip();
            switch( lockmap.type )
            {
            case LockType::Lockable:
                TextFocused( "Type:", "lockable" );
                break;
            case LockType::SharedLockable:
                TextFocused( "Type:", "shared lockable" );
                break;
            default:
                assert( false );
                break;
            }
            ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
            ImGui::Separator();
            TextFocused( ICON_FA_SHUFFLE " Appeared at", TimeToString( tinfo.firstTime ) );
            TextFocused( ICON_FA_SHUFFLE " Last event at", TimeToString( tinfo.lastTime ) );
            TextFocused( ICON_FA_SHUFFLE " Activity time:", TimeToString( activity ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of lock lifetime)", activity / double( lockLen ) * 100 );
            ImGui::Separator();
            TextFocused( "Announce time:", TimeToString( timeAnnounce ) );
            TextFocused( "Terminate time:", TimeToString( timeTerminate ) );
            TextFocused( "Lifetime:", TimeToString( lockLen ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%% of trace time)", lockLen / double( traceLen ) * 100 );
            ImGui::Separator();
            TextDisabledUnformatted( "Thread list:" );
            ImGui::Indent( ty );
            for( const auto& ti : lockmap.threads )
            {
                SmallColorBox( GetThreadColor( ti.thread, 0 ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( ti.thread ) );
            }
            ImGui::Unindent( ty );
            ImGui::Separator();
            TextFocused( "Lock events:", RealToString( lockmap.timeline.size() ) );
            ImGui::EndTooltip();

            if( IsMouseClicked( ImGuiMouseButton_Left ) )
            {
                m_lockInfoWindow = id;
            }
            if( IsMouseClicked( ImGuiMouseButton_Middle ) )
            {
                ZoomToRange( tinfo.firstTime, tinfo.lastTime );
            }
        }
    }
}

int View::DrawLocks( const TimelineContext& ctx, const std::vector<std::unique_ptr<LockDraw>>& lockDraw, uint64_t tid, int _offset, LockHighlight& highlight )
{
    const auto w = ctx.w;
    const auto ty = ctx.sty;
    const auto ostep = ty + 1;
    const auto& wpos = ctx.wpos;
    const auto hover = ctx.hover;
    const auto vStart = ctx.vStart;
    const auto pxns = ctx.pxns;

    auto draw = ImGui::GetWindowDrawList();

    const auto ty025 = round( ty * 0.25f );
    const auto ty05  = round( ty * 0.5f );

    const auto& lockMapData = m_worker.GetLockMap();
    const auto MinVisPx = GetScale() * MinVisSize;

    int cnt = 0;
    for( auto& _lock : lockDraw )
    {
        const auto& lock = *_lock;
        if( lock.data.empty() && !lock.forceDraw ) continue;

        auto it = lockMapData.find( lock.id );
        assert( it != lockMapData.end() );
        const auto& lockmap = *it->second;

        const auto& srcloc = m_worker.GetSourceLocation( lockmap.srcloc );
        const auto offset = _offset + ostep * cnt;
        if( lock.data.empty() )
        {
            draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x2288DD88 );
            draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x4488DD88 );
            DrawLockHeader( lock.id, lockmap, srcloc, hover, draw, wpos, w, ty, offset, lock.thread );
            cnt++;
            continue;
        }

        for( int pass = 0; pass < 3; pass++ )
        {
            for( auto& v : lock.data )
            {
                const int rank = v.state == LockEventState::WaitLock ? 2 : v.state == LockEventState::HasBlockingLock ? 1 : 0;
                if( rank != pass ) continue;
                const auto t0 = lockmap.timeline[ v.seg->evStart ].Time();
                const auto t1 = v.t1;
                const auto px0 = ( t0 - vStart ) * pxns;
                // The usual method of collapsing single small zones into zig-zags would be very bad here. Lock wait zones should
                // be easily visible without having to zoom in first. This sets a minimum width for any lock zone.
                const auto px1 = std::max( ( t1 - vStart ) * pxns, px0 + MinVisPx );

                bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ostep ) );
                if( itemHovered )
                {
                    if( IsMouseClicked( ImGuiMouseButton_Left ) )
                    {
                        m_lockInfoWindow = lock.id;
                    }
                    if( IsMouseClicked( ImGuiMouseButton_Middle ) )
                    {
                        ZoomToRange( t0, t1 );
                    }

                    if( v.num > 1 )
                    {
                        ImGui::BeginTooltip();
                        TextFocused( "Multiple lock events:", RealToString( v.num ) );
                        ImGui::EndTooltip();
                    }
                    else
                    {
                        const auto cursorTime = ( int64_t )( vStart + ( ImGui::GetMousePos().x - wpos.x ) / pxns );
                        const auto zoneBegin = lockmap.timeline.begin() + v.seg->evStart;
                        const auto zoneEnd = v.seg->nextEv == LockEvent::NoEvent ? lockmap.timeline.end() : lockmap.timeline.begin() + v.seg->nextEv;
                        auto evIt = std::upper_bound( zoneBegin, zoneEnd, cursorTime,
                            [] ( int64_t t, const LockEvent& e ) { return t < e.Time(); } );
                        const uint32_t cursorIdx = evIt != zoneBegin ? ( uint32_t )( evIt - lockmap.timeline.begin() - 1 ) : v.seg->evStart;
                        highlight.blocked = v.state == LockEventState::HasBlockingLock;
                        const auto hinfo = HolderAt( lockmap, cursorIdx );
                        if( !highlight.blocked )
                        {
                            highlight.id = lock.id;
                            highlight.begin = t0;
                            highlight.end = t1;
                            highlight.thread = lock.thread;
                            highlight.blocked = false;
                        }
                        else if( hinfo.count > 0 )
                        {
                            const auto h = hinfo.holder;
                            const auto& log = lockmap.holderChanges;
                            auto cit = std::upper_bound( log.begin(), log.end(), cursorIdx, [] ( uint32_t val, const LockHolderChange& e ) { return val < e.idx; } );
                            assert( cit != log.begin() );
                            auto b = std::prev( cit );
                            while( b != log.begin() )
                            {
                                auto prev = std::prev( b );
                                if( prev->holder != h || prev->count == 0 ) break;
                                b = prev;
                            }
                            highlight.begin = lockmap.timeline[b->idx].Time();

                            auto e2 = cit;
                            while( e2 != log.end() && e2->holder == h && e2->count != 0 ) e2++;
                            if( e2 != log.end() )
                            {
                                highlight.id = lock.id;
                                highlight.end = lockmap.timeline[e2->idx].Time();
                                highlight.thread = lock.thread;
                            }
                        }
                        else if( v.seg->flags & LockEventFlags::SharedHolding )
                        {
                            const auto& segs = lockmap.threads[lock.thread].segments;
                            auto sit = segs.begin() + ( v.seg - segs.data() );
                            while( sit != segs.begin() && ( ( sit - 1 )->flags & LockEventFlags::SharedHolding ) != 0 && !SharedHoldEnded( lockmap, lock.thread, *( sit - 1 ) ) ) --sit;
                            auto e1 = sit;
                            do { ++e1; } while( e1 != segs.end() && ( e1->flags & LockEventFlags::SharedHolding ) != 0 && !SharedHoldEnded( lockmap, lock.thread, *( e1 - 1 ) ) );
                            const auto last = e1 - 1;
                            if( last->nextEv != LockEvent::NoEvent )
                            {
                                highlight.id = lock.id;
                                highlight.begin = lockmap.timeline[sit->evStart].Time();
                                highlight.end = lockmap.timeline[last->nextEv].Time();
                                highlight.thread = lock.thread;
                            }
                        }

                        ImGui::BeginTooltip();
                        if( lockmap.customName.Active() )
                        {
                            ImGui::Text( "Lock #%" PRIu32 ": %s", lock.id, m_worker.GetString( lockmap.customName ) );
                        }
                        else
                        {
                            ImGui::Text( "Lock #%" PRIu32 ": %s", lock.id, m_worker.GetString( srcloc.function ) );
                        }
                        ImGui::Separator();
                        ImGui::TextUnformatted( LocationToString( m_worker.GetString( srcloc.file ), srcloc.line ) );
                        TextFocused( "Time:", TimeToString( t1 - t0 ) );
                        ImGui::Separator();

                        int16_t markloc = 0;
                        {
                            const auto& marks = lockmap.threads[lock.thread].marks;
                            auto mit = std::upper_bound( marks.begin(), marks.end(), cursorIdx );
                            if( mit != marks.begin() )
                            {
                                markloc = lockmap.timeline[*( mit - 1 )].SrcLoc();
                            }
                        }
                        if( markloc != 0 )
                        {
                            const auto& marklocdata = m_worker.GetSourceLocation( markloc );
                            ImGui::TextUnformatted( "Lock event location:" );
                            ImGui::TextUnformatted( m_worker.GetString( marklocdata.function ) );
                            ImGui::TextUnformatted( LocationToString( m_worker.GetString( marklocdata.file ), marklocdata.line ) );
                            ImGui::Separator();
                        }

                        if( lockmap.type == LockType::Lockable )
                        {
                            switch( ( LockEventState::Type )v.state )
                            {
                            case LockEventState::HasLock:
                                if( hinfo.count == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadName( tid ), (int)hinfo.count );
                                }
                                if( ( v.seg->flags & ( LockEventFlags::LockHolding | LockEventFlags::Waiting ) ) == ( LockEventFlags::LockHolding | LockEventFlags::Waiting ) )
                                {
                                    ImGui::TextUnformatted( "Recursive lock acquire in thread." );
                                }
                                break;
                            case LockEventState::HasBlockingLock:
                            {
                                const auto nBlocked = CountRoleAt( lockmap, cursorIdx, LockEventFlags::Waiting );
                                if( hinfo.count == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%zu):", m_worker.GetThreadName( tid ), nBlocked );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%zu):", m_worker.GetThreadName( tid ), (int)hinfo.count, nBlocked );
                                }
                                ImGui::Indent( ty );
                                ForEachRoleAt( lockmap, cursorIdx, LockEventFlags::Waiting, [this, &lockmap] ( uint16_t slot ) {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[slot].thread ) );
                                } );
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockEventState::WaitLock:
                            {
                                if( hinfo.count > 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other thread:", m_worker.GetThreadName( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadName( tid ) );
                                }
                                ImGui::Indent( ty );
                                ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[hinfo.holder].thread ) );
                                ImGui::Unindent( ty );
                                break;
                            }
                            default:
                                assert( false );
                                break;
                            }
                        }
                        else
                        {
                            const auto idx = cursorIdx;
                            switch( ( LockEventState::Type )v.state )
                            {
                            case LockEventState::HasLock:
                            {
                                const auto nShared = CountRoleAt( lockmap, idx, LockEventFlags::SharedHolding );
                                if( nShared == 0 )
                                {
                                    if( hinfo.count == 1 )
                                        ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                    else
                                        ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadName( tid ), ( int )hinfo.count );
                                }
                                else if( nShared == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%zu):", nShared - 1 );
                                    ImGui::Indent( ty );
                                    ForEachRoleAt( lockmap, idx, LockEventFlags::SharedHolding, [this, &lockmap, slot = lock.thread] ( uint16_t s ) {
                                        if( s != slot ) ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[s].thread ) );
                                    } );
                                    ImGui::Unindent( ty );
                                }
                                break;
                            }
                            case LockEventState::HasBlockingLock:
                            {
                                const auto nShared = CountRoleAt( lockmap, idx, LockEventFlags::SharedHolding );
                                const auto nBlocked = CountRoleAt( lockmap, idx, LockEventFlags::Waiting ) + CountRoleAt( lockmap, idx, LockEventFlags::SharedWaiting );
                                if( nShared == 0 )
                                {
                                    if( hinfo.count == 1 )
                                        ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%zu):", m_worker.GetThreadName( tid ), nBlocked );
                                    else
                                        ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%zu):", m_worker.GetThreadName( tid ), ( int )hinfo.count, nBlocked );
                                }
                                else if( nShared == 1 )
                                {
                                    ImGui::Text( "Thread \"%s\" has a sole shared lock. Blocked threads (%zu):", m_worker.GetThreadName( tid ), nBlocked );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" has shared lock.", m_worker.GetThreadName( tid ) );
                                    ImGui::Text( "Threads sharing the lock (%zu):", nShared - 1 );
                                    ImGui::Indent( ty );
                                    ForEachRoleAt( lockmap, idx, LockEventFlags::SharedHolding, [this, &lockmap, slot = lock.thread] ( uint16_t s ) {
                                        if( s != slot ) ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[s].thread ) );
                                    } );
                                    ImGui::Unindent( ty );
                                    ImGui::Text( "Blocked threads (%zu):", nBlocked );
                                }

                                ImGui::Indent( ty );
                                ForEachRoleAt( lockmap, idx, LockEventFlags::Waiting, [this, &lockmap] ( uint16_t s ) {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[s].thread ) );
                                } );
                                ForEachRoleAt( lockmap, idx, LockEventFlags::SharedWaiting, [this, &lockmap] ( uint16_t s ) {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[s].thread ) );
                                } );
                                ImGui::Unindent( ty );
                                break;
                            }
                            case LockEventState::WaitLock:
                            {
                                const auto nShared = CountRoleAt( lockmap, idx, LockEventFlags::SharedHolding );
                                if( hinfo.count != 0 || nShared != 0 )
                                {
                                    ImGui::Text( "Thread \"%s\" is blocked by other threads (%zu):", m_worker.GetThreadName( tid ), ( size_t )( hinfo.count != 0 ? 1 : 0 ) + nShared );
                                }
                                else
                                {
                                    ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadName( tid ) );
                                }
                                ImGui::Indent( ty );
                                if( hinfo.count != 0 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[hinfo.holder].thread ) );
                                }
                                ForEachRoleAt( lockmap, idx, LockEventFlags::SharedHolding, [this, &lockmap] ( uint16_t s ) {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threads[s].thread ) );
                                } );
                                ImGui::Unindent( ty );
                                break;
                            }
                            default:
                                assert( false );
                                break;
                            }
                        }
                        ImGui::EndTooltip();
                    }
                }

                const auto cfilled  = v.state == LockEventState::HasLock ? 0xFF228A22 : ( v.state == LockEventState::HasBlockingLock ? 0xFF228A8A : 0xFF2222BD );
                draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), cfilled );
                if( m_lockHighlight.thread != lock.thread && ( v.state == LockEventState::HasBlockingLock ) != m_lockHighlight.blocked && v.seg->nextEv != LockEvent::NoEvent && m_lockHighlight.id == int64_t( lock.id ) && m_lockHighlight.begin <= t1 && m_lockHighlight.end >= t0 )
                {
                    const auto t = uint8_t( ( sin( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count() * 0.01 ) * 0.5 + 0.5 ) * 255 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), 0x00FFFFFF | ( t << 24 ), 0.f, 2.f );
                    m_wasActive.store( true, std::memory_order_release );
                }
                else if( v.num == 1 )
                {
                    const auto coutline = v.state == LockEventState::HasLock ? 0xFF3BA33B : ( v.state == LockEventState::HasBlockingLock ? 0xFF3BA3A3 : 0xFF3B3BD6 );
                    draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), coutline );
                }
                else
                {
                    DrawZigZag( draw, wpos + ImVec2( 0, offset + ty05 ), px0, px1, ty025, DarkenColor( cfilled ) );
                }
            }
        }

        if( m_lockInfoWindow == lock.id )
        {
            draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x2288DD88 );
            draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x4488DD88 );
        }
        else if( m_lockHoverHighlight == lock.id )
        {
            draw->AddRectFilled( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x228888DD );
            draw->AddRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty ), 0x448888DD );
        }
        DrawLockHeader( lock.id, lockmap, srcloc, hover, draw, wpos, w, ty, offset, lock.thread );

        cnt++;
    }

    return cnt;
}

void View::DrawLockInfoWindow()
{
    bool visible = true;
    ImGui::Begin( "Lock info", &visible, ImGuiWindowFlags_AlwaysAutoResize );
    if( !ImGui::GetCurrentWindowRead()->SkipItems )
    {
        auto it = m_worker.GetLockMap().find( m_lockInfoWindow );
        assert( it != m_worker.GetLockMap().end() );
        const auto& lock = *it->second;
        const auto& srcloc = m_worker.GetSourceLocation( lock.srcloc );
        auto fileName = m_worker.GetString( srcloc.file );

        int64_t timeAnnounce = lock.timeAnnounce;
        int64_t timeTerminate = lock.timeTerminate;
        if( !lock.timeline.empty() )
        {
            if( timeAnnounce <= 0 )
            {
                timeAnnounce = lock.timeline.front().Time();
            }
            if( timeTerminate <= 0 )
            {
                timeTerminate = lock.timeline.back().Time();
            }
        }

        ImGui::PushFont( g_fonts.normal, FontBig );
        if( lock.customName.Active() )
        {
            ImGui::Text( "Lock #%" PRIu32 ": %s", m_lockInfoWindow, m_worker.GetString( lock.customName ) );
        }
        else
        {
            ImGui::Text( "Lock #%" PRIu32 ": %s", m_lockInfoWindow, m_worker.GetString( srcloc.function ) );
        }
        ImGui::PopFont();
        if( lock.customName.Active() )
        {
            TextFocused( "Name:", m_worker.GetString( srcloc.function ) );
        }
        TextDisabledUnformatted( "Location:" );
        if( m_lockInfoAnim.Match( m_lockInfoWindow ) )
        {
            const auto time = m_lockInfoAnim.Time();
            const auto indentVal = sin( time * 60.f ) * 10.f * time;
            ImGui::SameLine( 0, ImGui::GetStyle().ItemSpacing.x + indentVal );
        }
        else
        {
            ImGui::SameLine();
        }
        ImGui::TextUnformatted( LocationToString( fileName, srcloc.line ) );
        if( ImGui::IsItemHovered() )
        {
            DrawSourceTooltip( fileName, srcloc.line, srcloc.line );
            if( ImGui::IsItemClicked( 1 ) )
            {
                if( SourceFileValid( fileName, m_worker.GetCaptureTime(), *this, m_worker ) )
                {
                    ViewSource( fileName, srcloc.line );
                }
                else
                {
                    m_lockInfoAnim.Enable( m_lockInfoWindow, 0.5f );
                }
            }
        }
        ImGui::Separator();

        switch( lock.type )
        {
        case LockType::Lockable:
            TextFocused( "Type:", "lockable" );
            break;
        case LockType::SharedLockable:
            TextFocused( "Type:", "shared lockable" );
            break;
        default:
            assert( false );
            break;
        }
        TextFocused( "Lock events:", RealToString( lock.timeline.size() ) );
        ImGui::Separator();

        const auto announce = timeAnnounce;
        const auto terminate = timeTerminate;
        const auto lifetime = timeTerminate - timeAnnounce;
        const auto traceLen = m_worker.GetLastTime();

        TextFocused( "Announce time:", TimeToString( announce ) );
        TextFocused( "Terminate time:", TimeToString( terminate ) );
        TextFocused( "Lifetime:", TimeToString( lifetime ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of trace time)", lifetime / double( traceLen ) * 100 );
        ImGui::Separator();

        TextFocused( "Lock hold time:", TimeToString( lock.holdTotal ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of lock lifetime)", lock.holdTotal / float( lifetime ) * 100.f );
        TextFocused( "Lock wait time:", TimeToString( lock.waitTotalAgg ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of lock lifetime)", lock.waitTotalAgg / float( lifetime ) * 100.f );
        TextFocused( "Max waiting threads:", RealToString( lock.maxWaiting ) );
        ImGui::Separator();

        const auto threadList = ImGui::TreeNode( "Thread list" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", lock.threads.size() );
        if( threadList )
        {
            for( const auto& ti : lock.threads )
            {
                SmallColorBox( GetThreadColor( ti.thread, 0 ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( ti.thread ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( ti.thread ) );
            }
            ImGui::TreePop();
        }
    }
    ImGui::End();
    if( !visible ) m_lockInfoWindow = InvalidId;
}

}
