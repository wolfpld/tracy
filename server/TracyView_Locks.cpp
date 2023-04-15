#include <inttypes.h>

#include "TracyColor.hpp"
#include "TracyFilesystem.hpp"
#include "TracyImGui.hpp"
#include "TracyLockHelpers.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineDraw.hpp"
#include "TracyView.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;

void View::DrawLockHeader( uint32_t id, const LockMap& lockmap, const SourceLocation& srcloc, bool hover, ImDrawList* draw, const ImVec2& wpos, float w, float ty, float offset, uint8_t tid )
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
    ImGui::PushFont( m_smallFont );
    DrawTextContrast( draw, wpos + ImVec2( 0, offset ), 0xFF8888FF, buf );
    ImGui::PopFont();
    if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( w, offset + ty + 1 ) ) )
    {
        m_lockHoverHighlight = id;

        if( ImGui::IsMouseHoveringRect( wpos + ImVec2( 0, offset ), wpos + ImVec2( ty + ImGui::CalcTextSize( buf ).x, offset + ty + 1 ) ) )
        {
            const auto& range = lockmap.range[tid];
            const auto activity = range.end - range.start;
            const auto traceLen = m_worker.GetLastTime();

            int64_t timeAnnounce = lockmap.timeAnnounce;
            int64_t timeTerminate = lockmap.timeTerminate;
            if( !lockmap.timeline.empty() )
            {
                if( timeAnnounce <= 0 )
                {
                    timeAnnounce = lockmap.timeline.front().ptr->Time();
                }
                if( timeTerminate <= 0 )
                {
                    timeTerminate = lockmap.timeline.back().ptr->Time();
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
            TextFocused( ICON_FA_SHUFFLE " Appeared at", TimeToString( range.start ) );
            TextFocused( ICON_FA_SHUFFLE " Last event at", TimeToString( range.end ) );
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
            for( const auto& t : lockmap.threadList )
            {
                SmallColorBox( GetThreadColor( t, 0 ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( t ) );
            }
            ImGui::Unindent( ty );
            ImGui::Separator();
            TextFocused( "Lock events:", RealToString( lockmap.timeline.size() ) );
            ImGui::EndTooltip();

            if( IsMouseClicked( 0 ) )
            {
                m_lockInfoWindow = id;
            }
            if( IsMouseClicked( 2 ) )
            {
                ZoomToRange( range.start, range.end );
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

        for( auto& v : lock.data )
        {
            const auto& le = *v.ptr;
            const auto t0 = le.ptr->Time();
            const auto t1 = v.t1.Val();
            const auto px0 = ( t0 - vStart ) * pxns;
            // The usual method of collapsing single small zones into zig-zags would be very bad here. Lock wait zones should
            // be easily visible without having to zoom in first. This sets a minimum width for any lock zone.
            const auto px1 = std::max( ( t1 - vStart ) * pxns, px0 + MinVisPx );

            bool itemHovered = hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( px0, offset ), wpos + ImVec2( px1, offset + ostep ) );
            if( itemHovered )
            {
                if( IsMouseClicked( 0 ) )
                {
                    m_lockInfoWindow = lock.id;
                }
                if( IsMouseClicked( 2 ) )
                {
                    ZoomToRange( t0, t1 );
                }

                if( v.condensed > 1 )
                {
                    ImGui::BeginTooltip();
                    TextFocused( "Multiple lock events:", RealToString( v.condensed ) );
                    ImGui::EndTooltip();
                }
                else
                {
                    highlight.blocked = v.state == LockState::HasBlockingLock;
                    if( !highlight.blocked )
                    {
                        highlight.id = lock.id;
                        highlight.begin = t0;
                        highlight.end = t1;
                        highlight.thread = lock.thread;
                        highlight.blocked = false;
                    }
                    else
                    {
                        const auto& tl = lockmap.timeline;
                        auto b = v.ptr.get();
                        while( b != tl.begin() )
                        {
                            if( b->lockingThread != v.ptr->lockingThread )
                            {
                                break;
                            }
                            b--;
                        }
                        b++;
                        highlight.begin = b->ptr->Time();

                        auto e = v.next.get();
                        while( e != tl.end() )
                        {
                            if( e->lockingThread != v.next->lockingThread )
                            {
                                highlight.id = lock.id;
                                highlight.end = e->ptr->Time();
                                highlight.thread = lock.thread;
                                break;
                            }
                            e++;
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

                    const auto threadBit = GetThreadBit( lock.thread );
                    int16_t markloc = 0;
                    auto it = v.ptr.get();
                    for(;;)
                    {
                        if( it->ptr->thread == lock.thread )
                        {
                            if( ( it->lockingThread == lock.thread || IsThreadWaiting( it->waitList, threadBit ) ) && it->ptr->SrcLoc() != 0 )
                            {
                                markloc = it->ptr->SrcLoc();
                                break;
                            }
                        }
                        if( it == lockmap.timeline.begin() ) break;
                        --it;
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
                        switch( v.state )
                        {
                        case LockState::HasLock:
                            if( v.ptr->lockCount == 1 )
                            {
                                ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                            }
                            else
                            {
                                ImGui::Text( "Thread \"%s\" has %i locks. No other threads are waiting.", m_worker.GetThreadName( tid ), v.ptr->lockCount );
                            }
                            if( v.ptr->waitList != 0 )
                            {
                                assert( !AreOtherWaiting( v.next->waitList, threadBit ) );
                                ImGui::TextUnformatted( "Recursive lock acquire in thread." );
                            }
                            break;
                        case LockState::HasBlockingLock:
                        {
                            if( v.ptr->lockCount == 1 )
                            {
                                ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), TracyCountBits( v.ptr->waitList ) );
                            }
                            else
                            {
                                ImGui::Text( "Thread \"%s\" has %i locks. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), v.ptr->lockCount, TracyCountBits( v.ptr->waitList ) );
                            }
                            auto waitList = v.ptr->waitList;
                            int t = 0;
                            ImGui::Indent( ty );
                            while( waitList != 0 )
                            {
                                if( waitList & 0x1 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                }
                                waitList >>= 1;
                                t++;
                            }
                            ImGui::Unindent( ty );
                            break;
                        }
                        case LockState::WaitLock:
                        {
                            if( v.ptr->lockCount > 0 )
                            {
                                ImGui::Text( "Thread \"%s\" is blocked by other thread:", m_worker.GetThreadName( tid ) );
                            }
                            else
                            {
                                ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadName( tid ) );
                            }
                            ImGui::Indent( ty );
                            ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[v.ptr->lockingThread] ) );
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
                        const auto ptr = (const LockEventShared*)(const LockEvent*)v.ptr->ptr;
                        switch( v.state )
                        {
                        case LockState::HasLock:
                            assert( v.ptr->waitList == 0 );
                            if( ptr->sharedList == 0 )
                            {
                                assert( v.ptr->lockCount == 1 );
                                ImGui::Text( "Thread \"%s\" has lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                            }
                            else if( TracyCountBits( ptr->sharedList ) == 1 )
                            {
                                ImGui::Text( "Thread \"%s\" has a sole shared lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                            }
                            else
                            {
                                ImGui::Text( "Thread \"%s\" has shared lock. No other threads are waiting.", m_worker.GetThreadName( tid ) );
                                ImGui::Text( "Threads sharing the lock (%" PRIu64 "):", TracyCountBits( ptr->sharedList ) - 1 );
                                auto sharedList = ptr->sharedList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( sharedList != 0 )
                                {
                                    if( sharedList & 0x1 && t != lock.thread )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                    }
                                    sharedList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                            }
                            break;
                        case LockState::HasBlockingLock:
                        {
                            if( ptr->sharedList == 0 )
                            {
                                assert( v.ptr->lockCount == 1 );
                                ImGui::Text( "Thread \"%s\" has lock. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), TracyCountBits( v.ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                            }
                            else if( TracyCountBits( ptr->sharedList ) == 1 )
                            {
                                ImGui::Text( "Thread \"%s\" has a sole shared lock. Blocked threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), TracyCountBits( v.ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                            }
                            else
                            {
                                ImGui::Text( "Thread \"%s\" has shared lock.", m_worker.GetThreadName( tid ) );
                                ImGui::Text( "Threads sharing the lock (%" PRIu64 "):", TracyCountBits( ptr->sharedList ) - 1 );
                                auto sharedList = ptr->sharedList;
                                int t = 0;
                                ImGui::Indent( ty );
                                while( sharedList != 0 )
                                {
                                    if( sharedList & 0x1 && t != lock.thread )
                                    {
                                        ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                    }
                                    sharedList >>= 1;
                                    t++;
                                }
                                ImGui::Unindent( ty );
                                ImGui::Text( "Blocked threads (%" PRIu64 "):", TracyCountBits( v.ptr->waitList ) + TracyCountBits( ptr->waitShared ) );
                            }

                            auto waitList = v.ptr->waitList;
                            int t = 0;
                            ImGui::Indent( ty );
                            while( waitList != 0 )
                            {
                                if( waitList & 0x1 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                }
                                waitList >>= 1;
                                t++;
                            }
                            auto waitShared = ptr->waitShared;
                            t = 0;
                            while( waitShared != 0 )
                            {
                                if( waitShared & 0x1 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                }
                                waitShared >>= 1;
                                t++;
                            }
                            ImGui::Unindent( ty );
                            break;
                        }
                        case LockState::WaitLock:
                        {
                            assert( v.ptr->lockCount == 0 || v.ptr->lockCount == 1 );
                            if( v.ptr->lockCount != 0 || ptr->sharedList != 0 )
                            {
                                ImGui::Text( "Thread \"%s\" is blocked by other threads (%" PRIu64 "):", m_worker.GetThreadName( tid ), v.ptr->lockCount + TracyCountBits( ptr->sharedList ) );
                            }
                            else
                            {
                                ImGui::Text( "Thread \"%s\" waits to obtain lock after release by thread:", m_worker.GetThreadName( tid ) );
                            }
                            ImGui::Indent( ty );
                            if( v.ptr->lockCount != 0 )
                            {
                                ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[v.ptr->lockingThread] ) );
                            }
                            auto sharedList = ptr->sharedList;
                            int t = 0;
                            while( sharedList != 0 )
                            {
                                if( sharedList & 0x1 )
                                {
                                    ImGui::Text( "\"%s\"", m_worker.GetThreadName( lockmap.threadList[t] ) );
                                }
                                sharedList >>= 1;
                                t++;
                            }
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

            const auto cfilled  = v.state == LockState::HasLock ? 0xFF228A22 : ( v.state == LockState::HasBlockingLock ? 0xFF228A8A : 0xFF2222BD );
            draw->AddRectFilled( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), cfilled );
            if( m_lockHighlight.thread != lock.thread && ( v.state == LockState::HasBlockingLock ) != m_lockHighlight.blocked && v.next != lockmap.timeline.end() && m_lockHighlight.id == int64_t( lock.id ) && m_lockHighlight.begin <= v.ptr->ptr->Time() && m_lockHighlight.end >= v.next->ptr->Time() )
            {
                const auto t = uint8_t( ( sin( std::chrono::duration_cast<std::chrono::milliseconds>( std::chrono::system_clock::now().time_since_epoch() ).count() * 0.01 ) * 0.5 + 0.5 ) * 255 );
                draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), 0x00FFFFFF | ( t << 24 ), 0.f, -1, 2.f );
                m_wasActive = true;
            }
            else if( v.condensed == 0 )
            {
                const auto coutline = v.state == LockState::HasLock ? 0xFF3BA33B : ( v.state == LockState::HasBlockingLock ? 0xFF3BA3A3 : 0xFF3B3BD6 );
                draw->AddRect( wpos + ImVec2( std::max( px0, -10.0 ), offset ), wpos + ImVec2( std::min( px1, double( w + 10 ) ), offset + ty ), coutline );
            }
            else if( v.condensed > 1 )
            {
                DrawZigZag( draw, wpos + ImVec2( 0, offset + ty05 ), px0, px1, ty025, DarkenColor( cfilled ) );
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
                timeAnnounce = lock.timeline.front().ptr->Time();
            }
            if( timeTerminate <= 0 )
            {
                timeTerminate = lock.timeline.back().ptr->Time();
            }
        }

        bool waitState = false;
        bool holdState = false;
        int64_t waitStartTime = 0;
        int64_t holdStartTime = 0;
        int64_t waitTotalTime = 0;
        int64_t holdTotalTime = 0;
        uint32_t maxWaitingThreads = 0;
        for( auto& v : lock.timeline )
        {
            if( holdState )
            {
                if( v.lockCount == 0 )
                {
                    holdTotalTime += v.ptr->Time() - holdStartTime;
                    holdState = false;
                }
            }
            else
            {
                if( v.lockCount != 0 )
                {
                    holdStartTime = v.ptr->Time();
                    holdState = true;
                }
            }
            if( waitState )
            {
                if( v.waitList == 0 )
                {
                    waitTotalTime += v.ptr->Time() - waitStartTime;
                    waitState = false;
                }
                else
                {
                    maxWaitingThreads = std::max<uint32_t>( maxWaitingThreads, TracyCountBits( v.waitList ) );
                }
            }
            else
            {
                if( v.waitList != 0 )
                {
                    waitStartTime = v.ptr->Time();
                    waitState = true;
                    maxWaitingThreads = std::max<uint32_t>( maxWaitingThreads, TracyCountBits( v.waitList ) );
                }
            }
        }

        ImGui::PushFont( m_bigFont );
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
            DrawSourceTooltip( fileName, srcloc.line );
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

        TextFocused( "Lock hold time:", TimeToString( holdTotalTime ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of lock lifetime)", holdTotalTime / float( lifetime ) * 100.f );
        TextFocused( "Lock wait time:", TimeToString( waitTotalTime ) );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%.2f%% of lock lifetime)", waitTotalTime / float( lifetime ) * 100.f );
        TextFocused( "Max waiting threads:", RealToString( maxWaitingThreads ) );
        ImGui::Separator();

        const auto threadList = ImGui::TreeNode( "Thread list" );
        ImGui::SameLine();
        ImGui::TextDisabled( "(%zu)", lock.threadList.size() );
        if( threadList )
        {
            for( const auto& t : lock.threadList )
            {
                SmallColorBox( GetThreadColor( t, 0 ) );
                ImGui::SameLine();
                ImGui::TextUnformatted( m_worker.GetThreadName( t ) );
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s)", RealToString( t ) );
            }
            ImGui::TreePop();
        }
    }
    ImGui::End();
    if( !visible ) m_lockInfoWindow = InvalidId;
}

}
