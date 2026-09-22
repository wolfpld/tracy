#include <algorithm>
#include <limits>

#include "TracyColor.hpp"
#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineItemThread.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

constexpr float MinVisSize = 3;
constexpr float MinCtxSize = 4;

static int64_t GetThreadLockWaitTime( const Worker& worker, uint64_t tid, size_t& lockCnt, uint64_t& waitCount )
{
    int64_t waitTotal = 0;
    lockCnt = 0;
    waitCount = 0;
    for( const auto& lock : worker.GetLockMap() )
    {
        const auto& lockmap = *lock.second;
        if( !lockmap.valid ) continue;
        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;
        lockCnt++;
        const auto& ti = lockmap.threads[it->second];
        waitTotal += ti.waitTotal;
        waitCount += ti.waitCount;
    }
    return waitTotal;
}


TimelineItemThread::TimelineItemThread( View& view, Worker& worker, const ThreadData* thread )
    : TimelineItem( view, worker, thread, true )
    , m_thread( thread )
    , m_ghost( false )
{
    auto name = worker.GetThreadName( thread->id );
    if( strncmp( name, "Tracy ", 6 ) == 0 )
    {
        m_showFull = false;
    }
}

bool TimelineItemThread::IsEmpty() const
{
    auto& crash = m_worker.GetCrashEvent();
    return crash.thread != m_thread->id &&
        m_thread->timeline.empty() &&
        m_thread->messages.empty() &&
        !m_thread->inLocks &&
        ( !m_worker.AreGhostZonesReady() || m_thread->ghostZones.empty() );
}

uint32_t TimelineItemThread::HeaderColor() const
{
    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread == m_thread->id ) return 0xFF2222FF;
    if( m_thread->isFiber ) return 0xFF88FF88;
    return 0xFFFFFFFF;
}

uint32_t TimelineItemThread::HeaderColorInactive() const
{
    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread == m_thread->id ) return 0xFF111188;
    if( m_thread->isFiber ) return 0xFF448844;
    return 0xFF888888;
}

uint32_t TimelineItemThread::HeaderLineColor() const
{
    return 0x33FFFFFF;
}

const char* TimelineItemThread::HeaderLabel() const
{
    return m_worker.GetThreadName( m_thread->id );
}

int64_t TimelineItemThread::RangeBegin() const
{
    int64_t first = std::numeric_limits<int64_t>::max();
    const auto ctx = m_worker.GetContextSwitchData( m_thread->id );
    if( ctx && !ctx->v.empty() )
    {
        first = ctx->v.begin()->Start();
    }
    if( !m_thread->timeline.empty() )
    {
        if( m_thread->timeline.is_magic() )
        {
            auto& tl = *((Vector<ZoneEvent>*)&m_thread->timeline);
            first = std::min( first, tl.front().Start() );
        }
        else
        {
            first = std::min( first, m_thread->timeline.front()->Start() );
        }
    }
    if( !m_thread->messages.empty() )
    {
        first = std::min( first, m_thread->messages.front()->time );
    }
    for( const auto& lock : m_worker.GetLockMap() )
    {
        const auto& lockmap = *lock.second;
        if( !lockmap.valid ) continue;
        auto it = lockmap.threadMap.find( m_thread->id );
        if( it == lockmap.threadMap.end() ) continue;
        const auto& ti = lockmap.threads[it->second];
        if( ti.firstTime < first ) first = ti.firstTime;
    }
    return first;
}

int64_t TimelineItemThread::RangeEnd() const
{
    int64_t last = -1;
    const auto ctx = m_worker.GetContextSwitchData( m_thread->id );
    if( ctx && !ctx->v.empty() )
    {
        const auto& back = ctx->v.back();
        last = back.IsEndValid() ? back.End() : back.Start();
    }
    if( !m_thread->timeline.empty() )
    {
        if( m_thread->timeline.is_magic() )
        {
            auto& tl = *((Vector<ZoneEvent>*)&m_thread->timeline);
            last = std::max( last, m_worker.GetZoneEnd( tl.back() ) );
        }
        else
        {
            last = std::max( last, m_worker.GetZoneEnd( *m_thread->timeline.back() ) );
        }
    }
    if( !m_thread->messages.empty() )
    {
        last = std::max( last, m_thread->messages.back()->time );
    }
    for( const auto& lock : m_worker.GetLockMap() )
    {
        const auto& lockmap = *lock.second;
        if( !lockmap.valid ) continue;
        auto it = lockmap.threadMap.find( m_thread->id );
        if( it == lockmap.threadMap.end() ) continue;
        const auto& ti = lockmap.threads[it->second];
        if( ti.lastTime > last ) last = ti.lastTime;
    }
    return last;
}

void TimelineItemThread::HeaderTooltip( const char* label ) const
{
    m_view.HighlightThread( m_thread->id );

    ImGui::BeginTooltip();
    SmallColorBox( GetThreadColor( m_thread->id, 0, m_view.GetViewData().dynamicColors ) );
    ImGui::SameLine();
    ImGui::TextUnformatted( m_worker.GetThreadName( m_thread->id ) );
    ImGui::SameLine();
    ImGui::TextDisabled( "(%s)", RealToString( m_thread->id ) );
    auto& crash = m_worker.GetCrashEvent();
    if( crash.thread == m_thread->id )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 1.f, 0.2f, 0.2f, 1.f ), ICON_FA_SKULL " Crashed" );
    }
    if( m_thread->isFiber )
    {
        ImGui::SameLine();
        TextColoredUnformatted( ImVec4( 0.2f, 0.6f, 0.2f, 1.f ), "Fiber" );
    }

    m_view.DrawDeadlockDetail( m_thread->id, View::AnyLock );

    const auto ctx = m_worker.GetContextSwitchData( m_thread->id );
    const auto first = RangeBegin();
    const auto last = RangeEnd();

    ImGui::Separator();

    size_t lockCnt = 0;
    uint64_t lockWaitCount = 0;
    const int64_t lockWaitTime = GetThreadLockWaitTime( m_worker, m_thread->id, lockCnt, lockWaitCount );

    if( last >= 0 )
    {
        const auto lifetime = last - first;
        const auto traceLen = m_worker.GetLastTime() - m_worker.GetFirstTime();

        TextFocused( "Appeared at", TimeToString( first ) );
        TextFocused( "Last event at", TimeToString( last ) );
        TextFocused( "Lifetime:", TimeToString( lifetime ) );
        ImGui::SameLine();
        char buf[64];
        PrintStringPercent( buf, lifetime / double( traceLen ) * 100 );
        TextDisabledUnformatted( buf );

        if( ctx )
        {
            TextFocused( "Time in running state:", TimeToString( ctx->runningTime ) );
            ImGui::SameLine();
            PrintStringPercent( buf, ctx->runningTime / double( lifetime ) * 100 );
            TextDisabledUnformatted( buf );
        }
        if( lockCnt != 0 || lockWaitTime > 0 )
        {
            TextFocused( "Lock wait time:", TimeToString( lockWaitTime ) );
            ImGui::SameLine();
            PrintStringPercent( buf, lockWaitTime / double( lifetime ) * 100 );
            TextDisabledUnformatted( buf );
            if( lockWaitCount != 0 )
            {
                ImGui::SameLine();
                ImGui::TextDisabled( "(%s waits)", RealToString( lockWaitCount ) );
            }
        }
    }

    ImGui::Separator();
    if( !m_thread->timeline.empty() )
    {
        TextFocused( "Zone count:", RealToString( m_thread->count ) );
        TextFocused( "Top-level zones:", RealToString( m_thread->timeline.size() ) );
    }
    if( !m_thread->messages.empty() )
    {
        TextFocused( "Messages:", RealToString( m_thread->messages.size() ) );
    }
    if( lockCnt != 0 )
    {
        TextFocused( "Locks:", RealToString( lockCnt ) );
    }
    if( ctx )
    {
        TextFocused( "Running state regions:", RealToString( ctx->v.size() ) );
    }
    if( !m_thread->samples.empty() )
    {
        TextFocused( "Call stack samples:", RealToString( m_thread->samples.size() ) );
        if( m_thread->kernelSampleCnt != 0 )
        {
            TextFocused( "Kernel samples:", RealToString( m_thread->kernelSampleCnt ) );
            ImGui::SameLine();
            ImGui::TextDisabled( "(%.2f%%)", 100.f * m_thread->kernelSampleCnt / m_thread->samples.size() );
        }
    }
    ImGui::EndTooltip();
}

void TimelineItemThread::HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth )
{
    m_view.DrawThreadMessagesList( ctx, m_msgDraw, offset, m_thread->id );

    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();
    auto px = 1.5f * ty + labelWidth;

    if( m_worker.IsDeadlockedThread( m_thread->id ) )
    {
        draw->AddText( ctx.wpos + ImVec2( px, offset ), 0xFF2222FF, ICON_FA_ARROWS_SPIN );
        px += ImGui::GetStyle().ItemSpacing.x + ImGui::CalcTextSize( ICON_FA_ARROWS_SPIN ).x;
    }

    const bool hasGhostZones = m_worker.AreGhostZonesReady() && !m_thread->ghostZones.empty();
    if( hasGhostZones && !m_thread->timeline.empty() )
    {
        const auto color = m_ghost ? 0xFFAA9999 : 0x88AA7777;
        draw->AddText( ctx.wpos + ImVec2( px, offset ), color, ICON_FA_GHOST );
        float ghostSz = ImGui::CalcTextSize( ICON_FA_GHOST ).x;

        if( ctx.hover && ImGui::IsMouseHoveringRect( ctx.wpos + ImVec2( px, offset ), ctx.wpos + ImVec2( px + ghostSz, offset + ty ) ) )
        {
            if( IsMouseClicked( ImGuiMouseButton_Left ) )
            {
                m_ghost = !m_ghost;
            }
        }
    }
}

bool TimelineItemThread::DrawContents( const TimelineContext& ctx, int& offset )
{
    m_view.DrawThread( ctx, *m_thread, m_draw, m_ctxDraw, m_samplesDraw, m_lockDraw, offset, m_depth, m_hasCtxSwitch, m_hasSamples );
    const bool lockRows = std::any_of( m_lockDraw.begin(), m_lockDraw.end(), [] ( const std::unique_ptr<LockDraw>& ld ) { return ld->forceDraw || !ld->data.empty(); } );
    if( m_depth == 0 && !m_hasMessages && !lockRows && ( !m_view.GetViewData().drawSamples || !m_hasSamples ) && !m_worker.IsDeadlockedThread( m_thread->id ) )
    {
        auto& crash = m_worker.GetCrashEvent();
        return crash.thread == m_thread->id;
    }
    return true;
}

void TimelineItemThread::DrawOverlay( const ImVec2& ul, const ImVec2& dr )
{
    m_view.DrawThreadOverlays( *m_thread, ul, dr );
}

void TimelineItemThread::DrawExtraPopupItems()
{
    if( m_view.GetSelectThread() == m_thread->id )
    {
        if( ImGui::MenuItem( ICON_FA_TIMELINE " Unselect in CPU timeline" ) )
        {
            m_view.SelectThread( 0 );
        }
    }
    else if( m_view.GetViewData().drawCpuData && ImGui::MenuItem( ICON_FA_TIMELINE " Select in CPU timeline" ) )
    {
        m_view.SelectThread( m_thread->id );
    }
 }

void TimelineItemThread::DrawFinished()
{
    m_samplesDraw.clear();
    m_ctxDraw.clear();
    m_draw.clear();
    m_msgDraw.clear();
    m_lockDraw.clear();
}

void TimelineItemThread::Preprocess( const TimelineContext& ctx, TaskDispatch& td, bool visible, int yPos )
{
    assert( m_samplesDraw.empty() );
    assert( m_ctxDraw.empty() );
    assert( m_draw.empty() );
    assert( m_msgDraw.empty() );
    assert( m_lockDraw.empty() );

    td.Queue( [this, &ctx, visible] {
        if( m_worker.AreGhostZonesReady() && ( m_ghost || ( m_view.GetViewData().ghostZones && m_thread->timeline.empty() ) ) )
        {
            m_depth = PreprocessGhostLevel( ctx, m_thread->ghostZones, 0, visible );
        }
        else
        {
            m_depth = PreprocessZoneLevel( ctx, m_thread->timeline, 0, visible, 0 );
        }
    } );

    const auto& vd = m_view.GetViewData();

    m_hasCtxSwitch = false;
    if( vd.drawContextSwitches )
    {
        auto ctxSwitch = m_worker.GetContextSwitchData( m_thread->id );
        if( ctxSwitch )
        {
            // There is no yPos passed here to enable more granular visibility check,
            // as context switch shadows will usually be projected down onto zones.
            td.Queue( [this, &ctx, ctxSwitch, visible] {
                PreprocessContextSwitches( ctx, *ctxSwitch, visible );
            } );
        }
    }

    m_hasSamples = false;
    if( vd.drawSamples && !m_thread->samples.empty() )
    {
        td.Queue( [this, &ctx, visible, yPos] {
            PreprocessSamples( ctx, m_thread->samples, visible, yPos );
        } );
    }

    m_hasMessages = false;
    td.Queue( [this, &ctx, visible, yPos] {
        PreprocessMessages( ctx, m_thread->messages, m_thread->id, visible, yPos );
    } );

    if( vd.drawLocks )
    {
        const auto& locks = m_worker.GetLockMap();
        if( !locks.empty() )
        {
            PreprocessLocks( ctx, locks, m_thread->id, td, visible );
        }
    }
}

int TimelineItemThread::PreprocessGhostLevel( const TimelineContext& ctx, const Vector<GhostZone>& vec, int depth, bool visible )
{
    const auto nspx = ctx.nspx;
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;

    const auto MinVisNs = int64_t( round( ctx.scale * MinVisSize * nspx ) );

    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, vStart - 2 * MinVisNs ), [] ( const auto& l, const auto& r ) { return l.end.Val() < r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), vEnd, [] ( const auto& l, const auto& r ) { return l.start.Val() < r; } );
    if( it == zitend ) return depth;
    if( (zitend-1)->end.Val() < vStart ) return depth;

    int maxdepth = depth + 1;

    while( it < zitend )
    {
        auto& ev = *it;
        const auto end = ev.end.Val();
        const auto zsz = end - ev.start.Val();
        if( zsz < MinVisNs )
        {
            auto nextTime = end + MinVisNs;
            auto next = it + 1;
            for(;;)
            {
                next = std::lower_bound( next, zitend, nextTime, [] ( const auto& l, const auto& r ) { return l.end.Val() < r; } );
                if( next == zitend ) break;
                auto prev = next - 1;
                const auto pt = prev->end.Val();
                const auto nt = next->end.Val();
                if( nt - pt >= MinVisNs ) break;
                nextTime = nt + MinVisNs;
            }
            if( visible ) m_draw.emplace_back( TimelineDraw { TimelineDrawType::GhostFolded, uint16_t( depth ), (void**)&ev, (next-1)->end } );
            it = next;
        }
        else
        {
            if( ev.child >= 0 )
            {
                const auto d = PreprocessGhostLevel( ctx, m_worker.GetGhostChildren( ev.child ), depth + 1, visible );
                if( d > maxdepth ) maxdepth = d;
            }
            if( visible ) m_draw.emplace_back( TimelineDraw { TimelineDrawType::Ghost, uint16_t( depth ), (void**)&ev } );
            ++it;
        }
    }

    return maxdepth;
}

int TimelineItemThread::PreprocessZoneLevel( const TimelineContext& ctx, const Vector<short_ptr<ZoneEvent>>& vec, int depth, bool visible, const uint32_t inheritedColor )
{
    if( vec.is_magic() )
    {
        return PreprocessZoneLevel<VectorAdapterDirect<ZoneEvent>>( ctx, *(Vector<ZoneEvent>*)( &vec ), depth, visible, inheritedColor );
    }
    else
    {
        return PreprocessZoneLevel<VectorAdapterPointer<ZoneEvent>>( ctx, vec, depth, visible, inheritedColor );
    }
}

template<typename Adapter, typename V>
int TimelineItemThread::PreprocessZoneLevel( const TimelineContext& ctx, const V& vec, int depth, bool visible, const uint32_t inheritedColor )
{
    if( depth >= 256 )
    {
        m_worker.NotifyExcessiveZoneDepth( Adapter{}( vec.front() ).Start() );
        return depth;
    }

    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;
    const auto nspx = ctx.nspx;

    const auto MinVisNs = int64_t( round( ctx.scale * MinVisSize * nspx ) );

    auto it = std::lower_bound( vec.begin(), vec.end(), vStart, [this] ( const auto& l, const auto& r ) { Adapter a; return m_worker.GetZoneEnd( a(l) ) < r; } );
    if( it == vec.end() ) return depth;

    const auto zitend = std::lower_bound( it, vec.end(), vEnd, [] ( const auto& l, const auto& r ) { Adapter a; return a(l).Start() < r; } );
    if( it == zitend ) return depth;
    Adapter a;
    if( !a(*it).IsEndValid() && m_worker.GetZoneEnd( a(*it) ) < vStart ) return depth;
    if( m_worker.GetZoneEnd( a(*(zitend-1)) ) < vStart ) return depth;

    int maxdepth = depth + 1;

    while( it < zitend )
    {
        auto& ev = a(*it);
        const auto end = m_worker.GetZoneEnd( ev );
        const auto zsz = end - ev.Start();
        if( zsz < MinVisNs )
        {
            auto nextTime = end + MinVisNs;
            auto next = it + 1;
            for(;;)
            {
                next = std::lower_bound( next, zitend, nextTime, [this] ( const auto& l, const auto& r ) { Adapter a; return m_worker.GetZoneEnd( a(l) ) < r; } );
                if( next == zitend ) break;
                auto prev = next - 1;
                const auto pt = m_worker.GetZoneEnd( a(*prev) );
                const auto nt = m_worker.GetZoneEnd( a(*next) );
                if( nt - pt >= MinVisNs ) break;
                nextTime = nt + MinVisNs;
            }
            if( visible ) m_draw.emplace_back( TimelineDraw { TimelineDrawType::Folded, uint16_t( depth ), (void**)&ev, m_worker.GetZoneEnd( a(*(next-1)) ), uint32_t( next - it ), inheritedColor } );
            it = next;
        }
        else
        {
            const auto hasChildren = ev.HasChildren();
            auto currentInherited = inheritedColor;
            auto childrenInherited = inheritedColor;
            if( m_view.GetViewData().inheritParentColors )
            {
                uint32_t color = 0;
                if( m_worker.HasZoneExtra( ev ) )
                {
                    const auto& extra = m_worker.GetZoneExtra( ev );
                    color = extra.color.Val();
                }
                if( color == 0 )
                {
                    auto& srcloc = m_worker.GetSourceLocation( ev.SrcLoc() );
                    color = srcloc.color;
                }
                if( color != 0 )
                {
                    currentInherited = color | 0xFF000000;
                    if( hasChildren ) childrenInherited = DarkenColorSlightly( color );
                }
            }
            if( hasChildren )
            {
                const auto d = PreprocessZoneLevel( ctx, m_worker.GetZoneChildren( ev.Child() ), depth + 1, visible, childrenInherited );
                if( d > maxdepth ) maxdepth = d;
            }
            if( visible ) m_draw.emplace_back( TimelineDraw { TimelineDrawType::Zone, uint16_t( depth ), (void**)&ev, 0, 0, currentInherited } );
            ++it;
        }
    }

    return maxdepth;
}

void TimelineItemThread::PreprocessContextSwitches( const TimelineContext& ctx, const ContextSwitch& ctxSwitch, bool visible )
{
    const auto nspx = ctx.nspx;
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;

    auto& vec = ctxSwitch.v;
    auto it = std::lower_bound( vec.begin(), vec.end(), std::max<int64_t>( 0, vStart ), [] ( const auto& l, const auto& r ) { return ( l.IsEndValid() ? l.End() : l.Start() ) < r; } );
    if( it == vec.end() ) return;
    if( it != vec.begin() ) --it;

    auto citend = std::lower_bound( it, vec.end(), vEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
    if( it == citend ) return;
    if( citend != vec.end() ) ++citend;

    m_hasCtxSwitch = true;
    if( !visible ) return;

    const auto MinCtxNs = int64_t( round( ctx.scale * MinCtxSize * nspx ) );
    const auto& sampleData = m_thread->samples;

    bool first = true;
    while( it < citend )
    {
        auto& ev = *it;
        if( first )
        {
            first = false;
        }
        else
        {
            uint32_t waitStack = 0;
            if( !sampleData.empty() )
            {
                auto sdit = std::lower_bound( sampleData.begin(), sampleData.end(), ev.Start(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                bool found = sdit != sampleData.end() && sdit->time.Val() == ev.Start();
                if( !found && it != vec.begin() )
                {
                    auto eit = it;
                    --eit;
                    sdit = std::lower_bound( sampleData.begin(), sampleData.end(), eit->End(), [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                    found = sdit != sampleData.end() && sdit->time.Val() == eit->End();
                }
                if( found ) waitStack = sdit->callstack.Val();
            }
            m_ctxDraw.emplace_back( ContextSwitchDraw { ContextSwitchDrawType::Waiting, uint32_t( it - vec.begin() ), waitStack } );
        }

        const auto end = ev.IsEndValid() ? ev.End() : ev.Start();
        const auto zsz = end - ev.Start();
        if( zsz < MinCtxNs )
        {
            auto nextTime = end + MinCtxNs;
            auto next = it + 1;
            for(;;)
            {
                next = std::lower_bound( next, citend, nextTime, [] ( const auto& l, const auto& r ) { return ( l.IsEndValid() ? l.End() : l.Start() ) < r; } );
                if( next == citend ) break;
                auto prev = next - 1;
                const auto pt = prev->IsEndValid() ? prev->End() : prev->Start();
                const auto nt = next->IsEndValid() ? next->End() : next->Start();
                if( nt - pt >= MinCtxNs ) break;
                nextTime = nt + MinCtxNs;
            }
            m_ctxDraw.emplace_back( ContextSwitchDraw { ContextSwitchDrawType::Folded, uint32_t( it - vec.begin() ), uint32_t( next - it ) } );
            it = next;
        }
        else
        {
            m_ctxDraw.emplace_back( ContextSwitchDraw { ContextSwitchDrawType::Running, uint32_t( it - vec.begin() ) } );
            ++it;
        }
    }
}

void TimelineItemThread::PreprocessSamples( const TimelineContext& ctx, const Vector<SampleData>& vec, bool visible, int yPos )
{
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;
    const auto nspx = ctx.nspx;
    const auto ty = ctx.ty;
    const auto ostep = ty + 1;
    const auto pos = yPos + ostep;

    const auto MinVis = 5 * ctx.scale;
    const auto MinVisNs = int64_t( round( MinVis * nspx ) );

    auto it = std::lower_bound( vec.begin(), vec.end(), vStart - MinVisNs, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
    if( it == vec.end() ) return;
    const auto itend = std::lower_bound( it, vec.end(), vEnd, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
    if( it == itend ) return;

    m_hasSamples = true;
    if( !visible ) return;

    const auto ty0375 = pos + round( ty * 0.375f );
    const auto ty02 = round( ty * 0.2f );
    const auto y0 = ty0375 - ty02 - 3;
    const auto y1 = ty0375 + ty02 - 1;
    if( y0 > ctx.yMax || y1 < ctx.yMin ) return;

    while( it < itend )
    {
        auto next = it + 1;
        if( next != itend )
        {
            const auto t0 = it->time.Val();
            auto nextTime = t0 + MinVisNs;
            for(;;)
            {
                next = std::lower_bound( next, itend, nextTime, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
                if( next == itend ) break;
                auto prev = next - 1;
                const auto pt = prev->time.Val();
                const auto nt = next->time.Val();
                if( nt - pt >= MinVisNs ) break;
                nextTime = nt + MinVisNs;
            }
        }
        const auto num = uint32_t( next - it - 1 );
        const auto idx = uint32_t( it - vec.begin() );
        if( num == 0 )
        {
            auto type = SampleType::Own;
            auto& cs = m_worker.GetCallstack( it->callstack.Val() );
            auto frameData = m_worker.GetCallstackFrame( cs[0] );
            if( frameData )
            {
                const auto& frame = frameData->data[0];
                if( frame.symAddr >> 63 != 0 )
                {
                    type = SampleType::Kernel;
                }
                else if( m_worker.IsFrameExternal( frame.file, frameData->imageName ) )
                {
                    type = SampleType::External;
                }
            }

            m_samplesDraw.emplace_back( SamplesDraw {
                .num = 0,
                .idx = idx,
                .type = type
            } );
        }
        else
        {
            m_samplesDraw.emplace_back( SamplesDraw {
                .num = num,
                .idx = idx
            } );
        }
        it = next;
    }
}

void TimelineItemThread::PreprocessMessages( const TimelineContext& ctx, const Vector<short_ptr<MessageData>>& vec, uint64_t tid, bool visible, int yPos )
{
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;
    const auto nspx = ctx.nspx;

    const auto MinVisNs = int64_t( round( ctx.scale * MinVisSize * nspx ) );

    auto it = std::lower_bound( vec.begin(), vec.end(), vStart, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
    if( it == vec.end() ) return;
    auto end = std::lower_bound( it, vec.end(), vEnd+1, [] ( const auto& lhs, const auto& rhs ) { return lhs->time < rhs; } );
    if( it == end ) return;

    m_hasMessages = true;
    if( !visible ) return;
    if( yPos > ctx.yMax || yPos + ctx.ty < ctx.yMin ) return;

    const auto hMsg = m_view.GetMessageHighlight();
    const auto hThread = hMsg ? m_worker.DecompressThread( hMsg->thread ) : 0;

    while( it < end )
    {
        const auto msgTime = (*it)->time;
        const auto nextTime = msgTime + MinVisNs;
        const auto next = std::upper_bound( it, vec.end(), nextTime, [] ( const auto& lhs, const auto& rhs ) { return lhs < rhs->time; } );
        const auto num = next - it;
        bool hilite;
        if( num == 1 )
        {
            hilite = hMsg == *it;
        }
        else
        {
            if( hMsg && hThread == tid )
            {
                const auto hTime = hMsg->time;
                hilite = (*it)->time <= hTime && ( next == vec.end() || (*next)->time > hTime );
            }
            else
            {
                hilite = false;
            }
        }
        m_msgDraw.emplace_back( MessagesDraw { *it, hilite, uint32_t( num ) } );
        it = next;
    }
}



void TimelineItemThread::PreprocessLocks( const TimelineContext& ctx, const unordered_flat_map<uint32_t, LockMap*>& locks, uint32_t tid, TaskDispatch& td, bool visible )
{
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;

    const auto& vd = m_view.GetViewData();
    const auto lockInfoWindow = m_view.GetLockInfoWindow();

    const auto MinVisNs = int64_t( round( ctx.scale * MinVisSize * ctx.nspx ) );

    for( auto& v : locks )
    {
        const auto& lockmap = *v.second;
        if( !lockmap.valid ) continue;
        if( !m_view.Vis( &lockmap ) ) continue;
        if( vd.onlyContendedLocks && lockInfoWindow != v.first && ( lockmap.threads.size() == 1 || !lockmap.isContended ) && !m_worker.IsDeadlockedPair( tid, v.first ) ) continue;

        auto it = lockmap.threadMap.find( tid );
        if( it == lockmap.threadMap.end() ) continue;

        const auto slot = it->second;
        const auto& ti = lockmap.threads[slot];
        assert( !lockmap.timeline.empty() );
        const auto drawnEnd = ti.segments.empty() ? ti.lastTime :
            ( ti.segments.back().nextEv == LockEvent::NoEvent ? m_worker.GetLastTime() : lockmap.timeline[ ti.segments.back().nextEv ].Time() );
        if( ti.firstTime > vEnd || drawnEnd < vStart )
        {
            if( lockInfoWindow == v.first )
            {
                m_lockDraw.emplace_back( std::make_unique<LockDraw>( LockDraw { v.first, true, slot } ) );
            }
            continue;
        }

        auto drawData = std::make_unique<LockDraw>( LockDraw { v.first, false, slot } );
        auto drawPtr = drawData.get();
        m_lockDraw.emplace_back( std::move( drawData ) );

        td.Queue( [this, &lockmap, &ti, &ctx, &vd, visible, drawPtr, MinVisNs] {
            const auto vStart = ctx.vStart;
            const auto vEnd = ctx.vEnd;
            const auto lastTime = m_worker.GetLastTime();
            const uint8_t mask = vd.onlyContendedLocks ? ( LockEventState::Nothing | LockEventState::HasLock ) : ( uint8_t )LockEventState::Nothing;

            if( !visible )
            {
                drawPtr->forceDraw = HasLockDrawItems( lockmap, ti, vStart, vEnd, mask, lastTime );
                return;
            }

            auto& dst = drawPtr->data;
            const auto& segs = ti.segments;
            ForEachLockDrawItem( lockmap, ti, vStart, vEnd, MinVisNs, mask, lastTime, [&dst, &segs] ( uint32_t first, uint32_t num, int64_t t1, uint8_t state ) {
                dst.emplace_back( LockDrawItem { t1, state, num, &segs[first] } );
            } );
        } );
    }
}

}
