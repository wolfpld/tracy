#include <algorithm>
#include <limits>

#include "TracyImGui.hpp"
#include "TracyMouse.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineItemThread.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

TimelineItemThread::TimelineItemThread( View& view, Worker& worker, const ThreadData* thread )
    : TimelineItem( view, worker, thread )
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
        m_thread->ghostZones.empty();
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
        const auto thread = it->second;
        auto lptr = lockmap.timeline.data();
        while( lptr->ptr->thread != thread ) lptr++;
        if( lptr->ptr->Time() < first ) first = lptr->ptr->Time();
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
        const auto thread = it->second;
        auto eptr = lockmap.timeline.data() + lockmap.timeline.size() - 1;
        while( eptr->ptr->thread != thread ) eptr--;
        if( eptr->ptr->Time() > last ) last = eptr->ptr->Time();
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

    const auto ctx = m_worker.GetContextSwitchData( m_thread->id );
    const auto first = RangeBegin();
    const auto last = RangeEnd();

    ImGui::Separator();

    size_t lockCnt = 0;
    for( const auto& lock : m_worker.GetLockMap() )
    {
        const auto& lockmap = *lock.second;
        if( !lockmap.valid ) continue;
        auto it = lockmap.threadMap.find( m_thread->id );
        if( it == lockmap.threadMap.end() ) continue;
        lockCnt++;
    }

    if( last >= 0 )
    {
        const auto lifetime = last - first;
        const auto traceLen = m_worker.GetLastTime();

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

void TimelineItemThread::HeaderExtraContents( int offset, const ImVec2& wpos, float labelWidth, double pxns, bool hover )
{
    m_view.DrawThreadMessages( *m_thread, pxns, offset, wpos, hover );

#ifndef TRACY_NO_STATISTICS
    const bool hasGhostZones = m_worker.AreGhostZonesReady() && !m_thread->ghostZones.empty();
    if( hasGhostZones && !m_thread->timeline.empty() )
    {
        auto draw = ImGui::GetWindowDrawList();
        const auto ty = ImGui::GetTextLineHeight();

        const auto color = m_ghost ? 0xFFAA9999 : 0x88AA7777;
        draw->AddText( wpos + ImVec2( 1.5f * ty + labelWidth, offset ), color, ICON_FA_GHOST );
        float ghostSz = ImGui::CalcTextSize( ICON_FA_GHOST ).x;

        if( hover && ImGui::IsMouseHoveringRect( wpos + ImVec2( 1.5f * ty + labelWidth, offset ), wpos + ImVec2( 1.5f * ty + labelWidth + ghostSz, offset + ty ) ) )
        {
            if( IsMouseClicked( 0 ) )
            {
                m_ghost = !m_ghost;
            }
        }
    }
#endif
}

bool TimelineItemThread::DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    const auto res = m_view.DrawThread( *m_thread, pxns, offset, wpos, hover, yMin, yMax, m_ghost );
    if( !res )
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

}
