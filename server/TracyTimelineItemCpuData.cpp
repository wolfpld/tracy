#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineItemCpuData.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

TimelineItemCpuData::TimelineItemCpuData( View& view, Worker& worker, void* key )
    : TimelineItem( view, worker, key, true )
{
}

void TimelineItemCpuData::SetVisible( bool visible )
{
    m_view.GetViewData().drawCpuData = visible;
}

bool TimelineItemCpuData::IsVisible() const
{
    return m_view.GetViewData().drawCpuData;
}

bool TimelineItemCpuData::IsEmpty() const
{
    return m_worker.GetCpuDataCpuCount() == 0;
}

int64_t TimelineItemCpuData::RangeBegin() const
{
    return -1;
}

int64_t TimelineItemCpuData::RangeEnd() const
{
    return -1;
}

bool TimelineItemCpuData::DrawContents( const TimelineContext& ctx, int& offset )
{
    m_view.DrawCpuData( ctx, m_cpuDraw, m_ctxDraw, offset, m_hasCpuData );
    return true;
}

void TimelineItemCpuData::DrawFinished()
{
    m_cpuDraw.clear();
    for( auto& v : m_ctxDraw ) v.clear();
}

void TimelineItemCpuData::Preprocess( const TimelineContext& ctx, TaskDispatch& td, bool visible, int yPos )
{
    assert( m_cpuDraw.empty() );
    for( auto& v : m_ctxDraw ) assert( v.empty() );

    if( !visible ) return;

    const auto yMin = ctx.yMin;
    const auto yMax = ctx.yMax;
    const auto ty = ctx.ty;
    const auto sty = ctx.sty;
    const auto ostep = ty + 1;
    const auto sstep = sty + 1;

    bool hasCpuData = false;
    auto pos = yPos + ostep;

#ifdef TRACY_NO_STATISTICS
    if( m_view.GetViewData().drawCpuUsageGraph )
#else
    if( m_view.GetViewData().drawCpuUsageGraph && m_worker.IsCpuUsageReady() )
#endif
    {
#ifndef TRACY_NO_STATISTICS
        auto& ctxUsage = m_worker.GetCpuUsage();
        if( !ctxUsage.empty() )
        {
            hasCpuData = true;
        }
        else
#endif
        {
            const auto cpuDataCount = m_worker.GetCpuDataCpuCount();
            const auto cpuData = m_worker.GetCpuData();
            for( int i=0; i<cpuDataCount; i++ )
            {
                if( !cpuData[i].cs.empty() )
                {
                    hasCpuData = true;
                    break;
                }
            }
        }
        if( hasCpuData )
        {
            const auto cpuUsageHeight = floor( 30.f * GetScale() );
            if( pos <= yMax && pos + cpuUsageHeight + 3 >= yMin )
            {
                td.Queue( [this, &ctx] {
                    PreprocessCpuUsage( ctx );
                } );
            }
            pos += cpuUsageHeight + 3;
        }
    }
    m_hasCpuData = hasCpuData;

    auto cpuData = m_worker.GetCpuData();
    const auto cpuCnt = m_worker.GetCpuDataCpuCount();
    if( m_ctxDraw.size() != cpuCnt ) m_ctxDraw.resize( cpuCnt );

    for( int i=0; i<cpuCnt; i++ )
    {
        auto& cs = cpuData[i].cs;
        if( !cs.empty() && pos <= yMax && pos + sty >= yMin )
        {
            td.Queue( [this, &ctx, &cs, i] {
                PreprocessCpuCtxSwitches( ctx, cs, m_ctxDraw[i] );
            } );
        }
        pos += sstep;
    }
}

constexpr float MinVisSize = 3;

void TimelineItemCpuData::PreprocessCpuCtxSwitches( const TimelineContext& ctx, const Vector<ContextSwitchCpu>& cs, std::vector<CpuCtxDraw>& out )
{
    const auto vStart = ctx.vStart;
    const auto vEnd = ctx.vEnd;
    const auto nspx = ctx.nspx;

    auto it = std::lower_bound( cs.begin(), cs.end(), std::max<int64_t>( 0, vStart ), [] ( const auto& l, const auto& r ) { return ( l.IsEndValid() ? l.End() : l.Start() ) < r; } );
    if( it == cs.end() ) return;
    auto eit = std::lower_bound( it, cs.end(), vEnd, [] ( const auto& l, const auto& r ) { return l.Start() < r; } );
    if( it == eit ) return;

    const auto MinVisNs = int64_t( round( GetScale() * MinVisSize * nspx ) );

    while( it < eit )
    {
        const auto end = it->IsEndValid() ? it->End() : it->Start();
        const auto zsz = end - it->Start();
        if( zsz < MinVisNs )
        {
            auto nextTime = end + MinVisNs;
            auto next = it + 1;
            for(;;)
            {
                next = std::lower_bound( next, eit, nextTime, [] ( const auto& l, const auto& r ) { return ( l.IsEndValid() ? l.End() : l.Start() ) < r; } );
                if( next == eit ) break;
                auto prev = next - 1;
                const auto pt = prev->IsEndValid() ? prev->End() : prev->Start();
                const auto nt = next->IsEndValid() ? next->End() : next->Start();
                if( nt - pt >= MinVisNs ) break;
                nextTime = nt + MinVisNs;
            }
            out.emplace_back( CpuCtxDraw { uint32_t( it - cs.begin() ), uint32_t( next - it ) } );
            it = next;
        }
        else
        {
            out.emplace_back( CpuCtxDraw { uint32_t( it - cs.begin() ), 0 } );
            ++it;
        }
    }
}

void TimelineItemCpuData::PreprocessCpuUsage( const TimelineContext& ctx )
{
    const auto vStart = ctx.vStart;
    const auto nspx = ctx.nspx;
    const auto w = ctx.w;
    const auto num = size_t( w );

    if( vStart > m_worker.GetLastTime() || int64_t( vStart + nspx * num ) < 0 ) return;

    const auto lastTime = m_worker.GetLastTime();

#ifndef TRACY_NO_STATISTICS
    auto& ctxUsage = m_worker.GetCpuUsage();
    if( !ctxUsage.empty() )
    {
        auto itBegin = ctxUsage.begin();
        for( size_t i=0; i<num; i++ )
        {
            const auto time = int64_t( vStart + nspx * i );
            if( time > lastTime ) return;
            if( time < 0 )
            {
                m_cpuDraw.emplace_back( CpuUsageDraw { 0, 0 } );
            }
            else
            {
                const auto test = ( time << 16 ) | 0xFFFF;
                auto it = std::upper_bound( itBegin, ctxUsage.end(), test, [] ( const auto& l, const auto& r ) { return l < r._time_other_own; } );
                if( it == ctxUsage.end() ) return;
                if( it == ctxUsage.begin() )
                {
                    m_cpuDraw.emplace_back( CpuUsageDraw { 0, 0 } );
                }
                else
                {
                    --it;
                    m_cpuDraw.emplace_back( CpuUsageDraw { it->Own(), it->Other() } );
                }
                itBegin = it;
            }
        }
    }
    else
#endif
    {
        m_cpuDraw.resize( num );
        memset( m_cpuDraw.data(), 0, sizeof( CpuUsageDraw ) * num );

        const auto pid = m_worker.GetPid();
        const auto cpuDataCount = m_worker.GetCpuDataCpuCount();
        const auto cpuData = m_worker.GetCpuData();

        for( int i=0; i<cpuDataCount; i++ )
        {
            auto& cs = cpuData[i].cs;
            if( !cs.empty() )
            {
                auto itBegin = cs.begin();
                auto ptr = m_cpuDraw.data();
                for( size_t i=0; i<num; i++ )
                {
                    const auto time = int64_t( vStart + nspx * i );
                    if( time > lastTime ) break;
                    if( time >= 0 )
                    {
                        auto it = std::lower_bound( itBegin, cs.end(), time, [] ( const auto& l, const auto& r ) { return (uint64_t)l.End() < (uint64_t)r; } );
                        if( it == cs.end() ) break;
                        if( it->IsEndValid() && it->Start() <= time  )
                        {
                            if( m_worker.GetPidFromTid( m_worker.DecompressThreadExternal( it->Thread() ) ) == pid )
                            {
                                ptr->own++;
                            }
                            else
                            {
                                ptr->other++;
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

}
