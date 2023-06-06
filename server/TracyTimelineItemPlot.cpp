#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineContext.hpp"
#include "TracyTimelineItemPlot.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

constexpr int PlotHeightPx = 100;
constexpr int MinVisSize = 3;


TimelineItemPlot::TimelineItemPlot( View& view, Worker& worker, PlotData* plot )
    : TimelineItem( view, worker, plot, true )
    , m_plot( plot )
{
}

bool TimelineItemPlot::IsEmpty() const
{
    return m_plot->data.empty();
}

const char* TimelineItemPlot::HeaderLabel() const
{
    static char tmp[1024];
    switch( m_plot->type )
    {
    case PlotType::User:
        return m_worker.GetString( m_plot->name );
    case PlotType::Memory:
        if( m_plot->name == 0 )
        {
            return ICON_FA_MEMORY " Memory usage";
        }
        else
        {
            sprintf( tmp, ICON_FA_MEMORY " %s", m_worker.GetString( m_plot->name ) );
            return tmp;
        }
    case PlotType::SysTime:
        return ICON_FA_GAUGE_HIGH " CPU usage";
    case PlotType::Power:
        sprintf( tmp, ICON_FA_BOLT " %s", m_worker.GetString( m_plot->name ) );
        return tmp;
    default:
        assert( false );
        return nullptr;
    }
}

void TimelineItemPlot::HeaderTooltip( const char* label ) const
{
    ImGui::BeginTooltip();
    SmallColorBox( GetPlotColor( *m_plot, m_worker ) );
    ImGui::SameLine();
    TextFocused( "Plot", label );
    ImGui::Separator();

    const auto first = RangeBegin();
    const auto last = RangeEnd();
    const auto activity = last - first;
    const auto traceLen = m_worker.GetLastTime() - m_worker.GetFirstTime();

    TextFocused( "Appeared at", TimeToString( first ) );
    TextFocused( "Last event at", TimeToString( last ) );
    TextFocused( "Activity time:", TimeToString( activity ) );
    ImGui::SameLine();
    char buf[64];
    PrintStringPercent( buf, activity / double( traceLen ) * 100 );
    TextDisabledUnformatted( buf );
    ImGui::Separator();
    TextFocused( "Data points:", RealToString( m_plot->data.size() ) );
    TextFocused( "Data range:", FormatPlotValue( m_plot->max - m_plot->min, m_plot->format ) );
    TextFocused( "Min value:", FormatPlotValue( m_plot->min, m_plot->format ) );
    TextFocused( "Max value:", FormatPlotValue( m_plot->max, m_plot->format ) );
    TextFocused( "Avg value:", FormatPlotValue( m_plot->sum / m_plot->data.size(), m_plot->format ) );
    TextFocused( "Data/second:", RealToString( double( m_plot->data.size() ) / activity * 1000000000ll ) );

    const auto it = std::lower_bound( m_plot->data.begin(), m_plot->data.end(), last - 1000000000ll * 10, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
    const auto tr10 = last - it->time.Val();
    if( tr10 != 0 )
    {
        TextFocused( "D/s (10s):", RealToString( double( std::distance( it, m_plot->data.end() ) ) / tr10 * 1000000000ll ) );
    }
    ImGui::EndTooltip();
}

void TimelineItemPlot::HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth )
{
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();

    char tmp[128];
    sprintf( tmp, "(y-range: %s, visible data points: %s)", FormatPlotValue( m_plot->rMax - m_plot->rMin, m_plot->format ), RealToString( m_plot->num ) );
    draw->AddText( ctx.wpos + ImVec2( ty * 1.5f + labelWidth, offset ), 0xFF226E6E, tmp );
}

int64_t TimelineItemPlot::RangeBegin() const
{
    return m_plot->data.front().time.Val();
}

int64_t TimelineItemPlot::RangeEnd() const
{
    return m_plot->data.back().time.Val();
}

bool TimelineItemPlot::DrawContents( const TimelineContext& ctx, int& offset )
{
    return m_view.DrawPlot( ctx, *m_plot, m_draw, offset );
}

void TimelineItemPlot::DrawFinished()
{
    m_draw.clear();
}

void TimelineItemPlot::Preprocess( const TimelineContext& ctx, TaskDispatch& td, bool visible, int yPos )
{
    assert( m_draw.empty() );

    if( !visible ) return;
    if( yPos > ctx.yMax ) return;
    if( m_plot->data.empty() ) return;
    const auto PlotHeight = int( round( PlotHeightPx * GetScale() ) );
    if( yPos + PlotHeight < ctx.yMin ) return;

    td.Queue( [this, &ctx] {
        const auto vStart = ctx.vStart;
        const auto vEnd = ctx.vEnd;
        const auto nspx = ctx.nspx;
        const auto MinVisNs = int64_t( round( MinVisSize * nspx ) );

        auto& vec = m_plot->data;
        vec.ensure_sorted();
        if( vec.front().time.Val() > vEnd || vec.back().time.Val() < vStart )
        {
            m_plot->rMin = 0;
            m_plot->rMax = 0;
            m_plot->num = 0;
            return;
        }

        auto it = std::lower_bound( vec.begin(), vec.end(), vStart, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );
        auto end = std::lower_bound( it, vec.end(), vEnd, [] ( const auto& l, const auto& r ) { return l.time.Val() < r; } );

        if( end != vec.end() ) end++;
        if( it != vec.begin() ) it--;

        double min = it->val;
        double max = it->val;
        const auto num = end - it;
        if( num > 1000000 )
        {
            min = m_plot->min;
            max = m_plot->max;
        }
        else
        {
            auto tmp = it;
            while( ++tmp < end )
            {
                if( tmp->val < min ) min = tmp->val;
                else if( tmp->val > max ) max = tmp->val;
            }
        }
        if( min == max )
        {
            min--;
            max++;
        }

        m_plot->rMin = min;
        m_plot->rMax = max;
        m_plot->num = num;

        m_draw.emplace_back( 0 );
        m_draw.emplace_back( it - vec.begin() );

        ++it;
        while( it < end )
        {
            auto next = std::upper_bound( it, end, int64_t( it->time.Val() + MinVisNs ), [] ( const auto& l, const auto& r ) { return l < r.time.Val(); } );
            assert( next > it );
            const auto rsz = uint32_t( next - it );
            if( rsz < 4 )
            {
                for( int i=0; i<rsz; i++ )
                {
                    m_draw.emplace_back( 0 );
                    m_draw.emplace_back( it - vec.begin() );
                    ++it;
                }
            }
            else
            {
                // Sync with View::DrawPlot()!
                constexpr int NumSamples = 256;
                uint32_t samples[NumSamples];
                uint32_t cnt = 0;
                uint32_t offset = it - vec.begin();
                if( rsz < NumSamples )
                {
                    for( cnt=0; cnt<rsz; cnt++ )
                    {
                        samples[cnt] = offset + cnt;
                    }
                }
                else
                {
                    const auto skip = ( rsz + NumSamples - 1 ) / NumSamples;
                    const auto limit = rsz / skip;
                    for( cnt=0; cnt<limit; cnt++ )
                    {
                        samples[cnt] = offset + cnt * skip;
                    }
                    if( cnt == limit ) cnt--;
                    samples[cnt++] = offset + rsz - 1;
                }
                it = next;

                pdqsort_branchless( samples, samples+cnt, [&vec] ( const auto& l, const auto& r ) { return vec[l].val < vec[r].val; } );

                assert( rsz > 0 );
                m_draw.emplace_back( rsz );
                m_draw.emplace_back( offset );
                m_draw.emplace_back( samples[0] );
                m_draw.emplace_back( samples[cnt-1] );
            }
        }
    } );
}

}
