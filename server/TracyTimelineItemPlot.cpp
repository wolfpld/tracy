#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineItemPlot.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

TimelineItemPlot::TimelineItemPlot( View& view, Worker& worker, PlotData* plot )
    : TimelineItem( view, worker, plot )
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
    const auto traceLen = m_worker.GetLastTime();

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

void TimelineItemPlot::HeaderExtraContents( int offset, const ImVec2& wpos, float labelWidth, double pxns, bool hover )
{
    auto draw = ImGui::GetWindowDrawList();
    const auto ty = ImGui::GetTextLineHeight();

    char tmp[128];
    sprintf( tmp, "(y-range: %s, visible data points: %s)", FormatPlotValue( m_plot->rMax - m_plot->rMin, m_plot->format ), RealToString( m_plot->num ) );
    draw->AddText( wpos + ImVec2( ty * 1.5f + labelWidth, offset ), 0xFF226E6E, tmp );
}

int64_t TimelineItemPlot::RangeBegin() const
{
    return m_plot->data.front().time.Val();
}

int64_t TimelineItemPlot::RangeEnd() const
{
    return m_plot->data.back().time.Val();
}

bool TimelineItemPlot::DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    return m_view.DrawPlot( *m_plot, pxns, offset, wpos, hover, yMin, yMax );
}

}
