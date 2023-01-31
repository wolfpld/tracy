#include "TracyImGui.hpp"
#include "TracyPrint.hpp"
#include "TracyTimelineItemCpuData.hpp"
#include "TracyUtility.hpp"
#include "TracyView.hpp"
#include "TracyWorker.hpp"

namespace tracy
{

TimelineItemCpuData::TimelineItemCpuData( View& view, Worker& worker, void* key )
    : TimelineItem( view, worker, key )
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

bool TimelineItemCpuData::DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax )
{
    return m_view.DrawCpuData( pxns, offset, wpos, hover, yMin, yMax );
}

}
