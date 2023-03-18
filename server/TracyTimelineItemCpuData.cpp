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
    : TimelineItem( view, worker, key, false )
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
    return m_view.DrawCpuData( ctx.pxns, offset, ctx.wpos, ctx.hover, ctx.yMin, ctx.yMax );
}

}
