#ifndef __TRACYTIMELINEITEMCPUDATA_HPP__
#define __TRACYTIMELINEITEMCPUDATA_HPP__

#include "TracyEvent.hpp"
#include "TracyTimelineItem.hpp"

namespace tracy
{

class TimelineItemCpuData final : public TimelineItem
{
public:
    TimelineItemCpuData( View& view, Worker& worker, void* key );

    void SetVisible( bool visible ) override;
    bool IsVisible() const override;

protected:
    uint32_t HeaderColor() const override { return 0xFFDD88DD; }
    uint32_t HeaderColorInactive() const override { return 0xFF6E446E; }
    uint32_t HeaderLineColor() const override { return 0x66DD88DD; }
    const char* HeaderLabel() const override { return "CPU data"; }

    int64_t RangeBegin() const override;
    int64_t RangeEnd() const override;

    bool DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax ) override;

    bool IsEmpty() const override;
};

}

#endif
