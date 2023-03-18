#ifndef __TRACYTIMELINEITEMGPU_HPP__
#define __TRACYTIMELINEITEMGPU_HPP__

#include "TracyEvent.hpp"
#include "TracyTimelineItem.hpp"

namespace tracy
{

class TimelineItemGpu final : public TimelineItem
{
public:
    TimelineItemGpu( View& view, Worker& worker, GpuCtxData* gpu );

    int GetIdx() const { return m_idx; }

protected:
    uint32_t HeaderColor() const override { return 0xFFFFAAAA; }
    uint32_t HeaderColorInactive() const override { return 0xFF886666; }
    uint32_t HeaderLineColor() const override { return 0x33FFFFFF; }
    const char* HeaderLabel() const override;

    int64_t RangeBegin() const override;
    int64_t RangeEnd() const override;

    void HeaderTooltip( const char* label ) const override;
    void HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth ) override;

    bool DrawContents( const TimelineContext& ctx, int& offset ) override;

    bool IsEmpty() const override;

private:
    GpuCtxData* m_gpu;
    int m_idx;
};

}

#endif
