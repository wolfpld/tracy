#ifndef __TRACYTIMELINEITEMTHREAD_HPP__
#define __TRACYTIMELINEITEMTHREAD_HPP__

#include "TracyEvent.hpp"
#include "TracyTimelineItem.hpp"

namespace tracy
{

class TimelineItemThread final : public TimelineItem
{
public:
    TimelineItemThread( View& view, Worker& worker, const ThreadData* plot );

protected:
    uint32_t HeaderColor() const override;
    uint32_t HeaderColorInactive() const override;
    uint32_t HeaderLineColor() const override;
    const char* HeaderLabel() const override;

    int64_t RangeBegin() const override;
    int64_t RangeEnd() const override;

    void HeaderTooltip( const char* label ) const override;
    void HeaderExtraContents( int offset, const ImVec2& wpos, float labelWidth, double pxns, bool hover ) override;

    bool DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax ) override;
    void DrawOverlay( const ImVec2& ul, const ImVec2& dr ) override;

    bool IsEmpty() const override;

private:
    const ThreadData* m_thread;
    bool m_ghost;
};

}

#endif
