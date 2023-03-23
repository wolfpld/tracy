#ifndef __TRACYTIMELINEITEMTHREAD_HPP__
#define __TRACYTIMELINEITEMTHREAD_HPP__

#include "TracyEvent.hpp"
#include "TracyTimelineItem.hpp"
#include "TracyTimelineDraw.hpp"

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
    void HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth ) override;

    bool DrawContents( const TimelineContext& ctx, int& offset ) override;
    void DrawOverlay( const ImVec2& ul, const ImVec2& dr ) override;
    void DrawFinished() override;

    bool IsEmpty() const override;

    void Preprocess( const TimelineContext& ctx, TaskDispatch& td ) override;

private:
#ifndef TRACY_NO_STATISTICS
    int PreprocessGhostLevel( const TimelineContext& ctx, const Vector<GhostZone>& vec, int depth );
#endif
    int PreprocessZoneLevel( const TimelineContext& ctx, const Vector<short_ptr<ZoneEvent>>& vec, int depth );

    template<typename Adapter, typename V>
    int PreprocessZoneLevel( const TimelineContext& ctx, const V& vec, int depth );

    void PreprocessContextSwitches( const TimelineContext& ctx, const ContextSwitch& ctxSwitch );
    void PreprocessSamples( const TimelineContext& ctx, const Vector<SampleData>& vec );
    void PreprocessMessages( const TimelineContext& ctx, const Vector<short_ptr<MessageData>>& vec, uint64_t tid );

    const ThreadData* m_thread;
    bool m_ghost;

    std::vector<SamplesDraw> m_samplesDraw;
    std::vector<ContextSwitchDraw> m_ctxDraw;
    std::vector<TimelineDraw> m_draw;
    std::vector<MessagesDraw> m_msgDraw;
    int m_depth;
};

}

#endif
