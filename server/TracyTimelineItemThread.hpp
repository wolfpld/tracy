#ifndef __TRACYTIMELINEITEMTHREAD_HPP__
#define __TRACYTIMELINEITEMTHREAD_HPP__

#include "TracyEvent.hpp"
#include "TracyTimelineDraw.hpp"
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
    void HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth ) override;

    bool DrawContents( const TimelineContext& ctx, int& offset ) override;
    void DrawOverlay( const ImVec2& ul, const ImVec2& dr ) override;
    void DrawFinished() override;

    bool IsEmpty() const override;

    void Preprocess( const TimelineContext& ctx, TaskDispatch& td, bool visible, int yPos ) override;

private:
#ifndef TRACY_NO_STATISTICS
    int PreprocessGhostLevel( const TimelineContext& ctx, const Vector<GhostZone>& vec, int depth, bool visible );
#endif
    int PreprocessZoneLevel( const TimelineContext& ctx, const Vector<short_ptr<ZoneEvent>>& vec, int depth, bool visible );

    template<typename Adapter, typename V>
    int PreprocessZoneLevel( const TimelineContext& ctx, const V& vec, int depth, bool visible );

    void PreprocessContextSwitches( const TimelineContext& ctx, const ContextSwitch& ctxSwitch, bool visible );
    void PreprocessSamples( const TimelineContext& ctx, const Vector<SampleData>& vec, bool visible, int yPos );
    void PreprocessMessages( const TimelineContext& ctx, const Vector<short_ptr<MessageData>>& vec, uint64_t tid, bool visible, int yPos );
    void PreprocessLocks( const TimelineContext& ctx, const unordered_flat_map<uint32_t, LockMap*>& locks, uint32_t tid, TaskDispatch& td, bool visible );

    const ThreadData* m_thread;
    bool m_ghost;

    std::vector<SamplesDraw> m_samplesDraw;
    std::vector<ContextSwitchDraw> m_ctxDraw;
    std::vector<TimelineDraw> m_draw;
    std::vector<MessagesDraw> m_msgDraw;
    std::vector<std::unique_ptr<LockDraw>> m_lockDraw;
    int m_depth;
    bool m_hasCtxSwitch;
    bool m_hasSamples;
    bool m_hasMessages;
};

}

#endif
