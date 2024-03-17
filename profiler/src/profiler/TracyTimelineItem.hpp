#ifndef __TRACYTIMELINEITEM_HPP__
#define __TRACYTIMELINEITEM_HPP__

#include <assert.h>
#include <stdint.h>

#include "imgui.h"

namespace tracy
{

struct TimelineContext;
class TaskDispatch;
class View;
class Worker;

class TimelineItem
{
public:
    TimelineItem( View& view, Worker& worker, const void* key, bool wantPreprocess );
    virtual ~TimelineItem() = default;

    // draws the timeline item and also updates the next frame height value
    void Draw( bool firstFrame, const TimelineContext& ctx, int yOffset );

    bool WantPreprocess() const { return m_wantPreprocess; }
    virtual void Preprocess( const TimelineContext& ctx, TaskDispatch& td, bool visible, int yPos ) { assert( false ); }

    void VisibilityCheckbox();
    virtual void SetVisible( bool visible ) { m_visible = visible; }
    virtual bool IsVisible() const { return m_visible; }

    void SetShowFull( bool showFull ) { m_showFull = showFull; }

    // returns 0 instead of the correct value for the first frame
    int GetHeight() const { return m_height; }

    const void* GetKey() const { return m_key; }

protected:
    virtual uint32_t HeaderColor() const = 0;
    virtual uint32_t HeaderColorInactive() const = 0;
    virtual uint32_t HeaderLineColor() const = 0;
    virtual const char* HeaderLabel() const = 0;

    virtual void HeaderTooltip( const char* label ) const {};
    virtual void HeaderExtraContents( const TimelineContext& ctx, int offset, float labelWidth ) {};

    virtual int64_t RangeBegin() const = 0;
    virtual int64_t RangeEnd() const = 0;

    virtual bool DrawContents( const TimelineContext& ctx, int& offset ) = 0;
    virtual void DrawOverlay( const ImVec2& ul, const ImVec2& dr ) {}
    virtual void DrawFinished() {}

    virtual bool IsEmpty() const { return false; }

    bool m_visible;
    bool m_showFull;

private:
    void AdjustThreadHeight( bool firstFrame, int yBegin, int yEnd );

    int m_height;
    bool m_wantPreprocess;

    const void* m_key;

protected:
    View& m_view;
    Worker& m_worker;
};

}

#endif
