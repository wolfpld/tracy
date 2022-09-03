#ifndef __TRACYTIMELINEITEM_HPP__
#define __TRACYTIMELINEITEM_HPP__

#include <stdint.h>

#include "imgui.h"

namespace tracy
{

class View;
class Worker;

class TimelineItem
{
public:
    TimelineItem( View& view, Worker& worker );
    virtual ~TimelineItem() = default;

    void Draw( bool firstFrame, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax );
    virtual bool DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax ) = 0;

    virtual bool IsEmpty() const { return false; }

    void VisibilityCheckbox();
    void SetVisible( bool visible ) { m_visible = visible; }

protected:
    virtual uint32_t HeaderColor() const = 0;
    virtual uint32_t HeaderColorInactive() const = 0;
    virtual uint32_t HeaderLineColor() const = 0;
    virtual const char* HeaderLabel() const = 0;

    virtual void HeaderTooltip( const char* label ) const {};
    virtual void HeaderExtraContents( int offset, const ImVec2& wpos, float labelWidth, double pxns, bool hover ) {};

    virtual int64_t RangeBegin() const = 0;
    virtual int64_t RangeEnd() const = 0;

private:
    void AdjustThreadHeight( bool firstFrame, int oldOffset, int& offset );
    float AdjustThreadPosition( float wy, int& offset );

    bool m_visible;
    bool m_showFull;
    int m_height;
    int m_offset;

protected:
    View& m_view;
    Worker& m_worker;
};

}

#endif
