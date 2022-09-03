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
    TimelineItem( View& view, const Worker& worker );
    virtual ~TimelineItem() = default;

    void Draw( bool firstFrame, double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax );
    virtual void DrawContents( double pxns, int& offset, const ImVec2& wpos, bool hover, float yMin, float yMax ) = 0;

    virtual bool IsEmpty() const { return false; }

    void VisibilityCheckbox();

protected:
    virtual uint32_t HeaderColor() const = 0;
    virtual uint32_t HeaderColorInactive() const = 0;
    virtual uint32_t HeaderLineColor() const = 0;
    virtual const char* HeaderLabel() const = 0;

    virtual void HeaderTooltip( const char* label ) const {};
    virtual void HeaderExtraContents( int offset, const ImVec2& wpos, float labelWidth ) {};

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
    const Worker& m_worker;
};

}

#endif
