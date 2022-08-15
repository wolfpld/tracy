#ifndef __TRACYTIMELINECONTROLLER_HPP__
#define __TRACYTIMELINECONTROLLER_HPP__

namespace tracy
{

class TimelineController
{
public:
    TimelineController();

    void End( float offset );

    float GetHeight() const { return m_height; }

private:
    float m_height;
    float m_offset;
    float m_scroll;
};

}

#endif
