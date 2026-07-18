#ifndef __TRACYWINDOWCONSTRAINTS_HPP__
#define __TRACYWINDOWCONSTRAINTS_HPP__

namespace tracy
{

class WindowConstraints
{
public:
    void Reset();
    void Constrain() const;
    void MarkMinWidth();

private:
    float m_minWidth = 0;
};

}

#endif
