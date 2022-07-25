#ifndef __WINDOWPOSITION_HPP__
#define __WINDOWPOSITION_HPP__

#include <string>

class WindowPosition
{
public:
    WindowPosition();
    ~WindowPosition();

    int x, y, w, h, maximize;

private:
    void Defaults();

    std::string m_fn;
};

#endif
