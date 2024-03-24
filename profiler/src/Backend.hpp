#ifndef __BACKEND_HPP__
#define __BACKEND_HPP__

#include <functional>
#include <stdint.h>

#include "WindowPosition.hpp"

class RunQueue;

class Backend
{
public:
    Backend( const char* title, const std::function<void()>& redraw, const std::function<void(float)>& scaleChanged, const std::function<int(void)>& isBusy, RunQueue* mainThreadTasks );
    ~Backend();

    void Show();
    void Run();
    void Attention();

    void NewFrame( int& w, int& h );
    void EndFrame();

    void SetIcon( uint8_t* data, int w, int h );
    void SetTitle( const char* title );

    float GetDpiScale();

private:
    WindowPosition m_winPos;
    int m_w, m_h;
};

#endif
