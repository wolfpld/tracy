#ifndef __TRACYMANUALWINDOW_HPP__
#define __TRACYMANUALWINDOW_HPP__

#include <stddef.h>

#include "TracyManualData.hpp"

namespace tracy
{

class Markdown;

class ManualWindow
{
public:
    explicit ManualWindow( const TracyManualData& manual );

    void Draw( Markdown& md );
    bool& Show() { return m_show; }

    bool Navigate( const char* anchor );
    const TracyManualData::ManualChunk* GetChunk( const char* anchor ) const;

private:
    const TracyManualData& m_manual;
    size_t m_activeChunk = 0;
    bool m_positionReset = true;
    bool m_show = false;
};

}

#endif
