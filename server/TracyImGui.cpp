#include "TracyImGui.hpp"

namespace tracy
{

void DrawZigZag( ImDrawList* draw, const ImVec2& wpos, double start, double end, double h, uint32_t color, float thickness )
{
    const auto dpos = wpos + ImVec2( 0.5f, 0.5f );

    const auto spanSz = end - start;
    if( spanSz <= h * 0.5 )
    {
        DrawLine( draw, dpos + ImVec2( start, 0 ), wpos + ImVec2( start + spanSz, round( -spanSz ) ), color, thickness );
        return;
    }

    const auto h05 = round( h * 0.5 );
    const auto h2 = h*2;
    int steps = int( ( end - start ) / h2 );

    auto path = (ImVec2*)alloca( sizeof( ImVec2 ) * ( 2 * steps + 4 ) );
    auto ptr = path;

    *ptr++ = dpos + ImVec2( start, 0 );
    *ptr++ = dpos + ImVec2( start + h05, -h05 );
    start += h05;

    while( steps-- )
    {
        *ptr++ = dpos + ImVec2( start + h,   h05 );
        *ptr++ = dpos + ImVec2( start + h2, -h05 );
        start += h2;
    }

    if( end - start <= h )
    {
        const auto span = end - start;
        *ptr++ = dpos + ImVec2( start + span, round( span - h*0.5 ) );
    }
    else
    {
        const auto span = end - start - h;
        *ptr++ = dpos + ImVec2( start + h, h05 );
        *ptr++ = dpos + ImVec2( start + h + span, round( h*0.5 - span ) );
    }

    draw->AddPolyline( path, ptr - path, color, 0, thickness );
}

}
