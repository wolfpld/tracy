#ifndef __TRACYSCOPED_HPP__
#define __TRACYSCOPED_HPP__

#include <stdint.h>

#include "TracyProfiler.hpp"
#include "TracyThread.hpp"

namespace tracy
{

class ScopedZone
{
public:
    ScopedZone( const char* file, const char* function, uint32_t line )
        : m_id( Profiler::ZoneBegin( QueueZoneBegin { Profiler::GetTime(), (uint64_t)file, (uint64_t)function, line, GetThreadHandle() } ) )
    {
    }

    ~ScopedZone()
    {
        Profiler::ZoneEnd( m_id, QueueZoneEnd { Profiler::GetTime() } );
    }

private:
    uint64_t m_id;
};

}

#endif
