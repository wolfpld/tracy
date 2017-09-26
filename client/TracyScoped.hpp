#ifndef __TRACYSCOPED_HPP__
#define __TRACYSCOPED_HPP__

#include <stdint.h>

#include "../common/TracySystem.hpp"
#include "TracyProfiler.hpp"

namespace tracy
{

class ScopedZone
{
public:
    ScopedZone( const SourceLocation* srcloc, uint32_t color )
        : m_id( Profiler::ZoneBegin( QueueZoneBegin { Profiler::GetTime(), (uint64_t)srcloc, GetThreadHandle(), color } ) )
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
