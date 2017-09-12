#ifndef __TRACYSCOPED_HPP__
#define __TRACYSCOPED_HPP__

#include <stdint.h>

#include "TracyProfiler.hpp"

namespace tracy
{

class ScopedZone
{
public:
    ScopedZone( const char* file, const char* function, uint32_t line )
        : m_id( Profiler::GetNewId() )
    {
        Profiler::ZoneBegin( QueueZoneBegin { m_id, (uint64_t)file, (uint64_t)function, line } );
    }

    ~ScopedZone()
    {
        Profiler::ZoneEnd( QueueZoneEnd { m_id } );
    }

private:
    uint64_t m_id;
};

}

#endif
