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
    ScopedZone( const SourceLocation* srcloc )
        : m_id( Profiler::ZoneBegin( QueueZoneBegin { Profiler::GetTime(), (uint64_t)srcloc, GetThreadHandle() } ) )
    {
    }

    ~ScopedZone()
    {
        Profiler::ZoneEnd( m_id, QueueZoneEnd { Profiler::GetTime() } );
    }

    void Text( const char* txt, size_t size )
    {
        auto ptr = new char[size+1];
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        Profiler::ZoneText( m_id, QueueZoneText { (uint64_t)ptr } );
    }

    void Name( const char* name )
    {
        Profiler::ZoneName( m_id, QueueZoneName { (uint64_t)name } );
    }

private:
    uint64_t m_id;
};

}

#endif
