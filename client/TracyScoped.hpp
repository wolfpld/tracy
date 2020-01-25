#ifndef __TRACYSCOPED_HPP__
#define __TRACYSCOPED_HPP__

#include <stdint.h>
#include <string.h>

#include "../common/TracySystem.hpp"
#include "../common/TracyAlign.hpp"
#include "../common/TracyAlloc.hpp"
#include "TracyProfiler.hpp"

namespace tracy
{

class ScopedZone
{
public:
    tracy_force_inline ScopedZone( const SourceLocationData* srcloc, bool is_active = true )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        m_connectionId = GetProfiler().ConnectionId();
#endif
        TracyLfqPrepare( QueueType::ZoneBegin );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        TracyLfqCommit;
    }

    tracy_force_inline ScopedZone( const SourceLocationData* srcloc, int depth, bool is_active = true )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        m_connectionId = GetProfiler().ConnectionId();
#endif
        TracyLfqPrepare( QueueType::ZoneBeginCallstack );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        TracyLfqCommit;

        GetProfiler().SendCallstack( depth );
    }

    tracy_force_inline ~ScopedZone()
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        TracyLfqPrepare( QueueType::ZoneEnd );
        MemWrite( &item->zoneEnd.time, Profiler::GetTime() );
        TracyLfqCommit;
    }

    tracy_force_inline void Text( const char* txt, size_t size )
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        TracyLfqPrepare( QueueType::ZoneText );
        MemWrite( &item->zoneText.text, (uint64_t)ptr );
        TracyLfqCommit;
    }

    tracy_force_inline void Name( const char* txt, size_t size )
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        TracyLfqPrepare( QueueType::ZoneName );
        MemWrite( &item->zoneText.text, (uint64_t)ptr );
        TracyLfqCommit;
    }

private:
    const bool m_active;

#ifdef TRACY_ON_DEMAND
    uint64_t m_connectionId;
#endif
};

}

#endif
