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
        , m_connectionId( GetProfiler().ConnectionId() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        char* nextPtr;
        auto item = LfqProducer::PrepareNext( nextPtr, QueueType::ZoneBegin );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        LfqProducer::CommitNext( nextPtr );
    }

    tracy_force_inline ScopedZone( const SourceLocationData* srcloc, int depth, bool is_active = true )
#ifdef TRACY_ON_DEMAND
        : m_active( is_active && GetProfiler().IsConnected() )
        , m_connectionId( GetProfiler().ConnectionId() )
#else
        : m_active( is_active )
#endif
    {
        if( !m_active ) return;
        char* nextPtr;
        auto item = LfqProducer::PrepareNext( nextPtr, QueueType::ZoneBeginCallstack );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        LfqProducer::CommitNext( nextPtr );

        GetProfiler().SendCallstack( depth );
    }

    tracy_force_inline ~ScopedZone()
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        char* nextPtr;
        auto item = LfqProducer::PrepareNext( nextPtr, QueueType::ZoneEnd );
        MemWrite( &item->zoneEnd.time, Profiler::GetTime() );
        LfqProducer::CommitNext( nextPtr );
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
        char* nextPtr;
        auto item = LfqProducer::PrepareNext( nextPtr, QueueType::ZoneText );
        MemWrite( &item->zoneText.text, (uint64_t)ptr );
        LfqProducer::CommitNext( nextPtr );
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
        char* nextPtr;
        auto item = LfqProducer::PrepareNext( nextPtr, QueueType::ZoneName );
        MemWrite( &item->zoneText.text, (uint64_t)ptr );
        LfqProducer::CommitNext( nextPtr );
    }

private:
    const bool m_active;

#ifdef TRACY_ON_DEMAND
    uint64_t m_connectionId;
#endif
};

}

#endif
