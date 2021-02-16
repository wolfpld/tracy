#ifndef __TRACYSCOPED_HPP__
#define __TRACYSCOPED_HPP__

#include <limits>
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
    ScopedZone( const ScopedZone& ) = delete;
    ScopedZone( ScopedZone&& ) = delete;
    ScopedZone& operator=( const ScopedZone& ) = delete;
    ScopedZone& operator=( ScopedZone&& ) = delete;

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
        GetProfiler().SendCallstack( depth );

        TracyLfqPrepare( QueueType::ZoneBeginCallstack );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        TracyLfqCommit;
    }

    tracy_force_inline ScopedZone( uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, bool is_active = true )
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
        TracyLfqPrepare( QueueType::ZoneBeginAllocSrcLoc );
        const auto srcloc = Profiler::AllocSourceLocation( line, source, sourceSz, function, functionSz, name, nameSz );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, srcloc );
        TracyLfqCommit;
    }

    tracy_force_inline ScopedZone( uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz, int depth, bool is_active = true )
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
        GetProfiler().SendCallstack( depth );

        TracyLfqPrepare( QueueType::ZoneBeginAllocSrcLocCallstack );
        const auto srcloc = Profiler::AllocSourceLocation( line, source, sourceSz, function, functionSz, name, nameSz );
        MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
        MemWrite( &item->zoneBegin.srcloc, srcloc );
        TracyLfqCommit;
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
        assert( size < std::numeric_limits<uint16_t>::max() );
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        auto ptr = (char*)tracy_malloc( size );
        memcpy( ptr, txt, size );
        TracyLfqPrepare( QueueType::ZoneText );
        MemWrite( &item->zoneTextFat.text, (uint64_t)ptr );
        MemWrite( &item->zoneTextFat.size, (uint16_t)size );
        TracyLfqCommit;
    }

    tracy_force_inline void Name( const char* txt, size_t size )
    {
        assert( size < std::numeric_limits<uint16_t>::max() );
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        auto ptr = (char*)tracy_malloc( size );
        memcpy( ptr, txt, size );
        TracyLfqPrepare( QueueType::ZoneName );
        MemWrite( &item->zoneTextFat.text, (uint64_t)ptr );
        MemWrite( &item->zoneTextFat.size, (uint16_t)size );
        TracyLfqCommit;
    }

    tracy_force_inline void Color( uint32_t color )
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        TracyLfqPrepare( QueueType::ZoneColor );
        MemWrite( &item->zoneColor.r, uint8_t( ( color       ) & 0xFF ) );
        MemWrite( &item->zoneColor.g, uint8_t( ( color >> 8  ) & 0xFF ) );
        MemWrite( &item->zoneColor.b, uint8_t( ( color >> 16 ) & 0xFF ) );
        TracyLfqCommit;
    }

    tracy_force_inline void Value( uint64_t value )
    {
        if( !m_active ) return;
#ifdef TRACY_ON_DEMAND
        if( GetProfiler().ConnectionId() != m_connectionId ) return;
#endif
        TracyLfqPrepare( QueueType::ZoneValue );
        MemWrite( &item->zoneValue.value, value );
        TracyLfqCommit;
    }

    tracy_force_inline bool IsActive() const { return m_active; }

private:
    const bool m_active;

#ifdef TRACY_ON_DEMAND
    uint64_t m_connectionId;
#endif
};

}

#endif
