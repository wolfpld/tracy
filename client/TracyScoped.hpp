#ifndef __TRACYSCOPED_HPP__
#define __TRACYSCOPED_HPP__

#include <stdint.h>
#include <string.h>

#include "../common/TracySystem.hpp"
#include "TracyProfiler.hpp"

namespace tracy
{

class ScopedZone
{
public:
    tracy_force_inline ScopedZone( const SourceLocation* srcloc )
        : m_id( Profiler::GetNewId() )
    {
        Magic magic;
        auto item = Profiler::StartItem( magic );
        item->hdr.type = QueueType::ZoneBegin;
        item->hdr.id = m_id;
        item->zoneBegin.time = Profiler::GetTime( item->zoneBegin.cpu );
        item->zoneBegin.srcloc = (uint64_t)srcloc;
        item->zoneBegin.thread = GetThreadHandle();
        Profiler::FinishItem( magic );
    }

    tracy_force_inline ~ScopedZone()
    {
        Magic magic;
        auto item = Profiler::StartItem( magic );
        item->hdr.type = QueueType::ZoneEnd;
        item->hdr.id = m_id;
        item->zoneEnd.time = Profiler::GetTime( item->zoneEnd.cpu );
        Profiler::FinishItem( magic );
    }

    tracy_force_inline void Text( const char* txt, size_t size )
    {
        Magic magic;
        auto ptr = new char[size+1];
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto item = Profiler::StartItem( magic );
        item->hdr.type = QueueType::ZoneText;
        item->hdr.id = m_id;
        item->zoneText.text = (uint64_t)ptr;
        Profiler::FinishItem( magic );
    }

    tracy_force_inline void Name( const char* name )
    {
        Magic magic;
        auto item = Profiler::StartItem( magic );
        item->hdr.type = QueueType::ZoneName;
        item->hdr.id = m_id;
        item->zoneName.name = (uint64_t)name;
        Profiler::FinishItem( magic );
    }

private:
    uint64_t m_id;
};

}

#endif
