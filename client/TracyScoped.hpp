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
    ScopedZone( const SourceLocation* srcloc )
        : m_id( Profiler::GetNewId() )
    {
        auto item = Profiler::StartItem();
        item->hdr.type = QueueType::ZoneBegin;
        item->hdr.id = m_id;
        item->zoneBegin.time = Profiler::GetTime();
        item->zoneBegin.srcloc = (uint64_t)srcloc;
        item->zoneBegin.thread = GetThreadHandle();
        Profiler::FinishItem();
    }

    ~ScopedZone()
    {
        auto item = Profiler::StartItem();
        item->hdr.type = QueueType::ZoneEnd;
        item->hdr.id = m_id;
        item->zoneEnd.time = Profiler::GetTime();
        Profiler::FinishItem();
    }

    void Text( const char* txt, size_t size )
    {
        auto ptr = new char[size+1];
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto item = Profiler::StartItem();
        item->hdr.type = QueueType::ZoneText;
        item->hdr.id = m_id;
        item->zoneText.text = (uint64_t)ptr;
        Profiler::FinishItem();
    }

    void Name( const char* name )
    {
        auto item = Profiler::StartItem();
        item->hdr.type = QueueType::ZoneName;
        item->hdr.id = m_id;
        item->zoneName.name = (uint64_t)name;
        Profiler::FinishItem();
    }

private:
    uint64_t m_id;
};

}

#endif
