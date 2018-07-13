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
    tracy_force_inline ScopedZone( const SourceLocation* srcloc )
#ifdef TRACY_ON_DEMAND
        : m_active( s_profiler.IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto thread = GetThreadHandle();
        m_thread = thread;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::ZoneBegin );
#ifdef TRACY_RDTSCP_OPT
        MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
        uint32_t cpu;
        MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
        MemWrite( &item->zoneBegin.cpu, cpu );
#endif
        MemWrite( &item->zoneBegin.thread, thread );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline ScopedZone( const SourceLocation* srcloc, int depth )
#ifdef TRACY_ON_DEMAND
        : m_active( s_profiler.IsConnected() )
#endif
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        const auto thread = GetThreadHandle();
        m_thread = thread;
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::ZoneBeginCallstack );
#ifdef TRACY_RDTSCP_OPT
        MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
        uint32_t cpu;
        MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
        MemWrite( &item->zoneBegin.cpu, cpu );
#endif
        MemWrite( &item->zoneBegin.thread, thread );
        MemWrite( &item->zoneBegin.srcloc, (uint64_t)srcloc );
        tail.store( magic + 1, std::memory_order_release );

        s_profiler.SendCallstack( depth, thread );
    }

    tracy_force_inline ~ScopedZone()
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::ZoneEnd );
#ifdef TRACY_RDTSCP_OPT
        MemWrite( &item->zoneEnd.time, Profiler::GetTime( item->zoneEnd.cpu ) );
#else
        uint32_t cpu;
        MemWrite( &item->zoneEnd.time, Profiler::GetTime( cpu ) );
        MemWrite( &item->zoneEnd.cpu, cpu );
#endif
        MemWrite( &item->zoneEnd.thread, m_thread );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline void Text( const char* txt, size_t size )
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::ZoneText );
        MemWrite( &item->zoneText.thread, m_thread );
        MemWrite( &item->zoneText.text, (uint64_t)ptr );
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline void Name( const char* txt, size_t size )
    {
#ifdef TRACY_ON_DEMAND
        if( !m_active ) return;
#endif
        Magic magic;
        auto& token = s_token.ptr;
        auto ptr = (char*)tracy_malloc( size+1 );
        memcpy( ptr, txt, size );
        ptr[size] = '\0';
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
        MemWrite( &item->hdr.type, QueueType::ZoneName );
        MemWrite( &item->zoneText.thread, m_thread );
        MemWrite( &item->zoneText.text, (uint64_t)ptr );
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    uint64_t m_thread;

#ifdef TRACY_ON_DEMAND
    const bool m_active;
#endif
};

}

#endif
