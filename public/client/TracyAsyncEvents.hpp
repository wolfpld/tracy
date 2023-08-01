#pragma once

#include "TracyProfiler.hpp"

#define DEBUG_TEMP 1
#if DEBUG_TEMP
#include <syncstream>
#include <iostream>
#include <string>
#endif

namespace tracy
{
    class AsyncScopedZone;
    struct SourceLocationData;
    inline thread_local tracy::AsyncScopedZone* g_pCurrentZone = nullptr;

    void StartAsyncEvent(const AsyncScopedZone* pAsyncScopedZone
#if DEBUG_TEMP
        , size_t nFiber
#endif
    );
    void StopAsyncEvent();

    class AsyncScopedZone
    {
    public:
        AsyncScopedZone(const SourceLocationData* pSourceLocation
#if DEBUG_TEMP
            , size_t nFiber
#endif
        );
        ~AsyncScopedZone();

        // private:
        const SourceLocationData* const m_pSourceLocation = nullptr;
#if DEBUG_TEMP
        const size_t m_nFiber = -1;
#endif
        AsyncScopedZone* m_pParent = nullptr;
    };
}


tracy_force_inline void tracy::StartAsyncEvent(const AsyncScopedZone* pAsyncScopedZone
#if DEBUG_TEMP
    , size_t nFiber
#endif
)
{
    TracyQueuePrepare( QueueType::ZoneBegin );
    MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
    MemWrite( &item->zoneBegin.srcloc, (uint64_t)pAsyncScopedZone->m_pSourceLocation );
    TracyQueueCommit( zoneBeginThread );

#if DEBUG_TEMP
    if (nFiber == 0)
    {
        const std::string sMessage = "fiber: " + std::to_string(nFiber);
        tracy::Profiler::Message(sMessage.c_str(), sMessage.size(), 0);
    }
#endif
}

tracy_force_inline void tracy::StopAsyncEvent()
{
    TracyQueuePrepare(QueueType::ZoneEnd);
    MemWrite(&item->zoneEnd.time, Profiler::GetTime());
    TracyQueueCommit(zoneEndThread);
}

tracy_force_inline tracy::AsyncScopedZone::AsyncScopedZone(const SourceLocationData* pSourceLocation
#if DEBUG_TEMP
    , size_t nFiber
#endif
)
    : m_pSourceLocation(pSourceLocation)
#if DEBUG_TEMP
    , m_nFiber(nFiber)
#endif
{
    if (g_pCurrentZone)
    {
#if DEBUG_TEMP
        std::osyncstream(std::cout) << "AsyncScopedZone: constructor, StopAsyncEvent"
            << ", location: " << g_pCurrentZone->m_pSourceLocation->function
            << ", fiber: " << nFiber
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
#endif

        m_pParent = g_pCurrentZone;
        StopAsyncEvent();
    }

#if DEBUG_TEMP
    std::osyncstream(std::cout) << "AsyncScopedZone: constructor, StartAsyncEvent"
        << ", location: " << pSourceLocation->function
        << ", fiber: " << nFiber
        << ", thread id: " << std::this_thread::get_id()
        << ", frame: " << GetProfiler().GetFrame()
        << std::endl;
#endif

    g_pCurrentZone = this;
    StartAsyncEvent(this
#if DEBUG_TEMP
        , nFiber
#endif
    );
}

tracy_force_inline tracy::AsyncScopedZone::~AsyncScopedZone()
{
    if (g_pCurrentZone)
    {
        StopAsyncEvent();
        g_pCurrentZone = g_pCurrentZone->m_pParent;
        if (g_pCurrentZone)
            StartAsyncEvent(g_pCurrentZone
#if DEBUG_TEMP
                , g_pCurrentZone->m_nFiber
#endif
            );
    }
}
