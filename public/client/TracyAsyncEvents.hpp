#pragma once

#include "TracyProfiler.hpp"

#if 0
    #define ASSERT(x)
#else
    #define ASSERT(x) if(!(x)) __debugbreak();
#endif

namespace tracy
{
    class AsyncScopedZone;
    struct SourceLocationData;
    inline thread_local AsyncScopedZone* g_pCurrentZone = nullptr;

    void StartAsyncEvent(AsyncScopedZone* pAsyncScopedZone);
    void StopAsyncEvent(AsyncScopedZone* pAsyncScopedZone);

    class AsyncScopedZone
    {
    public:
        AsyncScopedZone(const SourceLocationData* pSourceLocation);
        ~AsyncScopedZone();

        // private:
        const SourceLocationData* const m_pSourceLocation = nullptr;
        AsyncScopedZone* m_pParent = nullptr;
        // std::thread::id m_LockThreadId;
    };
}

inline void tracy::StartAsyncEvent(AsyncScopedZone* pAsyncScopedZone)
{
    ASSERT(pAsyncScopedZone);
    ASSERT(!g_pCurrentZone);
    // pAsyncScopedZone->m_LockThreadId = std::this_thread::get_id();
    g_pCurrentZone = pAsyncScopedZone;

    TracyQueuePrepare( QueueType::ZoneBegin );
    MemWrite( &item->zoneBegin.time, Profiler::GetTime() );
    MemWrite( &item->zoneBegin.srcloc, (uint64_t)pAsyncScopedZone->m_pSourceLocation );
    TracyQueueCommit( zoneBeginThread );
}

inline void tracy::StopAsyncEvent(AsyncScopedZone* pAsyncScopedZone)
{
    ASSERT(pAsyncScopedZone);
    ASSERT(pAsyncScopedZone == g_pCurrentZone);
    // ASSERT(pAsyncScopedZone->m_LockThreadId == std::this_thread::get_id());
    g_pCurrentZone = nullptr;

    TracyQueuePrepare(QueueType::ZoneEnd);
    MemWrite(&item->zoneEnd.time, Profiler::GetTime());
    TracyQueueCommit(zoneEndThread);
}

inline tracy::AsyncScopedZone::AsyncScopedZone(const SourceLocationData* pSourceLocation)
    : m_pSourceLocation(pSourceLocation)
{
    if (g_pCurrentZone)
    {
        m_pParent = g_pCurrentZone;
        StopAsyncEvent(g_pCurrentZone);
    }

    StartAsyncEvent(this);
}

inline tracy::AsyncScopedZone::~AsyncScopedZone()
{
    if (g_pCurrentZone)
    {
        auto pZoneToContinue = g_pCurrentZone->m_pParent;
        StopAsyncEvent(g_pCurrentZone);
        if (pZoneToContinue)
            StartAsyncEvent(pZoneToContinue);
    }
}
