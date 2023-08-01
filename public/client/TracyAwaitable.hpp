#pragma once

#include "TracyAsyncEvents.hpp"

#include <type_traits>

namespace tracy
{
    template<class BaseAwaitableType>
    class Awaitable : public BaseAwaitableType
    {
    public:
        Awaitable(BaseAwaitableType baseAwaitable);
#if DEBUG_TEMP
        ~Awaitable();
#endif
        auto await_suspend(auto handle);
        auto await_resume();

    private:
        AsyncScopedZone* m_pCurrentZone = nullptr;
    };

    template<class BaseAwaitableType>
    Awaitable<BaseAwaitableType>::Awaitable(BaseAwaitableType baseAwaitable)
        : BaseAwaitableType(std::move(baseAwaitable))
    {
#if DEBUG_TEMP
        std::osyncstream(std::cout) << "Awaitable: constructor"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
#endif
    }

#if DEBUG_TEMP
    template <class BaseAwaitableType>
    Awaitable<BaseAwaitableType>::~Awaitable()
    {
        std::osyncstream(std::cout) << "Awaitable: destructor"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
    }
#endif

    template<class BaseAwaitableType>
    auto Awaitable<BaseAwaitableType>::await_suspend(auto handle)
    {
#if DEBUG_TEMP
        std::osyncstream(std::cout) << "Awaitable: await_suspend"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
#endif

        if (g_pCurrentZone)
        {
#if DEBUG_TEMP
            std::osyncstream(std::cout) << "Awaitable: await_suspend, StopAsyncEvent"
                << ", location: " << g_pCurrentZone->m_pSourceLocation->function
                << ", fiber: " << g_pCurrentZone->m_nFiber
                << ", thread id: " << std::this_thread::get_id()
                << ", frame: " << GetProfiler().GetFrame()
                << std::endl;
#endif

            m_pCurrentZone = g_pCurrentZone;
            g_pCurrentZone = nullptr;
            StopAsyncEvent();
        }

        return BaseAwaitableType::await_suspend(handle);
    }

    template<class BaseAwaitableType>
    auto Awaitable<BaseAwaitableType>::await_resume()
    {
#if DEBUG_TEMP
        std::osyncstream(std::cout) << "Awaitable: await_resume"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
#endif

        if (m_pCurrentZone)
        {
#if DEBUG_TEMP
            std::osyncstream(std::cout) << "Awaitable: await_resume, StartAsyncEvent"
                << ", location: " << m_pCurrentZone->m_pSourceLocation->function
                << ", fiber: " << m_pCurrentZone->m_nFiber
                << ", thread id: " << std::this_thread::get_id()
                << ", frame: " << GetProfiler().GetFrame()
                << std::endl;
#endif

            StartAsyncEvent(m_pCurrentZone
#if DEBUG_TEMP
                , m_pCurrentZone->m_nFiber
#endif
            );
            g_pCurrentZone = m_pCurrentZone;
            m_pCurrentZone = nullptr;
        }

        return BaseAwaitableType::await_resume();
    }
}
