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
        ~Awaitable();

    private:
        AsyncScopedZone* m_pCurrentZone = nullptr;
    };

    template<class BaseAwaitableType>
    Awaitable<BaseAwaitableType>::Awaitable(BaseAwaitableType baseAwaitable)
        : BaseAwaitableType(std::move(baseAwaitable))
    {
        if (g_pCurrentZone)
        {
            m_pCurrentZone = g_pCurrentZone;
            StopAsyncEvent(g_pCurrentZone);
        }
    }

    template <class BaseAwaitableType>
    Awaitable<BaseAwaitableType>::~Awaitable()
    {
        if (m_pCurrentZone)
            StartAsyncEvent(m_pCurrentZone);
    }
}
