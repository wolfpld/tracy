#pragma once

#include "TracyAwaitable.hpp"

#include <coroutine>

namespace tracy
{
    template<class BaseResultType>
    class Result : public BaseResultType
    {
    public:
        Result(BaseResultType&& result);
#if DEBUG_TEMP
        ~Result();
#endif
        auto operator co_await();
    };

    template<class BaseResultType>
    Result<BaseResultType>::Result(BaseResultType&& result)
        : BaseResultType(std::forward<BaseResultType>(result))
    {
#if DEBUG_TEMP
        std::osyncstream(std::cout) << "Result: constructor"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
#endif
    }

#if DEBUG_TEMP
    template <class BaseResultType>
    Result<BaseResultType>::~Result()
    {
        std::osyncstream(std::cout) << "Result: destructor"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
    }
#endif

    template<class BaseResultType>
    auto Result<BaseResultType>::operator co_await()
    {
#if DEBUG_TEMP
        std::osyncstream(std::cout) << "Result: operator co_await"
            << ", thread id: " << std::this_thread::get_id()
            << ", frame: " << GetProfiler().GetFrame()
            << std::endl;
#endif

        return Awaitable(BaseResultType::operator co_await());
    }
}

template<template<class> class original_result, class type, class... arguments>
struct std::coroutine_traits<tracy::Result<original_result<type>>, arguments...>
{
    using promise_type = typename coroutine_traits<original_result<type>, arguments...>::promise_type;
};
