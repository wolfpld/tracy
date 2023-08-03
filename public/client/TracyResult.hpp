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
        auto operator co_await();
    };

    template<class BaseResultType>
    Result<BaseResultType>::Result(BaseResultType&& result)
        : BaseResultType(std::forward<BaseResultType>(result))
    {
    }

    template<class BaseResultType>
    auto Result<BaseResultType>::operator co_await()
    {
        return Awaitable(BaseResultType::operator co_await());
    }
}

template<template<class> class original_result, class type, class... arguments>
struct std::coroutine_traits<tracy::Result<original_result<type>>, arguments...>
{
    using promise_type = typename coroutine_traits<original_result<type>, arguments...>::promise_type;
};
