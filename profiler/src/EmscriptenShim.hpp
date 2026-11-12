#ifndef __EMSCRIPTENSHIM_HPP__
#define __EMSCRIPTENSHIM_HPP__

#include <atomic>
#include <memory>

// Any standard library without std::atomic<std::shared_ptr> (P0718), such as libc++ on any platform
#if !defined __cpp_lib_atomic_shared_ptr

namespace std {

template<typename T>
struct atomic<shared_ptr<T>> {
    shared_ptr<T> value;

    bool compare_exchange_weak(shared_ptr<T>& expected, const shared_ptr<T>& desired) noexcept {
        return atomic_compare_exchange_weak_explicit(&value, &expected, desired, std::memory_order_acq_rel, std::memory_order_acquire);
    }

    shared_ptr<T> load(memory_order order = std::memory_order_seq_cst) const noexcept {
        return atomic_load_explicit(&value, order);
    }

    void store(shared_ptr<T> desired, memory_order order = std::memory_order_seq_cst) noexcept {
        atomic_store_explicit(&value, desired, order);
    }
};

} // namespace std

#endif

#endif
