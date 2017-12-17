#ifndef __TRACYLOCK_HPP__
#define __TRACYLOCK_HPP__

#include <atomic>
#include <limits>

#include "../common/TracySystem.hpp"
#include "TracyProfiler.hpp"

namespace tracy
{

extern std::atomic<uint32_t> s_lockCounter;

template<class T>
class Lockable
{
public:
    tracy_force_inline Lockable( const SourceLocation* srcloc )
        : m_id( s_lockCounter.fetch_add( 1, std::memory_order_relaxed ) )
    {
        assert( m_id != std::numeric_limits<uint32_t>::max() );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockAnnounce;
        item->lockAnnounce.id = m_id;
        item->lockAnnounce.lckloc = (uint64_t)srcloc;
        item->lockAnnounce.type = LockType::Lockable;
        tail.store( magic + 1, std::memory_order_release );
    }

    Lockable( const Lockable& ) = delete;
    Lockable& operator=( const Lockable& ) = delete;

    tracy_force_inline void lock()
    {
        const auto thread = GetThreadHandle();
        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockWait;
            item->lockWait.id = m_id;
            item->lockWait.thread = thread;
            item->lockWait.time = Profiler::GetTime();
            item->lockWait.type = LockType::Lockable;
            tail.store( magic + 1, std::memory_order_release );
        }

        m_lockable.lock();

        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockObtain;
            item->lockObtain.id = m_id;
            item->lockObtain.thread = thread;
            item->lockObtain.time = Profiler::GetTime();
            tail.store( magic + 1, std::memory_order_release );
        }
    }

    tracy_force_inline void unlock()
    {
        m_lockable.unlock();

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockRelease;
        item->lockRelease.id = m_id;
        item->lockRelease.thread = GetThreadHandle();
        item->lockRelease.time = Profiler::GetTime();
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline bool try_lock()
    {
        const auto ret = m_lockable.try_lock();
        if( ret )
        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockObtain;
            item->lockObtain.id = (uint64_t)&m_lockable;
            item->lockObtain.thread = GetThreadHandle();
            item->lockObtain.time = Profiler::GetTime();
            tail.store( magic + 1, std::memory_order_release );
        }
        return ret;
    }

    tracy_force_inline void Mark( const SourceLocation* srcloc ) const
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockMark;
        item->lockMark.id = m_id;
        item->lockMark.thread = GetThreadHandle();
        item->lockMark.srcloc = (uint64_t)srcloc;
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    T m_lockable;
    uint32_t m_id;
};


template<class T>
class SharedLockable
{
public:
    tracy_force_inline SharedLockable( const SourceLocation* srcloc )
        : m_id( s_lockCounter.fetch_add( 1, std::memory_order_relaxed ) )
    {
        assert( m_id != std::numeric_limits<uint32_t>::max() );

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockAnnounce;
        item->lockAnnounce.id = m_id;
        item->lockAnnounce.lckloc = (uint64_t)srcloc;
        item->lockAnnounce.type = LockType::SharedLockable;
        tail.store( magic + 1, std::memory_order_release );
    }

    SharedLockable( const SharedLockable& ) = delete;
    SharedLockable& operator=( const SharedLockable& ) = delete;

    tracy_force_inline void lock()
    {
        const auto thread = GetThreadHandle();
        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockWait;
            item->lockWait.id = m_id;
            item->lockWait.thread = thread;
            item->lockWait.time = Profiler::GetTime();
            item->lockWait.type = LockType::SharedLockable;
            tail.store( magic + 1, std::memory_order_release );
        }

        m_lockable.lock();

        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockObtain;
            item->lockObtain.id = m_id;
            item->lockObtain.thread = thread;
            item->lockObtain.time = Profiler::GetTime();
            tail.store( magic + 1, std::memory_order_release );
        }
    }

    tracy_force_inline void unlock()
    {
        m_lockable.unlock();

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockRelease;
        item->lockRelease.id = m_id;
        item->lockRelease.thread = GetThreadHandle();
        item->lockRelease.time = Profiler::GetTime();
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline bool try_lock()
    {
        const auto ret = m_lockable.try_lock();
        if( ret )
        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockObtain;
            item->lockObtain.id = (uint64_t)&m_lockable;
            item->lockObtain.thread = GetThreadHandle();
            item->lockObtain.time = Profiler::GetTime();
            tail.store( magic + 1, std::memory_order_release );
        }
        return ret;
    }

    tracy_force_inline void lock_shared()
    {
        const auto thread = GetThreadHandle();
        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockSharedWait;
            item->lockWait.id = m_id;
            item->lockWait.thread = thread;
            item->lockWait.time = Profiler::GetTime();
            item->lockWait.type = LockType::SharedLockable;
            tail.store( magic + 1, std::memory_order_release );
        }

        m_lockable.lock_shared();

        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockSharedObtain;
            item->lockObtain.id = m_id;
            item->lockObtain.thread = thread;
            item->lockObtain.time = Profiler::GetTime();
            tail.store( magic + 1, std::memory_order_release );
        }
    }

    tracy_force_inline void unlock_shared()
    {
        m_lockable.unlock_shared();

        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockSharedRelease;
        item->lockRelease.id = m_id;
        item->lockRelease.thread = GetThreadHandle();
        item->lockRelease.time = Profiler::GetTime();
        tail.store( magic + 1, std::memory_order_release );
    }

    tracy_force_inline bool try_lock_shared()
    {
        const auto ret = m_lockable.try_lock_shared();
        if( ret )
        {
            Magic magic;
            auto& token = s_token.ptr;
            auto& tail = token->get_tail_index();
            auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
            item->hdr.type = QueueType::LockSharedObtain;
            item->lockObtain.id = (uint64_t)&m_lockable;
            item->lockObtain.thread = GetThreadHandle();
            item->lockObtain.time = Profiler::GetTime();
            tail.store( magic + 1, std::memory_order_release );
        }
        return ret;
    }

    tracy_force_inline void Mark( const SourceLocation* srcloc ) const
    {
        Magic magic;
        auto& token = s_token.ptr;
        auto& tail = token->get_tail_index();
        auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
        item->hdr.type = QueueType::LockMark;
        item->lockMark.id = m_id;
        item->lockMark.thread = GetThreadHandle();
        item->lockMark.srcloc = (uint64_t)srcloc;
        tail.store( magic + 1, std::memory_order_release );
    }

private:
    T m_lockable;
    uint32_t m_id;
};


};

#endif
