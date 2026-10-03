#ifndef __TRACYMEMORY_HPP__
#define __TRACYMEMORY_HPP__

#include <atomic>
#include <stdint.h>

namespace tracy
{

// Process-wide tracked allocation counter. Changes made on a thread that has
// a scope installed are also credited to that scope's counter.
class MemCounter
{
public:
    int64_t load( std::memory_order order ) const { return m_total.load( order ); }
    int64_t fetch_add( int64_t v, std::memory_order order ) { if( s_scope ) s_scope->fetch_add( v, order ); return m_total.fetch_add( v, order ); }
    int64_t fetch_sub( int64_t v, std::memory_order order ) { if( s_scope ) s_scope->fetch_sub( v, order ); return m_total.fetch_sub( v, order ); }

    static std::atomic<int64_t>* SetScope( std::atomic<int64_t>* scope ) { auto prev = s_scope; s_scope = scope; return prev; }

private:
    std::atomic<int64_t> m_total { 0 };
    static thread_local std::atomic<int64_t>* s_scope;
};

extern MemCounter memUsage;

// Credits this thread's tracked allocations to `counter` until destroyed,
// then restores the previously active scope.
class MemScope
{
public:
    explicit MemScope( std::atomic<int64_t>& counter ) : m_prev( MemCounter::SetScope( &counter ) ) {}
    ~MemScope() { MemCounter::SetScope( m_prev ); }
    MemScope( const MemScope& ) = delete;
    MemScope& operator=( const MemScope& ) = delete;

private:
    std::atomic<int64_t>* m_prev;
};

}

#endif
