#include <stdio.h>
#include <thread>

#include "TracyMemory.hpp"

using namespace tracy;

static int failures = 0;

#define CHECK( cond ) do { if( !( cond ) ) { printf( "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond ); failures++; } } while( 0 )

int main()
{
    const auto total = []{ return memUsage.load( std::memory_order_relaxed ); };

    const auto base = total();
    memUsage.fetch_add( 100, std::memory_order_relaxed );
    CHECK( total() == base + 100 );

    std::atomic<int64_t> a { 0 };
    std::atomic<int64_t> b { 0 };
    std::thread ta( [&] {
        MemScope scope( a );
        memUsage.fetch_add( 40, std::memory_order_relaxed );
        memUsage.fetch_sub( 10, std::memory_order_relaxed );
    } );
    ta.join();
    CHECK( a.load() == 30 );
    CHECK( total() == base + 130 );

    std::thread tb( [&] {
        MemScope scope( b );
        memUsage.fetch_add( 1000, std::memory_order_relaxed );
    } );
    std::thread tc( [&] { memUsage.fetch_add( 5000, std::memory_order_relaxed ); } );
    tb.join();
    tc.join();
    CHECK( a.load() == 30 );
    CHECK( b.load() == 1000 );

    {
        MemScope scope( a );
    }
    memUsage.fetch_add( 7, std::memory_order_relaxed );
    CHECK( a.load() == 30 );

    std::atomic<int64_t> outer { 0 };
    std::atomic<int64_t> inner { 0 };
    {
        MemScope o( outer );
        memUsage.fetch_add( 1, std::memory_order_relaxed );
        {
            MemScope i( inner );
            memUsage.fetch_add( 10, std::memory_order_relaxed );
        }
        memUsage.fetch_add( 100, std::memory_order_relaxed );
    }
    CHECK( outer.load() == 101 );
    CHECK( inner.load() == 10 );

    if( failures == 0 ) printf( "All memory counter tests passed.\n" );
    return failures == 0 ? 0 : 1;
}
