#include <chrono>
#include <mutex>
#include <thread>
#include <shared_mutex>
#include <stdlib.h>
#include "../Tracy.hpp"
#include "../common/TracySystem.hpp"

struct static_init_test_t
{
    static_init_test_t()
    {
        ZoneScoped;
        new char[64*1024];
    }
};

static const static_init_test_t static_init_test;

void* operator new( std::size_t count )
{
    auto ptr = malloc( count );
    TracyAllocS( ptr, count, 10 );
    return ptr;
}

void operator delete( void* ptr ) noexcept
{
    TracyFreeS( ptr, 10 );
    free( ptr );
}

void TestFunction()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        ZoneScopedN( "Test function" );
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
}

void ResolutionCheck()
{
    for(;;)
    {
        {
            ZoneScoped;
            std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        }
        {
            ZoneScoped;
            std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        }
    }

}

void ScopeCheck()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        ZoneScoped;
    }
}

static TracyLockable( std::mutex, mutex );
static TracyLockable( std::recursive_mutex, recmutex );

void Lock1()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 4 ) );
        std::lock_guard<LockableBase( std::mutex )> lock( mutex );
        LockMark( mutex );
        ZoneScoped;
        std::this_thread::sleep_for( std::chrono::milliseconds( 4 ) );
    }
}

void Lock2()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 3 ) );
        std::unique_lock<LockableBase( std::mutex )> lock( mutex );
        LockMark( mutex );
        ZoneScoped;
        std::this_thread::sleep_for( std::chrono::milliseconds( 5 ) );
    }
}

void Lock3()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        std::unique_lock<LockableBase( std::mutex )> lock( mutex );
        LockMark( mutex );
        ZoneScoped;
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
}

void RecLock()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 7 ) );
        std::lock_guard<LockableBase( std::recursive_mutex )> lock1( recmutex );
        TracyMessageL( "First lock" );
        LockMark( recmutex );
        ZoneScoped;
        {
            std::this_thread::sleep_for( std::chrono::milliseconds( 3 ) );
            std::lock_guard<LockableBase( std::recursive_mutex )> lock2( recmutex );
            TracyMessageL( "Second lock" );
            LockMark( recmutex );
            std::this_thread::sleep_for( std::chrono::milliseconds( 2 ) );
        }
    }
}

void Plot()
{
    unsigned char i = 0;
    for(;;)
    {
        for( int j=0; j<1024; j++ )
        {
            TracyPlot( "Test plot", (int64_t)i++ );
        }
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
}

void MessageTest()
{
    for(;;)
    {
        TracyMessage( "Tock", 4 );
        std::this_thread::sleep_for( std::chrono::milliseconds( 5 ) );
    }
}

static int Fibonacci( int n );

static inline int FibonacciInline( int n )
{
    return Fibonacci( n );
}

static int Fibonacci( int n )
{
    ZoneScoped;
    if( n < 2 ) return n;
    return FibonacciInline( n-1 ) + FibonacciInline( n-2 );
}

void DepthTest()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 20 ) );
        ZoneScoped;
        const auto txt = "Fibonacci (15)";
        ZoneText( txt, strlen( txt ) );
        Fibonacci( 15 );
    }
}

static TracySharedLockable( std::shared_mutex, sharedMutex );

void SharedRead1()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        std::shared_lock<SharedLockableBase( std::shared_mutex )> lock( sharedMutex );
        std::this_thread::sleep_for( std::chrono::milliseconds( 4 ) );
    }
}

void SharedRead2()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 6 ) );
        std::shared_lock<SharedLockableBase( std::shared_mutex )> lock( sharedMutex );
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
}

void SharedWrite1()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 3 ) );
        std::unique_lock<SharedLockableBase( std::shared_mutex )> lock( sharedMutex );
        std::this_thread::sleep_for( std::chrono::milliseconds( 2 ) );
    }
}

void SharedWrite2()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 5 ) );
        std::unique_lock<SharedLockableBase( std::shared_mutex )> lock( sharedMutex );
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
}

void CaptureCallstack()
{
    ZoneScopedS( 10 );
}

void CallstackTime()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        CaptureCallstack();
    }
}

void OnlyMemory()
{
    new int;
}

static TracyLockable( std::mutex, deadlockMutex1 );
static TracyLockable( std::mutex, deadlockMutex2 );

void DeadlockTest1()
{
    deadlockMutex1.lock();
    std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    deadlockMutex2.lock();
}

void DeadlockTest2()
{
    deadlockMutex2.lock();
    std::this_thread::sleep_for( std::chrono::milliseconds( 100 ) );
    deadlockMutex1.lock();
}

int main()
{
    auto t1 = std::thread( TestFunction );
    auto t2 = std::thread( TestFunction );
    auto t3 = std::thread( ResolutionCheck );
    auto t4 = std::thread( ScopeCheck );
    auto t5 = std::thread( Lock1 );
    auto t6 = std::thread( Lock2 );
    auto t7 = std::thread( Lock3 );
    auto t8 = std::thread( Plot );
    auto t9 = std::thread( Plot );
    auto t10 = std::thread( MessageTest );
    auto t11 = std::thread( DepthTest );
    auto t12 = std::thread( RecLock );
    auto t13 = std::thread( RecLock );
    auto t14 = std::thread( SharedRead1 );
    auto t15 = std::thread( SharedRead1 );
    auto t16 = std::thread( SharedRead2 );
    auto t17 = std::thread( SharedWrite1 );
    auto t18 = std::thread( SharedWrite2 );
    auto t19 = std::thread( CallstackTime );
    auto t20 = std::thread( OnlyMemory );
    auto t21 = std::thread( DeadlockTest1 );
    auto t22 = std::thread( DeadlockTest2 );

    tracy::SetThreadName( t1, "First thread" );
    tracy::SetThreadName( t2, "Second thread" );
    tracy::SetThreadName( t3, "Resolution check" );
    tracy::SetThreadName( t4, "Scope check" );
    tracy::SetThreadName( t5, "Lock 1" );
    tracy::SetThreadName( t6, "Lock 2" );
    tracy::SetThreadName( t7, "Lock 3" );
    tracy::SetThreadName( t8, "Plot 1" );
    tracy::SetThreadName( t9, "Plot 2" );
    tracy::SetThreadName( t10, "Message test" );
    tracy::SetThreadName( t11, "Depth test" );
    tracy::SetThreadName( t12, "Recursive mtx 1" );
    tracy::SetThreadName( t13, "Recursive mtx 2" );
    tracy::SetThreadName( t14, "Shared read 1" );
    tracy::SetThreadName( t15, "Shared read 2" );
    tracy::SetThreadName( t16, "Shared read 3" );
    tracy::SetThreadName( t17, "Shared write 1" );
    tracy::SetThreadName( t18, "Shared write 2" );
    tracy::SetThreadName( t19, "Callstack time" );
    tracy::SetThreadName( t20, "Only memory" );
    tracy::SetThreadName( t21, "Deadlock test 1" );
    tracy::SetThreadName( t22, "Deadlock test 2" );

    for(;;)
    {
        TracyMessageL( "Tick" );
        std::this_thread::sleep_for( std::chrono::milliseconds( 2 ) );
        {
            ZoneScoped;
            std::this_thread::sleep_for( std::chrono::milliseconds( 2 ) );
        }
        FrameMark;
    }
}
