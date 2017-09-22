#include <chrono>
#include <thread>
#include "../client/Tracy.hpp"
#include "../common/TracySystem.hpp"

void TestFunction()
{
    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        ZoneScoped;
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


int main()
{
    auto t1 = std::thread( TestFunction );
    auto t2 = std::thread( TestFunction );
    auto t3 = std::thread( ResolutionCheck );

    tracy::SetThreadName( t1, "First thread" );
    tracy::SetThreadName( t2, "Second thread" );
    tracy::SetThreadName( t3, "Resolution check" );

    for(;;)
    {
        std::this_thread::sleep_for( std::chrono::milliseconds( 2 ) );
        {
            ZoneScoped;
            std::this_thread::sleep_for( std::chrono::milliseconds( 2 ) );
        }
        FrameMark;
    }
}
