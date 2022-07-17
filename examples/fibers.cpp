// g++ fibers.cpp ../public/TracyClient.cpp -I../public/tracy -DTRACY_ENABLE -DTRACY_FIBERS -lpthread -ldl

#include <thread>
#include <unistd.h>

#include "Tracy.hpp"
#include "TracyC.h"

const char* fiber = "job1";
TracyCZoneCtx zone;

int main()
{
    std::thread t1( [] {
        TracyFiberEnter( fiber );
        TracyCZone( ctx, 1 );
        zone = ctx;
        sleep( 1 );
        TracyFiberLeave;
    });
    t1.join();

    std::thread t2( [] {
        TracyFiberEnter( fiber );
        sleep( 1 );
        TracyCZoneEnd( zone );
        TracyFiberLeave;
    });
    t2.join();
}
