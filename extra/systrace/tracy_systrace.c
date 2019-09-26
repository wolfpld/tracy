#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

enum { BufSize = 64*1024 };

void _start()
{
    char buf[BufSize];

    int kernelFd = open( "/sys/kernel/debug/tracing/trace_pipe", O_RDONLY );
    if( kernelFd < 0 ) exit( 0 );

    struct pollfd pfd;
    pfd.fd = kernelFd;
    pfd.events = POLLIN | POLLERR;

    struct timespec sleepTime;
    sleepTime.tv_sec = 0;
    sleepTime.tv_nsec = 1000 * 1000 * 10;

    for(;;)
    {
        while( poll( &pfd, 1, 0 ) <= 0 ) nanosleep( &sleepTime, NULL );
        const int rd = read( kernelFd, buf, BufSize );
        if( rd <= 0 ) break;
        write( STDOUT_FILENO, buf, rd );
    }

    exit( 0 );
}
