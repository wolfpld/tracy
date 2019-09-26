#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum { BufSize = 64*1024 };

int main()
{
    char buf[BufSize];

    int kernelFd = open( "/sys/kernel/debug/tracing/trace_pipe", O_RDONLY );
    if( kernelFd == -1 ) return -1;

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

    close( kernelFd );
    return 0;
}
