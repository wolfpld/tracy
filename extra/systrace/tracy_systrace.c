#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>

enum { BufSize = 64*1024 };

typedef int (*open_t)( const char*, int, ... );
typedef void (*exit_t)( int );
typedef int (*poll_t)( struct pollfd*, nfds_t, int timeout );
typedef int (*nanosleep_t)( const struct timespec*, struct timespec* );
typedef ssize_t (*read_t)( int, void*, size_t );
typedef ssize_t (*write_t)( int, const void*, size_t );

void _start()
{
    void* libc = dlopen( "libc.so", RTLD_LAZY );

    open_t sym_open = dlsym( libc, "open" );
    exit_t sym_exit = dlsym( libc, "exit" );
    poll_t sym_poll = dlsym( libc, "poll" );
    nanosleep_t sym_nanosleep = dlsym( libc, "nanosleep" );
    read_t sym_read = dlsym( libc, "read" );
    write_t sym_write = dlsym( libc, "write" );

    char buf[BufSize];

    int kernelFd = sym_open( "/sys/kernel/debug/tracing/trace_pipe", O_RDONLY );
    if( kernelFd < 0 ) sym_exit( 0 );

    struct pollfd pfd;
    pfd.fd = kernelFd;
    pfd.events = POLLIN | POLLERR;

    struct timespec sleepTime;
    sleepTime.tv_sec = 0;
    sleepTime.tv_nsec = 1000 * 1000 * 10;

    for(;;)
    {
        while( sym_poll( &pfd, 1, 0 ) <= 0 ) sym_nanosleep( &sleepTime, NULL );
        const int rd = sym_read( kernelFd, buf, BufSize );
        if( rd <= 0 ) break;
        sym_write( STDOUT_FILENO, buf, rd );
    }

    sym_exit( 0 );
}
