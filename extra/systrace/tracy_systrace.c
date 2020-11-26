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

    struct pollfd pfd_in;
    pfd_in.fd = kernelFd;
    pfd_in.events = POLLIN | POLLERR;

    struct pollfd pfd_out;
    pfd_out.fd = STDOUT_FILENO;
    pfd_out.events = POLLERR;

    struct timespec sleepTime;
    sleepTime.tv_sec = 0;
    sleepTime.tv_nsec = 1000 * 1000 * 10;

    // While the pipe is open (no POLLERR on the output fd)
    while( sym_poll( &pfd_out, 1, 0) <= 0 )
    {
        // If there is neither data (POLLIN) nor an error (POLLERR) on
        // the read fd, sleep. This implements a blocking read without relying
        // on the Linux kernel's implementation of blocking reads which causes
        // a large number of context switches.
        if( sym_poll( &pfd_in, 1, 0 ) <= 0 ) {
            sym_nanosleep( &sleepTime, NULL );
            continue;  // go back to the while condition polling the output fd
        }
        const ssize_t rd = sym_read( kernelFd, buf, BufSize );
        if( rd <= 0 ) break;
        sym_write( STDOUT_FILENO, buf, rd );
    }

    sym_exit( 0 );
}
