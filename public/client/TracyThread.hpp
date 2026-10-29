#ifndef __TRACYTHREAD_HPP__
#define __TRACYTHREAD_HPP__

#if defined _WIN32
#  include <windows.h>
#else
#  include <pthread.h>
#endif

#ifdef TRACY_MANUAL_LIFETIME
#  include "../common/TracyAlloc.hpp"
#endif

namespace tracy
{

#ifdef TRACY_MANUAL_LIFETIME
extern thread_local bool RpThreadInitDone;
#endif

class ThreadExitHandler
{
public:
    ~ThreadExitHandler()
    {
#ifdef TRACY_MANUAL_LIFETIME
#  if defined TRACY_HAS_CUSTOM_ALLOCATOR
        PlatformAllocatorThreadFinalize();
#  elif defined TRACY_USE_RPMALLOC
        rpmalloc_thread_finalize( 1 );
#  endif
        RpThreadInitDone = false;
#endif
    }
};

#if defined _WIN32

class Thread
{
public:
    Thread( void(*func)( void* ptr ), void* ptr )
        : m_func( func )
        , m_ptr( ptr )
        , m_exit( CreateEventW( nullptr, TRUE, FALSE, nullptr ) )
        , m_hnd( CreateThread( nullptr, 0, Launch, this, 0, nullptr ) )
    {}

    ~Thread()
    {
        // The thread signals m_exit when it is done and then parks, instead of exiting, so that
        // it can be joined from DllMain (e.g. a static Profiler destroyed by FreeLibrary).
        // A normal thread exit needs the loader lock, which the joining thread already holds.
        HANDLE handles[2] = { m_exit, m_hnd };
        WaitForMultipleObjects( 2, handles, FALSE, INFINITE );
        CloseHandle( m_exit );
        if( InLoaderCallout() )
        {
            TerminateThread( m_hnd, 0 );
        }
        else
        {
            QueueUserAPC( WakeUp, m_hnd, 0 );
            WaitForSingleObject( m_hnd, INFINITE );
        }
        CloseHandle( m_hnd );
    }

    HANDLE Handle() const { return m_hnd; }

private:
    static bool InLoaderCallout()
    {
        typedef BOOLEAN(NTAPI* IsWithinCallout)();
        static const auto fn = (IsWithinCallout)GetProcAddress( GetModuleHandleW( L"ntdll.dll" ), "RtlIsThreadWithinLoaderCallout" );
        return fn && fn();
    }

    static void CALLBACK WakeUp( ULONG_PTR ) {}

    static DWORD WINAPI Launch( void* ptr )
    {
        auto self = (Thread*)ptr;
        self->m_func( self->m_ptr );
        // *self may be gone as soon as m_exit is signaled.
        const HANDLE exit = self->m_exit;
        SetEvent( exit );
        SleepEx( INFINITE, TRUE );
        return 0;
    }

    void(*m_func)( void* ptr );
    void* m_ptr;
    HANDLE m_exit;
    HANDLE m_hnd;
};

#else

class Thread
{
public:
    Thread( void(*func)( void* ptr ), void* ptr )
        : m_func( func )
        , m_ptr( ptr )
    {
        pthread_create( &m_thread, nullptr, Launch, this );
    }

    ~Thread()
    {
        pthread_join( m_thread, nullptr );
    }

    pthread_t Handle() const { return m_thread; }

private:
    static void* Launch( void* ptr ) { ((Thread*)ptr)->m_func( ((Thread*)ptr)->m_ptr ); return nullptr; }
    void(*m_func)( void* ptr );
    void* m_ptr;
    pthread_t m_thread;
};

#endif

}

#endif
