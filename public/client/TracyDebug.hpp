#ifndef __TRACYPRINT_HPP__
#define __TRACYPRINT_HPP__

#ifdef TRACY_ON_DEMAND
#  define TRACY_VERBOSE_EARLY_OUT_COND if( !GetProfiler().IsConnected() ) break
#else
#  define TRACY_VERBOSE_EARLY_OUT_COND assert( tracy::ProfilerAvailable() )
#endif

#define TracyInternalMessage( severity, ... )																				   \
	do {																													   \
        TRACY_VERBOSE_EARLY_OUT_COND;																						   \
		char buffer[4096];																									   \
		snprintf( buffer, sizeof(buffer), __VA_ARGS__ );																	   \
		tracy::Profiler::LogString( tracy::MessageSourceType::Tracy, severity, 0, TRACY_CALLSTACK, strlen( buffer ), buffer ); \
	} while( 0 )

#ifdef TRACY_VERBOSE
#  include <stdio.h>
#  define TracyDebug(...) do { fprintf( stderr, __VA_ARGS__ ); fputc( '\n', stderr ); } while( 0 )
// Note: We can't use LogString when using TRACY_DELAYED_INIT due to a deadlock in the init code. 
// This is caused by `GetProfilerData` triggerting ProfileData ctor, which itself will call `GetProfilerData` and deadlock.
// TRACY_MANUAL_LIFETIME does not have this issue since StartupProfiler sets s_profilerData before calling the constructor.
// In general, this also means we can only call TracyDebug after and the first logging is after queue initialization and critical init (such as InitCallstackCritical).
#elif !defined(TRACY_NO_INTERNAL_MESSAGE) && (!defined(TRACY_DELAYED_INIT) || defined(TRACY_MANUAL_LIFETIME))
#  define TracyDebug(...) TracyInternalMessage( tracy::MessageSeverity::Debug, __VA_ARGS__ )
#else
#  define TracyDebug(...)
#endif

#endif
