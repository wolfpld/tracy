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
#elif !defined(TRACY_NO_INTERNAL_MESSAGE)
#  define TracyDebug(...) TracyInternalMessage( tracy::MessageSeverity::Debug, __VA_ARGS__ )
#else
#  define TracyDebug(...)
#endif

#endif
