#ifndef __TRACYPRINT_HPP__
#define __TRACYPRINT_HPP__

#ifdef TRACY_ON_DEMAND
#  define TRACY_VERBOSE_EARLY_OUT_COND if( !GetProfiler().IsConnected() ) break
#else
#  define TRACY_VERBOSE_EARLY_OUT_COND assert( tracy::ProfilerAvailable() )
#endif
																		
#define TracyInternalMessage( severity, ... ) 																\
	do {																									\
        TRACY_VERBOSE_EARLY_OUT_COND;																		\
		char buffer[4096];																					\
		snprintf( buffer, sizeof(buffer), __VA_ARGS__ );													\
		tracy::Profiler::Message( buffer, strlen( buffer ), 0, tracy::MessageSourceType::Tracy, severity ); \
	} while(0)

#ifdef TRACY_VERBOSE
#  include <stdio.h>
#  define TracyDebug(...) fprintf( stderr, __VA_ARGS__ )
#elif !defined(TRACY_VERBOSE_NO_MESSAGE)
#  define TracyDebug(...) TracyInternalMessage( tracy::MessageSeverity::Debug, __VA_ARGS__ )
#else
#  define TracyDebug(...)
#endif

#endif
