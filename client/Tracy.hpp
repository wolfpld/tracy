#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#ifdef TRACY_DISABLE

#define ZoneScoped
#define ZoneScopedC(x)

#define FrameMark

#else

#include "TracyProfiler.hpp"
#include "TracyScoped.hpp"

#define ZoneScoped static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, __LINE__ }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location, 0 );
#define ZoneScopedC( color ) static const tracy::SourceLocation __tracy_source_location {  __FUNCTION__,  __FILE__, __LINE__ }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location, color );

#define FrameMark tracy::Profiler::FrameMark();

#endif

#endif
