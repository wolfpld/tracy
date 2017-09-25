#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#ifdef TRACY_DISABLE

#define ZoneScoped
#define ZoneScopedC(x)

#define FrameMark

#else

#include "TracyProfiler.hpp"
#include "TracyScoped.hpp"

#define ZoneScoped tracy::ScopedZone ___tracy_scoped_zone( __FILE__, __FUNCTION__, __LINE__, 0 );
#define ZoneScopedC( color ) tracy::ScopedZone ___tracy_scoped_zone( __FILE__, __FUNCTION__, __LINE__, color );

#define FrameMark tracy::Profiler::FrameMark();

#endif

#endif
