#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#include "TracyProfiler.hpp"
#include "TracyScoped.hpp"

#define ZoneScoped tracy::ScopedZone ___tracy_scoped_zone( __FILE__, __FUNCTION__, __LINE__ );
#define FrameMark tracy::Profiler::FrameMark();

#endif
