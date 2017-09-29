#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#ifdef TRACY_DISABLE

#define ZoneScoped
#define ZoneScopedC(x)

#define ZoneText(x,y)
#define ZoneName(x)

#define FrameMark

#else

#include "TracyProfiler.hpp"
#include "TracyScoped.hpp"

#define ZoneScoped static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedC( color ) static const tracy::SourceLocation __tracy_source_location {  __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );

#define ZoneText( txt, size ) ___tracy_scoped_zone.Text( txt, size );
#define ZoneName( name ) ___tracy_scoped_zone.Name( name );

#define FrameMark tracy::Profiler::FrameMark();

#endif

#endif
