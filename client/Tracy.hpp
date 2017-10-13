#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#ifdef TRACY_DISABLE

#define ZoneScoped
#define ZoneScopedC(x)

#define ZoneText(x,y)
#define ZoneName(x)

#define FrameMark

#define TracyLockable( type, varname ) type varname;
#define TracyLockableN( type, varname, desc ) type varname;
#define LockableBase( type ) type
#define LockMark(x)

#define TracyPlot(x,y)

#else

#include "TracyLock.hpp"
#include "TracyProfiler.hpp"
#include "TracyScoped.hpp"

#define ZoneScoped static const tracy::SourceLocation __tracy_source_location { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedC( color ) static const tracy::SourceLocation __tracy_source_location {  __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );

#define ZoneText( txt, size ) ___tracy_scoped_zone.Text( txt, size );
#define ZoneName( name ) ___tracy_scoped_zone.Name( name );

#define FrameMark tracy::Profiler::FrameMark();

#define TracyLockable( type, varname ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { #type " " #varname, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracyLockableN( type, varname, desc ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { desc, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define LockableBase( type ) tracy::Lockable<type>
#define LockMark( varname ) static const tracy::SourceLocation __tracy_lock_location_##varname { __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; varname.Mark( &__tracy_lock_location_##varname );

#define TracyPlot( name, val ) tracy::Profiler::PlotData( name, val );

#endif

#endif
