#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#include "common/TracySystem.hpp"

#ifndef TRACY_ENABLE

#define ZoneScoped
#define ZoneScopedN(x)
#define ZoneScopedC(x)
#define ZoneScopedNC(x,y)

#define ZoneText(x,y)
#define ZoneName(x)

#define FrameMark

#define TracyLockable( type, varname ) type varname;
#define TracyLockableN( type, varname, desc ) type varname;
#define LockableBase( type ) type
#define LockMark(x)

#define TracyPlot(x,y)

#define TracyMessage(x,y)
#define TracyMessageL(x)

#else

#include "client/TracyLock.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyScoped.hpp"

#define ZoneScoped static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedN( name ) static const tracy::SourceLocation __tracy_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedC( color ) static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedNC( name, color ) static const tracy::SourceLocation __tracy_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );

#define ZoneText( txt, size ) ___tracy_scoped_zone.Text( txt, size );

#define FrameMark tracy::Profiler::FrameMark();

#define TracyLockable( type, varname ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { nullptr, #type " " #varname, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracyLockableN( type, varname, desc ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { nullptr, desc, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define LockableBase( type ) tracy::Lockable<type>
#define LockMark( varname ) static const tracy::SourceLocation __tracy_lock_location_##varname { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; varname.Mark( &__tracy_lock_location_##varname );

#define TracyPlot( name, val ) tracy::Profiler::PlotData( name, val );

#define TracyMessage( txt, size ) tracy::Profiler::Message( txt, size );
#define TracyMessageL( txt ) tracy::Profiler::Message( txt );

#endif

#endif
