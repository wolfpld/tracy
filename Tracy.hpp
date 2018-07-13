#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#include "common/TracyColor.hpp"
#include "common/TracySystem.hpp"

#ifndef TRACY_ENABLE

#define ZoneScoped
#define ZoneScopedN(x)
#define ZoneScopedC(x)
#define ZoneScopedNC(x,y)

#define ZoneText(x,y)
#define ZoneName(x,y)

#define FrameMark

#define TracyLockable( type, varname ) type varname;
#define TracyLockableN( type, varname, desc ) type varname;
#define TracySharedLockable( type, varname ) type varname;
#define TracySharedLockableN( type, varname, desc ) type varname;
#define LockableBase( type ) type
#define SharedLockableBase( type ) type
#define LockMark(x) (void)x;

#define TracyPlot(x,y)

#define TracyMessage(x,y)
#define TracyMessageL(x)

#define TracyAlloc(x,y)
#define TracyFree(x)
#define TracyAllocS(x,y,z)
#define TracyFreeS(x,y)

#else

#include "client/TracyLock.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyScoped.hpp"

#define ZoneScoped static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedN( name ) static const tracy::SourceLocation __tracy_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedC( color ) static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );
#define ZoneScopedNC( name, color ) static const tracy::SourceLocation __tracy_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location );

#define ZoneText( txt, size ) ___tracy_scoped_zone.Text( txt, size );
#define ZoneName( txt, size ) ___tracy_scoped_zone.Name( txt, size );

#define FrameMark tracy::Profiler::SendFrameMark();

#define TracyLockable( type, varname ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { nullptr, #type " " #varname, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracyLockableN( type, varname, desc ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { nullptr, desc, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracySharedLockable( type, varname ) tracy::SharedLockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { nullptr, #type " " #varname, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracySharedLockableN( type, varname, desc ) tracy::SharedLockable<type> varname { [] () -> const tracy::SourceLocation* { static const tracy::SourceLocation srcloc { nullptr, desc, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define LockableBase( type ) tracy::Lockable<type>
#define SharedLockableBase( type ) tracy::SharedLockable<type>
#define LockMark( varname ) static const tracy::SourceLocation __tracy_lock_location_##varname { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; varname.Mark( &__tracy_lock_location_##varname );

#define TracyPlot( name, val ) tracy::Profiler::PlotData( name, val );

#define TracyMessage( txt, size ) tracy::Profiler::Message( txt, size );
#define TracyMessageL( txt ) tracy::Profiler::Message( txt );

#define TracyAlloc( ptr, size ) tracy::Profiler::MemAlloc( ptr, size );
#define TracyFree( ptr ) tracy::Profiler::MemFree( ptr );

#ifdef TRACY_HAS_CALLSTACK
#  define ZoneScopedS( depth ) static const tracy::SourceLocation __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location, depth );
#  define ZoneScopedNS( name, depth ) static const tracy::SourceLocation __tracy_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location, depth );
#  define ZoneScopedCS( color, depth ) __tracy_source_location { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location, depth );
#  define ZoneScopedNCS( name, color, depth ) static const tracy::SourceLocation __tracy_source_location { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone ___tracy_scoped_zone( &__tracy_source_location, depth );

#  define TracyAllocS( ptr, size, depth ) tracy::Profiler::MemAllocCallstack( ptr, size, depth );
#  define TracyFreeS( ptr, depth ) tracy::Profiler::MemFreeCallstack( ptr, depth );
#else
#  define ZoneScopedS( depth ) ZoneScoped
#  define ZoneScopedNS( name, depth ) ZoneScopedN( name )
#  define ZoneScopedCS( color, depth ) ZoneScopedC( color )
#  define ZoneScopedNCS( name, color, depth ) ZoneScopedNC( name, color )

#  define TracyAllocS( ptr, size, depth ) TracyAlloc( ptr, size )
#  define TracyFreeS( ptr, depth ) TracyFree( ptr )
#endif

#endif

#endif
