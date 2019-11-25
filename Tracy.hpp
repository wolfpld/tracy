#ifndef __TRACY_HPP__
#define __TRACY_HPP__

#include "common/TracyColor.hpp"
#include "common/TracySystem.hpp"

#ifndef TRACY_ENABLE

#define ZoneNamed(x,y)
#define ZoneNamedN(x,y,z)
#define ZoneNamedC(x,y,z)
#define ZoneNamedNC(x,y,z,w)

#define ZoneScoped
#define ZoneScopedN(x)
#define ZoneScopedC(x)
#define ZoneScopedNC(x,y)

#define ZoneText(x,y)
#define ZoneName(x,y)

#define FrameMark
#define FrameMarkNamed(x)
#define FrameMarkStart(x)
#define FrameMarkEnd(x)

#define FrameImage(x,y,z,w,a)

#define TracyLockable( type, varname ) type varname;
#define TracyLockableN( type, varname, desc ) type varname;
#define TracySharedLockable( type, varname ) type varname;
#define TracySharedLockableN( type, varname, desc ) type varname;
#define LockableBase( type ) type
#define SharedLockableBase( type ) type
#define LockMark(x) (void)x;

#define TracyPlot(x,y)
#define TracyPlotConfig(x,y)

#define TracyMessage(x,y)
#define TracyMessageL(x)
#define TracyMessageC(x,y,z)
#define TracyMessageLC(x,y)
#define TracyAppInfo(x,y)

#define TracyAlloc(x,y)
#define TracyFree(x)

#define ZoneNamedS(x,y,z)
#define ZoneNamedNS(x,y,z,w)
#define ZoneNamedCS(x,y,z,w)
#define ZoneNamedNCS(x,y,z,w,a)

#define ZoneScopedS(x)
#define ZoneScopedNS(x,y)
#define ZoneScopedCS(x,y)
#define ZoneScopedNCS(x,y,z)

#define TracyAllocS(x,y,z)
#define TracyFreeS(x,y)

#define TracyMessageS(x,y,z)
#define TracyMessageLS(x,y)
#define TracyMessageCS(x,y,z,w)
#define TracyMessageLCS(x,y,z)

#define TracyParameterRegister(x)
#define TracyParameterSetup(x,y,z,w)

#else

#include "client/TracyLock.hpp"
#include "client/TracyProfiler.hpp"
#include "client/TracyScoped.hpp"

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define ZoneNamed( varname, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define ZoneNamedN( varname, name, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define ZoneNamedC( varname, color, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define ZoneNamedNC( varname, name, color, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#else
#  define ZoneNamed( varname, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), active );
#  define ZoneNamedN( varname, name, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), active );
#  define ZoneNamedC( varname, color, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), active );
#  define ZoneNamedNC( varname, name, color, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), active );
#endif

#define ZoneScoped ZoneNamed( ___tracy_scoped_zone, true )
#define ZoneScopedN( name ) ZoneNamedN( ___tracy_scoped_zone, name, true )
#define ZoneScopedC( color ) ZoneNamedC( ___tracy_scoped_zone, color, true )
#define ZoneScopedNC( name, color ) ZoneNamedNC( ___tracy_scoped_zone, name, color, true )

#define ZoneText( txt, size ) ___tracy_scoped_zone.Text( txt, size );
#define ZoneName( txt, size ) ___tracy_scoped_zone.Name( txt, size );

#define FrameMark tracy::Profiler::SendFrameMark( nullptr );
#define FrameMarkNamed( name ) tracy::Profiler::SendFrameMark( name );
#define FrameMarkStart( name ) tracy::Profiler::SendFrameMark( name, tracy::QueueType::FrameMarkMsgStart );
#define FrameMarkEnd( name ) tracy::Profiler::SendFrameMark( name, tracy::QueueType::FrameMarkMsgEnd );

#define FrameImage( image, width, height, offset, flip ) tracy::Profiler::SendFrameImage( image, width, height, offset, flip );

#define TracyLockable( type, varname ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocationData* { static const tracy::SourceLocationData srcloc { nullptr, #type " " #varname, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracyLockableN( type, varname, desc ) tracy::Lockable<type> varname { [] () -> const tracy::SourceLocationData* { static const tracy::SourceLocationData srcloc { nullptr, desc, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracySharedLockable( type, varname ) tracy::SharedLockable<type> varname { [] () -> const tracy::SourceLocationData* { static const tracy::SourceLocationData srcloc { nullptr, #type " " #varname, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define TracySharedLockableN( type, varname, desc ) tracy::SharedLockable<type> varname { [] () -> const tracy::SourceLocationData* { static const tracy::SourceLocationData srcloc { nullptr, desc, __FILE__, __LINE__, 0 }; return &srcloc; }() };
#define LockableBase( type ) tracy::Lockable<type>
#define SharedLockableBase( type ) tracy::SharedLockable<type>
#define LockMark( varname ) static const tracy::SourceLocationData __tracy_lock_location_##varname { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; varname.Mark( &__tracy_lock_location_##varname );

#define TracyPlot( name, val ) tracy::Profiler::PlotData( name, val );
#define TracyPlotConfig( name, type ) tracy::Profiler::ConfigurePlot( name, type );

#define TracyAppInfo( txt, size ) tracy::Profiler::MessageAppInfo( txt, size );

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyMessage( txt, size ) tracy::Profiler::Message( txt, size, TRACY_CALLSTACK );
#  define TracyMessageL( txt ) tracy::Profiler::Message( txt, TRACY_CALLSTACK );
#  define TracyMessageC( txt, size, color ) tracy::Profiler::MessageColor( txt, size, color, TRACY_CALLSTACK );
#  define TracyMessageLC( txt, color ) tracy::Profiler::MessageColor( txt, color, TRACY_CALLSTACK );

#  define TracyAlloc( ptr, size ) tracy::Profiler::MemAllocCallstack( ptr, size, TRACY_CALLSTACK );
#  define TracyFree( ptr ) tracy::Profiler::MemFreeCallstack( ptr, TRACY_CALLSTACK );
#else
#  define TracyMessage( txt, size ) tracy::Profiler::Message( txt, size, 0 );
#  define TracyMessageL( txt ) tracy::Profiler::Message( txt, 0 );
#  define TracyMessageC( txt, size, color ) tracy::Profiler::MessageColor( txt, size, color, 0 );
#  define TracyMessageLC( txt, color ) tracy::Profiler::MessageColor( txt, color, 0 );

#  define TracyAlloc( ptr, size ) tracy::Profiler::MemAlloc( ptr, size );
#  define TracyFree( ptr ) tracy::Profiler::MemFree( ptr );
#endif

#ifdef TRACY_HAS_CALLSTACK
#  define ZoneNamedS( varname, depth, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), depth, active );
#  define ZoneNamedNS( varname, name, depth, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), depth, active );
#  define ZoneNamedCS( varname, color, depth, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { nullptr, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), depth, active );
#  define ZoneNamedNCS( varname, name, color, depth, active ) static const tracy::SourceLocationData TracyConcat(__tracy_source_location,__LINE__) { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; tracy::ScopedZone varname( &TracyConcat(__tracy_source_location,__LINE__), depth, active );

#  define ZoneScopedS( depth ) ZoneNamedS( ___tracy_scoped_zone, depth, true )
#  define ZoneScopedNS( name, depth ) ZoneNamedNS( ___tracy_scoped_zone, name, depth, true )
#  define ZoneScopedCS( color, depth ) ZoneNamedCS( ___tracy_scoped_zone, color, depth, true )
#  define ZoneScopedNCS( name, color, depth ) ZoneNamedNCS( ___tracy_scoped_zone, name, color depth, true )

#  define TracyAllocS( ptr, size, depth ) tracy::Profiler::MemAllocCallstack( ptr, size, depth );
#  define TracyFreeS( ptr, depth ) tracy::Profiler::MemFreeCallstack( ptr, depth );

#  define TracyMessageS( txt, size, depth ) tracy::Profiler::Message( txt, size, depth );
#  define TracyMessageLS( txt, depth ) tracy::Profiler::Message( txt, depth );
#  define TracyMessageCS( txt, size, color, depth ) tracy::Profiler::MessageColor( txt, size, color, depth );
#  define TracyMessageLCS( txt, color, depth ) tracy::Profiler::MessageColor( txt, color, depth );
#else
#  define ZoneNamedS( varname, depth, active ) ZoneNamed( varname, active )
#  define ZoneNamedNS( varname, name, depth, active ) ZoneNamedN( varname, name, active )
#  define ZoneNamedCS( varname, color, depth, active ) ZoneNamedC( varname, color, active )
#  define ZoneNamedNCS( varname, name, color, depth, active ) ZoneNamedNC( varname, name, color, active )

#  define ZoneScopedS( depth ) ZoneScoped
#  define ZoneScopedNS( name, depth ) ZoneScopedN( name )
#  define ZoneScopedCS( color, depth ) ZoneScopedC( color )
#  define ZoneScopedNCS( name, color, depth ) ZoneScopedNC( name, color )

#  define TracyAllocS( ptr, size, depth ) TracyAlloc( ptr, size )
#  define TracyFreeS( ptr, depth ) TracyFree( ptr )

#  define TracyMessageS( txt, size, depth ) TracyMessage( txt, size )
#  define TracyMessageLS( txt, depth ) TracyMessageL( txt )
#  define TracyMessageCS( txt, size, color, depth ) TracyMessageC( txt, size, color )
#  define TracyMessageLCS( txt, color, depth ) TracyMessageLC( txt, color )
#endif

#define TracyParameterRegister( cb ) tracy::Profiler::ParameterRegister( cb );
#define TracyParameterSetup( idx, name, isBool, val ) tracy::Profiler::ParameterSetup( idx, name, isBool, val );

#endif

#endif
