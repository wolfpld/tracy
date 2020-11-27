#ifndef __TRACYC_HPP__
#define __TRACYC_HPP__

#include <stddef.h>
#include <stdint.h>

#include "client/TracyCallstack.h"
#include "common/TracyApi.h"

#ifdef __cplusplus
extern "C" {
#endif

TRACY_API void ___tracy_set_thread_name( const char* name );

#define TracyCSetThreadName( name ) ___tracy_set_thread_name( name );


#ifndef TRACY_ENABLE

typedef const void* TracyCZoneCtx;

#define TracyCZone(c,x)
#define TracyCZoneN(c,x,y)
#define TracyCZoneC(c,x,y)
#define TracyCZoneNC(c,x,y,z)
#define TracyCZoneEnd(c)
#define TracyCZoneText(c,x,y)
#define TracyCZoneName(c,x,y)
#define TracyCZoneColor(c,x)
#define TracyCZoneValue(c,x)

#define TracyCAlloc(x,y)
#define TracyCFree(x)
#define TracyCSecureAlloc(x,y)
#define TracyCSecureFree(x)

#define TracyCAllocN(x,y,z)
#define TracyCFreeN(x,y)
#define TracyCSecureAllocN(x,y,z)
#define TracyCSecureFreeN(x,y)

#define TracyCFrameMark
#define TracyCFrameMarkNamed(x)
#define TracyCFrameMarkStart(x)
#define TracyCFrameMarkEnd(x)
#define TracyCFrameImage(x,y,z,w,a)

#define TracyCPlot(x,y)
#define TracyCMessage(x,y)
#define TracyCMessageL(x)
#define TracyCMessageC(x,y,z)
#define TracyCMessageLC(x,y)
#define TracyCAppInfo(x,y)

#define TracyCZoneS(x,y,z)
#define TracyCZoneNS(x,y,z,w)
#define TracyCZoneCS(x,y,z,w)
#define TracyCZoneNCS(x,y,z,w,a)

#define TracyCAllocS(x,y,z)
#define TracyCFreeS(x,y)
#define TracyCSecureAllocS(x,y,z)
#define TracyCSecureFreeS(x,y)

#define TracyCAllocNS(x,y,z,w)
#define TracyCFreeNS(x,y,z)
#define TracyCSecureAllocNS(x,y,z,w)
#define TracyCSecureFreeNS(x,y,z)

#define TracyCMessageS(x,y,z)
#define TracyCMessageLS(x,y)
#define TracyCMessageCS(x,y,z,w)
#define TracyCMessageLCS(x,y,z)

#else

#ifndef TracyConcat
#  define TracyConcat(x,y) TracyConcatIndirect(x,y)
#endif
#ifndef TracyConcatIndirect
#  define TracyConcatIndirect(x,y) x##y
#endif

struct ___tracy_source_location_data
{
    const char* name;
    const char* function;
    const char* file;
    uint32_t line;
    uint32_t color;
};

struct ___tracy_c_zone_context
{
    uint32_t id;
    int active;
};

// Some containers don't support storing const types.
// This struct, as visible to user, is immutable, so treat it as if const was declared here.
typedef /*const*/ struct ___tracy_c_zone_context TracyCZoneCtx;

TRACY_API void ___tracy_init_thread(void);
TRACY_API uint64_t ___tracy_alloc_srcloc( uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz );
TRACY_API uint64_t ___tracy_alloc_srcloc_name( uint32_t line, const char* source, size_t sourceSz, const char* function, size_t functionSz, const char* name, size_t nameSz );

TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin( const struct ___tracy_source_location_data* srcloc, int active );
TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin_callstack( const struct ___tracy_source_location_data* srcloc, int depth, int active );
TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin_alloc( uint64_t srcloc, int active );
TRACY_API TracyCZoneCtx ___tracy_emit_zone_begin_alloc_callstack( uint64_t srcloc, int depth, int active );
TRACY_API void ___tracy_emit_zone_end( TracyCZoneCtx ctx );
TRACY_API void ___tracy_emit_zone_text( TracyCZoneCtx ctx, const char* txt, size_t size );
TRACY_API void ___tracy_emit_zone_name( TracyCZoneCtx ctx, const char* txt, size_t size );
TRACY_API void ___tracy_emit_zone_color( TracyCZoneCtx ctx, uint32_t color );
TRACY_API void ___tracy_emit_zone_value( TracyCZoneCtx ctx, uint64_t value );

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyCZone( ctx, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { NULL, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define TracyCZoneN( ctx, name, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define TracyCZoneC( ctx, color, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { NULL, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#  define TracyCZoneNC( ctx, name, color, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), TRACY_CALLSTACK, active );
#else
#  define TracyCZone( ctx, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { NULL, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin( &TracyConcat(__tracy_source_location,__LINE__), active );
#  define TracyCZoneN( ctx, name, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin( &TracyConcat(__tracy_source_location,__LINE__), active );
#  define TracyCZoneC( ctx, color, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { NULL, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin( &TracyConcat(__tracy_source_location,__LINE__), active );
#  define TracyCZoneNC( ctx, name, color, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin( &TracyConcat(__tracy_source_location,__LINE__), active );
#endif

#define TracyCZoneEnd( ctx ) ___tracy_emit_zone_end( ctx );

#define TracyCZoneText( ctx, txt, size ) ___tracy_emit_zone_text( ctx, txt, size );
#define TracyCZoneName( ctx, txt, size ) ___tracy_emit_zone_name( ctx, txt, size );
#define TracyCZoneColor( ctx, color ) ___tracy_emit_zone_color( ctx, color );
#define TracyCZoneValue( ctx, value ) ___tracy_emit_zone_value( ctx, value );


TRACY_API void ___tracy_emit_memory_alloc( const void* ptr, size_t size, int secure );
TRACY_API void ___tracy_emit_memory_alloc_callstack( const void* ptr, size_t size, int depth, int secure );
TRACY_API void ___tracy_emit_memory_free( const void* ptr, int secure );
TRACY_API void ___tracy_emit_memory_free_callstack( const void* ptr, int depth, int secure );

TRACY_API void ___tracy_emit_message( const char* txt, size_t size, int callstack );
TRACY_API void ___tracy_emit_messageL( const char* txt, int callstack );
TRACY_API void ___tracy_emit_messageC( const char* txt, size_t size, uint32_t color, int callstack );
TRACY_API void ___tracy_emit_messageLC( const char* txt, uint32_t color, int callstack );

#if defined TRACY_HAS_CALLSTACK && defined TRACY_CALLSTACK
#  define TracyCAlloc( ptr, size ) ___tracy_emit_memory_alloc_callstack( ptr, size, TRACY_CALLSTACK, 0 )
#  define TracyCFree( ptr ) ___tracy_emit_memory_free_callstack( ptr, TRACY_CALLSTACK, 0 )
#  define TracyCSecureAlloc( ptr, size ) ___tracy_emit_memory_alloc_callstack( ptr, size, TRACY_CALLSTACK, 1 )
#  define TracyCSecureFree( ptr ) ___tracy_emit_memory_free_callstack( ptr, TRACY_CALLSTACK, 1 )

#  define TracyCAllocN( ptr, size, name ) ___tracy_emit_memory_alloc_callstack_named( ptr, size, TRACY_CALLSTACK, 0, name )
#  define TracyCFreeN( ptr, name ) ___tracy_emit_memory_free_callstack_named( ptr, TRACY_CALLSTACK, 0, name )
#  define TracyCSecureAllocN( ptr, size, name ) ___tracy_emit_memory_alloc_callstack_named( ptr, size, TRACY_CALLSTACK, 1, name )
#  define TracyCSecureFreeN( ptr, name ) ___tracy_emit_memory_free_callstack_named( ptr, TRACY_CALLSTACK, 1, name )

#  define TracyCMessage( txt, size ) ___tracy_emit_message( txt, size, TRACY_CALLSTACK );
#  define TracyCMessageL( txt ) ___tracy_emit_messageL( txt, TRACY_CALLSTACK );
#  define TracyCMessageC( txt, size, color ) ___tracy_emit_messageC( txt, size, color, TRACY_CALLSTACK );
#  define TracyCMessageLC( txt, color ) ___tracy_emit_messageLC( txt, color, TRACY_CALLSTACK );
#else
#  define TracyCAlloc( ptr, size ) ___tracy_emit_memory_alloc( ptr, size, 0 );
#  define TracyCFree( ptr ) ___tracy_emit_memory_free( ptr, 0 );
#  define TracyCSecureAlloc( ptr, size ) ___tracy_emit_memory_alloc( ptr, size, 1 );
#  define TracyCSecureFree( ptr ) ___tracy_emit_memory_free( ptr, 1 );

#  define TracyCAllocN( ptr, size, name ) ___tracy_emit_memory_alloc_named( ptr, size, 0, name );
#  define TracyCFreeN( ptr, name ) ___tracy_emit_memory_free_named( ptr, 0, name );
#  define TracyCSecureAllocN( ptr, size, name ) ___tracy_emit_memory_alloc_named( ptr, size, 1, name );
#  define TracyCSecureFreeN( ptr, name ) ___tracy_emit_memory_free_named( ptr, 1, name );

#  define TracyCMessage( txt, size ) ___tracy_emit_message( txt, size, 0 );
#  define TracyCMessageL( txt ) ___tracy_emit_messageL( txt, 0 );
#  define TracyCMessageC( txt, size, color ) ___tracy_emit_messageC( txt, size, color, 0 );
#  define TracyCMessageLC( txt, color ) ___tracy_emit_messageLC( txt, color, 0 );
#endif


TRACY_API void ___tracy_emit_frame_mark( const char* name );
TRACY_API void ___tracy_emit_frame_mark_start( const char* name );
TRACY_API void ___tracy_emit_frame_mark_end( const char* name );
TRACY_API void ___tracy_emit_frame_image( const void* image, uint16_t w, uint16_t h, uint8_t offset, int flip );

#define TracyCFrameMark ___tracy_emit_frame_mark( 0 );
#define TracyCFrameMarkNamed( name ) ___tracy_emit_frame_mark( name );
#define TracyCFrameMarkStart( name ) ___tracy_emit_frame_mark_start( name );
#define TracyCFrameMarkEnd( name ) ___tracy_emit_frame_mark_end( name );
#define TracyCFrameImage( image, width, height, offset, flip ) ___tracy_emit_frame_image( image, width, height, offset, flip );


TRACY_API void ___tracy_emit_plot( const char* name, double val );
TRACY_API void ___tracy_emit_message_appinfo( const char* txt, size_t size );

#define TracyCPlot( name, val ) ___tracy_emit_plot( name, val );
#define TracyCAppInfo( txt, color ) ___tracy_emit_message_appinfo( txt, color );


#ifdef TRACY_HAS_CALLSTACK
#  define TracyCZoneS( ctx, depth, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { NULL, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), depth, active );
#  define TracyCZoneNS( ctx, name, depth, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, 0 }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), depth, active );
#  define TracyCZoneCS( ctx, color, depth, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { NULL, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), depth, active );
#  define TracyCZoneNCS( ctx, name, color, depth, active ) static const struct ___tracy_source_location_data TracyConcat(__tracy_source_location,__LINE__) = { name, __FUNCTION__,  __FILE__, (uint32_t)__LINE__, color }; TracyCZoneCtx ctx = ___tracy_emit_zone_begin_callstack( &TracyConcat(__tracy_source_location,__LINE__), depth, active );

#  define TracyCAllocS( ptr, size, depth ) ___tracy_emit_memory_alloc_callstack( ptr, size, depth, 0 )
#  define TracyCFreeS( ptr, depth ) ___tracy_emit_memory_free_callstack( ptr, depth, 0 )
#  define TracyCSecureAllocS( ptr, size, depth ) ___tracy_emit_memory_alloc_callstack( ptr, size, depth, 1 )
#  define TracyCSecureFreeS( ptr, depth ) ___tracy_emit_memory_free_callstack( ptr, depth, 1 )

#  define TracyCAllocNS( ptr, size, depth, name ) ___tracy_emit_memory_alloc_callstack_named( ptr, size, depth, 0, name )
#  define TracyCFreeNS( ptr, depth, name ) ___tracy_emit_memory_free_callstack_named( ptr, depth, 0, name )
#  define TracyCSecureAllocNS( ptr, size, depth, name ) ___tracy_emit_memory_alloc_callstack_named( ptr, size, depth, 1, name )
#  define TracyCSecureFreeNS( ptr, depth, name ) ___tracy_emit_memory_free_callstack_named( ptr, depth, 1, name )

#  define TracyCMessageS( txt, size, depth ) ___tracy_emit_message( txt, size, depth );
#  define TracyCMessageLS( txt, depth ) ___tracy_emit_messageL( txt, depth );
#  define TracyCMessageCS( txt, size, color, depth ) ___tracy_emit_messageC( txt, size, color, depth );
#  define TracyCMessageLCS( txt, color, depth ) ___tracy_emit_messageLC( txt, color, depth );
#else
#  define TracyCZoneS( ctx, depth, active ) TracyCZone( ctx, active )
#  define TracyCZoneNS( ctx, name, depth, active ) TracyCZoneN( ctx, name, active )
#  define TracyCZoneCS( ctx, color, depth, active ) TracyCZoneC( ctx, color, active )
#  define TracyCZoneNCS( ctx, name, color, depth, active ) TracyCZoneNC( ctx, name, color, active )

#  define TracyCAllocS( ptr, size, depth ) TracyCAlloc( ptr, size )
#  define TracyCFreeS( ptr, depth ) TracyCFree( ptr )
#  define TracyCSecureAllocS( ptr, size, depth ) TracyCSecureAlloc( ptr, size )
#  define TracyCSecureFreeS( ptr, depth ) TracyCSecureFree( ptr )

#  define TracyCAllocNS( ptr, size, depth, name ) TracyCAllocN( ptr, size, name )
#  define TracyCFreeNS( ptr, depth, name ) TracyCFreeN( ptr, name )
#  define TracyCSecureAllocNS( ptr, size, depth, name ) TracyCSecureAllocN( ptr, size, name )
#  define TracyCSecureFreeNS( ptr, depth, name ) TracyCSecureFreeN( ptr, name )

#  define TracyCMessageS( txt, size, depth ) TracyCMessage( txt, size )
#  define TracyCMessageLS( txt, depth ) TracyCMessageL( txt )
#  define TracyCMessageCS( txt, size, color, depth ) TracyCMessageC( txt, size, color )
#  define TracyCMessageLCS( txt, color, depth ) TracyCMessageLC( txt, color )
#endif

#endif

#ifdef __cplusplus
}
#endif

#endif
