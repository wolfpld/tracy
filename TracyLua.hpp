#ifndef __TRACYLUA_HPP__
#define __TRACYLUA_HPP__

// Include this file after you include lua headers.

#ifndef TRACY_ENABLE

#include <string.h>

namespace tracy
{

namespace detail
{
static inline int noop( lua_State* L ) { return 0; }
}

static inline void LuaRegister( lua_State* L )
{
    lua_newtable( L );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "ZoneBegin" );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "ZoneBeginN" );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "ZoneEnd" );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "ZoneText" );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "ZoneName" );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "Message" );
    lua_setglobal( L, "tracy" );
}

static inline char* FindEnd( char* ptr )
{
    unsigned int cnt = 1;
    while( cnt != 0 )
    {
        if( *ptr == '(' ) cnt++;
        else if( *ptr == ')' ) cnt--;
        ptr++;
    }
    return ptr;
}

static inline void LuaRemove( char* script )
{
    while( *script )
    {
        if( strncmp( script, "tracy.", 6 ) == 0 )
        {
            if( strncmp( script + 6, "Zone", 4 ) == 0 )
            {
                if( strncmp( script + 10, "End()", 5 ) == 0 )
                {
                    memset( script, ' ', 15 );
                    script += 15;
                }
                else if( strncmp( script + 10, "Begin()", 7 ) == 0 )
                {
                    memset( script, ' ', 17 );
                    script += 17;
                }
                else if( strncmp( script + 10, "Text(", 5 ) == 0 )
                {
                    auto end = FindEnd( script + 15 );
                    memset( script, ' ', end - script );
                    script = end;
                }
                else if( strncmp( script + 10, "Name(", 5 ) == 0 )
                {
                    auto end = FindEnd( script + 15 );
                    memset( script, ' ', end - script );
                    script = end;
                }
                else if( strncmp( script + 10, "BeginN(", 7 ) == 0 )
                {
                    auto end = FindEnd( script + 17 );
                    memset( script, ' ', end - script );
                    script = end;
                }
                else
                {
                    script += 10;
                }
            }
            else if( strncmp( script + 6, "Message(", 8 ) == 0 )
            {
                auto end = FindEnd( script + 14 );
                memset( script, ' ', end - script );
                script = end;
            }
            else
            {
                script += 6;
            }
        }
        else
        {
            script++;
        }
    }
}

}

#else

#include <assert.h>

#include "common/TracyColor.hpp"
#include "common/TracyAlign.hpp"
#include "common/TracySystem.hpp"
#include "client/TracyProfiler.hpp"

namespace tracy
{

#ifdef TRACY_ON_DEMAND
extern thread_local LuaZoneState s_luaZoneState;
#endif

namespace detail
{

static inline int LuaZoneBegin( lua_State* L )
{
#ifdef TRACY_ON_DEMAND
    const auto zoneCnt = s_luaZoneState.counter++;
    if( zoneCnt != 0 && !s_luaZoneState.active ) return 0;
    s_luaZoneState.active = s_profiler.IsConnected();
    if( !s_luaZoneState.active ) return 0;
#endif

    const uint32_t color = Color::DeepSkyBlue3;

    lua_Debug dbg;
    lua_getstack( L, 1, &dbg );
    lua_getinfo( L, "Snl", &dbg );

    const uint32_t line = dbg.currentline;
    const auto func = dbg.name ? dbg.name : dbg.short_src;
    const auto fsz = strlen( func );
    const auto ssz = strlen( dbg.source );

    // Data layout:
    //  4b  payload size
    //  4b  color
    //  4b  source line
    //  fsz function name
    //  1b  null terminator
    //  ssz source file name
    //  1b  null terminator
    const uint32_t sz = 4 + 4 + 4 + fsz + 1 + ssz + 1;
    auto ptr = (char*)tracy_malloc( sz );
    memcpy( ptr, &sz, 4 );
    memcpy( ptr + 4, &color, 4 );
    memcpy( ptr + 8, &line, 4 );
    memcpy( ptr + 12, func, fsz+1 );
    memcpy( ptr + 12 + fsz + 1, dbg.source, ssz + 1 );

    Magic magic;
    auto& token = s_token.ptr;
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::ZoneBeginAllocSrcLoc );
#ifdef TRACY_RDTSCP_OPT
    MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
    uint32_t cpu;
    MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
    MemWrite( &item->zoneBegin.cpu, cpu );
#endif
    MemWrite( &item->zoneBegin.thread, GetThreadHandle() );
    MemWrite( &item->zoneBegin.srcloc, (uint64_t)ptr );
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaZoneBeginN( lua_State* L )
{
#ifdef TRACY_ON_DEMAND
    const auto zoneCnt = s_luaZoneState.counter++;
    if( zoneCnt != 0 && !s_luaZoneState.active ) return 0;
    s_luaZoneState.active = s_profiler.IsConnected();
    if( !s_luaZoneState.active ) return 0;
#endif

    const uint32_t color = Color::DeepSkyBlue3;

    lua_Debug dbg;
    lua_getstack( L, 1, &dbg );
    lua_getinfo( L, "Snl", &dbg );

    const uint32_t line = dbg.currentline;
    const auto func = dbg.name ? dbg.name : dbg.short_src;
    size_t nsz;
    const auto name = lua_tolstring( L, 1, &nsz );
    const auto fsz = strlen( func );
    const auto ssz = strlen( dbg.source );

    // Data layout:
    //  4b  payload size
    //  4b  color
    //  4b  source line
    //  fsz function name
    //  1b  null terminator
    //  ssz source file name
    //  1b  null terminator
    //  nsz zone name
    const uint32_t sz = 4 + 4 + 4 + fsz + 1 + ssz + 1 + nsz;
    auto ptr = (char*)tracy_malloc( sz );
    memcpy( ptr, &sz, 4 );
    memcpy( ptr + 4, &color, 4 );
    memcpy( ptr + 8, &line, 4 );
    memcpy( ptr + 12, func, fsz+1 );
    memcpy( ptr + 12 + fsz + 1, dbg.source, ssz + 1 );
    memcpy( ptr + 12 + fsz + 1 + ssz + 1, name, nsz );

    Magic magic;
    auto& token = s_token.ptr;
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::ZoneBeginAllocSrcLoc );
#ifdef TRACY_RDTSCP_OPT
    MemWrite( &item->zoneBegin.time, Profiler::GetTime( item->zoneBegin.cpu ) );
#else
    uint32_t cpu;
    MemWrite( &item->zoneBegin.time, Profiler::GetTime( cpu ) );
    MemWrite( &item->zoneBegin.cpu, cpu );
#endif
    MemWrite( &item->zoneBegin.thread, GetThreadHandle() );
    MemWrite( &item->zoneBegin.srcloc, (uint64_t)ptr );
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaZoneEnd( lua_State* L )
{
#ifdef TRACY_ON_DEMAND
    assert( s_luaZoneState.counter != 0 );
    s_luaZoneState.counter--;
    if( !s_luaZoneState.active ) return 0;
    if( !s_profiler.IsConnected() )
    {
        s_luaZoneState.active = false;
        return 0;
    }
#endif

    Magic magic;
    auto& token = s_token.ptr;
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::ZoneEnd );
#ifdef TRACY_RDTSCP_OPT
    MemWrite( &item->zoneEnd.time, Profiler::GetTime( item->zoneEnd.cpu ) );
#else
    uint32_t cpu;
    MemWrite( &item->zoneEnd.time, Profiler::GetTime( cpu ) );
    MemWrite( &item->zoneEnd.cpu, cpu );
#endif
    MemWrite( &item->zoneEnd.thread, GetThreadHandle() );
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaZoneText( lua_State* L )
{
#ifdef TRACY_ON_DEMAND
    if( !s_luaZoneState.active ) return 0;
    if( !s_profiler.IsConnected() )
    {
        s_luaZoneState.active = false;
        return 0;
    }
#endif

    auto txt = lua_tostring( L, 1 );
    const auto size = strlen( txt );

    Magic magic;
    auto& token = s_token.ptr;
    auto ptr = (char*)tracy_malloc( size+1 );
    memcpy( ptr, txt, size );
    ptr[size] = '\0';
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::ZoneText );
    MemWrite( &item->zoneText.thread, GetThreadHandle() );
    MemWrite( &item->zoneText.text, (uint64_t)ptr );
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaZoneName( lua_State* L )
{
#ifdef TRACY_ON_DEMAND
    if( !s_luaZoneState.active ) return 0;
    if( !s_profiler.IsConnected() )
    {
        s_luaZoneState.active = false;
        return 0;
    }
#endif

    auto txt = lua_tostring( L, 1 );
    const auto size = strlen( txt );

    Magic magic;
    auto& token = s_token.ptr;
    auto ptr = (char*)tracy_malloc( size+1 );
    memcpy( ptr, txt, size );
    ptr[size] = '\0';
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::ZoneName );
    MemWrite( &item->zoneText.thread, GetThreadHandle() );
    MemWrite( &item->zoneText.text, (uint64_t)ptr );
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaMessage( lua_State* L )
{
#ifdef TRACY_ON_DEMAND
    if( !s_profiler.IsConnected() ) return 0;
#endif

    auto txt = lua_tostring( L, 1 );
    const auto size = strlen( txt );

    Magic magic;
    auto& token = s_token.ptr;
    auto ptr = (char*)tracy_malloc( size+1 );
    memcpy( ptr, txt, size );
    ptr[size] = '\0';
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<tracy::moodycamel::CanAlloc>( magic );
    MemWrite( &item->hdr.type, QueueType::Message );
    MemWrite( &item->message.time, Profiler::GetTime() );
    MemWrite( &item->message.thread, GetThreadHandle() );
    MemWrite( &item->message.text, (uint64_t)ptr );
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

}

static inline void LuaRegister( lua_State* L )
{
    lua_newtable( L );
    lua_pushcfunction( L, detail::LuaZoneBegin );
    lua_setfield( L, -2, "ZoneBegin" );
    lua_pushcfunction( L, detail::LuaZoneBeginN );
    lua_setfield( L, -2, "ZoneBeginN" );
    lua_pushcfunction( L, detail::LuaZoneEnd );
    lua_setfield( L, -2, "ZoneEnd" );
    lua_pushcfunction( L, detail::LuaZoneText );
    lua_setfield( L, -2, "ZoneText" );
    lua_pushcfunction( L, detail::LuaZoneName );
    lua_setfield( L, -2, "ZoneName" );
    lua_pushcfunction( L, detail::LuaMessage );
    lua_setfield( L, -2, "Message" );
    lua_setglobal( L, "tracy" );
}

static inline void LuaRemove( char* script ) {}

}

#endif

#endif
