#ifndef __TRACYLUA_HPP__
#define __TRACYLUA_HPP__

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
    lua_setfield( L, -2, "ZoneEnd" );
    lua_pushcfunction( L, detail::noop );
    lua_setfield( L, -2, "Message" );
    lua_setglobal( L, "tracy" );
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
                else
                {
                    script += 10;
                }
            }
            else if( strncmp( script + 6, "Message(", 8 ) == 0 )
            {
                unsigned int cnt = 1;
                auto end = script + 14;
                while( cnt != 0 )
                {
                    if( *end == '(' ) cnt++;
                    else if( *end == ')' ) cnt--;
                    end++;
                }
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

#include "common/TracySystem.hpp"
#include "client/TracyProfiler.hpp"

namespace tracy
{

namespace detail
{

static inline int LuaZoneBegin( lua_State* L )
{
    const uint32_t color = 0x00CC8855;

    lua_Debug dbg;
    lua_getstack( L, 1, &dbg );
    lua_getinfo( L, "Snl", &dbg );

    const uint32_t line = dbg.currentline;
    const auto name = dbg.name ? dbg.name : dbg.short_src;
    const auto fsz = strlen( name );
    const auto ssz = strlen( dbg.source );

    // Data layout:
    //  4b  payload size
    //  4b  color
    //  4b  source line
    //  fsz function name
    //  1b  null terminator
    //  ssz source file name
    const uint32_t sz = 4 + 4 + 4 + fsz + 1 + ssz;
    auto ptr = (char*)tracy_malloc( sz );
    memcpy( ptr, &sz, 4 );
    memcpy( ptr + 4, &color, 4 );
    memcpy( ptr + 8, &line, 4 );
    memcpy( ptr + 12, name, fsz+1 );
    memcpy( ptr + 12 + fsz + 1, dbg.source, ssz );

    Magic magic;
    auto& token = s_token.ptr;
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
    item->hdr.type = QueueType::ZoneBeginAllocSrcLoc;
    item->zoneBegin.time = Profiler::GetTime( item->zoneBegin.cpu );
    item->zoneBegin.thread = GetThreadHandle();
    item->zoneBegin.srcloc = (uint64_t)ptr;
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaZoneEnd( lua_State* L )
{
    Magic magic;
    auto& token = s_token.ptr;
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
    item->hdr.type = QueueType::ZoneEnd;
    item->zoneEnd.time = Profiler::GetTime( item->zoneEnd.cpu );
    item->zoneEnd.thread = GetThreadHandle();
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

static inline int LuaMessage( lua_State* L )
{
    auto txt = lua_tostring( L, 1 );
    const auto size = strlen( txt );

    Magic magic;
    auto& token = s_token.ptr;
    auto ptr = (char*)tracy_malloc( size+1 );
    memcpy( ptr, txt, size );
    ptr[size] = '\0';
    auto& tail = token->get_tail_index();
    auto item = token->enqueue_begin<moodycamel::CanAlloc>( magic );
    item->hdr.type = QueueType::Message;
    item->message.time = Profiler::GetTime();
    item->message.thread = GetThreadHandle();
    item->message.text = (uint64_t)ptr;
    tail.store( magic + 1, std::memory_order_release );
    return 0;
}

}

static inline void LuaRegister( lua_State* L )
{
    lua_newtable( L );
    lua_pushcfunction( L, detail::LuaZoneBegin );
    lua_setfield( L, -2, "ZoneBegin" );
    lua_pushcfunction( L, detail::LuaZoneEnd );
    lua_setfield( L, -2, "ZoneEnd" );
    lua_pushcfunction( L, detail::LuaMessage );
    lua_setfield( L, -2, "Message" );
    lua_setglobal( L, "tracy" );
}

static inline void LuaRemove( char* script ) {}

}

#endif

#endif
