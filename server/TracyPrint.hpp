#ifndef __TRACYPRINT_HPP__
#define __TRACYPRINT_HPP__

#if ( defined _MSC_VER && _MSVC_LANG >= 201703L ) || __cplusplus >= 201703L
#  if __has_include(<charconv>) && __has_include(<type_traits>)
#    include <charconv>
#    include <type_traits>
#  else
#    define NO_CHARCONV
#  endif
#else
#  define NO_CHARCONV
#endif

#if defined _MSC_VER && _MSC_VER < 1924
#  define NO_CHARCONV
#endif

#ifdef __GNUC__
#  define NO_CHARCONV
#endif

#ifdef NO_CHARCONV
#  include <stdio.h>
#endif

#include "../common/TracyForceInline.hpp"

namespace tracy
{

namespace detail
{

char* RealToStringGetBuffer();

static tracy_force_inline void RealToStringFloating( char* ptr, char* end )
{
    if( *ptr == '-' ) ptr++;
    const auto vbegin = ptr;

    while( *ptr != '\0' && *ptr != '.' ) ptr++;
    auto sz = end - ptr + 1;

    while( ptr - vbegin > 3 )
    {
        ptr -= 3;
        memmove( ptr+1, ptr, sz+3 );
        *ptr = ',';
        sz += 4;
    }

    while( *ptr != '\0' && *ptr != '.' ) ptr++;
    if( *ptr == '\0' ) return;

    while( *ptr != '\0' ) ptr++;
    ptr--;
    while( *ptr == '0' ) ptr--;
    if( *ptr != '.' && *ptr != ',' ) ptr++;
    *ptr = '\0';
}

static tracy_force_inline void RealToStringInteger( char* buf, char* end )
{
    if( *buf == '-' ) buf++;
    auto ptr = end;
    auto sz = 1;
    while( ptr - buf > 3 )
    {
        ptr -= 3;
        memmove( ptr+1, ptr, sz+3 );
        *ptr = ',';
        sz += 4;
    }
}

}

template<typename T>
static inline char* PrintFloat( char* begin, char* end, T value, int precision )
{
#ifndef NO_CHARCONV
    return std::to_chars( begin, end, value, std::chars_format::fixed, precision ).ptr;
#else
    return begin + sprintf( begin, "%.*f", precision, value );
#endif
}

template<typename T>
static inline char* PrintFloat( char* begin, char* end, T value )
{
#ifndef NO_CHARCONV
    return std::to_chars( begin, end, value, std::chars_format::fixed ).ptr;
#else
    return begin + sprintf( begin, "%f", value );
#endif
}

#ifndef NO_CHARCONV
template<typename T>
static inline const char* RealToString( T val )
{
    auto buf = detail::RealToStringGetBuffer();
    auto end = std::to_chars( buf, buf+64, val ).ptr;
    *end = '\0';
    if constexpr ( std::is_integral_v<T> )
    {
        detail::RealToStringInteger( buf, end );
    }
    else
    {
        detail::RealToStringFloating( buf, end );
    }
    return buf;
}
#else
static inline const char* RealToString( double val )
{
    auto buf = detail::RealToStringGetBuffer();
    const auto sz = sprintf( buf, "%f", val );
    detail::RealToStringFloating( buf, buf+sz );
    return buf;
}
#endif

const char* TimeToString( int64_t ns );
const char* TimeToStringExact( int64_t ns );
const char* MemSizeToString( int64_t val );
const char* LocationToString( const char* fn, uint32_t line );

}

#endif
