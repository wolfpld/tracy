#ifndef __TRACYPRINT_HPP__
#define __TRACYPRINT_HPP__

#if ( defined _MSC_VER && _MSVC_LANG >= 201703L ) || __cplusplus >= 201703L
#  include <charconv>
#else
#  include <stdio.h>
#endif

namespace tracy
{

template<typename T>
static inline char* PrintFloat( char* begin, char* end, T value, int precision )
{
#if ( defined _MSC_VER && _MSVC_LANG >= 201703L ) || __cplusplus >= 201703L
    return std::to_chars( begin, end, value, std::chars_format::fixed, precision ).ptr;
#else
    return begin + sprintf( begin, "%.*f", precision, value );
#endif
}

template<typename T>
static inline char* PrintFloat( char* begin, char* end, T value )
{
#if ( defined _MSC_VER && _MSVC_LANG >= 201703L ) || __cplusplus >= 201703L
    return std::to_chars( begin, end, value, std::chars_format::fixed ).ptr;
#else
    return begin + sprintf( begin, "%f", value );
#endif
}

const char* TimeToString( int64_t ns );
const char* RealToString( double val );
const char* MemSizeToString( int64_t val );

}

#endif
