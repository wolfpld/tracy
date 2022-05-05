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

#include <stdint.h>
#include <string.h>
#include <cmath>

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

template<typename T>
int DigitsLeftOfDecimalPoint( T val ) {
  int digits = 1;
  T absVal = std::abs( val );
  T maxAbsValForCurrentDigits = 10;
  while( absVal >= maxAbsValForCurrentDigits ) {
    ++digits;
    maxAbsValForCurrentDigits *= static_cast<T>( 10 );
  }
  return digits;
}

template<typename T>
int CharsLeftOfDecimalPoint( T val ) {
  int extraChars = std::signbit( val ) ? 1 : 0;
  return extraChars + DigitsLeftOfDecimalPoint( val );
}

template<typename T>
int DigitsRightOfDecimalPoint( T val, int maxChars ) {
  int charsLeftOfPoint = CharsLeftOfDecimalPoint( val );
  if( charsLeftOfPoint > maxChars ) {
    fprintf( stderr, "Maximum of %d chars is insufficient to print value %g\n",
             maxChars, val );
    abort();
  }
  if ( charsLeftOfPoint == maxChars ) {
    // maxChars is just large enough for the integer part, no room left for
    // a decimal point.
    return 0;
  } else {
    assert( charsLeftOfPoint < maxChars );
    return maxChars - 1 - charsLeftOfPoint;
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

// Similar to PrintFloat, but prints exactly `fixedWidth` characters,
// right-justified.
template<typename T>
char* PrintFloatFixedWidth( char* begin, char* end, T value, int fixedWidth ) {
  int digitsRight = detail::DigitsRightOfDecimalPoint( value, fixedWidth );
  char buf[32];
  char* bufEnd = buf + sizeof buf;
  char* printEnd = PrintFloat( buf, bufEnd, value, digitsRight );
  int width = printEnd - buf;
  assert( width <= fixedWidth );
  char* dstPtr = begin;
  for( int i = width; i < fixedWidth; ++i ) {
    assert( end > dstPtr );
    *dstPtr++ = ' ';
  }
  assert( end >= dstPtr + width );
  memcpy( dstPtr, buf, width );
  dstPtr += width;
  assert(dstPtr == begin + fixedWidth);
  return dstPtr;
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
