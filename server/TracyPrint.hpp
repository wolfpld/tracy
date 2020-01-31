#ifndef __TRACYPRINT_HPP__
#define __TRACYPRINT_HPP__

#include <stdio.h>

namespace tracy
{

template<typename T>
static inline char* PrintFloat( char* begin, char* end, T value, int precision )
{
    return begin + sprintf( begin, "%.*f", precision, value );
}

const char* TimeToString( int64_t ns );
const char* RealToString( double val, bool separator );
const char* MemSizeToString( int64_t val );

}

#endif
