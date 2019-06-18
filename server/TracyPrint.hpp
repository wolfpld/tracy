#ifndef __TRACYPRINT_HPP__
#define __TRACYPRINT_HPP__

namespace tracy
{

const char* TimeToString( int64_t ns );
const char* RealToString( double val, bool separator );
const char* MemSizeToString( int64_t val );

}

#endif
