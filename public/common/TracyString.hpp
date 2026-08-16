#ifndef __TRACYSTRING_HPP__
#define __TRACYSTRING_HPP__

#include <stddef.h>
#include <string.h>

#include "TracyAssert.hpp"

namespace tracy
{

static inline size_t strzcpy( char* __restrict dst, const char* __restrict src, size_t dstSize )
{
    TRACY_ASSERT( dstSize > 0 );

    const auto end = (const char*)memchr( src, '\0', dstSize );
    if( end != nullptr )
    {
        const auto srcSz = end - src;
        memcpy( dst, src, srcSz + 1 );
        return srcSz;
    }
    else
    {
        memcpy( dst, src, dstSize - 1 );
        dst[dstSize - 1] = '\0';
        return dstSize - 1;
    }
}

}

#endif
