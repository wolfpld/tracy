#ifndef __TRACYSTRINGHELPERS_HPP__
#define __TRACYSTRINGHELPERS_HPP__

#include <assert.h>
#include <string.h>

#include "../common/TracyAlloc.hpp"

namespace tracy
{

static inline char* CopyString( const char* src, size_t sz )
{
    assert( strlen( src ) == sz );
    auto dst = (char*)tracy_malloc( sz + 1 );
    memcpy( dst, src, sz );
    dst[sz] = '\0';
    return dst;
}

static inline char* CopyString( const char* src )
{
    const auto sz = strlen( src );
    auto dst = (char*)tracy_malloc( sz + 1 );
    memcpy( dst, src, sz );
    dst[sz] = '\0';
    return dst;
}

static inline char* CopyStringFast( const char* src, size_t sz )
{
    assert( strlen( src ) == sz );
    auto dst = (char*)tracy_malloc_fast( sz + 1 );
    memcpy( dst, src, sz );
    dst[sz] = '\0';
    return dst;
}

static inline char* CopyStringFast( const char* src )
{
    const auto sz = strlen( src );
    auto dst = (char*)tracy_malloc_fast( sz + 1 );
    memcpy( dst, src, sz );
    dst[sz] = '\0';
    return dst;
}

}

#endif
