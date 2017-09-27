#ifndef __TRACY__CHARUTIL_HPP__
#define __TRACY__CHARUTIL_HPP__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace tracy
{
namespace charutil
{

static inline uint32_t hash( const char* str )
{
    uint32_t hash = 5381;
    int c;

    while( c = *str++ )
    {
        hash = ( ( hash << 5 ) + hash ) ^ c;
    }

    return hash;
}

struct Hasher
{
    size_t operator()( const char* key ) const
    {
        return hash( key );
    }
};

struct Comparator
{
    bool operator()( const char* lhs, const char* rhs ) const
    {
        return strcmp( lhs, rhs ) == 0;
    }
};

struct LessComparator
{
    bool operator()( const char* lhs, const char* rhs ) const
    {
        return strcmp( lhs, rhs ) < 0;
    }
};

}
}

#endif
