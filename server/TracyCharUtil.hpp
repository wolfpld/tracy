#ifndef __TRACY__CHARUTIL_HPP__
#define __TRACY__CHARUTIL_HPP__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "tracy_flat_hash_map.hpp"

namespace tracy
{
namespace charutil
{

static inline uint32_t hash( const char* str )
{
    uint32_t hash = 5381;
    int c;

    while( ( c = *str++ ) != 0 )
    {
        hash = ( ( hash << 5 ) + hash ) ^ c;
    }

    return hash;
}

static inline uint32_t hash( const char* str, size_t sz )
{
    uint32_t hash = 5381;
    int c;

    while( sz > 0 )
    {
        c = *str++;
        hash = ( ( hash << 5 ) + hash ) ^ c;
        sz--;
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

struct HasherPOT : public Hasher
{
    typedef tracy::power_of_two_hash_policy hash_policy;
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

struct StringKey
{
    const char* ptr;
    size_t sz;

    struct Hasher
    {
        size_t operator()( const StringKey& key ) const
        {
            return hash( key.ptr, key.sz );
        }
    };

    struct HasherPOT : public Hasher
    {
        typedef tracy::power_of_two_hash_policy hash_policy;
    };

    struct Comparator
    {
        bool operator()( const StringKey& lhs, const StringKey& rhs ) const
        {
            return lhs.sz == rhs.sz && memcmp( lhs.ptr, rhs.ptr, lhs.sz ) == 0;
        }
    };
};

}
}

#endif
