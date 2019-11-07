#ifndef __TRACY__CHARUTIL_HPP__
#define __TRACY__CHARUTIL_HPP__

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define XXH_STATIC_LINKING_ONLY
#include "tracy_xxh3.h"
#include "tracy_flat_hash_map.hpp"

namespace tracy
{
namespace charutil
{

static inline size_t hash( const char* str )
{
    const auto sz = strlen( str );
    return XXH3_64bits( str, sz );
}

static inline size_t hash( const char* str, size_t sz )
{
    return XXH3_64bits( str, sz );
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
