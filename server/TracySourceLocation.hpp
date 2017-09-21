#ifndef __TRACYSOURCELOCATION_HPP__
#define __TRACYSOURCELOCATION_HPP__

#include <functional>
#include <stdint.h>
#include <string.h>

namespace tracy
{

struct SourceLocation
{
    uint64_t filename;
    uint64_t function;
    uint32_t line;

    struct Hasher
    {
        size_t operator()( const SourceLocation& v ) const
        {
            const static std::hash<uint64_t> hash;
            return hash( v.filename ) ^ hash( v.function ) ^ hash( v.line );
        }
    };

    struct Comparator
    {
        bool operator()( const SourceLocation& lhs, const SourceLocation& rhs ) const
        {
            return memcmp( &lhs, &rhs, sizeof( SourceLocation ) ) == 0;
        }
    };
};

}

#endif
