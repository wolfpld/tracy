#ifdef _MSC_VER
#  pragma warning( disable: 4244 )  // conversion from don't care to whatever, possible loss of data
#endif
#ifdef __MINGW32__
#  define __STDC_FORMAT_MACROS
#endif

#include <assert.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h> // llabs()
#include <string.h>

#include "TracyPrint.hpp"

namespace tracy
{

static const char* IntTable100 =
    "00010203040506070809"
    "10111213141516171819"
    "20212223242526272829"
    "30313233343536373839"
    "40414243444546474849"
    "50515253545556575859"
    "60616263646566676869"
    "70717273747576777879"
    "80818283848586878889"
    "90919293949596979899";

static inline void PrintTinyInt( char*& buf, uint64_t v )
{
    assert( v < 100 );
    if( v >= 10 )
    {
        *buf++ = '0' + v/10;
    }
    *buf++ = '0' + v%10;
}

static inline void PrintTinyInt0( char*& buf, uint64_t v )
{
    assert( v < 100 );
    if( v >= 10 )
    {
        *buf++ = '0' + v/10;
    }
    else
    {
        *buf++ = '0';
    }
    *buf++ = '0' + v%10;
}

static inline void PrintSmallInt( char*& buf, uint64_t v )
{
    assert( v < 1000 );
    if( v >= 100 )
    {
        memcpy( buf, IntTable100 + v/10*2, 2 );
        buf += 2;
    }
    else if( v >= 10 )
    {
        *buf++ = '0' + v/10;
    }
    *buf++ = '0' + v%10;
}

static inline void PrintSmallInt0( char*& buf, uint64_t v )
{
    assert( v < 1000 );
    if( v >= 100 )
    {
        memcpy( buf, IntTable100 + v/10*2, 2 );
        buf += 2;
    }
    else if( v >= 10 )
    {
        *buf++ = '0';
        *buf++ = '0' + v/10;
    }
    else
    {
        memcpy( buf, "00", 2 );
        buf += 2;
    }
    *buf++ = '0' + v%10;
}

static inline void PrintFrac00( char*& buf, uint64_t v )
{
    *buf++ = '.';
    v += 5;
    if( v/10%10 == 0 )
    {
        *buf++ = '0' + v/100;
    }
    else
    {
        memcpy( buf, IntTable100 + v/10*2, 2 );
        buf += 2;
    }
}

static inline void PrintFrac0( char*& buf, uint64_t v )
{
    *buf++ = '.';
    *buf++ = '0' + (v+50)/100;
}

static inline void PrintSmallIntFrac( char*& buf, uint64_t v )
{
    uint64_t in = v / 1000;
    uint64_t fr = v % 1000;
    if( fr >= 995 )
    {
        if( in < 999 )
        {
            PrintSmallInt( buf, in+1 );
        }
        else
        {
            memcpy( buf, "1000", 4 );
            buf += 4;
        }
    }
    else
    {
        PrintSmallInt( buf, in );
        if( fr > 5 )
        {
            PrintFrac00( buf, fr );
        }
    }
}

static inline void PrintSecondsFrac( char*& buf, uint64_t v )
{
    uint64_t in = v / 1000;
    uint64_t fr = v % 1000;
    if( fr >= 950 )
    {
        PrintTinyInt0( buf, in+1 );
    }
    else
    {
        PrintTinyInt0( buf, in );
        if( fr > 50 )
        {
            PrintFrac0( buf, fr );
        }
    }
}

const char* TimeToString( int64_t _ns )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    char* bufstart = buf;
    bufsel = ( bufsel + 1 ) % Pool;

    uint64_t ns;
    if( _ns < 0 )
    {
        *buf = '-';
        buf++;
        ns = -_ns;
    }
    else
    {
        ns = _ns;
    }

    if( ns < 1000 )
    {
        PrintSmallInt( buf, ns );
        memcpy( buf, " ns", 4 );
    }
    else if( ns < 1000ll * 1000 )
    {
        PrintSmallIntFrac( buf, ns );
        memcpy( buf, " \xce\xbcs", 5 );
    }
    else if( ns < 1000ll * 1000 * 1000 )
    {
        PrintSmallIntFrac( buf, ns / 1000 );
        memcpy( buf, " ms", 4 );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 )
    {
        PrintSmallIntFrac( buf, ns / ( 1000ll * 1000 ) );
        memcpy( buf, " s", 3 );
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 )
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns - m * ( 1000ll * 1000 * 1000 * 60 ) ) / ( 1000ll * 1000 );
        PrintTinyInt( buf, m );
        *buf++ = ':';
        PrintSecondsFrac( buf, s );
        *buf++ = '\0';
    }
    else if( ns < 1000ll * 1000 * 1000 * 60 * 60 * 24 )
    {
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - h * ( 60 * 60 ) - m * 60 );
        PrintTinyInt( buf, h );
        *buf++ = ':';
        PrintTinyInt0( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        *buf++ = '\0';
    }
    else
    {
        const auto d = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 * 24 ) );
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) - d * 24 );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - d * ( 60 * 24 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - d * ( 60 * 60 * 24 ) - h * ( 60 * 60 ) - m * 60 );
        assert( d < 100 );
        PrintTinyInt( buf, d );
        *buf++ = 'd';
        PrintTinyInt0( buf, h );
        *buf++ = ':';
        PrintTinyInt0( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        *buf++ = '\0';
    }
    return bufstart;
}

const char* TimeToStringExact( int64_t _ns )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    char* bufstart = buf;
    bufsel = ( bufsel + 1 ) % Pool;

    uint64_t ns;
    if( _ns < 0 )
    {
        *buf = '-';
        buf++;
        ns = -_ns;
    }
    else
    {
        ns = _ns;
    }

    const char* numStart = buf;

    if( ns >= 1000ll * 1000 * 1000 * 60 * 60 * 24 )
    {
        const auto d = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 * 24 ) );
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) - d * 24 );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - d * ( 60 * 24 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - d * ( 60 * 60 * 24 ) - h * ( 60 * 60 ) - m * 60 );
        if( d < 100 )
        {
            PrintTinyInt( buf, d );
            *buf++ = 'd';
        }
        else
        {
            memcpy( buf, "100+d", 5 );
            buf += 5;
        }
        PrintTinyInt0( buf, h );
        *buf++ = ':';
        PrintTinyInt0( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        ns %= 1000ll * 1000 * 1000;
    }
    else if( ns >= 1000ll * 1000 * 1000 * 60 * 60 )
    {
        const auto h = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 * 60 ) );
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) - h * 60 );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - h * ( 60 * 60 ) - m * 60 );
        PrintTinyInt( buf, h );
        *buf++ = ':';
        PrintTinyInt0( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        ns %= 1000ll * 1000 * 1000;
    }
    else if( ns >= 1000ll * 1000 * 1000 * 60 )
    {
        const auto m = int64_t( ns / ( 1000ll * 1000 * 1000 * 60 ) );
        const auto s = int64_t( ns / ( 1000ll * 1000 * 1000 ) - m * 60 );
        PrintTinyInt( buf, m );
        *buf++ = ':';
        PrintTinyInt0( buf, s );
        ns %= 1000ll * 1000 * 1000;
    }
    else if( ns >= 1000ll * 1000 * 1000 )
    {
        PrintTinyInt( buf, int64_t( ns / ( 1000ll * 1000 * 1000 ) ) );
        *buf++ = 's';
        ns %= 1000ll * 1000 * 1000;
    }

    if( ns > 0 )
    {
        if( buf != numStart ) *buf++ = ' ';
        if( ns >= 1000ll * 1000 )
        {
            PrintSmallInt0( buf, int64_t( ns / ( 1000ll * 1000 ) ) );
            *buf++ = ',';
            ns %= 1000ll * 1000;
        }
        else
        {
            memcpy( buf, "000,", 4 );
            buf += 4;
        }
        if( ns >= 1000ll )
        {
            PrintSmallInt0( buf, int64_t( ns / 1000ll ) );
            *buf++ = ',';
            ns %= 1000ll;
        }
        else
        {
            memcpy( buf, "000,", 4 );
            buf += 4;
        }
        PrintSmallInt0( buf, ns );
        *buf++ = 'n';
        *buf++ = 's';
    }
    else
    {
        memcpy( buf, "000,000,000ns", 13 );
        buf += 13;
    }

    *buf++ = '\0';

    return bufstart;
}

const char* MemSizeToString( int64_t val )
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    const auto aval = llabs( val );

    if( aval < 10000ll )
    {
        sprintf( buf, "%" PRIi64 " bytes", val );
        return buf;
    }

    enum class Unit
    {
        Kilobyte,
        Megabyte,
        Gigabyte,
        Terabyte
    };
    Unit unit;

    char* ptr;
    if( aval < 10000ll * 1024 )
    {
        ptr = PrintFloat( buf, buf+64, val / 1024., 2 );
        unit = Unit::Kilobyte;
    }
    else if( aval < 10000ll * 1024 * 1024 )
    {
        ptr = PrintFloat( buf, buf+64, val / ( 1024. * 1024 ), 2 );
        unit = Unit::Megabyte;
    }
    else if( aval < 10000ll * 1024 * 1024 * 1024 )
    {
        ptr = PrintFloat( buf, buf+64, val / ( 1024. * 1024 * 1024 ), 2 );
        unit = Unit::Gigabyte;
    }
    else
    {
        ptr = PrintFloat( buf, buf+64, val / ( 1024. * 1024 * 1024 * 1024 ), 2 );
        unit = Unit::Terabyte;
    }

    ptr--;
    while( ptr >= buf && *ptr == '0' ) ptr--;
    if( *ptr != '.' ) ptr++;

    *ptr++ = ' ';
    switch( unit )
    {
    case Unit::Kilobyte:
        *ptr++ = 'K';
        break;
    case Unit::Megabyte:
        *ptr++ = 'M';
        break;
    case Unit::Gigabyte:
        *ptr++ = 'G';
        break;
    case Unit::Terabyte:
        *ptr++ = 'T';
        break;
    default:
        assert( false );
        break;
    }
    *ptr++ = 'B';
    *ptr++ = '\0';

    return buf;
}

const char* LocationToString( const char* fn, uint32_t line )
{
    if( line == 0 ) return fn;

    enum { Pool = 8 };
    static char bufpool[Pool][4096];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;

    sprintf( buf, "%s:%i", fn, line );
    return buf;
}

namespace detail
{

char* RealToStringGetBuffer()
{
    enum { Pool = 8 };
    static char bufpool[Pool][64];
    static int bufsel = 0;
    char* buf = bufpool[bufsel];
    bufsel = ( bufsel + 1 ) % Pool;
    return buf;
}

}

}
