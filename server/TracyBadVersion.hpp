#ifndef __TRACYBADVERSION_HPP__
#define __TRACYBADVERSION_HPP__

#include "../common/TracyForceInline.hpp"

namespace tracy
{

namespace detail
{
void BadVersionImpl( int& badVer );
}

tracy_force_inline void BadVersion( int& badVer ) { if( badVer != 0 ) detail::BadVersionImpl( badVer ); }

}

#endif
