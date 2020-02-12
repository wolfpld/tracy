#ifndef __TRACYBADVERSION_HPP__
#define __TRACYBADVERSION_HPP__

#include "../common/TracyForceInline.hpp"

namespace tracy
{

struct BadVersionState
{
    enum State
    {
        Ok,
        BadFile,
        ReadError,
        UnsupportedVersion,
        LegacyVersion
    };

    State state = Ok;
    int version = 0;
};

namespace detail
{
void BadVersionImpl( BadVersionState& badVer );
}

tracy_force_inline void BadVersion( BadVersionState& badVer ) { if( badVer.state != BadVersionState::Ok ) detail::BadVersionImpl( badVer ); }

}

#endif
