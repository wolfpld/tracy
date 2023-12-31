#ifndef __TRACYBADVERSION_HPP__
#define __TRACYBADVERSION_HPP__

#include <string>

#include "../public/common/TracyForceInline.hpp"

struct ImFont;

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
        LegacyVersion,
        LoadFailure
    };

    State state = Ok;
    int version = 0;
    std::string msg;
};

namespace detail
{
void BadVersionImpl( BadVersionState& badVer, ImFont* big );
}

tracy_force_inline void BadVersion( BadVersionState& badVer, ImFont* big ) { if( badVer.state != BadVersionState::Ok ) detail::BadVersionImpl( badVer, big ); }

}

#endif
