#ifndef __TRACYSTACKFRAMES_HPP__
#define __TRACYSTACKFRAMES_HPP__

namespace tracy
{

struct StringMatch
{
    const char* str;
    size_t len;
};

extern const char** s_tracyStackFrames;
extern const StringMatch* s_tracySkipSubframes;

}

#endif
