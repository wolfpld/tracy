#ifndef __TRACYVIEWDATA_HPP__
#define __TRACYVIEWDATA_HPP__

#include <stdint.h>

namespace tracy
{

struct ViewData
{
    int64_t zvStart = 0;
    int64_t zvEnd = 0;
};

}

#endif
