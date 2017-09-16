#ifndef __TRACYMEMORY_HPP__
#define __TRACYMEMORY_HPP__

#include <atomic>
#include <stdlib.h>

namespace tracy
{

extern std::atomic<size_t> memUsage;

}

#endif
