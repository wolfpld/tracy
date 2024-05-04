#ifndef __TRACYMEMORY_HPP__
#define __TRACYMEMORY_HPP__

#include <atomic>
#include <stdint.h>

namespace tracy
{

extern std::atomic<int64_t> memUsage;

}

#endif
