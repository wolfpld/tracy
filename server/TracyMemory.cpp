#include "TracyMemory.hpp"

namespace tracy
{

MemCounter memUsage;
thread_local std::atomic<int64_t>* MemCounter::s_scope = nullptr;

}
