#include "TracyStackFrames.hpp"

namespace tracy
{

const char* s_tracyStackFrames_[] = {
    "tracy::Callstack",
    "tracy::Callstack(int)",
    "tracy::GpuCtxScope::{ctor}",
    "tracy::Profiler::SendCallstack",
    "tracy::Profiler::SendCallstack(int)",
    "tracy::Profiler::SendCallstack(int, unsigned long)",
    "tracy::Profiler::MemAllocCallstack",
    "tracy::Profiler::MemAllocCallstack(void const*, unsigned long, int)",
    "tracy::Profiler::MemFreeCallstack",
    "tracy::Profiler::MemFreeCallstack(void const*, int)",
    "tracy::ScopedZone::{ctor}",
    "tracy::ScopedZone::ScopedZone(tracy::SourceLocationData const*, int, bool)",
    "tracy::CallTrace",
    "tracy::Profiler::Message",
    nullptr
};

const char** s_tracyStackFrames = s_tracyStackFrames_;

}
