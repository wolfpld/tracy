//
//          Tracy profiler
//         ----------------
//
// On multi-DLL projects compile and
// link with this source file (and none
// other) in the executable and in
// DLLs / shared objects that link to
// the main DLL.
//

// Define TRACY_ENABLE to enable profiler.

#include "common/TracySystem.cpp"

#ifdef TRACY_ENABLE

#include "client/TracyProfiler.hpp"
#include "client/concurrentqueue.h"

#include "common/TracyQueue.hpp"

namespace tracy
{
#ifdef _MSC_VER
#  define DLL_IMPORT __declspec(dllimport)
#else
#  define DLL_IMPORT
#endif

    DLL_IMPORT moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* get_token();
    DLL_IMPORT void*(*get_rpmalloc())(size_t size);
    DLL_IMPORT void(*get_rpfree())(void* ptr);
    DLL_IMPORT Profiler& get_profiler();

#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6
    DLL_IMPORT int64_t(*get_GetTimeImpl())();

    int64_t(*GetTimeImpl)() = get_GetTimeImpl();
#endif

#ifdef TRACY_COLLECT_THREAD_NAMES
    DLL_IMPORT std::atomic<ThreadNameData*>& get_threadNameData();
    DLL_IMPORT void(*get_rpmalloc_thread_initialize())();

    std::atomic<ThreadNameData*>& s_threadNameData = get_threadNameData();
    void(*rpmalloc_thread_initialize_fpt)() = get_rpmalloc_thread_initialize();

    void rpmalloc_thread_initialize(void)
    {
        rpmalloc_thread_initialize_fpt();
    }
#endif

    static void*(*rpmalloc_fpt)(size_t size) = get_rpmalloc();
    static void(*rpfree_fpt)(void* ptr) = get_rpfree();

    RPMALLOC_RESTRICT void* rpmalloc(size_t size)
    {
        return rpmalloc_fpt(size);
    }

    void rpfree(void* ptr)
    {
        rpfree_fpt(ptr);
    }

    Profiler& s_profiler = get_profiler();

    thread_local ProducerWrapper s_token { get_token() };
}

#endif
