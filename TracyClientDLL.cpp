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

#ifdef __APPLE__
#  include <TargetConditionals.h>
#endif

namespace tracy
{
#ifdef _WIN32
#  define DLL_IMPORT __declspec(dllimport)
#else
#  define DLL_IMPORT
#endif

    DLL_IMPORT void*(*get_rpmalloc())(size_t size);
    DLL_IMPORT void(*get_rpfree())(void* ptr);
    DLL_IMPORT moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer*(*get_token())();
    DLL_IMPORT Profiler&(*get_profiler())();
    DLL_IMPORT std::atomic<uint32_t>&(*get_getlockcounter())();
    DLL_IMPORT std::atomic<uint8_t>&(*get_getgpuctxcounter())();
    DLL_IMPORT GpuCtxWrapper&(*get_getgpuctx())();

    static void*(*rpmalloc_fpt)(size_t size) = get_rpmalloc();
    static void(*rpfree_fpt)(void* ptr) = get_rpfree();
    static moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer*(*GetToken_fpt)() = get_token();
    static Profiler&(*GetProfiler_fpt)() = get_profiler();
    static std::atomic<uint32_t>&(*GetLockCounter_fpt)() = get_getlockcounter();
    static std::atomic<uint8_t>&(*GetGpuCtxCounter_fpt)() = get_getgpuctxcounter();
    static GpuCtxWrapper&(*GetGpuCtx_fpt)() = get_getgpuctx();

    RPMALLOC_RESTRICT void* rpmalloc(size_t size) { return rpmalloc_fpt(size); }
    void rpfree(void* ptr) { rpfree_fpt(ptr); }
    moodycamel::ConcurrentQueue<QueueItem>::ExplicitProducer* GetToken() { return GetToken_fpt(); }
    Profiler& GetProfiler() { return GetProfiler_fpt(); }
    std::atomic<uint32_t>& GetLockCounter() { return GetLockCounter_fpt(); }
    std::atomic<uint8_t>& GetGpuCtxCounter() { return GetGpuCtxCounter_fpt(); }
    GpuCtxWrapper& GetGpuCtx() { return GetGpuCtx_fpt(); }

#if defined TRACY_HW_TIMER && __ARM_ARCH >= 6 && !defined TARGET_OS_IOS
    DLL_IMPORT int64_t(*get_GetTimeImpl())();

    int64_t(*GetTimeImpl)() = get_GetTimeImpl();
#endif

#ifdef TRACY_COLLECT_THREAD_NAMES
    DLL_IMPORT std::atomic<ThreadNameData*>&(*get_getthreadnamedata())();
    DLL_IMPORT void(*get_rpmalloc_thread_initialize())();
    DLL_IMPORT void(*get_InitRPMallocThread())();

    static std::atomic<ThreadNameData*>&(*GetThreadNameData_fpt)() = get_getthreadnamedata();
    static void(*rpmalloc_thread_initialize_fpt)() = get_rpmalloc_thread_initialize();
    static void(*InitRPMallocThread_fpt)() = get_InitRPMallocThread();

    std::atomic<ThreadNameData*>& GetThreadNameData() { return GetThreadNameData_fpt(); }
    void rpmalloc_thread_initialize(void) { rpmalloc_thread_initialize_fpt(); }
    void InitRPMallocThread() { InitRPMallocThread_fpt(); }
#endif

#ifdef TRACY_ON_DEMAND
    DLL_IMPORT LuaZoneState&(*get_getluazonestate())();

    static LuaZoneState&(*GetLuaZoneState_fpt)() = get_getluazonestate();

    LuaZoneState& GetLuaZoneState() { return GetLuaZoneState_fpt(); }
#endif
}

#endif
