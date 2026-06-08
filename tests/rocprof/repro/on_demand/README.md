# Rocprofiler On-Demand Profiling Repro

Demonstrates that unpatched Tracy crashes when a profiler connects to a
HIP application built with `TRACY_ON_DEMAND` and `TRACY_ROCPROF`.

## Root cause

Three bugs in `TracyRocprof.cpp` break on-demand profiling:

1. **GpuNewContext not deferred.** `gpu_context_allocate()` writes a
   `GpuNewContext` queue item but does not call `DeferItem()`. When a
   Tracy client connects late, the context creation message is never
   replayed. The server then receives `GpuZoneBegin` events for a
   context it has never seen, triggering:

       Assertion `ctx' failed in ProcessGpuZoneBeginImplCommon

2. **GpuContextName not deferred.** Same function writes the context
   name ("rocprofv3") without calling `DeferItem()`. Even after fixing
   bug 1, a late-connecting client sees the GPU context but it appears
   unnamed in the profiler. Use `check_gpu_ctx_name` to verify.

3. **Kernel symbols dropped before init.** The `data->init` guard at the
   top of `tool_callback_tracing_callback()` blocks all callbacks before
   the GPU context is allocated. Kernel symbol registrations
   (`CODE_OBJECT_DEVICE_KERNEL_SYMBOL_REGISTER`) happen at HIP init
   time — before `data->init` is true — so they are silently dropped.
   Even if the crash is worked around, kernel names would be missing.

## Prerequisites

- AMD GPU with working ROCm driver
- `librocprofiler-sdk.so` available (typically at `/opt/rocm/lib/`)
- `/opt/rocm/bin/hipcc`

## Build and run

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/repro &
tracy-capture -o repro.tracy -s 5
```

If ROCm is not under `/opt/rocm`, pass `-DROCM_PATH=/path/to/rocm`.

The reproducer is also registered as a ctest target:

```bash
ctest --test-dir build -R repro
```

## Verifying the context name

`check_gpu_ctx_name` loads a `.tracy` file and prints the GPU context
names. It links the Tracy server library, so it is built only on request:

```bash
cmake -B build -DBUILD_CHECK_TOOL=ON
cmake --build build --target check_gpu_ctx_name
./build/check_gpu_ctx_name repro.tracy
# Expected (patched):   "GPU context 0: rocprofv3"
# Expected (unpatched): "GPU context 0: (unnamed)"
```

Exit codes: 0 = all contexts named, 2 = unnamed context found.

## What to expect

| Tracy version | Result |
|---|---|
| Unpatched | `tracy-capture` crashes: `Assertion 'ctx' failed` |
| Patched (GpuNewContext only) | Capture succeeds but GPU context is unnamed |
| Fully patched | Capture succeeds with ~50 GPU zones and context named "rocprofv3" |
