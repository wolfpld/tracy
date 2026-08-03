# Tracy CUDA On-Demand Profiling Repro

Demonstrates that unpatched Tracy crashes when a profiler connects to a
CUDA application built with `TRACY_ON_DEMAND`.

## Root cause

`CUDACtx`'s constructor (`TracyCUDA.hpp`) writes a `GpuNewContext` queue
item but does not call `DeferItem()`, unlike every other GPU backend
(Vulkan, OpenGL, D3D11/12, Metal, WebGPU, Rocprof), which all defer it
under `#ifdef TRACY_ON_DEMAND`.

Under on-demand mode, a new connection clears the client's pending
serial queue (`ClearQueues()`) before replaying deferred items. Since
`GpuNewContext` is never deferred, it never survives that clear — no
matter how early the connection happens, even immediately after the
context is created. The `GpuContextName` message that `Name()` sends
right after (already correctly deferred) is then replayed to a server
that has no record of the context, triggering:

    Assertion `ctx' failed in Worker::ProcessGpuContextName

In release builds (assert compiled out) this is undefined behavior —
a null-pointer dereference, typically a segfault.

This is the same bug already fixed for the Rocprof backend in #1336;
see also the closed issue #1171, which describes this exact crash.

## Build and run

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/repro &
tracy-capture -o repro.tracy -s 5
```

The reproducer is also registered as a ctest target:

```bash
ctest --test-dir build -R repro
```

## Verifying the GPU zones

`check_gpu_zones` loads a `.tracy` file and prints, for each GPU
context, whether it is named and how many GPU zones it recorded. It
links the Tracy server library, so it is built only on request:

```bash
cmake -B build -DBUILD_CHECK_TOOL=ON
cmake --build build --target check_gpu_zones
./build/check_gpu_zones repro.tracy
# Expected (patched): "GPU context 0: line_scan_processing_cuda, 200 zones"
```

Exit codes: 0 = at least one named context with recorded zones, 2 =
otherwise.

## What to expect

| Tracy version | Result |
|---|---|
| Unpatched | `tracy-capture` crashes: `Assertion 'ctx' failed` |
| Patched | Capture succeeds, GPU context named and populated with zones |
