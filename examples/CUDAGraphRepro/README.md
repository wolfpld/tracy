# Tracy CUDA Graph GPU Zone Repro

Demonstrates that unpatched Tracy fails to show GPU zones for kernels
launched via CUDA Graphs (`cudaGraphLaunch`).

## Root cause

When kernels are launched through CUDA Graphs, CUPTI delivers
`CONCURRENT_KERNEL` and `MEMCPY` activity records but no corresponding
API callback fires for the individual kernel launches. Tracy's
`matchActivityToAPICall()` always fails, and `matchError()` silently
drops every GPU zone.

## Build and run

```bash
make
./repro
```

## What to expect

| Tracy version | GPU zones shown |
|---|---|
| Unpatched | 0 |
| Patched (cuda-graph-gpu-zones.patch) | ~30 (10 launches x 3 ops) |

## The graph structure

Each graph launch contains:
1. `vector_add` kernel (c = a + b)
2. Device-to-device memcpy
3. `vector_add` kernel (c = a + c)

The graph is launched 10 times, so 30 GPU operations total.
