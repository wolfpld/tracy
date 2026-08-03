// Tracy CUDA On-Demand Profiling Repro
//
// When Tracy is built with TRACY_ON_DEMAND, a profiler connecting at any
// point after the CUDA context is created crashes the server:
//
//   Assertion `ctx' failed in Worker::ProcessGpuContextName
//
// Root cause: CUDACtx's constructor writes a GpuNewContext queue item but
// never calls DeferItem(), so a new connection's ClearQueues() wipes it
// before it can be replayed. GpuContextName is deferred correctly and gets
// replayed anyway, referencing a context the server never registered.
//
// Build:
//   cmake -B build -DCMAKE_BUILD_TYPE=Release
//   cmake --build build
//
// Run:
//   ./build/repro &
//   tracy-capture -o repro.tracy -s 5
//
// Expected (unpatched): tracy-capture crashes with assertion failure
// Expected (patched):   capture succeeds with GPU zones showing kernel/memcpy names

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cuda_runtime.h>

#include "tracy/Tracy.hpp"
#include "tracy/TracyCUDA.hpp"

__global__ void vector_add(float* a, float* b, float* c, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) c[i] = a[i] + b[i];
}

#define CHECK_CUDA(call)                                                      \
    do {                                                                       \
        cudaError_t err = (call);                                              \
        if (err != cudaSuccess) {                                              \
            fprintf(stderr, "CUDA error at %s:%d: %s\n", __FILE__, __LINE__,  \
                    cudaGetErrorString(err));                                   \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

int main() {
    printf("CUDA on-demand repro - waiting for profiler to connect...\n");
    fflush(stdout);

    auto ctx = TracyCUDAContext();
    static constexpr char name[] = "line_scan_processing_cuda";
    TracyCUDAContextName(ctx, static_cast<const char*>(name), sizeof(name) - 1);
    TracyCUDAStartProfiling(ctx);

    const int N = 1 << 16;
    const size_t bytes = N * sizeof(float);
    const int threads = 256;
    const int blocks  = (N + threads - 1) / threads;

    float *d_a, *d_b, *d_c;
    CHECK_CUDA(cudaMalloc(&d_a, bytes));
    CHECK_CUDA(cudaMalloc(&d_b, bytes));
    CHECK_CUDA(cudaMalloc(&d_c, bytes));

    float* h_a = (float*)malloc(bytes);
    float* h_b = (float*)malloc(bytes);
    for (int i = 0; i < N; i++) { h_a[i] = 1.0f; h_b[i] = 2.0f; }
    CHECK_CUDA(cudaMemcpy(d_a, h_a, bytes, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(d_b, h_b, bytes, cudaMemcpyHostToDevice));

    // Run many iterations so tracy-capture has time to connect.
    // With 100ms sleep per iteration this runs for ~10 seconds.
    for (int iter = 0; iter < 100; iter++) {
        ZoneScopedN("iteration");
        vector_add<<<blocks, threads>>>(d_a, d_b, d_c, N);
        CHECK_CUDA(cudaDeviceSynchronize());
        TracyCUDACollect(ctx);
        usleep(100000);
        FrameMark;
    }

    float* h_c = (float*)malloc(bytes);
    CHECK_CUDA(cudaMemcpy(h_c, d_c, bytes, cudaMemcpyDeviceToHost));
    bool ok = h_c[0] == h_a[0] + h_b[0];
    printf("Result: %s\n", ok ? "PASS" : "FAIL");

    CHECK_CUDA(cudaFree(d_a));
    CHECK_CUDA(cudaFree(d_b));
    CHECK_CUDA(cudaFree(d_c));
    free(h_a);
    free(h_b);
    free(h_c);

    TracyCUDAStopProfiling(ctx);
    TracyCUDAContextDestroy(ctx);

    return ok ? 0 : 1;
}
