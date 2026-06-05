// Tracy CUDA Graph GPU Zone Repro
//
// Tests GPU zone correlation for CUDA Graph launches covering:
//   - Multiple distinct graphs (different graphIds)
//   - Multiple kernels per graph
//   - Mixed kernel + memcpy nodes
//   - Interleaved launches from different graphs on the same stream
//   - Repeated launches of the same graph (cache overwrite path)
//
// Expected GPU zone counts:
//   graphA (kernel + memcpy + kernel): 5 launches x 3 nodes = 15 zones
//   graphB (kernel + kernel + kernel): 5 launches x 3 nodes = 15 zones
//   Total graph zones: 30
//   Plus setup memcpys, syncs, etc.
//
// Build:
//   make          # release build
//   make debug    # debug build (asserts enabled)
//
// Run:
//   tracy-capture -o out.tracy -f & sleep 1 && ./repro

#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>

#include "tracy/Tracy.hpp"
#include "tracy/TracyCUDA.hpp"

__global__ void vector_add(float* a, float* b, float* c, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) c[i] = a[i] + b[i];
}

__global__ void vector_scale(float* a, float scale, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) a[i] *= scale;
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
    ZoneScoped;

    auto ctx = TracyCUDAContext();
    TracyCUDAStartProfiling(ctx);

    const int N = 1 << 20;
    const size_t bytes = N * sizeof(float);
    const int threads = 256;
    const int blocks  = (N + threads - 1) / threads;

    float *d_a, *d_b, *d_c, *d_tmp;
    CHECK_CUDA(cudaMalloc(&d_a,   bytes));
    CHECK_CUDA(cudaMalloc(&d_b,   bytes));
    CHECK_CUDA(cudaMalloc(&d_c,   bytes));
    CHECK_CUDA(cudaMalloc(&d_tmp, bytes));

    float* h_a = (float*)malloc(bytes);
    float* h_b = (float*)malloc(bytes);
    for (int i = 0; i < N; i++) { h_a[i] = 1.0f; h_b[i] = 2.0f; }
    CHECK_CUDA(cudaMemcpy(d_a, h_a, bytes, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(d_b, h_b, bytes, cudaMemcpyHostToDevice));

    cudaStream_t stream;
    CHECK_CUDA(cudaStreamCreate(&stream));

    // --- Graph A: kernel(add) + memcpy + kernel(add) ---
    // 3 nodes, graphId will be assigned by CUPTI
    CHECK_CUDA(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal));
    vector_add<<<blocks, threads, 0, stream>>>(d_a, d_b, d_c, N);
    CHECK_CUDA(cudaMemcpyAsync(d_tmp, d_c, bytes, cudaMemcpyDeviceToDevice, stream));
    vector_add<<<blocks, threads, 0, stream>>>(d_a, d_tmp, d_c, N);
    cudaGraph_t    graphA;
    cudaGraphExec_t execA;
    CHECK_CUDA(cudaStreamEndCapture(stream, &graphA));
    CHECK_CUDA(cudaGraphInstantiate(&execA, graphA, nullptr, nullptr, 0));

    // --- Graph B: kernel(scale) + kernel(add) + kernel(scale) ---
    // 3 nodes, different graphId from A
    CHECK_CUDA(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal));
    vector_scale<<<blocks, threads, 0, stream>>>(d_c, 0.5f, N);
    vector_add  <<<blocks, threads, 0, stream>>>(d_a, d_b, d_c, N);
    vector_scale<<<blocks, threads, 0, stream>>>(d_c, 2.0f, N);
    cudaGraph_t     graphB;
    cudaGraphExec_t execB;
    CHECK_CUDA(cudaStreamEndCapture(stream, &graphB));
    CHECK_CUDA(cudaGraphInstantiate(&execB, graphB, nullptr, nullptr, 0));

    printf("Graph A: kernel + memcpy + kernel  (3 nodes)\n");
    printf("Graph B: scale  + add   + scale    (3 nodes)\n");
    printf("Interleaving 5 launches each...\n");

    // Interleave launches: A, B, A, B, ... to stress graphId cache switching
    for (int i = 0; i < 5; i++) {
        {
            ZoneScopedN("graphA launch");
            CHECK_CUDA(cudaGraphLaunch(execA, stream));
        }
        {
            ZoneScopedN("graphB launch");
            CHECK_CUDA(cudaGraphLaunch(execB, stream));
        }
    }
    CHECK_CUDA(cudaStreamSynchronize(stream));

    printf("Done.\n");
    printf("Expected GPU zones:\n");
    printf("  graphA: 5 launches x 3 nodes = 15\n");
    printf("  graphB: 5 launches x 3 nodes = 15\n");
    printf("  Total graph zones: 30\n");

    // Verify correctness
    float* h_c = (float*)malloc(bytes);
    CHECK_CUDA(cudaMemcpy(h_c, d_c, bytes, cudaMemcpyDeviceToHost));
    printf("Result check: c[0] = %.1f (expected 6.0: (a+b)*2 after last graphB)\n", h_c[0]);

    CHECK_CUDA(cudaGraphExecDestroy(execA));
    CHECK_CUDA(cudaGraphExecDestroy(execB));
    CHECK_CUDA(cudaGraphDestroy(graphA));
    CHECK_CUDA(cudaGraphDestroy(graphB));
    CHECK_CUDA(cudaStreamDestroy(stream));
    CHECK_CUDA(cudaFree(d_a));
    CHECK_CUDA(cudaFree(d_b));
    CHECK_CUDA(cudaFree(d_c));
    CHECK_CUDA(cudaFree(d_tmp));
    free(h_a);
    free(h_b);
    free(h_c);

    TracyCUDAStopProfiling(ctx);
    TracyCUDAContextDestroy(ctx);

    return 0;
}
