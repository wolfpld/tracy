// Tracy CUDA Graph GPU Zone Repro
//
// Demonstrates that Tracy (unpatched) fails to show GPU zones for kernels
// launched via CUDA Graphs. The CUPTI activity records arrive but have no
// matching API callback correlation, so matchActivityToAPICall() fails and
// matchError() silently drops every GPU zone.
//
// Build:
//   nvcc -o repro repro.cu -lcuda -lcupti -I/path/to/tracy/public \
//        -DTRACY_ENABLE -DTRACY_ON_DEMAND
//
// Run with Tracy profiler connected to see:
//   - Unpatched: 0 GPU zones from the graph-launched kernels
//   - Patched:   GPU zones appear for each kernel invocation

#include <cstdio>
#include <cstdlib>
#include <cuda_runtime.h>

// A trivial kernel — just increments each element.
__global__ void vector_add(float* a, float* b, float* c, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        c[i] = a[i] + b[i];
    }
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
    const int N = 1 << 20;  // 1M elements
    const size_t bytes = N * sizeof(float);

    // Allocate device memory
    float *d_a, *d_b, *d_c;
    CHECK_CUDA(cudaMalloc(&d_a, bytes));
    CHECK_CUDA(cudaMalloc(&d_b, bytes));
    CHECK_CUDA(cudaMalloc(&d_c, bytes));

    // Initialize with some data
    float* h_a = (float*)malloc(bytes);
    float* h_b = (float*)malloc(bytes);
    for (int i = 0; i < N; i++) {
        h_a[i] = 1.0f;
        h_b[i] = 2.0f;
    }
    CHECK_CUDA(cudaMemcpy(d_a, h_a, bytes, cudaMemcpyHostToDevice));
    CHECK_CUDA(cudaMemcpy(d_b, h_b, bytes, cudaMemcpyHostToDevice));

    // --- Create a CUDA Graph via stream capture ---
    cudaStream_t stream;
    CHECK_CUDA(cudaStreamCreate(&stream));

    // Begin capture
    CHECK_CUDA(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal));

    // Record operations into the graph
    int threadsPerBlock = 256;
    int blocksPerGrid = (N + threadsPerBlock - 1) / threadsPerBlock;
    vector_add<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_a, d_b, d_c, N);
    CHECK_CUDA(cudaMemcpyAsync(d_c, d_c, bytes, cudaMemcpyDeviceToDevice, stream));
    vector_add<<<blocksPerGrid, threadsPerBlock, 0, stream>>>(d_a, d_c, d_c, N);

    // End capture
    cudaGraph_t graph;
    CHECK_CUDA(cudaStreamEndCapture(stream, &graph));

    // Instantiate the graph
    cudaGraphExec_t graphExec;
    CHECK_CUDA(cudaGraphInstantiate(&graphExec, graph, nullptr, nullptr, 0));

    printf("CUDA Graph created with 3 nodes (kernel + memcpy + kernel)\n");
    printf("Launching graph 10 times...\n");

    // --- Launch the graph multiple times ---
    // With unpatched Tracy, these produce 0 GPU zones.
    // With patched Tracy, each launch produces 3 GPU zones (2 kernels + 1 memcpy).
    for (int i = 0; i < 10; i++) {
        CHECK_CUDA(cudaGraphLaunch(graphExec, stream));
    }
    CHECK_CUDA(cudaStreamSynchronize(stream));

    printf("Done. Expected ~30 GPU zones in Tracy (10 launches x 3 ops).\n");
    printf("Unpatched Tracy will show 0 GPU zones.\n");

    // Verify correctness
    float* h_c = (float*)malloc(bytes);
    CHECK_CUDA(cudaMemcpy(h_c, d_c, bytes, cudaMemcpyDeviceToHost));
    printf("Result check: c[0] = %.1f (expected 4.0 after two additions)\n", h_c[0]);

    // Cleanup
    CHECK_CUDA(cudaGraphExecDestroy(graphExec));
    CHECK_CUDA(cudaGraphDestroy(graph));
    CHECK_CUDA(cudaStreamDestroy(stream));
    CHECK_CUDA(cudaFree(d_a));
    CHECK_CUDA(cudaFree(d_b));
    CHECK_CUDA(cudaFree(d_c));
    free(h_a);
    free(h_b);
    free(h_c);

    return 0;
}
