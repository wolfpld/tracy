#include <cuda_runtime.h>

// WARN: for simplicity, we enable and "embed" the Tracy client directly into the code
#define TRACY_ENABLE
#include <TracyClient.cpp>

#include <tracy/Tracy.hpp>
#include <tracy/TracyCUDA.hpp>

#include <cstdio>
#include <cstdlib>
#include <vector>

#define CUDA_CHECK(call)                                                          \
    do {                                                                          \
        cudaError_t err__ = (call);                                               \
        if (err__ != cudaSuccess) {                                               \
            std::fprintf(stderr, "CUDA error %s at %s:%d: %s\n",                  \
                         cudaGetErrorName(err__), __FILE__, __LINE__,             \
                         cudaGetErrorString(err__));                              \
            std::exit(EXIT_FAILURE);                                              \
        }                                                                         \
    } while (0)

__global__ void saxpy(float a, const float* x, float* y, int n)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) y[i] = a * x[i] + y[i];
}

int main()
{
    // CUPTI-backed Tracy context. Auto-captures all CUDA activity from the
    // point StartProfiling() is called until StopProfiling(). The background
    // collector thread flushes activity into Tracy; the explicit Collect()
    // calls below just force a flush at known phase boundaries.
    auto* cudaCtx = TracyCUDAContext();
    {
        constexpr char ctxName[] = "CUDA Graph Demo";
        TracyCUDAContextName(cudaCtx, ctxName, sizeof(ctxName) - 1);
    }
    TracyCUDAStartProfiling(cudaCtx);

    constexpr int N = 1 << 16;              // small N => kernel is short => launch overhead dominates
    constexpr int KERNELS_PER_GRAPH = 32;   // chain length captured into the graph
    constexpr int OUTER_ITERS = 2000;       // how many times we replay the chain

    // allocate device buffers
    float *dX = nullptr, *dY = nullptr;
    CUDA_CHECK(cudaMalloc(&dX, N * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&dY, N * sizeof(float)));

    std::vector<float> hX(N, 1.0f);
    CUDA_CHECK(cudaMemcpy(dX, hX.data(), N * sizeof(float), cudaMemcpyHostToDevice));

    cudaStream_t stream = nullptr;
    CUDA_CHECK(cudaStreamCreate(&stream));

    const dim3 block(256);
    const dim3 grid((N + block.x - 1) / block.x);

    cudaEvent_t evStart, evStop;
    CUDA_CHECK(cudaEventCreate(&evStart));
    CUDA_CHECK(cudaEventCreate(&evStop));

    // warm-up (so first-launch lazy-init and/or JIT doesn't bias the measurement)
    saxpy<<<grid, block, 0, stream>>>(0.0f, dX, dY, N);
    CUDA_CHECK(cudaStreamSynchronize(stream));

    // baseline: launch each kernel directly on the stream
    float msStream = 0.0f;
    {
        ZoneScopedN("stream-launches");
        CUDA_CHECK(cudaMemsetAsync(dY, 0, N * sizeof(float), stream));
        CUDA_CHECK(cudaEventRecord(evStart, stream));
        for (int outer = 0; outer < OUTER_ITERS; ++outer) {
            for (int k = 0; k < KERNELS_PER_GRAPH; ++k) {
                saxpy<<<grid, block, 0, stream>>>(1.0e-6f, dX, dY, N);
            }
        }
        CUDA_CHECK(cudaEventRecord(evStop, stream));
        CUDA_CHECK(cudaEventSynchronize(evStop));
        CUDA_CHECK(cudaEventElapsedTime(&msStream, evStart, evStop));
        TracyCUDACollect(cudaCtx);
    }

    // capture: record the same kernel chain into a graph
    cudaGraph_t     graph     = nullptr;
    cudaGraphExec_t graphExec = nullptr;
    {
        ZoneScopedN("graph-capture");
        // cudaStreamCaptureModeRelaxed allows the calling thread to perform
        // unrelated CUDA work during capture; ThreadLocal is stricter if you need
        // isolation. Most short, single-stream captures work fine in either mode.
        CUDA_CHECK(cudaStreamBeginCapture(stream, cudaStreamCaptureModeRelaxed));
        for (int k = 0; k < KERNELS_PER_GRAPH; ++k) {
            saxpy<<<grid, block, 0, stream>>>(1.0e-6f, dX, dY, N);
        }
        CUDA_CHECK(cudaStreamEndCapture(stream, &graph));

        // Instantiate once -> reusable executable graph.
        CUDA_CHECK(cudaGraphInstantiate(&graphExec, graph, nullptr, nullptr, 0));

        // The template graph isn't needed once instantiated.
        CUDA_CHECK(cudaGraphDestroy(graph));
    }

    // replay: launch the instantiated graph OUTER_ITERS times
    float msGraph = 0.0f;
    {
        ZoneScopedN("graph-launches");
        CUDA_CHECK(cudaMemsetAsync(dY, 0, N * sizeof(float), stream));
        CUDA_CHECK(cudaEventRecord(evStart, stream));
        for (int outer = 0; outer < OUTER_ITERS; ++outer) {
            CUDA_CHECK(cudaGraphLaunch(graphExec, stream));
        }
        CUDA_CHECK(cudaEventRecord(evStop, stream));
        CUDA_CHECK(cudaEventSynchronize(evStop));
        CUDA_CHECK(cudaEventElapsedTime(&msGraph, evStart, evStop));
        TracyCUDACollect(cudaCtx);
    }

    // sanity check: y[i] = OUTER_ITERS * KERNELS_PER_GRAPH * 1e-6 * x[i]
    std::vector<float> hY(N);
    CUDA_CHECK(cudaMemcpy(hY.data(), dY, N * sizeof(float), cudaMemcpyDeviceToHost));
    const float expected = float(OUTER_ITERS) * float(KERNELS_PER_GRAPH) * 1.0e-6f;

    std::printf("Stream launches: %8.3f ms  (%d kernels)\n",
                msStream, OUTER_ITERS * KERNELS_PER_GRAPH);
    std::printf("Graph  launches: %8.3f ms  (%d graph launches x %d kernels)\n",
                msGraph, OUTER_ITERS, KERNELS_PER_GRAPH);
    std::printf("Speedup        : %8.2fx\n", msStream / msGraph);
    std::printf("hY[0] = %.6e  (expected %.6e)\n", hY[0], expected);

    // shutdown
    CUDA_CHECK(cudaGraphExecDestroy(graphExec));
    CUDA_CHECK(cudaEventDestroy(evStart));
    CUDA_CHECK(cudaEventDestroy(evStop));
    CUDA_CHECK(cudaStreamDestroy(stream));
    CUDA_CHECK(cudaFree(dX));
    CUDA_CHECK(cudaFree(dY));

    TracyCUDAStopProfiling(cudaCtx);
    TracyCUDAContextDestroy(cudaCtx);
    return 0;
}
