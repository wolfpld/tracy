// test_graphid_recycle.cu
//
// Investigates whether CUPTI recycles graphId values after cudaGraphExecDestroy.
//
// Question: Can two *different* graph exec handles ever produce the same graphId?
// (If yes, the graphLaunchCache in TracyCUDA.hpp could serve stale entries.)
//
// Rounds:
//   Round 1: create + instantiate + launch + destroy graph A → record graphId
//   Round 2: create + instantiate + launch + destroy graph B → does it reuse A's graphId?
//   Round 3: 20 rapid create/launch/destroy cycles → attempt to exhaust any counter

#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <vector>
#include <set>
#include <cuda_runtime.h>
#include <cupti.h>

#define CHECK_CUDA(call)                                                       \
    do {                                                                       \
        cudaError_t err = (call);                                              \
        if (err != cudaSuccess) {                                              \
            fprintf(stderr, "CUDA error at %s:%d: %s\n",                      \
                    __FILE__, __LINE__, cudaGetErrorString(err));              \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

#define CHECK_CUPTI(call)                                                      \
    do {                                                                       \
        CUptiResult err = (call);                                              \
        if (err != CUPTI_SUCCESS) {                                            \
            const char* msg;                                                   \
            cuptiGetResultString(err, &msg);                                   \
            fprintf(stderr, "CUPTI error at %s:%d: %s\n",                     \
                    __FILE__, __LINE__, msg);                                  \
            exit(1);                                                           \
        }                                                                      \
    } while (0)

static std::vector<uint32_t> g_observed_graphIds;

static void CUPTIAPI bufferRequested(uint8_t** buffer, size_t* size, size_t* maxNumRecords) {
    *size = 1 << 20;
    *buffer = (uint8_t*)malloc(*size);
    *maxNumRecords = 0;
}

static void CUPTIAPI bufferCompleted(CUcontext ctx, uint32_t streamId,
                                     uint8_t* buffer, size_t size, size_t validSize) {
    CUpti_Activity* record = nullptr;
    while (cuptiActivityGetNextRecord(buffer, validSize, &record) == CUPTI_SUCCESS) {
        if (record->kind == CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
            auto* kernel = (CUpti_ActivityKernel9*)record;
            g_observed_graphIds.push_back(kernel->graphId);
        }
    }
    free(buffer);
}

__global__ void dummy_kernel() {}

static uint32_t launchAndGetGraphId(cudaStream_t stream) {
    size_t before = g_observed_graphIds.size();

    cudaGraph_t graph;
    cudaGraphExec_t exec;
    CHECK_CUDA(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal));
    dummy_kernel<<<1, 1, 0, stream>>>();
    CHECK_CUDA(cudaStreamEndCapture(stream, &graph));
    CHECK_CUDA(cudaGraphInstantiate(&exec, graph, nullptr, nullptr, 0));
    CHECK_CUDA(cudaGraphLaunch(exec, stream));
    CHECK_CUDA(cudaStreamSynchronize(stream));
    CHECK_CUPTI(cuptiActivityFlushAll(CUPTI_ACTIVITY_FLAG_FLUSH_FORCED));

    CHECK_CUDA(cudaGraphExecDestroy(exec));
    CHECK_CUDA(cudaGraphDestroy(graph));

    if (g_observed_graphIds.size() <= before) {
        fprintf(stderr, "ERROR: No CONCURRENT_KERNEL record received\n");
        return 0;
    }
    return g_observed_graphIds.back();
}

int main() {
    // Initialize CUDA context
    cudaFree(0);

    CHECK_CUPTI(cuptiActivityRegisterCallbacks(bufferRequested, bufferCompleted));
    CHECK_CUPTI(cuptiActivityEnable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL));

    cudaStream_t stream;
    CHECK_CUDA(cudaStreamCreate(&stream));

    // Round 1
    uint32_t id1 = launchAndGetGraphId(stream);
    printf("Round 1 graphId: %u\n", id1);

    // Round 2: new exec after round 1 destroyed
    uint32_t id2 = launchAndGetGraphId(stream);
    printf("Round 2 graphId: %u\n", id2);

    if (id1 == id2) {
        printf("*** RECYCLE DETECTED: id1 == id2 == %u ***\n", id1);
    } else {
        printf("Round 2 got different graphId (no recycle after 1 destroy)\n");
    }

    // Round 3: 20 rapid cycles — try to exhaust monotonic counter
    printf("\nRound 3: 20 rapid create/launch/destroy cycles\n");
    std::set<uint32_t> seen;
    seen.insert(id1);
    seen.insert(id2);
    bool recycle_seen = false;
    for (int i = 0; i < 20; i++) {
        uint32_t id = launchAndGetGraphId(stream);
        printf("  cycle %2d: graphId = %u", i + 1, id);
        if (seen.count(id)) {
            printf("  *** RECYCLED (seen before) ***");
            recycle_seen = true;
        }
        printf("\n");
        seen.insert(id);
    }

    if (!recycle_seen) {
        printf("\nNo graphId recycling observed across %zu total launches.\n", seen.size());
        printf("graphId appears to be a monotonically increasing counter.\n");
        printf("Min=%u  Max=%u  Count=%zu\n",
               *seen.begin(), *seen.rbegin(), seen.size());
    }

    CHECK_CUDA(cudaStreamDestroy(stream));
    CHECK_CUPTI(cuptiActivityDisable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL));
    return 0;
}
