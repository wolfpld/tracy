// Investigate: does relaunching the same cudaGraphExec produce a new correlationId
// each time, or is the correlationId reused/fixed per exec handle?
//
// Also checks: do different graphExec handles for the same graph share graphId?
#include <cstdio>
#include <cuda_runtime.h>
#include <cupti.h>

#define CHECK(x) do { cudaError_t e=(x); if(e!=cudaSuccess){fprintf(stderr,"CUDA %s:%d: %s\n",__FILE__,__LINE__,cudaGetErrorString(e));exit(1);} } while(0)
#define CHECK_CUPTI(x) do { CUptiResult e=(x); if(e!=CUPTI_SUCCESS){const char*s;cuptiGetResultString(e,&s);fprintf(stderr,"CUPTI %s:%d: %s\n",__FILE__,__LINE__,s);exit(1);} } while(0)

struct Record { uint32_t corr; uint32_t graphId; };
static Record records[64];
static int nrecords = 0;

static void CUPTIAPI bufferRequested(uint8_t** buf, size_t* size, size_t* maxNumRecords) {
    *size = 1 << 20; *buf = (uint8_t*)malloc(*size); *maxNumRecords = 0;
}
static void CUPTIAPI bufferCompleted(CUcontext ctx, uint32_t streamId,
                                      uint8_t* buf, size_t size, size_t validSize) {
    CUpti_Activity* record = nullptr;
    while (cuptiActivityGetNextRecord(buf, validSize, &record) == CUPTI_SUCCESS) {
        if (record->kind == CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL) {
            auto* k = (CUpti_ActivityKernel9*)record;
            if (nrecords < 64)
                records[nrecords++] = { k->correlationId, k->graphId };
        }
    }
    free(buf);
}

__global__ void dummy(int* x) { atomicAdd(x, 1); }

static uint32_t launchCorrId[32];
static int nlaunch = 0;

// Intercept cudaGraphLaunch via CUPTI callback to capture the correlationId
// assigned to each launch on the CPU side
static void CUPTIAPI onCallback(void* userdata, CUpti_CallbackDomain domain,
                                 CUpti_CallbackId cbid, const void* cbdata) {
    if (domain != CUPTI_CB_DOMAIN_RUNTIME_API) return;
    if (cbid != CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000) return;
    auto* api = (CUpti_CallbackData*)cbdata;
    if (api->callbackSite == CUPTI_API_ENTER && nlaunch < 32)
        launchCorrId[nlaunch++] = api->correlationId;
}

int main() {
    CHECK_CUPTI(cuptiActivityRegisterCallbacks(bufferRequested, bufferCompleted));
    CHECK_CUPTI(cuptiActivityEnable(CUPTI_ACTIVITY_KIND_CONCURRENT_KERNEL));

    CUpti_SubscriberHandle sub;
    CHECK_CUPTI(cuptiSubscribe(&sub, onCallback, nullptr));
    CHECK_CUPTI(cuptiEnableCallback(1, sub, CUPTI_CB_DOMAIN_RUNTIME_API,
                                    CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000));

    cudaStream_t stream; CHECK(cudaStreamCreate(&stream));
    int* d_x; CHECK(cudaMalloc(&d_x, sizeof(int)));

    // Build a simple graph with one kernel
    cudaGraph_t graph; cudaGraphExec_t exec;
    CHECK(cudaStreamBeginCapture(stream, cudaStreamCaptureModeGlobal));
    dummy<<<1,1,0,stream>>>(d_x);
    CHECK(cudaStreamEndCapture(stream, &graph));
    CHECK(cudaGraphInstantiate(&exec, graph, nullptr, nullptr, 0));

    // Launch the SAME exec handle 5 times
    printf("=== Same exec, 5 launches ===\n");
    for (int i = 0; i < 5; i++)
        CHECK(cudaGraphLaunch(exec, stream));
    CHECK(cudaStreamSynchronize(stream));
    CHECK_CUPTI(cuptiActivityFlushAll(1));

    printf("CPU-side launch correlationIds:\n");
    for (int i = 0; i < nlaunch; i++)
        printf("  launch[%d] corr=%u\n", i, launchCorrId[i]);
    printf("GPU activity records (CONCURRENT_KERNEL):\n");
    for (int i = 0; i < nrecords; i++)
        printf("  kernel[%d] corr=%-4u graphId=%u\n", i, records[i].corr, records[i].graphId);

    // Check: do CPU launch corrIds match GPU activity corrIds?
    bool allMatch = (nlaunch == nrecords);
    for (int i = 0; allMatch && i < nlaunch; i++)
        allMatch = (launchCorrId[i] == records[i].corr);
    printf("All launch corrIds match kernel corrIds: %s\n", allMatch ? "YES" : "NO (order may differ)");

    // Now test: two different exec handles from the same graph — same graphId?
    printf("\n=== Two exec handles from same graph ===\n");
    nlaunch = 0; nrecords = 0;
    cudaGraphExec_t exec2;
    CHECK(cudaGraphInstantiate(&exec2, graph, nullptr, nullptr, 0));
    CHECK(cudaGraphLaunch(exec,  stream));
    CHECK(cudaGraphLaunch(exec2, stream));
    CHECK(cudaStreamSynchronize(stream));
    CHECK_CUPTI(cuptiActivityFlushAll(1));
    for (int i = 0; i < nrecords; i++)
        printf("  kernel[%d] corr=%-4u graphId=%u\n", i, records[i].corr, records[i].graphId);

    CHECK(cudaGraphExecDestroy(exec));
    CHECK(cudaGraphExecDestroy(exec2));
    CHECK(cudaGraphDestroy(graph));
    CHECK(cudaFree(d_x));
    CHECK(cudaStreamDestroy(stream));
    CHECK_CUPTI(cuptiUnsubscribe(sub));
    return 0;
}
