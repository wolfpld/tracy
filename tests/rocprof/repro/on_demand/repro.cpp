// Reproduces the rocprofiler on-demand profiling crash.
//
// When Tracy is built with TRACY_ON_DEMAND, a late-connecting profiler
// (tracy-capture / GUI) triggers an assertion failure in the server:
//
//   Assertion `ctx' failed in ProcessGpuZoneBeginImplCommon
//
// Root cause: gpu_context_allocate() writes a GpuNewContext queue item
// but does not call DeferItem(), so the context is never replayed to a
// late-connecting client. The client then receives GpuZoneBegin events
// for a context it has never seen.
//
// A secondary issue: tool_callback_tracing_callback() guards ALL
// callbacks on data->init, which is only set after the calibration
// thread allocates the GPU context. Kernel symbol registrations
// (CODE_OBJECT_DEVICE_KERNEL_SYMBOL_REGISTER) happen at HIP init time,
// before data->init is true, so they are silently dropped. This causes
// kernel names to be missing in the profiler.
//
// Usage:
//   make
//   ./repro &
//   tracy-capture -o repro.tracy -s 5
//
// Expected (unpatched): tracy-capture crashes with assertion failure
// Expected (patched):   capture succeeds with GPU zones showing kernel names

#include <cstdio>
#include <unistd.h>
#include <hip/hip_runtime.h>
#include "tracy/Tracy.hpp"

__global__ void vectorAdd( const float* a, const float* b, float* c, int n )
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if( i < n ) c[i] = a[i] + b[i];
}

int main()
{
    printf( "Rocprofiler on-demand repro — waiting for profiler to connect...\n" );
    fflush( stdout );

    constexpr int N = 1024;
    float h_a[N], h_b[N], h_c[N];
    float *d_a, *d_b, *d_c;

    for( int i = 0; i < N; i++ )
    {
        h_a[i] = float( i );
        h_b[i] = float( i * 2 );
    }

    (void)hipMalloc( &d_a, N * sizeof( float ) );
    (void)hipMalloc( &d_b, N * sizeof( float ) );
    (void)hipMalloc( &d_c, N * sizeof( float ) );

    (void)hipMemcpy( d_a, h_a, N * sizeof( float ), hipMemcpyHostToDevice );
    (void)hipMemcpy( d_b, h_b, N * sizeof( float ), hipMemcpyHostToDevice );

    // Run many iterations so tracy-capture has time to connect.
    // With 100ms sleep per iteration this runs for ~10 seconds.
    for( int iter = 0; iter < 100; iter++ )
    {
        ZoneScopedN( "iteration" );
        vectorAdd<<<( N + 255 ) / 256, 256>>>( d_a, d_b, d_c, N );
        (void)hipDeviceSynchronize();
        usleep( 100000 );
        FrameMark;
    }

    (void)hipMemcpy( h_c, d_c, N * sizeof( float ), hipMemcpyDeviceToHost );

    bool ok = true;
    for( int i = 0; i < N; i++ )
    {
        if( h_c[i] != h_a[i] + h_b[i] ) { ok = false; break; }
    }
    printf( "Result: %s\n", ok ? "PASS" : "FAIL" );

    (void)hipFree( d_a );
    (void)hipFree( d_b );
    (void)hipFree( d_c );
    return ok ? 0 : 1;
}
