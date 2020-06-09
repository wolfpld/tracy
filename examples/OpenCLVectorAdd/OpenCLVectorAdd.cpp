#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <numeric>

#include <CL/cl.h>

#include <Tracy.hpp>
#include <TracyOpenCL.hpp>

#define CL_ASSERT(err)                                              \
    if((err) != CL_SUCCESS)                                         \
    {                                                               \
        std::cerr << "OpenCL Call Returned " << err << std::endl;   \
        assert(false);                                              \
    }

const char kernelSource[] =
"   void __kernel vectorAdd(global float* C, global float* A, global float* B, int N)  "
"   {                                                                                  "
"       int i = get_global_id(0);                                                      "
"       if (i < N) {                                                                   "
"           C[i] = A[i] + B[i];                                                        "
"       }                                                                              "
"   }                                                                                  ";

int main()
{
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue commandQueue;
    cl_kernel vectorAddKernel;
    cl_program program;
    cl_int err;
    cl_mem bufferA, bufferB, bufferC;

    TracyCLCtx tracyCLCtx;

    {
        ZoneScopedN("OpenCL Init");

        cl_uint numPlatforms = 0;
        CL_ASSERT(clGetPlatformIDs(0, nullptr, &numPlatforms));

        if (numPlatforms == 0)
        {
            std::cerr << "Cannot find OpenCL platform to run this application" << std::endl;
            return 1;
        }

        CL_ASSERT(clGetPlatformIDs(1, &platform, nullptr));

        size_t platformNameBufferSize = 0;
        CL_ASSERT(clGetPlatformInfo(platform, CL_PLATFORM_NAME, 0, nullptr, &platformNameBufferSize));
        std::string platformName(platformNameBufferSize, '\0');
        CL_ASSERT(clGetPlatformInfo(platform, CL_PLATFORM_NAME, platformNameBufferSize, &platformName[0], nullptr));

        std::cout << "OpenCL Platform: " << platformName << std::endl;

        CL_ASSERT(clGetDeviceIDs(platform, CL_DEVICE_TYPE_ALL, 1, &device, nullptr));
        size_t deviceNameBufferSize = 0;
        CL_ASSERT(clGetDeviceInfo(device, CL_DEVICE_NAME, 0, nullptr, &deviceNameBufferSize));
        std::string deviceName(deviceNameBufferSize, '\0');
        CL_ASSERT(clGetDeviceInfo(device, CL_DEVICE_NAME, deviceNameBufferSize, &deviceName[0], nullptr));

        std::cout << "OpenCL Device: " << deviceName << std::endl;

        err = CL_SUCCESS;
        context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
        CL_ASSERT(err);

        size_t kernelSourceLength = sizeof(kernelSource);
        const char* kernelSourceArray = { kernelSource };
        program = clCreateProgramWithSource(context, 1, &kernelSourceArray, &kernelSourceLength, &err);
        CL_ASSERT(err);

        if (clBuildProgram(program, 1, &device, nullptr, nullptr, nullptr) != CL_SUCCESS)
        {
            size_t programBuildLogBufferSize = 0;
            CL_ASSERT(clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &programBuildLogBufferSize));
            std::string programBuildLog(programBuildLogBufferSize, '\0');
            CL_ASSERT(clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, programBuildLogBufferSize, &programBuildLog[0], nullptr));
            std::clog << programBuildLog << std::endl;
            return 1;
        }

        vectorAddKernel = clCreateKernel(program, "vectorAdd", &err);
        CL_ASSERT(err);

        commandQueue = clCreateCommandQueue(context, device, CL_QUEUE_PROFILING_ENABLE, &err);
        CL_ASSERT(err);
    }

    tracyCLCtx = TracyCLContext(context, device);

    size_t N = 10 * 1024 * 1024 / sizeof(float); // 10MB of floats
    std::vector<float> hostA, hostB, hostC;

    {
        ZoneScopedN("Host Data Init");
        hostA.resize(N);
        hostB.resize(N);
        hostC.resize(N);

        std::iota(std::begin(hostA), std::end(hostA), 0);
        std::iota(std::begin(hostB), std::end(hostB), 0);
    }

    {
        ZoneScopedN("Host to Device Memory Copy");

        bufferA = clCreateBuffer(context, CL_MEM_READ_WRITE, N * sizeof(float), nullptr, &err);
        CL_ASSERT(err);
        bufferB = clCreateBuffer(context, CL_MEM_READ_WRITE, N * sizeof(float), nullptr, &err);
        CL_ASSERT(err);
        bufferC = clCreateBuffer(context, CL_MEM_READ_WRITE, N * sizeof(float), nullptr, &err);
        CL_ASSERT(err);

        cl_event writeBufferAEvent, writeBufferBEvent;
        {
            ZoneScopedN("Write Buffer A");
            TracyCLZoneS(tracyCLCtx, "Write BufferA", 5);

            CL_ASSERT(clEnqueueWriteBuffer(commandQueue, bufferA, CL_TRUE, 0, N * sizeof(float), hostA.data(), 0, nullptr, &writeBufferAEvent));

            TracyCLZoneSetEvent(writeBufferAEvent);
        }
        {
            ZoneScopedN("Write Buffer B");
            TracyCLZone(tracyCLCtx, "Write BufferB");

            CL_ASSERT(clEnqueueWriteBuffer(commandQueue, bufferB, CL_TRUE, 0, N * sizeof(float), hostB.data(), 0, nullptr, &writeBufferBEvent));

            TracyCLZoneSetEvent(writeBufferBEvent);
        }
    }

    for (int i = 0; i < 10; ++i)
    {
        ZoneScopedN("VectorAdd Kernel Launch");
        TracyCLZoneC(tracyCLCtx, "VectorAdd Kernel", tracy::Color::Blue4);

        CL_ASSERT(clSetKernelArg(vectorAddKernel, 0, sizeof(cl_mem), &bufferC));
        CL_ASSERT(clSetKernelArg(vectorAddKernel, 1, sizeof(cl_mem), &bufferA));
        CL_ASSERT(clSetKernelArg(vectorAddKernel, 2, sizeof(cl_mem), &bufferB));
        CL_ASSERT(clSetKernelArg(vectorAddKernel, 3, sizeof(int), &static_cast<int>(N)));

        cl_event vectorAddKernelEvent;
        CL_ASSERT(clEnqueueNDRangeKernel(commandQueue, vectorAddKernel, 1, nullptr, &N, nullptr, 0, nullptr, &vectorAddKernelEvent));

        CL_ASSERT(clWaitForEvents(1, &vectorAddKernelEvent));

        TracyCLZoneSetEvent(vectorAddKernelEvent);

        cl_ulong kernelStartTime, kernelEndTime;
        CL_ASSERT(clGetEventProfilingInfo(vectorAddKernelEvent, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &kernelStartTime, nullptr));
        CL_ASSERT(clGetEventProfilingInfo(vectorAddKernelEvent, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &kernelEndTime, nullptr));
        std::cout << "VectorAdd Kernel Elapsed: " << ((kernelEndTime - kernelStartTime) / 1000) << " us" << std::endl;
    }

    {
        ZoneScopedN("Device to Host Memory Copy");
        TracyCLZone(tracyCLCtx, "Read Buffer C");

        cl_event readbufferCEvent;
        CL_ASSERT(clEnqueueReadBuffer(commandQueue, bufferC, CL_TRUE, 0, N * sizeof(float), hostC.data(), 0, nullptr, &readbufferCEvent));
        TracyCLZoneSetEvent(readbufferCEvent);
    }

    CL_ASSERT(clFinish(commandQueue));

    TracyCLCollect(tracyCLCtx);

    {
        ZoneScopedN("Checking results");

        for (int i = 0; i < N; ++i)
        {
            assert(hostC[i] == hostA[i] + hostB[i]);
        }
    }

    std::cout << "Results are correct!" << std::endl;

    TracyCLDestroy(tracyCLCtx);

    return 0;
}
