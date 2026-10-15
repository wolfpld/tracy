# Profile the GPU

A zone around your draw calls only measures the CPU time spent submitting commands, because the GPU runs them asynchronously. Tracy's [GPU profiling](#gpuprofiling) bindings time the execution on the graphics card itself, and the resulting GPU zones appear in the timeline on a row labeled with the graphics context.

For [OpenGL](#gpuopengl), include `public/tracy/TracyOpenGL.hpp`, declare your rendering context once with `TracyGpuContext`, wrap your drawing code with `TracyGpuZone( "Render" )`, and call `TracyGpuCollect` after swapping buffers. [Vulkan](#gpuvulkan), [Direct3D 11](#gpudirect3d11)/[12](#gpudirect3d12), [Metal](#gpumetal), [OpenCL](#gpuopencl) and [WebGPU](#gpuwebgpu) work the same way, with the macros prefixed by the API name, while [CUDA](#gpucuda) is instrumented automatically via CUPTI.

Click a GPU zone to open its zone information window and see the real device-side time. Try it out!
