# First profiling session

Let's start our adventure by instrumenting your application and connecting it to the profiler. Here's a quick refresher:

1. Integrate Tracy Profiler into your application. This can be done using CMake, Meson, or simply by adding the source files to your project.
2. Make sure that `TracyClient.cpp` (or the Tracy library) is included in your build.
3. Define `TRACY_ENABLE` in your build configuration, for the whole application. Do not do it in a single source file because it won't work.
4. Start your application, and * Connect* to it with the profiler.

Please refer to the [user manual](https://github.com/wolfpld/tracy/releases) for more details.
