# First profiling session

Let's start our adventure by instrumenting your application and connecting it to the profiler. Here's a quick refresher:

1. Integrate Tracy Profiler into your application. This can be done using CMake, Meson, or simply by adding the source files to your project.
2. Make sure that `TracyClient.cpp` is added to your build, or that the Tracy library is linked.
3. Define `TRACY_ENABLE` in your build configuration, for the whole application. Do not do it in a single source file because it won't work.
4. Start your application, and * Connect* to it with the profiler.

