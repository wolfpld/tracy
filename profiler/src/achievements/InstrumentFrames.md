# Instrumenting frames

In addition to instrumenting functions, you can also instrument frames. This allows you to see how much time is spent in each frame of your application.

To instrument frames, you need to add the `FrameMark` macro at the beginning of each frame. This can be done in the main loop of your application, or in a separate function that is called at the beginning of each frame.

```c++
#include "Tracy.hpp"

void Render()
{
    // Render the frame
    SwapBuffers();
    FrameMark;
}
```

When you profile your application, you will see a new frame appear on the timeline each time the `FrameMark` macro is called. This allows you to see how much time is spent in each frame and how many frames are rendered per second.

The `FrameMark` macro is a great way to see at a glance how your application is performing over time. Maybe there are some performance problems that only appear after a few minutes of running the application? A frame graph is drawn at the top of the profiler window where you can see the timing of all frames.

Note that some applications do not have a frame-based structure, and in such cases, frame instrumentation may not be useful. That's ok.
