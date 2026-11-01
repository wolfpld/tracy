# Survive a crash

When the application crashes, Tracy's [crash handler](#crashhandling) intercepts the fault, finishes sending the profiling data, and reports the crash: time, thread, reason, and the call stack at the crash site. Its * Call stack* button opens the stack where the fault occurred, and * Focus* jumps the timeline to the crash point. Crash handling runs automatically on Windows, Linux, and Android.

After you close this report, the crash remains marked on the trace. On the timeline, the crashed thread's label reads * Crashed* in red. The * skull* button in the notification area reopens the crash stack. The Trace information window shows the crash's time, thread, and reason.

> [!TIP]
> **Tip**
>
> The stack resolves into function names only if the profiler can read symbols from your binary, the same [requirement as call stack capture](#collectingcallstacks).

Now crash your application on purpose and read the report.
