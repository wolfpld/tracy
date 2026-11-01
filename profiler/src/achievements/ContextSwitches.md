# See the whole machine

Your program shares the CPU cores with every other process on the machine. When another process wants to run, the scheduler can take a core away and later give your thread a different one. A thread can be ready to run and still not get a core. [Context switches](#contextswitches) capture exactly that: the kernel reports every time a thread leaves or enters a core.

With context switch data, each thread carries a thick state line: green while it runs, red while it waits to be resumed by the scheduler, bronze just before it is resumed, and blue while it waits to continue on a different core. Hover a red region for the waiting time. A blue one shows the two cores involved. While the thread is off a core, the zones covering that time are drawn darkened.

Above your threads, the *CPU data* lane has one row per logical CPU. Each row shows who holds that core: bright colors are threads the profiler tracks, dark blue is your application's threads it doesn't know, gray is other programs. When a thread stalls, check the row of the core it was running on. Gray at that moment means another program held the core. Empty means the core was idle: your thread was waiting on I/O, a lock, or a sleep.

> [!TIP]
> **Tip**
>
> If there is no lane and no state lines under your threads, the client captured no system data. The collection runs inside the profiled application, so the elevated rights the kernel demands must be granted to it. Details in [privilege elevation](#privilegeelevation).

Try finding a long red wait on a hot thread and check what the lane says about its core.
