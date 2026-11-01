# See every process that ran

Context switch data also remembers every other process that ran during the session. The [CPU data window](#cpudata) lists them. You find it under the * Tools* menu as * CPU data*. Green entries are your program. Yellow marks threads the profiler knows. Sort by *Running time*: browsers, indexers, and daemons often use more CPU than the program you are profiling. The figure is real CPU time scaled to trace length, so above 100% means several cores were busy at once. *Slices* counts how often the scheduler put an entry on a core, *Core jumps* how often it put it on a different one. Hover your program in the list and the timeline draws its threads' paths across the cores.

> [!TIP]
> **Tip**
>
> If the menu entry is disabled, the client captured no system data. The collection runs inside the profiled application, so the elevated rights the kernel demands must be granted to it. Details in [privilege elevation](#privilegeelevation).

Try it on a busy capture and see who has been eating your CPU.
