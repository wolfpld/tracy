# GPU statistics

The timeline tells you when each GPU zone ran. To see their combined cost, the [Statistics window](#statistics) has a * GPU* mode, available whenever the trace contains [GPU zones](#gpuprofiling). It aggregates device-side execution time per zone across the whole capture, with no self/total split on the GPU, and therefore no `Timing` selector.

Switch to it and see which zones kept your GPU busy. Try it out!
