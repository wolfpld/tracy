# Light the flame

The timeline shows what happened when: every zone drawn at its exact duration, on its own thread. The [flame graph](#flamegraph) answers the other question, where the total time went. It merges all threads and sums every run of each zone per call stack, so a box's width is total time, not a single execution.

Open it with the * Flame* button on the top bar. In *Instrumentation* mode the tree is built from your zones; hovering a box shows its execution and self time, clicking jumps to the zone statistics. In *Sampling* mode the tree is built from call stack samples, and clicking a box opens the source code.

Open the flame graph and see where the time goes. Try it out!
