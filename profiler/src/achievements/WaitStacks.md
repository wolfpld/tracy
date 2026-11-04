# Read wait stacks

Context switch sampling also captures a thread's call stack as it leaves the CPU. [Wait stacks](#waitstacks) collect those stacks over the whole capture, rank the wait sites by frequency, and show what the threads were doing when they waited.

Open * Wait stacks* in the * Tools* menu.

1. The list shows one wait stack at a time, most frequent first.
2. The bottom-up and top-down trees group the stacks by call path (see [Stacks windows](#stackwindows)).

A lot of it is noise: the scheduler takes threads off cores for its own reasons, and a stack ending in a sleep, a lock, or I/O is a wait your program chose. The stacks worth attention are the waits you did not expect.

Wait stacks are captured at scheduling events, so the counts show how often each wait happened.

Try it out: open the window and read the top stack of your capture.
