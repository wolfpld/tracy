# Trace allocation call stacks

The allocation lists tell you what is in memory, but not who put it there. Swap the macros for their [S-postfix](#collectingcallstacks) variants, `TracyAllocS( ptr, size, depth )` and `TracyFreeS( ptr, depth )`, and every event carries a call stack. Capturing a stack costs time, and the cost grows with `depth`.

When the events carry stacks, the [Memory window](#memorywindow) can group them into trees. The * Top-down call stack tree* starts at the allocating functions and expands the call paths that led there, each level sorted by the bytes allocated in its branch, so the hottest allocators sit at the top. The bottom-up pane walks the same data the other way, from the call stack entry point down to the allocation site. Right-click a function name to list the [allocations](#alloclist) behind it.

Expand the top-down tree and follow the top branch. Try it out!
