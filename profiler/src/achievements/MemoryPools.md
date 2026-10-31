# Separate pools

An application rarely allocates from a single heap: the C runtime provides `malloc`, a graphics API manages device memory on its own, and a script VM runs its allocator. Report all of it through plain `TracyAlloc` and the usage curve is a single total that hides which heap is which.

[`TracyAllocN( ptr, size, name )` and `TracyFreeN( ptr, name )`](#memorypools) attribute events to the pool named by `name`, a [unique pointer to a string literal](#uniquepointers) like every other Tracy string. Every pool gets its own usage plot above the timeline, and once a second pool shows up the [Memory window](#memorywindow) grows a * Memory pool* selector, so its lists, memory map and call stack trees describe that pool alone.

Switch to your named pool and see what it holds. Try it out!
