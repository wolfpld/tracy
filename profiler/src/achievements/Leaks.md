# Hunt leaks

A leak is memory your program allocated and never freed. Once your program has finished, everything still listed under `Active allocations` in the [Memory window](#memorywindow) is a leak, ordered by allocation time, with the total on the pane header.

Click a block's address to open the [allocation information window](#memallocinfo) with its time, thread and zone data. Middle-clicking an allocation in the list zooms without opening the window.

Let your program finish and expand `Active allocations`. Try it out!
