# Track memory

Zones tell you where time goes, but memory tells its own story: leaks and high-water marks hide in the allocation pattern, not in the call graph. Report every allocation and free with [`TracyAlloc( ptr, size )` and `TracyFree( ptr )`](#memoryprofiling), typically from your allocation wrappers, so that the whole program is tracked without touching call sites:

```c++
std::mutex memoryLock;

void* operator new( std::size_t count )
{
    std::lock_guard lock( memoryLock );
    auto ptr = malloc( count );
    TracyAlloc( ptr, count );
    return ptr;
}

void operator delete( void* ptr ) noexcept
{
    std::lock_guard lock( memoryLock );
    TracyFree( ptr );
    free( ptr );
}
```

> [!NOTE]
> **Note**
>
> Report the events atomically, in the order in which they really happen, and make sure every free has a matching allocation. Tracy aborts the profiling session when it sees a free of memory it never saw allocated.

Once the events flow, a memory usage graph shows up above the threads, and each zone learns its own memory statistics. Click the * Memory* button on the top bar to open the [Memory window](#memorywindow) and explore: allocation lists, active allocations (whatever your program still holds at exit is a leak), and a graphical memory map. Run your application and take a look. Try it out!
