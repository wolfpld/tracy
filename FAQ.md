# A quick tracy FAQ

### I already use VTune/perf/Very Sleepy/callgrind/MSVC profiler.

These are statistical profilers, which can be used to find hot spots in the code. This is very useful, but it won't show you the underlying reason for semi-random frame stutter that may occur every couple of seconds.

### You can use Telemetry for that.

Telemetry license costs about 8000 $ per year. Tracy is open source software. Telemetry doesn't have Lua bindings.

### You can use the free Brofiler. Crytek does use it, so it has to be good.

After a cursory look at the Brofiler code I can tell that the timer resolution there is at 300 ns. Tracy can achieve 5 ns timer resolution. Brofiler event logging infrastructure seems to be over-engineered. Brofiler can't track lock contention, nor does it have Lua bindings.

### So tracy is supposedly faster?

My measurements show that logging a single zone with tracy takes only 15 ns. In theory, if the program was doing nothing else, tracy should be able to log 66 million zones per second.

### Bullshit, RAD is advertising that they are able only to log about a million zones, over the network nevertheless: "Capture over a million timing zones per second in real-time!"

Tracy can perform network transfer of 15 million zones per second. Should the client and server be on separate machines, this number will be even higher, but you will need more than a gigabit link to achieve the maximum throughput. [Click here for a video of a max-throughput capture.](https://www.youtube.com/watch?v=DSMIHShKGAc)

### Can I connect to my application at any time and start profiling at this moment?

By default no, all events are registered from the beginning of program execution and are waiting in a queue. There's a separate on-demand mode, enabled by using a `TRACY_ON_DEMAND` macro.

### Am I seeing correctly that the profiler allocates one gigabyte of memory per second?

Only in extreme cases. Normal usage has much lower memory pressure.

### Why do you do magic with the static initialization order? Everyone says that's a bad practice.

It allows tracking construction of static objects and memory allocations performed before main() is entered.

### There's no support for consoles.

Welp. But there's mobile support.

### I do need console support.

The code is open. Write your own, then send a patch.
