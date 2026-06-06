# It's over 100 million!

Tracy can handle a lot of data. How about 100 million zones in a single trace? Add a lot of zones to your program and see how it handles it!

Capturing a long-running profile trace is easy. Need to profile an hour of your program execution? You can do it.

Note that it doesn't make much sense to instrument every little function you might have. The cost of the instrumentation itself will be higher than the cost of the function in such a case.

> [!TIP]
> Keep in mind that the more zones you have, the more memory and CPU time the profiler will use. Be careful not to run out of memory.
>
> To capture 100 million zones, you will need approximately 4 GB of RAM.
