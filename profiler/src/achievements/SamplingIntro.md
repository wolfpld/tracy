# Sampling program execution

Sampling program execution is a great way to find out where the hot spots are in your program. It can be used to find out which functions take the most time, or which lines of code are executed the most often.

While instrumentation requires changes to your code, sampling does not. However, because of the way it works, the results are coarser and it's not possible to know when functions are called or when they return.

Sampling is automatic on Linux. On Windows, you must run the profiled application as an administrator for it to work.

> [!WARNING]
> Depending on your system configuration, some additional steps may be required. Please refer to the user manual for more information.
