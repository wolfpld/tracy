# Name your threads

A busy application can run dozens of threads. Without names, the timeline shows rows of identical fallback labels and you have no way to tell which thread does what.

Label them from your code. Call [`tracy::SetThreadName(name)`](#namingthreads) once from within each thread you start, typically as its first statement:

```c++
void WorkerLoop()
{
    tracy::SetThreadName( "Worker" );
    while( true ) { DoWork(); }
}
```

The name labels the thread's row in the timeline and identifies it across the UI. Give pool workers distinct names, like `Worker 1` and `Worker 2`, so you can follow where a job lands. Click a thread label to collapse its row and give the other threads more room. Try it out!
