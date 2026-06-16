# Call stacks

A call stack is a trace of program execution at the moment of capture. This capture can happen at any time, but it usually occurs when a program crashes, so the developer can trace the path that led to the failure. The case of call stacks in a profiler is very different. During profiling, the operating system halts execution of the program at a predefined rate-for example, 10 kHz-notes where the program execution is and the function calls that led it there, then resumes the program. As can be seen, the call stacks in a profiler are slices of a normal workflow you can use to explore execution characteristics, not indications of failure.

# Call stack structure

The top call stack frame is numbered 0, and it always is the place *where the program execution is* during the stack capture. Stack frame numbers increase the farther toward the origin function we go, as the usual convention goes. A stack trace is always a snapshot of what a *single thread* is doing.

In Tracy Profiler, each execution frame can have multiple *inline* frames. When a program is compiled, the compiler, as an optimization, may inline function calls into the base function ("symbol"), and the profiler can track that.

To show how it works, let's consider the following source code:

```c++
float Square(float val) { return val*val; }
float Distance(Point p1, Point p2) { return sqrt(Square(p1.x-p2.x)+Square(p1.y-p2.y)); }
bool CanReach(Player p, Item i) { return Distance(p.pos, i.pos)<5; }
```

Now, let's say we capture a call stack inside the `Square` function. This is how the call stack can look:

```callstack
0. Square() [inline 0]
0. Distance() [inline 1]
0. CanReach() [inline 2]
1. ItemsLoop()
2. PlayerLogic()
3. ...
```

There are three frames with index 0, which means that both `Square` and `Distance` have been inlined into the `CanReach` function, forming a symbol named `CanReach`. Following the inline stack frame indices, we can also see that the call order is `CanReach` -> `Distance` -> `Square`, which matches what the source code does.

Note that while the example is at the top level, inline frames can appear at any depth of the call stack.

# Call stacks are return stacks

You need to be very careful when reading call stacks. The usual notion is that call stacks (as the name suggests) show function call stacks, that is, which function called which to get where we are. Unfortunately, this is not true. In reality, call stacks are *function return stacks*. The call stack shows where each function will **return**, not from where it was called.

## Example 1

To fully understand how this works, consider the following source code:

```c++
int main()
{
    auto app = std::make_unique<Application>();
    app->Run();
    app.reset();
}
```

Let's assume the `Application` instance (`app`) is already created and we have entered the `Run` method, where, somewhere inside, we're capturing a call stack. Here's a result we might get:

```callstack
0. Application::Run()
1. std::unique_ptr<Application>::reset()
2. main()
```

At the first glance it may look like `unique_ptr::reset` was the *call site* of the `Application::Run`, which would make no sense, but this is not the case here. When you remember these are the *function return points*, it becomes much more clear what is happening. As an optimization, `Application::Run` is returning directly into `unique_ptr::reset`, skipping the return to `main` and an unnecessary `reset` function call.

## Example 2

Here you will see how a function on the call chain can be entirely absent:

```c++
int ComputeHash(const Buffer& b) {
    // expensive hashing
    ...
}

int Validate(const Buffer& b) {
    if(b.empty()) return 0;
    return ComputeHash(b);
}

void HandleRequest(Request& r) {
    int h = Validate(r.payload);
    Store(r, h);
}
```

A sample lands inside ComputeHash. The captured stack looks like this: 

```callstack
0. ComputeHash()
1. HandleRequest()
2. RequestLoop()
```

**Naive (call-stack) reading:** `HandleRequest` called `ComputeHash` directly. Conclusion: optimize the call site in `HandleRequest`, or rethink why `HandleRequest` is hashing.

**Correct (return-stack) reading:** Frame 1 is where `ComputeHash` will return to, not who called it. `Validate` ended with return `ComputeHash(b)`, so the compiler turned that into a tail call — `Validate`'s own frame was reused for `ComputeHash`. When `ComputeHash` returns, it skips `Validate` entirely and lands in `HandleRequest`. `Validate` is on the actual call chain (`HandleRequest` -> `Validate` -> `ComputeHash`) but is missing from the stack.

**Why the divergence matters:** The naive reading sends you to fix the wrong code. `HandleRequest` doesn't decide to hash anything — `Validate` does. If you act on the naive interpretation, you investigate a function that has no agency in this hot path while the actual decision-maker (`Validate`) is invisible.

**Lesson the example teaches:** Any frame below a given frame in the stack may not be its caller. It is only guaranteed to be the return target. Functions on the real call chain can be entirely absent — tail-called away or inlined.

# Crash handler

Tracy Profiler can intercept crashes and report them to the user for analysis. To do this, some code machinery is needed, and then the Tracy crash handler needs to run, capture the call stack, and send it over the network. All this only happens after the actual crash occurred; otherwise, there would be no reason to run the crash handler. As a consequence, the retrieved crash trace may include parts of the crash handler stack, which you must ignore.

# Base address and instruction pointer

Each frame in a call stack has an associated instruction pointer, `ip` – the return address where the execution will return from the function a frame above. This address is somewhere in the symbol code. The start of the symbol is provided as the `baseAddr` value. This base address identifies the symbol and can be used in various symbol-related tool calls as the symbol address.

# Wait stacks

Some call stacks represent time spent waiting for something to happen. For example, the program may want to read something from the disk. In such cases, program execution will be paused, and the CPU will start running kernel code responsible for filesystem access, I/O routines, or just idling while waiting for a response from the hardware.

A wait stack is identified by the presence of the `wait_time` field, which shows how much time was spent waiting for execution to return to the program. Further information about the wait stack can be inferred from the optional fields `wait_reason` (with an explanation in `wait_reason_hint`) and `wait_state` (with an explanation in `wait_state_hint`).

# Inspecting call stacks

1. Focus on user's code. Ignore standard library boilerplate.
2. Retrieve source code to verify call stack validity. Frames in call stacks are return locations, and the call site may actually be near the reported source line, or in a different function altogether.
3. Top of the call stack is the most interesting, as it shows what the program is doing *now*. The bottom of the call stack shows what the program did to do what it's doing.
4. If the call stack contains Tracy's crash handler, the profiled program has crashed. In this case, ignore the crash handler and any functions it may be calling. The crash happened *before* the handler intercepted it.
