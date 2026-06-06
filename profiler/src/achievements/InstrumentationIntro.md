# Instrumentating your application

Instrumentation is a powerful feature that allows you to see the exact runtime of each call to the selected set of functions. The downside is that it takes a bit of manual work to get it set up.

To get started, open a source file and include the `Tracy.hpp` header. This will give you access to a variety of macros provided by Tracy. Next, add the `ZoneScoped` macro to the beginning of one of your functions, like this:

```c++
#include "Tracy.hpp"

void SomeFunction()
{
    ZoneScoped;
    // Your code here
}
```

Now, when you profile your application, you will see a new zone appear on the timeline for each call to the function. This allows you to see how much time is spent in each call and how many times the function is called.

> [!NOTE]
> The `ZoneScoped` macro is just one of the many macros provided by Tracy. See the documentation for more information.

The above description applies to C++ code, but things are done similarly in other programming languages. Refer to the documentation for your language for more information.
