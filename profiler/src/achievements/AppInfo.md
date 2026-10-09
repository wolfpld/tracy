# Describe your application

When traces pile up, it helps to know which build produced them. Use the `TracyAppInfo(txt, size)` macro to attach information about your application, for example, the source repository revision, the build configuration, or the environment (dev/prod) it is running in:

```c++
const char* info = "revision: a1b2c3d, config: Release";
TracyAppInfo( info, strlen( info ) );
```

Call it as your application starts up. You can report several facts by calling it multiple times. Each call adds its own line to the application info. The text becomes part of the trace, so it is available whenever you load it later.

Click the * Info* button on the top bar to open the Trace information window and find your description under the `Application info:` label. Try it out!
