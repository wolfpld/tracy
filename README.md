# Tracy Profiler

[![Sponsor](.github/sponsor.png)](https://github.com/sponsors/wolfpld/)

### A real time, nanosecond resolution, remote telemetry, hybrid frame and sampling profiler for games and other applications.

Tracy supports profiling CPU (Direct support is provided for C, C++, and Lua integration. At the same time, third-party bindings to many other languages exist on the internet, such as [Rust](https://github.com/nagisa/rust_tracy_client), [Zig](https://github.com/nektro/zig-tracy), [C#](https://github.com/clibequilibrium/Tracy-CSharp), [OCaml](https://github.com/imandra-ai/ocaml-tracy), [Odin](https://github.com/oskarnp/odin-tracy), etc.), GPU (All major graphic APIs: OpenGL, Vulkan, Direct3D 11/12, OpenCL.), memory allocations, locks, context switches, automatically attribute screenshots to captured frames, and much more.

- [Documentation](https://github.com/wolfpld/tracy/releases/latest/download/tracy.pdf) for usage and build process instructions
- [Releases](https://github.com/wolfpld/tracy/releases) containing the documentation (`tracy.pdf`) and compiled Windows x64 binaries (`Tracy-<version>.7z`) as assets
- [Changelog](NEWS)
- [Interactive demo](https://tracy.nereid.pl/)

![](doc/profiler.png)

![](doc/profiler2.png)

![](doc/profiler3.png)

[An Introduction to Tracy Profiler in C++ - Marcos Slomp - CppCon 2023](https://youtu.be/ghXk3Bk5F2U?t=37)

[Introduction to Tracy Profiler v0.2](https://www.youtube.com/watch?v=fB5B46lbapc)  
[New features in Tracy Profiler v0.3](https://www.youtube.com/watch?v=3SXpDpDh2Uo)  
[New features in Tracy Profiler v0.4](https://www.youtube.com/watch?v=eAkgkaO8B9o)  
[New features in Tracy Profiler v0.5](https://www.youtube.com/watch?v=P6E7qLMmzTQ)  
[New features in Tracy Profiler v0.6](https://www.youtube.com/watch?v=uJkrFgriuOo)  
[New features in Tracy Profiler v0.7](https://www.youtube.com/watch?v=_hU7vw00MZ4)  
[New features in Tracy Profiler v0.8](https://www.youtube.com/watch?v=30wpRpHTTag)

# Building the executables

For an indepth build guide please refer to the [documentation](https://github.com/wolfpld/tracy/releases/latest/download/tracy.pdf)

For a quick build guide with CMake:

### Profiler

```bash
cmake -B build/profiler -S profiler
cmake --build build/profiler
```

### Update

```bash
cmake -B build/update -S update
cmake --build build/update
```

### Capture

```bash
cmake -B build/capture -S capture
cmake --build build/capture
```

### Csv Export

```bash
cmake -B build/csvexport -S csvexport
cmake --build build/csvexport
```

### Import Chrome

```bash
cmake -B build/import-chrome -S import-chrome
cmake --build build/import-chrome
```

## Import Fuchsia

```bash
cmake -B build/import-fuchsia -S import-fuchsia
cmake --build build/import-fuchsia
```