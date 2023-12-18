Tracy Profiler

The user manual

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.001.png)

**Bartosz Taudul** [<wolf@nereid.pl> ](mailto:wolf@nereid.pl)October 16, 2023

<https://github.com/wolfpld/tracy>

Tracy Profiler The user manual![ref1]

**Quick overview**

Hello and welcome to the Tracy Profileruser manual! Here you will findall the information you need to start using the profiler. This manual has the following layout:

- Chapter [1, *A quick look at Tracy Profiler*,](#_page6_x63.64_y90.71) gives a short description of what Tracy is and how it works.
- Chapter [2, *First steps*,](#_page10_x63.64_y533.87) shows how you can integrate the profilerinto your application and how to build the graphical user interface (section [2.3). A](#_page19_x63.64_y255.32)t this point, you will be able to establish a connection from the profilerto your application.
- Chapter [3, *Client markup*,](#_page22_x63.64_y725.77) provides information on how to instrument your application, in order to retrieve useful profilingdata. This includes a description of the C API (section 3.13), [which ](#_page42_x63.64_y636.27)enables usage of Tracy in any programming language.
- Chapter [4, *Capturing the data*,](#_page52_x63.64_y589.65) goes into more detail on how the profilinginformation can be captured and stored on disk.
- Chapter [5, *Analyzing captured data*,](#_page58_x63.64_y346.67) guides you through the graphical user interface of the profiler.
- Chapter [6, *Exporting zone statistics to CSV* ,](#_page87_x63.64_y583.51) explains how to export some zone timing statistics into a CSV format.
- Chapter [7, *Importing external profilingdata*,](#_page88_x63.64_y388.34) documents how to import data from other profilers.
- Chapter [8, *Configuration files*,](#_page89_x63.64_y118.43) gives information on the profilersettings.

**Quick-start guide**

For Tracy to profileyour application, you will need to integrate the profilerinto your application and run an independent executable that will act both as a server with which your application will communicate and as a profilingviewer. The most basic integration looks like this:

- Add the Tracy repository to your project directory.
- Tracy source filesin the project/tracy/public directory.
- Add TracyClient.cpp as a source file.
- Add tracy/Tracy.hpp as an include file.
- Include Tracy.hpp in every fileyou are interested in profiling.
- Define TRACY\_ENABLEfor the **WHOLE** project.
- Add the macro FrameMark at the end of each frame loop.
- Add the macro ZoneScoped as the first line of your function definitionsto include them in the profile.
- Compile and run both your application and the profilerserver.
- Hit *Connect* on the profilerserver.
- Tada! You’re profilingyour program!

There’s much more Tracy can do, which can be explored by carefully reading this manual. In case any problems should surface, refer to section 2.1 t[o ensure](#_page11_x63.64_y255.91) you’ve correctly included Tracy in your project. Additionally, you should refer to section 3 to[ mak](#_page22_x63.64_y725.77)e sure you are using FrameMark, ZoneScoped, and any other Tracy constructs correctly.

**Contents**

[**1 A quick look at Tracy Profiler](#_page6_x63.64_y90.71) **6**

1. [Real-time ](#_page6_x63.64_y293.68). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 6
1. [Nanosecond resolution . ](#_page6_x63.64_y487.50). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 6

   [1.2.1 Timer accuracy ](#_page7_x63.64_y141.14). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 7

3. [Frame profiler .](#_page7_x63.64_y552.81) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 7
4. [Sampling profiler .](#_page7_x63.64_y637.78) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8
4. [Remote or embedded telemetry . .](#_page8_x63.64_y198.08) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8
4. [Why Tracy? .](#_page8_x63.64_y488.48) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8
4. [Performance impact . ](#_page9_x63.64_y270.85). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 9

   [1.7.1 Assembly analysis ](#_page9_x63.64_y466.57). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 9

8. [Examples ](#_page10_x63.64_y185.62). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 10
9. [On the web .](#_page10_x63.64_y248.34) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 10

   [1.9.1 Binary distribution . ](#_page10_x63.64_y409.34). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 10

2  [**First steps](#_page10_x63.64_y533.87) **10**
1. [Initial client setup . ](#_page11_x63.64_y255.91). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 11
1. [Short-lived applications . ](#_page12_x63.64_y622.11). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 12
1. [On-demand profiling . .](#_page12_x63.64_y720.61) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
1. [Client discovery . ](#_page13_x63.64_y293.87). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
1. [Client network interface . ](#_page13_x63.64_y378.66). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
1. [Setup for multi-DLL projects .](#_page13_x63.64_y485.65) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 13
1. [Problematic platforms . ](#_page14_x63.64_y247.01). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 14
1. [Microsoft Visual Studio . ](#_page14_x63.64_y307.85). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 14
1. [Universal Windows Platform . .](#_page14_x63.64_y390.22) . . . . . . . . . . . . . . . . . . . . . . . . . . 14
1. [Apple woes .](#_page14_x63.64_y551.29) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 14
1. [Android lunacy ](#_page14_x63.64_y699.81). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 15
1. [Virtual machines . ](#_page15_x63.64_y298.18). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 15
7. [Changing network port . ](#_page15_x63.64_y527.48). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 15
8. [Limitations ](#_page16_x63.64_y160.51). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 16
2. [Check your environment . ](#_page16_x63.64_y480.19). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 16
1. [Operating system . ](#_page16_x63.64_y555.45). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 16
1. [CPU design ](#_page17_x63.64_y164.09). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 17
1. [Superscalar out-of-order speculative execution . . ](#_page17_x63.64_y274.94). . . . . . . . . . . . . . . 17
1. [Simultaneous multithreading . ](#_page17_x63.64_y397.34). . . . . . . . . . . . . . . . . . . . . . . . . . 17
1. [Turbo mode frequency scaling . .](#_page17_x63.64_y544.85) . . . . . . . . . . . . . . . . . . . . . . . . . 17
1. [Power saving .](#_page18_x63.64_y264.87) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 18
1. [AVX offsetand power licenses . ](#_page18_x63.64_y377.53). . . . . . . . . . . . . . . . . . . . . . . . . . 18
1. [Summing it up .](#_page18_x63.64_y524.21) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 18
3. [Building the server .](#_page19_x63.64_y255.32) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 19
1. [Required libraries . ](#_page19_x63.64_y484.07). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 19
1. [Windows ](#_page19_x63.64_y631.58). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 19
1. [Unix ](#_page20_x63.64_y272.17). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 20
2. [Build process ](#_page20_x63.64_y564.81). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 20
3. [Embedding the server in profiledapplication . . .](#_page20_x63.64_y650.76) . . . . . . . . . . . . . . . . . . . . . 20
3. [DPI scaling ](#_page21_x63.64_y315.09). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 21
4. [Naming threads . ](#_page21_x63.64_y375.71). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 21

   [2.4.1 Source location data customization . . ](#_page21_x63.64_y473.50). . . . . . . . . . . . . . . . . . . . . . . . . . . . 21

5. [Crash handling ](#_page21_x63.64_y703.26). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 22
6. [Feature support matrix . ](#_page22_x63.64_y357.24). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 22
3  [**Client markup](#_page22_x63.64_y725.77) **23**
1. [Handling text strings . ](#_page23_x63.64_y218.36). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 23
1. [Program data lifetime .](#_page23_x63.64_y431.91) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 23
1. [Unique pointers . ](#_page23_x63.64_y565.27). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 23
2. [Specifying colors ](#_page24_x63.64_y471.18). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 24
3. [Marking frames .](#_page24_x63.64_y581.52) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 24
1. [Secondary frame sets . ](#_page25_x63.64_y90.71). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 25
1. [Discontinuous frames .](#_page25_x63.64_y147.57) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 25
1. [Frame images ](#_page25_x63.64_y375.56). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 25

   [3.3.3.1 OpenGL screen capture code example . ](#_page26_x63.64_y312.42). . . . . . . . . . . . . . . . . . . . . 26

4. [Marking zones . ](#_page28_x63.64_y607.86). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 28
1. [Manual management of zone scope . ](#_page29_x63.64_y305.59). . . . . . . . . . . . . . . . . . . . . . . . . . . . 29
1. [Multiple zones in one scope . ](#_page29_x63.64_y388.64). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 29
1. [Filtering zones ](#_page30_x63.64_y186.99). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
1. [Transient zones .](#_page30_x63.64_y590.37) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
1. [Variable shadowing ](#_page30_x63.64_y698.32). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 30
1. [Exiting program from within a zone . . ](#_page31_x63.64_y240.52). . . . . . . . . . . . . . . . . . . . . . . . . . . 31
5. [Marking locks ](#_page31_x63.64_y373.87). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 31

   [3.5.1 Custom locks ](#_page32_x63.64_y284.07). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 32

6. [Plotting data .](#_page32_x63.64_y370.02) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 32
7. [Message log ](#_page33_x63.64_y190.70). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 33

   [3.7.1 Application information . ](#_page33_x63.64_y301.69). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 33

8. [Memory profiling . ](#_page33_x63.64_y384.83). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 33

   [3.8.1 Memory pools . ](#_page34_x63.64_y508.99). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 34

9. [GPU profiling ](#_page34_x63.64_y620.04). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 34
1. [OpenGL ](#_page35_x63.64_y485.75). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 35
1. [Vulkan ](#_page36_x63.64_y137.00). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 36
1. [Direct3D 11 ](#_page36_x63.64_y650.14). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 36
1. [Direct3D 12 ](#_page37_x63.64_y166.25). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 37
1. [OpenCL ](#_page37_x63.64_y450.23). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 37
1. [Multiple zones in one scope . ](#_page37_x63.64_y671.46). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 37
1. [Transient GPU zones . ](#_page38_x63.64_y141.14). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 38
10. [Fibers ](#_page38_x63.64_y186.62). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 38
11. [Collecting call stacks ](#_page38_x63.64_y711.23). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 39

    [3.11.1 Debugging symbols .](#_page40_x63.64_y301.88) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 40

1. [External libraries . ](#_page40_x63.64_y600.45). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 40
1. [Using the dbghelp library on Windows . . ](#_page41_x63.64_y333.02). . . . . . . . . . . . . . . . . . . . 41
1. [Disabling resolution of inline frames . ](#_page41_x63.64_y679.55). . . . . . . . . . . . . . . . . . . . . . 42
12. [Lua support ](#_page42_x63.64_y183.21). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42
1. [Call stacks ](#_page42_x63.64_y358.91). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42
1. [Instrumentation cleanup . .](#_page42_x63.64_y565.64) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42
13. [C API ](#_page42_x63.64_y636.27). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42
1. [Setting thread names . ](#_page43_x63.64_y438.28). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 43
1. [Frame markup ](#_page43_x63.64_y486.50). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 43
1. [Zone markup .](#_page43_x63.64_y643.96) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 43
1. [Zone context data structure . ](#_page44_x63.64_y438.41). . . . . . . . . . . . . . . . . . . . . . . . . . . 44
1. [Zone validation ](#_page44_x63.64_y659.90). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 44
1. [Transient zones in C API .](#_page45_x63.64_y127.31) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 45
4. [Memory profiling . ](#_page45_x63.64_y188.44). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 45
5. [Plots and messages . ](#_page45_x63.64_y428.39). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 45
5. [GPU zones .](#_page45_x63.64_y659.97) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 46
5. [Fibers ](#_page46_x63.64_y462.99). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 46
8. [Connection Status ](#_page46_x63.64_y521.03). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 46
8. [Call stacks ](#_page46_x63.64_y566.51). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 46 [3.13.10Using the C API to implement bindings . . ](#_page46_x63.64_y635.95). . . . . . . . . . . . . . . . . . . . . . . . . 46
14. [Automated data collection . ](#_page47_x63.64_y486.91). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 47
1. [Privilege elevation ](#_page47_x63.64_y549.84). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 47
1. [CPU usage .](#_page48_x63.64_y188.87) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 48
1. [Context switches .](#_page48_x63.64_y261.96) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 48
1. [CPU topology .](#_page48_x63.64_y455.18) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 48
1. [Call stack sampling . ](#_page49_x63.64_y158.34). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 49

   [3.14.5.1 Wait stacks ](#_page49_x63.64_y506.03). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 49

6. [Hardware sampling .](#_page50_x63.64_y177.15) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 50
7. [Executable code retrieval .](#_page51_x63.64_y178.80) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 51
7. [Vertical synchronization . ](#_page51_x63.64_y455.68). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 51
15. [Trace parameters ](#_page51_x63.64_y591.84). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 51
16. [Source contents callback .](#_page52_x63.64_y272.11) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 52
16. [Connection status . ](#_page52_x63.64_y530.67). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 52
4  [**Capturing the data](#_page52_x63.64_y589.65) **52**
1. [Command line . ](#_page52_x63.64_y660.98). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 52
1. [Interactive profiling . ](#_page53_x63.64_y391.20). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 53
1. [Connection information pop-up . ](#_page53_x63.64_y677.28). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 54
1. [Automatic loading or connecting . .](#_page54_x63.64_y613.27) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 54
3. [Connection speed . ](#_page54_x63.64_y696.23). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 55
4. [Memory usage . ](#_page55_x63.64_y195.48). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 55
4. [Trace versioning .](#_page55_x63.64_y346.07) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 55
1. [Archival mode ](#_page55_x63.64_y526.55). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 55
1. [Frame images dictionary . .](#_page57_x63.64_y357.28) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 57
1. [Data removal ](#_page57_x63.64_y503.18). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 57
6. [Source filecache scan .](#_page58_x63.64_y138.55) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 58
7. [Instrumentation failures . ](#_page58_x63.64_y261.44). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 58

[**5 Analyzing captured data](#_page58_x63.64_y346.67) **58**

1. [Time display .](#_page58_x63.64_y441.97) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 58
1. [Main profilerwindow .](#_page58_x63.64_y577.41) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 58
1. [Control menu .](#_page58_x63.64_y637.54) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 58

   [5.2.1.1 Notificationarea .](#_page60_x63.64_y320.27) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 60

2. [Frame time graph . ](#_page60_x63.64_y664.66). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 60
3. [Timeline view .](#_page61_x63.64_y494.12) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 61
1. [Time scale .](#_page61_x63.64_y641.01) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 61
1. [Frame sets ](#_page62_x63.64_y185.12). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 62
1. [Zones, locks and plots display . ](#_page62_x63.64_y526.21). . . . . . . . . . . . . . . . . . . . . . . . . . 62
4. [Navigating the view .](#_page66_x63.64_y361.93) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 66
3. [Time ranges ](#_page66_x63.64_y550.49). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 66

[5.3.1 Annotating the trace .](#_page67_x63.64_y202.61) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 67

4. [Options menu .](#_page67_x63.64_y452.14) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 67
5. [Messages window . ](#_page68_x63.64_y696.73). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 69
5. [Statistics window .](#_page69_x63.64_y377.90) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 69
1. [Instrumentation mode . ](#_page69_x63.64_y515.94). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 69
1. [Sampling mode .](#_page69_x63.64_y738.45) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 70
1. [GPU zones mode .](#_page70_x63.64_y701.20) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 71
7. [Find zone window .](#_page71_x63.64_y132.43) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 71
1. [Timeline interaction ](#_page73_x63.64_y460.25). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 73
2. [Frame time graph interaction . ](#_page73_x63.64_y533.65). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 73
2. [Limiting zone time range .](#_page74_x63.64_y90.71) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 74
2. [Zone samples .](#_page74_x63.64_y160.13) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 74
8. [Compare traces window . ](#_page74_x63.64_y280.93). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 74

   [5.8.1 Source filesdiff ](#_page75_x63.64_y247.07). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 75

9. [Memory window .](#_page75_x63.64_y345.37) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 75
1. [Allocations .](#_page76_x63.64_y103.48) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 76
1. [Active allocations .](#_page76_x63.64_y161.52) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 76
1. [Memory map ](#_page76_x63.64_y232.10). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 76
1. [Bottom-up call stack tree . ](#_page76_x63.64_y340.35). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 76
1. [Top-down call stack tree . ](#_page76_x63.64_y664.58). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 77
1. [Looking back at the memory history . . ](#_page77_x63.64_y147.57). . . . . . . . . . . . . . . . . . . . . . . . . . . 77
10. [Allocations list window .](#_page77_x63.64_y218.16) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 77
11. [Memory allocation information window . . ](#_page77_x63.64_y277.64). . . . . . . . . . . . . . . . . . . . . . . . . . . . . 77
11. [Trace information window . .](#_page77_x63.64_y349.40) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 77
11. [Zone information window . .](#_page78_x63.64_y165.60) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 78
11. [Call stack window . ](#_page79_x63.64_y262.70). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 79

    [5.14.1 Reading call stacks .](#_page79_x63.64_y645.14) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 79

15. [Sample entry call stacks window . ](#_page80_x63.64_y373.37). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 80
16. [Source view window . ](#_page80_x63.64_y496.26). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 80
1. [Source fileview .](#_page80_x63.64_y566.34) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 80
1. [Symbol view ](#_page81_x63.64_y320.07). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 81
1. [Source mode ](#_page81_x63.64_y576.20). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 81
1. [Assembly mode ](#_page82_x63.64_y141.14). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 82
1. [Combined mode . ](#_page84_x63.64_y221.84). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 84
1. [Instruction pointer cost statistics . . ](#_page84_x63.64_y345.67). . . . . . . . . . . . . . . . . . . . . . . . 84
1. [Inspecting hardware samples . ](#_page85_x63.64_y209.35). . . . . . . . . . . . . . . . . . . . . . . . . . 85
17. [Wait stacks window . ](#_page86_x63.64_y90.71). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 86
18. [Lock information window . ](#_page86_x63.64_y246.49). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 86
18. [Frame image playback window . .](#_page86_x63.64_y316.58) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 86
18. [CPU data window ](#_page86_x63.64_y454.62). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 86
18. [Annotation settings window . . ](#_page86_x63.64_y627.72). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 86
18. [Annotation list window .](#_page86_x63.64_y687.84) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 87
18. [Time range limits ](#_page87_x63.64_y335.67). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 87
6  [**Exporting zone statistics to CSV](#_page87_x63.64_y583.51) **87**
6  [**Importing external profilingdata](#_page88_x63.64_y388.34) **88**
6  [**Configurationfiles](#_page89_x63.64_y118.43) **89**
1. [Root directory .](#_page89_x63.64_y245.94) . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 89
1. [Trace specificsettings . ](#_page89_x63.64_y308.67). . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 89

[**A License](#_page90_x63.64_y124.76) **90 [B List of contributors](#_page90_x63.64_y498.37) 90 [C Inventory of external libraries](#_page91_x63.64_y149.53) 91**

<a name="_page6_x63.64_y90.71"></a>**1 A quick look at Tracy Profiler**

Tracy is a real-time, nanosecond resolution *hybrid frame and sampling profiler*that can you can use for remote

or embedded telemetry of games and other applications. It can profileCPU , GPU [, ](#_page6_x77.98_y658.89)[memory](#_page6_x77.98_y678.43) allocations, locks, context switches, automatically attribute screenshots to captured frames, and much more.

While Tracy can perform statistical analysis of sampled call stack data, just like other *statistical profilers* (such as VTune, perf, or Very Sleepy), it mainly focuses on manual markup of the source code. Such markup allows frame-by-frame inspection of the program execution. For example, you will be able to see exactly which functions are called, how much time they require, and how they interact with each other in a multi-threaded environment. In contrast, the statistical analysis may show you the hot spots in your code, but it cannot accurately pinpoint the underlying cause for semi-random frame stutter that may occur every couple of seconds.

Even though Tracy targets *frame* profiling, with the emphasis on analysis of *frame time* in real-time applications(i.e.games), itdoesworkwithutilitiesthatdonotemploytheconceptofaframe. There’snothing that would prohibit the profilingof, for example, a compression tool or an event-driven UI application.

You may think of Tracy as the RAD Telemetry plus Intel VTune, on overdrive.

1. **Real-time**

<a name="_page6_x63.64_y293.68"></a>The concept of Tracy being a real-time profilermay be explained in a couple of different ways:

1. The profiledapplication is not slowed down by profiling . The[ act](#_page6_x77.98_y688.04) of recording a profilingevent has virtually zero cost – it only takes a few nanoseconds. Even on low-power mobile devices, execution speed has no noticeable impact.
1. The profiler itself works in real-time, without the need to process collected data in a complex way. Actually, it is pretty inefficientin how it works because it recalculates the data it presents each frame anew. And yet, it can run at 60 frames per second.
1. The profilerhas full functionality when the profiledapplication runs and the data is still collected. You may interact with your application and immediately switch to the profilerwhen a performance drop occurs.
2. **Nanosecond<a name="_page6_x63.64_y487.50"></a> resolution**

It is hard to imagine how long a nanosecond is. One good analogy is to compare it with a measure of length. Let’s say that one second is one meter (the average doorknob is at the height of one meter).

One millisecond ( 1 of a second) would be then the length of a millimeter. The average size of a red ant

1000

or the width of a pencil is 5 or 6 mm. A modern game running at 60 frames per second has only 16 ms to update the game world and render the entire scene.

One microsecond ( 1 of a millisecond) in our comparison equals one micron. The diameter of a typical

1000

bacterium ranges from 1 to 10 microns. The diameter of a red blood cell or width of a strand of spider web silk is about 7 m.

Andfinally,onenanosecond( 1 ofamicrosecond)wouldbeonenanometer. Themodernmicroprocessor

1000

transistor gate, the width of the DNA helix, or the thickness of a cell membrane are in the range of 5 nm. In one ns the light can travel only 30 cm.![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.003.png)

` `<a name="_page6_x77.98_y658.89"></a>Direct support is provided for C, C++, and Lua integration. At the same time, third-party bindings to many other languages exist on the<a name="_page6_x77.98_y678.43"></a> internet, such as Rust, Zig, C#, OCaml, Odin, etc.

` `All<a name="_page6_x77.98_y688.04"></a> major graphic APIs: OpenGL, Vulkan, Direct3D 11/12, OpenCL.

` `See section [1.7 f](#_page9_x63.64_y270.85)or a benchmark.

Tracy can achieve single-digit nanosecond measurement resolution due to usage of hardware timing mechanisms on the x86 and ARM architectures . [Other](#_page7_x77.98_y642.82) profilersmay rely on the timers provided by the operating system, which do have significantly reduced resolution (about 300 ns – 1 s). This is enough to hide the subtle impact of cache access optimization, etc.

<a name="_page7_x63.64_y141.14"></a>**1.2.1 Timer accuracy**

You may wonder why it is vital to have a genuinely high resolution timer . After[ all,](#_page7_x77.98_y682.24) you only want to profilefunctions with long execution times and not some short-lived procedures that have no impact on the application’s run time.

It is wrong to think so. Optimizing a function to execute in 430 ns, instead of 535 ns (note that there is only a 100 ns difference) results in 14 ms savings if the function is executed 18000 times . It[ ma](#_page7_x77.98_y691.85)y not seem like a big number, but this is how much time there is to render a complete frame in a 60 FPS game. Imagine

that this is your particle processing loop.

You also need to understand how timer precision is reflected in measurement errors. Take a look at figure[1. ](#_page7_x63.64_y304.40)There you can see three discrete timer tick events, which increase the value reported by the timer by 300 ns. You can also see four readings of time ranges, marked 𝐴1, 𝐴2; 𝐵1, 𝐵2; 𝐶1, 𝐶2 and 𝐷1, 𝐷2.

<a name="_page7_x63.64_y304.40"></a>300 ns![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.004.png)

Time![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.005.png)

𝐶1𝐵1 𝐷1𝐷2 𝐴1𝐴2 𝐵2𝐶2 **Figure 1:** *Low precision (300 ns) timer. Discrete timer ticks are indicated by the*  *icon.*

Now let’s take a look at the timer readings.

- The 𝐴and 𝐷ranges both take a very short amount of time (10 ns), but the 𝐴range is reported as 300 ns, and the 𝐷range is reported as 0 ns.
- The 𝐵range takes a considerable amount of time (590 ns), but according to the timer readings, it took

the same time (300 ns) as the short lived 𝐴range.

- The 𝐶range(610 ns)isonly20 ns longerthanthe 𝐵range, butitisreportedas900 ns, a600 ns difference!

Here, you can see why using a high-precision timer is essential. While there is no escape from the measurement errors, a profilercan reduce their impact by increasing the timer accuracy.

3. **Frame<a name="_page7_x63.64_y552.81"></a> profiler**

Tracy aims to give you an understanding of the inner workings of a tight loop of a game (or any other kind of interactive application). That’s why it slices the execution time of a program using the *frame[  ](#_page7_x77.98_y711.39)*as a basic work-unit [. ](#_page7_x77.98_y730.94)The most interesting frames are the ones that took longer than the allocated time, producing

visible hitches in the on-screen animation. Tracy allows inspection of such misbehavior.![ref2]

<a name="_page7_x63.64_y637.78"></a> <a name="_page7_x77.98_y642.82"></a>In both 32 and 64 bit variants. On x86, Tracy requires a modern version of the rdtsc instruction (Sandy Bridge and later). Note that TimeStampCounterreadings’resolutionmaydependontheusedhardwareanditsdesigndecisionsrelatedtohowTSCsynchronization is handled between different CPU sockets, etc. On ARM-based systems Tracy will try to use the timer register (~40 ns resolution). If it fails<a name="_page7_x77.98_y682.24"></a> (due to kernel configuration), Tracy falls back to system provided timer, which can range in resolution from 250 ns to 1 s.

` `<a name="_page7_x77.98_y691.85"></a>Interestingly the std::chrono::high\_resolution\_clock is not really a high-resolution clock.

` `This is a real optimization case. The values are median function run times and do not reflectthe real execution time, which explains the discrepancy<a name="_page7_x77.98_y711.39"></a> in the total reported time.

` `A frame is used to describe a single image displayed on the screen by the game (or any other program), preferably 60 times per second<a name="_page7_x77.98_y730.94"></a> to achieve smooth animation. You can also think about physics update frames, audio processing frames, etc.

` `Frame usage is not required. See section 3.3[ for ](#_page24_x63.64_y581.52)more information.

4. **Sampling profiler**

Tracy can periodically sample what the profiledapplication is doing, which provides detailed performance information at the source line/assembly instruction level. This can give you a deep understanding of how the processor executes the program. Using this information, you can get a coarse view at the call stacks, fine-tuneyour algorithms, or even ’steal’ an optimization performed by one compiler and make it available for the others.

On some platforms, it is possible to sample the hardware performance counters, which will give you information not only *where*your program is running slowly, but also *why*.

5. **Remote<a name="_page8_x63.64_y198.08"></a> or embedded telemetry**

Tracy uses the client-server model to enable a wide range of use-cases (see figure2). For [exam](#_page8_x63.64_y288.99)ple, you may profile a game on a mobile phone over the wireless connection, with the profiler running on a desktop computer. Or you can run the client and server on the same machine, using a localhost connection. It is also possible to embed the visualization front-end in the profiledapplication, making the profilingself-contained .

<a name="_page8_x63.64_y288.99"></a>  Thread 1 ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.007.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.008.png)

Display  ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.009.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.010.png) Thread 2 Tracy client Network Tracy server![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.011.png)

`  `Storage   Thread 3

**Figure 2:** *Client-server model.*

In Tracy terminology, the profiledapplication is a *client*, and the profileritself is a *server*. It was named this way because the client is a thin layer that just collects events and sends them for processing and long-term storage on the server. The fact that the server needs to connect to the client to begin the profilingsession may be a bit confusing at first.

6. **Why<a name="_page8_x63.64_y488.48"></a> Tracy?**

You may wonder why you should use Tracy when so many other profilers are available. Here are some arguments:

- Tracy is free and open-source (BSD license), while RAD Telemetry costs about $8000 per year.
- Tracy provides out-of-the-box Lua bindings. It has been successfully integrated with other native and interpreted languages (Rust, Arma scripting language) using the C API (see chapter 3.13 for[ reference).](#_page42_x63.64_y636.27)
- Tracy has a wide variety of profilingoptions. For example, you can profileCPU, GPU, locks, memory allocations, context switches, and more.
- Tracy is feature-rich. For example, statistical information about zones, trace comparisons, or inclusion of inline function frames in call stacks (even in statistics of sampled stacks) are features unique to Tracy.
- Tracy focuses on performance. It uses many tricks to reduce memory requirements and network bandwidth. As a result, the impact on the client execution speed is minimal, while other profilers perform heavy data processing within the profiledapplication (and then claim to be lightweight).![ref3]

` `<a name="_page8_x77.98_y721.63"></a>See section [2.3.3 f](#_page20_x63.64_y650.76)or guidelines.

- Tracy uses low-level kernel APIs, or even raw assembly, where other profilers rely on layers of abstraction.
- Tracy is multi-platform right from the very beginning. Both on the client and server-side. Other profilers tend to have Windows-specific graphical interfaces.
- Tracy can handle millions of frames, zones, memory events, and so on, while other profilerstend to target very short captures.
- Tracy doesn’t require manual markup of interesting areas in your code to start profiling. Instead, you may rely on automated call stack sampling and add instrumentation later when you know where it’s needed.
- Tracy provides a mapping of source code to the assembly, with detailed information about the cost of executing each instruction on the CPU.
7. **Performance<a name="_page9_x63.64_y270.85"></a> impact**

Let’s profilean example application to check how much slowdown is introduced by using Tracy. For this purpose we have used etcpak  . [The](#_page9_x77.98_y725.13) input data was a 16384 × 16384 pixels test image, and the 4 × 4 pixel block compression function was selected to be instrumented. The image was compressed on 12 parallel threads, and the timing data represents a mean compression time of a single image.

The results are presented in table 1. [Dividing](#_page9_x63.64_y388.81) the average of run time differences (37.7 ms) by the count of captured zones per single image (16,777,216) shows us that the impact of profilingis only 2.25 ns per zone (this includes two events: start and end of a zone).

<a name="_page9_x63.64_y388.81"></a>**Mode**

|**Zones (total)**|**Zones (single image)**|**Clean run**|**Profilingrun**|
| - | - | - | - |
|201,326,592 201,326,592|16,777,216 16,777,216|110\.9 ms 212.4 ms|148\.2 ms 250.5 ms|

**Difference**

ETC1 ETC2

+37.3 ms +38.1 ms

**Table 1:** *Zone capture time cost.*

**1.7.1<a name="_page9_x63.64_y466.57"></a> Assembly analysis**

To see how Tracy achieves such small overhead (only 2.25 ns), let’s take a look at the assembly. The following x64 code is responsible for logging the start of a zone. Do note that it is generated by compiling fully portable C++.

10
Tracy Profiler The user manual![ref1]

mov byte ptr [rsp+0C0h],1

mov r15d,28h

mov rax,qword ptr gs:[58h]

mov r14, qword ptr [rax]

mov rdi,qword ptr [r15+r14]

mov rbp, qword ptr [rdi+28h] mov rbx,rbp

and ebx ,7Fh

jne function+54h -----------+ mov rdx,rbp | mov rcx,rdi | call enqueue\_begin\_alloc | shl rbx,5 <-----------------+

add rbx, qword ptr [rdi+48h] mov byte ptr [rbx],10h

rdtsc

shl rdx,20h![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.013.png)

`  `<https://github.com/wolfpld/etcpak>

- store zone activity information
- TLS
- queue address
- data address
- buffer counter
- 128 item buffer
- check if current buffer is usable
- reclaim/alloc next buffer
- buffer items are 32 bytes
- calculate queue item address
- queue item type
- retrieve time

11
Tracy Profiler The user manual![ref1]

or rax,rdx ; construct 64 bit timestamp mov qword ptr [rbx+1],rax ; write timestamp

lea rax,[\_\_tracy\_source\_location] ; static struct address

mov qword ptr [rbx+9],rax ; write source location data lea rax,[rbp+1] ; increment buffer counter mov qword ptr [rdi+28h],rax ; write buffer counter

The second code block, responsible for ending a zone, is similar but smaller, as it can reuse some variables <a name="_page10_x63.64_y185.62"></a>retrieved in the above code.

8. **Examples**

To see how to integrate Tracy into your application, you may look at example programs in the examples directory. Looking at the commit history might be the best way to do that.

9. **On<a name="_page10_x63.64_y248.34"></a> the web**

Tracy can be found at the following web addresses:

- Homepage – <https://github.com/wolfpld/tracy>
- Bug tracker – <https://github.com/wolfpld/tracy/issues>
- Discord chat – <https://discord.gg/pk78auc>
- Sponsoring development – <https://github.com/sponsors/wolfpld/>
- Interactive demo – <https://tracy.nereid.pl/>

**1.9.1<a name="_page10_x63.64_y409.34"></a> Binary distribution**

The version releases of the profiler are provided as precompiled Windows binaries for download at [https://github.com/wolfpld/tracy/releases, along with t](https://github.com/wolfpld/tracy/releases)he user manual. You will need to install the latest Visual C++ redistributable package to use them.

Development builds of Windows binaries, and the user manual are available as artifacts created by the automated Continuous Integration system on GitHub.

Note that these binary releases require AVX2 instruction set support on the processor. If you have an older CPU, you will need to set a proper instruction set architecture in the project properties and build the executables yourself.

<a name="_page10_x63.64_y533.87"></a>**2 First steps**

Tracy Profiler supports MSVC, GCC, and clang. You will need to use a reasonably recent version of the compiler due to the C++11 requirement. The following platforms are confirmed to be working (this is not a complete list):

- Windows (x86, x64)
- Linux (x86, x64, ARM, ARM64)
- Android (ARM, ARM64, x86)
- FreeBSD (x64)
- WSL (x64)
- OSX (x64)
- iOS (ARM, ARM64)

Moreover, the following platforms are not supported due to how secretive their owners are but were reported to be working after extending the system integration layer:

- PlayStation 4
- Xbox One
- Nintendo Switch
- Google Stadia

You may also try your luck with Mingw, but don’t get your hopes too high. This platform was usable some time ago, but nobody is actively working on resolving any issues you might encounter with it.

1. **Initial<a name="_page11_x63.64_y255.91"></a> client setup**

The recommended way to integrate Tracy into an application is to create a git submodule in the repository (assuming that you use git for version control). This way, it is straightforward to update Tracy to newly released versions. If that’s not an option, all the filesrequired to integrate your application with Tracy are contained in the public directory.

**What revision should I use?![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.014.png)**

You have two options when deciding on the Tracy Profiler version you want to use. Take into consideration the following pros and cons:

- Using the last-version-tagged revision will give you a stable platform to work with. You won’t experience any breakages, major UI overhauls, or network protocol changes. Unfortunately, you also won’t be getting any bug fixes.
- Working with the bleeding edge master development branch will give you access to all the new improvements and features added to the profiler. While it is generally expected that master should always be usable, **there are no guarantees that it will be so.**

Do note that all bug fixes and pull requests are made against the master branch.

With the source code included in your project, add the public/TracyClient.cpp source fileto the IDE project or makefile. You’re done. Tracy is now integrated into the application.

In the default configuration, Tracy is disabled. This way, you don’t have to worry that the production builds will collect profiling data. To enable profiling, you will probably want to create a separate build configuration, with the TRACY\_ENABLEdefine.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.015.png)**

- Double-check that the definename is entered correctly (as TRACY\_ENABLE), don’t make a mistake of adding an additional Dat the end. Make sure that this macro is definedfor all filesacross your project (e.g. it should be specifiedin the CFLAGSvariable, which is always passed to the compiler, or in an equivalent way), and *not* as a #define in just some of the source files.
- Tracy does not consider the value of the definition,only the fact if the macro is definedor not (unless specifiedotherwise). Be careful not to make the mistake of assigning numeric values to Tracy defines,which could lead you to be puzzled why constructs such as TRACY\_ENABLE=0don’t

work as you expect them to do.![ref4]

You should compile the application you want to profilewith all the usual optimization options enabled (i.e. make a release build). Profiling debugging builds makes little sense, as the unoptimized code and additional checks (asserts, etc.) completely change how the program behaves. In addition, you should enable usage of the native architecture of your CPU (e.g. -march=native) to leverage the expanded instruction sets, which may not be available in the default baseline target configuration.

Finally, on Unix, make sure that the application is linked with libraries libpthread and libdl. BSD systems will also need to be linked with libexecinfo.

**CMake integration![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.017.png)**

You can integrate Tracy with CMake by adding the git submodule folder as a subdirectory.

- set options before add\_subdirectory
- available options: TRACY\_ENABLE, TRACY\_ON\_DEMAND, TRACY\_NO\_BROADCAST, TRACY\_NO\_CODE\_TRANSFER, ...

option(TRACY\_ENABLE "" ON)

option(TRACY\_ON\_DEMAND "" ON)

add\_subdirectory(3rdparty/tracy) # target: TracyClient or alias Tracy::TracyClient

Link Tracy::TracyClient to any target where you use Tracy for profiling:

target\_link\_libraries(<TARGET> PUBLIC Tracy::TracyClient)

**CMake FetchContent![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.018.png)**

When using CMake 3.11 or newer, you can use Tracy via CMake FetchContent. In this case, you do not need to add a git submodule for Tracy manually. Add this to your CMakeLists.txt:

FetchContent\_Declare(

tracy

GIT\_REPOSITORY https://github.com/wolfpld/tracy.git GIT\_TAG master

GIT\_SHALLOW TRUE

GIT\_PROGRESS TRUE

) FetchContent\_MakeAvailable(tracy)

Then add this to any target where you use tracy for profiling:

target\_link\_libraries(<TARGET> PUBLIC TracyClient)

1. **Short-lived<a name="_page12_x63.64_y622.11"></a> applications**

In case you want to profilea short-lived program (for example, a compression utility that finishesits work in one second), set the TRACY\_NO\_EXITenvironment variable to 1. With this option enabled, Tracy will not exit until an incoming connection is made, even if the application has already finishedexecuting. If your platform

doesn’t support an easy setup of environment variables, you may also add the TRACY\_NO\_EXITdefineto your build configuration, which has the same effect.

2. **On-demand profiling**

By default, Tracy will begin profilingeven before the program enters the main function. However, suppose you don’t want to perform a full capture of the application lifetime. In that case, you may define the TRACY\_ON\_DEMANDmacro, which will enable profilingonly when there’s an established connection with the server.

You should note that if on-demand profilingis *disabled*(which is the default), then the recorded events will be stored in the system memory until a server connection is made and the data can be uploaded  . Depending on the amount of the things profiled,the requirements for event storage can quickly grow up to a couple of gigabytes. Furthermore, since this data is no longer available after the initial connection, you won’t be able to perform a second connection to a client unless the on-demand mode is used.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.019.png)**

The client with on-demand profilingenabled needs to perform additional bookkeeping to present a coherent application state to the profiler. This incurs additional time costs for each profilingevent.

3. **Client<a name="_page13_x63.64_y293.87"></a> discovery**

By default, the Tracy client will announce its presence to the local network  . If y[ou ](#_page13_x77.98_y711.39)want to disable this feature, definethe TRACY\_NO\_BROADCASTmacro.

The program name that is sent out in the broadcast messages can be customized by using the TracySetProgramName(name) macro.

4. **Client<a name="_page13_x63.64_y378.66"></a> network interface**

By default, the Tracy client will listen on all network interfaces. If you want to restrict it to only lis- tening on the localhost interface, define the TRACY\_ONLY\_LOCALHOSTmacro at compile-time, or set the TRACY\_ONLY\_LOCALHOSTenvironment variable to 1 at runtime.

By default, the Tracy client will listen on IPv6 interfaces, falling back to IPv4 only if IPv6 is unavailable. If you want to restrict it to only listening on IPv4 interfaces, definethe TRACY\_ONLY\_IPV4macro at compile-time, <a name="_page13_x63.64_y485.65"></a>or set the TRACY\_ONLY\_IPV4environment variable to 1 at runtime.

5. **Setup for multi-DLL projects**

ThingsareabitdifferentinprojectsthatconsistofmultipleDLLs/sharedobjects. Compiling TracyClient.cpp into every DLL is not an option because this would result in several instances of Tracy objects lying around in the process. We instead need to pass their instances to the different DLLs to be reused there.

For that, you need a *profilerDLL* to which your executable and the other DLLs link. If that doesn’t exist,

you have to createone explicitly for Tracy  . [This](#_page13_x77.98_y730.94) libraryshouldcontain the public/TracyClient.cpp source file. Link the executable and all DLLs you want to profileto this DLL.

If you are targeting Windows with Microsoft Visual Studio or MinGW, add the TRACY\_IMPORTSdefineto your application.

If you are experiencing crashes or freezes when manually loading/unloading a separate DLL with Tracy integration, you might want to try definingboth TRACY\_DELAYED\_INITand TRACY\_MANUAL\_LIFETIMEmacros.

TRACY\_DELAYED\_INITenables a path where profilerdata is gathered into one structure and initialized on the first request rather than statically at the DLL load at the expense of atomic load on each request to the profiler data. TRACY\_MANUAL\_LIFETIMEflag augments this behavior to provide manual StartupProfiler and ShutdownProfiler functions that allow you to create and destroy the profiler data manually. This![ref5]

`  `This<a name="_page13_x77.98_y711.39"></a><a name="_page13_x77.98_y701.78"></a> memory is never released, but the profilerreuses it for collection of other events.

`  `Additional configuration may be required to achieve full functionality, depending on your network layout. Read about UDP broadcas<a name="_page13_x77.98_y730.94"></a>ts for more information.

`  `You may also look at the library directory in the profilersource tree.

manual management removes the need to do an atomic load on each call and lets you definean appropriate place to free the resources.

**Keep everything consistent![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.021.png)**

When working with multiple libraries, it is easy to make a mistake and use different sets of feature macros between any two compilation jobs. If you do so, Tracy will not be able to work correctly, and there will be no error or warning messages about the problem. Henceforth, you must make sure each shared object you want to link with, or load uses the same set of macro definitions.

Please note that using a prebuilt shared Tracy library, as provided by some package manager or system distribution, also qualifiesas using multiple libraries.

6. **Problematic<a name="_page14_x63.64_y247.01"></a> platforms**

In the case of some programming environments, you may need to take extra steps to ensure Tracy can work correctly.

1. **Microsoft<a name="_page14_x63.64_y307.85"></a> Visual Studio**

If you are using MSVC, you will need to disable the *Edit And Continue* feature, as it makes the compiler non-conformant to some aspects of the C++ standard. In order to do so, open the project properties and ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.022.png)go to C/C++ General Debug Information Format and make sure *Program Database for Edit And Continue (/ZI)* is *not <a name="_page14_x63.64_y390.22"></a>*selected.

2. **Universal Windows Platform**

Due to a restricted access to Win32 APIs and other sandboxing issues (like network isolation), several limitations apply to using Tracy in a UWP application compared to Windows Desktop:

- Call stack sampling is not available.
- System profilingis not available.
- To be able to connect from another machine on the local network, the app needs the *privateNetwork- ClientServer* capability. To connect from localhost, an active inbound loopback exemption is also necessary [ .](#_page14_x77.98_y692.70)
3. **Apple<a name="_page14_x63.64_y551.29"></a> woes**

Because Apple *has*to be *think different*, there are some problems with using Tracy on OSX and iOS. First, the performance hit due to profilingis higher than on other platforms. Second, some critical features are missing and won’t be possible to achieve:

- There’s no support for the TRACY\_NO\_EXITmode.
- Profilingisinterruptedwhentheapplicationexits. Thiswillresultinmissingzones,memoryallocations, or even source location names.
- OpenGL can’t be profiled.![ref5]

<a name="_page14_x63.64_y699.81"></a>  <a name="_page14_x77.98_y692.70"></a><https://docs.microsoft.com/en-us/windows/uwp/communication/interprocess-communication#loopback>

4. **Android lunacy**

Starting with Android 8.0, you are no longer allowed to use the /proc filesystem. One of the consequences of this change is the inability to check system CPU usage.

This is apparently a security enhancement. Unfortunately, in its infinitewisdom, Google has decided not to give you an option to bypass this restriction.

To workaround this limitation, you will need to have a rooted device. Execute the following commands using root shell:

setenforce 0

mount -o remount,hidepid=0 /proc

echo -1 > /proc/sys/kernel/perf\_event\_paranoid echo 0 > /proc/sys/kernel/kptr\_restrict

The first command will allow access to system CPU statistics. The second one will enable inspection of foreign processes (required for context switch capture). The third one will lower restrictions on access to performance counters. The last one will allow retrieval of kernel symbol pointers. *Be sure that you are fully aware of the consequences of making these changes.*

5. **Virtual<a name="_page15_x63.64_y298.18"></a> machines**

The best way to run Tracy is on bare metal. Avoid profiling applications in virtualized environments, including services provided in the cloud. Virtualization interferes with the critical facilities needed for the profilerto work, influencingthe results you get. Possible problems may vary, depending on the configuration of the VM, and include:

- Reduced precision of time stamps.
- Inability to obtain precise timestamps, resulting in error messages such as *CPU doesn’t support RDTSC instruction*, or *CPU doesn’t support invariant TSC*. On Windows, you can work this around by rebuilding the profiledapplication with the TRACY\_TIMER\_QPCdefine,which severely lowers the resolution of time readings.
- Frequency of call stack sampling may be reduced.
- Call stack sampling might lack time stamps. While you can use such a reduced data set to perform statistical analysis, you won’t be able to limit the time range or see the sampling zones on the timeline.
7. **Changing<a name="_page15_x63.64_y527.48"></a> network port**

By default, the client and server communicate on the network using port 8086. The profilingsession utilizes the TCP protocol, and the client sends presence announcement broadcasts over UDP.

Suppose for some reason you want to use another port  . In [that](#_page15_x77.98_y721.00) case, you can change it using the TRACY\_DATA\_PORTmacro for the data connection and TRACY\_BROADCAST\_PORTmacro for client broadcasts. Alternatively, you may change both ports at the same time by declaring the TRACY\_PORTmacro (specific macroslistedbeforehavehigherpriority). Youmayalsochangethedataconnectionportwithoutrecompiling

the client application by setting the TRACY\_PORTenvironment variable.

If a custom port is not specified and the default listening port is already occupied, the profiler will automatically try to listen on a number of other ports.![ref6]

`  `<a name="_page15_x77.98_y721.00"></a>For example, other programs may already be using it, or you may have overzealous firewall rules, or you may want to run two clients on the same IP address.

**Important![ref7]**

To enable network communication, Tracy needs to open a listening port. Make sure it is not blocked by an overzealous firewall or anti-virus program.

8. **Limitations**

<a name="_page16_x63.64_y160.51"></a>When using Tracy Profiler, keep in mind the following requirements:

- The application may use each lock in no more than 64 unique threads.
- There can be no more than 65534 unique source locations  . [This](#_page16_x77.98_y721.00) number is further split in half between native code source locations and dynamic source locations (for example, when Lua instrumentation is used).
- If there are recursive zones at any point in a zone stack, each unique zone source location should not appear more than 255 times.
- Profilingsession cannot be longer than 1.6 days (247 ns). This also includes on-demand sessions.
- No more than 4 billion (232) memory free events may be recorded.
- No more than 16 million (224) unique call stacks can be captured.

The following conditions also need to apply but don’t trouble yourself with them too much. You would probably already know if you’d be breaking any.

- Only little-endian CPUs are supported.
- Virtual address space must be limited to 48 bits.
- Tracy server requires CPU which can handle misaligned memory accesses.
2. **Check<a name="_page16_x63.64_y480.19"></a> your environment**

It is not an easy task to reliably measure the performance of an application on modern machines. There are many factors affecting program execution characteristics, some of which you will be able to minimize and others you will have to live with. It is critically important that you understand how these variables impact profilingresults, as it is key to understanding the data you get.

1. **Operating<a name="_page16_x63.64_y555.45"></a> system**

In a multitasking operating system, applications compete for system resources with each other. This has a visible effect on the measurements performed by the profiler, which you may or may not accept.

To get the most accurate profilingresults, you should minimize interference caused by other programs running on the same machine. Before starting a profilesession, close all web browsers, music players, instant messengers, and all other non-essential applications like Steam, Uplay, etc. Make sure you don’t have the debugger hooked into the profiledprogram, as it also impacts the timing results.

Interference caused by other programs can be seen in the profilerif context switch capture (section 3.14.3) is enabled.![ref6]

`  `A<a name="_page16_x77.98_y721.00"></a> source location is a place in the code, which is identifiedby source filename and line number, for example, when you markup a

zone.

**Debugger in Visual Studio![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.025.png)**

In MSVC, you would typically run your program using the *Start Debugging* menu option, which is conveniently available as a F5 shortcut. You should instead use the *Start Without Debugging* option, available as Ctrl + F5 shortcut.

2. **CPU<a name="_page17_x63.64_y164.09"></a> design**

Where to even begin here? Modern processors are such complex beasts that it’s almost impossible to say anything about how they will behave surely. Cache configuration, prefetcher logic, memory timings, branch predictor, execution unit counts are all the drivers of instructions-per-cycle uplift nowadays after the megahertz race had hit the wall. Not only is it challenging to reason about, but you also need to take into account how the CPU topology affects things, which is described in more detail in section 3.14.4.

Nevertheless, let’s look at how we can try to stabilize the profilingdata.

1. **Superscalar<a name="_page17_x63.64_y274.94"></a> out-of-order speculative execution**

Also known as: the *spectre*thing we have to deal with now.

You must be aware that most processors available on the market [  ](#_page17_x77.98_y721.33)*do not* execute machine code linearly, as laid out in the source code. This can lead to counterintuitive timing results reported by Tracy. Trying to get more ’reliable’ readings   [would](#_page17_x77.98_y730.94) require a change in the behavior of the code, and this is not a thing a profilershould do. So instead, Tracy shows you what the hardware is *really*doing.

Thisisacomplexsubject,andthedetailsvaryfromoneCPUtoanother. Youcanreadabriefrundownofthe topic at the following address: [https://travisdowns.github.io/blog/2019/06/11/speed-limits.html.](https://travisdowns.github.io/blog/2019/06/11/speed-limits.html)

2. **Simultaneous<a name="_page17_x63.64_y397.34"></a> multithreading**

Also known as: Hyper-threading. Typically present on Intel and AMD processors.

To get the most reliable results, you should have all the CPU core resources dedicated to a single thread of your program. Otherwise, you’re no longer measuring the behavior of your code but rather how it keeps up when its computing resources are randomly taken away by some other thing running on another pipeline within the same physical core.

Note that you might *want* to observe this behavior if you plan to deploy your application on a machine with simultaneous multithreading enabled. This would require careful examination of what else is running on the machine, or even how the operating system schedules the threads of your own program, as various combinations of competing workloads (e.g., integer/floating-pointoperations) will be impacted differently.

3. **Turbo<a name="_page17_x63.64_y544.85"></a> mode frequency scaling**

Also known as: Turbo Boost (Intel), Precision Boost (AMD).

While the CPU is more-or-less designed always to be able to work at the advertised *base*frequency, there is usually some headroom left, which allows usage of the built-in automatic overclocking. There are no guarantees that the CPU can attain the turbo frequencies or how long it will uphold them, as there are many things to take into consideration:

- How many cores are in use? Just one, or all 8? All 16?
- What type of work is being performed? Integer? Floating-point? 128-wide SIMD? 256-wide SIMD? 512-wide SIMD?
- Were you lucky in the silicon lottery? Some dies are just better made and can achieve higher frequencies.![ref8]

`  `<a name="_page17_x77.98_y730.94"></a><a name="_page17_x77.98_y721.33"></a>Except low-cost ARM CPUs.

`  `And by saying ’reliable,’ you do in reality mean: behaving in a way you expect it.

- Are you running on the best-rated core or at the worst-rated core? Some cores may be unable to match the performance of other cores in the same processor.
- What kind of cooling solution are you using? The cheap one bundled with the CPU or a hefty chunk of metal that has no problem with heat dissipation?
- Do you have complete control over the power profile? Spoiler alert: no. The operating system may run anything at any time on any of the other cores, which will impact the turbo frequency you’re able to achieve.

As you can see, this feature basically screams ’unreliable results!’ Best keep it disabled and run at the base frequency. Otherwise, your timings won’t make much sense. A true example: branchless compression function executing multiple times with the same input data was measured executing at *four* different speeds.

Keep in mind that even at the base frequency, you may hit the thermal limits of the silicon and be down <a name="_page18_x63.64_y264.87"></a>throttled.

4. **Power saving**

This is, in essence, the same as turbo mode, but in reverse. While unused, processor cores are kept at lower frequencies (or even wholly disabled) to reduce power usage. When your code starts running  , the core frequency needs to ramp up, which may be visible in the measurements.

Even worse, if your code doesn’t do a lot of work (for example, because it is waiting for the GPU to finish rendering the frame), the CPU might not ramp up the core frequency to 100%, which will skew the results.

Again, to get the best results, keep this feature disabled.

5. **AVX<a name="_page18_x63.64_y377.53"></a> offsetand power licenses**

Intel CPUs are unable to run at their advertised frequencies when they perform wide SIMD operations due to increased power requirements [ .](#_page18_x77.98_y698.18) Therefore, depending on the width *and* type of operations executed, the core operating frequency will be reduced, in some cases quite drastically [ .](#_page18_x77.98_y707.78) To make things even better, *some* parts of the workload will execute within the available power license, at a twice reduced processing rate.

After that, the CPU may be stopped for some time so that the wide parts of executions units can be powered up. Then the work will continue at full processing rate but at a reduced frequency.

Be very careful when using AVX2 or AVX512.

Moreinformationcanbefoundat [https://travisdowns.github.io/blog/2020/01/17/avxfreq1.html, ](https://travisdowns.github.io/blog/2020/01/17/avxfreq1.html)[https://en.wikichip.org/wiki/intel/frequency_behavior.](https://en.wikichip.org/wiki/intel/frequency_behavior)

6. **Summing<a name="_page18_x63.64_y524.21"></a> it up**

Power management schemes employed in various CPUs make it hard to reason about the true performance of the code. For example, figure3 [contains](#_page19_x63.64_y84.43) a histogram of function execution times (as described in chapter 5.7), as measured on an AMD Ryzen CPU. The results ranged from 13.05 s to 61.25 s (extreme outliers were not included on the graph, limiting the longest displayed time to 36.04 s).

We can immediately see that there are two distinct peaks, at 13.4 s and 15.3 s. A reasonable assumption would be that there are two paths in the code, one that can omit some work, and the second one which must do some additional job. But here’s a catch – the measured code is actually branchless and always executes the same way. The two peaks represent two turbo frequencies between which the CPU was aggressively switching.![ref3]

`  `<a name="_page18_x77.98_y678.63"></a>Not necessarily when the application is started, but also when, for example, a blocking mutex becomes released by other thread and is acquired.

<a name="_page18_x77.98_y698.18"></a>  AMD<a name="_page18_x77.98_y707.78"></a> processors are not affected by this issue.

`  `<https://en.wikichip.org/wiki/intel/xeon_gold/5120#Frequencies>

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.027.png)

<a name="_page19_x63.64_y84.43"></a>**Figure 3:** *Example function execution times on a Ryzen CPU*

We can also see that the graph gradually falls offto the right (representing longer times), with a slight bump near the end. Again, this can be attributed to running in power-saving mode, with different reaction times to the required operating frequency boost to full power.

3. **Building<a name="_page19_x63.64_y255.32"></a> the server**

The easiest way to get going is to build the data analyzer, available in the profiler directory. Then, you can connect to localhost or remote clients and view the collected data right away with it.

If you prefer to inspect the data only after a trace has been performed, you may use the command-line utility in the capture directory. It will save a data dump that you may later open in the graphical viewer application.

Ideally, it would be best to use the same version of the Tracy profiler on both client and server. The network protocol may change in-between releases, in which case you won’t be able to make a connection.

See section [4 f](#_page52_x63.64_y589.65)or more information about performing captures.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.028.png)**

Due to the memory requirements for data storage, the Tracy server is only supposed to run on 64-bit platforms. While nothing prevents the program from building and executing in a 32-bit environment, doing so is not supported.

1. **Required<a name="_page19_x63.64_y484.07"></a> libraries**

To build the application contained in the profiler directory, you will need to install external libraries, which

are not bundled with Tracy.

**Capstone library** At the time of writing, the capstone library is in a bit of disarray. The officially released version 4.0.2 can’t disassemble some AVX instructions, which are successfully parsed by the next branch. However, the next branch somehow lost information about input/output registers for some functions. You

may want to explore the various available versions to findone that suits your needs the best. Note that only the next branch is actively maintained. Be aware that your package manager might distribute the deprecated <a name="_page19_x63.64_y631.58"></a>master branch.

1. **Windows**

On Windows, you will need to use the vcpkg utility. If you are not familiar with this tool, please read the description at the following address: [https://docs.microsoft.com/en-us/cpp/build/vcpkg.](https://docs.microsoft.com/en-us/cpp/build/vcpkg)

There are two ways you can run vcpkg to install the dependencies for Tracy:

- Local installation within the project directory – run this script to download and build both vcpkg and the required dependencies:

vcpkg\install\_vcpkg\_dependencies.bat

This writes filesonly to the vcpkg\vcpkg directory and makes no other changes on your machine.

- System-wideinstallationwithManifestmode–install vcpkg byfollowingtheinstructionsonitswebsite, make sure that the environment variable VCPKG\_ROOTis set to the path where you have clone the repository, and then execute the following command:

vcpkg integrate install

After this step, you can use any Visual Studio project files to build as usual. Dependencies will be installed automatically based on vcpkg manifest listing (the vcpkg.json fileat repository root). For more information about vcpkg manifest mode in Visual Studio, you can read more details at the following address: [https://vcpkg.io/en/docs/users/manifests.html#msbuild-integration.](https://vcpkg.io/en/docs/users/manifests.html#msbuild-integration)

2. **Unix**

<a name="_page20_x63.64_y272.17"></a>On Unix systems you will need to install the pkg-config utility and the following libraries: glfw, freetype, capstone, dbus. Some Linux distributions will require you to add a lib prefix and a -dev, or -devel postfixto library names. You may also need to add a seemingly random number to the library name (for example: freetype2, or freetype6). Be aware that your package manager might distribute the deprecated master-branch version of capstone, and a build from source from the next-branch might be necessary for you. Have fun!

In addition to the beforementioned libraries, you might also have to install the tbb library [ . ](#_page20_x77.98_y714.44)Installation of the libraries on OSX can be facilitated using the brew package manager.

**Wayland** Linux builds of Tracy use the Wayland protocol by default, which allows proper support for            Hi-DPI scaling and high-precision input devices such as touchpads. As such, the glfw library is no longer needed, but you will have to install libxkbcommon, wayland, libglvnd (or libegl on some distributions).

You can build the profilerthe old way on Linux by enabling the LEGACYflag,e.g. by issuing the following build command make LEGACY=1.

**Window decorations![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.029.png)**

Please don’t ask about window decorations in Gnome. The current behavior is the intended behavior. Gnome does not want windows to have decorations, and Tracy respects that choice. If you findthis problematic, use a desktop environment that actually listens to its users.

2. **Build<a name="_page20_x63.64_y564.81"></a> process**

As mentioned earlier, each utility is contained in its own directory, for example profiler or capture  [. ](#_page20_x77.98_y724.05)Where do you go within these directories depends on the operating system you are using.

On Windows navigate to the build/win32 directory and open the solution filein Visual Studio. On Unix

go to the build/unix directory and build the release target using GNU make.

3. **Embedding<a name="_page20_x63.64_y650.76"></a> the server in profiledapplication**

While not officially supported, it is possible to embed the server in your application, the same one running the client part of Tracy. How to make this work is left up for you to figureout.![ref9]

`  `T<a name="_page20_x77.98_y724.05"></a><a name="_page20_x77.98_y714.44"></a>echnically this is not a dependency of Tracy but rather of libstdc++ but it may still not be installed by default.   Other utilities are contained in the csvexport, import-chrome and update directories.

Note that most libraries bundled with Tracy are modified in some way and contained in the tracy namespace. The one exception is Dear ImGui, which can be freely replaced.

Be aware that while the Tracy client uses its own separate memory allocator, the server part of Tracy will use global memory allocation facilities shared with the rest of your application. This will affect both the memory usage statistics and Tracy memory profiling.

The following definesmay be of interest:

- TRACY\_NO\_FILESELECTOR– controls whether a system load/save dialog is compiled in. If it’s enabled, the saved traces will be named trace.tracy.
- TRACY\_NO\_STATISTICS– Tracy will perform statistical data collection on the fly, if this macro is *not* defined. This allows extended trace analysis (for example, you can perform a live search for matching zones) at a small CPU processing cost and a considerable memory usage increase (at least 8 bytes per zone).
- TRACY\_NO\_ROOT\_WINDOW– the main profiler view won’t occupy the whole window if this macro is defined. Additional setup is required for this to work. If you want to embed the server into your application, you probably should enable this option.
4. **DPI<a name="_page21_x63.64_y315.09"></a> scaling**

The graphic server application will adapt to the system DPI scaling. If for some reason, this doesn’t work in your case, you may try setting the TRACY\_DPI\_SCALEenvironment variable to a scale fraction, where a value of 1 indicates no scaling.

4. **Naming<a name="_page21_x63.64_y375.71"></a> threads**

Remember to set thread names for proper identificationof threads. You should do so by using the function tracy::SetThreadName(name) exposed in the public/common/TracySystem.hpp header, as the system facilities typically have limited functionality.

Tracy will try to capture thread names through operating system data if context switch capture is active. However, this is only a fallback mechanism, and it shouldn’t be relied upon.

<a name="_page21_x63.64_y473.50"></a>**2.4.1 Source location data customization**

Some source location data such as function name, filepath or line number can be overriden with defines TracyFunction, TracyFile, TracyLine   [made](#_page21_x77.98_y708.91) before including public/tracy/Tracy.hpp header file  .

#if defined(\_\_clang\_\_) || defined(\_\_GNUC\_\_)

- define TracyFunction \_\_PRETTY\_FUNCTION\_\_ #elif defined(\_MSC\_VER)
- define TracyFunction \_\_FUNCSIG\_\_

  #endif

#include <tracy/Tracy.hpp> ...

void Graphics::Render()

{

ZoneScoped; ...

}![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.031.png)

<a name="_page21_x63.64_y703.26"></a>  <a name="_page21_x77.98_y708.91"></a><a name="_page21_x77.98_y718.52"></a>By default the macros unwrap to \_\_FUNCTION\_\_, \_\_FILE\_\_ and \_\_LINE\_\_respectively.

`  `You should add either public or public/tracy directory from the Tracy root to the include directories list in your project. Then you will be able to #include "tracy/Tracy.hpp" or #include "Tracy.hpp", respectively.

5. **Crash handling**

On selected platforms (see section [2.6) Tr](#_page22_x63.64_y357.24)acy will intercept application crashes  . This[ ser](#_page22_x77.98_y730.94)ves two purposes. First, the client application will be able to send the remaining profilingdata to the server. Second, the server will receive a crash report with the crash reason, call stack at the time of the crash, etc.

This is an automatic process, and it doesn’t require user interaction. If you are experiencing issues with crash handling you may want to try defining the TRACY\_NO\_CRASH\_HANDLERmacro to disable the built in crash handling.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.032.png)**

- On MSVC the debugger has priority over the application in handling exceptions. If you want to finishthe profilerdata collection with the debugger hooked-up, select the *continue* option in the debugger pop-up dialog.
- On Linux, crashes are handled with signals. Tracy needs to have SIGPWRavailable, which is rather rarely used. Still, the program you are profilingmay expect to employ it for its purposes, which would cause a conflict *[a*.](#_page22_x98.91_y330.60)* To workaround such cases, you may set the TRACY\_CRASH\_SIGNALmacro value to some other signal (see man 7 signal for a list of signals). Ensure that you avoid conflicts

  by selecting a signal that the application wouldn’t usually receive or emit.

*a<a name="_page22_x98.91_y330.60"></a>*For example, Mono may use it to trigger garbage collection.

6. **Feature<a name="_page22_x63.64_y357.24"></a> support matrix**

Some features of the profilerare only available on selected platforms. Please refer to table 2 for [details. ](#_page22_x63.64_y412.61)<a name="_page22_x63.64_y412.61"></a>**Feature Windows Linux Android OSX iOS BSD![ref10]![ref10]![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.034.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.035.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.036.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.037.png)**

Profilingprogram init

CPU zones

Locks

Plots

Messages

Memory

GPU zones (OpenGL)

GPU zones (Vulkan)

Call stacks

Symbol resolution

Crash handling

CPU usage probing

Context switches

Wait stacks

CPU topology information

Call stack sampling

Hardware sampling *a*

VSync capture

- Not possible to support due to platform limitations. *a*Possible through WSL2.

**Table 2:** *Feature support matrix![ref11]*

<a name="_page22_x63.64_y725.77"></a>  <a name="_page22_x77.98_y730.94"></a>For example, invalid memory accesses (’segmentation faults’, ’null pointer exceptions’), divisions by zero, etc.

**3 Client markup**

With the steps mentioned above, you will be able to connect to the profiled program, but there probably won’t be any data collection performed  . [Unless](#_page23_x77.98_y671.49) you’re able to perform automatic call stack sampling (see chapter [3.14.5), ](#_page49_x63.64_y158.34)you will have to instrument the application manually. All the user-facing interface is contained in the public/tracy/Tracy.hpp header file [ .](#_page23_x77.98_y681.10)

Manual instrumentation is best started with adding markup to the application’s main loop, along with a few functions that the loop calls. Such an approach will give you a rough outline of the function’s time cost, which you may then further refineby instrumenting functions deeper in the call stack. Alternatively, automated sampling might guide you more quickly to places of interest.

1. **Handling<a name="_page23_x63.64_y218.36"></a> text strings**

When dealing with Tracy macros, you will encounter two ways of providing string data to the profiler. In both cases, you should pass const char\* pointers, but there are differences in the expected lifetime of the pointed data.

1. When a macro only accepts a pointer (for example: TracyMessageL(text)), the provided string data

must be accessible at any time in program execution ( *this also includes the time after exiting the* main *function*). The string also cannot be changed. This basically means that the only option is to use a string literal (e.g.: TracyMessageL("Hello")).

2. If there’s a string pointer with a size parameter (for example TracyMessage(text, size)), the profiler will allocate a temporary internal buffer to store the data. The size count should not include the terminating null character, using strlen(text) is fine. The pointed-to data is not used afterward. Remember that allocating and copying memory involved in this operation has a small time cost.

Be aware that every single instance of text string data passed to the profilercan’t be larger than 64 KB.

1. **Program<a name="_page23_x63.64_y431.91"></a> data lifetime**

Take extra care to consider the lifetime of program code (which includes string literals) in your application. For example, if you dynamically add and remove modules (i.e., DLLs, shared objects) during the runtime, text data will only be present when the module is loaded. Additionally, when a module is unloaded, the operating system can place another one in its space in the process memory map, resulting in the aliasing of text strings. This leads to all sorts of confusion and potential crashes.

Note that string literals are the only option in many parts of the Tracy API. For example, look at how frame or plot names are specified. You cannot unload modules that contain string literals that you passed to the profiler [ .](#_page23_x77.98_y700.64)

2. **Unique<a name="_page23_x63.64_y565.27"></a> pointers**

In some cases marked in the manual, Tracy expects you to provide a unique pointer in each occurrence the same string literal is used. This can be exemplifiedin the following listing:

FrameMarkStart("Audio processing"); ...

FrameMarkEnd("Audio processing");![ref9]

`  `W<a name="_page23_x77.98_y681.10"></a><a name="_page23_x77.98_y671.49"></a>ith some small exceptions, see section [3.14.](#_page47_x63.64_y486.91)

`  `You should add either public or public/tracy directory from the Tracy root to the include directories list in your project. Then you<a name="_page23_x77.98_y700.64"></a> will be able to #include "tracy/Tracy.hpp" or #include "Tracy.hpp", respectively.

`  `If you really do must unload a module, manually allocating a char buffer, as described in section [3.1.2, will](#_page23_x63.64_y565.27) give you a persistent string in memory.

Here, we pass two string literals with identical contents to two different macros. It is entirely up to the compiler to decide if it will pool these two strings into one pointer or if there will be two instances

present in the executable image  . [For](#_page24_x77.98_y707.98) example, on MSVC, this is controlled by Configuration Properties C/C++ Code![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.039.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.040.png) Generation Enable String Pooling option in the project properties (optimized builds enable it automatically).

Note that even if string pooling is used on the compilation unit level, it is still up to the linker to implement pooling across object files.

As you can see, making sure that string literals are properly pooled can be surprisingly tricky. To work around this problem, you may employ the following technique. In *one*source filecreate the unique pointer for a string literal, for example:

const char\* const sl\_AudioProcessing = "Audio processing";

Then in each filewhere you want to use the literal, use the variable name instead. Notice that if you’d like to change a name passed to Tracy, you’d need to do it only in one place with such an approach.

extern const char\* const sl\_AudioProcessing;

FrameMarkStart(sl\_AudioProcessing); ... FrameMarkEnd(sl\_AudioProcessing);

In some cases, you may want to have semi-dynamic strings. For example, you may want to enumerate workers but don’t know how many will be used. You can handle this by allocating a never-freed char buffer, which you can then propagate where it’s needed. For example:

char \* workerId = new char [16]; snprintf(workerId, 16, "Worker %i", id); ...

FrameMarkStart(workerId);

Youhavetomakesureit’sinitializedonlyonce, beforepassingittoanyTracyAPI,thatitisnotoverwritten by new data, etc. In the end, this is just a pointer to character-string data. It doesn’t matter if the memory was loaded from the program image or allocated on the heap.

2. **Specifying<a name="_page24_x63.64_y471.18"></a> colors**

In some cases, you will want to provide your own colors to be displayed by the profiler. You should use a hexadecimal 0xRRGGBBnotation in all such places.

Alternativelyyoumayusenamedcolorspredefinedin common/TracyColor.hpp (includedby Tracy.hpp). Visual reference: [https://en.wikipedia.org/wiki/X11_color_names.](https://en.wikipedia.org/wiki/X11_color_names)

Do not use 0x000000 if you want to specify black color, as zero is a special value indicating that no color was set. Instead, use a value close to zero, e.g. 0x000001.

3. **Marking<a name="_page24_x63.64_y581.52"></a> frames**

To slice the program’s execution recording into frame-sized chunks  , put t[he](#_page24_x77.98_y717.58) FrameMark macro after you have completed rendering the frame. Ideally, that would be right after the swap buffers command.

**Do I need this?![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.041.png)**

This step is optional, as some applications do not use the concept of a frame.![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.042.png)

`  `[<a name="_page24_x77.98_y717.58"></a><a name="_page24_x77.98_y707.98"></a>[ISO12\]](#_page92_x63.64_y160.76) §2.14.5.12: "Whether all string literals are distinct (that is, are stored in nonoverlapping objects) is implementation-defined."   Each frame starts immediately after previous has ended.

1. **Secondary<a name="_page25_x63.64_y90.71"></a> frame sets**

In some cases, you may want to track more than one set of frames in your program. To do so, you may use the FrameMarkNamed(name) macro, which will create a new set of frames for each unique name you provide. But, first, make sure you are correctly pooling the passed string literal, as described in section 3.1.2.

2. **Discontinuous<a name="_page25_x63.64_y147.57"></a> frames**

Some types of frames are discontinuous by their nature – they are executed periodically, with a pause between each run. Examples of such frames are a physics processing step in a game loop or an audio callback running on a separate thread. Tracy can also track this kind of frames.

To mark the beginning of a discontinuous frame use the FrameMarkStart(name) macro. After the work is finished,use the FrameMarkEnd(name) macro.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.043.png)**

- Frame types *must not* be mixed. For each frame set, identified by an unique name, use either continuous or discontinuous frames only!
- You *must* issue the FrameMarkStart and FrameMarkEnd macros in proper order. Be extra careful, especially if multi-threading is involved.
- String literals passed as frame names must be properly pooled, as described in section 3.1.2.
3. **Frame<a name="_page25_x63.64_y375.56"></a> images**

It is possible to attach a screen capture of your application to any frame in the main frame set. This can help you see the context of what’s happening in various places in the trace. You need to implement retrieval of the image data from GPU by yourself.

Images are sent using the FrameImage(image, width, height, offset, flip) macro, where image is a pointer to RGBA[   ](#_page25_x77.98_y692.51)pixel data, width and height are the image dimensions, which *must be divisible by 4*, offset specifieshow much frame lag was there for the current image (see chapter 3.3.3.1),[ and ](#_page26_x63.64_y312.42)flip should be set, if the graphics API stores images upside-down  . [The ](#_page25_x77.98_y702.12)profilercopies the image data, so you don’t

need to retain it.

Handling image data requires a lot of memory and bandwidth  . To [achie](#_page25_x77.98_y711.72)ve sane memory usage, you should scale down taken screenshots to a suitable size, e.g., 320 × 180.

To further reduce image data size, frame images are internally compressed using the DXT1 Texture Compressiontechnique  ,[which](#_page25_x77.98_y721.33)significantlyreducesdatasize  ,ata[slight](#_page25_x77.98_y730.94)qualitydecrease. Thecompression algorithm is high-speed and can be made even faster by enabling SIMD processing, as indicated in table 3.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.044.png)**

- Frame images are compressed on a second client profilerthread *[a*,](#_page26_x98.91_y274.20)* to reduce memory usage of queued images. This might have an impact on the performance of the profiledapplication.
- This second thread will be periodically woken up, even if there are no frame images to compress *[b*. ](#_page26_x98.91_y284.56)*If you are not using the frame image capture functionality and you don’t wish this thread to be running, you can definethe TRACY\_NO\_FRAME\_IMAGEmacro.![ref8]

`  `Alpha<a name="_page25_x77.98_y702.12"></a><a name="_page25_x77.98_y692.51"></a> value is ignored, but leaving it out wouldn’t map well to the way graphics hardware works.   <a name="_page25_x77.98_y711.72"></a>For example, OpenGL flipsimages, but Vulkan does not.

`  `<a name="_page25_x77.98_y721.33"></a>One uncompressed 1080p image takes 8 MB.

`  `<https://en.wikipedia.org/wiki/S3_Texture_Compression>

`  `<a name="_page25_x77.98_y730.94"></a>One pixel is stored in a nibble (4 bits) instead of 32 bits.

28
Tracy Profiler The user manual![ref1]

<a name="_page26_x63.64_y84.43"></a>**Implementation Required define Time ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.045.png)**x86 Reference — 198.2 s

x86 SSE4.1a \_\_SSE4\_1\_\_ 25.4 s x86 AVX2 \_\_AVX2\_\_ 17.4  s ARM Reference — 1.04 ms

ARM32 NEON b \_\_ARM\_NEON 529  s ARM64 NEON \_\_ARM\_NEON 438  s

a) VEX encoding; b) ARM32 NEON code compiled for ARM64

**Table 3:** *Client compression time of* 320 × 180 *image. x86: Ryzen 9 3900X (MSVC); ARM: ODROID-C2 (gcc).*

- Due to implementation details of the network buffer, a single frame image cannot be greater than![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.046.png)

  256 KB after compression. Note that a 960 × 540 image fitsin this limit.

*a<a name="_page26_x98.91_y284.56"></a><a name="_page26_x98.91_y274.20"></a>*Small part of compression task is offloadedto the server.

*b*This way of doing things is required to prevent a deadlock in specificcircumstances.

<a name="_page26_x63.64_y312.42"></a>**3.3.3.1 OpenGL screen capture code example**

Therearemanypitfallsassociatedwithefficientlyretrievingscreencontent. Forexample,using glReadPixels and then resizing the image using some library is terrible for performance, as it forces synchronization of the GPU to CPU and performs the downscaling in software. To do things properly, we need to scale the image using the graphics hardware and transfer data asynchronously, which allows the GPU to run independently of the CPU.

The following example shows how this can be achieved using OpenGL 3.2. Of course, more recent OpenGL versions allow doing things even better (for example, using persistent buffer mapping), but this manual won’t cover it here.

Let’s begin by definingthe required objects. First, we need a *texture* to store the resized image, a *framebuffer object*to be able to write to the texture, a *pixel buffer object*to store the image data for access by the CPU, and a *fence*to know when the data is ready for retrieval. We need everything in *at least*three copies (we’ll use four) because the rendering, as seen in the program, can run ahead of the GPU by a couple of frames. Next, we

need an index to access the appropriate data set in a ring-buffer manner. And finally, we need a queue to store indices to data sets that we are still waiting for.

GLuint m\_fiTexture[4]; GLuint m\_fiFramebuffer[4]; GLuint m\_fiPbo[4];

GLsync m\_fiFence[4];

int m\_fiIdx = 0; std::vector<int > m\_fiQueue;

Everything needs to be correctly initialized (the cleanup is left for the reader to figureout).

glGenTextures(4, m\_fiTexture);

glGenFramebuffers(4, m\_fiFramebuffer);

glGenBuffers(4, m\_fiPbo);

for ( int i=0; i<4; i++)

{

glBindTexture(GL\_TEXTURE\_2D, m\_fiTexture[i]);

glTexParameteri(GL\_TEXTURE\_2D, GL\_TEXTURE\_MIN\_FILTER, GL\_NEAREST); glTexParameteri(GL\_TEXTURE\_2D, GL\_TEXTURE\_MAG\_FILTER, GL\_NEAREST); glTexImage2D(GL\_TEXTURE\_2D, 0, GL\_RGBA, 320, 180, 0, GL\_RGBA, GL\_UNSIGNED\_BYTE, nullptr);

glBindFramebuffer(GL\_FRAMEBUFFER, m\_fiFramebuffer[i]);

glFramebufferTexture2D(GL\_FRAMEBUFFER, GL\_COLOR\_ATTACHMENT0, GL\_TEXTURE\_2D,

m\_fiTexture[i], 0);

glBindBuffer(GL\_PIXEL\_PACK\_BUFFER, m\_fiPbo[i]); glBufferData(GL\_PIXEL\_PACK\_BUFFER, 320\*180\*4, nullptr, GL\_STREAM\_READ);

}

We will now set up a screen capture, which will downscale the screen contents to 320 × 180 pixels and copy the resulting image to a buffer accessible by the CPU when the operation is done. This should be placed right before *swap buffers*or *present* call.

assert(m\_fiQueue.empty() || m\_fiQueue.front() != m\_fiIdx); // check for buffer overrun glBindFramebuffer(GL\_DRAW\_FRAMEBUFFER, m\_fiFramebuffer[m\_fiIdx]);

glBlitFramebuffer(0, 0, res.x, res.y, 0, 0, 320, 180, GL\_COLOR\_BUFFER\_BIT, GL\_LINEAR); glBindFramebuffer(GL\_DRAW\_FRAMEBUFFER, 0);

glBindFramebuffer(GL\_READ\_FRAMEBUFFER, m\_fiFramebuffer[m\_fiIdx]); glBindBuffer(GL\_PIXEL\_PACK\_BUFFER, m\_fiPbo[m\_fiIdx]);

glReadPixels(0, 0, 320, 180, GL\_RGBA, GL\_UNSIGNED\_BYTE, nullptr); glBindFramebuffer(GL\_READ\_FRAMEBUFFER, 0);

m\_fiFence[m\_fiIdx] = glFenceSync(GL\_SYNC\_GPU\_COMMANDS\_COMPLETE, 0); m\_fiQueue.emplace\_back(m\_fiIdx);

m\_fiIdx = (m\_fiIdx + 1) % 4;

And lastly, just before the capture setup code that was just added   we [need](#_page27_x77.98_y722.48) to have the image retrieval code. We are checking if the capture operation has finished. If it has, we map the *pixel buffer object*to memory, inform the profilerthat there are image data to be handled, unmap the buffer and go to check the next queue

item. If capture is still pending, we break out of the loop. We will have to wait until the next frame to check if the GPU has finishedperforming the capture.

while (!m\_fiQueue.empty())

{

const auto fiIdx = m\_fiQueue.front();

if (glClientWaitSync(m\_fiFence[fiIdx], 0, 0) == GL\_TIMEOUT\_EXPIRED) break ; glDeleteSync(m\_fiFence[fiIdx]);

glBindBuffer(GL\_PIXEL\_PACK\_BUFFER, m\_fiPbo[fiIdx]);

auto ptr = glMapBufferRange(GL\_PIXEL\_PACK\_BUFFER, 0, 320\*180\*4, GL\_MAP\_READ\_BIT); FrameImage(ptr, 320, 180, m\_fiQueue.size(), true); glUnmapBuffer(GL\_PIXEL\_PACK\_BUFFER);

m\_fiQueue.erase(m\_fiQueue.begin());

}

Notice that in the call to FrameImage we are passing the remaining queue size as the offset parameter. Queue size represents how many frames ahead our program is relative to the GPU. Since we are sending past frame images, we need to specify how many frames behind the images are. Of course, if this would be synchronous capture (without the use of fences and with retrieval code after the capture setup), we would set offset to zero, as there would be no frame lag.

**High quality capture** The code above uses glBlitFramebuffer function, which can only use nearest neighbor filtering. The use of such filtering can result in low-quality screenshots, as shown in figure 4. However, with a bit more work, it is possible to obtain nicer-looking screenshots, as presented in figure5. Unfortunately, you will need to set up a complete rendering pipeline for this to work.

First, you need to allocate an additional set of intermediate frame buffers and textures, sized the same as the screen. These new textures should have a minificationfilterset to GL\_LINEAR\_MIPMAP\_LINEAR. You will also need to set up everything needed to render a full-screen quad: a simple texturing shader and vertex

buffer with appropriate data. Since you will use this vertex buffer to render to the scaled-down frame buffer, you may prepare its contents beforehand and update it only when the aspect ratio changes.![ref8]

`  `Y<a name="_page27_x77.98_y722.48"></a>es, before. We are handling past screen captures here.

With all this done, you can perform the screen capture as follows:

- Setup vertex buffer configuration for the full-screen quad buffer (you only need position and uv coordi- nates).
- Blit the screen contents to the full-sized frame buffer.
- Bind the texture backing the full-sized frame buffer.
- Generate mipmaps using glGenerateMipmap.
- Set viewport to represent the scaled-down image size.
- Bind vertex buffer data, shader, setup the required uniforms.
- Draw full-screen quad to the scaled-down frame buffer.
- Retrieve frame buffer contents, as in the code above.
- Restore viewport, vertex buffer configuration, bound textures, etc.

While this approach is much more complex than the previously discussed one, the resulting image quality increase makes it worthwhile.

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.047.png) ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.048.png)

<a name="_page28_x63.64_y338.38"></a>**Figure 4:** *Low-quality screen shot* **Figure 5:** *High-quality screen shot* You can see the performance results you may expect in a simple application in table 4. The [naïv](#_page28_x63.64_y530.28)e capture

performs synchronous retrieval of full-screen image and resizes it using *stb\_image\_resize*. The proper and high-quality captures do things as described in this chapter.

<a name="_page28_x63.64_y530.28"></a>**Resolution Naïve capture Proper capture High quality ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.049.png)**1280 × 720 80 FPS 4200 FPS 2800 FPS

2560 × 1440 23 FPS 3300 FPS 1600 FPS

**Table 4:** *Frame capture efficiency*

4. **Marking<a name="_page28_x63.64_y607.86"></a> zones**

To record a zone’s  [ ex](#_page28_x77.98_y721.00)ecution time add the ZoneScoped macro at the beginning of the scope you want to measure. This will automatically record function name, source filename, and location. Optionally you may use the ZoneScopedC(color) macro to set a custom color for the zone. Note that the color value will be constant in the recording (don’t try to parametrize it). You may also set a custom name for the zone, using the ZoneScopedN(name) macro. Color and name may be combined by using the ZoneScopedNC(name, color) macro.![ref6]

`  `A<a name="_page28_x77.98_y721.00"></a> zone represents the lifetime of a special on-stack profilervariable. Typically it would exist for the duration of a whole scope of the profiledfunction, but you also can measure time spent in scopes of a for-loop or an if-branch.

Use the ZoneText(text, size) macro to add a custom text string that the profiler will display along with the zone information (for example, name of the file you are opening). Multiple text strings can be attached to any single zone. The dynamic color of a zone can be specifiedwith the ZoneColor(uint32\_t) macro to override the source location color. If you want to send a numeric value and don’t want to pay the cost of converting it to a string, you may use the ZoneValue(uint64\_t) macro. Finally, you can check if the current zone is active with the ZoneIsActive macro.

If you want to set zone name on a per-call basis, you may do so using the ZoneName(text, size) macro. However, this name won’t be used in the process of grouping the zones for statistical purposes (sections 5.6 and [5.7).](#_page71_x63.64_y132.43)

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.050.png)**

Zones are identifiedusing static data structures embedded in program code. Therefore, you need to consider the lifetime of code in your application, as discussed in section 3.1.1, t[o mak](#_page23_x63.64_y431.91)e sure that the profilercan access this data at any time during the program lifetime.

If you can’t fulfillthis requirement, you must use transient zones, described in section 3.4.4.

1. **Manual<a name="_page29_x63.64_y305.59"></a> management of zone scope**

The zone markup macros automatically report when they end, through the RAII mechanism  . This is[ ver](#_page29_x77.98_y721.33)y helpful, but sometimes you may want to mark the zone start and end points yourself, for example, if you want to have a zone that crosses the function’s boundary. You can achieve this by using the C API, which is <a name="_page29_x63.64_y388.64"></a>described in section [3.13.](#_page42_x63.64_y636.27)

2. **Multiple zones in one scope**

Using the ZoneScoped family of macros creates a stack variable named \_\_\_tracy\_scoped\_zone. If you want to measure more than one zone in the same scope, you will need to use the ZoneNamedmacros, which require that you provide a name for the created variable. For example, instead of ZoneScopedN("Zone name"), you would use ZoneNamedN(variableName, "Zone name", true)  .

The ZoneText, ZoneColor, ZoneValue, ZoneIsActive, and ZoneNamemacros apply to the zones cre-

ated using the ZoneScoped macros. For zones created using the ZoneNamedmacros, you can use the ZoneTextV(variableName, text, size),ZoneColorV(variableName, uint32\_t),ZoneValueV(variableName, uint64\_t),ZoneIsActiveV(variableName),or ZoneNameV(variableName, text, size) macros,orinvoke

the methods Text, Color, Value, IsActive, or Namedirectly on the variable you have created.

Zone objects can’t be moved or copied.

**Zone stack![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.051.png)**

The ZoneScoped macros are imposing the creation and usage of an implicit zone stack. You must also follow the rules of this stack when using the named macros, which give you some more leeway in doing things. For example, you can only set the text for the zone which is on top of the stack, as you only could do with the ZoneText macro. It doesn’t matter that you can call the Text method of a non-top zone which is accessible through a variable. Take a look at the following code:

{

ZoneNamed(Zone1, true);

a

{

ZoneNamed(Zone2, true);

`  `<a name="_page29_x77.98_y721.33"></a>[https://en.cppreference.com/w/cpp/language/raii ](https://en.cppreference.com/w/cpp/language/raii)  The<a name="_page29_x77.98_y730.94"></a> last parameter is explained in section [3.4.3.](#_page30_x63.64_y186.99)

b![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.052.png)

}

c

}

It is valid to set the Zone1 text or name *only* in places a or c . After Zone2 is created at b you can no longer perform operations on Zone1, until Zone2 is destroyed.

3. **Filtering<a name="_page30_x63.64_y186.99"></a> zones**

Zone logging can be disabled on a per-zone basis by making use of the ZoneNamedmacros. Each of the macros takes an active argument (’true’ in the example in section [3.4.2), which](#_page29_x63.64_y388.64) will determine whether the zone should be logged.

Note that this parameter may be a run-time variable, such as a user-controlled switch to enable profiling of a specificpart of code only when required.

If the condition is constant at compile-time, the resulting code will not contain a branch (the profiling code will either be always enabled or won’t be there at all). The following listing presents how you might implement profilingof specificapplication subsystems:

enum SubSystems

{

Sys\_Physics = 1 << 0, Sys\_Rendering = 1 << 1, Sys\_NasalDemons = 1 << 2

} ...

// Preferably a define in the build system

#define SUBSYSTEMS (Sys\_Physics | Sys\_NasalDemons)

...

void Physics::Process() {

ZoneNamed( \_\_tracy, SUBSYSTEMS & Sys\_Physics ); // always true, no runtime cost ...

}

void Graphics::Render() {

ZoneNamed( \_\_tracy, SUBSYSTEMS & Sys\_Graphics ); // always false, no runtime cost ...

}

4. **Transient<a name="_page30_x63.64_y590.37"></a> zones**

In order to prevent problems caused by unloadable code, described in section 3.1.1, tr[ansient](#_page23_x63.64_y431.91) zones copy the source location data to an on-heap buffer. This way, the requirement on the string literal data being accessible for the rest of the program lifetime is relaxed, at the cost of increased memory usage.

Transient zones can be declared through the ZoneTransient and ZoneTransientN macros, with the same set of parameters as the ZoneNamedmacros. See section [3.4.2 f](#_page29_x63.64_y388.64)or details and make sure that you observe the requirements outlined there.

5. **Variable<a name="_page30_x63.64_y698.32"></a> shadowing**

The following code is fully compliant with the C++ standard:

void Function() {

ZoneScoped;

...

for ( int i=0; i<10; i++) {

ZoneScoped; ...

}

}

This doesn’t stop some compilers from dispensing *fashion advice* about variable shadowing (as both ZoneScoped calls create a variable with the same name, with the inner scope one shadowing the one in the outer scope). If you want to avoid these warnings, you will also need to use the ZoneNamedmacros.

6. **Exiting<a name="_page31_x63.64_y240.52"></a> program from within a zone**

Exiting the profiledapplication from inside a zone is not supported. When the client calls exit(), the profiler will wait for all zones to end before a program can be truly terminated. If program execution stops inside a zone, this will never happen, and the profiledapplication will seemingly hang up. At this point, you will need to manually terminate the program (or disconnect the profilerserver).

As a workaround, you may add a try/catch pair at the bottom of the function stack (for example in the main() function) and replace exit() calls with throwing a custom exception. When this exception is caught, you may call exit(), knowing that the application’s data structures (including profilingzones) were properly cleaned up.

5. **Marking<a name="_page31_x63.64_y373.87"></a> locks**

Modern programs must use multi-threading to achieve the full performance capability of the CPU. However, correctexecutionrequiresclaimingexclusiveaccesstodatasharedbetweenthreads. Whenmanythreadswant to simultaneously enter the same critical section, the application’s multi-threaded performance advantage nullifies. To help solve this problem, Tracy can collect and display lock interactions in threads.

To mark a lock (mutex) for event reporting, use the TracyLockable(type, varname) macro. Note that the lock must implement the Mutex requirement   [(i.e.,](#_page31_x77.98_y725.23) there’s no support for timed mutexes). For a concrete example, you would replace the line

std::mutex m\_lock;

with

TracyLockable(std::mutex, m\_lock);

Alternatively, you may use TracyLockableN(type, varname, description) to provide a custom lock name at a global level, which will replace the automatically generated ’std::mutex m\_lock’-like name. You may also set a custom name for a specific instance of a lock, through the LockableName(varname, name, size) macro.

The standard std::lock\_guard and std::unique\_lock wrappers should use the LockableBase(type) macrofortheirtemplateparameter(unlessyou’reusingC++17,withimprovedtemplateargumentdeduction). For example:

std::lock\_guard<LockableBase(std::mutex)> lock(m\_lock);

To mark the location of a lock being held, use the LockMark(varname) macro after you have obtained the lock. Note that the varname must be a lock variable (a reference is also valid). This step is optional.![ref12]

`  `<a name="_page31_x77.98_y725.23"></a><https://en.cppreference.com/w/cpp/named_req/Mutex>

Similarly, you can use TracySharedLockable, TracySharedLockableN and SharedLockableBase to mark locks implementing the SharedMutex requirement  . N[ote](#_page32_x77.98_y702.61) that while there’s no support for timed mutices in Tracy, both std::shared\_mutex and std::shared\_timed\_mutex may be used [ .](#_page32_x77.98_y712.22)

**Condition variables![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.054.png)**

The standard std::condition\_variable is only able to accept std::mutex locks. To be able to use Tracy lock wrapper, use std::condition\_variable\_any instead.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.055.png)**

Due to the limits of internal bookkeeping in the profiler, you may use each lock in no more than 64 unique threads. If you have many short-lived temporary threads, consider using a thread pool to limit the number of created threads.

<a name="_page32_x63.64_y284.07"></a>**3.5.1 Custom locks**

If using the TracyLockable or TracySharedLockable wrappers does not fit your needs, you may want

to add a more fine-grained instrumentation to your code. Classes LockableCtx and SharedLockableCtx contained in the TracyLock.hpp header contain all the required functionality. Lock implementations in classes Lockable and SharedLockable show how to properly perform context handling.

6. **Plotting<a name="_page32_x63.64_y370.02"></a> data**

Tracy can capture and draw numeric value changes over time. You may use it to analyze draw call counts, number of performed queries, etc. To report data, use the TracyPlot(name, value) macro.

To configure how plot values are presented by the profiler, you may use the TracyPlotConfig(name, format, step, fill, color) macro, where format is one of the following options:

35
Tracy Profiler The user manual![ref1]

- tracy::PlotFormatType::Number
- tracy::PlotFormatType::Memory megabytes, etc.
- tracy::PlotFormatType::Percentage equal to 100%).
- values will be displayed as plain numbers.
- treats the values as memory sizes. Will display kilobytes,
  - values will be displayed as percentage (with value 100 being


Tracy Profiler The user manual![ref1]

The step parameter determines whether the plot will be displayed as a staircase or will smoothly change between plot points (see figure6).[ The](#_page32_x63.64_y594.63) fill parameter can be used to disable fillingthe area below the plot with a solid color.

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.056.png) ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.057.png)

<a name="_page32_x63.64_y594.63"></a>**Figure 6:** *An identical set of values on a smooth plot (left) and a staircase plot (right).![ref13]*

`  `<a name="_page32_x77.98_y702.61"></a><https://en.cppreference.com/w/cpp/named_req/SharedMutex>

`  `<a name="_page32_x77.98_y712.22"></a>Since std::shared\_mutex wasaddedinC++17,using std::shared\_timed\_mutex istheonlywaytohavesharedmutexfunctionality in C++14.

Each plot has its own color, which by default is derived from the plot name (each unique plot name produces its own color, which does not change between profilingruns). If you want to provide your own color instead, you may enter the color parameter. Note that you should set the color value to 0 if you do not want to set your own color.

For reference, the following command sets the default parameters of the plot (that is, it’s a no-op): TracyPlotConfig(name, tracy::PlotFormatType::Number, false, true, 0).

It is beneficialbut not required to use a unique pointer for name string literal (see section 3.1.2 for[ more ](#_page23_x63.64_y565.27)details).

7. **Message<a name="_page33_x63.64_y190.70"></a> log**

Fast navigation in large data sets and correlating zones with what was happening in the application may be difficult. To ease these issues, Tracy provides a message log functionality. You can send messages (for example, your typical debug output) using the TracyMessage(text, size) macro. Alternatively, use TracyMessageL(text) for string literal messages.

If you want to include color coding of the messages (for example to make critical messages easily visible), you can use TracyMessageC(text, size, color) or TracyMessageLC(text, color) macros.

<a name="_page33_x63.64_y301.69"></a>**3.7.1 Application information**

Tracy can collect additional information about the profiledapplication, which will be available in the trace description. This can include data such as the source repository revision, the application’s environment (dev/prod), etc.

Use the TracyAppInfo(text, size) macro to report the data.

8. **Memory<a name="_page33_x63.64_y384.83"></a> profiling**

Tracy can monitor the memory usage of your application. Knowledge about each performed memory allocation enables the following:

- Memory usage graph (like in massif, but fully interactive).
- List of active allocations at program exit (memory leaks).
- Visualization of the memory map.
- Ability to rewind view of active allocations and memory map to any point of program execution.
- Information about memory statistics of each zone.
- Memory allocation hot-spot tree.

To mark memory events, use the TracyAlloc(ptr, size) and TracyFree(ptr) macros. Typically you would do that in overloads of operator new and operator delete, for example:

void \* operator new(std::size\_t count) {

auto ptr = malloc(count); TracyAlloc(ptr, count);

return ptr;

}

void operator delete( void \* ptr) noexcept {

TracyFree(ptr);

free(ptr);

}

In some rare cases (e.g., destruction of TLS block), events may be reported after the profileris no longer available, which would lead to a crash. To work around this issue, you may use TracySecureAlloc and TracySecureFree variants of the macros.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.059.png)**

Each tracked memory-free event must also have a corresponding memory allocation event. Tracy will terminate the profilingsession if this assumption is broken (see section 4.7). [If you](#_page58_x63.64_y261.44) encounter this issue, you may want to check for:

- Mismatched malloc/newor free/delete.
- Reporting the same memory address being allocated twice (without a free between two alloca- tions).
- Double freeing the memory.
- Untracked allocations made in external libraries that are freed in the application.
- Places where the memory is allocated, but profilingmarkup is added.

This requirement is relaxed in the on-demand mode (section 2.1.2)[ because](#_page12_x63.64_y720.61) the memory allocation event might have happened before the server made the connection.

**Non-stable memory addresses![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.060.png)**

Note that the pointer data you provide to the profilerdoes not have to reflectthe actual memory layout, which you may not know in some cases. This includes the possibility of having multiple overlapping memory allocation regions. For example, you may want to track GPU memory, which may be mapped to different locations in the program address space during allocation and freeing. Or maybe you use some memory defragmentation scheme, which by its very design moves pointers around. You may instead use unique numeric identifiersto identify allocated objects in such cases. This will make some profilerfacilities unavailable. For example, the memory map won’t have much sense anymore.

<a name="_page34_x63.64_y508.99"></a>**3.8.1 Memory pools**

Sometimes an application will use more than one memory pool. For example, in addition to tracking the malloc/free heap, you may also be interested in memory usage of a graphic API, such as Vulkan. Or maybe you want to see how your scripting language is managing memory.

Tomarkthataseparatememorypoolistobetrackedyoushouldusethenamedversionofmemorymacros, forexample TracyAllocN(ptr, size, name) and TracyFreeN(ptr, name),where nameisanuniquepointer to a string literal (section [3.1.2) ](#_page23_x63.64_y565.27)identifying the memory pool.

9. **GPU<a name="_page34_x63.64_y620.04"></a> profiling**

Tracy provides bindings for profilingOpenGL, Vulkan, Direct3D 11, Direct3D 12, and OpenCL execution time on GPU.

Note that the CPU and GPU timers may be unsynchronized unless you create a calibrated context, but the availability of calibrated contexts is limited. You can try to correct the desynchronization of uncalibrated contexts in the profiler’s options (section [5.4).](#_page67_x63.64_y452.14)

**Check the scope![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.061.png)**

If the graphic API you are using requires explicitly stating that you start and finishthe recording of command buffers, remember that the instrumentation macros requirements must be satisfiedduring the zone’s construction and destruction. For example, the zone destructor will be executed in the following code after buffer recording has ended, which is an error.

{

vkBeginCommandBuffer(cmd, &beginInfo); TracyVkZone(ctx, cmd, "Render"); vkEndCommandBuffer(cmd);

}

Add a nested scope encompassing the command buffer recording section to fixsuch issues.

**Caveat emptor![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.062.png)**

The profiling results you will get can be unreliable or plainly wrong. It all depends on the quality of graphics drivers and how the underlying hardware implements timers. While Tracy employs some heuristics to make things as reliable as possible, it must talk to the GPU through the commonly unreliable API calls.

Forexample,onLinux,theIntelGPUdriverwillreport64-bitprecisionoftimestamps. Unfortunately, this is not true, as the driver will only provide timestamps with 36-bit precision, rolling over the exceeding values. Tracy can detect such problems and employ workarounds. This is, sadly, not enough to make the readings reliable, as this timer we can access through the API is not a real one. Deep down, the driver has access to the actual timer, which it uses to provide the virtual values we can get. Unfortunately, this hardware timer has a period which *does not match*the period of the API timer. As a result, the virtual timer will sometimes overflow *in midst* of a cycle, making the reported time values jump forward. This is a problem that only the driver vendor can fix.

If you experience crippling problems while profilingthe GPU, you might get better results with a different driver, different operating system, or different hardware.

1. **OpenGL**

<a name="_page35_x63.64_y485.75"></a>You will need to include the public/tracy/TracyOpenGL.hpp header fileand declare each of your rendering contexts using the TracyGpuContext macro (typically, you will only have one context). Tracy expects no more than one context per thread and no context migration. To set a custom name for the context, use the TracyGpuContextName(name, size) macro.

To mark a GPU zone use the TracyGpuZone(name) macro, where nameis a string literal name of the zone. Alternatively you may use TracyGpuZoneC(name, color) to specify zone color.

You also need to periodically collect the GPU events using the TracyGpuCollect macro. An excellent place to do it is after the swap buffers function call.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.063.png)**

- OpenGL profilingis not supported on OSX, iOS *[a*.](#_page36_x98.91_y109.14)*
- Nvidia drivers are unable to provide consistent timing results when two OpenGL contexts are used simultaneously.
- Calling the TracyGpuCollect macro is a fairly slow operation (couple s).![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.064.png)

*a<a name="_page36_x98.91_y109.14"></a>*Because Apple is unable to implement standards properly.

2. **Vulkan**

<a name="_page36_x63.64_y137.00"></a>Similarly, for Vulkan support you should include the public/tracy/TracyVulkan.hpp header file. Tracing Vulkandevicesandqueuesisabitmoreinvolved,andtheVulkaninitializationmacro TracyVkContext(physdev, device, queue, cmdbuf) returns an instance of TracyVkCtx object, which tracks an associated Vulkan queue. Cleanup is performed using the TracyVkDestroy(ctx) macro. You may create multiple Vulkan contexts. To set a custom name for the context, use the TracyVkContextName(ctx, name, size) macro.

The physical device, logical device, queue, and command buffer must relate to each other. The queue must support graphics or compute operations. The command buffer must be in the initial state and be able to be reset. The profilerwill rerecord and submit it to the queue multiple times, and it will be in the executable state on exit from the initialization function.

To mark a GPU zone use the TracyVkZone(ctx, cmdbuf, name) macro, where name is a string literal name of the zone. Alternatively you may use TracyVkZoneC(ctx, cmdbuf, name, color) to specify zone color. The provided command buffer must be in the recording state, and it must be created within the queue

that is associated with ctx context.

You also need to periodically collect the GPU events using the TracyVkCollect(ctx, cmdbuf) macro[  . ](#_page36_x77.98_y713.83)The provided command buffer must be in the recording state and outside a render pass instance.

**Calibrated context** In order to maintain synchronization between CPU and GPU time domains, you will need to enable the VK\_EXT\_calibrated\_timestamps device extension and retrieve the following function pointers: vkGetPhysicalDeviceCalibrateableTimeDomainsEXT and vkGetCalibratedTimestampsEXT.

To enable calibrated context, replace the macro TracyVkContext with TracyVkContextCalibrated and pass the two functions as additional parameters, in the order specifiedabove.

**Using Vulkan 1.2 features** Vulkan 1.2 and VK\_EXT\_host\_query\_reset provide mechanics to reset the

query pool without the need of a command buffer. By using TracyVkContextHostCalibrated you can make

use of this feature. It only requires a function pointer to vkResetQueryPool in addition to the ones required

for TracyVkContextCalibrated instead of the VkQueue and VkCommandBuffer handles.

However,usingthisfeaturerequiresthephysicaldevicetohavecalibrateddeviceandhosttimedomains. In

addition to VK\_TIME\_DOMAIN\_DEVICE\_EXT, vkGetPhysicalDeviceCalibrateableTimeDomainsEXT will have

toadditionallyreturneither VK\_TIME\_DOMAIN\_CLOCK\_MONOTONIC\_RAW\_EXTor VK\_TIME\_DOMAIN\_QUERY\_PERFORMANCE\_COUNTER\_EXT for Unix and Windows, respectively. If this is not the case, you will need to use TracyVkContextCalibrated

or TracyVkContext macro instead.

**Dynamically loading the Vulkan symbols** Some applications dynamically link the Vulkan loader, and manage a local symbol table, to remove the trampoline overhead of calling through the Vulkan loader itself.

When TRACY\_VK\_USE\_SYMBOL\_TABLEisdefinedthesignatureof TracyVkContext,TracyVkContextCalibrated, and TracyVkContextHostCalibrated are adjusted to take in the VkInstance, PFN\_vkGetInstanceProcAddr, and PFN\_vkGetDeviceProcAddr to enable constructing a local symbol table to be used to call through the Vulkan API when tracing.

3. **Direct3D<a name="_page36_x63.64_y650.14"></a> 11**

To enable Direct3D 11 support, include the public/tracy/TracyD3D11.hpp header file, and create a TracyD3D11Ctx object with the TracyD3D11Context(device, devicecontext) macro. The object should![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.065.png)

`  `<a name="_page36_x77.98_y713.83"></a>It is considerably faster than the OpenGL’s TracyGpuCollect.

later be cleaned up with the TracyD3D11Destroy macro. Tracy does not support D3D11 command lists. To set a custom name for the context, use the TracyGpuContextName(name, size) macro.

To mark a GPU zone, use the TracyD3D11Zone(name) macro, where nameis a string literal name of the zone. Alternatively you may use TracyD3D11ZoneC(name, color) to specify zone color.

You also need to periodically collect the GPU events using the TracyD3D11Collect macro. An excellent place to do it is after the swap chain present function.

4. **Direct3D<a name="_page37_x63.64_y166.25"></a> 12**

To enable Direct3D 12 support, include the public/tracy/TracyD3D12.hpp header file. Tracing Direct3D 12 queues is nearly on par with the Vulkan implementation, where a TracyD3D12Ctx is returned from a call to TracyD3D12Context(device, queue), which should be later cleaned up with the TracyD3D12Destroy(ctx) macro. Multiple contexts can be created, each with any queue type. To set a custom name for the context,

use the TracyD3D12ContextName(ctx, name, size) macro.

The queue must have been created through the specifieddevice, however, a command list is not needed for this stage.

Using GPU zones is the same as the Vulkan implementation, where the TracyD3D12Zone(ctx, cmdList, name) macro is used, with nameas a string literal. TracyD3D12ZoneC(ctx, cmdList, name, color) can be used to create a custom-colored zone. The given command list must be in an open state.

The macro TracyD3D12NewFrame(ctx) is used to mark a new frame, and should appear before or after recording command lists, similar to FrameMark. This macro is a key component that enables automatic query data synchronization, so the user doesn’t have to worry about synchronizing GPU execution before invoking

a collection. Event data can then be collected and sent to the profilerusing the TracyD3D12Collect(ctx) macro.

Note that GPU profiling may be slightly inaccurate due to artifacts from dynamic frequency scaling.         To counter this, ID3D12Device::SetStablePowerState() can be used to enable accurate profiling, at the expense of some performance. If the machine is not in developer mode, the operating system will remove

the device upon calling. Do not use this in the shipping code.

Direct3D 12 contexts are always calibrated.

5. **OpenCL**

<a name="_page37_x63.64_y450.23"></a>OpenCL support is achieved by including the public/tracy/TracyOpenCL.hpp header file. Tracing OpenCL requiresthecreationofaTracyOpenCLcontextusingthemacro TracyCLContext(context, device),which will return an instance of TracyCLCtx object that must be used when creating zones. The specified device must be part of the context. Cleanup is performed using the TracyCLDestroy(ctx) macro. Although not common, it is possible to create multiple OpenCL contexts for the same application. To set a custom name for the context, use the TracyCLContextName(ctx, name, size) macro.

To mark an OpenCL zone one must make sure that a valid OpenCL cl\_event object is available. The event will be the object that Tracy will use to query profilinginformation from the OpenCL driver. For this to work, you must create all OpenCL queues with the CL\_QUEUE\_PROFILING\_ENABLEproperty.

OpenCLzonescanbecreatedwiththe TracyCLZone(ctx, name) where namewillusuallybeadescriptive name for the operation represented by the cl\_event. Within the scope of the zone, you must call TracyCLSetEvent(event) for the event to be registered in Tracy.

Similar to Vulkan and OpenGL, you also need to periodically collect the OpenCL events using the TracyCLCollect(ctx) macro. An excellent place to perform this operation is after a clFinish since this will ensure that any previously queued OpenCL commands will have finishedby this point.

6. **Multiple<a name="_page37_x63.64_y671.46"></a> zones in one scope**

Putting more than one GPU zone macro in a single scope features the same issue as with the ZoneScoped macros, described in section [3.4.2 (but](#_page29_x63.64_y388.64) this time the variable name is \_\_\_tracy\_gpu\_zone).

To solve this problem, in case of OpenGL use the TracyGpuNamedZonemacro in place of TracyGpuZone     (or the color variant). The same applies to Vulkan and Direct3D 11/12 – replace TracyVkZone with      TracyVkNamedZoneand TracyD3D11Zone/TracyD3D12Zonewith TracyD3D11NamedZone/TracyD3D12NamedZone.

Remember to provide your name for the created stack variable as the first parameter to the macros.

7. **Transient<a name="_page38_x63.64_y141.14"></a> GPU zones**

Transient zones (see section [3.4.4 for](#_page30_x63.64_y590.37) details) are available in OpenGL, Vulkan, and Direct3D 11/12 macros.

10. **Fibers**

<a name="_page38_x63.64_y186.62"></a>Fibers are lightweight threads, which are not under the operating system’s control and need to be manually scheduledbytheapplication. AsfarasTracyisconcerned,thereareothercooperativemultitaskingprimitives, like coroutines, or green threads, which also fall under this umbrella.

To enable fibersupport in the client code, you will need to add the TRACY\_FIBERSdefineto your project. You need to do this explicitly, as there is a small performance hit due to additional processing.

To properly instrument fibers, you will need to modify the fiber dispatch code in your program. You will need to insert the TracyFiberEnter(fiber) macro every time a fiberstarts or resumes execution. You will also need to insert the TracyFiberLeave macro when the execution control in a thread returns to the non-fiber part of the code. Note that you can safely call TracyFiberEnter multiple times in succession, without an intermediate TracyFiberLeave if one fiberis directly switching to another, without returning control to the fiberdispatch worker.

Fibers are identifiedby unique const char\* string names. Remember that you should observe the rules laid out in section [3.1.2 while](#_page23_x63.64_y565.27) handling such strings.

No additional instrumentation is needed in other parts of the code. Zones, messages, and other such events will be properly attributed to the currently running fiberin its own separate track.

A straightforward example, which is not actually using any OS fiberfunctionality, is presented below:

const char\* fiber = "job1"; TracyCZoneCtx zone;

int main() {

std::thread t1([]{

TracyFiberEnter(fiber); TracyCZone(ctx, 1); zone = ctx;

sleep(1); TracyFiberLeave;

});

t1.join();

std::thread t2([]{

TracyFiberEnter(fiber); sleep(1); TracyCZoneEnd(zone); TracyFiberLeave;

});

t2.join();

}

As you can see, there are two threads, t1 and t2, which are simulating worker threads that a real fiber library would use. A C API zone is created in thread t1 and is ended in thread t2. Without the fibermarkup, this would be an invalid operation, but with fibers,the zone is attributed to fiber job1, and not to thread t1 or<a name="_page38_x63.64_y711.23"></a> t2.

11. **Collecting call stacks**

Capture of true calls stacks can be performed by using macros with the Spostfix,which require an additional parameter, specifying the depth of call stack to be captured. The greater the depth, the longer it will take toperformcapture. Currentlyyoucanusethefollowingmacros: ZoneScopedS,ZoneScopedNS,ZoneScopedCS, ZoneScopedNCS,TracyAllocS,TracyFreeS,TracySecureAllocS,TracySecureFreeS,TracyMessageS,TracyMessageLS, TracyMessageCS, TracyMessageLCS, TracyGpuZoneS, TracyGpuZoneCS, TracyVkZoneS, TracyVkZoneCS, and

the named and transient variants.

Be aware that call stack collection is a relatively slow operation. Table 5 and [figure](#_page39_x63.64_y216.31)7 show [ho](#_page39_x63.64_y486.99)w long it

took to perform a single capture of varying depth on multiple CPU architectures.

<a name="_page39_x63.64_y216.31"></a>**Depth x86 x64 ARM ARM64![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.066.png)**

1  34 ns 98 ns 6.62 s 6.63 s
1  35 ns 150 ns 8.08 s 8.25 s
1  36 ns 168 ns 9.75 s 10 s
1  39 ns 190 ns 10.92 s 11.58 s
1  42 ns 206 ns 12.5 s 13.33 s

10 52 ns 306 ns 19.62 s 21.71 s

15 63 ns 415 ns 26.83 s 30.13 s

20 77 ns 531 ns 34.25 s 38.71 s

25 89 ns 630 ns 41.17 s 47.17 s

30 109 ns 735 ns 48.33 s 55.63 s

35 123 ns 843 ns 55.87 s 64.09 s

40 142 ns 950 ns 63.12 s 72.59 s

45 154 ns 1.05 s 70.54 s 81 s

50 167 ns 1.16 s 78 s 89.5 s

55 179 ns 1.26 s 85.04 s 98 s

60 193 ns 1.37 s 92.75 s 106.59 s

**Table 5:** *Median times of zone capture with call stack. x86, x64: i7 8700K; ARM: Banana Pi; ARM64: ODROID-C2. Selected*

*architectures are plotted on figure 7*

<a name="_page39_x63.64_y486.99"></a>1,500 ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.067.png)

x64

x86 1,000

)

ns

Time( 500

0

0  10 20 30 40 50 60 Call stack depth

**Figure 7:** *Plot of call stack capture times (see t[able 5).](#_page39_x63.64_y216.31) Notice that the capture time grows linearly with requested capture depth*

You can force call stack capture in the non-Spostfixed macros by adding the TRACY\_CALLSTACKdefine,set

to the desired call stack capture depth. This setting doesn’t affect the explicit call stack macros.

The maximum call stack depth that the profilercan retrieve is 62 frames. This is a restriction at the level of the operating system.

Tracy will automatically exclude certain uninteresting functions from the captured call stacks. So, for example, the pass-through intrinsic wrapper functions won’t be reported.

**Important!![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.068.png)**

Collecting call stack data will also trigger retrieval of profiledprogram’s executable code by the profiler. See section [3.14.7 f](#_page51_x63.64_y178.80)or details.

**How to disable![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.069.png)**

Tracy will prepare for call stack collection regardless of whether you use the functionality or not. In some cases, this may be unwanted or otherwise troublesome for the user. To disable support for collecting call stacks, definethe TRACY\_NO\_CALLSTACKmacro.

<a name="_page40_x63.64_y301.88"></a>**3.11.1 Debugging symbols**

You must compile the profiled application with debugging symbols enabled to have correct call stack information. You can achieve that in the following way:

- On MSVC, open the project properties and go to Linker Debugging Generate Debug Info , where you should ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.070.png)select the *Generate Debug Information* option.
- On gcc or clang remember to specify the debugging information -g parameter during compilation and *do not* add the strip symbols -s parameter. Additionally, omitting frame pointers will severely reduce the quality of stack traces, which can be fixed by adding the -fno-omit-frame-pointer parameter. Link the executable with an additional option -rdynamic (or --export-dynamic, if you are passing parameters directly to the linker).
- On OSX, you may need to run dsymutil to extract the debugging data out of the executable binary.
- On iOS you will have to add a *New Run Script Phase* to your XCode project, which shall execute the following shell script:

cp -rf ${TARGET\_BUILD\_DIR}/${WRAPPER\_NAME}.dSYM/\* ${TARGET\_BUILD\_DIR}/${

UNLOCALIZED\_RESOURCES\_FOLDER\_PATH}/${PRODUCT\_NAME}.dSYM

You will also need to setup proper dependencies, by setting the following input file: ${TARGET\_BUILD\_DIR}/${WRAPPER\_NAME}.dSYM, and the following output file: ${TARGET\_BUILD\_DIR}/${UNLOCALIZED\_RESOURCES\_FOLDER\_PATH}/${PRODUCT\_NAME}.dSYM.

1. **External<a name="_page40_x63.64_y600.45"></a> libraries**

You may also be interested in symbols from external libraries, especially if you have sampling profiling enabled (section [3.14.5).](#_page49_x63.64_y158.34)

**Windows** In MSVC you can retrieve such symbols by going to Tools Options Debugging Symbols and selecting![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.071.png) appropriate *Symbol file (.pdb) location* servers. Note that additional symbols may significantly increase application startup times.

Libraries built with vcpkg typically provide PDB symbol files,even for release builds. Using vcpkg to obtain libraries has the extra benefitthat everything is built using local source files,which allows Tracy to provide a source view not only of your application but also the libraries you use.

**Unix** On Linux[   ](#_page41_x77.98_y685.20)information needed for debugging traditionally has been provided by special packages named debuginfo, dbgsym, or similar. You can use them to retrieve symbols, but keep in mind the following:

1. Your distribution has to provide such packages. Not each one does.
1. Debug packages are usually stored in a separate repository, which you must manually enable.
1. You need to install a separate package for each library you want to have symbols for.
1. Debugging information can require large amounts of disk space.

A modern alternative to installing static debug packages is to use the *debuginfod*system, which performs on-demanddeliveryofdebugginginformationacrosstheinternet. See [https://sourceware.org/elfutils/ Debuginfod.html ](https://sourceware.org/elfutils/Debuginfod.html)formoredetails. Sincethisnewmethodofsymboldeliveryisnotyetuniversallysupported, you will have to manually enable it, both in your system and in Tracy.

First,makesureyourdistributionmaintainsadebuginfodserver. Then,installthe debuginfod library. You also need to ensure you have appropriately configuredwhich server to access, but distribution maintainers usually provide this. Next, add the TRACY\_DEBUGINFODdefineto the program you want to profileand link it with libdebuginfod. This will enable network delivery of symbols and source filecontents. However, the first run (including after a system update) may be slow to respond until the local debuginfod cache becomes <a name="_page41_x63.64_y333.02"></a>filled.

2. **Using the dbghelp library on Windows**

While Tracy will try to expand the known symbols list when it encounters a new module for the first time, you may want to be able to do such a thing manually. Or maybe you are using the dbghelp.dll library in some other way in your project, for example, to present a call stack to the user at some point during execution.

Since dbghelp functions are not thread-safe, you must take extra steps to make sure your calls to the Sym\* family of functions are not colliding with calls made by Tracy. To do so, perform the following steps:

1. Add a TRACY\_DBGHELP\_LOCKdefine,with the value set to prefixof lock-handling functions (for example: TRACY\_DBGHELP\_LOCK=DbgHelp).
1. Create a dbghelp lock (i.e., mutex) in your application.
1. Provide a set of Init, Lock and Unlock functions, including the provided prefix name, which will operate on the lock. These functions must be defined using the C linkage. Notice that there’s no cleanup function.
1. Remember to protect access to dbghelp in your code appropriately!

An example implementation of such a lock interface is provided below, as a reference:

extern "C"

{

static HANDLE dbgHelpLock;

void DbgHelpInit() { dbgHelpLock = CreateMutex(nullptr, FALSE, nullptr); } void DbgHelpLock() { WaitForSingleObject(dbgHelpLock, INFINITE); }

void DbgHelpUnlock() { ReleaseMutex(dbgHelpLock); }

}![ref12]

<a name="_page41_x63.64_y679.55"></a>  And<a name="_page41_x77.98_y685.20"></a> possibly other systems, if they decide to adapt the required tooling.

3. **Disabling resolution of inline frames**

Inline frames retrieval on Windows can be multiple orders of magnitude slower than just performing essential symbol resolution. This manifests as profiler seemingly being stuck for a long time, having hundreds of thousands of query backlog entries queued, which are slowly trickling down. If your use case requires speed of operation rather than having call stacks with inline frames included, you may define the TRACY\_NO\_CALLSTACK\_INLINESmacro, which will make the profiler stick to the basic but fast frame <a name="_page42_x63.64_y183.21"></a>resolution mode.

12. **Lua support**

To profileLua code using Tracy, include the public/tracy/TracyLua.hpp header filein your Lua wrapper and execute tracy::LuaRegister(lua\_State\*) function to add instrumentation support.

In the Lua code, add tracy.ZoneBegin() and tracy.ZoneEnd() calls to mark execution zones. You need to call the ZoneEnd method because there is no automatic destruction of variables in Lua, and we don’t know when the garbage collection will be performed. *Double check if you have included all return paths!*

Use tracy.ZoneBeginN(name) if you want to set a custom zone name  .

Use tracy.ZoneText(text) to set zone text.

Use tracy.Message(text) to send messages.

Use tracy.ZoneName(text) to set zone name on a per-call basis.

Lua instrumentation needs to perform additional work (including memory allocation) to store source location. This approximately doubles the data collection cost.

1. **Call<a name="_page42_x63.64_y358.91"></a> stacks**

TocollectLuacallstacks(seesection[3.11),](#_page38_x63.64_y711.23)replace tracy.ZoneBegin() callswith tracy.ZoneBeginS(depth), and tracy.ZoneBeginN(name) calls with tracy.ZoneBeginNS(name, depth). Using the TRACY\_CALLSTACK macro automatically enables call stack collection in all zones.

Be aware that for Lua call stack retrieval to work, you need to be on a platform that supports the collection of native call stacks.

Cost of performing Lua call stack capture is presented in table 6 and [figure](#_page43_x63.64_y84.43) 8. Lua [call](#_page44_x63.64_y84.43) stacks include native call stacks, which have a capture cost of their own (table 5), [and t](#_page39_x63.64_y216.31)he depth parameter is applied for both captures. The presented data were captured with full Lua stack depth, but only 13 frames were available

on the native call stack. Hence, to explain the non-linearity of the graph, you need to consider what was truly measured:

CostLua(depth) + Costnative(depth) when depth ≤ 13 Cost total(depth ) = Cost Lua(depth ) + Cost native (13) when depth > 13

2. **Instrumentation<a name="_page42_x63.64_y565.64"></a> cleanup**

Even if Tracy is disabled, you still have to pay the no-op function call cost. To prevent that, you may want to use the tracy::LuaRemove(char\* script) function, which will replace instrumentation calls with white-space. This function does nothing if the profileris enabled.

13. **C<a name="_page42_x63.64_y636.27"></a> API**

To profilecode written in C programming language, you will need to include the public/tracy/TracyC.h header file,which exposes the C API.![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.072.png)

`  `While<a name="_page42_x77.98_y702.05"></a> technically this name doesn’t need to be constant, like in the ZoneScopedN macro, it should be, as it is used to group the zones. This grouping is then used to display various statistics in the profiler. You may still set the per-call name using the tracy.ZoneName method.

<a name="_page43_x63.64_y84.43"></a>**Depth Time![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.073.png)**

1  707 ns
1  699 ns
1  624 ns
1  727 ns
1  836 ns

10 1.77 s

15 2.44 s

20 2.51 s

25 2.98 s

30 3.6 s

35 4.33 s

40 5.17 s

45 6.01 s

50 6.99 s

55 8.11 s

60 9.17 s

**Table 6:** *Median times of Lua zone capture with call stack (x64, 13 native frames)* At the moment, there’s no support for C API based markup of locks, GPU zones, or Lua.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.074.png)**

Tracy is written in C++, so you will need to have a C++ compiler and link with C++ standard library, even if your program is strictly pure C.

1. **Setting<a name="_page43_x63.64_y438.28"></a> thread names**

To set thread names (section [2.4) using](#_page21_x63.64_y375.71) the C API you should use the TracyCSetThreadName(name) macro.

2. **Frame<a name="_page43_x63.64_y486.50"></a> markup**

To mark frames, as described in section 3.3,[ use](#_page24_x63.64_y581.52) the following macros:

- TracyCFrameMark
- TracyCFrameMarkNamed(name)
- TracyCFrameMarkStart(name)
- TracyCFrameMarkEnd(name)
- TracyCFrameImage(image, width, height, offset, flip)
3. **Zone<a name="_page43_x63.64_y643.96"></a> markup**

The following macros mark the beginning of a zone:

- TracyCZone(ctx, active)
- TracyCZoneN(ctx, name, active)
- TracyCZoneC(ctx, color, active)

<a name="_page44_x63.64_y84.43"></a>10 ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.075.png)8 

s) 6 4 

Time( 

2 

0 

0 10 20 30 40 50 60 Call stack depth

**Figure 8:** *Plot of call Lua stack capture times (see t[able 6)*](#_page43_x63.64_y84.43)*

- TracyCZoneNC(ctx, name, color, active)

Refer to sections [3.4 and](#_page28_x63.64_y607.86) [3.4.2 for](#_page29_x63.64_y388.64) description of macro variants and parameters. The ctx parameter specifiesthe name of a data structure, which the macro will create on the stack to hold the internal zone data.

Unlike C++, there’s no automatic destruction mechanism in C, so you will need to mark where the zone ends manually. To do so use the TracyCZoneEnd(ctx) macro.[  ](#_page44_x77.98_y730.94)

Zone text and name may be set by using the TracyCZoneText(ctx, txt, size), TracyCZoneValue(ctx,      value) and TracyCZoneName(ctx, txt, size) macros. Make sure you are following the zone stack rules,

<a name="_page44_x63.64_y438.41"></a>as described in section [3.4.2!](#_page29_x63.64_y388.64)

1. **Zone context data structure**

In typical use cases the zone context data structure is hidden from your view, requiring only to specify its name for the TracyCZone and TracyCZoneEnd macros. However, it is possible to use it in advanced scenarios, for example, if you want to start a zone in one function, then end it in another one. To do so, you will

need to forward the data structure either through a function parameter or as a return value or place it in a thread-local stack structure. To accomplish this, you need to keep in mind the following rules:

- The created variable name is exactly what you pass as the ctx parameter.
- The data structure is of an opaque, immutable type TracyCZoneCtx.
- Contents of the data structure can be copied by assignment. Do not retrieve or use the structure’s address – this is asking for trouble.
- You *must* use the data structure (or any of its copies) exactly *once*to end a zone.
- Zone *must* end in the same thread in which it was started.
2. **Zone<a name="_page44_x63.64_y659.90"></a> validation**

Since all C API instrumentation has to be done by hand, it is possible to miss some code paths where a zone should be started or ended. Tracy will perform additional validation of instrumentation correctness to prevent bad profilingruns. Read section 4.7 [for ](#_page58_x63.64_y261.44)more information.![ref11]

`  `<a name="_page44_x77.98_y730.94"></a>GCC and Clang provide \_\_attribute\_\_((cleanup)) which can used to run a function when a variable goes out of scope.

However, the validation comes with a performance cost, which you may not want to pay. Therefore, if you are *entirely sure* that the instrumentation is not broken in any way, you may use the TRACY\_NO\_VERIFY macro, which will disable the validation code.

3. **Transient<a name="_page45_x63.64_y127.31"></a> zones in C API**

There is no explicit support for transient zones (section 3.4.4)[ in the](#_page30_x63.64_y590.37) C API macros. However, this functionality can be implemented by following instructions outlined in section 3.13.10.

4. **Memory<a name="_page45_x63.64_y188.44"></a> profiling**

Use the following macros in your implementations of malloc and free:

- TracyCAlloc(ptr, size)
- TracyCFree(ptr)
- TracyCSecureAlloc(ptr, size)
- TracyCSecureFree(ptr)

Correctly using this functionality can be pretty tricky. You also will need to handle all the memory allocations made by external libraries (which typically allow usage of custom memory allocation functions) and the allocations made by system functions. If you can’t track such an allocation, you will need to make sure freeing is not reported  .

There is no explicit support for realloc function. You will need to handle it by marking memory allocations and frees, according to the system manual describing the behavior of this routine.

Memory pools (section [3.8.1) are](#_page34_x63.64_y508.99) supported through macros with Npostfix.

For more information about memory profiling,refer to section 3.8.

5. **Plots<a name="_page45_x63.64_y428.39"></a> and messages**

To send additional markup in form of plot data points or messages use the following macros:

- TracyCPlot(name, val)
- TracyCPlotF(name, val)
- TracyCPlotI(name, val)
- TracyCMessage(txt, size)
- TracyCMessageL(txt)
- TracyCMessageC(txt, size, color)
- TracyCMessageLC(txt, color)
- TracyCAppInfo(txt, size)

<a name="_page45_x63.64_y659.97"></a>Consult sections [3.6 and](#_page32_x63.64_y370.02) [3.7 for](#_page33_x63.64_y190.70) more information.![ref13]

`  `<a name="_page45_x77.98_y665.62"></a>It’s not uncommon to see a pattern where a system function returns some allocated memory, which you then need to release.

6. **GPU zones**

Hooking up support for GPU zones requires a bit more work than usual. The C API provides a low-level interface that you can use to submit the data, but there are no facilities to help you with timestamp processing.

Moreover, there are two sets of functions described below. The standard set sends data asynchronously, while the \_serial one ensures proper ordering of all events, regardless of the originating thread. Generally speaking, you should be using the asynchronous functions only in the case of strictly single-threaded APIs, like OpenGL.

A GPU context can be created with the \_\_\_tracy\_emit\_gpu\_new\_context function (or the serialized variant). You’ll need to specify:

- context – a unique context id.
- gpuTime – an initial GPU timestamp.
- period – the timestamp period of the GPU.
- flags – the flagsto use.
- type – the GPU context type.

GPU contexts can be named using the \_\_\_tracy\_emit\_gpu\_context\_name function.

GPUzonescanbecreatedwiththe \_\_\_tracy\_emit\_gpu\_zone\_begin\_alloc function. The srcloc parame- teristheaddressofthesourcelocationdataallocatedvia \_\_\_tracy\_alloc\_srcloc or \_\_\_tracy\_alloc\_srcloc\_name. The queryId parameter is the id of the corresponding timestamp query. It should be unique on a per-frame

basis.

GPU zones are ended via \_\_\_tracy\_emit\_gpu\_zone\_end.

WhenthetimestampsarefetchedfromtheGPU,theymustthenbeemittedviathe \_\_\_tracy\_emit\_gpu\_time function. After all timestamps for a frame are emitted, queryIds may be re-used.

To see how you should use this API, you should look at the reference implementation contained in API-specific C++ headers provided by Tracy. For example, to see how to write your instrumentation of OpenGL, you should closely follow the contents of the TracyOpenGL.hpp implementation.

7. **Fibers**

<a name="_page46_x63.64_y462.99"></a>Fibers are available in the C API through the TracyCFiberEnter and TracyCFiberLeave macros. To use them, you should observe the requirements listed in section 3.10.

8. **Connection<a name="_page46_x63.64_y521.03"></a> Status**

To query the connection status (section [3.17) using](#_page52_x63.64_y530.67) the C API you should use the TracyCIsConnected macro.

9. **Call<a name="_page46_x63.64_y566.51"></a> stacks**

You can collect call stacks of zones and memory allocation events, as described in section 3.11, by[ using ](#_page38_x63.64_y711.23)macros with Spostfix,such as: TracyCZoneS, TracyCZoneNS, TracyCZoneCS, TracyCZoneNCS, TracyCAllocS, TracyCFreeS, and so on.

10. **Using<a name="_page46_x63.64_y635.95"></a> the C API to implement bindings**

Tracy C API exposes functions with the \_\_\_tracy prefix that you may use to write bindings to other programming languages. Most of the functions available are a counterpart to macros described in sec- tion [3.13.](#_page42_x63.64_y636.27) However, some functions do not have macro equivalents and are dedicated expressly for binding implementation purposes. This includes the following:

- \_\_\_tracy\_startup\_profiler(void)
- \_\_\_tracy\_shutdown\_profiler(void)
- \_\_\_tracy\_alloc\_srcloc(uint32\_t line, const char\* source, size\_t sourceSz, const char\* function, size\_t functionSz)
- \_\_\_tracy\_alloc\_srcloc\_name(uint32\_t line, const char\* source, size\_t sourceSz, const char\* function, size\_t functionSz, const char\* name, size\_t nameSz)

Here line is line number in the source source fileand function is the name of a function in which the zone is created. sourceSz and functionSz are the size of the corresponding string arguments in bytes. You may additionally specify an optional zone name, by providing it in the namevariable, and specifying its size in nameSz.

The \_\_\_tracy\_alloc\_srcloc and \_\_\_tracy\_alloc\_srcloc\_name functions return an uint64\_t source location identifiercorresponding to an *allocated source location*. As these functions do not require the provided string data to be available after they return, the calling code is free to deallocate them at any time afterward.

This way, the string lifetime requirements described in section 3.1 are[ relax](#_page23_x63.64_y218.36)ed.

The uint64\_t return value from allocation functions must be passed to one of the zone begin functions:

- \_\_\_tracy\_emit\_zone\_begin\_alloc(srcloc, active)
- \_\_\_tracy\_emit\_zone\_begin\_alloc\_callstack(srcloc, depth, active)

These functions return a TracyCZoneCtx context value, which must be handled, as described in sec- tions [3.13.3 ](#_page43_x63.64_y643.96)and [3.13.3.1.](#_page44_x63.64_y438.41)

The variable representing an allocated source location is of an opaque type. After it is passed to one of the      zone begin functions, its value *cannot be reused*(the variable is consumed). You must allocate a new source location for each zone begin event, even if the location data would be the same as in the previous instance.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.076.png)**

Sinceyouaredirectlycallingtheprofilerfunctionshere,youwillneedtotakecareofmanuallydisabling the code if the TRACY\_ENABLEmacro is not defined.

14. **Automated<a name="_page47_x63.64_y486.91"></a> data collection**

Tracy will perform an automatic collection of system data without user intervention. This behavior is platform-specificand may not be available everywhere. Refer to section 2.6 for[ more](#_page22_x63.64_y357.24) information.

1. **Privilege<a name="_page47_x63.64_y549.84"></a> elevation**

Some profilingdata can only be retrieved using the kernel facilities, which are not available to users with normal privilege level. To collect such data, you will need to elevate your rights to the administrator level. You can do so either by running the profiledprogram from the root account on Unix or through the *Run as administrator* option on Windows [ .](#_page47_x77.98_y721.00) On Android, you will need to have a rooted device (see section 2.1.6.4[ for ](#_page14_x63.64_y699.81)additional information).

As this system-level tracing functionality is part of the automated collection process, no user intervention is necessary to enable it (assuming that the program was granted the rights needed). However, if, for some reason, you would want to prevent your application from trying to access kernel data, you may recompile your program with the TRACY\_NO\_SYSTEM\_TRACINGdefine.![ref6]

`  `T<a name="_page47_x77.98_y721.00"></a>o make this easier, you can run MSVC with admin privileges, which will be inherited by your program when you start it from within the IDE.

**What should be granted privileges?![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.077.png)**

Sometimes it may be confusing which program should be given admin access. After all, some other profilershave to run elevated to access all their capabilities.

In the case of Tracy, you should give the administrative rights to *the profiledapplication*. Remember that the server part of the profiler (where the data is collected and displayed) may be running on another machine, and thus you can’t use it to access kernel data.

2. **CPU<a name="_page48_x63.64_y188.87"></a> usage**

System-wide CPU load is gathered with relatively high granularity (one reading every 100 ms). The readings are available as a plot (see section [5.2.3.3). N](#_page64_x63.64_y401.56)ote that this parameter considers all applications running on the system, not only the profiledprogram.

3. **Context<a name="_page48_x63.64_y261.96"></a> switches**

Since the profiledprogram is executing simultaneously with other applications, you can’t have exclusive access to the CPU. Instead, the multitasking operating system’s scheduler gives threads waiting to execute short time slices to do part of their work. Afterward, threads are preempted to give other threads a chance to run. This ensures that each program running in the system has a fair environment, and no program can hog the system resources for itself.

As a corollary, it is often not enough to know how long it took to execute a zone. For example, the thread in which a zone was running might have been suspended by the system. This would have artificially increased the time readings.

To solve this problem, Tracy collects context switch   [infor](#_page48_x77.98_y721.33)mation. This data can then be used to see when a zone was in the executing state and where it was waiting to be resumed.

You may disable context switch data capture by adding the TRACY\_NO\_CONTEXT\_SWITCHdefine to the client. Since with this feature you are observing other programs, you can only use it after privilege elevation, which<a name="_page48_x63.64_y455.18"></a> is described in section [3.14.1.](#_page47_x63.64_y549.84)

4. **CPU topology**

Tracy may discover CPU topology data to provide further information about program performance charac- teristics. It is handy when combined with context switch information (section 3.14.3).

In essence, the topology information gives you context about what any given *logical CPU* really is and how it relates to other logical CPUs. The topology hierarchy consists of packages, cores, and threads.

Packages contain cores and shared resources, such as memory controller, L3 cache, etc. A store-bought CPU is an example of a package. While you may think that multi-package configurations would be a domain of servers, they are actually quite common in the mobile devices world, with many platforms using the *big.LITTLE* arrangement of two packages in one silicon chip.

Cores contain at least one thread and shared resources: execution units, L1 and L2 cache, etc.

Threads (or *logical CPUs*; not to be confused with program threads) are basically the processor instruction pipelines. A pipeline might become stalled, for example, due to pending memory access, leaving core resources unused. To reduce this bottleneck, some CPUs may use simultaneous multithreading  , in [which ](#_page48_x77.98_y730.94)more than one pipeline will be using a single physical core resources.

Knowing which package and core any logical CPU belongs to enables many insights. For example, two threads scheduled to run on the same core will compete for shared execution units and cache, resulting in reduced performance. Or, migrating a program thread from one core to another will invalidate the L1 and L2 cache. However, such invalidation is less costly than migration from one package to another, which also invalidates the L3 cache.![ref8]

`  `A<a name="_page48_x77.98_y730.94"></a><a name="_page48_x77.98_y721.33"></a> context switch happens when any given CPU core stops executing one thread and starts running another one.   Commonly known as Hyper-threading.

**Important![ref7]**

In this manual, the word *core*is typically used as a short term for *logical CPU*. Please do not confuse it with physical processor cores.

5. **Call<a name="_page49_x63.64_y158.34"></a> stack sampling**

Manual markup of zones doesn’t cover every function existing in a program and cannot be performed in system libraries or the kernel. This can leave blank spaces on the trace, leaving you no clue what the application was doing. However, Tracy can periodically inspect the state of running threads, providing you with a snapshot of the call stack at the time when sampling was performed. While this information doesn’t have the fidelityof manually inserted zones, it can sometimes give you an insight into where to go next.

This feature requires privilege elevation on Windows, but not on Linux. However, running as root on Linux will also provide you the kernel stack traces. Additionally, you should review chapter 3.11 to see[ if ](#_page38_x63.64_y711.23)you have proper setup for the required program debugging data.

By default, sampling is performed at 8 kHz frequency on Windows (the maximum possible value). On Linux and Android, it is performed at 10 kHz  . Y[ou](#_page49_x77.98_y730.94) can change this value by providing the sampling frequency (in Hz) through the TRACY\_SAMPLING\_HZmacro.

Call stack sampling may be disabled by using the TRACY\_NO\_SAMPLINGdefine.

**Linux sampling rate limits![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.078.png)**

The operating system may decide that sampling takes too much CPU time and reduce the allowed sampling rate. This can be seen in dmesg output as:

perf: interrupt took too long, lowering kernel.perf\_event\_max\_sample\_rate to value.

If the *value* goes below the sample rate Tracy wants to use, sampling will be silently disabled. To make it work again, you can set an appropriate value in the kernel.perf\_event\_max\_sample\_rate

kernel parameter, using the sysctl utility.

Should you want to disable this mechanism, you can set the kernel.perf\_cpu\_time\_max\_percent parameter to zero. Be sure to read what this would do, as it may have serious consequences that you should be aware of.

<a name="_page49_x63.64_y506.03"></a>**3.14.5.1 Wait stacks**

The sampling functionality also captures call stacks for context switch events. Such call stacks will show you what the application was doing when the thread was suspended and subsequently resumed, hence the name. We can categorize wait stacks into the following categories:

1. Random preemptive multitasking events, which are expected and do not have any significance.
1. Expected waits, which may be caused by issuing sleep commands, waiting for a lock to become available, performing I/O, and so on. Quantitative analysis of such events may (but probably won’t) direct you to some problems in your code.
1. Unexpected waits, which should be immediately taken care of. After all, what’s the point of profiling and optimizing your program if it is constantly waiting for something? An example of such an unexpected wait may be some anti-virus service interfering with each of your fileread operations. In this case, you could have assumed that the system would buffer a large chunk of the data after the first read to make it immediately available to the application in the following calls.![ref11]

`  `The<a name="_page49_x77.98_y730.94"></a> maximum sampling frequency is limited by the kernel.perf\_event\_max\_sample\_rate sysctl parameter.

**Platform differences![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.079.png)**

Wait stacks capture happen at a different time on the supported operating systems due to differences in the implementation details. For example, on Windows, the stack capture will occur when the program execution is resumed. However, on Linux, the capture will happen when the scheduler decides to preempt execution.

6. **Hardware<a name="_page50_x63.64_y177.15"></a> sampling**

While the call stack sampling is a generic software-implemented functionality of the operating system, there’s another way of sampling program execution patterns. Modern processors host a wide array of different hardware performance counters, which increase when some event in a CPU core happens. These could be as simple as counting each clock cycle or as implementation-specificas counting ’retired instructions that are delivered to the back-end after the front-end had at least 1 bubble-slot for a period of 2 cycles’.

Tracy can use these counters to present you the following three statistics, which may help guide you in discovering why your code is not as fast as possible:

1. *Instructions Per Cycle (IPC)* – shows how many instructions were executing concurrently within a single core cycle. Higher values are better. The maximum achievable value depends on the design of the CPU, including things such as the number of execution units and their individual capabilities. Calculated as #instructions retired . You can disable it with the TRACY\_NO\_SAMPLE\_RETIREMENTmacro.

#cycles

2. *Branch miss rate*– shows how frequently the CPU branch predictor makes a wrong choice. Lower values are better. Calculated as #branch misses~~ . You can disable it with the TRACY\_NO\_SAMPLE\_BRANCHmacro.

#branch instructions

3. *Cache miss rate*– shows how frequently the CPU has to retrieve data from memory. Lower values are better. The specificsof which cache level is taken into account here vary from one implementation to another. Calculated as #cache misses~~ . You can disable it with the TRACY\_NO\_SAMPLE\_CACHEmacro.

#cache references

Each performance counter has to be collected by a dedicated Performance Monitoring Unit (PMU). However, the availability of PMUs is very limited, so you may not be able to capture all the statistics mentioned above at the same time (as each requires capture of two different counters). In such a case, you will need to manually select what needs to be sampled with the macros specifiedabove.

If the provided measurements are not specific enough for your needs, you will need to use a profiler better tailored to the hardware you are using, such as Intel VTune, or AMD Prof.

Another problem to consider here is the measurement skid. It is pretty hard to accurately pinpoint the exact assembly instruction which has caused the counter to trigger. Due to this, the results you’ll get may look a bit nonsense at times. For example, a branch miss may be attributed to the multiply instruction. Unfortunately, not much can be done with that, as this is exactly what the hardware is reporting. The amount of skid you will encounter depends on the specificimplementation of a processor, and each vendor has its own solution to minimize it. Intel uses Precise Event Based Sampling (PEBS), which is rather good, but it still can, for example, blend the branch statistics across the comparison instruction and the following jump instruction. AMD employs its own Instruction Based Sampling (IBS), which tends to provide worse results in comparison.

Do note that the statistics presented by Tracy are a combination of two randomly sampled counters, so you should take them with a grain of salt. The random nature of sampling   makes[ it](#_page50_x77.98_y705.13) entirely possible to count more branch misses than branch instructions or some other similar silliness. You should always cross-check this data with the count of sampled events to decide if you can reliably act upon the provided values.![ref12]

`  `The<a name="_page50_x77.98_y705.13"></a> hardware counters in practice can be triggered only once per million-or-so events happening.

**Availability** Currently, the hardware performance counter readings are only available on Linux, which also includes the WSL2 layer on Windows  . [Access](#_page51_x77.98_y705.39) to them is performed using the kernel-provided infrastructure, so what you get may depend on how your kernel was configured. This also means that the exact set of supported hardware is not known, as it depends on what has been implemented in Linux itself. At this point, the x86 hardware is fully supported (including features such as PEBS or IBS), and there’s PMU support on a selection of ARM designs. The performance counter data can be captured with no need for privilege elevation.

7. **Executable<a name="_page51_x63.64_y178.80"></a> code retrieval**

Tracy will capture small chunks of the executable image during profilingto enable deep insight into program execution. The retrieved code can be subsequently disassembled to be inspected in detail. The profilerwill perform this functionality only for functions no larger than 128 KB and only if symbol information is present.

The discovery of previously unseen executable code may result in reduced performance of real-time capture. This is especially true when the profiling session had just started. However, such behavior is expected and will go back to normal after several moments.

It would be best to be extra careful when working with non-public code, as parts of your program will be embedded in the captured trace. You can disable the collection of program code by compiling the profiled application with the TRACY\_NO\_CODE\_TRANSFERdefine. You can also strip the code from a saved trace using the update utility (section [4.5.3).](#_page57_x63.64_y503.18)

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.080.png)**

For proper program code retrieval, you can unload no module used by the application during the runtime. See section [3.1.1 for](#_page23_x63.64_y431.91) an explanation.

On Linux, Tracy will override the dlclose function call to prevent shared objects from being unloaded. Note that in a well-behaved program this shouldn’t have any effect, as calling dlclose does not guarantee that the shared object will be unloaded.

8. **Vertical<a name="_page51_x63.64_y455.68"></a> synchronization**

On Windows and Linux, Tracy will automatically capture hardware Vsync events, provided that the application has access to the kernel data (privilege elevation may be needed, see section 3.14.1). [These ](#_page47_x63.64_y549.84)events will be reported as ’[x] Vsync’ frame sets, where x is the identifierof a specificmonitor. Note that hardware vertical synchronization might not correspond to the one seen by your application due to desktop composition, command queue buffering, and so on. Also, in some instances, when there is nothing to update on the screen, the graphic driver may choose to stop issuing screen refresh. As a result, there may be periods where no vertical synchronization events are reported.

Use the TRACY\_NO\_VSYNC\_CAPTUREmacro to disable capture of Vsync events.

15. **Trace<a name="_page51_x63.64_y591.84"></a> parameters**

Sometimes it is desired to change how the profiledapplication behaves during the profilingrun. For example, you may want to enable or disable the capture of frame images without recompiling and restarting your pro- gram. Tobeabletodosoyoumustregisteracallbackfunctionusingthe TracyParameterRegister(callback, data) macro, where callback is a function conforming to the following signature:

void Callback(void \* data, uint32\_t idx, int32\_t val)![ref8]

`  `Y<a name="_page51_x77.98_y705.39"></a>ou may need Windows 11 and the WSL preview from Microsoft Store for this to work.

The data parameter will have the same value as was specified in the macro. The idx argument is an user-definedparameter index and val is the value set in the profileruser interface.

Tospecifyindividualparameters,usethe TracyParameterSetup(idx, name, isBool, val) macro. The idx value will be passed to the callback function for identificationpurposes (Tracy doesn’t care what it’s set to). Nameis the parameter label, displayed on the list of parameters. Finally, isBool determines if val should be interpreted as a boolean value, or as an integer number.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.081.png)**

Usage of trace parameters makes profilingruns dependent on user interaction with the profiler, and thusit’snotrecommendedtobeemployedifaconsistentprofilingenvironmentisdesired. Furthermore, interaction with the parameters is only possible in the graphical profilingapplication but not in the command line capture utility.

16. **Source<a name="_page52_x63.64_y272.11"></a> contents callback**

Tracy performs several data discovery attempts to show you the source filecontents associated with the exe- cuted program, which is explained in more detail in chapter 5.16. [How](#_page80_x63.64_y496.26)ever, sometimes the source filescannot be accessed without your help. For example, you may want to profilea script that is loaded by the game and whichonlyresidesinanarchiveaccessibleonlybyyourprogram. Accordingly,Tracyallowsinsertingyourown custom step at the end of the source discovery chain, with the TracySourceCallbackRegister(callback, data) macro, where callback is a function conforming to the following signature:

char \* Callback(void \* data, const char\* filename, size\_t& size)

The data parameter will have the same value as was specifiedin the macro. The filename parameter contains the filename of the queried source file. Finally, the size parameter is used only as an out-value and does not contain any functional data.

The return value must be nullptr if the input filename is not accessible to the client application. If the filecan be accessed, then the data size must be stored in the size parameter, and the filecontents must be returned in a buffer allocated with the tracy::tracy\_malloc\_fast(size) function. Buffer contents do not need to be null-terminated. If for some reason the already allocated buffer can no longer be used, it must be

freed with the tracy::tracy\_free\_fast(ptr) function.

Transfer of source fileslarger than some unspecified,but reasonably large   t[hreshold](#_page52_x77.98_y726.76) won’t be performed.

17. **Connection<a name="_page52_x63.64_y530.67"></a> status**

To determine if a connection is currently established between the client and the server, you may use the TracyIsConnected macro, which returns a boolean value.

<a name="_page52_x63.64_y589.65"></a>**4 Capturing the data**

After the client application has been instrumented, you will want to connect to it using a server, available either as a headless capture-only utility or as a full-fledged graphical profilinginterface.

1. **Command<a name="_page52_x63.64_y660.98"></a> line**

You can capture a trace using a command line utility contained in the capture directory. To use it you may provide the following parameters:![ref2]

`  `<a name="_page52_x77.98_y726.76"></a>Let’s say around 256 KB sounds reasonable.

- -o output.tracy – the filename of the resulting trace (required).
- -a address – specifiesthe IP address (or a domain name) of the client application (uses localhost if not provided).
- -p port – network port which should be used (optional).
- -f – force overwrite, if output filealready exists.
- -s seconds – number of seconds to capture before automatically disconnecting (optional).

If no client is running at the given address, the server will wait until it can make a connection. During the capture, the utility will display the following information:

- ./capture -a 127.0.0.1 -o trace

Connecting to 127.0.0.1:8086...

Queue delay: 5 ns

Timer resolution: 3 ns

1\.33 Mbps / 40.4% = 3.29 Mbps | Net: 64.42 MB | Mem: 283.03 MB | Time: 10.6 s

The *queue delay*and *timer resolution* parameters are calibration results of timers used by the client. The following line is a status bar, which displays: network connection speed, connection compression ratio, and the resulting uncompressed data rate; the total amount of data transferred over the network; memory usage of the capture utility; time extent of the captured data.

You can disconnect from the client and save the captured trace by pressing Ctrl + C . If you prefer to ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.082.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.083.png)disconnect after a fixed time, use the -s seconds parameter.

2. **Interactive<a name="_page53_x63.64_y391.20"></a> profiling**

If you want to look at the profiledata in real-time (or load a saved trace file),you can use the data analysis utility contained in the profiler directory. After starting the application, you will be greeted with a welcome dialog (figure[9), ](#_page54_x63.64_y84.43)presenting a bunch of useful links (  *User manual*,  *Web*,  *Join chat*and ♥ *Sponsor*). The   *Web* button opens a drop-down list with links to the profiler’s *Home page*and a bunch of  *Feature videos*.

The client *address entry* fieldand the  *Connect* button are used to connect to a running client [ .](#_page53_x77.98_y682.94) You can use the connection history button  to display a list of commonly used targets, from which you can quickly select an address. You can remove entries from this list by hovering the  mouse cursor over an entry and ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.084.png)pressing the Del. button on the keyboard.

If you want to open a trace that you have stored on the disk, you can do so by pressing the *Open saved trace*button.

The *discovered clients*list is only displayed if clients are broadcasting their presence on the local network [ . ](#_page53_x77.98_y692.54)Each entry shows the client’s address   [(and](#_page53_x77.98_y702.15) port, if different from the default one), how long the client has been running, and the name of the profiledapplication. Clicking on an entry will connect to the client. Incompatible clients are grayed out and can’t be connected to, but Tracy will suggest a compatible version, if able. Clicking on the  *Filter*toggle button will display client filteringinput fields,allowing removal of the displayed entries according to their address, port number, or program name. If filtersare active, a yellow

warning icon will be displayed.

Both connecting to a client and opening a saved trace will present you with the main profilerview, which you can use to analyze the data (see section 5).![ref11]

<a name="_page53_x63.64_y677.28"></a>  <a name="_page53_x77.98_y682.94"></a><a name="_page53_x77.98_y692.54"></a>Note that a custom port may be provided here, for example by entering ’127.0.0.1:1234’.   <a name="_page53_x77.98_y702.15"></a>Only on IPv4 network and only within the broadcast domain.

`  `Either as an IP address or as a hostname, if able to resolve.

<a name="_page54_x63.64_y84.43"></a>♥ Address![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.085.png) entry

Connect Open trace

Discovered clients: 127.0.0.1 | 21 s | Application

**Figure 9:** *Welcome dialog.*

1. **Connection information pop-up**

If this is a real-time capture, you will also have access to the connection information pop-up (figure 10) through the  *Connection* button, with the capture status similar to the one displayed by the command-line utility. This dialog also shows the connection speed graphed over time and the profiledapplication’s current frames per second and frame time measurements. The *Query backlog* consists of two numbers. The first represents the number of queries that were held back due to the bandwidth volume overwhelming the available network send buffer. The second one shows how many queries are in-flight,meaning requests sent to the client but not yet answered. While these numbers drain down to zero, the performance of real time profilingmay be temporarily compromised. The circle displayed next to the bandwidth graph signals the connection status. If it’s red, the connection is active. If it’s gray, the client has disconnected.

You can use the  *Save trace*button to save the current profiledata to a file [ .](#_page54_x77.98_y701.45) The available compression modes are discussed in sections [4.5.1 and](#_page55_x63.64_y526.55) [4.5.2. Use](#_page57_x63.64_y357.28) the  *Stop* button to disconnect from the client [ .](#_page54_x77.98_y721.00) The

*Discard* button is used to discard current trace.

<a name="_page54_x63.64_y404.39"></a>Connected to: 127.0.0.1![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.086.png)

Bandwidth graph 1.33 Mbps

Ratio 40.4% Real: 3.29 Mbps Data transferred: 23.11 MB Query backlog: 0 + 12

FPS: 60 Frame time: 16.7 ms

`  `Save trace  Stop Discard **Figure 10:** *Connection information pop-up.*

If frame image capture has been implemented (chapter 3.3.3),[ a thumbnail](#_page25_x63.64_y375.56) of the last received frame image will be provided for reference.

Suppose the profiledapplication opted to provide trace parameters (see section 3.15) [and the](#_page51_x63.64_y591.84) connection is still active. In that case, this pop-up will also contain a *trace parameters*section, listing all the provided options. A callback function will be executed on the client when you change any value here.

2. **Automatic<a name="_page54_x63.64_y613.27"></a> loading or connecting**

You can pass the trace filename as an argument to the profilerapplication to open the capture, skipping the welcome dialog. You can also use the -a address argument to connect to the given address automatically. Finally, to specify the network port, pass the -p port parameter. The profilerwill use it for client connections (overridable in the UI) and for listening to client discovery broadcasts.![ref9]

<a name="_page54_x63.64_y696.23"></a>  Y<a name="_page54_x77.98_y701.45"></a>ou should take this literally. If a live capture is in progress and a save is performed, some data may be missing from the capture and<a name="_page54_x77.98_y721.00"></a> won’t be saved.

`  `While requesting disconnect stops retrieval of any new events, the profilerwill wait for any data that is still pending for the current set of events.

3. **Connection speed**

Tracy network bandwidth requirements depend on the amount of data collection the profiledapplication performs. You may expect anything between 1 Mbps and 100 Mbps data transfer rate in typical use case scenarios.

The maximum attainable connection speed is determined by the ability of the client to provide data and the ability of the server to process the received data. In an extreme conditions test performed on an i7 8700K, the maximum transfer rate peaked at 950 Mbps. In each second, the profilercould process 27 million zones <a name="_page55_x63.64_y195.48"></a>and consume 1 GB of RAM.

4. **Memory usage**

The captured data is stored in RAM and only written to the disk when the capture finishes. This can result in memory exhaustion when you capture massive amounts of profiledata or even in typical usage situations when the capture is performed over a long time. Therefore, the recommended usage pattern is to perform moderate instrumentation of the client code and limit capture time to the strict necessity.

In some cases, it may be helpful to perform an *on-demand* capture, as described in section [2.1.2. In](#_page12_x63.64_y720.61) such a case, you will be able to profileonly the exciting topic (e.g., behavior during loading of a level in a game), ignoring all the unneeded data.

If you genuinely need to capture large traces, you have two options. Either buy more RAM or use a large swap fileon a fast disk drive  .

5. **Trace<a name="_page55_x63.64_y346.07"></a> versioning**

Each new release of Tracy changes the internal format of trace files. While there is a backward compatibility layer, allowing loading traces created by previous versions of Tracy in new releases, it won’t be there forever. You are thus advised to upgrade your traces using the utility contained in the update directory.

To use it, you will need to provide the input file and the output file. The program will print a short summary when it finishes,with information about trace fileversions, their respective sizes and the output trace filecompression ratio:

- ./update old.tracy new.tracy

old.tracy (0.3.0) {916.4 MB} -> new.tracy (0.4.0) {349.4 MB, 31.53%} 9.7 s, 38.13% change

The new filecontains the same data as the old one but with an updated internal representation. Note that the whole trace needs to be loaded to memory to perform an upgrade.

1. **Archival<a name="_page55_x63.64_y526.55"></a> mode**

The update utility supports optional higher levels of data compression, which reduce disk size of traces at the cost of increased compression times. The output fileshave a reasonable size and are quick to save and load with the default settings. A list of available compression modes and their respective results is available in table [7 ](#_page56_x63.64_y84.43)and figures[11, ](#_page57_x63.64_y96.39)[12 and](#_page57_x304.66_y96.39) [13. The](#_page56_x63.64_y464.51) following command-line options control compression mode selection:

- -h – enables LZ4 HC compression.
- -e – uses LZ4 extreme compression.
- -z level – selects Zstandard algorithm, with a specifiedcompression level.![ref14]

`  `The<a name="_page55_x77.98_y688.86"></a> operating system can manage memory paging much better than Tracy would be ever able to.



|<a name="_page56_x63.64_y84.43"></a>**Mode**|**Size**|**Ratio**|**Save time**|**Load time**|
| - | - | - | - | - |
|*default* hc extreme|<p>162\.48 MB</p><p>77\.33 MB</p><p>72\.67 MB</p>|17\.19% 8.18% 7.68%|<p>1\.91 s</p><p>39\.24 s 4:30</p>|470 ms 401 ms 406 ms|
|zstd 1 zstd 2 zstd 3 zstd 4 zstd 5 zstd 6 zstd 7 zstd 8 zstd 9 zstd 10 zstd 11 zstd 12 zstd 13 zstd 14 zstd 15 zstd 16 zstd 17 zstd 18 zstd 19 zstd 20 zstd 21 zstd 22|<p>63\.17 MB</p><p>63\.29 MB</p><p>62\.94 MB</p><p>62\.81 MB</p><p>61\.04 MB</p><p>60\.27 MB</p><p>61\.53 MB</p><p>60\.44 MB</p><p>59\.58 MB</p><p>59\.36 MB</p><p>59\.2 MB</p><p>58\.51 MB</p><p>56\.16 MB</p><p>55\.76 MB</p><p>54\.65 MB</p><p>50\.94 MB</p><p>50\.18 MB</p><p>49\.91 MB</p><p>46\.99 MB</p><p>46\.81 MB</p><p>45\.77 MB</p><p>45\.52 MB</p>|<p>6\.68% 6.69% 6.65% 6.64% 6.45% 6.37%</p><p>6\.5% 6.39% 6.3% 6.28% 6.26% 6.19% 5.94% 5.89% 5.78% 5.38% 5.30% 5.28% 4.97% 4.95% 4.84% 4.81%</p>|<p>2\.27 s</p><p>2\.31 s</p><p>2.43 s</p><p>2.44 s</p><p>3\.98 s</p><p>4\.19 s</p><p>6\.6 s</p><p>7\.84 s</p><p>9\.6 s</p><p>10\.29 s</p><p>11\.23 s</p><p>15\.43 s</p><p>35\.55 s</p><p>37\.74 s 1:01 1:34 1:44 2:17 7:09 7:08 13:01 15:11</p>|868 ms 884 ms 867 ms 855 ms 855 ms 827 ms 761 ms 746 ms 724 ms 706 ms 717 ms 695 ms 642 ms 627 ms 600 ms 537 ms 542 ms 554 ms 605 ms 608 ms 614 ms 621 ms|

**Table 7:** *Compression results for an example trace.*

*Tests performed on Ryzen 9 3900X.*

<a name="_page56_x63.64_y464.51"></a>900 ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.088.png)

800 

700 

600 

Time(ms) zstd 500 default

hc

400 extreme

0 5 10 15 20 25

Mode

**Figure 13:** *Plot of trace load times for different compression modes (see t[able ](#_page56_x63.64_y84.43)7).*

Trace filescreated using the *default*, *hc* and *extreme* modes are optimized for fast decompression and can be further compressed using filecompression utilities. For example, using 7-zip results in archives of the following sizes: 77.2 MB, 54.3 MB, 52.4 MB.

For archival purposes, it is, however, much better to use the *zstd* compression modes, which are

59
Tracy Profiler The user manual![ref1]

zstd ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.089.png)150 default

hc extreme

100

Size(MB)

50

0 5 10 15 20 25

<a name="_page57_x63.64_y96.39"></a><a name="_page57_x304.66_y96.39"></a>103 zstd default

hc![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.090.png)

102 extreme Time(s)

101

0 5 10 15 20 25

60
Tracy Profiler The user manual![ref1]

Mode Mode

**Figure 11:** *Plot of trace sizes for different compression modes* **Figure 12:** *Logarithmic plot of trace compression times for*

*(see table 7). different compression modes (see table 7).*

faster, compress trace filesmore tightly, and are directly loadable by the profiler, without the intermediate decompression step.

2. **Frame<a name="_page57_x63.64_y357.28"></a> images dictionary**

Frame images have to be compressed individually so that there are no delays during random access to the contents of any image. Unfortunately, because of this, there is no reuse of compression state between similar (or even identical) images, which leads to increased memory consumption. The profilercan partially remedy this by enabling the calculation of an optional frame images dictionary with the -d command line parameter.

Saving a trace with frame images dictionary-enabled will need some extra time, depending on the amount of image data you have captured. Loading such a trace will also be slower, but not by much. How much RAM the dictionary will save depends on the similarity of frame images. Be aware that post-processing effects such as artificialfilmgrain have a subtle impact on image contents, which is significantin this case.

The dictionary cannot be used when you are capturing a trace.

3. **Data<a name="_page57_x63.64_y503.18"></a> removal**

In some cases you may want to share just a portion of the trace file,omitting sensitive data such as source file cache, or machine code of the symbols. This can be achieved using the -s flags command line option. To select what kind of data is to be stripped, you need to provide a list of flagsselected from the following:

- l – locks.
- m– messages.
- p – plots.
- M– memory.
- i – frame images.
- c – context switches.
- s – sampling data.
- C– symbol code.
- S – source filecache.

Flags can be concatenated. For example specifying -s CSi will remove symbol code, source filecache, and frame images in the destination trace file.

6. **Source<a name="_page58_x63.64_y138.55"></a> filecache scan**

Sometimes access to source filesmay not be possible during the capture. This may be due to capturing the trace on a machine without the source fileson disk, use of paths relative to the build directory, clash of file location schemas (e.g., on Windows, you can have native paths, like C:\directory\file and WSL paths, like /mnt/c/directory/file, pointing to the same file),and so on.

You may force a recheck of the source fileavailability during the update process with the -c command line parameter. All the source filesmissing from the cache will be then scanned again and added to the cache if they do pass the validity checks (see section [5.16).](#_page80_x63.64_y496.26)

7. **Instrumentation<a name="_page58_x63.64_y261.44"></a> failures**

In some cases, your program may be incorrectly instrumented. For example, you could have unbalanced zone begin and end events or report a memory-free event without first reporting a memory allocation event. When Tracy detects such misbehavior, it immediately terminates the connection with the client and displays an error message.

<a name="_page58_x63.64_y346.67"></a>**5 Analyzing captured data**

You have instrumented your application, and you have captured a profilingtrace. Now you want to look at the collected data. You can do this in the application contained in the profiler directory.

The workflow is identical, whether you are viewing a previously saved trace or if you’re performing a live capture, as described in section 4.2.

1. **Time<a name="_page58_x63.64_y441.97"></a> display**

In most cases Tracy will display an approximation of time value, depending on how big it is. For example, a short time range will be displayed as 123 ns, and some longer ones will be shortened to 123.45 s, 123.45 ms, 12.34 s, 1:23.4, 12:34:56, or even 1d12:34:56 to indicate more than a day has passed.

While such a presentation makes time values easy to read, it is not always appropriate. For example, you may have multiple events happen at a time approximated to 1:23.4, giving you the precision of only 1/10 of a second. And there’s certainly a lot that can happen in 100 ms.

An alternative time display is used in appropriate places to solve this problem. It combines a day–hour–       minute–second value with full nanosecond resolution, resulting in values such as 1:23 456,789,012 ns.

2. **Main<a name="_page58_x63.64_y577.41"></a> profilerwindow**

The main profilerwindow is split into three sections, as seen in figure14: the[ control](#_page59_x63.64_y84.43) menu, the frame time graph, and the timeline display.

1. **Control<a name="_page58_x63.64_y637.54"></a> menu**

The control menu (top row of buttons) provides access to various profilerfeatures. The buttons perform the following actions:

- *Connection* – Opens the connection information popup (see section 4.2.1).[ Onl](#_page53_x63.64_y677.28)y available when live capture is in progress.



||
| :- |
|<a name="_page59_x63.64_y84.43"></a>  Options Messages Find zone Statistics  Memory  Compare  Info ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.091.png) Frames: 364 ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.092.png) 52.7 ms  6.06 s 195.2 MB Notificationarea|
|Frame time graph|
|Timeline view|

**Figure 14:** *Main profilerwindow. Note that this manual has split the top line of buttons into two rows.*

- *Close*– This button unloads the current profiling trace and returns to the welcome menu, where another trace can be loaded. In live captures it is replaced by  *Pause*,  *Resume* and  *Stopped* buttons.
- *Pause*– While a live capture is in progress, the profilerwill display recent events, as either the last three fully captured frames, or a certain time range. You can use this to see the current behavior of the program. The pause button   [will](#_page59_x77.98_y716.24) stop the automatic updates of the timeline view (the capture will still be progressing).
- *Resume* – This button allows to resume following the most recent events in a live capture. You will have selection of one of the following options:  *Newest three frames*, or  *Use current zoom level*.
- *Stopped* – Inactive button used to indicate that the client application was terminated.
- *Options* – Toggles the settings menu (section [5.4).](#_page67_x63.64_y452.14)
- *Messages*– Toggles the message log window (section [5.5), which](#_page68_x63.64_y696.73) displays custom messages sent by the client, as described in section [3.7.](#_page33_x63.64_y190.70)
- *Find zone* – This buttons toggles the findzone window, which allows inspection of zone behavior statistics (section [5.7).](#_page71_x63.64_y132.43)
- *Statistics* – Toggles the statistics window, which displays zones sorted by their total time cost (section [5.6).](#_page69_x63.64_y377.90)
- *Memory* – Various memory profilingoptions may be accessed here (section 5.9).
- *Compare*– Toggles the trace compare window, which allows you to see the performance difference between two profilingruns (section [5.8).](#_page74_x63.64_y280.93)
- *Info* – Show general information about the trace (section 5.12).
- *Tools*– Allows access to optional data collected during capture. Some choices might be unavailable.
- *Playback*– If frame images were captured (section [3.3.3), you](#_page25_x63.64_y375.56) will have option to open frame image playback window, described in chapter 5.19.
- *CPU data*– If context switch data was captured (section [3.14.3), this](#_page48_x63.64_y261.96) button will allow inspecting what was the processor load during the capture, as described in section 5.20.![ref12]

`  `<a name="_page59_x77.98_y716.24"></a>Or perform any action on the timeline view, apart from changing the zoom level.

- *Annotations* – If annotations have been made (section [5.3.1), you](#_page67_x63.64_y202.61) can open a list of all annotations, described in chapter [5.22.](#_page86_x63.64_y687.84)
- *Limits* – Displays time range limits window (section 5.3).
- *Wait stacks* – If sampling was performed, an option to display wait stacks may be available. See chapter [3.14.5.1 f](#_page49_x63.64_y506.03)or more details.
- *Displayscale*–Enablesrun-timeresizingofthedisplayedcontent. Thismaybeusefulinenvironments with potentially reduced visibility, e.g. during a presentation. Note that this setting is independent to the UI scaling coming from the system DPI settings.

The frame information block   [consis](#_page60_x77.98_y718.38)ts of four elements: the current frame set name along with the        number of captured frames (click on it with the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.093.png)left mouse button to go to a specifiedframe), the two

navigational buttons  and , which allow you to focus the timeline view on the previous or next frame, and the frame set selection button , which is used to switch to another frame set  . F[or ](#_page60_x77.98_y727.99)more information about marking frames, see section [3.3.](#_page24_x63.64_y581.52)

The following three items show the *view time range*, the  *time span* of the whole capture (clicking on it with the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.094.png)middle mouse button will set the view range to the entire capture), and the *memory usage* of

the profiler.

<a name="_page60_x63.64_y320.27"></a>**5.2.1.1 Notificationarea**

The notification area displays informational notices, for example, how long it took to load a trace from the disk. A pulsating dot next to the icon indicates that some background tasks are being performed that may need to be completed before full capabilities of the profilerare available. If a crash was captured during profiling(section [2.5), a](#_page21_x63.64_y703.26) *crash*icon will be displayed. The red icon indicates that queries are currently being backlogged, while the same yellow icon indicates that some queries are currently in-flight (see chapter [4.2.1 f](#_page53_x63.64_y677.28)or more information).

If the drawing of timeline elements was disabled in the options menu (section 5.4), the[ profiler](#_page67_x63.64_y452.14)will use the following orange icons to remind you about that fact. Click on the icons to enable drawing of the selected elements. Note that collapsed labels (section [5.2.3.3) are](#_page62_x63.64_y526.21) not taken into account here.

- – Display of empty labels is enabled.
- – Context switches are hidden.
- – CPU data is hidden.
- – GPU zones are hidden.
- – CPU zones are hidden.
- – Locks are hidden.
- – Plots are hidden.
- – Ghost zones are not displayed.
- – At least one timeline item (e.g. a single thread, a single plot, a single lock, etc.) is hidden.
2. **Frame<a name="_page60_x63.64_y664.66"></a> time graph**

The graph of the currently selected frame set (figure15) [pro](#_page61_x63.64_y84.43)vides an outlook on the time spent in each frame, allowing you to see where the problematic frames are and to navigate to them quickly.![ref8]

`  `V<a name="_page60_x77.98_y727.99"></a><a name="_page60_x77.98_y718.38"></a>isible only if frame instrumentation was included in the capture.   See section [5.2.3.2 f](#_page62_x63.64_y185.12)or another way to change the active frame set.



|||||||||||||||||||||||
| :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- | :- |
|||||||||||||||||||||||
|||||||||||||||||||||||
|||||||||||||||||||||||
<a name="_page61_x63.64_y84.43"></a>**Figure 15:** *Frame time graph.*

Each bar displayed on the graph represents a unique frame in the current frame set  . The [prog](#_page61_x77.98_y730.94)ress of time is in the right direction. The bar height indicates the time spent in the frame, complemented by the color information, which depends on the target FPS value. You can set the desired FPS in the options menu (see section [5.4).](#_page67_x63.64_y452.14)

- If the bar is *blue*, then the frame met the *best* time of twice the target FPS (represented by the green target line).
- If the bar is *green*, then the frame met the *good*time of target FPS (represented by the yellow line).
- If the bar is *yellow*, then the frame met the *bad*time of half the FPS (represented by the red target line).
- If the bar is *red*, then the frame didn’t meet any time limits.

The frames visible on the timeline are marked with a violet box drawn over them.

When a zone is displayed in the findzone window (section 5.7), t[he ](#_page71_x63.64_y132.43)coloring of frames may be changed, as described in section [5.7.2.](#_page73_x63.64_y533.65)

Moving the  mouse cursor over the frames displayed on the graph will display a tooltip with information about frame number, frame time, frame image (if available, see chapter 3.3.3),[ etc. ](#_page25_x63.64_y375.56)Such tooltips are common for many UI elements in the profilerand won’t be mentioned later in the manual.

You may focus the timeline view on the frames by clicking or dragging the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.095.png)left mouse button on the graph. The graph may be scrolled left and right by dragging the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.096.png)right mouse button over the graph.

Finally, you may zoom the view in and out by using the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.097.png)mouse wheel. If the view is zoomed out, so that multiple frames are merged into one column, the profilerwill use the highest frame time to represent the given column.

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.098.png)left mouse button on the graph while the Ctrl key is pressed will open the frame image ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.099.png)playback window (section [5.19) and](#_page86_x63.64_y316.58) set the playback to the selected frame. See section 3.3.3 for[ more ](#_page25_x63.64_y375.56)information about frame images.

3. **Timeline<a name="_page61_x63.64_y494.12"></a> view**

The timeline is the most crucial element of the profiler UI. All the captured data is displayed there, laid out on the horizontal axis, according to time flow. Where there was no profilingperformed, the timeline is dimmed out. The view is split into three parts: the time scale, the frame sets, and the combined zones, locks, and plots display.

**Collapsed items** Due to extreme differences in time scales, you will almost constantly see events too small to be displayed on the screen. Such events have preset minimum size (so they can be seen) and are marked with a zig-zag pattern to indicate that you need to zoom in to see more detail.

The zig-zag pattern can be seen applied to frame sets on figure17, [and zones](#_page62_x63.64_y250.65) on figure18.

1. **Time<a name="_page61_x63.64_y641.01"></a> scale**

The time scale is a quick aid in determining the relation between screen space and the time it represents (figure[16).](#_page62_x63.64_y84.43)

The leftmost value on the scale represents when the timeline starts. The rest of the numbers label the notches on the scale, with some numbers omitted if there’s no space to display them.![ref11]

`  `<a name="_page61_x77.98_y730.94"></a>Unless the view is zoomed out and multiple frames are merged into one column.

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.100.png)

<a name="_page62_x63.64_y84.43"></a>+13.76 s 20 s 40 s 60 s 80 s 100 s

**Figure 16:** *Time scale.*

Hovering the  mouse pointer over the time scale will display a tooltip with the exact timestamp at the position of the mouse cursor.

2. **Frame<a name="_page62_x63.64_y185.12"></a> sets**

Frames from each frame set are displayed directly underneath the time scale. Each frame set occupies a separate row. The currently selected frame set is highlighted with bright colors, with the rest dimmed out.

<a name="_page62_x63.64_y250.65"></a>Frame 312 (6.99 ms) Frame 347 (5.24 ms) 1.63 ms![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.101.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.102.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.103.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.104.png)

**Figure 17:** *Frames on the timeline.*

In figure [17 w](#_page62_x63.64_y250.65)e can see the fully described frames 312 and 347. The description consists of the frame name, which is *Frame*for the default frame set (section [3.3) or](#_page24_x63.64_y581.52) the name you used for the secondary name set (section [3.3.1),](#_page25_x63.64_y90.71) the frame number, and the frame time. Since frame 348 is too small to be fully labeled, only the frame time is shown. On the other hand, frame 349 is even smaller, with no space for any text. Moreover, frames 313 to 346 are too small to be displayed individually, so they are replaced with a zig-zag pattern, as described in section [5.2.3.](#_page61_x63.64_y494.12)

You can also see frame separators are projected down to the rest of the timeline view. Note that only the separators for the currently selected frame set are displayed. You can make a frame set active by clicking the

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.105.png)left mouse button on a frame set row you want to select (also see section 5.2.1).![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.106.png)

Clicking the middle mouse button on a frame will zoom the view to the extent of the frame.

If a frame has an associated frame image (see chapter [3.3.3), you](#_page25_x63.64_y375.56) can hold the Ctrl key and click the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.107.png)left mouse button on ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.108.png)the frame to open the frame image playback window (see chapter 5.19) [and set ](#_page86_x63.64_y316.58)the playback to the selected frame.

If the  *Draw frame targets* option is enabled (see section [5.4), time](#_page67_x63.64_y452.14) regions in frames exceeding the set target value will be marked with a red background.

3. **Zones,<a name="_page62_x63.64_y526.21"></a> locks and plots display**

You will findthe zones with locks and their associated threads on this combined view. The plots are graphed right below.

The left-hand side *index area*of the timeline view displays various labels (threads, locks), which can be categorized in the following way:

- *Light blue label* – GPU context. Multi-threaded Vulkan, OpenCL, and Direct3D 12 contexts are additionally split into separate threads.
- *Pink label*– CPU data graph.
- *White label* – A CPU thread. It will be replaced by a bright red label in a thread that has crashed ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.109.png)(section [2.5).](#_page21_x63.64_y703.26) If automated sampling was performed, clicking the left mouse button on the  *ghost zones* button will switch zone display mode between ’instrumented’ and ’ghost.’
- *Green label*– Fiber, coroutine, or any other sort of cooperative multitasking ’green thread.’

<a name="_page63_x63.64_y84.43"></a>Main thread![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.110.png)

Update Render 6![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.111.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.112.png) Physics

Physics lock ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.113.png)

Streaming thread![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.114.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.115.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.116.png)

Streaming job Streaming job![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.117.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.118.png)

Load image

**Figure 18:** *Zones and locks display.*

- *Light red label*– Indicates a lock.
- *Yellow label*– Plot.

Labels accompanied by the  symbol can be collapsed out of the view to reduce visual clutter. Hover        the  mouse pointer over the label to display additional information. Click the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.119.png)middle mouse button on a title to zoom the view to the extent of the label contents. Finally, click the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.120.png)right mouse button on a label to

display the context menu with available actions:

- *Hide* – Hides the label along with the content associated to it. To make the label visible again, you must findit in the options menu (section 5.4).

**Zones** In an example in figure 18[ you](#_page63_x63.64_y84.43) can see that there are two threads: *Main thread* and *Streaming thread[  .](#_page63_x77.98_y728.94)* We can see that the *Main thread* has two root level zones visible: *Update* and *Render*. The *Update* zone is split into further sub-zones, some of which are too small to be displayed at the current zoom level.

This is indicated by drawing a zig-zag pattern over the merged zones box (section 5.2.3), [with t](#_page61_x63.64_y494.12)he number of collapsed zones printed in place of the zone name. We can also see that the *Physics* zone acquires the *Physics lock*mutex for most of its run time.

Meanwhile, the *Streaming thread* is performing some *Streaming jobs*. The first *Streaming job* sent a message (section [3.7).](#_page33_x63.64_y190.70) In addition to being listed in the message log, it is indicated by a triangle over the thread separator. When multiple messages are in one place, the triangle outline shape changes to a filledtriangle.

The GPU zones are displayed just like CPU zones, with an OpenGL/Vulkan/Direct3D/OpenCL context in place of a thread name.

Hovering the  mouse pointer over a zone will highlight all other zones that have the exact source location

with a white outline. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.121.png)left mouse button on a zone will open the zone information window (section [5.13).](#_page78_x63.64_y165.60) Holding the Ctrl key and clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.122.png)left mouse button on a zone will open the zone ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.123.png)statistics window (section [5.7). ](#_page71_x63.64_y132.43)Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.124.png)middle mouse button on a zone will zoom the view to the

extent of the zone.

**Ghost zones** You can enable the view of ghost zones (not pictured on figure18, [but similar](#_page63_x63.64_y84.43) to standard zones view) by clicking on the  *ghost zones* icon next to the thread label, available if automated sampling (see chapter [3.14.5) ](#_page49_x63.64_y158.34)was performed. Ghost zones will also be displayed by default if no instrumented zones are available for a given thread to help with pinpointing functions that should be instrumented.![ref11]

`  `<a name="_page63_x77.98_y728.94"></a>By clicking on a thread name, you can temporarily disable the display of the zones in this thread.

Ghost zones represent true function calls in the program, periodically reported by the operating system. Due to the limited sampling resolution, you need to take great care when looking at reported timing data. While it may be apparent that some small function requires a relatively long time to execute, for example, 125 s (8 kHz sampling rate), in reality, this time represents a period between taking two distinct samples, not the actual function run time. Similarly, two (or more) separate function calls may be represented as a single ghost zone because the profilerdoesn’t have the information needed to know about the actual lifetime of a sampled function.

Another common pitfall to watch for is the order of presented functions. *It is not what you expect it to be!* Read chapter [5.14.1 f](#_page79_x63.64_y645.14)or critical insight on how call stacks might seem nonsensical at first and why they aren’t.

The available information about ghost zones is quite limited, but it’s enough to give you a rough outlook on the execution of your application. The timeline view alone is more than any other statistical profiler can present. In addition, Tracy correctly handles inlined function calls, which are indicated by a darker backgroundofghostzones. Lastly, zonesrepresentingkernel-modefunctionsaredisplayedwithredfunction names. ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.125.png)

Clicking the left mouse button on a ghost zone will open the corresponding source filelocation, if able (see chapter [5.16 f](#_page80_x63.64_y496.26)or conditions). There are three ways in which source locations can be assigned to a ghost zone:

1. If the selected ghost zone is *not* an inline frame and its symbol data has been retrieved, the source location points to the function entry location (first line of the function).
1. If the selected ghost zone is *not* an inline frame, but its symbol data is not available, the source location will point to a semi-random location within the function body (i.e. to one of the sampled addresses in the program, but not necessarily the one representing the selected time stamp, as multiple samples with different addresses may be merged into one ghost zone).
1. If<a name="_page64_x63.64_y401.56"></a> the selected ghost zone *is* an inline frame, the source location will point to a semi-random location within the inlined function body (see details in the above point). It is impossible to go to such a function’s entry location, as it doesn’t exist in the program binary. Inlined functions begin in the parent function.

**Call stack samples** The row of dots right below the *Main thread* label shows call stack sample points, which may have been automatically captured (see chapter 3.14.5[ for more](#_page49_x63.64_y158.34) detail). Hovering the  mouse pointer over each dot will display a short call stack summary while clicking on the dot with the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.126.png)left mouse button will open a more detailed call stack information window (see section 5.14).

**Contextswitches** Thethicklinerightbelowthesamplesrepresentscontextswitchdata(seesection3.14.3). We can see that the main thread, as displayed, starts in a suspended state, represented by the dotted region. Then it is woken up and starts execution of the Update zone. It is preempted amid the physics processing, which explains why there is an empty space between child zones. Then it is resumed again and continues execution into the Render zone, where it is preempted again, but for a shorter time. After rendering is done, the thread sleeps again, presumably waiting for the vertical blanking to indicate the next frame. Similar information is also available for the streaming thread.

Context switch regions are using the following color key:

- *Green*– Thread is running.
- *Red* – Thread is waiting to be resumed by the scheduler. There are many reasons why a thread may be in the waiting state. Hovering the  mouse pointer over the region will display more information. If sampling was performed, the profilermight display a wait stack. See section 3.14.5.1[ for additional ](#_page49_x63.64_y506.03)details.
- *Blue* – Thread is waiting to be resumed and is migrating to another CPU core. This might have visible performance effects because low-level CPU caches are not shared between cores, which may result in additional cache misses. To avoid this problem, you may pin a thread to a specificcore by setting its affinity.
- *Bronze* – Thread has been placed in the scheduler’s run queue and is about to be resumed. Fiber work and yield states are presented in the same way as context switch regions.

**CPU data** This label is only available if the profiler collected context switch data. It is split into two parts: a graph of CPU load by various threads running in the system and a per-core thread execution display.

The CPU load graph shows how much CPU resources were used at any given time during program execution. The green part of the graph represents threads belonging to the profiledapplication, and the gray part of the graph shows all other programs running in the system. Hovering the  mouse pointer over the graph will display a list of threads running on the CPU at the given time.

Each line in the thread execution display represents a separate logical CPU thread. If CPU topology data is available (see section [3.14.4), ](#_page48_x63.64_y455.18)package and core assignment will be displayed in brackets, in addition to numerical processor identifier(i.e. [package:core] CPU thread). When a core is busy executing a thread, a zone will be drawn at the appropriate time. Zones are colored according to the following key:

- *Bright color*– or *orange*if dynamic thread colors are disabled – Thread tracked by the profiler.
- *Dark blue*– Thread existing in the profiledapplication but not known to the profiler. This may include internal profilerthreads, helper threads created by external libraries, etc.
- *Gray* – Threads assigned to other programs running in the system.

When the  mouse pointer is hovered over either the CPU data zone or the thread timeline label, Tracy will display a line connecting all zones associated with the selected thread. This can be used to quickly see how the thread migrated across the CPU cores.

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.127.png)left mouse button on a tracked thread will make it visible on the timeline if it was either hidden or collapsed before.

Careful examination of the data presented on this graph may allow you to determine areas where the profiledapplication was fightingfor system resources with other programs (see section 2.2.1) or [give y](#_page16_x63.64_y555.45)ou a hint to add more instrumentation macros.

**Locks** Mutual exclusion zones are displayed in each thread that tries to acquire them. There are three color-coded kinds of lock event regions that may be displayed. Note that the contention regions are always displayed over the uncontented ones when the timeline view is zoomed out.

- *Green r[egion*   ](#_page65_x77.98_y730.94)*– The lock is being held solely by one thread, and no other thread tries to access it. In the case of shared locks, multiple threads hold the read lock, but no thread requires a write lock.
- *Yellow region*– The lock is being owned by this thread, and some other thread also wants to acquire the lock.
- *Red region*– The thread wants to acquire the lock but is blocked by other thread or threads in case of a shared lock.

Hovering the  mouse pointer over a lock timeline will highlight the lock in all threads to help read the lock behavior. Hovering the  mouse pointer over a lock event will display important information, for example, a list of threads that are currently blocking or which are blocked by the lock. Clicking the

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.128.png)left mouse button on a lock event or a lock label will open the lock information window, as described in section [5.18. ](#_page86_x63.64_y246.49)Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.129.png)middle mouse button on a lock event will zoom the view to the extent of the

event.![ref11]

`  `This<a name="_page65_x77.98_y730.94"></a> region type is disabled by default and needs to be enabled in options (section 5.4).

**Plots** The numerical data values (figure19)[ are](#_page66_x63.64_y146.39) plotted right below the zones and locks. Note that the minimum and maximum values currently displayed on the plot are visible on the screen, along with the y range of the plot and the number of drawn data points. The discrete data points are indicated with little rectangles. A filledrectangle indicates multiple data points.

<a name="_page66_x63.64_y146.39"></a>Queue size (y-range: 463, visible data points: 7) 731![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.130.png)

268

**Figure 19:** *Plot display.*

When memory profiling(section 3.8)[ is ](#_page33_x63.64_y384.83)enabled, Tracy will automatically generate a *Memory usage* plot, which has extended capabilities. For example, hovering over a data point (memory allocation event)

will visually display the allocation duration. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.131.png)left mouse button on the data point will open the memory allocation information window, which will show the duration of the allocation as long as the window is open.

Another plot that Tracy automatically provides is the *CPU usage*plot, which represents the total system CPU usage percentage (it is not limited to the profiledapplication).

4. **Navigating<a name="_page66_x63.64_y361.93"></a> the view**

Hovering the  mouse pointer over the timeline view will display a vertical line that you can use to line up ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.132.png)events in multiple threads visually. Dragging the left mouse button will display the time measurement of the selected region.

The timeline view may be scrolled both vertically and horizontally by dragging the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.133.png)right mouse button. Note that only the zones, locks, and plots scroll vertically, while the time scale and frame sets always stay on the top.

You can zoom in and out the timeline view by using the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.134.png)mouse wheel. Pressing the Ctrl key will make ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.135.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.136.png)zooming more precise while pressing the key will make it faster. You can select a range to which you want to zoom in by dragging the middle mouse button. Dragging the middle mouse button while the![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.137.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.138.png)![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.139.png)

Ctrl key is pressed will zoom out. ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.140.png)

It is also possible to navigate the timeline using the keyboard. The A and D keys scroll the view to the left and right, respectively. The W and S keys change the zoom level.

3. **Time<a name="_page66_x63.64_y550.49"></a> ranges**

Sometimes, you may want to specify a time range, such as limiting some statistics to a specificpart of your program execution or marking interesting places.

To definea time range, drag the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.141.png)left mouse button over the timeline view while holding the Ctrl key. ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.142.png)When the mouse key is released, the profilerwill mark the selected time extent with a blue striped pattern, and it will display a context menu with the following options:

- *Limit findzone time range* – this will limit findzone results. See chapter 5.7 [for ](#_page71_x63.64_y132.43)more details.
- *Limit statistics time range* – selecting this option will limit statistics results. See chapter 5.6 f[or more ](#_page69_x63.64_y377.90)details.
- *Limit wait stacks time range* – limits wait stacks results. Refer to chapter [5.17.](#_page86_x63.64_y90.71)
- *Limit memory time range* – limits memory results. Read more about this in chapter 5.9.
- *Add annotation* – use to annotate regions of interest, as described in chapter 5.3.1.

Alternatively, you may specify the time range by clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.143.png)right mouse button on a zone or a frame. The resulting time extent will match the selected item.

To reduce clutter, time range regions are only displayed if the windows they affect are open or if the time range limits control window is open (section [5.23). Y](#_page87_x63.64_y335.67)ou can access the time range limits window through the   *Tools*button on the control menu. ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.144.png)

You can freely adjust each time range on the timeline by clicking the left mouse button on the range’s edge and dragging the mouse.

<a name="_page67_x63.64_y202.61"></a>**5.3.1 Annotating the trace**

Tracy allows adding custom notes to the trace. For example, you may want to mark a region to ignore because the application was out-of-focus or a region where a new user was connecting to the game, which resulted in a frame drop that needs to be investigated.

Methods of specifying the annotation region are described in section 5.3. [When ](#_page66_x63.64_y550.49)a new annotation is added, a settings window is displayed (section 5.21),[ allo](#_page86_x63.64_y627.72)wing you to enter a description.

Annotations are displayed on the timeline, as presented in figure20. [Clicking](#_page67_x63.64_y354.19) on the circle next to the text description will open the annotation settings window, in which you can modify or remove the region. List of all annotations in the trace is available in the annotations list window described in section 5.22, [which ](#_page86_x63.64_y687.84)is accessible through the  *Tools*button on the control menu.

<a name="_page67_x63.64_y354.19"></a>Description![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.145.png)

**Figure 20:** *Annotation region.*

Please note that while the annotations persist between profilingsessions, they are not saved in the trace

but in the user data files,as described in section 8.2.

4. **Options<a name="_page67_x63.64_y452.14"></a> menu**

In this window, you can set various trace-related options. For example, the timeline view might sometimes become overcrowded, in which case disabling the display of some profilingevents can increase readability.

- *Draw empty labels* – By default threads that don’t have anything to display at the current zoom level are hidden. Enabling this option will show them anyway.
- *Draw frame targets* – If enabled, time regions in any frame from the currently selected frame set, which exceed the specified *Target FPS* value will be marked with a red background on timeline view.
- *Target FPS* – Controls the option above, but also the frame bar colors in the frame time graph (section [5.2.2).](#_page60_x63.64_y664.66) The color range thresholds are presented in a line directly below.
- *Draw context switches* – Allows disabling context switch display in threads.
- *Darken inactive thread* – If enabled, inactive regions in threads will be dimmed out.
- *Draw CPU data* – Per-CPU behavior graph can be disabled here.
- *Draw CPU usage graph* – You can disable drawing of the CPU usage graph here.
- *Draw GPU zones* – Allows disabling display of OpenGL/Vulkan/Direct3D/OpenCL zones. The *GPU zones* drop-down allows disabling individual GPU contexts and setting CPU/GPU drift offsets of uncalibrated contexts (see section 3.9[ for ](#_page34_x63.64_y620.04)more information). The *Auto* button automatically measures the GPU drift value  .
- *Draw CPU zones* – Determines whether CPU zones are displayed.
- *Draw ghost zones* – Controls if ghost zones should be displayed in threads which don’t have any instrumented zones available.
- *Zone colors*– Zones with no user-set color may be colored according to the following schemes:

`  `*Disabled*– A constant color (blue) will be used.

`  `*Thread dynamic* – Zones are colored according to a thread (identifiernumber) they belong to

and depth level.

`  `*Source location dynamic* – Zone color is determined by source location (function name) and

depth level.

Enablingthe *Ignorecustom*optionwillforceusageoftheselectedzonecoloringscheme,disregarding any colors set by the user in profiledcode.

- *Zone name shortening* – controls display behavior of long zone names, which don’t fitinside a zone box:

`  `*Disabled*– Shortening of zone names is not performed and names are always displayed in full

(e.g. bool ns::container<float>::add(const float&)).

`  `*Minimal length* – Always reduces zone name to minimal length, even if there is space available

for a longer form (e.g. add()).

`  `*Only normalize* – Only performs normalization of the zone name [ ,](#_page68_x77.98_y721.00) but does not remove

namespaces (e.g. ns::container<>::add()).

`  `*As needed* – Name shortening steps will be performed only if there is no space to display a

complete zone name, and only until the name fitsavailable space, or shortening is no longer possible (e.g. container<>::add()).

`  `*As needed + normalize*– Same as above, but zone name normalization will always be performed,

even if the entire zone name fitsin the space available.

Function names in the remaining places across the UI will be normalized unless this option is set to *Disabled*.

- *Draw locks*– Controls the display of locks. If the *Only contended* option is selected, the profilerwon’t displaythenon-blockingregionsoflocks(seesection[5.2.3.3). The](#_page62_x63.64_y526.21) *Locks*drop-downallowsdisablingthe display of locks on a per-lock basis. As a convenience, the list of locks is split into the single-threaded

  and multi-threaded (contended and uncontended) categories. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.146.png)right mouse button on a lock label opens the lock information window (section 5.18).

- *Draw plots* – Allows disabling display of plots. Individual plots can be disabled in the *Plots* drop-down.
- *Visible threads* – Here you can select which threads are visible on the timeline. You can change the display order of threads by dragging thread labels.
- *Visible frame sets*– Frame set display can be enabled or disabled here. Note that disabled frame sets are still available for selection in the frame set selection drop-down (section 5.2.1) [but are](#_page58_x63.64_y637.54) marked with a dimmed font.

Disabling the display of some events is especially recommended when the profilerperformance drops below acceptable levels for interactive usage.![ref9]

<a name="_page68_x63.64_y696.73"></a>  There<a name="_page68_x77.98_y701.45"></a> is an assumption that drift is linear. Automated measurement calculates and removes change over time in delay-to-execution of GPU<a name="_page68_x77.98_y721.00"></a> zones. Resulting value may still be incorrect.

`  `The normalization process removes the function const qualifier, some common return type declarations and all function parameters and template arguments.

5. **Messages window**

Inthiswindow,youcanseeallthemessagesthatweresentbytheclientapplication,asdescribedinsection3.7. The window is split into four columns: *time*, *thread*, *message*and *call stack*. Hovering the  mouse cursor over

a message will highlight it on the timeline view. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.147.png)left mouse button on a message will center the timeline view on the selected message.

The *call stack*column is filledonly if a call stack capture was requested, as described in section 3.11. A single entry consists of the  *Show* button, which opens the call stack information window (chapter 5.14) [and ](#_page79_x63.64_y262.70)of abbreviated information about the call path.

If the  *Show frame images* option is selected, hovering the  mouse cursor over a message will show a tooltip containing frame image (see section [3.3.3) associated](#_page25_x63.64_y375.56) with a frame in which the message was issued, if available.

The message list will automatically scroll down to display the most recent message during live capture. You can disable this behavior by manually scrolling the message list up. The auto-scrolling feature will be enabled again when the view is scrolled down to display the last message.

You can filterthe message list in the following ways:

- By the originating thread in the  *Visible threads* drop-down.
- By matching the message text to the expression in the *Filter messages*entry field. Multiple filter expressions can be comma-separated (e.g. ’warn, info’ will match messages containing strings ’warn’ *or*’info’). You can exclude matches by preceding the term with a minus character (e.g., ’-debug’ will hide all messages containing the string ’debug’).
6. **Statistics<a name="_page69_x63.64_y377.90"></a> window**

Looking at the timeline view gives you a very localized outlook on things. However, sometimes you want to look at the general overview of the program’s behavior. For example, you want to know which function takes the most of the application’s execution time. The statistics window provides you with exactly that information.

If the trace capture was performed with call stack sampling enabled (as described in chapter 3.14.5), [you ](#_page49_x63.64_y158.34)will be presented with an option to switch between  *Instrumentation* and  *Sampling* modes. If the profiler collected no sampling data, but it retrieved symbols, the second mode will be displayed as *Symbols*, enabling you to list available symbols.

If GPU zones were captured, you would also have the *GPU* option to view the GPU zones statistics.

1. **Instrumentation<a name="_page69_x63.64_y515.94"></a> mode**

Here you will finda multi-column display of captured zones, which contains: the zone *name* and *location*, *total time* spent in the zone, the *count* of zone executions and the *mean time spent in the zone per call*. You may sort the view according to the three displayed values.

In the *Timing* menu, the *With children* selection displays inclusive measurements, that is, containing execution time of zone’s children. The *Self only* selection switches the measurement to exclusive, displaying

just the time spent in the zone, subtracting the child calls. Finally, the *Non-reentrant* selection shows inclusive time but counts only the first appearance of a given zone on a thread’s stack.

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.148.png)left mouse button on a zone will open the individual zone statistics view in the findzone window (section [5.7).](#_page71_x63.64_y132.43)

You can filterthe displayed list of zones by matching the zone name to the expression in the  *Filter zones* entry field. Refer to section [5.5 for](#_page68_x63.64_y696.73) a more detailed description of the expression syntax.

To limit the statistics to a specifictime extent, you may enable the *Limit range* option (chapter [5.3). ](#_page66_x63.64_y550.49)The inclusion region will be marked with a red striped pattern. Note that a zone must be entirely inside the region to be counted. You can access more options through the *Limits* button, which will open the time range limits window, described in section 5.23.

2. **Sampling mode**

Data displayed in this mode is, in essence, very similar to the instrumentation one. Here you will find function names, their locations in source code, and time measurements. There are, however, some significant differences.

First and foremost, the presented information is constructed from many call stack samples, which represent real addresses in the application’s binary code, mapped to the line numbers in the source files. This reverse mapping may not always be possible or could be erroneous. Furthermore, due to the nature of the sampling process, it is impossible to obtain exact time measurements. Instead, time values are guesstimated by multiplying the number of sample counts by mean time between two different samples.

The *Name* column contains name of the function in which the sampling was done. Kernel-mode function samples are distinguished with the red color. If the *Inlines* option is enabled, functions which were inlined will be preceded with a ’ ’ symbol and additionally display their parent function name in parenthesis. Otherwise, only non-inlined functions are listed, with a count of inlined functions in parenthesis. You may expand any entry containing an inlined function to display the corresponding functions list (some functions

may be hidden if the *Show all* option is disabled due to lack of sampling data). Clicking on a function name will open the sample entry call stacks window (see chapter 5.15). [Note ](#_page80_x63.64_y373.37)that if inclusive times are displayed, listed functions will be partially or completely coming from mid-stack frames, preventing, or limiting the capability to display parent call stacks.

The *Location* column displays the corresponding source file name and line number. Depending on the *Location*option selection, it can either show the function entry address or the instruction at which the sampling was performed. The *Entry* mode points at the beginning of a non-inlined function or at the place where the compiler inserted an inlined function in its parent function. The *Sample* mode is not useful for non-inlined functions, as it points to one randomly selected sampling point out of many that were captured. However, in the case of inlined functions, this random sampling point is within the inlined function body. Using these options in tandem lets you look at both the inlined function code and the place where it was inserted. If the *Smart* location is selected, the profilerwill display the entry point position for non-inlined functions and sample location for inlined functions. Selecting the @ *Address* option will instead print the symbol address.

The location data is complemented by the originating executable image name, contained in the *Image* column.

The profilermay not findsome function locations due to insufficientdebugging data available on the client-side. To filterout such entries, use the *Hide unknown* option.

The *Time* or *Count* column (depending on the  *Show time* option selection) shows number of taken samples, either as a raw count, or in an easier to understand time format. Note that the percentage value of time is calculated relative to the wall-clock time. The percentage value of sample counts is relative to the total number of collected samples.

The last column, *Code size*, displays the size of the symbol in the executable image of the program. Since inlined routines are directly embedded into other functions, their symbol size will be based on the parent symbol and displayed as ’less than’. In some cases, this data won’t be available. If the symbol code has been

retrieved [  symbol](#_page70_x77.98_y706.85) size will be prepended with the  icon, and clicking the right mouse button on the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.149.png)location column entry will open symbol view window (section 5.16.2).

Finally, the list can be filtered using the *Filter symbols* entry field, just like in the instrumentation mode case. Additionally, you can also filterresults by the originating image name of the symbol. You may disable the display of kernel symbols with the  *Include kernel*switch. The exclusive/inclusive time counting mode can be switched using the *Timing* menu (non-reentrant timing is not available in the Sampling view). Limiting the time range is also available but is restricted to self-time. If the *Show all* option is selected, the list will include not only the call stack samples but also all other symbols collected during the profiling process (this is enabled by default if no sampling was performed).![ref14]

<a name="_page70_x63.64_y701.20"></a>  <a name="_page70_x77.98_y706.85"></a>Symbols larger than 128 KB are not captured.

3. **GPU zones mode**

This is an analog of the instrumentation mode, but for the GPU zones. Note that the available options may <a name="_page71_x63.64_y132.43"></a>be limited here.

7. **Find zone window**

The individual behavior of zones may be influencedby many factors, like CPU cache effects, access times amortized by the disk cache, thread context switching, etc. Moreover, sometimes the execution time depends on the internal data structures and their response to different inputs. In other words, it is hard to determine the actual performance characteristics by looking at any single zone.

Tracy gives you the ability to display an execution time histogram of all occurrences of a zone. On this view, you can see how the function behaves in general. You can inspect how various data inputs influence the execution time. You can filterthe data to eventually drill down to the individual zone calls to see the environment in which they were called.

You start by entering a search query, which will be matched against known zone names (see section 3.4 for information on the grouping of zone names). If the search found some results, you will be presented with a list of zones in the *matched source locations*drop-down. The selected zone’s graph is displayed on the *histogram*

drop-down, and also the matching zones are highlighted on the timeline view. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.150.png)right mouse button on the source filelocation will open the source fileview window (if applicable, see section 5.16).

An example histogram is presented in figure 21. [Here](#_page71_x63.64_y377.40) you can see that the majority of zone calls (by          count) are clustered in the 300 ns group, closely followed by the 10 s cluster. There are some outliers at the

1 and 10 ms marks, which can be ignored on most occasions, as these are single occurrences.

<a name="_page71_x63.64_y377.40"></a>1 s 10 s 100 s 1 ms![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.151.png)

100 ns  10 ms  10 ms

**Figure 21:** *Zone execution time histogram. Note that the extreme time labels and time range indicator (middle time value) are*

*displayed in a separate line.*

Various data statistics about displayed data accompany the histogram, for example, the *total time* of the displayed samples or the *maximum number of counts* in histogram bins. The following options control how the data is presented:

- *Log values*– Switches between linear and logarithmic scale on the y axis of the graph, representing the call counts [ .](#_page71_x77.98_y730.94)
- *Log time* – Switches between linear and logarithmic scale on the x axis of the graph, representing the time bins.
- *Cumulate time* – Changes how the histogram bin values are calculated. By default, the vertical bars on the graph represent the *call counts* of zones that fitin the given time bin. If this option is enabled, the

  bars represent the *time spent* in the zones. For example, on the graph presented in figure21 the[ 10](#_page71_x63.64_y377.40)  s cluster is the dominating one, if we look at the time spent in the zone, even if the 300 ns cluster has a greater number of call counts.![ref11]

`  `<a name="_page71_x77.98_y730.94"></a>Or time, if the *cumulate time* option is enabled.

- *Self time* – Removes children time from the analyzed zones, which results in displaying only the time spent in the zone itself (or in non-instrumented function calls). It cannot be selected when *Running time* is active.
- *Running time* – Removes time when zone’s thread execution was suspended by the operating system due to preemption by other threads, waiting for system resources, lock contention, etc. Available only when the profilerperformed context switch capture (section 3.14.3).[ It canno](#_page48_x63.64_y261.96)t be selected when *Self time* is active.
- *Minimum values in bin* – Excludes display of bins that do not hold enough values at both ends of the time range. Increasing this parameter will eliminate outliers, allowing us to concentrate on the interesting part of the graph.

You can drag the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.152.png)left mouse button over the histogram to select a time range that you want to look at closely. This will display the data in the histogram info section, and it will also filterzones shown in the *found zones* section. This is quite useful if you actually want to look at the outliers, i.e., where did they originate

from, what the program was doing at the moment, etc  . Y[ou ](#_page72_x77.98_y715.96)can reset the selection range by pressing the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.153.png) right mouse button on the histogram.

The *found zones* section displays the individual zones grouped according to the following criteria:

- *Thread*– In this mode you can see which threads were executing the zone.
- *User text* – Splits the zones according to the custom user text (see section 3.4).
- *Zone name* – Groups zones by the name set on a per-call basis (see section 3.4).
- *Call stacks*– Zones are grouped by the originating call stack (see section 3.11).[ Note](#_page38_x63.64_y711.23) that two call stacks may sometimes appear identical, even if they are not, due to an easily overlooked difference in the source line numbers.
- *Parent* – Groups zones according to the parent zone. This mode relies on the zone hierarchy and *not* on the call stack information.
- *No grouping* – Disables zone grouping. It may be useful when you want to see zones in order as they appear.

You may sort each group according to the *order*in which it appeared, the call *count*, the total *time* spent in the group, or the *mean time per call*. Expanding the group view will display individual occurrences of the zone, which can be sorted by application’s time, execution time, or zone’s name. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.154.png)left mouse button on a zone will open the zone information window (section 5.13). [Clicking](#_page78_x63.64_y165.60) the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.155.png)middle mouse button on a zone will zoom the timeline view to the zone’s extent.![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.156.png)

Clicking the left mouse button on the group name will highlight the group time data on the histogram     (figure[22).](#_page73_x63.64_y84.43) This function provides a quick insight into the impact of the originating thread or input data on        the zone performance. Clicking on the *Clear*button will reset the group selection. If the grouping mode

is set to *Parent* option, clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.157.png)middle mouse button on the parent zone group will switch the find zone view to display the selected zone.

The call stack grouping mode has a different way of listing groups. Here only one group is displayed at any time due to the need to display the call stack frames. You can switch between call stack groups by using the  and  buttons. You can select the group by clicking on the *Select* button. You can open the call stack window (section [5.14) b](#_page79_x63.64_y262.70)y pressing the  *Call stack*button.

Tracy displays a variety of statistical values regarding the selected function: mean (average value), median            (middle value), mode (most common value, quantized using histogram bins), and σ (standard deviation).![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.158.png)

`  `<a name="_page72_x77.98_y715.96"></a>More often than not you will findout, that the application was just starting, or access to a cold filewas required and there’s not much you can do to optimize that particular case.

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.159.png)

<a name="_page73_x63.64_y84.43"></a>100 ns 1 s 10 s 100 s 1 ms 10 ms

**Figure 22:** *Zone execution time histogram with a group highlighted.*

The mean and median zone times are also displayed on the histogram as red (mean) and blue (median) vertical bars. Additional bars will indicate the mean group time (orange) and median group time (green). You can disable the drawing of either set of markers by clicking on the check-box next to the color legend.

Hovering the  mouse cursor over a zone on the timeline, which is currently selected in the findzone window, will display a pulsing vertical bar on the histogram, highlighting the bin to which the hovered zone has been assigned. In addition, it will also highlight zone entry on the zone list.

**Keyboard shortcut![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.160.png)**

You may press Ctrl + F to open or focus the find zone window and set the keyboard input on the search box.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.161.png)**

Whenusingtheexecutiontimeshistogram,youmustknowthehardwarepeculiarities. Readsection2.2.2 for more detail.

1. **Timeline<a name="_page73_x63.64_y460.25"></a> interaction**

The profilerwill highlight matching zones on the timeline display when the zone statistics are displayed in the findzone menu. Highlight colors match the histogram display. A bright blue highlight indicates that a zone is in the optional selection range, while the yellow highlight is used for the rest of the zones.

2. **Frame<a name="_page73_x63.64_y533.65"></a> time graph interaction**

The frame time graph (section [5.2.2) beha](#_page60_x63.64_y664.66)vior is altered when a zone is displayed in the findzone window and the *Show zone time in frames* option is selected. An accumulated zone execution time is shown instead of coloring the frame bars according to the frame time targets.

Each bar is drawn in gray color, with the white part accounting for the zone time. If the execution time is greater than the frame time (this is possible if more than one thread was executing the same zone), the overflow will be displayed using red color.

Enabling *Self time* option affects the displayed values, but *Running time* does not.

**Caveats![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.162.png)**

The profilermight not calculate the displayed data correctly, and it may not include some zones in the reported times.

3. **Limiting<a name="_page74_x63.64_y90.71"></a> zone time range**

If the *Limit range* option is selected, the profilerwill include only the zones within the specifiedtime range (chapter [5.3) ](#_page66_x63.64_y550.49)in the data. The inclusion region will be marked with a green striped pattern. Note that a zone must be entirely inside the region to be counted. You can access more options through the *Limits* button, which will open the time range limits window, described in section 5.23.

4. **Zone<a name="_page74_x63.64_y160.13"></a> samples**

If sampling data has been captured (see section [3.14.5), an ](#_page49_x63.64_y158.34)additional expandable *Samples* section will be displayed. This section contains only the sample data attributed to the displayed zone. Looking at this list may give you additional insight into what is happening within the zone. Refer to section 5.6.2 for [more ](#_page69_x63.64_y738.45)information about this view.

You can further narrow down the list of samples by selecting a time range on the histogram or by choosing a group in the *Found zones* section. However, do note that the random nature of sampling makes it highly unlikely that short-lived zones (i.e., left part of the histogram) will have any sample data collected.

8. **Compare<a name="_page74_x63.64_y280.93"></a> traces window**

Comparing the performance impact of the optimization work is not an easy thing to do. Benchmarking is often inconclusive, if even possible, in the case of interactive applications, where the benchmarked function might not have a visible impact on frame render time. Furthermore, doing isolated micro-benchmarks loses the application’s execution environment, in which many different parts compete for limited system resources.

Tracy solves this problem by providing a compare traces functionality, very similar to the find zone window, described in section 5.7.[ Y](#_page71_x63.64_y132.43)ou can compare traces either by zone or frame timing data.

You would begin your work by recording a reference trace that represents the usual behavior of the program. Then, after the optimization of the code is completed, you record another trace, doing roughly what you did for the reference one. Finally, having the optimized trace open, you select the *Open second trace*option in the compare traces window and load the reference trace.

Now things start to get familiar. You search for a zone, similarly like in the findzone window, choose the one you want in the *matched source locations*drop-down, and then you look at the histogram [ .](#_page74_x77.98_y727.93) This time there are two overlaid graphs, one representing the current trace and the second one representing the external

(reference) trace (figure[23). ](#_page74_x63.64_y509.92)You can easily see how the performance characteristics of the zone were affected by your modifications.

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.163.png)

<a name="_page74_x63.64_y509.92"></a>100 ns 1 s 10 s 100 s 1 ms 10 ms

**Figure 23:** *Compare traces histogram.*

Note that the traces are color and symbol-coded. The current trace is marked by a yellow symbol, and the external one is marked by a red symbol.

When searching for source locations it’s not uncommon to match more than one zone (for example a               search for Drawmay result in DrawCircle and DrawRectangle matches). Typically you wouldn’t want to     compare execution profilesof two unrelated functions, which is prevented by the *link selection*option, which![ref11]

`  `When<a name="_page74_x77.98_y727.93"></a> comparing frame times you are presented with a list of available frame sets, without the search box.

ensures that when you choose a source location in one trace, the corresponding one is also selected in the second trace. Be aware that this may still result in a mismatch, for example, if you have overloaded functions. In such a case, you will need to select the appropriate function in the other trace manually.

It may be difficult,if not impossible, to perform identical runs of a program. This means that the number of collected zones may differ in both traces, influencingthe displayed results. To fixthis problem, enable the *Normalize values* option, which will adjust the displayed results as if both traces had the same number of recorded zones.

**Trace descriptions![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.164.png)**

Set custom trace descriptions (see section [5.12) to ](#_page77_x63.64_y349.40)easily differentiate the two loaded traces. If no trace description is set, the name of the profiledprogram will be displayed along with the capture time.

<a name="_page75_x63.64_y247.07"></a>**5.8.1 Source filesdiff**

To see what changes were made in the source code between the two compared traces, select the *Source diff* compare mode. This will display a list of deleted, added, and changed files. By default, the difference is calculated from the older trace to the newer one. You can reverse this by clicking on the *Switch* button.

Please note that changes will be registered only if the filehas the same name and location in both traces. Tracy does not resolve filerenames or moves.

9. **Memory<a name="_page75_x63.64_y345.37"></a> window**

You can view the data gathered by profiling memory usage (section 3.8) in [the ](#_page33_x63.64_y384.83)memory window. If the profilertracked more than one memory pool during the capture, you would be able to select which collection you want to look at, using the *Memory pool* selection box.

The top row contains statistics, such as *total allocations*count, number of *active allocations*, current *memory usage*and process *memory span[  .](#_page75_x77.98_y701.78)*

The lists of captured memory allocations are displayed in a common multi-column format through the profiler. The first column specifiesthe memory address of an allocation or an address and an offsetif the

address is not at the start of the allocation. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.165.png)left mouse button on an address will open the memory allocation information window   [(see ](#_page75_x77.98_y721.33)section 5.11).[ Clicking](#_page77_x63.64_y277.64) the middle mouse button on an ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.166.png)address will zoom the timeline view to memory allocation’s range. The next column contains the allocation size. ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.167.png)

The allocation’s timing data is contained in two columns: *appeared at*and *duration*. Clicking the left mouse button on the first one will center the timeline view at the beginning of allocation, and likewise, clicking on the second one will center the timeline view at the end of allocation. Note that allocations that have not yet been freed will have their duration displayed in green color.

The memory event location in the code is displayed in the last four columns. The *thread*column contains the thread where the allocation was made and freed (if applicable), or an *alloc / free*pair of the threads if it was allocated in one thread and freed in another. The *zone alloc*contains the zone in which the allocation was performed![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.168.png) [ , or](#_page75_x77.98_y730.94) - if there was no active zone in the given thread at the time of allocation. Clicking the left mouse button on the zone name will open the zone information window (section 5.13). [Similar](#_page78_x63.64_y165.60)ly, the *zone free*column displays the zone which freed the allocation, which may be colored yellow, if it is the same zone

that did the allocation. Alternatively, if the zone has not yet been freed, a green *active*text is displayed. The last column contains the *alloc*and *free*call stack buttons, or their placeholders, if no call stack is available

(see section [3.11 f](#_page38_x63.64_y711.23)or more information). Clicking on either of the buttons will open the call stack window (section [5.14).](#_page79_x63.64_y262.70) Note that the call stack buttons that match the information window will be highlighted.![ref5]

`  `<a name="_page75_x77.98_y701.78"></a>Memory span describes the address space consumed by the program. It is calculated as a difference between the maximum and minimum<a name="_page75_x77.98_y721.33"></a> observed in-use memory address.

`  `While<a name="_page75_x77.98_y730.94"></a> the allocation information window is opened, the address will be highlighted on the list.

`  `The actual allocation is typically a couple functions deeper in the call stack.

The memory window is split into the following sections:

1. **Allocations**

<a name="_page76_x63.64_y103.48"></a>The @ *Allocations* pane allows you to search for the specifiedaddress usage during the whole lifetime of the program. All recorded memory allocations that match the query will be displayed on a list.

2. **Active<a name="_page76_x63.64_y161.52"></a> allocations**

The  *Active allocations* pane displays a list of currently active memory allocations and their total memory usage. Here, you can see where your program allocated memory it is now using. If the application has already exited, this becomes a list of leaked memory.

3. **Memory<a name="_page76_x63.64_y232.10"></a> map**

On the  *Memory map* pane, you can see the graphical representation of your program’s address space. Active allocations are displayed as green lines, while the freed memory is red. The brightness of the color indicates how much time has passed since the last memory event at the given location – the most recent events are the most vibrant.

This view may help assess the general memory behavior of the application or in debugging the problems resulting from address space fragmentation.

4. **Bottom-up<a name="_page76_x63.64_y340.35"></a> call stack tree**

The  *Bottom-up call stack tree*pane is only available, if the memory events were collecting the call stack data (section [3.11).](#_page38_x63.64_y711.23) In this view, you are presented with a tree of memory allocations, starting at the call stack entry point and going up to the allocation’s pinpointed place. Each tree level is sorted according to the number of bytes allocated in the given branch.

Each tree node consists of the function name, the source filelocation, and the memory allocation data. The memory allocation data is either yellow *inclusive* events count (allocations performed by children) or the cyan *exclusive* events count (allocations that took place in the node) [ .](#_page76_x77.98_y670.24) Two values are counted: total memory size and number of allocations.

The *Group by function name* option controls how tree nodes are grouped. If it is disabled, the grouping is performed at a machine instruction-level granularity. This may result in a very verbose output, but the displayed source locations are precise. To make the tree more readable, you may opt to perform grouping at the function name level, which will result in less valid source filelocations, as multiple entries are collapsed into one.

Enabling the *Only active allocations* option will limit the call stack tree only to display active allocations. Enabling *Only inactive allocations* option will have similar effect for inactive allocations. Both are mutually exclusive, enabling one disables the other. Displaing inactive allocations, when combined with *Limit range*, will show short lived allocatios highlighting potentially unwanted behavior in the code.

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.169.png)right mouse button on the function name will open the allocations list window (see section [5.10),](#_page77_x63.64_y218.16) which lists all the allocations included at the current call stack tree level. Likewise, clicking the

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.170.png)right mouse button on the source filelocation will open the source fileview window (if applicable, see section [5.16).](#_page80_x63.64_y496.26)

Some function names may be too long to correctly display, with the events count data at the end. In such cases, you may press the *control* button, which will display the events count tooltip.![ref12]

<a name="_page76_x63.64_y664.58"></a>  <a name="_page76_x77.98_y670.24"></a>Due to the way call stacks work, there is no possibility for an entry to have both inclusive and exclusive counts, in an adequately instrumented program.

5. **Top-down call stack tree**

This pane is identical in functionality to the *Bottom-up call stack tree*, but the call stack order is reversed when the tree is built. This means that the tree starts at the memory allocation functions and goes down to the call stack entry point.

6. **Looking<a name="_page77_x63.64_y147.57"></a> back at the memory history**

By default, the memory window displays the memory data at the current point of program execution. It is, however, possible to view the historical data by enabling the *Limits* option. The profilerwill consider only the memory events within the time range in the displayed results. See section 5.23 for[ more](#_page87_x63.64_y335.67) information.

10. **Allocations<a name="_page77_x63.64_y218.16"></a> list window**

This window displays the list of allocations included at the selected call stack tree level (see section 5.9 and [5.9.4).](#_page76_x63.64_y340.35)

11. **Memory<a name="_page77_x63.64_y277.64"></a> allocation information window**

The information about the selected memory allocation is displayed in this window. It lists the allocation’s address and size, along with the time, thread, and zone data of the allocation and free events. Clicking the <a name="_page77_x63.64_y349.40"></a>  *Zoom to allocation*button will zoom the timeline view to the allocation’s extent.

12. **Trace information window**

This window contains information about the current trace: captured program name, time of the capture, profilerversion which performed the capture, and a custom trace description, which you can fillin.

Open the *Trace statistics* section to see information about the trace, such as achieved timer resolution, number of captured zones, lock events, plot data points, memory allocations, etc.

There’s also a section containing the selected frame set timing statistics and histogram  . As a[ con](#_page77_x77.98_y707.20)venience, you can switch the active frame set here and limit the displayed frame statistics to the frame range visible on the screen.

If *CPU topology*data is available (see section [3.14.4), y](#_page48_x63.64_y455.18)ou will be able to view the package, core, and thread hierarchy.

The *Source location substitutions* section allows adapting the source filepaths, as captured by the profiler, to the actual on-disk locations [ .](#_page77_x77.98_y716.80) You can create a new substitution by clicking the *Add new substitution* button. This will add a new entry, with input fieldsfor ECMAScript-conforming regular expression pattern and its corresponding replacement string. You can quickly test the outcome of substitutions in the *example source location*input field,which will be transformed and displayed below, as *result*.

**Quick example![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.171.png)**

Let’s say we have an Unix-based operating system with program sources in /home/user/program/src/ directory. We have also performed a capture of an application running under Windows, with sources in C:\Users\user\Desktop\program\src directory. The source locations don’t match, and the profiler can’t access the source fileson our disk. We can fixthat by adding two substitution patterns:

- ˆC:\\Users\\user\\Desktop /home/user
- \\ /![ref12]

`  `<a name="_page77_x77.98_y716.80"></a><a name="_page77_x77.98_y707.20"></a>See section [5.7 f](#_page71_x63.64_y132.43)or a description of the histogram. Note that there are subtle differences in the available functionality.   This does not affect source filescached during the profilingrun.

In this window, you can view the information about the machine on which the profiledapplication was running. This includes the operating system, used compiler, CPU name, total available RAM, etc. In addition, if application information was provided (see section 3.7.1),[ it will](#_page33_x63.64_y301.69) also be displayed here.

If an application should crash during profiling(section 2.5), [the ](#_page21_x63.64_y703.26)profilerwill display the crash information in this window. It provides you information about the thread that has crashed, the crash reason, and the crash call stack (section [5.14).](#_page79_x63.64_y262.70)

13. **Zone<a name="_page78_x63.64_y165.60"></a> information window**

The zone information window displays detailed information about a single zone. There can be only one zone information window open at any time. While the window is open, the profilerwill highlight the zone on the timeline view with a green outline. The following data is presented:

- Basic source location information: function name, source filelocation, and the thread name.
- Timing information.
- If the profilerperformed context switch capture (section 3.14.3)[ and a](#_page48_x63.64_y261.96) thread was suspended during zone execution, a list of wait regions will be displayed, with complete information about the timing, CPU migrations, and wait reasons. If CPU topology data is available (section 3.14.4),[ the profiler](#_page48_x63.64_y455.18)will mark zone migrations across cores with ’C’ and migrations across packages – with ’P.’ In some cases, context switch data might be incomplete  , [in which](#_page78_x77.98_y711.39) case a warning message will be displayed.
- Memory events list, both summarized and a list of individual allocation/free events (see section 5.9 for more information on the memory events list).
- List of messages that the profilerlogged in the zone’s scope. If the *exclude children*option is disabled, messages emitted in child zones will also be included.
- Zone trace, taking into account the zone tree and call stack information (section 3.11), tr[ying ](#_page38_x63.64_y711.23)to reconstruct a combined zone + call stack trace  . [Cap](#_page78_x77.98_y721.00)tured zones are displayed as standard text, while not instrumented functions are dimmed. Hovering the  mouse pointer over a zone will highlight it on

  the timeline view with a red outline. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.172.png)left mouse button on a zone will switch the zone info window to that zone. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.173.png)middle mouse button on a zone will zoom the timeline view to the zone’s extent. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.174.png)right mouse button on a source filelocation will open the source

fileview window (if applicable, see section [5.16).](#_page80_x63.64_y496.26)

- Child zones list, showing how the current zone’s execution time was used. Zones on this list can be grouped according to their source location. Each group can be expanded to show individual entries. All the controls from the zone trace are also available here.
- Time distribution in child zones, which expands the information provided in the child zones list by processing *all*zone children (including multiple levels of grandchildren). This results in a statistical list of zones that were really doing the work in the current zone’s time span. If a group of zones is selected on this list, the findzone window (section 5.7)[ will](#_page71_x63.64_y132.43) open, with a time range limited to show only the children of the current zone.

The zone information window has the following controls available:

- *Zoom to zone* – Zooms the timeline view to the zone’s extent.
- *Go to parent* – Switches the zone information window to display current zone’s parent zone (if available).![ref9]

`  `<a name="_page78_x77.98_y721.00"></a><a name="_page78_x77.98_y711.39"></a>For example, when capture is ongoing and context switch information has not yet been received.

`  `Reconstruction is only possible if all zones have complete call stack capture data available. In the case where that’s not available, an *unknown frames* entry will be present.

- *Statistics* –Displaysthezonegeneralperformancecharacteristicsinthefindzonewindow(section5.7).
- *Call stack*– Views the current zone’s call stack in the call stack window (section 5.14).[ The](#_page79_x63.64_y262.70) button will be highlighted if the call stack window shows the zone’s call stack. Only available if zone had captured call stack data (section [3.11).](#_page38_x63.64_y711.23)
- *Source*– Display source fileview window with the zone source code (only available if applicable, see section [5.16).](#_page80_x63.64_y496.26) The button will be highlighted if the source fileis displayed (but the focused source line might be different).
- *Go back* – Returns to the previously viewed zone. The viewing history is lost when the zone information window is closed or when the type of displayed zone changes (from CPU to GPU or vice versa).

Clicking on the  *Copy to clipboard*buttons will copy the appropriate data to the clipboard.

14. **Call<a name="_page79_x63.64_y262.70"></a> stack window**

This window shows the frames contained in the selected call stack. Each frame is described by a function name, source filelocation, and originating image   [name.](#_page79_x77.98_y721.33) Function frames originating from the kernel are marked with a red color. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.175.png)left mouse button on either the function name of source filelocation

will copy the name to the clipboard. Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.176.png)right mouse button on the source filelocation will open

the source fileview window (if applicable, see section 5.16).

A single stack frame may have multiple function call places associated with it. This happens in the case of inlined function calls. Such entries will be displayed in the call stack window, with *inline* in place of frame number [ .](#_page79_x77.98_y730.94)

Stack frame location may be displayed in the following number of ways, depending on the @ *Frame location*option selection:

- *Source code*– displays source fileand line number associated with the frame.
- *Entry point* – source code at the beginning of the function containing selected frame, or function call place in case of inline frames.
- *Return address* – shows return address, which you may use to pinpoint the exact instruction in the disassembly.
- *Symbol address* – displays begin address of the function containing the frame address.

In some cases, it may not be possible to decode stack frame addresses correctly. Such frames will be presented with a dimmed ’[ntdll.dll]’ name of the image containing the frame address, or simply ’[unknown]’ if the profilercannot retrieve even this information. Additionally, ’[kernel]’ is used to indicate unknown stack frames within the operating system’s internal routines.

If the displayed call stack is a sampled call stack (chapter [3.14.5), an ](#_page49_x63.64_y158.34)additional button will be available,

*Global entry statistics*. Clicking it will open the sample entry call stacks window (chapter 5.15) f[or the ](#_page80_x63.64_y373.37)current call stack.

Clicking on the  *Copy to clipboard*button will copy call stack to the clipboard.

<a name="_page79_x63.64_y645.14"></a>**5.14.1 Reading call stacks**

You need to take special care when reading call stacks. Contrary to their name, call stacks do not show *function call stacks*, but rather *function return stacks* . This might not be very clear at first, but this is how programs do work. Consider the following source code:![ref8]

`  `<a name="_page79_x77.98_y730.94"></a><a name="_page79_x77.98_y721.33"></a>Executable images are called *modules* by Microsoft.   Or ’ ’ icon in case of call stack tooltips.

int main() {

auto app = std::make\_unique<Application>(); app->Run();

app.reset();

}

Let’s say you are looking at the call stack of some function called within Application::Run. This is the result you might get:

0. ...
0. ...
0. Application::Run
0. std::unique\_ptr<Application>::reset
0. main

At the first glance it may look like unique\_ptr::reset was the *call site*of the Application::Run , which would make no sense, but this is not the case here. When you remember these are the *function return points* , it becomes much more clear what is happening. As an optimization, Application::Run is returning directly into unique\_ptr::reset, skipping the return to main and an unnecessary reset function call.

Moreover, the linker may determine in some rare cases that any two functions in your program are identical [ . ](#_page80_x77.98_y730.94)As a result, only one copy of the binary code will be provided in the executable for both functions to share. While this optimization produces more compact programs, it also means that there’s no way to distinguish the two functions apart in the resulting machine code. In effect, some call stacks may look nonsensical until you perform a small investigation.

15. **Sample<a name="_page80_x63.64_y373.37"></a> entry call stacks window**

Thiswindowdisplaysstatisticalinformationabouttheselectedsymbol. Allsampledcallstacks(chapter3.14.5) leading to the symbol are counted and displayed in descending order. You can choose the displayed call stack using the *entry call stack*controls, which also display time spent in the selected call stack. Alternatively, sample counts may be shown by disabling the  *Show time* option, which is described in more detail in chapter [5.6.2.](#_page69_x63.64_y738.45)

The layout of frame list and the @ *Frame location*option selection is similar to the call stack window, described in chapter [5.14.](#_page79_x63.64_y262.70)

16. **Source<a name="_page80_x63.64_y496.26"></a> view window**

This window can operate in one of the two modes. The first one is quite simple, just showing the source code associated with a source file. The second one, which is used if symbol context is available, is considerably <a name="_page80_x63.64_y566.34"></a>more feature-rich.

1. **Source fileview**

In source view mode, you can view the source code of the profiledapplication to take a quick glance at the context of the function behavior you are analyzing. The profilerwill highlight the selected line (for example, a location of a profilingzone) both in the source code listing and on the scroll bar.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.177.png)**

To display source files, Tracy has to gain access to them somehow. Since having the source code is not needed for the profiledapplication to run, this can be problematic in some cases. The source files search order is as follows:![ref11]

`  `<a name="_page80_x77.98_y730.94"></a>For example, if all they do is zero-initialize a region of memory. As some constructors would do.

1. Discovery is performed on the server side. Found filesare cached in the trace. *This is appropriate ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.178.png)when the client and the server run on the same machine or if you’re deploying your application to the target device and then run the profileron the same workstation.*
1. If not found, discovery is performed on the client-side. Found filesare cached in the trace. *This is appropriate when you are developing your code on another machine, for example, you may be working on a dev-board through an SSH connection.*
1. If not found, Tracy will try to open source filesthat you might have on your disk later on. The profilerwon’t store these filesin the trace. You may provide custom filepath substitution rules to redirect this search to the right place (see section [5.12).](#_page77_x63.64_y349.40)

Note that the discovery process not only looks for a fileon the disk but it also checks its time stamp andvalidatesitagainsttheexecutableimagetimestampor, ifit’snotavailable, thetimeoftheperformed capture. This will prevent the use of newer source files(i.e., were changed) than the program you’re profiling.

Nevertheless, **the displayed source filesmight still not reflectthe code that you profiled!** It is up to you to verify that you don’t have a modifiedversion of the code with regards to the trace.

2. **Symbol<a name="_page81_x63.64_y320.07"></a> view**

A much more capable symbol view mode is available if the inspected source location has an associated symbol context (i.e., if it comes from a call stack capture, from call stack sampling, etc.). A symbol is a unit of machine code, basically a callable function. It may be generated using multiple source files and may consist of numerous inlined functions. A list of all captured symbols is available in the statistics window, as described in chapter [5.6.2.](#_page69_x63.64_y738.45)

The header of symbol view window contains a name of the selected *symbol*, a list of  *functions* that contribute to the symbol, and information such as count of probed  *Samples*.

Additionally, you may use the *Mode* selector to decide what content should be displayed in the panels below:

- *Source* – only the source code will be displayed.
- *Assembly* – only the machine code disassembly will be shown.
- *Both* – selects combined mode, in which source code and disassembly will be listed next to each other.

Some modes may be unavailable in some circumstances (missing or outdated source files,lack of machine code). In case the *Assembly* mode is unavailable, this might be due to the capstone disassembly engine failing to disassemble the machine instructions. See section 2.3 f[or more](#_page19_x63.64_y255.32) information.

1. **Source<a name="_page81_x63.64_y576.20"></a> mode**

This is pretty much the source fileview window, but with the ability to select one of the source filesthat the compiler used to build the symbol. Additionally, each source fileline that produced machine code in the symbol will show a count of associated assembly instructions, displayed with an ’@’ prefix,and will be marked with grey color on the scroll bar. Due to how optimizing compilers work, some lines may seemingly not produce any machine code, for example, because iterating a loop counter index might have been reduced to advancing a data pointer. Some other lines may have a disproportionate amount of associated instructions, e.g., when the compiler applied a loop unrolling optimization. This varies from case to case and from compiler to compiler.

The *Propagate inlines* option, available when sample data is present, will enable propagation of the instruction costs down the local call stack. For example, suppose a base function in the symbol issues a call to an inlined function (which may not be readily visible due to being contained in another source file). In that case, any cost attributed to the inlined function will be visible in the base function. Because the cost information is added to all the entries in the local call stacks, it is possible to see seemingly nonsense total ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.179.png)cost values when this feature is enabled. To quickly toggle this on or off,you may also press the X key.

2. **Assembly<a name="_page82_x63.64_y141.14"></a> mode**

This mode shows the disassembly of the symbol machine code. If only one inline function is selected through the  *Function* selector, assembly instructions outside of this function will be dimmed out. Each assembly instruction is displayed listed with its location in the program memory during execution. If the *Relative address*option is selected, the profilerwill print an offsetfrom the symbol beginning instead. Clicking the

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.180.png)left mouse button on the address/offsetwill switch to counting line numbers, using the selected one as the origin (i.e., zero value). Line numbers are displayed inside [] brackets. This display mode can be useful to correlate lines with the output of external tools, such as llvm-mca. To disable line numbering click the

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.181.png)right mouse button on a line number.

If the  *Source locations*option is selected, each line of the assembly code will also contain information about the originating source file name and line number. Each file is assigned its own color for easier

differentiationbetweendifferentsourcefiles. Clickingthe ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.182.png)leftmousebuttononadisplayedsourcelocation will switch the source file,if necessary, and focus the source view on the selected line. Additionally, hovering the  mouse cursor over the presented location will show a tooltip containing the name of a function the instruction originates from, along with an appropriate source code fragment and the local call stack if it exists.

**Local call stack![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.183.png)**

In some cases, it may be challenging to understand what is being displayed in the disassembly. For example, calling the std::lower\_bound function may generate multiple levels of inlined functions:

first, we enter the search algorithm, then the comparison functions, which in turn may be lambdas that call even more external code, and so on. In such an event, you will most likely see that some external code is taking a long time to execute, and you will be none the wiser on improving things.

The local call stack for an assembly instruction represents all the inline function calls *within the symbol* (hence the ’local’ part), which were made to reach the instruction. Deeper inspection of the local call stack, including navigation to the source call site of each participating inline function, can be performed through the context menu accessible by pressing the right mouse button on the source location.

Selectingthe  *Rawcode*optionwillenablethedisplayofrawmachinecodebytesforeachline. Individual bytes are displayed with interwoven colors to make reading easier.

If any instruction would jump to a predefined address, the symbolic name of the jump target will be additionally displayed. If the destination location is within the currently displayed symbol, an -> arrow will be prepended to the name. Hovering the  mouse pointer over such symbol name will highlight the target

location. Clicking on it with the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.184.png)left mouse button will focus the view on the destination instruction or switch view to the destination symbol.

Enabling the  *Jumps* option will show jumps within the symbol code as a series of arrows from the    jump source to the jump target, and hovering the  mouse pointer over a jump arrow will display a jump information tooltip. It will also draw the jump range on the scroll bar as a green line. A horizontal green line

will mark the jump target location. Clicking on a jump arrow with the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.185.png)left mouse button will focus the view on the target location. The ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.186.png)right mouse button opens a jump context menu, which allows inspection

and navigation to the target location or any of the source locations. Jumps going out of the symbol   will be indicated by a smaller arrow pointing away from the code.![ref6]

`  `This<a name="_page82_x77.98_y721.00"></a> includes jumps, procedure calls, and returns. For example, in x86 assembly the respective operand names can be: jmp, call,

ret.

Portions of the executable used to show the symbol view are stored within the captured profileand don’t rely on the available local disk files.

**Exploring microarchitecture** If the listed assembly code targets x86 or x64 instruction set architectures, hovering  mouse pointer over an instruction will display a tooltip with microarchitectural data, based on measurements made in [ [AR19](#_page92_x63.64_y115.13)]. *This information is retrieved from instruction cycle tables and does not represent the true behavior of the profiledcode.*Reading the cited article will give you a detailed definitionof the presented data, but here’s a quick (and inaccurate) explanation:

- *Throughput* –Howmanycyclesarerequiredtoexecuteaninstructioninastreamofthesameindependent instructions. For example, if the CPU may execute two independent add instructions simultaneously on different execution units, then the throughput (cycle cost per instruction) is 0.5.
- *Latency* – How many cycles it takes for an instruction to finishexecuting. This is reported as a min-max range, as some output values may be available earlier than the rest.
- *ops*– How many microcode operations have to be dispatched for an instruction to retire. For example, adding a value from memory to a register may consist of two microinstructions: first load the value from memory, then add it to the register.
- *Ports* – Which ports (execution units) are required for dispatch of microinstructions. For example, 2\*p0+1\*p015 wouldmeanthatoutofthethreemicroinstructionsimplementingtheassemblyinstruction, two can only be executed on port 0, and one microinstruction can be executed on ports 0, 1, or 5. The number of available ports and their capabilities varies between different processors architectures. Refer to[ https://wikichip.org/ ](https://wikichip.org/)for more information.

Selection of the CPU microarchitecture can be performed using the   *arch*drop-down. Each architecture is accompanied by the name of an example CPU implementing it. If the current selection matches the microarchitecture on which the profiledapplication was running, the  icon will be green  [. Ot](#_page83_x77.98_y711.72)herwise, it will be red [ . ](#_page83_x77.98_y721.33)Clicking on the  icon when it is red will reset the selected microarchitecture to the one the profiledapplication was running on.

Clicking on the  *Save* button lets you write the disassembly listing to a file. You can then manually            extract some critical loop kernel and pass it to a CPU simulator, such as *LLVM Machine Code Analyzer* (llvm-mca) [ , t](#_page83_x77.98_y730.94)o see how the code is executed and if there are any pipeline bubbles. Consult the llvm-mca

documentation for more details. Alternatively, you might click the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.187.png)right mouse button on a jump arrow and save only the instructions within the jump range, using the  *Save jump range* button.

**Instruction dependencies** Assembly instructions may read values stored in registers and may also write values to registers. As a result, a dependency between two instructions is created when one produces some result, which the other then consumes. Combining this dependency graph with information about instruction latencies may give a deep understanding of the bottlenecks in code performance.

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.188.png)left mouse button on any assembly instruction will mark it as a target for resolving register dependencies between instructions. To cancel this selection, click on any assembly instruction with

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.189.png)right mouse button.

The selected instruction will be highlighted in white, while its dependencies will be highlighted in red. Additionally, a list of dependent registers will be listed next to each instruction which reads or writes to them, with the following color code:

- *Green*– Register value is read (is a dependency *after*target instruction).
- *Red* – A value is written to a register (is a dependency *before*target instruction).![ref2]

`  `<a name="_page83_x77.98_y721.33"></a><a name="_page83_x77.98_y711.72"></a>Comparing sampled instruction counts with microarchitectural details only makes sense when this selection is properly matched.   Y<a name="_page83_x77.98_y730.94"></a>ou can use this to gain insight into how the code *may* behave on other processors.

`  `<https://llvm.org/docs/CommandGuide/llvm-mca.html>

- *Yellow* – Register is read and then modified.
- *Grey* – Value in a register is either discarded (overwritten) or was already consumed by an earlier instruction (i.e., it is readily available  ).[ The](#_page84_x77.98_y716.41) profilerwill not follow the dependency chain further.

Searchfordependenciesfollowsprogramcontrolflow, sotheremaybemultipleproducersandconsumers for any single register. While the *after* and *before*guidelines mentioned above hold in the general case, things may be more complicated when there’s a large number of conditional jumps in the code. Note that dependencies further away than 64 instructions are not displayed.

For more straightforward navigation, dependencies are also marked on the left side of the scroll bar, following the green, red and yellow conventions. The selected instruction is marked in blue.

3. **Combined<a name="_page84_x63.64_y221.84"></a> mode**

In this mode, the source and assembly panes will be displayed together, providing the best way to gain insight into the code. Hovering the  mouse pointer over the source fileline or the location of the assembly line will highlight the corresponding lines in the second pane (both in the listing and on the scroll bar).

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.190.png)left mouse button on a line will select it and focus on it in both panes. Note that while an assembly line always has only one corresponding source line, a single source line may have many associated assembly lines, not necessarily next to each other. Clicking on the same *source*line more than once will focus the *assembly* view on the next associated instructions block.

4. **Instruction<a name="_page84_x63.64_y345.67"></a> pointer cost statistics**

If automated call stack sampling (see chapter [3.14.5) was](#_page49_x63.64_y158.34) performed, additional profilinginformation will be available. The first column of source and assembly views will contain percentage counts of collected instruction pointer samples for each displayed line, both in numerical and graphical bar form. You can use this information to determine which function line takes the most time. The displayed percentage values are heat map color-coded, with the lowest values mapped to dark red and the highest to bright yellow. The color code will appear next to the percentage value and on the scroll bar so that you can identify ’hot’ places in the code at a glance.

By default, samples are displayed only within the selected symbol, in isolation. In some cases, you may, however, want to include samples from functions that the selected symbol called. To do so, enable ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.191.png)the  *Child calls*option, which you may also temporarily toggle by holding the Z key. You can also click the  drop down control to display a child call distribution list, which shows each known function   that t[he ](#_page84_x77.98_y726.02)symbol called. Make sure to familiarize yourself with section 5.14.1[ to be ](#_page79_x63.64_y645.14)able to read the results correctly.

Instruction timings can be viewed as a group. To begin constructing such a group, click the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.192.png)left mouse button on the percentage value. Additional instructions can be added using the Ctrl key while holding![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.193.png)

the key will allow selection of a range. To cancel the selection, click the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.194.png)right mouse button on a ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.195.png)percentage value. Group statistics can be seen at the bottom of the pane.

Clicking the ![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.196.png)middle mouse button on the percentage value of an assembly instruction will display entry call stacks of the selected sample (see chapter [5.15). This](#_page80_x63.64_y373.37) functionality is only available for instructions that have collected sampling data and only in the assembly view, as the source code may be inlined multiple times, which would result in ambiguous location data. Note that number of entry call stacks is displayed in a tooltip for a quick reference.

The sample data source is controlled by the *Function* control in the window header. If this option should be disabled, sample data will represent the whole symbol. If it is enabled, then the sample data will only include the selected function. You can change the currently selected function by opening the drop-down box, which includes time statistics. The time percentage values of each contributing function are calculated relative to the total number of samples collected within the symbol.![ref8]

`  `This<a name="_page84_x77.98_y726.02"></a><a name="_page84_x77.98_y716.41"></a> is actually a bit of simplification. Run a pipeline simulator, e.g., llvm-mca for a better analysis.   You should remember that these are results of random sampling. Some function calls may be missing here.

Selecting the *Limit range* option will restrict counted samples to the time extent shared with the statistics view (displayed as a red-striped region on the timeline). See section 5.3 for[ more](#_page66_x63.64_y550.49) detail.

**Important![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.197.png)**

Be aware that the data is not entirely accurate, as it results from a random sampling of program execution. Furthermore, undocumented implementation details of an out-of-order CPU architecture will highly impact the measurement. Read chapter 2.2.2[ to see](#_page17_x63.64_y164.09) the tip of an iceberg.

5. **Inspecting<a name="_page85_x63.64_y209.35"></a> hardware samples**

As described in chapter [3.14.6, on](#_page50_x63.64_y177.15) some platforms, Tracy can capture the internal statistics counted by the CPU hardware. If this data has been collected, the *Cost* selection list will be available. It allows changing what is taken into consideration for display by the cost statistics. You can select the following options:

- *Samplecount* –thisselectstheinstructionpointerstatistics, collectedbycallstacksamplingperformedby the operating system. This is the default data shown when hardware samples have not been captured.
- *Cycles*– an option very similar to the *sample count*, but the data is collected directly by the CPU hardware counters. This may make the results more reliable.
- *Branch impact* – indicates places where√many branch instructions are issued, and at the same time, incorrectly predicted. Calculated as #branch instructions ∗#branch misses. This is more useful than the raw branch miss rate, as it considers the number of events taking place.
- *Cac*√*he impact*– similar to *branch impact*, but it shows cache miss data instead. These values are calculated as #cache references ∗#cache misses and will highlight places with lots of cache accesses that also

  miss.

- The rest of the available selections just show raw values gathered from the hardware counters. These are: *Retirements*, *Branches taken*, *Branch miss*, *Cache access*and *Cache miss*.

If the  *HW* (hardware samples) switch is enabled, the profilerwill supplement the cost percentages column with three additional columns. The first added column displays the instructions per cycle (IPC) value. The two remaining columns show branch and cache data, as described below. The displayed values are color-coded, with green indicating good execution performance and red indicating that the code stalled the CPU pipeline for one reason or another.

If the  *Impact* switch is enabled, the branch and cache columns will show how much impact the branch mispredictions and cache misses have. The way these statistics are calculated is described in the list above. In the other case, the columns will show the raw branch and cache miss rate ratios, isolated to their respective source and assembly lines and not relative to the whole symbol.

**Isolated values![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.198.png)**

The percentage values when *Impact* option is not selected will not take into account the relative count of events. For example, you may see a 100% cache miss rate when some instruction missed 10 out of 10 cache accesses. While not ideal, this is not as important as a seemingly better 50% cache miss rate instruction, which actually has missed 1000 out of 2000 accesses. Therefore, you should always cross-check the presented information with the respective event counts. To help with this, Tracy will dim statistically unimportant values.

17. **Wait<a name="_page86_x63.64_y90.71"></a> stacks window**

If wait stack information has been captured (chapter [3.14.5.1), here](#_page49_x63.64_y506.03) you will be able to inspect the collected data. There are three different views available:

- *List* – shows all unique wait stacks, sorted by the number of times they were observed.
- *Bottom-up tree* – displays wait stacks in the form of a collapsible tree, which starts at the bottom of the call stack.
- *Top-down tree*– displays wait stacks in the form of a collapsible tree, which starts at the top of the call stack.

Displayed data may be narrowed down to a specifictime range or to include only selected threads.

18. **Lock<a name="_page86_x63.64_y246.49"></a> information window**

This window presents information and statistics about a lock. The lock events count represents the total number collected of wait, obtain and release events. The announce, termination, and lock lifetime measure <a name="_page86_x63.64_y316.58"></a>the time from the lockable construction until destruction.

19. **Frame image playback window**

You may view a live replay of the profiledapplication screen captures (see section 3.3.3) [using t](#_page25_x63.64_y375.56)his window. Playback is controlled by the  *Play* and  *Pause*buttons and the *Frame image*slider can be used to scrub to the desired timestamp. Alternatively you may use the  and  buttons to change single frame back or forward.

If the *Sync timeline* option is selected, the profilerwill focus the timeline view on the frame corresponding to the currently displayed screenshot. The *Zoom 2*× option enlarges the image for easier viewing.

The following parameters also accompany each displayed frame image: *timestamp*, showing at which time the image was captured, *frame*, displaying the numerical value of the corresponding frame, and *ratio*, telling how well the in-memory loss-less compression was able to reduce the image data size.

20. **CPU<a name="_page86_x63.64_y454.62"></a> data window**

Statistical data about all processes running on the system during the capture is available in this window if the profilerperformed context switch capture (section [3.14.3).](#_page48_x63.64_y261.96)

Each running program has an assigned process identifier(PID), which is displayed in the first column. The profilerwill also display a list of thread identifiers(TIDs) if a program entry is expanded.

The *runningtime* columnshowshowmuchprocessortimewasusedbyaprocessorthread. Thepercentage may be over 100%, as it is scaled to trace length, and multiple threads belonging to a single program may be executing simultaneously. The *running regions* column displays how many times a given entry was in the *running* state, and the *CPU migrations* shows how many times an entry was moved from one CPU core to another when the system scheduler suspended an entry.

The profiled program is highlighted using green color. Furthermore, the yellow highlight indicates threads known to the profiler(that is, which sent events due to instrumentation).

21. **Annotation<a name="_page86_x63.64_y627.72"></a> settings window**

In this window, you may modify how a timeline annotation (section 5.3.1) is[ presented](#_page67_x63.64_y202.61) by setting its text description or selecting region highlight color. If the note is no longer needed, you may also remove it here.

22. **Annotation list window**

Thiswindowlistsallannotationsmarkedonthetimeline. Eachannotationispresented, asshownonfigure24. From left to right the elements are:

- *Edit* – Opens the annotation settings window (section 5.21).
- *Zoom* – Zooms timeline to the annotation extent.
- *Remove* – Removes the annotation. You must press the Ctrl key to enable this button.![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.199.png)
- Colored box – Color of the annotation.
- Text description of the annotation.

![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.200.png)<a name="_page87_x63.64_y252.97"></a> Text description

**Figure 24:** *Annotation list entry*

A new view-sized annotation can be added in this window by pressing the + *Add annotation* button. This effectively saves your current viewport for further reference.

23. **Time<a name="_page87_x63.64_y335.67"></a> range limits**

This window displays information about time range limits (section 5.3) f[or find](#_page66_x63.64_y550.49)zone (section 5.7), s[tatistics ](#_page71_x63.64_y132.43)(section [5.6),](#_page69_x63.64_y377.90) memory (section [5.9) and](#_page75_x63.64_y345.37) wait stacks (section [5.17) results.](#_page86_x63.64_y90.71) Each limit can be enabled or disabled and adjusted through the following options:

- *Limit to view* – Set the time range limit to current view.
- *Focus*– Set the timeline view to the time range extent.
- *Set from annotation* – Allows using the annotation region for limiting purposes.
- *Copy from statistics* – Copies the statistics time range limit.
- *Copy from findzone* – Copies the findzone time range limit.
- *Copy from wait stacks* – Copies the wait stacks time range limit.
- *Copy from memory* – Copies the memory time range limit.

Note that ranges displayed in the window have color hints that match the color of the striped regions on <a name="_page87_x63.64_y583.51"></a>the timeline.

**6 Exporting zone statistics to CSV**

You can use a command-line utility in the csvexport directory to export primary zone statistics from a saved trace into a CSV format. The tool requires a single .tracy fileas an argument and prints the result into the standard output (stdout), from where you can redirect it into a fileor use it as an input into another tool. By default, the utility will list all zones with the following columns:

- name– Zone name
- src\_file – Source filewhere the zone was set
- src\_line – Line in the source filewhere the zone was set
- total\_ns – Total zone time in nanoseconds
- total\_perc – Total zone time as a percentage of the program’s execution time
- counts – Zone count
- mean\_ns – Mean zone time (equivalent to MPTC in the profilerGUI) in nanoseconds
- min\_ns – Minimum zone time in nanoseconds
- max\_ns – Maximum zone time in nanoseconds
- std\_ns – Standard deviation of the zone time in nanoseconds

You can customize the output with the following command line options:

- -h, --help – Display a help message
- -f, --filter <name> – Filter the zone names
- -c, --case – Make the name filteringcase sensitive
- -s, --sep <separator> – Customize the CSV separator (default is “,”)
- -e, --self – Use self time (equivalent to the “Self time” toggle in the profilerGUI)
- -u, --unwrap – Report each zone individually; this will discard the statistics columns and instead report the timestamp and duration for each zone entry

<a name="_page88_x63.64_y388.34"></a>**7 Importing external profilingdata**

Tracy can import data generated by other profilers. This external data cannot be directly loaded but must be converted first. Currently, there’s only support for converting chrome:tracing data through the import-chrome utility.

**Compressed traces![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.201.png)**

Tracy can import traces compressed with the Zstandard algorithm (for example, using the zstd command-line utility). Traces ending with .zst extension are assumed to be compressed.

**Source locations![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.202.png)**

Chrome tracing format doesn’t document a way to provide source location data. The import-chrome utility will however recognize a custom loc tag in the root of zone begin events. You should be formatting this data in the usual filename:line style, for example: hello.c:42. Providing the line number (including a colon) is optional but highly recommended.

**Limitations![](Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.203.png)**

- Tracy is a single-process profiler. Should the imported trace contain PID entries, each PID+TID pair will create a new *pseudo-TID* number, which the profilerwill then decode into a PID+TID pair in thread labels. If you want to preserve the original TID numbers, your traces should omit PID entries.
- The imported data may be severely limited, either by not mapping directly to the data structures

used by Tracy or by following undocumented practices.![ref4]

<a name="_page89_x63.64_y118.43"></a>**8 Configurationfiles**

While the client part doesn’t read or write anything to the disk (except for accessing the /proc filesystem on Linux), the server part has to keep some persistent state. The naming conventions or internal data format of the filesare not meant to be known by profilerusers, but you may want to do a backup of the configuration or move it to another machine.

On Windows settings are stored in the %APPDATA%/tracydirectory. All other platforms use the $XDG\_CONFIG\_HOME/tracydirectory,or $HOME/.config/tracy ifthe XDG\_CONFIG\_HOMEenvironmentvariable <a name="_page89_x63.64_y245.94"></a>is not set.

1. **Root directory**

Various filesat the root configuration directory store common profilerstate such as UI windows position, connections history, etc.

2. **Trace<a name="_page89_x63.64_y308.67"></a> specificsettings**

Trace filessaved on disk are immutable and can’t be changed. Still, it may be desirable to store additional per-trace information to be used by the profiler, for example, a custom description of the trace or the timeline view position used in the previous profilingsession.

This external data is stored in the user/[letter]/[program]/[week]/[epoch] directory, relative to the configuration’s root directory. The program part is the name of the profiled application (for example program.exe). The letter part is the first letter of the profiledapplication’s name. The week part is a count of weeks since the Unix epoch, and the epoch part is a count of seconds since the Unix epoch. This rather unusual convention prevents the creation of directories with hundreds of entries.

The profilernever prunes user settings.

**Appendices**

<a name="_page90_x63.64_y124.76"></a>**A License**

Tracy Profiler (https://github.com/wolfpld/tracy) is licensed under the 3-clause BSD license.

Copyright (c) 2017-2023, Bartosz Taudul <wolf@nereid.pl> All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of the <organization> nor the

names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY

DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;

LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND

ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

**B<a name="_page90_x63.64_y498.37"></a> List of contributors**

Bartosz Taudul <wolf@nereid.pl>

Kamil Klimek <kamil.klimek@sharkbits.com> (initial find zone implementation)

Bartosz Szreder <zgredder@gmail.com> (view/worker split)

Arvid Gerstmann <dev@arvid-g.de> (compatibility fixes)

Rokas Kupstys <rokups@zoho.com> (compatibility fixes, initial CI work, MingW support) Till Rathmann <till.rathmann@gmx.de> (DLL support)

Sherief Farouk <sherief.personal@gmail.com> (compatibility fixes)

Dedmen Miller <dedmen@dedmen.de> (find zone bug fixes, improvements)

Michał Cichoń <michcic@gmail.com> (OSX call stack decoding backport)

Thales Sabino <thales@codeplay.com> (OpenCL support)

Andrew Depke <andrewdepke@gmail.com> (Direct3D 12 support)

Simonas Kazlauskas <git@kazlauskas.me> (OSX CI, external bindings)

Jakub Žádník <kubouch@gmail.com> (csvexport utility)

Andrey Voroshilov <andrew.voroshilov@gmail.com> (multi-DLL fixes)

Benoit Jacob <benoitjacob@google.com> (Android improvements)

David Farrel <dafarrel@adobe.com> (Direct3D 11 support)

Terence Rokop <rokopt@sharpears.net> (Non-reentrant zones)

Lukas Berbuer <lukas.berbuer@gmail.com> (CMake integration)

Xavier Bouchoux <xavierb@gmail.com> (sample data in find zone) Balazs Kovacsics <kovab93@gmail.com> (Universal Windows Platform)

<a name="_page91_x63.64_y149.53"></a>**C Inventory of external libraries**

The following libraries are included with and used by the Tracy Profiler. Entries marked with a icon are used in the client code.

- 3-clause BSD license
- getopt\_port – <https://github.com/kimgr/getopt_port>
- libbacktrace  –[ https://github.com/ianlancetaylor/libbacktrace](https://github.com/ianlancetaylor/libbacktrace)
- Zstandard – <https://github.com/facebook/zstd>
- DiffTemplate Library – <https://github.com/cubicdaiya/dtl>
- 2-clause BSD license
- concurrentqueue –[ https://github.com/cameron314/concurrentqueue](https://github.com/cameron314/concurrentqueue)
- LZ4  –[ https://github.com/lz4/lz4](https://github.com/lz4/lz4)
- xxHash – <https://github.com/Cyan4973/xxHash>
- Public domain
- rpmalloc  –[ https://github.com/rampantpixels/rpmalloc](https://github.com/rampantpixels/rpmalloc)
- gl3w –[ https://github.com/skaslev/gl3w](https://github.com/skaslev/gl3w)
- stb\_image – <https://github.com/nothings/stb>
- stb\_image\_resize – <https://github.com/nothings/stb>
- zlib license
- Native File Dialog Extended – <https://github.com/btzy/nativefiledialog-extended>
- IconFontCppHeaders – <https://github.com/juliettef/IconFontCppHeaders>
- pdqsort – <https://github.com/orlp/pdqsort>
- MIT license
- Dear ImGui – <https://github.com/ocornut/imgui>
- JSON for Modern C++ – <https://github.com/nlohmann/json>
- robin-hood-hashing – <https://github.com/martinus/robin-hood-hashing>
- SPSCQueue  –[ https://github.com/rigtorp/SPSCQueue](https://github.com/rigtorp/SPSCQueue)
- ini –[ https://github.com/rxi/ini](https://github.com/rxi/ini)
- Apache license 2.0
  - Droid Sans – <https://www.fontsquirrel.com/fonts/droid-sans>
- SIL Open Font License 1.1
- Fira Code – <https://github.com/tonsky/FiraCode>
- Font Awesome – <https://fontawesome.com/>

**References**

<a name="_page92_x63.64_y115.13"></a>[AR19] Andreas Abel and Jan Reineke. uops.info: Characterizing latency, throughput, and port usage of

instructions on intel microarchitectures. In *ASPLOS* , ASPLOS ’19, pages 673–686, New York, NY, USA, 2019. ACM.

<a name="_page92_x63.64_y160.76"></a>[ISO12] ISO. *ISO/IEC 14882:2011 Information technology — Programming languages — C++* . International

Organization for Standardization, Geneva, Switzerland, February 2012.
95

[ref1]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.002.png
[ref2]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.006.png
[ref3]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.012.png
[ref4]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.016.png
[ref5]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.020.png
[ref6]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.023.png
[ref7]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.024.png
[ref8]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.026.png
[ref9]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.030.png
[ref10]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.033.png
[ref11]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.038.png
[ref12]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.053.png
[ref13]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.058.png
[ref14]: Aspose.Words.1acaf9d8-b063-4ac8-9d19-7893039db694.087.png
