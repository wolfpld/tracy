# Tracy Profiler

Tracy is a frame profiler that can be used for remote or embedded telemetry of your application.

![](doc/profiler.png)

Tracy requires compiler support for C++14 and Thread Local Storage. There are no other requirements. The following platforms are confirmed to be working:

- Windows (x64)
- Linux (x64, ARM64)
- Android (ARM)

Other platforms should also work fine.

### High-level overview

![](doc/design.svg)

Tracy is split into client and server side. The client side collects events using a high-efficiency queue and awaits for an incoming connection. The server part connects to client and receives collected data from the client, which is then reconstructed into a viewable timeline. The transfer is performed using a TCP connection.

## Usage instructions

#### Initial client setup

Add source files from `tracy/client` and `tracy/common` to your project. That's all. Tracy is now integrated into your application.

#### Marking zones

To begin data collection, tracy requires that you manually instrument your application (automatic tracing of every entered function is not feasible due to the amount of data that would generate). All the user-facing interface is contained in the `tracy/client/Tracy.hpp` header file.

To slice the program's execution recording into frame-sized chunks, put the `FrameMark` macro after you have completed rendering the frame. Ideally that would be right after the swap buffers command. Note that this step is optional, as some applications (for example: a compression utility) do not have the concept of a frame.

To record a zone's execution time add the `ZoneScoped` macro at the beginning of the scope you want to measure. This will automatically record function name, source file name and location. Optionally you may use the `ZoneScopedC( 0xBBGGRR )` macro to set a custom color for the zone. Note that the color value will be constant in the recording (don't try to parametrize it). After you have marked the zone, you may further parametrize it.

Use the `ZoneName( const char* name )` macro to set a custom name for the zone, which will be displayed instead of the function's name in the timeline view. The text string that you have provided **must** be accessible indefinitely at the given address. Tracy does not guarantee at which point in time it will be sent to the server and there  is no notification when it happens.

Use the `ZoneText( const char* text, size_t size )` macro to add a custom text string that will be displayed along the zone information (for example, name of the file you are opening). Note that every time `ZoneText` is invoked, a memory allocation is performed to store an internal copy of the data. The string you have provided is not used by tracy.

#### Running the server

The easiest way to get going is to build the standalone server, available in the `standalone` directory. You can connect to localhost or remote clients and view the collected data right away.

Alternatively, you may want to embed the server in your application, the same which is running the client part of tracy. Doing so requires that you also include the `server` and `imgui` directories. Include the `tracy/server/TracyView.hpp` header file, create an instance of the `tracy::View` class and call its `Draw()` method every frame. Unfortunately, there's also the hard part - you need to integrate the imgui library into the innards of your program. How to do so is outside the scope of this document.

## Good practices

- Remember to set thread names for proper identification of threads. You may use the functions exposed in the `tracy/common/TracySystem.hpp` header to do so. Note that the max thread name length in pthreads is limited to 15 characters. Proper thread naming support is available in MSVC only if you are using Windows SDK 10.0.15063 or newer (a tracy-specific workaround may be added in the future).
- Enable the MSVC String Pooling option (`/GF`) or the gcc counterpart, `-fmerge-constants`. This will reduce number of queries the server needs to perform to the client. Note that these options are enabled in optimized builds by default.

## Practical considerations

Tracy's time measurement precision is not infinite. It's only as good as the system-provided timers are.

- On the embedded ARM-based systems you can expect to have something around 1 µs time resolution.
- On x86 (currently only implemented on Windows) the time resolution depends on the hardware implementation of the RDTSCP instruction and typically is in the low nanoseconds. This may vary from one micro-architecture to another and requires a fairly modern (Sandy Bridge) processor for reliable results.

While the data collection is very lightweight, it is not completely free. Each recorded zone event has a cost, which tracy tries to calculate and display on the timeline view, as a red zone. Note that this is an *approximation* of the real cost, which ignores many important factors. For example, you can't determine the impact of cache effects. The CPU frequency may be reduced in some situations, which will increase the recorded time, but the displayed profiler cost will not compensate for that.

![](doc/cost.png)
