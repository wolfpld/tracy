# Ghost zones

Automated sampling gives Tracy a rough picture of what your application was doing, even in places where you placed no zones. That data can be displayed as ghost zones, approximate spans of execution reconstructed from the samples, marked with the * ghost* icon so they are never mistaken for real instrumentation.

On any thread track that has both instrumented zones and sampling data, a * ghost* icon appears next to the thread label. Click it to switch that track between instrumented and ghost display, the same time range, viewed two ways. Threads that contain no instrumented zones display ghost zones automatically.

Ghost zone boundaries are only as accurate as the sampling period: sampling runs at 8 kHz on Windows and 10 kHz on Linux and Android, so times are quantized into steps of roughly 125 and 100 microseconds. Treat ghost zones as a guide, not a measurement. Switch a thread over and use the ghosts to pinpoint the functions that deserve real zones.

Now pick a thread and click its * ghost* icon. Try it out!
