# Compare traces

Everything you have profiled so far was a single capture. The [compare traces window](#compare) compares two: it overlays the same data from both captures, so you can see exactly how a code change shifted your program's behavior.

Say the histogram showed you a slow zone and you optimized it. Did the edit help? Record the current program as a reference trace, apply your optimization, record a second trace doing roughly the same work, and open it. Click the * Compare* button on the top bar and press *Open second trace* to load the reference. Searching for that zone in the *Zones* tab overlays the histograms from both captures at the same source location: a curve shifted to the left means the zone truly got faster, while a wider curve or a longer tail means the behavior became less consistent.

The *Frames* tab applies the same overlay to the frame time data of the [frame statistics window](#framestatistics), and *Source diff* lists the source files that were added, deleted, or changed between the two captures, connecting the timing change to the code that caused it. Throughout the window the current trace is marked with a yellow lemon and the reference one with a red gem.

Load a second trace and watch how your change moves the histogram curves. Try it out!
