# Frame statistics

The [frame time graph](#frametimegraph) shows frames in time order: pick a slow frame, see it took 90 ms, zoom in, find what caused it. It cannot tell you whether 90 ms happens to one frame in a thousand or to one in twenty, and that decides whether you have a problem at all.

The [Frame statistics window](#framestatistics) draws a histogram instead: each bar is a span of frame times, and its height is how many frames landed inside. The mean hides what matters: a program that runs its usual frame in 16 ms but stalls 200 ms once per second still reports a healthy average, while the player swears the game is stuttering. The percentiles show how long the *slow* frames actually ran. P99, for example, is the time ninety-nine of a hundred frames finished under.

> [!TIP]
> **Tip**
>
> Hover a frame on the frame time graph and the histogram pulses a line at the bar containing it, so you can tell at a glance whether that stall was typical.

Try clicking the * Frame statistics* button in the * Tools* menu and see what your frame times really look like.
