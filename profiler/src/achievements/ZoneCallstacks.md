# Capture zone call stacks

A zone shows how long a function ran. The [call stack](#collectingcallstacks) shows who called it, and a zone can capture one as it opens.

Add the `S` postfix to a macro and pass a depth: `ZoneScopedS( 24 )`, `ZoneNamedNS( zone, "Load", 24, true )`, `ZoneTransientNS( zone, "boot", 24, true )`. The depth is how many frames to keep. Capturing a stack costs time, so keep only the frames you need. Resolution needs [debug symbols](#debuggingsymbols) in the binary, and a stripped build leaves the frames unnamed.

When [sampling](#sampling) is enabled, the zone info window already shows a call stack for most zones, reconstructed from samples and marked . Those are guesses and they can be wrong. A captured stack carries no mark and comes with the  *Call stack* button, which opens it in a [separate window](#callstackwindow). Put an `S` macro on your hottest zone and compare the guess with the capture. Try it out!
