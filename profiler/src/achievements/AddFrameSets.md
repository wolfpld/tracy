# Add frame sets

A repeating phase of the program can have its own [frame set](#secondaryframeset). Mark every step with `FrameMarkNamed( "Physics" )` and Tracy keeps a separate timeline for it, on its own lane above the threads. A phase that runs intermittently, an audio callback for example, uses `FrameMarkStart` and `FrameMarkEnd` pairs instead.

The name must be a string literal, [unique per set](#uniquepointers) like every Tracy string, and one set must never mix continuous and discontinuous marks.

Click a set's lane header, or choose it in the top bar frame selector, and the [frame view](#framesets) moves to it: the lanes, the time limits and the frame statistics then all describe that set alone. Try it out!
