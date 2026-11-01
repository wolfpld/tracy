# Annotate the timeline

The context that explains a capture often comes from outside the profiled program: the debugger was attached, a build was running, the capture was a warm-up. An annotation stores that context on the timeline, at a range you choose.

Right-click a zone, frame, or section bar to select its exact extent, or hold Ctrl and drag a range over the timeline. Pick * Add annotation* from the menu. The editor opens with a placeholder name, so type the reason ("debugger attached", "warm-up run") and pick a color if the trace will carry several notes.

The note appears on the timeline as a bracket with its text. Clicking the text reopens the editor. From the [annotation list](#annotationlist) under the * Tools* menu you can hide a note, zoom to it, or delete it with Ctrl held. Annotations are stored in a separate sidecar file, so they are still there when you reopen the capture.

> [!NOTE]
> **Note**
>
> A trace is written once and never modified, so extras like annotations go into their own sidecar file. By default that file lives in the profiler's configuration directory and does not travel with the trace. Once the trace is saved, the [Trace information window](#traceinfo) shows a * Public sidecar* checkbox: checking it saves the sidecar next to the trace file with a `.json` extension. Move or share both files together, or the annotations get left behind.

> [!TIP]
> **Tip**
>
> The menu that adds annotations also sets [time range limits](#timerangelimits). Its *Set time range for:* entries limit Statistics, the flame graph, and other windows to the selected range, and the Limits window can reuse an annotation's range as a limit.

Try finding a slow part of the trace you can explain and annotate it.
