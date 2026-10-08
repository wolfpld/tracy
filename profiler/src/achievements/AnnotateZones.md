# Annotate zones

Zones can carry more than just timing. Use the `ZoneText(txt, size)` macro to attach a contextual note to the current zone (the name of the file being opened, the id of the entity being processed) or `ZoneValue(value)` to report a number without paying the cost of converting it to a string. For printf-style formatting, use `ZoneTextF(fmt, ...)`.

```c++
void LoadTexture( const std::string& path )
{
    ZoneScoped;
    ZoneText( path.data(), path.size() );
    // ...
}
```

The annotation shows up wherever the zone is displayed: in the tooltip when you hover over it on the timeline, and in the Zone info window. A `ZoneValue` is reported as a text note of the `1024 [0x400]` style. If you want to replace the zone's displayed name instead, use `ZoneName(txt, size)`, but note that such a per-call name is not used when zones are grouped for statistics.

Zones can be colored, too: `ZoneScopedC(color)` sets a constant color at compile time, while `ZoneColor(color)` overrides it per call.

Now add an annotation to one of your instrumented functions, profile your application, and click the zone on the timeline to open the Zone info window, your note will be waiting on the `User text:` line. Try it out!
