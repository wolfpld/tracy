# Tracy MCP eval guide

This document covers the bindings-layer detail that the analysis
guidance (`tracy://prompt`) does not.

## ctx

`ctx` is a `TracyServerBindings.Worker` — the same object Tracy Assist's
C++ tools query through `Worker::Get*`. The pybind methods are the canonical
data surface. Common entry points:

- Zones: `get_all_zone_stats()` (every callsite, large), `get_root_zone_stats()`
  (top-level zones only, useful for "where is the program spending time"),
  `get_zone_stats(srcloc_id)`, `get_child_zone_stats(srcloc_id)` (subtract for
  self-time), `get_zone_durations(name)`, `get_zone_count()`,
  `get_all_zone_source_locations()`
- GPU zones: `get_all_gpu_zone_stats()`, `get_gpu_zone_durations(...)`,
  `get_gpu_contexts()`
- Frames: `get_frame_count()`, `get_frame_times()`, `get_frame_times_named(name)`,
  `get_frame_boundaries()`, `get_zones_in_frame(...)`
- Threads: `get_threads()`, `get_thread_name(tid)`, `get_thread_context_switches(tid)`
- Messages / plots / locks / memory / callstacks: `get_messages()`, `get_plots()`,
  `get_locks()`, `get_memory_events()`, `get_callstack_frames(...)`
- Sections: `get_sections()` — timed code sections from
  `TracySectionEnter`/`TracySectionLeave` instrumentation. Returns a list of
  `{start, end, text}` dicts (start/end in ns).
- Capture metadata: `get_capture_name()`, `get_capture_program()`,
  `get_first_time()`, `get_last_time()`, `get_resolution()`, `get_host_info()`

Run `print([m for m in dir(ctx) if not m.startswith('_')])` for the full list.

## Units and conventions

- All time values returned by Worker methods are **nanoseconds** (int).
  `get_first_time()` / `get_last_time()` bound the capture timeline.
- `ZoneStats` fields: `count`, `total`, `min`, `max`, `avg`, `sum_sq`. `total`
  is the inclusive aggregate; use `get_child_zone_stats(srcloc_id)` to subtract
  child time when you need self-time.
- `get_all_zone_stats()` returns `dict[str, ZoneStats]` keyed by an opaque label
  of the form `'name (addr)[arch] <srcloc_id>'`. The trailing `<id>` is the
  source-location ID — the int accepted by `get_zone_stats(int)`,
  `get_zone_durations_by_id`, and friends. Parse it with a regex if you need
  to join across calls.
- Source-location IDs from `get_all_zone_source_locations()` are the join key
  between zone-name lookups and per-callsite queries.

## Common query patterns

Small Python snippets for the queries you'll reach for most often:

```python
# top 10 hottest zones by total time
top = sorted(ctx.get_all_zone_stats().items(),
             key=lambda kv: kv[1].total, reverse=True)[:10]
for k, v in top:
    print(f"{v.total/1e6:.2f}ms  count={v.count}  {k}")

# primary frame set timing
times = ctx.get_frame_times()  # ns per frame
print(f"frames={len(times)}  avg={sum(times)/len(times)/1e6:.2f}ms  "
      f"p99={sorted(times)[int(len(times)*0.99)]/1e6:.2f}ms")

# stats for a named zone — find the srcloc id, then drill in
import re
matches = [k for k in ctx.get_all_zone_stats() if k.startswith("MyFunc ")]
sid = int(re.search(r"<(\d+)>$", matches[0]).group(1))
stats = ctx.get_zone_stats(sid)
```

## Async mode

For long-running queries pass `async_mode=True` to `eval`; it returns
`{task_id, status: "running"}`. Poll with the `task` tool
(`action="poll", task_id=...`).

## Instance lifecycle

`tracy_mcp.py` runs as a long-lived singleton process shared across every
MCP client (all VS Code windows), and every `live_connect`/`load_capture`
instance holds its *entire* trace — zones, messages, callstacks, memory
events — resident in memory for as long as that process runs. Nothing
frees it just because your conversation ends.

- Call `unload_capture(instance_id)` as soon as you're done analyzing a
  capture. Don't rely on automatic eviction as your primary cleanup path —
  treat it as a backstop for forgotten sessions, not a substitute.
- `list_instances` reports `idle_seconds` and `connected` per instance; use
  it to spot stale ones before starting a new session, especially if you're
  about to load several captures for comparison.
- The server provides three backstops, all configurable via environment
  variables at startup: it evicts the least-recently-used *evictable*
  instance (disconnected live sessions, or any loaded file capture — never
  a still-connected live one) once the instance count reaches
  `TRACY_MCP_MAX_INSTANCES` (default 4); it drops a disconnected live
  instance that's sat idle for `TRACY_MCP_DISCONNECTED_TTL_S` (default
  1800s / 30 min) so a session is still there for analysis right after the
  target disconnects, but doesn't linger forever if forgotten; and it drops
  a file-loaded capture that's sat idle for `TRACY_MCP_FILE_IDLE_TTL_S`
  (default 1800s) — safe to let expire since it's already durably on disk,
  just `load_capture` it again.
