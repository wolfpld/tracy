# Tracy MCP eval guide

This document covers the bindings-layer detail that the curated catalog
(`tracy://catalog`) and analysis guidance (`tracy://prompt`) do not.

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

## Translating catalog entries to ctx Python

The catalog (`tracy://catalog`) lists curated queries. Each maps to a small
Python snippet:

```python
# zone_list — top 10 hottest zones by total time
top = sorted(ctx.get_all_zone_stats().items(),
             key=lambda kv: kv[1].total, reverse=True)[:10]
for k, v in top:
    print(f"{v.total/1e6:.2f}ms  count={v.count}  {k}")

# frame_list — primary frame set timing
times = ctx.get_frame_times()  # ns per frame
print(f"frames={len(times)}  avg={sum(times)/len(times)/1e6:.2f}ms  "
      f"p99={sorted(times)[int(len(times)*0.99)]/1e6:.2f}ms")

# zone_stats for a named zone — find the srcloc id, then drill in
import re
matches = [k for k in ctx.get_all_zone_stats() if k.startswith("MyFunc ")]
sid = int(re.search(r"<(\d+)>$", matches[0]).group(1))
stats = ctx.get_zone_stats(sid)
```

## Async mode

For long-running queries pass `async_mode=True` to `eval`; it returns
`{task_id, status: "running"}`. Poll with the `task` tool
(`action="poll", task_id=...`).
