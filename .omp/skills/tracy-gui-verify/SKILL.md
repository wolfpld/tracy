---
name: tracy-gui-verify
description: Build, serve, and drive the Tracy Profiler's emscripten (web) GUI in a headless browser with verified mouse/keyboard semantics. Use when developing or testing the profiler GUI. No X11/Wayland/DISPLAY required — the browser is the display server.
---

# Test the Tracy web GUI in a browser

Build the emscripten profiler GUI into an instrumented temporary workspace,
serve it, and drive it with the browser tool. The harness exports
(`debug_snapshot`/`debug_clear`) expose the app-side mouse/ID state — they
are the ground truth for targeting and verification, not screenshots.

Applies to this repo's emscripten build with ImGui 1.92.9b-docking and
Emscripten 5.0.7. Constants marked M are workstation-dependent — re-verify
them. Everything else is stable; do not re-derive it.

## Setup

```sh
sh <this-skill-dir>/setup.sh            # workspace=/tmp/tracy-protocol
# or: TRACY_WEB_WS=/elsewhere TRACY_WEB_REPO=<repo> sh setup.sh
```

`<this-skill-dir>` is the project-scoped `.omp/skills/tracy-gui-verify/`
under the active project root — not a fixed home directory. If multiple
copies exist (one per project that has used this skill), use the copy
inside the repo being tested; `TRACY_WEB_REPO` controls which repo is
copied into the workspace.

The script: fresh source copy (excludes `.git` and build dirs) → applies
`harness.patch` (adds `debug_snapshot`/`debug_clear` exports + event/frame
recording to the emscripten backend, in the COPY only) → configures → builds
Release with the emsdk at `$EMSDK_DIR` (default `~/emsdk`) and the CPM cache at
`~/.cache/cpm`.

**Pitfall:** if the workspace is deleted while a `tracy-web` server is running,
stop the hub process first — a stale server keeps the *deleted* cwd and silently
returns empty responses while the port still accepts connections.

**Pitfall:** a `tracy-web` that died in an earlier session leaves the daemon in
`failed` state: `stop` only reports the old failure, and `start` keeps returning
"Daemon tracy-web has unacknowledged completion notifications" while the port
stays free. Drain the daemon with `hub op=logs name=tracy-web` (the log also
shows the cause), then relaunch with `hub op=restart name=tracy-web` (retained
spec). If the port is NOT free, a stale process owns it — often one serving an
earlier (now-stale) build directory: the new `httpd.py` dies on the bind and
your requests silently hit the old directory. Check `ss -tlnp | grep 8000` and
kill the owner. After any start/restart, verify the server is actually
serving: `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/index.html`
must return 200 — the daemon message is not proof of a server.

**After editing the GUI in the repo:** copy the changed files into
`$WS/src/` (same relative path), re-run `cmake --build $WS/build -j$(nproc)`,
reload the page. If a change touches `profiler/src/BackendEmscripten.cpp` or
`profiler/CMakeLists.txt`, the harness patch may no longer apply — re-apply it
manually (keep the `Dbg*` harness section, the `DbgPushEvent`/`DbgPushFrame`
calls in the mouse callbacks + `NewFrame`, and the two `debug_*` exports in
`-sEXPORTED_FUNCTIONS`).

## Serve + open + ready

Server (long-running → `hub`):

```
hub op=start name=tracy-web application=python3 args=["$WS/build/httpd.py"]
    cwd=$WS/build ready={port:8000} persist=true
```

`httpd.py` sends the COOP/COEP headers required for pthreads/SharedArrayBuffer —
use it, not a bare http.server.

Browser:

```
browser open url=http://127.0.0.1:8000/index.html viewport={width:1600,height:900}
```

**Ready signal** (in a `run` cell; `run` code executes in Node scope — page JS
goes through `tab.evaluate`):

```js
let title = null;
for (let i = 0; i < 360; i++) {
  title = await tab.evaluate(() => document.title);
  if (/ - Tracy Profiler/.test(title)) break;
  await new Promise(r => setTimeout(r, 250));
}
```

Title is `Tracy Profiler X.Y.Z` until the preloaded `embed.tracy` (DarkRL
capture) finishes loading, then `<trace> (embed.tracy) - Tracy Profiler X.Y.Z`
(`profiler/src/main.cpp` `SetWindowTitleCallback`). Wait ~1.5 s after, then
confirm the app loop lives: `snap().frames.at(-1).tick > 0`.

## Harness API (ground truth)

```js
const snap  = () => tab.evaluate(() => JSON.parse(Module.ccall('debug_snapshot','string',[],[])));
const clear = () => tab.evaluate(() => Module.ccall('debug_clear','void',[],[]));
```

`snap()` → `{ dpr, innerW, innerH, bufW, bufH, rectL, rectT, rectW, rectH,
title, cursor, frames:[…64], events:[…64] }` (newest last).

- `frames[]`: one sample **per rAF tick, including idle ticks**. `tick` = main-loop
  count (always advances), `f` = `ImGui::GetFrameCount()` (advances only when a
  frame actually renders — the idle gate, §Idle), `mx/my` = app mouse position,
  `md[3]` = mouse button states, `q` = pending input events, `wa` =
  `tracy::s_wasActive` at tick start, `hi`/`ai` = ImGui `HoveredId`/`ActiveId`.
- `events[]`: raw callback data as the app received it. `type` 0=move 1=down
  2=up 3=enter 4=leave 5=wheel; `tx/ty` = Emscripten int `targetX/Y`; `ax/ay` =
  position passed to ImGui (`-1` for non-move); `t` = DOMHighResTimeStamp.

## Coordinate mapping

```
appX = floor( trunc(cssX - rectL) * dpr )     // device px, what ImGui hit-tests
cssX = appX / dpr                              // inverse for targeting
screenshot_px = cssX * dpr
```

Chain: DOM `clientX` → Emscripten `targetX = int(clientX - (rect.left|0))`
(`src/lib/libhtml5.js`, `EmscriptenMouseEvent.targetX` is an `int`) → Tracy
`AddMousePosEvent(targetX * dpr, …)` (`BackendEmscripten.cpp`) → ImGui `ImFloor`
(`imgui.cpp` `AddMousePosEvent`). Canvas fills the viewport, so `rectL/rectT`
are 0 (re-read anyway).

**M: `dpr` on this workstation's headless browser is 1.25** (canvas buffer
2000×1125 for a 1600×900 viewport; screenshots are captured at device px).
Never assume 1. App positions come in multiples of `dpr`; verify targeting
within ±1 px via `frames[].mx/my`.

## Click protocol

Click = move, press, refresh through the hold, release, verify — all
against rendered frames. The idle gate (§Idle) renders only 3 frames per
wake, and a hold with no mouse events at all refreshes nothing, so a
fixed-wait down/up from a cold idle can be swallowed (both events received,
zero frames rendered) or released after the wake budget expires. Issuing
mouse moves while the button is down keeps the budget alive: a same-coord
re-move is delivered (verified: it reaches the canvas handler, wakes the
app, and a same-coord hold click straddles cleanly) and is the safest
refresh — zero hover drift; a ±`dx` px wiggle works too, but must stay
inside the hit area:

```js
async function click(cssX, cssY, holdMs = 400) {
  await page.mouse.move(cssX, cssY);          // 1. ALWAYS move first
  await new Promise(r => setTimeout(r, 150)); // 2. >= 1 rendered frame
  const pre = await snap();
  const pf = pre.frames.at(-1);
  await clear();
  await page.mouse.down();                    // 3. press
  let df = null, hiDuring = null;
  const t0 = Date.now();
  while (Date.now() - t0 < holdMs) {
    await new Promise(r => setTimeout(r, 70));
    await page.mouse.move(cssX, cssY);        // 4. same-coord re-move refreshes the wake budget
    const f = (await snap()).frames.at(-1);
    if (f.md[0] === 1) { df ??= f.f; hiDuring = f.hi; }
  }
  await page.mouse.up();                      // 5. release
  let uf = null;
  for (let i = 0; i < 40; i++) {
    await new Promise(r => setTimeout(r, 40));
    const f = (await snap()).frames.at(-1);
    if (f.md[0] === 0) { uf = f.f; break; }
  }
  await new Promise(r => setTimeout(r, 400));
  const s = await snap();
  const d = s.dpr, ex = Math.floor(Math.trunc(cssX - s.rectL) * d), ey = Math.floor(Math.trunc(cssY - s.rectT) * d);
  return { hoverID: pf.hi, hiDuring, appPos: [pf.mx, pf.my], expected: [ex, ey],
           straddle: { df, uf },
           ok: df !== null && uf !== null && uf > df && hiDuring === pf.hi &&
               Math.abs(pf.mx - ex) <= 1 && Math.abs(pf.my - ey) <= 1 };
}
```

Rules:

1. **Move before every click.** The emscripten mousemove handler is the only
   thing that sets the app mouse position; mousedown/mouseup only queue button
   state. Fresh page position is invalid (`-FLT_MAX`) — a click without a prior
   move activates nothing.
2. **Press and release must each render** in separate frames with the item
   hovered (ImGui's `PressedOnClickRelease` — doc table at
   `imgui_widgets.cpp:489-497`; input trickling,
   `ConfigInputTrickleEventQueue`, defers a same-frame release). The
   same-coord refresh is what guarantees rendered frames across the hold
   from a cold idle.
3. **Verify every click:** `ok: true` (position landed, press and release each
   rendered, hover held — `hiDuring === hoverID`) plus a screenshot diff.
   Non-ImGui targets (timeline zone bars) have `hi = 0` by design — for those
   verify by screenshot, not hover.
4. **Double-click trap:** two same-position clicks <300 ms apart = double-click
   (`MouseDoubleClickTime = 0.3 s`) → zoom/thread-info actions fire. Wait
   ≥350 ms between repeated clicks at one spot.
5. **Drag:** move → down → (move + wait 70 ms)×n → up. **Wheel:**
   `page.mouse.wheel({ deltaY: ±500 })` after positioning. **Keys:**
   `page.keyboard.type(..., { delay: 50 })` after focusing the input by click;
   `page.keyboard.press('Enter')`.
6. **Danger:** toolbar device x 10–32 (css 8–26) = red power button (leftmost
   toolbar icon, hover ID 3313137574), closes the trace view (back to "Get
   started"). Never click it unless intended.

## Idle and power saving

`main.cpp DrawContents` keeps an `activeFrames = 3` budget refreshed on any
input event (`tracy::s_wasActive`), a connected client, view animation, or a
queued input; exhausted → `sleep 16 ms` with **no `ImGui::NewFrame` and no GL
draw** (canvas keeps the last frame). Expect ~97 % of ticks to skip rendering
while idle.

- Clicks from a cold idle land only via the click protocol's hold refresh
  (§Click protocol) — a fixed-wait down/up can be swallowed by the idle gate
  (both events received, zero frames rendered). **Before interacting, assert
  `tick`/`f` is advancing**; a stalled main loop (initial trace parse, hidden
  tab) renders nothing and drops everything. During the initial load the
  cursor style is `wait`.
- `focusLostLimit` (reduce render rate on focus loss) is desktop-only; it does
  not exist in the emscripten path.
- `canvas.style.cursor` is **not** a hover oracle: this ImGui build sets the
  Hand cursor only in `TextLink`, not on buttons.

## Targeting

Screenshots never resolve targeting. Full-page shots arrive downscaled JPEG
(1024 px wide for a 2000-px device buffer; the factor varies), and
`page.screenshot({ clip })` returns a PNG at device scale — a W×H CSS clip
returns W·dpr × H·dpr px (CSS = clip offset + px/dpr). Icon buttons are
15–25 device px wide, so visual estimates carry ±20 px error, enough to hit
the neighboring button or a gap. Target from the app's own hit-testing —
sweep the row and click the run's center:

```js
async function sweepRow(dpr, cssY, devFrom, devTo, step = 4) {
  const ranges = []; let cur = null;
  for (let dev = devFrom; dev <= devTo; dev += step) {
    await page.mouse.move(dev / dpr, cssY);
    await new Promise(r => setTimeout(r, 50));
    const s = await snap();
    const hi = s.frames[s.frames.length - 1].hi;
    if (cur && hi === cur.id) cur.end = dev;
    else { if (cur) ranges.push(cur); cur = { id: hi, start: dev, end: dev }; }
  }
  ranges.push(cur);
  return ranges.filter(r => r.id !== 0 && r.end - r.start >= 4);
}
```

- Same non-zero `hi` across consecutive steps = one widget; `hi = 0` = gap.
  Click the run's center: `click((r.start + r.end) / 2 / dpr, cssY)`.
- **Layout is state-dependent:** docked panels (Statistics, Flame, …) resize the
  main window and shift the toolbar — **re-sweep after any state change.**
- **Close popups before sweeping:** while a popup is open, hovers outside the
  popup can read `hi = 0` even over live widgets (verified with ZoomPopup over
  the toolbar). A % click in ZoomPopup does not close the popup — click an
  empty area first.
- Hover IDs are stable across sessions (label hashes) — the map below holds for
  the default state (fresh load, no panels, 1600×900, dpr 1.25).
- Zoomed region shots (for correlating IDs with icons): `page.screenshot({clip})`
  returns a Buffer — write it with Node `fs`, then `read` the file:

```js
const fs = require('fs');
const buf = await page.screenshot({ clip: { x: 0, y: 0, width: 720, height: 28 } });
fs.writeFileSync('/tmp/toolbar-zoom.png', buf);
```

### Toolbar map — default state (device px; css = device/1.25; row y css 15)

| device x | hover ID | function |
|---|---|---|
| 10–32 | 3313137574 | ⏻ power (red, leftmost) — **closes the trace view (DANGER)** |
| 44–68 | 608241489 | ⚙ Options gear — opens the Options window (clickable; do not confuse with the power button) |
| 81–185 | 2246346107 | 💬 Messages panel toggle |
| 199–259 | 3177774389 | 🔍 Find zone toggle (search input hover ID 3637961452, css ~x 100–440, y ~90) |
| 271–367 | 1419322276 | 📊 Statistics toggle |
| 383–451 | 322727105 | 🔥 Flame graph toggle |
| 463–551 | 37993378 | 💾 Memory graph toggle |
| 567–667 | 2133895361 | ⚖ Compare toggle |
| 679–735 | 1808024465 | ⌗ Info (trace information) toggle |
| 751–775 | 2535445525 | 🛠 wrench → ToolsPopup (Playback, CPU data, Annotations, Limits, Wait stacks, Frame statistics) |
| 791–811 | 3101356487 | 📖 book → User manual toggle |
| 827–851 | 2335673581 | 🔍+ → ZoomPopup (50–300 % user scale) |
| 864–888 | 1263603982 | ◀ previous frame — focuses the timeline on the previous frame (view range shrinks to the frame's timespan) |
| ~890–1010 | 0 | frame set name + count text ("Frames: N") — LMB jumps to a specified frame (custom hit-test, like timeline zones) |
| 1012–1036 | 2142681495 | ▶ next frame — focuses the timeline on the next frame (verified: view range 25.82 s → 203.38 ms) |
| 1052–1072 | 2961929287 | ▼ frame set selection (switch the active frame set) |

Button names and functions: the user manual, *Control menu* (`manual/tracy.md`). The
web build omits *Connection* (live capture only) and *Tracy Assist* (desktop only).

## User scale (DPI zoom)

The 🔍+ button (hover ID 2335673581) — *Display scale* in the user manual —
opens a ZoomPopup with 50–300 % steps.
In the web build this scales the UI **layout only**: fonts,
`Style::ScaleAllSizes`, and window sizes (`main.cpp SetupDPIScale`,
`scale = devicePixelRatio × userScale`). The canvas buffer and the mouse→app
mapping stay at `devicePixelRatio` (`BackendEmscripten.cpp`) — hit regions
become physically larger in the same coordinate space, targeting precision is
unchanged, and the standard click protocol works as-is.

Use it when small buttons are hard to hit or details are hard to read in
screenshots. At 200 % every toolbar hit region is roughly 2× (verified: power
16→40 px, gear 25→50 px, Messages 105→190 px wide; row height 24→46 device
px). The layout **reflows completely** at any scale — re-sweep after changing
it and after setting it back. `userScale` is session-only unless Options →
"Save UI scale" is on; a fresh page load starts at 100 %.

## Limitations

- A *connected* live-streaming client cannot be tested in the web build (the
  browser GUI cannot open a TCP server). The embedded-trace GUI is the
  live-app proxy: real trace data, full GUI.
- `embed.tracy` (10 MB) is downloaded from share.nereid.pl at configure time —
  network needed once per fresh workspace; the file then lives in `$WS/build`.

## References

Sources for the behavior the rules above encode — consult them when re-verifying
a constant or a rule fails:

- `profiler/src/BackendEmscripten.cpp` — emscripten input handlers, canvas/dpr
  sizing, cursor mapping.
- `profiler/src/main.cpp:540-574` — idle gate (`activeFrames` budget).
- `profiler/src/profiler/TracyMouse.cpp` — per-frame click state cache.
- `profiler/CMakeLists.txt:334-353` — emscripten link options.
- ImGui 1.92.9b (vendored copy in the CPM cache, `~/.cache/cpm/imgui/`):
  `imgui_widgets.cpp:483-545` (click semantics table), `imgui.cpp:11278-11403`
  (event trickling), `imgui.cpp:1736` (trickle default on), `imgui.cpp:1992-2016`
  (AddMousePosEvent floor/dedup).
- Emscripten 5.0.7: `src/lib/libhtml5.js` (`fillMouseEventData`,
  `targetX = e.clientX - (rect.left|0)` into HEAP32), `system/include/emscripten/html5.h`
  (`EmscriptenMouseEvent.targetX` is `int`; `EmscriptenWheelEvent` embeds a
  `mouse` sub-struct).
- Upstream: imgui issue #4921 (new input event API — events spread over
  multiple frames), PR #2525 (same-frame click/release), issue #1992 (rapid
  down/up "soft clicks" dropped).
