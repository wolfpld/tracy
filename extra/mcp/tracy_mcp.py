# -*- coding: utf-8 -*-
from __future__ import annotations

import asyncio
import atexit
import builtins
import concurrent.futures
import glob
import io
import os
import logging
import re
import socket
import struct
import sys
import time
import uuid
from contextlib import redirect_stdout

import mcp.server.fastmcp as fastmcp

# Suppress noisy ASGI shutdown errors known to occur with SSE and Control-C.
# These occur when Starlette attempts to send a 500 error after the loop is cancelled
# but after the SSE 200 OK headers have already been sent. Global level suppression
# is used because surgical filtering of ASGI exceptions is unreliable in this stack.
logging.getLogger("uvicorn.error").setLevel(logging.CRITICAL)
logging.getLogger("starlette").setLevel(logging.CRITICAL)

_HERE = os.path.dirname(os.path.abspath(__file__))
_PORT_FILE = os.path.join(_HERE, "tracy_mcp.port")
_PID_FILE  = os.path.join(_HERE, "tracy_mcp.pid")
_PREFERRED_PORT = int(os.environ.get("TRACY_MCP_PORT", "47380"))

# Shared documentation surfaces. system.prompt.md is Tracy Assist's source
# system prompt; exposing it as an MCP resource keeps analysis guidance in
# sync across both surfaces with no plumbing. eval_guide.md covers
# bindings-layer detail (ctx object model, units, source-location ID joins).
_LLM_DIR = os.path.normpath(os.path.join(_HERE, "..", "..", "profiler", "src", "llm"))
_PROMPT_PATH = os.path.join(_LLM_DIR, "system.prompt.md")
_EVAL_GUIDE_PATH = os.path.join(_HERE, "eval_guide.md")


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"(unavailable: {e})"


# Tracy UDP broadcast packet support. Tracy clients announce themselves on
# port 8086 with a BroadcastMessage (see public/common/TracyProtocol.hpp).
# The dev GUI reads protocolVersion from the broadcast and refuses connection
# on mismatch instead of hitting an opaque TCP timeout. We do the same.
_PROTOCOL_HPP = os.path.normpath(
    os.path.join(_HERE, "..", "..", "public", "common", "TracyProtocol.hpp")
)
_BROADCAST_PORT = 8086
_PROGRAM_NAME_SIZE = 64


def _read_bindings_protocol_version() -> int | None:
    """Parse ProtocolVersion from TracyProtocol.hpp at startup so our 'expected'
    version stays in sync with the bindings build without extra C++ wiring."""
    try:
        with open(_PROTOCOL_HPP, encoding="utf-8") as f:
            for line in f:
                m = re.search(r"constexpr\s+uint32_t\s+ProtocolVersion\s*=\s*(\d+)", line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return None


_OUR_PROTOCOL_VERSION = _read_bindings_protocol_version()


def _parse_broadcast(data: bytes) -> dict | None:
    """Parse a Tracy BroadcastMessage. Handles broadcast versions 0-3.

    Fixed-field sizes (from TracyProtocol.hpp, packed):
      v3: u16 bv, u16 lp, u32 pv, u64 pid, i32 at, char[<=64] name  (>=20 + name)
      v2: u16 bv, u16 lp, u32 pv, i32 at, char[<=64] name           (>=12 + name)
      v1: u32 bv, u32 pv, u32 lp, u32 at, char[<=64] name           (>=16 + name)
      v0: u32 bv, u32 pv, u32 at, char[<=64] name                   (>=12 + name)

    The programName field is variable-length on the wire — the sender writes
    only the actual name plus null terminator, not the full 64-byte buffer.
    """
    if len(data) < 4:
        return None

    def _name(buf: bytes) -> str:
        return buf[:_PROGRAM_NAME_SIZE].split(b"\0", 1)[0].decode("utf-8", "replace")

    bv16 = struct.unpack_from("<H", data, 0)[0]
    if bv16 == 3 and len(data) >= 21:
        bv, lp, pv, pid, at = struct.unpack_from("<HHIQi", data, 0)
        return {"broadcast_version": bv, "listen_port": lp,
                "protocol_version": pv, "pid": pid,
                "active_seconds": at, "program": _name(data[20:])}
    if bv16 == 2 and len(data) >= 13:
        bv, lp, pv, at = struct.unpack_from("<HHIi", data, 0)
        return {"broadcast_version": bv, "listen_port": lp,
                "protocol_version": pv, "active_seconds": at,
                "program": _name(data[12:])}
    bv32 = struct.unpack_from("<I", data, 0)[0]
    if bv32 == 1 and len(data) >= 17:
        bv, pv, lp, at = struct.unpack_from("<IIII", data, 0)
        return {"broadcast_version": bv, "listen_port": lp,
                "protocol_version": pv, "active_seconds": at,
                "program": _name(data[16:])}
    if bv32 == 0 and len(data) >= 13:
        bv, pv, at = struct.unpack_from("<III", data, 0)
        return {"broadcast_version": bv, "listen_port": None,
                "protocol_version": pv, "active_seconds": at,
                "program": _name(data[12:])}
    return None


async def _listen_broadcasts(timeout_s: float = 1.5) -> list[dict]:
    """Listen briefly on UDP 8086 for Tracy client announcements.

    Returns a list of parsed broadcasts (deduplicated by listen_port). Empty
    list means no broadcast received — the target may use TRACY_ON_DEMAND,
    a non-default broadcast port, or simply isn't running.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("", _BROADCAST_PORT))
    except OSError:
        s.close()
        return []
    s.setblocking(False)
    loop = asyncio.get_running_loop()
    seen: dict[int | None, dict] = {}
    deadline = loop.time() + timeout_s
    try:
        while loop.time() < deadline:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                fut = loop.sock_recvfrom(s, 2048)
                data, _addr = await asyncio.wait_for(fut, timeout=remaining)
            except (asyncio.TimeoutError, BlockingIOError):
                break
            parsed = _parse_broadcast(data)
            if parsed:
                seen.setdefault(parsed.get("listen_port"), parsed)
    finally:
        s.close()
    return list(seen.values())


def _is_our_server_running() -> tuple[bool, int]:
    """
    Check the PID file to see if our server is already running.
    Returns (running, port). Uses os.kill(pid, 0) to confirm the process is alive.
    """
    try:
        with open(_PID_FILE) as f:
            pid = int(f.read().strip())
        with open(_PORT_FILE) as f:
            port = int(f.read().strip())
        os.kill(pid, 0)   # raises OSError if process is gone
        return True, port
    except Exception:
        return False, 0


def _find_free_port() -> int:
    """Scan from preferred port upward; fall back to OS-assigned if the range is exhausted."""
    for port in range(_PREFERRED_PORT, _PREFERRED_PORT + 16):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            s.close()
            return port
        except OSError:
            s.close()
    # Let OS assign any free port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _write_pid_and_port(port: int) -> None:
    try:
        with open(_PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        with open(_PORT_FILE, "w") as f:
            f.write(str(port))
    except Exception:
        pass


def _cleanup_pid_files() -> None:
    for path in (_PID_FILE, _PORT_FILE):
        try:
            os.unlink(path)
        except Exception:
            pass


# Attempt to import Tracy Server bindings
try:
    import TracyServerBindings as tracy_server
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(__file__), "../../build/python"))
    try:
        import TracyServerBindings as tracy_server
    except ImportError:
        tracy_server = None

mcp_server = fastmcp.FastMCP("Tracy Profiler")
executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)


class Task:
    def __init__(self, task_id: str, code: str):
        self.id = task_id
        self.code = code
        self.status = "pending"
        self.result = None
        self.error = None
        self.start_time = time.time()
        self.end_time = None


class TracyInstance:
    def __init__(self, name: str, worker: object | None = None):
        self.name = name
        self.worker = worker
        self.path = None
        self.mtime = None


instances: dict[str, TracyInstance] = {}
tasks: dict[str, Task] = {}
captures_dir: str | None = os.environ.get("TRACY_CAPTURES_DIR")


@mcp_server.resource("tracy://prompt")
def _prompt_resource() -> str:
    """Tracy Assist's analysis guidance (system.prompt.md). Contains workflows
    for optimization, callstack inspection, and privacy rules. %TIME%, %USER%,
    and %PROGRAMNAME% are placeholders filled by the in-app chat — ignore them
    when reading from MCP."""
    return _read_text(_PROMPT_PATH)


@mcp_server.resource("tracy://eval-guide")
def _eval_guide_resource() -> str:
    """Bindings-layer guide for the eval tool: ctx object model, time units,
    source-location ID semantics, and worked examples translating catalog
    entries into ctx Python."""
    return _read_text(_EVAL_GUIDE_PATH)


@mcp_server.tool()
async def list_captures() -> list[str]:
    """List .tracy capture files in the TRACY_CAPTURES_DIR directory (non-recursive)."""
    if not captures_dir:
        return []
    return sorted(glob.glob(os.path.join(captures_dir, "*.tracy")))


@mcp_server.tool()
async def list_instances() -> list[dict]:
    """List all loaded Tracy instances and captures with metadata."""
    return [
        {
            "id": name,
            "path": inst.path,
            "mtime": inst.mtime,
            "live": inst.path is None
        }
        for name, inst in instances.items()
    ]


@mcp_server.tool()
async def discover_instances(port_range: str = "8086-8095") -> list[dict]:
    """
    Scan for running Tracy-instrumented applications on local ports.

    Returns a list of discovered ports that are listening.
    """
    start_port, end_port = map(int, port_range.split("-"))
    discovered = []

    async def check_port(port: int) -> None:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", port), timeout=0.1
            )
            writer.close()
            await writer.wait_closed()
            discovered.append({"port": port, "address": "127.0.0.1"})
        except (OSError, asyncio.TimeoutError, ConnectionRefusedError):
            pass

    await asyncio.gather(*(check_port(p) for p in range(start_port, end_port + 1)))
    return discovered


@mcp_server.tool()
async def live_connect(address: str = "127.0.0.1", port: int = 8086, alias: str | None = None) -> str:
    """
    Connect to a live running Tracy-instrumented application.

    Wraps Worker(addr, port, memoryLimit=-1). Returns the instance_id.
    """
    if not tracy_server:
        return "Error: Tracy Server bindings not found."

    # Pre-flight: read Tracy's UDP broadcast on port 8086 and compare protocol
    # versions before attempting TCP. Mirrors what the Tracy GUI does so a
    # version mismatch produces a precise error instead of an opaque timeout.
    # Tracy clients broadcast every ~3s (TracyProfiler.cpp), so we listen a
    # little longer to guarantee catching at least one beat.
    broadcasts = await _listen_broadcasts(timeout_s=3.5)
    match = next((b for b in broadcasts if b.get("listen_port") == port), None)
    if match and _OUR_PROTOCOL_VERSION is not None:
        if match["protocol_version"] != _OUR_PROTOCOL_VERSION:
            return (
                f"Protocol mismatch: target program '{match['program']}' "
                f"announces Tracy protocol v{match['protocol_version']} on "
                f"{address}:{port}, but these server bindings are built "
                f"against v{_OUR_PROTOCOL_VERSION}. Rebuild the bindings or "
                f"the target against a matching Tracy version."
            )

    try:
        w = tracy_server.Worker(address, port)
    except Exception as e:
        return f"Failed to connect: {str(e)}"

    # Worker construction returns immediately even on protocol failure (the
    # bindings expose no error state — is_connected() is the only signal).
    # Probe briefly so silent failures (e.g. TRACY_ON_DEMAND with no profiler
    # request yet, or a target broadcasting on a non-default port) surface
    # cleanly even when broadcast pre-flight didn't catch them.
    deadline_s = 2.0
    step_s = 0.1
    elapsed = 0.0
    while elapsed < deadline_s and not w.is_connected():
        await asyncio.sleep(step_s)
        elapsed += step_s

    if not w.is_connected():
        try:
            w.shutdown()
        except Exception:
            pass
        hint = ""
        if broadcasts and not match:
            seen = ", ".join(
                f"'{b['program']}' on port {b.get('listen_port')} (protocol v{b['protocol_version']})"
                for b in broadcasts
            )
            hint = f" Detected other Tracy broadcasts: {seen}."
        elif not broadcasts:
            hint = (
                " No Tracy broadcasts were received on port 8086 in 3.5s — "
                "the target may use TRACY_ON_DEMAND, a non-default broadcast "
                "port, or isn't running."
            )
        return (
            f"Reached {address}:{port} but the Tracy handshake did not complete "
            f"within {deadline_s:.1f}s.{hint} Common causes: (1) the Tracy "
            f"client version embedded in the target program differs from these "
            f"server bindings; (2) the target was built with TRACY_ON_DEMAND "
            f"and is awaiting a profiler request; (3) another client is "
            f"already attached."
        )

    name = alias or f"live_{address}_{port}"
    instances[name] = TracyInstance(name, w)
    return (
        f"Connected to live instance as '{name}'. "
        f"Before your first eval, read resources tracy://prompt "
        f"(analysis guidance) and tracy://eval-guide (ctx object model, "
        f"ns time units, srcloc IDs)."
    )


@mcp_server.tool()
async def load_capture(path: str, alias: str | None = None) -> str:
    """
    Load a .tracy capture file by absolute path.

    Parameters:
      path  — absolute path to a .tracy file. On Windows use backslashes
              (e.g. 'E:\\\\traces\\\\foo.tracy').
      alias — optional instance name; overwrites existing on collision.
              If omitted, an ID is derived from filename and mtime.

    If you don't already have a path, call `list_captures` first — it lists
    .tracy files in the TRACY_CAPTURES_DIR environment directory.
    """
    if not tracy_server:
        return "Error: Tracy Server bindings not found."
    try:
        mtime = os.path.getmtime(path)
        if alias:
            name = alias
        else:
            # unique name including mtime to avoid version collision
            name = f"{os.path.basename(path)}@{int(mtime):x}"

        if name in instances:
            inst = instances[name]
            if inst.path == path and inst.mtime == mtime:
                return f"Instance '{name}' is already loaded and up to date."

        f = tracy_server.open_file(path)
        w = tracy_server.create_worker_from_file(f)
        inst = TracyInstance(name, w)
        inst.path = path
        inst.mtime = mtime
        instances[name] = inst
        return (
            f"Loaded as '{name}'. "
            f"Before your first eval, read resources tracy://prompt "
            f"(analysis guidance) and tracy://eval-guide (ctx object model, "
            f"ns time units, srcloc IDs)."
        )
    except Exception as e:
        return f"Failed to load: {str(e)}"


@mcp_server.tool()
async def unload_capture(instance_id: str) -> str:
    """Unload a Tracy instance and release its memory."""
    if instance_id in instances:
        del instances[instance_id]
        return f"Instance '{instance_id}' unloaded."
    return f"Instance '{instance_id}' not found."


@mcp_server.tool(name="eval")
async def tracy_eval(code: str, instance_id: str, async_mode: bool = False) -> object:
    """
    Execute Python code against a specific Tracy Worker bound as `ctx`.

    On first use, read the `tracy://prompt` (analysis guidance) and
    `tracy://eval-guide` (ctx object model, units, source-location ID joins)
    resources. Time values returned by Worker methods are nanoseconds.

    If async_mode=True, returns a task_id immediately; poll via the `task` tool.
    """
    if instance_id not in instances:
        return f"Error: Instance '{instance_id}' not found. Use list_instances to find valid IDs."

    instance = instances[instance_id]
    if not instance.worker:
        return f"Error: Instance '{instance_id}' has no worker."

    if not async_mode:
        return await _execute_eval(code, instance.worker)

    # Async mode: spawn task and return immediately
    task_id = str(uuid.uuid4())
    task = Task(task_id, code)
    tasks[task_id] = task
    asyncio.get_running_loop().run_in_executor(
        executor, _run_task_sync, task, instance.worker
    )
    return {"task_id": task_id, "status": "running"}


def _run_task_sync(task: Task, worker: object) -> None:
    """Run a background eval task in the thread pool."""
    task.status = "running"
    try:
        task.result = _execute_eval_sync(task.code, worker)
        task.status = "completed"
    except Exception as e:
        task.error = str(e)
        task.status = "failed"
    finally:
        task.end_time = time.time()


def _execute_eval_sync(code: str, ctx: object) -> str:
    """Execute *code* with `ctx` bound to the Tracy worker. Captures stdout."""
    global_vars = {
        "__builtins__": builtins,
        "ctx": ctx,
        "tracy": tracy_server,
        "instances": {name: inst.worker for name, inst in instances.items()},
    }
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            result = eval(compile(code, "<eval>", "eval"), global_vars)
        except SyntaxError:
            exec(compile(code, "<exec>", "exec"), global_vars)
            result = None
    output = buf.getvalue()
    if result is None:
        return output or ""
    return str(result)


async def _execute_eval(code: str, ctx: object) -> str:
    """Async wrapper: runs `_execute_eval_sync` in the thread-pool executor."""
    return await asyncio.get_running_loop().run_in_executor(
        executor, _execute_eval_sync, code, ctx
    )


@mcp_server.tool()
async def task(action: str, task_id: str | None = None) -> object:
    """
    Manage background analysis tasks.

    Actions: poll, cancel, list
    """
    if action == "list":
        return [
            {"id": t.id, "status": t.status, "elapsed": time.time() - t.start_time}
            for t in tasks.values()
        ]

    if not task_id or task_id not in tasks:
        return "Error: Task ID not found."

    t = tasks[task_id]
    if action == "poll":
        res: dict = {"id": t.id, "status": t.status}
        if t.status == "completed":
            res["result"] = t.result
        elif t.status == "failed":
            res["error"] = t.error
        return res

    if action == "cancel":
        # Cancellation of thread-pool work is not possible post-submission;
        # mark the task so callers know it was abandoned.
        if t.status == "running":
            t.status = "cancelled"
            return f"Task {task_id} marked as cancelled."
        return f"Task {task_id} is not running."

    return "Error: Unknown action."


@mcp_server.tool()
async def shutdown_server() -> str:
    """
    Shut down the Tracy MCP server.

    Because the server runs as a singleton (SSE transport, one process shared
    across all VS Code windows), this releases the TracyServerBindings.pyd lock
    for all clients at once. Restart tracy_mcp.py after rebuilding.
    """
    import threading
    def _exit() -> None:
        time.sleep(0.2)
        os._exit(0)
    threading.Thread(target=_exit, daemon=True).start()
    return "Server shutting down. Restart tracy_mcp.py to reconnect."


if __name__ == "__main__":
    atexit.register(_cleanup_pid_files)

    running, existing_port = _is_our_server_running()
    if running:
        print(
            f"Tracy MCP already running on port {existing_port}. "
            "All VS Code windows share that instance.",
            file=sys.stderr,
        )
        sys.exit(0)

    port = _find_free_port()
    _write_pid_and_port(port)

    print(f"Tracy MCP listening on http://127.0.0.1:{port}/sse", file=sys.stderr)

    mcp_server.settings.host = "127.0.0.1"
    mcp_server.settings.port = port
    try:
        mcp_server.run(transport="sse")
    except KeyboardInterrupt:
        print("\nTracy MCP server stopped.", file=sys.stderr)
        sys.exit(0)
