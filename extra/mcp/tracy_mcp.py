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
import socket
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

_PORT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tracy_mcp.port")
_PID_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tracy_mcp.pid")
_PREFERRED_PORT = int(os.environ.get("TRACY_MCP_PORT", "47380"))


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
    try:
        w = tracy_server.Worker(address, port)
        name = alias or f"live_{address}_{port}"
        instances[name] = TracyInstance(name, w)
        return f"Connected to live instance as '{name}'"
    except Exception as e:
        return f"Failed to connect: {str(e)}"


@mcp_server.tool()
async def load_capture(path: str, alias: str | None = None) -> str:
    """
    Load a .tracy capture file.

    If alias is provided, it is used as the instance name (overwrites existing).
    If no alias, returns a unique ID based on filename and mtime.
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
        return f"Loaded as '{name}'"
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
    Execute Python code against a specific Tracy Worker.

    The variable `ctx` is available for analysis.
    If async_mode=True, returns a task_id immediately.
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
