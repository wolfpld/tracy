#!/bin/sh
# Start the Tracy MCP server.
#
# Set PYTHONPATH to the directory containing TracyServerBindings.so/.pyd.
# Adjust the Release/Debug suffix to match your CMake build configuration.
PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$(dirname "$0")/../../build/python/Release"
export PYTHONPATH

# Machine-local overrides (not committed). Create start_mcp.local.sh next to
# this file to set TRACY_CAPTURES_DIR, TRACY_MCP_PORT, or any other env var:
#   export TRACY_CAPTURES_DIR=/path/to/captures
#   export TRACY_MCP_PORT=47380
if [ -f "$(dirname "$0")/start_mcp.local.sh" ]; then
    . "$(dirname "$0")/start_mcp.local.sh"
fi

exec python3 "$(dirname "$0")/tracy_mcp.py" "$@"
