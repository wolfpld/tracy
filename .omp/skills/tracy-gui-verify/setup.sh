#!/bin/sh
# setup.sh - build the instrumented Tracy web GUI workspace (see SKILL.md).
#
# Usage:
#   sh setup.sh
#   TRACY_WEB_WS=/custom/ws TRACY_WEB_REPO=<repo> sh setup.sh
#
# Idempotent: reuses an existing source copy and build dir, skips
# already-applied harness patch hunks, rebuilds.
set -e

WS="${TRACY_WEB_WS:-/tmp/tracy-protocol}"
# The skill is project-scoped: <repo>/.omp/skills/tracy-gui-verify/
SKILL_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -n "$TRACY_WEB_REPO" ]; then
	REPO="$TRACY_WEB_REPO"
else
	REPO=$(cd "$SKILL_DIR/../../.." 2>/dev/null && pwd) || REPO=""
fi
EMSDK="${EMSDK_DIR:-$HOME/emsdk}"

[ -x "$EMSDK/emsdk" ] || { echo "error: emsdk not found at $EMSDK (set EMSDK_DIR)" >&2; exit 1; }
[ -f "$REPO/profiler/CMakeLists.txt" ] || { echo "error: not a Tracy repo: '$REPO' (set TRACY_WEB_REPO)" >&2; exit 1; }

. "$EMSDK/emsdk_env.sh" >/dev/null 2>&1 || true
command -v emcc >/dev/null || { echo "error: emcc not on PATH after emsdk_env.sh" >&2; exit 1; }

if [ ! -f "$WS/src/profiler/CMakeLists.txt" ]; then
	echo "[setup] fresh source copy -> $WS/src (from $REPO)"
	mkdir -p "$WS/src"
	# -C applies to both archive creation and extraction; exclude all build dirs
	tar -C "$REPO" \
		--exclude=.git \
		--exclude='*/build*' \
		-cf - . | tar -xf - -C "$WS/src"
else
	echo "[setup] reusing source copy in $WS/src (copy changed repo files into it first)"
fi

# The harness is fully in place iff each patch hunk's signature line is present.
# patch --forward skips a whole file once its first hunk is detected as already
# applied, so a failed later hunk is invisible in patch's output and exit code —
# verify the content instead of trusting either.
harness_complete()
{
	grep -q '_debug_snapshot' "$WS/src/profiler/CMakeLists.txt" \
	&& grep -qF 'EMSCRIPTEN_KEEPALIVE const char* debug_snapshot' "$WS/src/profiler/src/BackendEmscripten.cpp" \
	&& grep -qF 'DbgPushEvent( 1,' "$WS/src/profiler/src/BackendEmscripten.cpp" \
	&& grep -qF 's_dbgTick++;' "$WS/src/profiler/src/BackendEmscripten.cpp"
}

echo "[setup] applying instrumentation harness"
if harness_complete; then
	echo "[setup] harness already applied"
	rm -f "$WS/src/profiler/CMakeLists.txt.rej" "$WS/src/profiler/src/BackendEmscripten.cpp.rej"
else
	rm -f "$WS/src/profiler/CMakeLists.txt.rej" "$WS/src/profiler/src/BackendEmscripten.cpp.rej"
	patch -p1 -d "$WS/src" --forward --no-backup-if-mismatch < "$SKILL_DIR/harness.patch" \
		|| {
			if harness_complete; then
				# mixed run: some hunks already present (skipped), the rest applied
				rm -f "$WS/src/profiler/CMakeLists.txt.rej" "$WS/src/profiler/src/BackendEmscripten.cpp.rej"
			else
				rej=$(ls "$WS/src/profiler/CMakeLists.txt.rej" "$WS/src/profiler/src/BackendEmscripten.cpp.rej" 2>/dev/null || true)
				if [ -n "$rej" ]; then
					kept="The unapplied hunks are kept in:
$(printf '%s\n' $rej | sed 's/^/  /')"
				else
					kept="No .rej files were produced (fatal patch error); the patch output above is the only evidence."
				fi
				cat >&2 <<EOF
error: harness patch did not fully apply — $WS/src has drifted from the repo.
$kept
Do not build from this workspace. Either re-apply the harness by hand
(SKILL.md, "After editing the GUI in the repo"), or start fresh:
  rm -rf $WS && sh <this-skill-dir>/setup.sh
EOF
				exit 1
			fi
		}
fi

if [ ! -f "$WS/build/CMakeCache.txt" ]; then
	echo "[setup] configuring"
	cmake -S "$WS/src/profiler" -B "$WS/build" \
		-DCMAKE_TOOLCHAIN_FILE="$EMSDK/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake" \
		-DCMAKE_BUILD_TYPE=Release \
		-DCPM_SOURCE_CACHE="$HOME/.cache/cpm"
fi

echo "[setup] building (first full build ~3-5 min, incremental ~30 s)"
cmake --build "$WS/build" -j "$(nproc)"

cat <<EOF
[setup] done.
  workspace : $WS
  repo      : $REPO
  emcc      : $(emcc --version | sed -n 1p)
  serve     : hub op=start name=tracy-web application=python3 args=[$WS/build/httpd.py] cwd=$WS/build ready={port:8000} persist=true
  open      : browser open url=http://127.0.0.1:8000/index.html viewport={width:1600,height:900}
  ready     : document.title matches / - Tracy Profiler/ (see SKILL.md)
EOF
