#!/bin/sh
# Derive the project version from the single source of truth:
# public/common/TracyVersion.hpp. Prints X.Y.Z, exits nonzero on failure.

header="$1"

[ -r "$header" ] || {
    echo "tracy-version: cannot read $header" >&2
    exit 1
}

major=$(sed -n 's/.*Major = \([0-9][0-9]*\).*/\1/p' "$header")
minor=$(sed -n 's/.*Minor = \([0-9][0-9]*\).*/\1/p' "$header")
patch=$(sed -n 's/.*Patch = \([0-9][0-9]*\).*/\1/p' "$header")

if [ -n "$major" ] && [ -n "$minor" ] && [ -n "$patch" ]; then
    printf '%s.%s.%s\n' "$major" "$minor" "$patch"
else
    echo "tracy-version: could not parse version from $header" >&2
    exit 1
fi
