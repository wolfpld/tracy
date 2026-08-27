#!/usr/bin/env python3
# Derive the project version from the single source of truth:
# public/common/TracyVersion.hpp. Prints X.Y.Z, exits nonzero on failure.
import re
import sys

header = sys.argv[1]
try:
    with open(header, encoding='utf-8') as f:
        text = f.read()
except OSError as exc:
    print('tracy-version: cannot read %s: %s' % (header, exc), file=sys.stderr)
    sys.exit(1)

numbers = {}
for name in ('Major', 'Minor', 'Patch'):
    match = re.search(r'%s\s*=\s*(\d+)' % name, text)
    if not match:
        print('tracy-version: could not parse version from %s' % header, file=sys.stderr)
        sys.exit(1)
    numbers[name] = match.group(1)

print('%s.%s.%s' % (numbers['Major'], numbers['Minor'], numbers['Patch']))
