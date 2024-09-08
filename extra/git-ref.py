#!/bin/env python3

import filecmp
import subprocess
import os

out = "GitRef.hpp"
tmp = f"{out}.tmp"

try:
    ref = subprocess.run(["git", "rev-parse", "--short", "HEAD"], check=True, capture_output=True).stdout.decode().strip()
except subprocess.CalledProcessError:
    ref = "unknown"

if not os.path.exists(out):
    with open(out, "w") as f:
        print(f"#pragma once\n\nnamespace tracy {{ static inline const char* GitRef = \"{ref}\"; }}", file=f)
else:
    with open(tmp, "w") as f:
        print(f"#pragma once\n\nnamespace tracy {{ static inline const char* GitRef = \"{ref}\"; }}", file=f)
    if not filecmp.cmp(out, tmp, shallow=False):
        os.replace(tmp, out)
    else:
        os.unlink(tmp)