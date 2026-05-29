#!/usr/bin/env python3
"""Append icon legend blocks to each markdown section containing Font Awesome icons."""

import re
import sys


def _extract_icons(lines):
    """Return deduplicated icon chars from lines, in order of first appearance."""
    seen = set()
    icons = []
    for line in lines:
        for ch in line:
            cp = ord(ch)
            if 0xE000 <= cp <= 0xF8FF and ch not in seen:
                seen.add(ch)
                icons.append(ch)
    return icons


def _append_legend(result_lines, icons, icon_names):
    """Append a legend block for the given icons."""
    result_lines.append('')
    result_lines.append('-----')
    result_lines.append('')
    for ch in icons:
        name = icon_names.get(ch, f'Unknown(U+{ord(ch):04X})')
        result_lines.append(f'{ch} - {name} icon')
    result_lines.append('')


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <header_path> <md_path>", file=sys.stderr)
        sys.exit(1)

    header_path = sys.argv[1]
    md_path = sys.argv[2]

    # Build char -> name mapping from header
    icon_names = {}
    with open(header_path) as f:
        for line in f:
            m = re.match(
                r'#define\s+ICON_FA_(\w+)\s+.*?//\s*(U\+([0-9a-fA-F]+))', line
            )
            if m:
                snake = m.group(1)
                parts = snake.split('_')
                pascal = ' '.join(p.capitalize() for p in parts)
                codepoint = int(m.group(3), 16)
                icon_names[chr(codepoint)] = pascal

    with open(md_path, encoding='utf-8') as f:
        lines = f.read().split('\n')

    # Build chunk boundaries: header lines and EOF
    chunk_starts = [i for i, line in enumerate(lines) if line.startswith('#')]

    # Also add index 0 as a chunk start if there's pre-header content
    if chunk_starts and chunk_starts[0] > 0:
        chunk_starts.insert(0, 0)

    result_lines = []
    for ci, start in enumerate(chunk_starts):
        end = chunk_starts[ci + 1] if ci + 1 < len(chunk_starts) else len(lines)
        icons = _extract_icons(lines[start:end])
        result_lines.extend(lines[start:end])
        if icons:
            _append_legend(result_lines, icons, icon_names)

    with open(md_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(result_lines))


if __name__ == '__main__':
    main()
