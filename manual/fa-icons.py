#!/usr/bin/env python3
"""Replace Font Awesome icon macros in LaTeX with Unicode codepoints."""

import re
import sys

def pascal_to_snake(name):
    """Convert PascalCase to UPPER_SNAKE_CASE."""
    result = name[0]
    for i in range(1, len(name)):
        if name[i].isupper() and name[i - 1].islower():
            result += '_'
        result += name[i]
    return result.upper()

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <header_path> <tex_path>", file=sys.stderr)
        sys.exit(1)

    header_path = sys.argv[1]
    tex_path = sys.argv[2]

    # Parse header: ICON_FA_SNAKE_CASE -> Unicode char
    icons = {}
    with open(header_path) as f:
        for line in f:
            m = re.match(
                r'#define\s+ICON_FA_(\w+)\s+.*?//\s*(U\+([0-9a-fA-F]+))', line
            )
            if m:
                snake = m.group(1)
                parts = snake.split('_')
                pascal = ''.join(p.capitalize() for p in parts)
                codepoint = int(m.group(3), 16)
                icons[pascal] = chr(codepoint)

    # Read tex file
    with open(tex_path) as f:
        text = f.read()

    # Find all \faXxx used in the text (uppercase first letter excludes \fancyhead etc.)
    used = set()
    for m in re.finditer(r'\\fa([A-Z][a-zA-Z0-9]*)', text):
        used.add(m.group(1))

    # Replace each used icon, longest names first to avoid prefix conflicts
    for name in sorted(used, key=lambda n: (-len(n), n)):
        if name not in icons:
            print(f"Warning: \\fa{name} not found in header", file=sys.stderr)
            continue
        char = icons[name]
        # Order matters: more specific patterns first
        text = text.replace(f'\\fa{name}{{}}~', f'{char} ')
        text = text.replace(f'\\fa{name}{{}}', char)
        text = text.replace(f'\\fa{name}~', f'{char} ')
        text = text.replace(f'\\fa{name}', char)

    # Write back
    with open(tex_path, 'w') as f:
        f.write(text)

if __name__ == '__main__':
    main()