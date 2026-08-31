#!/usr/bin/env python3
"""Generate the Markdown user manual from the LaTeX source.

Cross-platform replacement for the previous sh/sed/awk pipeline. pandoc is
invoked as a subprocess; its Lua filter (filter.lua, next to the .tex file)
stays with pandoc.
"""

import argparse
import os
import re
import subprocess
import sys

PANDOC_MARKDOWN = 'markdown-simple_tables-multiline_tables-grid_tables+pipe_tables'

NAMES = (
    ('quicklook', 'A quick look at Tracy Profiler'),
    ('firststeps', 'First steps'),
    ('client', 'Client markup'),
    ('capturing', 'Capturing the data'),
    ('analyzingdata', 'Analyzing captured data'),
    ('tracyassist', 'Tracy Assist'),
    ('csvexport', 'Exporting zone statistics to CSV'),
    ('importingdata', 'Importing external profiling data'),
    ('configurationfiles', 'Configuration files'),
)


def parse_icon_header(path):
    """Return (pascal_name -> char, char -> 'Word Word') maps from the icon header."""
    fa = {}
    names = {}
    with open(path, encoding='utf-8') as f:
        for line in f:
            m = re.match(
                r'#define\s+ICON_FA_(\w+)\s+.*?//\s*(U\+([0-9a-fA-F]+))', line
            )
            if m:
                parts = m.group(1).split('_')
                ch = chr(int(m.group(3), 16))
                fa[''.join(p.capitalize() for p in parts)] = ch
                names[ch] = ' '.join(p.capitalize() for p in parts)
    return fa, names


def substitute_icons(text, fa):
    used = set(re.findall(r'\\fa([A-Z][a-zA-Z0-9]*)', text))
    for name in sorted(used, key=lambda n: (-len(n), n)):
        if name not in fa:
            print(f"Warning: \\fa{name} not found in header", file=sys.stderr)
            continue
        ch = fa[name]
        text = text.replace(f'\\fa{name}{{}}~', f'{ch} ')
        text = text.replace(f'\\fa{name}{{}}', ch)
        text = text.replace(f'\\fa{name}~', f'{ch} ')
        text = text.replace(f'\\fa{name}', ch)
    return text


def pre_sed(text):
    text = text.replace('\\menu[,]', '')
    text = text.replace('\\keys', '')
    text = text.replace('\\ctrl', 'Ctrl')
    text = text.replace('\\shift', 'Shift')
    text = text.replace('\\Alt', 'Alt')
    text = text.replace('\\del', 'Delete')
    return text


def post_sed(text):
    for m in ('LMB', 'MMB', 'RMB', 'Scroll'):
        text = text.replace(f'\\{m}{{}}~', '')
    text = text.replace('\\textsigma', 'σ')
    for l in 'abc':
        text = text.replace(f'@\\circled{{{l}}}@', f'({l})')
    for l in 'abc':
        text = text.replace(f'\\circled{{{l}}}', f'({l})')
    text = text.replace('@\\ldots@', '…')
    text = re.sub(r',?escapeinside=\{\}\{\}', '', text)
    for label, name in NAMES:
        text = text.replace(f'\\nameref{{{label}}}', name)
    return text


def bclogo2quote(text):
    """Convert \\begin{bclogo} admonition blocks to \\begin{quote}\\textbf{PREFIX:...}."""
    prefix = {'bcbombe': 'IMPORTANT', 'bcattention': 'CAUTION', 'bclampe': 'TIP'}
    out = []
    in_bclogo = False
    bclogo_type = ''
    for line in text.split('\n'):
        if not in_bclogo and r'\begin{bclogo}[' in line:
            in_bclogo = True
            bclogo_type = ''
            continue
        if in_bclogo and 'logo=' in line:
            if r'\bcbombe' in line:
                bclogo_type = 'bcbombe'
            elif r'\bcattention' in line:
                bclogo_type = 'bcattention'
            elif r'\bclampe' in line:
                bclogo_type = 'bclampe'
            elif r'\bcquestion' in line:
                bclogo_type = 'bcquestion'
            continue
        if in_bclogo and ('noborder' in line or 'couleur' in line):
            continue
        if in_bclogo:
            title = re.sub(r'\}.*$', '', re.sub(r'^[ \t]*\]?\{', '', line))
            out.append(f"\\begin{{quote}}\\textbf{{{prefix.get(bclogo_type, 'NOTE')}:{title}}}\\par")
            in_bclogo = False
            continue
        if r'\end{bclogo}' in line:
            out.append('\\end{quote}')
            continue
        out.append(line)
    return '\n'.join(out)


def run_pandoc(pandoc, filter_path, tex):
    args = [
        pandoc,
        '--wrap=none',
        '--reference-location=block',
        '--number-sections',
        '-f', 'latex',
        '-t', PANDOC_MARKDOWN,
        '-s',
        '-L', filter_path,
        '-',
    ]
    proc = subprocess.run(args, input=tex.encode('utf-8'), capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode('utf-8', 'replace'))
        sys.exit(proc.returncode)
    return proc.stdout.decode('utf-8')


def tablecaption(text):
    """Pandoc emits table captions as ": ..." lines; italicize them instead."""
    out = []
    incap = False
    for line in text.split('\n'):
        if not incap and line.startswith(': '):
            incap = True
            line = '_' + line[2:]
        if incap and not line.endswith('\\'):
            out.append(line + '_')
            incap = False
            continue
        out.append(line)
    return '\n'.join(out)


def admonitions(text):
    for kind in ('IMPORTANT', 'TIP', 'CAUTION', 'NOTE'):
        text = re.sub(
            rf'^> \*\*{kind}:([^*]*)\*\*',
            f'> [!{kind}]\n> **\\1**',
            text,
            flags=re.M,
        )
    return text


def icon_explain(text, names):
    """Append an icon legend to each top-level section containing FA icons."""
    lines = text.split('\n')
    chunk_starts = [i for i, line in enumerate(lines) if line.startswith('#')]
    if chunk_starts and chunk_starts[0] > 0:
        chunk_starts.insert(0, 0)
    out = []
    for ci, start in enumerate(chunk_starts):
        end = chunk_starts[ci + 1] if ci + 1 < len(chunk_starts) else len(lines)
        chunk = lines[start:end]
        icons = []
        seen = set()
        for line in chunk:
            for ch in line:
                cp = ord(ch)
                if 0xE000 <= cp <= 0xF8FF and ch not in seen:
                    seen.add(ch)
                    icons.append(ch)
        out.extend(chunk)
        if icons:
            out.append('')
            out.append('-----')
            out.append('')
            for ch in icons:
                out.append(f"{ch} - {names.get(ch, f'Unknown(U+{ord(ch):04X})')} icon")
            out.append('')
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser(description='Generate the Markdown user manual')
    ap.add_argument('--tex', required=True, help='path to tracy.tex')
    ap.add_argument('--out', required=True, help='path of the generated tracy.md')
    ap.add_argument('--pandoc', required=True, help='path to the pandoc executable')
    ap.add_argument('--icons', required=True, help='path to IconsFontAwesome7.h')
    args = ap.parse_args()

    fa, names = parse_icon_header(args.icons)

    with open(args.tex, encoding='utf-8') as f:
        text = f.read()

    text = pre_sed(text)
    text = substitute_icons(text, fa)
    text = post_sed(text)
    text = bclogo2quote(text)

    md = run_pandoc(
        args.pandoc,
        os.path.join(os.path.dirname(os.path.abspath(args.tex)), 'filter.lua'),
        text,
    )

    md = tablecaption(md)
    md = admonitions(md)
    md = icon_explain(md, names)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, 'w', encoding='utf-8', newline='\n') as f:
        f.write(md)


if __name__ == '__main__':
    main()
