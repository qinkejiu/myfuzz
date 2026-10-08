"""Read the documented runtime evidence inventory without starting any harness."""
from __future__ import annotations

import hashlib
from pathlib import Path, PurePosixPath
import re
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DOCUMENT = ROOT / 'docs/LOCAL_HARNESS_RUNTIME.md'
_HEADER = ('组件/协议', '当前证据', '等级')


def _cells(line: str) -> list[str]:
    if not line.startswith('|') or not line.endswith('|'):
        raise ValueError('capability table row must start and end with |')
    # Preserve Markdown verbatim, including escaped literal pipes in cell text.
    return [item.strip() for item in re.split(r'(?<!\\)\|', line)[1:-1]]


def _evidence_paths(text: str) -> list[str]:
    paths = []
    for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', text):
        if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target) or target.startswith(('/', '#')):
            continue
        # Links in LOCAL_HARNESS_RUNTIME are relative to docs/.
        parts: list[str] = ['docs']
        for part in PurePosixPath(target.split('#', 1)[0]).parts:
            if part == '..':
                if not parts:
                    raise ValueError('evidence link escapes repository')
                parts.pop()
            elif part != '.':
                parts.append(part)
        path = '/'.join(parts)
        if path not in paths:
            paths.append(path)
    return paths


def parse_capabilities_document(text: str) -> dict[str, Any]:
    """Parse the single authoritative table; refuse malformed or missing evidence."""
    lines = text.splitlines(keepends=True)
    headings = [index for index, line in enumerate(lines)
                if line.rstrip('\r\n') == '## 当前可运行路径']
    if len(headings) != 1:
        raise ValueError('expected exactly one 当前可运行路径 section')
    index = headings[0] + 1
    while index < len(lines) and not lines[index].strip():
        index += 1
    if index >= len(lines) or tuple(_cells(lines[index].strip())) != _HEADER:
        raise ValueError('unexpected capability table header')
    index += 1
    if index >= len(lines):
        raise ValueError('missing capability table separator')
    separators = _cells(lines[index].strip())
    if len(separators) != 3 or not all(re.fullmatch(r':?-{3,}:?', cell)
                                          for cell in separators):
        raise ValueError('invalid capability table separator')
    index += 1
    rows = []
    while index < len(lines) and lines[index].strip():
        source_text = lines[index].rstrip('\r\n')
        fields = _cells(source_text)
        if len(fields) != 3 or not all(fields):
            raise ValueError(f'invalid capability table row at line {index + 1}')
        rows.append(dict(zip(('component', 'evidence', 'level'), fields),
                         source_line=index + 1, source_text=source_text,
                         evidence_paths=_evidence_paths(source_text)))
        index += 1
    if not rows:
        raise ValueError('capability evidence table is empty')
    # Keep all later prose: global boundaries must remain visible after filtering.
    # Split by headings only to supply usable source references, without interpreting
    # the prose or declaring more capabilities than the table provides.
    sections = []
    start, title = index, '当前可运行路径补充'
    for cursor in range(index, len(lines) + 1):
        heading = re.match(r'^#{2,6} (.+?)\s*$', lines[cursor]) if cursor < len(lines) else None
        if cursor == len(lines) or heading:
            raw = ''.join(lines[start:cursor])
            if raw.strip():
                sections.append({'title': title, 'source_line': start + 1,
                                 'text': raw, 'evidence_paths': _evidence_paths(raw)})
            if heading:
                start, title = cursor, heading.group(1)
    return {'capabilities': rows, 'limitations': sections}


def query_capabilities(*, match: str | None = None) -> dict[str, Any]:
    """Expose current documented evidence and its digest; never revalidate RTL."""
    content = DOCUMENT.read_bytes()
    result = parse_capabilities_document(content.decode('utf-8'))
    total = len(result['capabilities'])
    if match is not None:
        needle = match.casefold()
        result['capabilities'] = [row for row in result['capabilities']
                                  if any(needle in row[field].casefold()
                                         for field in ('component', 'evidence', 'level'))]
    return {'schema': 'myfuzz.documented_capabilities.v1',
            'basis': 'documented_evidence', 'runtime_revalidated': False,
            'source': {'path': 'docs/LOCAL_HARNESS_RUNTIME.md',
                       'sha256': hashlib.sha256(content).hexdigest()},
            'total_documented_rows': total, **result}
