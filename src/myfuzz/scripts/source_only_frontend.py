#!/usr/bin/env python3
"""Source-only frontend manifest fallback for generated RTL projects.

This lightweight frontend reads a Verilog/SystemVerilog filelist, parses module
headers for ports, and emits the subset of the myfuzz frontend manifest needed
by source instrumentation, TOML generation, and harness creation. Source
instrumentation still scans files for branch/case points and hierarchy.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

HDL_SUFFIXES = {".sv", ".v", ".svh", ".vh"}
MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\b")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
RANGE_RE = re.compile(r"\[\s*([^:\]]+)\s*:\s*([^\]]+)\s*\]")
DIRECTION_WORDS = ("input", "output", "inout", "ref")
DECL_KEYWORDS = set(DIRECTION_WORDS) | {
    "wire",
    "reg",
    "logic",
    "signed",
    "unsigned",
    "tri",
    "bit",
}


def mask_comments_and_strings(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            j = text.find("\n", i)
            if j < 0:
                out.append(" " * (n - i))
                break
            out.append(" " * (j - i))
            i = j
            continue
        if ch == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                segment = text[i:]
                out.append("".join("\n" if c == "\n" else " " for c in segment))
                break
            segment = text[i:j + 2]
            out.append("".join("\n" if c == "\n" else " " for c in segment))
            i = j + 2
            continue
        if ch == '"':
            start = i
            i += 1
            escaped = False
            while i < n:
                c = text[i]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    i += 1
                    break
                i += 1
            segment = text[start:i]
            out.append("".join("\n" if c == "\n" else " " for c in segment))
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def find_matching(text: str, start: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    for i in range(start, len(text)):
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return -1


def line_col(text: str, pos: int) -> tuple[int, int]:
    line = text.count("\n", 0, pos) + 1
    bol = text.rfind("\n", 0, pos)
    col = pos + 1 if bol < 0 else pos - bol
    return line, col


def split_top_level_commas(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    paren = bracket = brace = 0
    for i, ch in enumerate(text):
        if ch == "(":
            paren += 1
        elif ch == ")" and paren:
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]" and bracket:
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}" and brace:
            brace -= 1
        elif ch == "," and paren == bracket == brace == 0:
            parts.append(text[start:i])
            start = i + 1
    tail = text[start:]
    if tail.strip():
        parts.append(tail)
    return parts


def const_int(expr: str) -> int | None:
    expr = expr.strip()
    if re.fullmatch(r"[0-9]+", expr):
        return int(expr)
    m = re.fullmatch(r"[0-9]+\s*'\s*[dD]\s*([0-9_]+)", expr)
    if m:
        return int(m.group(1).replace("_", ""))
    m = re.fullmatch(r"[0-9]+\s*'\s*[hH]\s*([0-9a-fA-F_]+)", expr)
    if m:
        return int(m.group(1).replace("_", ""), 16)
    return None


def width_from_ranges(fragment: str) -> int:
    width = 1
    for msb, lsb in RANGE_RE.findall(fragment):
        a = const_int(msb)
        b = const_int(lsb)
        if a is None or b is None:
            continue
        width *= abs(a - b) + 1
    return width


def parse_ansi_ports(header: str) -> list[dict]:
    ports: list[dict] = []
    current_dir = ""
    current_width = 1
    for raw in split_top_level_commas(header):
        part = raw.strip()
        if not part:
            continue
        direction = ""
        for word in DIRECTION_WORDS:
            if re.search(rf"\b{word}\b", part):
                direction = word
                break
        if direction:
            current_dir = direction
            current_width = width_from_ranges(part)
        tokens = IDENT_RE.findall(part)
        names = [tok for tok in tokens if tok not in DECL_KEYWORDS]
        if not names:
            continue
        name = names[-1]
        ports.append(
            {
                "name": name,
                "direction": current_dir or "input",
                "width": current_width,
                "packedWidth": current_width,
                "unpackedRanges": [],
            }
        )
    return ports


def parse_modules(path: Path, project_root: Path, top: str) -> list[dict]:
    text = path.read_text(errors="ignore")
    masked = mask_comments_and_strings(text)
    modules: list[dict] = []
    for match in MODULE_RE.finditer(masked):
        name = match.group(1)
        open_pos = masked.find("(", match.end())
        semi_pos = masked.find(";", match.end())
        ports: list[dict] = []
        if open_pos >= 0 and semi_pos >= 0 and open_pos < semi_pos:
            close_pos = find_matching(masked, open_pos, "(", ")")
            if close_pos >= 0 and close_pos < semi_pos:
                ports = parse_ansi_ports(text[open_pos + 1:close_pos])
        line, col = line_col(text, match.start())
        try:
            rel = path.resolve().relative_to(project_root.resolve()).as_posix()
        except ValueError:
            rel = path.name
        modules.append(
            {
                "name": name,
                "origName": name,
                "file": path.resolve().as_posix(),
                "line": line,
                "column": col,
                "top": name == top,
                "ports": ports,
                "branches": [],
                "instances": [],
                "sourceOnly": True,
                "relPath": rel,
            }
        )
    return modules


def parse_flist(flist: Path, project_root: Path, seen: set[Path] | None = None) -> list[Path]:
    if seen is None:
        seen = set()
    flist = flist.resolve()
    if flist in seen:
        return []
    seen.add(flist)
    files: list[Path] = []
    base = flist.parent
    for raw in flist.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("+"):
            continue
        if line.startswith("-f "):
            files.extend(parse_flist((base / line[3:].strip()).resolve(), project_root, seen))
            continue
        if line.startswith("-F "):
            files.extend(parse_flist((project_root / line[3:].strip()).resolve(), project_root, seen))
            continue
        if line.startswith("-"):
            continue
        path = Path(line.split()[0])
        if not path.is_absolute():
            path = project_root / path
        path = path.resolve()
        if path.suffix in HDL_SUFFIXES and path.exists():
            files.append(path)
    return files


def run_source_only_frontend(root: Path, cfg: dict, paths: dict, *, write_debug_json: bool = True) -> dict:
    del root
    project_root = paths["project_root"].resolve()
    flist = paths["flist"].resolve()
    top = str(cfg["top"])
    modules: list[dict] = []
    for path in parse_flist(flist, project_root):
        modules.extend(parse_modules(path, project_root, top))
    manifest = {
        "frontend": "source_only",
        "projectRoot": project_root.as_posix(),
        "filelist": flist.as_posix(),
        "top": top,
        "modules": modules,
        "module_count": len(modules),
    }
    if write_debug_json:
        paths["frontend_json"].parent.mkdir(parents=True, exist_ok=True)
        paths["frontend_json"].write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
