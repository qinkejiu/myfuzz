#!/usr/bin/env python3
"""Source-tree coverage inserter for Verilog/SystemVerilog.

This tool keeps the original RTL tree read-only. It copies HDL files into an
output tree, then inserts simple sticky coverage-hit signals into the copied
files and records source-level metadata for non-runtime expression/static forms.
It also propagates coverage from instantiated children to their parents by
adding a coverage output port to instrumented modules and wiring child coverage
vectors into the parent vector.

The implementation is intentionally conservative: it scans source text and only
instruments executable bodies inside runtime regions
(always/initial/final/function/task). Generate/module-level constructs are
reported as metadata. Single-statement runtime bodies are wrapped in begin/end
only when the corresponding setting explicitly enables that source rewrite.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

sys.dont_write_bytecode = True


HDL_SUFFIXES = {".sv", ".svh", ".v", ".vh"}
DEFAULT_EXCLUDES = {
    ".git",
    "build",
    "obj_dir",
    "sim_build",
    "__pycache__",
}
MARKER_BEGIN = "// myfuzz coverage begin"
MARKER_END = "// myfuzz coverage end"
HIER_MARKER_BEGIN = "// myfuzz hierarchy coverage begin"
HIER_MARKER_END = "// myfuzz hierarchy coverage end"
ELSE_IF_CLOSE_ORDER_BASE = 1_000_000_000


@dataclass(frozen=True)
class Token:
    text: str
    start: int
    end: int


@dataclass(frozen=True)
class ModuleRegion:
    name: str
    start: int
    name_end: int
    header_end: int
    end: int


@dataclass(frozen=True)
class RuntimeRange:
    start: int
    end: int
    kind: str
    begin_pos: int


@dataclass(frozen=True)
class Insertion:
    offset: int
    text: str
    order: int


@dataclass(frozen=True)
class CoveragePoint:
    file: str
    module: str
    signal: str
    kind: str
    subtype: str
    line: int
    column: int
    fail: bool = False
    expr: str = ""


@dataclass(frozen=True)
class MetadataPoint:
    file: str
    module: str
    kind: str
    subtype: str
    line: int
    column: int
    detail: str = ""


@dataclass(frozen=True)
class InstanceInfo:
    file: str
    parent: str
    child: str
    name: str
    port_open: int
    port_close: int
    named_ports: bool
    line: int
    column: int


@dataclass
class ChildConnection:
    instance: InstanceInfo
    width: int
    wire: str


@dataclass
class FrontendBranchCandidate:
    kind: str
    subtype: str
    line: int
    column: int
    file: str = ""
    used: bool = False


@dataclass(frozen=True)
class FrontendInstanceCandidate:
    name: str
    orig_name: str
    child: str
    child_orig: str
    line: int
    column: int
    file: str = ""


@dataclass
class FrontendModuleInfo:
    name: str
    source_name: str
    rel_path: Path | None
    branches: list[FrontendBranchCandidate] = field(default_factory=list)
    instances: list[FrontendInstanceCandidate] = field(default_factory=list)


@dataclass
class FrontendIndex:
    by_key: dict[tuple[str, str], FrontendModuleInfo] = field(default_factory=dict)
    by_module: dict[str, list[FrontendModuleInfo]] = field(default_factory=dict)


@dataclass
class FlistParseResult:
    files: list[Path] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    incdirs: set[Path] = field(default_factory=set)


@dataclass(frozen=True)
class BranchSettings:
    if_enable: bool = True
    case_enable: bool = True
    case_default: bool = True
    else_if: bool = False
    else_missing: bool = False


@dataclass(frozen=True)
class StatementSettings:
    block_enter: bool = False
    procedural_assign: bool = False
    call: bool = False
    control: bool = False


@dataclass(frozen=True)
class LoopSettings:
    body: bool = False
    single_statement: bool = False


@dataclass(frozen=True)
class ExpressionSettings:
    ternary: bool = False
    condition: bool = False
    toggle: bool = False


@dataclass(frozen=True)
class AssertionSettings:
    hit: bool = False
    metadata: bool = True
    fail_on_side_effect: bool = False
    neutralize_side_effects: bool = False


@dataclass(frozen=True)
class StaticSettings:
    generate: bool = True


@dataclass(frozen=True)
class HierarchySettings:
    propagate_to_top: bool = True


@dataclass(frozen=True)
class InstrumentationSettings:
    branch: BranchSettings = field(default_factory=BranchSettings)
    statement: StatementSettings = field(default_factory=StatementSettings)
    loop: LoopSettings = field(default_factory=LoopSettings)
    expression: ExpressionSettings = field(default_factory=ExpressionSettings)
    assertion: AssertionSettings = field(default_factory=AssertionSettings)
    static: StaticSettings = field(default_factory=StaticSettings)
    hierarchy: HierarchySettings = field(default_factory=HierarchySettings)

    @classmethod
    def from_dict(cls, data: dict | None) -> "InstrumentationSettings":
        if not data:
            return cls()
        if "instrumentation" in data and isinstance(data["instrumentation"], dict):
            data = data["instrumentation"]
        branch = data.get("branch", {}) if isinstance(data.get("branch", {}), dict) else {}
        statement = data.get("statement", {}) if isinstance(data.get("statement", {}), dict) else {}
        loop = data.get("loop", {}) if isinstance(data.get("loop", {}), dict) else {}
        expression = data.get("expression", {}) if isinstance(data.get("expression", {}), dict) else {}
        assertion = data.get("assertion", {}) if isinstance(data.get("assertion", {}), dict) else {}
        static = data.get("static", {}) if isinstance(data.get("static", {}), dict) else {}
        hierarchy = data.get("hierarchy", {}) if isinstance(data.get("hierarchy", {}), dict) else {}
        return cls(
            branch=BranchSettings(
                if_enable=bool(branch.get("if", True)),
                case_enable=bool(branch.get("case", True)),
                case_default=bool(branch.get("case_default", True)),
                else_if=bool(branch.get("else_if", False)),
                else_missing=bool(branch.get("else_missing", False)),
            ),
            statement=StatementSettings(
                block_enter=bool(statement.get("block_enter", False)),
                procedural_assign=bool(statement.get("procedural_assign", False)),
                call=bool(statement.get("call", False)),
                control=bool(statement.get("control", False)),
            ),
            loop=LoopSettings(
                body=bool(loop.get("body", False)),
                single_statement=bool(loop.get("single_statement", False)),
            ),
            expression=ExpressionSettings(
                ternary=bool(expression.get("ternary", False)),
                condition=bool(expression.get("condition", False)),
                toggle=bool(expression.get("toggle", False)),
            ),
            assertion=AssertionSettings(
                hit=bool(assertion.get("hit", False)),
                metadata=bool(assertion.get("metadata", True)),
                fail_on_side_effect=bool(assertion.get("fail_on_side_effect", False)),
                neutralize_side_effects=bool(assertion.get("neutralize_side_effects", False)),
            ),
            static=StaticSettings(generate=bool(static.get("generate", True))),
            hierarchy=HierarchySettings(propagate_to_top=bool(hierarchy.get("propagate_to_top", True))),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "branch": {
                "if": self.branch.if_enable,
                "case": self.branch.case_enable,
                "case_default": self.branch.case_default,
                "else_if": self.branch.else_if,
                "else_missing": self.branch.else_missing,
            },
            "statement": {
                "block_enter": self.statement.block_enter,
                "procedural_assign": self.statement.procedural_assign,
                "call": self.statement.call,
                "control": self.statement.control,
            },
            "loop": {
                "body": self.loop.body,
                "single_statement": self.loop.single_statement,
            },
            "expression": {
                "ternary": self.expression.ternary,
                "condition": self.expression.condition,
                "toggle": self.expression.toggle,
            },
            "assertion": {
                "hit": self.assertion.hit,
                "metadata": self.assertion.metadata,
                "fail_on_side_effect": self.assertion.fail_on_side_effect,
                "neutralize_side_effects": self.assertion.neutralize_side_effects,
            },
            "static": {
                "generate": self.static.generate,
            },
            "hierarchy": {
                "propagate_to_top": self.hierarchy.propagate_to_top,
            },
        }


@dataclass
class RewriteResult:
    insertions: list[Insertion]
    points: list[CoveragePoint]
    skipped: dict[str, int]
    metadata: list[MetadataPoint] = field(default_factory=list)


@dataclass
class ModulePlan:
    path: Path
    rel_path: Path
    text: str
    masked: str
    region: ModuleRegion
    insertions: list[Insertion]
    points: list[CoveragePoint]
    skipped: dict[str, int]
    metadata: list[MetadataPoint] = field(default_factory=list)
    instances: list[InstanceInfo] = field(default_factory=list)
    child_connections: list[ChildConnection] = field(default_factory=list)
    coverage_width: int = 0
    frontend: FrontendModuleInfo | None = None


@dataclass
class FilePlan:
    src: Path
    rel_path: Path
    text: str
    masked: str
    insertions: list[Insertion]
    points: list[CoveragePoint]
    skipped: dict[str, int]
    modules: list[ModulePlan]
    metadata: list[MetadataPoint] = field(default_factory=list)


WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]*")
MODULE_RE = re.compile(r"\bmodule\b")
PORT_DIRECTION_WORDS = {"input", "output", "inout", "ref"}
HEADER_IMPORT_WORDS = {"import", "export"}
DECLARATION_WORDS = {
    "automatic",
    "bit",
    "byte",
    "chandle",
    "event",
    "int",
    "integer",
    "logic",
    "longint",
    "real",
    "realtime",
    "reg",
    "shortint",
    "shortreal",
    "signed",
    "string",
    "time",
}


def mask_comments_and_strings(text: str) -> str:
    chars = list(text)
    i = 0
    while i < len(chars):
        if text.startswith("//", i):
            j = text.find("\n", i + 2)
            if j < 0:
                j = len(chars)
            for k in range(i, j):
                chars[k] = " "
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                j = len(chars) - 2
            for k in range(i, min(j + 2, len(chars))):
                if chars[k] != "\n":
                    chars[k] = " "
            i = j + 2
        elif chars[i] == '"':
            i += 1
            while i < len(chars):
                if chars[i] == "\\":
                    if chars[i] != "\n":
                        chars[i] = " "
                    if i + 1 < len(chars) and chars[i + 1] != "\n":
                        chars[i + 1] = " "
                    i += 2
                    continue
                old = chars[i]
                if old != "\n":
                    chars[i] = " "
                i += 1
                if old == '"':
                    break
        else:
            i += 1
    return "".join(chars)


def line_col(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_nl = text.rfind("\n", 0, offset)
    col = offset + 1 if last_nl < 0 else offset - last_nl
    return line, col


def line_indent(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    match = re.match(r"[ \t]*", text[start:offset])
    return match.group(0) if match else ""


def skip_ws(masked: str, pos: int, limit: int | None = None) -> int:
    if limit is None:
        limit = len(masked)
    while pos < limit and masked[pos].isspace():
        pos += 1
    return pos


def word_at(masked: str, pos: int, word: str) -> bool:
    end = pos + len(word)
    if masked[pos:end] != word:
        return False
    before = pos == 0 or not re.match(r"[A-Za-z0-9_$]", masked[pos - 1])
    after = end >= len(masked) or not re.match(r"[A-Za-z0-9_$]", masked[end])
    return before and after


def next_token(masked: str, pos: int, limit: int | None = None) -> Token | None:
    if limit is None:
        limit = len(masked)
    pos = skip_ws(masked, pos, limit)
    if pos >= limit:
        return None
    match = WORD_RE.match(masked, pos)
    if match:
        return Token(match.group(0), match.start(), match.end())
    return Token(masked[pos], pos, pos + 1)


def iter_tokens(masked: str, start: int, end: int) -> Iterable[Token]:
    pos = start
    while True:
        tok = next_token(masked, pos, end)
        if tok is None:
            return
        yield tok
        pos = tok.end


def find_matching_pair(masked: str, open_pos: int, open_ch: str, close_ch: str) -> int | None:
    depth = 0
    i = open_pos
    while i < len(masked):
        ch = masked[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def find_matching_begin(masked: str, begin_pos: int, limit: int) -> int | None:
    depth = 0
    for tok in iter_tokens(masked, begin_pos, limit):
        if tok.text == "begin":
            depth += 1
        elif tok.text == "end":
            depth -= 1
            if depth == 0:
                return tok.start
    return None


def find_matching_case(masked: str, case_pos: int, limit: int) -> int | None:
    depth = 0
    for tok in iter_tokens(masked, case_pos, limit):
        if tok.text in {"case", "casez", "casex"}:
            depth += 1
        elif tok.text == "endcase":
            depth -= 1
            if depth == 0:
                return tok.start
    return None


def find_matching_end_word(masked: str, start: int, limit: int, end_word: str) -> int | None:
    for tok in iter_tokens(masked, start, limit):
        if tok.text == end_word:
            return tok.start
    return None


def after_begin_label(masked: str, begin_pos: int, limit: int) -> int:
    pos = begin_pos + len("begin")
    pos = skip_ws(masked, pos, limit)
    if pos < limit and masked[pos] == ":":
        pos = skip_ws(masked, pos + 1, limit)
        label = WORD_RE.match(masked, pos)
        if label:
            pos = label.end()
    return pos


def after_begin_declarations(masked: str, begin_pos: int, limit: int) -> int:
    pos = after_begin_label(masked, begin_pos, limit)
    pos = skip_ws(masked, pos, limit)
    while True:
        tok = next_token(masked, pos, limit)
        if tok is None or tok.text not in DECLARATION_WORDS:
            return pos
        stmt_end = find_statement_end(masked, tok.start, limit)
        if stmt_end is None:
            return pos
        pos = skip_ws(masked, stmt_end + 1, limit)


def skip_module_header_imports(masked: str, pos: int, limit: int) -> int | None:
    """Skip SystemVerilog module header import/export declarations.

    SystemVerilog permits declarations such as:

      module m import pkg::*; #(parameter int N = 1) (...);

    The semicolon after the import is not the end of the module header.
    """
    pos = skip_ws(masked, pos, limit)
    while pos < limit:
        tok = next_token(masked, pos, limit)
        if tok is None or tok.text not in HEADER_IMPORT_WORDS:
            return pos
        semi = masked.find(";", tok.end, limit)
        if semi < 0:
            return None
        pos = skip_ws(masked, semi + 1, limit)
    return pos


def module_header_port_list(masked: str, name_end: int, limit: int) -> tuple[int, int, int] | None:
    """Return (header_end, port_open, port_close) for a module header.

    port_open/port_close are -1 for legal no-port module declarations.
    """
    pos = skip_module_header_imports(masked, name_end, limit)
    if pos is None:
        return None

    if pos < limit and masked[pos] == "#":
        pos = skip_ws(masked, pos + 1, limit)
        if pos >= limit or masked[pos] != "(":
            return None
        param_close = find_matching_pair(masked, pos, "(", ")")
        if param_close is None or param_close >= limit:
            return None
        pos = skip_ws(masked, param_close + 1, limit)
        pos = skip_module_header_imports(masked, pos, limit)
        if pos is None:
            return None

    if pos < limit and masked[pos] == "(":
        port_close = find_matching_pair(masked, pos, "(", ")")
        if port_close is None or port_close >= limit:
            return None
        semi = skip_ws(masked, port_close + 1, limit)
        if semi >= limit or masked[semi] != ";":
            return None
        return semi + 1, pos, port_close

    if pos < limit and masked[pos] == ";":
        return pos + 1, -1, -1
    return None


def find_module_regions(masked: str) -> list[ModuleRegion]:
    regions: list[ModuleRegion] = []
    for match in MODULE_RE.finditer(masked):
        pos = match.start()
        name_tok = next_token(masked, match.end())
        if name_tok is None or not WORD_RE.fullmatch(name_tok.text):
            continue
        header = module_header_port_list(masked, name_tok.end, len(masked))
        if header is None:
            continue
        header_end = header[0]
        end_match = re.search(r"\bendmodule\b", masked[header_end:])
        if not end_match:
            continue
        end = header_end + end_match.end()
        regions.append(ModuleRegion(name_tok.text, pos, name_tok.end, header_end, end))
    return regions


def find_module_port_list(masked: str, module: ModuleRegion) -> tuple[int, int] | None:
    """Return the module header port-list parens, after any parameter list."""
    header = module_header_port_list(masked, module.name_end, module.header_end)
    if header is None:
        return None
    _, port_open, port_close = header
    if port_open < 0 or port_close < 0:
        return None
    return port_open, port_close


def header_uses_ansi_ports(masked: str, port_open: int, port_close: int) -> bool:
    for tok in iter_tokens(masked, port_open + 1, port_close):
        if tok.text in PORT_DIRECTION_WORDS:
            return True
    return False


def previous_non_ws(masked: str, start: int, end: int) -> str | None:
    pos = end - 1
    while pos >= start:
        if not masked[pos].isspace():
            return masked[pos]
        pos -= 1
    return None


def append_list_item_text(
    text: str,
    masked: str,
    open_pos: int,
    close_pos: int,
    item: str,
) -> str:
    has_items = bool(masked[open_pos + 1 : close_pos].strip())
    prev = previous_non_ws(masked, open_pos + 1, close_pos)
    comma = "," if has_items and prev != "," else ""
    indent = line_indent(text, close_pos) + "  "
    return f"{comma}\n{indent}{item}"


def append_list_item_offset(masked: str, open_pos: int, close_pos: int) -> int:
    pos = close_pos - 1
    while pos > open_pos and masked[pos].isspace():
        pos -= 1
    if pos > open_pos:
        return pos + 1
    return close_pos


def width_prefix(width: int) -> str:
    return "" if width == 1 else f"[{width - 1}:0] "


def safe_identifier(raw: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_$]", "_", raw)
    if not safe or safe[0].isdigit():
        safe = f"_{safe}"
    return safe


def normalize_frontend_module_name(name: str) -> str:
    if "__V" in name:
        return name.split("__V", 1)[0]
    return name


def frontend_rel_path(raw: str, project_root: Path) -> Path | None:
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute():
        path = (project_root / path).resolve()
    else:
        path = path.resolve()
    try:
        return path.relative_to(project_root.resolve())
    except ValueError:
        return Path(path.name)


def load_frontend_index_from_data(data: dict | None, project_root: Path) -> FrontendIndex | None:
    if not data:
        return None
    index = FrontendIndex()
    for raw_mod in data.get("modules", []):
        name = str(raw_mod.get("name", ""))
        orig_name = str(raw_mod.get("origName", "")) or name
        source_name = normalize_frontend_module_name(orig_name or name)
        rel_path = frontend_rel_path(str(raw_mod.get("file", "")), project_root)
        info = FrontendModuleInfo(name=name, source_name=source_name, rel_path=rel_path)
        for raw_branch in raw_mod.get("branches", []):
            line = int(raw_branch.get("line") or 0)
            if line <= 0:
                continue
            info.branches.append(
                FrontendBranchCandidate(
                    kind=str(raw_branch.get("kind", "")),
                    subtype=str(raw_branch.get("subtype", "")),
                    line=line,
                    column=int(raw_branch.get("column") or 0),
                    file=str(raw_branch.get("file", "")),
                )
            )
        for raw_inst in raw_mod.get("instances", []):
            line = int(raw_inst.get("line") or 0)
            if line <= 0:
                continue
            child = normalize_frontend_module_name(str(raw_inst.get("childOrig", "")) or str(raw_inst.get("child", "")))
            info.instances.append(
                FrontendInstanceCandidate(
                    name=str(raw_inst.get("name", "")),
                    orig_name=str(raw_inst.get("origName", "")),
                    child=child,
                    child_orig=str(raw_inst.get("childOrig", "")),
                    line=line,
                    column=int(raw_inst.get("column") or 0),
                    file=str(raw_inst.get("file", "")),
                )
            )
        keys = {(info.source_name, rel_path.as_posix() if rel_path else "")}
        keys.add((name, rel_path.as_posix() if rel_path else ""))
        keys.add((orig_name, rel_path.as_posix() if rel_path else ""))
        for key in keys:
            index.by_key[key] = info
        for mod_name in {info.source_name, name, orig_name}:
            index.by_module.setdefault(mod_name, []).append(info)
    return index


def load_frontend_index(frontend_json: str | None, project_root: Path) -> FrontendIndex | None:
    if not frontend_json:
        return None
    path = Path(frontend_json).resolve()
    return load_frontend_index_from_data(json.loads(path.read_text()), project_root)


def match_frontend_module(
    frontend: FrontendIndex | None,
    module_name: str,
    rel_path: Path,
) -> FrontendModuleInfo | None:
    if frontend is None:
        return None
    rel_key = rel_path.as_posix()
    for name in (module_name, normalize_frontend_module_name(module_name)):
        info = frontend.by_key.get((name, rel_key))
        if info is not None:
            return info
    candidates = frontend.by_module.get(module_name, [])
    if len(candidates) == 1:
        return candidates[0]
    for info in candidates:
        if info.rel_path == rel_path:
            return info
    return None


def offset_from_line_col(text: str, line: int, column: int = 0) -> int | None:
    if line <= 0:
        return None
    pos = 0
    current = 1
    while current < line:
        nxt = text.find("\n", pos)
        if nxt < 0:
            return None
        pos = nxt + 1
        current += 1
    if column > 0:
        return min(pos + column - 1, len(text))
    return pos


def token_line(tok_text: str, text: str, token_start: int) -> int:
    return line_col(text, token_start)[0]


def branch_matches_candidate(
    candidate: FrontendBranchCandidate,
    kind: str,
    subtype: str,
    text: str,
    token_start: int,
) -> bool:
    if candidate.used:
        return False
    if candidate.kind != kind:
        return False
    if candidate.subtype != subtype:
        return False
    return abs(candidate.line - token_line(kind, text, token_start)) <= 1


def next_frontend_branch(
    frontend: FrontendModuleInfo | None,
    kind: str,
    subtype: str,
    text: str,
    token_start: int,
) -> FrontendBranchCandidate | None:
    if frontend is None:
        return FrontendBranchCandidate(kind=kind, subtype=subtype, line=token_line(kind, text, token_start), column=0)
    for candidate in frontend.branches:
        if branch_matches_candidate(candidate, kind, subtype, text, token_start):
            candidate.used = True
            return candidate
    for candidate in frontend.branches:
        if candidate.used:
            continue
        if candidate.kind == kind and candidate.subtype == subtype:
            candidate.used = True
            return candidate
    return None


def candidate_line_col(
    candidate: FrontendBranchCandidate | None,
    text: str,
    token_start: int,
) -> tuple[int, int]:
    if candidate is not None and candidate.line > 0:
        return candidate.line, candidate.column
    return line_col(text, token_start)


def find_statement_end(masked: str, start: int, limit: int) -> int | None:
    paren = bracket = brace = 0
    pos = start
    while pos < limit:
        ch = masked[pos]
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
        elif ch == ";" and paren == bracket == brace == 0:
            return pos
        pos += 1
    return None


def port_list_is_named(masked: str, open_pos: int, close_pos: int) -> bool:
    pos = skip_ws(masked, open_pos + 1, close_pos)
    return pos < close_pos and masked[pos] == "."


def parse_instance_statement(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    child_name: str,
    pos: int,
    stmt_end: int,
    skipped: dict[str, int],
) -> list[InstanceInfo]:
    instances: list[InstanceInfo] = []

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    while pos < stmt_end:
        name_tok = next_token(masked, pos, stmt_end)
        if name_tok is None or not WORD_RE.fullmatch(name_tok.text):
            break
        inst_name = name_tok.text
        body_pos = skip_ws(masked, name_tok.end, stmt_end)
        if body_pos < stmt_end and masked[body_pos] == "[":
            skip("instance_array_unpropagated")
            arr_close = find_matching_pair(masked, body_pos, "[", "]")
            if arr_close is None or arr_close >= stmt_end:
                break
            body_pos = skip_ws(masked, arr_close + 1, stmt_end)
        if body_pos >= stmt_end or masked[body_pos] != "(":
            skip("instance_without_port_list")
            break
        port_close = find_matching_pair(masked, body_pos, "(", ")")
        if port_close is None or port_close > stmt_end:
            skip("instance_unmatched_port_list")
            break
        line, col = line_col(text, name_tok.start)
        instances.append(
            InstanceInfo(
                file=path.as_posix(),
                parent=module.name,
                child=child_name,
                name=inst_name,
                port_open=body_pos,
                port_close=port_close,
                named_ports=port_list_is_named(masked, body_pos, port_close),
                line=line,
                column=col,
            )
        )
        pos = skip_ws(masked, port_close + 1, stmt_end)
        if pos < stmt_end and masked[pos] == ",":
            pos = skip_ws(masked, pos + 1, stmt_end)
            continue
        break
    return instances


def collect_instances(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    module_names: set[str],
) -> tuple[list[InstanceInfo], dict[str, int]]:
    instances: list[InstanceInfo] = []
    skipped: dict[str, int] = {}
    runtime_ranges = collect_runtime_ranges(masked, module)
    pos = module.header_end
    while True:
        tok = next_token(masked, pos, module.end)
        if tok is None:
            break
        pos = tok.end
        if tok.text not in module_names or tok.text == module.name:
            continue
        if inside_any(tok.start, runtime_ranges):
            continue
        after_type = skip_ws(masked, tok.end, module.end)
        if after_type < module.end and masked[after_type] == "#":
            param_open = skip_ws(masked, after_type + 1, module.end)
            if param_open >= module.end or masked[param_open] != "(":
                skipped["instance_bad_parameter_override"] = skipped.get("instance_bad_parameter_override", 0) + 1
                continue
            param_close = find_matching_pair(masked, param_open, "(", ")")
            if param_close is None:
                skipped["instance_unmatched_parameter_override"] = (
                    skipped.get("instance_unmatched_parameter_override", 0) + 1
                )
                continue
            after_type = skip_ws(masked, param_close + 1, module.end)
        stmt_end = find_statement_end(masked, after_type, module.end)
        if stmt_end is None:
            skipped["instance_unmatched_statement"] = skipped.get("instance_unmatched_statement", 0) + 1
            continue
        instances.extend(
            parse_instance_statement(
                text, masked, path, module, tok.text, after_type, stmt_end, skipped
            )
        )
        pos = stmt_end + 1
    return instances, skipped


def collect_frontend_instances(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    frontend: FrontendModuleInfo,
    module_names: set[str],
) -> tuple[list[InstanceInfo], dict[str, int]]:
    instances: list[InstanceInfo] = []
    skipped: dict[str, int] = {}
    runtime_ranges = collect_runtime_ranges(masked, module)
    seen_port_lists: set[tuple[int, int]] = set()

    for candidate in frontend.instances:
        child = normalize_frontend_module_name(candidate.child)
        if child not in module_names:
            skipped["frontend_instance_child_not_in_source"] = (
                skipped.get("frontend_instance_child_not_in_source", 0) + 1
            )
            continue
        start = offset_from_line_col(text, candidate.line, candidate.column) or module.header_end
        search_from = max(module.header_end, start - 256)
        name_match: re.Match[str] | None = None
        port_open: int | None = None
        port_close: int | None = None
        saw_name = False
        saw_array = False
        saw_unmatched_port_list = False
        names = [name for name in (candidate.name, candidate.orig_name) if name]
        for inst_name in dict.fromkeys(names):
            name_re = re.compile(rf"\b{re.escape(inst_name)}\b")
            for match in name_re.finditer(masked, search_from, module.end):
                if inside_any(match.start(), runtime_ranges):
                    continue
                saw_name = True
                maybe_port_open = skip_ws(masked, match.end(), module.end)
                if maybe_port_open < module.end and masked[maybe_port_open] == "[":
                    saw_array = True
                    continue
                if maybe_port_open >= module.end or masked[maybe_port_open] != "(":
                    continue
                maybe_port_close = find_matching_pair(masked, maybe_port_open, "(", ")")
                if maybe_port_close is None:
                    saw_unmatched_port_list = True
                    continue
                name_match = match
                port_open = maybe_port_open
                port_close = maybe_port_close
                break
            if name_match is not None:
                break
        if name_match is None:
            if saw_unmatched_port_list:
                skipped["frontend_instance_unmatched_port_list"] = (
                    skipped.get("frontend_instance_unmatched_port_list", 0) + 1
                )
            elif saw_array:
                skipped["frontend_instance_array_unpropagated"] = (
                    skipped.get("frontend_instance_array_unpropagated", 0) + 1
                )
            elif saw_name:
                skipped["frontend_instance_without_port_list"] = (
                    skipped.get("frontend_instance_without_port_list", 0) + 1
                )
            else:
                skipped["frontend_instance_name_not_found"] = skipped.get(
                    "frontend_instance_name_not_found", 0
                ) + 1
            continue
        assert port_open is not None
        assert port_close is not None
        port_key = (port_open, port_close)
        if port_key in seen_port_lists:
            skipped["frontend_instance_same_source_port_list_deduped"] = (
                skipped.get("frontend_instance_same_source_port_list_deduped", 0) + 1
            )
            continue
        seen_port_lists.add(port_key)
        line, col = line_col(text, name_match.start())
        instances.append(
            InstanceInfo(
                file=path.as_posix(),
                parent=module.name,
                child=child,
                name=candidate.name,
                port_open=port_open,
                port_close=port_close,
                named_ports=port_list_is_named(masked, port_open, port_close),
                line=line,
                column=col,
            )
        )
    return instances, skipped


def collect_runtime_ranges(masked: str, module: ModuleRegion) -> list[RuntimeRange]:
    ranges: list[RuntimeRange] = []
    runtime_words = {"always", "always_comb", "always_ff", "always_latch", "initial", "final"}
    for tok in iter_tokens(masked, module.header_end, module.end):
        if tok.text in runtime_words:
            body_pos = runtime_body_start(masked, tok, module.end)
            if body_pos is None or not is_begin_at(masked, body_pos):
                continue
            end = find_matching_begin(masked, body_pos, module.end)
            if end is not None:
                ranges.append(RuntimeRange(tok.start, end + len("end"), tok.text, body_pos))
        elif tok.text == "function":
            end = find_matching_end_word(masked, tok.end, module.end, "endfunction")
            if end is not None:
                semi = masked.find(";", tok.end, end)
                body_pos = semi + 1 if semi >= 0 else tok.end
                ranges.append(RuntimeRange(tok.start, end + len("endfunction"), tok.text, body_pos or tok.end))
        elif tok.text == "task":
            end = find_matching_end_word(masked, tok.end, module.end, "endtask")
            if end is not None:
                semi = masked.find(";", tok.end, end)
                body_pos = semi + 1 if semi >= 0 else tok.end
                ranges.append(RuntimeRange(tok.start, end + len("endtask"), tok.text, body_pos or tok.end))
    return ranges


def runtime_body_start(masked: str, runtime_tok: Token, limit: int) -> int | None:
    pos = skip_ws(masked, runtime_tok.end, limit)
    if pos < limit and masked[pos] == "@":
        pos = skip_ws(masked, pos + 1, limit)
        if pos < limit and masked[pos] == "(":
            close = find_matching_pair(masked, pos, "(", ")")
            if close is None:
                return None
            pos = skip_ws(masked, close + 1, limit)
        elif pos < limit and masked[pos] == "*":
            pos = skip_ws(masked, pos + 1, limit)
        else:
            event_tok = next_token(masked, pos, limit)
            if event_tok is None:
                return None
            pos = skip_ws(masked, event_tok.end, limit)
    return pos if pos < limit else None


def find_next_word(masked: str, word: str, start: int, limit: int) -> int | None:
    pattern = re.compile(rf"\b{re.escape(word)}\b")
    match = pattern.search(masked, start, limit)
    return None if match is None else match.start()


def inside_any(pos: int, ranges: list[RuntimeRange]) -> bool:
    return any(r.start <= pos < r.end for r in ranges)


def containing_range(pos: int, ranges: list[RuntimeRange]) -> RuntimeRange | None:
    for runtime in ranges:
        if runtime.start <= pos < runtime.end:
            return runtime
    return None


def nested_runtime_depth(pos: int, ranges: list[RuntimeRange]) -> int:
    return sum(1 for runtime in ranges if runtime.start <= pos < runtime.end)


def is_begin_at(masked: str, pos: int) -> bool:
    return word_at(masked, pos, "begin")


def make_hit_text(text: str, offset: int, signal: str, comment: str) -> str:
    base_indent = line_indent(text, offset)
    hit_indent = "  "
    return f"{hit_indent}{signal} = 1'b1; // {comment}\n{base_indent}"


def make_standalone_hit_text(text: str, offset: int, signal: str, comment: str) -> str:
    indent = line_indent(text, offset)
    return f"\n{indent}{signal} = 1'b1; // {comment}"


def make_pre_statement_hit_text(text: str, offset: int, signal: str, comment: str) -> str:
    indent = line_indent(text, offset)
    return f"{indent}{signal} = 1'b1; // {comment}\n"


def line_head_insertion_offset(text: str, offset: int) -> int:
    return text.rfind("\n", 0, offset) + 1


def else_if_close_order(if_pos: int) -> int:
    return ELSE_IF_CLOSE_ORDER_BASE - if_pos


def instrument_begin_body(
    text: str,
    masked: str,
    begin_pos: int,
    limit: int,
    signal: str,
    comment: str,
    order: int,
) -> Insertion | None:
    end = find_matching_begin(masked, begin_pos, limit)
    if end is None:
        return None
    insert_at = after_begin_declarations(masked, begin_pos, limit)
    return Insertion(insert_at, make_hit_text(text, insert_at, signal, comment), order)


def statement_body_supported(masked: str, body_pos: int, limit: int) -> bool:
    tok = next_token(masked, body_pos, limit)
    if tok is None:
        return False
    # Avoid changing nested control-statement binding in the source rewriter.
    return tok.text not in {
        "if",
        "case",
        "casez",
        "casex",
        "for",
        "foreach",
        "while",
        "repeat",
        "forever",
        "begin",
        "fork",
        "priority",
        "unique",
        "unique0",
    }


def instrument_single_statement_body(
    text: str,
    masked: str,
    body_pos: int,
    limit: int,
    signal: str,
    comment: str,
    order: int,
) -> tuple[list[Insertion], int] | None:
    if not statement_body_supported(masked, body_pos, limit):
        return None
    stmt_end = find_statement_end(masked, body_pos, limit)
    if stmt_end is None:
        return None
    indent = line_indent(text, body_pos)
    open_text = f"begin\n{indent}  {signal} = 1'b1; // {comment}\n{indent}  "
    close_text = f"\n{indent}end"
    return [Insertion(body_pos, open_text, order), Insertion(stmt_end + 1, close_text, order + 1)], stmt_end + 1


def instrument_branch_body(
    text: str,
    masked: str,
    body_pos: int,
    limit: int,
    signal: str,
    comment: str,
    order: int,
) -> tuple[list[Insertion], int] | None:
    if is_begin_at(masked, body_pos):
        insertion = instrument_begin_body(text, masked, body_pos, limit, signal, comment, order)
        if insertion is None:
            return None
        end = find_matching_begin(masked, body_pos, limit)
        if end is None:
            return None
        return [insertion], end + len("end")
    return instrument_single_statement_body(text, masked, body_pos, limit, signal, comment, order)


ASSERT_SIDE_EFFECT_RE = re.compile(r"\$(?:fatal|stop)\b")
ASSERT_ACTION_LINE_RE = re.compile(
    r"(?m)^([ \t]*)\$(?:fatal|stop)(?:\s*\([^;\n]*\))?\s*;.*$"
)
ASSERT_MESSAGE_LINE_RE = re.compile(
    r"(?m)^([ \t]*)\$fwrite\s*\([^;\n]*\)\s*;.*$"
)


def branch_body_has_assert_side_effect(text: str, body_pos: int, body_end: int) -> bool:
    return ASSERT_SIDE_EFFECT_RE.search(text[body_pos:body_end]) is not None


def neutralize_assertion_side_effects(text: str) -> str:
    text = ASSERT_ACTION_LINE_RE.sub(r"\1; // myfuzz neutralized assertion side effect", text)
    return ASSERT_MESSAGE_LINE_RE.sub(r"\1; // myfuzz neutralized assertion message", text)


def if_statement_end(masked: str, if_pos: int, limit: int) -> int | None:
    tok = next_token(masked, if_pos, limit)
    if tok is None or tok.text != "if":
        return None
    open_pos = skip_ws(masked, tok.end, limit)
    if open_pos >= limit or masked[open_pos] != "(":
        return None
    close_pos = find_matching_pair(masked, open_pos, "(", ")")
    if close_pos is None:
        return None
    body_pos = skip_ws(masked, close_pos + 1, limit)
    if is_begin_at(masked, body_pos):
        body_end = find_matching_begin(masked, body_pos, limit)
        if body_end is None:
            return None
        then_end = body_end + len("end")
    else:
        stmt_end = find_statement_end(masked, body_pos, limit)
        if stmt_end is None:
            return None
        then_end = stmt_end + 1
    after_then = skip_ws(masked, then_end, limit)
    if not word_at(masked, after_then, "else"):
        return then_end
    else_pos = skip_ws(masked, after_then + len("else"), limit)
    if word_at(masked, else_pos, "if"):
        return if_statement_end(masked, else_pos, limit)
    if is_begin_at(masked, else_pos):
        else_end = find_matching_begin(masked, else_pos, limit)
        return None if else_end is None else else_end + len("end")
    stmt_end = find_statement_end(masked, else_pos, limit)
    return None if stmt_end is None else stmt_end + 1


def instrument_block_enter_points(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    runtime_ranges: list[RuntimeRange],
    new_signal,
    insertions: list[Insertion],
    points: list[CoveragePoint],
    skipped: dict[str, int],
) -> None:
    for runtime in runtime_ranges:
        if runtime.kind not in {"always", "always_comb", "always_ff", "always_latch", "initial", "final"}:
            continue
        if not is_begin_at(masked, runtime.begin_pos):
            skipped["block_enter_without_begin"] = skipped.get("block_enter_without_begin", 0) + 1
            continue
        end = find_matching_begin(masked, runtime.begin_pos, module.end)
        if end is None:
            skipped["block_enter_unmatched_begin"] = skipped.get("block_enter_unmatched_begin", 0) + 1
            continue
        insert_at = after_begin_declarations(masked, runtime.begin_pos, module.end)
        sig = new_signal()
        line, col = line_col(text, runtime.start)
        insertions.append(
            Insertion(
                insert_at,
                make_hit_text(text, insert_at, sig, f"{module.name} block {runtime.kind} line {line}"),
                len(insertions),
            )
        )
        points.append(CoveragePoint(path.as_posix(), module.name, sig, "block", runtime.kind, line, col))


def loop_body_start(masked: str, tok: Token, limit: int) -> int | None:
    pos = skip_ws(masked, tok.end, limit)
    if tok.text in {"for", "foreach", "while", "repeat"}:
        if pos >= limit or masked[pos] != "(":
            return None
        close = find_matching_pair(masked, pos, "(", ")")
        if close is None:
            return None
        pos = skip_ws(masked, close + 1, limit)
    return pos if pos < limit else None


def instrument_loop_body_points(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    runtime_ranges: list[RuntimeRange],
    new_signal,
    insertions: list[Insertion],
    points: list[CoveragePoint],
    skipped: dict[str, int],
    allow_single_statement: bool = False,
) -> None:
    loop_words = {"for", "foreach", "while", "repeat", "forever"}
    for tok in iter_tokens(masked, module.header_end, module.end):
        if tok.text not in loop_words:
            continue
        if not inside_any(tok.start, runtime_ranges):
            skipped["loop_outside_runtime"] = skipped.get("loop_outside_runtime", 0) + 1
            continue
        body_pos = loop_body_start(masked, tok, module.end)
        if body_pos is None:
            skipped[f"loop_{tok.text}_bad_header"] = skipped.get(f"loop_{tok.text}_bad_header", 0) + 1
            continue
        sig = new_signal()
        line, col = line_col(text, tok.start)
        if is_begin_at(masked, body_pos):
            insertion = instrument_begin_body(
                text,
                masked,
                body_pos,
                module.end,
                sig,
                f"{module.name} loop {tok.text} line {line}",
                len(insertions),
            )
            if insertion is None:
                skipped["loop_body_unsupported"] = skipped.get("loop_body_unsupported", 0) + 1
                continue
            insertions.append(insertion)
            points.append(CoveragePoint(path.as_posix(), module.name, sig, "loop", tok.text, line, col))
        else:
            if not allow_single_statement:
                skipped["loop_single_statement_body_unsupported"] = (
                    skipped.get("loop_single_statement_body_unsupported", 0) + 1
                )
                continue
            body_result = instrument_single_statement_body(
                text,
                masked,
                body_pos,
                module.end,
                sig,
                f"{module.name} loop {tok.text} line {line}",
                len(insertions),
            )
            if body_result is None:
                skipped["loop_single_statement_body_unsupported"] = (
                    skipped.get("loop_single_statement_body_unsupported", 0) + 1
                )
                continue
            new_insertions, _ = body_result
            insertions.extend(new_insertions)
            points.append(CoveragePoint(path.as_posix(), module.name, sig, "loop", tok.text, line, col))


CONTROL_WORDS = {"return", "break", "continue", "disable"}
ASSERTION_WORDS = {"assert", "assume", "cover"}
CONDITION_WORDS = {"if", "case", "casez", "casex", "for", "foreach", "while", "repeat"}
ASSIGNMENT_OPERATOR_RE = re.compile(r"(?:<=|\+=|-=|\*=|/=|%=|&=|\|=|\^=|(?<![=!<>])=(?![=>=]))")
STATEMENT_SKIP_WORDS = {
    "begin",
    "end",
    "if",
    "else",
    "case",
    "casez",
    "casex",
    "endcase",
    "for",
    "foreach",
    "while",
    "repeat",
    "forever",
    "always",
    "always_comb",
    "always_ff",
    "always_latch",
    "initial",
    "final",
    "function",
    "task",
    "endfunction",
    "endtask",
    *DECLARATION_WORDS,
}


def next_non_ws_char(masked: str, pos: int, limit: int) -> tuple[str, int] | tuple[None, int]:
    pos = skip_ws(masked, pos, limit)
    if pos >= limit:
        return None, pos
    return masked[pos], pos


def statement_kind_at(masked: str, tok: Token, limit: int, settings: InstrumentationSettings) -> tuple[str, str] | None:
    if not WORD_RE.fullmatch(tok.text):
        return None
    if tok.text in STATEMENT_SKIP_WORDS:
        return None
    if tok.text in CONTROL_WORDS:
        return ("control", tok.text) if settings.statement.control else None
    if tok.text in ASSERTION_WORDS:
        return ("assertion", tok.text) if settings.assertion.hit else None
    ch, _ = next_non_ws_char(masked, tok.end, limit)
    if ch == "(":
        return ("call", tok.text) if settings.statement.call else None
    stmt_end = find_statement_end(masked, tok.start, limit)
    if stmt_end is None:
        return None
    snippet = masked[tok.start : stmt_end + 1]
    if settings.statement.procedural_assign and has_assignment_operator(snippet):
        return ("statement", "procedural_assign")
    return None


def has_assignment_operator(snippet: str) -> bool:
    return ASSIGNMENT_OPERATOR_RE.search(snippet) is not None


def assignment_lhs_name(masked: str, tok: Token, limit: int) -> str | None:
    stmt_end = find_statement_end(masked, tok.start, limit)
    if stmt_end is None:
        return None
    snippet = masked[tok.start : stmt_end + 1]
    if not has_assignment_operator(snippet):
        return None
    if tok.text == "assign":
        lhs = next_token(masked, tok.end, stmt_end)
        if lhs is None or not WORD_RE.fullmatch(lhs.text):
            return None
        return lhs.text
    ch, _ = next_non_ws_char(masked, tok.end, stmt_end)
    if ch == "(":
        return None
    return tok.text


def collect_ternary_metadata_in_range(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    start: int,
    end: int,
    metadata: list[MetadataPoint],
) -> None:
    for tok in iter_tokens(masked, start, end):
        if tok.text == "?":
            line, col = line_col(text, tok.start)
            metadata.append(MetadataPoint(path.as_posix(), module.name, "expression", "ternary", line, col))


def find_statement_start_before(masked: str, pos: int, lower: int) -> int:
    stmt_start = masked.rfind(";", lower, pos)
    if stmt_start < 0:
        return lower
    return stmt_start + 1


def top_level_assignment_pos(masked: str, start: int, end: int) -> int | None:
    paren = bracket = brace = 0
    pos = start
    assign_pos: int | None = None
    while pos < end:
        ch = masked[pos]
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
        elif ch == "=" and paren == bracket == brace == 0:
            prev_ch = masked[pos - 1] if pos > start else ""
            next_ch = masked[pos + 1] if pos + 1 < end else ""
            if prev_ch not in {"=", "!", "<", ">", ":"} and next_ch not in {"=", ">"}:
                assign_pos = pos
                break
        pos += 1
    return assign_pos


def compact_expression(expr: str) -> str:
    return " ".join(expr.strip().split())


def instrument_ternary_expression_points(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    runtime_ranges: list[RuntimeRange],
    new_signal,
    insertions: list[Insertion],
    points: list[CoveragePoint],
    skipped: dict[str, int],
) -> None:
    seen_offsets: set[int] = set()
    for tok in iter_tokens(masked, module.header_end, module.end):
        if tok.text != "?":
            continue
        if tok.start in seen_offsets:
            continue
        if inside_any(tok.start, runtime_ranges):
            skipped["expression_ternary_runtime_unsupported"] = (
                skipped.get("expression_ternary_runtime_unsupported", 0) + 1
            )
            continue
        stmt_start = find_statement_start_before(masked, tok.start, module.header_end)
        stmt_end = find_statement_end(masked, stmt_start, module.end)
        if stmt_end is None or stmt_end < tok.start:
            skipped["expression_ternary_unmatched_statement"] = (
                skipped.get("expression_ternary_unmatched_statement", 0) + 1
            )
            continue
        assign_pos = top_level_assignment_pos(masked, stmt_start, tok.start)
        if assign_pos is None:
            skipped["expression_ternary_without_assignment"] = (
                skipped.get("expression_ternary_without_assignment", 0) + 1
            )
            continue
        expr_start = skip_ws(masked, assign_pos + 1, tok.start)
        expr = compact_expression(text[expr_start:tok.start])
        if not expr or "?" in expr:
            skipped["expression_ternary_nested_unsupported"] = (
                skipped.get("expression_ternary_nested_unsupported", 0) + 1
            )
            continue
        sig = new_signal()
        line, col = line_col(text, tok.start)
        indent = line_indent(text, stmt_start)
        insertions.append(
            Insertion(
                stmt_end + 1,
                f"\n{indent}wire {sig} = ({expr}); // {module.name} expression ternary line {line}",
                len(insertions),
            )
        )
        points.append(CoveragePoint(path.as_posix(), module.name, sig, "expression", "ternary", line, col, False, expr))
        seen_offsets.add(tok.start)


def statement_starts_at_line_head(masked: str, token_start: int) -> bool:
    line_start = masked.rfind("\n", 0, token_start) + 1
    prefix = masked[line_start:token_start].strip()
    if not prefix:
        return True
    return prefix in {";", "end", "endcase"} or prefix.endswith(";")


def statement_inside_header(masked: str, token_start: int, region_start: int) -> bool:
    line_start = masked.rfind("\n", 0, token_start) + 1
    prefix = masked[line_start:token_start]
    return bool(re.search(r"\b(if|case|casez|casex|for|foreach|while|repeat)\b", prefix))


def statement_is_case_label(masked: str, token_start: int, runtime_start: int) -> bool:
    line_end = masked.find("\n", token_start)
    if line_end < 0:
        line_end = len(masked)
    colon = masked.find(":", token_start, line_end)
    if colon < 0:
        return False
    prefix = masked[runtime_start:token_start]
    return prefix.rfind("case") > prefix.rfind("endcase")


def instrument_statement_points(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    runtime_ranges: list[RuntimeRange],
    settings: InstrumentationSettings,
    new_signal,
    insertions: list[Insertion],
    points: list[CoveragePoint],
    skipped: dict[str, int],
) -> None:
    seen_offsets: set[int] = set()
    pos = module.header_end
    while True:
        tok = next_token(masked, pos, module.end)
        if tok is None:
            break
        pos = tok.end
        runtime = containing_range(tok.start, runtime_ranges)
        if runtime is None:
            continue
        if runtime.kind in {"function", "task"}:
            continue
        if tok.start in seen_offsets:
            continue
        if not statement_starts_at_line_head(masked, tok.start):
            continue
        if statement_inside_header(masked, tok.start, runtime.start):
            continue
        if statement_is_case_label(masked, tok.start, runtime.start):
            continue
        kind_info = statement_kind_at(masked, tok, runtime.end, settings)
        if kind_info is None:
            continue
        stmt_end = find_statement_end(masked, tok.start, runtime.end)
        if stmt_end is None:
            skipped["statement_unmatched_end"] = skipped.get("statement_unmatched_end", 0) + 1
            continue
        sig = new_signal()
        kind, subtype = kind_info
        line, col = line_col(text, tok.start)
        insert_at = line_head_insertion_offset(text, tok.start)
        insertions.append(
            Insertion(
                insert_at,
                make_pre_statement_hit_text(text, tok.start, sig, f"{module.name} {kind} {subtype} line {line}"),
                len(insertions),
            )
        )
        points.append(CoveragePoint(path.as_posix(), module.name, sig, kind, subtype, line, col))
        seen_offsets.add(tok.start)
        pos = stmt_end + 1


def collect_static_metadata(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    runtime_ranges: list[RuntimeRange],
    settings: InstrumentationSettings,
) -> list[MetadataPoint]:
    metadata: list[MetadataPoint] = []
    pos = module.header_end
    while True:
        tok = next_token(masked, pos, module.end)
        if tok is None:
            break
        pos = tok.end
        runtime = containing_range(tok.start, runtime_ranges)
        if settings.assertion.metadata and tok.text in ASSERTION_WORDS:
            line, col = line_col(text, tok.start)
            metadata.append(MetadataPoint(path.as_posix(), module.name, "assertion", tok.text, line, col))
        if settings.expression.ternary and tok.text == "?":
            line, col = line_col(text, tok.start)
            metadata.append(MetadataPoint(path.as_posix(), module.name, "expression", "ternary", line, col))
        if runtime is not None:
            if settings.expression.condition and tok.text in CONDITION_WORDS:
                line, col = line_col(text, tok.start)
                metadata.append(MetadataPoint(path.as_posix(), module.name, "condition", tok.text, line, col))
            if (
                settings.expression.toggle
                and WORD_RE.fullmatch(tok.text)
                and tok.text not in STATEMENT_SKIP_WORDS
                and tok.text not in CONTROL_WORDS
                and tok.text not in ASSERTION_WORDS
            ):
                if runtime.kind not in {"function", "task"} and statement_starts_at_line_head(masked, tok.start):
                    if not statement_inside_header(masked, tok.start, runtime.start) and not statement_is_case_label(
                        masked, tok.start, runtime.start
                    ):
                        lhs_name = assignment_lhs_name(masked, tok, runtime.end)
                        if lhs_name:
                            line, col = line_col(text, tok.start)
                            metadata.append(
                                MetadataPoint(
                                    path.as_posix(),
                                    module.name,
                                    "toggle",
                                    "procedural_lhs",
                                    line,
                                    col,
                                    lhs_name,
                                )
                            )
                            stmt_end = find_statement_end(masked, tok.start, runtime.end)
                            if stmt_end is not None:
                                if settings.expression.ternary:
                                    collect_ternary_metadata_in_range(
                                        text, masked, path, module, tok.start, stmt_end + 1, metadata
                                    )
                                pos = stmt_end + 1
            continue
        if settings.expression.toggle and tok.text == "assign":
            lhs_name = assignment_lhs_name(masked, tok, module.end)
            if lhs_name:
                line, col = line_col(text, tok.start)
                metadata.append(
                    MetadataPoint(path.as_posix(), module.name, "toggle", "continuous_lhs", line, col, lhs_name)
                )
                stmt_end = find_statement_end(masked, tok.start, module.end)
                if stmt_end is not None:
                    if settings.expression.ternary:
                        collect_ternary_metadata_in_range(
                            text, masked, path, module, tok.start, stmt_end + 1, metadata
                        )
                    pos = stmt_end + 1
                continue
        if settings.static.generate and tok.text in {"generate", "genvar"}:
            line, col = line_col(text, tok.start)
            metadata.append(MetadataPoint(path.as_posix(), module.name, "static", tok.text, line, col))
        elif settings.static.generate and tok.text in {"if", "case", "for"}:
            line, col = line_col(text, tok.start)
            metadata.append(MetadataPoint(path.as_posix(), module.name, "static", f"generate_{tok.text}", line, col))
    return metadata


def rewrite_module(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    signal_prefix: str,
    start_index: int,
    frontend: FrontendModuleInfo | None = None,
    settings: InstrumentationSettings | None = None,
) -> RewriteResult:
    if settings is None:
        settings = InstrumentationSettings()
    runtime_ranges = collect_runtime_ranges(masked, module)
    insertions: list[Insertion] = []
    points: list[CoveragePoint] = []
    skipped: dict[str, int] = {}
    metadata: list[MetadataPoint] = collect_static_metadata(text, masked, path, module, runtime_ranges, settings)
    local_index = 0

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    def new_signal() -> str:
        nonlocal local_index
        sig = f"{signal_prefix}_{start_index + local_index}"
        local_index += 1
        return sig

    if settings.statement.block_enter:
        instrument_block_enter_points(text, masked, path, module, runtime_ranges, new_signal, insertions, points, skipped)

    if settings.loop.body:
        instrument_loop_body_points(
            text,
            masked,
            path,
            module,
            runtime_ranges,
            new_signal,
            insertions,
            points,
            skipped,
            settings.loop.single_statement,
        )

    if settings.statement.procedural_assign or settings.statement.call or settings.statement.control or settings.assertion.hit:
        instrument_statement_points(text, masked, path, module, runtime_ranges, settings, new_signal, insertions, points, skipped)

    if settings.expression.ternary:
        instrument_ternary_expression_points(
            text,
            masked,
            path,
            module,
            runtime_ranges,
            new_signal,
            insertions,
            points,
            skipped,
        )

    for tok in iter_tokens(masked, module.header_end, module.end):
        if not inside_any(tok.start, runtime_ranges):
            continue
        if tok.text == "if":
            if not settings.branch.if_enable:
                skip("branch_if_disabled_by_config")
                continue
            true_candidate = next_frontend_branch(frontend, "if", "true", text, tok.start)
            if true_candidate is None:
                skip("frontend_if_true_source_fallback")
            open_pos = skip_ws(masked, tok.end, module.end)
            if open_pos >= module.end or masked[open_pos] != "(":
                skip("if_without_condition_paren")
                continue
            close_pos = find_matching_pair(masked, open_pos, "(", ")")
            if close_pos is None:
                skip("if_unmatched_condition")
                continue
            body_pos = skip_ws(masked, close_pos + 1, module.end)
            sig = new_signal()
            line, col = candidate_line_col(true_candidate, text, tok.start)
            then_result = instrument_branch_body(
                text,
                masked,
                body_pos,
                module.end,
                sig,
                f"{module.name} if true line {line}",
                len(insertions),
            )
            if then_result is None:
                skip("if_then_body_unsupported")
                continue
            else:
                new_insertions, then_end = then_result
                insertions.extend(new_insertions)
                fail = settings.assertion.fail_on_side_effect and branch_body_has_assert_side_effect(
                    text, body_pos, then_end
                )
                points.append(CoveragePoint(path.as_posix(), module.name, sig, "if", "true", line, col, fail))

            body_is_begin = is_begin_at(masked, body_pos)
            then_end_for_else = find_matching_begin(masked, body_pos, module.end) if body_is_begin else find_statement_end(masked, body_pos, module.end)
            if then_end_for_else is None:
                continue
            then_end = then_end_for_else + (len("end") if body_is_begin else 1)
            after_then = skip_ws(masked, then_end, module.end)
            if not word_at(masked, after_then, "else"):
                if settings.branch.else_missing:
                    false_candidate = next_frontend_branch(frontend, "if", "false", text, tok.start)
                    sig = new_signal()
                    if false_candidate is None:
                        skip("frontend_if_missing_false_source_fallback")
                        false_line, false_col = line_col(text, tok.start)
                    else:
                        false_line, false_col = (
                            (false_candidate.line, false_candidate.column)
                            if false_candidate.line > 0
                            else (line, col)
                        )
                    indent = line_indent(text, after_then)
                    insertions.append(
                        Insertion(
                            then_end,
                            f"\n{indent}else begin\n{indent}  {sig} = 1'b1; // {module.name} if missing false line {false_line}\n{indent}end\n{indent}",
                            len(insertions),
                        )
                    )
                    points.append(CoveragePoint(path.as_posix(), module.name, sig, "if", "missing_false", false_line, false_col))
                continue
            else_pos = skip_ws(masked, after_then + len("else"), module.end)
            if word_at(masked, else_pos, "if"):
                if not settings.branch.else_if:
                    skip("if_else_is_else_if")
                    continue
                false_candidate = next_frontend_branch(frontend, "if", "false", text, tok.start)
                if false_candidate is None:
                    skip("frontend_if_else_if_false_source_fallback")
                sig = new_signal()
                false_line, false_col = candidate_line_col(false_candidate, text, tok.start)
                nested_end = if_statement_end(masked, else_pos, module.end)
                if nested_end is None:
                    skip("if_else_if_body_unsupported")
                    continue
                indent = line_indent(text, else_pos)
                insertions.append(
                    Insertion(
                        else_pos,
                        f"begin\n{indent}  {sig} = 1'b1; // {module.name} if else_if false line {false_line}\n{indent}  ",
                        len(insertions),
                    )
                )
                insertions.append(Insertion(nested_end, f"\n{indent}end", else_if_close_order(tok.start)))
                points.append(CoveragePoint(path.as_posix(), module.name, sig, "if", "else_if_false", false_line, false_col))
                continue
            false_candidate = next_frontend_branch(frontend, "if", "false", text, tok.start)
            if false_candidate is None:
                skip("frontend_if_false_source_fallback")
            sig = new_signal()
            false_line, false_col = candidate_line_col(false_candidate, text, tok.start)
            else_result = instrument_branch_body(
                text,
                masked,
                else_pos,
                module.end,
                sig,
                f"{module.name} if false line {false_line}",
                len(insertions),
            )
            if else_result is None:
                skip("if_else_body_unsupported")
            else:
                new_insertions, else_end = else_result
                insertions.extend(new_insertions)
                fail = settings.assertion.fail_on_side_effect and branch_body_has_assert_side_effect(
                    text, else_pos, else_end
                )
                points.append(
                    CoveragePoint(path.as_posix(), module.name, sig, "if", "false", false_line, false_col, fail)
                )

        elif tok.text in {"case", "casez", "casex"}:
            if not settings.branch.case_enable:
                skip("branch_case_disabled_by_config")
                continue
            open_pos = masked.find("(", tok.end, module.end)
            if open_pos < 0:
                skip("case_without_expr_paren")
                continue
            close_pos = find_matching_pair(masked, open_pos, "(", ")")
            if close_pos is None:
                skip("case_unmatched_expr")
                continue
            endcase = find_matching_case(masked, tok.start, module.end)
            if endcase is None:
                skip("case_unmatched_endcase")
                continue
            scan_case_items(
                text,
                masked,
                path,
                module,
                tok,
                close_pos + 1,
                endcase,
                signal_prefix,
                start_index,
                new_signal,
                insertions,
                points,
                skipped,
                frontend,
                settings,
            )

    sticky_points = [point for point in points if not point.expr]
    if sticky_points:
        decl_indent = line_indent(text, module.header_end)
        decl_lines = [f"\n{decl_indent}{MARKER_BEGIN}"]
        for point in sticky_points:
            decl_lines.append(f"{decl_indent}logic {point.signal} = 1'b0;")
        decl_lines.append(f"{decl_indent}{MARKER_END}\n")
        insertions.append(Insertion(module.header_end, "\n".join(decl_lines), -1))

    return RewriteResult(insertions, points, skipped, metadata)


def scan_case_items(
    text: str,
    masked: str,
    path: Path,
    module: ModuleRegion,
    case_tok: Token,
    start: int,
    endcase: int,
    signal_prefix: str,
    start_index: int,
    new_signal,
    insertions: list[Insertion],
    points: list[CoveragePoint],
    skipped: dict[str, int],
    frontend: FrontendModuleInfo | None = None,
    settings: InstrumentationSettings | None = None,
) -> None:
    del signal_prefix, start_index
    if settings is None:
        settings = InstrumentationSettings()

    def skip(reason: str) -> None:
        skipped[reason] = skipped.get(reason, 0) + 1

    paren = bracket = brace = begin_depth = case_depth = ternary_depth = 0
    pos = start
    while pos < endcase:
        ch = masked[pos]
        tok = next_token(masked, pos, endcase)
        if tok is None:
            break
        if tok.start > pos:
            pos = tok.start
            ch = masked[pos]

        if tok.text == "begin":
            begin_depth += 1
            pos = tok.end
            continue
        if tok.text == "end" and begin_depth:
            begin_depth -= 1
            pos = tok.end
            continue
        if tok.text in {"case", "casez", "casex"}:
            case_depth += 1
            pos = tok.end
            continue
        if tok.text == "endcase" and case_depth:
            case_depth -= 1
            pos = tok.end
            continue

        if len(tok.text) == 1:
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
            elif ch == "?" and paren == bracket == brace == begin_depth == case_depth == 0:
                ternary_depth += 1
            elif ch == ":" and paren == bracket == brace == begin_depth == case_depth == 0:
                if (pos > start and masked[pos - 1] == ":") or (pos + 1 < endcase and masked[pos + 1] == ":"):
                    pos = tok.end
                    continue
                if ternary_depth:
                    ternary_depth -= 1
                    pos = tok.end
                    continue
                before = previous_word(masked, ch_pos=pos, start=start)
                if before == "begin":
                    pos = tok.end
                    continue
                subtype = "default" if before == "default" else "item"
                if subtype == "default" and not settings.branch.case_default:
                    skip("case_default_disabled_by_config")
                    pos = tok.end
                    continue
                body_pos = skip_ws(masked, tok.end, endcase)
                candidate = next_frontend_branch(frontend, case_tok.text, "item", text, pos)
                if candidate is None:
                    skip("frontend_case_item_source_fallback")
                sig = new_signal()
                line, col = candidate_line_col(candidate, text, pos)
                body_result = instrument_branch_body(
                    text,
                    masked,
                    body_pos,
                    endcase,
                    sig,
                    f"{module.name} case {subtype} line {line}",
                    len(insertions),
                )
                if body_result is None:
                    skip("case_item_body_unsupported")
                else:
                    new_insertions, body_end = body_result
                    insertions.extend(new_insertions)
                    fail = settings.assertion.fail_on_side_effect and branch_body_has_assert_side_effect(
                        text, body_pos, body_end
                    )
                    points.append(CoveragePoint(path.as_posix(), module.name, sig, "case", subtype, line, col, fail))
                matched = find_matching_begin(masked, body_pos, endcase) if is_begin_at(masked, body_pos) else None
                pos = body_end if body_result is not None else (tok.end if matched is None else matched + len("end"))
                continue
        pos = tok.end


def previous_word(masked: str, ch_pos: int, start: int) -> str | None:
    prefix = masked[start:ch_pos]
    matches = list(WORD_RE.finditer(prefix))
    if not matches:
        return None
    return matches[-1].group(0)


def apply_insertions(text: str, insertions: list[Insertion]) -> str:
    result = text
    for item in sorted(insertions, key=lambda ins: (ins.offset, ins.order), reverse=True):
        result = result[: item.offset] + item.text + result[item.offset :]
    return result


def analyze_file(
    path: Path,
    rel_path: Path,
    signal_prefix: str,
    coverage_port: str,
    first_index: int,
    frontend: FrontendIndex | None = None,
    settings: InstrumentationSettings | None = None,
) -> tuple[FilePlan, int]:
    if settings is None:
        settings = InstrumentationSettings()
    text = path.read_text(errors="ignore")
    if MARKER_BEGIN in text or signal_prefix in text or coverage_port in text:
        plan = FilePlan(
            src=path,
            rel_path=rel_path,
            text=text,
            masked=mask_comments_and_strings(text),
            insertions=[],
            points=[],
            skipped={"already_instrumented": 1},
            modules=[],
            metadata=[],
        )
        return plan, first_index
    masked = mask_comments_and_strings(text)
    modules = find_module_regions(masked)
    all_insertions: list[Insertion] = []
    all_points: list[CoveragePoint] = []
    all_metadata: list[MetadataPoint] = []
    skipped: dict[str, int] = {}
    module_plans: list[ModulePlan] = []
    next_index = first_index
    for module in modules:
        frontend_module = match_frontend_module(frontend, module.name, rel_path)
        if frontend is not None and frontend_module is None:
            skipped["frontend_module_not_matched"] = skipped.get("frontend_module_not_matched", 0) + 1
        result = rewrite_module(
            text,
            masked,
            rel_path,
            module,
            signal_prefix,
            next_index,
            frontend_module,
            settings,
        )
        all_insertions.extend(result.insertions)
        all_points.extend(result.points)
        all_metadata.extend(result.metadata)
        next_index += len(result.points)
        for reason, count in result.skipped.items():
            skipped[reason] = skipped.get(reason, 0) + count
        module_plans.append(
            ModulePlan(
                path=path,
                rel_path=rel_path,
                text=text,
                masked=masked,
                region=module,
                insertions=list(result.insertions),
                points=list(result.points),
                skipped=dict(result.skipped),
                metadata=list(result.metadata),
                frontend=frontend_module,
            )
        )
    plan = FilePlan(
        src=path,
        rel_path=rel_path,
        text=text,
        masked=masked,
        insertions=all_insertions,
        points=all_points,
        skipped=skipped,
        modules=module_plans,
        metadata=all_metadata,
    )
    return plan, next_index


def rewrite_file(path: Path, rel_path: Path, signal_prefix: str, first_index: int) -> tuple[str, list[CoveragePoint], dict[str, int], int]:
    plan, next_index = analyze_file(path, rel_path, signal_prefix, "__vi_coverage", first_index)
    return apply_insertions(plan.text, plan.insertions), plan.points, plan.skipped, next_index


def merge_skipped(dst: dict[str, int], src: dict[str, int]) -> None:
    for reason, count in src.items():
        dst[reason] = dst.get(reason, 0) + count


def coverage_by_kind(points: list[CoveragePoint]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for point in points:
        key = f"{point.kind}.{point.subtype}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def metadata_by_kind(points: list[MetadataPoint]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for point in points:
        key = f"{point.kind}.{point.subtype}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def module_can_export_coverage(plan: ModulePlan) -> bool:
    return find_module_port_list(plan.masked, plan.region) is not None


def collect_hierarchy(
    file_plans: list[FilePlan],
    top_module: str | None,
) -> tuple[dict[str, ModulePlan], list[str], set[str], dict[str, int]]:
    skipped: dict[str, int] = {}
    module_map: dict[str, ModulePlan] = {}
    duplicate_modules: set[str] = set()
    for file_plan in file_plans:
        for module_plan in file_plan.modules:
            name = module_plan.region.name
            if name in module_map:
                duplicate_modules.add(name)
                continue
            module_map[name] = module_plan
    for name in duplicate_modules:
        skipped[f"duplicate_module_{name}"] = skipped.get(f"duplicate_module_{name}", 0) + 1

    module_names = set(module_map)
    for module_plan in module_map.values():
        if module_plan.frontend is not None:
            instances, inst_skipped = collect_frontend_instances(
                module_plan.text,
                module_plan.masked,
                module_plan.rel_path,
                module_plan.region,
                module_plan.frontend,
                module_names,
            )
        else:
            instances, inst_skipped = collect_instances(
                module_plan.text,
                module_plan.masked,
                module_plan.rel_path,
                module_plan.region,
                module_names,
            )
        module_plan.instances = instances
        merge_skipped(module_plan.skipped, inst_skipped)

    if top_module:
        requested = [item.strip() for item in top_module.split(",") if item.strip()]
        missing = [name for name in requested if name not in module_map]
        if missing:
            raise SystemExit(f"Top module not found: {', '.join(missing)}")
        roots = requested
    else:
        instantiated = {inst.child for plan in module_map.values() for inst in plan.instances}
        roots = sorted(name for name in module_names if name not in instantiated)
        if not roots:
            roots = sorted(module_names)

    active: set[str] = set()

    def visit_module(name: str) -> None:
        if name in active:
            return
        active.add(name)
        plan = module_map.get(name)
        if plan is None:
            return
        for inst in plan.instances:
            if inst.child in module_map:
                visit_module(inst.child)

    for root in roots:
        visit_module(root)
    return module_map, roots, active, skipped


def compute_coverage_widths(
    module_map: dict[str, ModulePlan],
    active_modules: set[str],
) -> dict[str, int]:
    can_export = {
        name: module_can_export_coverage(plan)
        for name, plan in module_map.items()
        if name in active_modules
    }
    widths = {name: 0 for name in module_map}
    for _ in range(len(active_modules) + 1):
        changed = False
        for name in active_modules:
            plan = module_map[name]
            if not can_export.get(name, False):
                new_width = 0
            else:
                child_width = 0
                for inst in plan.instances:
                    if inst.child in active_modules and can_export.get(inst.child, False):
                        child_width += widths.get(inst.child, 0)
                new_width = len(plan.points) + child_width
            if new_width != widths[name]:
                widths[name] = new_width
                changed = True
        if not changed:
            break
    for name, width in widths.items():
        if name in module_map:
            module_map[name].coverage_width = width
    return widths


def make_module_port_insertions(
    plan: ModulePlan,
    coverage_port: str,
    width: int,
    skipped: dict[str, int],
) -> list[Insertion]:
    port_list = find_module_port_list(plan.masked, plan.region)
    if port_list is None:
        skipped["module_without_port_list_for_coverage"] = (
            skipped.get("module_without_port_list_for_coverage", 0) + 1
        )
        return []
    port_open, port_close = port_list
    ansi_ports = header_uses_ansi_ports(plan.masked, port_open, port_close)
    insertions: list[Insertion] = []
    if ansi_ports:
        item = f"output wire {width_prefix(width)}{coverage_port}"
        insertions.append(
            Insertion(
                append_list_item_offset(plan.masked, port_open, port_close),
                append_list_item_text(plan.text, plan.masked, port_open, port_close, item),
                -3,
            )
        )
    else:
        item = coverage_port
        insertions.append(
            Insertion(
                append_list_item_offset(plan.masked, port_open, port_close),
                append_list_item_text(plan.text, plan.masked, port_open, port_close, item),
                -3,
            )
        )
        indent = line_indent(plan.text, plan.region.header_end)
        decl = f"\n{indent}output wire {width_prefix(width)}{coverage_port};\n"
        insertions.append(Insertion(plan.region.header_end, decl, -2))
    return insertions


def make_instance_connection_insertions(
    plan: ModulePlan,
    coverage_port: str,
    widths: dict[str, int],
    active_modules: set[str],
) -> None:
    plan.child_connections.clear()
    child_counter = 0
    for inst in plan.instances:
        child_width = widths.get(inst.child, 0)
        if inst.child not in active_modules or child_width <= 0:
            continue
        wire = f"__vi_cov_child_{safe_identifier(inst.name)}_{child_counter}"
        child_counter += 1
        plan.child_connections.append(ChildConnection(inst, child_width, wire))
        if inst.named_ports:
            item = f".{coverage_port}({wire})"
        else:
            item = wire
        plan.insertions.append(
            Insertion(
                append_list_item_offset(plan.masked, inst.port_open, inst.port_close),
                append_list_item_text(plan.text, plan.masked, inst.port_open, inst.port_close, item),
                20 + child_counter,
            )
        )


def make_hierarchy_body_insertion(
    plan: ModulePlan,
    coverage_port: str,
) -> Insertion | None:
    if plan.coverage_width <= 0:
        return None
    indent = line_indent(plan.text, plan.region.header_end)
    lines = [f"\n{indent}{HIER_MARKER_BEGIN}"]
    for conn in plan.child_connections:
        lines.append(f"{indent}wire {width_prefix(conn.width)}{conn.wire};")
    terms: list[str] = [point.signal for point in plan.points]
    terms.extend(conn.wire for conn in plan.child_connections)
    if not terms:
        return None
    if len(terms) == 1:
        rhs = terms[0]
    else:
        rhs = "{" + ", ".join(terms) + "}"
    lines.append(f"{indent}assign {coverage_port} = {rhs};")
    lines.append(f"{indent}{HIER_MARKER_END}\n")
    return Insertion(plan.region.header_end, "\n".join(lines), 1)


def add_hierarchy_insertions(
    file_plans: list[FilePlan],
    top_module: str | None,
    coverage_port: str,
) -> tuple[list[str], set[str], list[dict[str, object]], dict[str, int]]:
    module_map, roots, active_modules, skipped = collect_hierarchy(file_plans, top_module)
    widths = compute_coverage_widths(module_map, active_modules)
    for plan in module_map.values():
        if plan.region.name not in active_modules or widths.get(plan.region.name, 0) <= 0:
            continue
        plan.insertions.extend(make_module_port_insertions(plan, coverage_port, widths[plan.region.name], skipped))
    for plan in module_map.values():
        if plan.region.name not in active_modules or widths.get(plan.region.name, 0) <= 0:
            continue
        make_instance_connection_insertions(plan, coverage_port, widths, active_modules)
        body_insertion = make_hierarchy_body_insertion(plan, coverage_port)
        if body_insertion is not None:
            plan.insertions.append(body_insertion)

    for file_plan in file_plans:
        file_plan.insertions = []
        for module_plan in file_plan.modules:
            if module_plan.region.name in active_modules:
                file_plan.insertions.extend(module_plan.insertions)

    module_summary: list[dict[str, object]] = []
    for name in sorted(module_map):
        plan = module_map[name]
        module_summary.append(
            {
                "module": name,
                "file": plan.rel_path.as_posix(),
                "active": name in active_modules,
                "local_points": len(plan.points),
                "coverage_width": widths.get(name, 0),
                "instance_count": len(plan.instances),
                "propagated_child_count": len(plan.child_connections),
                "frontend_matched": plan.frontend is not None,
            }
        )
    return roots, active_modules, module_summary, skipped


def expand_path(raw: str, base: Path) -> Path:
    expanded = os.path.expandvars(os.path.expanduser(raw))
    path = Path(expanded)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def strip_line_comment(line: str) -> str:
    idx = line.find("//")
    return line if idx < 0 else line[:idx]


def parse_flist(flist: Path, project_root: Path, seen: set[Path] | None = None) -> FlistParseResult:
    if seen is None:
        seen = set()
    flist = flist.resolve()
    if flist in seen:
        return FlistParseResult()
    seen.add(flist)
    result = FlistParseResult()
    base = flist.parent
    for raw_line in flist.read_text(errors="ignore").splitlines():
        line = strip_line_comment(raw_line).strip()
        if not line:
            result.lines.append(raw_line)
            continue
        if line in {"-f", "-F"}:
            result.lines.append(raw_line)
            continue
        if line.startswith("-f "):
            nested = expand_path(line[3:].strip(), base)
            nested_result = parse_flist(nested, project_root, seen)
            result.files.extend(nested_result.files)
            result.lines.extend(nested_result.lines)
            result.incdirs.update(nested_result.incdirs)
            continue
        if line.startswith("-F "):
            nested = expand_path(line[3:].strip(), project_root)
            nested_result = parse_flist(nested, project_root, seen)
            result.files.extend(nested_result.files)
            result.lines.extend(nested_result.lines)
            result.incdirs.update(nested_result.incdirs)
            continue
        if line.startswith("+incdir+"):
            for item in line[len("+incdir+") :].split("+"):
                path = expand_path(item, base)
                if path.exists() and path.is_dir():
                    result.incdirs.add(path)
            result.lines.append(raw_line)
            continue
        if line.startswith("-I"):
            item = line[2:].strip()
            if item:
                path = expand_path(item, base)
                if path.exists() and path.is_dir():
                    result.incdirs.add(path)
            result.lines.append(raw_line)
            continue
        first = line.split()[0]
        path = expand_path(first, base)
        if path.suffix.lower() in HDL_SUFFIXES and path.exists():
            result.files.append(path)
        result.lines.append(raw_line)
    return result


def discover_hdl_files(project_root: Path, out_dir: Path) -> list[Path]:
    files: list[Path] = []
    out_resolved = out_dir.resolve()
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in HDL_SUFFIXES:
            continue
        parts = set(path.parts)
        if parts & DEFAULT_EXCLUDES:
            continue
        try:
            if path.resolve().is_relative_to(out_resolved):
                continue
        except AttributeError:
            pass
        files.append(path.resolve())
    return files


def rel_to_project(path: Path, project_root: Path) -> Path:
    try:
        return path.resolve().relative_to(project_root.resolve())
    except ValueError:
        return Path(path.name)


def map_flist_line(raw_line: str, flist_base: Path, project_root: Path, out_dir: Path) -> str:
    line = strip_line_comment(raw_line).strip()
    if not line:
        return raw_line
    if line.startswith("+incdir+"):
        dirs = line[len("+incdir+") :].split("+")
        mapped = []
        for item in dirs:
            path = expand_path(item, flist_base)
            try:
                rel = path.relative_to(project_root)
                mapped.append((out_dir / rel).as_posix())
            except ValueError:
                mapped.append(item)
        return "+incdir+" + "+".join(mapped)
    first = line.split()[0]
    path = expand_path(first, flist_base)
    if path.suffix.lower() in HDL_SUFFIXES:
        try:
            rel = path.relative_to(project_root)
            return (out_dir / rel).as_posix()
        except ValueError:
            return raw_line
    return raw_line


def copy_include_dirs(incdirs: set[Path], project_root: Path, out_dir: Path) -> int:
    copied = 0
    for incdir in sorted(incdirs):
        if not incdir.exists() or not incdir.is_dir():
            continue
        for src in incdir.rglob("*"):
            if not src.is_file():
                continue
            parts = set(src.parts)
            if parts & DEFAULT_EXCLUDES:
                continue
            rel = rel_to_project(src, project_root)
            dst = out_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            copied += 1
    return copied


def instrument_project(
    project_root: Path,
    out_dir: Path,
    *,
    flist: Path | None = None,
    frontend_manifest: dict | None = None,
    frontend_json: Path | None = None,
    settings: InstrumentationSettings | dict | None = None,
    signal_prefix: str = "__vi_branch_cov",
    coverage_port: str = "__vi_coverage",
    top_module: str | None = None,
    force: bool = False,
) -> dict:
    project_root = project_root.resolve()
    out_dir = out_dir.resolve()
    if isinstance(settings, InstrumentationSettings):
        resolved_settings = settings
    else:
        resolved_settings = InstrumentationSettings.from_dict(settings)
    frontend_index = (
        load_frontend_index_from_data(frontend_manifest, project_root)
        if frontend_manifest is not None
        else load_frontend_index(frontend_json.as_posix() if frontend_json else None, project_root)
    )
    if out_dir.exists():
        if not force:
            raise SystemExit(f"Output directory exists, use --force: {out_dir}")
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    flist_files: list[Path] = []
    flist_lines: list[str] = []
    flist_incdirs: set[Path] = set()
    flist_path: Path | None = flist.resolve() if flist else None
    if flist_path:
        flist_result = parse_flist(flist_path, project_root)
        flist_files = flist_result.files
        flist_lines = flist_result.lines
        flist_incdirs = flist_result.incdirs

    all_files = set(flist_files) if flist_files else set(discover_hdl_files(project_root, out_dir))
    next_index = 0
    file_plans: list[FilePlan] = []

    for src in sorted(all_files):
        rel = rel_to_project(src, project_root)
        file_plan, next_index = analyze_file(
            src, rel, signal_prefix, coverage_port, next_index, frontend_index, resolved_settings
        )
        file_plans.append(file_plan)

    if resolved_settings.hierarchy.propagate_to_top:
        top_modules, active_modules, module_coverage, hierarchy_skipped = add_hierarchy_insertions(
            file_plans, top_module, coverage_port
        )
    else:
        top_modules = [item.strip() for item in top_module.split(",") if item.strip()] if top_module else []
        active_modules = {module_plan.region.name for file_plan in file_plans for module_plan in file_plan.modules}
        module_coverage = [
            {
                "module": module_plan.region.name,
                "file": module_plan.rel_path.as_posix(),
                "active": True,
                "local_points": len(module_plan.points),
                "coverage_width": len(module_plan.points),
                "instance_count": 0,
                "propagated_child_count": 0,
                "frontend_matched": module_plan.frontend is not None,
            }
            for file_plan in file_plans
            for module_plan in file_plan.modules
        ]
        hierarchy_skipped = {"hierarchy_propagation_disabled_by_config": 1}
    points: list[CoveragePoint] = []
    metadata: list[MetadataPoint] = []
    skipped: dict[str, int] = dict(hierarchy_skipped)
    for file_plan in file_plans:
        metadata.extend(file_plan.metadata)
        if not file_plan.modules:
            merge_skipped(skipped, file_plan.skipped)
            continue
        for module_plan in file_plan.modules:
            if module_plan.region.name in active_modules:
                points.extend(module_plan.points)
                merge_skipped(skipped, module_plan.skipped)

    copied_include_file_count = copy_include_dirs(flist_incdirs, project_root, out_dir)

    for file_plan in file_plans:
        dst = out_dir / file_plan.rel_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        rewritten = apply_insertions(file_plan.text, file_plan.insertions)
        if resolved_settings.assertion.neutralize_side_effects:
            rewritten = neutralize_assertion_side_effects(rewritten)
        dst.write_text(rewritten)

    out_flist = None
    if flist_path:
        out_flist = out_dir / "instrumented_sources.f"
        mapped_lines = [
            map_flist_line(line, flist_path.parent, project_root, out_dir)
            for line in flist_lines
        ]
        out_flist.write_text("\n".join(mapped_lines) + "\n")

    manifest = {
        "project_root": project_root.as_posix(),
        "out_dir": out_dir.as_posix(),
        "file_count": len(all_files),
        "copied_include_file_count": copied_include_file_count,
        "coverage_point_count": len(points),
        "coverage_by_kind": coverage_by_kind(points),
        "metadata_point_count": len(metadata),
        "metadata_by_kind": metadata_by_kind(metadata),
        "signal_prefix": signal_prefix,
        "coverage_port": coverage_port,
        "instrumentation_settings": resolved_settings.to_dict(),
        "frontend_json": str(frontend_json.resolve()) if frontend_json else "",
        "top_modules": top_modules,
        "instrumented_flist": out_flist.as_posix() if out_flist else "",
        "coverage": [point.__dict__ for point in points],
        "metadata": [point.__dict__ for point in metadata],
        "module_coverage": module_coverage,
        "skipped": skipped,
    }
    (out_dir / "instrumentation.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def copy_and_rewrite(args: argparse.Namespace) -> dict:
    project_root = Path(args.project_root).resolve()
    out_dir = Path(args.out_dir).resolve()
    settings_data = None
    if args.instrumentation_config:
        raw_settings = json.loads(Path(args.instrumentation_config).read_text())
        settings_data = raw_settings.get("instrumentation", raw_settings)
    return instrument_project(
        project_root,
        out_dir,
        flist=Path(args.flist).resolve() if args.flist else None,
        frontend_json=Path(args.frontend_json).resolve() if args.frontend_json else None,
        settings=settings_data,
        signal_prefix=args.signal_prefix,
        coverage_port=args.coverage_port,
        top_module=args.top_module,
        force=args.force,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Copy and branch-instrument a Verilog source tree.")
    parser.add_argument("--project-root", required=True, help="Original RTL project root.")
    parser.add_argument("--out-dir", required=True, help="Output directory for copied instrumented RTL.")
    parser.add_argument("--flist", help="Optional filelist to map into the output tree.")
    parser.add_argument(
        "--frontend-json",
        help="Optional Verilator frontend manifest. When set, source insertion is driven by frontend branch and instance locations.",
    )
    parser.add_argument("--signal-prefix", default="__vi_branch_cov", help="Coverage signal prefix.")
    parser.add_argument("--coverage-port", default="__vi_coverage", help="Hierarchical coverage output port name.")
    parser.add_argument("--instrumentation-config", help="Optional JSON file containing the instrumentation settings object.")
    parser.add_argument(
        "--top-module",
        help="Optional comma-separated top module name(s). Defaults to modules not instantiated by other known modules.",
    )
    parser.add_argument("--force", action="store_true", help="Replace an existing output directory.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = copy_and_rewrite(args)
    print(f"Instrumented HDL files: {manifest['file_count']}")
    print(f"Coverage points: {manifest['coverage_point_count']}")
    print(f"Coverage port: {manifest['coverage_port']}")
    if manifest["top_modules"]:
        print(f"Top module(s): {', '.join(manifest['top_modules'])}")
    if manifest["instrumented_flist"]:
        print(f"Instrumented filelist: {manifest['instrumented_flist']}")
    print(f"Manifest: {Path(manifest['out_dir']) / 'instrumentation.json'}")
    if manifest["skipped"]:
        print("Skipped:")
        for reason, count in sorted(manifest["skipped"].items()):
            print(f"  {reason}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
