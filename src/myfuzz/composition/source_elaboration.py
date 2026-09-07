"""Read bounded physical port facts from a Verilator JSON syntax tree."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


class ElaborationError(ValueError):
    """Compiler evidence is missing, ambiguous, or outside the supported subset."""


_MAX_AST_NODES = 1_500_000
_MAX_TYPE_DEPTH = 128
_MAX_PORTS = 65_536
_MAX_MEMBERS = 65_536
_MAX_WIDTH = 1 << 24
_ELABORATION_TIMEOUT_SECONDS = 30
_DIAGNOSTIC_BYTES = 64 * 1024
_VERSION_BYTES = 4096
_MAX_JSON_BYTES = 64 * 1024 * 1024
_MAX_JSON_STRUCTURE_TOKENS = 3_000_000
_MAX_CLOSURE_FILES = 20_000
_MAX_CLOSURE_ENTRIES = 100_000
_MAX_CLOSURE_BYTES = 512 * 1024 * 1024
_LOCATION = re.compile(r"^([^,]+),(\d+):(\d+)(?:,\d+:\d+)?$")
_RANGE = re.compile(r"^\[?(-?\d+):(-?\d+)\]?$")
_ATOM_WIDTHS = {
    "byte": 8,
    "shortint": 16,
    "int": 32,
    "integer": 32,
    "longint": 64,
    "time": 64,
}
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DEFINE_VALUE = re.compile(r"^[A-Za-z0-9_]+$")
_DECIMAL_INTEGER = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
_FRONTEND_WRAPPER = r"""
import os
import subprocess
import sys
import time

diagnostic_path, version_path = sys.argv[1:3]
diagnostic_limit, version_limit = map(int, sys.argv[3:5])
tool = sys.argv[5]
command = sys.argv[6:]

def run(argv, path, limit):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    with open(path, "wb", buffering=0) as output:
        retained = 0
        assert process.stdout is not None
        descriptor = process.stdout.fileno()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            if retained <= limit:
                payload = chunk[:limit + 1 - retained]
                output.write(payload)
                retained += len(payload)
    return process.wait()

version_status = run([tool, "--version"], version_path, version_limit)
if version_status:
    time.sleep(0.2)
    raise SystemExit(version_status)
frontend_status = run(command, diagnostic_path, diagnostic_limit)
time.sleep(0.2)
raise SystemExit(frontend_status)
"""


@dataclass(frozen=True, slots=True)
class _Leaf:
    path: tuple[str, ...]
    width: int
    signed: bool
    source: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _PhysicalType:
    width: int
    signed: bool
    leaves: tuple[_Leaf, ...]
    aggregate: bool = False


def _objects(root: object):
    pending: list[object] = [root]
    count = 0
    while pending:
        current = pending.pop()
        count += 1
        if count > _MAX_AST_NODES:
            raise ElaborationError("compiler tree exceeds node limit")
        if isinstance(current, Mapping):
            yield current
            pending.extend(reversed(tuple(current.values())))
        elif isinstance(current, list):
            pending.extend(reversed(current))
        elif isinstance(current, (str, int, float, bool, type(None))):
            continue
        else:
            raise ElaborationError("compiler tree contains an unsupported value")


def _sequence(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ElaborationError(f"{context} is not a list")
    return value


def _bounded_width(value: int, context: str) -> int:
    if value <= 0 or value > _MAX_WIDTH:
        raise ElaborationError(f"{context} width is outside supported bounds")
    return value


def _range_width(value: object, context: str) -> int:
    if not isinstance(value, str):
        raise ElaborationError(f"{context} range is missing")
    match = _RANGE.fullmatch(value)
    if match is None:
        raise ElaborationError(f"{context} range is invalid")
    left, right = int(match.group(1)), int(match.group(2))
    return _bounded_width(abs(left - right) + 1, context)


def _signed(node: Mapping[str, object], default: bool) -> bool:
    if "signed" not in node:
        return default
    value = node["signed"]
    if not isinstance(value, bool):
        raise ElaborationError("signed flag is not boolean")
    return value


class _Reader:
    def __init__(self, tree: object, metadata: object, source_files: object) -> None:
        if not isinstance(tree, Mapping):
            raise ElaborationError("compiler tree is not an object")
        if not isinstance(metadata, Mapping):
            raise ElaborationError("compiler metadata is not an object")
        if not isinstance(source_files, Mapping):
            raise ElaborationError("source mapping is not an object")
        files = metadata.get("files")
        if not isinstance(files, Mapping):
            raise ElaborationError("compiler metadata files are missing")
        self.tree = tree
        self.files = files
        self.source_files: dict[str, str] = {}
        for realpath, label in source_files.items():
            if not isinstance(realpath, str) or not os.path.isabs(realpath):
                raise ElaborationError("source mapping path is not absolute")
            if not isinstance(label, str) or not label:
                raise ElaborationError("source mapping label is invalid")
            normalized = os.path.realpath(realpath)
            if normalized in self.source_files:
                raise ElaborationError("duplicate source mapping path")
            self.source_files[normalized] = label
        self.types: dict[str, Mapping[str, object]] = {}
        for item in _objects(tree):
            kind = item.get("type")
            if not isinstance(kind, str) or not kind.endswith("DTYPE") or kind == "MEMBERDTYPE":
                continue
            address = item.get("addr")
            if not isinstance(address, str) or not address:
                raise ElaborationError("type ID is missing")
            if address in self.types:
                raise ElaborationError(f"duplicate type ID: {address}")
            self.types[address] = item

    def source(self, node: Mapping[str, object]) -> dict[str, object]:
        location = node.get("loc")
        match = _LOCATION.fullmatch(location) if isinstance(location, str) else None
        if match is None:
            raise ElaborationError("compiler location is invalid")
        file_id, line_text, column_text = match.groups()
        record = self.files.get(file_id)
        if not isinstance(record, Mapping):
            raise ElaborationError("compiler location file is unknown")
        realpath = record.get("realpath")
        if not isinstance(realpath, str) or not os.path.isabs(realpath):
            raise ElaborationError("compiler location is not source-owned")
        label = self.source_files.get(os.path.realpath(realpath))
        if label is None:
            raise ElaborationError("compiler location has no source mapping")
        line, column = int(line_text), int(column_text)
        if line <= 0 or column <= 0:
            raise ElaborationError("compiler location is invalid")
        return {"file": label, "line": line, "column": column}

    def pointer(self, node: Mapping[str, object], field: str) -> Mapping[str, object]:
        pointer = node.get(field)
        if not isinstance(pointer, str) or pointer in {"", "UNLINKED"}:
            raise ElaborationError(f"unresolved type reference in {field}")
        target = self.types.get(pointer)
        if target is None:
            raise ElaborationError(f"unresolved type reference: {pointer}")
        return target

    def physical_type(
        self,
        node: Mapping[str, object],
        *,
        active: frozenset[str] = frozenset(),
        depth: int = 0,
    ) -> _PhysicalType:
        if depth >= _MAX_TYPE_DEPTH:
            raise ElaborationError("type nesting exceeds depth limit")
        address = node.get("addr")
        if not isinstance(address, str):
            raise ElaborationError("type ID is missing")
        if address in active:
            raise ElaborationError(f"type reference cycle at {address}")
        active = active | {address}
        self.source(node)
        kind = node.get("type")
        if kind == "BASICDTYPE":
            return self._basic(node)
        if kind == "REFDTYPE":
            return self.physical_type(self.pointer(node, "refDTypep"), active=active, depth=depth + 1)
        if kind == "PARAMTYPEDTYPE":
            return self.physical_type(self.pointer(node, "dtypep"), active=active, depth=depth + 1)
        if kind == "ENUMDTYPE":
            base = self.physical_type(self.pointer(node, "refDTypep"), active=active, depth=depth + 1)
            if base.aggregate:
                raise ElaborationError("unsupported structured enum base")
            return base
        if kind == "PACKARRAYDTYPE":
            element = self.physical_type(self.pointer(node, "refDTypep"), active=active, depth=depth + 1)
            count = _range_width(node.get("declRange"), "packed array")
            width = _bounded_width(element.width * count, "packed array")
            # Structured array indices are not stable semantic member names.
            # Validate the complete element closure above, then expose the
            # array only as one aggregate leaf when embedded in a structure.
            return _PhysicalType(width, _signed(node, element.signed), (), element.aggregate)
        if kind == "STRUCTDTYPE":
            return self._structure(node, active, depth)
        raise ElaborationError(f"unsupported physical type: {kind}")

    def _basic(self, node: Mapping[str, object]) -> _PhysicalType:
        keyword = node.get("keyword", node.get("name"))
        if keyword not in {"logic", "bit", "reg", *_ATOM_WIDTHS}:
            raise ElaborationError(f"unsupported non-integral basic type: {keyword}")
        raw_range = node.get("range")
        if raw_range is None:
            range_nodes = node.get("rangep")
            if not isinstance(range_nodes, list) or range_nodes:
                raise ElaborationError("missing range is not proven scalar")
            width = _ATOM_WIDTHS.get(str(keyword), 1)
        else:
            width = _range_width(raw_range, "basic type")
            expected = _ATOM_WIDTHS.get(str(keyword))
            if expected is not None and width != expected:
                raise ElaborationError(f"basic type range does not match {keyword}")
        signed_default = keyword in {"byte", "shortint", "int", "integer", "longint"}
        return _PhysicalType(width, _signed(node, signed_default), ())

    def _structure(
        self, node: Mapping[str, object], active: frozenset[str], depth: int
    ) -> _PhysicalType:
        if node.get("packed") is not True:
            raise ElaborationError("unsupported unpacked structure")
        members = _sequence(node.get("membersp"), "structure members")
        if not members or len(members) > _MAX_MEMBERS:
            raise ElaborationError("structure member count is outside supported bounds")
        expanded: list[_Leaf] = []
        total = 0
        names: set[str] = set()
        for member in members:
            if not isinstance(member, Mapping) or member.get("type") != "MEMBERDTYPE":
                raise ElaborationError("structure contains an unsupported member")
            name = member.get("name")
            if not isinstance(name, str) or not name:
                raise ElaborationError("structure member name is invalid")
            if name in names:
                raise ElaborationError(f"duplicate structure member: {name}")
            names.add(name)
            self.source(member)
            member_type = self.physical_type(
                self.pointer(member, "refDTypep"), active=active, depth=depth + 1
            )
            total = _bounded_width(total + member_type.width, "structure")
            if member_type.leaves:
                expanded.extend(
                    _Leaf((name, *leaf.path), leaf.width, leaf.signed, leaf.source)
                    for leaf in member_type.leaves
                )
            else:
                expanded.append(_Leaf((name,), member_type.width, member_type.signed, self.source(member)))
            if len(expanded) > _MAX_MEMBERS:
                raise ElaborationError("flattened member count exceeds supported bounds")
        return _PhysicalType(total, _signed(node, False), tuple(expanded), True)

    def port(self, node: Mapping[str, object]) -> dict[str, object]:
        name = node.get("name")
        if not isinstance(name, str) or not name:
            raise ElaborationError("port name is invalid")
        direction = {"INPUT": "input", "OUTPUT": "output", "INOUT": "inout"}.get(node.get("direction"))
        if direction is None:
            raise ElaborationError(f"port direction is unsupported: {node.get('direction')}")
        physical = self.physical_type(self.pointer(node, "dtypep"))
        if physical.aggregate and not physical.leaves:
            raise ElaborationError("unsupported top-level aggregate without member paths")
        members: list[dict[str, object]] = []
        high = physical.width - 1
        for leaf in physical.leaves:
            low = high - leaf.width + 1
            members.append({
                "path": list(leaf.path), "width": leaf.width, "raw_lo": low,
                "raw_hi": high, "signed": leaf.signed, "source": dict(leaf.source),
            })
            high = low - 1
        return {
            "name": name,
            "direction": direction,
            "width": physical.width,
            "signed": physical.signed,
            "source": self.source(node),
            "members": members,
        }


def extract_physical_ports(
    tree: object,
    metadata: object,
    *,
    top_module: str,
    source_files: Mapping[str, str],
) -> dict[str, object]:
    """Return deterministic, source-owned physical facts for one elaborated module."""
    if not isinstance(top_module, str) or not top_module:
        raise ElaborationError("top module name is invalid")
    reader = _Reader(tree, metadata, source_files)
    modules = [
        item for item in _objects(tree)
        if item.get("type") == "MODULE" and item.get("name") == top_module
    ]
    if len(modules) != 1:
        raise ElaborationError(f"top module match is missing or duplicate: {top_module}")
    statements = _sequence(modules[0].get("stmtsp"), "module statements")
    port_nodes = [
        item for item in statements
        if isinstance(item, Mapping)
        and item.get("type") == "VAR"
        and item.get("varType") == "PORT"
        and item.get("isPrimaryIO") is True
    ]
    if len(port_nodes) > _MAX_PORTS:
        raise ElaborationError("port count exceeds supported bounds")
    names: set[str] = set()
    ports: list[dict[str, object]] = []
    total_members = 0
    for port_node in port_nodes:
        name = port_node.get("name")
        if isinstance(name, str) and name in names:
            raise ElaborationError(f"duplicate port: {name}")
        if isinstance(name, str):
            names.add(name)
        port = reader.port(port_node)
        total_members += len(port["members"])
        if total_members > _MAX_MEMBERS:
            raise ElaborationError("total output member count exceeds supported bounds")
        ports.append(port)
    return {"schema_version": "elaborated_ports.v1", "top_module": top_module, "ports": ports}


def _rooted_path(root: Path, value: object, *, kind: str, directory: bool) -> tuple[Path, str]:
    if not isinstance(value, str) or not value or Path(value).is_absolute():
        raise ElaborationError(f"{kind} path must be relative")
    relative = Path(value)
    if any(part in {"", ".", ".."} for part in relative.parts):
        raise ElaborationError(f"{kind} path escape is forbidden")
    candidate = root.joinpath(relative)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ElaborationError(f"{kind} symlink is forbidden")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        word = "missing" if not candidate.exists() else "escape"
        raise ElaborationError(f"{kind} {word}: {value}") from error
    if directory and not candidate.is_dir():
        raise ElaborationError(f"{kind} is not a directory: {value}")
    if not directory and not candidate.is_file():
        raise ElaborationError(f"{kind} is missing: {value}")
    return candidate.resolve(), relative.as_posix()


def _pairs(value: object, *, kind: str, value_pattern: re.Pattern[str]) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, (tuple, list)):
        raise ElaborationError(f"{kind} entries are invalid")
    result: list[tuple[str, str]] = []
    names: set[str] = set()
    for entry in value:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise ElaborationError(f"{kind} entry is invalid")
        name, item_value = entry
        if not isinstance(name, str) or _IDENTIFIER.fullmatch(name) is None:
            raise ElaborationError(f"unsafe {kind} identifier")
        if name in names:
            raise ElaborationError(f"duplicate {kind}: {name}")
        names.add(name)
        if not isinstance(item_value, str) or value_pattern.fullmatch(item_value) is None:
            qualifier = "decimal " if kind == "parameter" else "unsafe "
            raise ElaborationError(f"{qualifier}{kind} value")
        result.append((name, item_value))
    return tuple(result)


def _bounded_text(path: Path, limit: int) -> tuple[str, bool]:
    try:
        status = path.lstat()
    except FileNotFoundError:
        return "", False
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise ElaborationError("diagnostic output is not a regular file")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    truncated = len(payload) > limit
    text = payload[:limit].decode("utf-8", errors="replace")
    encoded = text.encode("utf-8")
    if len(encoded) > limit:
        text = encoded[:limit].decode("utf-8", errors="ignore")
        truncated = True
    return text.strip(), truncated


def _file_hash(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > _MAX_CLOSURE_BYTES:
                raise ElaborationError("source closure exceeds byte limit")
            digest.update(chunk)
    return digest.hexdigest(), size


def _closure(
    root: Path,
    explicit: Sequence[tuple[Path, str]],
    includes: Sequence[Path],
    *,
    excluded: Path | None = None,
) -> dict[Path, tuple[str, int]]:
    if len(explicit) > _MAX_CLOSURE_FILES:
        raise ElaborationError("source closure exceeds file limit")
    paths = {path: label for path, label in explicit}
    if len(paths) > _MAX_CLOSURE_FILES:
        raise ElaborationError("source closure exceeds file limit")
    entry_count = 0
    for include in includes:
        pending = [include]
        while pending:
            directory = pending.pop()
            entries = []
            with os.scandir(directory) as iterator:
                for entry in iterator:
                    entry_count += 1
                    if entry_count > _MAX_CLOSURE_ENTRIES:
                        raise ElaborationError("source closure exceeds entry limit")
                    entries.append(entry)
            for entry in sorted(entries, key=lambda item: item.name):
                path = Path(entry.path)
                if excluded is not None and (path == excluded or excluded in path.parents):
                    continue
                if entry.is_symlink():
                    raise ElaborationError("include closure contains a symlink")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                elif entry.is_file(follow_symlinks=False):
                    resolved = path.resolve()
                    paths.setdefault(resolved, resolved.relative_to(root).as_posix())
                else:
                    raise ElaborationError("include closure contains a non-regular file")
                if len(paths) > _MAX_CLOSURE_FILES:
                    raise ElaborationError("source closure exceeds file limit")
    result: dict[Path, tuple[str, int]] = {}
    total = 0
    for path in sorted(paths, key=lambda item: paths[item]):
        status = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(status.st_mode):
            raise ElaborationError("source closure contains a non-regular file")
        digest, size = _file_hash(path)
        total += size
        if total > _MAX_CLOSURE_BYTES:
            raise ElaborationError("source closure exceeds byte limit")
        result[path] = (digest, size)
    return result


def _json_file(path: Path) -> object:
    try:
        status = path.lstat()
    except FileNotFoundError as error:
        raise ElaborationError("frontend JSON output is missing") from error
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise ElaborationError("frontend JSON output is not a regular file or is a symlink")
    if status.st_size > _MAX_JSON_BYTES:
        raise ElaborationError("frontend JSON output size exceeds limit")
    with path.open("rb") as stream:
        payload = stream.read(_MAX_JSON_BYTES + 1)
    if len(payload) > _MAX_JSON_BYTES:
        raise ElaborationError("frontend JSON output is too large")
    in_string = False
    escaped = False
    structure_tokens = 0
    for byte in payload:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in b"{[,:":
            structure_tokens += 1
            if structure_tokens > _MAX_JSON_STRUCTURE_TOKENS:
                raise ElaborationError("frontend JSON structure exceeds limit")
    try:
        return json.loads(payload)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ElaborationError("frontend JSON output is malformed") from error


def _write_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _tool_source_allowlist(tool: str) -> dict[str, Path]:
    executable = Path(tool).resolve(strict=True)
    candidates = (
        executable.parent.parent / "share" / "verilator" / "include",
        executable.parent.parent / "include",
    )
    result: dict[str, Path] = {}
    for pseudo, basename in (
        ("<verilated_std>", "verilated_std.sv"),
        ("<verilated_std_waiver>", "verilated_std_waiver.vlt"),
    ):
        matches: list[Path] = []
        for directory in candidates:
            path = directory / basename
            try:
                status = path.lstat()
            except OSError:
                continue
            if not path.is_symlink() and stat.S_ISREG(status.st_mode):
                matches.append(path.resolve())
        if len(set(matches)) == 1:
            result[pseudo] = matches[0]
    return result


def _validate_metadata_closure(
    metadata: object,
    closure: Mapping[Path, object],
    tool_sources: Mapping[str, Path],
) -> None:
    if not isinstance(metadata, Mapping):
        raise ElaborationError("compiler metadata is not an object")
    files = metadata.get("files")
    if not isinstance(files, Mapping):
        raise ElaborationError("compiler metadata files are missing")
    allowed = {path.as_posix() for path in closure}
    for file_id, record in files.items():
        if not isinstance(file_id, str) or not file_id or not isinstance(record, Mapping):
            raise ElaborationError("compiler metadata file record is invalid")
        filename = record.get("filename")
        realpath = record.get("realpath")
        if not isinstance(filename, str) or not filename or not isinstance(realpath, str) or not realpath:
            raise ElaborationError("compiler metadata file fields are missing")
        if filename in {"<built-in>", "<command-line>"}:
            if realpath != filename:
                raise ElaborationError("compiler metadata pseudo file shape is invalid")
            continue
        if filename in {"<verilated_std>", "<verilated_std_waiver>"}:
            allowed_tool_source = tool_sources.get(filename)
            if allowed_tool_source is None or not os.path.isabs(realpath) or Path(realpath).resolve() != allowed_tool_source:
                raise ElaborationError("compiler metadata verilated_std tool source is not proven")
            continue
        if not os.path.isabs(realpath):
            raise ElaborationError("compiler metadata file path is not absolute")
        if os.path.realpath(realpath) not in allowed:
            raise ElaborationError("compiler metadata file is outside source closure")


def run_verilator_elaboration(
    *,
    source_root: Path,
    top_module: str,
    source_files: Sequence[str],
    include_roots: Sequence[str] = (),
    defines: Sequence[tuple[str, str]] = (),
    parameters: Sequence[tuple[str, str]] = (),
    output_dir: Path,
) -> Mapping[str, object]:
    """Run a bounded Verilator JSON frontend over one explicit source closure."""
    from myfuzz.integration.campaign import CampaignLimits, CampaignOptions, run_supervised_command

    if not isinstance(source_root, Path) or not isinstance(output_dir, Path):
        raise ElaborationError("source root and output path must be pathlib paths")
    if source_root.is_symlink() or not source_root.is_dir():
        raise ElaborationError("source root is missing or a symlink")
    root = source_root.resolve()
    if not isinstance(top_module, str) or _IDENTIFIER.fullmatch(top_module) is None:
        raise ElaborationError("top module identifier is unsafe")
    if not isinstance(source_files, (tuple, list)) or not source_files:
        raise ElaborationError("source files are missing")
    resolved_sources: list[tuple[Path, str]] = []
    labels: set[str] = set()
    for value in source_files:
        path, label = _rooted_path(root, value, kind="source", directory=False)
        if label in labels:
            raise ElaborationError(f"duplicate source file: {label}")
        labels.add(label)
        resolved_sources.append((path, label))
    resolved_includes: list[Path] = []
    include_labels: set[str] = set()
    if not isinstance(include_roots, (tuple, list)):
        raise ElaborationError("include roots are invalid")
    for value in include_roots:
        path, label = _rooted_path(root, value, kind="include", directory=True)
        if label in include_labels:
            raise ElaborationError(f"duplicate include root: {label}")
        include_labels.add(label)
        resolved_includes.append(path)
    define_pairs = _pairs(defines, kind="define", value_pattern=_DEFINE_VALUE)
    parameter_pairs = _pairs(parameters, kind="parameter", value_pattern=_DECIMAL_INTEGER)

    if ".." in output_dir.parts:
        raise ElaborationError("output path escape is forbidden")
    if output_dir.is_absolute():
        candidate_output = output_dir
    else:
        candidate_output = root / output_dir
    try:
        candidate_output.relative_to(root)
    except ValueError as error:
        raise ElaborationError("output path escape is forbidden") from error
    output_dir = candidate_output
    if output_dir.exists() or output_dir.is_symlink():
        raise ElaborationError("output path already exists or is a symlink")
    if not output_dir.parent.is_dir():
        raise ElaborationError("output parent is missing or contains a symlink")
    current = root
    for part in output_dir.relative_to(root).parts[:-1]:
        current = current / part
        if current.is_symlink():
            raise ElaborationError("output parent contains a symlink")

    initial_closure = _closure(root, resolved_sources, resolved_includes)
    output_dir.mkdir()

    tree_path = output_dir / "ports.tree.json"
    metadata_path = output_dir / "ports.meta.json"
    diagnostic_path = output_dir / "frontend.log"
    version_path = output_dir / "tool-version.log"
    manifest_path = output_dir / "manifest.json"
    tool = shutil.which("verilator")
    tool_sources = {} if tool is None else _tool_source_allowlist(tool)
    initial_tool_snapshot: dict[str, tuple[Path, str, int]] = {}
    for name, path in sorted(tool_sources.items()):
        digest, size = _file_hash(path)
        initial_tool_snapshot[name] = (path, digest, size)
    logical_command: tuple[str, ...] = (
        () if tool is None else (
            "nice", "-n15", tool, "--json-only",
            "--json-only-output", tree_path.as_posix(),
            "--json-only-meta-output", metadata_path.as_posix(),
            "--top-module", top_module,
            *(f"-I{path.as_posix()}" for path in resolved_includes),
            *(f"-D{name}={value}" for name, value in define_pairs),
            *(f"-G{name}={value}" for name, value in parameter_pairs),
            *(path.as_posix() for path, _ in resolved_sources),
        )
    )
    manifest: dict[str, object] = {
        "schema_version": "elaboration_manifest.v1",
        "top_module": top_module,
        "command": list(logical_command),
        "tool_version": "",
        "sources": [
            {"file": path.relative_to(root).as_posix(), "sha256": digest, "size": size}
            for path, (digest, size) in initial_closure.items()
        ],
        "tool_sources": [
            {
                "name": name,
                "sha256": digest,
                "size": size,
                "path": path.as_posix(),
            }
            for name, (path, digest, size) in initial_tool_snapshot.items()
        ],
        "status": "pending",
        "frontend_status": "pending",
        "returncode": None,
        "peak_rss_bytes": 0,
        "rss_sample_count": 0,
        "diagnostics": "",
        "diagnostics_truncated": False,
        "error": None,
    }
    _write_manifest(manifest_path, manifest)
    if tool is None:
        manifest.update(status="startup-error", frontend_status="startup-error", error="verilator tool not found")
        _write_manifest(manifest_path, manifest)
        raise ElaborationError("verilator tool not found")

    try:
        result = run_supervised_command(CampaignOptions(
            command=(
                "nice", "-n15", sys.executable, "-c", _FRONTEND_WRAPPER,
                diagnostic_path.as_posix(), version_path.as_posix(),
                str(_DIAGNOSTIC_BYTES), str(_VERSION_BYTES), tool,
                *logical_command[2:],
            ),
            output_dir=output_dir / "supervision",
            duration_seconds=_ELABORATION_TIMEOUT_SECONDS,
            checkpoint_seconds=1,
            limits=CampaignLimits(512 * 1024 * 1024, 768 * 1024 * 1024),
            env={"JOBS": "1"},
        ))
    except KeyboardInterrupt:
        manifest.update(status="interrupted", error="supervision interrupted")
        _write_manifest(manifest_path, manifest)
        raise
    except Exception as error:
        manifest.update(status="supervision-error", error=f"{type(error).__name__}: {error}")
        _write_manifest(manifest_path, manifest)
        raise

    try:
        diagnostics, diagnostics_truncated = _bounded_text(diagnostic_path, _DIAGNOSTIC_BYTES)
        version, _ = _bounded_text(version_path, _VERSION_BYTES)
        manifest.update(
            frontend_status=result.get("status"),
            returncode=result.get("returncode"),
            peak_rss_bytes=result.get("peak_rss_bytes", 0),
            rss_sample_count=result.get("rss_sample_count", 0),
            diagnostics=diagnostics,
            diagnostics_truncated=diagnostics_truncated,
            tool_version=version,
        )
        if result.get("status") != "completed" or result.get("returncode") != 0:
            manifest.update(status="frontend-error", error="frontend did not complete successfully")
            _write_manifest(manifest_path, manifest)
            detail = "\n" + diagnostics if diagnostics else ""
            raise ElaborationError(f"verilator frontend failed: {result.get('status')}{detail}")

        current_tool_sources = _tool_source_allowlist(tool)
        current_tool_snapshot: dict[str, tuple[Path, str, int]] = {}
        for name, path in sorted(current_tool_sources.items()):
            digest, size = _file_hash(path)
            current_tool_snapshot[name] = (path, digest, size)
        if current_tool_snapshot != initial_tool_snapshot:
            manifest.update(status="stale-tool-source", error="tool source changed during elaboration")
            _write_manifest(manifest_path, manifest)
            raise ElaborationError("tool source changed or is stale")

        current_closure = _closure(
            root, resolved_sources, resolved_includes, excluded=output_dir
        )
        if current_closure != initial_closure:
            manifest.update(status="stale-source", error="source closure changed during elaboration")
            _write_manifest(manifest_path, manifest)
            raise ElaborationError("source closure changed or is stale")
        try:
            tree = _json_file(tree_path)
            metadata = _json_file(metadata_path)
        except ElaborationError as error:
            manifest.update(status="malformed-output", error=str(error))
            _write_manifest(manifest_path, manifest)
            raise
        mapping = {path.as_posix(): path.relative_to(root).as_posix() for path in initial_closure}
        try:
            _validate_metadata_closure(metadata, initial_closure, tool_sources)
            evidence = extract_physical_ports(
                tree, metadata, top_module=top_module, source_files=mapping
            )
        except Exception as error:
            manifest.update(status="evidence-error", error=f"{type(error).__name__}: {error}")
            _write_manifest(manifest_path, manifest)
            raise
        (output_dir / "elaborated_ports.json").write_text(
            json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        manifest.update(status="completed", error=None)
        _write_manifest(manifest_path, manifest)
        return evidence
    except KeyboardInterrupt:
        manifest.update(status="interrupted", error="post-frontend processing interrupted")
        _write_manifest(manifest_path, manifest)
        raise
    except Exception as error:
        if manifest.get("status") == "pending":
            manifest.update(status="artifact-error", error=f"{type(error).__name__}: {error}")
        _write_manifest(manifest_path, manifest)
        raise
