"""Read bounded physical port facts from a Verilator JSON syntax tree."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


class ElaborationError(ValueError):
    """Compiler evidence is missing, ambiguous, or outside the supported subset."""


_MAX_AST_NODES = 250_000
_MAX_TYPE_DEPTH = 128
_MAX_PORTS = 65_536
_MAX_MEMBERS = 65_536
_MAX_WIDTH = 1 << 24
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
        if kind == "PACKARRAYDTYPE":
            element = self.physical_type(self.pointer(node, "refDTypep"), active=active, depth=depth + 1)
            if element.leaves:
                raise ElaborationError("unsupported packed array of structured elements")
            count = _range_width(node.get("declRange"), "packed array")
            width = _bounded_width(element.width * count, "packed array")
            return _PhysicalType(width, _signed(node, element.signed), ())
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
        return _PhysicalType(total, _signed(node, False), tuple(expanded))

    def port(self, node: Mapping[str, object]) -> dict[str, object]:
        name = node.get("name")
        if not isinstance(name, str) or not name:
            raise ElaborationError("port name is invalid")
        direction = {"INPUT": "input", "OUTPUT": "output", "INOUT": "inout"}.get(node.get("direction"))
        if direction is None:
            raise ElaborationError(f"port direction is unsupported: {node.get('direction')}")
        physical = self.physical_type(self.pointer(node, "dtypep"))
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
