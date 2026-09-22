"""Independent structural audit of a generated SoC.

The audit deliberately does not read the renderer's bookkeeping.  It runs the
SystemVerilog frontend over the generated top and the source list that was
actually published, extracts the elaborated netlist (top ports, cell instances,
resolved submodule identities and pin expressions) and compares that against the
plan, the port-disposition ledger and the interrupt plan.

What it can prove here is structural: names, directions, widths, which instance
drives which net, which fabric source owns which arbiter lane (and which lane's
responses it consumes), which controller bit a peripheral interrupt lands on,
which router target the controller's MMIO port is attached to, and whether the
CPU is held in reset by the rendered structure the drive profile declares.  What
it cannot prove is protocol behaviour over time; that stays with the
protocol-level simulation evidence and is reported as ``unknown`` rather than
passed.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .component_profile import ComponentProfileError
from .soc_composition import CompositionPlan
from .soc_port_dispositions import (
    DispositionEntry,
    aligned_segments,
    cpu_entry_expression,
    port_segments,
    segment_net,
    top_port_name,
)

AUDIT_SCHEMA = "soc_structure_audit.v1"
PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"


class StructureAuditError(ValueError):
    """The audit could not run at all (missing source, tool or plan)."""


@dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    status: str
    subject: str
    detail: str
    expected: object = None
    actual: object = None

    def document(self) -> dict[str, object]:
        record: dict[str, object] = {
            "check_id": self.check_id,
            "status": self.status,
            "subject": self.subject,
            "detail": self.detail,
        }
        if self.expected is not None:
            record["expected"] = self.expected
        if self.actual is not None:
            record["actual"] = self.actual
        return record


@dataclass(frozen=True, slots=True)
class Netlist:
    """The elaborated structure extracted from the generated RTL."""

    top_module: str
    ports: tuple[dict[str, object], ...]
    cells: tuple[dict[str, object], ...]
    warnings: int = 0

    def cell(self, name: str) -> dict[str, object] | None:
        for item in self.cells:
            if item["instance"] == name:
                return item
        return None

    def pin(self, cell: str, pin: str) -> str | None:
        record = self.cell(cell)
        if record is None:
            return None
        pins = record["pins"]
        assert isinstance(pins, Mapping)
        value = pins.get(pin)
        return None if value is None else str(value)


def _expr_text(node: object) -> str:
    """Canonical text for the expression forms the generated top produces."""
    if isinstance(node, list):
        if len(node) == 1:
            return _expr_text(node[0])
        return "{" + ", ".join(_expr_text(item) for item in node) + "}"
    if not isinstance(node, Mapping):
        return "?"
    kind = node.get("type")
    if kind == "VARREF":
        return str(node.get("name"))
    if kind == "CONST":
        return str(node.get("name"))
    if kind == "SEL":
        base = _expr_text(node.get("fromp"))
        lsb = _const_value(node.get("lsbp"))
        width = int(node.get("widthConst", 1))
        if lsb is None:
            return f"{base}[?]"
        return f"{base}[{lsb + width - 1}:{lsb}]" if width > 1 else f"{base}[{lsb}]"
    if kind in ("AND", "OR", "XOR"):
        operator = {"AND": "&", "OR": "|", "XOR": "^"}[str(kind)]
        return f"({operator}{_expr_text(node.get('lhsp'))}{_expr_text(node.get('rhsp'))})"
    if kind == "NOT":
        return f"~{_expr_text(node.get('lhsp'))}"
    if kind == "EXTEND":
        return f"extend({_expr_text(node.get('lhsp'))})"
    if kind == "CONCAT":
        return "{" + _expr_text(node.get("lhsp")) + ", " + _expr_text(node.get("rhsp")) + "}"
    if kind == "REPLICATE":
        return f"replicate({_expr_text(node.get('srcp'))})"
    if kind == "ARRAYSEL":
        return f"{_expr_text(node.get('fromp'))}[{_expr_text(node.get('bitp'))}]"
    return f"<{kind}>"


def _expr_leaves(node: object) -> list[str]:
    """The leaf expressions of a (possibly nested) concatenation, MSB first.

    A struct port connection rendered as an assignment pattern or a
    concatenation elaborates into a nested CONCAT tree; flattening it recovers
    the member order the source wrote, which is the order the plan's member
    record uses.
    """
    items = node if isinstance(node, list) else [node]
    result: list[str] = []
    for item in items:
        if isinstance(item, Mapping) and item.get("type") == "CONCAT":
            result.extend(_expr_leaves(item.get("lhsp")))
            result.extend(_expr_leaves(item.get("rhsp")))
        else:
            result.append(_expr_text(item))
    return result


def _access_of(node: object) -> str:
    """The cell-side access of a pin: ``RD`` the cell samples, ``WR`` it drives."""
    if isinstance(node, list):
        for item in node:
            found = _access_of(item)
            if found:
                return found
        return ""
    if isinstance(node, Mapping):
        if node.get("type") == "VARREF" and node.get("access"):
            return str(node["access"])
        for value in node.values():
            found = _access_of(value)
            if found:
                return found
    return ""


def _const_value(node: object) -> int | None:
    """Value of a Verilator CONST literal such as ``3'h3`` or ``32'd5``."""
    if isinstance(node, list):
        return _const_value(node[0]) if node else None
    if not isinstance(node, Mapping) or node.get("type") != "CONST":
        return None
    name = str(node.get("name", "")).strip()
    if "'" in name:
        _, _, rest = name.partition("'")
        rest = rest.lower().removeprefix("s")
        base, digits = rest[:1], rest[1:]
        bases = {"h": 16, "d": 10, "b": 2, "o": 8}
        radix = bases.get(base, 10)
        digits = digits.replace("_", "")
        try:
            return int(digits, radix) if digits else None
        except ValueError:
            return None
    try:
        return int(name, 10)
    except ValueError:
        return None


def extract_netlist(top_text: str, source_files: Sequence[str], *, top_module: str,
                    base_dir: Path, source_root: str = ".",
                    include_roots: Sequence[str] = ()) -> Netlist:
    """Elaborate the published RTL and return the netlist facts it really has.

    This runs the SystemVerilog frontend over the generated top plus the source
    list that was published, in one temporary directory, and reads the ports and
    the cell structure out of that single elaboration.  Nothing here consults the
    renderer's own records.
    """
    import tempfile

    from .source_elaboration import ElaborationError, extract_physical_ports

    root = (Path(base_dir) / source_root).resolve()
    with tempfile.TemporaryDirectory(prefix=".myfuzz-audit-", dir=root) as temporary:
        temporary_root = Path(temporary)
        top_path = temporary_root / "generated_top.sv"
        top_path.write_text(top_text, encoding="utf-8")
        files = [top_path.as_posix()]
        mapping = {top_path.as_posix(): "generated_top.sv"}
        # A published source closure may contain include roots in the same
        # sequence as source files (the profile elaborator accepts both forms,
        # and older callers pass that sequence directly).  A directory is not
        # a Verilator compilation unit, but it is a valid include root.  Treat
        # it as such here instead of reporting a false ``audit-source-missing``
        # failure before the independent elaboration even starts.
        resolved_includes: list[str] = []
        for item in include_roots:
            candidate = (root / item).resolve()
            if not candidate.is_dir():
                raise StructureAuditError(f"audit-include-root-missing:{item}")
            resolved_includes.append(candidate.as_posix())
        for item in source_files:
            candidate = (root / item).resolve()
            if candidate.is_dir():
                if candidate.as_posix() not in resolved_includes:
                    resolved_includes.append(candidate.as_posix())
                continue
            if not candidate.is_file():
                raise StructureAuditError(f"audit-source-missing:{item}")
            files.append(candidate.as_posix())
            mapping[candidate.as_posix()] = item
        tree, meta, warnings = _dump_tree(files, top_module, root,
                                          include_roots=tuple(resolved_includes))
        try:
            evidence = extract_physical_ports(tree, meta, top_module=top_module,
                                              source_files=mapping)
        except ElaborationError as error:
            raise StructureAuditError(f"audit-port-extraction:{error}") from error
        ports = tuple({"name": item["name"], "direction": item["direction"],
                       "width": item["width"]} for item in evidence["ports"])
    return _netlist_from_tree(tree, ports, top_module, warnings)


def _dump_tree(files: Sequence[str], top_module: str, root: Path,
               *, include_roots: Sequence[str] = ()) -> tuple[dict, dict, int]:
    import shutil
    import subprocess
    import tempfile

    tool = shutil.which("verilator")
    if tool is None:
        raise StructureAuditError("audit-tool-missing")
    with tempfile.TemporaryDirectory(prefix=".myfuzz-audit-tree-", dir=root) as temporary:
        tree_path = Path(temporary) / "tree.json"
        meta_path = Path(temporary) / "meta.json"
        command = ["/usr/bin/nice", "-n15", tool, "--json-only", "-Wno-fatal",
                   "--json-only-output", tree_path.as_posix(),
                   "--json-only-meta-output", meta_path.as_posix(),
                   "--top-module", top_module,
                   *(f"-I{item}" for item in include_roots), *files]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False,
                                    timeout=600, cwd=root.as_posix())
        except (OSError, subprocess.TimeoutExpired) as error:
            raise StructureAuditError(f"audit-frontend-failed:{error}") from error
        diagnostics = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            raise StructureAuditError(
                f"audit-frontend-error:{diagnostics.strip()[:2000]}")
        warnings = len([line for line in diagnostics.splitlines() if "%Warning" in line])
        return (json.loads(tree_path.read_text(encoding="utf-8")),
                json.loads(meta_path.read_text(encoding="utf-8")), warnings)


def _netlist_from_tree(tree: Mapping[str, object], ports: Sequence[Mapping[str, object]],
                       top_module: str, warnings: int) -> Netlist:
    modules = [item for item in tree.get("modulesp", [])  # type: ignore[union-attr]
               if isinstance(item, Mapping) and item.get("name") == top_module]
    if len(modules) != 1:
        raise StructureAuditError(f"audit-top-module-ambiguous:{len(modules)}")
    module = modules[0]
    index: dict[str, Mapping[str, object]] = {}

    def walk(node: object) -> None:
        if isinstance(node, Mapping):
            address = node.get("addr")
            if isinstance(address, str):
                index.setdefault(address, node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(tree)
    cells: list[dict[str, object]] = []
    for statement in module.get("stmtsp", []):  # type: ignore[union-attr]
        if not isinstance(statement, Mapping) or statement.get("type") != "CELL":
            continue
        target = index.get(str(statement.get("modp")))
        submodule = str(target.get("name")) if target is not None else None
        pins: dict[str, str] = {}
        accesses: dict[str, str] = {}
        leaves: dict[str, list[str]] = {}
        for pin in statement.get("pinsp", []):  # type: ignore[union-attr]
            if not isinstance(pin, Mapping):
                continue
            expression = pin.get("exprp")
            items = expression if isinstance(expression, list) else [expression]
            pins[str(pin.get("name"))] = _expr_text(items)
            accesses[str(pin.get("name"))] = _access_of(items)
            # The individual expressions a multi-role port is assembled from.
            # A single-expression pin yields exactly one leaf.
            leaves[str(pin.get("name"))] = _expr_leaves(items)
        cells.append({
            "instance": str(statement.get("name")),
            "module": submodule,
            "pin_leaves": leaves,
            "parameters": {
                str(item["name"]): _const_value(item.get("valuep"))
                for item in (target or {}).get("stmtsp", [])
                if isinstance(item, Mapping) and item.get("isParam") is True
            },
            "pins": pins,
            "pin_access": accesses,
            "location": statement.get("loc"),
        })
    return Netlist(top_module=top_module,
                   ports=tuple({"name": str(item["name"]), "direction": str(item["direction"]),
                                "width": int(item["width"])} for item in ports),
                   cells=tuple(sorted(cells, key=lambda item: str(item["instance"]))),
                   warnings=warnings)


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------


def _expected_top_ports(entries: Sequence[DispositionEntry],
                        synthetic: Mapping[str, object] | None = None,
                        peers: Sequence[object] = ()) -> dict[str, tuple[str, int]]:
    expected: dict[str, tuple[str, int]] = {"clk_i": ("input", 1), "rst_ni": ("input", 1)}
    for entry in entries:
        if entry.disposition not in ("fuzz", "external", "observe"):
            continue
        name = top_port_name(entry)
        direction = "input" if entry.direction == "input" else "output"
        expected[name] = (direction, entry.bit_hi - entry.bit_lo + 1)
        if entry.disposition == "fuzz":
            # The driver's applied value is exported so a run can report the
            # timing it really produced; it is an observation, never an input.
            expected[f"{name}__applied"] = ("output", entry.bit_hi - entry.bit_lo + 1)
    for item in (synthetic or {}).get("raw_ports", []):  # type: ignore[union-attr]
        # The synthetic master's raw fields are exported inputs at the offsets
        # the compiled stimulus document records; the top boundary must match.
        expected[str(item["name"])] = ("input", int(item["width"]))
    for peer in peers:
        # A peer's stimulus inputs and its observed outputs are the peer's own
        # boundary: the pins it owns are *not* exported, and a peer whose
        # counters were dropped from this set is a peer nothing observes.
        for slot in peer.slots:  # type: ignore[attr-defined]
            for signal in slot.signals:
                expected[str(signal.top_port)] = ("input", int(signal.width))
        for observation in peer.observations:  # type: ignore[attr-defined]
            expected[str(observation.top_port)] = ("output", int(observation.width))
    return expected


def _base_net(expression: str) -> str:
    """The net a pin expression ultimately names, ignoring selects and braces."""
    text = expression.strip().strip("{}")
    for separator in (",", "[", "(", " "):
        if separator in text:
            text = text.split(separator)[0]
    return text.strip("{} ")


def _lane_expressions(net: str, lane: int, width: int, lanes: int) -> tuple[str, ...]:
    """The elaborated spellings of one lane of a packed SoC signal.

    The frontend flattens a two-dimensional packed vector, so lane ``k`` of a
    ``NUM_SOURCES x width`` signal appears either as ``net[k]`` (1-bit lanes) or
    as the flat slice ``net[k*width +: width]``; a single-lane signal may lose
    the select entirely.
    """
    candidates = [f"{net}[{lane}]"]
    if width > 1:
        candidates.append(f"{net}[{lane * width + width - 1}:{lane * width}]")
    if lanes == 1:
        candidates.append(net)
    return tuple(dict.fromkeys(candidates))


def _pin_cells(netlist: Netlist) -> dict[str, list[tuple[str, str, str]]]:
    """expression text -> [(cell, pin, access)] for every elaborated pin."""
    index: dict[str, list[tuple[str, str, str]]] = {}
    for cell in netlist.cells:
        pins = cell.get("pins") or {}
        accesses = cell.get("pin_access") or {}
        assert isinstance(pins, Mapping)
        for pin, expression in pins.items():
            text = str(expression).strip()
            index.setdefault(text, []).append(
                (str(cell["instance"]), str(pin), str(accesses.get(pin, ""))))
    return index


def _expr_leaves_text(text: str) -> list[str]:
    """Split the audit's own ``{a, b}`` rendering of a concatenation into parts."""
    stripped = text.strip()
    if not stripped.startswith("{"):
        return [stripped]
    body = stripped[1:-1] if stripped.endswith("}") else stripped[1:]
    parts: list[str] = []
    depth = 0
    current = ""
    for character in body:
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
        if character == "," and depth == 0:
            parts.append(current.strip())
            current = ""
            continue
        current += character
    if current.strip():
        parts.append(current.strip())
    return parts


def _leaf_layout(instance: object, port: str
                 ) -> tuple[tuple[int, int, tuple[str, ...], DispositionEntry], ...]:
    """The segments of one port in the order the rendered connection emits them.

    The layout is recomputed from the profile binding's elaborated member facts
    and the disposition ledger, so the audit never reads the renderer's record to
    decide what the rendered expression should look like.
    """
    entries = port_segments(instance.dispositions).get(port, ())  # type: ignore[attr-defined]
    if not entries:
        return ()
    fact = instance.binding.facts.port(port)  # type: ignore[attr-defined]
    members = tuple(getattr(fact, "members", ()))
    return aligned_segments(entries, members, entries[0].width)


def _folded_constant(record: Mapping[str, object], wanted: Sequence[str]) -> int | None:
    """The value a wholly-constant segment set must fold to, or ``None``.

    A struct or vector port whose every segment is a literal is one constant in
    the elaborated netlist, so the member-by-member comparison becomes a value
    comparison: the literals are packed most significant segment first, exactly
    as the rendered connection packs them.
    """
    segments = [seg for seg in record["segments"] if seg["expression"] is not None]
    if len(segments) != len(wanted) or not segments:
        return None
    value = 0
    for segment, expression in zip(segments, wanted):
        piece = _pin_constant(expression)
        if piece is None:
            return None
        width = int(segment["bit_hi"]) - int(segment["bit_lo"]) + 1
        if piece >= (1 << width):
            return None
        value = (value << width) | piece
    return value


def _leaf_key(text: str) -> tuple[str, object]:
    """A comparable identity for one elaborated leaf expression."""
    value = _pin_constant(text)
    if value is not None:
        return ("const", value)
    return ("net", _base_net(text))


def segment_net_of(instance: object, port: str, role: str) -> str:
    """The net a role is wired on, named by the ledger's own rule.

    A whole-port role keeps ``{instance}__{port}``; a role that owns part of its
    port is qualified by its role.  The expectation is the ledger's entry for
    this role, so it is derived from the plan rather than from the rendered text.
    A role with no ledger entry cannot have been wired at all, and is reported as
    a mismatch instead of being guessed.
    """
    for entry in instance.dispositions:  # type: ignore[attr-defined]
        if entry.port == port and entry.role == role:
            return segment_net(entry)
    return f"<no-ledger-entry:{port}:{role}>"


def _segment_leaf(netlist: Netlist, instance: object, port: str,
                  bit_lo: int, bit_hi: int) -> str | None:
    """The elaborated expression carrying one bit span of one port."""
    cell = netlist.cell(f"u_{instance.instance_id}")  # type: ignore[attr-defined]
    if cell is None:
        return None
    leaves = dict(cell.get("pin_leaves") or {}).get(port)
    if not leaves:
        return None
    for index, (low, high, _path, _entry) in enumerate(_leaf_layout(instance, port)):
        if (low, high) == (bit_lo, bit_hi) and index < len(leaves):
            return str(leaves[index])
    return None


def _field_leaf(netlist: Netlist, instance: object, port: str, role: str
                ) -> str | None:
    """The elaborated expression carrying one role of one multi-role port."""
    cell = netlist.cell(f"u_{instance.instance_id}")  # type: ignore[attr-defined]
    if cell is None:
        return None
    leaves = dict(cell.get("pin_leaves") or {}).get(port)
    if not leaves:
        return None
    for index, (_low, _high, _path, entry) in enumerate(_leaf_layout(instance, port)):
        if entry.role == role and index < len(leaves):
            return str(leaves[index])
    return None


def _audit_multi_role_ports(plan: CompositionPlan, netlist: Netlist) -> dict[str, object]:
    """Re-read every multi-role port connection against the plan's own record.

    Three independent claims are checked for each recorded port: the member
    layout the plan read from the elaboration is the layout the elaboration
    really has; the segments the plan records are the segments the binding and
    the disposition ledger imply, tiling the port in the recorded order; and the
    elaborated connection expression of the component instance carries exactly
    those expressions, in that order, with the port's own direction.
    """
    errors: list[dict[str, object]] = []
    expected: list[dict[str, object]] = []
    for instance in plan.instances:
        for record in instance.port_bindings:
            port = str(record["port"])
            fact = instance.binding.facts.port(port)
            entry = {"instance": instance.instance_id, "port": port}
            if fact is None:
                errors.append({**entry, "check": "port_missing"})
                continue
            actual_members = [{"path": list(member.path), "bit_lo": member.raw_lo,
                               "bit_hi": member.raw_hi, "width": member.width,
                               "signed": bool(member.signed),
                               "enum_type": str(getattr(member, "enum_type", ""))}
                              for member in fact.members]
            if actual_members != [dict(item) for item in record["members"]]:
                errors.append({**entry, "check": "member_layout",
                               "plan": record["members"], "elaborated": actual_members})
                continue
            layout = _leaf_layout(instance, port)
            recorded = [(int(seg["bit_lo"]), int(seg["bit_hi"]))
                        for seg in record["segments"]]
            recomputed = [(low, high) for low, high, _path, _entry in layout]
            if recorded != recomputed:
                errors.append({**entry, "check": "segment_layout",
                               "plan": recorded, "ledger": recomputed})
                continue
            wanted = [str(seg["expression"]) for seg in record["segments"]
                      if seg["expression"] is not None]
            cell = netlist.cell(f"u_{instance.instance_id}")
            leaves = [str(item) for item in
                      dict((cell or {}).get("pin_leaves") or {}).get(port, [])]
            folded = dict((cell or {}).get("pins") or {}).get(port)
            expected_value = _folded_constant(record, wanted)
            if expected_value is not None and _pin_constant(str(folded or "")) is not None:
                # The frontend folds a segment set that is entirely constant into
                # one literal, so the comparison is by value and width.
                if _pin_constant(str(folded)) != expected_value:
                    errors.append({**entry, "check": "member_net_mapping",
                                   "plan": wanted, "elaborated": leaves})
                    continue
            elif [_leaf_key(item) for item in leaves] != [_leaf_key(item) for item in wanted]:
                errors.append({**entry, "check": "member_net_mapping",
                               "plan": wanted, "elaborated": leaves})
                continue
            access = str(dict((cell or {}).get("pin_access") or {}).get(port, ""))
            direction = str(record["direction"])
            if access and access != ("RD" if direction == "input" else "WR"):
                errors.append({**entry, "check": "port_direction",
                               "plan": direction, "elaborated_access": access})
                continue
            expected.append({**entry, "members": len(actual_members),
                             "segments": len(recorded), "leaves": wanted})
    return {"errors": errors, "expected": expected}


def audit_structure(plan: CompositionPlan, *, top_text: str,
                    source_files: Sequence[str], base_dir: Path,
                    include_roots: Sequence[str] = ()) -> dict[str, object]:
    """Re-elaborate the generated RTL and check it against the plan."""
    if not isinstance(plan, CompositionPlan):
        raise StructureAuditError("composition-plan-required")
    try:
        netlist = extract_netlist(top_text, source_files, top_module="myfuzz_soc_top",
                                  base_dir=base_dir, include_roots=include_roots)
    except ComponentProfileError as error:
        raise StructureAuditError(f"audit-elaboration:{error}") from error
    findings: list[Finding] = []
    unknown: list[dict[str, object]] = []
    entries = [entry for item in plan.instances for entry in item.dispositions]

    # 1. The top-level boundary is exactly the ledger's exported ports.
    expected_ports = _expected_top_ports(entries, plan.synthetic, plan.peers)
    actual_ports = {str(port["name"]): (str(port["direction"]), int(port["width"]))
                    for port in netlist.ports}
    findings.append(Finding(
        "top_ports", PASS if actual_ports == expected_ports else FAIL, "myfuzz_soc_top",
        "the exported top-level boundary equals the disposition ledger, the "
        "synthetic master's recorded raw ports and the attached peers' stimulus and "
        "observation ports",
        expected=dict(sorted(expected_ports.items())),
        actual=dict(sorted(actual_ports.items()))))

    # 1b. Every multi-role (struct/array/sliced) port the plan records really is
    #     assembled from those member nets in the elaborated netlist.
    multi_role = _audit_multi_role_ports(plan, netlist)
    if multi_role["expected"] or multi_role["errors"]:
        findings.append(Finding(
            "struct_port_mapping",
            PASS if not multi_role["errors"] else FAIL,
            "multi-role port connections",
            "every recorded multi-role port connection carries exactly the recorded "
            "member nets, in the recorded order, on a port of the recorded direction",
            expected=multi_role["expected"],
            actual=multi_role["errors"] if multi_role["errors"]
            else f"{len(multi_role['expected'])} port(s) verified"))

    # 2. Every planned instance exists, with the module the plan implies.
    fabric = plan.plan["fabric"]
    expected_cells: dict[str, str] = {"u_soc_arbiter": "soc_arbiter", "u_soc_router": "soc_router"}
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    expected_cells[f"u_{cpu_instance.instance_id}"] = cpu_instance.top_module
    for index, target in enumerate(fabric["targets"]):
        if target.get("backing_kind") == "memory":
            expected_cells[f"u_mem_{index}"] = "riscv_boot_memory_"
    for binding in plan.plan["processor_execution"]["bindings"]:
        source_id = str(binding["source_id"])
        lane = next(index for index, source in enumerate(fabric["sources"])
                    if str(source["source_id"]) == source_id)
        expected_cells[f"u_{cpu_instance.instance_id}_adapter_{lane}"] = str(binding["rtl_module"])
    if plan.synthetic:
        expected_cells[f"u_{plan.synthetic['instance_id']}"] = str(plan.synthetic["module"])
    for peer in plan.peers:
        # The peer instance is part of the planned structure: a top that omits it
        # leaves the interface it was attached to undriven.
        expected_cells[peer.instance] = peer.module
    for target in plan.target_records:
        if "instance_id" not in target:
            continue
        instance = plan.instance(str(target["instance_id"]))
        expected_cells[f"u_{instance.instance_id}"] = instance.top_module
        expected_cells[f"u_{instance.instance_id}_adapter"] = \
            str(target["resolved_adapter"]["rtl_module"])
    if plan.interrupt_plan.present:
        expected_cells["u_irq_controller"] = plan.interrupt_plan.module
    missing = sorted(set(expected_cells) - {str(item["instance"]) for item in netlist.cells})
    wrong_module = []
    for name, module in sorted(expected_cells.items()):
        record = netlist.cell(name)
        if record is None:
            continue
        actual = str(record["module"])
        if not actual.startswith(module):
            wrong_module.append({"instance": name, "expected": module, "actual": actual})
    findings.append(Finding(
        "instances", PASS if not missing and not wrong_module else FAIL, "instance set",
        "every planned instance is present and elaborates to the planned module",
        expected=dict(sorted(expected_cells.items())),
        actual={"missing": missing, "wrong_module": wrong_module}))

    # 3. Each peripheral's protocol roles are wired to the component's own port.
    role_findings: list[dict[str, object]] = []
    for target in plan.target_records:
        if "instance_id" not in target:
            continue
        instance = plan.instance(str(target["instance_id"]))
        adapter = target["resolved_adapter"]
        for item in adapter["target_side_ports"]:
            role = str(item["role"])
            bridge_net = _base_net(netlist.pin(f"u_{instance.instance_id}_adapter", role) or "")
            binding = adapter["role_widths"][role]
            # A struct/array port carries several roles at once, so the role's own
            # member expression is read instead of the whole port's connection.
            leaf = _field_leaf(netlist, instance, str(binding["component_port"]), role)
            component_net = _base_net(leaf if leaf is not None else
                                      netlist.pin(f"u_{instance.instance_id}",
                                                  str(binding["component_port"])) or "")
            expected_net = f"{instance.instance_id}__{role}"
            role_findings.append({
                "instance": instance.instance_id,
                "role": role,
                "bridge_pin_net": bridge_net,
                "component_pin_net": component_net,
                "expected_net": expected_net,
                "ok": bridge_net == component_net == expected_net,
            })
    bad_roles = [item for item in role_findings if not item["ok"]]
    findings.append(Finding(
        "target_role_wiring", PASS if not bad_roles else FAIL, "peripheral protocol roles",
        "each bridge role and the component port of that role share one net",
        expected="every role net is shared between bridge and component",
        actual=bad_roles if bad_roles else f"{len(role_findings)} roles verified"))

    # 4. The CPU adapter's component-side pins reach the CPU's declared ports.
    cpu_findings: list[dict[str, object]] = []
    for binding in plan.plan["processor_execution"]["bindings"]:
        source_id = str(binding["source_id"])
        lane = next(index for index, source in enumerate(fabric["sources"])
                    if str(source["source_id"]) == source_id)
        master = next(item for item in plan.spec["masters"]
                      if str(item["source_id"]) == source_id)
        endpoint = cpu_instance.binding.endpoint(str(master["port"]))
        adapter_ports = {str(item["role"]): str(item["adapter_port"])
                         for item in plan.cpu_adapter["source_ports"]}
        for field in endpoint.fields:
            adapter_net = _base_net(netlist.pin(
                f"u_{cpu_instance.instance_id}_adapter_{lane}", adapter_ports[field.role]) or "")
            leaf = _field_leaf(netlist, cpu_instance, field.port, field.role)
            cpu_net = _base_net(leaf if leaf is not None else netlist.pin(
                f"u_{cpu_instance.instance_id}", field.port) or "")
            expected_net = _base_net(segment_net_of(cpu_instance, field.port, field.role))
            cpu_findings.append({
                "role": field.role,
                "adapter_pin_net": adapter_net,
                "cpu_pin_net": cpu_net,
                "expected_net": expected_net,
                "ok": adapter_net == cpu_net == expected_net,
            })
    bad_cpu = [item for item in cpu_findings if not item["ok"]]
    findings.append(Finding(
        "cpu_adapter_wiring", PASS if not bad_cpu else FAIL, "processor adapter boundary",
        "every CPU master field and its adapter pin share the declared net",
        expected="every CPU master field net is shared with its adapter pin",
        actual=bad_cpu if bad_cpu else f"{len(cpu_findings)} fields verified"))

    # 5. Fabric lane ownership: every declared source owns exactly one lane, and
    #    that lane's request nets are driven by the module the plan binds to the
    #    source (a CPU adapter for a CPU master, the synthetic master otherwise).
    lane_findings = _audit_source_lanes(plan, netlist, fabric)
    findings.append(Finding(
        "fabric_source_lanes",
        PASS if not lane_findings["errors"] else FAIL,
        "fabric source lanes",
        "each declared fabric source drives its own lane with the module the plan "
        "binds to that source",
        expected=lane_findings["expected"],
        actual=lane_findings["errors"] if lane_findings["errors"] else lane_findings["actual"]))

    # 6. Response ownership: the response nets a source consumes are the ones its
    #    own lane returns, and the ready it drives is that lane's ready.  A
    #    swapped lane breaks both halves at once.
    ownership_findings = _audit_response_ownership(plan, netlist, fabric)
    findings.append(Finding(
        "response_ownership",
        PASS if not ownership_findings["errors"] else FAIL,
        "fabric response routing",
        "each source consumes only its own lane's rsp_valid/rdata/error and drives "
        "only its own lane's rsp_ready",
        expected=ownership_findings["expected"],
        actual=ownership_findings["errors"] if ownership_findings["errors"]
        else ownership_findings["actual"]))

    # 7. Interrupt source numbering, polarity and controller capacity.
    interrupt_findings = _audit_interrupts(plan, netlist)
    findings.append(Finding(
        "interrupt_paths",
        PASS if not interrupt_findings["errors"] else FAIL,
        "interrupt sources and notification",
        "source id k+1 lands on controller bit k with the recorded polarity, and the "
        "notification reaches the declared CPU entry",
        expected=interrupt_findings["expected"],
        actual=interrupt_findings["actual"] if interrupt_findings["errors"]
        else interrupt_findings["actual"]))

    # 8. The controller's MMIO window is the plan's own router target.
    mmio_findings = _audit_controller_mmio(plan, netlist, fabric)
    findings.append(Finding(
        "controller_mmio",
        PASS if mmio_findings["ok"] else FAIL,
        "interrupt controller MMIO",
        "the controller sits on its planned router target index",
        expected=mmio_findings["expected"],
        actual=mmio_findings["actual"]))

    # 8b. Every declared edge-shaped source really goes through its converter.
    # Nothing to check when no source declares one, and then the check is absent
    # rather than trivially passing, so a plan cannot claim converter support it
    # never rendered.
    normalizer_errors, normalizer_facts = _audit_interrupt_normalizers(plan, netlist)
    if normalizer_facts.get("expected"):
        findings.append(Finding(
            "interrupt_normalizers",
            PASS if not normalizer_errors else FAIL,
            "interrupt edge converters",
            "each held edge-shaped source passes through soc_irq_edge_detect with the "
            "planned EDGE/PULSE_CYCLES, from the declared pin to the controller's own "
            "source slot",
            expected=normalizer_facts["expected"],
            actual=normalizer_errors if normalizer_errors else normalizer_facts["actual"]))

    # 9. Clock and reset distribution.
    clock_findings: list[dict[str, object]] = []
    for instance in plan.instances:
        for binding_record, field in instance.binding.clocks:
            net = _base_net(netlist.pin(f"u_{instance.instance_id}", field.port) or "")
            clock_findings.append({"instance": instance.instance_id, "port": field.port,
                                   "net": net, "ok": net == "clk_i"})
    bad_clocks = [item for item in clock_findings if not item["ok"]]
    findings.append(Finding(
        "clock_distribution", PASS if not bad_clocks else FAIL, "clock ports",
        "every component clock port is driven by the SoC clock input",
        expected="clk_i", actual=bad_clocks if bad_clocks else "all clock ports on clk_i"))

    # 10. Reset polarity: every module reset port is driven through the polarity
    #    its declared contract requires.  The expected map is derived from the
    #    plan (fabric, memory backings, resolved target adapters, the synthetic
    #    master's own declared contract), not from module names.
    from .soc_profile_renderer import FABRIC_RESET_CONTRACT, MEMORY_RESET_CONTRACT

    expected_resets = {
        "u_soc_arbiter": FABRIC_RESET_CONTRACT,
        "u_soc_router": FABRIC_RESET_CONTRACT,
    }
    if plan.synthetic:
        expected_resets[f"u_{plan.synthetic['instance_id']}"] = plan.synthetic["reset_contract"]
    for index, target in enumerate(fabric["targets"]):
        if target.get("backing_kind") == "memory":
            expected_resets[f"u_mem_{index}"] = MEMORY_RESET_CONTRACT
    for target in plan.target_records:
        adapter = target.get("resolved_adapter")
        if isinstance(adapter, Mapping) and "instance_id" in target:
            expected_resets[f"u_{target['instance_id']}_adapter"] = {
                "port": str(adapter["reset"]["port"]),
                "polarity": str(adapter["reset"]["polarity"]),
            }
    reset_findings: list[dict[str, object]] = []
    for cell_name, contract in sorted(expected_resets.items()):
        actual = netlist.pin(cell_name, str(contract["port"])) or ""
        expected = "rst_ni" if contract["polarity"] == "active_low" else "~rst_ni"
        reset_findings.append({
            "cell": cell_name,
            "polarity": contract["polarity"],
            "pin": actual,
            "expected": expected,
            "ok": actual.strip().replace(" ", "") == expected,
        })
    bad_resets = [item for item in reset_findings if not item["ok"]]
    findings.append(Finding(
        "reset_polarity", PASS if not bad_resets else FAIL, "reset distribution",
        "every module reset port is driven with the polarity its contract declares",
        expected="active-high modules get ~rst_ni, active-low modules get rst_ni",
        actual=bad_resets if bad_resets else f"{len(reset_findings)} reset ports verified"))

    # 11. The synthetic master's reset follows the contract the plan declares for
    #     it, on the port the contract names: a driver reset that is inverted,
    #     tied off or moved to another pin would never clear its state machine.
    synthetic_reset = _audit_synthetic_reset(plan, netlist)
    if synthetic_reset is not None:
        findings.append(Finding(
            "fuzz_master_reset",
            PASS if not synthetic_reset["errors"] else FAIL,
            "synthetic master reset",
            "the generated MMIO master's reset pin is driven with the polarity its "
            "declared contract requires",
            expected=synthetic_reset["expected"],
            actual=synthetic_reset["errors"] if synthetic_reset["errors"]
            else synthetic_reset["actual"]))

    # 12. The synthetic master carries exactly the compiled stimulus parameters.
    synthetic_parameters = _audit_synthetic_parameters(plan, netlist)
    if synthetic_parameters is not None:
        if synthetic_parameters["errors"]:
            findings.append(Finding(
                "fuzz_master_parameters", FAIL, "synthetic master parameters",
                "a rendered parameter no longer matches the compiled stimulus projection",
                expected=synthetic_parameters["expected"],
                actual=synthetic_parameters["errors"]))
        elif synthetic_parameters["unknown"]:
            unknown.append({
                "check_id": "fuzz_master_parameters",
                "status": UNKNOWN,
                "detail": "the frontend did not expose constant parameters of the synthetic "
                          "master, so its projection parameters could not be re-read",
            })
        else:
            findings.append(Finding(
                "fuzz_master_parameters", PASS, "synthetic master parameters",
                "the elaborated master carries exactly the compiled stimulus projection",
                expected=synthetic_parameters["expected"],
                actual=synthetic_parameters["actual"]))

    # 13. The CPU reset hold: a held CPU is held by the rendered constant and the
    #     CPU's reset pin, and a released CPU is not connected to that structure.
    cpu_hold = _audit_cpu_reset_hold(plan, netlist, top_text)
    findings.append(Finding(
        "cpu_reset_hold",
        PASS if not cpu_hold["errors"] else FAIL,
        "CPU reset hold",
        "the CPU reset pin follows the compiled drive profile: held in reset for the "
        "whole test in bfm_isolated, plain SoC reset in every other profile",
        expected=cpu_hold["expected"],
        actual=cpu_hold["errors"] if cpu_hold["errors"] else cpu_hold["actual"]))

    # 14. The adapter binding: for every protocol pair the plan claims, the
    #     elaborated cell is the claimed module and carries exactly the stated
    #     adapter parameters.  This is the claim the scope record publishes as
    #     "supported" for each family, so it is re-read from the netlist here.
    adapter_binding = _audit_adapter_binding(plan, netlist)
    if adapter_binding["errors"]:
        findings.append(Finding(
            "adapter_binding", FAIL, "declared adapter binding",
            "every planned adapter instance elaborates to the claimed module with the "
            "planned parameters",
            expected=adapter_binding["expected"],
            actual=adapter_binding["errors"]))
    elif adapter_binding["unknown"]:
        unknown.append({
            "check_id": "adapter_binding",
            "status": UNKNOWN,
            "detail": adapter_binding["unknown"],
        })
    else:
        findings.append(Finding(
            "adapter_binding", PASS, "declared adapter binding",
            "every planned adapter instance elaborates to the claimed module with the "
            "planned parameters",
            expected=adapter_binding["expected"],
            actual=adapter_binding["actual"]))

    # 15. The reset topology: one reset domain, released simultaneously.  Every
    #     planned reset pin is driven by the SoC reset net (or its inverse, per
    #     the declared polarity); the CPU hold of a bfm drive profile is the only
    #     other legal expression.  Any other reset net is a sequence, a gate or a
    #     second domain, and the composer does not build one.
    reset_topology = _audit_reset_topology(plan, netlist)
    findings.append(Finding(
        "reset_topology",
        PASS if not reset_topology["errors"] else FAIL,
        "reset topology",
        "every planned reset pin is driven by rst_ni or ~rst_ni according to its "
        "declared polarity, with the drive profile's CPU hold as the only other "
        "legal expression; no second, gated or sequenced reset net exists",
        expected=reset_topology["expected"],
        actual=reset_topology["errors"] if reset_topology["errors"]
        else reset_topology["actual"]))

    # 16. The CPU input dispositions: every input port of the CPU is driven by
    #     the net the plan's own cpu_inputs record states (a constant literal, a
    #     soc_special_input_driver with the declared strategy, an exported top
    #     port, or the clock), so no CPU control input floats or is silently
    #     taken from another net.
    cpu_inputs = _audit_cpu_input_dispositions(plan, netlist)
    findings.append(Finding(
        "cpu_input_dispositions",
        PASS if not cpu_inputs["errors"] else FAIL,
        "CPU input dispositions",
        "every CPU input port is driven exactly as the disposition ledger records: "
        "constant literal, declared special-input driver with its compiled strategy, "
        "exported pin, or clock distribution",
        expected=cpu_inputs["expected"],
        actual=cpu_inputs["errors"] if cpu_inputs["errors"] else cpu_inputs["actual"]))

    # 17. The attached peer models: each one is instantiated with the planned
    #     parameters, every declared role is wired to the component port of that
    #     same role, the pins it owns are not also exported, its stimulus inputs
    #     are top-level inputs, and every declared counter is exported so a run
    #     can observe it.  A peer is the only other end of an external interface,
    #     so any of these wrong means the interface is not the one the plan says.
    peer_findings = _audit_peers(plan, netlist, actual_ports)
    for check_id, detail, errors, expectation, actual in peer_findings:
        findings.append(Finding(
            check_id, PASS if not errors else FAIL, detail, detail,
            expected=expectation, actual=errors if errors else actual))

    # 9. Read resolved parameter constants from each elaborated adapter module.
    # Missing/nonconstant facts are unknown; mismatches fail independently of
    # the frontend's specialization-name encoding.
    parameter_findings: list[dict[str, object]] = []
    unknown_parameter_encoding = False
    for target in plan.target_records:
        adapter = target.get("resolved_adapter")
        if not isinstance(adapter, Mapping) or "instance_id" not in target:
            continue
        window = target.get("window")
        if not isinstance(window, Mapping):
            continue
        cell = netlist.cell(f"u_{target['instance_id']}_adapter")
        if cell is None:
            continue
        module = str(cell["module"] or "")
        parameters = cell.get("parameters", {})
        expected = {"WINDOW_BASE": int(window["base"]), "WINDOW_SIZE": int(window["size"])}
        expected.update({str(item["name"]): int(item["value"])
                         for item in adapter.get("parameters", [])
                         if item["name"] == "HAS_PSTRB"})
        actual = {name: parameters.get(name) for name in expected}
        # Read resolved parameter constants from the elaborated module. Names
        # such as __pi5 are frontend identities, not encoded parameter values.
        if any(value is None for value in actual.values()):
            unknown_parameter_encoding = True
            continue
        parameter_findings.append({
            "instance": target["instance_id"],
            "module": module,
            "expected": expected,
            "actual": actual,
            "ok": actual == expected,
        })
    bad_parameters = [item for item in parameter_findings if not item["ok"]]
    if bad_parameters:
        findings.append(Finding(
            "adapter_parameters", FAIL, "adapter window parameters",
            "a rendered adapter no longer carries the planned window",
            expected="elaborated window and optional-strobe parameters match the plan",
            actual=bad_parameters))
    elif unknown_parameter_encoding or not parameter_findings:
        unknown.append({
            "check_id": "adapter_parameters",
            "status": UNKNOWN,
            "detail": "the frontend did not expose constant adapter window parameters, "
                      "so parameter consistency could not be re-read",
        })
    else:
        findings.append(Finding(
            "adapter_parameters", PASS, "adapter window parameters",
            "every rendered adapter carries the planned window base and size",
            expected="matching elaborated parameter constants",
            actual=f"{len(parameter_findings)} adapters verified"))

    # 10. Observations never drive anything: an observe/fuzz top port must not
    #    appear as the source of a component input.
    driver_findings: list[dict[str, object]] = []
    observe_nets = {top_port_name(entry) for entry in entries
                    if entry.disposition == "observe"}
    for cell in netlist.cells:
        accesses = dict(cell.get("pin_access") or {})
        for pin, expression in dict(cell["pins"]).items():  # type: ignore[arg-type]
            if _base_net(str(expression)) not in observe_nets:
                continue
            if pin in ("clk_i", "rst_ni"):
                continue
            # Only a pin the cell *samples* would make an observation net an
            # input to something; the component output that drives it is fine.
            if str(accesses.get(pin)) != "RD":
                continue
            driver_findings.append({"cell": cell["instance"], "pin": pin,
                                    "expression": expression})
    findings.append(Finding(
        "observation_outputs", PASS if not driver_findings else FAIL, "observation ports",
        "no observation net is consumed by a component input",
        expected="observation nets appear only as SoC outputs",
        actual=driver_findings))

    unknown.append({
        "check_id": "memory_parameters",
        "status": UNKNOWN,
        "detail": "the byte-image memory model's BASE_ADDR/BYTES do not appear in the "
                  "elaborated specialization name, so this frontend cannot re-read them; "
                  "the address map is checked at plan level and through the router windows",
    })
    failures = [item for item in findings if item.status == FAIL]
    unknown.append({
        "check_id": "protocol_behaviour",
        "status": UNKNOWN,
        "detail": "the audit proves structure only; adapter, arbiter and controller "
                  "behaviour over time is verified by the protocol-level simulations",
    })
    return {
        "schema_version": AUDIT_SCHEMA,
        "plan_hash": plan.plan_hash,
        "top_module": netlist.top_module,
        "elaboration_warnings": netlist.warnings,
        "findings": [item.document() for item in findings],
        "unknown": unknown,
        "summary": {
            "passed": len(findings) - len(failures),
            "failed": len(failures),
            "unknown": len(unknown),
            "status": FAIL if failures else PASS,
        },
        "netlist": {
            "cells": [{"instance": item["instance"], "module": item["module"]}
                      for item in netlist.cells],
            "ports": [dict(port) for port in netlist.ports],
        },
    }


def _source_cells(plan: CompositionPlan,
                  fabric: Mapping[str, object]) -> tuple[dict[int, dict[str, str]], dict[int, dict]]:
    """lane -> expected driving cell, and the source record the lane belongs to."""
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    expected: dict[int, dict[str, str]] = {}
    sources: dict[int, dict] = {}
    for source in fabric["sources"]:
        lane = int(source["index"])
        source_id = str(source["source_id"])
        kind = str(source["kind"])
        sources[lane] = {"lane": lane, "source_id": source_id, "kind": kind}
        if kind == "fuzz_mmio":
            record = plan.synthetic
            if not record or str(record.get("source_id")) != source_id:
                continue
            expected[lane] = {
                "cell": f"u_{record['instance_id']}",
                "module": str(record["module"]),
                "role": "synthetic_master",
            }
            continue
        binding = next((item for item in plan.plan["processor_execution"]["bindings"]
                        if str(item["source_id"]) == source_id), None)
        if binding is None:
            continue
        expected[lane] = {
            "cell": f"u_{cpu_instance.instance_id}_adapter_{lane}",
            "module": str(binding["rtl_module"]),
            "role": "cpu_adapter",
        }
    return expected, sources


#: The lane's request-side nets and how the source must touch each of them:
#: ``WR`` means the source drives it, ``RD`` means the source samples it.
REQUEST_LANE_NETS = (
    ("req_valid", "bit", "WR"),
    ("write", "bit", "WR"),
    ("addr", "address", "WR"),
    ("wdata", "data", "WR"),
    ("be", "byte_enable", "WR"),
    ("req_ready", "bit", "RD"),
)
RESPONSE_LANE_NETS = (
    ("rsp_valid", "bit", "RD"),
    ("rsp_ready", "bit", "WR"),
    ("rdata", "data", "RD"),
    ("error", "bit", "RD"),
)


def _lane_net_width(kind: str, address_width: int, data_width: int) -> int:
    if kind == "address":
        return address_width
    if kind == "data":
        return data_width
    if kind == "byte_enable":
        return data_width // 8
    return 1


def _audit_lane_nets(plan: CompositionPlan, netlist: Netlist, fabric: Mapping[str, object],
                     roles: Sequence[tuple[str, str, str]]) -> dict[str, object]:
    """Check one half of the lane contract for every declared source."""
    parameters = fabric["rtl"]["parameters"]
    address_width = int(parameters["ADDRESS_WIDTH"])
    data_width = int(parameters["DATA_WIDTH"])
    expected_cells, sources = _source_cells(plan, fabric)
    lanes = len(fabric["sources"])
    index = _pin_cells(netlist)
    errors: list[dict[str, object]] = []
    checked = 0
    for lane in sorted(sources):
        record = expected_cells.get(lane)
        if record is None:
            errors.append({"lane": lane, "source_id": sources[lane]["source_id"],
                           "check": "expected-cell", "expected": "a bound source module",
                           "actual": "no module is bound to this lane"})
            continue
        for name, kind, access in roles:
            width = _lane_net_width(kind, address_width, data_width)
            net = f"src_{name}"
            touching: list[str] = []
            for expression in _lane_expressions(net, lane, width, lanes):
                for cell, pin, pin_access in index.get(expression, []):
                    if pin_access == access and cell not in touching:
                        touching.append(cell)
            checked += 1
            if sorted(touching) != [record["cell"]]:
                errors.append({
                    "lane": lane, "source_id": sources[lane]["source_id"], "net": net,
                    "access": access, "expected_cell": record["cell"],
                    "actual_cells": sorted(touching),
                    "expected_net": _lane_expressions(net, lane, width, lanes)[0],
                })
    return {
        "errors": errors,
        "checked": checked,
        "expected": [
            {"lane": lane, "source_id": sources[lane]["source_id"],
             "cell": expected_cells.get(lane, {}).get("cell"),
             "nets": [f"src_{name}" for name, _kind, _access in roles]}
            for lane in sorted(sources)
        ],
        "actual": f"{checked} lane nets owned by their declared module",
    }


def _audit_source_lanes(plan: CompositionPlan, netlist: Netlist,
                        fabric: Mapping[str, object]) -> dict[str, object]:
    """Every declared fabric source drives its own lane's request nets."""
    return _audit_lane_nets(plan, netlist, fabric, REQUEST_LANE_NETS)


def _audit_response_ownership(plan: CompositionPlan, netlist: Netlist,
                              fabric: Mapping[str, object]) -> dict[str, object]:
    """Every source consumes exactly the response nets its own lane returns."""
    return _audit_lane_nets(plan, netlist, fabric, RESPONSE_LANE_NETS)


def _audit_synthetic_reset(plan: CompositionPlan, netlist: Netlist) -> dict[str, object] | None:
    """The synthetic master's reset follows its declared contract."""
    if not plan.synthetic:
        return None
    contract = plan.synthetic["reset_contract"]
    assert isinstance(contract, Mapping)
    cell = f"u_{plan.synthetic['instance_id']}"
    pin = netlist.pin(cell, str(contract["port"]))
    expected = "~rst_ni" if str(contract["polarity"]) == "active_high" else "rst_ni"
    errors: list[dict[str, object]] = []
    if pin is None:
        errors.append({"cell": cell, "check": "reset-pin", "expected": str(contract["port"]),
                       "actual": "the elaborated cell has no such pin"})
    elif pin.strip().replace(" ", "") != expected:
        errors.append({"cell": cell, "pin": str(contract["port"]), "expected": expected,
                       "actual": pin})
    return {"errors": errors,
            "expected": {"cell": cell, "pin": str(contract["port"]),
                         "polarity": str(contract["polarity"]), "expression": expected},
            "actual": {"pin": pin}}


def _audit_synthetic_parameters(plan: CompositionPlan,
                                netlist: Netlist) -> dict[str, object] | None:
    """The elaborated synthetic master carries the compiled projection parameters."""
    if not plan.synthetic:
        return None
    cell = netlist.cell(f"u_{plan.synthetic['instance_id']}")
    parameters = plan.synthetic["parameters"]
    assert isinstance(parameters, Mapping)
    address_width = int(parameters["ADDRESS_WIDTH"])
    slots = int(parameters["NUM_WINDOWS"])
    expected: dict[str, object] = {}
    for name, value in sorted(parameters.items()):
        if isinstance(value, list):
            expected[str(name)] = sum(int(item) << (index * address_width)
                                      for index, item in enumerate(value))
        else:
            expected[str(name)] = int(value)  # type: ignore[arg-type]
    if cell is None:
        return {"errors": [{"cell": f"u_{plan.synthetic['instance_id']}",
                            "check": "cell", "expected": "the synthetic master instance",
                            "actual": "missing"}],
                "expected": expected, "actual": None, "unknown": False}
    actual_raw = cell.get("parameters", {})
    assert isinstance(actual_raw, Mapping)
    actual = {name: actual_raw.get(name) for name in expected}
    if any(value is None for value in actual.values()):
        return {"errors": [], "expected": expected, "actual": actual, "unknown": True}
    errors = [{"parameter": name, "expected": expected[name], "actual": actual[name]}
              for name in sorted(expected) if actual[name] != expected[name]]
    return {"errors": errors, "expected": expected, "actual": actual, "unknown": False}


def _audit_adapter_binding(plan: CompositionPlan, netlist: Netlist) -> dict[str, object]:
    """The claimed adapter for every supported protocol pair, re-read.

    Each target adapter and each CPU adapter lane is checked for its claimed
    module and for every plan parameter the elaborated cell exposes.  A
    parameter the frontend does not expose is not silently accepted: it is
    reported as unknown instead.
    """
    expected: dict[str, object] = {}
    errors: list[dict[str, object]] = []
    verified = 0
    unexposed: list[str] = []

    def check(cell_name: str, subject: str, module: str,
              parameters: Mapping[str, object]) -> None:
        nonlocal verified
        cell = netlist.cell(cell_name)
        if cell is None:
            errors.append({"instance": cell_name, "check": "missing-cell",
                           "expected": module, "actual": None})
            return
        actual_module = str(cell["module"] or "")
        expected[subject] = {"module": module, "parameters": dict(parameters)}
        if not actual_module.startswith(module):
            errors.append({"instance": cell_name, "check": "module",
                           "expected": module, "actual": actual_module})
            return
        exposed = dict(cell.get("parameters") or {})
        checked = {name: value for name, value in sorted(parameters.items())
                   if name in exposed}
        for name, value in checked.items():
            if int(exposed[name]) != int(value):
                errors.append({"instance": cell_name, "check": "parameter",
                               "parameter": name, "expected": int(value),
                               "actual": int(exposed[name])})
        if not checked:
            unexposed.append(subject)
        else:
            verified += 1

    for target in plan.target_records:
        adapter = target.get("resolved_adapter")
        if not isinstance(adapter, Mapping) or "instance_id" not in target:
            continue
        parameters = {str(item["name"]): int(item["value"])
                      for item in adapter.get("parameters", [])}
        check(f"u_{target['instance_id']}_adapter",
              f"target:{target['instance_id']}:"
              f"{adapter['target_protocol']['protocol']}@{adapter['target_protocol']['version']}",
              str(adapter["rtl_module"]), parameters)

    fabric = plan.plan["fabric"]
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    for binding in plan.plan["processor_execution"]["bindings"]:
        source_id = str(binding["source_id"])
        lane = next(index for index, source in enumerate(fabric["sources"])
                    if str(source["source_id"]) == source_id)
        route = next(item for item in plan.plan["processor_execution"]["routes"]
                     if str(item["route_id"]) == str(binding["route_id"]))
        parameters = {str(name): int(value)
                      for name, value in dict(route.get("parameters") or {}).items()}
        check(f"u_{cpu_instance.instance_id}_adapter_{lane}",
              f"master:{source_id}:{route['source_protocol'][0]}@"
              f"{route['source_protocol'][1]}",
              str(binding["rtl_module"]), parameters)

    unknown = ""
    if unexposed and not verified:
        unknown = ("the frontend did not expose any adapter parameter for "
                   + ", ".join(sorted(unexposed)))
    if not plan.target_records and not plan.plan["processor_execution"]["bindings"]:
        unknown = "the plan declares no adapter at all, so nothing could be re-read"
    return {
        "errors": errors,
        "expected": expected,
        "actual": f"{verified} adapter instances re-read from the elaborated netlist",
        "unknown": unknown,
    }


def _audit_reset_topology(plan: CompositionPlan, netlist: Netlist) -> dict[str, object]:
    """One reset domain, released simultaneously, for every planned cell.

    The expectation is derived from each instance's own declared reset binding:
    the reset net is ``rst_ni`` for an active-low binding and ``~rst_ni`` for an
    active-high one.  A cell whose reset pin is driven by anything else -- a
    second net, a gate, a delayed copy or a constant -- is a reset order the
    composer never built, so it fails.
    """
    from .soc_profile_renderer import CPU_HELD_CONSTANT, CPU_RESET_NET

    expected: dict[str, object] = {}
    errors: list[dict[str, object]] = []
    allowed = {"rst_ni", "~rst_ni"}
    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    if plan.cpu_held_in_reset:
        allowed.add(CPU_RESET_NET)

    for instance in plan.instances:
        for binding_record, field in instance.binding.resets:
            polarity = str(binding_record.polarity)
            plain = "rst_ni" if polarity == "active_low" else "~rst_ni"
            if instance.instance_id == cpu_instance.instance_id and plan.cpu_held_in_reset:
                # The hold is the CPU's own declared reset for the whole test and
                # the cpu_reset_hold check owns its exact shape.
                continue
            expected[f"u_{instance.instance_id}.{field.port}"] = plain
    from .soc_profile_renderer import FABRIC_RESET_CONTRACT, MEMORY_RESET_CONTRACT

    fabric_contracts = {
        "u_soc_arbiter": FABRIC_RESET_CONTRACT,
        "u_soc_router": FABRIC_RESET_CONTRACT,
    }
    for index, target in enumerate(plan.plan["fabric"]["targets"]):
        if target.get("backing_kind") == "memory":
            fabric_contracts[f"u_mem_{index}"] = MEMORY_RESET_CONTRACT
    for target in plan.target_records:
        adapter = target.get("resolved_adapter")
        if isinstance(adapter, Mapping) and "instance_id" in target:
            fabric_contracts[f"u_{target['instance_id']}_adapter"] = {
                "port": str(adapter["reset"]["port"]),
                "polarity": str(adapter["reset"]["polarity"]),
            }
    for cell_name, contract in fabric_contracts.items():
        polarity = str(contract["polarity"])
        expected[f"{cell_name}.{contract['port']}"] = \
            "rst_ni" if polarity == "active_low" else "~rst_ni"

    used: dict[str, str] = {}
    for subject, expectation in sorted(expected.items()):
        cell_name, _, port = subject.partition(".")
        actual = (netlist.pin(cell_name, port) or "").strip()
        used[subject] = actual
        if actual.replace(" ", "") != str(expectation):
            errors.append({"cell": cell_name, "port": port, "expected": expectation,
                           "actual": actual})
    # The single-domain claim is also a statement about what must not exist: no
    # planned reset pin may be driven by a net outside the allowed set.
    for subject, actual in sorted(used.items()):
        compact = actual.replace(" ", "")
        if compact and compact not in allowed:
            errors.append({"cell": subject, "port": "reset-topology",
                           "expected": "one of " + " / ".join(sorted(allowed)),
                           "actual": actual})
    if plan.cpu_held_in_reset:
        cpu_reset_port = cpu_instance.binding.resets[0][0].port
        actual = (netlist.pin(f"u_{cpu_instance.instance_id}", cpu_reset_port) or "").strip()
        used[f"u_{cpu_instance.instance_id}.{cpu_reset_port}"] = actual
    return {
        "errors": errors,
        "expected": {"reset_domain": plan.request.reset_domain,
                     "polarity": plan.request.reset_polarity,
                     "nets": sorted(allowed),
                     "pins": expected},
        "actual": used,
    }


def _audit_cpu_input_dispositions(plan: CompositionPlan, netlist: Netlist
                                  ) -> dict[str, object]:
    """Every CPU input pin driven exactly as the plan's cpu_inputs record says."""
    expected: dict[str, object] = {}
    errors: list[dict[str, object]] = []
    verified = 0
    for record in plan.cpu_inputs:
        audit = record.get("audit")
        if audit != "cpu_input_dispositions":
            continue
        instance_id = str(record["instance_id"])
        port = str(record["port"])
        net = str(record["expected_net"])
        subject = f"u_{instance_id}.{port}"
        expected[subject] = {"disposition": record["disposition"], "net": net,
                             "driver": record["driver"]}
        # A multi-role port carries several drivers at once, so the record's own
        # bit span selects the segment expression; a whole-port record keeps
        # reading the pin itself.
        bits = record.get("bits")
        low = int(bits.get("lo", 0)) if isinstance(bits, Mapping) else 0
        high = int(bits.get("hi", 0)) if isinstance(bits, Mapping) else 0
        leaf = _segment_leaf(netlist, plan.instance(instance_id), port, low, high)
        actual = (leaf if leaf is not None
                  else netlist.pin(f"u_{instance_id}", port) or "").strip()
        if record["disposition"] == "fuzz":
            cell_name = str(record["driver_cell"])
            cell = netlist.cell(cell_name)
            if cell is None:
                errors.append({"cell": subject, "check": "driver-missing",
                               "expected": cell_name, "actual": None})
                continue
            value_net = (netlist.pin(cell_name, "value_o") or "").strip()
            if value_net != net or actual != net:
                errors.append({"cell": subject, "check": "driver-wiring",
                               "expected": net, "actual": {"value_o": value_net,
                                                           "cpu_pin": actual}})
                continue
            parameters = dict(cell.get("parameters") or {})
            width = int(record["width"])
            if "WIDTH" in parameters and int(parameters["WIDTH"]) != width:
                errors.append({"cell": subject, "check": "driver-width",
                               "expected": width, "actual": int(parameters["WIDTH"])})
                continue
            if str(record.get("strategy")) is not None and "STRATEGY" in parameters:
                from .soc_profile_renderer import STRATEGY_CODES

                code = STRATEGY_CODES.get(str(record["strategy"]))
                if code is None or int(parameters["STRATEGY"]) != code:
                    errors.append({"cell": subject, "check": "driver-strategy",
                                   "expected": code, "actual": parameters["STRATEGY"]})
                    continue
            verified += 1
            continue
        if record["disposition"] == "constant":
            # The rendered literal is checked by value, not by spelling: the
            # frontend normalises a constant to its own literal form.
            value = int(record.get("value") or 0)
            if _pin_constant(actual) != value:
                errors.append({"cell": subject, "check": "constant-value",
                               "expected": value, "actual": actual})
                continue
            verified += 1
            continue
        if actual.replace(" ", "") != net.replace(" ", ""):
            errors.append({"cell": subject, "check": "cpu-input-net",
                           "expected": net, "actual": actual})
            continue
        verified += 1
    return {
        "errors": errors,
        "expected": expected,
        "actual": f"{verified} CPU input pins re-read from the elaborated netlist",
    }


def _pin_constant(text: str) -> int | None:
    """The value of a constant pin expression such as ``1'h0`` or ``1'b1``."""
    compact = text.replace(" ", "")
    if compact.isdigit():
        return int(compact)
    match = re.fullmatch(r"(\d+)'[sS]?([hdbHDB])([0-9a-fA-F_]+)", compact)
    if match is None:
        return None
    radix = {"h": 16, "d": 10, "b": 2}[match.group(2).lower()]
    try:
        return int(match.group(3).replace("_", ""), radix)
    except ValueError:
        return None


def _audit_cpu_reset_hold(plan: CompositionPlan, netlist: Netlist,
                          top_text: str) -> dict[str, object]:
    """The CPU reset pin follows the compiled drive profile's hold declaration.

    A held CPU is accepted either as the rendered hold net or as the constant the
    frontend folds that net into (an asserted level); the RTL text is checked as
    well, because the hold must be a rendered structure and not a metadata claim.
    """
    from .soc_profile_renderer import CPU_HELD_CONSTANT, CPU_RESET_NET

    cpu_instance = next(item for item in plan.instances if item.kind == "cpu")
    reset_port = cpu_instance.binding.resets[0][0].port
    polarity = cpu_instance.binding.resets[0][0].polarity
    plain = "rst_ni" if polarity == "active_low" else "~rst_ni"
    held_driver = f"rst_ni & ~{CPU_HELD_CONSTANT}" if polarity == "active_low" \
        else f"~rst_ni | {CPU_HELD_CONSTANT}"
    asserted_level = 0 if polarity == "active_low" else 1
    pin = (netlist.pin(f"u_{cpu_instance.instance_id}", reset_port) or "").strip()
    errors: list[dict[str, object]] = []
    if plan.cpu_held_in_reset:
        constant = _pin_constant(pin)
        if pin.replace(" ", "") != CPU_RESET_NET and constant != asserted_level:
            errors.append({"check": "cpu-reset-pin",
                           "expected": f"{CPU_RESET_NET} or the asserted level "
                                       f"{asserted_level}",
                           "actual": pin})
        if not re.search(rf"localparam\s+bit\s+{CPU_HELD_CONSTANT}\s*=\s*1\s*;", top_text):
            errors.append({"check": "held-constant", "expected":
                           f"localparam bit {CPU_HELD_CONSTANT} = 1;",
                           "actual": "the generated top does not assert the held constant"})
        if not re.search(rf"wire\s+{CPU_RESET_NET}\s*=\s*{re.escape(held_driver)}\s*;", top_text):
            errors.append({"check": "held-expression", "expected":
                           f"wire {CPU_RESET_NET} = {held_driver};",
                           "actual": "the held reset wire is missing or has another driver"})
    else:
        if pin.replace(" ", "") != plain:
            errors.append({"check": "cpu-reset-pin", "expected": plain, "actual": pin})
        if CPU_HELD_CONSTANT in top_text or CPU_RESET_NET in top_text:
            errors.append({"check": "unexpected-hold",
                           "expected": "no held reset structure",
                           "actual": f"the generated top contains {CPU_HELD_CONSTANT}/"
                                     f"{CPU_RESET_NET} while the plan releases the CPU"})
    return {
        "errors": errors,
        "expected": {"held_in_reset": plan.cpu_held_in_reset, "pin": reset_port,
                     "expression": CPU_RESET_NET if plan.cpu_held_in_reset else plain},
        "actual": {"pin": pin, "held_structure": CPU_HELD_CONSTANT in top_text},
    }


def _audit_peers(plan: CompositionPlan, netlist: Netlist,
                 actual_ports: Mapping[str, tuple[str, int]],
                 ) -> list[tuple[str, str, list[dict[str, object]], object, object]]:
    """Re-read every attached peer from the elaborated netlist.

    Five independent questions are asked of the same structure:

    ``peer_instances``    is the planned peer instance present, with the module the
                          plan resolved?
    ``peer_parameters``   does the elaborated instance carry exactly the parameters
                          the plan resolved (a peer that samples at another divisor
                          or in another SPI mode is a different model)?
    ``peer_role_wiring``  does every declared role connect the peer's own port to
                          the component port of that same role (and not to another
                          role's port)?
    ``peer_boundary``     are the pins the peer owns *not* exported as top ports,
                          and are the peer's stimulus inputs top-level inputs?
    ``peer_counters``     is every declared counter and observation present on the
                          peer instance and exported as a top-level output, so a
                          run can read it?
    """
    instance_findings: list[dict[str, object]] = []
    parameter_findings: list[dict[str, object]] = []
    wiring_findings: list[dict[str, object]] = []
    boundary_findings: list[dict[str, object]] = []
    counter_findings: list[dict[str, object]] = []
    expectations: dict[str, object] = {"peers": []}
    for peer in plan.peers:
        record = netlist.cell(peer.instance)
        expectations["peers"].append({  # type: ignore[union-attr]
            "instance_id": peer.instance_id,
            "cell": peer.instance,
            "module": peer.module,
            "parameters": {item.name: item.value for item in peer.parameters},
            "roles": [item.document() for item in peer.bindings],
            "counters": [item.top_port for item in peer.counters],
        })
        if record is None:
            instance_findings.append({
                "instance_id": peer.instance_id, "cell": peer.instance,
                "check": "cell", "expected": peer.module, "actual": "missing"})
            # The peer is not there; if its pins are exported as well, the plan
            # says the interface is driven inside the top while the generated top
            # leaves it to the environment, which is the double-driving case.
            exported = sorted(f"{peer.instance_id}__{item.component_port}"
                              for item in peer.bindings
                              if f"{peer.instance_id}__{item.component_port}" in actual_ports)
            boundary_findings.append({
                "instance_id": peer.instance_id, "check": "peer-cell-missing",
                "expected": "the attached peer instance owns the interface pins",
                "actual": (f"the peer cell is absent while {exported} are still top-level "
                           f"ports" if exported else "the peer cell is absent")})
            continue
        if not str(record["module"]).startswith(peer.module):
            instance_findings.append({
                "instance_id": peer.instance_id, "cell": peer.instance,
                "check": "module", "expected": peer.module,
                "actual": str(record["module"])})
        parameters = dict(record.get("parameters") or {})
        for item in peer.parameters:
            actual = parameters.get(item.name)
            if actual is None:
                # The frontend did not expose the constant.  That is reported as
                # a failure of this peer's parameter check rather than assumed:
                # the plan resolved the value and the RTL must carry it.
                parameter_findings.append({
                    "instance_id": peer.instance_id, "parameter": item.name,
                    "check": "parameter-unreadable", "expected": item.value,
                    "actual": None})
            elif int(actual) != item.value:
                parameter_findings.append({
                    "instance_id": peer.instance_id, "parameter": item.name,
                    "check": "parameter", "expected": item.value, "actual": int(actual)})
        # Role wiring: the pin of the peer's own port and the pin of the
        # component port of the same role must name one shared net.
        for item in peer.bindings:
            peer_expression = (netlist.pin(peer.instance, item.peer_port) or "").strip()
            component_expression = (netlist.pin(f"u_{peer.instance_id}", item.component_port)
                                    or "").strip()
            expected_net = f"{peer.instance_id}__{item.component_port}"
            access = (record.get("pin_access") or {}).get(item.peer_port)
            if peer_expression != expected_net:
                wiring_findings.append({
                    "instance_id": peer.instance_id, "role": item.role,
                    "peer_port": item.peer_port, "check": "net",
                    "expected": expected_net, "actual": peer_expression})
                continue
            if component_expression != expected_net:
                wiring_findings.append({
                    "instance_id": peer.instance_id, "role": item.role,
                    "component_port": item.component_port, "check": "component-net",
                    "expected": expected_net, "actual": component_expression})
                continue
            # Direction of ownership: a role the component samples must be driven
            # by the peer, and a role the component drives must be sampled by it.
            expected_access = "WR" if item.component_direction == "input" else "RD"
            if str(access) != expected_access:
                wiring_findings.append({
                    "instance_id": peer.instance_id, "role": item.role,
                    "peer_port": item.peer_port, "check": "direction",
                    "expected": expected_access, "actual": str(access)})
        # Boundary: a peer-bound pin must not also be a top-level port.
        for item in peer.bindings:
            name = f"{peer.instance_id}__{item.component_port}"
            if name in actual_ports:
                boundary_findings.append({
                    "instance_id": peer.instance_id, "port": name,
                    "check": "exported-peer-pin",
                    "expected": "the peer drives this pin inside the top",
                    "actual": f"the pin is also a top-level {actual_ports[name][0]} port"})
        for slot in peer.slots:
            for signal in slot.signals:
                if str(signal.top_port) not in actual_ports:
                    boundary_findings.append({
                        "instance_id": peer.instance_id, "port": signal.top_port,
                        "check": "missing-stimulus-port",
                        "expected": "input", "actual": "missing"})
                    continue
                if actual_ports[str(signal.top_port)][0] != "input":
                    boundary_findings.append({
                        "instance_id": peer.instance_id, "port": signal.top_port,
                        "check": "stimulus-direction", "expected": "input",
                        "actual": actual_ports[str(signal.top_port)][0]})
                # The port must reach the peer's own pin: a tied-off stimulus
                # input means the event plan drives nothing.
                expression = (netlist.pin(peer.instance, signal.peer_port) or "").strip()
                access = str((record.get("pin_access") or {}).get(signal.peer_port, ""))
                if expression != str(signal.top_port):
                    boundary_findings.append({
                        "instance_id": peer.instance_id, "port": signal.top_port,
                        "peer_port": signal.peer_port, "check": "stimulus-net",
                        "expected": str(signal.top_port), "actual": expression})
                elif access != "RD":
                    boundary_findings.append({
                        "instance_id": peer.instance_id, "port": signal.top_port,
                        "peer_port": signal.peer_port, "check": "stimulus-driver",
                        "expected": "the peer samples this net",
                        "actual": f"access={access or 'none'}"})
        # Counters and observations: connected to their own net on the peer and
        # exported, so the run's evidence contains what the peer really did.
        for item in peer.observations:
            expression = (netlist.pin(peer.instance, item.peer_port) or "").strip()
            access = str((record.get("pin_access") or {}).get(item.peer_port, ""))
            if expression != item.top_port:
                counter_findings.append({
                    "instance_id": peer.instance_id, "observation": item.peer_port,
                    "check": "net", "expected": item.top_port, "actual": expression})
            elif access != "WR":
                counter_findings.append({
                    "instance_id": peer.instance_id, "observation": item.peer_port,
                    "check": "driver", "expected": "the peer drives this net",
                    "actual": f"access={access or 'none'}"})
            elif str(item.top_port) not in actual_ports:
                counter_findings.append({
                    "instance_id": peer.instance_id, "observation": item.peer_port,
                    "check": "observed", "expected": f"top-level output {item.top_port}",
                    "actual": "not exported, so no run can report it"})
            elif actual_ports[str(item.top_port)][0] != "output":
                counter_findings.append({
                    "instance_id": peer.instance_id, "observation": item.peer_port,
                    "check": "observed-direction", "expected": "output",
                    "actual": actual_ports[str(item.top_port)][0]})
    return [
        ("peer_instances", "attached peer instances",
         instance_findings,
         "every attached peer is instantiated with the module the plan resolved",
         f"{len(plan.peers)} peer instance(s) verified"),
        ("peer_parameters", "peer instance parameters",
         parameter_findings,
         "every elaborated peer instance carries exactly the parameters the plan "
         "resolved, so the peer's timing is the plan's timing",
         f"{sum(len(peer.parameters) for peer in plan.peers)} parameter(s) verified"),
        ("peer_role_wiring", "peer role connections",
         wiring_findings,
         "every declared role connects the peer's port and the component's port of that "
         "role to one net, in the direction the component declares",
         f"{sum(len(peer.bindings) for peer in plan.peers)} role(s) verified"),
        ("peer_boundary", "peer pin ownership",
         boundary_findings,
         "a pin a peer owns is not exported as a top-level pin, and every peer stimulus "
         "input is a top-level input", f"{len(plan.peers)} peer boundary(ies) verified"),
        ("peer_counters", "peer observation ports",
         counter_findings,
         "every declared peer counter and observation is driven by the peer itself and "
         "exported as a top-level output",
         f"{sum(len(peer.observations) for peer in plan.peers)} observation(s) verified"),
    ]


def _audit_interrupts(plan: CompositionPlan, netlist: Netlist) -> dict[str, object]:
    controller = plan.interrupt_document["controller"]
    errors: list[dict[str, object]] = []
    if not controller["present"]:
        # No source is declared, so the plan says the CPU entry is disabled by
        # contract.  The entry must then be the declared inactive literal: a
        # floating entry or one driven by a net no module declares would make
        # every interrupt claim about this composition meaningless.
        cpu_entry = plan.interrupt_document.get("cpu_entry")
        if not isinstance(cpu_entry, Mapping):
            return {"errors": [], "expected": "no controller", "actual": "no controller"}
        expected = cpu_entry_expression(plan.interrupt_document)
        actual = netlist.pin(f"u_{cpu_entry['instance_id']}", str(cpu_entry["port"])) or ""
        for leaf in _expr_leaves_text(actual):
            if _pin_constant(leaf) != _pin_constant(str(expected)):
                errors.append({"check": "cpu_entry_disabled", "expected": expected,
                               "actual": actual})
                break
        return {"errors": errors,
                "expected": {"cpu_entry": expected, "port": cpu_entry["port"]},
                "actual": {"cpu_entry": actual}}
    order = sorted(plan.interrupt_document["sources"], key=lambda item: int(item["source_id"]))
    expected_vector = []
    for item in order:
        net = f"{item['instance_id']}__{item['port']}"
        normalizer = item.get("normalizer") or {}
        if str(normalizer.get("kind", "direct")) == "edge_detect":
            # A held edge-shaped source reaches the controller through the
            # converter's output net, not through the raw component pin.
            expected_vector.append(f"irq_src_{int(item['source_id'])}")
        else:
            expected_vector.append(f"~{net}" if item["polarity_inversion"] else net)
    actual_expression = netlist.pin("u_irq_controller", "source_i") or ""
    actual_bits = [part.strip().lstrip("{} ") for part in actual_expression.strip("{} ").split(",")]
    if actual_bits != list(reversed(expected_vector)):
        errors.append({"check": "source_vector", "expected": list(reversed(expected_vector)),
                       "actual": actual_bits})
    size = netlist.pin("u_irq_controller", "source_i")
    cpu_entry = plan.interrupt_document.get("cpu_entry")
    if cpu_entry is not None:
        entry_net = plan.interrupt_document["paths"]["controller_to_cpu"]
        expression = netlist.pin(f"u_{cpu_entry['instance_id']}", str(cpu_entry["port"])) or ""
        expected = "~irq_notify" if cpu_entry["inversion"] else "irq_notify"
        if _base_net(expression) != expected.lstrip("~"):
            errors.append({"check": "cpu_entry", "expected": expected, "actual": expression})
        if entry_net and not entry_net[0]["inversion"] == bool(cpu_entry["inversion"]):
            errors.append({"check": "cpu_entry_plan", "expected": cpu_entry["inversion"],
                           "actual": entry_net[0]["inversion"]})
    source_count = int(controller["num_sources"])
    return {
        "errors": errors,
        "expected": {"num_sources": source_count,
                     "vector_lsb_first": expected_vector,
                     "cpu_entry": (cpu_entry or {}).get("port")},
        "actual": {"vector_expression": size, "bits_msb_first": actual_bits},
    }


def _audit_interrupt_normalizers(plan: CompositionPlan, netlist: Netlist
                                 ) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Re-read every rendered ``soc_irq_edge_detect`` against the plan's claim.

    This is the check that makes the item-5 converter support a *checked* claim
    rather than a comment: for each edge-detected source the audit requires the
    converter instance to exist, to carry exactly the ``EDGE`` and
    ``PULSE_CYCLES`` the plan recorded, to have its raw input connected to the
    (optionally polarity-inverted) declared source pin, and to have its output
    be the very net that appears in the controller's ``source_i`` slot for that
    source id.
    """
    errors: list[dict[str, object]] = []
    expected: list[dict[str, object]] = []
    if not plan.interrupt_plan.present:
        return errors, {"expected": "no controller", "actual": "no controller"}
    controller_vector = (netlist.pin("u_irq_controller", "source_i") or "").strip("{} ")
    vector_bits = [part.strip() for part in controller_vector.split(",")]
    order = sorted(plan.interrupt_document["sources"], key=lambda item: int(item["source_id"]))
    # ``source_i`` is rendered most-significant id first, so bit k of the
    # controller belongs to source id k+1 and lives at the reversed position.
    for item in order:
        normalizer = item.get("normalizer") or {}
        if str(normalizer.get("kind", "direct")) != "edge_detect":
            continue
        module = str(normalizer["module"])
        net = f"irq_src_{int(item['source_id'])}"
        record = {"source_id": int(item["source_id"]), "instance": f"u_{net}",
                  "module": module, "edge": normalizer["edge"],
                  "edge_parameter": int(normalizer["edge_parameter"]),
                  "pulse_cycles": int(normalizer["pulse_cycles"]),
                  "reset_level": int(normalizer["reset_level"])}
        expected.append(record)
        cell = netlist.cell(f"u_{net}")
        if cell is None:
            errors.append({"check": "normalizer_instance", "source_id": record["source_id"],
                           "expected": f"u_{net} ({module})", "actual": "absent"})
            continue
        cell_type = str(cell.get("module") or "")
        if module not in cell_type:
            errors.append({"check": "normalizer_module", "source_id": record["source_id"],
                           "expected": module, "actual": cell_type})
        parameters = cell.get("parameters") or {}
        for key, want in (("EDGE", record["edge_parameter"]),
                          ("PULSE_CYCLES", record["pulse_cycles"]),
                          ("RESET_LEVEL", record["reset_level"])):
            got = parameters.get(key) if isinstance(parameters, Mapping) else None
            if got is None:
                errors.append({"check": "normalizer_parameter",
                               "source_id": record["source_id"], "parameter": key,
                               "expected": want, "actual": "not-rendered"})
            elif int(got) != int(want):
                errors.append({"check": "normalizer_parameter",
                               "source_id": record["source_id"], "parameter": key,
                               "expected": want, "actual": int(got)})
        # The detector's own input must be the declared source pin, with the
        # declared polarity applied before the detector.
        raw = (netlist.pin(f"u_{net}", "raw_i") or "").strip()
        pin = f"{item['instance_id']}__{item['port']}"
        if int(item["bit"]) != 0:
            pin = f"{pin}[{int(item['bit'])}]"
        want_raw = f"~{pin}" if item["polarity_inversion"] else pin
        if _base_net(raw) != _base_net(want_raw):
            errors.append({"check": "normalizer_input", "source_id": record["source_id"],
                           "expected": want_raw, "actual": raw})
        # ... and the detector's output must be the controller's source slot.
        position = len(order) - 1 - (record["source_id"] - 1)
        actual_bit = vector_bits[position] if 0 <= position < len(vector_bits) else None
        if actual_bit != net:
            errors.append({"check": "normalizer_output", "source_id": record["source_id"],
                           "expected": net, "actual": actual_bit})
        driven = (netlist.pin(f"u_{net}", "irq_o") or "").strip()
        if _base_net(driven) != net:
            errors.append({"check": "normalizer_drive", "source_id": record["source_id"],
                           "expected": net, "actual": driven})
    return errors, {"expected": expected, "actual": {"instances": [row["instance"]
                                                                 for row in expected]}}


def _audit_controller_mmio(plan: CompositionPlan, netlist: Netlist,
                           fabric: Mapping[str, object]) -> dict[str, object]:
    if not plan.interrupt_plan.present:
        return {"ok": True, "expected": "no controller", "actual": "no controller"}
    target_id = f"{plan.interrupt_plan.controller_instance_id}_win"
    index = next(int(row["target_index"]) for row in fabric["decode"]["windows"]
                 if str(row["target_id"]) == target_id)
    pin = netlist.pin("u_irq_controller", "req_valid_i") or ""
    ok = _base_net(pin) == "t_req_valid" and pin.strip().endswith(f"[{index}]")
    # The controller decodes a window-local offset, so its address pin must be
    # the proven low-bit slice of the router's global address; feeding it the
    # full address would make every register unreachable while still decoding
    # to "some" index.
    width = int(plan.interrupt_document["controller"]["window"]["address_width"])
    address_pin = (netlist.pin("u_irq_controller", "req_addr_i") or "").strip()
    # The frontend may flatten a multi-dimensional slice, so the check is on the
    # property that matters: the pin is a slice of the router's address bus of
    # exactly the documented local width, not the whole global address.
    match = re.fullmatch(r"t_addr\[(\d+):(\d+)\]", address_pin)
    address_ok = bool(match) and (int(match.group(1)) - int(match.group(2)) + 1 == width)
    # LATCH_MASK is a plan claim about which sources are set-dominant, so it is
    # re-read from the elaborated controller exactly like the window parameters.
    # A missing parameter is "not rendered", not "matches the default".
    latch_parameter = _controller_parameter(netlist, "LATCH_MASK")
    latch_expected = int(plan.interrupt_document["controller"].get("latch_mask", 0))
    latch_ok = latch_parameter is not None and int(latch_parameter) == latch_expected
    return {"ok": ok and address_ok and latch_ok,
            "expected": {"req_valid_i": f"t_req_valid[{index}]",
                         "req_addr_i": f"t_addr[{index}][{width - 1}:0]",
                         "LATCH_MASK": latch_expected},
            "actual": {"req_valid_i": pin, "req_addr_i": address_pin,
                       "LATCH_MASK": latch_parameter}}


def _controller_parameter(netlist: Netlist, name: str) -> int | None:
    """One elaborated controller parameter as a constant, or None if unreadable."""
    cell = netlist.cell("u_irq_controller")
    if cell is None:
        return None
    parameters = cell.get("parameters")
    if not isinstance(parameters, Mapping):
        return None
    value = parameters.get(name)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def audit_document(result: Mapping[str, object], *,
                   provenance: Mapping[str, object] | None = None) -> dict[str, object]:
    document = dict(result)
    if provenance is not None:
        document["provenance"] = dict(provenance)
    return document


__all__ = [
    "AUDIT_SCHEMA",
    "FAIL",
    "PASS",
    "UNKNOWN",
    "Finding",
    "Netlist",
    "StructureAuditError",
    "audit_document",
    "audit_structure",
    "extract_netlist",
]
