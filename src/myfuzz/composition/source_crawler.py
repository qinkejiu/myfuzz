"""Pinned, source-only HDL interface evidence collection.

The crawler deliberately consumes an already materialized local checkout.  It
does not acquire sources or invoke a HDL compiler; callers can therefore use
it in constrained, reproducible analysis environments.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from myfuzz.contracts import validate_contract
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import ProtocolDefinitionError
from myfuzz.scripts.source_only_frontend import (
    HDL_SUFFIXES,
    IDENT_RE,
    RANGE_RE,
    const_int,
    find_matching,
    line_col,
    mask_comments_and_strings,
    width_from_ranges,
)

from .interface_description import EndpointDescription, FieldHint, InterfaceDescription, SourceLocator


_MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\b")
_ENDMODULE_RE = re.compile(r"\bendmodule\b")
_DIRECTION_RE = re.compile(r"\b(input|output|inout)\b")
_DECL_KEYWORDS = frozenset(
    {
        "input", "output", "inout", "ref", "wire", "reg", "logic", "signed", "unsigned",
        "tri", "bit", "var", "const", "integer", "time", "realtime", "byte", "shortint",
        "int", "longint",
    }
)
_SOURCE_TAG_RE = re.compile(
    r"myfuzz:\s*endpoint=([^\s]+)\s+field=([^\s]+)", re.IGNORECASE
)
_PIN_RE = re.compile(r"(?:git:[0-9a-f]{40}|sha256:[0-9a-f]{64})\Z")


class SourceCrawlError(ValueError):
    """Raised when source evidence is unsafe, unpinned, or insufficient."""


@dataclass(frozen=True, slots=True)
class SourcePortFact:
    module: str
    name: str
    direction: str
    width: int
    signed: bool
    source_file: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class TimingObservation:
    kind: str
    fields: tuple[str, ...]
    clock: str | None
    source_file: str
    line: int


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    revision: str
    content_hash: str
    files: tuple[str, ...]
    modules: tuple[str, ...]
    ports: tuple[SourcePortFact, ...]
    timing: tuple[TimingObservation, ...]


def _relative(root: Path, value: Path) -> str:
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise SourceCrawlError("path-outside-source-root") from error


def source_tree_hash(root: Path, files: Sequence[Path]) -> str:
    """Hash sorted relative file names and their bytes, independent of root path."""
    resolved_root = root.resolve()
    entries = sorted((_relative(resolved_root, path), path.resolve()) for path in files)
    digest = hashlib.sha256()
    for relative, path in entries:
        if not path.is_file():
            raise SourceCrawlError(f"source-file-missing:{relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(path.read_bytes())
    return f"sha256:{digest.hexdigest()}"


def _safe_child(root: Path, raw: str) -> Path:
    path = Path(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise SourceCrawlError("path-outside-source-root")
    candidate = (root / path).resolve()
    _relative(root, candidate)
    return candidate


def _declared_files(root: Path, locator: SourceLocator) -> tuple[Path, ...]:
    files: set[Path] = set()

    def add_source(raw: str) -> None:
        source = _safe_child(root, raw)
        if source.suffix not in HDL_SUFFIXES or not source.is_file():
            raise SourceCrawlError(f"source-file-missing:{raw}")
        files.add(source)

    def expand_filelist(path: Path, seen: set[Path]) -> None:
        path = path.resolve()
        _relative(root, path)
        if path in seen:
            return
        if not path.is_file():
            raise SourceCrawlError(f"source-file-missing:{_relative(root, path)}")
        seen.add(path)
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            item = raw_line.strip()
            if not item or item.startswith("#") or item.startswith("+"):
                continue
            if item.startswith("-f "):
                nested = _safe_child(root, _relative(root, path.parent / item[3:].strip()))
                expand_filelist(nested, seen)
                continue
            if item.startswith("-F "):
                expand_filelist(_safe_child(root, item[3:].strip()), seen)
                continue
            if item.startswith("-"):
                continue
            candidate = item.split()[0]
            base_relative = _relative(root, path.parent)
            add_source(f"{base_relative}/{candidate}" if base_relative else candidate)

    for raw in locator.files:
        add_source(raw)
    if locator.filelist is not None:
        expand_filelist(_safe_child(root, locator.filelist), set())
    for raw in locator.include_roots:
        directory = _safe_child(root, raw)
        if not directory.is_dir():
            raise SourceCrawlError(f"include-root-missing:{raw}")
    return tuple(sorted(files, key=lambda item: _relative(root, item)))


def _parts(text: str, offset: int) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    start = 0
    paren = bracket = brace = 0
    for index, char in enumerate(text):
        if char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket:
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}" and brace:
            brace -= 1
        elif char == "," and not (paren or bracket or brace):
            result.append((text[start:index], offset + start))
            start = index + 1
    if text[start:].strip():
        result.append((text[start:], offset + start))
    return result


def _constant_width(fragment: str) -> int:
    for most_significant, least_significant in RANGE_RE.findall(fragment):
        if const_int(most_significant) is None or const_int(least_significant) is None:
            raise SourceCrawlError("unsupported-port-width")
    return width_from_ranges(fragment)


def _declaration_ports(
    original: str,
    masked: str,
    offset: int,
    module: str,
    source_file: str,
) -> list[tuple[SourcePortFact, int]]:
    records: list[tuple[SourcePortFact, int]] = []
    direction = ""
    width = 1
    signed = False
    for fragment, fragment_offset in _parts(masked, offset):
        matched_direction = _DIRECTION_RE.search(fragment)
        if matched_direction is not None:
            direction = matched_direction.group(1)
            width = _constant_width(fragment)
            signed = bool(re.search(r"\bsigned\b", fragment)) and not bool(
                re.search(r"\bunsigned\b", fragment)
            )
        if not direction:
            continue
        names = [
            match for match in IDENT_RE.finditer(fragment)
            if match.group(0) not in _DECL_KEYWORDS
        ]
        if not names:
            continue
        name_match = names[-1]
        absolute = fragment_offset + name_match.start()
        line, column = line_col(original, absolute)
        records.append(
            (
                SourcePortFact(module, name_match.group(0), direction, width, signed, source_file, line, column),
                absolute,
            )
        )
    return records


def _module_ports(
    original: str,
    masked: str,
    module_match: re.Match[str],
    module_end: int,
    module: str,
    source_file: str,
) -> list[tuple[SourcePortFact, int]]:
    semi = masked.find(";", module_match.end(), module_end)
    if semi < 0:
        return []
    opens: list[int] = []
    cursor = module_match.end()
    while True:
        opening = masked.find("(", cursor, semi)
        if opening < 0:
            break
        closing = find_matching(masked, opening, "(", ")")
        if closing < 0 or closing > semi:
            break
        opens.append(opening)
        cursor = closing + 1
    header_ports: list[tuple[SourcePortFact, int]] = []
    if opens:
        opening = opens[-1]
        closing = find_matching(masked, opening, "(", ")")
        header_ports = _declaration_ports(
            original, masked[opening + 1:closing], opening + 1, module, source_file
        )
    if header_ports:
        return header_ports
    body = masked[semi + 1:module_end]
    records: list[tuple[SourcePortFact, int]] = []
    for declaration in re.finditer(r"\b(?:input|output|inout)\b[^;]*;", body):
        start = semi + 1 + declaration.start()
        records.extend(_declaration_ports(original, declaration.group(0)[:-1], start, module, source_file))
    return records


def _timing(
    original: str, masked: str, start: int, end: int, source_file: str
) -> list[TimingObservation]:
    observations: list[TimingObservation] = []
    body = masked[start:end]
    always_re = re.compile(r"\balways(?:_ff)?\s*@\s*\(([^)]*)\)")
    for always in always_re.finditer(body):
        event = always.group(1)
        edges = re.findall(r"\b(posedge|negedge)\s+([A-Za-z_][A-Za-z0-9_$]*)", event)
        clock = next((name for edge, name in edges if edge == "posedge"), None)
        resets = tuple(name for edge, name in edges if edge == "negedge")
        begin = re.match(r"\s*begin\b", body[always.end():])
        if begin is None:
            block_end = body.find(";", always.end()) + 1
            if block_end <= 0:
                block_end = len(body)
            block_start = always.end()
        else:
            begin_word = always.end() + begin.end() - len("begin")
            block_start = begin_word + len("begin")
            # Nested blocks are uncommon in the source-only subset.  Find a balanced
            # begin/end region so assignments in the enclosing block are retained.
            depth = 0
            block_end = len(body)
            for token in re.finditer(r"\b(begin|end)\b", body[begin_word:]):
                if token.group(1) == "begin":
                    depth += 1
                else:
                    depth -= 1
                    if depth == 0:
                        block_end = begin_word + token.end()
                        break
        block = body[block_start:block_end]
        for assignment in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_$]*)\s*(?:<=|=)", block):
            line, _ = line_col(original, start + block_start + assignment.start())
            observations.append(
                TimingObservation("sequential_assignment" if clock else "combinational_assignment", (assignment.group(1),), clock, source_file, line)
            )
            if clock and resets:
                observations.append(
                    TimingObservation("reset_membership", (assignment.group(1), *resets), clock, source_file, line)
                )
        for stalled in re.finditer(
            r"\bif\s*\(\s*([A-Za-z_][A-Za-z0-9_$]*)\s*&&\s*!\s*([A-Za-z_][A-Za-z0-9_$]*)\s*\)\s*(?:begin\s*)?\s*([A-Za-z_][A-Za-z0-9_$]*)\s*<=\s*\3\b",
            block,
        ):
            line, _ = line_col(original, start + block_start + stalled.start())
            observations.append(TimingObservation("stall_holds_payload", stalled.groups(), clock, source_file, line))
        for transfer in re.finditer(
            r"\bif\s*\(\s*([A-Za-z_][A-Za-z0-9_$]*)\s*&&\s*([A-Za-z_][A-Za-z0-9_$]*)\s*\)",
            block,
        ):
            if "!" not in transfer.group(0):
                line, _ = line_col(original, start + block_start + transfer.start())
                observations.append(TimingObservation("transfer_accept", transfer.groups(), clock, source_file, line))
    for combinational in re.finditer(r"\balways_(?:comb|latch)\b", body):
        line, _ = line_col(original, start + combinational.start())
        observations.append(TimingObservation("combinational_assignment", (), None, source_file, line))
    return observations


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


class SourceCrawler:
    def __init__(self) -> None:
        self._tags: dict[tuple[str, str, str, int], tuple[tuple[str, str], ...]] = {}

    def crawl(self, locator: SourceLocator, *, base_dir: Path) -> SourceSnapshot:
        if _PIN_RE.fullmatch(locator.revision) is None:
            raise SourceCrawlError("invalid-source-pin")
        root = _safe_child(base_dir.resolve(), locator.source_root)
        if not root.is_dir():
            raise SourceCrawlError("source-root-missing")
        files = _declared_files(root, locator)
        content_hash = source_tree_hash(root, files)
        if locator.revision.startswith("sha256:"):
            if locator.revision != content_hash:
                raise SourceCrawlError("content-hash-mismatch")
        else:
            revision = locator.revision[4:]
            command = ["git", "-C", root.as_posix(), "rev-parse", "--verify", f"{revision}^{{commit}}"]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0 or result.stdout.strip() != revision:
                raise SourceCrawlError("git-revision-mismatch")
            head = subprocess.run(
                ["git", "-C", root.as_posix(), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if head.returncode != 0 or head.stdout.strip() != revision:
                raise SourceCrawlError("git-revision-mismatch")

        ports: list[SourcePortFact] = []
        modules: list[str] = []
        timing: list[TimingObservation] = []
        self._tags = {}
        for path in files:
            relative = _relative(root, path)
            original = path.read_text(encoding="utf-8", errors="ignore")
            masked = mask_comments_and_strings(original)
            matches = list(_MODULE_RE.finditer(masked))
            for module_match in matches:
                module = module_match.group(1)
                end_match = _ENDMODULE_RE.search(masked, module_match.end())
                if end_match is None:
                    continue
                modules.append(module)
                records = _module_ports(original, masked, module_match, end_match.start(), module, relative)
                ports.extend(record[0] for record in records)
                tags = [
                    (tag.start(), tag.group(1), tag.group(2))
                    for tag in _SOURCE_TAG_RE.finditer(original, module_match.start(), end_match.end())
                ]
                for port, position in records:
                    attached = tuple(
                        (endpoint, field)
                        for tag_position, endpoint, field in tags
                        if tag_position < position
                        and not any(other_position < position and other_position > tag_position for _, other_position in records)
                    )
                    if attached:
                        self._tags[(port.module, port.name, port.source_file, port.line)] = attached
                header_end = masked.find(";", module_match.end(), end_match.start())
                if header_end >= 0:
                    timing.extend(_timing(original, masked, header_end + 1, end_match.start(), relative))
        return SourceSnapshot(
            locator.revision,
            content_hash,
            tuple(_relative(root, path) for path in files),
            tuple(sorted(modules)),
            tuple(sorted(ports, key=lambda item: (item.module, item.name, item.source_file, item.line, item.column))),
            tuple(sorted(timing, key=lambda item: (item.source_file, item.line, item.kind, item.fields))),
        )

    def _module_ports(self, snapshot: SourceSnapshot, endpoint: EndpointDescription) -> tuple[SourcePortFact, ...]:
        module = endpoint.module or ""
        if not module:
            raise SourceCrawlError(f"endpoint-unresolved:{endpoint.endpoint_id}")
        if snapshot.modules.count(module) > 1:
            raise SourceCrawlError(f"endpoint-ambiguous:{endpoint.endpoint_id}")
        matches = tuple(port for port in snapshot.ports if port.module == module)
        if not matches:
            raise SourceCrawlError(f"endpoint-unresolved:{endpoint.endpoint_id}")
        return matches

    def _field_port(
        self, endpoint: EndpointDescription, field: FieldHint, ports: tuple[SourcePortFact, ...]
    ) -> tuple[SourcePortFact, str]:
        aliases = set(field.aliases)
        explicit = tuple(port for port in ports if port.name in aliases)
        tagged = tuple(
            port for port in ports
            if (endpoint.endpoint_id, field.role) in self._tags.get(
                (port.module, port.name, port.source_file, port.line), ()
            )
        )
        if explicit and tagged and {port.name for port in explicit} != {port.name for port in tagged}:
            raise SourceCrawlError(f"source-semantic-conflict:{endpoint.endpoint_id}:{field.role}")
        candidates: tuple[SourcePortFact, ...]
        evidence: str
        if explicit:
            candidates, evidence = explicit, "explicit_alias"
        elif tagged:
            candidates, evidence = tagged, "source_documentation"
        else:
            exact = tuple(port for port in ports if port.name == field.role)
            if exact:
                candidates, evidence = exact, "exact_role_label"
            else:
                candidates = tuple(port for port in ports if _normalized(port.name) == _normalized(field.role))
                evidence = "normalized_name"
        if not candidates:
            raise SourceCrawlError(f"field-unresolved:{endpoint.endpoint_id}:{field.role}")
        if len(candidates) != 1:
            raise SourceCrawlError(f"field-ambiguous:{endpoint.endpoint_id}:{field.role}")
        return candidates[0], evidence

    @staticmethod
    def _protocol_candidates(
        endpoint: EndpointDescription,
        fields: list[dict[str, object]],
        catalog: ProtocolCatalog | None,
    ) -> list[dict[str, object]]:
        if endpoint.protocol is None:
            return []
        protocol_id, version = endpoint.protocol
        candidate: dict[str, object] = {"id": protocol_id, "version": version, "evidence": "declared"}
        if catalog is None:
            candidate["status"] = "unverified"
            return [candidate]
        try:
            plugin = catalog.require(protocol_id, version)
        except ProtocolDefinitionError as error:
            raise SourceCrawlError(f"protocol-unsupported:{endpoint.endpoint_id}:{protocol_id}@{version}") from error
        by_role = {_normalized(str(field["role"])): field for field in fields}
        aliases = {"addr": "address", "wdata": "writedata", "rdata": "readdata"}
        for spec in plugin.fields:
            role = aliases.get(_normalized(spec.field_id), _normalized(spec.field_id))
            matched = by_role.get(role)
            if matched is None:
                if spec.required:
                    raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:missing:{spec.field_id}")
                continue
            expected = "output" if spec.direction == "host_to_device" else "input"
            if endpoint.function.endswith("master") and matched["direction"] != expected:
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:direction:{spec.field_id}")
        candidate["status"] = "consistent"
        return [candidate]

    def annotate(
        self,
        snapshot: SourceSnapshot,
        description: InterfaceDescription,
        *,
        protocol_catalog: ProtocolCatalog | None = None,
    ) -> dict[str, object]:
        endpoint_documents: list[dict[str, object]] = []
        for endpoint in description.endpoints:
            resolved = EndpointDescription(
                endpoint.endpoint_id,
                endpoint.function,
                endpoint.required,
                endpoint.module or description.source.top_module,
                endpoint.hierarchy,
                endpoint.aliases,
                endpoint.protocol,
                endpoint.fields,
            )
            try:
                ports = self._module_ports(snapshot, resolved)
            except SourceCrawlError:
                if endpoint.required:
                    raise
                continue
            fields: list[dict[str, object]] = []
            matched_names: dict[str, str] = {}
            for field in resolved.fields:
                try:
                    port, evidence = self._field_port(resolved, field, ports)
                except SourceCrawlError:
                    if field.required:
                        raise
                    continue
                matched_names[port.name] = field.role
                fields.append(
                    {
                        "role": field.role,
                        "port": port.name,
                        "direction": port.direction,
                        "width": port.width,
                        "signed": port.signed,
                        "source": {"file": port.source_file, "line": port.line, "column": port.column},
                        "evidence": [evidence, "hdl_declaration"],
                        "confidence": "high" if evidence != "normalized_name" else "low",
                    }
                )
            related = [observation for observation in snapshot.timing if set(observation.fields) & set(matched_names)]
            clocks = sorted({observation.clock for observation in related if observation.clock is not None})
            if len(clocks) > 1:
                raise SourceCrawlError(f"clock-ambiguous:{endpoint.endpoint_id}")
            resets = sorted(
                {
                    reset
                    for observation in related
                    if observation.kind == "reset_membership"
                    for reset in observation.fields[1:]
                }
            )
            endpoint_documents.append(
                {
                    "endpoint_id": endpoint.endpoint_id,
                    "function": endpoint.function,
                    "module": resolved.module,
                    "fields": sorted(fields, key=lambda item: str(item["role"])),
                    "clock": clocks[0] if clocks else None,
                    "reset": resets[0] if len(resets) == 1 else None,
                    "timing": [
                        {
                            "kind": observation.kind,
                            "fields": [matched_names.get(name, name) for name in observation.fields],
                            "clock": observation.clock,
                            "source": {"file": observation.source_file, "line": observation.line},
                        }
                        for observation in related
                    ],
                    "protocol_candidates": self._protocol_candidates(endpoint, fields, protocol_catalog),
                    "evidence": ["explicit_module" if endpoint.module else "source_top_module"],
                    "confidence": "high",
                    "diagnostics": [],
                }
            )
        document: dict[str, object] = {
            "schema_version": "interface_annotations.v1",
            "source": {
                "revision": snapshot.revision,
                "content_hash": snapshot.content_hash,
                "files": list(snapshot.files),
                "modules": list(snapshot.modules),
            },
            "endpoints": sorted(endpoint_documents, key=lambda item: str(item["endpoint_id"])),
            "diagnostics": [],
        }
        validate_contract(document, "interface_annotations.v1")
        return document


def annotate_interfaces(
    description: InterfaceDescription,
    *,
    base_dir: Path,
    protocol_catalog: ProtocolCatalog | None = None,
) -> dict[str, object]:
    crawler = SourceCrawler()
    return crawler.annotate(
        crawler.crawl(description.source, base_dir=base_dir),
        description,
        protocol_catalog=protocol_catalog,
    )
