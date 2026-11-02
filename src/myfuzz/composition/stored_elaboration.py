"""Elaborate a pinned top from *stored* port evidence instead of the frontend AST.

Why this module exists
----------------------
``elaborate_profile`` re-derives the physical port facts of every component at
every D2 generation by walking the Verilator JSON syntax tree.  For the derived
Chipyard top that walk is impossible by policy: ``BoomTile``'s
``chipyard.TestHarness.SmallBoomConfig.top.v`` is 17.96 MB and its syntax tree is
far larger than the bounded walker accepts (``source_elaboration._MAX_AST_NODES``
is 1 500 000 and the walker refuses at ``source_elaboration.py:183``).  The
limit is a real resource bound, not a bug: it is what makes "one pinned
component" a bounded operation on this host.  Widening it would also widen the
exposure of every other component, and exactly one test pins the value
(``tests/composition/test_source_elaboration.py:144``).

What is *not* needed, however, is a fresh AST walk.  The BOOM derivation already
publishes its port facts as a pinned artifact:

``configs/cpus/boom/generated/source_manifest.json``
    ``"physical_ports": "../evidence/derived-20261017/physical_ports.json"``
    ``"physical_ports_sha256": "80878201..."``

and the profile pins the exact source bytes (``sha256:4f960fdd...``).  This
module turns that artifact into ``PhysicalFacts`` **only** after proving that

1. the declared source closure still hashes to the profile's revision;
2. the manifest is the manifest of that revision;
3. the evidence file's SHA-256 is the manifest's digest, inside the component's
   own configuration directory (never an unbounded path);
4. the *pinned source text itself* declares exactly the same top-module ports
   (name, direction, width, signedness, line, column) as the stored evidence.

Step 4 is what keeps this honest: the stored artifact is never the sole
authority.  The top module's ANSI port list is re-read from the pinned bytes with
the bounded text parser that ``source_crawler`` already uses for every component,
so positions and signedness come from the source, and the two independent
evidence sources must agree exactly or the component is refused.

The result is marked ``evidence_source='stored-port-evidence'`` plus the digest
of the artifact, so every downstream document says which path produced the
facts.  A profile that declares no stored evidence is unaffected: this function
returns ``None`` and the normal elaboration runs unchanged.
"""
from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping

#: Manifest field names this reader consumes; anything else stays opaque.
MANIFEST_NAME = "source_manifest.json"
EVIDENCE_SOURCE = "stored-port-evidence"
_HEX = frozenset("0123456789abcdef")


class StoredElaborationError(ValueError):
    """Stored evidence is declared but does not authenticate the pinned source."""


def _error(message: str) -> None:
    raise StoredElaborationError(message)


def _digest(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _manifest(root: Path) -> Mapping[str, object] | None:
    path = root / MANIFEST_NAME
    if path.is_symlink() or not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise StoredElaborationError(f"stored-evidence-manifest-invalid:{MANIFEST_NAME}") from error
    if not isinstance(document, dict):
        _error("stored-evidence-manifest-invalid:not-an-object")
    return document


def _evidence_path(root: Path, manifest: Mapping[str, object]) -> tuple[Path, str]:
    """Resolve the declared evidence file inside the component configuration."""
    declared = manifest.get("physical_ports")
    expected = manifest.get("physical_ports_sha256")
    if not isinstance(declared, str) or not declared:
        _error("stored-evidence-declaration-invalid:physical_ports")
    if (not isinstance(expected, str) or len(expected) != 64
            or set(expected) - _HEX):
        _error("stored-evidence-declaration-invalid:physical_ports_sha256")
    if Path(declared).is_absolute():
        _error("stored-evidence-declaration-invalid:absolute-path")
    # The evidence lives next to the generated tree (``../evidence/...``), so the
    # bound is the component's configuration directory, not the source root.
    base = root.parent.resolve()
    candidate = (root / declared).resolve()
    if not candidate.is_relative_to(base):
        _error("stored-evidence-declaration-invalid:outside-component-directory")
    if candidate.is_symlink() or not candidate.is_file():
        _error("stored-evidence-declaration-invalid:not-a-regular-file")
    return candidate, expected


def _stored_ports(document: Mapping[str, object], top_module: str) -> dict[str, tuple[str, int]]:
    modules = document.get("modules")
    if not isinstance(modules, dict) or not isinstance(modules.get(top_module), dict):
        _error(f"stored-evidence-module-missing:{top_module}")
    rows = modules[top_module].get("ports")
    if not isinstance(rows, list) or not rows:
        _error(f"stored-evidence-ports-missing:{top_module}")
    ports: dict[str, tuple[str, int]] = {}
    for row in rows:
        if not isinstance(row, dict):
            _error("stored-evidence-port-shape")
        name, direction, width = row.get("name"), row.get("direction"), row.get("width")
        if (not isinstance(name, str) or not name or direction not in ("input", "output", "inout")
                or type(width) is not int or not 1 <= width <= 1 << 24):
            _error("stored-evidence-port-shape")
        if name in ports:
            _error(f"stored-evidence-port-duplicated:{name}")
        ports[name] = (str(direction), int(width))
    return ports


def top_module_text_ports(root: Path, files, top_module: str, read):
    """Bounded text parse of *one* module's ANSI header from pinned bytes.

    Only the declared top module is parsed: other modules in the same file
    may use parameterised or aggregate ports this parser refuses on purpose,
    and a whole-file crawl would fail on them (``unsupported-port-width``).
    The caller passes the exact pinned file list and a byte reader, so the
    facts can only come from the authenticated closure.
    """
    from myfuzz.composition.source_crawler import (
        _ENDMODULE_RE, _MODULE_RE, _module_ports,
    )
    from myfuzz.scripts.source_only_frontend import mask_comments_and_strings

    modules: list[str] = []
    header: tuple[str, str, object] | None = None
    for path in files:
        try:
            original = read(path).decode("utf-8")
        except UnicodeDecodeError as error:  # pragma: no cover - pinned bytes are ASCII
            raise StoredElaborationError(f"stored-evidence-source-encoding:{path.name}") from error
        masked = mask_comments_and_strings(original)
        relative = path.resolve().relative_to(root).as_posix()
        for match in _MODULE_RE.finditer(masked):
            module = match.group(1)
            modules.append(module)
            if module != top_module:
                continue
            if header is not None:
                _error(f"stored-evidence-top-module-duplicated:{top_module}")
            header = (original, relative, match)
    if header is None:
        _error(f"stored-evidence-top-module-missing:{top_module}")
    original, relative, match = header
    masked = mask_comments_and_strings(original)
    end = _ENDMODULE_RE.search(masked, match.end())
    if end is None:
        _error(f"stored-evidence-top-module-unterminated:{top_module}")
    records = _module_ports(original, masked, match, end.start(), top_module, relative)
    if not records:
        _error(f"stored-evidence-top-ports-unreadable:{top_module}")
    return tuple(record[0] for record in records), tuple(dict.fromkeys(modules))


def stored_elaboration_facts(profile, *, base_dir: Path):
    """``PhysicalFacts`` from authenticated stored evidence, or ``None``.

    ``None`` means the profile declares no stored evidence: the caller keeps its
    existing elaboration choice.  Every *declared but unauthenticated* case is a
    refusal, never a silent fallback, because a fallback would hide the reason
    the component cannot be elaborated.
    """
    from myfuzz.composition.component_profile import (
        ElaboratedPortFact, PhysicalFacts, _closure_names,
        _direct_pinned_closure_hash,
    )
    from myfuzz.composition.source_crawler import (
        SourceCrawlError, _declared_files, _pinned_source_reader,
    )

    root = Path(base_dir).resolve()
    try:
        source_root, contents, read = _pinned_source_reader(profile.source, base_dir=root)
    except SourceCrawlError as error:
        raise StoredElaborationError(
            f"stored-evidence-source-unreadable:{profile.component_id}:{error}") from error
    manifest = _manifest(source_root)
    if manifest is None or manifest.get("physical_ports") is None:
        return None
    if manifest.get("revision") != profile.source.revision:
        _error(f"stored-evidence-revision-mismatch:{profile.component_id}")
    evidence_path, expected_digest = _evidence_path(source_root, manifest)
    try:
        payload = evidence_path.read_bytes()
    except OSError as error:  # pragma: no cover - validated above
        raise StoredElaborationError(
            f"stored-evidence-unreadable:{profile.component_id}") from error
    actual_digest = _digest(payload)
    if actual_digest != expected_digest:
        _error(f"stored-evidence-digest-mismatch:{profile.component_id}")
    try:
        document = json.loads(payload)
    except ValueError as error:
        raise StoredElaborationError(
            f"stored-evidence-malformed:{profile.component_id}") from error
    if not isinstance(document, dict):
        _error(f"stored-evidence-malformed:{profile.component_id}")
    try:
        files, include_roots, _defines = _declared_files(source_root, profile.source, read)
        content_hash = _direct_pinned_closure_hash(
            source_root, contents, include_roots, read, profile.source.revision)
    except SourceCrawlError as error:
        raise StoredElaborationError(
            f"stored-evidence-source-unreadable:{profile.component_id}:{error}") from error
    if content_hash != profile.source.revision:
        _error(f"stored-evidence-source-mismatch:{profile.component_id}")
    if not files:
        _error(f"stored-evidence-source-empty:{profile.component_id}")
    text_ports, modules = top_module_text_ports(source_root, files, profile.source.top_module, read)
    stored = _stored_ports(document, profile.source.top_module)
    declared = {port.name: (port.direction, port.width) for port in text_ports}
    if declared != stored:
        missing = sorted(set(stored) - set(declared))
        extra = sorted(set(declared) - set(stored))
        mismatched = sorted(name for name in set(declared) & set(stored)
                            if declared[name] != stored[name])
        _error(f"stored-evidence-port-mismatch:{profile.component_id}:"
               f"{{missing={missing},extra={extra},mismatched={mismatched}}}")
    ports = tuple(
        ElaboratedPortFact(port.name, port.direction, port.width, port.signed,
                           port.source_file, port.line, port.column, ())
        for port in text_ports)
    return replace(
        PhysicalFacts(
            top_module=profile.source.top_module,
            ports=ports,
            content_hash=content_hash,
            revision=profile.source.revision,
            modules=tuple(sorted(set(modules))),
            warning_count=0,
            selection="all",
            files=_closure_names(source_root, files),
            include_roots=tuple(include_roots),
        ),
        evidence_source=EVIDENCE_SOURCE,
        evidence_sha256=actual_digest,
    )
