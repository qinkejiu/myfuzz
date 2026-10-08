"""Internal RTL branch coverage, proven to come from RTL instrumentation.

The campaign distinguishes two things that must never be confused:

* **port semantic hits** - predicates over observed local RTL outputs
  (:mod:`myfuzz.scenario.feedback`).  They say "this port took this value at
  some point", which is a statement about interface behaviour.
* **internal branch coverage** - sticky bits/counters inserted into the CPU/IP
  RTL by :mod:`scripts.source_branch_instrumenter` and exported on a dedicated
  coverage port.  They say "this ``if``/``case`` arm inside the RTL was
  executed", which is a statement about internal control flow.

Only the second is branch coverage, and it is only branch coverage when its
provenance is *proven*.  This module therefore refuses to report a number
unless the artifact carries, and matches, every piece of the instrumentation
identity:

===========================  =================================================
identity item                how it is checked
===========================  =================================================
instrumenter version         must be a supported ``source_branch_instrumenter``
                             schema version
instrumenter source digest   recomputed from the instrumenter source file
instrumented RTL files       every declared file must exist under the
                             instrumented root with the declared sha256, and
                             the file list must be the *complete* set of
                             runtime compiler inputs
instrumented output digest   the frozen ``source_instrumented_output.v1``
                             content hash, recomputed from the tree by the
                             production enumerator that created it
instrumentation manifest     optional, but if referenced its digest and its
                             port/width/bit-kind tables must agree
coverage port list + width   the exposed ``(port, bit)`` list and the
                             instrumented vector width, matched against the
                             observed vector
harness/run identity         the attestation must claim the run it is offered
                             for
===========================  =================================================

Any missing, forged or contradictory item is **rejected**, and a rejected
document reports ``branch_points``/``observed_branches`` as ``None``: it never
falls back to "the port semantics looked right", and it never fills the branch
count from semantic hits.  ``separation`` always carries the two counts side by
side with ``combined`` pinned to ``None``.

Everything is bounded: port count, instrumented file count, per-file size and
the recorded rejection list all have hard caps, so a corrupted or hostile
artifact cannot make evaluation unbounded.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from myfuzz.scenario.feedback import CoverageTarget, observed_targets


SCHEMA_VERSION = "rtl_branch_coverage.v1"
VERIFIED = "verified"
REJECTED = "rejected"

#: The instrumented branch vector port produced by the source instrumenter.
COVERAGE_PORT = "__vi_coverage"
#: Instrumentation point kinds that constitute a real control-flow branch.
BRANCH_POINT_KINDS = ("if", "case")
#: Counter encoding used by the RFuzz coverage transport (8-bit saturating).
ENCODING_COUNTER = "u8-saturating-counter"
#: Strict one-bit-per-point encoding.
ENCODING_BIT = "bit"
ENCODINGS = (ENCODING_COUNTER, ENCODING_BIT)
SUPPORTED_INSTRUMENTER_SCHEMAS = ("source_branch_instrumenter.v1",)
#: Schema of the aggregate digest the production builder emits per tree.
INSTRUMENTED_OUTPUT_SCHEMA = "source_instrumented_output.v1"

DEFAULT_INSTRUMENTER_SOURCE = "scripts/source_branch_instrumenter.py"

MAX_PORTS = 1 << 16
MAX_REJECTIONS = 64
MAX_RTL_FILES = 4096
MAX_RTL_FILE_BYTES = 64 * 1024 * 1024
MAX_FIRST_SEEN_ENTRIES = MAX_PORTS

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

_ROOT = Path(__file__).resolve().parents[3]


def digest_of(payload: bytes) -> str:
    """Return the ``sha256:<hex>`` digest the campaign uses for identities."""
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def file_digest(path: Path) -> str:
    return digest_of(path.read_bytes())


@dataclass(frozen=True)
class Rejection:
    reason: str
    detail: str = ""

    def to_document(self) -> dict:
        return {"reason": self.reason, "detail": self.detail}


class _Rejector:
    """Collects bounded, deterministic rejections."""

    def __init__(self, limit: int = MAX_REJECTIONS) -> None:
        self.limit = limit
        self.total = 0
        self.recorded: list[Rejection] = []
        self._seen: set[tuple[str, str]] = set()

    def add(self, reason: str, detail: str = "") -> None:
        key = (reason, detail)
        if key in self._seen:
            return
        self._seen.add(key)
        self.total += 1
        if len(self.recorded) < self.limit:
            self.recorded.append(Rejection(reason, detail))

    def __bool__(self) -> bool:
        return self.total > 0

    def document(self) -> list[dict]:
        return [item.to_document() for item in self.recorded]

    def counts(self) -> dict:
        return {"total": self.total, "recorded": len(self.recorded),
                "overflow": self.total - len(self.recorded), "limit": self.limit}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and bool(_DIGEST.match(value))


def coverage_attestation(provenance: dict, run_dir) -> tuple[dict, list, list, str]:
    """The coverage attestation of one run, in either shipped shape.

    Older runs record three flat keys (``coverage_instrumentation``,
    ``coverage_ports``, ``branch_coverage_ports``).  Runs built by the current
    builder record one nested ``coverage`` document whose ``observations`` are
    the exposed counters in plan order, so the branch ports are re-derived from
    that run's own saved plan (``build/soc_coverage_plan.json``): the plan names
    each observed point's bit, and the exposed counters must agree with it
    element-wise, otherwise the attestation is refused instead of guessed.
    """
    instrumentation = provenance.get("coverage_instrumentation")
    coverage_ports = provenance.get("coverage_ports")
    branch_ports = provenance.get("branch_coverage_ports")
    if (isinstance(instrumentation, dict) and isinstance(coverage_ports, list)
            and isinstance(branch_ports, list) and branch_ports):
        return instrumentation, coverage_ports, branch_ports, "flat_attestation"
    coverage = provenance.get("coverage")
    if not isinstance(coverage, dict):
        raise ArtifactUnavailable(
            "no coverage_instrumentation or coverage attestation")
    observations = coverage.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ArtifactUnavailable("no coverage observations attestation")
    plan_path = Path(run_dir) / "build" / str(
        coverage.get("observation_plan") or "soc_coverage_plan.json")
    if not plan_path.is_file():
        raise ArtifactUnavailable(f"observation plan is missing: {plan_path}")
    try:
        plan = json.loads(plan_path.read_text())
    except (OSError, ValueError) as error:
        raise ArtifactUnavailable(f"unreadable observation plan: {plan_path}") from error
    observed = plan.get("observed") if isinstance(plan, dict) else None
    if not isinstance(observed, list) or not observed:
        raise ArtifactUnavailable("observation plan carries no observed points")
    signal = coverage.get("signal") or "__vi_coverage"
    # Element type follows the flat attestation (two-element lists), because
    # consumers compare them with the plan and with the harness port list.
    derived = [[str(signal), int(row["bit"])] for row in observed
               if isinstance(row, dict) and type(row.get("bit")) is int]
    if len(derived) != len(observed):
        raise ArtifactUnavailable("an observed plan point has no integer bit")
    if [bit for _, bit in derived] != [row[1] for row in observations[:len(derived)]]:
        raise ArtifactUnavailable(
            "the saved plan and the exposed counter list disagree on the "
            "observed points, so the branch ports cannot be re-derived")
    return coverage, observations, derived, "nested_coverage_attestation"


def coverage_kind(provenance: dict) -> str:
    """The instrumented-coverage kind, from either attestation shape."""
    kind = provenance.get("coverage_kind")
    if isinstance(kind, str) and kind:
        return kind
    coverage = provenance.get("coverage")
    if isinstance(coverage, dict) and isinstance(coverage.get("kind"), str):
        return coverage["kind"]
    return ""


def executable_sha256(provenance: dict) -> str:
    """The compiled executable digest, from either attestation shape."""
    flat = provenance.get("executable_sha256")
    if isinstance(flat, str) and flat:
        return flat
    executable = provenance.get("executable")
    if isinstance(executable, dict) and isinstance(executable.get("sha256"), str):
        return executable["sha256"]
    return ""


class ArtifactUnavailable(Exception):
    """A saved run does not carry the coverage attestation this reader needs."""


def _port_key(value: object) -> tuple[str, int] | None:
    if (isinstance(value, (list, tuple)) and len(value) == 2
            and isinstance(value[0], str) and value[0] and _is_int(value[1])
            and value[1] >= 0):
        return (value[0], int(value[1]))
    return None


def _port_list(value: object) -> list[tuple[str, int]] | None:
    if not isinstance(value, (list, tuple)) or len(value) > MAX_PORTS:
        return None
    rows = [_port_key(item) for item in value]
    if any(row is None for row in rows):
        return None
    return [row for row in rows if row is not None]


def _read_bounded(path: Path, rejector: _Rejector, reason: str) -> bytes | None:
    try:
        if path.stat().st_size > MAX_RTL_FILE_BYTES:
            rejector.add("rtl-file-oversized", f"{path.name} exceeds the read bound")
            return None
        return path.read_bytes()
    except OSError:
        rejector.add(reason, path.name)
        return None


def _enumerate_inputs(root: Path, rejector: _Rejector) -> list[tuple[str, str]] | None:
    """Mirror the production enumerator: every regular file but the manifest.

    ``scripts/source_branch_instrumenter`` output is hashed by the builder with
    exactly this rule, so the file list derived here is the same list the
    attested aggregate was computed over.
    """
    rows: list[tuple[str, str]] = []
    try:
        entries = sorted(root.rglob("*"))
    except OSError:
        rejector.add("instrumented-tree-unreadable", root.name)
        return None
    for path in entries:
        if path.is_symlink():
            rejector.add("instrumented-tree-symlink-unsupported", path.name)
            return None
        if not path.is_file() or path.name == "instrumentation.json":
            continue
        if len(rows) >= MAX_RTL_FILES:
            rejector.add("instrumented-tree-too-large", f">{MAX_RTL_FILES} files")
            return None
        payload = _read_bounded(path, rejector, "rtl-file-unreadable")
        if payload is None:
            return None
        rows.append((path.relative_to(root).as_posix(), digest_of(payload)))
    return rows


def _aggregate_digest(root: Path, flist: Path, aliases: Iterable[str]) -> str:
    """Recompute the frozen production tree digest.

    The implementation lives in the builder that produced the attestation; it
    is imported (never re-implemented) so this check cannot drift from the
    producer.
    """
    from myfuzz.integration.soc_builder import _instrumented_output_sha256

    return _instrumented_output_sha256(root, flist, path_aliases=tuple(aliases))


def _canonical(value: object) -> bytes:
    import json

    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


@dataclass(frozen=True)
class _PortSemantics:
    total_targets: int
    observed: int
    non_branch_lit_ports: int
    lit_by_class: dict
    targeted_ports: tuple

    def to_document(self) -> dict:
        return {
            "total_targets": self.total_targets,
            "observed_targets": self.observed,
            "non_branch_lit_ports": self.non_branch_lit_ports,
            "observed_lit_ports_by_class": self.lit_by_class,
            "targeted_ports": list(self.targeted_ports),
            "basis": ("feedback.CoverageTarget predicates over observed outputs; "
                      "counted apart from instrumented branch coverage"),
        }


class RtlBranchCoverage:
    """Evaluate one run's instrumented branch vector, or reject it.

    ``attribution`` is the declared instrumentation identity (the saved
    ``coverage_instrumentation``/provenance block), ``observation`` is the
    coverage vector actually read out of the run, and ``harness_identity`` is
    the run the data is offered for.  ``port_semantic_targets``/``
    port_semantic_events`` are the independent :mod:`feedback` measurement that
    is reported alongside - never merged into - the branch count.
    """

    def __init__(self, *,
                 attribution: object = None,
                 harness_identity: object = None,
                 observation: object = None,
                 instrumented_root: object = None,
                 instrumenter_source_path: object = None,
                 instrumentation_manifest: object = None,
                 manifest_sha256: object = None,
                 derive_rtl_file_digests: bool = False,
                 port_semantic_targets: Iterable[CoverageTarget] = (),
                 port_semantic_events: Iterable[Mapping] = (),
                 max_ports: int = MAX_PORTS,
                 max_rejections: int = MAX_REJECTIONS) -> None:
        self._attribution = attribution
        self._harness_identity = harness_identity
        self._observation = observation
        self._root_hint = instrumented_root
        self._instrumenter_source = instrumenter_source_path
        self._manifest = instrumentation_manifest
        self._manifest_sha256 = manifest_sha256
        self._derive_rtl_files = bool(derive_rtl_file_digests)
        self._targets = tuple(port_semantic_targets)
        self._events = tuple(port_semantic_events)
        self._max_ports = max_ports
        self._max_rejections = max_rejections
        self._rejector = _Rejector(max_rejections)
        self._document: dict | None = None

    # -- public API --------------------------------------------------------

    def evaluate(self) -> dict:
        if self._document is None:
            self._document = self._evaluate()
        return self._document

    @property
    def rejections(self) -> tuple[Rejection, ...]:
        self.evaluate()
        return tuple(self._rejector.recorded)

    @property
    def ok(self) -> bool:
        return self.evaluate()["status"] == VERIFIED

    def canonical_bytes(self) -> bytes:
        return _canonical(self.evaluate())

    # -- evaluation --------------------------------------------------------

    def _evaluate(self) -> dict:
        semantics = self._port_semantics()
        attribution = self._attribution
        if not isinstance(attribution, Mapping) or not attribution:
            self._rejector.add("instrumentation-attribution-missing",
                               "no declared instrumentation identity was supplied")
            return self._document_for(None, None, None, semantics)

        root = self._resolve_root(attribution)
        instrumenter = self._check_instrumenter(attribution)
        harness = self._check_harness(attribution)
        manifest = self._check_manifest(attribution, root)
        width = self._declared_width(attribution)
        declared_ports = self._declared_ports(attribution)
        branch_ports = self._declared_branch_ports(attribution, declared_ports, width)
        self._check_branch_kinds(attribution, manifest, branch_ports)
        identity = self._check_tree(attribution, root)
        observed = self._check_observation(attribution, declared_ports, branch_ports)
        counters = observed["counters"] if observed else None
        encoding = observed["encoding"] if observed else None
        first_seen = self._check_first_seen(observed, branch_ports, counters)

        if self._rejector:
            return self._document_for(instrumenter, harness, identity, semantics)

        return self._verified_document(instrumenter, harness, identity, manifest,
                                       declared_ports, branch_ports, width,
                                       encoding, counters, first_seen, semantics)

    # -- identity ----------------------------------------------------------

    def _resolve_root(self, attribution: Mapping) -> Path | None:
        declared = attribution.get("instrumented_root")
        for candidate in (self._root_hint, declared):
            if isinstance(candidate, (str, Path)) and str(candidate):
                return Path(candidate)
        self._rejector.add("instrumented-root-missing",
                           "no instrumented tree was declared or supplied")
        return None

    def _check_instrumenter(self, attribution: Mapping) -> dict | None:
        instrumenter = attribution.get("instrumenter")
        if not isinstance(instrumenter, Mapping) or not instrumenter:
            self._rejector.add("instrumenter-identity-missing",
                               "no instrumenter version and source digest")
            return None
        schema = instrumenter.get("schema_version")
        declared = instrumenter.get("source_sha256")
        record = {"schema_version": schema, "source_sha256": declared}
        if schema not in SUPPORTED_INSTRUMENTER_SCHEMAS:
            self._rejector.add("instrumenter-version-unsupported", str(schema))
            return record
        if not _valid_digest(declared):
            self._rejector.add("instrumenter-source-digest-invalid", str(declared))
            return record
        path = self._instrumenter_source
        if path is None:
            path = _ROOT / DEFAULT_INSTRUMENTER_SOURCE
        path = Path(path)
        if not path.is_file():
            self._rejector.add("instrumenter-source-unavailable", path.name)
            return record
        payload = _read_bounded(path, self._rejector, "instrumenter-source-unavailable")
        if payload is None:
            return record
        actual = digest_of(payload)
        record["source_verified"] = actual == declared
        if not record["source_verified"]:
            self._rejector.add("instrumenter-source-mismatch",
                               f"declared {declared} != recomputed {actual}")
        return record

    def _check_harness(self, attribution: Mapping) -> dict | None:
        declared = attribution.get("harness")
        if not isinstance(declared, Mapping) or not declared:
            self._rejector.add("harness-identity-missing",
                               "the attestation names no harness/run")
            return None
        actual = self._harness_identity
        if not isinstance(actual, Mapping) or not actual:
            self._rejector.add("harness-identity-missing",
                               "no harness/run identity was supplied to compare")
            return None
        if dict(declared) != dict(actual):
            differing = sorted(
                key for key in set(declared) | set(actual)
                if declared.get(key) != actual.get(key))
            self._rejector.add("harness-identity-mismatch",
                               "differing fields: " + ",".join(differing))
        return dict(declared)

    def _check_manifest(self, attribution: Mapping, root: Path | None) -> dict | None:
        declared_digest = attribution.get("instrumentation_manifest_sha256")
        if declared_digest is not None and not _valid_digest(declared_digest):
            self._rejector.add("instrumentation-manifest-digest-invalid",
                               str(declared_digest))
            declared_digest = None
        # The manifest on disk is the stronger evidence; a caller-supplied
        # digest is only a fallback for callers that hold the bytes themselves.
        actual = None
        if root is not None:
            path = root / "instrumentation.json"
            if path.is_file():
                payload = _read_bounded(path, self._rejector,
                                        "instrumentation-manifest-unreadable")
                if payload is not None:
                    actual = digest_of(payload)
        if actual is None and _valid_digest(self._manifest_sha256):
            actual = str(self._manifest_sha256)
        manifest = self._manifest
        if manifest is None:
            # Without a manifest there are no bit kinds to justify here.
            if declared_digest is not None and actual is not None \
                    and actual != declared_digest:
                self._rejector.add("instrumentation-manifest-digest-mismatch",
                                   f"declared {declared_digest} != on-disk {actual}")
            return None
        if not isinstance(manifest, Mapping):
            self._rejector.add("instrumentation-manifest-invalid",
                               "the manifest is not an object")
            return None
        if declared_digest is None:
            self._rejector.add(
                "instrumentation-manifest-unattested",
                "bit kinds are justified by a manifest with no declared digest")
        elif actual is None:
            self._rejector.add(
                "instrumentation-manifest-unverified",
                "no manifest bytes were available to recompute the declared digest")
        elif actual != declared_digest:
            self._rejector.add("instrumentation-manifest-digest-mismatch",
                               f"declared {declared_digest} != recomputed {actual}")
        return manifest

    def _declared_width(self, attribution: Mapping) -> int | None:
        width = attribution.get("coverage_vector_width")
        if not _is_int(width) or width < 0:
            self._rejector.add("coverage-vector-width-missing",
                               "the instrumented vector width is not declared")
            return None
        if width > self._max_ports:
            self._rejector.add("coverage-vector-too-wide",
                               f"{width} exceeds the bound {self._max_ports}")
            return None
        return int(width)

    def _declared_ports(self, attribution: Mapping) -> list[tuple[str, int]] | None:
        ports = _port_list(attribution.get("coverage_ports"))
        if ports is None:
            self._rejector.add("coverage-ports-missing",
                               "the exposed coverage-port list is missing or malformed")
            return None
        return ports

    def _declared_branch_ports(self, attribution: Mapping,
                               declared_ports: list[tuple[str, int]] | None,
                               width: int | None) -> list[tuple[str, int]] | None:
        declared = attribution.get("branch_coverage_ports")
        ports = _port_list(declared)
        if ports is None:
            self._rejector.add("branch-coverage-ports-invalid",
                               "the instrumented branch-port list is missing or malformed")
            return None
        if len(set(ports)) != len(ports):
            self._rejector.add("branch-coverage-ports-invalid",
                               "the instrumented branch-port list repeats a point")
            return None
        exposed = set(declared_ports) if declared_ports is not None else None
        for port, bit in ports:
            if width is not None and bit >= width:
                self._rejector.add("branch-bit-out-of-range",
                                   f"{port}[{bit}] >= declared width {width}")
            if exposed is not None and (port, bit) not in exposed:
                self._rejector.add("branch-port-not-in-coverage-ports",
                                   f"{port}[{bit}] is not exposed by the harness")
        return ports

    def _check_branch_kinds(self, attribution: Mapping, manifest: Mapping | None,
                            branch_ports: list[tuple[str, int]] | None) -> None:
        if not branch_ports:
            return
        kinds: dict[int, str] = {}
        manifest_kinds: dict[int, str] = {}
        if isinstance(manifest, Mapping):
            port = manifest.get("coverage_port")
            if port != attribution.get("coverage_port"):
                self._rejector.add("instrumentation-manifest-port-mismatch",
                                   f"manifest {port!r} vs declared "
                                   f"{attribution.get('coverage_port')!r}")
            width = attribution.get("coverage_vector_width")
            if manifest.get("coverage_vector_width") != width:
                self._rejector.add(
                    "instrumentation-manifest-width-mismatch",
                    f"manifest {manifest.get('coverage_vector_width')!r} vs declared "
                    f"{width!r}")
            bits = manifest.get("coverage_bits")
            if not isinstance(bits, list) or len(bits) != width:
                self._rejector.add("instrumentation-manifest-bits-invalid",
                                   "coverage_bits does not match the declared width")
            else:
                for item in bits:
                    if isinstance(item, Mapping) and _is_int(item.get("bit")):
                        manifest_kinds[int(item["bit"])] = str(item.get("kind", ""))
        declared_kinds = attribution.get("branch_point_kinds")
        if isinstance(declared_kinds, Mapping):
            for key, value in declared_kinds.items():
                try:
                    kinds[int(key)] = str(value)
                except (TypeError, ValueError):
                    continue
        for _, bit in branch_ports:
            from_manifest = manifest_kinds.get(bit)
            from_declaration = kinds.get(bit)
            if (from_manifest is not None and from_declaration is not None
                    and from_manifest != from_declaration):
                self._rejector.add("branch-point-kind-mismatch",
                                   f"bit {bit}: manifest {from_manifest!r} vs declared "
                                   f"{from_declaration!r}")
                continue
            kind = from_manifest if from_manifest is not None else from_declaration
            if kind is None:
                self._rejector.add("branch-point-kind-unverified",
                                   f"bit {bit} has no instrumentation point kind")
            elif kind not in BRANCH_POINT_KINDS:
                self._rejector.add("branch-bit-not-branch-kind",
                                   f"bit {bit} is a {kind!r} point, not a branch")

    def _check_tree(self, attribution: Mapping, root: Path | None) -> dict | None:
        record = {
            "attested": False,
            "level": "none",
            "instrumented_root": attribution.get("instrumented_root"),
            "instrumented_flist": attribution.get("instrumented_flist"),
            "instrumented_output_sha256": attribution.get("instrumented_output_sha256"),
            "instrumented_output_verified": False,
            "rtl_file_count": 0,
            "rtl_files_declared": False,
        }
        if root is None or not root.is_dir():
            self._rejector.add("instrumented-tree-unavailable",
                               "the instrumented tree is not present")
            return record
        declared_aggregate = attribution.get("instrumented_output_sha256")
        if not _valid_digest(declared_aggregate):
            self._rejector.add("instrumented-output-digest-invalid",
                               str(declared_aggregate))
        flist = attribution.get("instrumented_flist")
        if not isinstance(flist, str) or not flist:
            self._rejector.add("instrumented-flist-missing", "no instrumented source list")
            return record

        enumerated = _enumerate_inputs(root, self._rejector)
        if enumerated is None:
            return record

        declared_rows = attribution.get("rtl_files")
        declared: dict[str, str] | None = None
        if declared_rows is None and self._derive_rtl_files:
            declared = dict(enumerated)
        elif declared_rows is None:
            self._rejector.add("rtl-file-digests-missing",
                               "the instrumented RTL files carry no digests")
        elif not isinstance(declared_rows, (list, tuple)):
            self._rejector.add("rtl-file-digests-invalid",
                               "rtl_files is not a list of {path, sha256}")
        elif len(declared_rows) > MAX_RTL_FILES:
            self._rejector.add("rtl-file-digests-invalid",
                               f"more than {MAX_RTL_FILES} declared files")
        else:
            declared = {}
            valid = True
            for item in declared_rows:
                if not isinstance(item, Mapping) or not isinstance(item.get("path"), str):
                    self._rejector.add("rtl-file-digests-invalid",
                                       "a declared file has no path")
                    valid = False
                    continue
                digest = item.get("sha256")
                if not _valid_digest(digest):
                    self._rejector.add("rtl-file-digests-invalid",
                                       f"{item['path']} has no sha256 digest")
                    valid = False
                    continue
                declared[item["path"]] = digest
            if not valid:
                declared = None
        if declared is None:
            return record
        record["rtl_files_declared"] = declared_rows is not None
        record["rtl_file_count"] = len(declared)

        actual = dict(enumerated)
        for relative, digest in sorted(declared.items()):
            if relative not in actual:
                self._rejector.add("rtl-file-missing", relative)
            elif actual[relative] != digest:
                self._rejector.add("rtl-file-digest-mismatch", relative)
        missing = sorted(set(actual) - set(declared))
        if missing:
            self._rejector.add("rtl-file-closure-incomplete",
                               f"{len(missing)} runtime input(s) not declared, "
                               f"first: {missing[0]}")

        if _valid_digest(declared_aggregate):
            declared_root = attribution.get("instrumented_root")
            aliases = (declared_root,) if isinstance(declared_root, str) else ()
            try:
                recomputed = _aggregate_digest(root, Path(flist), aliases)
            except Exception as error:  # producer raises SocBuildError and friends
                self._rejector.add("instrumented-output-unverifiable", type(error).__name__)
            else:
                record["instrumented_output_verified"] = \
                    recomputed == declared_aggregate
                if not record["instrumented_output_verified"]:
                    self._rejector.add(
                        "instrumented-output-sha256-mismatch",
                        f"declared {declared_aggregate} != recomputed {recomputed}")
        record["attested"] = not self._rejector
        record["level"] = ("full" if record["rtl_files_declared"] else "aggregate-and-tree") \
            if record["attested"] else "none"
        return record

    # -- observation -------------------------------------------------------

    def _check_observation(self, attribution: Mapping,
                           declared_ports: list[tuple[str, int]] | None,
                           branch_ports: list[tuple[str, int]] | None) -> dict | None:
        observation = self._observation
        if not isinstance(observation, Mapping) or not observation:
            self._rejector.add("coverage-observation-missing",
                               "no coverage vector was supplied")
            return None
        encoding = attribution.get("encoding")
        if encoding not in ENCODINGS:
            self._rejector.add("coverage-encoding-unsupported", str(encoding))
            return None
        port = observation.get("coverage_port")
        if port != attribution.get("coverage_port"):
            self._rejector.add("coverage-port-observed-mismatch",
                               f"observed {port!r} vs declared "
                               f"{attribution.get('coverage_port')!r}")
        observed_ports = _port_list(observation.get("coverage_ports"))
        if observed_ports is None:
            self._rejector.add("coverage-ports-missing",
                               "the observed coverage-port list is missing or malformed")
            return None
        values = observation.get("counters")
        if values is None:
            values = observation.get("bits")
        if not isinstance(values, (list, tuple)):
            self._rejector.add("coverage-values-missing",
                               "the observed coverage values are not a list")
            return None
        if len(values) > self._max_ports:
            self._rejector.add("coverage-vector-too-wide",
                               f"{len(values)} exceeds the bound {self._max_ports}")
            return None
        if declared_ports is not None and observed_ports != declared_ports:
            self._rejector.add("coverage-port-observed-mismatch",
                               "the observed port list differs from the declared list")
        observed_set = set(observed_ports)
        for port, bit in branch_ports or []:
            if (port, bit) not in observed_set:
                self._rejector.add("branch-port-observed-missing",
                                   f"{port}[{bit}] is declared but was not read out")
        if len(values) != len(observed_ports):
            self._rejector.add("coverage-vector-width-mismatch",
                               f"{len(values)} values for {len(observed_ports)} ports")
            return None
        counter_max = attribution.get("counter_max", 255)
        if encoding == ENCODING_COUNTER:
            if not _is_int(counter_max) or not 1 <= counter_max <= 255:
                self._rejector.add("counter-max-invalid", str(counter_max))
                counter_max = 255
        for index, value in enumerate(values):
            if not _is_int(value):
                self._rejector.add("coverage-value-not-integer", f"index {index}")
            elif encoding == ENCODING_BIT and value not in (0, 1):
                self._rejector.add("coverage-value-not-binary",
                                   f"index {index} value {value}")
            elif encoding == ENCODING_COUNTER and not 0 <= value <= counter_max:
                self._rejector.add("coverage-value-out-of-range",
                                   f"index {index} value {value} > {counter_max}")
        if self._rejector:
            return None
        return {"ports": observed_ports, "counters": [int(v) for v in values],
                "encoding": encoding, "counter_max": counter_max,
                "first_seen": observation.get("first_seen")}

    def _check_first_seen(self, observed: dict | None,
                          branch_ports: list[tuple[str, int]] | None,
                          counters: list[int] | None) -> dict:
        unavailable = {"available": False, "points": 0, "entries": [],
                       "earliest": None,
                       "reason": "the artifact preserves no per-point first-seen evidence"}
        if observed is None or branch_ports is None or counters is None:
            return unavailable
        raw = observed.get("first_seen")
        if raw is None:
            return unavailable
        if not isinstance(raw, (list, tuple)):
            self._rejector.add("first-seen-invalid", "first_seen is not a list")
            return unavailable
        if len(raw) > MAX_FIRST_SEEN_ENTRIES:
            self._rejector.add("first-seen-invalid", "first_seen exceeds the bound")
            return unavailable
        if len(raw) != len(observed["ports"]):
            self._rejector.add("first-seen-length-mismatch",
                               f"{len(raw)} entries for {len(observed['ports'])} ports")
            return unavailable
        index_of = {point: index for index, point in enumerate(observed["ports"])}
        entries = []
        for port, bit in branch_ports:
            index = index_of.get((port, bit))
            if index is None or not counters[index]:
                continue
            entry = raw[index]
            if entry is None:
                continue
            if (not isinstance(entry, Mapping) or "event" not in entry
                    or not isinstance(entry.get("event"), (str, int))):
                self._rejector.add("first-seen-entry-invalid", f"{port}[{bit}]")
                continue
            time = entry.get("time")
            if time is not None and not isinstance(time, (int, float)):
                self._rejector.add("first-seen-entry-invalid", f"{port}[{bit}] time")
                continue
            entries.append({"bit": bit, "port": port, "event": entry["event"],
                            "time": time})
        for port, bit in branch_ports:
            index = index_of.get((port, bit))
            if index is None or counters[index]:
                continue
            if raw[index] is not None:
                self._rejector.add("first-seen-without-observation",
                                   f"{port}[{bit}] claims a first sighting but is dark")
        if self._rejector:
            return unavailable
        entries.sort(key=lambda item: (item["time"] is None, item["time"], item["bit"]))
        return {"available": True, "points": len(entries), "entries": entries,
                "earliest": entries[0] if entries else None, "reason": None}

    # -- port semantics ----------------------------------------------------

    def _port_semantics(self) -> _PortSemantics:
        targets = []
        for target in self._targets:
            if not isinstance(target, CoverageTarget):
                self._rejector.add("port-semantic-target-invalid",
                                   type(target).__name__)
                continue
            targets.append(target)
        branch_names = set()
        attribution = self._attribution
        if isinstance(attribution, Mapping):
            declared = _port_list(attribution.get("branch_coverage_ports")) or []
            branch_names = {name for name, _ in declared}
        permitted = []
        for target in targets:
            if target.port in branch_names:
                self._rejector.add(
                    "port-semantic-target-on-branch-port",
                    f"{target.target_id} targets instrumented port {target.port!r}")
                continue
            permitted.append(target)
        hits = observed_targets(self._events, tuple(permitted))
        lit_by_class: dict[str, int] = {}
        non_branch_lit = 0
        observation = self._observation
        if isinstance(observation, Mapping):
            ports = _port_list(observation.get("coverage_ports"))
            values = observation.get("counters")
            if values is None:
                values = observation.get("bits")
            branch_port_name = (attribution.get("coverage_port")
                                if isinstance(attribution, Mapping) else None)
            branch_port_name = branch_port_name or COVERAGE_PORT
            if ports is not None and isinstance(values, (list, tuple)) \
                    and len(ports) == len(values):
                for index, (name, _) in enumerate(ports):
                    if name == branch_port_name:
                        continue
                    value = values[index]
                    if _is_int(value) and value > 0:
                        non_branch_lit += 1
                        lit_by_class[name] = lit_by_class.get(name, 0) + 1
        return _PortSemantics(total_targets=len(targets), observed=len(hits),
                              non_branch_lit_ports=non_branch_lit,
                              lit_by_class={key: lit_by_class[key]
                                            for key in sorted(lit_by_class)},
                              targeted_ports=tuple(sorted(
                                  {target.port for target in permitted})))

    # -- documents ---------------------------------------------------------

    def _document_for(self, instrumenter, harness, identity,
                      semantics: _PortSemantics) -> dict:
        return self._compose(status=REJECTED, instrumenter=instrumenter,
                             harness=harness, identity=identity, manifest=None,
                             declared_ports=None, branch_ports=None, width=None,
                             encoding=None, counters=None, first_seen=None,
                             branch_points=None, observed=None,
                             semantics=semantics)

    def _verified_document(self, instrumenter, harness, identity, manifest,
                           declared_ports, branch_ports, width, encoding,
                           counters, first_seen,
                           semantics: _PortSemantics) -> dict:
        index_of = {point: index for index, point in enumerate(declared_ports or [])}
        lit = []
        kinds: dict[str, int] = {}
        manifest_kinds = {}
        if isinstance(manifest, Mapping) and isinstance(manifest.get("coverage_bits"), list):
            for item in manifest["coverage_bits"]:
                if isinstance(item, Mapping) and _is_int(item.get("bit")):
                    manifest_kinds[int(item["bit"])] = str(item.get("kind", ""))
        for port, bit in branch_ports or []:
            kind = manifest_kinds.get(bit, "unknown")
            kinds[kind] = kinds.get(kind, 0) + 1
            index = index_of.get((port, bit))
            if index is not None and counters and counters[index]:
                lit.append(bit)
        lit.sort()
        total = len(branch_ports or [])
        source_points = None
        if isinstance(manifest, Mapping) and _is_int(manifest.get("coverage_point_count")):
            source_points = int(manifest["coverage_point_count"])
        branch_points = {
            "coverage_port": self._attribution.get("coverage_port"),
            "instrumented_source_points": source_points,
            "declared_points": total,
            "declared_width": width,
            "kinds": {key: kinds[key] for key in sorted(kinds)},
        }
        observed = {
            "observed_points": len(lit),
            "total_points": total,
            "ratio": round(len(lit) / total, 12) if total else 0.0,
            "bit_indices": lit,
            "first_seen": first_seen,
        }
        return self._compose(status=VERIFIED, instrumenter=instrumenter,
                             harness=harness, identity=identity, manifest=manifest,
                             declared_ports=declared_ports, branch_ports=branch_ports,
                             width=width, encoding=encoding, counters=counters,
                             first_seen=first_seen, branch_points=branch_points,
                             observed=observed, semantics=semantics)

    def _compose(self, *, status, instrumenter, harness, identity, manifest,
                 declared_ports, branch_ports, width, encoding, counters,
                 first_seen, branch_points, observed,
                 semantics: _PortSemantics) -> dict:
        attribution = self._attribution if isinstance(self._attribution, Mapping) else {}
        manifest_digest = attribution.get("instrumentation_manifest_sha256")
        return {
            "schema_version": SCHEMA_VERSION,
            "status": status,
            "coverage_kind": ("source-instrumented-rtl-branch" if status == VERIFIED
                              else None),
            "instrumentation": {
                "instrumenter_schema_version": (instrumenter or {}).get("schema_version"),
                "instrumenter_source_sha256": (instrumenter or {}).get("source_sha256"),
                "instrumenter_source_verified": bool(
                    (instrumenter or {}).get("source_verified")),
                "instrumented_output_sha256": (identity or {}).get(
                    "instrumented_output_sha256"),
                "instrumented_output_verified": bool(
                    (identity or {}).get("instrumented_output_verified")),
                "rtl_file_count": (identity or {}).get("rtl_file_count", 0),
                "rtl_files_declared": bool((identity or {}).get("rtl_files_declared")),
                "instrumentation_manifest_sha256": manifest_digest,
                "manifest_verified": bool(manifest is not None and status == VERIFIED),
                "attested": status == VERIFIED,
                "level": (identity or {}).get("level", "none") if status == VERIFIED
                else "none",
            },
            "harness": dict(harness) if isinstance(harness, Mapping) else None,
            "vector": {
                "coverage_port": attribution.get("coverage_port"),
                "encoding": encoding,
                "declared_width": width,
                "exposed_ports": len(declared_ports or []),
                "monitored_branch_ports": len(branch_ports or []),
            },
            "branch_points": branch_points,
            "observed_branches": observed,
            "port_semantic_hits": semantics.to_document(),
            "separation": {
                "branch_coverage": (observed or {}).get("observed_points"),
                "port_semantic_hits": semantics.observed,
                "non_branch_lit_ports": semantics.non_branch_lit_ports,
                "combined": None,
                "sum_forbidden": True,
                "basis": ("instrumented RTL branch points and port semantic hits are "
                          "measured from different evidence and are never added"),
            },
            "rejections": self._rejector.document(),
            "rejection_counts": self._rejector.counts(),
            "bounds": {"max_ports": self._max_ports,
                       "max_rejections": self._max_rejections,
                       "max_rtl_files": MAX_RTL_FILES,
                       "max_rtl_file_bytes": MAX_RTL_FILE_BYTES},
        }
