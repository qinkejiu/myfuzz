"""Identity closure and fingerprint for the online decode space.

The session manifest answers "which sources did the executor run"; it does not
answer "which sources decided what the raw records mean".  A run whose legal
instruction operators, source ownership, candidate paths or decoder algorithm
changed produces *different cases from the same raw bytes* while every saved
artifact still matches its own digest.  This module makes that input set an
explicit, fingerprinted part of the run identity.

Closure rule
------------
A path belongs here when its bytes can change the decoded payload or the case
identity of one online record:

===============================================  =============================
``src/myfuzz/scenario/online_case_decoder.py``   the decode algorithm: path and
                                                 source selection, payload
                                                 entropy, case/action identity
``src/myfuzz/scenario/rv32i_sources.py``         the legal instruction/mutation
                                                 operator space (``decode_
                                                 instruction_fragment``)
``src/myfuzz/scenario/ibex_pulp_dual_source.py`` the concrete online decoder
                                                 declaration for this campaign:
                                                 sources, ownership map, MMIO
                                                 windows, schedule and budgets
``src/myfuzz/scenario/ownership.py``             ``compile_ownership`` decides
                                                 which input bits are fuzzable
``src/myfuzz/scenario/dependency.py``            source/rule declarations decide
                                                 candidate paths and directions
``src/myfuzz/scenario/genome.py``                ``DIRECTIONS`` and genome
                                                 semantics decide case identity
``src/myfuzz/scenario/rejection_codes.py``       decides which decoded candidates
                                                 are admitted or refused
``src/myfuzz/scenario/batch.py``                 the admitted source-event and
                                                 advance payload shape
``src/myfuzz/scenario/rfuzz_decoder.py``         ``_RuntimePathCache`` supplies
                                                 the decoder's path candidates
``src/myfuzz/scenario/runtime_path_contract.py`` the compiled path contract
                                                 decides which paths are admitted
``src/myfuzz/scenario/session_runtime.py``       ``OnlineCase``/``OnlineInstruction``
                                                 are the decoded value's own
                                                 validation
``src/myfuzz/scenario/source_actions.py``        the declared source action
                                                 derived from each decoded case
===============================================  =============================

The first ten are the decode implementation plus every ``myfuzz`` module it
imports directly: ``tests/integration/test_online_decode_space_identity.py``
re-derives that import set from ``online_case_decoder.py`` and fails when a new
direct dependency is not declared here.  ``ibex_pulp_dual_source.py`` is added
explicitly because it is the declaration that parameterises the decoder for
this campaign (the closure cannot see it as an import).  ``session_runtime.py``
and ``source_actions.py`` arrive through the decoder's own imports and are
listed for precise drift attribution; both are also members of the session
manifest closure.

Deliberately excluded: ``local_harness/*`` and the ``configs/**`` profiles feed
the RTL wiring, not decode -- the online decoder factory reads no file (it is
built from in-module constants), and the executor side is already bound by the
session manifest and the selected-template identities.  Checkers such as
``ibex_pulp_online_checker.py`` judge observed behaviour after the RTL ran and
are bound separately by the ``decoder_checker`` identity.

``cv32e40p_pulp_dual_source.py`` is the CV32E40P sibling of the declaration
module above and is *not* in this closure: the identity writer receives no
decoder object, so it cannot tell which campaign a bundle belongs to, and
adding the sibling would report -- and skip on -- that campaign's edits while
reproducing an Ibex run that they cannot affect.  Its declaration parameters
are still recorded in the saved ``decoder_manifest.json``; closing that gap
needs the claim to be per-run (a declaration source stamped by the decoder
factory, or the sibling added to the session closure in ``session_runtime``).

Backward compatibility
----------------------
``compare_online_decode_space`` never treats missing evidence as a mismatch.
A bundle recorded before this closure existed has no record, or a record with a
shorter file list; those paths are reported as ``unknown`` and the comparison
stays acceptable.  Only a path present on both sides with different bytes is
drift, and drift is the only state that refuses a replay.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType

_ROOT = Path(__file__).resolve().parents[3]

#: Schema of the ``decode_space`` member of ``scenario_online_run_identity.v1``.
ONLINE_DECODE_SPACE_SCHEMA_VERSION = "online_decode_space.v1"
#: Schema of one verification verdict, as attached to a verified identity.
ONLINE_DECODE_SPACE_COMPARISON_SCHEMA_VERSION = "online_decode_space_comparison.v1"

#: The recorded closure matches the current sources.
DECODE_SPACE_STATUS_VERIFIED = "verified"
#: The bundle does not record every current path (or records retired ones);
#: the unverified paths are named as ``unrecorded``/``retired`` -- never drift.
DECODE_SPACE_STATUS_UNKNOWN = "unknown"
#: At least one path is recorded by both sides with different bytes.
DECODE_SPACE_STATUS_DRIFT = "drift"

ONLINE_DECODE_SPACE_PATHS: tuple[str, ...] = (
    "src/myfuzz/scenario/online_case_decoder.py",
    "src/myfuzz/scenario/rv32i_sources.py",
    "src/myfuzz/scenario/ibex_pulp_dual_source.py",
    "src/myfuzz/scenario/ownership.py",
    "src/myfuzz/scenario/dependency.py",
    "src/myfuzz/scenario/genome.py",
    "src/myfuzz/scenario/rejection_codes.py",
    "src/myfuzz/scenario/batch.py",
    "src/myfuzz/scenario/rfuzz_decoder.py",
    "src/myfuzz/scenario/runtime_path_contract.py",
    "src/myfuzz/scenario/session_runtime.py",
    "src/myfuzz/scenario/source_actions.py",
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def online_decode_space_sources(*, root: Path | None = None,
                                ) -> tuple[dict[str, str], ...]:
    """Hash every declared decode-space source under ``root`` as ``{path, sha256}``."""
    base = _ROOT if root is None else Path(root)
    sources = []
    for name in ONLINE_DECODE_SPACE_PATHS:
        path = base / name
        if not path.is_file():
            raise ValueError(f"online decode space source is missing: {name}")
        sources.append({"path": name,
                        "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return tuple(sources)


def _complete_sources(sources: Mapping[str, str]) -> dict[str, str]:
    """Reject a partial override: a digest over an unnamed subset is not one."""
    missing = [name for name in ONLINE_DECODE_SPACE_PATHS if name not in sources]
    if missing:
        raise ValueError("online decode space sources are incomplete: "
                         + ", ".join(missing))
    return {name: sources[name] for name in ONLINE_DECODE_SPACE_PATHS}


def online_decode_space_sha256(*, root: Path | None = None,
                               sources: Mapping[str, str] | None = None) -> str:
    """Canonical digest of the decode-space closure bytes.

    The digest is taken over ``{"schema_version", "source_files"}`` so a record
    written by any caller is comparable byte for byte.  ``sources`` overrides
    the on-disk read (``{path: sha256}``) for callers replaying a saved tree and
    must name every declared path.
    """
    if sources is None:
        entries = [dict(item) for item in online_decode_space_sources(root=root)]
    else:
        entries = [{"path": name, "sha256": sources[name]}
                   for name in _complete_sources(sources)]
    return hashlib.sha256(_canonical({
        "schema_version": ONLINE_DECODE_SPACE_SCHEMA_VERSION,
        "source_files": entries})).hexdigest()


def online_decode_space_document(*, root: Path | None = None) -> dict:
    """The ``decode_space`` member a new run identity records."""
    sources = online_decode_space_sources(root=root)
    return {
        "schema_version": ONLINE_DECODE_SPACE_SCHEMA_VERSION,
        "sha256": online_decode_space_sha256(
            sources={item["path"]: item["sha256"] for item in sources}),
        "source_files": [dict(item) for item in sources],
    }


def recorded_decode_space(identity: object) -> object | None:
    """Return the ``decode_space`` member of a saved run identity, if it has one."""
    if not isinstance(identity, Mapping):
        return None
    return identity.get("decode_space")


def _recorded_source_map(recorded: object) -> tuple[dict[str, str], bool]:
    """Interpret a recorded closure; report whether it was usable at all."""
    if not isinstance(recorded, Mapping):
        return {}, False
    files = recorded.get("source_files")
    if not isinstance(files, (list, tuple)):
        return {}, False
    sources: dict[str, str] = {}
    for item in files:
        if (isinstance(item, Mapping) and isinstance(item.get("path"), str)
                and isinstance(item.get("sha256"), str)):
            sources[item["path"]] = item["sha256"]
    return sources, True


@dataclass(frozen=True)
class OnlineDecodeSpaceComparison:
    """One verdict for a recorded decode-space closure against the current tree.

    ``drifted`` is the only refusal: it names paths present on both sides whose
    bytes differ.  ``unrecorded`` and ``retired`` are explicit unknowns, kept so
    a legacy bundle is never presented as fully verified.
    """

    status: str
    recorded_present: bool
    recorded_sha256: str | None
    current_sha256: str
    drifted: tuple[str, ...]
    unrecorded: tuple[str, ...]
    retired: tuple[str, ...]
    recorded_shas: Mapping[str, str]
    current_shas: Mapping[str, str]

    @property
    def verified(self) -> bool:
        return self.status == DECODE_SPACE_STATUS_VERIFIED

    def document(self) -> dict:
        return {
            "schema_version": ONLINE_DECODE_SPACE_COMPARISON_SCHEMA_VERSION,
            "status": self.status,
            "recorded_present": self.recorded_present,
            "recorded_sha256": self.recorded_sha256,
            "current_sha256": self.current_sha256,
            "drifted": list(self.drifted),
            "unrecorded": list(self.unrecorded),
            "retired": list(self.retired),
        }

    def raise_for_drift(self) -> None:
        """Refuse a two-sided mismatch, naming every drifted file and both hashes."""
        if not self.drifted:
            return
        detail = ", ".join(
            f"{name} (recorded {self.recorded_shas[name][:12]}…, "
            f"current {self.current_shas[name][:12]}…)"
            for name in self.drifted)
        raise ValueError(
            "online decode space source identity mismatch: " + detail)


def compare_online_decode_space(recorded: object = None, *,
                                root: Path | None = None,
                                sources: Mapping[str, str] | None = None,
                                ) -> OnlineDecodeSpaceComparison:
    """Compare a recorded closure with the current decode space.

    ``recorded`` is the ``decode_space`` member of a saved identity (``None`` or
    any unusable value means the bundle predates the closure: everything is
    unknown, nothing is drift).  ``sources`` overrides the on-disk read for
    tests and for callers comparing two saved trees; it must name every
    declared path, so a partial override can never pass as a full comparison.
    """
    current = (_complete_sources(sources)
               if sources is not None
               else {item["path"]: item["sha256"]
                     for item in online_decode_space_sources(root=root)})
    recorded_sources, recorded_present = _recorded_source_map(recorded)
    drifted = tuple(sorted(name for name, digest in recorded_sources.items()
                           if name in current and current[name] != digest))
    unrecorded = tuple(sorted(name for name in current
                              if name not in recorded_sources))
    retired = tuple(sorted(name for name in recorded_sources
                           if name not in current))
    if drifted:
        status = DECODE_SPACE_STATUS_DRIFT
    elif unrecorded or retired or not recorded_present:
        status = DECODE_SPACE_STATUS_UNKNOWN
    else:
        status = DECODE_SPACE_STATUS_VERIFIED
    recorded_sha256 = (recorded.get("sha256")
                       if isinstance(recorded, Mapping)
                       and isinstance(recorded.get("sha256"), str) else None)
    return OnlineDecodeSpaceComparison(
        status=status, recorded_present=recorded_present,
        recorded_sha256=recorded_sha256,
        current_sha256=online_decode_space_sha256(sources=current),
        drifted=drifted, unrecorded=unrecorded, retired=retired,
        recorded_shas=MappingProxyType(dict(recorded_sources)),
        current_shas=MappingProxyType(dict(current)))
