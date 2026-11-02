"""Saved ``generic_runtime_bundle.v1`` evidence: writer and independent verifier.

The bundle is a directory of archived bytes.  Verification reconstructs every
claim from those bytes only: the mutable repository, a live ``PreparedTarget``,
a certified boolean or a stored summary is never consulted.  The same module
also writes bundles for the G6 integration, and refuses to publish one whose own
integrity check fails.

Directory layout
----------------

``bundle.json``
    Canonical JSON manifest (closed object)::

        {"schema_version": "generic_runtime_bundle.v1",
         "producer": {"id", "version", "implementation_sha256"},
         "preparation": {"compose", "capability_paths", "supplement", "flows"},
         "input_digests": {"d2", "d3"},
         "plan": {"schema_version", "document_sha256", "identity_sha256"},
         "source_closure_sha256": <digest>,
         "case_count": <int >= 1>,
         "exit_status": "closed" | "faulted" | "aborted",
         "fresh_of": null | <bundle id>,
         "normalized_identity_fields": [<exact field path>, ...],
         "files": [{"path": <bundle-relative>, "sha256": <digest>}, ...]}

    ``files`` covers every archived regular file except ``bundle.json`` itself,
    sorted by ``path``.  The manifest is stored as its own canonical bytes, so

    ``bundle_id == sha256(manifest bytes)``

    and a fresh bundle records its original through ``fresh_of``.

Documents
---------

``plan.json``
    Canonical ``generic_execution_plan.v1`` bytes.  In v1
    ``document_sha256 == identity_sha256 == sha256(plan.json)`` because
    ``GenericExecutionPlan`` derives its identity from exactly those bytes.
    Each ``components`` row must carry ``instance_id`` and ``artifact_sha256``
    (optionally ``source_sha256``/``profile_sha256``/``semantic_contract_sha256``
    which must then agree); each ``selections`` row must be an
    ``AdapterSelection`` document; each ``paths`` row must carry ``path_id``;
    each ``sources`` row must carry ``source_id``.  A ``sources`` row may also
    carry ``source_closure_sha256``, which must then equal the bundle closure.

``components.json``
    ``{"components": [VerifiedComponent.document(), ...]}``; every descriptor is
    re-validated as a ``VerifiedComponent`` (closed shape, canonical bytes,
    digests, endpoints).

``selections.json``
    ``{"selections": [AdapterSelection.document(), ...]}``.  The artifact
    digests of components and selections form a bijection, and every selection's
    ``semantic_contract_sha256`` must equal that of the component it selects.

``inputs.json``
    ``{"compose", "capability_paths", "supplement", "flows", "input_digests",
    "source_closure", "generated"}`` where ``source_closure`` is a list of
    ``{"path": "archive/...", "sha256"}`` sorted by ``path`` (bundle-relative
    archive copies, never repository paths) and ``generated`` is a list of
    ``{"instance_id", "files": {name: sha256}}`` sorted by ``instance_id``.
    Generated files that belong to no instance (for example
    ``generated/wiring_contract.json``) are archived and hashed by the manifest
    but do not appear in ``generated``.

``sources.json``
    ``{"source_closure_sha256", "files": [{"path": <repo-relative>,
    "archive_path": <bundle-relative>, "sha256"}, ...]}``.

    The closure digest is::

        sha256( archive_path + "\\0" + sha256 + "\\n"  for archive paths sorted )

    matching the G0 source-audit discipline.  It is recomputed from the archived
    copies only; a missing/mutated archive copy, a differing per-file hash or a
    differing closure digest is refused.

``cases.json``
    ``{"schema_version": "generic_case_sequence.v1", "plan_sha256", "cases":
    [{index, testcase_id, path_id, flow_id, source_id, raw_records_hex,
    instruction_sha256, receipt_sha256, certificate, version_chain:
    {before_sha256, after_sha256}}]}``.  ``cases`` is exactly ``0..N-1`` in
    order.  ``raw_records_hex`` entries are lowercase even-length hex strings of
    one uniform byte width (a trimmed record changes that width).

    The stored receipt is::

        receipt_sha256 == sha256(canonical({"schema_version":
            "generic_case_receipt.v1",
            "case": {case fields except receipt_sha256},
            "certificate": <certificate document>}))

    ``certificate`` is the flow's real per-case certificate document; it is
    opaque to this verifier but is sealed by the receipt.

``evidence.json``
    ``{"cases": [{"index", "evidence": [EffectEvidence.document(), ...]}]}``;
    one entry per case in order.

``events.json``
    The raw journal: a list of event objects.  Required keys are ``event_id``,
    ``component``, ``kind`` and ``provenance``; every other key is retained
    verbatim.  ``event_id`` is the acquisition counter: unique, strictly
    increasing in file order and contiguous from 0.  ``provenance`` is an
    object that carries ``case_id`` for archived evidence and may carry
    ``transaction`` (a full transaction key) and ``process``
    (``{"session", "pid", "nonce", "executable_sha256"?}``).

    Exactly three kinds are joined as evidence, one per proof layer:

    ==================  ===================  ===============================
    ref list            kind                 payload
    ==================  ===================  ===============================
    ``source_refs``     ``cpu_source_accept`` ``{"operation": "read"|"write",
                                              "address": int, "data": int}``
    ``native_refs``     ``apb_storage_probe`` ``{"write": bool, "wdata": int,
                                              "rdata": int, "be": int}``
    ``destination_refs`` ``ip_register_version`` ``{"phase": "before"|"after",
                                              "version": {...}}``
    ==================  ===================  ===============================

    v1 admits exactly one source sample, one native sample and one before/after
    pair per case (one effect edge per case), and no raw event and no evidence
    document may be reused: an ``event_id`` appears in at most one evidence ref
    of the whole bundle and a sealed ``EffectEvidence`` document appears in at
    most one case.

    A version document must carry ``register, value, write_count, reset_epoch,
    command_sequence`` and must not carry process identity (``pid``, ``nonce``,
    ``execution_id``); the stable projection is what a fresh replay must
    reproduce byte for byte.  A case's ``version_chain`` digests are
    ``sha256(canonical(version))`` over the archived documents.  Chain
    continuity compares the *state* projection (``schema_version, register,
    value, write_count, reset_epoch, field_version``): case *N*'s ``before``
    state must equal case *N-1*'s ``after`` state, while the volatile
    ``local_tick``/``command_sequence`` counters are re-issued per case and are
    checked as counters.  v1 admits exactly one before/after pair per case (one
    effect chain per case).

``processes.json``
    ``{"sessions": {name: {"pid", "nonce", "executable_sha256", "ready"}},
    "build_sha256", "binary_sha256"}``.  Every event that declares
    ``provenance.process`` or a ``build_sha256``/``binary_sha256`` payload fact
    must agree with this document; every declared session must actually appear,
    so the process identity set cannot change between cases.

``prefix.json`` / ``execution_audit.json``
    Raw saved flow documents.  They are hash-pinned and must be JSON objects;
    their internals are audited by the flow itself, not re-derived here.

Independence and limits
-----------------------

The verifier never reads the repository, a live handle, a native token or a
stored ``certified`` boolean.  The effective status of every case is derived
from ref resolution, counter continuity and version-chain facts; a stored status
that disagrees with the derived one is a refusal (an ``unsupported`` status is
never upgraded).  What the verifier cannot do is prove native authority or
anchor the closure externally: an attacker who rewrites source bytes, the
closure digest, the plan and every sealed document consistently forges an
alternative internally consistent run.  Fresh comparison (identical plan bytes,
identical accepted case sequence and instruction digests, new pid/nonce,
normalization limited to declared process/execution identity fields) is the
cross-run anchor, and ``runs/generic-runtime/G0/source-hashes.json`` is the
external baseline.
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from hashlib import sha256
from pathlib import Path, PurePosixPath

from myfuzz.runtime.contracts import (
    PLAN_SCHEMA,
    AdapterSelection,
    GenericExecutionPlan,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
    strict_json_loads,
)
from myfuzz.runtime.evidence.contracts import (
    STATUSES,
    EffectEvidence,
    EvidenceRef,
    combine_status,
)
from myfuzz.scenario.ledger import TransactionKey

BUNDLE_SCHEMA = "generic_runtime_bundle.v1"
CASE_SCHEMA = "generic_case_sequence.v1"
RECEIPT_SCHEMA = "generic_case_receipt.v1"
VERIFICATION_SCHEMA = "generic_runtime_saved_verification.v1"

BUNDLE_FILE = "bundle.json"
REQUIRED_DOCUMENTS = (
    "plan.json",
    "inputs.json",
    "components.json",
    "selections.json",
    "sources.json",
    "cases.json",
    "evidence.json",
    "events.json",
    "prefix.json",
    "execution_audit.json",
    "processes.json",
)
MANIFEST_KEYS = (
    "schema_version",
    "producer",
    "preparation",
    "input_digests",
    "plan",
    "source_closure_sha256",
    "case_count",
    "exit_status",
    "fresh_of",
    "normalized_identity_fields",
    "files",
)
PREPARATION_KEYS = ("compose", "capability_paths", "supplement", "flows")
INPUT_KEYS = ("compose", "capability_paths", "supplement", "flows",
              "input_digests", "source_closure", "generated")
PLAN_KEYS = ("schema_version", "document_sha256", "identity_sha256")
CASE_FIELDS = ("index", "testcase_id", "path_id", "flow_id", "source_id",
               "raw_records_hex", "instruction_sha256", "receipt_sha256",
               "certificate", "version_chain")
#: Real persistent runtimes issue one run-level testcase id while the sealed
#: certificate carries a distinct per-case id (``run:case``).  ``event_case_id``
#: records that per-case id; event provenance joins on it, while the evidence
#: transaction key keeps the run-level ``testcase_id``.  Bundles written from
#: pre-existing fixtures may omit it, in which case both ids are equal.
CASE_OPTIONAL_FIELDS = ("event_case_id",)
EVIDENCE_DOCUMENT_KEYS = ("key", "status", "scope", "binding_sha256",
                          "semantic_contract_sha256", "source_refs",
                          "native_refs", "destination_refs",
                          "obligation_results")
EXIT_STATUSES = ("closed", "faulted", "aborted")

#: Flow classes.  ``read`` flows may return only zeros and must not advance the
#: storage version; ``effect`` flows must advance ``write_count`` and must show
#: at least one nonzero and two distinct written values across the bundle (a
#: repeated *equal* write is legal, a bundle made only of one repeated value is
#: not evidence of effect variety).
FLOW_CLASSES = {"F2": "read", "F4": "effect"}

#: Kinds emitted by the real ScenarioRunner journal.  These have no per-event
#: process claim, so their owning process is resolved from the archived session
#: records by the event component (which is the session name for local harnesses).
REAL_RUNTIME_EVENT_KINDS = frozenset({
    "local_tick_sample", "mmio_acceptance", "mmio_delivery",
    "memory_read", "memory_write", "state_dependency",
    "transaction_request", "transaction_accept", "transaction_response",
    "instruction_source", "source_admission",
})

ARCHIVE_PREFIX = "archive/"
GENERATED_PREFIX = "generated/"

EVENT_REQUIRED = ("event_id", "component", "kind", "provenance")
EVENT_ROLES = {
    "source_refs": ("cpu_source_accept",),
    "native_refs": ("apb_storage_probe",),
    "destination_refs": ("ip_register_version",),
}
ROLE_PAYLOAD_KEYS = {
    "source_refs": ("operation", "address", "data"),
    "native_refs": ("write", "wdata", "rdata", "be"),
    "destination_refs": ("phase", "version"),
}
VERSION_KEYS = ("register", "value", "write_count", "reset_epoch",
                "command_sequence")
PROCESS_FORBIDDEN_VERSION_KEYS = frozenset({"pid", "nonce", "execution_id",
                                            "execution_nonce"})
PROCESS_FIELDS = ("pid", "nonce", "executable_sha256", "ready")

#: Normalized identity paths are limited to process identity and the run's
#: execution identity.  Everything else -- payload, source byte version, reset
#: ordering, evidence status, event presence -- is never normalizable.
IDENTITY_PATH_PREFIXES = ("processes/", "execution/")
IDENTITY_FIELD_NAMES = {
    "pid": ("pid",),
    "nonce": ("nonce", "execution_nonce"),
    "execution_id": ("execution_id",),
}
_PAYLOAD_NAME_HINTS = ("payload", "raw", "bytes", "value", "data", "wdata",
                       "rdata", "read_return", "write_data", "record",
                       "hex", "code")
_VERSION_NAME_HINTS = ("sha256", "digest", "archive_path", "path", "closure",
                       "version_chain", "identity")
_RESET_NAME_HINTS = ("reset", "epoch", "order", "sequence")
_STATUS_NAME_HINTS = ("status", "missing", "contradicted", "unsupported",
                      "certified", "events", "evidence", "version")

NORMALIZED_PLACEHOLDERS = {
    "pid": "<normalized:pid>",
    "nonce": "<normalized:nonce>",
    "execution_id": "<normalized:execution_id>",
}


class SavedBundleRefused(GenericRuntimeRefused):
    """Typed saved-evidence refusal carrying the checks completed so far."""

    checks: list = []

    def __init__(self, code: str, pointer: str = "", detail=None, *,
                 checks=None):
        super().__init__(code, pointer, detail)
        self.checks = list(checks or ())


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise SavedBundleRefused(code, pointer, detail)


def _canonical(value) -> bytes:
    return canonical_json_bytes(value)


def _digest_bytes(payload: bytes) -> str:
    return sha256(payload).hexdigest()


def _digest_value(value) -> str:
    return _digest_bytes(_canonical(value))


# ---------------------------------------------------------------------------
# primitive closed-shape checks
# ---------------------------------------------------------------------------
def _object(value, pointer: str, code: str) -> dict:
    if type(value) is not dict:
        _refuse(code, pointer, {"expected": "JSON object"})
    return value


def _text(value, pointer: str, code: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not value and not allow_empty):
        _refuse(code, pointer, {"expected": "nonempty string"})
    return value


def _integer(value, pointer: str, code: str, *, minimum: int = 0,
             maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (
            maximum is not None and value > maximum):
        detail = {"expected": "int", "minimum": minimum}
        if maximum is not None:
            detail["maximum"] = maximum
        _refuse(code, pointer, detail)
    return value


def _boolean(value, pointer: str, code: str) -> bool:
    if type(value) is not bool:
        _refuse(code, pointer, {"expected": "bool"})
    return value


def _digest(value, pointer: str, code: str) -> str:
    if type(value) is not str or len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value):
        _refuse(code, pointer, {"expected": "lowercase hex SHA-256"})
    return value


def _closed(value, required, pointer: str, code: str, optional=()) -> dict:
    rows = _object(value, pointer, code)
    required = tuple(required)
    optional = tuple(optional)
    missing = [name for name in required if name not in rows]
    extra = [name for name in rows
             if name not in required and name not in optional]
    if missing:
        _refuse(code, pointer + "/" + missing[0], {"reason": "missing-field"})
    if extra:
        _refuse(code, pointer + "/" + extra[0], {"reason": "unexpected-field"})
    return {name: rows[name] for name in (*required, *optional)
            if name in rows}


def _relpath(value, pointer: str, code: str, *, prefixes=()) -> str:
    """Bundle-relative POSIX relative path: no escape, no symlink bait."""
    if type(value) is not str or not value:
        _refuse(code, pointer, {"expected": "relative path"})
    if "\\" in value or "\x00" in value:
        _refuse(code, pointer, {"reason": "invalid-path-character"})
    parsed = PurePosixPath(value)
    if (parsed.is_absolute() or str(parsed) != value or ".." in parsed.parts
            or "." in parsed.parts):
        _refuse(code, pointer, {"reason": "relative-path-required"})
    if prefixes and not value.startswith(tuple(prefixes)):
        _refuse(code, pointer, {"expected_prefix": list(prefixes)})
    return value


def _hex_records(value, pointer: str) -> tuple[list[str], int]:
    if type(value) is not list or not value:
        _refuse("saved-case-records", pointer,
                {"expected": "nonempty list of hex records"})
    width = None
    for index, record in enumerate(value):
        item_pointer = f"{pointer}/{index}"
        if type(record) is not str or not record:
            _refuse("saved-case-records", item_pointer,
                    {"expected": "lowercase hex bytes"})
        if len(record) % 2 or any(
                character not in "0123456789abcdef" for character in record):
            _refuse("saved-case-records", item_pointer,
                    {"expected": "even-length lowercase hex"})
        if width is None:
            width = len(record)
        elif len(record) != width:
            _refuse("saved-case-records", item_pointer,
                    {"reason": "ragged-record-width", "expected": width})
    return [record for record in value], width // 2


def _transaction_key(value, pointer: str) -> TransactionKey:
    rows = _closed(
        value,
        ("execution_id", "testcase_id", "source_component", "source_epoch",
         "channel_id", "source_sequence"),
        pointer, "saved-evidence-contradicted")
    for name in ("execution_id", "testcase_id", "source_component",
                 "channel_id"):
        _text(rows[name], pointer + "/" + name, "saved-evidence-contradicted")
    for name in ("source_epoch", "source_sequence"):
        _integer(rows[name], pointer + "/" + name,
                 "saved-evidence-contradicted")
    try:
        return TransactionKey(rows["execution_id"], rows["testcase_id"],
                              rows["source_component"],
                              rows["source_epoch"], rows["channel_id"],
                              rows["source_sequence"])
    except ValueError as error:
        _refuse("saved-evidence-contradicted", pointer,
                {"reason": str(error)[:120]})


def transaction_document(key: TransactionKey) -> dict:
    """Documentary transaction key, identical to ``EffectEvidence.document``."""
    return {"execution_id": key.execution_id,
            "testcase_id": key.testcase_id,
            "source_component": key.source_component,
            "source_epoch": key.source_epoch,
            "channel_id": key.channel_id,
            "source_sequence": key.source_sequence}


def parse_evidence_ref(document, *, pointer: str = "") -> EvidenceRef:
    rows = _closed(document, ("component", "event_id", "kind"), pointer,
                   "saved-evidence-shape")
    _text(rows["component"], pointer + "/component", "saved-evidence-shape")
    _text(rows["kind"], pointer + "/kind", "saved-evidence-shape")
    _integer(rows["event_id"], pointer + "/event_id", "saved-evidence-shape")
    return EvidenceRef(rows["component"], rows["event_id"], rows["kind"])


def parse_effect_evidence(document, *, pointer: str = "") -> EffectEvidence:
    """Shared saved/live schema for evidence documents (no authority implied)."""
    rows = _closed(document, EVIDENCE_DOCUMENT_KEYS, pointer,
                   "saved-evidence-shape")
    key = _transaction_key(rows["key"], pointer + "/key")
    for name in ("status", "scope"):
        _text(rows[name], pointer + "/" + name, "saved-evidence-shape")
    for name in ("binding_sha256", "semantic_contract_sha256"):
        _digest(rows[name], pointer + "/" + name, "saved-evidence-shape")
    groups = []
    for name in ("source_refs", "native_refs", "destination_refs"):
        refs = rows[name]
        if type(refs) is not list:
            _refuse("saved-evidence-shape", pointer + "/" + name,
                    {"expected": "list of evidence refs"})
        groups.append(tuple(
            parse_evidence_ref(ref, pointer=f"{pointer}/{name}/{index}")
            for index, ref in enumerate(refs)))
    obligations = rows["obligation_results"]
    if type(obligations) is not list:
        _refuse("saved-evidence-shape", pointer + "/obligation_results",
                {"expected": "list of (name, status)"})
    pairs = []
    for index, row in enumerate(obligations):
        row_pointer = f"{pointer}/obligation_results/{index}"
        if type(row) is not list or len(row) != 2:
            _refuse("saved-evidence-shape", row_pointer,
                    {"expected": "[name, status]"})
        name, status = row
        _text(name, row_pointer + "/0", "saved-evidence-shape")
        if type(status) is not str or status not in STATUSES:
            _refuse("saved-evidence-shape", row_pointer + "/1",
                    {"allowed": list(STATUSES)})
        pairs.append((name, status))
    try:
        return EffectEvidence(key, rows["status"], rows["scope"],
                             rows["binding_sha256"],
                             rows["semantic_contract_sha256"], groups[0],
                             groups[1], groups[2], tuple(pairs))
    except SavedBundleRefused:
        raise
    except GenericRuntimeRefused as error:
        _refuse("saved-evidence-shape", pointer, error.document())


# ---------------------------------------------------------------------------
# exported helpers the producer/director and the writer share
# ---------------------------------------------------------------------------
#: Version facts that carry over from one case's ``after`` to the next case's
#: ``before``.  Volatile, process-local counters (``local_tick``,
#: ``command_sequence``) are re-issued every case and stay out of the state
#: projection; they are checked as counters instead.
CHAIN_STATE_KEYS = ("schema_version", "register", "value", "write_count",
                    "reset_epoch", "field_version")


def version_sha256(version_document) -> str:
    """Byte-exact digest of one archived version document."""
    return _digest_value(version_document)


def _version_state(version_document) -> dict:
    if type(version_document) is not dict:
        _refuse("saved-version-chain-break", "/version_chain",
                {"expected": "version document"})
    return {name: version_document[name] for name in CHAIN_STATE_KEYS
            if name in version_document}


def version_state_sha256(version_document) -> str:
    """Stable storage-state digest; equal across a persisted case boundary."""
    return _digest_value(_version_state(version_document))


def source_closure_sha256(entries) -> str:
    """Closure digest over ``(archive_path, sha256)`` pairs, G0 discipline."""
    rows = []
    for entry in entries:
        if type(entry) in (tuple, list) and len(entry) == 2:
            path, digest = entry
        elif type(entry) is dict:
            path, digest = entry.get("path"), entry.get("sha256")
        else:
            _refuse("saved-source-closure-mismatch", "/source_closure",
                    {"expected": "archive path and sha256"})
        rows.append((_relpath(path, "/source_closure",
                              "saved-source-closure-mismatch",
                              prefixes=(ARCHIVE_PREFIX,)), digest))
    combined = sha256()
    for path, digest in sorted(rows):
        _digest(digest, "/source_closure", "saved-source-closure-mismatch")
        combined.update(path.encode("utf-8"))
        combined.update(b"\0")
        combined.update(digest.encode("ascii"))
        combined.update(b"\n")
    return combined.hexdigest()


def receipt_document(case, *, certificate=None) -> dict:
    """Closed receipt document sealing one case and its flow certificate."""
    if type(case) is not dict:
        _refuse("saved-case-shape", "/receipt/case",
                {"expected": "JSON object"})
    extra = [name for name in case
             if name not in CASE_FIELDS and name not in CASE_OPTIONAL_FIELDS]
    if extra:
        _refuse("saved-case-shape", "/receipt/case/" + extra[0],
                {"reason": "unexpected-field"})
    document = {}
    for name in (*CASE_FIELDS, *CASE_OPTIONAL_FIELDS):
        if name == "receipt_sha256":
            continue
        if name not in case:
            if name in CASE_OPTIONAL_FIELDS:
                continue
            _refuse("saved-case-shape", "/receipt/case/" + name,
                    {"reason": "missing-field"})
        document[name] = case[name]
    if certificate is not None:
        document["certificate"] = certificate
    return {"schema_version": RECEIPT_SCHEMA, "case": document,
            "certificate": document["certificate"]}


def case_receipt_sha256(case) -> str:
    """``receipt_sha256`` a producer must store for this case document."""
    return _digest_value(receipt_document(case))


def bundle_id(manifest_document) -> str:
    """Bundle identity: digest of the canonical manifest bytes."""
    return _digest_value(manifest_document)


def normalize_identity(document, rules):
    """Copy ``document`` replacing only declared identity field values.

    ``rules`` is a sequence of ``(field_names, existing_value, placeholder)``.
    Only an object member whose *key* is one of the declared identity field
    names is replaced, so payload bytes that happen to contain the same value
    are never rewritten.
    """
    if type(document) is dict:
        result = {}
        for key, item in document.items():
            replacement = None
            for names, existing, placeholder in rules:
                if key in names and type(item) is type(existing) and \
                        item == existing:
                    replacement = placeholder
                    break
            result[key] = (replacement if replacement is not None
                           else normalize_identity(item, rules))
        return result
    if type(document) is list:
        return [normalize_identity(item, rules) for item in document]
    return document


# ---------------------------------------------------------------------------
# bundle loading
# ---------------------------------------------------------------------------
class _Checks:
    def __init__(self, label: str = ""):
        self.label = label
        self.rows: list[dict] = []

    def add(self, name: str, **detail) -> None:
        row = {"name": (f"{self.label}.{name}" if self.label else name),
               "status": "verified"}
        if detail:
            row["detail"] = detail
        self.rows.append(row)


def _read_bytes(path: Path, pointer: str) -> bytes:
    if path.is_symlink():
        _refuse("saved-bundle-symlink", pointer, {"reason": "symlink"})
    if not path.exists():
        _refuse("saved-bundle-missing-file", pointer,
                {"reason": "missing-file"})
    if not path.is_file():
        _refuse("saved-bundle-unreadable-file", pointer,
                {"reason": "not-a-regular-file"})
    try:
        return path.read_bytes()
    except OSError as error:
        _refuse("saved-bundle-unreadable-file", pointer,
                {"reason": type(error).__name__})


def _parse_json(raw: bytes, pointer: str, code: str):
    try:
        return strict_json_loads(raw, pointer=pointer)
    except GenericRuntimeRefused as error:
        _refuse(code, pointer, error.detail)


def _locate(bundle_dir) -> Path:
    root = Path(bundle_dir)
    if root.is_symlink():
        _refuse("saved-bundle-symlink", str(root), {"reason": "symlink"})
    if not root.exists():
        _refuse("saved-bundle-missing", str(root),
                {"reason": "bundle-directory-missing"})
    if not root.is_dir():
        _refuse("saved-bundle-missing", str(root),
                {"reason": "bundle-directory-required"})
    try:
        os.listdir(root)
    except OSError as error:
        _refuse("saved-bundle-unreadable", str(root),
                {"reason": type(error).__name__})
    return root


def _scan_files(root: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    stack = [root]
    while stack:
        directory = stack.pop()
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            _refuse("saved-bundle-unreadable", str(directory),
                    {"reason": type(error).__name__})
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if entry.is_symlink():
                _refuse("saved-bundle-symlink", "/files/" + relative,
                        {"reason": "symlink"})
            if entry.is_dir(follow_symlinks=False):
                stack.append(path)
            elif entry.is_file(follow_symlinks=False):
                found[relative] = path
            else:
                _refuse("saved-bundle-unreadable-file", "/files/" + relative,
                        {"reason": "not-a-regular-file"})
    return found


def _parse_manifest(root: Path) -> tuple[dict, bytes, str]:
    raw = _read_bytes(root / BUNDLE_FILE, "/" + BUNDLE_FILE)
    document = _parse_json(raw, "/" + BUNDLE_FILE, "saved-bundle-manifest")
    rows = _closed(document, MANIFEST_KEYS, "/" + BUNDLE_FILE,
                   "saved-bundle-manifest")
    if rows["schema_version"] != BUNDLE_SCHEMA:
        _refuse("saved-bundle-manifest", "/bundle.json/schema_version",
                {"expected": BUNDLE_SCHEMA})
    producer = _closed(rows["producer"], ("id", "version",
                                          "implementation_sha256"),
                       "/bundle.json/producer", "saved-bundle-manifest")
    _text(producer["id"], "/bundle.json/producer/id", "saved-bundle-manifest")
    _text(producer["version"], "/bundle.json/producer/version",
          "saved-bundle-manifest")
    _digest(producer["implementation_sha256"],
            "/bundle.json/producer/implementation_sha256",
            "saved-bundle-manifest")
    preparation = _closed(rows["preparation"], PREPARATION_KEYS,
                          "/bundle.json/preparation", "saved-bundle-manifest")
    _relpath(preparation["compose"], "/bundle.json/preparation/compose",
             "saved-bundle-manifest")
    _relpath(preparation["supplement"],
             "/bundle.json/preparation/supplement", "saved-bundle-manifest")
    capabilities = preparation["capability_paths"]
    if type(capabilities) is not list or not capabilities:
        _refuse("saved-bundle-manifest",
                "/bundle.json/preparation/capability_paths",
                {"expected": "nonempty list"})
    for index, capability in enumerate(capabilities):
        _relpath(capability,
                 f"/bundle.json/preparation/capability_paths/{index}",
                 "saved-bundle-manifest")
    flows = preparation["flows"]
    if type(flows) is not list or not flows:
        _refuse("saved-bundle-manifest", "/bundle.json/preparation/flows",
                {"expected": "nonempty list"})
    for index, flow in enumerate(flows):
        _text(flow, f"/bundle.json/preparation/flows/{index}",
              "saved-bundle-manifest")
        if flow not in FLOW_CLASSES:
            _refuse("saved-bundle-manifest",
                    f"/bundle.json/preparation/flows/{index}",
                    {"allowed": sorted(FLOW_CLASSES)})
    if len(set(flows)) != len(flows):
        _refuse("saved-bundle-manifest", "/bundle.json/preparation/flows",
                {"reason": "duplicate-flow"})
    digests = _closed(rows["input_digests"], ("d2", "d3"),
                      "/bundle.json/input_digests", "saved-bundle-manifest")
    for name in ("d2", "d3"):
        _digest(digests[name], "/bundle.json/input_digests/" + name,
                "saved-bundle-manifest")
    plan = _closed(rows["plan"], PLAN_KEYS, "/bundle.json/plan",
                   "saved-bundle-manifest")
    if plan["schema_version"] != PLAN_SCHEMA:
        _refuse("saved-bundle-manifest", "/bundle.json/plan/schema_version",
                {"expected": PLAN_SCHEMA})
    _digest(plan["document_sha256"], "/bundle.json/plan/document_sha256",
            "saved-bundle-manifest")
    _digest(plan["identity_sha256"], "/bundle.json/plan/identity_sha256",
            "saved-bundle-manifest")
    _digest(rows["source_closure_sha256"],
            "/bundle.json/source_closure_sha256", "saved-bundle-manifest")
    _integer(rows["case_count"], "/bundle.json/case_count",
             "saved-bundle-manifest", minimum=1)
    if rows["exit_status"] not in EXIT_STATUSES:
        _refuse("saved-bundle-manifest", "/bundle.json/exit_status",
                {"allowed": list(EXIT_STATUSES)})
    if rows["fresh_of"] is not None:
        _digest(rows["fresh_of"], "/bundle.json/fresh_of",
                "saved-bundle-manifest")
    fields = rows["normalized_identity_fields"]
    if type(fields) is not list or any(type(item) is not str for item in fields):
        _refuse("saved-bundle-manifest",
                "/bundle.json/normalized_identity_fields",
                {"expected": "list of field paths"})
    if list(fields) != sorted(set(fields)):
        _refuse("saved-bundle-manifest",
                "/bundle.json/normalized_identity_fields",
                {"expected": "unique, lexicographically sorted"})
    files = rows["files"]
    if type(files) is not list or not files:
        _refuse("saved-bundle-manifest", "/bundle.json/files",
                {"expected": "nonempty list"})
    declared: dict[str, str] = {}
    for index, entry in enumerate(files):
        pointer = f"/bundle.json/files/{index}"
        row = _closed(entry, ("path", "sha256"), pointer,
                      "saved-bundle-manifest")
        path = _relpath(row["path"], pointer + "/path",
                        "saved-bundle-manifest")
        if path == BUNDLE_FILE:
            _refuse("saved-bundle-manifest", pointer + "/path",
                    {"reason": "manifest-cannot-archive-itself"})
        if path in declared:
            _refuse("saved-bundle-manifest", pointer + "/path",
                    {"reason": "duplicate-path"})
        declared[path] = _digest(row["sha256"], pointer + "/sha256",
                                 "saved-bundle-manifest")
    if list(declared) != sorted(declared):
        _refuse("saved-bundle-manifest", "/bundle.json/files",
                {"expected": "sorted by path"})
    manifest = {
        "schema_version": rows["schema_version"],
        "producer": producer,
        "preparation": {"compose": preparation["compose"],
                        "capability_paths": list(capabilities),
                        "supplement": preparation["supplement"],
                        "flows": list(flows)},
        "input_digests": dict(digests),
        "plan": dict(plan),
        "source_closure_sha256": rows["source_closure_sha256"],
        "case_count": rows["case_count"],
        "exit_status": rows["exit_status"],
        "fresh_of": rows["fresh_of"],
        "normalized_identity_fields": list(fields),
        "files": declared,
    }
    if _canonical(document) != raw:
        _refuse("saved-bundle-manifest", "/" + BUNDLE_FILE,
                {"expected": "canonical JSON bytes"})
    return manifest, raw, _digest_bytes(raw)


def _check_files(root: Path, manifest: dict, checks: _Checks) -> dict[str, Path]:
    declared = manifest["files"]
    root_resolved = root.resolve()
    paths: dict[str, Path] = {}
    for index, (relative, digest) in enumerate(declared.items()):
        pointer = f"/bundle.json/files/{index}/sha256"
        path = root / relative
        if not path.exists():
            _refuse("saved-bundle-missing-file", pointer,
                    {"path": relative, "reason": "archived-file-missing"})
        if path.is_symlink():
            _refuse("saved-bundle-symlink", pointer,
                    {"path": relative, "reason": "symlink"})
        if not path.is_file():
            _refuse("saved-bundle-unreadable-file", pointer,
                    {"path": relative, "reason": "not-a-regular-file"})
        if not path.resolve().is_relative_to(root_resolved):
            _refuse("saved-bundle-escape", pointer,
                    {"path": relative, "reason": "outside-bundle"})
        actual = _digest_bytes(_read_bytes(path, pointer))
        if actual != digest:
            _refuse("saved-bundle-hash-mismatch", pointer,
                    {"path": relative})
        paths[relative] = path
    for relative in _scan_files(root):
        if relative == BUNDLE_FILE:
            continue
        if relative not in declared:
            _refuse("saved-bundle-extra-file", "/files/" + relative,
                    {"reason": "not-in-manifest"})
    for document in REQUIRED_DOCUMENTS:
        if document not in declared:
            _refuse("saved-bundle-missing-file", "/bundle.json/files",
                    {"document": document, "reason": "required-document"})
    checks.add("files-closed-and-hashed", count=len(declared),
               required_documents=len(REQUIRED_DOCUMENTS))
    return paths


def _document(paths: dict[str, Path], name: str, checks: _Checks = None):
    raw = _read_bytes(paths[name], "/" + name)
    return _parse_json(raw, "/" + name, "saved-bundle-document")


# ---------------------------------------------------------------------------
# per-document checks
# ---------------------------------------------------------------------------
def _check_plan(paths, manifest, checks) -> GenericExecutionPlan:
    raw = _read_bytes(paths["plan.json"], "/plan.json")
    document = _parse_json(raw, "/plan.json", "saved-plan-invalid")
    if _canonical(document) != raw:
        _refuse("saved-plan-not-canonical", "/plan.json",
                {"expected": "canonical generic_execution_plan.v1 bytes"})
    actual = _digest_bytes(raw)
    declared = manifest["plan"]
    if (declared["document_sha256"] != actual
            or declared["identity_sha256"] != actual):
        _refuse("saved-plan-identity-mismatch", "/bundle.json/plan",
                {"reason": "manifest-digest-differs-from-plan-bytes"})
    try:
        plan = GenericExecutionPlan(PLAN_SCHEMA, raw, declared["identity_sha256"])
    except GenericRuntimeRefused as error:
        _refuse("saved-plan-invalid", "/plan.json", error.document())
    if document.get("schema_version") != declared["schema_version"]:
        _refuse("saved-plan-identity-mismatch",
                "/bundle.json/plan/schema_version")
    checks.add("plan-canonical-and-identified",
               identity_sha256=plan.identity_sha256)
    return plan


def _check_inputs(paths, manifest, checks) -> dict:
    rows = _closed(_document(paths, "inputs.json"), INPUT_KEYS, "/inputs.json",
                   "saved-bundle-document")
    _relpath(rows["compose"], "/inputs.json/compose", "saved-bundle-document")
    _relpath(rows["supplement"], "/inputs.json/supplement",
             "saved-bundle-document")
    capabilities = rows["capability_paths"]
    if type(capabilities) is not list or not capabilities:
        _refuse("saved-bundle-document", "/inputs.json/capability_paths",
                {"expected": "nonempty list"})
    for index, capability in enumerate(capabilities):
        _relpath(capability, f"/inputs.json/capability_paths/{index}",
                 "saved-bundle-document")
    flows = rows["flows"]
    if type(flows) is not list or not flows or len(set(flows)) != len(flows):
        _refuse("saved-bundle-document", "/inputs.json/flows",
                {"expected": "nonempty unique list"})
    for index, flow in enumerate(flows):
        if flow not in FLOW_CLASSES:
            _refuse("saved-bundle-document", f"/inputs.json/flows/{index}",
                    {"allowed": sorted(FLOW_CLASSES)})
    digests = _closed(rows["input_digests"], ("d2", "d3"),
                      "/inputs.json/input_digests", "saved-bundle-document")
    for name in ("d2", "d3"):
        _digest(digests[name], "/inputs.json/input_digests/" + name,
                "saved-bundle-document")
    if digests != manifest["input_digests"]:
        _refuse("saved-input-digest-mismatch", "/inputs.json/input_digests",
                {"reason": "manifest-and-inputs-disagree"})
    closure = rows["source_closure"]
    if type(closure) is not list or not closure:
        _refuse("saved-source-closure-mismatch", "/inputs.json/source_closure",
                {"expected": "nonempty list"})
    parsed_closure: list[dict] = []
    for index, entry in enumerate(closure):
        pointer = f"/inputs.json/source_closure/{index}"
        row = _closed(entry, ("path", "sha256"), pointer,
                      "saved-source-closure-mismatch")
        path = _relpath(row["path"], pointer + "/path",
                        "saved-source-closure-mismatch",
                        prefixes=(ARCHIVE_PREFIX,))
        digest = _digest(row["sha256"], pointer + "/sha256",
                         "saved-source-closure-mismatch")
        parsed_closure.append({"path": path, "sha256": digest})
    if [row["path"] for row in parsed_closure] != sorted(
            row["path"] for row in parsed_closure):
        _refuse("saved-source-closure-mismatch",
                "/inputs.json/source_closure", {"expected": "sorted by path"})
    if len({row["path"] for row in parsed_closure}) != len(parsed_closure):
        _refuse("saved-source-closure-mismatch",
                "/inputs.json/source_closure", {"reason": "duplicate-path"})
    generated = rows["generated"]
    if type(generated) is not list:
        _refuse("saved-generated-mismatch", "/inputs.json/generated",
                {"expected": "list"})
    parsed_generated: list[dict] = []
    for index, entry in enumerate(generated):
        pointer = f"/inputs.json/generated/{index}"
        row = _closed(entry, ("instance_id", "files"), pointer,
                      "saved-generated-mismatch")
        instance = _text(row["instance_id"], pointer + "/instance_id",
                         "saved-generated-mismatch")
        files = row["files"]
        if type(files) is not dict or not files:
            _refuse("saved-generated-mismatch", pointer + "/files",
                    {"expected": "nonempty name->sha256 object"})
        hashes = {}
        for name, digest in files.items():
            _relpath(name, pointer + "/files/" + name,
                     "saved-generated-mismatch")
            hashes[name] = _digest(digest, pointer + "/files/" + name,
                                   "saved-generated-mismatch")
        parsed_generated.append({"instance_id": instance, "files": hashes})
    instances = [row["instance_id"] for row in parsed_generated]
    if instances != sorted(instances):
        _refuse("saved-generated-mismatch", "/inputs.json/generated",
                {"expected": "sorted by instance_id"})
    if len(set(instances)) != len(instances):
        _refuse("saved-generated-mismatch", "/inputs.json/generated",
                {"reason": "duplicate-instance"})
    out = {"compose": rows["compose"],
           "capability_paths": list(capabilities),
           "supplement": rows["supplement"],
           "flows": list(flows),
           "input_digests": dict(digests),
           "source_closure": parsed_closure,
           "generated": parsed_generated}
    if out["compose"] != manifest["preparation"]["compose"] or \
            out["capability_paths"] != manifest["preparation"][
                "capability_paths"] or \
            out["supplement"] != manifest["preparation"]["supplement"] or \
            out["flows"] != manifest["preparation"]["flows"]:
        _refuse("saved-preparation-mismatch", "/inputs.json",
                {"reason": "manifest-and-inputs-disagree"})
    checks.add("preparation-and-input-digests",
               d2=digests["d2"], d3=digests["d3"])
    return out


def _check_components(paths, checks) -> tuple[VerifiedComponent, ...]:
    rows = _closed(_document(paths, "components.json"), ("components",),
                   "/components.json", "saved-component-mismatch")
    entries = rows["components"]
    if type(entries) is not list or not entries:
        _refuse("saved-component-mismatch", "/components.json/components",
                {"expected": "nonempty list"})
    components: list[VerifiedComponent] = []
    instance_ids = set()
    artifact_digests = set()
    for index, entry in enumerate(entries):
        pointer = f"/components.json/components/{index}"
        document = _object(entry, pointer, "saved-component-mismatch")
        try:
            frozen = _canonical(document)
            rows_ = _closed(document,
                            ("schema_version", "instance_id", "source_sha256",
                             "profile_sha256", "artifact_sha256",
                             "semantic_contract_sha256", "source_verifier",
                             "endpoints"),
                            pointer, "saved-component-mismatch")
            component = VerifiedComponent(
                rows_["instance_id"], rows_["source_sha256"],
                rows_["profile_sha256"], rows_["artifact_sha256"],
                rows_["semantic_contract_sha256"], frozen)
        except SavedBundleRefused:
            raise
        except GenericRuntimeRefused as error:
            _refuse("saved-component-mismatch", pointer, error.document())
        if component.instance_id in instance_ids:
            _refuse("saved-component-mismatch", pointer + "/instance_id",
                    {"reason": "duplicate-instance"})
        if component.artifact_sha256 in artifact_digests:
            _refuse("saved-component-mismatch", pointer + "/artifact_sha256",
                    {"reason": "duplicate-artifact-digest"})
        instance_ids.add(component.instance_id)
        artifact_digests.add(component.artifact_sha256)
        components.append(component)
    checks.add("components-revalidated", count=len(components))
    return tuple(components)


def _check_selections(paths, components, checks) -> tuple[AdapterSelection, ...]:
    rows = _closed(_document(paths, "selections.json"), ("selections",),
                   "/selections.json", "saved-selection-mismatch")
    entries = rows["selections"]
    if type(entries) is not list or not entries:
        _refuse("saved-selection-mismatch", "/selections.json/selections",
                {"expected": "nonempty list"})
    selections: list[AdapterSelection] = []
    seen = set()
    for index, entry in enumerate(entries):
        pointer = f"/selections.json/selections/{index}"
        document = _closed(entry, ("adapter_id", "adapter_version",
                                   "implementation_sha256",
                                   "component_artifact_sha256",
                                   "semantic_contract_sha256"), pointer,
                           "saved-selection-mismatch")
        try:
            selection = AdapterSelection(
                document["adapter_id"], document["adapter_version"],
                document["implementation_sha256"],
                document["component_artifact_sha256"],
                document["semantic_contract_sha256"])
        except GenericRuntimeRefused as error:
            _refuse("saved-selection-mismatch", pointer, error.document())
        if selection.canonical_bytes() in seen:
            _refuse("saved-selection-mismatch", pointer,
                    {"reason": "duplicate-selection"})
        seen.add(selection.canonical_bytes())
        selections.append(selection)
    selection_artifacts = {row.component_artifact_sha256
                           for row in selections}
    component_artifacts = {row.artifact_sha256 for row in components}
    if selection_artifacts != component_artifacts:
        _refuse("saved-selection-mismatch", "/selections.json/selections",
                {"reason": "component-coverage"})
    for selection in selections:
        matches = [component for component in components
                   if component.artifact_sha256
                   == selection.component_artifact_sha256]
        if any(component.semantic_contract_sha256
               != selection.semantic_contract_sha256 for component in matches):
            _refuse("saved-selection-mismatch", "/selections.json/selections",
                    {"reason": "semantic-contract-mismatch",
                     "adapter_id": selection.adapter_id})
    checks.add("selections-joined-to-components", count=len(selections))
    return tuple(selections)


def _check_plan_references(plan, components, selections, inputs, checks) -> dict:
    document = plan.document()
    component_rows = document["components"]
    if not component_rows:
        _refuse("saved-component-mismatch", "/plan.json/components",
                {"reason": "plan-declares-no-component"})
    referenced: dict[str, dict] = {}
    for index, row in enumerate(component_rows):
        pointer = f"/plan.json/components/{index}"
        row = _object(row, pointer, "saved-component-mismatch")
        instance = _text(row.get("instance_id"), pointer + "/instance_id",
                         "saved-component-mismatch")
        _digest(row.get("artifact_sha256"), pointer + "/artifact_sha256",
                "saved-component-mismatch")
        if instance in referenced:
            _refuse("saved-component-mismatch", pointer + "/instance_id",
                    {"reason": "duplicate-instance-in-plan"})
        referenced[instance] = row
    admitted = {component.instance_id: component for component in components}
    if set(referenced) != set(admitted):
        _refuse("saved-component-mismatch", "/plan.json/components",
                {"reason": "admitted-component-set-mismatch"})
    for instance, row in referenced.items():
        component = admitted[instance]
        if row["artifact_sha256"] != component.artifact_sha256:
            _refuse("saved-component-mismatch",
                    "/plan.json/components",
                    {"reason": "artifact-digest-mismatch",
                     "instance_id": instance})
        for name in ("source_sha256", "profile_sha256",
                     "semantic_contract_sha256"):
            if name in row and row[name] != getattr(component, name):
                _refuse("saved-component-mismatch", "/plan.json/components",
                        {"reason": name + "-mismatch",
                         "instance_id": instance})
    plan_selections = []
    for index, row in enumerate(document["selections"]):
        pointer = f"/plan.json/selections/{index}"
        row = _closed(row, ("adapter_id", "adapter_version",
                            "implementation_sha256",
                            "component_artifact_sha256",
                            "semantic_contract_sha256"), pointer,
                      "saved-selection-mismatch",
                      optional=("instance_id", "endpoint_id", "role",
                                "selection_sha256"))
        try:
            selection = AdapterSelection(
                row["adapter_id"], row["adapter_version"],
                row["implementation_sha256"],
                row["component_artifact_sha256"],
                row["semantic_contract_sha256"])
        except GenericRuntimeRefused as error:
            _refuse("saved-selection-mismatch", pointer, error.document())
        digest = row.get("selection_sha256")
        if digest is not None and digest != selection.sha256():
            _refuse("saved-selection-mismatch",
                    pointer + "/selection_sha256",
                    {"reason": "selection-digest-differs"})
        plan_selections.append(selection)
    declared = {row.canonical_bytes() for row in plan_selections}
    admitted_selections = {row.canonical_bytes() for row in selections}
    if declared != admitted_selections:
        _refuse("saved-selection-mismatch", "/plan.json/selections",
                {"reason": "plan-selection-set-mismatch"})
    paths = {}
    for index, row in enumerate(document["paths"]):
        pointer = f"/plan.json/paths/{index}"
        row = _object(row, pointer, "saved-case-plan-join")
        path_id = _text(row.get("path_id"), pointer + "/path_id",
                        "saved-case-plan-join")
        if path_id in paths:
            _refuse("saved-case-plan-join", pointer + "/path_id",
                    {"reason": "duplicate-path-id"})
        paths[path_id] = row
    if not paths:
        _refuse("saved-case-plan-join", "/plan.json/paths",
                {"reason": "plan-declares-no-path"})
    sources = {}
    seen_source_paths = set()
    for index, row in enumerate(document["sources"]):
        pointer = f"/plan.json/sources/{index}"
        row = _object(row, pointer, "saved-case-plan-join")
        source_id = _text(row.get("source_id"), pointer + "/source_id",
                          "saved-case-plan-join")
        # The generic plan declares one row per (path, source); instruction
        # images legitimately appear once per flow path.
        declared_path = row.get("path_id")
        key = (source_id, declared_path)
        if key in seen_source_paths:
            _refuse("saved-case-plan-join", pointer + "/source_id",
                    {"reason": "duplicate-source-id-in-path"})
        seen_source_paths.add(key)
        sources.setdefault(source_id, row)
    if not sources:
        _refuse("saved-case-plan-join", "/plan.json/sources",
                {"reason": "plan-declares-no-source"})
    declared_flows = set()
    for row in sources.values():
        flow = row.get("flow_id")
        if type(flow) is str:
            declared_flows.add(flow)
        closure = row.get("source_closure_sha256")
        if closure is not None:
            _digest(closure, "/plan.json/sources",
                    "saved-source-closure-mismatch")
    if document["input_digests"] != inputs["input_digests"]:
        _refuse("saved-input-digest-mismatch", "/plan.json/input_digests",
                {"reason": "plan-and-inputs-disagree"})
    checks.add("plan-references-admitted-digests",
               components=len(referenced), selections=len(declared),
               paths=len(paths), sources=len(sources))
    return {"paths": paths, "sources": sources,
            "flows": declared_flows, "document": document}


def _check_source_closure(paths, manifest, inputs, plan_evidence, checks) -> str:
    sources = _closed(_document(paths, "sources.json"),
                      ("source_closure_sha256", "files"),
                      "/sources.json", "saved-source-closure-mismatch")
    declared_digest = _digest(sources["source_closure_sha256"],
                              "/sources.json/source_closure_sha256",
                              "saved-source-closure-mismatch")
    entries = sources["files"]
    if type(entries) is not list or not entries:
        _refuse("saved-source-closure-mismatch", "/sources.json/files",
                {"expected": "nonempty list"})
    rows = []
    for index, entry in enumerate(entries):
        pointer = f"/sources.json/files/{index}"
        row = _closed(entry, ("path", "archive_path", "sha256"), pointer,
                      "saved-source-closure-mismatch")
        repo_path = _relpath(row["path"], pointer + "/path",
                             "saved-source-closure-mismatch")
        archive_path = _relpath(row["archive_path"],
                               pointer + "/archive_path",
                               "saved-source-closure-mismatch",
                               prefixes=(ARCHIVE_PREFIX,))
        digest = _digest(row["sha256"], pointer + "/sha256",
                         "saved-source-closure-mismatch")
        rows.append({"path": repo_path, "archive_path": archive_path,
                     "sha256": digest})
    archive_paths = [row["archive_path"] for row in rows]
    if archive_paths != sorted(archive_paths):
        _refuse("saved-source-closure-mismatch", "/sources.json/files",
                {"expected": "sorted by archive_path"})
    if len(set(archive_paths)) != len(archive_paths):
        _refuse("saved-source-closure-mismatch", "/sources.json/files",
                {"reason": "duplicate-archive-path"})
    declared_closure = {(row["path"], row["sha256"])
                        for row in inputs["source_closure"]}
    declared_pairs = {(row["archive_path"], row["sha256"]) for row in rows}
    if declared_closure != declared_pairs:
        _refuse("saved-source-closure-mismatch", "/sources.json/files",
                {"reason": "inputs-and-sources-disagree"})
    # Recompute from the archived copies only; the repository is never read.
    recomputed = []
    for index, row in enumerate(rows):
        pointer = f"/sources.json/files/{index}/sha256"
        archive_path = row["archive_path"]
        if archive_path not in paths:
            _refuse("saved-source-closure-mismatch", pointer,
                    {"reason": "archive-copy-not-archived",
                     "path": archive_path})
        actual = _digest_bytes(_read_bytes(paths[archive_path], pointer))
        if actual != row["sha256"]:
            _refuse("saved-source-closure-mismatch", pointer,
                    {"reason": "archive-copy-bytes-changed",
                     "path": archive_path})
        recomputed.append((archive_path, actual))
    recomputed_digest = source_closure_sha256(recomputed)
    if recomputed_digest != declared_digest:
        _refuse("saved-source-closure-mismatch",
                "/sources.json/source_closure_sha256",
                {"reason": "closure-digest-differs-from-archived-bytes"})
    if declared_digest != manifest["source_closure_sha256"]:
        _refuse("saved-source-closure-mismatch",
                "/bundle.json/source_closure_sha256",
                {"reason": "manifest-and-sources-disagree"})
    for row in plan_evidence["sources"].values():
        closure = row.get("source_closure_sha256")
        if closure is not None and closure != declared_digest:
            _refuse("saved-source-closure-mismatch", "/plan.json/sources",
                    {"reason": "plan-closure-evidence-differs"})
    checks.add("source-closure-recomputed-from-archive",
               files=len(rows), closure_sha256=recomputed_digest)
    return recomputed_digest, {"source_closure_sha256": declared_digest,
                               "files": rows}


def _check_generated(paths, components, inputs, checks) -> None:
    admitted = {component.instance_id for component in components}
    expected: dict[str, str] = {}
    for index, entry in enumerate(inputs["generated"]):
        instance = entry["instance_id"]
        if instance not in admitted:
            _refuse("saved-generated-mismatch", "/inputs.json/generated",
                    {"reason": "instance-not-admitted", "instance_id": instance})
        for name, digest in entry["files"].items():
            archive_path = f"{GENERATED_PREFIX}{instance}/{name}"
            expected[archive_path] = digest
    for archive_path, digest in sorted(expected.items()):
        path = paths.get(archive_path)
        if path is None:
            _refuse("saved-generated-mismatch", "/inputs.json/generated",
                    {"reason": "generated-file-not-archived",
                     "path": archive_path})
        actual = _digest_bytes(_read_bytes(path, "/inputs.json/generated"))
        if actual != digest:
            _refuse("saved-generated-mismatch", "/inputs.json/generated",
                    {"reason": "generated-file-changed",
                     "path": archive_path})
    covered = {entry["instance_id"] for entry in inputs["generated"]}
    for instance in covered:
        prefix = f"{GENERATED_PREFIX}{instance}/"
        for archive_path in paths:
            if archive_path.startswith(prefix) and archive_path not in expected:
                _refuse("saved-generated-mismatch", "/inputs.json/generated",
                        {"reason": "generated-file-not-declared",
                         "path": archive_path})
    checks.add("generated-files-declared-and-hashed", files=len(expected))


def _check_cases(paths, plan, inputs, plan_evidence, manifest,
                 checks) -> list[dict]:
    rows = _closed(_document(paths, "cases.json"),
                   ("schema_version", "plan_sha256", "cases"),
                   "/cases.json", "saved-case-shape")
    if rows["schema_version"] != CASE_SCHEMA:
        _refuse("saved-case-shape", "/cases.json/schema_version",
                {"expected": CASE_SCHEMA})
    plan_sha = _digest(rows["plan_sha256"], "/cases.json/plan_sha256",
                       "saved-case-shape")
    if plan_sha != plan.identity_sha256:
        _refuse("saved-case-plan-join", "/cases.json/plan_sha256",
                {"reason": "plan-identity-differs"})
    entries = rows["cases"]
    if type(entries) is not list or not entries:
        _refuse("saved-case-shape", "/cases.json/cases",
                {"expected": "nonempty list"})
    if manifest["case_count"] != len(entries):
        _refuse("saved-case-count-mismatch", "/bundle.json/case_count",
                {"declared": manifest["case_count"], "actual": len(entries)})
    cases = []
    seen_indexes = set()
    seen_testcases = set()
    width = None
    for position, entry in enumerate(entries):
        pointer = f"/cases.json/cases/{position}"
        case = _closed(entry, CASE_FIELDS, pointer, "saved-case-shape",
                       optional=CASE_OPTIONAL_FIELDS)
        index = _integer(case["index"], pointer + "/index", "saved-case-order")
        if index != position:
            _refuse("saved-case-order", pointer + "/index",
                    {"reason": "index-not-at-position",
                     "expected": position, "actual": index,
                     "duplicate": index in seen_indexes})
        seen_indexes.add(index)
        testcase = _text(case["testcase_id"], pointer + "/testcase_id",
                         "saved-case-shape")
        event_case = _text(case.get("event_case_id", testcase),
                           pointer + "/event_case_id", "saved-case-shape")
        if (testcase, event_case) in seen_testcases:
            _refuse("saved-case-order", pointer + "/event_case_id",
                    {"reason": "duplicate-testcase-and-event-case-id"})
        seen_testcases.add((testcase, event_case))
        path_id = _text(case["path_id"], pointer + "/path_id",
                        "saved-case-shape")
        flow_id = _text(case["flow_id"], pointer + "/flow_id",
                        "saved-case-shape")
        source_id = _text(case["source_id"], pointer + "/source_id",
                          "saved-case-shape")
        if path_id not in plan_evidence["paths"]:
            _refuse("saved-case-plan-join", pointer + "/path_id",
                    {"reason": "path-not-in-plan"})
        if source_id not in plan_evidence["sources"]:
            _refuse("saved-case-plan-join", pointer + "/source_id",
                    {"reason": "source-not-in-plan"})
        if flow_id not in inputs["flows"]:
            _refuse("saved-case-plan-join", pointer + "/flow_id",
                    {"reason": "flow-not-prepared"})
        if flow_id not in FLOW_CLASSES:
            _refuse("saved-case-plan-join", pointer + "/flow_id",
                    {"reason": "unknown-flow"})
        records, record_width = _hex_records(case["raw_records_hex"],
                                             pointer + "/raw_records_hex")
        if width is None:
            width = record_width
        elif record_width != width:
            _refuse("saved-case-records", pointer + "/raw_records_hex",
                    {"reason": "record-width-changed", "expected": width})
        _digest(case["instruction_sha256"], pointer + "/instruction_sha256",
                "saved-case-shape")
        _digest(case["receipt_sha256"], pointer + "/receipt_sha256",
                "saved-case-shape")
        _object(case["certificate"], pointer + "/certificate",
                "saved-case-shape")
        chain = _closed(case["version_chain"],
                        ("before_sha256", "after_sha256"),
                        pointer + "/version_chain", "saved-version-chain-break")
        for name in ("before_sha256", "after_sha256"):
            _digest(chain[name], pointer + "/version_chain/" + name,
                    "saved-version-chain-break")
        expected_receipt = case_receipt_sha256(case)
        if expected_receipt != case["receipt_sha256"]:
            _refuse("saved-receipt-mismatch", pointer + "/receipt_sha256",
                    {"reason": "receipt-digest-differs-from-sealed-case"})
        # Real F2/F4 certificates carry the stable storage-version documents.
        # When present they must be the same documents the version events and
        # the case chain are sealed over.
        certificate = case["certificate"]
        for source_name, chain_name in (("prerequisite", "before_sha256"),
                                        ("postcondition", "after_sha256")):
            version = certificate.get(source_name)
            if (isinstance(version, dict)
                    and all(name in version for name in VERSION_KEYS)):
                if version_sha256(version) != chain[chain_name]:
                    _refuse("saved-version-chain-break",
                            pointer + "/certificate/" + source_name,
                            {"reason": "certificate-version-differs-from-chain",
                             "field": chain_name})
        cases.append({"index": index, "testcase_id": testcase,
                      "event_case_id": event_case,
                      "path_id": path_id, "flow_id": flow_id,
                      "source_id": source_id, "raw_records_hex": list(records),
                      "record_bytes": record_width,
                      "instruction_sha256": case["instruction_sha256"],
                      "receipt_sha256": case["receipt_sha256"],
                      "certificate": case["certificate"],
                      "version_chain": {"before_sha256": chain["before_sha256"],
                                        "after_sha256": chain["after_sha256"]},
                      "flow_class": FLOW_CLASSES[flow_id]})
    checks.add("case-order-plan-join-and-receipts", cases=len(cases),
               record_bytes=width)
    return cases


def _check_evidence(paths, cases, checks) -> list[list[EffectEvidence]]:
    rows = _closed(_document(paths, "evidence.json"), ("cases",),
                   "/evidence.json", "saved-evidence-shape")
    entries = rows["cases"]
    if type(entries) is not list or len(entries) != len(cases):
        _refuse("saved-evidence-shape", "/evidence.json/cases",
                {"expected": "one entry per case", "cases": len(cases)})
    evidence: list[list[EffectEvidence]] = []
    for position, entry in enumerate(entries):
        pointer = f"/evidence.json/cases/{position}"
        row = _closed(entry, ("index", "evidence"), pointer,
                      "saved-evidence-shape")
        index = _integer(row["index"], pointer + "/index",
                         "saved-case-order")
        if index != position:
            _refuse("saved-case-order", pointer + "/index",
                    {"reason": "evidence-index-not-at-position"})
        documents = row["evidence"]
        if type(documents) is not list or not documents:
            _refuse("saved-evidence-missing", pointer + "/evidence",
                    {"reason": "case-has-no-evidence"})
        parsed = [parse_effect_evidence(document,
                                        pointer=f"{pointer}/evidence/{offset}")
                  for offset, document in enumerate(documents)]
        evidence.append(parsed)
    checks.add("evidence-documents-parsed",
               cases=len(evidence), documents=sum(len(rows) for rows in evidence))
    return evidence


def _check_processes(paths, checks) -> dict:
    rows = _closed(_document(paths, "processes.json"),
                   ("sessions", "build_sha256", "binary_sha256"),
                   "/processes.json", "saved-process-shape")
    sessions = rows["sessions"]
    if type(sessions) is not dict or not sessions:
        _refuse("saved-process-shape", "/processes.json/sessions",
                {"expected": "nonempty name->session object"})
    parsed = {}
    pids = set()
    nonces = set()
    for name, entry in sessions.items():
        pointer = f"/processes.json/sessions/{name}"
        _text(name, "/processes.json/sessions", "saved-process-shape")
        row = _closed(entry, PROCESS_FIELDS, pointer, "saved-process-shape")
        pid = _integer(row["pid"], pointer + "/pid", "saved-process-shape",
                       minimum=1)
        nonce = _text(row["nonce"], pointer + "/nonce", "saved-process-shape")
        _digest(row["executable_sha256"], pointer + "/executable_sha256",
                "saved-process-shape")
        ready = _boolean(row["ready"], pointer + "/ready",
                         "saved-process-shape")
        if pid in pids:
            _refuse("saved-process-shape", pointer + "/pid",
                    {"reason": "duplicate-pid"})
        if nonce in nonces:
            _refuse("saved-process-shape", pointer + "/nonce",
                    {"reason": "duplicate-nonce"})
        pids.add(pid)
        nonces.add(nonce)
        parsed[name] = {"pid": pid, "nonce": nonce,
                        "executable_sha256": row["executable_sha256"],
                        "ready": ready}
    out = {"sessions": parsed,
           "build_sha256": _digest(rows["build_sha256"],
                                   "/processes.json/build_sha256",
                                   "saved-process-shape"),
           "binary_sha256": _digest(rows["binary_sha256"],
                                    "/processes.json/binary_sha256",
                                    "saved-process-shape")}
    checks.add("process-records", sessions=len(parsed),
               pids=sorted(pids))
    return out


def _check_events(paths, checks) -> tuple[dict[int, dict], list[dict]]:
    events = _document(paths, "events.json")
    if type(events) is not list or not events:
        _refuse("saved-event-shape", "/events.json",
                {"expected": "nonempty list"})
    index: dict[int, dict] = {}
    for position, event in enumerate(events):
        pointer = f"/events.json/{position}"
        if type(event) is not dict:
            _refuse("saved-event-shape", pointer, {"expected": "event object"})
        for name in EVENT_REQUIRED:
            if name not in event:
                _refuse("saved-event-shape", pointer + "/" + name,
                        {"reason": "missing-field"})
        event_id = _integer(event["event_id"], pointer + "/event_id",
                            "saved-event-shape")
        if event_id in index:
            _refuse("saved-counter-conflict", pointer + "/event_id",
                    {"reason": "duplicate-event-id"})
        if event_id != position:
            _refuse("saved-event-sequence", pointer + "/event_id",
                    {"reason": "journal-gap-or-reorder",
                     "expected": position, "actual": event_id})
        _text(event["component"], pointer + "/component",
              "saved-event-shape")
        _text(event["kind"], pointer + "/kind", "saved-event-shape")
        _object(event["provenance"], pointer + "/provenance",
                "saved-event-shape")
        if "payload" in event:
            _object(event["payload"], pointer + "/payload",
                    "saved-event-shape")
        index[event_id] = event
    checks.add("event-journal-sequence", events=len(events))
    return index, events


def _join_process(event, pointer: str, sessions: dict) -> dict:
    provenance = event["provenance"]
    process = provenance.get("process")
    if process is None and event.get("kind") not in REAL_RUNTIME_EVENT_KINDS:
        return None
    if process is None:
        # The real runner journal names the owning endpoint by component and
        # carries no per-event process claims.  Resolve the process from the
        # archived session records instead of trusting an event field.
        component = event.get("component")
        record = sessions.get(component) if isinstance(component, str) else None
        if record is None:
            return None
        return {"session": component, "pid": record["pid"],
                "nonce": record["nonce"]}
    row = _object(process, pointer + "/provenance/process",
                  "saved-process-identity-change")
    allowed = {"session", "pid", "nonce", "executable_sha256"}
    unknown = [name for name in row if name not in allowed]
    if unknown:
        _refuse("saved-process-identity-change",
                pointer + "/provenance/process/" + unknown[0],
                {"reason": "unexpected-field"})
    for name in ("session", "pid", "nonce"):
        if name not in row:
            _refuse("saved-process-identity-change",
                    pointer + "/provenance/process/" + name,
                    {"reason": "missing-field"})
    session = _text(row["session"], pointer + "/provenance/process/session",
                    "saved-process-identity-change")
    pid = _integer(row["pid"], pointer + "/provenance/process/pid",
                   "saved-process-identity-change", minimum=1)
    nonce = _text(row["nonce"], pointer + "/provenance/process/nonce",
                  "saved-process-identity-change")
    record = sessions.get(session)
    if record is None:
        _refuse("saved-process-identity-change",
                pointer + "/provenance/process/session",
                {"reason": "session-not-recorded", "session": session})
    if record["pid"] != pid or record["nonce"] != nonce:
        _refuse("saved-process-identity-change",
                pointer + "/provenance/process",
                {"reason": "process-identity-differs", "session": session})
    executable = row.get("executable_sha256")
    if executable is not None:
        _digest(executable, pointer + "/provenance/process/executable_sha256",
                "saved-process-identity-change")
        if executable != record["executable_sha256"]:
            _refuse("saved-process-identity-change",
                    pointer + "/provenance/process/executable_sha256",
                    {"reason": "executable-digest-differs",
                     "session": session})
    return {"session": session, "pid": pid, "nonce": nonce}


def _join_build_identity(event, pointer: str, processes: dict) -> None:
    payload = event.get("payload")
    if type(payload) is not dict:
        return
    for name, expected in (("build_sha256", processes["build_sha256"]),
                           ("binary_sha256", processes["binary_sha256"])):
        if name not in payload:
            continue
        value = _digest(payload[name], pointer + "/payload/" + name,
                        "saved-process-identity-change")
        if value != expected:
            _refuse("saved-process-identity-change",
                    pointer + "/payload/" + name,
                    {"reason": "recorded-" + name + "-differs"})


def _version_document(payload, pointer: str) -> dict:
    document = _object(payload["version"], pointer + "/version",
                       "saved-version-chain-break")
    for name in VERSION_KEYS:
        if name not in document:
            _refuse("saved-version-chain-break", pointer + "/version/" + name,
                    {"reason": "missing-version-field"})
    _text(document["register"], pointer + "/version/register",
          "saved-version-chain-break")
    for name in ("value", "write_count", "reset_epoch", "command_sequence"):
        _integer(document[name], pointer + "/version/" + name,
                 "saved-version-chain-break")
    _integer(document["value"], pointer + "/version/value",
             "saved-version-chain-break", maximum=0xFFFFFFFFFFFFFFFF)
    for name in PROCESS_FORBIDDEN_VERSION_KEYS:
        if name in document:
            _refuse("saved-version-chain-break",
                    pointer + "/version/" + name,
                    {"reason": "process-identity-in-stable-version"})
    return document


def _resolve_ref(event_id: int, ref: EvidenceRef, *, role: str, case: dict,
                 pointer: str, events: dict, sessions: dict,
                 processes: dict, key_documents: set, used: dict,
                 observed: set) -> dict:
    event = events.get(event_id)
    if event is None:
        return None
    if event["component"] != ref.component or event["kind"] != ref.kind:
        _refuse("saved-evidence-contradicted", pointer,
                {"reason": "event-component-or-kind-differs",
                 "event_id": event_id})
    if ref.kind not in EVENT_ROLES[role]:
        _refuse("saved-evidence-contradicted", pointer,
                {"reason": "kind-not-valid-for-layer", "kind": ref.kind})
    provenance = event["provenance"]
    expected_case = case.get("event_case_id", case["testcase_id"])
    if "case_id" in provenance:
        case_id = _text(provenance["case_id"],
                        pointer + "/provenance/case_id",
                        "saved-evidence-contradicted")
    else:
        observed = provenance.get("observed_case")
        if not isinstance(observed, dict) or "case_id" not in observed:
            _refuse("saved-evidence-contradicted", pointer,
                    {"reason": "event-provenance-lacks-case-id",
                     "event_id": event_id})
        case_id = _text(observed["case_id"],
                        pointer + "/provenance/observed_case/case_id",
                        "saved-evidence-contradicted")
    if case_id != expected_case:
        _refuse("saved-evidence-contradicted", pointer,
                {"reason": "event-belongs-to-another-case",
                 "event_id": event_id})
    transaction = provenance.get("transaction")
    if transaction is not None:
        key = _transaction_key(transaction, pointer + "/provenance/transaction")
        if _canonical(transaction_document(key)) not in key_documents:
            _refuse("saved-evidence-contradicted",
                    pointer + "/provenance/transaction",
                    {"reason": "transaction-differs-from-evidence-key",
                     "event_id": event_id})
    process = _join_process(event, pointer, sessions)
    if process is not None:
        observed.add((process["session"], process["pid"], process["nonce"]))
    if role == "native_refs" and process is None:
        _refuse("saved-process-identity-change", pointer,
                {"reason": "native-event-lacks-process-identity",
                 "event_id": event_id})
    _join_build_identity(event, pointer, processes)
    payload = event.get("payload")
    if type(payload) is not dict:
        _refuse("saved-evidence-shape", pointer,
                {"reason": "evidence-event-lacks-payload",
                 "event_id": event_id})
    for name in ROLE_PAYLOAD_KEYS[role]:
        if name not in payload:
            _refuse("saved-evidence-shape", pointer + "/payload/" + name,
                    {"reason": "missing-payload-field", "event_id": event_id})
    previous = used.get(event_id)
    if previous is not None:
        _refuse("saved-evidence-reuse", pointer,
                {"reason": "event-reused-as-evidence",
                 "event_id": event_id, "first_use": previous})
    used[event_id] = pointer
    return event


def _check_evidence_joins(cases, evidence, events, processes, checks) -> dict:
    """Resolve every ref and derive the effective status from archived facts."""
    sessions = processes["sessions"]
    used: dict[int, str] = {}
    observed_processes: set[tuple[str, int, str]] = set()
    evidence_digests: dict[str, int] = {}
    execution_ids: set[str] = set()
    chain_after: dict[str, str] = {}
    chain_epoch: dict[str, int] = {}
    last_command: dict[str, int] = {}
    write_values: list[int] = []
    derived_statuses: list[list[str]] = []
    version_facts: list[dict] = []

    for position, case in enumerate(cases):
        pointer = f"/cases.json/cases/{position}"
        documents = evidence[position]
        key_documents = set()
        for offset, document in enumerate(documents):
            key_documents.add(_canonical(transaction_document(document.key)))
            execution_ids.add(document.key.execution_id)
            sealed = _canonical(document.document())
            if sealed in evidence_digests:
                _refuse("saved-evidence-reuse",
                        f"/evidence.json/cases/{position}/evidence/{offset}",
                        {"reason": "same-evidence-document-in-another-case",
                         "first_case": evidence_digests[sealed]})
            evidence_digests[sealed] = position
            if document.key.testcase_id != case["testcase_id"]:
                _refuse("saved-evidence-contradicted",
                        f"/evidence.json/cases/{position}/evidence/{offset}/key",
                        {"reason": "evidence-key-belongs-to-another-case"})
        statuses: list[str] = []
        collected = {"source_refs": [], "native_refs": [],
                     "destination_refs": []}
        for offset, document in enumerate(documents):
            doc_pointer = (f"/evidence.json/cases/{position}"
                           f"/evidence/{offset}")
            missing: list[str] = []
            for role in ("source_refs", "native_refs", "destination_refs"):
                refs = getattr(document, role)
                for number, ref in enumerate(refs):
                    ref_pointer = f"{doc_pointer}/{role}/{number}"
                    resolved = _resolve_ref(
                        ref.event_id, ref, role=role, case=case,
                        pointer=ref_pointer, events=events,
                        sessions=sessions, processes=processes,
                        key_documents=key_documents, used=used,
                        observed=observed_processes)
                    if resolved is None:
                        missing.append(ref_pointer)
                        continue
                    collected[role].append((ref_pointer, resolved))
            if missing:
                if document.status == "certified":
                    _refuse("saved-evidence-ref-missing", missing[0],
                            {"reason": "stored-certified-but-ref-unresolved",
                             "missing": len(missing)})
                derived = "missing"
            else:
                derived = "certified"
            if document.status == "missing" and derived == "certified":
                _refuse("saved-evidence-status-mismatch",
                        doc_pointer + "/status",
                        {"reason": "stored-missing-but-every-ref-resolves"})
            if document.status == "contradicted":
                _refuse("saved-evidence-contradicted", doc_pointer + "/status",
                        {"reason": "stored-contradicted-evidence-in-closed-run"})
            if document.status == "unsupported":
                derived = "unsupported"
            statuses.append(derived)
        effective = combine_status(tuple(statuses))
        derived_statuses.append(statuses)
        if effective == "missing":
            _refuse("saved-evidence-missing", pointer,
                    {"reason": "case-effective-status-missing"})
        if effective == "unsupported":
            _refuse("saved-evidence-unsupported", pointer,
                    {"reason": "case-effective-status-unsupported"})
        if effective != "certified":
            _refuse("saved-evidence-contradicted", pointer,
                    {"reason": "case-effective-status-" + effective})

        version_facts.append(_check_case_facts(
            case, pointer, collected, chain_after, chain_epoch,
            last_command, write_values,
            [document.key for document in documents]))

    for name, record in sessions.items():
        if (name, record["pid"], record["nonce"]) not in observed_processes:
            _refuse("saved-process-identity-change",
                    f"/processes.json/sessions/{name}",
                    {"reason": "declared-session-never-observed"})
    for name, _, _ in sorted(observed_processes):
        if name not in sessions:
            _refuse("saved-process-identity-change", "/processes.json/sessions",
                    {"reason": "undeclared-session-observed",
                     "session": name})
    execution = sorted(execution_ids)
    if len(execution) != 1:
        _refuse("saved-process-identity-change", "/evidence.json",
                {"reason": "execution-id-not-stable", "values": len(execution)})
    if write_values:
        if not any(write_values):
            _refuse("saved-case-values", "/cases.json/cases",
                    {"reason": "no-nonzero-effect-value",
                     "values": len(write_values)})
        if len(set(write_values)) < 2:
            _refuse("saved-case-values", "/cases.json/cases",
                    {"reason": "effect-values-all-equal",
                     "values": len(write_values)})
    checks.add("evidence-joins-and-derived-status",
               cases=len(cases), referenced_events=len(used),
               execution_id=execution[0], effect_values=len(write_values))
    return {"execution_id": execution[0], "used_events": len(used),
            "version_facts": version_facts,
            "derived_statuses": derived_statuses,
            "processes_observed": len(observed_processes)}


def _check_case_facts(case, pointer, collected, chain_after, chain_epoch,
                      last_command, write_values, keys) -> dict:
    """Version chain, counters and cross-layer agreement for one case."""
    before_events = [event for _, event in collected["destination_refs"]
                     if event["payload"]["phase"] == "before"]
    after_events = [event for _, event in collected["destination_refs"]
                    if event["payload"]["phase"] == "after"]
    if len(before_events) != 1 or len(after_events) != 1:
        _refuse("saved-version-chain-break", pointer + "/version_chain",
                {"reason": "exactly-one-before-and-after-required",
                 "before": len(before_events), "after": len(after_events)})
    before = _version_document(before_events[0]["payload"],
                               pointer + "/version_chain")
    after = _version_document(after_events[0]["payload"],
                              pointer + "/version_chain")
    if version_sha256(before) != case["version_chain"]["before_sha256"]:
        _refuse("saved-version-chain-break",
                pointer + "/version_chain/before_sha256",
                {"reason": "before-digest-differs-from-archived-version"})
    if version_sha256(after) != case["version_chain"]["after_sha256"]:
        _refuse("saved-version-chain-break",
                pointer + "/version_chain/after_sha256",
                {"reason": "after-digest-differs-from-archived-version"})
    if before["register"] != after["register"]:
        _refuse("saved-version-chain-break", pointer + "/version_chain",
                {"reason": "register-changed-within-case"})
    if before["reset_epoch"] != after["reset_epoch"]:
        _refuse("saved-reset-order-change", pointer + "/version_chain",
                {"reason": "reset-epoch-changed-within-case"})
    source_id = case["source_id"]
    previous_after = chain_after.get(source_id)
    if previous_after is not None and \
            _version_state(before) != previous_after:
        differing = sorted(
            name for name in set(previous_after) | set(_version_state(before))
            if previous_after.get(name) != _version_state(before).get(name))
        if differing == ["reset_epoch"]:
            _refuse("saved-reset-order-change", pointer + "/version_chain",
                    {"reason": "reset-epoch-changed-between-cases"})
        _refuse("saved-version-chain-break",
                pointer + "/version_chain/before_sha256",
                {"reason": "before-state-differs-from-previous-after",
                 "differing_fields": differing[:6]})
    recorded_epoch = chain_epoch.setdefault(source_id, before["reset_epoch"])
    if recorded_epoch != before["reset_epoch"]:
        _refuse("saved-reset-order-change", pointer + "/version_chain",
                {"reason": "reset-epoch-changed-between-cases"})
    chain_after[source_id] = _version_state(after)
    if after["command_sequence"] < before["command_sequence"] + 1:
        _refuse("saved-counter-conflict", pointer + "/version_chain",
                {"reason": "command-sequence-did-not-advance"})
    previous_command = last_command.get(source_id)
    # A persisted campaign re-issues the previous case's final version as the
    # next case's prerequisite, so equality at the case boundary is the
    # registered continuity, not a counter reuse.  Only a *decrease* is refused.
    if previous_command is not None and \
            before["command_sequence"] < previous_command:
        _refuse("saved-counter-conflict", pointer + "/version_chain",
                {"reason": "command-sequence-decreased-between-cases"})
    last_command[source_id] = after["command_sequence"]

    source_events = [event for _, event in collected["source_refs"]]
    native_events = [event for _, event in collected["native_refs"]]
    multi_hop = len(native_events) == 4 and len(source_events) in (2, 3, 4)
    if not multi_hop and (len(source_events) != 1 or len(native_events) != 1):
        _refuse("saved-evidence-shape", pointer,
                {"reason": "one-or-write/read-hop-source-and-native-samples-required",
                 "source": len(source_events), "native": len(native_events)})
    read_hop = None
    if multi_hop:
        by_operation = {}
        for event in source_events:
            operation = event["payload"].get("operation")
            if operation not in ("write", "read"):
                _refuse("saved-evidence-contradicted", pointer,
                        {"reason": "unknown-source-operation",
                         "operation": operation})
            by_operation.setdefault(operation, []).append(event)
        # The producer keeps the runtime's per-hop order: the first pair of
        # samples is the write command (pre/post) and the second pair the read
        # command.  The command-phase sample of each hop carries the operation.
        write_samples = list(native_events[0:2])
        read_samples = list(native_events[2:4])
        if (set(by_operation) != {"write", "read"}
                or write_samples[0]["payload"].get("write") is not True
                or read_samples[0]["payload"].get("write") is not False):
            _refuse("saved-evidence-contradicted", pointer,
                    {"reason": "real-write-then-read-hop-spans-required",
                     "source_operations": sorted(by_operation),
                     "write_sample_flag": write_samples[0]["payload"].get("write"),
                     "read_sample_flag": read_samples[0]["payload"].get("write")})
        source_payload = by_operation["write"][0]["payload"]
        native_payload = write_samples[0]["payload"]
        read_hop = (by_operation["read"][0]["payload"],
                    read_samples[0]["payload"])
    else:
        source_payload = source_events[0]["payload"]
        native_payload = native_events[0]["payload"]
    operation = _text(source_payload["operation"],
                      pointer + "/source/operation",
                      "saved-evidence-shape")
    write = _boolean(native_payload["write"], pointer + "/native/write",
                     "saved-evidence-shape")
    address = _integer(source_payload["address"], pointer + "/source/address",
                       "saved-evidence-shape")
    _integer(native_payload["wdata"], pointer + "/native/wdata",
             "saved-evidence-shape", maximum=0xFFFFFFFF)
    _integer(native_payload["rdata"], pointer + "/native/rdata",
             "saved-evidence-shape", maximum=0xFFFFFFFF)
    be = _integer(native_payload["be"], pointer + "/native/be",
                  "saved-evidence-shape", minimum=1, maximum=0xFFFFFFFF)
    data = _integer(source_payload["data"], pointer + "/source/data",
                    "saved-evidence-shape", maximum=0xFFFFFFFFFFFFFFFF)
    source_components = {event["component"] for event in source_events}
    for key in keys:
        if key.source_component not in source_components:
            _refuse("saved-evidence-contradicted",
                    pointer + "/source_refs",
                    {"reason": "evidence-key-source-component-not-the-sample",
                     "source_component": key.source_component})
    if case["flow_class"] == "read":
        if operation != "read" or write:
            _refuse("saved-evidence-contradicted", pointer,
                    {"reason": "read-flow-with-write-sample",
                     "operation": operation})
        if after["value"] != before["value"] or \
                after["write_count"] != before["write_count"]:
            _refuse("saved-version-chain-break", pointer + "/version_chain",
                    {"reason": "read-flow-advanced-storage"})
        if not (data == native_payload["rdata"] == after["value"]):
            _refuse("saved-read-return-mismatch", pointer,
                    {"reason": "cpu-read-return-differs-from-sample-and-version"})
    else:
        if operation != "write" or not write:
            _refuse("saved-evidence-contradicted", pointer,
                    {"reason": "effect-flow-with-read-sample",
                     "operation": operation})
        if after["write_count"] != before["write_count"] + 1:
            _refuse("saved-counter-conflict", pointer + "/version_chain",
                    {"reason": "write-count-did-not-advance-by-one"})
        if data != native_payload["wdata"]:
            _refuse("saved-write-data-mismatch", pointer,
                    {"reason": "cpu-write-data-differs-from-sample"})
        for byte in range(32):
            if not (be >> byte) & 1:
                continue
            if ((after["value"] >> (8 * byte)) & 0xFF) != \
                    ((native_payload["wdata"] >> (8 * byte)) & 0xFF):
                _refuse("saved-write-data-mismatch", pointer,
                        {"reason": "written-byte-differs-from-versioned-value",
                         "byte": byte})
        if read_hop is not None:
            read_source, read_native = read_hop
            if read_source.get("operation") != "read":
                _refuse("saved-evidence-contradicted", pointer,
                        {"reason": "read-hop-operation-mismatch"})
            if read_native.get("rdata") != after["value"]:
                _refuse("saved-read-return-mismatch", pointer + "/read_hop",
                        {"reason": "cpu-readback-sample-differs-from-version",
                         "sampled": read_native.get("rdata"),
                         "version": after["value"]})
            if read_source.get("data") != read_native.get("rdata"):
                _refuse("saved-read-return-mismatch", pointer + "/read_hop",
                        {"reason": "cpu-read-data-differs-from-sample"})
        write_values.append(data)
    return {"before": before, "after": after, "address": address,
            "data": data, "source_components": sorted(source_components)}


def _check_semantic_contract_join(cases, evidence, components, checks) -> None:
    admitted = {component.semantic_contract_sha256 for component in components}
    for position, documents in enumerate(evidence):
        for offset, document in enumerate(documents):
            if document.semantic_contract_sha256 not in admitted:
                _refuse("saved-evidence-contradicted",
                        f"/evidence.json/cases/{position}/evidence/{offset}"
                        "/semantic_contract_sha256",
                        {"reason": "semantic-contract-not-admitted"})
    checks.add("evidence-semantic-contracts-admitted",
               contracts=len(admitted))


def _check_evidence_key_sequences(cases, evidence, checks) -> None:
    last: dict[str, int] = {}
    for position, case in enumerate(cases):
        sequences = sorted({document.key.source_sequence
                            for document in evidence[position]})
        for sequence in sequences:
            previous = last.get(case["source_id"])
            if previous is not None and sequence <= previous:
                _refuse("saved-counter-conflict",
                        f"/evidence.json/cases/{position}/evidence/0/key",
                        {"reason": "source-sequence-not-increasing"})
        if sequences:
            last[case["source_id"]] = max(sequences)
    checks.add("transaction-sequence-monotonic", sources=len(last))


def _check_source_epoch_join(cases, evidence, version_facts, checks) -> None:
    for position, case in enumerate(cases):
        fact = version_facts[position]
        for document in evidence[position]:
            if document.key.source_epoch != fact["before"]["reset_epoch"]:
                _refuse("saved-reset-order-change",
                        f"/evidence.json/cases/{position}/evidence/0/key",
                        {"reason": "key-epoch-differs-from-version-epoch"})
    checks.add("transaction-epoch-joined-to-version")


def _check_process_reuse(processes, execution, checks) -> None:
    for name, record in processes["sessions"].items():
        _digest(record["executable_sha256"],
                f"/processes.json/sessions/{name}/executable_sha256",
                "saved-process-identity-change")
    checks.add("process-executable-digests-recorded",
               sessions=len(processes["sessions"]),
               execution_id=execution)


def _check_exit_status(manifest, processes, audit, checks) -> None:
    if type(audit) is not dict:
        _refuse("saved-bundle-document", "/execution_audit.json",
                {"expected": "JSON object"})
    if "closed" in audit:
        closed = _boolean(audit["closed"], "/execution_audit.json/closed",
                          "saved-bundle-document")
        if manifest["exit_status"] == "closed" and not closed:
            _refuse("saved-exit-status-mismatch", "/execution_audit.json/closed",
                    {"reason": "manifest-closed-but-audit-open"})
    if manifest["exit_status"] == "closed":
        for name, record in processes["sessions"].items():
            if not record["ready"]:
                _refuse("saved-exit-status-mismatch",
                        f"/processes.json/sessions/{name}/ready",
                        {"reason": "closed-run-with-unready-session"})
    checks.add("exit-status-consistency", exit_status=manifest["exit_status"])


# ---------------------------------------------------------------------------
# normalization declarations
# ---------------------------------------------------------------------------
def _identity_rules(manifest, processes, execution_id, *, label: str = ""):
    rules = []
    for index, path in enumerate(manifest["normalized_identity_fields"]):
        pointer = f"/bundle.json/normalized_identity_fields/{index}"
        if not path.startswith(IDENTITY_PATH_PREFIXES):
            hints = []
            lowered = path.lower()
            if any(hint in lowered for hint in _PAYLOAD_NAME_HINTS):
                hints.append("payload")
            if any(hint in lowered for hint in _VERSION_NAME_HINTS):
                hints.append("source-byte-version")
            if any(hint in lowered for hint in _RESET_NAME_HINTS):
                hints.append("reset-ordering")
            if any(hint in lowered for hint in _STATUS_NAME_HINTS):
                hints.append("evidence-status-or-event-presence")
            _refuse("saved-normalization-refused", pointer,
                    {"reason": "not-an-identity-field", "path": path,
                     "touches": hints or ["undeclared-scope"]})
        parts = path.split("/")
        if len(parts) == 3 and parts[0] == "processes" and parts[2] in (
                "pid", "nonce"):
            session = processes["sessions"].get(parts[1])
            if session is None:
                _refuse("saved-normalization-refused", pointer,
                        {"reason": "session-not-recorded",
                         "path": path})
            rules.append((IDENTITY_FIELD_NAMES[parts[2]],
                          session[parts[2]],
                          NORMALIZED_PLACEHOLDERS[parts[2]]))
            continue
        if path == "execution/execution_id":
            rules.append((IDENTITY_FIELD_NAMES["execution_id"], execution_id,
                          NORMALIZED_PLACEHOLDERS["execution_id"]))
            continue
        _refuse("saved-normalization-refused", pointer,
                {"reason": "unknown-identity-path", "path": path})
    return tuple(rules)


# ---------------------------------------------------------------------------
# one bundle
# ---------------------------------------------------------------------------
def _verify_bundle(bundle_dir, *, label: str = "") -> dict:
    checks = _Checks(label)
    checks.add("scope", live_authority=False, repository_reads=False)
    try:
        root = _locate(bundle_dir)
        checks.add("bundle-directory", path=str(root))
        manifest, manifest_bytes, identity = _parse_manifest(root)
        checks.add("manifest-canonical-and-closed", bundle_id=identity,
                   exit_status=manifest["exit_status"],
                   case_count=manifest["case_count"])
        paths = _check_files(root, manifest, checks)
        return _continue_verification(root, manifest, manifest_bytes, identity,
                                      paths, checks)
    except SavedBundleRefused as error:
        error.checks = list(checks.rows)
        raise
    except GenericRuntimeRefused as error:
        refused = SavedBundleRefused(error.code, error.pointer, error.detail)
        refused.checks = list(checks.rows)
        raise refused from None


def _continue_verification(root, manifest, manifest_bytes, identity, paths,
                           checks) -> dict:
    plan = _check_plan(paths, manifest, checks)
    inputs = _check_inputs(paths, manifest, checks)
    components = _check_components(paths, checks)
    selections = _check_selections(paths, components, checks)
    plan_evidence = _check_plan_references(plan, components, selections,
                                           inputs, checks)
    closure, sources_document = _check_source_closure(
        paths, manifest, inputs, plan_evidence, checks)
    _check_generated(paths, components, inputs, checks)
    cases = _check_cases(paths, plan, inputs, plan_evidence, manifest, checks)
    evidence = _check_evidence(paths, cases, checks)
    processes = _check_processes(paths, checks)
    events, event_rows = _check_events(paths, checks)
    audit = _object(_document(paths, "execution_audit.json"),
                    "/execution_audit.json", "saved-bundle-document")
    prefix = _object(_document(paths, "prefix.json"), "/prefix.json",
                     "saved-bundle-document")
    _check_exit_status(manifest, processes, audit, checks)
    joins = _check_evidence_joins(cases, evidence, events, processes, checks)
    _check_semantic_contract_join(cases, evidence, components, checks)
    _check_evidence_key_sequences(cases, evidence, checks)
    _check_source_epoch_join(cases, evidence, joins["version_facts"], checks)
    _check_process_reuse(processes, joins["execution_id"], checks)
    rules = _identity_rules(manifest, processes, joins["execution_id"])
    checks.add("normalization-declarations-pinned",
               fields=list(manifest["normalized_identity_fields"]))
    return {"root": str(root), "bundle_id": identity,
            "manifest": manifest, "manifest_bytes": manifest_bytes,
            "plan": plan, "plan_bytes": plan.document_bytes,
            "inputs": inputs, "components": components,
            "selections": selections, "cases": cases,
            "evidence": evidence, "events": event_rows, "processes": processes,
            "audit": audit, "prefix": prefix,
            "sources": sources_document,
            "source_closure_sha256": closure,
            "execution_id": joins["execution_id"],
            "identity_rules": rules,
            "checks": checks.rows}


def _run_bundle(bundle_dir, *, label: str = "") -> dict:
    try:
        return _verify_bundle(bundle_dir, label=label)
    except SavedBundleRefused as error:
        error.checks = list(getattr(error, "checks", []) or ())
        raise
    except GenericRuntimeRefused as error:
        raise SavedBundleRefused(error.code, error.pointer, error.detail)


# ---------------------------------------------------------------------------
# fresh comparison
# ---------------------------------------------------------------------------
def _case_document(case) -> dict:
    document = {name: case[name] for name in CASE_FIELDS
                if name != "receipt_sha256"}
    if "event_case_id" in case:
        document["event_case_id"] = case["event_case_id"]
    return document


def _verify_fresh(original: dict, fresh: dict, checks: _Checks) -> None:
    if fresh["manifest"]["fresh_of"] != original["bundle_id"]:
        _refuse("saved-fresh-link-mismatch", "/bundle.json/fresh_of",
                {"reason": "fresh-bundle-does-not-name-the-original"})
    if fresh["manifest"]["plan"] != original["manifest"]["plan"]:
        _refuse("saved-fresh-plan-mismatch", "/bundle.json/plan",
                {"reason": "plan-digests-differ"})
    if fresh["plan_bytes"] != original["plan_bytes"]:
        _refuse("saved-fresh-plan-mismatch", "/plan.json",
                {"reason": "plan-bytes-differ"})
    if fresh["plan"].identity_sha256 != original["plan"].identity_sha256:
        _refuse("saved-fresh-plan-mismatch", "/plan.json",
                {"reason": "plan-identity-differs"})
    checks.add("fresh.plan-identity", plan=original["plan"].identity_sha256)
    if fresh["inputs"]["input_digests"] != original["inputs"]["input_digests"]:
        _refuse("saved-fresh-plan-mismatch", "/inputs.json/input_digests",
                {"reason": "input-digests-differ"})
    if (fresh["inputs"]["compose"] != original["inputs"]["compose"]
            or fresh["inputs"]["capability_paths"]
            != original["inputs"]["capability_paths"]
            or fresh["inputs"]["supplement"] != original["inputs"]["supplement"]
            or fresh["inputs"]["flows"] != original["inputs"]["flows"]):
        _refuse("saved-fresh-plan-mismatch", "/inputs.json",
                {"reason": "preparation-differs"})
    if fresh["source_closure_sha256"] != original["source_closure_sha256"]:
        _refuse("saved-fresh-source-mismatch", "/sources.json",
                {"reason": "closure-digest-differs"})
    if _canonical(fresh["sources"]) != _canonical(original["sources"]):
        _refuse("saved-fresh-source-mismatch", "/sources.json",
                {"reason": "source-file-set-differs"})
    if _canonical(fresh["inputs"]["generated"]) != \
            _canonical(original["inputs"]["generated"]):
        _refuse("saved-fresh-source-mismatch", "/inputs.json/generated",
                {"reason": "generated-file-set-differs"})
    checks.add("fresh.source-closure",
               closure=original["source_closure_sha256"])
    if [row.document() for row in fresh["components"]] != \
            [row.document() for row in original["components"]]:
        _refuse("saved-fresh-components-mismatch", "/components.json",
                {"reason": "component-descriptors-differ"})
    if [row.document() for row in fresh["selections"]] != \
            [row.document() for row in original["selections"]]:
        _refuse("saved-fresh-components-mismatch", "/selections.json",
                {"reason": "adapter-selections-differ"})
    checks.add("fresh.components-and-selections")
    if (fresh["processes"]["build_sha256"]
            != original["processes"]["build_sha256"]
            or fresh["processes"]["binary_sha256"]
            != original["processes"]["binary_sha256"]):
        _refuse("saved-fresh-build-mismatch", "/processes.json",
                {"reason": "build-or-binary-identity-differs"})
    original_sessions = original["processes"]["sessions"]
    fresh_sessions = fresh["processes"]["sessions"]
    if set(original_sessions) != set(fresh_sessions):
        _refuse("saved-fresh-build-mismatch", "/processes.json/sessions",
                {"reason": "session-set-differs"})
    for name, record in original_sessions.items():
        if record["executable_sha256"] != fresh_sessions[name]["executable_sha256"]:
            _refuse("saved-fresh-build-mismatch",
                    f"/processes.json/sessions/{name}/executable_sha256",
                    {"reason": "executable-digest-differs"})
        if record["pid"] == fresh_sessions[name]["pid"]:
            _refuse("saved-fresh-identity-reuse",
                    f"/processes.json/sessions/{name}/pid",
                    {"reason": "pid-reused-by-fresh-process"})
        if record["nonce"] == fresh_sessions[name]["nonce"]:
            _refuse("saved-fresh-identity-reuse",
                    f"/processes.json/sessions/{name}/nonce",
                    {"reason": "nonce-reused-by-fresh-process"})
    if list(original["manifest"]["normalized_identity_fields"]) != list(
            fresh["manifest"]["normalized_identity_fields"]):
        _refuse("saved-fresh-normalization-mismatch",
                "/bundle.json/normalized_identity_fields",
                {"reason": "declared-fields-differ"})
    checks.add("fresh.process-identity-renewed",
               sessions=len(original_sessions))

    original_rules = original["identity_rules"]
    fresh_rules = fresh["identity_rules"]
    original_cases = original["cases"]
    fresh_cases = fresh["cases"]
    if len(original_cases) != len(fresh_cases):
        _refuse("saved-fresh-case-mismatch", "/cases.json/cases",
                {"reason": "accepted-case-count-differs"})
    for position, (left, right) in enumerate(zip(original_cases, fresh_cases)):
        pointer = f"/cases.json/cases/{position}"
        if left["testcase_id"] != right["testcase_id"]:
            _refuse("saved-fresh-case-mismatch", pointer + "/testcase_id",
                    {"reason": "testcase-id-differs"})
        if left["instruction_sha256"] != right["instruction_sha256"]:
            _refuse("saved-fresh-case-mismatch", pointer + "/instruction_sha256",
                    {"reason": "instruction-digest-differs"})
        if left["raw_records_hex"] != right["raw_records_hex"]:
            _refuse("saved-fresh-case-mismatch", pointer + "/raw_records_hex",
                    {"reason": "accepted-raw-records-differ"})
        if left["flow_id"] != right["flow_id"] or \
                left["path_id"] != right["path_id"] or \
                left["source_id"] != right["source_id"]:
            _refuse("saved-fresh-case-mismatch", pointer,
                    {"reason": "case-selection-differs"})
        if left["version_chain"] != right["version_chain"]:
            _refuse("saved-fresh-evidence-mismatch",
                    pointer + "/version_chain",
                    {"reason": "version-chain-differs"})
        left_case = normalize_identity(_case_document(left), original_rules)
        right_case = normalize_identity(_case_document(right), fresh_rules)
        if _canonical(left_case) != _canonical(right_case):
            _refuse("saved-fresh-case-mismatch", pointer + "/certificate",
                    {"reason": "sealed-case-differs-after-identity-normalization"})
    checks.add("fresh.accepted-case-sequence", cases=len(original_cases))

    left_events = normalize_identity(original["events"], original_rules)
    right_events = normalize_identity(fresh["events"], fresh_rules)
    if _canonical(left_events) != _canonical(right_events):
        _refuse("saved-fresh-event-mismatch", "/events.json",
                {"reason": "raw-events-differ-after-identity-normalization"})
    checks.add("fresh.raw-events", events=len(original["events"]))
    left_evidence = normalize_identity(
        [[document.document() for document in documents]
         for documents in original["evidence"]], original_rules)
    right_evidence = normalize_identity(
        [[document.document() for document in documents]
         for documents in fresh["evidence"]], fresh_rules)
    if _canonical(left_evidence) != _canonical(right_evidence):
        _refuse("saved-fresh-evidence-mismatch", "/evidence.json",
                {"reason": "evidence-differs-after-identity-normalization"})
    checks.add("fresh.evidence", documents=sum(
        len(documents) for documents in original["evidence"]))
    if normalize_identity(original["audit"], original_rules) != \
            normalize_identity(fresh["audit"], fresh_rules):
        _refuse("saved-fresh-evidence-mismatch", "/execution_audit.json",
                {"reason": "execution-audit-differs"})
    checks.add("fresh.execution-audit")


# ---------------------------------------------------------------------------
# public verifier
# ---------------------------------------------------------------------------
LIMITATIONS = [
    "archived bytes only: no live handle, native token or certified boolean is consulted",
    "the closure digest is an internal anchor; an attacker who reseals source "
    "bytes, closure, plan and every document consistently forges an internally "
    "consistent run, so the G0 baseline and the fresh comparison remain the "
    "external anchors",
    "obligation_results are sealed evidence claims; ref resolution, counter "
    "continuity and version-chain facts are the parts this verifier re-derives",
    "prefix.json and execution_audit.json are hash-pinned raw flow documents; "
    "their internals are audited by the flow, not re-derived here",
    "v1 admits exactly one before/after version pair per case",
    "effect variety is enforced on written values; a repeated equal write is "
    "legal but cannot by itself satisfy the bundle",
]


def verify_saved_bundle(bundle_dir, *, fresh_bundle_dir=None) -> dict:
    """Independently verify one saved bundle, optionally against its fresh run."""
    original = _run_bundle(bundle_dir, label="")
    checks = _Checks()
    checks.rows.extend(original["checks"])
    fresh = None
    if fresh_bundle_dir is not None:
        try:
            fresh = _run_bundle(fresh_bundle_dir, label="fresh")
        except GenericRuntimeRefused as error:
            refused = SavedBundleRefused(
                "saved-fresh-bundle-refused", "",
                {"bundle": "fresh", "code": error.code,
                 "pointer": error.pointer, "detail": error.detail})
            refused.checks = list(checks.rows) + list(
                getattr(error, "checks", []) or ())
            raise refused from None
        checks.rows.extend(fresh["checks"])
        try:
            _verify_fresh(original, fresh, checks)
        except SavedBundleRefused as error:
            error.checks = list(checks.rows)
            raise
        except GenericRuntimeRefused as error:
            refused = SavedBundleRefused(error.code, error.pointer,
                                         error.detail)
            refused.checks = list(checks.rows)
            raise refused from None
    incomplete = original["manifest"]["exit_status"] != "closed"
    verdict = "integrity_verified_incomplete_run" if incomplete else "verified"
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "scope": {"bundle": original["root"],
                  "fresh_bundle": fresh["root"] if fresh else None,
                  "mode": "saved-evidence-only-no-live-authority"},
        "verdict": verdict,
        "checks": checks.rows,
        "tampered_refusals": [],
        "bundle_ids": ([original["bundle_id"], fresh["bundle_id"]]
                       if fresh else [original["bundle_id"]]),
        "exit_status": original["manifest"]["exit_status"],
        "case_count": len(original["cases"]),
        "plan_identity_sha256": original["plan"].identity_sha256,
        "source_closure_sha256": original["source_closure_sha256"],
        "execution_identity": original["execution_id"],
        "processes": {name: {"pid": record["pid"],
                             "nonce": record["nonce"],
                             "executable_sha256": record["executable_sha256"],
                             "ready": record["ready"]}
                      for name, record in original["processes"]["sessions"].items()},
        "fresh_verified": fresh is not None,
        "limitations": list(LIMITATIONS),
    }


def refusal_report(error: GenericRuntimeRefused, *, bundle=None,
                   fresh_bundle=None) -> dict:
    """JSON document for a refused verification (CLI refusal output)."""
    checks = list(getattr(error, "checks", ()) or ())
    return {
        "schema_version": VERIFICATION_SCHEMA,
        "scope": {"bundle": str(bundle) if bundle is not None else None,
                  "fresh_bundle": (str(fresh_bundle)
                                   if fresh_bundle is not None else None),
                  "mode": "saved-evidence-only-no-live-authority"},
        "verdict": "refused",
        "refusal": error.document(),
        "checks": checks,
        "tampered_refusals": [error.document()],
        "limitations": list(LIMITATIONS),
    }


# ---------------------------------------------------------------------------
# writer
# ---------------------------------------------------------------------------
def _require_plain_directory(path: Path, pointer: str) -> None:
    if path.is_symlink():
        _refuse("saved-bundle-escape", pointer, {"reason": "symlink"})
    if not path.exists():
        return
    if not path.is_dir():
        _refuse("saved-bundle-escape", pointer, {"reason": "not-a-directory"})


def _write_bytes(root: Path, relative: str, payload: bytes) -> None:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or target.parent.is_symlink():
        _refuse("saved-bundle-escape", "/" + relative,
                {"reason": "symlink-in-write-path"})
    with target.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _write_document(root: Path, name: str, document) -> bytes:
    payload = _canonical(document)
    _write_bytes(root, name, payload)
    return payload


def _source_bytes(base: Path, relative: str) -> bytes:
    path = base / relative
    if path.is_symlink():
        _refuse("saved-source-closure-mismatch", "/" + relative,
                {"reason": "symlinked-source-file"})
    if not path.is_file():
        _refuse("saved-source-closure-mismatch", "/" + relative,
                {"reason": "source-file-missing"})
    try:
        return path.read_bytes()
    except OSError as error:
        _refuse("saved-source-closure-mismatch", "/" + relative,
                {"reason": type(error).__name__})


def write_bundle(bundle_dir, *, producer, preparation, input_digests, plan,
                 components, selections, source_files, generated, cases,
                 evidence, events, processes, prefix, execution_audit,
                 exit_status="closed", fresh_of=None,
                 normalized_identity_fields=(), base_dir=None) -> dict:
    """Atomically publish one ``generic_runtime_bundle.v1`` directory.

    ``source_files`` is an iterable of ``(repository-relative path,
    archive-relative path)`` pairs; the repository bytes are archived and the
    verifier later recomputes the closure from those copies only.
    ``generated`` maps ``instance_id -> {file name: path}``.
    ``cases`` carry every case field except ``receipt_sha256`` (the writer seals
    it).  ``evidence`` is one document list per case (objects or dicts).

    A non-empty existing directory is never overwritten.  The bundle is built in
    a temporary sibling, verified by :func:`verify_saved_bundle`, and only then
    renamed into place; an integrity failure removes the temporary directory and
    raises, so no unverified bundle is ever published.
    """
    if type(plan) is not GenericExecutionPlan:
        _refuse("saved-plan-invalid", "/plan",
                {"expected": "GenericExecutionPlan"})
    base = Path(base_dir if base_dir is not None else Path.cwd())
    target = Path(bundle_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    _require_plain_directory(target.parent, "/bundle")
    if target.exists():
        if not target.is_dir():
            _refuse("saved-bundle-exists", "/bundle",
                    {"reason": "target-exists-and-is-not-a-directory"})
        try:
            empty = not any(target.iterdir())
        except OSError as error:
            _refuse("saved-bundle-unreadable", "/bundle",
                    {"reason": type(error).__name__})
        if not empty:
            _refuse("saved-bundle-exists", "/bundle",
                    {"reason": "refusing-to-overwrite-a-non-empty-bundle"})
    staging = target.parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
    staging.mkdir(parents=True)
    published = False
    try:
        archive_rows = []
        for index, pair in enumerate(source_files):
            if type(pair) not in (tuple, list) or len(pair) != 2:
                _refuse("saved-source-closure-mismatch", "/source_files",
                        {"reason": "expected (repository path, archive path)"})
            repository_path, archive_path = pair
            repository_path = _relpath(repository_path,
                                       "/source_files",
                                       "saved-source-closure-mismatch")
            archive_path = _relpath(archive_path, "/source_files",
                                    "saved-source-closure-mismatch",
                                    prefixes=(ARCHIVE_PREFIX,))
            payload = _source_bytes(base, repository_path)
            _write_bytes(staging, archive_path, payload)
            archive_rows.append({"path": repository_path,
                                 "archive_path": archive_path,
                                 "sha256": _digest_bytes(payload)})
        archive_rows.sort(key=lambda row: row["archive_path"])
        if not archive_rows:
            _refuse("saved-source-closure-mismatch", "/source_files",
                    {"reason": "source-closure-cannot-be-empty"})
        closure_sha256 = source_closure_sha256(
            [(row["archive_path"], row["sha256"]) for row in archive_rows])
        generated_rows = []
        for instance_id in sorted(generated):
            files = generated[instance_id]
            if type(files) is not dict or not files:
                _refuse("saved-generated-mismatch", "/generated",
                        {"reason": "instance-files-required",
                         "instance_id": str(instance_id)})
            hashes = {}
            for name in sorted(files):
                archive_path = f"{GENERATED_PREFIX}{instance_id}/{name}"
                _relpath(name, "/generated", "saved-generated-mismatch")
                source_path = Path(files[name])
                if not source_path.is_absolute():
                    source_path = base / source_path
                if source_path.is_symlink() or not source_path.is_file():
                    _refuse("saved-generated-mismatch", "/generated",
                            {"reason": "generated-file-missing",
                             "instance_id": str(instance_id)})
                payload = source_path.read_bytes()
                _write_bytes(staging, archive_path, payload)
                hashes[name] = _digest_bytes(payload)
            generated_rows.append({"instance_id": instance_id,
                                   "files": hashes})
        sealed_cases = []
        for position, case in enumerate(cases):
            rows = _closed(case, tuple(name for name in CASE_FIELDS
                                       if name != "receipt_sha256"),
                           f"/cases/{position}", "saved-case-shape",
                           optional=CASE_OPTIONAL_FIELDS)
            entry = dict(rows)
            if "index" in case and case["index"] != position:
                _refuse("saved-case-order", f"/cases/{position}/index",
                        {"expected": position, "actual": case["index"]})
            entry["index"] = position
            entry["receipt_sha256"] = case_receipt_sha256(entry)
            sealed_cases.append(entry)
        documents = _evidence_rows(evidence, len(sealed_cases))
        prepared = _closed(preparation, PREPARATION_KEYS, "/preparation",
                           "saved-bundle-manifest")
        manifest = {
            "schema_version": BUNDLE_SCHEMA,
            "producer": _closed(producer, ("id", "version",
                                           "implementation_sha256"),
                                "/producer", "saved-bundle-manifest"),
            "preparation": {"compose": prepared["compose"],
                            "capability_paths": list(
                                prepared["capability_paths"]),
                            "supplement": prepared["supplement"],
                            "flows": list(prepared["flows"])},
            "input_digests": dict(_closed(input_digests, ("d2", "d3"),
                                          "/input_digests",
                                          "saved-bundle-manifest")),
            "plan": {"schema_version": plan.schema_version,
                     "document_sha256": plan.identity_sha256,
                     "identity_sha256": plan.identity_sha256},
            "source_closure_sha256": closure_sha256,
            "case_count": len(sealed_cases),
            "exit_status": exit_status,
            "fresh_of": fresh_of,
            "normalized_identity_fields": sorted(
                set(normalized_identity_fields)),
        }
        inputs = {
            "compose": manifest["preparation"]["compose"],
            "capability_paths": manifest["preparation"]["capability_paths"],
            "supplement": manifest["preparation"]["supplement"],
            "flows": manifest["preparation"]["flows"],
            "input_digests": manifest["input_digests"],
            "source_closure": [{"path": row["archive_path"],
                                "sha256": row["sha256"]}
                               for row in archive_rows],
            "generated": generated_rows,
        }
        sources_document = {"source_closure_sha256": closure_sha256,
                            "files": archive_rows}
        _write_bytes(staging, "plan.json", plan.document_bytes)
        written = {"plan.json": plan.document_bytes}
        written["inputs.json"] = _write_document(staging, "inputs.json", inputs)
        written["components.json"] = _write_document(
            staging, "components.json",
            {"components": [component.document() for component in components]})
        written["selections.json"] = _write_document(
            staging, "selections.json",
            {"selections": [selection.document()
                            for selection in selections]})
        written["sources.json"] = _write_document(staging, "sources.json",
                                                  sources_document)
        written["cases.json"] = _write_document(
            staging, "cases.json",
            {"schema_version": CASE_SCHEMA,
             "plan_sha256": plan.identity_sha256,
             "cases": sealed_cases})
        written["evidence.json"] = _write_document(
            staging, "evidence.json", {"cases": documents})
        written["events.json"] = _write_document(staging, "events.json",
                                                 list(events))
        written["prefix.json"] = _write_document(staging, "prefix.json", prefix)
        written["execution_audit.json"] = _write_document(
            staging, "execution_audit.json", execution_audit)
        written["processes.json"] = _write_document(staging, "processes.json",
                                                    processes)
        files = {}
        for name, payload in written.items():
            files[name] = _digest_bytes(payload)
        for path in sorted(staging.rglob("*")):
            if path.is_dir():
                continue
            relative = path.relative_to(staging).as_posix()
            if relative == BUNDLE_FILE:
                continue
            if relative not in files:
                files[relative] = _digest_bytes(path.read_bytes())
        manifest["files"] = [{"path": path, "sha256": files[path]}
                             for path in sorted(files)]
        _write_document(staging, BUNDLE_FILE, manifest)
        verify_saved_bundle(staging)
        try:
            if target.exists():
                os.rmdir(target)
            os.rename(staging, target)
        except OSError as error:
            _refuse("saved-bundle-exists", "/bundle",
                    {"reason": "target-appeared-during-publish",
                     "error": type(error).__name__})
        published = True
        return verify_saved_bundle(target)
    finally:
        if not published and staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _evidence_rows(evidence, count: int) -> list[dict]:
    if type(evidence) is dict:
        rows = [evidence.get(index) for index in range(count)]
    else:
        rows = list(evidence)
    if len(rows) != count:
        _refuse("saved-evidence-shape", "/evidence",
                {"expected": count, "actual": len(rows)})
    documents = []
    for index, entry in enumerate(rows):
        if entry is None:
            _refuse("saved-evidence-missing", f"/evidence/{index}",
                    {"reason": "case-has-no-evidence"})
        parsed = []
        for offset, document in enumerate(entry):
            if isinstance(document, EffectEvidence):
                parsed.append(document.document())
            else:
                parsed.append(parse_effect_evidence(
                    document, pointer=f"/evidence/{index}/{offset}").document())
        if not parsed:
            _refuse("saved-evidence-missing", f"/evidence/{index}",
                    {"reason": "case-has-no-evidence"})
        documents.append({"index": index, "evidence": parsed})
    return documents


__all__ = [
    "BUNDLE_SCHEMA",
    "CASE_SCHEMA",
    "RECEIPT_SCHEMA",
    "VERIFICATION_SCHEMA",
    "FLOW_CLASSES",
    "SavedBundleRefused",
    "bundle_id",
    "case_receipt_sha256",
    "normalize_identity",
    "parse_effect_evidence",
    "parse_evidence_ref",
    "receipt_document",
    "refusal_report",
    "source_closure_sha256",
    "transaction_document",
    "verify_saved_bundle",
    "version_sha256",
    "version_state_sha256",
    "write_bundle",
]
