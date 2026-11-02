"""Closed descriptive contracts, unique capability selection and plan identity.

Nothing here grants native authority.  ``GenericExecutionPlan`` is a static,
detached documentary object; accepted live handles are issued in-process by
``PreparationContext``/``TargetProvider`` registries and are checked by object
identity, never by re-parsing JSON.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from threading import RLock

PLAN_SCHEMA = "generic_execution_plan.v1"
DESCRIPTOR_SCHEMA = "verified_component_descriptor.v1"

PLAN_TOP_LEVEL = (
    "schema_version",
    "components",
    "selections",
    "paths",
    "sources",
    "constraints",
    "seeds",
    "assertions",
    "memory",
    "scheduling",
    "termination",
    "evidence_obligations",
    "input_digests",
)

DESCRIPTOR_TOP_LEVEL = (
    "schema_version",
    "instance_id",
    "source_sha256",
    "profile_sha256",
    "artifact_sha256",
    "semantic_contract_sha256",
    "source_verifier",
    "endpoints",
)

ENDPOINT_KEYS = (
    "endpoint_id",
    "role",
    "protocol",
    "template",
    "semantic_kind",
    "operations",
    "data_width",
    "address_width",
    "address_units",
    "max_outstanding",
    "completion_kind",
    "byte_enable",
    "evidence_capabilities",
)

ROLES = frozenset({"cpu", "target", "dma_master", "irq_source"})
ADDRESS_UNITS = frozenset({"byte", "word"})
TARGET_OPERATIONS = frozenset({"read", "write"})

# Reference refusal codes from design section 5.3.  Contract-level codes are
# additional; every refusal carries a JSON pointer and a value-free detail.
REFUSAL_CODES = frozenset({
    "generic-source-unverified",
    "generic-semantic-unsupported",
    "generic-template-mismatch",
    "generic-adapter-missing",
    "generic-adapter-ambiguous",
    "generic-binding-drift",
    "generic-plan-mismatch",
    "generic-route-refused",
    "generic-evidence-missing",
})

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:+/@-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class GenericRuntimeRefused(ValueError):
    """Typed refusal: machine code, JSON pointer and value-free detail."""

    def __init__(self, code: str, pointer: str = "", detail=None):
        if type(code) is not str or not _IDENTIFIER.match(code):
            raise TypeError("refusal code must be a stable identifier")
        if type(pointer) is not str:
            raise TypeError("refusal pointer must be a string")
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f"{code} at {pointer or '/'}")

    def document(self) -> dict:
        return {"code": self.code, "pointer": self.pointer,
                "detail": self.detail}


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def require_identifier(value, pointer: str = "") -> str:
    if type(value) is not str or not _IDENTIFIER.match(value):
        _refuse("generic-contract-type", pointer,
                {"expected": "stable identifier", "maximum_length": 200})
    return value


def require_digest(value, pointer: str = "") -> str:
    if type(value) is not str or not _DIGEST.match(value):
        _refuse("generic-contract-type", pointer,
                {"expected": "lowercase hex SHA-256"})
    return value


def canonical_json_bytes(value) -> bytes:
    """Canonical UTF-8 bytes; same JSON value always yields the same bytes."""
    try:
        text = json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        _refuse("generic-contract-json", "", {"reason": type(error).__name__,
                                              "message": str(error)[:120]})
    return text.encode("utf-8")


def _pairs_hook(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKey(key)
        seen[key] = value
    return seen


class _DuplicateKey(ValueError):
    def __init__(self, key):
        self.key = key
        super().__init__(key)


def _reject_constant(name):
    raise GenericRuntimeRefused("generic-contract-json", "",
                                {"reason": "non-finite-number",
                                 "token": str(name)[:16]})


def strict_json_loads(raw, *, pointer: str = ""):
    """Parse JSON refusing duplicate keys, NaN/Infinity and non-UTF-8 bytes."""
    if type(raw) is bytes or type(raw) is bytearray:
        try:
            text = bytes(raw).decode("utf-8")
        except UnicodeDecodeError as error:
            _refuse("generic-contract-json", pointer,
                    {"reason": "invalid-utf-8", "position": error.start})
    elif type(raw) is str:
        text = raw
    else:
        _refuse("generic-contract-json", pointer,
                {"expected": "UTF-8 bytes or text"})
    try:
        return json.loads(text, object_pairs_hook=_pairs_hook,
                          parse_constant=_reject_constant)
    except _DuplicateKey as error:
        _refuse("generic-contract-json-duplicate-key", pointer,
                {"key": str(error.key)[:64]})
    except GenericRuntimeRefused:
        raise
    except (ValueError, UnicodeDecodeError) as error:
        _refuse("generic-contract-json", pointer,
                {"reason": type(error).__name__, "message": str(error)[:120]})


def parse_closed_json(document, required, *, optional=(), pointer: str = ""):
    """Closed-shape object check; accepts an already-parsed dict."""
    required = tuple(required)
    optional = tuple(optional)
    if type(document) is not dict:
        _refuse("generic-contract-shape", pointer,
                {"expected": "JSON object"})
    missing = [name for name in required if name not in document]
    extra = [name for name in document
             if name not in required and name not in optional]
    if missing:
        _refuse("generic-contract-shape", pointer + "/" + missing[0],
                {"reason": "missing-field", "required": list(required)})
    if extra:
        _refuse("generic-contract-shape", pointer + "/" + extra[0],
                {"reason": "unexpected-field"})
    return {name: document[name] for name in required}


def _require_tuple(value, pointer: str, *, length: int, item_check):
    if type(value) is not tuple or len(value) != length:
        _refuse("generic-contract-type", pointer,
                {"expected": f"tuple of {length}", "length": length})
    for index, item in enumerate(value):
        item_check(item, pointer + f"/{index}")
    return value


def _require_text_tuple(value, pointer: str, *, length: int,
                        allowed=None, sorted_unique: bool = True):
    def check(item, item_pointer):
        if type(item) is not str or not item:
            _refuse("generic-contract-type", item_pointer,
                    {"expected": "nonempty string"})
    _require_tuple(value, pointer, length=length, item_check=check)
    if allowed is not None:
        for index, item in enumerate(value):
            if item not in allowed:
                _refuse("generic-contract-type", pointer + f"/{index}",
                        {"allowed": sorted(allowed)})
    if sorted_unique:
        if list(value) != sorted(set(value)):
            _refuse("generic-contract-shape", pointer,
                    {"expected": "unique, lexicographically sorted"})
    return value


def _require_positive_int(value, pointer: str, *, maximum: int):
    if type(value) is not int or not 1 <= value <= maximum:
        _refuse("generic-contract-type", pointer,
                {"expected": "int", "minimum": 1, "maximum": maximum})
    return value


def _require_bool(value, pointer: str):
    if type(value) is not bool:
        _refuse("generic-contract-type", pointer, {"expected": "bool"})
    return value


@dataclass(frozen=True, slots=True)
class CapabilityRequirement:
    """What a caller needs; never a claim about what the source provides."""

    role: str
    endpoint_id: str
    protocol: tuple[str, str]
    template: tuple[str, str, str]
    semantic_kind: str
    operations: tuple[str, ...]
    data_width: int
    address_width: int
    max_outstanding: int
    completion_kind: str
    byte_enable_required: bool
    address_units: str
    evidence_obligations: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self) is not CapabilityRequirement:
            _refuse("generic-contract-type", "/requirement")
        if type(self.role) is not str or self.role not in ROLES:
            _refuse("generic-contract-type", "/role", {"allowed": sorted(ROLES)})
        require_identifier(self.endpoint_id, "/endpoint_id")
        _require_text_tuple(self.protocol, "/protocol", length=2,
                            sorted_unique=False)
        _require_text_tuple(self.template, "/template", length=3,
                            sorted_unique=False)
        require_identifier(self.semantic_kind, "/semantic_kind")
        _require_text_tuple(self.operations, "/operations", length=len(self.operations),
                            allowed=TARGET_OPERATIONS)
        if not self.operations:
            _refuse("generic-contract-shape", "/operations",
                    {"expected": "at least one operation"})
        _require_positive_int(self.data_width, "/data_width", maximum=4096)
        _require_positive_int(self.address_width, "/address_width", maximum=64)
        _require_positive_int(self.max_outstanding, "/max_outstanding",
                              maximum=1024)
        require_identifier(self.completion_kind, "/completion_kind")
        _require_bool(self.byte_enable_required, "/byte_enable_required")
        if type(self.address_units) is not str or self.address_units not in ADDRESS_UNITS:
            _refuse("generic-contract-type", "/address_units",
                    {"allowed": sorted(ADDRESS_UNITS)})
        _require_text_tuple(self.evidence_obligations, "/evidence_obligations",
                            length=len(self.evidence_obligations))
        for obligation in self.evidence_obligations:
            require_identifier(obligation, "/evidence_obligations")

    def document(self) -> dict:
        return {
            "role": self.role,
            "endpoint_id": self.endpoint_id,
            "protocol": list(self.protocol),
            "template": list(self.template),
            "semantic_kind": self.semantic_kind,
            "operations": list(self.operations),
            "data_width": self.data_width,
            "address_width": self.address_width,
            "max_outstanding": self.max_outstanding,
            "completion_kind": self.completion_kind,
            "byte_enable_required": self.byte_enable_required,
            "address_units": self.address_units,
            "evidence_obligations": list(self.evidence_obligations),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.document())

    def sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def _validate_endpoint(document, pointer: str) -> dict:
    rows = parse_closed_json(document, ENDPOINT_KEYS, pointer=pointer)
    require_identifier(rows["endpoint_id"], pointer + "/endpoint_id")
    if type(rows["role"]) is not str or rows["role"] not in ROLES:
        _refuse("generic-contract-type", pointer + "/role",
                {"allowed": sorted(ROLES)})
    for name in ("protocol", "template"):
        if type(rows[name]) is not list or not all(
                type(item) is str and item for item in rows[name]):
            _refuse("generic-contract-type", pointer + "/" + name,
                    {"expected": "list of nonempty strings"})
    if len(rows["protocol"]) != 2:
        _refuse("generic-contract-shape", pointer + "/protocol",
                {"expected_length": 2, "actual": len(rows["protocol"])})
    if len(rows["template"]) != 3:
        _refuse("generic-contract-shape", pointer + "/template",
                {"expected_length": 3, "actual": len(rows["template"])})
    require_identifier(rows["semantic_kind"], pointer + "/semantic_kind")
    for name in ("operations", "evidence_capabilities"):
        values = rows[name]
        if type(values) is not list or not values:
            _refuse("generic-contract-shape", pointer + "/" + name,
                    {"expected": "nonempty list"})
        if any(type(item) is not str or not item for item in values):
            _refuse("generic-contract-type", pointer + "/" + name)
        if values != sorted(set(values)):
            _refuse("generic-contract-shape", pointer + "/" + name,
                    {"expected": "unique, lexicographically sorted"})
    for name in ("data_width", "address_width", "max_outstanding"):
        _require_positive_int(rows[name], pointer + "/" + name, maximum=4096)
    if type(rows["address_units"]) is not str or rows["address_units"] not in ADDRESS_UNITS:
        _refuse("generic-contract-type", pointer + "/address_units",
                {"allowed": sorted(ADDRESS_UNITS)})
    require_identifier(rows["completion_kind"], pointer + "/completion_kind")
    if type(rows["byte_enable"]) is not bool:
        _refuse("generic-contract-type", pointer + "/byte_enable",
                {"expected": "bool"})
    return rows


@dataclass(frozen=True, slots=True)
class VerifiedComponent:
    """Admitted source/profile/artifact identity plus its closed descriptor."""

    instance_id: str
    source_sha256: str
    profile_sha256: str
    artifact_sha256: str
    semantic_contract_sha256: str
    descriptor_bytes: bytes

    def __post_init__(self) -> None:
        if type(self) is not VerifiedComponent:
            _refuse("generic-contract-type", "/component")
        require_identifier(self.instance_id, "/instance_id")
        for name in ("source_sha256", "profile_sha256", "artifact_sha256",
                     "semantic_contract_sha256"):
            require_digest(getattr(self, name), "/" + name)
        if type(self.descriptor_bytes) not in (bytes, bytearray):
            _refuse("generic-contract-type", "/descriptor_bytes",
                    {"expected": "canonical UTF-8 JSON bytes"})
        object.__setattr__(self, "descriptor_bytes", bytes(self.descriptor_bytes))
        document = strict_json_loads(self.descriptor_bytes,
                                     pointer="/descriptor")
        rows = parse_closed_json(document, DESCRIPTOR_TOP_LEVEL,
                                 pointer="/descriptor")
        if rows["schema_version"] != DESCRIPTOR_SCHEMA:
            _refuse("generic-contract-shape", "/descriptor/schema_version",
                    {"expected": DESCRIPTOR_SCHEMA})
        if rows["instance_id"] != self.instance_id:
            _refuse("generic-contract-mismatch", "/descriptor/instance_id")
        for name in ("source_sha256", "profile_sha256", "artifact_sha256",
                     "semantic_contract_sha256"):
            if rows[name] != getattr(self, name):
                _refuse("generic-contract-mismatch", "/descriptor/" + name)
        verifier = parse_closed_json(rows["source_verifier"],
                                     ("id", "version", "implementation_sha256"),
                                     pointer="/descriptor/source_verifier")
        require_identifier(verifier["id"], "/descriptor/source_verifier/id")
        require_identifier(verifier["version"],
                           "/descriptor/source_verifier/version")
        require_digest(verifier["implementation_sha256"],
                       "/descriptor/source_verifier/implementation_sha256")
        endpoints = rows["endpoints"]
        if type(endpoints) is not list or not endpoints:
            _refuse("generic-contract-shape", "/descriptor/endpoints",
                    {"expected": "nonempty list"})
        seen = set()
        for index, endpoint in enumerate(endpoints):
            validated = _validate_endpoint(
                endpoint, f"/descriptor/endpoints/{index}")
            if validated["endpoint_id"] in seen:
                _refuse("generic-contract-duplicate",
                        f"/descriptor/endpoints/{index}/endpoint_id")
            seen.add(validated["endpoint_id"])
        if self.descriptor_bytes != canonical_json_bytes(document):
            _refuse("generic-contract-shape", "/descriptor",
                    {"expected": "canonical JSON bytes"})

    def document(self) -> dict:
        return strict_json_loads(self.descriptor_bytes, pointer="/descriptor")

    def endpoints(self) -> tuple[dict, ...]:
        return tuple(self.document()["endpoints"])

    def descriptor_sha256(self) -> str:
        return sha256(self.descriptor_bytes).hexdigest()


@dataclass(frozen=True, slots=True)
class AdapterSelection:
    """Code-owned implementation choice; not a source or native token."""

    adapter_id: str
    adapter_version: str
    implementation_sha256: str
    component_artifact_sha256: str
    semantic_contract_sha256: str

    def __post_init__(self) -> None:
        if type(self) is not AdapterSelection:
            _refuse("generic-contract-type", "/selection")
        require_identifier(self.adapter_id, "/adapter_id")
        require_identifier(self.adapter_version, "/adapter_version")
        for name in ("implementation_sha256", "component_artifact_sha256",
                     "semantic_contract_sha256"):
            require_digest(getattr(self, name), "/" + name)

    def document(self) -> dict:
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "implementation_sha256": self.implementation_sha256,
            "component_artifact_sha256": self.component_artifact_sha256,
            "semantic_contract_sha256": self.semantic_contract_sha256,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.document())

    def sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def _validate_object_list(document, name: str) -> list:
    rows = document[name]
    if type(rows) is not list:
        _refuse("generic-contract-type", "/" + name, {"expected": "list"})
    for index, row in enumerate(rows):
        if type(row) is not dict:
            _refuse("generic-contract-type", f"/{name}/{index}",
                    {"expected": "JSON object"})
    digests = [canonical_json_bytes(row) for row in rows]
    if len(set(digests)) != len(digests):
        _refuse("generic-contract-duplicate", "/" + name)
    return rows


def _validate_plan_document(document) -> dict:
    rows = parse_closed_json(document, PLAN_TOP_LEVEL, pointer="/plan")
    if rows["schema_version"] != PLAN_SCHEMA:
        _refuse("generic-contract-shape", "/plan/schema_version",
                {"expected": PLAN_SCHEMA})
    for name in ("components", "selections", "paths", "sources", "constraints",
                 "seeds", "assertions"):
        _validate_object_list(rows, name)
    for name in ("memory", "scheduling", "termination"):
        if type(rows[name]) is not dict:
            _refuse("generic-contract-type", "/plan/" + name,
                    {"expected": "JSON object"})
    obligations = rows["evidence_obligations"]
    if type(obligations) is not list:
        _refuse("generic-contract-type", "/plan/evidence_obligations",
                {"expected": "list"})
    for index, item in enumerate(obligations):
        require_identifier(item, f"/plan/evidence_obligations/{index}")
    if obligations != sorted(set(obligations)):
        _refuse("generic-contract-shape", "/plan/evidence_obligations",
                {"expected": "unique, lexicographically sorted"})
    digests = parse_closed_json(rows["input_digests"], ("d2", "d3"),
                                pointer="/plan/input_digests")
    for name in ("d2", "d3"):
        require_digest(digests[name], "/plan/input_digests/" + name)
    return rows


@dataclass(frozen=True, slots=True)
class GenericExecutionPlan:
    """Static documentary plan.  Detached copies only; never live authority."""

    schema_version: str
    document_bytes: bytes
    identity_sha256: str

    def __post_init__(self) -> None:
        if type(self) is not GenericExecutionPlan:
            _refuse("generic-contract-type", "/plan")
        if self.schema_version != PLAN_SCHEMA:
            _refuse("generic-contract-shape", "/schema_version",
                    {"expected": PLAN_SCHEMA})
        if type(self.document_bytes) not in (bytes, bytearray):
            _refuse("generic-contract-type", "/document_bytes",
                    {"expected": "canonical UTF-8 JSON bytes"})
        object.__setattr__(self, "document_bytes", bytes(self.document_bytes))
        require_digest(self.identity_sha256, "/identity_sha256")
        document = strict_json_loads(self.document_bytes, pointer="/plan")
        _validate_plan_document(document)
        if canonical_json_bytes(document) != self.document_bytes:
            _refuse("generic-contract-shape", "/plan",
                    {"expected": "canonical JSON bytes"})
        if sha256(self.document_bytes).hexdigest() != self.identity_sha256:
            _refuse("generic-contract-mismatch", "/identity_sha256",
                    {"expected": "sha256(document_bytes)"})

    @classmethod
    def freeze(cls, document: dict) -> "GenericExecutionPlan":
        """Validate, canonicalize and freeze a caller-owned plan document."""
        if type(document) is not dict:
            _refuse("generic-contract-type", "/plan", {"expected": "JSON object"})
        _validate_plan_document(document)
        frozen = canonical_json_bytes(document)
        return cls(PLAN_SCHEMA, frozen, sha256(frozen).hexdigest())

    def document(self) -> dict:
        return strict_json_loads(self.document_bytes, pointer="/plan")

    def documentary_snapshot(self) -> dict:
        return json.loads(self.document_bytes.decode("utf-8"))


class ProcessLocalIssuance:
    """Identity membership for live handles issued in this process.

    Values issued here are compared with ``is``.  An equal dataclass value, a
    JSON round-trip or a hand-built reconstruction is not a member.  The
    documentary snapshot is a separate non-authoritative export.
    """

    __slots__ = ("_name", "_records", "_lock", "_closed")

    def __init__(self, name: str):
        self._name = require_identifier(name)
        self._records: dict[int, tuple[object, bytes]] = {}
        self._lock = RLock()
        self._closed = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def issue(self, handle, *, snapshot: bytes) -> object:
        if type(snapshot) is not bytes:
            _refuse("generic-contract-type", "/snapshot",
                    {"expected": "canonical UTF-8 JSON bytes"})
        with self._lock:
            if self._closed:
                _refuse("generic-binding-drift", "/issuance",
                        {"issuance": self._name, "state": "closed"})
            self._records[id(handle)] = (handle, snapshot)
        return handle

    def records(self) -> tuple:
        """Issued handles in insertion order (identity-bearing, live only)."""
        with self._lock:
            return tuple(row[0] for row in self._records.values())

    def holds(self, handle) -> bool:
        with self._lock:
            if self._closed:
                return False
            row = self._records.get(id(handle))
            return row is not None and row[0] is handle

    def snapshot(self, handle) -> bytes:
        self.require(handle)
        return self._records[id(handle)][1]

    def require(self, handle, *, pointer: str = "") -> object:
        if not self.holds(handle):
            _refuse("generic-binding-drift", pointer or "/handle",
                    {"issuance": self._name,
                     "reason": "not-issued-by-this-process"})
        return handle

    def revoke(self, handle) -> None:
        with self._lock:
            row = self._records.get(id(handle))
            if row is not None and row[0] is handle:
                self._records.pop(id(handle))

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._records.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
