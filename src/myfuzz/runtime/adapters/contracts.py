"""Adapter-facing structural contracts for the generic runtime.

The dataclasses below describe transfers, pending operations and progress.  A
Python ``Protocol`` only constrains structure: it never certifies an
implementation, a source ABI or a native issuer.  Trusted implementations are
selected from a code-owned registry and re-check the actual artifact/ABI.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Mapping, Optional, Protocol, runtime_checkable

from myfuzz.scenario.ledger import TransactionKey

from ..contracts import (
    GenericRuntimeRefused,
    canonical_json_bytes,
    parse_closed_json,
    require_digest,
    require_identifier,
)
from ..evidence.contracts import EvidenceRef, parse_evidence_ref

PROGRESS_STATUSES = frozenset({"pending", "completed", "refused", "faulted",
                               "uncertain_effect"})
TARGET_OPERATIONS = frozenset({"read", "write"})


def _refuse(code: str, pointer: str, detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _require_int(value, pointer: str, *, minimum: int, maximum: int):
    if type(value) is not int or not minimum <= value <= maximum:
        _refuse("generic-contract-type", pointer,
                {"expected": "int", "minimum": minimum, "maximum": maximum})
    return value


def _require_key(value, pointer: str):
    if type(value) is not TransactionKey:
        _refuse("generic-contract-type", pointer, {"expected": "TransactionKey"})
    return value


def _key_document(key: TransactionKey) -> dict:
    return {
        "execution_id": key.execution_id,
        "testcase_id": key.testcase_id,
        "source_component": key.source_component,
        "source_epoch": key.source_epoch,
        "channel_id": key.channel_id,
        "source_sequence": key.source_sequence,
    }


def parse_transaction_key(document, *, pointer: str = "/key") -> TransactionKey:
    required = ("execution_id", "testcase_id", "source_component", "source_epoch",
                "channel_id", "source_sequence")
    rows = parse_closed_json(document, required, pointer=pointer)
    for name in ("execution_id", "testcase_id", "source_component", "channel_id"):
        require_identifier(rows[name], pointer + "/" + name)
    for name in ("source_epoch", "source_sequence"):
        _require_int(rows[name], pointer + "/" + name,
                     minimum=0, maximum=(1 << 63) - 1)
    return TransactionKey(rows["execution_id"], rows["testcase_id"],
                          rows["source_component"], rows["source_epoch"],
                          rows["channel_id"], rows["source_sequence"])


@dataclass(frozen=True, slots=True)
class TargetRequest:
    """One typed target transfer, already in source-protocol byte units.

    ``source_ref`` must join the current runner's real source-acceptance event
    for the same key; a bare address write is never accepted.
    """

    path_id: str
    source_ref: EvidenceRef
    address: int
    operation: str
    write_data: Optional[int]
    byte_enable: int
    size_bytes: int

    def __post_init__(self) -> None:
        if type(self) is not TargetRequest:
            _refuse("generic-contract-type", "/request")
        require_identifier(self.path_id, "/path_id")
        if type(self.source_ref) is not EvidenceRef:
            _refuse("generic-contract-type", "/source_ref")
        _require_int(self.address, "/address", minimum=0, maximum=(1 << 64) - 1)
        if type(self.operation) is not str or self.operation not in TARGET_OPERATIONS:
            _refuse("generic-contract-type", "/operation",
                    {"allowed": sorted(TARGET_OPERATIONS)})
        _require_int(self.size_bytes, "/size_bytes", minimum=1, maximum=512)
        if self.size_bytes not in (1, 2, 4, 8):
            _refuse("generic-contract-type", "/size_bytes",
                    {"allowed": [1, 2, 4, 8]})
        _require_int(self.byte_enable, "/byte_enable", minimum=0,
                     maximum=(1 << self.size_bytes) - 1)
        if self.operation == "read":
            if self.write_data is not None:
                _refuse("generic-contract-type", "/write_data",
                        {"expected": None, "operation": "read"})
            if self.byte_enable != (1 << self.size_bytes) - 1:
                _refuse("generic-contract-type", "/byte_enable",
                        {"expected": (1 << self.size_bytes) - 1,
                         "operation": "read"})
            return
        _require_int(self.write_data, "/write_data", minimum=0,
                     maximum=(1 << (8 * self.size_bytes)) - 1)
        if self.byte_enable == 0:
            _refuse("generic-contract-type", "/byte_enable",
                    {"expected": "nonzero write lanes"})

    def document(self) -> dict:
        return {
            "path_id": self.path_id,
            "source_ref": self.source_ref.document(),
            "address": self.address,
            "operation": self.operation,
            "write_data": self.write_data,
            "byte_enable": self.byte_enable,
            "size_bytes": self.size_bytes,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_json_bytes(self.document())

    def sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()

    @classmethod
    def from_document(cls, document, *, pointer: str = "") -> "TargetRequest":
        required = ("path_id", "source_ref", "address", "operation", "write_data",
                    "byte_enable", "size_bytes")
        rows = parse_closed_json(document, required, pointer=pointer)
        source_ref = parse_evidence_ref(rows["source_ref"],
                                        pointer=pointer + "/source_ref")
        return cls(rows["path_id"], source_ref, rows["address"], rows["operation"],
                   rows["write_data"], rows["byte_enable"], rows["size_bytes"])


@dataclass(frozen=True, slots=True)
class PreparedTargetOperation:
    """Provider-private pending handle.  Not serializable, not re-adoptable.

    The provider keeps its own ledger entry and binding object; constructing an
    equal dataclass value by hand grants nothing because ``advance``/``complete``
    only accept identities the provider itself issued.
    """

    key: TransactionKey
    operation_id: str
    request_sha256: str
    route_sha256: str
    binding_sha256: str

    def __post_init__(self) -> None:
        if type(self) is not PreparedTargetOperation:
            _refuse("generic-contract-type", "/operation")
        _require_key(self.key, "/key")
        require_digest(self.operation_id, "/operation_id")
        require_digest(self.request_sha256, "/request_sha256")
        require_digest(self.route_sha256, "/route_sha256")
        require_digest(self.binding_sha256, "/binding_sha256")


@dataclass(frozen=True, slots=True)
class ProviderProgress:
    """Result of one bounded advance of a prepared target operation."""

    key: TransactionKey
    status: str
    advanced_ticks: int
    response_bytes: Optional[bytes]
    raw_refs: tuple[EvidenceRef, ...]
    reason_code: Optional[str]

    def __post_init__(self) -> None:
        _require_key(self.key, "/key")
        if type(self.status) is not str or self.status not in PROGRESS_STATUSES:
            _refuse("generic-contract-type", "/status",
                    {"allowed": sorted(PROGRESS_STATUSES)})
        _require_int(self.advanced_ticks, "/advanced_ticks", minimum=0,
                     maximum=(1 << 31) - 1)
        if self.response_bytes is not None:
            if type(self.response_bytes) not in (bytes, bytearray):
                _refuse("generic-contract-type", "/response_bytes",
                        {"expected": "bytes or None"})
            object.__setattr__(self, "response_bytes", bytes(self.response_bytes))
            if len(self.response_bytes) not in (1, 2, 4, 8):
                _refuse("generic-contract-type", "/response_bytes",
                        {"expected": "1, 2, 4 or 8 canonical bytes"})
        if type(self.raw_refs) is not tuple or any(
                type(ref) is not EvidenceRef for ref in self.raw_refs):
            _refuse("generic-contract-type", "/raw_refs",
                    {"expected": "tuple of EvidenceRef"})
        if len({ref.canonical_bytes() for ref in self.raw_refs}) != len(self.raw_refs):
            _refuse("generic-contract-duplicate", "/raw_refs")
        if self.reason_code is not None:
            require_identifier(self.reason_code, "/reason_code")
        if self.status == "completed" and self.response_bytes is None:
            _refuse("generic-contract-shape", "/response_bytes",
                    {"status": self.status, "expected": "canonical response payload"})
        if self.status != "completed" and self.response_bytes is not None:
            _refuse("generic-contract-shape", "/response_bytes",
                    {"status": self.status, "expected": None})

    def document(self) -> dict:
        return {
            "key": _key_document(self.key),
            "status": self.status,
            "advanced_ticks": self.advanced_ticks,
            "response_hex": None if self.response_bytes is None
            else self.response_bytes.hex(),
            "raw_refs": [ref.document() for ref in self.raw_refs],
            "reason_code": self.reason_code,
        }


@runtime_checkable
class BoundProtocolAdapter(Protocol):
    """Structural view only; the concrete object keeps its trusted binding."""

    component_instance_id: str
    adapter_id: str
    adapter_version: str

    def assert_current(self) -> None: ...

    def close(self) -> None: ...


@runtime_checkable
class TargetProvider(Protocol):
    def prepare(self, key: TransactionKey, request: TargetRequest) -> object: ...

    def advance(self, operation: object, budget: int) -> ProviderProgress: ...

    def complete(self, operation: object) -> object: ...


@runtime_checkable
class CpuDriver(Protocol):
    def program_slots(self) -> Mapping[str, object]: ...

    def local_step_map(self) -> Mapping[str, object]: ...

    def assert_current(self) -> None: ...


@runtime_checkable
class ProtocolAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    def bind(self, component, session, selection) -> BoundProtocolAdapter: ...


def request_digest(request: TargetRequest) -> str:
    """Canonical request digest used by prepared-operation identities."""
    if type(request) is not TargetRequest:
        _refuse("generic-contract-type", "/request")
    return request.sha256()


def operation_id_for(*, key: TransactionKey, request_sha256: str,
                     route_sha256: str, binding_sha256: str) -> str:
    """Operation identity over the complete key/request/route/binding tuple."""
    require_digest(request_sha256, "/request_sha256")
    require_digest(route_sha256, "/route_sha256")
    require_digest(binding_sha256, "/binding_sha256")
    payload = {
        "schema_version": "prepared_target_operation_id.v1",
        "key": _key_document(key),
        "request_sha256": request_sha256,
        "route_sha256": route_sha256,
        "binding_sha256": binding_sha256,
    }
    return sha256(canonical_json_bytes(payload)).hexdigest()
