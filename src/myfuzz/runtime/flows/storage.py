"""First code-owned flow kernel: APB3 storage over F2 read-response and F4 write/readback.

Scope and honesty rules
-----------------------
* A kernel is component-neutral.  Every fact it derives comes from a *declared
  token* of the same D3/plan path (``flow_id``, source ``kind``, the declared
  ``register_access``, ``bound_inputs``, ``assertions``, ``termination``) or
  from the plan path's ``bindings`` rows the compiler emits (role, instance,
  endpoint, protocol, template, semantic kind, operations, widths, units,
  outstanding, completion, byte enable, evidence obligations).  Component,
  register and instance names are only identity pointers for joining rows; they
  never select behaviour.
* ``requirements`` refuses ``generic-template-mismatch`` with a JSON pointer
  when a required token is absent.  It never defaults a protocol, template,
  width, unit or completion kind.  Obligations declared by the plan must cover
  the flow's own minimum obligation set, never shrink it.
* ``prepare`` may only *reference* the live binding: the bound plan, its plan
  document, its declared source layout and the existing raw event log.  It
  creates no session, runner, memory, ledger or scheduler and drives no RTL.
* ``lower`` validates the directed closed shape ``generic_case_sequence.v1``
  (plan digest, path, declared fuzzable source, every raw record) before
  anything is admitted, and never truncates a raw record list.
* ``capture`` translates a real per-case certificate into the four-state
  evidence vocabulary.  ``unsupported`` means the receipt provided no witness
  for that obligation at all, ``missing`` means a claimed reference is not in
  the live raw event store, ``contradicted`` means two declared witnesses
  disagree.  Nothing is promoted from observed to consumed, and a receipt that
  does not certify its own chain cannot certify an obligation.
* ``feedback`` derives candidate program inputs from the supplied checker/edge
  evidence and the declared mutation layout only.  It never reads expected
  values of a case, and a source whose declared domain holds a single value
  yields no invented alternative.

Two path shapes are accepted, because G4's compiled plan restates the same
declared facts differently from the raw D3 rows:

* raw D3 (``sources`` carry their own ``register_access`` and the path carries
  ``runtime_path_identity``/``termination_observation``), and
* compiled plan (``sources`` carry identity only, the declared register access
  lives in ``constraints.source_constraints``, edges are ``from``/``to`` and the
  F2 read contract is the path's own ``execution_contract``).

The plan shape is re-joined from declared values only and handed to the shipped
pure candidate-layout compilers, whose own checks (constraint mirrors, read
contract marker) refuse if the re-join is not exactly the declared plan.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from collections.abc import Sequence
from hashlib import sha256
import json
from pathlib import Path
import re

from ...scenario.ledger import TransactionKey
from ..contracts import (
    ADDRESS_UNITS,
    ROLES,
    TARGET_OPERATIONS,
    CapabilityRequirement,
    GenericRuntimeRefused,
    canonical_json_bytes,
    parse_closed_json,
    require_identifier,
)
from ..evidence.contracts import EffectEvidence, EvidenceRef, combine_status
from ..semantics.contracts import STORAGE_RW

KERNEL_ID = "storage.kernel.v1"
KERNEL_SCHEMA = "generic_flow_kernel.v1"
CASE_SEQUENCE_SCHEMA = "generic_case_sequence.v1"
SEQUENCE_KEYS = ("schema_version", "plan_sha256", "cases")
CASE_KEYS = ("testcase_id", "path_id", "source_id", "raw_records_hex")
STORAGE_FLOWS = ("F2", "F4")
STREAM_KIND_BY_FLOW = {"F2": "cpu_load_stream", "F4": "cpu_mmio_stream"}
STREAM_KINDS = frozenset(STREAM_KIND_BY_FLOW.values())
IMAGE_KIND = "instruction_image"
MAX_RECORD_BYTES = 128
MAX_FEEDBACK_VALUES = 8
DEFAULT_FEEDBACK_VALUES = 2

#: Obligations the kernel can state, in the same vocabulary as
#: ``myfuzz.runtime.evidence.contracts.SCOPES`` and the registry's endpoint
#: ``evidence_capabilities``.
OBLIGATIONS = ("component_semantic_effect", "cross_component_consumption",
               "cross_component_source", "physical_protocol_sample")

#: Minimum obligations of each side of each flow, derived from the code-owned
#: storage semantics (F2 returns the live register version to the CPU, F4
#: commits the register and reads it back through the CPU).
_FLOW_OBLIGATIONS = {
    "F2": {
        "target": ("component_semantic_effect", "cross_component_source",
                   "physical_protocol_sample"),
        "cpu": ("cross_component_consumption", "physical_protocol_sample"),
    },
    "F4": {
        "target": ("component_semantic_effect", "cross_component_consumption",
                   "physical_protocol_sample"),
        "cpu": ("cross_component_source", "physical_protocol_sample"),
    },
}
_DEFAULT_OPERATIONS = {
    "F2": {"target": ("read",), "cpu": ("read",)},
    "F4": {"target": ("write",), "cpu": ("write",)},
}

_ENDPOINT_BINDING_KEYS = (
    "role", "instance_id", "endpoint_id", "protocol", "template",
    "semantic_kind", "operations", "data_width", "address_width",
    "address_units", "max_outstanding", "completion_kind", "byte_enable",
)
_ENDPOINT_BINDING_OPTIONAL = (
    "required_operations", "supported_operations", "evidence_obligations",
    "supported_evidence", "adapter", "descriptor_sha256", "flows", "path_ids",
    "adapter_id", "adapter_version", "implementation_sha256",
)
_ACCESS_KEYS = (
    "schema_version", "source_component", "source_endpoint", "target_component",
    "target_endpoint", "operation", "width_bytes", "value_mask",
    "access_alignment", "register", "field",
)
#: The exact key set the shipped candidate-layout compilers accept on a source
#: row and on its constraint mirror.
_LAYOUT_MIRROR_KEYS = ("source_id", "origin", "kind", "width", "bit_offset",
                       "mask", "alignment", "range", "constraint_basis",
                       "register_access")
_LAYOUT_SOURCE_EXTRA = ("component", "endpoint_id", "port", "register", "field",
                        "origin_ref")
_LAYOUT_SHARED = ("origin", "kind", "width", "bit_offset", "mask", "alignment",
                  "range")
_TRANSACTION_KEYS = ("execution_id", "testcase_id", "source_component",
                     "source_epoch", "channel_id", "source_sequence")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _hex64(value) -> bool:
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _is_int(value) -> bool:
    return type(value) is int and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# Directed case sequence (generic_case_sequence.v1)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class LoweredCase:
    """One validated directed case, already bound to its D3 path and source."""

    testcase_id: str
    path_id: str
    source_id: str
    flow_id: str
    record_length: int
    raw_records: tuple[bytes, ...]

    def document(self) -> dict:
        return {
            "testcase_id": self.testcase_id,
            "path_id": self.path_id,
            "source_id": self.source_id,
            "flow_id": self.flow_id,
            "record_length": self.record_length,
            "raw_records_hex": [raw.hex() for raw in self.raw_records],
        }


def _require_hex_record(value, pointer: str) -> bytes:
    if type(value) is not str or not value:
        _refuse("generic-case-shape", pointer,
                {"expected": "nonempty hex string", "reason": "raw-record-text"})
    if len(value) % 2 or len(value) > MAX_RECORD_BYTES * 2:
        _refuse("generic-case-shape", pointer,
                {"expected_bytes": len(value) // 2,
                 "maximum_bytes": MAX_RECORD_BYTES,
                 "reason": "raw-record-length"})
    try:
        return bytes.fromhex(value)
    except ValueError:
        _refuse("generic-case-shape", pointer, {"reason": "raw-record-hex"})


def load_case_sequence(*, plan_sha256: str, path_flows: Mapping, document,
                       allow_mixed: bool = False):
    """Validate one closed ``generic_case_sequence.v1`` document before admission.

    Refuses a plan digest mismatch, an unknown path, a closed-shape violation,
    a duplicate case and -- critically -- a sequence whose cases resolve to
    more than one compiled flow.  A mixed F2/F4 sequence is not silently run as
    one flow: no versioned wire/flow selector exists yet.
    """
    if type(plan_sha256) is not str or not _hex64(plan_sha256):
        _refuse("generic-plan-mismatch", "/plan_sha256",
                {"reason": "bound-plan-digest-required"})
    rows = parse_closed_json(document, SEQUENCE_KEYS, pointer="/sequence")
    if rows["schema_version"] != CASE_SEQUENCE_SCHEMA:
        _refuse("generic-case-shape", "/sequence/schema_version",
                {"expected": CASE_SEQUENCE_SCHEMA})
    if type(rows["plan_sha256"]) is not str:
        _refuse("generic-case-shape", "/sequence/plan_sha256",
                {"expected": "lowercase hex SHA-256"})
    if rows["plan_sha256"] != plan_sha256:
        _refuse("generic-plan-mismatch", "/sequence/plan_sha256",
                {"reason": "sequence-plan-digest-mismatch"})
    cases = rows["cases"]
    if type(cases) is not list or not cases:
        _refuse("generic-case-shape", "/sequence/cases",
                {"expected": "nonempty list of directed cases"})
    seen: set[str] = set()
    resolved: list[tuple[dict, str]] = []
    for index, case in enumerate(cases):
        pointer = f"/sequence/cases/{index}"
        closed = parse_closed_json(case, CASE_KEYS, pointer=pointer)
        testcase_id = require_identifier(closed["testcase_id"],
                                         pointer + "/testcase_id")
        if testcase_id in seen:
            _refuse("generic-case-duplicate", pointer + "/testcase_id",
                    {"testcase_id": testcase_id})
        seen.add(testcase_id)
        path_id = closed["path_id"]
        if type(path_id) is not str or path_id not in path_flows:
            _refuse("generic-plan-mismatch", pointer + "/path_id",
                    {"reason": "path-not-declared-by-plan", "path_id": path_id})
        require_identifier(closed["source_id"], pointer + "/source_id")
        raw = closed["raw_records_hex"]
        if type(raw) is not list or not raw:
            _refuse("generic-case-shape", pointer + "/raw_records_hex",
                    {"expected": "nonempty list; records are never truncated"})
        for record_index, record in enumerate(raw):
            _require_hex_record(record,
                                pointer + f"/raw_records_hex/{record_index}")
        resolved.append((dict(closed), path_flows[path_id]))
    flows = sorted({flow for _, flow in resolved})
    if len(flows) > 1 and not allow_mixed:
        _refuse("generic-flow-mixed-unsupported", "/sequence/cases",
                {"flows": flows,
                 "reason": "one campaign fixes one compiled flow and layout; a "
                           "mixed directed sequence needs a versioned outer "
                           "dispatch contract that does not exist in G5"})
    return tuple(row for row, _ in resolved)


# ---------------------------------------------------------------------------
# D3 / plan path facts and requirement derivation
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _PathFacts:
    path: dict
    path_id: str
    flow_id: str
    stream: dict
    image: dict
    access: dict
    bindings: tuple[dict, ...]
    cpu_binding: dict
    target_binding: dict
    source_ids: tuple[str, ...]
    bound_input_kinds: tuple[str, ...]
    assertion_ids: tuple[str, ...]
    termination_kind: str
    execution_contract: dict | None

    @property
    def cpu_component(self) -> str:
        return self.access["source_component"]

    @property
    def target_component(self) -> str:
        return self.access["target_component"]

    @property
    def instruction_component(self) -> str:
        return self.image["component"]

    @property
    def source_id(self) -> str:
        return self.stream["source_id"]

    @property
    def fuzzable_source_ids(self) -> tuple[str, ...]:
        return tuple(row["source_id"] for row in self.path["sources"]
                     if row.get("origin") == "fuzzable")


def _path_document(d3_path) -> dict:
    if isinstance(d3_path, Mapping):
        return dict(d3_path)
    document = getattr(d3_path, "document", None)
    if callable(document):
        value = document()
        if isinstance(value, Mapping):
            return dict(value)
    path = getattr(d3_path, "path", None)
    if isinstance(path, Mapping):
        return dict(path)
    _refuse("generic-contract-type", "/d3_path",
            {"expected": "D3/plan path mapping or an object exposing document()"})


def _endpoint_binding(row, pointer: str) -> dict:
    """Closed endpoint-token row; an absent token is a refusal, never a default."""
    if not isinstance(row, Mapping):
        _refuse("generic-template-mismatch", pointer,
                {"expected": "declared endpoint binding row"})
    missing = [name for name in _ENDPOINT_BINDING_KEYS if name not in row]
    if missing:
        _refuse("generic-template-mismatch", pointer + "/" + missing[0],
                {"reason": "missing-endpoint-token", "token": missing[0],
                 "required": list(_ENDPOINT_BINDING_KEYS)})
    extra = sorted(name for name in row
                   if name not in _ENDPOINT_BINDING_KEYS
                   and name not in _ENDPOINT_BINDING_OPTIONAL)
    if extra:
        _refuse("generic-template-mismatch", pointer + "/" + extra[0],
                {"reason": "unexpected-endpoint-token"})
    role = row["role"]
    if type(role) is not str or role not in ROLES:
        _refuse("generic-template-mismatch", pointer + "/role",
                {"allowed": sorted(ROLES)})
    require_identifier(row["instance_id"], pointer + "/instance_id")
    require_identifier(row["endpoint_id"], pointer + "/endpoint_id")
    require_identifier(row["semantic_kind"], pointer + "/semantic_kind")
    require_identifier(row["completion_kind"], pointer + "/completion_kind")
    for name, length in (("protocol", 2), ("template", 3)):
        value = row[name]
        if (type(value) not in (list, tuple) or len(value) != length
                or any(type(item) is not str or not item for item in value)):
            _refuse("generic-template-mismatch", pointer + "/" + name,
                    {"expected": f"{length} nonempty tokens"})
    for name in ("operations", "required_operations", "supported_operations",
                 "evidence_obligations", "supported_evidence"):
        if name not in row or row[name] is None:
            continue
        value = row[name]
        if type(value) not in (list, tuple) or any(
                type(item) is not str or not item for item in value):
            _refuse("generic-template-mismatch", pointer + "/" + name,
                    {"expected": "list of declared tokens"})
        if list(value) != sorted(set(value)):
            _refuse("generic-template-mismatch", pointer + "/" + name,
                    {"reason": "tokens must be unique and sorted"})
    operations = row["operations"]
    if (type(operations) not in (list, tuple) or not operations
            or any(item not in TARGET_OPERATIONS for item in operations)):
        _refuse("generic-template-mismatch", pointer + "/operations",
                {"allowed": sorted(TARGET_OPERATIONS)})
    for name in ("data_width", "address_width", "max_outstanding"):
        value = row[name]
        if not _is_int(value) or not 1 <= value <= 4096:
            _refuse("generic-template-mismatch", pointer + "/" + name,
                    {"expected": "positive int, bool rejected"})
    if row["address_units"] not in ADDRESS_UNITS:
        _refuse("generic-template-mismatch", pointer + "/address_units",
                {"allowed": sorted(ADDRESS_UNITS)})
    if type(row["byte_enable"]) is not bool:
        _refuse("generic-template-mismatch", pointer + "/byte_enable",
                {"expected": "bool"})
    return dict(row)


def _declared_operations(binding: Mapping, flow_id: str, role: str,
                         pointer: str) -> tuple[str, ...]:
    declared = binding.get("required_operations")
    if declared is None:
        declared = binding.get("operations")
    if declared is None:
        declared = _DEFAULT_OPERATIONS[flow_id][role]
    operations = tuple(declared)
    if not operations or any(item not in TARGET_OPERATIONS
                             for item in operations):
        _refuse("generic-template-mismatch", pointer + "/operations",
                {"allowed": sorted(TARGET_OPERATIONS)})
    return operations


def _declared_obligations(binding: Mapping, flow_id: str, role: str,
                          pointer: str) -> tuple[str, ...]:
    """The plan's declared obligations, never below the flow's own minimum."""
    minimum = _FLOW_OBLIGATIONS[flow_id][role]
    if binding.get('semantic_kind')=='mmio.register-bank.v1':
        minimum=tuple(v for v in minimum if v!='component_semantic_effect')
    declared = binding.get("evidence_obligations")
    if declared is None:
        return tuple(minimum)
    obligations = tuple(declared)
    unknown = sorted(set(obligations) - set(OBLIGATIONS))
    if unknown:
        _refuse("generic-evidence-missing", pointer + "/evidence_obligations",
                {"reason": "obligation-not-in-the-kernel-vocabulary",
                 "unknown": unknown, "supported": list(OBLIGATIONS)})
    missing = sorted(set(minimum) - set(obligations))
    if missing:
        _refuse("generic-evidence-missing", pointer + "/evidence_obligations",
                {"reason": "declared-obligations-remove-a-flow-obligation",
                 "missing": missing, "required_by_flow": sorted(minimum)})
    supported = binding.get("supported_evidence")
    if supported is not None:
        unsupported = sorted(set(obligations) - set(supported))
        if unsupported:
            _refuse("generic-evidence-missing",
                    pointer + "/evidence_obligations",
                    {"reason": "obligation-not-supported-by-endpoint",
                     "unsupported": unsupported,
                     "supported": sorted(supported)})
    return tuple(sorted(set(obligations)))


def _register_access(path: Mapping, sources: tuple[dict, ...]):
    """The one declared target-register access of this path (raw or plan shape)."""
    constraints = path.get("constraints")
    if not isinstance(constraints, Mapping):
        _refuse("generic-plan-mismatch", "/path/constraints",
                {"expected": "declared constraints object"})
    found = []
    for index, row in enumerate(constraints.get("source_constraints") or ()):
        if isinstance(row, Mapping) and isinstance(row.get("register_access"),
                                                   Mapping):
            found.append((f"/path/constraints/source_constraints/{index}"
                          f"/register_access", dict(row["register_access"])))
    if not found:
        for index, row in enumerate(sources):
            if isinstance(row.get("register_access"), Mapping):
                found.append((f"/path/sources/{index}/register_access",
                              dict(row["register_access"])))
    if len(found) != 1:
        _refuse("generic-semantic-unsupported", "/path/constraints",
                {"reason": "one-declared-register-access-required",
                 "matches": len(found)})
    pointer, access = found[0]
    absent = [name for name in _ACCESS_KEYS if name not in access]
    if absent:
        _refuse("generic-semantic-unsupported", pointer + "/" + absent[0],
                {"reason": "register-access-token-missing"})
    return access, pointer


def _path_facts(path: Mapping) -> _PathFacts:
    if not isinstance(path, Mapping):
        _refuse("generic-contract-type", "/path", {"expected": "JSON object"})
    path = dict(path)
    path_id = require_identifier(path.get("path_id"), "/path/path_id")
    flow_id = path.get("flow_id")
    if flow_id not in STORAGE_FLOWS:
        _refuse("generic-flow-unsupported", "/path/flow_id",
                {"flow_id": flow_id, "supported": list(STORAGE_FLOWS)})
    if path.get("status") != "executable":
        _refuse("generic-plan-mismatch", "/path/status",
                {"status": path.get("status"),
                 "reason": "only an executable path can carry requirements"})
    sources = path.get("sources")
    if not isinstance(sources, list) or not sources:
        _refuse("generic-source-unverified", "/path/sources",
                {"expected": "nonempty declared source list"})
    rows: list[dict] = []
    for index, row in enumerate(sources):
        if not isinstance(row, Mapping):
            _refuse("generic-source-unverified", f"/path/sources/{index}",
                    {"expected": "declared source row"})
        require_identifier(row.get("source_id"),
                           f"/path/sources/{index}/source_id")
        kind = row.get("kind")
        if type(kind) is not str or not kind:
            _refuse("generic-source-unverified", f"/path/sources/{index}/kind",
                    {"reason": "source-kind-undeclared"})
        origin = row.get("origin")
        if origin not in ("fuzzable", "bound"):
            _refuse("generic-source-unverified",
                    f"/path/sources/{index}/origin",
                    {"reason": "source-origin-undeclared", "origin": origin})
        rows.append(dict(row))
    streams = [row for row in rows if row["kind"] in STREAM_KINDS]
    if len(streams) != 1:
        _refuse("generic-source-unverified", "/path/sources",
                {"reason": "cpu-stream-source-not-unique",
                 "matching": [row["source_id"] for row in streams]})
    stream = streams[0]
    if stream["kind"] != STREAM_KIND_BY_FLOW[flow_id]:
        _refuse("generic-semantic-unsupported", "/path/sources",
                {"reason": "flow-stream-kind-mismatch",
                 "flow_id": flow_id, "source_kind": stream["kind"]})
    images = [row for row in rows if row["kind"] == IMAGE_KIND]
    if len(images) != 1:
        _refuse("generic-source-unverified", "/path/sources",
                {"reason": "instruction-image-not-unique",
                 "matching": [row["source_id"] for row in images]})
    image = images[0]
    access, access_pointer = _register_access(path, tuple(rows))
    for name in ("source_component", "source_endpoint", "target_component",
                 "target_endpoint", "register", "field"):
        require_identifier(access[name], access_pointer + "/" + name)
    if access["operation"] not in TARGET_OPERATIONS:
        _refuse("generic-semantic-unsupported", access_pointer + "/operation",
                {"allowed": sorted(TARGET_OPERATIONS)})
    expected_operation = "read" if flow_id == "F2" else "write"
    if access["operation"] != expected_operation:
        _refuse("generic-semantic-unsupported", access_pointer + "/operation",
                {"expected": expected_operation,
                 "reason": "flow-operation-mismatch"})
    if (not _is_int(access["width_bytes"]) or access["width_bytes"] != 4
            or not _is_int(access["value_mask"])
            or not 0 <= access["value_mask"] <= 0xffffffff):
        _refuse("generic-semantic-unsupported", access_pointer,
                {"reason": "register-word-shape-unsupported"})
    if stream.get("component") != access["source_component"]:
        _refuse("generic-source-unverified", "/path/sources",
                {"reason": "stream-component-not-the-declared-source"})
    if image.get("component") != access["source_component"]:
        _refuse("generic-source-unverified", "/path/sources",
                {"reason": "image-component-not-the-declared-source"})
    bindings_raw = path.get("bindings")
    if bindings_raw is None:
        bindings_raw = path.get("endpoint_bindings")
    if not isinstance(bindings_raw, list) or not bindings_raw:
        _refuse("generic-template-mismatch", "/path/bindings",
                {"reason": "declared-endpoint-bindings-required",
                 "required": list(_ENDPOINT_BINDING_KEYS)})
    bindings = tuple(
        _endpoint_binding(row, f"/path/bindings/{index}")
        for index, row in enumerate(bindings_raw))
    cpu_rows = [row for row in bindings
                if row["endpoint_id"] == access["source_endpoint"]]
    target_rows = [row for row in bindings
                   if row["endpoint_id"] == access["target_endpoint"]]
    if len(cpu_rows) != 1:
        _refuse("generic-template-mismatch", "/path/bindings",
                {"reason": "source-endpoint-binding-ambiguous",
                 "endpoint_id": access["source_endpoint"],
                 "matches": len(cpu_rows)})
    if len(target_rows) != 1:
        _refuse("generic-template-mismatch", "/path/bindings",
                {"reason": "target-endpoint-binding-ambiguous",
                 "endpoint_id": access["target_endpoint"],
                 "matches": len(target_rows)})
    cpu_binding, target_binding = cpu_rows[0], target_rows[0]
    if cpu_binding["role"] != "cpu" or target_binding["role"] != "target":
        _refuse("generic-semantic-unsupported", "/path/bindings",
                {"reason": "endpoint-role-mismatch",
                 "roles": [cpu_binding["role"], target_binding["role"]]})
    if cpu_binding["instance_id"] != access["source_component"]:
        _refuse("generic-source-unverified", "/path/bindings",
                {"reason": "source-endpoint-instance-mismatch"})
    if target_binding["instance_id"] != access["target_component"]:
        _refuse("generic-source-unverified", "/path/bindings",
                {"reason": "target-endpoint-instance-mismatch"})
    gpio_bank = target_binding['semantic_kind']=='gpio.register-bank.v1'
    if gpio_bank:
        scoped = ((flow_id=='F4' and (access.get('register'),access.get('register_offset'),access.get('operation'))==('GPIOEN',4,'write'))
            or (flow_id=='F2' and (access.get('register'),access.get('register_offset'),access.get('operation')) in (
                ('PADIN',8,'read'),('GPIOEN',4,'read'))))
        if tuple(target_binding['template'])!=('pulp.gpio.causal','1','pulp_gpio_causal_v1') or not scoped:
            _refuse('generic-semantic-unsupported','/path/register_access',
                    {'reason':'GPIO-register-subcontract-required'})
    if target_binding["semantic_kind"] not in (STORAGE_RW,"mmio.register-bank.v1") and not gpio_bank:
        _refuse("generic-semantic-unsupported", "/path/bindings",
                {"reason": "storage-semantic-required",
                 "semantic_kind": target_binding["semantic_kind"]})
    expected_width = access["width_bytes"] * 8
    if target_binding["data_width"] != expected_width:
        _refuse("generic-template-mismatch", "/path/bindings",
                {"reason": "target-data-width-mismatch",
                 "declared": target_binding["data_width"],
                 "register": expected_width})
    for role, binding in (("target", target_binding), ("cpu", cpu_binding)):
        operations = _declared_operations(binding, flow_id, role,
                                          "/path/bindings")
        if access["operation"] not in operations:
            _refuse("generic-semantic-unsupported", "/path/bindings",
                    {"reason": "declared-endpoint-cannot-run-the-path-operation",
                     "endpoint_id": binding["endpoint_id"],
                     "operation": access["operation"],
                     "declared": list(operations)})
    bound_inputs = path.get("bound_inputs") or []
    if not isinstance(bound_inputs, list) or any(
            not isinstance(row, Mapping) for row in bound_inputs):
        _refuse("generic-plan-mismatch", "/path/bound_inputs",
                {"expected": "declared bound input rows"})
    for index, row in enumerate(bound_inputs):
        require_identifier(row.get("input_id"),
                           f"/path/bound_inputs/{index}/input_id")
        if type(row.get("kind")) is not str or not row["kind"]:
            _refuse("generic-plan-mismatch", f"/path/bound_inputs/{index}/kind",
                    {"reason": "bound-input-kind-undeclared"})
    assertions = path.get("assertions") or []
    if not isinstance(assertions, list) or any(
            not isinstance(row, Mapping) for row in assertions):
        _refuse("generic-plan-mismatch", "/path/assertions",
                {"expected": "declared assertion rows"})
    assertion_ids = []
    for index, row in enumerate(assertions):
        assertion_ids.append(require_identifier(
            row.get("expectation_id"),
            f"/path/assertions/{index}/expectation_id"))
    termination = path.get("termination")
    if termination is None:
        termination = path.get("termination_observation")
    if not isinstance(termination, Mapping) or not isinstance(
            termination.get("kind"), str):
        _refuse("generic-plan-mismatch", "/path/termination",
                {"expected": "declared termination observation kind"})
    contract = path.get("execution_contract")
    execution_contract = dict(contract) if isinstance(contract, Mapping) else None
    return _PathFacts(
        path=path, path_id=path_id, flow_id=flow_id, stream=stream,
        image=image, access=access, bindings=bindings,
        cpu_binding=cpu_binding, target_binding=target_binding,
        source_ids=tuple(row["source_id"] for row in rows),
        bound_input_kinds=tuple(row["kind"] for row in bound_inputs),
        assertion_ids=tuple(assertion_ids),
        termination_kind=termination["kind"],
        execution_contract=execution_contract)


def _requirement(binding: Mapping, *, role: str, flow_id: str,
                 pointer: str) -> CapabilityRequirement:
    try:
        return CapabilityRequirement(
            role=role,
            endpoint_id=binding["endpoint_id"],
            protocol=tuple(binding["protocol"]),
            template=tuple(binding["template"]),
            semantic_kind=binding["semantic_kind"],
            operations=tuple(sorted(set(_declared_operations(
                binding, flow_id, role, pointer)))),
            data_width=binding["data_width"],
            address_width=binding["address_width"],
            max_outstanding=binding["max_outstanding"],
            completion_kind=binding["completion_kind"],
            byte_enable_required=binding["byte_enable"],
            address_units=binding["address_units"],
            evidence_obligations=_declared_obligations(
                binding, flow_id, role, pointer),
        )
    except GenericRuntimeRefused:
        raise
    except (TypeError, ValueError) as error:
        raise GenericRuntimeRefused("generic-template-mismatch", pointer,
                                    {"reason": "declared-token-invalid",
                                     "detail": str(error)[:160]}) from error


def _requirements(facts: _PathFacts) -> tuple[CapabilityRequirement, ...]:
    cpu = _requirement(facts.cpu_binding, role="cpu",
                       flow_id=facts.flow_id, pointer="/path/bindings")
    target = _requirement(facts.target_binding, role="target",
                          flow_id=facts.flow_id, pointer="/path/bindings")
    return tuple(sorted((cpu, target), key=lambda row: (row.role,
                                                       row.endpoint_id)))


# ---------------------------------------------------------------------------
# Declared mutation layout: reused, never re-invented
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class MutationDomain:
    """One declared fuzzable value domain of the selected path's layout."""

    source_id: str
    minimum: int
    maximum: int
    alignment: int
    width: int
    mask: int | None

    @property
    def steps(self) -> int:
        if self.maximum < self.minimum or self.alignment < 1:
            return 0
        return (self.maximum - self.minimum) // self.alignment + 1

    def value(self, digest: bytes, index: int) -> int | None:
        """Deterministic bounded value derived from observed-evidence digest."""
        total = self.steps
        if total < 1:
            return None
        material = digest + index.to_bytes(4, "big") + self.source_id.encode()
        offset = int.from_bytes(sha256(material).digest()[:8], "big") % total
        value = self.minimum + offset * self.alignment
        if self.mask is not None and value & ~self.mask:
            return None
        if value > (1 << self.width) - 1:
            return None
        return value

    def document(self) -> dict:
        return {"source_id": self.source_id, "minimum": self.minimum,
                "maximum": self.maximum, "alignment": self.alignment,
                "width": self.width, "mask": self.mask,
                "declared_values": self.steps}


def _layout_path(facts: _PathFacts) -> dict:
    """Re-join the declared source layout from the path's own declared rows."""
    path = facts.path
    constraints = path.get("constraints")
    if not isinstance(constraints, Mapping):
        _refuse("generic-plan-mismatch", "/path/constraints",
                {"expected": "declared constraints object"})
    mirrors = constraints.get("source_constraints")
    sources = [dict(row) for row in path["sources"]]
    if isinstance(mirrors, list) and mirrors:
        joined = []
        for index, source in enumerate(sources):
            matches = [row for row in mirrors if isinstance(row, Mapping)
                       and row.get("source_id") == source["source_id"]]
            if len(matches) != 1:
                _refuse("generic-plan-mismatch",
                        f"/path/constraints/source_constraints/{index}",
                        {"reason": "source-constraint-mirror-not-unique",
                         "source_id": source["source_id"],
                         "matches": len(matches)})
            mirror = dict(matches[0])
            extra = sorted(set(mirror) - set(_LAYOUT_MIRROR_KEYS))
            if extra:
                _refuse("generic-plan-mismatch",
                        f"/path/constraints/source_constraints/{index}/"
                        f"{extra[0]}",
                        {"reason": "layout-mirror-has-undeclared-keys",
                         "keys": extra})
            for name in _LAYOUT_SHARED:
                if (name in source and name in mirror
                        and source[name] != mirror[name]):
                    _refuse("generic-plan-mismatch",
                            f"/path/constraints/source_constraints/{index}/"
                            f"{name}",
                            {"reason": "plan-source-disagrees-with-declared-"
                                       "constraint"})
            row = dict(mirror)
            for name in _LAYOUT_SOURCE_EXTRA:
                if name in source:
                    row[name] = source[name]
            joined.append(row)
        sources = joined
    else:
        for index, row in enumerate(sources):
            extra = sorted(set(row) - set(_LAYOUT_MIRROR_KEYS)
                           - set(_LAYOUT_SOURCE_EXTRA))
            if extra:
                _refuse("generic-plan-mismatch", f"/path/sources/{index}",
                        {"reason": "source-row-has-undeclared-keys",
                         "keys": extra})
    layout_path = {
        "path_id": facts.path_id,
        "flow_id": facts.flow_id,
        "status": "executable",
        "sources": sources,
        "constraints": dict(constraints),
    }
    if isinstance(path.get("assertions"), list):
        layout_path["assertions"] = [dict(row) for row in path["assertions"]]
    identity = path.get("runtime_path_identity")
    if isinstance(identity, Mapping):
        layout_path["runtime_path_identity"] = dict(identity)
    elif isinstance(path.get("edges"), list):
        edges = []
        for index, edge in enumerate(path["edges"]):
            if not isinstance(edge, Mapping) or "from" not in edge \
                    or "to" not in edge:
                _refuse("generic-plan-mismatch", f"/path/edges/{index}",
                        {"reason": "declared-edge-without-endpoints"})
            if index and edges[-1]["target"] != edge["from"]:
                _refuse("generic-plan-mismatch", f"/path/edges/{index}",
                        {"reason": "declared-edges-are-not-a-chain"})
            edges.append({"kind": edge.get("kind"),
                          "rule_index": edge.get("rule_index"),
                          "prerequisite": edge["from"], "target": edge["to"]})
        layout_path["runtime_path_identity"] = {
            "path_id": path.get("runtime_path_id"),
            "source_ids": list(path.get("runtime_source_ids") or ()),
            "edges": edges,
        }
    if facts.execution_contract is not None:
        layout_path["execution_contract"] = dict(facts.execution_contract)
    return layout_path


def _candidate_layout(facts: _PathFacts):
    """Reuse the shipped pure candidate layout of the selected flow."""
    path = _layout_path(facts)
    if facts.flow_id == "F2":
        from myfuzz.integration.compiled_f2_layout import (
            compile_f2_candidate_layout)
        compiler = compile_f2_candidate_layout
    else:
        from myfuzz.integration.compiled_candidate_layout import (
            LAYOUT_SCHEMA, compile_candidate_layout)
        compiler = compile_candidate_layout

    def document(layout):
        if facts.flow_id == "F2":
            return layout.document()
        return {
            "schema_version": LAYOUT_SCHEMA,
            "digest": layout.digest,
            "byte_length": layout.byte_length,
            "bit_length": layout.bit_length,
            "derived_image_source_id": layout.derived_image_source_id,
            "slices": [
                {"source_id": row.source_id, "kind": row.kind,
                 "component": row.component, "endpoint_id": row.endpoint_id,
                 "port": row.port, "raw_bit_offset": row.raw_bit_offset,
                 "width": row.width, "bit_offset": row.bit_offset,
                 "mask": row.mask, "minimum": row.minimum,
                 "maximum": row.maximum, "alignment": row.alignment}
                for row in layout.slices],
        }

    try:
        layout = compiler(path)
    except (ValueError, TypeError, KeyError, IndexError) as error:
        _refuse("generic-flow-unsupported", "/path",
                {"reason": "declared-candidate-layout-refused",
                 "flow_id": facts.flow_id,
                 "detail": f"{type(error).__name__}:{str(error)[:120]}"})
    return layout, document(layout)


def _domains(layout, facts: _PathFacts) -> tuple[MutationDomain, ...]:
    if facts.flow_id == "F2":
        rows = [
            MutationDomain(row.source_id, row.minimum, row.maximum,
                           row.alignment, row.width, None)
            for row in layout.source_slices]
    else:
        rows = [
            MutationDomain(row.source_id, row.minimum, row.maximum,
                           row.alignment, row.width, row.mask)
            for row in layout.slices if row.kind != IMAGE_KIND]
    return tuple(rows)


def _declared_semantic_digest(plan_document, facts: _PathFacts):
    declared = facts.path.get("semantic_contract_sha256")
    if declared is not None:
        return declared
    components = plan_document.get("components")
    if isinstance(components, list):
        matches = [row for row in components
                   if isinstance(row, Mapping)
                   and row.get("instance_id") == facts.target_component]
        if len(matches) == 1:
            return matches[0].get("semantic_contract_sha256")
    return None


# ---------------------------------------------------------------------------
# Flow context: references only
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class FlowContext:
    """References to the existing binding/plan/source layout; owns no runtime.

    ``prepare`` fills the public fields once.  Only the private event index
    grows, incrementally, from the bound plan's existing raw event log.
    """

    kernel_id: str
    plan_sha256: str
    path_id: str
    flow_id: str
    path_bytes: bytes
    requirements: tuple[CapabilityRequirement, ...]
    obligations: tuple[str, ...]
    record_length: int
    layout: object
    layout_document: dict
    domains: tuple[MutationDomain, ...]
    max_feedback_values: int
    cpu_component: str
    target_component: str
    instruction_component: str
    source_ids: tuple[str, ...]
    fuzzable_source_ids: tuple[str, ...]
    current_source_id: str
    bindings: tuple[dict, ...]
    execution_contract: dict | None
    bound_plan: object
    semantic_contract_sha256: str | None = None
    _index: dict = field(default_factory=dict, repr=False)
    _scanned: int = field(default=0, repr=False)

    @property
    def path(self) -> dict:
        return json.loads(self.path_bytes.decode("utf-8"))

    def document(self) -> dict:
        """Documentary snapshot; contains no live handle."""
        return {
            "schema_version": KERNEL_SCHEMA,
            "kernel_id": self.kernel_id,
            "plan_sha256": self.plan_sha256,
            "path_id": self.path_id,
            "flow_id": self.flow_id,
            "record_length": self.record_length,
            "cpu_component": self.cpu_component,
            "target_component": self.target_component,
            "instruction_component": self.instruction_component,
            "source_ids": list(self.source_ids),
            "fuzzable_source_ids": list(self.fuzzable_source_ids),
            "current_source_id": self.current_source_id,
            "requirements": [row.document() for row in self.requirements],
            "evidence_obligations": list(self.obligations),
            "mutation_domains": [row.document() for row in self.domains],
            "max_feedback_values": self.max_feedback_values,
            "candidate_layout": dict(self.layout_document),
            "bindings": [dict(row) for row in self.bindings],
            "execution_contract": (dict(self.execution_contract)
                                   if self.execution_contract else None),
            "semantic_contract_sha256": self.semantic_contract_sha256,
            "live_handle": False,
            "owns_session": False,
            "owns_runner": False,
            "owns_memory": False,
        }

    def lookup_event(self, event_id) -> dict | None:
        """Resolve one integer event id in the bound plan's existing event log."""
        if not _is_int(event_id) or event_id <= 0:
            return None
        runner = getattr(self.bound_plan, "runner", None)
        events = getattr(runner, "events", None) if runner is not None else None
        # ``runner.events`` is a plain tuple, or an ``EventJournalSnapshot``
        # (a Sequence) once the bounded online journal is enabled.  Both expose
        # len/slice; reject strings and anything without ordered indexing.
        if isinstance(events, (str, bytes)) or not isinstance(events, Sequence):
            return None
        for event in events[self._scanned:]:
            if isinstance(event, Mapping) and _is_int(event.get("event_id")):
                self._index[event["event_id"]] = dict(event)
        self._scanned = len(events)
        return self._index.get(event_id)


# ---------------------------------------------------------------------------
# The kernel
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Obligation:
    name: str
    status: str


class StorageFlowKernel:
    """Code-owned APB3 storage kernel for the F2 and F4 flows."""

    kernel_id = KERNEL_ID
    flow_ids = STORAGE_FLOWS
    case_schema = CASE_SEQUENCE_SCHEMA

    # -- documentary ------------------------------------------------------
    def document(self) -> dict:
        return {
            "schema_version": KERNEL_SCHEMA,
            "kernel_id": self.kernel_id,
            "flow_ids": list(self.flow_ids),
            "case_schema": self.case_schema,
            "obligations": list(OBLIGATIONS),
            "flow_obligations": {flow: {role: list(names)
                                        for role, names in rows.items()}
                                 for flow, rows in _FLOW_OBLIGATIONS.items()},
            "native_authority": False,
        }

    # -- requirements -----------------------------------------------------
    def requirements(self, d3_path) -> tuple[CapabilityRequirement, ...]:
        """Capability requirements derived from the path's declared tokens."""
        return _requirements(_path_facts(_path_document(d3_path)))

    # -- prepare ----------------------------------------------------------
    def prepare(self, bound_plan, path_id) -> FlowContext:
        """Reference-only preparation of one selected path of the bound plan."""
        if bound_plan is None:
            _refuse("generic-contract-type", "/bound_plan",
                    {"expected": "BoundExecutionPlan"})
        require_identifier(path_id, "/path_id")
        plan = getattr(bound_plan, "plan", None)
        document_method = getattr(plan, "document", None)
        if not callable(document_method):
            _refuse("generic-contract-type", "/bound_plan/plan",
                    {"expected": "GenericExecutionPlan"})
        plan_document = document_method()
        paths = plan_document.get("paths")
        if not isinstance(paths, list):
            _refuse("generic-plan-mismatch", "/plan/paths",
                    {"reason": "plan-paths-required"})
        matches = [row for row in paths
                   if isinstance(row, Mapping) and row.get("path_id") == path_id]
        if len(matches) != 1:
            _refuse("generic-plan-mismatch", "/plan/paths",
                    {"reason": "selected-path-not-unique", "path_id": path_id,
                     "matches": len(matches)})
        path = dict(matches[0])
        facts = _path_facts(path)
        plan_sha256 = getattr(bound_plan, "plan_sha256", None)
        if type(plan_sha256) is not str or not _hex64(plan_sha256):
            _refuse("generic-binding-drift", "/bound_plan/plan_sha256",
                    {"reason": "bound-plan-digest-required"})
        identity = getattr(plan, "identity_sha256", None)
        if type(identity) is str and identity != plan_sha256:
            _refuse("generic-plan-mismatch", "/bound_plan/plan_sha256",
                    {"reason": "bound-digest-differs-from-plan-identity"})
        requirements = _requirements(facts)
        layout, layout_document = _candidate_layout(facts)
        record_length = getattr(layout, "byte_length", None)
        if not _is_int(record_length) or not 1 <= record_length <= MAX_RECORD_BYTES:
            _refuse("generic-flow-unsupported", "/path",
                    {"reason": "declared-candidate-layout-byte-length"})
        semantic = _declared_semantic_digest(plan_document, facts)
        if semantic is not None and not _hex64(semantic):
            _refuse("generic-contract-type",
                    "/plan/components/" + facts.target_component
                    + "/semantic_contract_sha256",
                    {"expected": "lowercase hex SHA-256"})
        return FlowContext(
            kernel_id=self.kernel_id,
            plan_sha256=plan_sha256,
            path_id=facts.path_id,
            flow_id=facts.flow_id,
            path_bytes=canonical_json_bytes(path),
            requirements=requirements,
            obligations=tuple(sorted({name for row in requirements
                                      for name in row.evidence_obligations})),
            record_length=record_length,
            layout=layout,
            layout_document=layout_document,
            domains=_domains(layout, facts),
            max_feedback_values=DEFAULT_FEEDBACK_VALUES,
            cpu_component=facts.cpu_component,
            target_component=facts.target_component,
            instruction_component=facts.instruction_component,
            source_ids=facts.source_ids,
            fuzzable_source_ids=facts.fuzzable_source_ids,
            current_source_id=facts.source_id,
            bindings=facts.bindings,
            execution_contract=facts.execution_contract,
            bound_plan=bound_plan,
            semantic_contract_sha256=semantic,
        )

    # -- lower ------------------------------------------------------------
    def lower(self, context, case) -> LoweredCase:
        """Closed-shape admission of one directed case; no RTL, no side effect."""
        if type(context) is not FlowContext:
            _refuse("generic-contract-type", "/context",
                    {"expected": "FlowContext"})
        rows = parse_closed_json(case, CASE_KEYS, pointer="/case")
        testcase_id = require_identifier(rows["testcase_id"],
                                         "/case/testcase_id")
        path_id = rows["path_id"]
        if type(path_id) is not str or path_id != context.path_id:
            _refuse("generic-plan-mismatch", "/case/path_id",
                    {"expected": context.path_id, "actual": path_id})
        source_id = require_identifier(rows["source_id"], "/case/source_id")
        if source_id not in context.fuzzable_source_ids:
            _refuse("generic-source-unverified", "/case/source_id",
                    {"reason": "source-not-a-declared-fuzzable-source",
                     "declared": list(context.fuzzable_source_ids)})
        raw = rows["raw_records_hex"]
        if type(raw) is not list or not raw:
            _refuse("generic-case-shape", "/case/raw_records_hex",
                    {"expected": "nonempty list; records are never truncated"})
        records = []
        for index, value in enumerate(raw):
            pointer = f"/case/raw_records_hex/{index}"
            record = _require_hex_record(value, pointer)
            if len(record) != context.record_length:
                _refuse("generic-case-shape", pointer,
                        {"expected_bytes": context.record_length,
                         "actual_bytes": len(record),
                         "reason": "flow-wire-record-length"})
            classification = context.layout.classify(record)
            accepted = (classification.accepted if context.flow_id == "F2"
                        else classification.valid)
            if not accepted:
                reason = (classification.reason if context.flow_id == "F2"
                          else classification.code)
                _refuse("generic-case-shape", pointer,
                        {"reason": "candidate-outside-declared-domain",
                         "detail": reason})
            records.append(record)
        return LoweredCase(testcase_id, path_id, source_id, context.flow_id,
                           context.record_length, tuple(records))

    def load_case_sequence(self, *, plan_sha256, path_flows, document):
        return load_case_sequence(plan_sha256=plan_sha256,
                                  path_flows=path_flows, document=document)

    # -- capture ----------------------------------------------------------
    def capture(self, context, receipt) -> tuple[EffectEvidence, ...]:
        """Translate one real per-case certificate into four-state evidence."""
        if type(context) is not FlowContext:
            _refuse("generic-contract-type", "/context",
                    {"expected": "FlowContext"})
        if not isinstance(receipt, Mapping):
            _refuse("generic-evidence-missing", "/receipt",
                    {"expected": "per-case certificate document"})
        receipt = dict(receipt)
        if receipt.get('schema_version')=='compiled_mmio_case.v1':
            from .mmio import capture_mmio
            return capture_mmio(context,receipt)
        case_id = receipt.get("case_id")
        if type(case_id) is not str or not case_id:
            _refuse("generic-evidence-missing", "/receipt/case_id",
                    {"reason": "case-identity-required"})
        binding_sha256 = receipt.get("execution_binding_sha256")
        if not _hex64(binding_sha256):
            _refuse("generic-evidence-missing",
                    "/receipt/execution_binding_sha256",
                    {"reason": "execution-binding-digest-required"})
        semantic_sha256 = receipt.get("semantic_contract_sha256")
        if not _hex64(semantic_sha256):
            semantic_sha256 = context.semantic_contract_sha256
        if not _hex64(semantic_sha256):
            _refuse("generic-evidence-missing", "/semantic_contract_sha256",
                    {"reason": "semantic-contract-digest-required"})
        joins = receipt.get("joins")
        if not isinstance(joins, (list, tuple)) or not joins or any(
                not isinstance(row, Mapping) for row in joins):
            _refuse("generic-evidence-missing", "/receipt/joins",
                    {"reason": "declared-transaction-joins-required"})
        joins = [dict(row) for row in joins]
        hops = receipt.get("exact_hops")
        hops = dict(hops) if isinstance(hops, Mapping) else {}
        ram_hop = hops.get("ram_write_hop")
        ram_hop = dict(ram_hop) if isinstance(ram_hop, Mapping) else None
        certified_chain = receipt.get("status") == "certified"

        primary = self._primary_join(context, joins, commit=receipt.get('commit'))
        key = _transaction_key(primary.get("source_transaction"))
        if key is None:
            _refuse("generic-evidence-missing",
                    "/receipt/joins/source_transaction",
                    {"reason": "real-transaction-key-required"})

        statuses = {}
        native_refs, native_status = _sample_refs(context, joins)
        source_refs, source_status = _source_refs(context, joins)
        destination_refs, consumption_status = _destination_refs(
            context, ram_hop, certified_chain)
        statuses["physical_protocol_sample"] = native_status
        statuses["cross_component_source"] = source_status
        statuses["component_semantic_effect"] = _effect_status(
            context, receipt, joins, native_status, certified_chain)
        statuses["cross_component_consumption"] = consumption_status
        results = []
        for name in context.obligations:
            status = statuses.get(name, "unsupported")
            if not certified_chain and status == "certified":
                status = "missing"
            results.append((name, status))
        status = combine_status([row[1] for row in results])
        evidence = [
            EffectEvidence(
                key=key, status=status, scope=_scope(results),
                binding_sha256=binding_sha256,
                semantic_contract_sha256=semantic_sha256,
                source_refs=source_refs, native_refs=native_refs,
                destination_refs=destination_refs,
                obligation_results=tuple(results),
            )
        ]
        if ram_hop is not None:
            destination_key = _transaction_key(ram_hop.get("transaction"))
            consumption = dict(results).get("cross_component_consumption",
                                            "unsupported")
            if destination_key is not None and destination_key != key:
                evidence.append(EffectEvidence(
                    key=destination_key, status=consumption,
                    scope="cross_component_consumption",
                    binding_sha256=binding_sha256,
                    semantic_contract_sha256=semantic_sha256,
                    source_refs=(), native_refs=(),
                    destination_refs=destination_refs,
                    obligation_results=(
                        ("cross_component_consumption", consumption),),
                ))
        return tuple(evidence)

    @staticmethod
    def _primary_join(context: FlowContext, joins: list[dict], *, commit=None) -> dict:
        commit_context = commit.get('context') if isinstance(commit, Mapping) else None
        if (context.flow_id=='F4' and isinstance(commit_context, Mapping)
                and 'source_transaction' in commit_context):
            key=_transaction_key(commit_context['source_transaction'])
            matches=[row for row in joins if key is not None
                     and _transaction_key(row.get('source_transaction'))==key]
            flagged=[row for row in joins if row.get('write') is True]
            if (key is None or commit_context.get('write') is not True or len(matches)!=1
                    or ('write' in matches[0] and matches[0]['write'] is not True)
                    or (flagged and (len(flagged)!=1 or flagged[0] is not matches[0]))):
                _refuse('generic-evidence-missing','/receipt/commit/context/source_transaction',
                        {'reason':'commit-transaction-join-mismatch'})
            return matches[0]
        wanted = True if context.flow_id == "F4" else False
        matches = [row for row in joins if row.get("write") is wanted]
        if len(matches) == 1:
            return matches[0]
        if len(joins) == 1:
            return joins[0]
        _refuse("generic-evidence-missing", "/receipt/joins",
                {"reason": "effecting-transaction-ambiguous",
                 "flow_id": context.flow_id})

    # -- feedback ---------------------------------------------------------
    def feedback(self, context, claims) -> tuple[int, ...]:
        """Bounded, deterministic program inputs from actual observed feedback.

        The signal is exactly what the runtime proved: transaction keys,
        evidence statuses, obligation results and the raw references of each
        supplied claim.  Expected values never enter this function, and a
        domain with a single declared value yields nothing.
        """
        if type(context) is not FlowContext:
            _refuse("generic-contract-type", "/context",
                    {"expected": "FlowContext"})
        if not isinstance(claims, (list, tuple)):
            _refuse("generic-contract-type", "/claims",
                    {"expected": "sequence of edge claims"})
        signals = [_claim_signal(claim) for claim in claims]
        if not signals:
            return ()
        signals.sort(key=canonical_json_bytes)
        digest = sha256(canonical_json_bytes(
            {"schema_version": KERNEL_ID, "flow_id": context.flow_id,
             "path_id": context.path_id, "signals": signals})).digest()
        limit = context.max_feedback_values
        if not _is_int(limit) or not 1 <= limit <= MAX_FEEDBACK_VALUES:
            _refuse("generic-contract-type", "/context/max_feedback_values",
                    {"minimum": 1, "maximum": MAX_FEEDBACK_VALUES})
        values: list[int] = []
        for domain in context.domains:
            if domain.steps < 2:
                # One declared value is not a mutation domain; inventing a
                # second address/value would be an unadmitted input.
                continue
            produced = 0
            attempt = 0
            while produced < limit and attempt < 4 * limit:
                value = domain.value(digest, attempt)
                attempt += 1
                if value is None or value in values:
                    continue
                values.append(value)
                produced += 1
        return tuple(values)


def _claim_signal(claim) -> dict:
    try:
        key = claim.key
        status = claim.status
        scope = claim.scope
        obligations = claim.obligation_results
        refs = (claim.source_refs, claim.native_refs, claim.destination_refs)
    except AttributeError as error:
        raise GenericRuntimeRefused(
            "generic-contract-type", "/claims",
            {"expected": "EffectEvidence or EdgeClaim member"}) from error
    if type(key) is not TransactionKey:
        _refuse("generic-contract-type", "/claims/key")
    return {
        "key": {
            "execution_id": key.execution_id,
            "testcase_id": key.testcase_id,
            "source_component": key.source_component,
            "source_epoch": key.source_epoch,
            "channel_id": key.channel_id,
            "source_sequence": key.source_sequence,
        },
        "status": status,
        "scope": scope,
        "obligations": [list(row) for row in obligations],
        "source_refs": [row.document() for row in refs[0]],
        "native_refs": [row.document() for row in refs[1]],
        "destination_refs": [row.document() for row in refs[2]],
    }


def _transaction_key(document) -> TransactionKey | None:
    if not isinstance(document, Mapping):
        return None
    if any(name not in document for name in _TRANSACTION_KEYS):
        return None
    try:
        rows = parse_closed_json(document, _TRANSACTION_KEYS,
                                 pointer="/transaction")
        return TransactionKey(rows["execution_id"], rows["testcase_id"],
                              rows["source_component"], rows["source_epoch"],
                              rows["channel_id"], rows["source_sequence"])
    except (ValueError, TypeError):
        return None


def _collect_refs(context: FlowContext, event_ids):
    declared = [value for value in event_ids if value is not None]
    refs: list[EvidenceRef] = []
    unresolved = []
    for event_id in declared:
        event = context.lookup_event(event_id)
        component = event.get("component") if event else None
        kind = event.get("kind") if event else None
        if type(component) is not str or not component \
                or type(kind) is not str or not kind:
            unresolved.append(event_id)
            continue
        ref = EvidenceRef(component, event_id, kind)
        if all(existing.canonical_bytes() != ref.canonical_bytes()
               for existing in refs):
            refs.append(ref)
    return tuple(refs), tuple(unresolved), len(declared)


def _status_from_refs(declared: int, unresolved, refs) -> str:
    if declared == 0:
        return "unsupported"
    if unresolved:
        return "missing"
    if not refs:
        return "unsupported"
    return "certified"


#: Native sample join keys by protocol family.  A join row names the actual
#: native observations with protocol-specific field names, so the kernel looks
#: for every declared pair and lets absent fields stay undeclared (``None``).
_NATIVE_SAMPLE_JOIN_KEYS = (
    ("native_APB_event", "native_post_event"),
    ("native_wishbone_event", "native_ack_event"),
)


def _sample_refs(context: FlowContext, joins: list[dict]):
    event_ids = []
    for row in joins:
        for names in _NATIVE_SAMPLE_JOIN_KEYS:
            event_ids.extend(row.get(name) for name in names)
    refs, unresolved, declared = _collect_refs(context, event_ids)
    return refs, _status_from_refs(declared, unresolved, refs)


def _source_refs(context: FlowContext, joins: list[dict]):
    event_ids = []
    transactions = []
    for row in joins:
        event_ids.extend((row.get("delivery_event"), row.get("acceptance_event")))
        transactions.append(row.get("source_transaction"))
    refs, unresolved, declared = _collect_refs(context, event_ids)
    keys = [_transaction_key(row) for row in transactions]
    keys = [key for key in keys if key is not None]
    if not keys:
        return refs, "unsupported"
    if any(key.source_component != context.cpu_component for key in keys):
        return refs, "contradicted"
    if unresolved:
        return refs, "missing"
    if not refs:
        return refs, "unsupported"
    return refs, "certified"


def _effect_status(context: FlowContext, receipt: dict, joins: list[dict],
                   native_status: str, certified_chain: bool) -> str:
    if not certified_chain:
        return "missing"
    if context.flow_id == "F4":
        commit = receipt.get("commit")
        postcondition = receipt.get("postcondition")
        if not isinstance(commit, Mapping) or not isinstance(postcondition,
                                                             Mapping):
            return "unsupported"
        after = commit.get("after")
        value = postcondition.get("value")
        if not _is_int(after) or not _is_int(value):
            return "missing"
        if after != value:
            return "contradicted"
        tick=commit.get('tick')
        if not _is_int(tick):
            return 'missing'
        if not any(row.get('tick') == tick for row in joins):
            # Legacy GPIO joins omit ticks. Resolve the already certified
            # commit's exact transaction to its actual native PRE sample and
            # delivery; never synthesize a tick or select by list position.
            scope=commit.get('context')
            if not isinstance(scope, Mapping) or 'source_transaction' not in scope:
                return 'missing'
            primary=StorageFlowKernel._primary_join(context,joins,commit=commit)
            native=context.lookup_event(primary.get('native_APB_event'))
            delivery=context.lookup_event(primary.get('delivery_event'))
            if (not isinstance(native, Mapping) or not isinstance(delivery, Mapping)
                    or native.get('kind')!='local_tick_sample' or native.get('phase')!='pre'
                    or native.get('component')!=context.target_component or native.get('local_tick')!=tick
                    or not _is_int(native.get('producer_event_id'))
                    or native['producer_event_id']!=delivery.get('producer_event_id')
                    or delivery.get('kind')!='mmio_delivery' or delivery.get('write') is not True
                    or delivery.get('component')!=context.cpu_component
                    or _transaction_key(delivery.get('source_transaction'))!=_transaction_key(scope['source_transaction'])
                    or delivery.get('write_value')!=after):
                return 'missing'
        return _native_dependency(native_status)
    postcondition = receipt.get("postcondition")
    witness = receipt.get("version_witness")
    if witness is None:
        witness = receipt.get("version_before")
    if not isinstance(postcondition, Mapping) or not isinstance(witness,
                                                               Mapping):
        return "unsupported"
    if postcondition.get("value") != witness.get("value"):
        return "contradicted"
    if not _is_int(postcondition.get("write_count")):
        return "missing"
    return _native_dependency(native_status)


def _native_dependency(native_status: str) -> str:
    """A semantic effect is only certifiable on a certified native sample."""
    if native_status == "certified":
        return "certified"
    return "unsupported" if native_status == "unsupported" else "missing"


def _destination_refs(context: FlowContext, ram_hop: dict | None,
                      certified_chain: bool):
    if ram_hop is None:
        return (), "unsupported"
    refs, unresolved, declared = _collect_refs(
        context, [ram_hop.get("memory_write_event")])
    if declared == 0:
        return refs, "unsupported"
    if unresolved:
        return refs, "missing"
    if not refs:
        return refs, "unsupported"
    if not certified_chain:
        return refs, "missing"
    return refs, "certified"


def _scope(results) -> str:
    statuses = dict(results)
    if statuses.get("cross_component_consumption") == "certified":
        return "cross_component_consumption"
    if statuses.get("cross_component_source") == "certified":
        return "cross_component_source"
    if statuses.get("component_semantic_effect") == "certified":
        return "component_semantic_effect"
    return "physical_protocol_sample"


# ---------------------------------------------------------------------------
# The fixed design interface (section 5.2), as module-level entry points
# ---------------------------------------------------------------------------
#
# ``requirements(d3_path)``, ``prepare(bound_plan, path_id)``,
# ``lower(context, case)``, ``capture(context, receipt)`` and
# ``feedback(context, claims)`` are the interface the registry/compiler/engine
# call.  The kernel is stateless, so these delegate to one code-owned instance;
# there is no public registration or factory.

_DEFAULT_KERNEL = StorageFlowKernel()


def requirements(d3_path) -> tuple[CapabilityRequirement, ...]:
    return _DEFAULT_KERNEL.requirements(d3_path)


def prepare(bound_plan, path_id) -> FlowContext:
    return _DEFAULT_KERNEL.prepare(bound_plan, path_id)


def lower(context, case) -> LoweredCase:
    return _DEFAULT_KERNEL.lower(context, case)


def capture(context, receipt) -> tuple[EffectEvidence, ...]:
    return _DEFAULT_KERNEL.capture(context, receipt)


def feedback(context, claims) -> tuple[int, ...]:
    return _DEFAULT_KERNEL.feedback(context, claims)


# ---------------------------------------------------------------------------
# Campaign backend: adapt one EXISTING single-flow persistent runtime
# ---------------------------------------------------------------------------

FLOW_EXECUTORS = {"F2": "compiled_f2_obi_apb", "F4": "compiled_f4_obi_apb"}

#: A flow keeps its original executor row; a protocol that needs a different
#: executor is registered here instead of overwriting that row.  The classic
#: Wishbone F4 executor is a sibling of the APB one and never replaces it, so
#: ``FLOW_EXECUTORS`` above keeps its exact previous meaning.
WISHBONE_FLOW_EXECUTORS = {"F4": "compiled_f4_wishbone"}

#: Executor id -> flow id over every registered executor row (reverse lookup).
EXECUTOR_FLOWS = {
    **{executor: flow for flow, executor in FLOW_EXECUTORS.items()},
    **{executor: flow for flow, executor in WISHBONE_FLOW_EXECUTORS.items()},
}


def refuse_mixed_flows(flows) -> None:
    """Explicit refusal for a sequence that resolves to several compiled flows."""
    ordered = sorted({str(flow) for flow in flows})
    if len(ordered) > 1:
        _refuse("generic-flow-mixed-unsupported", "/flow_id",
                {"flows": ordered,
                 "reason": "one campaign fixes one compiled flow and layout; a "
                           "directed sequence that mixes F2 and F4 needs a "
                           "versioned outer dispatch contract that does not "
                           "exist in G5"})


@dataclass(frozen=True, slots=True)
class CompiledFlowSpec:
    """One already-prepared D2/D3 object pair and its fixed code-owned executor.

    The mapping must come from a single ``prepare_compiled_execution_inputs``
    call (one D2 generation, one D3 build); the backend never prepares twice.
    """

    artifacts: Mapping
    compiled_inputs: Mapping
    executor: str
    base_dir: Path
    cache_dir: Path
    run_id: str = "generic-storage-campaign"
    rounds_per_case: int = 128
    max_cases: int = 64

    @property
    def flow_id(self) -> str:
        try:
            return EXECUTOR_FLOWS[self.executor]
        except KeyError:
            raise GenericRuntimeRefused("generic-adapter-missing", "/executor",
                                        {"executor": self.executor,
                                         "supported": sorted(EXECUTOR_FLOWS)})


class StorageFlowChannel:
    """Structural campaign view of one existing persistent flow runtime.

    The runtime object is adopted unchanged: its runner, sessions, memory,
    ledger, authority and native issuer stay the only ones.  This class only
    reads them, counts the one construction/begin/bootstrap and forwards the
    existing ``submit(raw)`` loop.  It creates no session, memory or runner.
    """

    channel_id = "storage.existing-runtime.channel.v1"
    accepts_flow = False
    _SURFACE = ("runner", "session", "records", "submit", "finish", "feedback",
                "execution_binding")

    def __init__(self, runtime, *, flow_id: str, executor: str | None = None):
        missing = [name for name in self._SURFACE
                   if not hasattr(runtime, name)]
        if missing:
            _refuse("generic-adapter-missing", "/runtime",
                    {"reason": "existing-runtime-surface-incomplete",
                     "missing": missing})
        if flow_id not in STORAGE_FLOWS:
            _refuse("generic-flow-unsupported", "/flow_id",
                    {"flow_id": flow_id, "supported": list(STORAGE_FLOWS)})
        self.runtime = runtime
        self._flow_id = flow_id
        self.executor = executor
        self._built = 1
        self._begun = 0
        self._initialized = 0
        self._closed = False
        self._submissions = 0

    # -- read-only views --------------------------------------------------
    @property
    def flow_id(self) -> str:
        return self._flow_id

    @property
    def runner(self):
        return getattr(self.runtime, "runner", None)

    @property
    def sessions(self) -> Mapping:
        sessions = getattr(self.runner, "sessions", None)
        return sessions if isinstance(sessions, Mapping) else {}

    @property
    def memory(self):
        for session in self.sessions.values():
            memory = getattr(session, "memory", None)
            if memory is not None:
                return memory
        return None

    @property
    def session(self):
        return getattr(self.runtime, "session", None)

    @property
    def authority(self):
        return getattr(self.runtime, "authority", None)

    @property
    def records(self):
        return getattr(self.runtime, "records", ())

    @property
    def execution_binding(self):
        return getattr(self.runtime, "execution_binding", None)

    @property
    def submissions(self) -> int:
        return self._submissions

    def counters(self) -> dict:
        """Initialization counts of the adopted runtime.

        ``build`` is one because this channel was handed exactly one existing
        runtime object; ``begin`` and ``init`` are *verified live* by
        ``begin_once`` (the session's own manifest probe and the observed
        native first fetch), never asserted by the caller.
        """
        return {"build": self._built, "begin": self._begun,
                "init": self._initialized}

    # -- lifecycle --------------------------------------------------------
    def begin_once(self) -> None:
        """Verify the single construction/begin/bootstrap; never begin twice."""
        if self._begun:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "existing-runtime-begun-more-than-once",
                     "counters": self.counters()})
        session = self.session
        if session is None:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "existing-runtime-exposes-no-session"})
        if getattr(self.runtime, "_deferred_begin", False):
            begin = getattr(self.runtime, "begin", None)
            if not callable(begin):
                _refuse("generic-binding-drift", "/runtime/begin",
                        {"reason": "deferred-runtime-exposes-no-begin"})
            # The bound plan was asserted current by the engine immediately
            # before this call; begin is therefore the first native effect.
            begin()
        try:
            manifest = session.manifest_sha256
        except Exception as error:  # the real session raises before begin
            _refuse("generic-binding-drift", "/session",
                    {"reason": "scenario-session-not-begun",
                     "error_type": type(error).__name__})
        if type(manifest) is not str or not manifest:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "scenario-session-manifest-unavailable"})
        if not isinstance(getattr(self.runtime, "first_fetch", None), Mapping):
            _refuse("generic-binding-drift", "/runtime/first_fetch",
                    {"reason": "native-bootstrap-not-observed"})
        self._begun = 1
        self._initialized = 1

    def assert_current(self) -> None:
        """Cheap stability probe over the adopted runtime (no full rescan)."""
        if self._closed:
            _refuse("generic-binding-drift", "/channel",
                    {"reason": "channel-closed"})
        session = self.session
        if session is None or getattr(session, "_finished", False):
            _refuse("generic-binding-drift", "/session",
                    {"reason": "existing-session-not-active"})
        if getattr(self.runtime, "finished", False):
            _refuse("generic-binding-drift", "/runtime",
                    {"reason": "existing-runtime-already-finished"})

    def submit(self, raw: bytes, flow_id=None) -> Mapping:
        if not self._begun:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "channel-not-begun"})
        if type(raw) is not bytes:
            _refuse("generic-contract-type", "/raw", {"expected": "bytes"})
        if getattr(self.runtime, "_mixed_flows", False):
            certificate = self.runtime.submit(raw, flow=flow_id)
        else:
            certificate = self.runtime.submit(raw)
        if not isinstance(certificate, Mapping):
            _refuse("generic-evidence-missing", "/certificate",
                    {"reason": "per-case-certificate-required"})
        self._submissions += 1
        return certificate

    def finish(self):
        return self.runtime.finish()

    def replay(self, plan, *, audit_sink=None):
        return self.runtime.replay(plan, audit_sink=audit_sink)

    def feedback(self) -> Mapping:
        value = self.runtime.feedback()
        return value if isinstance(value, Mapping) else {}

    def execution_audit(self):
        audit = getattr(self.runtime, "execution_audit", None)
        if not callable(audit):
            return None
        value = audit()
        return value if isinstance(value, Mapping) else None

    def close(self) -> None:
        """Release references only; the existing runtime keeps its processes."""
        self._closed = True


class StorageFlowBackend:
    """Adapts the existing single-flow persistent runtimes for campaign use.

    Two supported sources of a channel:

    * ``runtime=``: an already-constructed ``CompiledF2Runtime`` /
      ``CompiledF4Runtime`` (or a structural stand-in).  Adopted unchanged --
      no session, memory or runner is rebuilt.
    * ``spec=``: one ``CompiledFlowSpec``; the channel is built exactly once
      through ``myfuzz.integration.compiled_execution_files``' own
      ``create_compiled_execution`` entry (the existing construction path), so
      the campaign runs one construction, one begin and N cases on the same
      runner/memory.

    A campaign fixes exactly one compiled flow.  A request for another flow --
    including a mixed F2+F4 sequence -- refuses ``generic-flow-mixed-unsupported``
    or ``generic-plan-mismatch`` instead of running one flow silently.
    """

    backend_id = "storage.flow.backend.v1"

    def __init__(self, *, runtime=None, flow_id: str | None = None,
                 spec: CompiledFlowSpec | None = None):
        if (runtime is None) == (spec is None):
            _refuse("generic-contract-type", "/backend",
                    {"expected": "exactly one of runtime= or spec="})
        if runtime is not None:
            if flow_id not in STORAGE_FLOWS:
                _refuse("generic-flow-unsupported", "/flow_id",
                        {"flow_id": flow_id,
                         "supported": list(STORAGE_FLOWS)})
            self._runtime = runtime
            self._flow_id = flow_id
            self._executor = None
            self._spec = None
        else:
            self._runtime = None
            self._flow_id = spec.flow_id
            self._executor = spec.executor
            self._spec = spec
        self._channel: StorageFlowChannel | None = None

    @property
    def flow_id(self) -> str:
        return self._flow_id

    def require_flow(self, flow_id: str) -> None:
        """One campaign fixes one compiled flow; mixing is never downgraded."""
        if flow_id != self._flow_id:
            _refuse("generic-plan-mismatch", "/flow_id",
                    {"expected": self._flow_id, "actual": flow_id,
                     "reason": "campaign-flow-fixed-by-backend"})

    def open(self) -> StorageFlowChannel:
        """Build (once) or adopt the existing runtime and return its channel."""
        if self._channel is not None:
            return self._channel
        runtime = self._runtime
        if runtime is None:
            spec = self._spec
            if not isinstance(spec, CompiledFlowSpec):
                _refuse("generic-contract-type", "/spec",
                        {"expected": "CompiledFlowSpec"})
            from myfuzz.integration import compiled_execution_files as files
            runtime = files.create_compiled_execution(
                artifacts=spec.artifacts,
                compiled_inputs=spec.compiled_inputs,
                executor=spec.executor,
                base_dir=Path(spec.base_dir),
                cache_dir=Path(spec.cache_dir),
                run_id=spec.run_id,
                rounds_per_case=spec.rounds_per_case,
                max_cases=spec.max_cases,
            )
        self._channel = StorageFlowChannel(runtime, flow_id=self._flow_id,
                                          executor=self._executor)
        return self._channel

    def unresolved(self) -> tuple[str, ...]:
        """Limitations of the single-flow channel."""
        return (
            "generic-flow-mixed-unsupported: this single-flow backend accepts "
            "one flow and path; use the mixed backend for F2/F4 sequences",
        )
