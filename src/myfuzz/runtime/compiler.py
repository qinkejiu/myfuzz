"""Compile one same-preparation D2/D3 pair into a static execution plan (G4).

The compiler is the only issuer of a ``generic_execution_plan.v1`` document.  It
reads the *same* ``PreparationContext`` that generated the artifacts and the
compiled path document: the caller cannot hand in a second D2/D3 tuple, an equal
dataclass value or another preparation's objects.  Components and adapter
selections are accepted only through the issuing context's object-identity
membership (:meth:`PreparationContext.require_component` /
:meth:`PreparationContext.require_selection`); the plan is registered back into
that context (:meth:`PreparationContext.issue_plan`).

What is derived here, and what is refused:

* the code-owned static flow kernels (``generic.flow.F2.static.v1`` /
  ``generic.flow.F4.static.v1``) derive, per executable path of the requested
  flows, which endpoints must be bound, the required operations and the
  evidence obligations.  The caller's requirements are compared item by item
  against that derivation; a removed operation obligation, a removed evidence
  obligation, an over-claim against the verified descriptor or a substituted
  kernel/semantic kind refuses the whole plan.
* every edge of an executable path must resolve to a provider: a declared
  shared persistent-memory resource or a bound endpoint.  An unknown edge or a
  route whose declared window does not match the path contract refuses.
* ``memory`` references the declared persistent-memory resources of the same
  preparation wiring (resource id, serving component, base/size/permissions).
  It never invents a second RAM; a persistent-state edge that names an
  undeclared resource refuses.
* the emitted document is canonical and detached: ``identity_sha256`` is
  computed over the sealed bytes only and mutating any caller dict afterwards
  cannot change it.

Compilation is static only.  It starts no process, builds no harness, issues no
native token and admits no execution: the plan is ``static_supported``
documentation for the later binding/engine stages.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from myfuzz.scenario.compiled_paths import compiled_document_sha256

from .contracts import (
    PLAN_SCHEMA,
    PLAN_TOP_LEVEL,
    AdapterSelection,
    CapabilityRequirement,
    GenericExecutionPlan,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
    parse_closed_json,
    require_digest,
    strict_json_loads,
)
from .preparation import PreparationContext
from .registry import (
    CPU_ADAPTER_ID,
    STORAGE_ADAPTER_ID,
    TL_COHERENT_CPU_ADAPTER_ID,
    TL_COHERENT_CPU_SEMANTIC_KIND,
    registrations,
)

__all__ = [
    "CPU_SEMANTIC_KIND",
    "EndpointBinding",
    "PLAN_MEMORY_SCHEMA",
    "PLAN_SCHEDULING_SCHEMA",
    "PLAN_TERMINATION_SCHEMA",
    "STORAGE_SEMANTIC_KIND",
    "SUPPORTED_FLOWS",
    "assert_plan_content",
    "compile_execution_plan",
    "load_execution_plan_document",
    "plan_bindings",
    "requirement_for_binding",
    "verify_execution_plan",
]

_ROOT = Path(__file__).resolve().parents[3]

PLAN_MEMORY_SCHEMA = "generic_plan_memory.v1"
PLAN_SCHEDULING_SCHEMA = "generic_plan_scheduling.v1"
PLAN_TERMINATION_SCHEMA = "generic_plan_termination.v1"

#: The only flows whose static kernels exist in G4.
SUPPORTED_FLOWS = ("F1", "F2", "F3", "F4", "F5")

STORAGE_SEMANTIC_KIND = "storage.rw.v1"
CPU_SEMANTIC_KIND = "cpu.obi.v1"
WISHBONE_STORAGE_SEMANTIC_KIND = "storage.rw.v1"
WISHBONE_CPU_SEMANTIC_KIND = "cpu.wishbone.v1"
WISHBONE_STORAGE_ADAPTER_ID = "wishbone.storage.v1"
WISHBONE_CPU_ADAPTER_ID = "wishbone.cpu.v1"

#: Evidence a stable-storage target must be able to produce.  These are the
#: kernel's *obligations*; the verified descriptor supplies the capability.
STORAGE_KERNEL_OBLIGATIONS = (
    "component_semantic_effect",
    "cross_component_consumption",
    "cross_component_source",
    "physical_protocol_sample",
)
CPU_KERNEL_OBLIGATIONS = (
    "cross_component_consumption",
    "cross_component_source",
    "physical_protocol_sample",
)

#: Kernel identity is pinned over the code-owned implementation files.  A
#: change there is a new kernel, never a silently re-baselined plan.
_KERNEL_FILES = (
    "src/myfuzz/runtime/compiler.py",
    "src/myfuzz/runtime/contracts.py",
    "src/myfuzz/runtime/preparation.py",
    "src/myfuzz/runtime/registry.py",
    "src/myfuzz/runtime/admission.py",
    "src/myfuzz/runtime/semantics/storage.py",
    "src/myfuzz/runtime/adapters/contracts.py",
)

_CPU_ENDPOINT_FUNCTIONS = frozenset({
    "memory_master",
    "processor_memory_master",
    "data_memory_master",
})
_TARGET_ENDPOINT_FUNCTIONS = frozenset({"mmio_slave"})

_PATH_EDGE_RELATIONS = frozenset({"persistent_state", "mmio_route"})


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _detached(value):
    """A fresh JSON value; later mutation of the source cannot reach the plan."""
    try:
        return strict_json_loads(canonical_json_bytes(value), pointer="/plan")
    except GenericRuntimeRefused:
        raise
    except (TypeError, ValueError) as error:  # pragma: no cover - defensive
        _refuse("generic-plan-mismatch", "/plan",
                {"reason": "value-not-json", "message": str(error)[:120]})


def _require_dict(value, pointer: str, *, code: str = "generic-plan-mismatch"):
    if type(value) is not dict:
        _refuse(code, pointer, {"expected": "JSON object"})
    return value


def _require_text(value, pointer: str, *, code: str = "generic-plan-mismatch"):
    if type(value) is not str or not value:
        _refuse(code, pointer, {"expected": "nonempty string"})
    return value


def _require_int(value, pointer: str, *, minimum: int = 0,
                 maximum: int | None = None, code: str = "generic-plan-mismatch"):
    if type(value) is not int or value < minimum:
        _refuse(code, pointer, {"expected": "int", "minimum": minimum})
    if maximum is not None and value > maximum:
        _refuse(code, pointer, {"expected": "int", "minimum": minimum,
                                "maximum": maximum})
    return value


def _require_list(value, pointer: str, *, code: str = "generic-plan-mismatch"):
    if type(value) is not list:
        _refuse(code, pointer, {"expected": "JSON array"})
    return value


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        _refuse("generic-source-unverified", "/kernel/source",
                {"reason": "implementation-unreadable", "file": relative})


def _kernel_implementation_sha256() -> str:
    digests = {name: _file_sha(name) for name in _KERNEL_FILES}
    return sha256(canonical_json_bytes(digests)).hexdigest()


# Import-time pin: a changed kernel is a new identity, never a silent rebase.
_KERNEL_IMPLEMENTATION = _kernel_implementation_sha256()


@dataclass(frozen=True, slots=True)
class _KernelExpectation:
    """Code-owned capability a static flow kernel requires of one role."""

    role: str
    protocol: tuple[str, str]
    semantic_kind: str
    address_units: str
    completion_kind: str
    byte_enable: bool
    evidence_obligations: tuple[str, ...]
    adapter_id: str


_STORAGE_EXPECTATION = _KernelExpectation(
    role="target",
    protocol=("apb", "3"),
    semantic_kind=STORAGE_SEMANTIC_KIND,
    address_units="byte",
    completion_kind="setup_access_response",
    byte_enable=False,
    evidence_obligations=STORAGE_KERNEL_OBLIGATIONS,
    adapter_id=STORAGE_ADAPTER_ID,
)
_MMIO_EXPECTATION = _KernelExpectation(
    role='target',protocol=('apb','3'),semantic_kind='mmio.register-bank.v1',
    address_units='byte',completion_kind='setup_access_response',byte_enable=False,
    evidence_obligations=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
    adapter_id='apb3.mmio.v1')
_WISHBONE_MMIO_EXPECTATION = _KernelExpectation(
    role='target',protocol=('wishbone','classic'),semantic_kind='mmio.register-bank.v1',
    address_units='word',completion_kind='registered_ack',byte_enable=True,
    evidence_obligations=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
    adapter_id='wishbone.mmio.v1')
_TLUL_MMIO_EXPECTATION = _KernelExpectation(
    role='target',protocol=('tl-ul','1'),semantic_kind='mmio.register-bank.v1',
    address_units='byte',completion_kind='a_valid_ready_then_d_valid_ready',byte_enable=True,
    evidence_obligations=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
    adapter_id='tlul.mmio.v1')
_AXI4LITE_MMIO_EXPECTATION = _KernelExpectation(
    role='target',protocol=('axi4-lite','1'),semantic_kind='mmio.register-bank.v1',
    address_units='byte',completion_kind='independent_channels_response',byte_enable=True,
    evidence_obligations=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
    adapter_id='axi4lite.mmio.v1')
_AHB_MMIO_EXPECTATION = _KernelExpectation(
    role='target',protocol=('ahb-lite','1'),semantic_kind='mmio.register-bank.v1',
    address_units='byte',completion_kind='address_phase_then_ready_completion',byte_enable=True,
    evidence_obligations=('cross_component_consumption','cross_component_source','physical_protocol_sample'),
    adapter_id='ahb-lite.mmio.v1')
_CPU_EXPECTATION = _KernelExpectation(
    role="cpu",
    protocol=("obi", "1"),
    semantic_kind=CPU_SEMANTIC_KIND,
    address_units="byte",
    completion_kind="grant_then_response",
    byte_enable=True,
    evidence_obligations=CPU_KERNEL_OBLIGATIONS,
    adapter_id=CPU_ADAPTER_ID,
)
_GPIO_STORAGE_EXPECTATION = _KernelExpectation(
    role='target',protocol=('apb','3'),semantic_kind='gpio.register-bank.v1',
    address_units='byte',completion_kind='setup_access_response',byte_enable=False,
    evidence_obligations=STORAGE_KERNEL_OBLIGATIONS,adapter_id='gpio.causal-storage.v1')
_WISHBONE_STORAGE_EXPECTATION = _KernelExpectation(
    role="target",
    protocol=("wishbone", "classic"),
    semantic_kind=WISHBONE_STORAGE_SEMANTIC_KIND,
    address_units="word",
    completion_kind="registered_ack",
    byte_enable=True,
    evidence_obligations=STORAGE_KERNEL_OBLIGATIONS,
    adapter_id=WISHBONE_STORAGE_ADAPTER_ID,
)
_WISHBONE_CPU_EXPECTATION = _KernelExpectation(
    role="cpu",
    protocol=("wishbone", "classic"),
    semantic_kind=WISHBONE_CPU_SEMANTIC_KIND,
    address_units="byte",
    completion_kind="cycle_strobe_held_until_ack",
    byte_enable=True,
    evidence_obligations=CPU_KERNEL_OBLIGATIONS,
    adapter_id=WISHBONE_CPU_ADAPTER_ID,
)
_AHB_CPU_EXPECTATION = _KernelExpectation(
    role='cpu',protocol=('ahb-lite','1'),semantic_kind='cpu.ahb-lite.v1',
    address_units='byte',completion_kind='address_phase_then_ready_completion',
    byte_enable=True,evidence_obligations=CPU_KERNEL_OBLIGATIONS,adapter_id='ahb-lite.cpu.v1')
_AXI4LITE_CPU_EXPECTATION = _KernelExpectation(
    role='cpu',protocol=('axi4-lite','1'),semantic_kind='cpu.axi4-lite.v1',
    address_units='byte',completion_kind='independent_channels_response',
    byte_enable=True,evidence_obligations=CPU_KERNEL_OBLIGATIONS,adapter_id='axi4-lite.cpu.v1')
#: Full AXI4 (not Lite) CPU: separate fetch and data request channels, real
#: ``rresp``/``bresp`` status, single outstanding transaction per channel.  The
#: bound adapter is ``runtime.adapters.axi4_cpu``; the native parser and the
#: generated wrapper session live in ``integration/cpu_axi4`` and
#: ``local_harness/vexii_axi_mmio_session``.
_AXI4_CPU_EXPECTATION = _KernelExpectation(
    role='cpu',protocol=('axi4','1'),semantic_kind='cpu.axi4.v1',
    address_units='byte',completion_kind='independent_channels_response',
    byte_enable=True,evidence_obligations=CPU_KERNEL_OBLIGATIONS,adapter_id='axi4.cpu.v1')
#: The packed single-port CVA6 row: same AXI4 protocol and semantic kind as the
#: reduced dual row above, one channel instead of two, and its own admission
#: verifier and bound adapter (integration/cva6_axi_mmio.py).
_CVA6_AXI4_CPU_EXPECTATION = _KernelExpectation(
    role='cpu',protocol=('axi4','1'),semantic_kind='cpu.axi4.v1',
    address_units='byte',completion_kind='independent_channels_response',
    byte_enable=True,evidence_obligations=CPU_KERNEL_OBLIGATIONS,
    adapter_id='cva6.axi4.cpu.v1')
#: The coherent TileLink client row.  Its completion is an independent A/D
#: channel response (the client may not touch the data until D arrives), its
#: beat is 64 bits with one byte enable per byte, and the denial bit is a real
#: response code rather than an error pin.
_TL_COHERENT_CPU_EXPECTATION = _KernelExpectation(
    role='cpu',protocol=('tilelink-coherent','1'),
    semantic_kind=TL_COHERENT_CPU_SEMANTIC_KIND,
    address_units='byte',completion_kind='independent_channels_response',
    byte_enable=True,evidence_obligations=CPU_KERNEL_OBLIGATIONS,
    adapter_id=TL_COHERENT_CPU_ADAPTER_ID)
_EXPECTATION_BY_ROLE = {
    ("target", ("apb", "3")): _STORAGE_EXPECTATION,
    ("cpu", ("obi", "1")): _CPU_EXPECTATION,
    ("target", ("wishbone", "classic")): _WISHBONE_STORAGE_EXPECTATION,
    ("cpu", ("wishbone", "classic")): _WISHBONE_CPU_EXPECTATION,
    ("cpu", ("ahb-lite", "1")): _AHB_CPU_EXPECTATION,
    ("cpu", ("axi4-lite", "1")): _AXI4LITE_CPU_EXPECTATION,
    ("cpu", ("axi4", "1")): _AXI4_CPU_EXPECTATION,
    ("cpu", ("tilelink-coherent", "1")): _TL_COHERENT_CPU_EXPECTATION,
    ("target", ("tl-ul", "1")): _TLUL_MMIO_EXPECTATION,
    ("target", ("axi4-lite", "1")): _AXI4LITE_MMIO_EXPECTATION,
    ("target", ("ahb-lite", "1")): _AHB_MMIO_EXPECTATION,
}


def _expectation_for(role: str, protocol, template=None, semantic_kind=None) -> _KernelExpectation:
    if role=='target' and tuple(protocol)==('wishbone','classic') and semantic_kind=='mmio.register-bank.v1':
        return _WISHBONE_MMIO_EXPECTATION
    if role=='target' and tuple(protocol)==('apb','3') and semantic_kind=='mmio.register-bank.v1':
        return _MMIO_EXPECTATION
    if role=='target' and tuple(protocol)==('apb','3') and tuple(template or ())==('pulp.gpio.causal','1','pulp_gpio_causal_v1'):
        return _GPIO_STORAGE_EXPECTATION
    if (role=='cpu' and tuple(protocol)==('axi4','1')
            and tuple(template or ())==('cpu.axi4','1','single-beat-id')):
        return _CVA6_AXI4_CPU_EXPECTATION
    key = (role, tuple(protocol))
    expectation = _EXPECTATION_BY_ROLE.get(key)
    if expectation is None:
        supported = sorted(protocol for name, protocol in _EXPECTATION_BY_ROLE
                           if name == role)
        _refuse("generic-semantic-unsupported", "/endpoints",
                {"reason": "static-kernel-protocol-unsupported", "role": role,
                 "protocol": list(protocol), "supported": supported})
    return expectation


@dataclass(frozen=True, slots=True)
class EndpointBinding:
    """One endpoint a static path kernel must have bound in the plan."""

    role: str
    instance_id: str
    endpoint_id: str
    protocol: tuple[str, str]
    template: tuple[str, str, str]
    semantic_kind: str
    required_operations: tuple[str, ...]
    evidence_obligations: tuple[str, ...]
    flows: tuple[str, ...]
    path_ids: tuple[str, ...]
    data_width: int | None = None
    address_width: int | None = None

    def document(self) -> dict:
        return {
            "role": self.role,
            "instance_id": self.instance_id,
            "endpoint_id": self.endpoint_id,
            "protocol": list(self.protocol),
            "template": list(self.template),
            "semantic_kind": self.semantic_kind,
            "required_operations": list(self.required_operations),
            "evidence_obligations": list(self.evidence_obligations),
            "flows": list(self.flows),
            "path_ids": list(self.path_ids),
            "data_width": self.data_width,
            "address_width": self.address_width,
        }


@dataclass(frozen=True, slots=True)
class _PathFacts:
    path_id: str
    flow_id: str
    flow_name: str
    direction: str
    kernel: dict
    bindings: tuple[EndpointBinding, ...]
    edges: tuple[dict, ...]
    assertions: tuple[dict, ...]
    sources: tuple[dict, ...]
    bound_inputs: tuple[dict, ...]
    constraints: dict
    termination: dict
    seed: object
    runtime_path_id: str
    runtime_source_ids: tuple[str, ...]
    target: dict
    execution_contract: dict | None
    target_data_width: int
    target_address_width: int


# ---------------------------------------------------------------------------
# same-pass compiled inputs
# ---------------------------------------------------------------------------

def _preparation_inputs(preparation) -> dict:
    """The one compiled-input mapping owned by ``preparation`` (never a copy)."""
    if type(preparation) is not PreparationContext:
        _refuse("generic-contract-type", "/preparation",
                {"expected": "PreparationContext"})
    preparation.require_open()
    inputs = preparation.compiled_inputs()
    if type(inputs) is not dict:
        _refuse("generic-plan-mismatch", "/compiled-inputs",
                {"reason": "preparation-has-no-compiled-inputs"})
    missing = [name for name in ("request", "compiled", "ownership",
                                 "physical_port_map") if name not in inputs]
    if missing:
        _refuse("generic-plan-mismatch", "/compiled-inputs",
                {"reason": "incomplete-compiled-inputs", "missing": missing})
    compiled = inputs["compiled"]
    _require_dict(compiled, "/compiled-inputs/compiled")
    if compiled.get("schema_version") != "compiled_paths.v1":
        _refuse("generic-plan-mismatch", "/compiled-inputs/compiled/schema_version",
                {"expected": "compiled_paths.v1"})
    try:
        digest = compiled_document_sha256(compiled)
    except ValueError as error:
        _refuse("generic-plan-mismatch", "/input_digests/d3",
                {"reason": "compiled-document-not-json",
                 "message": str(error)[:120]})
    if digest != preparation.input_digests.get("d3"):
        _refuse("generic-binding-drift", "/input_digests/d3",
                {"reason": "d3-digest-changed"})
    return inputs


def _wiring_document(inputs: dict) -> dict:
    request = inputs["request"]
    wiring = getattr(request, "wiring", None)
    document = getattr(wiring, "document", None)
    if type(document) is not dict:
        _refuse("generic-template-mismatch", "/wiring",
                {"reason": "wiring-document-required"})
    return document


def _memory_resources(wiring: dict) -> tuple[dict, ...]:
    """Declared persistent-memory resources of this preparation's wiring."""
    raw = wiring.get("resources")
    if type(raw) is not list:
        _refuse("generic-plan-mismatch", "/memory/resources",
                {"reason": "wiring-resource-declaration-required"})
    rows = []
    for index, row in enumerate(raw):
        pointer = f"/memory/resources/{index}"
        _require_dict(row, pointer)
        resource_id = _require_text(row.get("resource_id"),
                                    pointer + "/resource_id")
        component = _require_text(row.get("component_instance"),
                                  pointer + "/component_instance")
        base = _require_int(row.get("base"), pointer + "/base")
        size = _require_int(row.get("size"), pointer + "/size", minimum=1)
        permissions = {}
        for name in ("read", "write", "execute"):
            value = row.get(name)
            if type(value) is not bool:
                _refuse("generic-plan-mismatch", pointer + "/" + name,
                        {"expected": "bool"})
            permissions[name] = value
        policy = _require_text(row.get("initialization_policy"),
                               pointer + "/initialization_policy")
        rows.append({
            "resource_id": resource_id,
            "component_instance": component,
            "base": base,
            "size": size,
            "read": permissions["read"],
            "write": permissions["write"],
            "execute": permissions["execute"],
            "initialization_policy": policy,
        })
    identifiers = [row["resource_id"] for row in rows]
    if len(set(identifiers)) != len(identifiers):
        _refuse("generic-plan-mismatch", "/memory/resources",
                {"reason": "duplicate-memory-resource"})
    return tuple(sorted(rows, key=lambda row: row["resource_id"]))


# ---------------------------------------------------------------------------
# path derivation
# ---------------------------------------------------------------------------

def _requested_paths(preparation,
                     compiled: dict) -> tuple[tuple[dict, ...], tuple[str, ...]]:
    flows = tuple(preparation.flow_ids)
    if not flows:
        _refuse("generic-flow-unsupported", "/flows",
                {"reason": "nonempty-flow-required"})
    unsupported = [flow for flow in flows if flow not in SUPPORTED_FLOWS]
    if unsupported:
        _refuse("generic-flow-unsupported", "/flows",
                {"unsupported": unsupported, "supported": list(SUPPORTED_FLOWS)})
    raw = _require_list(compiled.get("paths"), "/compiled-inputs/compiled/paths")
    paths = []
    for flow_id in sorted(flows):
        flow_paths = [row for row in raw
                      if type(row) is dict and row.get("flow_id") == flow_id]
        executable = [row for row in flow_paths
                      if row.get("status") == "executable"]
        if not executable:
            _refuse("generic-plan-mismatch", "/paths",
                    {"flow_id": flow_id, "reason": "no-executable-path"})
        paths.extend(sorted(executable, key=lambda row: str(row.get("path_id"))))
    return tuple(paths), tuple(sorted(flows))


def _protocol_tuple(row: dict, pointer: str) -> tuple[str, str]:
    protocol = row.get("protocol")
    if type(protocol) is not list or len(protocol) != 2:
        _refuse("generic-template-mismatch", pointer + "/protocol",
                {"expected": "two-element protocol token"})
    for index, item in enumerate(protocol):
        _require_text(item, pointer + f"/protocol/{index}")
    return (protocol[0], protocol[1])


def _path_endpoint_row(path: dict, functions, pointer: str,
                       reason: str) -> dict:
    rows = [row for row in path.get("endpoints") or ()
            if type(row) is dict and row.get("function") in functions]
    # A unified fetch/data master is emitted once per declared role by D3;
    # deduplicate rows that name the same endpoint/function/protocol.  A
    # genuinely second bus endpoint or protocol still refuses below.
    unique = {}
    for row in rows:
        key = (row.get("instance_id"), row.get("endpoint_id"),
               row.get("function"), tuple(row.get("protocol") or ()))
        unique.setdefault(key, row)
    if len(unique) != 1:
        _refuse("generic-semantic-unsupported", pointer + "/endpoints",
                {"reason": reason, "matches": len(unique)})
    row = next(iter(unique.values()))
    _require_text(row.get("instance_id"), pointer + "/endpoints/instance_id")
    _require_text(row.get("endpoint_id"), pointer + "/endpoints/endpoint_id")
    _protocol_tuple(row, pointer + "/endpoints")
    return row


def _register_access(path: dict, pointer: str) -> tuple[dict, int]:
    constraints = _require_dict(path.get("constraints"),
                                pointer + "/constraints")
    candidates = []
    for index, source in enumerate(constraints.get("source_constraints") or ()):
        if type(source) is dict and type(source.get("register_access")) is dict:
            candidates.append((index, source["register_access"]))
    if len(candidates) != 1:
        _refuse("generic-plan-mismatch",
                pointer + "/constraints/source_constraints",
                {"reason": "one-register-access-required",
                 "matches": len(candidates)})
    index, access = candidates[0]
    base = pointer + f"/constraints/source_constraints/{index}/register_access"
    _require_dict(access, base)
    operation = access.get("operation")
    if operation not in ("read", "write"):
        _refuse("generic-plan-mismatch", base + "/operation",
                {"allowed": ["read", "write"]})
    for name in ("target_component", "target_endpoint",
                 "source_component", "source_endpoint", "register", "field"):
        _require_text(access.get(name), base + "/" + name)
    _require_int(access.get("address"), base + "/address")
    _require_int(access.get("width_bytes"), base + "/width_bytes",
                 minimum=1, maximum=64)
    _require_int(access.get("window_base"), base + "/window_base")
    window_size = _require_int(access.get("window_size"), base + "/window_size",
                               minimum=1)
    if window_size & (window_size - 1):
        _refuse("generic-template-mismatch", base + "/window_size",
                {"reason": "power-of-two-window-required"})
    byte_enables = access.get("allowed_byte_enables")
    _require_list(byte_enables, base + "/allowed_byte_enables")
    for byte_index, value in enumerate(byte_enables):
        _require_int(value, base + f"/allowed_byte_enables/{byte_index}")
    if not byte_enables:
        _refuse("generic-template-mismatch", base + "/allowed_byte_enables",
                {"reason": "nonempty-byte-enable-required"})
    return access, window_size.bit_length() - 1


def _assertions_of(path: dict, pointer: str) -> tuple[dict, ...]:
    assertions = path.get("assertions")
    if type(assertions) is not list or not assertions:
        _refuse("generic-plan-mismatch", pointer + "/assertions",
                {"reason": "required-assertion-missing"})
    rows = []
    for index, assertion in enumerate(assertions):
        base = pointer + f"/assertions/{index}"
        _require_dict(assertion, base)
        row = {
            "expectation_id": _require_text(assertion.get("expectation_id"),
                                            base + "/expectation_id"),
            "assertion_class": _require_text(assertion.get("assertion_class"),
                                             base + "/assertion_class"),
            "asserts": _require_text(assertion.get("asserts"),
                                     base + "/asserts"),
            "declared_by": _require_text(assertion.get("declared_by"),
                                         base + "/declared_by"),
        }
        rows.append(row)
    identifiers = [(row["expectation_id"], row["assertion_class"])
                   for row in rows]
    if len(set(identifiers)) != len(identifiers):
        _refuse("generic-plan-mismatch", pointer + "/assertions",
                {"reason": "duplicate-assertion"})
    return tuple(sorted(rows, key=lambda row: (row["expectation_id"],
                                               row["assertion_class"])))


def _sources_of(path: dict, pointer: str) -> tuple[dict, ...]:
    raw = path.get("sources")
    if type(raw) is not list or not raw:
        _refuse("generic-plan-mismatch", pointer + "/sources",
                {"reason": "no-fuzzable-source"})
    rows = []
    for index, source in enumerate(raw):
        base = pointer + f"/sources/{index}"
        _require_dict(source, base)
        row = {
            "source_id": _require_text(source.get("source_id"),
                                       base + "/source_id"),
            "component": _require_text(source.get("component"),
                                       base + "/component"),
            "endpoint_id": _require_text(source.get("endpoint_id"),
                                         base + "/endpoint_id"),
            "kind": _require_text(source.get("kind"), base + "/kind"),
            "origin": _require_text(source.get("origin"), base + "/origin"),
            "origin_ref": _require_text(source.get("origin_ref"),
                                        base + "/origin_ref"),
            "port": source.get("port"),
            "register": source.get("register"),
            "field": source.get("field"),
            "range": (None if source.get('kind')=='external_pin' and source.get('range') is None
                      else _require_list(source.get("range"), base + "/range")),
            "mask": _require_int(source.get("mask"), base + "/mask"),
            "alignment": _require_int(source.get("alignment"),
                                      base + "/alignment", minimum=1),
            "bit_offset": _require_int(source.get("bit_offset"),
                                       base + "/bit_offset"),
            "width": _require_int(source.get("width"), base + "/width",
                                  minimum=1),
            "basis": source.get("basis"),
        }
        if row['range'] is None:
            rows.append(row)
            continue
        if len(row["range"]) != 2:
            _refuse("generic-plan-mismatch", base + "/range",
                    {"expected_length": 2})
        for range_index, value in enumerate(row["range"]):
            _require_int(value, base + f"/range/{range_index}")
        rows.append(row)
    if not any(row["origin"] == "fuzzable" for row in rows):
        _refuse("generic-plan-mismatch", pointer + "/sources",
                {"reason": "no-fuzzable-source"})
    identifiers = [row["source_id"] for row in rows]
    if len(set(identifiers)) != len(identifiers):
        _refuse("generic-plan-mismatch", pointer + "/sources",
                {"reason": "duplicate-source"})
    return tuple(sorted(rows, key=lambda row: row["source_id"]))


def _bound_inputs_of(path: dict, pointer: str) -> tuple[dict, ...]:
    raw = path.get("bound_inputs") or []
    if type(raw) is not list:
        _refuse("generic-plan-mismatch", pointer + "/bound_inputs",
                {"expected": "JSON array"})
    rows = []
    for index, item in enumerate(raw):
        base = pointer + f"/bound_inputs/{index}"
        _require_dict(item, base)
        row = {
            "input_id": _require_text(item.get("input_id"), base + "/input_id"),
            "component": _require_text(item.get("component"),
                                       base + "/component"),
            "endpoint_id": _require_text(item.get("endpoint_id"),
                                         base + "/endpoint_id"),
            "kind": _require_text(item.get("kind"), base + "/kind"),
            "origin": _require_text(item.get("origin"), base + "/origin"),
            "basis": item.get("basis"),
        }
        if row["origin"] != "bound":
            _refuse("generic-plan-mismatch", base + "/origin",
                    {"expected": "bound"})
        rows.append(row)
    return tuple(sorted(rows, key=lambda row: row["input_id"]))


def _termination_of(path: dict, pointer: str) -> dict:
    observation = path.get("termination_observation")
    _require_dict(observation, pointer + "/termination_observation")
    return {
        "kind": _require_text(observation.get("kind"),
                              pointer + "/termination_observation/kind"),
        "basis": _require_text(observation.get("basis"),
                               pointer + "/termination_observation/basis"),
    }


def _contract_node(compiled: dict, node_id: str) -> dict:
    contract = compiled.get("runtime_path_contract")
    if type(contract) is not dict:
        _refuse("generic-route-refused", "/compiled-inputs/compiled/runtime_path_contract",
                {"reason": "runtime-path-contract-required"})
    rows = [node for node in contract.get("nodes") or ()
            if type(node) is dict and node.get("node_id") == node_id]
    if len(rows) != 1:
        _refuse("generic-route-refused", "/target",
                {"reason": "declared-target-node-required", "node": node_id,
                 "matches": len(rows)})
    return rows[0]


def _path_edges(path: dict, compiled: dict, *, target_row: dict,
                cpu_row: dict, access: dict, resources_by_id: dict,
                pointer: str) -> tuple[dict, ...]:
    contract = _require_dict(compiled.get("runtime_path_contract"),
                             "/compiled-inputs/compiled/runtime_path_contract")
    nodes = {}
    for node in contract.get("nodes") or ():
        if type(node) is dict and type(node.get("node_id")) is str:
            nodes[node["node_id"]] = node
    rules = {}
    for edge in contract.get("edges") or ():
        if type(edge) is dict and type(edge.get("rule_index")) is int:
            rules[edge["rule_index"]] = edge
    identity = _require_dict(path.get("runtime_path_identity"),
                             pointer + "/runtime_path_identity")
    raw_edges = identity.get("edges")
    if type(raw_edges) is not list or not raw_edges:
        _refuse("generic-route-refused", pointer + "/runtime_path_identity/edges",
                {"reason": "declared-edge-required"})
    window = {"base": access["window_base"], "size": access["window_size"]}
    rows = []
    for index, edge in enumerate(raw_edges):
        base = pointer + f"/runtime_path_identity/edges/{index}"
        _require_dict(edge, base)
        kind = _require_text(edge.get("kind"), base + "/kind")
        rule_index = _require_int(edge.get("rule_index"), base + "/rule_index")
        source_node = _require_text(edge.get("prerequisite"),
                                    base + "/prerequisite")
        target_node = _require_text(edge.get("target"), base + "/target")
        rule = rules.get(rule_index)
        if rule is None:
            _refuse("generic-route-refused", base,
                    {"reason": "edge-rule-undeclared", "rule_index": rule_index})
        relation = rule.get("relation")
        if relation not in _PATH_EDGE_RELATIONS:
            _refuse("generic-route-refused", base + "/relation",
                    {"allowed": sorted(_PATH_EDGE_RELATIONS),
                     "actual": relation})
        if relation == "persistent_state":
            resource_id = _require_text(rule.get("resource_id"),
                                        base + "/resource_id")
            component = _require_text(rule.get("resource_component"),
                                      base + "/resource_component")
            resource = resources_by_id.get(resource_id)
            if resource is None:
                _refuse("generic-plan-mismatch", base + "/resource_id",
                        {"reason": "undeclared-persistent-memory-resource",
                         "resource_id": resource_id})
            if resource["component_instance"] != component:
                _refuse("generic-plan-mismatch", base + "/resource_component",
                        {"reason": "memory-serving-component-mismatch",
                         "declared": component,
                         "wiring": resource["component_instance"]})
            provider = {"kind": "persistent_memory", "resource_id": resource_id,
                        "component": component}
        else:
            device = rule.get("device_id")
            if device != access["target_component"]:
                _refuse("generic-route-refused", base + "/device_id",
                        {"reason": "route-device-does-not-match-path-target",
                         "declared": device,
                         "target": access["target_component"]})
            declared_window = {"base": rule.get("base"), "size": rule.get("size")}
            if declared_window != window:
                _refuse("generic-route-refused", base + "/window",
                        {"reason": "route-window-does-not-match-path-access",
                         "declared": declared_window,
                         "path": window})
            node = nodes.get(target_node)
            node_component = node.get("component") if type(node) is dict else None
            if node_component == target_row["instance_id"]:
                provider = {"kind": "target_endpoint",
                            "instance_id": target_row["instance_id"],
                            "endpoint_id": target_row["endpoint_id"]}
            elif node_component == cpu_row["instance_id"]:
                provider = {"kind": "cpu_endpoint",
                            "instance_id": cpu_row["instance_id"],
                            "endpoint_id": cpu_row["endpoint_id"]}
            else:
                _refuse("generic-route-refused", base + "/target",
                        {"reason": "edge-target-has-no-bound-endpoint",
                         "node": target_node,
                         "component": node_component})
        rows.append({
            "kind": kind,
            "relation": relation,
            "rule_index": rule_index,
            "from": source_node,
            "to": target_node,
            "provider": provider,
        })
    return tuple(rows)


def _execution_contract(path: dict, *, target_row: dict, cpu_row: dict,
                        access: dict, pointer: str) -> dict | None:
    contract = path.get("execution_contract")
    if contract is None:
        return None
    _require_dict(contract, pointer + "/execution_contract")
    expected = {
        "target_component": target_row["instance_id"],
        "target_endpoint": target_row["endpoint_id"],
        "source_component": cpu_row["instance_id"],
        "source_endpoint": cpu_row["endpoint_id"],
        "address": access["address"],
        "width_bytes": access["width_bytes"],
    }
    for name, value in expected.items():
        if contract.get(name) != value:
            _refuse("generic-route-refused",
                    pointer + "/execution_contract/" + name,
                    {"declared": contract.get(name), "path": value})
    window = contract.get("window")
    if window != {"base": access["window_base"], "size": access["window_size"]}:
        _refuse("generic-route-refused", pointer + "/execution_contract/window",
                {"declared": window,
                 "path": {"base": access["window_base"],
                          "size": access["window_size"]}})
    return _detached(contract)


def _target_address_width(access: dict, units: str, pointer: str) -> int:
    """Width of the target's own address, in its declared address units.

    ``byte`` rows keep ``window_size.bit_length() - 1``.  ``word`` rows publish
    the width of the word index, so the byte window is divided by the register
    width first; a non-integral or non-power-of-two word window is refused
    rather than rounded.
    """
    window_size = access["window_size"]
    if units == "byte":
        return window_size.bit_length() - 1
    if units != "word":
        _refuse("generic-template-mismatch", pointer + "/register_access",
                {"reason": "address-units-unsupported", "units": units})
    width_bytes = access["width_bytes"]
    if (width_bytes not in (1, 2, 4, 8) or window_size % width_bytes
            or not 0 < window_size // width_bytes < 1 << 16):
        _refuse("generic-template-mismatch",
                pointer + "/register_access/window_size",
                {"reason": "word-addressed-window-not-integral",
                 "window_size": window_size, "width_bytes": width_bytes})
    words = window_size // width_bytes
    if words & (words - 1):
        _refuse("generic-template-mismatch",
                pointer + "/register_access/window_size",
                {"reason": "power-of-two-word-window-required",
                 "words": words})
    return words.bit_length() - 1


def _flow_kernel(preparation, flow_id: str, path_id: str) -> dict:
    support = preparation.flow_support(flow_id)
    if support.get("execution_supported") != 1:
        _refuse("generic-plan-mismatch", "/paths",
                {"flow_id": flow_id, "reason": "flow-support-refused"})
    if support.get("runtime_admitted") is not False:
        _refuse("generic-plan-mismatch", "/paths",
                {"flow_id": flow_id,
                 "reason": "static-support-must-not-claim-runtime-admission"})
    if support.get("path_id") != path_id:
        _refuse("generic-plan-mismatch", "/paths",
                {"flow_id": flow_id, "reason": "support-path-mismatch",
                 "support_path_id": support.get("path_id"),
                 "path_id": path_id})
    executor = _require_text(support.get("executor"), f"/paths/{flow_id}/executor")
    producer = support.get("producer_binding")
    if producer is None and flow_id=='F4':
        from myfuzz.integration.compiled_storage_producer import select_storage_producer
        producer=select_storage_producer(artifacts=preparation.artifacts,
            compiled_inputs=_preparation_inputs(preparation),base_dir=preparation.base_dir).document()
    if type(producer) is not dict:
        _refuse("generic-plan-mismatch", "/paths",
                {"flow_id": flow_id, "reason": "producer-binding-required"})
    startup = support.get("startup_requires") or []
    if type(startup) is not list or not all(
            type(item) is str and item for item in startup):
        _refuse("generic-plan-mismatch", "/paths",
                {"flow_id": flow_id, "reason": "startup-requirements-invalid"})
    return {
        "id": f"generic.flow.{flow_id}.static.v1",
        "version": "1",
        "flow_id": flow_id,
        "implementation_sha256": _KERNEL_IMPLEMENTATION,
        "executor": executor,
        "support_status": support.get("status"),
        "support_scope": support.get("support_scope"),
        "producer_binding_sha256": sha256(
            canonical_json_bytes(producer)).hexdigest(),
        "startup_requires": sorted(set(startup)),
    }


def _path_facts(preparation, path: dict, *, compiled: dict,
                resources_by_id: dict, pointer: str) -> _PathFacts:
    path_id = _require_text(path.get("path_id"), pointer + "/path_id")
    flow_id = _require_text(path.get("flow_id"), pointer + "/flow_id")
    if flow_id not in SUPPORTED_FLOWS:
        _refuse("generic-flow-unsupported", pointer + "/flow_id",
                {"flow_id": flow_id, "supported": list(SUPPORTED_FLOWS)})
    if path.get("status") != "executable":
        _refuse("generic-plan-mismatch", pointer + "/status",
                {"reason": "executable-path-required",
                 "actual": path.get("status")})
    if flow_id in ("F1", "F3"):
        return _memory_path_facts(preparation, path, compiled=compiled,
                                  resources_by_id=resources_by_id, pointer=pointer)
    if flow_id=='F5':
        return _pin_path_facts(preparation,path,compiled=compiled,pointer=pointer)
    flow_name = _require_text(path.get("flow_name"), pointer + "/flow_name")
    direction = _require_text(path.get("direction"), pointer + "/direction")

    target_row = _path_endpoint_row(
        path, _TARGET_ENDPOINT_FUNCTIONS, pointer,
        "one-mmio-slave-target-required")
    cpu_row = _path_endpoint_row(
        path, _CPU_ENDPOINT_FUNCTIONS, pointer, "one-cpu-data-endpoint-required")

    access, target_address_width = _register_access(path, pointer)
    if (access["target_component"], access["target_endpoint"]) != (
            target_row["instance_id"], target_row["endpoint_id"]):
        _refuse("generic-route-refused", pointer + "/constraints",
                {"reason": "register-access-target-not-the-path-target"})
    if (access["source_component"], access["source_endpoint"]) != (
            cpu_row["instance_id"], cpu_row["endpoint_id"]):
        _refuse("generic-route-refused", pointer + "/constraints",
                {"reason": "register-access-source-not-the-path-cpu"})

    target_protocol = _protocol_tuple(target_row, pointer + "/endpoints")
    cpu_protocol = _protocol_tuple(cpu_row, pointer + "/endpoints")
    target_expectation = _expectation_for("target", target_protocol)
    cpu_expectation = _expectation_for("cpu", cpu_protocol)
    # A word-addressed target addresses words, not bytes: the verified
    # descriptor of such an endpoint publishes only the width of its word
    # index.  The byte window is converted through the register width, which
    # is exactly what the adapter does at runtime.  Byte-addressed rows keep
    # the historical byte-width derivation untouched.
    target_address_width = _target_address_width(
        access, target_expectation.address_units, pointer + "/constraints")
    declared_cpu_endpoint = preparation.declared_cpu_data_endpoint(
        cpu_row["instance_id"])
    if declared_cpu_endpoint != cpu_row["endpoint_id"]:
        _refuse("generic-template-mismatch", pointer + "/endpoints",
                {"reason": "declared-cpu-data-endpoint-mismatch",
                 "declared": declared_cpu_endpoint,
                 "path": cpu_row["endpoint_id"]})
    target_template = preparation.declared_endpoint_template(
        target_row["instance_id"], target_row["endpoint_id"])
    target_artifact=preparation.artifact(target_row['instance_id'])
    if target_artifact.runtime_document.get('kind')=='apb_gpio':
        selected=target_artifact.runtime_document.get('selected_template',{}).get('contract',{})
        actual=tuple(selected.get(k) for k in ('template_id','template_version','variant_id'))
        if actual!=('pulp.gpio.causal','1','pulp_gpio_causal_v1'):
            _refuse('generic-template-mismatch',pointer+'/template')
        target_template=actual
    cpu_template = preparation.declared_endpoint_template(
        cpu_row["instance_id"], cpu_row["endpoint_id"])
    target_expectation = _expectation_for('target',target_protocol,target_template)
    if (target_artifact.runtime_document.get('kind')=='apb3_register_observe'
            and target_artifact.runtime_document.get('storage_observation') is None):
        target_expectation = _MMIO_EXPECTATION
    if (target_artifact.runtime_document.get('kind')=='wishbone_register_observe'
            and target_artifact.runtime_document.get('storage_observation') is None):
        target_expectation = _WISHBONE_MMIO_EXPECTATION
    if target_expectation is _GPIO_STORAGE_EXPECTATION:
        from .adapters.gpio_storage import bank_contract_facts
        bank=bank_contract_facts(target_artifact,base_dir=preparation.base_dir,
            endpoint_id=target_row['endpoint_id'],template=target_template)
        if not bank.supports(register=access.get('register'),operation=access.get('operation'),offset=access.get('register_offset')):
            _refuse('generic-semantic-unsupported',pointer+'/register_access',
                    {'reason':'GPIO-register-subcontract-required'})

    target = _require_dict(path.get("target"), pointer + "/target")
    target_node = _require_text(target.get("node"), pointer + "/target/node")
    target_component = _require_text(target.get("component"),
                                     pointer + "/target/component")

    identity = _require_dict(path.get("runtime_path_identity"),
                             pointer + "/runtime_path_identity")
    runtime_path_id = _require_text(identity.get("path_id"),
                                    pointer + "/runtime_path_identity/path_id")
    runtime_sources = identity.get("source_ids")
    if type(runtime_sources) is not list or not runtime_sources or not all(
            type(item) is str and item for item in runtime_sources):
        _refuse("generic-plan-mismatch",
                pointer + "/runtime_path_identity/source_ids",
                {"reason": "declared-source-ids-required"})

    assertions = _assertions_of(path, pointer)
    sources = _sources_of(path, pointer)
    bound_inputs = _bound_inputs_of(path, pointer)
    constraints = _detached(_require_dict(path.get("constraints"),
                                          pointer + "/constraints"))
    for name in ("policy_hash", "layout_hash"):
        if constraints.get(name) is not None and type(
                constraints.get(name)) is not str:
            _refuse("generic-plan-mismatch",
                    pointer + "/constraints/" + name,
                    {"expected": "string or null"})
    if type(constraints.get("rule_ids")) is not list or not all(
            type(item) is str for item in constraints["rule_ids"]):
        _refuse("generic-plan-mismatch", pointer + "/constraints/rule_ids",
                {"expected": "list of rule ids"})
    if type(constraints.get("rules")) is not list:
        _refuse("generic-plan-mismatch", pointer + "/constraints/rules",
                {"expected": "JSON array"})
    termination = _termination_of(path, pointer)
    seed = path.get("seed")
    if seed is not None and type(seed) is not dict:
        _refuse("generic-plan-mismatch", pointer + "/seed",
                {"expected": "JSON object or null"})

    edges = _path_edges(path, compiled, target_row=target_row,
                        cpu_row=cpu_row, access=access,
                        resources_by_id=resources_by_id, pointer=pointer)
    if edges[-1]["to"] != target_node:
        _refuse("generic-route-refused", pointer + "/target",
                {"reason": "declared-target-is-not-the-terminal-edge-node",
                 "target": target_node, "terminal": edges[-1]["to"]})
    node = _contract_node(compiled, target_node)
    if node.get("component") != target_component:
        _refuse("generic-route-refused", pointer + "/target/component",
                {"reason": "target-node-component-mismatch",
                 "declared": target_component,
                 "nodes": node.get("component")})
    if not any(edge["provider"]["kind"] == "persistent_memory"
               for edge in edges):
        _refuse("generic-route-refused", pointer + "/runtime_path_identity/edges",
                {"reason": "persistent-memory-provider-required"})
    if not any(edge["provider"]["kind"] == "target_endpoint"
               for edge in edges):
        _refuse("generic-route-refused", pointer + "/runtime_path_identity/edges",
                {"reason": "target-endpoint-provider-required"})

    execution_contract = _execution_contract(
        path, target_row=target_row, cpu_row=cpu_row, access=access,
        pointer=pointer)
    kernel = _flow_kernel(preparation, flow_id, path_id)

    operation = access["operation"]
    target_binding = EndpointBinding(
        role="target",
        instance_id=target_row["instance_id"],
        endpoint_id=target_row["endpoint_id"],
        protocol=target_protocol,
        template=tuple(target_template),
        semantic_kind=target_expectation.semantic_kind,
        required_operations=(operation,),
        evidence_obligations=target_expectation.evidence_obligations,
        flows=(flow_id,),
        path_ids=(path_id,),
        data_width=access["width_bytes"] * 8,
        address_width=target_address_width,
    )
    cpu_binding = EndpointBinding(
        role="cpu",
        instance_id=cpu_row["instance_id"],
        endpoint_id=cpu_row["endpoint_id"],
        protocol=cpu_protocol,
        template=tuple(cpu_template),
        semantic_kind=cpu_expectation.semantic_kind,
        required_operations=(operation,),
        evidence_obligations=cpu_expectation.evidence_obligations,
        flows=(flow_id,),
        path_ids=(path_id,),
    )
    return _PathFacts(
        path_id=path_id, flow_id=flow_id, flow_name=flow_name,
        direction=direction, kernel=kernel,
        bindings=(cpu_binding, target_binding), edges=edges,
        assertions=assertions, sources=sources, bound_inputs=bound_inputs,
        constraints=constraints, termination=termination, seed=seed,
        runtime_path_id=runtime_path_id,
        runtime_source_ids=tuple(sorted(runtime_sources)),
        target=_detached(target), execution_contract=execution_contract,
        target_data_width=access["width_bytes"] * 8,
        target_address_width=target_address_width)


def _pin_path_facts(preparation,path,*,compiled,pointer):
    """Document the physical pin/IRQ route without inventing an IRQ bus API."""
    from myfuzz.integration.shared_f5_runtime import admit_shared_f5_declaration
    inputs=_preparation_inputs(preparation)
    admit_shared_f5_declaration(artifacts=preparation.artifacts,compiled_inputs=inputs)
    identity=path['runtime_path_identity']
    cpu_id=inputs['request'].cpu.instance_id
    endpoint_id=preparation.declared_cpu_data_endpoint(cpu_id)
    artifact=preparation.artifact(cpu_id)
    endpoint=next(e for e in artifact.plan.binding.endpoints if e.endpoint_id==endpoint_id)
    protocol=tuple(endpoint.protocol)
    expectation=_expectation_for('cpu',protocol)
    binding=EndpointBinding(role='cpu',instance_id=cpu_id,endpoint_id=endpoint_id,
        protocol=protocol,template=tuple(preparation.declared_endpoint_template(cpu_id,endpoint_id)),
        semantic_kind=expectation.semantic_kind,required_operations=('read',),
        evidence_obligations=expectation.evidence_obligations,flows=('F5',),path_ids=(path['path_id'],))
    contracts={(e['rule_index'],e['prerequisite_index']):e for e in compiled['runtime_path_contract']['edges']}
    deliveries=inputs['request'].wiring.deliveries
    edges=[]
    for edge in identity['edges']:
        declaration=contracts.get((edge['rule_index'],edge['prerequisite_index']))
        if declaration and declaration['relation']=='direct_binding':
            source = _contract_node(compiled,edge['prerequisite'])
            target = _contract_node(compiled,edge['target'])
            matches = [d for d in deliveries if d.producer_instance == source['component']
                       and d.consumer_instance == target['component']
                       and (d.consumer_bit_offset is None or d.consumer_bit_offset == target['bit_offset'])]
            if len(matches) != 1:
                raise ValueError('F5 direct binding requires one matching IRQ delivery')
            provider={'kind':'irq_delivery','delivery_id':matches[0].delivery_id,
                'source':_detached(source), 'target':_detached(target)}
            relation='direct_binding'
        else:
            provider={'kind':'physical_source','source':_detached(_contract_node(compiled,edge['prerequisite']))}
            relation='causal_order'
        edges.append({'kind':edge['kind'],'relation':relation,'rule_index':edge['rule_index'],
            'from':edge['prerequisite'],'to':edge['target'],'provider':provider})
    return _PathFacts(path_id=path['path_id'],flow_id='F5',flow_name=path['flow_name'],
        direction=path['direction'],kernel=_flow_kernel(preparation,'F5',path['path_id']),
        bindings=(binding,),edges=tuple(edges),assertions=_assertions_of(path,pointer),
        sources=_sources_of(path,pointer),bound_inputs=_bound_inputs_of(path,pointer),
        constraints=_detached(path['constraints']),termination=_termination_of(path,pointer),
        seed=path.get('seed'),runtime_path_id=identity['path_id'],
        runtime_source_ids=tuple(identity['source_ids']),target=_detached(path['target']),
        execution_contract=None,target_data_width=32,target_address_width=32)


def _memory_path_facts(preparation, path, *, compiled, resources_by_id, pointer):
    """Derive the CPU and actual RAM edges without fabricating an IP target."""
    from .flows.memory import prepare_memory_paths
    flow = path['flow_id']
    inputs = _preparation_inputs(preparation)
    prepared, image_bindings = prepare_memory_paths(request=inputs['request'], compiled=compiled)
    identity = _require_dict(path.get('runtime_path_identity'), pointer + '/runtime_path_identity')
    runtime_id = _require_text(identity.get('path_id'), pointer + '/runtime_path_identity/path_id')
    bindings = [binding for binding in image_bindings if binding.path_id == runtime_id]
    if len(bindings) != 1:
        _refuse('generic-plan-mismatch', pointer, {'reason': 'memory-source-binding-required'})
    image = bindings[0]
    source_rows = _sources_of(path, pointer)
    if not any(source['source_id'] == image.logical_source_id for source in source_rows):
        _refuse('generic-source-unverified', pointer + '/sources')
    cpu_id = image.component
    endpoint_id = preparation.declared_cpu_data_endpoint(cpu_id)
    artifact = preparation.artifact(cpu_id)
    endpoint_rows = [item for item in artifact.plan.binding.endpoints if item.endpoint_id == endpoint_id]
    if len(endpoint_rows) != 1 or endpoint_rows[0].protocol is None:
        _refuse('generic-template-mismatch', pointer + '/endpoints')
    protocol = tuple(endpoint_rows[0].protocol)
    expectation = _expectation_for('cpu', protocol)
    template = preparation.declared_endpoint_template(cpu_id, endpoint_id)
    cpu_binding = EndpointBinding(role='cpu', instance_id=cpu_id, endpoint_id=endpoint_id,
        protocol=protocol, template=tuple(template), semantic_kind=expectation.semantic_kind,
        required_operations=('read',) if flow == 'F1' else ('write',),
        evidence_obligations=expectation.evidence_obligations,
        flows=(flow,), path_ids=(path['path_id'],))
    declarations = {(edge['rule_index'], edge['prerequisite_index']): edge
                    for edge in compiled['runtime_path_contract']['edges']}
    edges = []
    for edge in identity['edges']:
        declaration = declarations.get((edge['rule_index'], edge['prerequisite_index']))
        if declaration is None or declaration['relation'] != 'persistent_state':
            _refuse('generic-route-refused', pointer + '/runtime_path_identity/edges')
        resource = resources_by_id.get(declaration['resource_id'])
        if resource is None or resource['component_instance'] != declaration['resource_component']:
            _refuse('generic-route-refused', pointer + '/runtime_path_identity/edges')
        edges.append({'kind': edge['kind'], 'relation': 'persistent_state',
            'rule_index': edge['rule_index'], 'from': edge['prerequisite'], 'to': edge['target'],
            'provider': {'kind': 'persistent_memory', 'resource_id': declaration['resource_id'],
                         'component': declaration['resource_component']}})
    target = _require_dict(path.get('target'), pointer + '/target')
    if _contract_node(compiled, target['node']).get('component') != cpu_id:
        _refuse('generic-route-refused', pointer + '/target')
    return _PathFacts(path_id=path['path_id'], flow_id=flow, flow_name=path['flow_name'],
        direction=path['direction'], kernel=_flow_kernel(preparation, flow, path['path_id']),
        bindings=(cpu_binding,), edges=tuple(edges), assertions=_assertions_of(path, pointer),
        sources=source_rows, bound_inputs=_bound_inputs_of(path, pointer),
        constraints=_detached(path['constraints']), termination=_termination_of(path, pointer),
        seed=path.get('seed'), runtime_path_id=runtime_id,
        runtime_source_ids=tuple(identity['source_ids']), target=_detached(target),
        execution_contract=None, target_data_width=32, target_address_width=32)


def _merge_bindings(facts: tuple[_PathFacts, ...]) -> tuple[EndpointBinding, ...]:
    merged: dict[tuple[str, str, str], EndpointBinding] = {}
    for fact in facts:
        for binding in fact.bindings:
            key = (binding.role, binding.instance_id, binding.endpoint_id)
            existing = merged.get(key)
            if existing is None:
                merged[key] = binding
                continue
            stable = (existing.protocol, existing.template,
                      existing.semantic_kind, existing.evidence_obligations,
                      existing.data_width, existing.address_width)
            candidate = (binding.protocol, binding.template,
                         binding.semantic_kind, binding.evidence_obligations,
                         binding.data_width, binding.address_width)
            if stable != candidate:
                _refuse("generic-plan-mismatch", "/paths",
                        {"reason": "inconsistent-endpoint-binding-across-paths",
                         "role": binding.role,
                         "instance_id": binding.instance_id,
                         "endpoint_id": binding.endpoint_id})
            merged[key] = EndpointBinding(
                role=existing.role,
                instance_id=existing.instance_id,
                endpoint_id=existing.endpoint_id,
                protocol=existing.protocol,
                template=existing.template,
                semantic_kind=existing.semantic_kind,
                required_operations=tuple(sorted(
                    set(existing.required_operations)
                    | set(binding.required_operations))),
                evidence_obligations=existing.evidence_obligations,
                flows=tuple(sorted(set(existing.flows) | set(binding.flows))),
                path_ids=tuple(sorted(set(existing.path_ids)
                                      | set(binding.path_ids))),
                data_width=existing.data_width,
                address_width=existing.address_width,
            )
    return tuple(merged[key] for key in sorted(merged))


def plan_bindings(preparation) -> tuple[EndpointBinding, ...]:
    """Derive the endpoints the static flow kernels require from this D3.

    Public helper for the explicit prepare entry point: the CLI builds its
    requirements and adapter selections from these bindings plus the verified
    descriptors, never from a caller-supplied tuple.
    """
    inputs = _preparation_inputs(preparation)
    wiring = _wiring_document(inputs)
    resources = _memory_resources(wiring)
    resources_by_id = {row["resource_id"]: row for row in resources}
    paths, _flows = _requested_paths(preparation, inputs["compiled"])
    facts = _derive_facts(preparation, inputs["compiled"], paths,
                          resources_by_id)
    return _merge_bindings(facts)


def _derive_facts(preparation, compiled: dict, paths: tuple[dict, ...],
                  resources_by_id: dict) -> tuple[_PathFacts, ...]:
    facts = []
    for index, path in enumerate(paths):
        facts.append(_path_facts(preparation, path, compiled=compiled,
                                 resources_by_id=resources_by_id,
                                 pointer=f"/paths/{index}"))
    return tuple(facts)


# ---------------------------------------------------------------------------
# verified-descriptor capability resolution
# ---------------------------------------------------------------------------

def _validate_components(preparation,
                         components) -> tuple[VerifiedComponent, ...]:
    if type(components) is not tuple:
        _refuse("generic-contract-type", "/components",
                {"expected": "tuple of VerifiedComponent"})
    if not components:
        _refuse("generic-plan-mismatch", "/components",
                {"reason": "no-verified-component"})
    seen = set()
    for index, component in enumerate(components):
        if type(component) is not VerifiedComponent:
            _refuse("generic-contract-type", f"/components/{index}")
        # Object-identity membership in this exact preparation context.
        preparation.require_component(component)
        if component.instance_id in seen:
            _refuse("generic-plan-mismatch", f"/components/{index}",
                    {"reason": "duplicate-instance"})
        seen.add(component.instance_id)
    return components


def _validate_selections(preparation, selections) -> tuple[AdapterSelection, ...]:
    if type(selections) is not tuple:
        _refuse("generic-contract-type", "/selections",
                {"expected": "tuple of AdapterSelection"})
    if not selections:
        _refuse("generic-plan-mismatch", "/selections",
                {"reason": "no-adapter-selection"})
    for index, selection in enumerate(selections):
        if type(selection) is not AdapterSelection:
            _refuse("generic-contract-type", f"/selections/{index}")
        preparation.require_selection(selection)
    return selections


def _validate_requirements(requirements) -> tuple[CapabilityRequirement, ...]:
    if type(requirements) is not tuple:
        _refuse("generic-contract-type", "/requirements",
                {"expected": "tuple of CapabilityRequirement"})
    if not requirements:
        _refuse("generic-plan-mismatch", "/requirements",
                {"reason": "no-capability-requirement"})
    for index, requirement in enumerate(requirements):
        if type(requirement) is not CapabilityRequirement:
            _refuse("generic-contract-type", f"/requirements/{index}")
    return requirements


def _endpoint_of(component: VerifiedComponent, endpoint_id: str,
                 pointer: str) -> dict:
    rows = [row for row in component.endpoints()
            if row.get("endpoint_id") == endpoint_id]
    if len(rows) != 1:
        _refuse("generic-plan-mismatch", pointer,
                {"reason": "verified-endpoint-missing",
                 "instance_id": component.instance_id,
                 "endpoint_id": endpoint_id,
                 "matches": len(rows)})
    return rows[0]


def _registration(adapter_id: str):
    rows = [row for row in registrations() if row.adapter_id == adapter_id]
    return rows[0] if len(rows) == 1 else None


def requirement_for_binding(component: VerifiedComponent,
                            binding: EndpointBinding) -> CapabilityRequirement:
    """Build the requirement for one kernel binding from the verified descriptor.

    This is the code-owned "descriptor + kernel derivation" the prepare CLI
    uses.  It does not choose the endpoint: the endpoint/role/semantic kind come
    from the same-pass D3 derivation (:func:`plan_bindings`); only the verified
    capability values are filled in here and checked against that derivation.
    """
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    if type(binding) is not EndpointBinding:
        _refuse("generic-contract-type", "/binding")
    pointer = "/descriptor/endpoints/" + binding.endpoint_id
    endpoint = _endpoint_of(component, binding.endpoint_id, pointer)
    expectation = _expectation_for(binding.role, binding.protocol,binding.template,binding.semantic_kind)
    if endpoint["role"] != binding.role:
        _refuse("generic-template-mismatch", pointer + "/role",
                {"expected": binding.role, "verified": endpoint["role"]})
    if tuple(endpoint["protocol"]) != binding.protocol:
        _refuse("generic-template-mismatch", pointer + "/protocol",
                {"expected": list(binding.protocol),
                 "verified": endpoint["protocol"]})
    if tuple(endpoint["template"]) != binding.template:
        _refuse("generic-template-mismatch", pointer + "/template",
                {"expected": list(binding.template),
                 "verified": endpoint["template"]})
    if endpoint["semantic_kind"] != expectation.semantic_kind:
        _refuse("generic-semantic-unsupported", pointer + "/semantic_kind",
                {"reason": "static-kernel-semantic-required",
                 "required": expectation.semantic_kind,
                 "verified": endpoint["semantic_kind"]})
    return CapabilityRequirement(
        role=endpoint["role"],
        endpoint_id=endpoint["endpoint_id"],
        protocol=tuple(endpoint["protocol"]),
        template=tuple(endpoint["template"]),
        semantic_kind=binding.semantic_kind,
        operations=tuple(endpoint["operations"]),
        data_width=endpoint["data_width"],
        address_width=endpoint["address_width"],
        max_outstanding=endpoint["max_outstanding"],
        completion_kind=endpoint["completion_kind"],
        byte_enable_required=endpoint["byte_enable"],
        address_units=endpoint["address_units"],
        evidence_obligations=binding.evidence_obligations,
    )


def _resolve_capabilities(facts: tuple[_PathFacts, ...],
                          bindings: tuple[EndpointBinding, ...],
                          components: tuple[VerifiedComponent, ...],
                          selections: tuple[AdapterSelection, ...],
                          requirements: tuple[CapabilityRequirement, ...]):
    component_by_instance = {}
    for index, component in enumerate(components):
        if component.instance_id in component_by_instance:
            _refuse("generic-plan-mismatch", f"/components/{index}",
                    {"reason": "duplicate-instance"})
        component_by_instance[component.instance_id] = component

    requirement_by_key = {}
    for index, requirement in enumerate(requirements):
        key = (requirement.role, requirement.endpoint_id)
        if key in requirement_by_key:
            _refuse("generic-plan-mismatch", f"/requirements/{index}",
                    {"reason": "duplicate-requirement",
                     "endpoint_id": requirement.endpoint_id})
        requirement_by_key[key] = (index, requirement)
    binding_keys = {(binding.role, binding.endpoint_id)
                    for binding in bindings}
    missing = sorted(set(binding_keys) - set(requirement_by_key))
    extra = sorted(set(requirement_by_key) - binding_keys)
    if missing or extra:
        _refuse("generic-plan-mismatch", "/requirements",
                {"reason": "requirement-set-mismatch",
                 "missing": [list(item) for item in missing],
                 "extra": [list(item) for item in extra]})

    used_selections: set[int] = set()
    capability_rows: dict[tuple[str, str, str], dict] = {}
    selection_rows: list[dict] = []
    for binding in bindings:
        expectation = _expectation_for(binding.role, binding.protocol,binding.template,binding.semantic_kind)
        component = component_by_instance.get(binding.instance_id)
        if component is None:
            _refuse("generic-plan-mismatch", "/components",
                    {"reason": "binding-component-missing",
                     "instance_id": binding.instance_id,
                     "role": binding.role})
        component_pointer = f"/components/{component.instance_id}"
        endpoint = _endpoint_of(component, binding.endpoint_id,
                                component_pointer + "/endpoints")
        for name, required in (
                ("role", binding.role),
                ("protocol", list(binding.protocol)),
                ("template", list(binding.template)),
                ("semantic_kind", binding.semantic_kind),
                ("address_units", expectation.address_units),
                ("completion_kind", expectation.completion_kind),
                ("byte_enable", expectation.byte_enable)):
            if endpoint[name] != required:
                _refuse("generic-template-mismatch",
                        component_pointer + "/endpoints/" + name,
                        {"reason": "verified-descriptor-does-not-match-static-kernel",
                         "role": binding.role,
                         "endpoint_id": binding.endpoint_id,
                         "required": required,
                         "verified": endpoint[name]})
        if binding.role == "target":
            if endpoint["data_width"] != binding.data_width \
                    or endpoint["address_width"] != binding.address_width:
                _refuse("generic-template-mismatch",
                        component_pointer + "/endpoints/widths",
                        {"reason": "path-width-does-not-match-verified-endpoint",
                         "path": {"data_width": binding.data_width,
                                  "address_width": binding.address_width},
                         "verified": {"data_width": endpoint["data_width"],
                                      "address_width": endpoint["address_width"]}})
        else:
            for fact in facts:
                roles = {(row.role, row.instance_id, row.endpoint_id)
                         for row in fact.bindings}
                if (binding.role, binding.instance_id,
                        binding.endpoint_id) not in roles:
                    continue
                if fact.target_data_width % 8 != 0:
                    _refuse("generic-template-mismatch",
                            component_pointer + "/endpoints/data_width",
                            {"reason": "register-width-is-not-a-byte-multiple",
                             "register_bits": fact.target_data_width})
                if fact.target_data_width != endpoint["data_width"]:
                    # A CPU beat wider than the register is still a correct
                    # access when the endpoint *proves* byte enables: the
                    # adapter enables exactly the register's bytes inside the
                    # wider beat, which is what the byte-enable mask is for.
                    # Without that proof the widths must be equal, because the
                    # beat would read or write neighbouring addresses too.
                    wider_but_masked = (
                        endpoint["byte_enable"] is True
                        and 0 < fact.target_data_width < endpoint["data_width"]
                        and endpoint["data_width"] % fact.target_data_width == 0)
                    if not wider_but_masked:
                        _refuse("generic-template-mismatch",
                                component_pointer + "/endpoints/data_width",
                                {"reason":
                                 "cpu-transaction-width-does-not-match-register-width",
                                 "register_bits": fact.target_data_width,
                                 "verified_data_width": endpoint["data_width"],
                                 "byte_enable": endpoint["byte_enable"]})
                if fact.flow_id not in ('F1', 'F3','F5'):
                    access = _register_access_for_fact(fact)
                    limit = 1 << endpoint["address_width"]
                    if access["address"] >= limit \
                            or access["window_base"] + access["window_size"] > limit:
                        _refuse("generic-template-mismatch",
                                component_pointer + "/endpoints/address_width",
                                {"reason":
                                 "declared-window-exceeds-verified-address-width",
                                 "verified_address_width": endpoint["address_width"]})

        index, requirement = requirement_by_key[(binding.role,
                                                 binding.endpoint_id)]
        requirement_pointer = f"/requirements/{index}"
        exact = (
            ("role", binding.role, requirement.role),
            ("protocol", list(binding.protocol), list(requirement.protocol)),
            ("template", list(binding.template), list(requirement.template)),
            ("semantic_kind", binding.semantic_kind,
             requirement.semantic_kind),
            ("data_width", endpoint["data_width"], requirement.data_width),
            ("address_width", endpoint["address_width"],
             requirement.address_width),
            ("address_units", endpoint["address_units"],
             requirement.address_units),
            ("completion_kind", endpoint["completion_kind"],
             requirement.completion_kind),
            ("byte_enable", endpoint["byte_enable"],
             requirement.byte_enable_required),
        )
        for name, required, actual in exact:
            if required != actual:
                _refuse("generic-plan-mismatch",
                        requirement_pointer + "/" + name,
                        {"reason": "requirement-does-not-match-derived-capability",
                         "required": required, "claimed": actual})
        if requirement.max_outstanding > endpoint["max_outstanding"]:
            _refuse("generic-template-mismatch",
                    requirement_pointer + "/max_outstanding",
                    {"required": requirement.max_outstanding,
                     "verified": endpoint["max_outstanding"]})
        missing_operations = sorted(set(binding.required_operations)
                                    - set(requirement.operations))
        if missing_operations:
            _refuse("generic-plan-mismatch",
                    requirement_pointer + "/operations",
                    {"reason": "required-operation-removed",
                     "missing": missing_operations})
        unsupported_operations = sorted(set(requirement.operations)
                                        - set(endpoint["operations"]))
        if unsupported_operations:
            _refuse("generic-semantic-unsupported",
                    requirement_pointer + "/operations",
                    {"reason": "operation-not-in-verified-descriptor",
                     "unsupported": unsupported_operations})
        missing_evidence = sorted(set(binding.evidence_obligations)
                                  - set(requirement.evidence_obligations))
        if missing_evidence:
            _refuse("generic-plan-mismatch",
                    requirement_pointer + "/evidence_obligations",
                    {"reason": "required-evidence-obligation-removed",
                     "missing": missing_evidence})
        unsupported_evidence = sorted(set(requirement.evidence_obligations)
                                      - set(endpoint["evidence_capabilities"]))
        if unsupported_evidence:
            _refuse("generic-evidence-missing",
                    requirement_pointer + "/evidence_obligations",
                    {"reason": "evidence-not-in-verified-descriptor",
                     "unsupported": unsupported_evidence,
                     "supported": endpoint["evidence_capabilities"]})
        extra_evidence = sorted(set(requirement.evidence_obligations)
                                - set(binding.evidence_obligations))
        if extra_evidence:
            _refuse("generic-plan-mismatch",
                    requirement_pointer + "/evidence_obligations",
                    {"reason": "obligation-not-required-by-flow-kernel",
                     "extra": extra_evidence})

        selection_index = None
        for candidate_index, selection in enumerate(selections):
            if (selection.component_artifact_sha256 == component.artifact_sha256
                    and selection.semantic_contract_sha256
                    == component.semantic_contract_sha256):
                if selection_index is not None:
                    _refuse("generic-plan-mismatch", "/selections",
                            {"reason": "ambiguous-adapter-selection",
                             "instance_id": component.instance_id})
                selection_index = candidate_index
        if selection_index is None:
            _refuse("generic-plan-mismatch", "/selections",
                    {"reason": "selection-missing-for-binding",
                     "instance_id": component.instance_id,
                     "endpoint_id": binding.endpoint_id})
        selection = selections[selection_index]
        used_selections.add(selection_index)
        if selection.adapter_id != expectation.adapter_id:
            _refuse("generic-plan-mismatch",
                    f"/selections/{selection_index}/adapter_id",
                    {"reason": "kernel-substitution",
                     "role": binding.role,
                     "endpoint_id": binding.endpoint_id,
                     "required_adapter": expectation.adapter_id,
                     "selected_adapter": selection.adapter_id})
        registration = _registration(selection.adapter_id)
        if registration is None:
            _refuse("generic-adapter-missing", f"/selections/{selection_index}",
                    {"adapter_id": selection.adapter_id})
        if selection.adapter_version != registration.adapter_version:
            _refuse("generic-binding-drift",
                    f"/selections/{selection_index}/adapter_version",
                    {"adapter_id": selection.adapter_id,
                     "selected": selection.adapter_version,
                     "registered": registration.adapter_version})
        if selection.implementation_sha256 != registration.implementation_sha256():
            _refuse("generic-binding-drift", f"/selections/{selection_index}",
                    {"reason": "adapter-implementation-changed",
                     "adapter_id": selection.adapter_id})
        if selection.semantic_contract_sha256 != component.semantic_contract_sha256:
            _refuse("generic-binding-drift", f"/selections/{selection_index}",
                    {"reason": "selection-semantic-contract-mismatch"})

        capability = {
            "role": binding.role,
            "instance_id": binding.instance_id,
            "endpoint_id": binding.endpoint_id,
            "protocol": list(binding.protocol),
            "template": list(binding.template),
            "semantic_kind": binding.semantic_kind,
            "required_operations": list(binding.required_operations),
            "operations": list(requirement.operations),
            "supported_operations": endpoint["operations"],
            "data_width": endpoint["data_width"],
            "address_width": endpoint["address_width"],
            "address_units": endpoint["address_units"],
            "max_outstanding": endpoint["max_outstanding"],
            "completion_kind": endpoint["completion_kind"],
            "byte_enable": endpoint["byte_enable"],
            "evidence_obligations": list(binding.evidence_obligations),
            "supported_evidence": endpoint["evidence_capabilities"],
            "adapter": {
                "adapter_id": selection.adapter_id,
                "adapter_version": selection.adapter_version,
                "implementation_sha256": selection.implementation_sha256,
            },
            "descriptor_sha256": component.descriptor_sha256(),
            "flows": list(binding.flows),
            "path_ids": list(binding.path_ids),
        }
        capability_rows[(binding.role, binding.instance_id,
                         binding.endpoint_id)] = capability
        selection_rows.append({
            "instance_id": binding.instance_id,
            "endpoint_id": binding.endpoint_id,
            "role": binding.role,
            "adapter_id": selection.adapter_id,
            "adapter_version": selection.adapter_version,
            "implementation_sha256": selection.implementation_sha256,
            "component_artifact_sha256": selection.component_artifact_sha256,
            "semantic_contract_sha256": selection.semantic_contract_sha256,
            "selection_sha256": selection.sha256(),
        })

    if len(used_selections) != len(selections):
        unbound = sorted(
            f"{selections[index].adapter_id}:{selections[index].component_artifact_sha256}"
            for index in range(len(selections)) if index not in used_selections)
        _refuse("generic-plan-mismatch", "/selections",
                {"reason": "selection-not-bound-to-a-plan-binding",
                 "unbound": [item[:96] for item in unbound]})
    bound_instances = {binding.instance_id for binding in bindings}
    unbound_components = sorted(set(component_by_instance) - bound_instances)
    if unbound_components:
        _refuse("generic-plan-mismatch", "/components",
                {"reason": "verified-component-not-bound-by-an-executable-path",
                 "unbound": unbound_components})
    return capability_rows, sorted(
        selection_rows,
        key=lambda row: (row["instance_id"], row["endpoint_id"]))


def _register_access_for_fact(fact: _PathFacts) -> dict:
    for source in fact.constraints.get("source_constraints") or ():
        if type(source) is dict and type(source.get("register_access")) is dict:
            return source["register_access"]
    _refuse("generic-plan-mismatch", "/paths",
            {"reason": "register-access-missing", "path_id": fact.path_id})


# ---------------------------------------------------------------------------
# plan document
# ---------------------------------------------------------------------------

def _component_rows(components: tuple[VerifiedComponent, ...]) -> list[dict]:
    rows = []
    for component in sorted(components, key=lambda row: row.instance_id):
        rows.append({
            "instance_id": component.instance_id,
            "source_sha256": component.source_sha256,
            "profile_sha256": component.profile_sha256,
            "artifact_sha256": component.artifact_sha256,
            "semantic_contract_sha256": component.semantic_contract_sha256,
            "descriptor_sha256": component.descriptor_sha256(),
            "descriptor": component.document(),
        })
    return rows


def _path_row(fact: _PathFacts, capability_rows: dict) -> dict:
    bindings = [capability_rows[(binding.role, binding.instance_id,
                                 binding.endpoint_id)]
                for binding in fact.bindings]
    seed_rows = [{
        "source_id": source["source_id"],
        "kind": source["kind"],
        "origin": source["origin"],
        "width": source["width"],
        "range": None if source['range'] is None else list(source["range"]),
        "mask": source["mask"],
        "alignment": source["alignment"],
        "bit_offset": source["bit_offset"],
        "seed": fact.seed,
    } for source in fact.sources]
    return {
        "path_id": fact.path_id,
        "flow_id": fact.flow_id,
        "flow_name": fact.flow_name,
        "direction": fact.direction,
        "status": "executable",
        "runtime_path_id": fact.runtime_path_id,
        "kernel": fact.kernel,
        "bindings": bindings,
        "edges": [dict(edge) for edge in fact.edges],
        "target": dict(fact.target),
        "runtime_source_ids": list(fact.runtime_source_ids),
        "provider_source_ids": list(fact.runtime_source_ids),
        "consumer_node_id": fact.target["node"],
        "consumer_component": fact.target["component"],
        "source_ids": [source["source_id"] for source in fact.sources],
        "sources": [dict(source) for source in fact.sources],
        "bound_inputs": [dict(item) for item in fact.bound_inputs],
        "seeds": seed_rows,
        "assertions": [dict(assertion) for assertion in fact.assertions],
        "constraints": dict(fact.constraints),
        "termination": dict(fact.termination),
        "execution_contract": fact.execution_contract,
    }


def _memory_document(resources: tuple[dict, ...],
                     facts: tuple[_PathFacts, ...],
                     components: tuple[VerifiedComponent, ...]) -> dict:
    component_instances = {component.instance_id for component in components}
    for resource in resources:
        if resource["component_instance"] not in component_instances:
            _refuse("generic-plan-mismatch", "/memory/resources",
                    {"reason": "memory-serving-component-not-verified",
                     "resource_id": resource["resource_id"],
                     "component_instance": resource["component_instance"]})
    references = []
    for fact in facts:
        for edge in fact.edges:
            provider = edge["provider"]
            if provider["kind"] != "persistent_memory":
                continue
            references.append({
                "path_id": fact.path_id,
                "flow_id": fact.flow_id,
                "rule_index": edge["rule_index"],
                "relation": edge["relation"],
                "resource_id": provider["resource_id"],
                "component": provider["component"],
            })
    if not resources and references:
        _refuse("generic-plan-mismatch", "/memory/resources",
                {"reason": "persistent-memory-declaration-required"})
    return {
        "schema_version": PLAN_MEMORY_SCHEMA,
        "scope": "declared_shared_persistent_memory_resources",
        "shared": True,
        "declaration_source": "same_preparation_wiring_resources",
        "resources": [dict(row) for row in resources],
        "d3_references": sorted(
            references, key=lambda row: (row["path_id"], row["rule_index"])),
    }


def _scheduling_document(preparation, flows: tuple[str, ...],
                         facts: tuple[_PathFacts, ...],
                         components: tuple[VerifiedComponent, ...]) -> dict:
    startup = set()
    for fact in facts:
        startup.update(fact.kernel["startup_requires"])
    clock_reset = []
    missing = []
    for component in sorted(components, key=lambda row: row.instance_id):
        artifact = preparation.artifact(component.instance_id)
        document = artifact.runtime_document
        clock = document.get("clock_schedule")
        reset = document.get("driver_reset")
        if type(clock) is dict and type(reset) is dict:
            clock_reset.append({
                "instance_id": component.instance_id,
                "clock_schedule": _detached(clock),
                "driver_reset": _detached(reset),
            })
        else:
            missing.append(component.instance_id)
    irq_endpoints = []
    for component in sorted(components, key=lambda row: row.instance_id):
        for endpoint in component.endpoints():
            if endpoint["role"] == "irq_source":
                irq_endpoints.append({
                    "instance_id": component.instance_id,
                    "endpoint_id": endpoint["endpoint_id"],
                    "protocol": list(endpoint["protocol"]),
                })
    return {
        "schema_version": PLAN_SCHEDULING_SCHEMA,
        "scope": "static_plan_no_live_execution",
        "flows": list(flows),
        "shared_startup": True,
        "one_runner_one_session_per_run": True,
        "shared_persistent_memory": True,
        "case_persistence": "state_persists_across_cases",
        "case_budget": "supplied_at_run_time_not_in_static_plan",
        "startup_requires": sorted(startup),
        "clock_reset": clock_reset,
        "clock_reset_missing": sorted(missing),
        "irq_endpoints": irq_endpoints,
    }


def _termination_document(facts: tuple[_PathFacts, ...]) -> dict:
    return {
        "schema_version": PLAN_TERMINATION_SCHEMA,
        "per_path": [{
            "path_id": fact.path_id,
            "flow_id": fact.flow_id,
            "kind": fact.termination["kind"],
            "basis": fact.termination["basis"],
        } for fact in sorted(facts, key=lambda row: (row.flow_id, row.path_id))],
        "pending_effect_policy": "uncertain_effect_preserved",
        "process_drain": "required_before_close",
        "case_budget": "supplied_at_run_time_not_in_static_plan",
    }


def assert_plan_content(document: dict) -> dict:
    """Refuse a structurally valid but empty or unbindable plan document.

    This is the static "bind-time style" guard: a plan with no executable path,
    no verified component, no seed/mutation layout, no required assertion or no
    evidence obligation cannot be executed and must never be issued.
    """
    rows = parse_closed_json(document, PLAN_TOP_LEVEL, pointer="/plan")
    if rows["schema_version"] != PLAN_SCHEMA:
        _refuse("generic-contract-shape", "/plan/schema_version",
                {"expected": PLAN_SCHEMA})
    if not rows["paths"]:
        _refuse("generic-plan-mismatch", "/paths",
                {"reason": "no-executable-path"})
    if not rows["components"]:
        _refuse("generic-plan-mismatch", "/components",
                {"reason": "no-verified-component"})
    if not rows["selections"]:
        _refuse("generic-plan-mismatch", "/selections",
                {"reason": "no-adapter-selection"})
    if not rows["seeds"]:
        _refuse("generic-plan-mismatch", "/seeds",
                {"reason": "no-seed-layout"})
    if not rows["assertions"]:
        _refuse("generic-plan-mismatch", "/assertions",
                {"reason": "no-required-assertion"})
    if not rows["evidence_obligations"]:
        _refuse("generic-plan-mismatch", "/evidence_obligations",
                {"reason": "no-evidence-obligation"})
    for index, path in enumerate(rows["paths"]):
        if type(path) is not dict:
            _refuse("generic-plan-mismatch", f"/paths/{index}",
                    {"expected": "JSON object"})
        bindings = path.get("bindings")
        if type(bindings) is not list or not bindings:
            _refuse("generic-plan-mismatch", f"/paths/{index}/bindings",
                    {"reason": "endpoint-bindings-required"})
        roles = sorted({row.get("role") for row in bindings
                        if type(row) is dict})
        required_roles = {'cpu'} if path.get('flow_id') in ('F1', 'F3','F5') else {'cpu', 'target'}
        if not required_roles <= set(roles):
            _refuse("generic-plan-mismatch", f"/paths/{index}/bindings",
                    {"reason": "required-endpoint-bindings-missing",
                     "roles": roles})
        kernel = path.get("kernel")
        if type(kernel) is not dict or not kernel.get("id"):
            _refuse("generic-plan-mismatch", f"/paths/{index}/kernel",
                    {"reason": "flow-kernel-identity-required"})
        edges = path.get("edges")
        if type(edges) is not list or not edges:
            _refuse("generic-plan-mismatch", f"/paths/{index}/edges",
                    {"reason": "provider-edge-bindings-required"})
        for edge_index, edge in enumerate(edges):
            if type(edge) is not dict or type(edge.get("provider")) is not dict:
                _refuse("generic-route-refused",
                        f"/paths/{index}/edges/{edge_index}",
                        {"reason": "edge-provider-binding-required"})
    return rows


def _plan_document(preparation, *, components, selections, requirements) -> dict:
    inputs = _preparation_inputs(preparation)
    wiring = _wiring_document(inputs)
    resources = _memory_resources(wiring)
    resources_by_id = {row["resource_id"]: row for row in resources}
    paths, flows = _requested_paths(preparation, inputs["compiled"])

    components = _validate_components(preparation, components)
    selections = _validate_selections(preparation, selections)
    requirements = _validate_requirements(requirements)

    facts = _derive_facts(preparation, inputs["compiled"], paths,
                          resources_by_id)
    bindings = _merge_bindings(facts)
    if not bindings:
        _refuse("generic-plan-mismatch", "/paths",
                {"reason": "no-endpoint-binding"})
    capability_rows, selection_rows = _resolve_capabilities(
        facts, bindings, components, selections, requirements)

    path_rows = [_path_row(fact, capability_rows) for fact in facts]
    source_rows = []
    seed_rows = []
    assertion_rows = []
    constraint_rows = []
    for fact in facts:
        for source in fact.sources:
            source_rows.append({
                "path_id": fact.path_id,
                "flow_id": fact.flow_id,
                "source_id": source["source_id"],
                "component": source["component"],
                "endpoint_id": source["endpoint_id"],
                "kind": source["kind"],
                "origin": source["origin"],
                "origin_ref": source["origin_ref"],
                "port": source["port"],
                "register": source["register"],
                "field": source["field"],
                "range": None if source['range'] is None else list(source["range"]),
                "mask": source["mask"],
                "alignment": source["alignment"],
                "bit_offset": source["bit_offset"],
                "width": source["width"],
                "basis": source["basis"],
            })
            seed_rows.append({
                "path_id": fact.path_id,
                "flow_id": fact.flow_id,
                "source_id": source["source_id"],
                "kind": source["kind"],
                "origin": source["origin"],
                "width": source["width"],
                "range": None if source['range'] is None else list(source["range"]),
                "mask": source["mask"],
                "alignment": source["alignment"],
                "bit_offset": source["bit_offset"],
                "seed": fact.seed,
            })
        for item in fact.bound_inputs:
            source_rows.append({
                "path_id": fact.path_id,
                "flow_id": fact.flow_id,
                "source_id": item["input_id"],
                "component": item["component"],
                "endpoint_id": item["endpoint_id"],
                "kind": item["kind"],
                "origin": item["origin"],
                "origin_ref": "compiled_paths.v1:bound_inputs",
                "port": None,
                "register": None,
                "field": None,
                "range": None,
                "mask": None,
                "alignment": None,
                "bit_offset": None,
                "width": None,
                "basis": item["basis"],
            })
        for assertion in fact.assertions:
            assertion_rows.append({
                "path_id": fact.path_id,
                "flow_id": fact.flow_id,
                "expectation_id": assertion["expectation_id"],
                "assertion_class": assertion["assertion_class"],
                "asserts": assertion["asserts"],
                "declared_by": assertion["declared_by"],
                "source": "compiled_paths.v1",
            })
        constraint_rows.append({
            "path_id": fact.path_id,
            "flow_id": fact.flow_id,
            "policy_hash": fact.constraints.get("policy_hash"),
            "layout_hash": fact.constraints.get("layout_hash"),
            "rule_ids": list(fact.constraints["rule_ids"]),
            "rules": _detached(fact.constraints["rules"]),
            "source_constraints": _detached(
                fact.constraints.get("source_constraints") or []),
        })

    obligations = sorted({obligation
                          for binding in bindings
                          for obligation in binding.evidence_obligations})
    digests = preparation.input_digests
    document = {
        "schema_version": PLAN_SCHEMA,
        "components": _component_rows(components),
        "selections": selection_rows,
        "paths": path_rows,
        "sources": sorted(source_rows,
                          key=lambda row: (row["path_id"], row["source_id"])),
        "constraints": sorted(constraint_rows,
                              key=lambda row: row["path_id"]),
        "seeds": sorted(seed_rows,
                        key=lambda row: (row["path_id"], row["source_id"])),
        "assertions": sorted(assertion_rows,
                             key=lambda row: (row["path_id"],
                                              row["expectation_id"],
                                              row["assertion_class"])),
        "memory": _memory_document(resources, facts, components),
        "scheduling": _scheduling_document(preparation, flows, facts,
                                           components),
        "termination": _termination_document(facts),
        "evidence_obligations": obligations,
        "input_digests": {
            "d2": require_digest(digests.get("d2"), "/input_digests/d2"),
            "d3": require_digest(digests.get("d3"), "/input_digests/d3"),
        },
    }
    assert_plan_content(document)
    return document


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def compile_execution_plan(preparation: PreparationContext, *,
                           components: tuple[VerifiedComponent, ...],
                           selections: tuple[AdapterSelection, ...],
                           requirements: tuple[CapabilityRequirement, ...],
                           ) -> GenericExecutionPlan:
    """Compile and freeze the static plan, then register it in its context.

    Every component/selection must be the exact object issued by
    ``preparation``; the plan is issued back into the same context, so an equal
    document from another preparation is not a member here.
    """
    document = _plan_document(preparation, components=components,
                              selections=selections,
                              requirements=requirements)
    plan = GenericExecutionPlan.freeze(document)
    preparation.issue_plan(plan)
    return plan


def verify_execution_plan(preparation: PreparationContext,
                          plan: GenericExecutionPlan, *,
                          components: tuple[VerifiedComponent, ...],
                          selections: tuple[AdapterSelection, ...],
                          requirements: tuple[CapabilityRequirement, ...],
                          ) -> GenericExecutionPlan:
    """Recompute this context's canonical plan and compare it to ``plan``.

    Used by directed/fresh replay: a saved plan is accepted only when a fresh
    preparation, fresh verified components and fresh adapter selections derive
    the identical sealed document.  No membership or live authority transfers.
    """
    if type(plan) is not GenericExecutionPlan:
        _refuse("generic-contract-type", "/plan",
                {"expected": "GenericExecutionPlan"})
    expected_document = _plan_document(
        preparation, components=components, selections=selections,
        requirements=requirements)
    expected_bytes = canonical_json_bytes(expected_document)
    if expected_bytes == plan.document_bytes:
        return plan
    expected = strict_json_loads(expected_bytes, pointer="/plan")
    actual = plan.document()
    pointer = _first_difference(expected, actual)
    _refuse("generic-plan-mismatch", pointer,
            {"reason": "plan-document-mismatch",
             "expected_sha256": sha256(expected_bytes).hexdigest(),
             "actual_sha256": plan.identity_sha256,
             "expected_counts": _document_counts(expected),
             "actual_counts": _document_counts(actual)})


def _document_counts(document: dict) -> dict:
    counts = {}
    for name in ("components", "selections", "paths", "sources", "constraints",
                 "seeds", "assertions", "evidence_obligations"):
        value = document.get(name)
        counts[name] = len(value) if isinstance(value, list) else None
    memory = document.get("memory")
    counts["memory_resources"] = (len(memory.get("resources") or [])
                                  if isinstance(memory, dict) else None)
    return counts


def _first_difference(expected, actual, pointer: str = "") -> str:
    if type(expected) is not type(actual):
        return pointer or "/"
    if isinstance(expected, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in expected or key not in actual:
                return (pointer or "") + "/" + key
            if expected[key] != actual[key]:
                return _first_difference(expected[key], actual[key],
                                         (pointer or "") + "/" + key)
        return pointer or "/"
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return pointer or "/"
        for index, (left, right) in enumerate(zip(expected, actual)):
            if left != right:
                return _first_difference(left, right,
                                         (pointer or "") + f"/{index}")
        return pointer or "/"
    return pointer or "/"


def load_execution_plan_document(raw) -> GenericExecutionPlan:
    """Parse saved canonical plan bytes; formatting tamper is refused."""
    if type(raw) not in (bytes, bytearray):
        _refuse("generic-contract-type", "/plan",
                {"expected": "canonical UTF-8 JSON bytes"})
    if type(raw) is bytearray:
        raw = bytes(raw)
    document = strict_json_loads(raw, pointer="/plan")
    canonical = canonical_json_bytes(document)
    if canonical != raw:
        _refuse("generic-plan-mismatch", "/plan",
                {"reason": "noncanonical-plan-bytes",
                 "expected_sha256": sha256(canonical).hexdigest(),
                 "actual_sha256": sha256(raw).hexdigest()})
    return GenericExecutionPlan(PLAN_SCHEMA, canonical,
                                sha256(canonical).hexdigest())
