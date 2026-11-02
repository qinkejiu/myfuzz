"""OBI CPU adapter boundary: certified ABI facts, never a CPU driver (G3).

The generic runtime selects a CPU by certified protocol/ABI capabilities, not by
a CPU or instance name.  This module derives those capabilities from the real
generated artifact (``selected_template.executor.binding`` role/width rows,
``boot_contract`` and the plan's instruction endpoints) and exposes the
``CpuDriver`` surface of the design (section 4.5): program slots, the local step
map and a stability check.

It deliberately **does not drive the CPU**: no ``step_local``, no instruction
injection, no IRQ and no retirement claim is made here.  Driving the real CPU
stays with ``GeneratedCve2Session`` and the existing Runner/ScenarioSession,
which G5 binds.

Trust
-----
``bind_cpu_adapter`` accepts only the exact ``GeneratedCve2Session`` class (type
identity plus pinned module SHA-256) whose artifact is the admitted component's
artifact.  Module/ABI/artifact drift refuses ``generic-binding-drift``.  No
software double is offered for this boundary: the CPU facts are pure functions
of the artifact document, so tests exercise them on real generated artifacts and
on explicit documentary fixtures without starting RTL.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
import sys

from myfuzz.local_harness.cpu_session import GeneratedCve2Session

from ..admission import CPU_SEMANTIC_KIND, cpu_execution_surface_document
from ..contracts import (
    AdapterSelection,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
    require_digest,
    require_identifier,
)

CPU_ADAPTER_ID = "obi.cpu.v1"
CPU_ADAPTER_VERSION = "1"

_DATA_FUNCTIONS = frozenset({"data_memory_master", "processor_memory_master"})
_INSTRUCTION_FUNCTIONS = frozenset({"instruction_memory_master"})
_REQUIRED_DATA_ROLES = ("req", "gnt", "addr", "we", "wdata", "be", "rvalid",
                        "rdata")
_CONTROL_ROLES = ("req", "gnt", "we", "rvalid", "error")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _canonical(value) -> bytes:
    return canonical_json_bytes(value)


def _digest(value) -> str:
    return sha256(_canonical(value)).hexdigest()


def _qualified(value) -> str:
    return value.__module__ + "." + value.__qualname__


_ROOT = Path(__file__).resolve().parents[4]

_PINNED_MODULES = MappingProxyType({
    "myfuzz.local_harness.cpu_session": "src/myfuzz/local_harness/cpu_session.py",
    "myfuzz.local_harness.session": "src/myfuzz/local_harness/session.py",
    "myfuzz.runtime.admission": "src/myfuzz/runtime/admission.py",
    "myfuzz.runtime.adapters.obi_cpu": "src/myfuzz/runtime/adapters/obi_cpu.py",
})


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError("obi-cpu-adapter-drift:unreadable:" + relative) from error


_CPU_CLASS = GeneratedCve2Session
_CPU_METHODS = MappingProxyType({
    name: (getattr(_CPU_CLASS, name), getattr(_CPU_CLASS, name).__code__)
    for name in ("step_local", "_serve", "begin_case", "reset_local",
                 "identity_document")
})
_CPU_STEP_FACTS = MappingProxyType({
    "max_local_ticks_per_step": getattr(_CPU_CLASS, "max_local_ticks_per_step"),
    "max_transaction_events_per_step":
        getattr(_CPU_CLASS, "max_transaction_events_per_step"),
})
_DEPENDENCIES = {
    "GeneratedCve2Session": GeneratedCve2Session,
    "cpu_execution_surface_document": cpu_execution_surface_document,
}
_PINNED = MappingProxyType({name: (value, getattr(value, "__code__", None))
                            for name, value in _DEPENDENCIES.items()})
_ORIGINS = MappingProxyType({name: value.__module__
                             for name, value in _DEPENDENCIES.items()})
_MODULE_PINS = MappingProxyType({name: _file_sha(relative)
                                 for name, relative in _PINNED_MODULES.items()})


def implementation_sha256() -> str:
    """Adapter implementation identity: own module plus every trusted dependency."""
    return _digest({
        "schema_version": "obi_cpu_adapter_implementation.v1",
        "adapter_id": CPU_ADAPTER_ID,
        "adapter_version": CPU_ADAPTER_VERSION,
        "session_class": _qualified(_CPU_CLASS),
        "files": {name: _file_sha(relative)
                  for name, relative in sorted(_PINNED_MODULES.items())},
    })


_IMPLEMENTATION_PIN = implementation_sha256()


def _check_pins() -> None:
    for name, (value, code) in _PINNED.items():
        current = globals().get(name)
        if current is not value or (code is not None
                                    and getattr(value, "__code__", None) is not code):
            raise ValueError("obi-cpu-adapter-drift:" + name)
        origin = sys.modules.get(_ORIGINS[name])
        if origin is not None and getattr(origin, name, None) is not value:
            raise ValueError("obi-cpu-adapter-drift:" + name)
    for name, (method, code) in _CPU_METHODS.items():
        if (getattr(_CPU_CLASS, name, None) is not method
                or getattr(method, "__code__", None) is not code):
            raise ValueError("obi-cpu-adapter-drift:session." + name)
    for name, value in _CPU_STEP_FACTS.items():
        if getattr(_CPU_CLASS, name, None) != value or type(value) is not int:
            raise ValueError("obi-cpu-adapter-drift:step." + name)
    for module_name, relative in _PINNED_MODULES.items():
        if sys.modules.get(module_name) is None:
            raise ValueError("obi-cpu-adapter-drift:module:" + module_name)
        if _file_sha(relative) != _MODULE_PINS[module_name]:
            raise ValueError("obi-cpu-adapter-drift:module:" + module_name)
    if implementation_sha256() != _IMPLEMENTATION_PIN:
        raise ValueError("obi-cpu-adapter-drift:implementation")


def _registry_implementation_pin(adapter_id: str) -> str:
    from ..registry import registrations
    rows = [row for row in registrations() if row.adapter_id == adapter_id]
    if len(rows) != 1:
        _refuse("generic-adapter-missing", "/selection",
                {"adapter_id": adapter_id, "matches": len(rows)})
    return rows[0].implementation_sha256()


def _registry_registration(adapter_id: str):
    from ..registry import registrations
    rows = [row for row in registrations() if row.adapter_id == adapter_id]
    if len(rows) != 1:
        _refuse("generic-adapter-missing", "/selection",
                {"adapter_id": adapter_id, "matches": len(rows)})
    return rows[0]


# ---------------------------------------------------------------------------
# Certified ABI facts derived from the artifact document
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class CpuAbiFacts:
    """OBI data-ABI facts of one artifact; no execution authority."""

    instance_id: str
    endpoint_id: str
    function: str
    protocol: tuple[str, str]
    template: tuple[str, str, str]
    roles: tuple[tuple[str, int], ...]
    instruction_endpoints: tuple[str, ...]
    boot_base: int
    first_fetch_verification: str
    data_width: int
    address_width: int
    byte_enable_width: int
    write_capable: bool
    error_observed: bool
    # Filled in by the binding from the live artifact; the pure derivation
    # above cannot know the artifact/surface digest it will be bound to.
    surface_sha256: str = ""
    artifact_sha256: str = ""

    def document(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "endpoint_id": self.endpoint_id,
            "function": self.function,
            "protocol": list(self.protocol),
            "template": list(self.template),
            "roles": [[name, width] for name, width in self.roles],
            "instruction_endpoints": list(self.instruction_endpoints),
            "boot_base": self.boot_base,
            "first_fetch_verification": self.first_fetch_verification,
            "data_width": self.data_width,
            "address_width": self.address_width,
            "byte_enable_width": self.byte_enable_width,
            "write_capable": self.write_capable,
            "error_observed": self.error_observed,
            "surface_sha256": self.surface_sha256,
            "artifact_sha256": self.artifact_sha256,
        }

    def sha256(self) -> str:
        return _digest({"schema_version": "cpu_obi_abi_facts.v1",
                        **self.document()})


def _executor_binding(runtime_document: dict) -> dict:
    selected = runtime_document.get("selected_template")
    executor = selected.get("executor") if isinstance(selected, dict) else None
    binding = executor.get("binding") if isinstance(executor, dict) else None
    if not isinstance(binding, dict) or not isinstance(
            binding.get("endpoints"), list):
        _refuse("generic-template-mismatch", "/artifact/selected_template",
                {"reason": "generated-executor-binding-required"})
    return binding


def derive_cpu_abi_facts(*, runtime_document, instance_id: str,
                         endpoint_id: str, template, instruction_endpoints):
    """Derive the OBI data ABI of one artifact document.

    ``instance_id`` never participates in the width/role derivation: it is only
    copied into the facts document for identification.  The same artifact
    document with another instance name therefore yields the same ABI facts.
    """
    if type(runtime_document) is not dict:
        _refuse("generic-contract-type", "/artifact/runtime_document")
    require_identifier(instance_id, "/instance_id")
    require_identifier(endpoint_id, "/endpoint_id")
    if (type(template) is not tuple or len(template) != 3
            or any(type(item) is not str or not item for item in template)):
        _refuse("generic-contract-type", "/template")
    if (type(instruction_endpoints) is not tuple or not instruction_endpoints
            or any(type(item) is not str or not item
                   for item in instruction_endpoints)):
        _refuse("generic-semantic-unsupported", "/artifact/instruction_endpoints",
                {"reason": "declared-instruction-endpoint-required"})
    for name in instruction_endpoints:
        require_identifier(name, "/artifact/instruction_endpoints")
    kind = runtime_document.get("kind")
    if kind != "obi_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "obi_cpu", "actual": kind})
    binding = _executor_binding(runtime_document)
    rows = [row for row in binding["endpoints"]
            if isinstance(row, dict) and row.get("endpoint_id") == endpoint_id]
    if len(rows) != 1:
        _refuse("generic-template-mismatch", "/artifact/endpoints",
                {"reason": "one-declared-data-endpoint-required",
                 "endpoint_id": endpoint_id, "matches": len(rows)})
    row = rows[0]
    protocol = row.get("protocol")
    if (type(protocol) is not list
            or tuple(str(item) for item in protocol) != ("obi", "1")):
        _refuse("generic-template-mismatch", "/artifact/endpoints/protocol",
                {"endpoint_id": endpoint_id,
                 "actual": row.get("protocol")})
    function = row.get("function")
    if function not in _DATA_FUNCTIONS:
        _refuse("generic-template-mismatch", "/artifact/endpoints/function",
                {"endpoint_id": endpoint_id, "actual": function,
                 "expected": sorted(_DATA_FUNCTIONS)})
    role_rows = row.get("roles")
    if type(role_rows) is not list or not role_rows:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles",
                {"reason": "declared-role-rows-required"})
    roles: dict[str, int] = {}
    for role_row in role_rows:
        if not isinstance(role_row, dict):
            _refuse("generic-template-mismatch", "/artifact/endpoints/roles")
        role = role_row.get("role")
        width = role_row.get("width")
        if type(role) is not str or not role or role in roles:
            _refuse("generic-template-mismatch", "/artifact/endpoints/roles",
                    {"reason": "unique-role-required"})
        if type(width) is not int or not 1 <= width <= 4096:
            _refuse("generic-template-mismatch",
                    "/artifact/endpoints/roles/" + role,
                    {"reason": "declared-width-required"})
        roles[role] = width
    missing = [role for role in _REQUIRED_DATA_ROLES if role not in roles]
    if missing:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles",
                {"reason": "incomplete-obi-data-abi", "missing": sorted(missing)})
    if "error" in roles and "error" not in _CONTROL_ROLES:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles")
    for role in _CONTROL_ROLES:
        if role in roles and roles[role] != 1:
            _refuse("generic-template-mismatch",
                    "/artifact/endpoints/roles/" + role,
                    {"expected": 1, "actual": roles[role]})
    data_width = roles["wdata"]
    if roles["rdata"] != data_width:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles/rdata",
                {"expected": data_width, "actual": roles["rdata"]})
    if roles["be"] != data_width // 8:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles/be",
                {"expected": data_width // 8, "actual": roles["be"]})
    address_width = roles["addr"]
    boot = runtime_document.get("boot_contract")
    if not isinstance(boot, dict):
        _refuse("generic-semantic-unsupported", "/artifact/boot_contract",
                {"reason": "boot-contract-required"})
    boot_base = boot.get("configured_boot_base")
    if type(boot_base) is not int or not 0 <= boot_base < (1 << 32):
        _refuse("generic-semantic-unsupported",
                "/artifact/boot_contract/configured_boot_base",
                {"reason": "declared-boot-base-required"})
    verification = boot.get("first_fetch_verification")
    if type(verification) is not str or not verification:
        _refuse("generic-semantic-unsupported",
                "/artifact/boot_contract/first_fetch_verification")
    # ``we``/``wdata`` are required data roles above, so a certified endpoint
    # here always has the read-write ABI; a read-only variant has to be
    # certified by its own task instead of being widened into this one.
    write_capable = "we" in roles and "wdata" in roles
    return CpuAbiFacts(
        instance_id=instance_id,
        endpoint_id=endpoint_id,
        function=function,
        protocol=("obi", "1"),
        template=template,
        roles=tuple(sorted(roles.items())),
        instruction_endpoints=tuple(sorted(instruction_endpoints)),
        boot_base=boot_base,
        first_fetch_verification=verification,
        data_width=data_width,
        address_width=address_width,
        byte_enable_width=roles["be"],
        write_capable=True,
        error_observed="error" in roles,
    )


# ---------------------------------------------------------------------------
# CpuDriver surface: facts only, never a CPU step
# ---------------------------------------------------------------------------

class ObiCpuDriver:
    """``CpuDriver`` over the real session's certified ABI facts.

    ``program_slots`` and ``local_step_map`` are read-only descriptions; this
    class never calls ``step_local`` and never injects instructions.
    """

    __slots__ = ("_session", "_artifact", "_facts", "_program_slots", "_closed")

    def __init__(self, *, session, artifact, facts: CpuAbiFacts):
        self._session = session
        self._artifact = artifact
        self._facts = facts
        self._program_slots = MappingProxyType({
            "instruction.boot": {
                "slot_id": "instruction.boot",
                "kind": "instruction_image",
                "boot_base": facts.boot_base,
                "first_fetch_verification": facts.first_fetch_verification,
                "endpoints": list(facts.instruction_endpoints),
                "address_width": facts.address_width,
                "instr_width": facts.data_width,
                "source": "artifact_boot_contract",
            },
            "instruction." + facts.endpoint_id: {
                "slot_id": "instruction." + facts.endpoint_id,
                "kind": "instruction_endpoint",
                "endpoint_id": facts.endpoint_id,
                "address_width": facts.address_width,
                "data_width": facts.data_width,
                "roles": [[role, width] for role, width in facts.roles],
                "source": "artifact_executor_binding",
            },
        })
        self._closed = False

    def program_slots(self) -> dict:
        if self._closed:
            _refuse("generic-provider-closed", "/driver",
                    {"reason": "driver-closed"})
        return {name: dict(value)
                for name, value in self._program_slots.items()}

    def local_step_map(self) -> dict:
        if self._closed:
            _refuse("generic-provider-closed", "/driver",
                    {"reason": "driver-closed"})
        session = self._session
        defer_mmio = getattr(session, "defer_mmio", None)
        mmio_accesses = getattr(session, "max_mmio_target_accesses_per_step", None)
        if type(defer_mmio) is not bool or type(mmio_accesses) is not int:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "cpu-step-facts-unreadable"})
        return {
            "schema_version": "cpu_local_step_map.v1",
            "max_local_ticks_per_step":
                _CPU_STEP_FACTS["max_local_ticks_per_step"],
            "max_transaction_events_per_step":
                _CPU_STEP_FACTS["max_transaction_events_per_step"],
            "defer_mmio": defer_mmio,
            "max_mmio_target_accesses_per_step": mmio_accesses,
            "pending_responses": session.pending_responses,
            "instruction_endpoints": list(self._facts.instruction_endpoints),
            "source": "artifact_abi_and_session_class",
        }

    def assert_current(self) -> None:
        if self._closed:
            _refuse("generic-provider-closed", "/driver",
                    {"reason": "driver-closed"})
        try:
            _check_pins()
        except ValueError as error:
            _refuse("generic-binding-drift", "/driver",
                    {"reason": str(error)[:160]})
        if type(self._session) is not _CPU_CLASS:
            _refuse("generic-binding-drift", "/driver",
                    {"reason": "session-class-changed",
                     "actual": _qualified(type(self._session))})
        if getattr(self._session, "artifact", None) is not self._artifact:
            _refuse("generic-binding-drift", "/driver",
                    {"reason": "session-artifact-replaced"})
        try:
            surface = cpu_execution_surface_document(self._artifact)
        except ValueError as error:
            _refuse("generic-binding-drift", "/driver",
                    {"reason": str(error)[:160]})
        if _digest(surface) != self._facts.surface_sha256:
            _refuse("generic-binding-drift", "/driver",
                    {"reason": "execution-surface-changed"})
        if (self._artifact.runtime_document.get("artifact_digest")
                != self._facts.artifact_sha256):
            _refuse("generic-binding-drift", "/driver",
                    {"reason": "artifact-digest-changed"})

    def close(self) -> None:
        self._closed = True


# ---------------------------------------------------------------------------
# Bound adapter and the production factory
# ---------------------------------------------------------------------------

def _binding_digest(*, component, session, selection, facts) -> str:
    try:
        session_identity = session.identity_document()
    except (AttributeError, ValueError, TypeError):
        session_identity = {"unavailable": _qualified(type(session))}
    return _digest({
        "schema_version": "obi_cpu_adapter_binding.v1",
        "adapter_id": CPU_ADAPTER_ID,
        "adapter_version": CPU_ADAPTER_VERSION,
        "implementation_sha256": _IMPLEMENTATION_PIN,
        "component_instance_id": component.instance_id,
        "component_artifact_sha256": component.artifact_sha256,
        "component_semantic_contract_sha256": component.semantic_contract_sha256,
        "endpoint_id": facts.endpoint_id,
        "abi_facts_sha256": facts.sha256(),
        "session_class": _qualified(type(session)),
        "session_object": id(session),
        "session_identity_sha256": _digest(session_identity),
        "session_abi": [[name, code.co_firstlineno, code.co_filename]
                        for name, (_, code) in sorted(_CPU_METHODS.items())],
        "selection_sha256": None if selection is None else selection.sha256(),
        "selection_implementation_sha256":
            None if selection is None else selection.implementation_sha256,
    })


class BoundCpuAdapter:
    """Process-local CPU adapter boundary: facts only, no CPU driving."""

    __slots__ = ("component_instance_id", "adapter_id", "adapter_version",
                 "endpoint_id", "driver", "binding_sha256", "abi_facts",
                 "template", "protocol", "_session", "_selection", "_closed")

    def __init__(self, *, component, session, selection, facts, driver,
                 binding_sha256):
        self.component_instance_id = component.instance_id
        self.adapter_id = CPU_ADAPTER_ID
        self.adapter_version = CPU_ADAPTER_VERSION
        self.endpoint_id = facts.endpoint_id
        self.driver = driver
        self.binding_sha256 = binding_sha256
        self.abi_facts = facts
        self.template = facts.template
        self.protocol = facts.protocol
        self._session = session
        self._selection = selection
        self._closed = False

    @property
    def program_slots(self) -> dict:
        return self.driver.program_slots()

    @property
    def local_step_map(self) -> dict:
        return self.driver.local_step_map()

    def assert_current(self) -> None:
        if self._closed:
            _refuse("generic-provider-closed", "/adapter",
                    {"reason": "adapter-closed"})
        self.driver.assert_current()
        if (self._session.artifact.runtime_document.get("artifact_digest")
                != self.abi_facts.artifact_sha256):
            _refuse("generic-binding-drift", "/adapter",
                    {"reason": "artifact-digest-changed"})
        if self.abi_facts.endpoint_id != self.endpoint_id:
            _refuse("generic-binding-drift", "/adapter",
                    {"reason": "abi-facts-replaced"})

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.driver.close()


def _check_selection(selection, *, component: VerifiedComponent,
                     implementation_pin: str) -> None:
    if type(selection) is not AdapterSelection:
        _refuse("generic-contract-type", "/selection")
    if (selection.adapter_id != CPU_ADAPTER_ID
            or selection.adapter_version != CPU_ADAPTER_VERSION):
        _refuse("generic-adapter-missing", "/selection",
                {"adapter_id": selection.adapter_id,
                 "adapter_version": selection.adapter_version,
                 "expected_id": CPU_ADAPTER_ID,
                 "expected_version": CPU_ADAPTER_VERSION})
    require_digest(selection.implementation_sha256,
                   "/selection/implementation_sha256")
    if selection.implementation_sha256 != implementation_pin:
        _refuse("generic-binding-drift", "/selection/implementation_sha256",
                {"reason": "registry-implementation-changed-since-import"})
    if (selection.component_artifact_sha256 != component.artifact_sha256
            or selection.semantic_contract_sha256
            != component.semantic_contract_sha256):
        _refuse("generic-plan-mismatch", "/selection",
                {"reason": "selection-does-not-belong-to-this-component"})


def _descriptor_cpu_endpoint(component: VerifiedComponent) -> dict:
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    endpoints = [row for row in component.endpoints() if row["role"] == "cpu"]
    if len(endpoints) != 1:
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "one-cpu-endpoint-required", "matches": len(endpoints)})
    endpoint = endpoints[0]
    if (tuple(endpoint["protocol"]) != ("obi", "1")
            or endpoint["semantic_kind"] != CPU_SEMANTIC_KIND):
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "obi-cpu-endpoint-required",
                 "protocol": endpoint["protocol"],
                 "semantic_kind": endpoint["semantic_kind"]})
    return endpoint


def bind_cpu_adapter(*, component, session, selection) -> BoundCpuAdapter:
    """Production factory: only the exact real OBI CPU session is accepted."""
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    if type(session) is not _CPU_CLASS:
        _refuse("generic-binding-drift", "/session",
                {"reason": "exact-GeneratedCve2Session-required",
                 "actual": _qualified(type(session))})
    if type(selection) is not AdapterSelection:
        _refuse("generic-contract-type", "/selection")
    try:
        _check_pins()
    except ValueError as error:
        _refuse("generic-binding-drift", "/adapter",
                {"reason": str(error)[:160]})
    registration = _registry_registration(CPU_ADAPTER_ID)
    _check_selection(selection, component=component,
                     implementation_pin=registration.implementation_sha256())
    endpoint = _descriptor_cpu_endpoint(component)
    if tuple(endpoint["template"]) not in registration.templates:
        _refuse("generic-template-mismatch", "/component/endpoints/template",
                {"template": endpoint["template"],
                 "supported": [list(row) for row in registration.templates]})
    if not set(endpoint["operations"]) <= set(registration.operations):
        _refuse("generic-semantic-unsupported", "/component/endpoints/operations",
                {"operations": endpoint["operations"]})
    artifact = getattr(session, "artifact", None)
    if artifact is None:
        _refuse("generic-source-unverified", "/session",
                {"reason": "session-carries-no-artifact"})
    if artifact.plan.request.instance_id != component.instance_id:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "instance-id-mismatch"})
    if artifact.runtime_document.get("artifact_digest") != component.artifact_sha256:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "artifact-digest-mismatch"})
    surface = cpu_execution_surface_document(artifact)
    if _digest(surface) != component.semantic_contract_sha256:
        _refuse("generic-source-unverified", "/semantic",
                {"reason": "semantic-contract-digest-mismatch"})
    instruction_endpoints = tuple(sorted(
        row.endpoint_id for row in artifact.plan.binding.endpoints
        if row.function in _INSTRUCTION_FUNCTIONS))
    facts = derive_cpu_abi_facts(
        runtime_document=artifact.runtime_document,
        instance_id=component.instance_id,
        endpoint_id=endpoint["endpoint_id"],
        template=tuple(endpoint["template"]),
        instruction_endpoints=instruction_endpoints)
    if (facts.data_width != endpoint["data_width"]
            or facts.address_width != endpoint["address_width"]
            or facts.endpoint_id != endpoint["endpoint_id"]):
        _refuse("generic-template-mismatch", "/component/endpoints",
                {"reason": "descriptor-widths-do-not-match-artifact-abi",
                 "data_width": facts.data_width,
                 "address_width": facts.address_width})
    facts = replace(facts, surface_sha256=_digest(surface),
                    artifact_sha256=component.artifact_sha256)
    binding = _binding_digest(component=component, session=session,
                              selection=selection, facts=facts)
    driver = ObiCpuDriver(session=session, artifact=artifact, facts=facts)
    bound = BoundCpuAdapter(component=component, session=session,
                            selection=selection, facts=facts, driver=driver,
                            binding_sha256=binding)
    bound.assert_current()
    return bound


def registration_document() -> dict:
    """Documentary description of this adapter implementation."""
    return {
        "schema_version": "generic_adapter_implementation.v1",
        "adapter_id": CPU_ADAPTER_ID,
        "adapter_version": CPU_ADAPTER_VERSION,
        "implementation_sha256": implementation_sha256(),
        "implementation_pin": _IMPLEMENTATION_PIN,
        "session_class": _qualified(_CPU_CLASS),
        "role": "cpu",
        "protocol": ["obi", "1"],
        "semantic_kinds": [CPU_SEMANTIC_KIND],
        "drives_cpu": False,
        "software_only": False,
    }
