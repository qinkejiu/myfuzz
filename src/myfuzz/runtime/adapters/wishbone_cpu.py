"""Wishbone classic CPU adapter boundary: certified ABI facts, never a CPU driver.

G8.1 selects the pinned PicoRV32 ``picorv32_wb`` master
(``cpu.wishbone/1/no-err-stall``).  The generic runtime selects a CPU by
certified protocol/ABI capabilities, not by a CPU or instance name, so this
module derives those capabilities from the real generated artifact
(``selected_template.executor.binding`` role/width/direction rows,
``declared_profile_facts``, ``boot_contract`` and the instruction-identity
observation) and exposes the ``CpuDriver`` surface of the design: program slots,
the local step map and a stability check.

Derived ABI, stated exactly
---------------------------
* request roles ``cyc stb we adr dat_w sel``; response roles ``ack dat_r``;
* ``adr`` is a **byte** address (``address_units = "byte"``); a target-side
  adapter performs the byte -> word index conversion;
* no ``err``, ``rty`` or ``stall`` role exists on this master, so none is
  claimed: :func:`derive_wishbone_cpu_abi_facts` refuses an artifact that
  declares one instead of silently ignoring it;
* no byte-enable overclaim: ``sel`` is a four-lane write strobe, and this pinned
  master drives ``sel = 0`` on reads while the data bus still returns a full
  word, so the facts record ``read_select = "zero_full_word_data"`` separately
  from the write strobe width.

It deliberately **does not drive the CPU**: no ``step_local``, no instruction
injection, no IRQ and no retirement claim is made here.  Driving the real CPU
stays with ``GeneratedWishboneCpuSession`` and the existing Runner.

Trust
-----
:func:`bind_wishbone_cpu_adapter` accepts only the exact
``GeneratedWishboneCpuSession`` class (type identity plus pinned module SHA-256)
whose artifact is the admitted component's artifact.  Module/ABI/artifact drift
refuses ``generic-binding-drift``.  No software double is offered for this
boundary: the facts are pure functions of the artifact document, so tests
exercise them on real generated artifacts without starting RTL.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
import sys

from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from . import contracts as _adapter_contracts  # Load the source-pinned public dependency explicitly.

from ..contracts import (
    AdapterSelection,
    GenericRuntimeRefused,
    VerifiedComponent,
    canonical_json_bytes,
    require_digest,
    require_identifier,
)

CPU_ADAPTER_ID = "wishbone.cpu.v1"
CPU_ADAPTER_VERSION = "1"

WISHBONE_CPU_PROTOCOL = ("wishbone", "classic")
WISHBONE_CPU_TEMPLATE = ("cpu.wishbone", "1", "no-err-stall")
WISHBONE_CPU_SEMANTIC_KIND = "cpu.wishbone.v1"
WISHBONE_CPU_ADDRESS_UNITS = "byte"
WISHBONE_CPU_COMPLETION_KIND = "cycle_strobe_held_until_ack"
WISHBONE_CPU_INSTRUCTION_FUNCTIONS = frozenset({"instruction_memory_master"})
WISHBONE_CPU_DATA_FUNCTIONS = frozenset({"memory_master", "data_memory_master",
                                         "processor_memory_master"})
WISHBONE_CPU_REQUEST_ROLES = ("cyc", "stb", "we", "adr", "dat_w", "sel")
WISHBONE_CPU_RESPONSE_ROLES = ("ack", "dat_r")
#: Roles this pinned master really has no pin for.  Declaring one is refused.
WISHBONE_CPU_ABSENT_ROLES = ("err", "rty", "stall")
_WIDE_REQUEST_ROLES = MappingProxyType({"cyc": 1, "stb": 1, "we": 1, "ack": 1})


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
    "myfuzz.local_harness.wishbone_cpu_session":
        "src/myfuzz/local_harness/wishbone_cpu_session.py",
    "myfuzz.local_harness.session": "src/myfuzz/local_harness/session.py",
    "myfuzz.runtime.adapters.contracts":
        "src/myfuzz/runtime/adapters/contracts.py",
    "myfuzz.runtime.adapters.wishbone_cpu":
        "src/myfuzz/runtime/adapters/wishbone_cpu.py",
})


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError("wishbone-cpu-adapter-drift:unreadable:" + relative) from error


_CPU_CLASS = GeneratedWishboneCpuSession
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
_MODULE_PINS = MappingProxyType({name: _file_sha(relative)
                                 for name, relative in _PINNED_MODULES.items()})


def implementation_sha256() -> str:
    """Adapter implementation identity: own module plus every trusted dependency."""
    return _digest({
        "schema_version": "wishbone_cpu_adapter_implementation.v1",
        "adapter_id": CPU_ADAPTER_ID,
        "adapter_version": CPU_ADAPTER_VERSION,
        "session_class": _qualified(_CPU_CLASS),
        "files": {name: _file_sha(relative)
                  for name, relative in sorted(_PINNED_MODULES.items())},
    })


_IMPLEMENTATION_PIN = implementation_sha256()


def _check_pins() -> None:
    for name, (method, code) in _CPU_METHODS.items():
        if (getattr(_CPU_CLASS, name, None) is not method
                or getattr(method, "__code__", None) is not code):
            raise ValueError("wishbone-cpu-adapter-drift:session." + name)
    for name, value in _CPU_STEP_FACTS.items():
        if getattr(_CPU_CLASS, name, None) != value or type(value) is not int:
            raise ValueError("wishbone-cpu-adapter-drift:step." + name)
    for module_name, relative in _PINNED_MODULES.items():
        if sys.modules.get(module_name) is None:
            raise ValueError("wishbone-cpu-adapter-drift:module:" + module_name)
        if _file_sha(relative) != _MODULE_PINS[module_name]:
            raise ValueError("wishbone-cpu-adapter-drift:module:" + module_name)
    if implementation_sha256() != _IMPLEMENTATION_PIN:
        raise ValueError("wishbone-cpu-adapter-drift:implementation")


def _registry_registration(adapter_id: str):
    from ..registry import registrations
    rows = [row for row in registrations() if row.adapter_id == adapter_id]
    if len(rows) > 1:
        _refuse("generic-adapter-ambiguous", "/selection",
                {"adapter_id": adapter_id, "matches": len(rows)})
    return rows[0] if rows else None


def registration_state() -> dict:
    """Code-owned registration state; ``registered`` is False until the lead wires it."""
    row = _registry_registration(CPU_ADAPTER_ID)
    return {
        "adapter_id": CPU_ADAPTER_ID,
        "adapter_version": CPU_ADAPTER_VERSION,
        "registered": row is not None,
        "registry_implementation_sha256": None if row is None
        else row.implementation_sha256(),
        "module_implementation_sha256": _IMPLEMENTATION_PIN,
    }


def selection_implementation_pin() -> tuple[str, bool]:
    """``(pin the selection must carry, registry_registered)``."""
    row = _registry_registration(CPU_ADAPTER_ID)
    if row is None:
        return (_IMPLEMENTATION_PIN, False)
    return (row.implementation_sha256(), True)


def _check_selection(selection: AdapterSelection, *,
                     component: VerifiedComponent) -> tuple[str, bool]:
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
    pin, registered = selection_implementation_pin()
    if selection.implementation_sha256 != pin:
        _refuse("generic-binding-drift", "/selection/implementation_sha256",
                {"reason": "registry-implementation-changed-since-import",
                 "registry_registered": registered})
    if (selection.component_artifact_sha256 != component.artifact_sha256
            or selection.semantic_contract_sha256
            != component.semantic_contract_sha256):
        _refuse("generic-plan-mismatch", "/selection",
                {"reason": "selection-does-not-belong-to-this-component"})
    return pin, registered


# ---------------------------------------------------------------------------
# Certified ABI facts derived from the artifact document
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class WishboneCpuAbiFacts:
    """Wishbone classic data-ABI facts of one artifact; no execution authority."""

    instance_id: str
    endpoint_id: str
    function: str
    protocol: tuple[str, str]
    template: tuple[str, str, str]
    roles: tuple[tuple[str, int], ...]
    request_roles: tuple[str, ...]
    response_roles: tuple[str, ...]
    instruction_endpoints: tuple[str, ...]
    instruction_identity_observation: str
    boot_base: int
    first_fetch_verification: str
    data_width: int
    address_width: int
    address_units: str
    byte_enable_width: int
    read_select: str
    write_capable: bool
    read_capable: bool
    max_outstanding: int
    error_observed: bool
    stall_observed: bool
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
            "request_roles": list(self.request_roles),
            "response_roles": list(self.response_roles),
            "instruction_endpoints": list(self.instruction_endpoints),
            "instruction_identity_observation":
                self.instruction_identity_observation,
            "boot_base": self.boot_base,
            "first_fetch_verification": self.first_fetch_verification,
            "data_width": self.data_width,
            "address_width": self.address_width,
            "address_units": self.address_units,
            "byte_enable_width": self.byte_enable_width,
            "read_select": self.read_select,
            "write_capable": self.write_capable,
            "read_capable": self.read_capable,
            "max_outstanding": self.max_outstanding,
            "error_observed": self.error_observed,
            "stall_observed": self.stall_observed,
            "surface_sha256": self.surface_sha256,
            "artifact_sha256": self.artifact_sha256,
        }

    def sha256(self) -> str:
        return _digest({"schema_version": "wishbone_cpu_abi_facts.v1",
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


def derive_wishbone_cpu_abi_facts(*, runtime_document, instance_id: str,
                                  endpoint_id: str, template,
                                  instruction_endpoints):
    """Derive the Wishbone classic data ABI of one artifact document.

    ``instance_id`` never participates in the width/role derivation: it is only
    copied into the facts document for identification.  Every width, direction
    and role comes from the generated ``selected_template.executor.binding``
    rows, never from caller input, and the artifact's own
    ``declared_profile_facts`` must agree with them.
    """
    if type(runtime_document) is not dict:
        _refuse("generic-contract-type", "/artifact/runtime_document")
    require_identifier(instance_id, "/instance_id")
    require_identifier(endpoint_id, "/endpoint_id")
    if (type(template) is not tuple or len(template) != 3
            or any(type(item) is not str or not item for item in template)):
        _refuse("generic-contract-type", "/template")
    if template != WISHBONE_CPU_TEMPLATE:
        _refuse("generic-template-mismatch", "/template",
                {"expected": list(WISHBONE_CPU_TEMPLATE),
                 "actual": list(template)})
    if (type(instruction_endpoints) is not tuple
            or any(type(item) is not str or not item
                   for item in instruction_endpoints)):
        _refuse("generic-contract-type", "/artifact/instruction_endpoints")
    for name in instruction_endpoints:
        require_identifier(name, "/artifact/instruction_endpoints")
    kind = runtime_document.get("kind")
    if kind != "wishbone_cpu":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "wishbone_cpu", "actual": kind})
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
            or tuple(str(item) for item in protocol) != WISHBONE_CPU_PROTOCOL):
        _refuse("generic-template-mismatch", "/artifact/endpoints/protocol",
                {"endpoint_id": endpoint_id, "actual": row.get("protocol")})
    function = row.get("function")
    if function not in WISHBONE_CPU_DATA_FUNCTIONS:
        _refuse("generic-template-mismatch", "/artifact/endpoints/function",
                {"endpoint_id": endpoint_id, "actual": function,
                 "expected": sorted(WISHBONE_CPU_DATA_FUNCTIONS)})
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
        if role in WISHBONE_CPU_ABSENT_ROLES:
            # This pinned master really has no error/retry/stall pin: an artifact
            # that declares one is a different ABI, not this adapter's.
            _refuse("generic-template-mismatch",
                    "/artifact/endpoints/roles/" + role,
                    {"reason": "role-not-present-on-wishbone-classic-cpu",
                     "absent": list(WISHBONE_CPU_ABSENT_ROLES)})
        roles[role] = width
    missing = [role for role in WISHBONE_CPU_REQUEST_ROLES
               if role not in roles]
    missing += [role for role in WISHBONE_CPU_RESPONSE_ROLES
                if role not in roles]
    if missing:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles",
                {"reason": "incomplete-wishbone-classic-cpu-abi",
                 "missing": sorted(missing)})
    unexpected = sorted(set(roles) - set(WISHBONE_CPU_REQUEST_ROLES)
                        - set(WISHBONE_CPU_RESPONSE_ROLES))
    if unexpected:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles",
                {"reason": "undeclared-role-not-in-this-abi",
                 "unexpected": unexpected})
    for role, width in _WIDE_REQUEST_ROLES.items():
        if roles[role] != width:
            _refuse("generic-template-mismatch",
                    "/artifact/endpoints/roles/" + role,
                    {"expected": width, "actual": roles[role]})
    data_width = roles["dat_w"]
    if roles["dat_r"] != data_width:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles/dat_r",
                {"expected": data_width, "actual": roles["dat_r"]})
    if roles["sel"] != data_width // 8:
        _refuse("generic-template-mismatch", "/artifact/endpoints/roles/sel",
                {"expected": data_width // 8, "actual": roles["sel"]})
    address_width = roles["adr"]
    facts = binding.get("declared_profile_facts")
    if not isinstance(facts, dict):
        _refuse("generic-semantic-unsupported", "/artifact/declared_profile_facts",
                {"reason": "declared-profile-facts-required"})
    if (facts.get("address_units") != WISHBONE_CPU_ADDRESS_UNITS
            or facts.get("data_width") != data_width
            or facts.get("address_width") != address_width
            or facts.get("byte_enable") is not True
            or facts.get("error_response") is not False
            or facts.get("max_outstanding") != 1):
        _refuse("generic-template-mismatch", "/artifact/declared_profile_facts",
                {"reason": "declared-facts-disagree-with-role-rows",
                 "address_units": facts.get("address_units"),
                 "data_width": facts.get("data_width"),
                 "address_width": facts.get("address_width"),
                 "error_response": facts.get("error_response")})
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
    marker = runtime_document.get("instruction_identity_observation")
    if type(marker) is not str or not marker:
        _refuse("generic-semantic-unsupported",
                "/artifact/instruction_identity_observation",
                {"reason": "measured-instruction-identity-observation-required"})
    identity_port = facts.get("instruction_identity_port")
    if type(identity_port) is not str or not identity_port:
        _refuse("generic-semantic-unsupported",
                "/artifact/declared_profile_facts/instruction_identity_port")
    exports = [row for row in runtime_document.get("physical_exports") or ()
               if isinstance(row, dict)
               and row.get("physical_port") == identity_port
               and row.get("direction") == "output"
               and row.get("width") == 1
               and row.get("runtime_name") == marker]
    if len(exports) != 1:
        _refuse("generic-template-mismatch",
                "/artifact/instruction_identity_observation",
                {"reason": "declared-instruction-identity-port-required",
                 "port": identity_port, "matches": len(exports)})
    return WishboneCpuAbiFacts(
        instance_id=instance_id,
        endpoint_id=endpoint_id,
        function=function,
        protocol=WISHBONE_CPU_PROTOCOL,
        template=template,
        roles=tuple(sorted(roles.items())),
        request_roles=tuple(sorted(WISHBONE_CPU_REQUEST_ROLES)),
        response_roles=tuple(sorted(WISHBONE_CPU_RESPONSE_ROLES)),
        instruction_endpoints=tuple(sorted(instruction_endpoints)),
        instruction_identity_observation=marker,
        boot_base=boot_base,
        first_fetch_verification=verification,
        data_width=data_width,
        address_width=address_width,
        address_units=WISHBONE_CPU_ADDRESS_UNITS,
        byte_enable_width=roles["sel"],
        # PicoRV32 drives sel = 0 for reads while the data bus still carries a
        # full word: recorded separately so no byte-enable is overclaimed.
        read_select="zero_full_word_data",
        write_capable=True,
        read_capable=True,
        max_outstanding=facts["max_outstanding"],
        error_observed=False,
        stall_observed=False,
    )


def _source_sha256(artifact) -> str:
    try:
        return sha256(canonical_json_bytes(
            artifact.source_verification)).hexdigest()
    except GenericRuntimeRefused:
        _refuse("generic-source-unverified", "/source_verification",
                {"reason": "source-closure-not-canonical"})


def _artifact_sha256(artifact) -> str:
    digest = artifact.runtime_document.get("artifact_digest")
    require_digest(digest, "/artifact_digest")
    return digest


def _profile_sha256(artifact) -> str:
    digest = getattr(artifact.plan, "profile_sha256", None)
    require_digest(digest, "/profile_sha256")
    return digest


def wishbone_cpu_surface_document(artifact) -> dict:
    """Documentary Wishbone CPU execution surface; no ABI authority.

    This is the derivation whose canonical digest the admitted component's
    ``semantic_contract_sha256`` must equal, so the admission verifier for a
    Wishbone CPU has to produce this exact document (import this function rather
    than re-deriving it).
    """
    document = artifact.runtime_document
    binding = _executor_binding(document)
    endpoints = []
    for row in binding.get("endpoints") or ():
        endpoints.append({
            "endpoint_id": row.get("endpoint_id"),
            "function": row.get("function"),
            "protocol": list(row.get("protocol") or ()),
            "roles": [
                {"role": role.get("role"), "width": role.get("width"),
                 "direction": role.get("direction"),
                 "physical_port": role.get("physical_port")}
                for role in sorted(row.get("roles") or (),
                                   key=lambda item: item.get("role") or "")
            ],
        })
    return {
        "schema_version": "wishbone_cpu_execution_surface.v1",
        "kind": WISHBONE_CPU_SEMANTIC_KIND,
        "source_sha256": _source_sha256(artifact),
        "profile_sha256": _profile_sha256(artifact),
        "artifact_sha256": _artifact_sha256(artifact),
        "executor_template": document.get("selected_template", {}).get(
            "contract"),
        "boot_contract": document.get("boot_contract"),
        "declared_profile_facts": binding.get("declared_profile_facts"),
        "instruction_identity_observation":
            document.get("instruction_identity_observation"),
        "instruction_endpoints": sorted(
            endpoint.endpoint_id for endpoint in artifact.plan.binding.endpoints
            if endpoint.function in WISHBONE_CPU_INSTRUCTION_FUNCTIONS),
        "endpoints": endpoints,
    }


# ---------------------------------------------------------------------------
# CpuDriver surface: facts only, never a CPU step
# ---------------------------------------------------------------------------

class WishboneCpuDriver:
    """``CpuDriver`` over the real session's certified ABI facts.

    ``program_slots`` and ``local_step_map`` are read-only descriptions; this
    class never calls ``step_local`` and never injects instructions.
    """

    __slots__ = ("_session", "_artifact", "_facts", "_program_slots", "_closed")

    def __init__(self, *, session, artifact, facts: WishboneCpuAbiFacts):
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
                "address_units": facts.address_units,
                "instruction_identity_observation":
                    facts.instruction_identity_observation,
                "source": "artifact_boot_contract",
            },
            "data." + facts.endpoint_id: {
                "slot_id": "data." + facts.endpoint_id,
                "kind": "shared_fetch_and_data_memory_endpoint",
                "endpoint_id": facts.endpoint_id,
                "function": facts.function,
                "address_width": facts.address_width,
                "data_width": facts.data_width,
                "address_units": facts.address_units,
                "byte_enable_width": facts.byte_enable_width,
                "read_select": facts.read_select,
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
            "schema_version": "wishbone_cpu_local_step_map.v1",
            "max_local_ticks_per_step":
                _CPU_STEP_FACTS["max_local_ticks_per_step"],
            "max_transaction_events_per_step":
                _CPU_STEP_FACTS["max_transaction_events_per_step"],
            "defer_mmio": defer_mmio,
            "max_mmio_target_accesses_per_step": mmio_accesses,
            "pending_responses": session.pending_responses,
            "instruction_endpoints": list(self._facts.instruction_endpoints),
            "address_units": self._facts.address_units,
            "no_error_or_stall_role": True,
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
            surface = wishbone_cpu_surface_document(self._artifact)
        except GenericRuntimeRefused:
            raise
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
        "schema_version": "wishbone_cpu_adapter_binding.v1",
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
    """Process-local Wishbone CPU adapter boundary: facts only, no CPU driving."""

    __slots__ = ("component_instance_id", "adapter_id", "adapter_version",
                 "endpoint_id", "driver", "binding_sha256", "abi_facts",
                 "template", "protocol", "semantic_kind", "address_units",
                 "implementation_sha256", "_session", "_selection", "_closed")

    def __init__(self, *, component, session, selection, facts, driver,
                 binding_sha256, implementation_pin):
        self.component_instance_id = component.instance_id
        self.adapter_id = CPU_ADAPTER_ID
        self.adapter_version = CPU_ADAPTER_VERSION
        self.endpoint_id = facts.endpoint_id
        self.driver = driver
        self.binding_sha256 = binding_sha256
        self.abi_facts = facts
        self.template = facts.template
        self.protocol = facts.protocol
        self.semantic_kind = WISHBONE_CPU_SEMANTIC_KIND
        self.address_units = facts.address_units
        self.implementation_sha256 = implementation_pin
        self._session = session
        self._selection = selection
        self._closed = False

    @property
    def program_slots(self) -> dict:
        return self.driver.program_slots()

    @property
    def local_step_map(self) -> dict:
        return self.driver.local_step_map()

    @property
    def drives_cpu(self) -> bool:
        return False

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


def _descriptor_cpu_endpoint(component: VerifiedComponent) -> dict:
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    endpoints = [row for row in component.endpoints() if row["role"] == "cpu"]
    if len(endpoints) != 1:
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "one-cpu-endpoint-required", "matches": len(endpoints)})
    endpoint = endpoints[0]
    if (tuple(endpoint["protocol"]) != WISHBONE_CPU_PROTOCOL
            or endpoint["semantic_kind"] != WISHBONE_CPU_SEMANTIC_KIND):
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "wishbone-classic-cpu-endpoint-required",
                 "protocol": endpoint["protocol"],
                 "semantic_kind": endpoint["semantic_kind"]})
    if (tuple(endpoint["template"]) != WISHBONE_CPU_TEMPLATE
            or endpoint["address_units"] != WISHBONE_CPU_ADDRESS_UNITS):
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "wishbone-no-err-stall-byte-addressed-template-required",
                 "template": endpoint["template"],
                 "address_units": endpoint["address_units"]})
    return endpoint


def bind_wishbone_cpu_adapter(*, component, session, selection,
                              preparation=None, endpoint_id=None
                              ) -> BoundCpuAdapter:
    """Production factory: only the exact real Wishbone CPU session is accepted.

    ``preparation``/``endpoint_id`` are accepted because the shared binding layer
    always passes them; this boundary needs neither (the ABI comes from the
    artifact and the component descriptor).
    """
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    if type(session) is not _CPU_CLASS:
        _refuse("generic-binding-drift", "/session",
                {"reason": "exact-GeneratedWishboneCpuSession-required",
                 "actual": _qualified(type(session))})
    if type(selection) is not AdapterSelection:
        _refuse("generic-contract-type", "/selection")
    try:
        _check_pins()
    except ValueError as error:
        _refuse("generic-binding-drift", "/adapter",
                {"reason": str(error)[:160]})
    _check_selection(selection, component=component)
    endpoint = _descriptor_cpu_endpoint(component)
    if endpoint_id is not None:
        require_identifier(endpoint_id, "/endpoint_id")
        if endpoint_id != endpoint["endpoint_id"]:
            _refuse("generic-route-refused", "/endpoint_id",
                    {"reason": "declared-endpoint-is-not-the-certified-cpu",
                     "declared": endpoint_id,
                     "certified": endpoint["endpoint_id"]})
    artifact = getattr(session, "artifact", None)
    if artifact is None:
        _refuse("generic-source-unverified", "/session",
                {"reason": "session-carries-no-artifact"})
    if artifact.plan.request.instance_id != component.instance_id:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "instance-id-mismatch",
                 "component": component.instance_id,
                 "artifact": artifact.plan.request.instance_id})
    if artifact.runtime_document.get("artifact_digest") != component.artifact_sha256:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "artifact-digest-mismatch"})
    surface = wishbone_cpu_surface_document(artifact)
    if _digest(surface) != component.semantic_contract_sha256:
        _refuse("generic-source-unverified", "/semantic",
                {"reason": "semantic-contract-digest-mismatch",
                 "surface_schema": surface["schema_version"]})
    instruction_endpoints = tuple(sorted(
        row.endpoint_id for row in artifact.plan.binding.endpoints
        if row.function in WISHBONE_CPU_INSTRUCTION_FUNCTIONS))
    facts = derive_wishbone_cpu_abi_facts(
        runtime_document=artifact.runtime_document,
        instance_id=component.instance_id,
        endpoint_id=endpoint["endpoint_id"],
        template=tuple(endpoint["template"]),
        instruction_endpoints=instruction_endpoints)
    if (facts.data_width != endpoint["data_width"]
            or facts.address_width != endpoint["address_width"]
            or facts.endpoint_id != endpoint["endpoint_id"]
            or facts.address_units != endpoint["address_units"]):
        _refuse("generic-template-mismatch", "/component/endpoints",
                {"reason": "descriptor-widths-do-not-match-artifact-abi",
                 "data_width": facts.data_width,
                 "address_width": facts.address_width,
                 "address_units": facts.address_units})
    facts = replace(facts, surface_sha256=_digest(surface),
                    artifact_sha256=component.artifact_sha256)
    binding = _binding_digest(component=component, session=session,
                              selection=selection, facts=facts)
    driver = WishboneCpuDriver(session=session, artifact=artifact, facts=facts)
    bound = BoundCpuAdapter(component=component, session=session,
                            selection=selection, facts=facts, driver=driver,
                            binding_sha256=binding,
                            implementation_pin=_IMPLEMENTATION_PIN)
    bound.assert_current()
    return bound


def registration_document() -> dict:
    """Documentary description of this adapter implementation."""
    state = registration_state()
    return {
        "schema_version": "generic_adapter_implementation.v1",
        "adapter_id": CPU_ADAPTER_ID,
        "adapter_version": CPU_ADAPTER_VERSION,
        "implementation_sha256": implementation_sha256(),
        "implementation_pin": _IMPLEMENTATION_PIN,
        "session_class": _qualified(_CPU_CLASS),
        "role": "cpu",
        "protocol": list(WISHBONE_CPU_PROTOCOL),
        "template": list(WISHBONE_CPU_TEMPLATE),
        "semantic_kinds": [WISHBONE_CPU_SEMANTIC_KIND],
        "address_units": [WISHBONE_CPU_ADDRESS_UNITS],
        "operations": ["read", "write"],
        "completion_kind": WISHBONE_CPU_COMPLETION_KIND,
        "drives_cpu": False,
        "error_observed": False,
        "stall_observed": False,
        "registry_registered": state["registered"],
        "registry_implementation_sha256":
            state["registry_implementation_sha256"],
        "software_only": False,
    }
