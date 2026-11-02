"""APB3 stable-storage target adapter and its bounded target provider (G3).

Scope, stated honestly
----------------------
This module binds one already-admitted ``storage.rw.v1`` APB3 target component
to the existing, reviewed session/authority pair and offers the
``TargetProvider`` surface of the generic runtime design (sections 4.5/5.3):

* ``prepare`` checks the declared route, the real alias rule, transport
  alignment, the full-word operation shape and the provider budget **without
  touching the IP**.  Same key + same canonical payload returns the same issued
  handle; same key + different payload refuses ``generic-plan-mismatch``.
* ``advance`` drives one atomic, key-bound access through the *existing*
  ``GeneratedApb3RegisterSession.routed_register_access`` hook.  This module
  never simulates a register in Python, never calls ``issue``/``consume`` on
  ``ApbStorageRegisterVersionAuthority`` and never parses JSON into a native
  token.
* ``complete`` returns ``EffectEvidence`` over this provider's raw observation
  index.  Because the native storage-version token and the native APB sample
  join belong to the existing in-row consumer (``generated_storage_consumer``),
  this provider reports ``missing`` for those obligations and never claims
  certification or consumption.  A software fixture run reports ``unsupported``
  for every obligation.

Trust
-----
The production entry point ``bind_storage_adapter`` accepts **only** the exact
``GeneratedApb3RegisterSession`` class (type identity plus pinned module
SHA-256) whose artifact is the admitted component's artifact and whose live
``ApbStorageRegisterVersionAuthority`` dispatch is registered.  A software test
double exists, but it is reachable solely through the module-private
``_software_storage_fixture`` hook; ``bind_storage_adapter`` refuses it.

No RTL, Verilator build or native process is started here.  ``advance`` on a
real session refuses before the driver hook when the session has no live
process, so software tests can prove the pre-effect refusal without pretending
a native run happened.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
import sys

from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
from myfuzz.local_harness.apb_storage_source_contract import (
    apb_storage_address_matches,
    validate_apb_storage_source_contract,
)
from myfuzz.scenario.apb_storage_register_version import (
    ApbStorageRegisterVersionAuthority,
)
from myfuzz.scenario.ledger import TransactionKey

from ..contracts import (
    AdapterSelection,
    GenericRuntimeRefused,
    ProcessLocalIssuance,
    VerifiedComponent,
    canonical_json_bytes,
    require_digest,
    require_identifier,
)
from ..evidence.contracts import EffectEvidence, EvidenceRef, combine_status
from ..semantics.contracts import STORAGE_RW, SemanticContract
from ..semantics.storage import (
    address_matches,
    aligned_offset,
    storage_register_facts,
    storage_semantic_contract,
)
from .contracts import (
    PreparedTargetOperation,
    ProviderProgress,
    TargetRequest,
    operation_id_for,
    request_digest,
)

STORAGE_ADAPTER_ID = "apb3.storage.v1"
STORAGE_ADAPTER_VERSION = "1"

# Transport facts of the registered full-word storage contract.
_HOST_ALIGNMENT_BYTES = 4
_FULL_WORD_BYTES = 4
_FULL_WORD_BYTE_ENABLE = 0xF
_MAX_OPERATIONS = 4096
_MAX_SAMPLES = 65536

_APB3_ROLES = ("paddr", "psel", "penable", "pwrite", "pwdata", "pready",
               "prdata", "pslverr")
_APB3_WIDTHS = MappingProxyType({"paddr": 12, "psel": 1, "penable": 1,
                                 "pwrite": 1, "pwdata": 32, "pready": 1,
                                 "prdata": 32, "pslverr": 1})

_RAW_COMMAND = "apb3_register_command"
_RAW_TICK = "apb3_register_tick_sample"
_SOFTWARE_RAW_COMMAND = "software_apb3_command"
_SOFTWARE_RAW_TICK = "software_apb3_tick_sample"

# Obligation names of this provider's evidence boundary.  None of them is ever
# certified from a software fixture and the two native obligations are never
# certified here: the existing token-issuing consumer owns them.
_OBLIGATION_RESPONSE = "apb3_target_response"
_OBLIGATION_EFFECT = "component_semantic_effect"
_OBLIGATION_SAMPLE = "physical_protocol_sample"
_OBLIGATION_TOKEN = "storage_version_token"


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _canonical(value) -> bytes:
    return canonical_json_bytes(value)


def _digest(value) -> str:
    return sha256(_canonical(value)).hexdigest()


def _qualified(value) -> str:
    return value.__module__ + "." + value.__qualname__


def _pin(value):
    return (value, getattr(value, "__code__", None))


_ROOT = Path(__file__).resolve().parents[4]

# Modules whose exact bytes back the trust claim.  Paths are the same files the
# code-owned registry already pins; this adapter adds its own module so that an
# edit of the adapter itself is visible in ``implementation_sha256``.
_PINNED_MODULES = MappingProxyType({
    "myfuzz.local_harness.apb3_register_session":
        "src/myfuzz/local_harness/apb3_register_session.py",
    "myfuzz.local_harness.apb_storage_source_contract":
        "src/myfuzz/local_harness/apb_storage_source_contract.py",
    "myfuzz.scenario.apb_storage_register_version":
        "src/myfuzz/scenario/apb_storage_register_version.py",
    "myfuzz.runtime.semantics.storage": "src/myfuzz/runtime/semantics/storage.py",
    "myfuzz.runtime.semantics.contracts":
        "src/myfuzz/runtime/semantics/contracts.py",
    "myfuzz.runtime.adapters.contracts":
        "src/myfuzz/runtime/adapters/contracts.py",
    "myfuzz.runtime.adapters.apb3_storage":
        "src/myfuzz/runtime/adapters/apb3_storage.py",
})


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError("apb3-storage-adapter-drift:unreadable:" + relative) from error


_DEPENDENCIES = {
    "GeneratedApb3RegisterSession": GeneratedApb3RegisterSession,
    "ApbStorageRegisterVersionAuthority": ApbStorageRegisterVersionAuthority,
    "apb_storage_address_matches": apb_storage_address_matches,
    "validate_apb_storage_source_contract": validate_apb_storage_source_contract,
    "address_matches": address_matches,
    "aligned_offset": aligned_offset,
    "storage_register_facts": storage_register_facts,
    "storage_semantic_contract": storage_semantic_contract,
}
_PINNED = MappingProxyType({name: _pin(value)
                            for name, value in _DEPENDENCIES.items()})
_ORIGINS = MappingProxyType({name: value.__module__
                             for name, value in _DEPENDENCIES.items()})

_SESSION_CLASS = GeneratedApb3RegisterSession
_ISSUER_CLASS = ApbStorageRegisterVersionAuthority
_SESSION_METHODS = MappingProxyType({
    name: (getattr(_SESSION_CLASS, name), getattr(_SESSION_CLASS, name).__code__)
    for name in ("routed_register_access", "routed_delivery_failed", "command",
                 "_take", "begin_case", "identity_document", "reset_local",
                 "read_register", "write_register")
})
_ISSUER_METHODS = MappingProxyType({
    name: (getattr(_ISSUER_CLASS, name), getattr(_ISSUER_CLASS, name).__code__)
    for name in ("issue", "consume", "writes", "_validate", "_source_contract")
})
_MODULE_PINS = MappingProxyType({name: _file_sha(relative)
                                 for name, relative in _PINNED_MODULES.items()})


def implementation_sha256() -> str:
    """Adapter implementation identity: own module plus every trusted dependency."""
    return _digest({
        "schema_version": "apb3_storage_adapter_implementation.v1",
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "session_class": _qualified(_SESSION_CLASS),
        "issuer_class": _qualified(_ISSUER_CLASS),
        "files": {name: _file_sha(relative)
                  for name, relative in sorted(_PINNED_MODULES.items())},
    })


_IMPLEMENTATION_PIN = implementation_sha256()


def _check_pins() -> None:
    """Import-time pins re-checked at every bind/stability boundary."""
    for name, (value, code) in _PINNED.items():
        current = globals().get(name)
        if current is not value or (code is not None
                                    and getattr(value, "__code__", None) is not code):
            raise ValueError("apb3-storage-adapter-drift:" + name)
        origin = sys.modules.get(_ORIGINS[name])
        if origin is not None and getattr(origin, name, None) is not value:
            raise ValueError("apb3-storage-adapter-drift:" + name)
    for name, (method, code) in _SESSION_METHODS.items():
        if (getattr(_SESSION_CLASS, name, None) is not method
                or getattr(method, "__code__", None) is not code):
            raise ValueError("apb3-storage-adapter-drift:session." + name)
    for name, (method, code) in _ISSUER_METHODS.items():
        if (getattr(_ISSUER_CLASS, name, None) is not method
                or getattr(method, "__code__", None) is not code):
            raise ValueError("apb3-storage-adapter-drift:issuer." + name)
    for module_name, relative in _PINNED_MODULES.items():
        if sys.modules.get(module_name) is None:
            raise ValueError("apb3-storage-adapter-drift:module:" + module_name)
        if _file_sha(relative) != _MODULE_PINS[module_name]:
            raise ValueError("apb3-storage-adapter-drift:module:" + module_name)
    if implementation_sha256() != _IMPLEMENTATION_PIN:
        raise ValueError("apb3-storage-adapter-drift:implementation")


def _registry_implementation_pin(adapter_id: str) -> str:
    """The code-owned registry pin the selection was issued against."""
    from ..registry import registrations
    rows = [row for row in registrations() if row.adapter_id == adapter_id]
    if len(rows) != 1:
        _refuse("generic-adapter-missing", "/selection",
                {"adapter_id": adapter_id, "matches": len(rows)})
    return rows[0].implementation_sha256()


def _registered_authority(session):
    from myfuzz.scenario import apb_storage_register_version as module
    return module._AUTHORITIES.get(session)


# ---------------------------------------------------------------------------
# Declared route of one certified storage register
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class TargetRoute:
    """Declared CPU -> target route for exactly one certified register.

    Every field comes from an explicit declaration (the same-pass prepared path
    contract in G4, or an equally explicit wiring record); nothing here is
    inferred from a register name, a profile title or an instance name.
    """

    path_id: str
    device_id: str
    endpoint_id: str
    window_base: int
    window_size: int
    register: str
    register_offset: int
    access_alignment: int
    width_bytes: int
    allowed_byte_enables: tuple[int, ...]
    declared_value_mask: int
    declared_operation: str

    def __post_init__(self) -> None:
        require_identifier(self.path_id, "/route/path_id")
        require_identifier(self.device_id, "/route/device_id")
        require_identifier(self.endpoint_id, "/route/endpoint_id")
        require_identifier(self.register, "/route/register")
        if type(self.window_base) is not int or not 0 <= self.window_base < (1 << 32):
            _refuse("generic-contract-type", "/route/window_base")
        if (type(self.window_size) is not int or self.window_size <= 0
                or self.window_base + self.window_size > (1 << 32)):
            _refuse("generic-contract-type", "/route/window_size")
        if (type(self.register_offset) is not int
                or not 0 <= self.register_offset < self.window_size):
            _refuse("generic-contract-type", "/route/register_offset")
        if type(self.access_alignment) is not int or self.access_alignment <= 0:
            _refuse("generic-contract-type", "/route/access_alignment")
        if type(self.width_bytes) is not int or self.width_bytes <= 0:
            _refuse("generic-contract-type", "/route/width_bytes")
        if (type(self.allowed_byte_enables) is not tuple
                or not self.allowed_byte_enables
                or any(type(value) is not int or value <= 0
                       for value in self.allowed_byte_enables)):
            _refuse("generic-contract-type", "/route/allowed_byte_enables")
        if (type(self.declared_value_mask) is not int
                or not 1 <= self.declared_value_mask < (1 << 32)):
            _refuse("generic-contract-type", "/route/declared_value_mask")
        if type(self.declared_operation) is not str or not self.declared_operation:
            _refuse("generic-contract-type", "/route/declared_operation")

    def document(self) -> dict:
        return {
            "path_id": self.path_id,
            "device_id": self.device_id,
            "endpoint_id": self.endpoint_id,
            "window_base": self.window_base,
            "window_size": self.window_size,
            "register": self.register,
            "register_offset": self.register_offset,
            "access_alignment": self.access_alignment,
            "width_bytes": self.width_bytes,
            "allowed_byte_enables": [int(value) for value in self.allowed_byte_enables],
            "declared_value_mask": self.declared_value_mask,
            "declared_operation": self.declared_operation,
        }

    def sha256(self) -> str:
        return _digest({"schema_version": "target_route.v1", **self.document()})


# ---------------------------------------------------------------------------
# Bound facts: certified semantic contract plus the real protocol trace
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class StorageAdapterFacts:
    """Facts this provider re-derives from the live artifact and source row."""

    instance_id: str
    endpoint_id: str
    source_contract_id: str
    source_contract_digest: str
    register: str
    canonical_offset: int
    register_width: int
    read_mask: int
    write_mask: int
    address_width: int
    decode_mask: int
    decode_value: int
    host_alignment_bytes: int
    alignment_bytes: int
    alias_period_bytes: int
    expression: str
    reset_port: str
    reset_observed: bool
    trace_roles: tuple[tuple[str, int], ...]
    max_wait_cycles: int
    observation_scope: str

    def document(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "endpoint_id": self.endpoint_id,
            "source_contract_id": self.source_contract_id,
            "source_contract_digest": self.source_contract_digest,
            "register": self.register,
            "canonical_offset": self.canonical_offset,
            "register_width": self.register_width,
            "read_mask": self.read_mask,
            "write_mask": self.write_mask,
            "address_width": self.address_width,
            "decode_mask": self.decode_mask,
            "decode_value": self.decode_value,
            "host_alignment_bytes": self.host_alignment_bytes,
            "alignment_bytes": self.alignment_bytes,
            "alias_period_bytes": self.alias_period_bytes,
            "expression": self.expression,
            "reset_port": self.reset_port,
            "reset_observed": self.reset_observed,
            "trace_roles": [[name, width] for name, width in self.trace_roles],
            "max_wait_cycles": self.max_wait_cycles,
            "observation_scope": self.observation_scope,
        }

    def sha256(self) -> str:
        return _digest({"schema_version": "apb3_storage_facts.v1",
                        **self.document()})


def descriptor_target_endpoint(component: VerifiedComponent) -> dict:
    """The single certified target endpoint of one storage component."""
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    endpoints = [row for row in component.endpoints() if row["role"] == "target"]
    if len(endpoints) != 1:
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "one-target-endpoint-required", "matches": len(endpoints)})
    endpoint = endpoints[0]
    if (tuple(endpoint["protocol"]) != ("apb", "3")
            or endpoint["semantic_kind"] != STORAGE_RW):
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "apb3-storage-endpoint-required",
                 "protocol": endpoint["protocol"],
                 "semantic_kind": endpoint["semantic_kind"]})
    return endpoint


def artifact_contract_facts(artifact, *, base_dir: Path, endpoint_id: str,
                            template: tuple[str, str, str]):
    """Re-derive source row, semantic contract and protocol trace from the artifact."""
    document = artifact.runtime_document
    if document.get("kind") != "apb3_register_observe":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "apb3_register_observe",
                 "actual": document.get("kind")})
    observation = document.get("storage_observation")
    if (type(observation) is not dict
            or observation.get("schema_version") != "apb_storage_probe.v1"
            or observation.get("scope") != "generated_expression_source_mapped"
            or any(observation.get(key) is not False for key in (
                "reset_authority", "version_authority", "source_authority"))):
        _refuse("generic-semantic-unsupported", "/artifact/storage_observation",
                {"reason": "closed-storage-observation-required"})
    selection = observation.get("selection")
    if (type(selection) is not dict
            or type(selection.get("register")) is not str
            or type(selection.get("contract_id")) is not str):
        _refuse("generic-semantic-unsupported",
                "/artifact/storage_observation/selection",
                {"reason": "explicit-storage-selection-required"})
    try:
        registered = validate_apb_storage_source_contract(
            observation.get("source_contract"), artifact.plan.profile,
            base_dir=Path(base_dir))
    except ValueError as error:
        _refuse("generic-source-unverified", "/storage_observation/source_contract",
                {"reason": str(error)[:160]})
    if (registered.get("contract_id") != selection["contract_id"]
            or registered["register"]["name"] != selection["register"]):
        _refuse("generic-semantic-unsupported",
                "/artifact/storage_observation/selection",
                {"reason": "source-contract-selection-mismatch"})
    semantic = storage_semantic_contract(
        registered=registered, endpoint_id=endpoint_id, template=template,
        observation_scope=observation["scope"])
    facts = storage_register_facts(semantic)
    register = registered["register"]
    decode = registered["decode"]
    if (facts["register_width"] != 32 or register["width"] != 32
            or facts["byte_enable"] is not False
            or facts["address_units"] != "byte"):
        _refuse("generic-semantic-unsupported", "/register",
                {"reason": "full-word-32-bit-byte-addressed-storage-required"})
    if (type(decode.get("host_alignment_bytes")) is not int
            or decode["host_alignment_bytes"] != _HOST_ALIGNMENT_BYTES):
        _refuse("generic-semantic-unsupported", "/decode/host_alignment_bytes",
                {"expected": _HOST_ALIGNMENT_BYTES,
                 "actual": decode.get("host_alignment_bytes")})
    if apb_storage_address_matches(
            registered, register["canonical_offset"]) is not True:
        _refuse("generic-semantic-unsupported", "/decode",
                {"reason": "canonical-offset-not-a-storage-alias"})
    trace = document.get("base_protocol_trace")
    if (type(trace) is not dict or trace.get("protocol") != "apb3"
            or trace.get("endpoint_id") != endpoint_id
            or type(trace.get("signals")) is not dict
            or set(trace["signals"]) != set(_APB3_ROLES)
            or type(trace.get("signal_widths")) is not dict):
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"reason": "full-word-apb3-trace-required"})
    for role, width in _APB3_WIDTHS.items():
        if trace["signal_widths"].get(role) != width:
            _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                    {"role": role, "expected_width": width,
                     "actual_width": trace["signal_widths"].get(role)})
    max_wait = trace.get("max_wait_cycles")
    if type(max_wait) is not int or not 0 <= max_wait <= 4096:
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"reason": "bounded-wait-cycle-declaration-required"})
    roles = tuple(sorted((role, width) for role, width in
                         trace["signal_widths"].items()))
    bound = StorageAdapterFacts(
        instance_id=artifact.plan.request.instance_id,
        endpoint_id=endpoint_id,
        source_contract_id=registered["contract_id"],
        source_contract_digest=registered["digest"],
        register=register["name"],
        canonical_offset=register["canonical_offset"],
        register_width=facts["register_width"],
        read_mask=facts["read_mask"],
        write_mask=facts["write_mask"],
        address_width=facts["address_width"],
        decode_mask=facts["decode_mask"],
        decode_value=facts["decode_value"],
        host_alignment_bytes=decode["host_alignment_bytes"],
        alignment_bytes=facts["alignment_bytes"],
        alias_period_bytes=facts["alias_period_bytes"],
        expression=facts["expression"],
        reset_port=facts["reset_port"],
        reset_observed=facts["reset_observed"],
        trace_roles=roles,
        max_wait_cycles=max_wait,
        observation_scope=observation["scope"],
    )
    return registered, semantic, bound, trace


def _check_component_matches_live(component: VerifiedComponent, *, artifact,
                                  endpoint: dict,
                                  semantic: SemanticContract) -> None:
    if artifact.plan.request.instance_id != component.instance_id:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "instance-id-mismatch",
                 "component": component.instance_id,
                 "artifact": artifact.plan.request.instance_id})
    if artifact.runtime_document.get("artifact_digest") != component.artifact_sha256:
        _refuse("generic-source-unverified", "/artifact",
                {"reason": "artifact-digest-mismatch"})
    if semantic.sha256_hex != component.semantic_contract_sha256:
        _refuse("generic-source-unverified", "/semantic",
                {"reason": "semantic-contract-digest-mismatch"})
    declared = (tuple(endpoint["protocol"]),
                tuple(endpoint["template"]),
                endpoint["semantic_kind"], endpoint["role"])
    expected = (("apb", "3"), tuple(semantic.document()["endpoint"]["template"]),
                STORAGE_RW, "target")
    if declared != expected:
        _refuse("generic-template-mismatch", "/component/endpoints",
                {"reason": "endpoint-does-not-match-live-artifact"})


def _check_selection(selection: AdapterSelection, *, component: VerifiedComponent,
                     implementation_pin: str) -> None:
    if type(selection) is not AdapterSelection:
        _refuse("generic-contract-type", "/selection")
    if (selection.adapter_id != STORAGE_ADAPTER_ID
            or selection.adapter_version != STORAGE_ADAPTER_VERSION):
        _refuse("generic-adapter-missing", "/selection",
                {"adapter_id": selection.adapter_id,
                 "adapter_version": selection.adapter_version,
                 "expected_id": STORAGE_ADAPTER_ID,
                 "expected_version": STORAGE_ADAPTER_VERSION})
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


def _check_route(route: TargetRoute, *, artifact, facts: StorageAdapterFacts) -> None:
    if route.endpoint_id != facts.endpoint_id:
        _refuse("generic-route-refused", "/route/endpoint_id",
                {"expected": facts.endpoint_id, "actual": route.endpoint_id})
    if route.register != facts.register:
        _refuse("generic-route-refused", "/route/register",
                {"expected": facts.register, "actual": route.register})
    window = artifact.plan.profile.address.window_size
    if route.window_size != window:
        _refuse("generic-route-refused", "/route/window_size",
                {"expected": window, "actual": route.window_size})
    if (route.access_alignment != facts.host_alignment_bytes
            or route.access_alignment != facts.alignment_bytes):
        _refuse("generic-route-refused", "/route/access_alignment",
                {"expected": facts.host_alignment_bytes,
                 "actual": route.access_alignment})
    if route.width_bytes != facts.register_width // 8:
        _refuse("generic-route-refused", "/route/width_bytes",
                {"expected": facts.register_width // 8,
                 "actual": route.width_bytes})
    if _FULL_WORD_BYTE_ENABLE not in route.allowed_byte_enables:
        _refuse("generic-semantic-unsupported", "/route/allowed_byte_enables",
                {"reason": "registered-contract-has-no-byte-enables"})
    if route.register_offset % route.access_alignment:
        _refuse("generic-route-refused", "/route/register_offset",
                {"reason": "route-register-offset-unaligned"})


# ---------------------------------------------------------------------------
# Raw observation index and phase validation
# ---------------------------------------------------------------------------

class _ObservationInvalid(Exception):
    """The raw APB3 sample span contradicts the request or the protocol."""


class _DriverRefused(Exception):
    """The session driver refused before any effect existed."""


@dataclass(frozen=True, slots=True)
class _AccessObservation:
    ticks: int
    phases: tuple[str, ...]
    rdata: int
    error: bool
    span_digest: str


def _tick_signals(sample, *, phase: str, trace: dict) -> dict:
    state = sample.get(phase) if type(sample) is dict else None
    backend = state.get("backend") if type(state) is dict else None
    if type(backend) is not dict:
        raise _ObservationInvalid("missing-native-backend-sample")
    values = {}
    for role in _APB3_ROLES:
        name = trace["signals"][role]
        value = backend.get(name)
        width = trace["signal_widths"][role]
        if type(value) is not int or not 0 <= value < (1 << width):
            raise _ObservationInvalid("invalid-native-signal:" + role)
        values[role] = value
    return values


def validate_apb3_span(samples, *, trace: dict, offset: int, write: bool,
                       value: int, byte_enable: int,
                       rdata: int) -> _AccessObservation:
    """One APB3 setup -> access -> (wait)* -> response ordering check.

    ``samples`` are the raw pre-phase samples of exactly one bounded access,
    each carrying the artifact-declared backend signal names.  Idle ticks before
    the selected transfer and after the response are allowed and trimmed; every
    tick of the transfer itself must match the requested address, direction and
    write data, and the response tick must carry the driver's read data.
    """
    if byte_enable != _FULL_WORD_BYTE_ENABLE:
        raise _ObservationInvalid("unsupported-byte-enable")
    if type(samples) is not list or not samples:
        raise _ObservationInvalid("empty-sample-span")
    staged = []
    for sample in samples:
        signals = _tick_signals(sample, phase="pre", trace=trace)
        if signals["psel"] == 0:
            staged.append(("idle", signals))
        elif signals["penable"] == 0:
            staged.append(("setup", signals))
        elif signals["pready"] == 0:
            staged.append(("transfer", signals))
        else:
            staged.append(("response", signals))
    active = [index for index, (kind, _) in enumerate(staged) if kind != "idle"]
    if not active:
        raise _ObservationInvalid("no-selected-apb3-tick")
    first, last = active[0], active[-1]
    span = staged[first:last + 1]
    if any(kind == "idle" for kind, _ in span):
        raise _ObservationInvalid("apb3-span-interrupted")
    kinds = [kind for kind, _ in span]
    if len(kinds) < 3 or kinds[0] != "setup" or kinds[-1] != "response":
        raise _ObservationInvalid("apb3-setup-or-response-missing")
    transfers = kinds[1:-1]
    if not transfers or any(kind != "transfer" for kind in transfers):
        raise _ObservationInvalid("apb3-access-or-wait-ordering")
    if len(transfers) - 1 > trace["max_wait_cycles"]:
        raise _ObservationInvalid("apb3-wait-cycle-bound")
    phases = (("setup", "access")
              + tuple("wait" for _ in range(len(transfers) - 1))
              + ("response",))
    expected_pwdata = value if write else 0
    for _, signals in span:
        if signals["paddr"] != offset:
            raise _ObservationInvalid("apb3-address-mismatch")
        if signals["pwrite"] != int(write):
            raise _ObservationInvalid("apb3-direction-mismatch")
        if signals["pwdata"] != expected_pwdata:
            raise _ObservationInvalid("apb3-write-data-mismatch")
    response = span[-1][1]
    error = bool(response["pslverr"])
    if not error and not write and response["prdata"] != rdata:
        raise _ObservationInvalid("apb3-read-data-mismatch")
    return _AccessObservation(
        ticks=len(samples), phases=phases, rdata=response["prdata"],
        error=error,
        span_digest=_digest({"offset": offset, "write": bool(write),
                             "value": value, "phases": list(phases),
                             "error": error, "rdata": response["prdata"]}))


# ---------------------------------------------------------------------------
# Target provider
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class _Issue:
    handle: PreparedTargetOperation
    request: TargetRequest
    epoch: int
    execution: str
    operation_id: str


@dataclass(frozen=True, slots=True)
class _OperationState:
    progress: ProviderProgress
    evidence: EffectEvidence | None = None


class StorageTargetProvider:
    """Bounded ``TargetProvider`` over one admitted APB3 storage target.

    Constructed only by :func:`bind_storage_adapter` (production) or by the
    module-private software fixture hook.  It never issues or consumes the
    native storage-version token; it only routes the existing causal driver
    call and joins its own raw observation.
    """

    __slots__ = ("_component", "_artifact", "_session", "_route", "_facts",
                 "_registered", "_semantic", "_trace", "_binding_sha256",
                 "_instance_id", "_endpoint_id", "_issuance", "_issues",
                 "_key_index", "_raw", "_raw_sequence", "_states", "_closed",
                 "_software_only")

    def __init__(self, *, component, artifact, session, route, facts,
                 registered, semantic, trace, binding_sha256, software_only):
        self._component = component
        self._artifact = artifact
        self._session = session
        self._route = route
        self._facts = facts
        self._registered = registered
        self._semantic = semantic
        self._trace = trace
        self._binding_sha256 = require_digest(binding_sha256, "/binding_sha256")
        self._instance_id = component.instance_id
        self._endpoint_id = facts.endpoint_id
        self._issuance = ProcessLocalIssuance("apb3-storage-operations")
        self._issues: dict[int, _Issue] = {}
        self._key_index: dict[bytes, str] = {}
        self._states: dict[int, _OperationState] = {}
        self._raw: dict[int, tuple[str, int, str]] = {}
        self._raw_sequence = 0
        self._closed = False
        self._software_only = bool(software_only)

    # -- identity ---------------------------------------------------------
    @property
    def binding_sha256(self) -> str:
        return self._binding_sha256

    @property
    def semantic_contract(self) -> SemanticContract:
        return self._semantic

    @property
    def route_sha256(self):
        return None if self._route is None else self._route.sha256()

    @property
    def software_only(self) -> bool:
        return self._software_only

    @property
    def raw_events(self) -> dict:
        return {event_id: {"kind": kind, "coordinate": coordinate,
                           "digest": digest}
                for event_id, (kind, coordinate, digest) in self._raw.items()}

    @property
    def operation_count(self) -> int:
        return len(self._issues)

    def _session_scope(self) -> tuple[int, str]:
        epoch = getattr(self._session, "reset_epoch", None)
        execution = getattr(self._session, "_execution", None)
        if type(epoch) is not int or type(execution) is not str:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "session-scope-unreadable"})
        return epoch, execution

    def _session_ticks(self) -> int:
        ticks = getattr(self._session, "local_ticks", None)
        if type(ticks) is not int or ticks < 0:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "local-tick-counter-unreadable"})
        return ticks

    def _base_dir(self) -> Path:
        base = getattr(self._session, "base_dir", None)
        return _ROOT if base is None else Path(base)

    def _assert_open(self) -> None:
        if self._closed:
            _refuse("generic-provider-closed", "/provider",
                    {"reason": "provider-closed"})

    def assert_bound(self) -> None:
        """Stability check shared by the adapter: pins, live objects, facts."""
        self._assert_open()
        try:
            _check_pins()
        except ValueError as error:
            _refuse("generic-binding-drift", "/adapter",
                    {"reason": str(error)[:160]})
        session = self._session
        expected_class = _FixtureSession if self._software_only else _SESSION_CLASS
        if type(session) is not expected_class:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "session-class-changed",
                     "actual": _qualified(type(session))})
        if getattr(session, "artifact", None) is not self._artifact:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "session-artifact-replaced"})
        template = tuple(self._semantic.document()["endpoint"]["template"])
        try:
            registered, semantic, bound, trace = artifact_contract_facts(
                self._artifact, base_dir=self._base_dir(),
                endpoint_id=self._endpoint_id, template=template)
        except GenericRuntimeRefused as error:
            _refuse("generic-binding-drift", "/artifact",
                    {"reason": "artifact-facts-unreadable",
                     "detail": error.code})
        if (semantic.sha256_hex != self._semantic.sha256_hex
                or bound.sha256() != self._facts.sha256()
                or registered["digest"] != self._facts.source_contract_digest
                or trace != self._trace):
            _refuse("generic-binding-drift", "/artifact",
                    {"reason": "semantic-facts-changed"})
        if self._software_only:
            return
        try:
            session._check_artifact_stable()
        except (AttributeError, ValueError) as error:
            _refuse("generic-binding-drift", "/session",
                    {"reason": str(error)[:160]})
        try:
            enabled = session.routed_register_access_enabled
        except ValueError as error:
            _refuse("generic-binding-drift", "/session",
                    {"reason": str(error)[:160]})
        if enabled is not True:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "storage-version-authority-not-dispatched"})
        authority = _registered_authority(session)
        if type(authority) is not _ISSUER_CLASS or authority.target is not session:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "issuer-not-bound-to-this-session"})

    def _bounded_ticks(self) -> int:
        value = getattr(self._session, "max_local_ticks_per_register_access", None)
        if type(value) is not int or not 1 <= value <= 65536:
            _refuse("generic-binding-drift", "/session",
                    {"reason": "bounded-access-cost-unreadable"})
        return value

    def _capacity_ok(self) -> bool:
        if len(self._issues) >= _MAX_OPERATIONS:
            return False
        samples = getattr(self._session, "_samples", None)
        queued = len(samples) if samples is not None else 0
        return queued + self._bounded_ticks() <= _MAX_SAMPLES

    # -- prepare ----------------------------------------------------------
    def prepare(self, key: TransactionKey, request: TargetRequest):
        """Check route/policy/budget; never touch the IP or the session."""
        self._assert_open()
        if type(key) is not TransactionKey:
            _refuse("generic-contract-type", "/key",
                    {"expected": "TransactionKey"})
        if type(request) is not TargetRequest:
            _refuse("generic-contract-type", "/request",
                    {"expected": "TargetRequest"})
        self.assert_bound()
        if self._route is None:
            _refuse("generic-route-refused", "/route",
                    {"reason": "route-not-declared"})
        if request.path_id != self._route.path_id:
            _refuse("generic-route-refused", "/request/path_id",
                    {"declared": self._route.path_id,
                     "requested": request.path_id})
        offset = request.address - self._route.window_base
        if not 0 <= offset < self._route.window_size:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "outside-declared-window"})
        alignment = max(self._route.access_alignment,
                        self._facts.host_alignment_bytes,
                        self._facts.alignment_bytes)
        if request.address % alignment or offset % alignment:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "transport-alignment",
                     "alignment_bytes": alignment})
        if not 0 <= offset < (1 << self._facts.address_width):
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "outside-source-address-width"})
        try:
            alias = apb_storage_address_matches(self._registered, offset)
        except ValueError as error:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": str(error)[:160]})
        if alias is not True:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "not-a-certified-storage-alias",
                     "decode_mask": self._facts.decode_mask,
                     "decode_value": self._facts.decode_value})
        if address_matches(self._semantic, offset) is not True:
            _refuse("generic-semantic-unsupported", "/request/address",
                    {"reason": "alias-rule-divergence"})
        if aligned_offset(self._semantic, offset) != offset:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "transport-alignment"})
        if request.operation not in ("read", "write"):
            _refuse("generic-contract-type", "/request/operation")
        if request.size_bytes != self._route.width_bytes:
            _refuse("generic-semantic-unsupported", "/request/size_bytes",
                    {"expected": self._route.width_bytes,
                     "actual": request.size_bytes,
                     "reason": "registered-full-word-contract"})
        if request.byte_enable != _FULL_WORD_BYTE_ENABLE:
            _refuse("generic-semantic-unsupported", "/request/byte_enable",
                    {"expected": _FULL_WORD_BYTE_ENABLE,
                     "actual": request.byte_enable,
                     "reason": "registered-contract-has-no-byte-enables"})
        if request.byte_enable not in self._route.allowed_byte_enables:
            _refuse("generic-semantic-unsupported", "/request/byte_enable",
                    {"allowed": list(self._route.allowed_byte_enables)})
        if request.operation == "write":
            mask = self._route.declared_value_mask & self._facts.write_mask
            if request.write_data is None or request.write_data & ~mask:
                _refuse("generic-route-refused", "/request/write_data",
                        {"reason": "write-outside-declared-mask",
                         "value_mask": mask})
        if not self._capacity_ok():
            _refuse("generic-provider-budget", "/provider",
                    {"reason": "operation-or-sample-capacity-exhausted"})
        request_sha256 = request_digest(request)
        route_sha256 = self._route.sha256()
        operation_id = operation_id_for(
            key=key, request_sha256=request_sha256, route_sha256=route_sha256,
            binding_sha256=self._binding_sha256)
        key_bytes = _canonical(asdict(key))
        existing_id = self._key_index.get(key_bytes)
        if existing_id is not None and existing_id != operation_id:
            _refuse("generic-plan-mismatch", "/key",
                    {"reason": "same-key-different-payload"})
        epoch, execution = self._session_scope()
        for issue in self._issues.values():
            # Idempotency is scoped to the live (reset epoch, execution) scope:
            # the same request after a reset is a *new* issued operation.
            if (issue.operation_id == operation_id
                    and issue.epoch == epoch and issue.execution == execution):
                if issue.request.canonical_bytes() != request.canonical_bytes():
                    _refuse("generic-plan-mismatch", "/request",
                            {"reason": "same-operation-different-payload"})
                return issue.handle
        handle = PreparedTargetOperation(
            key=key, operation_id=operation_id, request_sha256=request_sha256,
            route_sha256=route_sha256, binding_sha256=self._binding_sha256)
        issue = _Issue(handle=handle, request=request, epoch=epoch,
                       execution=execution, operation_id=operation_id)
        self._issuance.issue(handle, snapshot=request.canonical_bytes())
        self._issues[id(handle)] = issue
        self._key_index[key_bytes] = operation_id
        return handle

    # -- advance ----------------------------------------------------------
    def advance(self, operation, budget: int) -> ProviderProgress:
        """One bounded, key-bound access through the existing driver hook.

        ``budget`` is a lower bound on the artifact-bounded cost of one access
        (``max_local_ticks_per_register_access``): a smaller grant is refused
        *before* the driver runs, so a measured advancement can never exceed the
        grant.  A terminal result is cached and never re-issued, and any
        ambiguous reply becomes ``uncertain_effect`` rather than a retry.

        ``completed`` always carries the observed APB3 response payload
        (``PRDATA`` at the response tick) because the closed ``ProviderProgress``
        contract requires response bytes for a completed operation; only reads
        require that payload to equal the CPU-consumed read data.
        """
        self._assert_open()
        issue = self._require_issue(operation)
        self.assert_bound()
        epoch, execution = self._session_scope()
        if epoch != issue.epoch or execution != issue.execution:
            _refuse("generic-provider-stale", "/operation",
                    {"reason": "session-reset-or-case-change-since-prepare"})
        state = self._states.get(id(operation))
        if state is not None:
            # Terminal: never re-issue a write that may have taken effect.
            return state.progress
        if type(budget) is not int or budget < 0:
            _refuse("generic-contract-type", "/budget",
                    {"expected": "nonnegative int, bool rejected"})
        bounded = self._bounded_ticks()
        if budget == 0:
            _refuse("generic-provider-budget", "/budget",
                    {"reason": "zero-budget", "bounded_ticks": bounded})
        if budget < bounded:
            _refuse("generic-provider-budget", "/budget",
                    {"reason": "budget-below-bounded-access",
                     "bounded_ticks": bounded, "granted": budget})
        request = issue.request
        offset = request.address - self._route.window_base
        before = self._session_ticks()
        try:
            rdata = self._drive(issue, offset)
        except _DriverRefused:
            return self._terminal(
                issue, "refused", 0, None, (), "driver-refused-before-effect")
        except _ObservationInvalid:
            return self._terminal(
                issue, "uncertain_effect", max(0, self._session_ticks() - before),
                None, self._span_refs(issue, offset, before),
                "driver-result-shape")
        except GenericRuntimeRefused:
            # A pre-effect policy/binding refusal is not a possible effect.
            raise
        except BaseException:
            # An absent/ill-formed reply may follow a real effect: the operation
            # is terminally uncertain and is never retried.
            return self._terminal(
                issue, "uncertain_effect", max(0, self._session_ticks() - before),
                None, self._span_refs(issue, offset, before), "driver-failure")
        after = self._session_ticks()
        advanced = after - before
        if advanced < 0:
            return self._terminal(issue, "uncertain_effect", 0, None, (),
                                  "session-tick-regression")
        samples = self._span_samples(before, after)
        try:
            observation = validate_apb3_span(
                samples, trace=self._trace, offset=offset,
                write=request.operation == "write",
                value=request.write_data or 0,
                byte_enable=request.byte_enable, rdata=rdata)
        except _ObservationInvalid:
            return self._terminal(issue, "uncertain_effect", advanced, None,
                                  self._span_refs(issue, offset, before),
                                  "apb3-observation-invalid")
        refs = self._span_refs(issue, offset, before, observation=observation)
        if observation.ticks > budget:
            return self._terminal(issue, "uncertain_effect", advanced, None,
                                  refs, "measured-ticks-exceeded-budget")
        if observation.error:
            status = "uncertain_effect" if request.operation == "write" else "faulted"
            return self._terminal(issue, status, advanced, None, refs,
                                  "target-error-response")
        if request.operation == "read" and observation.rdata != rdata:
            return self._terminal(issue, "uncertain_effect", advanced, None,
                                  refs, "response-payload-mismatch")
        response = observation.rdata.to_bytes(_FULL_WORD_BYTES, "little")
        return self._terminal(issue, "completed", advanced, response, refs, None)

    def _require_issue(self, operation) -> _Issue:
        if type(operation) is not PreparedTargetOperation:
            _refuse("generic-contract-type", "/operation",
                    {"expected": "PreparedTargetOperation"})
        self._issuance.require(operation, pointer="/operation")
        issue = self._issues.get(id(operation))
        if issue is None or issue.handle is not operation:
            _refuse("generic-binding-drift", "/operation",
                    {"reason": "operation-not-issued-by-this-provider"})
        return issue

    def _span_samples(self, before: int, after: int) -> list:
        if after <= before:
            return []
        samples = getattr(self._session, "_samples", None)
        if samples is None:
            return []
        return list(samples)[-max(0, after - before):]

    def _drive(self, issue: _Issue, offset: int) -> int:
        request = issue.request
        write = request.operation == "write"
        value = request.write_data if write else 0
        if self._software_only:
            result = self._session.routed_register_access(
                issue.handle.key, address=request.address, offset=offset,
                write=write, value=value, be=request.byte_enable,
                delivery_context=self._delivery_context(issue, offset))
            if type(result) is not dict or type(result.get("rdata")) is not int:
                raise _ObservationInvalid("driver-result-shape")
            return result["rdata"]
        if self._session.process is None or self._session.process.poll() is not None:
            # Refuse before the driver hook: no command is issued and no effect
            # can exist.  Real native proof is deferred to G6.
            _refuse("generic-provider-closed", "/session",
                    {"reason": "session-not-running"})
        result = self._session.routed_register_access(
            issue.handle.key, address=request.address, offset=offset,
            write=write, value=value, be=request.byte_enable,
            delivery_context=self._delivery_context(issue, offset))
        if type(result) is not dict or type(result.get("rdata")) is not int:
            raise _ObservationInvalid("driver-result-shape")
        return result["rdata"]

    def _delivery_context(self, issue: _Issue, offset: int) -> dict:
        request = issue.request
        write = request.operation == "write"
        return {
            "source_transaction": asdict(issue.handle.key),
            "address": request.address,
            "offset": offset,
            "write": write,
            "value": request.write_data if write else 0,
            "be": request.byte_enable,
            "device_id": self._route.device_id,
            "window_base": self._route.window_base,
            "window_size": self._route.window_size,
        }

    # -- raw observation index -------------------------------------------
    def _raw_ref(self, kind: str, coordinate: int, digest: str) -> EvidenceRef:
        self._raw_sequence += 1
        event_id = self._raw_sequence
        self._raw[event_id] = (kind, coordinate, digest)
        return EvidenceRef(self._instance_id, event_id, kind)

    def _span_refs(self, issue: _Issue, offset: int, before: int,
                   *, observation=None) -> tuple[EvidenceRef, ...]:
        command_kind = (_SOFTWARE_RAW_COMMAND if self._software_only
                        else _RAW_COMMAND)
        tick_kind = _SOFTWARE_RAW_TICK if self._software_only else _RAW_TICK
        command_digest = issue.request.sha256() if observation is None \
            else observation.span_digest
        refs = [self._raw_ref(command_kind, offset, command_digest)]
        for sample in self._span_samples(before, self._session_ticks()):
            local_tick = sample.get("local_tick") if type(sample) is dict else None
            if type(local_tick) is not int or not 0 <= local_tick < (1 << 31):
                continue
            refs.append(self._raw_ref(tick_kind, local_tick, _digest(sample)))
        return tuple(refs)

    def _terminal(self, issue: _Issue, status: str, advanced: int,
                  response, raw_refs, reason_code) -> ProviderProgress:
        progress = ProviderProgress(
            key=issue.handle.key, status=status, advanced_ticks=advanced,
            response_bytes=response, raw_refs=tuple(raw_refs),
            reason_code=reason_code)
        self._states[id(issue.handle)] = _OperationState(progress=progress)
        return progress

    # -- complete ---------------------------------------------------------
    def complete(self, operation) -> EffectEvidence:
        """Evidence over this provider's raw observation of the operation.

        The scope is derived from what this provider can prove: it only speaks
        at the component-semantic-effect layer and never at cross-component
        source/consumption.  Native sample and storage-version-token
        obligations stay ``missing`` (real path) because the existing in-row
        consumer owns them; a software fixture reports ``unsupported`` and
        always has empty ``native_refs``.
        """
        self._assert_open()
        issue = self._require_issue(operation)
        self.assert_bound()
        epoch, execution = self._session_scope()
        if epoch != issue.epoch or execution != issue.execution:
            # Revocation outranks completeness: a reset ends the operation.
            _refuse("generic-provider-stale", "/operation",
                    {"reason": "session-reset-or-case-change-since-prepare"})
        state = self._states.get(id(operation))
        if state is None:
            _refuse("generic-provider-incomplete", "/operation",
                    {"reason": "advance-before-complete"})
        if state.evidence is not None:
            return state.evidence
        evidence = self._evidence(issue, state.progress)
        self._states[id(operation)] = _OperationState(
            progress=state.progress, evidence=evidence)
        return evidence

    def _evidence(self, issue: _Issue, progress: ProviderProgress) -> EffectEvidence:
        if self._software_only:
            results = ((_OBLIGATION_EFFECT, "unsupported"),
                       (_OBLIGATION_RESPONSE, "unsupported"),
                       (_OBLIGATION_SAMPLE, "unsupported"),
                       (_OBLIGATION_TOKEN, "unsupported"))
        elif progress.status == "completed":
            results = ((_OBLIGATION_EFFECT, "missing"),
                       (_OBLIGATION_RESPONSE, "certified"),
                       (_OBLIGATION_SAMPLE, "missing"),
                       (_OBLIGATION_TOKEN, "missing"))
        elif progress.reason_code in ("apb3-observation-invalid",
                                      "response-payload-mismatch"):
            # The raw observation itself contradicts the requested transfer.
            results = ((_OBLIGATION_EFFECT, "contradicted"),
                       (_OBLIGATION_RESPONSE, "contradicted"),
                       (_OBLIGATION_SAMPLE, "missing"),
                       (_OBLIGATION_TOKEN, "missing"))
        else:
            # faulted/refused/uncertain without a contradicting observation:
            # the needed proof was not obtained here.
            results = ((_OBLIGATION_EFFECT, "missing"),
                       (_OBLIGATION_RESPONSE, "missing"),
                       (_OBLIGATION_SAMPLE, "missing"),
                       (_OBLIGATION_TOKEN, "missing"))
        return EffectEvidence(
            key=issue.handle.key,
            status=combine_status(tuple(value for _, value in results)),
            scope="component_semantic_effect",
            binding_sha256=self._binding_sha256,
            semantic_contract_sha256=self._semantic.sha256_hex,
            source_refs=(issue.request.source_ref,),
            native_refs=(),
            destination_refs=(),
            obligation_results=tuple(sorted(results)),
        )

    # -- lifecycle --------------------------------------------------------
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._issuance.close()
        self._issues.clear()
        self._key_index.clear()
        self._states.clear()
        self._raw.clear()

    def __len__(self) -> int:
        return len(self._issues)


# ---------------------------------------------------------------------------
# Software-only fixture (unreachable from the production factory)
# ---------------------------------------------------------------------------

class _FixtureSession:
    """Software-only stand-in for ``GeneratedApb3RegisterSession``.

    It is **not** the real class, it never starts a process and it can never be
    admitted by :func:`bind_storage_adapter`.  It exposes the same attribute
    names the provider reads on the real session so the phase/ordering checks
    run over the very same code path.
    """

    software_fixture = True

    def __init__(self, artifact, *, program, max_ticks):
        if type(max_ticks) is not int or not 1 <= max_ticks <= 65536:
            raise ValueError("software fixture requires a bounded tick cost")
        if type(program) is not list:
            raise ValueError("software fixture requires an explicit program")
        self.artifact = artifact
        self.base_dir = _ROOT
        self.cache_dir = _ROOT
        self.process = None
        self.reset_epoch = 0
        self.local_ticks = 0
        self._execution = "software-fixture-execution-1"
        self._case_id = "software-fixture-case"
        self._samples = []
        self.max_local_ticks_per_register_access = max_ticks
        self.calls = []
        self.program = list(program)
        self.cursor = 0

    def identity_document(self) -> dict:
        return {"schema_version": "software_apb3_fixture_session_identity.v1",
                "software_only": True, "calls": len(self.calls),
                "program_entries": len(self.program)}

    def reset_local(self) -> dict:
        """Fixture-only reset: a new epoch, exactly like the real session."""
        self.reset_epoch += 1
        self._samples.clear()
        return {"cancelled_responses": 0}

    def _next(self) -> dict:
        if self.cursor >= len(self.program):
            raise _DriverRefused("software-fixture-program-exhausted")
        entry = self.program[self.cursor]
        self.cursor += 1
        return entry

    def routed_register_access(self, source_transaction, *, address, offset,
                               write, value, be, delivery_context):
        self.calls.append({"address": address, "offset": offset,
                           "write": bool(write), "value": value, "be": be,
                           "context": dict(delivery_context)})
        entry = self._next()
        if entry.get("driver_refusal"):
            raise _DriverRefused("software-fixture-driver-refusal")
        trace = self.artifact.runtime_document["base_protocol_trace"]
        for phase in entry["phases"]:
            if phase == "setup":
                level = {"psel": 1, "penable": 0, "pready": 0, "pslverr": 0}
            elif phase in ("access", "wait"):
                level = {"psel": 1, "penable": 1, "pready": 0, "pslverr": 0}
            elif phase == "response":
                level = {"psel": 1, "penable": 1, "pready": 1,
                         "pslverr": int(bool(entry.get("error", False)))}
            elif phase == "idle":
                level = {"psel": 0, "penable": 0, "pready": 0, "pslverr": 0}
            else:
                raise ValueError("software fixture phase unsupported")
            self.local_ticks += 1
            backend = {trace["signals"][role]: 0 for role in _APB3_ROLES}
            backend[trace["signals"]["paddr"]] = offset
            backend[trace["signals"]["pwrite"]] = int(bool(write))
            backend[trace["signals"]["pwdata"]] = value if write else 0
            backend[trace["signals"]["psel"]] = level["psel"]
            backend[trace["signals"]["penable"]] = level["penable"]
            backend[trace["signals"]["pready"]] = level["pready"]
            backend[trace["signals"]["pslverr"]] = level["pslverr"]
            backend[trace["signals"]["prdata"]] = entry["rdata"]
            self._samples.append({
                "local_tick": self.local_ticks,
                "pre": {"backend": dict(backend)},
                "post": {"backend": dict(backend)},
            })
        if entry.get("fault_after_ticks") is True:
            raise RuntimeError("software-fixture-driver-fault")
        return {"rdata": entry["rdata"],
                "target_access_id": "software-fixture:%d" % len(self.calls),
                "target_context_schema_version": "software_fixture.v1",
                "source_authenticated": False}


class _SoftwareStorageFixture:
    """Explicit software-only fixture pair (session + bound adapter)."""

    def __init__(self, *, component, artifact, route, program, max_ticks=12):
        self.session = _FixtureSession(artifact, program=program,
                                       max_ticks=max_ticks)
        self.bound = _build_bound_adapter(
            component=component, session=self.session, route=route,
            selection=None, software_only=True)

    @property
    def provider(self):
        return self.bound.provider

    def program(self, entries) -> None:
        """Replace the remaining fixture driver program (fixtures only)."""
        self.session.program = list(entries)
        self.session.cursor = 0


def _software_storage_fixture(*, component, artifact, route, program,
                              max_ticks: int = 12) -> _SoftwareStorageFixture:
    """Module-private software-only fixture hook; production never calls it."""
    return _SoftwareStorageFixture(component=component, artifact=artifact,
                                   route=route, program=program,
                                   max_ticks=max_ticks)


# ---------------------------------------------------------------------------
# Bound adapter and the production factory
# ---------------------------------------------------------------------------

def _binding_digest(*, component, session, selection, route, facts,
                    semantic, trace, software_only) -> str:
    try:
        session_identity = session.identity_document()
    except (AttributeError, ValueError, TypeError):
        session_identity = {"unavailable": _qualified(type(session))}
    return _digest({
        "schema_version": "apb3_storage_adapter_binding.v1",
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "software_only": bool(software_only),
        "implementation_sha256": _IMPLEMENTATION_PIN,
        "component_instance_id": component.instance_id,
        "component_artifact_sha256": component.artifact_sha256,
        "component_semantic_contract_sha256": component.semantic_contract_sha256,
        "endpoint_id": facts.endpoint_id,
        "semantic_contract_sha256": semantic.sha256_hex,
        "facts_sha256": facts.sha256(),
        "route_sha256": None if route is None else route.sha256(),
        "session_class": _qualified(type(session)),
        "session_identity_sha256": _digest(session_identity),
        "session_object": id(session),
        "session_abi": [[name, code.co_firstlineno, code.co_filename]
                        for name, (_, code) in sorted(_SESSION_METHODS.items())],
        "issuer_class": _qualified(_ISSUER_CLASS),
        "issuer_module_sha256": _MODULE_PINS[
            "myfuzz.scenario.apb_storage_register_version"],
        "selection_sha256": None if selection is None else selection.sha256(),
        "selection_implementation_sha256":
            None if selection is None else selection.implementation_sha256,
        "trace_sha256": _digest(trace),
    })


def _build_bound_adapter(*, component, session, route, selection,
                         software_only: bool) -> "BoundStorageAdapter":
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    endpoint = descriptor_target_endpoint(component)
    artifact = getattr(session, "artifact", None)
    if artifact is None:
        _refuse("generic-source-unverified", "/session",
                {"reason": "session-carries-no-artifact"})
    template = tuple(endpoint["template"])
    registered, semantic, facts, trace = artifact_contract_facts(
        artifact, base_dir=Path(getattr(session, "base_dir", _ROOT)),
        endpoint_id=endpoint["endpoint_id"], template=template)
    _check_component_matches_live(component, artifact=artifact,
                                  endpoint=endpoint, semantic=semantic)
    if route is not None:
        _check_route(route, artifact=artifact, facts=facts)
    binding = _binding_digest(component=component, session=session,
                              selection=selection, route=route, facts=facts,
                              semantic=semantic, trace=trace,
                              software_only=software_only)
    provider = StorageTargetProvider(
        component=component, artifact=artifact, session=session, route=route,
        facts=facts, registered=registered, semantic=semantic, trace=trace,
        binding_sha256=binding, software_only=software_only)
    bound = BoundStorageAdapter(component=component, session=session,
                                selection=selection, provider=provider,
                                endpoint=endpoint, semantic=semantic,
                                binding_sha256=binding)
    provider.assert_bound()
    return bound


class BoundStorageAdapter:
    """Process-local binding of one admitted storage target to its real session.

    No JSON round-trip restores it: the object holds the live session, the
    re-derived semantic contract and the issued operation registry.
    """

    __slots__ = ("component_instance_id", "adapter_id", "adapter_version",
                 "endpoint_id", "provider", "semantic_contract",
                 "binding_sha256", "_session", "_selection", "_closed")

    def __init__(self, *, component, session, selection, provider, endpoint,
                 semantic, binding_sha256):
        self.component_instance_id = component.instance_id
        self.adapter_id = STORAGE_ADAPTER_ID
        self.adapter_version = STORAGE_ADAPTER_VERSION
        self.endpoint_id = endpoint["endpoint_id"]
        self.provider = provider
        self.semantic_contract = semantic
        self.binding_sha256 = binding_sha256
        self._session = session
        self._selection = selection
        self._closed = False

    @property
    def software_only(self) -> bool:
        return self.provider.software_only

    def assert_current(self) -> None:
        if self._closed:
            _refuse("generic-provider-closed", "/adapter",
                    {"reason": "adapter-closed"})
        self.provider.assert_bound()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.provider.close()


def target_endpoint_id(component: VerifiedComponent) -> str:
    """The certified target endpoint id of one storage component."""
    return descriptor_target_endpoint(component)["endpoint_id"]


def bind_storage_adapter(*, component, session, selection,
                         route=None, preparation=None) -> BoundStorageAdapter:
    """Production factory: only the exact real session class is accepted.

    ``route`` is the declared CPU->target route for this register (see
    ``TargetRoute``).  Without it the adapter still binds its artifact-derived
    facts, but every ``prepare`` refuses ``generic-route-refused``.

    When the issuing ``preparation`` is supplied as well, the route must be
    byte-identical to the route derived from that preparation's same-pass D3
    document; a caller-supplied window base or register is then refused instead
    of trusted.  The binding layer is responsible for passing it.
    """
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    if type(session) is not _SESSION_CLASS:
        _refuse("generic-binding-drift", "/session",
                {"reason": "exact-GeneratedApb3RegisterSession-required",
                 "actual": _qualified(type(session))})
    if type(selection) is not AdapterSelection:
        _refuse("generic-contract-type", "/selection")
    if route is not None and type(route) is not TargetRoute:
        _refuse("generic-contract-type", "/route", {"expected": "TargetRoute"})
    try:
        _check_pins()
    except ValueError as error:
        _refuse("generic-binding-drift", "/adapter",
                {"reason": str(error)[:160]})
    _check_selection(selection, component=component,
                     implementation_pin=_registry_implementation_pin(
                         STORAGE_ADAPTER_ID))
    if preparation is not None:
        from ..preparation import PreparationContext
        if type(preparation) is not PreparationContext:
            _refuse("generic-contract-type", "/preparation")
        preparation.require_open()
        preparation.require_component(component)
        declared = declare_target_route(
            preparation=preparation, component=component,
            endpoint_id=target_endpoint_id(component))
        if route is None:
            route = declared
        elif declared.sha256() != route.sha256():
            _refuse("generic-route-refused", "/route",
                    {"reason": "route-differs-from-same-pass-declaration",
                     "declared_sha256": declared.sha256(),
                     "supplied_sha256": route.sha256()})
    authority = _registered_authority(session)
    if type(authority) is not _ISSUER_CLASS or authority.target is not session:
        _refuse("generic-binding-drift", "/session",
                {"reason": "storage-version-authority-not-registered"})
    return _build_bound_adapter(component=component, session=session,
                                route=route, selection=selection,
                                software_only=False)


_ROUTE_ACCESS_KEYS = ("schema_version", "source_component", "source_endpoint",
                      "target_component", "target_endpoint", "device_id",
                      "register", "field", "register_offset", "address",
                      "window_base", "window_size", "window_alignment",
                      "access_alignment", "width_bytes", "byte_enable_domain",
                      "allowed_byte_enables", "operation", "value_origin",
                      "register_origin", "value_mask")


def _route_int(value, pointer: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _refuse("generic-route-refused", pointer,
                {"expected": "int", "minimum": minimum, "maximum": maximum})
    return value


def declare_target_route(*, preparation, component: VerifiedComponent,
                         endpoint_id: str) -> TargetRoute:
    """Derive the declared route from the *same-pass* prepared D3 document.

    This is the binding-layer hook G4/G5 use: exactly one executable F4 path of
    the same preparation must declare one ``register_access`` row for this
    component's endpoint.  Nothing is guessed from a register or instance name.
    """
    from ..preparation import PreparationContext
    if type(preparation) is not PreparationContext:
        _refuse("generic-contract-type", "/preparation")
    preparation.require_open()
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    preparation.require_component(component)
    artifact = preparation.artifact(component.instance_id)
    rows = [row for row in component.endpoints() if row["endpoint_id"] == endpoint_id]
    if len(rows) != 1:
        _refuse("generic-route-refused", "/endpoint_id",
                {"reason": "certified-endpoint-required",
                 "endpoint_id": endpoint_id, "matches": len(rows)})
    endpoint = rows[0]
    if endpoint["role"] != "target" or tuple(endpoint["protocol"]) != ("apb", "3"):
        _refuse("generic-route-refused", "/endpoint_id",
                {"reason": "apb3-target-endpoint-required",
                 "role": endpoint["role"], "protocol": endpoint["protocol"]})
    observation = artifact.runtime_document.get("storage_observation")
    selection = observation.get("selection") if isinstance(observation, dict) else None
    if type(selection) is not dict or type(selection.get("register")) is not str:
        _refuse("generic-route-refused", "/storage_observation/selection",
                {"reason": "explicit-storage-selection-required"})
    try:
        compiled = preparation.compiled_inputs()["compiled"]
    except (KeyError, TypeError):
        _refuse("generic-route-refused", "/preparation/d3",
                {"reason": "same-pass-compiled-document-required"})
    paths = compiled.get("paths") if isinstance(compiled, dict) else None
    if type(paths) is not list:
        _refuse("generic-route-refused", "/preparation/d3/paths",
                {"reason": "compiled-paths-required"})
    matches = []
    for path in paths:
        if not isinstance(path, dict):
            continue
        if path.get("flow_id") != "F4" or path.get("status") != "executable":
            continue
        target = path.get("target")
        if not isinstance(target, dict) or target.get("component") != (
                component.instance_id):
            continue
        for source in path.get("sources") or ():
            access = source.get("register_access") if isinstance(source, dict) else None
            if not isinstance(access, dict):
                continue
            if (access.get("target_component") != component.instance_id
                    or access.get("target_endpoint") != endpoint_id):
                continue
            matches.append((path, access))
    if len(matches) != 1:
        _refuse("generic-route-refused", "/paths",
                {"reason": "one-declared-register-route-required",
                 "instance_id": component.instance_id,
                 "endpoint_id": endpoint_id, "matches": len(matches)})
    path, access = matches[0]
    if type(access) is not dict or set(access) != set(_ROUTE_ACCESS_KEYS):
        _refuse("generic-route-refused", "/paths/register_access",
                {"reason": "closed-register-route-required"})
    if access["schema_version"] != "register_source_access.v1":
        _refuse("generic-route-refused", "/paths/register_access/schema_version",
                {"expected": "register_source_access.v1"})
    if access["register"] != selection["register"]:
        _refuse("generic-route-refused", "/paths/register_access/register",
                {"reason": "route-register-does-not-match-certified-register",
                 "route": access["register"],
                 "certified": selection["register"]})
    if access["field"] != "value":
        _refuse("generic-route-refused", "/paths/register_access/field",
                {"reason": "whole-register-value-route-required"})
    if (access["value_origin"] != "cpu_transaction_wdata"
            or access["register_origin"] != "bound_target_register_commit"):
        _refuse("generic-route-refused", "/paths/register_access/origin",
                {"reason": "cpu-write-commit-route-required"})
    if access["operation"] not in ("read", "write"):
        _refuse("generic-route-refused", "/paths/register_access/operation")
    if access["byte_enable_domain"] != "target_word_lanes":
        _refuse("generic-route-refused",
                "/paths/register_access/byte_enable_domain",
                {"expected": "target_word_lanes"})
    window_base = _route_int(access["window_base"],
                             "/paths/register_access/window_base",
                             minimum=0, maximum=(1 << 32) - 1)
    window_size = _route_int(access["window_size"],
                             "/paths/register_access/window_size",
                             minimum=4, maximum=1 << 32)
    _route_int(access["window_alignment"],
               "/paths/register_access/window_alignment", minimum=1,
               maximum=1 << 32)
    offset = _route_int(access["register_offset"],
                        "/paths/register_access/register_offset",
                        minimum=0, maximum=window_size - 1)
    address = _route_int(access["address"], "/paths/register_access/address",
                         minimum=0, maximum=(1 << 32) - 1)
    if address != window_base + offset:
        _refuse("generic-route-refused", "/paths/register_access/address",
                {"reason": "route-address-must-equal-window-base-plus-offset"})
    alignment = _route_int(access["access_alignment"],
                           "/paths/register_access/access_alignment",
                           minimum=1, maximum=4096)
    width_bytes = _route_int(access["width_bytes"],
                             "/paths/register_access/width_bytes",
                             minimum=1, maximum=8)
    enables = access["allowed_byte_enables"]
    if (type(enables) is not list or not enables
            or any(type(value) is not int or value <= 0 for value in enables)):
        _refuse("generic-route-refused",
                "/paths/register_access/allowed_byte_enables")
    if window_size != artifact.plan.profile.address.window_size:
        _refuse("generic-route-refused", "/paths/register_access/window_size",
                {"reason": "route-window-differs-from-profile-window",
                 "profile_window": artifact.plan.profile.address.window_size,
                 "route_window": window_size})
    endpoint_rows = [row for row in path.get("endpoints") or ()
                     if isinstance(row, dict)
                     and row.get("instance_id") == component.instance_id
                     and row.get("endpoint_id") == endpoint_id]
    if (len(endpoint_rows) != 1
            or tuple(endpoint_rows[0].get("protocol") or ()) != ("apb", "3")
            or endpoint_rows[0].get("function") != "mmio_slave"):
        _refuse("generic-route-refused", "/paths/endpoints",
                {"reason": "prepared-path-apb3-mmio-slave-endpoint-required"})
    return TargetRoute(
        path_id=path["path_id"],
        device_id=access["device_id"],
        endpoint_id=access["target_endpoint"],
        window_base=window_base,
        window_size=window_size,
        register=access["register"],
        register_offset=offset,
        access_alignment=alignment,
        width_bytes=width_bytes,
        allowed_byte_enables=tuple(enables),
        declared_value_mask=_route_int(access["value_mask"],
                                       "/paths/register_access/value_mask",
                                       minimum=1, maximum=(1 << 32) - 1),
        declared_operation=access["operation"],
    )


def registration_document() -> dict:
    """Documentary description of this adapter implementation."""
    return {
        "schema_version": "generic_adapter_implementation.v1",
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "implementation_sha256": implementation_sha256(),
        "implementation_pin": _IMPLEMENTATION_PIN,
        "session_class": _qualified(_SESSION_CLASS),
        "issuer_class": _qualified(_ISSUER_CLASS),
        "role": "target",
        "protocol": ["apb", "3"],
        "semantic_kinds": [STORAGE_RW],
        "operations": ["read", "write"],
        "transport": {"host_alignment_bytes": _HOST_ALIGNMENT_BYTES,
                      "register_bytes": _FULL_WORD_BYTES,
                      "byte_enable": _FULL_WORD_BYTE_ENABLE},
        "software_only": False,
    }
