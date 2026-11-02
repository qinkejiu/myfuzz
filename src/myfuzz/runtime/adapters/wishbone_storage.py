"""Wishbone stable-storage target adapter and bounded target provider (G8.1).

Scope, stated honestly
----------------------
This module binds one already-admitted Wishbone ``storage.rw.v1`` target
component (the registered ``zipcpu-wbuart.setup.storage.v1`` row: word-index 0
of the ZipCPU ``wbuart``, ``target.wishbone/1/word-addressed-registered-ack``)
to the **real** ``GeneratedWishboneRegisterSession`` and offers the
``TargetProvider`` surface of the generic runtime design.

* ``prepare`` checks the declared route, the byte->word index conversion, the
  real alias rule, transport alignment, the full-word shape (``sel = 4'b1111``)
  and the provider budget without touching the IP.  Same key + same canonical
  payload returns the same issued handle; same key + different payload refuses
  ``generic-plan-mismatch``.
* ``advance`` drives one atomic access through the *existing* session transport
  (``read_register`` / ``write_register`` -> ``command('ACCESS_WB_REG', ...)``)
  and validates the measured Wishbone pre/post tick span itself: ``CYC`` held
  through ``ACK``, one ``STB`` pulse, ``adr`` equal to the converted word
  index, ``we``/``dat_w``/``sel`` on the request, no ``STALL`` observed, one
  ``ACK`` and ``dat_r`` for reads.  Nothing is simulated in Python.
* ``complete`` returns ``EffectEvidence`` over this provider's raw observation
  index and refuses a second (duplicate) completion of the same handle.  The
  native sample join and the storage-version token belong to the sibling
  consumer (``generated_wishbone_storage_consumer``) and are never certified
  here.

Byte -> word index
------------------
Wishbone ``adr`` is a **word index** while the host/session API is byte
addressed.  The conversion ``word = (address - window_base) >> 2`` is derived in
:func:`declare_target_route` (via ``wishbone_word_index``) and stored in the
route document as ``word_index``; :class:`WishboneTargetRoute` re-checks that
self-consistency in ``__post_init__``, so a route whose recorded word index does
not match its byte offset cannot be constructed.  ``compiled_paths`` keeps
carrying byte addresses.

Trust
-----
:func:`bind_wishbone_storage_adapter` accepts the real
``GeneratedWishboneRegisterSession`` or a caller-supplied **subclass** of it
(the sibling storage session that adds routed-context hooks), but never a class
that replaces the measured transport: the inherited ``command``/``_take``/
``_access``/``read_register``/``write_register`` methods must still be the base
implementations, and any class flagged ``software_fixture`` is refused.  A
software test double exists only behind the module-private
``_software_wishbone_storage_fixture`` hook and never claims a native effect.

The process-local single-use operation authority is a ``ProcessLocalIssuance``
supplied by the binding layer; the provider never issues or consumes the native
``WishboneStorageRegisterVersionAuthority`` token.  No RTL, Verilator build or
native process is started here: ``advance`` on a real session refuses *before*
the driver hook when the session has no live process.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
import sys

from myfuzz.local_harness.wishbone_register_session import (
    GeneratedWishboneRegisterSession,
)
from myfuzz.local_harness.wishbone_storage_source_contract import (
    registered_wishbone_storage_source_contracts,
    select_wishbone_storage_source_contract,
    validate_wishbone_storage_source_contract,
    wishbone_setup_matches,
    wishbone_word_index,
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
from ..semantics.storage import storage_register_facts
from .contracts import (
    PreparedTargetOperation,
    ProviderProgress,
    TargetRequest,
    operation_id_for,
    request_digest,
)

STORAGE_ADAPTER_ID = "wishbone.storage.v1"
STORAGE_ADAPTER_VERSION = "1"

# Declared transport facts of the registered Wishbone storage row.
WISHBONE_STORAGE_PROTOCOL = ("wishbone", "classic")
WISHBONE_STORAGE_TEMPLATE = ("target.wishbone", "1",
                             "word-addressed-registered-ack")
WISHBONE_STORAGE_SEMANTIC_KIND = STORAGE_RW
WISHBONE_STORAGE_COMPLETION_KIND = "registered_ack"
WISHBONE_STORAGE_ADDRESS_UNITS = "word"
WISHBONE_STORAGE_ISSUER_ID = "WishboneStorageRegisterVersionAuthority"
WISHBONE_STORAGE_OBSERVATION_SCHEMA = "wishbone_storage_probe.v1"

_REQUEST_ROLES = ("cyc", "stb", "we", "adr", "dat_w", "sel")
_RESPONSE_ROLES = ("ack", "dat_r", "stall")
_ROLE_WIDTHS = MappingProxyType({"cyc": 1, "stb": 1, "we": 1, "dat_w": 32,
                                "sel": 4, "ack": 1, "stall": 1, "dat_r": 32})

_WORD_BYTES = 4
_FULL_WORD_BYTE_ENABLE = 0xF
_MAX_OPERATIONS = 4096
_MAX_SAMPLES = 65536

_RAW_COMMAND = "wishbone_storage_command"
_RAW_TICK = "wishbone_storage_tick_sample"
_SOFTWARE_RAW_COMMAND = "software_wishbone_storage_command"
_SOFTWARE_RAW_TICK = "software_wishbone_storage_tick_sample"

_OBLIGATION_RESPONSE = "wishbone_target_response"
_OBLIGATION_EFFECT = "component_semantic_effect"
_OBLIGATION_SAMPLE = "physical_protocol_sample"
_OBLIGATION_TOKEN = "storage_version_token"

_SELECTION_KEYS = frozenset({"endpoint_id", "contract_id", "register"})
_SOURCE_CONTRACT_SELECTION_KEYS = frozenset({"contract_id", "register"})


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

# Modules whose exact bytes back this adapter's trust claim.  The witnesses that
# a sibling task owns (probe contract/verification, version authority, consumer,
# template) are pinned *as available*: they enter the digest the moment they
# exist, so landing them changes the implementation identity instead of silently
# widening this adapter's claim.
_PINNED_MODULES = MappingProxyType({
    "myfuzz.local_harness.wishbone_register_session":
        "src/myfuzz/local_harness/wishbone_register_session.py",
    "myfuzz.local_harness.tlul_register_session":
        "src/myfuzz/local_harness/tlul_register_session.py",
    "myfuzz.local_harness.wishbone_storage_source_contract":
        "src/myfuzz/local_harness/wishbone_storage_source_contract.py",
    "myfuzz.runtime.semantics.contracts":
        "src/myfuzz/runtime/semantics/contracts.py",
    "myfuzz.runtime.semantics.storage": "src/myfuzz/runtime/semantics/storage.py",
    "myfuzz.runtime.adapters.contracts":
        "src/myfuzz/runtime/adapters/contracts.py",
    "myfuzz.runtime.adapters.wishbone_storage":
        "src/myfuzz/runtime/adapters/wishbone_storage.py",
})
_WITNESS_MODULES = MappingProxyType({
    "myfuzz.local_harness.wishbone_storage_probe_contract":
        "src/myfuzz/local_harness/wishbone_storage_probe_contract.py",
    "myfuzz.local_harness.wishbone_storage_probe_verification":
        "src/myfuzz/local_harness/wishbone_storage_probe_verification.py",
    "myfuzz.scenario.wishbone_storage_register_version":
        "src/myfuzz/scenario/wishbone_storage_register_version.py",
    "myfuzz.integration.generated_wishbone_storage_consumer":
        "src/myfuzz/integration/generated_wishbone_storage_consumer.py",
    "myfuzz.local_harness.wishbone_register_template":
        "src/myfuzz/local_harness/wishbone_register_template.py",
})


def _file_sha(relative: str) -> str:
    try:
        return sha256((_ROOT / relative).read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError(
            "wishbone-storage-adapter-drift:unreadable:" + relative) from error


def _available_pins(modules) -> dict:
    pins = {}
    for module_name, relative in sorted(modules.items()):
        if (_ROOT / relative).is_file():
            pins[module_name] = _file_sha(relative)
    return pins


_DEPENDENCIES = {
    "GeneratedWishboneRegisterSession": GeneratedWishboneRegisterSession,
    "select_wishbone_storage_source_contract":
        select_wishbone_storage_source_contract,
    "validate_wishbone_storage_source_contract":
        validate_wishbone_storage_source_contract,
    "wishbone_word_index": wishbone_word_index,
    "wishbone_setup_matches": wishbone_setup_matches,
    "registered_wishbone_storage_source_contracts":
        registered_wishbone_storage_source_contracts,
    "storage_register_facts": storage_register_facts,
}
_PINNED = MappingProxyType({name: _pin(value)
                            for name, value in _DEPENDENCIES.items()})
_ORIGINS = MappingProxyType({name: value.__module__
                             for name, value in _DEPENDENCIES.items()})

_SESSION_CLASS = GeneratedWishboneRegisterSession
# Transport methods a binding may inherit but never replace: a subclass may add
# routed-context hooks, it may not fake the measured tick stream.
_SESSION_TRANSPORT = MappingProxyType({
    name: (getattr(_SESSION_CLASS, name), getattr(_SESSION_CLASS, name).__code__)
    for name in ("command", "_take", "_access", "read_register", "write_register",
                 "step_local", "reset_local", "begin_case", "identity_document")
})
_MODULE_PINS = MappingProxyType({name: _file_sha(relative)
                                 for name, relative in _PINNED_MODULES.items()})
_WITNESS_PINS = MappingProxyType(_available_pins(_WITNESS_MODULES))


def witness_modules_present() -> tuple[str, ...]:
    """Names of the sibling witness modules that exist in this checkout."""
    return tuple(sorted(_WITNESS_PINS))


def verifier_identity() -> dict:
    """Identity of the source verifier behind the registered storage row."""
    files = dict(_MODULE_PINS)
    files.update(_WITNESS_PINS)
    return {"id": "wishbone-storage-source.v1", "version": "1",
            "implementation_sha256": _digest(files)}


def issuer_identity() -> dict:
    """Documentary identity of the (sibling-owned) version issuer."""
    module = "myfuzz.scenario.wishbone_storage_register_version"
    relative = _WITNESS_MODULES[module]
    pin = _WITNESS_PINS.get(module, _digest({"pending": relative}))
    return {"issuer_id": WISHBONE_STORAGE_ISSUER_ID, "version": "1",
            "implementation_sha256": pin}


def implementation_sha256() -> str:
    """Adapter implementation identity: own module plus every trusted dependency."""
    return _digest({
        "schema_version": "wishbone_storage_adapter_implementation.v1",
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "session_class": _qualified(_SESSION_CLASS),
        "issuer_class": WISHBONE_STORAGE_ISSUER_ID,
        "files": {name: _file_sha(relative)
                  for name, relative in sorted(_PINNED_MODULES.items())},
        "witness_files": dict(_WITNESS_PINS),
    })


_IMPLEMENTATION_PIN = implementation_sha256()


def _check_pins() -> None:
    """Import-time pins re-checked at every bind/stability boundary."""
    for name, (value, code) in _PINNED.items():
        current = globals().get(name)
        if current is not value or (code is not None
                                    and getattr(value, "__code__", None) is not code):
            raise ValueError("wishbone-storage-adapter-drift:" + name)
        origin = sys.modules.get(_ORIGINS[name])
        if origin is not None and getattr(origin, name, None) is not value:
            raise ValueError("wishbone-storage-adapter-drift:" + name)
    for name, (method, code) in _SESSION_TRANSPORT.items():
        if (getattr(_SESSION_CLASS, name, None) is not method
                or getattr(method, "__code__", None) is not code):
            raise ValueError("wishbone-storage-adapter-drift:session." + name)
    for module_name, relative in _PINNED_MODULES.items():
        if sys.modules.get(module_name) is None:
            raise ValueError("wishbone-storage-adapter-drift:module:" + module_name)
        if _file_sha(relative) != _MODULE_PINS[module_name]:
            raise ValueError("wishbone-storage-adapter-drift:module:" + module_name)
    for module_name, digest in _WITNESS_PINS.items():
        relative = _WITNESS_MODULES[module_name]
        if not (_ROOT / relative).is_file():
            raise ValueError("wishbone-storage-adapter-drift:witness-vanished:"
                             + module_name)
        if _file_sha(relative) != digest:
            raise ValueError("wishbone-storage-adapter-drift:witness:"
                             + module_name)
    # A witness module that appears *after* this process imported the adapter is
    # a new identity, not a mutation: it enters the pin only on re-import (and
    # ``implementation_sha256`` therefore stays stable within one process).
    if implementation_sha256() != _IMPLEMENTATION_PIN:
        raise ValueError("wishbone-storage-adapter-drift:implementation")


def _registry_registration(adapter_id: str):
    """The code-owned registry row for this adapter, when it exists yet."""
    from ..registry import registrations
    rows = [row for row in registrations() if row.adapter_id == adapter_id]
    if len(rows) > 1:
        _refuse("generic-adapter-ambiguous", "/selection",
                {"adapter_id": adapter_id, "matches": len(rows)})
    return rows[0] if rows else None


def registration_state() -> dict:
    """Code-owned registration state; ``registered`` is False until the lead wires it."""
    row = _registry_registration(STORAGE_ADAPTER_ID)
    return {
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "registered": row is not None,
        "registry_implementation_sha256": None if row is None
        else row.implementation_sha256(),
        "module_implementation_sha256": _IMPLEMENTATION_PIN,
    }


def selection_implementation_pin() -> tuple[str, bool]:
    """``(pin the selection must carry, registry_registered)``.

    Once the lead adds the ``wishbone.storage.v1`` row the selection is issued
    against that registry pin; until then this module's own implementation
    identity is the only code-owned pin a selection can carry, and it is marked
    ``registered=False`` so the integration layer can refuse an unregistered
    plan.
    """
    row = _registry_registration(STORAGE_ADAPTER_ID)
    if row is None:
        return (_IMPLEMENTATION_PIN, False)
    return (row.implementation_sha256(), True)


def _check_selection(selection: AdapterSelection, *,
                     component: VerifiedComponent) -> tuple[str, bool]:
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
# Byte -> word index conversion
# ---------------------------------------------------------------------------

def _word_index(byte_offset, pointer: str = "/route/register_offset") -> int:
    """Host byte offset -> Wishbone word index, refusing every non-word offset."""
    try:
        return wishbone_word_index(byte_offset)
    except ValueError as error:
        _refuse("generic-route-refused", pointer,
                {"reason": str(error)[:160]})


def _verify_storage_observation(observation, artifact, *, base_dir: Path,
                                endpoint_id: str) -> dict:
    """Re-derive one closed probe document against the artifact bytes.

    The sibling verifier owns this derivation; it refuses a tampered digest,
    port, expression, source contract, selection or trace, and any claim of
    hierarchy/native proof.  A fully documented prospective probe returns
    ``None`` there and still gives this adapter its explicit selection.
    """
    try:
        from myfuzz.local_harness.wishbone_storage_probe_verification import (
            verified_wishbone_storage_observation)
    except ImportError:
        _refuse("generic-source-unverified", "/artifact/storage_observation",
                {"reason": "wishbone-storage-probe-verification-unavailable"})
    if (type(observation) is not dict
            or observation.get("schema_version") != WISHBONE_STORAGE_OBSERVATION_SCHEMA
            or observation.get("scope") != "generated_expression_source_mapped"):
        _refuse("generic-semantic-unsupported", "/artifact/storage_observation",
                {"reason": "closed-wishbone-storage-observation-required"})
    selection = observation.get("selection")
    if (type(selection) is not dict or set(selection) != _SELECTION_KEYS
            or any(type(selection[key]) is not str or not selection[key]
                   for key in _SELECTION_KEYS)
            or selection.get("endpoint_id") != endpoint_id):
        _refuse("generic-semantic-unsupported",
                "/artifact/storage_observation/selection",
                {"reason": "explicit-wishbone-storage-selection-required"})
    try:
        verified_wishbone_storage_observation(
            observation, artifact, base_dir=Path(base_dir))
    except (TypeError, ValueError) as error:
        _refuse("generic-source-unverified", "/artifact/storage_observation",
                {"reason": str(error)[:160]})
    return {key: selection[key] for key in _SOURCE_CONTRACT_SELECTION_KEYS}


def _registered_row(*, profile, base_dir: Path, document, artifact,
                    endpoint_id: str) -> dict:
    """Re-validate the code-owned source row against the live profile/bytes.

    The selection is explicit: the artifact's own closed storage observation when
    the probe producer emitted one, otherwise the single registered row.  A
    caller-declared contract id or register name never reaches this function
    unchecked -- the selection is re-derived from the verified probe document (or
    from the single registered row) and ``select_wishbone_storage_source_contract``
    compares it with the registered document and re-reads the pinned source bytes.
    """
    observation = document.get("storage_observation")
    if observation is None:
        rows = registered_wishbone_storage_source_contracts()
        if type(rows) is not tuple or len(rows) != 1:
            _refuse("generic-semantic-unsupported", "/registers",
                    {"reason": "exactly-one-registered-wishbone-storage-row",
                     "registered": list(rows)})
        # The registered document is code-owned; its identity is re-derived by
        # validating the closed row against the live profile and source bytes.
        try:
            return validate_wishbone_storage_source_contract(
                _registered_document(), profile, base_dir=Path(base_dir))
        except (TypeError, ValueError) as error:
            _refuse("generic-source-unverified", "/source_contract",
                    {"reason": str(error)[:160]})
    selection = _verify_storage_observation(
        observation, artifact, base_dir=base_dir, endpoint_id=endpoint_id)
    try:
        registered = select_wishbone_storage_source_contract(
            profile, base_dir=Path(base_dir), selection=selection)
    except (TypeError, ValueError) as error:
        _refuse("generic-source-unverified", "/source_contract",
                {"reason": str(error)[:160]})
    if _canonical(observation.get("source_contract")) != _canonical(registered):
        _refuse("generic-semantic-unsupported", "/artifact/storage_observation",
                {"reason": "probe-embeds-another-source-contract"})
    return registered


def _registered_document() -> dict:
    from myfuzz.local_harness import wishbone_storage_source_contract as module
    return module._registered_document()


def _preparation_base_dir(preparation) -> Path:
    """The checkout root a preparation issued its artifacts against."""
    inputs = getattr(preparation, "inputs", None)
    base = getattr(inputs, "base_dir", None)
    return _ROOT if base is None else Path(base)


# ---------------------------------------------------------------------------
# Semantic contract of the registered Wishbone storage row
# ---------------------------------------------------------------------------

def wishbone_storage_semantic_contract(*, registered: dict, endpoint_id: str,
                                       template: tuple[str, str, str],
                                       observation_scope: str,
                                       observation_native: bool) -> SemanticContract:
    """Closed Wishbone semantics of one validated source row.

    Same document shape as the APB3 storage contract (``storage.rw.v1``), with
    the protocol token, the ``word`` address units and the host word alignment
    that this transport really has.  Transport is not semantics: the kind stays
    ``storage.rw.v1``; the protocol/units fields are what distinguish the row.
    """
    try:
        contract_id = registered["contract_id"]
        source = registered["source"]
        register = registered["register"]
        decode = registered["decode"]
        reset = registered["reset"]
        effects_scope = registered["writers"]["scope"]
    except (KeyError, TypeError) as error:
        _refuse("generic-semantic-unsupported", "/source_contract",
                {"reason": "registered-contract-shape"})
        raise AssertionError from error  # unreachable, keeps type checkers quiet
    if register["width"] != 32:
        _refuse("generic-semantic-unsupported", "/register/width",
                {"expected": 32, "actual": register["width"]})
    if decode.get("address_units") != WISHBONE_STORAGE_ADDRESS_UNITS:
        _refuse("generic-semantic-unsupported", "/decode/address_units",
                {"expected": WISHBONE_STORAGE_ADDRESS_UNITS,
                 "actual": decode.get("address_units")})
    if decode.get("host_alignment_bytes") != _WORD_BYTES:
        _refuse("generic-semantic-unsupported", "/decode/host_alignment_bytes",
                {"expected": _WORD_BYTES,
                 "actual": decode.get("host_alignment_bytes")})
    document = {
        "schema_version": "semantic_contract.v1",
        "kind": STORAGE_RW,
        "source": {
            "contract_id": contract_id,
            "root": source["root"],
            "revision": source["revision"],
            "top_module": source["top_module"],
            "files": dict(sorted(source["files"].items())),
            "verifier": verifier_identity(),
            "identity_basis": source["identity_basis"],
        },
        "endpoint": {
            "endpoint_id": endpoint_id,
            "role": "target",
            "protocol": list(WISHBONE_STORAGE_PROTOCOL),
            "template": list(template),
            "semantic_kind": STORAGE_RW,
        },
        "decode": {
            "address_width": decode["address_width"],
            "address_units": WISHBONE_STORAGE_ADDRESS_UNITS,
            "alignment_bytes": decode["host_alignment_bytes"],
            "mask": decode["mask"],
            "value": decode["value"],
            "alias_period_bytes": decode["alias_period_bytes"],
            "expression": decode["expression"],
        },
        "operations": [
            {
                "operation": "read",
                "width_bits": register["width"],
                "read_mask": register["read_mask"],
                "write_mask": 0,
                # The RTL implements per-lane selects; the runtime contract of
                # this row is full-word only, and the provider refuses any
                # sel != 4'b1111 instead of pretending partial writes work.
                "byte_enable": True,
                "value_origin": "target_register_read",
            },
            {
                "operation": "write",
                "width_bits": register["width"],
                "read_mask": register["read_mask"],
                "write_mask": register["write_mask"],
                "byte_enable": True,
                "value_origin": "cpu_transaction_wdata",
            },
        ],
        "reset": {
            "declared": True,
            "port": reset["port"],
            "polarity": reset["polarity"],
            "observed": False,
            "evidence_ref": None,
            "case_begin_is_reset": False,
        },
        "side_effects": [{
            "kind": "stable_storage",
            "scope": effects_scope + " (registered Wishbone row only; UART RX/TX "
                     "state, FIFOs, serial pins and interrupts excluded)"}],
        "observations": [
            {"name": "storage_probes",
             "layer": "component_semantic_effect",
             "native": bool(observation_native),
             "reference": observation_scope}
        ],
        "issuer_contract": {
            "issuer_id": WISHBONE_STORAGE_ISSUER_ID,
            "version": "1",
            "implementation_sha256": issuer_identity()["implementation_sha256"],
            "token_scope": "existing_process_local_single_use",
            "single_use": True,
            "authority": False,
        },
    }
    return SemanticContract.freeze(document)


# ---------------------------------------------------------------------------
# Static facts
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class WishboneStorageFacts:
    """Facts re-derived from the live artifact, profile and source row."""

    instance_id: str
    endpoint_id: str
    source_contract_id: str
    source_contract_digest: str
    register: str
    canonical_offset: int
    word_index: int
    register_width: int
    read_mask: int
    write_mask: int
    address_units: str
    address_width: int
    window_bytes: int
    window_alignment_bytes: int
    alias_period_bytes: int
    host_alignment_bytes: int
    decode_mask: int
    decode_value: int
    expression: str
    reset_port: str
    reset_observed: bool
    trace_roles: tuple[tuple[str, int], ...]
    max_wait_cycles: int
    observation_scope: str
    storage_observation_present: bool
    stall_policy: str
    has_error: bool

    def document(self) -> dict:
        return {
            "instance_id": self.instance_id,
            "endpoint_id": self.endpoint_id,
            "source_contract_id": self.source_contract_id,
            "source_contract_digest": self.source_contract_digest,
            "register": self.register,
            "canonical_offset": self.canonical_offset,
            "word_index": self.word_index,
            "register_width": self.register_width,
            "read_mask": self.read_mask,
            "write_mask": self.write_mask,
            "address_units": self.address_units,
            "address_width": self.address_width,
            "window_bytes": self.window_bytes,
            "window_alignment_bytes": self.window_alignment_bytes,
            "alias_period_bytes": self.alias_period_bytes,
            "host_alignment_bytes": self.host_alignment_bytes,
            "decode_mask": self.decode_mask,
            "decode_value": self.decode_value,
            "expression": self.expression,
            "reset_port": self.reset_port,
            "reset_observed": self.reset_observed,
            "trace_roles": [[name, width] for name, width in self.trace_roles],
            "max_wait_cycles": self.max_wait_cycles,
            "observation_scope": self.observation_scope,
            "storage_observation_present": self.storage_observation_present,
            "stall_policy": self.stall_policy,
            "has_error": self.has_error,
        }

    def sha256(self) -> str:
        return _digest({"schema_version": "wishbone_storage_facts.v1",
                        **self.document()})


def descriptor_target_endpoint(component: VerifiedComponent) -> dict:
    """The single certified Wishbone storage target endpoint of one component."""
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    endpoints = [row for row in component.endpoints() if row["role"] == "target"]
    if len(endpoints) != 1:
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "one-target-endpoint-required", "matches": len(endpoints)})
    endpoint = endpoints[0]
    if (tuple(endpoint["protocol"]) != WISHBONE_STORAGE_PROTOCOL
            or endpoint["semantic_kind"] != STORAGE_RW
            or tuple(endpoint["template"]) != WISHBONE_STORAGE_TEMPLATE
            or endpoint["address_units"] != WISHBONE_STORAGE_ADDRESS_UNITS):
        _refuse("generic-semantic-unsupported", "/component/endpoints",
                {"reason": "wishbone-word-addressed-storage-endpoint-required",
                 "protocol": endpoint["protocol"],
                 "template": endpoint["template"],
                 "semantic_kind": endpoint["semantic_kind"],
                 "address_units": endpoint["address_units"]})
    return endpoint


def target_endpoint_id(component: VerifiedComponent) -> str:
    """The certified target endpoint id of one Wishbone storage component."""
    return descriptor_target_endpoint(component)["endpoint_id"]


def _trace_of(document: dict, *, endpoint_id: str):
    trace = document.get("base_protocol_trace")
    if (type(trace) is not dict or trace.get("protocol") != "wishbone"
            or trace.get("endpoint_id") != endpoint_id
            or type(trace.get("signals")) is not dict
            or type(trace.get("signal_widths")) is not dict):
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"reason": "wishbone-target-trace-required"})
    declared = set(trace["signals"])
    if declared != set(_REQUEST_ROLES) | set(_RESPONSE_ROLES):
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"reason": "exact-wishbone-classic-role-set-required",
                 "declared": sorted(declared),
                 "required": sorted(set(_REQUEST_ROLES) | set(_RESPONSE_ROLES))})
    if any(role in declared for role in ("err", "rty")):
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"reason": "no-error-or-retry-role-is-certified"})
    widths = trace["signal_widths"]
    for role, width in _ROLE_WIDTHS.items():
        if widths.get(role) != width:
            _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                    {"role": role, "expected_width": width,
                     "actual_width": widths.get(role)})
    if type(widths.get("adr")) is not int or not 1 <= widths["adr"] <= 32:
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"role": "adr", "reason": "declared-word-index-width-required"})
    wait = trace.get("max_wait_cycles")
    if type(wait) is not int or not 0 <= wait <= 4096:
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"reason": "bounded-wait-cycle-declaration-required"})
    return trace


def artifact_contract_facts(artifact, *, base_dir: Path, endpoint_id: str,
                            template: tuple[str, str, str]):
    """Re-derive source row, semantics, protocol trace and facts from the artifact."""
    document = artifact.runtime_document
    if document.get("kind") != "wishbone_register_observe":
        _refuse("generic-semantic-unsupported", "/artifact/kind",
                {"expected": "wishbone_register_observe",
                 "actual": document.get("kind")})
    if template != WISHBONE_STORAGE_TEMPLATE:
        _refuse("generic-template-mismatch", "/template",
                {"expected": list(WISHBONE_STORAGE_TEMPLATE),
                 "actual": list(template)})
    trace = _trace_of(document, endpoint_id=endpoint_id)
    profile = artifact.plan.profile
    capabilities = profile.capabilities
    declared = sorted(row.endpoint_id for row in profile.endpoints
                      if tuple(row.protocol or ()) == WISHBONE_STORAGE_PROTOCOL)
    if declared != [endpoint_id]:
        _refuse("generic-template-mismatch", "/profile/endpoints",
                {"reason": "exactly-one-declared-wishbone-endpoint-required",
                 "endpoint_id": endpoint_id, "declared": declared})
    if profile.address is None:
        _refuse("generic-template-mismatch", "/profile/address",
                {"reason": "declared-target-window-required"})
    if (capabilities.get("address_units") != WISHBONE_STORAGE_ADDRESS_UNITS
            or capabilities.get("data_width") != 32
            or capabilities.get("sel_implemented") is not True
            or capabilities.get("wishbone_flavour") != "registered-ack"
            or capabilities.get("ack_requires_cyc") is not True
            or capabilities.get("has_error") is not False
            or capabilities.get("max_outstanding") != 1):
        _refuse("generic-semantic-unsupported", "/profile/capabilities",
                {"reason": "registered-word-addressed-full-word-target-required",
                 "address_units": capabilities.get("address_units"),
                 "wishbone_flavour": capabilities.get("wishbone_flavour"),
                 "has_error": capabilities.get("has_error")})
    if type(capabilities.get("partial_write")) is not bool:
        _refuse("generic-semantic-unsupported", "/profile/capabilities",
                {"reason": "declared-partial-write-fact-required"})
    window_bytes = profile.address.window_size
    if type(window_bytes) is not int or window_bytes <= 0:
        _refuse("generic-semantic-unsupported", "/profile/address/window_size")
    try:
        registered = _registered_row(profile=profile, base_dir=Path(base_dir),
                                     document=document, artifact=artifact,
                                     endpoint_id=endpoint_id)
    except GenericRuntimeRefused:
        raise
    except (TypeError, ValueError) as error:
        _refuse("generic-source-unverified", "/source_contract",
                {"reason": str(error)[:160]})
    observation = document.get("storage_observation")
    observation_present = observation is not None
    observation_scope = ("generated_expression_source_mapped"
                         if observation_present
                         else "wishbone_probe_not_generated")
    if observation_present:
        selection = observation.get("selection")
        if (not isinstance(selection, dict)
                or selection.get("contract_id") != registered["contract_id"]
                or selection.get("register") != registered["register"]["name"]):
            _refuse("generic-semantic-unsupported",
                    "/artifact/storage_observation/selection",
                    {"reason": "source-contract-selection-mismatch"})
    semantic = wishbone_storage_semantic_contract(
        registered=registered, endpoint_id=endpoint_id, template=template,
        observation_scope=observation_scope,
        observation_native=observation_present)
    facts = storage_register_facts(semantic)
    register = registered["register"]
    decode = registered["decode"]
    if (facts["register_width"] != 32 or register["width"] != 32
            or facts["address_units"] != WISHBONE_STORAGE_ADDRESS_UNITS
            or facts["address_width"] != decode["address_width"]):
        _refuse("generic-semantic-unsupported", "/register",
                {"reason": "full-word-32-bit-word-addressed-storage-required"})
    word_index = _word_index(register["canonical_offset"],
                             "/register/canonical_offset")
    if word_index != register["word_index"]:
        _refuse("generic-semantic-unsupported", "/register/word_index",
                {"expected": register["word_index"], "actual": word_index})
    if decode["alias_period_bytes"] != window_bytes:
        _refuse("generic-semantic-unsupported", "/decode/alias_period_bytes",
                {"expected": window_bytes,
                 "actual": decode["alias_period_bytes"]})
    if decode["host_alignment_bytes"] != _WORD_BYTES:
        _refuse("generic-semantic-unsupported", "/decode/host_alignment_bytes",
                {"expected": _WORD_BYTES,
                 "actual": decode["host_alignment_bytes"]})
    if wishbone_setup_matches(registered, register["canonical_offset"]) is not True:
        _refuse("generic-semantic-unsupported", "/decode",
                {"reason": "canonical-offset-not-the-certified-storage-word"})
    if trace["signal_widths"].get("adr") != decode["address_width"]:
        _refuse("generic-template-mismatch", "/artifact/base_protocol_trace",
                {"role": "adr", "expected_width": decode["address_width"],
                 "actual_width": trace["signal_widths"].get("adr")})
    bound = WishboneStorageFacts(
        instance_id=artifact.plan.request.instance_id,
        endpoint_id=endpoint_id,
        source_contract_id=registered["contract_id"],
        source_contract_digest=registered["digest"],
        register=register["name"],
        canonical_offset=register["canonical_offset"],
        word_index=word_index,
        register_width=facts["register_width"],
        read_mask=facts["read_mask"],
        write_mask=facts["write_mask"],
        address_units=facts["address_units"],
        address_width=facts["address_width"],
        window_bytes=window_bytes,
        window_alignment_bytes=profile.address.alignment,
        alias_period_bytes=facts["alias_period_bytes"],
        host_alignment_bytes=decode["host_alignment_bytes"],
        decode_mask=facts["decode_mask"],
        decode_value=facts["decode_value"],
        expression=facts["expression"],
        reset_port=facts["reset_port"],
        reset_observed=facts["reset_observed"],
        trace_roles=tuple(sorted((role, width) for role, width
                                 in trace["signal_widths"].items())),
        max_wait_cycles=trace["max_wait_cycles"],
        observation_scope=observation_scope,
        storage_observation_present=observation_present,
        stall_policy="observed_zero_only",
        has_error=False,
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
    declared = (tuple(endpoint["protocol"]), tuple(endpoint["template"]),
                endpoint["semantic_kind"], endpoint["role"],
                endpoint["address_units"], endpoint["data_width"])
    expected = (WISHBONE_STORAGE_PROTOCOL, WISHBONE_STORAGE_TEMPLATE, STORAGE_RW,
                "target", WISHBONE_STORAGE_ADDRESS_UNITS, 32)
    if declared != expected:
        _refuse("generic-template-mismatch", "/component/endpoints",
                {"reason": "endpoint-does-not-match-live-artifact"})


# ---------------------------------------------------------------------------
# Declared route
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class WishboneTargetRoute:
    """Declared CPU -> Wishbone target route for exactly one certified register.

    ``word_index`` is the converted Wishbone ``adr`` value, not a second source of
    truth: the dataclass refuses a route whose ``word_index`` is not
    ``wishbone_word_index(register_offset)``.
    """

    path_id: str
    device_id: str
    endpoint_id: str
    window_base: int
    window_size: int
    register: str
    register_offset: int
    word_index: int
    address_units: str
    access_alignment: int
    width_bytes: int
    allowed_byte_enables: tuple[int, ...]
    declared_value_mask: int
    declared_operation: str
    source_contract_id: str
    source_contract_digest: str

    def __post_init__(self) -> None:
        require_identifier(self.path_id, "/route/path_id")
        require_identifier(self.device_id, "/route/device_id")
        require_identifier(self.endpoint_id, "/route/endpoint_id")
        require_identifier(self.register, "/route/register")
        require_identifier(self.source_contract_id, "/route/source_contract_id")
        require_digest(self.source_contract_digest, "/route/source_contract_digest")
        if type(self.window_base) is not int or not 0 <= self.window_base < (1 << 32):
            _refuse("generic-contract-type", "/route/window_base")
        if (type(self.window_size) is not int or self.window_size <= 0
                or self.window_base + self.window_size > (1 << 32)):
            _refuse("generic-contract-type", "/route/window_size")
        if (type(self.register_offset) is not int
                or not 0 <= self.register_offset < self.window_size):
            _refuse("generic-contract-type", "/route/register_offset")
        if self.address_units != WISHBONE_STORAGE_ADDRESS_UNITS:
            _refuse("generic-contract-type", "/route/address_units",
                    {"expected": WISHBONE_STORAGE_ADDRESS_UNITS})
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
        if type(self.word_index) is not int:
            _refuse("generic-contract-type", "/route/word_index")
        converted = _word_index(self.register_offset, "/route/register_offset")
        if self.word_index != converted:
            _refuse("generic-route-refused", "/route/word_index",
                    {"reason": "recorded-word-index-differs-from-byte-offset",
                     "derived": converted, "recorded": self.word_index})

    def document(self) -> dict:
        return {
            "path_id": self.path_id,
            "device_id": self.device_id,
            "endpoint_id": self.endpoint_id,
            "window_base": self.window_base,
            "window_size": self.window_size,
            "register": self.register,
            "register_offset": self.register_offset,
            "word_index": self.word_index,
            "address_units": self.address_units,
            "access_alignment": self.access_alignment,
            "width_bytes": self.width_bytes,
            "allowed_byte_enables": [int(value) for value in self.allowed_byte_enables],
            "declared_value_mask": self.declared_value_mask,
            "declared_operation": self.declared_operation,
            "source_contract_id": self.source_contract_id,
            "source_contract_digest": self.source_contract_digest,
        }

    def sha256(self) -> str:
        return _digest({"schema_version": "wishbone_target_route.v1",
                        **self.document()})


def _check_route(route: WishboneTargetRoute, *, artifact,
                 facts: WishboneStorageFacts) -> None:
    if type(route) is not WishboneTargetRoute:
        _refuse("generic-contract-type", "/route", {"expected": "WishboneTargetRoute"})
    if route.endpoint_id != facts.endpoint_id:
        _refuse("generic-route-refused", "/route/endpoint_id",
                {"expected": facts.endpoint_id, "actual": route.endpoint_id})
    if route.register != facts.register:
        _refuse("generic-route-refused", "/route/register",
                {"expected": facts.register, "actual": route.register})
    if route.source_contract_id != facts.source_contract_id \
            or route.source_contract_digest != facts.source_contract_digest:
        _refuse("generic-route-refused", "/route/source_contract_id",
                {"reason": "route-names-another-registered-source-row"})
    window = artifact.plan.profile.address.window_size
    if route.window_size != window or route.window_size != facts.window_bytes:
        _refuse("generic-route-refused", "/route/window_size",
                {"expected": window, "actual": route.window_size})
    if route.access_alignment != facts.host_alignment_bytes:
        _refuse("generic-route-refused", "/route/access_alignment",
                {"expected": facts.host_alignment_bytes,
                 "actual": route.access_alignment})
    if route.width_bytes != facts.register_width // 8:
        _refuse("generic-route-refused", "/route/width_bytes",
                {"expected": facts.register_width // 8,
                 "actual": route.width_bytes})
    if _FULL_WORD_BYTE_ENABLE not in route.allowed_byte_enables:
        _refuse("generic-semantic-unsupported", "/route/allowed_byte_enables",
                {"reason": "full-word-select-required"})
    if route.register_offset % route.access_alignment:
        _refuse("generic-route-refused", "/route/register_offset",
                {"reason": "route-register-offset-unaligned"})
    if route.register_offset != facts.canonical_offset:
        _refuse("generic-route-refused", "/route/register_offset",
                {"reason": "route-register-offset-is-not-the-certified-word",
                 "expected": facts.canonical_offset,
                 "actual": route.register_offset})
    if route.word_index != facts.word_index:
        _refuse("generic-route-refused", "/route/word_index",
                {"expected": facts.word_index, "actual": route.word_index})


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
                         endpoint_id: str) -> WishboneTargetRoute:
    """Derive the declared route from the *same-pass* prepared D3 document.

    Exactly one executable F4 path of the same preparation must declare one
    ``register_access`` row for this component's Wishbone target endpoint.  The
    byte offset of that row is converted to the Wishbone word index here and the
    converted value is recorded in the route document; ``compiled_paths`` keeps
    carrying byte addresses.
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
    if (endpoint["role"] != "target"
            or tuple(endpoint["protocol"]) != WISHBONE_STORAGE_PROTOCOL):
        _refuse("generic-route-refused", "/endpoint_id",
                {"reason": "wishbone-classic-target-endpoint-required",
                 "role": endpoint["role"], "protocol": endpoint["protocol"]})
    if tuple(endpoint["template"]) != WISHBONE_STORAGE_TEMPLATE:
        _refuse("generic-route-refused", "/endpoint_id/template",
                {"reason": "word-addressed-registered-ack-template-required",
                 "actual": endpoint["template"]})
    if endpoint["address_units"] != WISHBONE_STORAGE_ADDRESS_UNITS:
        _refuse("generic-route-refused", "/endpoint_id/address_units",
                {"reason": "word-addressed-target-required",
                 "actual": endpoint["address_units"]})
    document = artifact.runtime_document
    try:
        registered = _registered_row(
            profile=artifact.plan.profile,
            base_dir=_preparation_base_dir(preparation), document=document,
            artifact=artifact, endpoint_id=endpoint_id)
    except GenericRuntimeRefused as error:
        _refuse("generic-route-refused", "/source_contract",
                {"reason": error.code,
                 "detail": error.detail if isinstance(error.detail, dict) else None})
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
    if set(access) != set(_ROUTE_ACCESS_KEYS):
        _refuse("generic-route-refused", "/paths/register_access",
                {"reason": "closed-register-route-required"})
    if access["schema_version"] != "register_source_access.v1":
        _refuse("generic-route-refused", "/paths/register_access/schema_version",
                {"expected": "register_source_access.v1"})
    if access["register"] != registered["register"]["name"]:
        _refuse("generic-route-refused", "/paths/register_access/register",
                {"reason": "route-register-does-not-match-certified-register",
                 "route": access["register"],
                 "certified": registered["register"]["name"]})
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
    profile_window = artifact.plan.profile.address.window_size
    if window_size != profile_window:
        _refuse("generic-route-refused", "/paths/register_access/window_size",
                {"reason": "route-window-differs-from-profile-window",
                 "profile_window": profile_window, "route_window": window_size})
    if window_size != registered["decode"]["alias_period_bytes"]:
        _refuse("generic-route-refused", "/paths/register_access/window_size",
                {"reason": "route-window-differs-from-registered-alias-period",
                 "alias_period_bytes": registered["decode"]["alias_period_bytes"],
                 "route_window": window_size})
    word_index = _word_index(offset, "/paths/register_access/register_offset")
    if word_index != registered["register"]["word_index"]:
        _refuse("generic-route-refused",
                "/paths/register_access/register_offset",
                {"reason": "route-offset-is-not-the-certified-word-index",
                 "word_index": word_index,
                 "certified_word_index": registered["register"]["word_index"]})
    if alignment % _WORD_BYTES:
        _refuse("generic-route-refused",
                "/paths/register_access/access_alignment",
                {"reason": "host-alignment-not-a-whole-word",
                 "alignment": alignment})
    endpoint_rows = [row for row in path.get("endpoints") or ()
                     if isinstance(row, dict)
                     and row.get("instance_id") == component.instance_id
                     and row.get("endpoint_id") == endpoint_id]
    if (len(endpoint_rows) != 1
            or tuple(endpoint_rows[0].get("protocol") or ())
            != WISHBONE_STORAGE_PROTOCOL
            or endpoint_rows[0].get("function") != "mmio_slave"):
        _refuse("generic-route-refused", "/paths/endpoints",
                {"reason": "prepared-path-wishbone-mmio-slave-endpoint-required"})
    return WishboneTargetRoute(
        path_id=path["path_id"],
        device_id=access["device_id"],
        endpoint_id=access["target_endpoint"],
        window_base=window_base,
        window_size=window_size,
        register=access["register"],
        register_offset=offset,
        word_index=word_index,
        address_units=WISHBONE_STORAGE_ADDRESS_UNITS,
        access_alignment=alignment,
        width_bytes=width_bytes,
        allowed_byte_enables=tuple(enables),
        declared_value_mask=_route_int(access["value_mask"],
                                       "/paths/register_access/value_mask",
                                       minimum=1, maximum=(1 << 32) - 1),
        declared_operation=access["operation"],
        source_contract_id=registered["contract_id"],
        source_contract_digest=registered["digest"],
    )


# ---------------------------------------------------------------------------
# Raw observation and span validation
# ---------------------------------------------------------------------------

class _ObservationInvalid(Exception):
    """The raw Wishbone sample span contradicts the request or the protocol."""


class _DriverRefused(Exception):
    """The session driver refused before any effect existed."""


@dataclass(frozen=True, slots=True)
class WishboneAccessObservation:
    """One validated registered-ack Wishbone cycle of the selected target."""

    ticks: int
    wait_ticks: int
    request_ticks: int
    rdata: int
    span_digest: str


def _tick_signals(sample, *, phase: str, trace: dict) -> dict:
    state = sample.get(phase) if type(sample) is dict else None
    backend = state.get("backend") if type(state) is dict else None
    if type(backend) is not dict:
        raise _ObservationInvalid("missing-native-backend-sample")
    values = {}
    for role, name in trace["signals"].items():
        value = backend.get(name)
        width = trace["signal_widths"][role]
        if type(value) is not int or not 0 <= value < (1 << width):
            raise _ObservationInvalid("invalid-native-signal:" + role)
        values[role] = value
    return values


def validate_wishbone_span(samples, *, trace: dict, word_index: int, write: bool,
                           value: int,
                           byte_enable: int) -> WishboneAccessObservation:
    """One ``registered-ack`` Wishbone cycle: 1 STB pulse, CYC held, one ACK.

    ``samples`` are the raw samples of exactly one bounded access, each carrying
    the artifact-declared backend signal names.  Idle ticks before the selected
    transfer and after the response are allowed and trimmed; every tick of the
    transfer itself must match the requested word index, direction, write data
    and full-word select, ``STALL`` must never be observed asserted, and the
    single ``ACK`` tick must be the last active tick of the span.
    """
    if byte_enable != _FULL_WORD_BYTE_ENABLE:
        raise _ObservationInvalid("unsupported-byte-enable")
    if type(samples) is not list or not samples:
        raise _ObservationInvalid("empty-sample-span")
    staged = []
    for sample in samples:
        signals = _tick_signals(sample, phase="pre", trace=trace)
        if signals["stall"] != 0:
            raise _ObservationInvalid("wishbone-stall-observed")
        if signals["cyc"] == 0 and signals["stb"] == 0 and signals["ack"] == 0:
            staged.append(("idle", signals))
        elif signals["stb"] == 1:
            staged.append(("request", signals))
        elif signals["ack"] == 1:
            staged.append(("ack", signals))
        elif signals["cyc"] == 1:
            staged.append(("wait", signals))
        else:
            # CYC released without an ACK: the cycle was abandoned.
            staged.append(("abandoned", signals))
    active = [index for index, (kind, _) in enumerate(staged) if kind != "idle"]
    if not active:
        raise _ObservationInvalid("no-selected-wishbone-tick")
    first, last = active[0], active[-1]
    span = staged[first:last + 1]
    if any(kind == "idle" for kind, _ in span):
        raise _ObservationInvalid("wishbone-span-interrupted")
    kinds = [kind for kind, _ in span]
    if kinds.count("request") != 1 or kinds[0] != "request":
        raise _ObservationInvalid("wishbone-single-stb-pulse-required")
    if kinds.count("ack") != 1 or kinds[-1] != "ack":
        raise _ObservationInvalid("wishbone-one-terminal-ack-required")
    if any(kind not in ("request", "wait", "ack") for kind in kinds):
        raise _ObservationInvalid("wishbone-cycle-abandoned-without-ack")
    wait_ticks = len(kinds) - 2
    if wait_ticks > trace["max_wait_cycles"]:
        raise _ObservationInvalid("wishbone-wait-cycle-bound")
    expected_dat_w = value if write else 0
    for _, signals in span:
        if signals["cyc"] != 1:
            raise _ObservationInvalid("wishbone-cyc-not-held-through-ack")
        if signals["adr"] != word_index:
            raise _ObservationInvalid("wishbone-word-index-mismatch")
        if signals["we"] != int(bool(write)):
            raise _ObservationInvalid("wishbone-direction-mismatch")
        if signals["sel"] != _FULL_WORD_BYTE_ENABLE:
            raise _ObservationInvalid("wishbone-select-mismatch")
        if signals["dat_w"] != expected_dat_w:
            raise _ObservationInvalid("wishbone-write-data-mismatch")
    response = span[-1][1]
    return WishboneAccessObservation(
        ticks=len(samples), wait_ticks=wait_ticks,
        request_ticks=1, rdata=response["dat_r"],
        span_digest=_digest({"word_index": word_index, "write": bool(write),
                             "value": value, "kinds": kinds,
                             "rdata": response["dat_r"],
                             "select": _FULL_WORD_BYTE_ENABLE}))


# ---------------------------------------------------------------------------
# Bounded target provider
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


class _OperationToken:
    """Opaque, process-local, single-use permission for one advance/complete."""

    __slots__ = ("operation_id", "kind")

    def __init__(self, operation_id: str, *, kind: str):
        self.operation_id = operation_id
        self.kind = kind


class StorageTargetProvider:
    """Bounded ``TargetProvider`` over one admitted Wishbone storage target.

    Constructed only by :func:`bind_wishbone_storage_adapter` or by the
    module-private software fixture hook.  It never issues or consumes the native
    store-version token: it routes the existing session transport and joins its
    own measured tick span.
    """

    __slots__ = ("_component", "_artifact", "_session", "_route", "_facts",
                 "_registered", "_semantic", "_trace", "_binding_sha256",
                 "_instance_id", "_endpoint_id", "_authority", "_issues",
                 "_key_index", "_raw", "_raw_sequence", "_states", "_tokens",
                 "_closed", "_software_only")

    def __init__(self, *, component, artifact, session, route, facts,
                 registered, semantic, trace, binding_sha256, authority,
                 software_only):
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
        self._authority = authority
        self._issues: dict[int, _Issue] = {}
        self._key_index: dict[bytes, str] = {}
        self._states: dict[int, _OperationState] = {}
        self._tokens: dict[int, _OperationToken] = {}
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
    def facts(self) -> WishboneStorageFacts:
        return self._facts

    @property
    def route(self):
        return self._route

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
        if self._software_only:
            if type(session) is not _WishboneFixtureSession:
                _refuse("generic-binding-drift", "/session",
                        {"reason": "fixture-session-class-changed",
                         "actual": _qualified(type(session))})
        else:
            if not isinstance(session, _SESSION_CLASS):
                _refuse("generic-binding-drift", "/session",
                        {"reason": "GeneratedWishboneRegisterSession-required",
                         "actual": _qualified(type(session))})
            if getattr(type(session), "software_fixture", False) is not False:
                _refuse("generic-binding-drift", "/session",
                        {"reason": "software-fixture-session-refused"})
            for name, method in _SESSION_TRANSPORT.items():
                if getattr(type(session), name, None) is not getattr(
                        _SESSION_CLASS, name):
                    _refuse("generic-binding-drift", "/session",
                            {"reason": "session-subclass-replaced-transport",
                             "method": name})
                if getattr(method, "__code__", None) is None:  # pragma: no cover
                    continue
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
        try:
            session._check_artifact_stable()
        except (AttributeError, ValueError) as error:
            _refuse("generic-binding-drift", "/session",
                    {"reason": str(error)[:160]})

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
        route = self._route
        if route is None:
            _refuse("generic-route-refused", "/route",
                    {"reason": "route-not-declared"})
        if request.path_id != route.path_id:
            _refuse("generic-route-refused", "/request/path_id",
                    {"declared": route.path_id, "requested": request.path_id})
        offset = request.address - route.window_base
        if not 0 <= offset < route.window_size:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "outside-declared-window"})
        alignment = route.access_alignment
        if request.address % alignment or offset % alignment:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "transport-alignment", "alignment_bytes": alignment})
        word_index = _word_index(offset, "/request/address")
        if word_index >= (1 << self._facts.address_width):
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "outside-declared-word-index-width",
                     "address_width": self._facts.address_width})
        try:
            certified = wishbone_setup_matches(self._registered, offset)
        except ValueError as error:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": str(error)[:160]})
        if certified is not True:
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "not-the-certified-storage-word",
                     "word_index": word_index,
                     "certified_word_index": self._facts.word_index,
                     "decode_mask": self._facts.decode_mask,
                     "decode_value": self._facts.decode_value})
        if word_index != route.word_index:  # pragma: no cover - route is closed
            _refuse("generic-route-refused", "/request/address",
                    {"reason": "route-word-index-mismatch"})
        facts = storage_register_facts(self._semantic)
        if (word_index & facts["decode_mask"]) != facts["decode_value"]:
            _refuse("generic-semantic-unsupported", "/request/address",
                    {"reason": "semantic-alias-rule-divergence"})
        if request.operation not in ("read", "write"):
            _refuse("generic-contract-type", "/request/operation")
        if request.size_bytes != route.width_bytes:
            _refuse("generic-semantic-unsupported", "/request/size_bytes",
                    {"expected": route.width_bytes,
                     "actual": request.size_bytes,
                     "reason": "registered-full-word-contract"})
        if request.byte_enable != _FULL_WORD_BYTE_ENABLE:
            _refuse("generic-semantic-unsupported", "/request/byte_enable",
                    {"expected": _FULL_WORD_BYTE_ENABLE,
                     "actual": request.byte_enable,
                     "reason": "runtime-full-word-sel-only"})
        if request.byte_enable not in route.allowed_byte_enables:
            _refuse("generic-semantic-unsupported", "/request/byte_enable",
                    {"allowed": list(route.allowed_byte_enables)})
        if request.operation == "write":
            mask = route.declared_value_mask & self._facts.write_mask
            if request.write_data is None or request.write_data & ~mask:
                _refuse("generic-route-refused", "/request/write_data",
                        {"reason": "write-outside-declared-mask",
                         "value_mask": mask})
        if not self._capacity_ok():
            _refuse("generic-provider-budget", "/provider",
                    {"reason": "operation-or-sample-capacity-exhausted"})
        request_sha256 = request_digest(request)
        route_sha256 = route.sha256()
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
        self._authority.issue(handle, snapshot=request.canonical_bytes())
        self._issues[id(handle)] = issue
        self._key_index[key_bytes] = operation_id
        # Single-use routed-context permission; the context document itself is
        # never serialized into evidence and carries no authority.
        self._tokens[id(handle)] = _OperationToken(operation_id, kind="routed")
        return handle

    # -- advance ----------------------------------------------------------
    def advance(self, operation, budget: int) -> ProviderProgress:
        """One bounded, key-bound Wishbone cycle through the real session.

        ``budget`` must be at least the artifact-bounded access cost; a smaller
        grant refuses *before* the transport runs.  A terminal result is cached
        and never re-issued, and an ambiguous reply becomes ``uncertain_effect``
        rather than a retry.  ``completed`` carries the measured ``dat_r`` word
        because ``completed`` always requires response bytes.
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
        token = self._tokens.pop(id(operation), None)
        if type(token) is not _OperationToken or token.kind != "routed":
            _refuse("generic-binding-drift", "/operation",
                    {"reason": "single-use-routed-token-missing"})
        request = issue.request
        offset = request.address - self._route.window_base
        word_index = _word_index(offset, "/request/address")
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
            raise
        except BaseException:
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
            observation = validate_wishbone_span(
                samples, trace=self._trace, word_index=word_index,
                write=request.operation == "write",
                value=request.write_data or 0,
                byte_enable=request.byte_enable)
        except _ObservationInvalid as error:
            reason = str(error)
            code = ("wishbone-stall-observed" if reason == "wishbone-stall-observed"
                    else "wishbone-observation-invalid")
            return self._terminal(issue, "uncertain_effect", advanced, None,
                                  self._span_refs(issue, offset, before), code)
        refs = self._span_refs(issue, offset, before, observation=observation)
        if observation.ticks > budget:
            return self._terminal(issue, "uncertain_effect", advanced, None,
                                  refs, "measured-ticks-exceeded-budget")
        if request.operation == "read" and observation.rdata != rdata:
            return self._terminal(issue, "uncertain_effect", advanced, None,
                                  refs, "response-payload-mismatch")
        response = observation.rdata.to_bytes(_WORD_BYTES, "little")
        return self._terminal(issue, "completed", advanced, response, refs, None)
    def _require_issue(self, operation) -> _Issue:
        if type(operation) is not PreparedTargetOperation:
            _refuse("generic-contract-type", "/operation",
                    {"expected": "PreparedTargetOperation"})
        self._authority.require(operation, pointer="/operation")
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

    def _drive(self, issue: _Issue, offset: int):
        """Route one access through the real session; return read data or None.

        The measured ``dat_r`` of a write cycle is taken from the validated tick
        span by the caller, never from Python state, so this method reports no
        value for writes.
        """
        request = issue.request
        write = request.operation == "write"
        value = request.write_data if write else 0
        session = self._session
        if not self._software_only:
            if session.process is None or session.process.poll() is not None:
                # Refuse before the transport: no command is issued and no
                # effect can exist.
                _refuse("generic-provider-closed", "/session",
                        {"reason": "session-not-running"})
        if write:
            session.write_register(offset, value, be=request.byte_enable)
            return None
        result = session.read_register(offset)
        if type(result) is not int or not 0 <= result < (1 << 32):
            raise _ObservationInvalid("driver-result-shape")
        return result

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
        command_digest = (issue.request.sha256() if observation is None
                          else observation.span_digest)
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
        # A terminal operation still needs its single-use completion token.
        self._tokens[id(issue.handle)] = _OperationToken(issue.operation_id,
                                                         kind="completion")
        return progress

    # -- complete ---------------------------------------------------------
    def complete(self, operation) -> EffectEvidence:
        """Evidence over this provider's raw observation; single use only."""
        self._assert_open()
        issue = self._require_issue(operation)
        self.assert_bound()
        epoch, execution = self._session_scope()
        if epoch != issue.epoch or execution != issue.execution:
            _refuse("generic-provider-stale", "/operation",
                    {"reason": "session-reset-or-case-change-since-prepare"})
        state = self._states.get(id(operation))
        if state is None:
            _refuse("generic-provider-incomplete", "/operation",
                    {"reason": "advance-before-complete"})
        if state.evidence is not None:
            _refuse("generic-binding-drift", "/operation",
                    {"reason": "single-use-token-already-consumed"})
        token = self._tokens.pop(id(operation), None)
        if type(token) is not _OperationToken or token.kind != "completion":
            _refuse("generic-binding-drift", "/operation",
                    {"reason": "single-use-completion-token-missing"})
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
        elif progress.reason_code in ("wishbone-observation-invalid",
                                      "wishbone-stall-observed",
                                      "response-payload-mismatch"):
            results = ((_OBLIGATION_EFFECT, "contradicted"),
                       (_OBLIGATION_RESPONSE, "contradicted"),
                       (_OBLIGATION_SAMPLE, "missing"),
                       (_OBLIGATION_TOKEN, "missing"))
        else:
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
        self._issues.clear()
        self._key_index.clear()
        self._states.clear()
        self._tokens.clear()
        self._raw.clear()

    def __len__(self) -> int:
        return len(self._issues)


# ---------------------------------------------------------------------------
# Software-only fixture (unreachable from the production factory)
# ---------------------------------------------------------------------------

class _WishboneFixtureSession(GeneratedWishboneRegisterSession):
    """Software-only stand-in that keeps the real session class in its MRO.

    It never starts a process and it *is* refused by the production factory (the
    ``software_fixture`` flag and the replaced ``_access`` transport both fail
    the bind checks).  Its measured tick stream is synthetic, so its evidence can
    never be certified.
    """

    software_fixture = True

    def __init__(self, artifact, *, program, max_ticks=12, base_dir=None,
                 cache_dir=None):
        if type(max_ticks) is not int or not 1 <= max_ticks <= 65536:
            raise ValueError("software fixture requires a bounded tick cost")
        if type(program) is not list:
            raise ValueError("software fixture requires an explicit program")
        super().__init__(artifact, base_dir=Path(base_dir or _ROOT),
                         cache_dir=Path(cache_dir or _ROOT))
        self.max_local_ticks_per_register_access = max_ticks
        self.max_local_ticks_per_step = max_ticks
        self.calls = []
        self.program = list(program)
        self.cursor = 0

    def identity_document(self) -> dict:
        return {"schema_version": "software_wishbone_fixture_session_identity.v1",
                "software_only": True, "calls": len(self.calls),
                "program_entries": len(self.program)}

    def _next(self) -> dict:
        if self.cursor >= len(self.program):
            raise _DriverRefused("software-fixture-program-exhausted")
        entry = self.program[self.cursor]
        self.cursor += 1
        return entry

    def _access(self, write, offset, value=0, be=15):
        if (type(offset) is not int or offset % 4 or not 0 <= offset < 16
                or type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                or type(be) is not int or not 0 <= be <= 15):
            raise ValueError("invalid software Wishbone access")
        self.calls.append({"offset": offset, "write": bool(write),
                           "value": value, "be": be})
        entry = self._next()
        if entry.get("driver_refusal"):
            raise _DriverRefused("software-fixture-driver-refusal")
        trace = self.artifact.runtime_document["base_protocol_trace"]
        word = offset >> 2
        levels = {
            "request": (1, 1, 0),
            "wait": (1, 0, 0),
            "ack": (1, 0, 1),
            "idle": (0, 0, 0),
        }
        for phase in entry["phases"]:
            if phase not in levels:
                raise ValueError("software fixture phase unsupported")
            cyc, stb, ack = levels[phase]
            self.local_ticks += 1
            backend = {name: 0 for name in trace["signals"].values()}
            backend[trace["signals"]["cyc"]] = cyc
            backend[trace["signals"]["stb"]] = stb
            backend[trace["signals"]["ack"]] = ack
            backend[trace["signals"]["stall"]] = int(entry.get("stall", 0))
            backend[trace["signals"]["we"]] = int(bool(write)) if cyc else 0
            backend[trace["signals"]["adr"]] = word if cyc else 0
            backend[trace["signals"]["dat_w"]] = ((value if write else 0)
                                                  if cyc else 0)
            backend[trace["signals"]["sel"]] = 15 if cyc else 0
            # ``dat_r`` is the measured response word; ``entry["rdata"]`` is what
            # the fixture transport returns.  They differ only in a negative test
            # that proves the provider compares them instead of trusting either.
            backend[trace["signals"]["dat_r"]] = entry.get("dat_r", entry["rdata"])
            self._samples.append({
                "local_tick": self.local_ticks,
                "pre": {"backend": dict(backend)},
                "post": {"backend": dict(backend)},
            })
        if entry.get("fault_after_ticks") is True:
            raise RuntimeError("software-fixture-driver-fault")
        return entry["rdata"]


class _SoftwareWishboneFixture:
    """Explicit software-only fixture pair (session + bound adapter)."""

    def __init__(self, *, component, artifact, route, program, max_ticks=12,
                 authority=None, base_dir=None):
        self.session = _WishboneFixtureSession(
            artifact, program=program, max_ticks=max_ticks, base_dir=base_dir)
        self.bound = _build_bound_adapter(
            component=component, session=self.session, route=route,
            selection=None, authority=authority, software_only=True)

    @property
    def provider(self):
        return self.bound.provider

    def program(self, entries) -> None:
        """Replace the remaining fixture driver program (fixtures only)."""
        self.session.program = list(entries)
        self.session.cursor = 0


def _software_wishbone_storage_fixture(*, component, artifact, route, program,
                                       max_ticks: int = 12, authority=None):
    """Module-private software-only fixture hook; production never calls it."""
    return _SoftwareWishboneFixture(component=component, artifact=artifact,
                                    route=route, program=program,
                                    max_ticks=max_ticks, authority=authority)


# ---------------------------------------------------------------------------
# Bound adapter and production factory
# ---------------------------------------------------------------------------

def _binding_digest(*, component, session, selection, route, facts, semantic,
                    trace, authority, software_only) -> str:
    try:
        session_identity = session.identity_document()
    except (AttributeError, ValueError, TypeError):
        session_identity = {"unavailable": _qualified(type(session))}
    return _digest({
        "schema_version": "wishbone_storage_adapter_binding.v1",
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "software_only": bool(software_only),
        "implementation_sha256": _IMPLEMENTATION_PIN,
        "witness_modules": dict(_WITNESS_PINS),
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
                        for name, (_, code) in sorted(_SESSION_TRANSPORT.items())],
        "issuer_id": WISHBONE_STORAGE_ISSUER_ID,
        "selection_sha256": None if selection is None else selection.sha256(),
        "selection_implementation_sha256":
            None if selection is None else selection.implementation_sha256,
        "authority_name": getattr(authority, "name", _qualified(type(authority))),
        "trace_sha256": _digest(trace),
    })


def _build_bound_adapter(*, component, session, route, selection, authority,
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
    if authority is None:
        authority = ProcessLocalIssuance("wishbone-storage-operations")
    binding = _binding_digest(component=component, session=session,
                              selection=selection, route=route, facts=facts,
                              semantic=semantic, trace=trace,
                              authority=authority, software_only=software_only)
    provider = StorageTargetProvider(
        component=component, artifact=artifact, session=session, route=route,
        facts=facts, registered=registered, semantic=semantic, trace=trace,
        binding_sha256=binding, authority=authority,
        software_only=software_only)
    bound = BoundStorageAdapter(component=component, session=session,
                                selection=selection, provider=provider,
                                endpoint=endpoint, semantic=semantic,
                                binding_sha256=binding,
                                implementation_pin=_IMPLEMENTATION_PIN)
    provider.assert_bound()
    return bound


class BoundStorageAdapter:
    """Process-local binding of one admitted Wishbone target to its real session.

    No JSON round-trip restores it: the object holds the live session, the
    re-derived source/semantic facts and the issued operation authority.
    """

    __slots__ = ("component_instance_id", "adapter_id", "adapter_version",
                 "endpoint_id", "provider", "semantic_contract",
                 "binding_sha256", "implementation_sha256", "facts",
                 "_session", "_selection", "_closed")

    def __init__(self, *, component, session, selection, provider, endpoint,
                 semantic, binding_sha256, implementation_pin):
        self.component_instance_id = component.instance_id
        self.adapter_id = STORAGE_ADAPTER_ID
        self.adapter_version = STORAGE_ADAPTER_VERSION
        self.endpoint_id = endpoint["endpoint_id"]
        self.provider = provider
        self.semantic_contract = semantic
        self.binding_sha256 = binding_sha256
        self.implementation_sha256 = implementation_pin
        self.facts = provider.facts
        self._session = session
        self._selection = selection
        self._closed = False

    @property
    def software_only(self) -> bool:
        return self.provider.software_only

    @property
    def route_sha256(self):
        return self.provider.route_sha256

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


def bind_wishbone_storage_adapter(*, component, session, selection,
                                  route=None, preparation=None,
                                  endpoint_id=None, authority=None
                                  ) -> BoundStorageAdapter:
    """Production factory: only a real Wishbone register session is accepted.

    ``route`` is the declared byte->word route of this register.  Without it the
    adapter still binds its artifact-derived facts, but every ``prepare``
    refuses ``generic-route-refused``.

    When the issuing ``preparation`` is supplied the route is re-derived from
    that same-pass D3 document and must be byte-identical; a caller-supplied
    window base, register or word index is then refused instead of trusted.

    ``authority`` is the process-local single-use operation authority supplied by
    the binding layer (a ``ProcessLocalIssuance``); it is never the native
    storage-version issuer.
    """
    if type(component) is not VerifiedComponent:
        _refuse("generic-contract-type", "/component")
    if not isinstance(session, _SESSION_CLASS):
        _refuse("generic-binding-drift", "/session",
                {"reason": "GeneratedWishboneRegisterSession-required",
                 "actual": _qualified(type(session))})
    if getattr(type(session), "software_fixture", False) is not False:
        _refuse("generic-binding-drift", "/session",
                {"reason": "software-fixture-session-refused",
                 "actual": _qualified(type(session))})
    for name in _SESSION_TRANSPORT:
        if getattr(type(session), name, None) is not getattr(_SESSION_CLASS, name):
            _refuse("generic-binding-drift", "/session",
                    {"reason": "session-subclass-replaced-transport",
                     "method": name})
    if type(selection) is not AdapterSelection:
        _refuse("generic-contract-type", "/selection")
    if route is not None and type(route) is not WishboneTargetRoute:
        _refuse("generic-contract-type", "/route",
                {"expected": "WishboneTargetRoute"})
    if endpoint_id is not None:
        require_identifier(endpoint_id, "/endpoint_id")
        if endpoint_id != target_endpoint_id(component):
            _refuse("generic-route-refused", "/endpoint_id",
                    {"reason": "declared-endpoint-is-not-the-certified-target",
                     "declared": endpoint_id,
                     "certified": target_endpoint_id(component)})
    try:
        _check_pins()
    except ValueError as error:
        _refuse("generic-binding-drift", "/adapter",
                {"reason": str(error)[:160]})
    _check_selection(selection, component=component)
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
    if authority is not None:
        for name in ("issue", "require", "holds", "close"):
            if not callable(getattr(authority, name, None)):
                _refuse("generic-contract-type", "/authority",
                        {"reason": "process-local-issuance-required",
                         "missing": name})
    return _build_bound_adapter(component=component, session=session,
                                route=route, selection=selection,
                                authority=authority, software_only=False)


def registration_document() -> dict:
    """Documentary description of this adapter implementation."""
    state = registration_state()
    return {
        "schema_version": "generic_adapter_implementation.v1",
        "adapter_id": STORAGE_ADAPTER_ID,
        "adapter_version": STORAGE_ADAPTER_VERSION,
        "implementation_sha256": implementation_sha256(),
        "implementation_pin": _IMPLEMENTATION_PIN,
        "session_class": _qualified(_SESSION_CLASS),
        "issuer_class": WISHBONE_STORAGE_ISSUER_ID,
        "role": "target",
        "protocol": list(WISHBONE_STORAGE_PROTOCOL),
        "template": list(WISHBONE_STORAGE_TEMPLATE),
        "semantic_kinds": [WISHBONE_STORAGE_SEMANTIC_KIND],
        "address_units": [WISHBONE_STORAGE_ADDRESS_UNITS],
        "operations": ["read", "write"],
        "transport": {"host_alignment_bytes": _WORD_BYTES,
                      "register_bytes": _WORD_BYTES,
                      "byte_enable": _FULL_WORD_BYTE_ENABLE,
                      "byte_enable_policy": "runtime_full_word_only",
                      "address_units": WISHBONE_STORAGE_ADDRESS_UNITS,
                      "word_index_conversion": "wishbone_word_index((address - window_base))",
                      "stall_policy": "observed_zero_only",
                      "error_role": None},
        "witness_modules": dict(_WITNESS_PINS),
        "registry_registered": state["registered"],
        "registry_implementation_sha256":
            state["registry_implementation_sha256"],
        "software_only": False,
    }
