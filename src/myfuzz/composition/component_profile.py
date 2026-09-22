"""Unified, source-pinned component profiles and composition requests.

This module is the user-facing input contract for automatic SoC composition.
It reuses the existing :mod:`myfuzz.composition.interface_description` endpoint
vocabulary (endpoint id, function, protocol, field roles, ``physical``
member-path selectors) and adds the facts a generator needs in order to bind
semantics to real RTL:

* ``clocks`` / ``resets``: which physical port is the clock / reset, its domain,
  polarity, synchrony and required release behaviour.
* ``capabilities``: address/data width, byte enable, partial write, read/write
  and per-target error reporting, each with an evidence reference.
* ``address`` (peripherals): declared window size, alignment and the register
  table with access attributes and side effects.
* ``interrupts`` (peripherals): which output carries a source, its trigger,
  polarity, hold and clear contract.
* ``port_actions``: an explicit disposition for every physical port or bit
  segment the interfaces above do not already bind.
* ``cpu`` (CPUs): ISA/ABI facts, reset vector requirement, master endpoints and
  the interrupt entry contract.

Two invariants are enforced here and nowhere else:

1. A profile never contains executable behaviour.  Only declared data and the
   finite operation vocabulary below are accepted; anything that looks like a
   script, callback or arbitrary program is rejected.
2. A profile's duplicate physical claims (direction, width, member path) are
   *checks*, never overrides.  They are verified against the real elaboration
   result and a conflict is reported instead of being silently repaired.

The composition request is deliberately separate from the profiles: it names
the instances, their parameter overrides, the requested access relations, the
fixed addresses and the memory/clock/reset resources.  The same RTL and profile
can therefore be instantiated many times without editing the component
description.
"""
from __future__ import annotations

import json
import re
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from os import PathLike
from pathlib import Path
from types import MappingProxyType

from .interface_description import (
    ElaborationSettings,
    EndpointDescription,
    FieldHint,
    InterfaceDescription,
    PhysicalSelector,
    RepositoryPin,
    SourceLocator,
)
from .soc_scope import RESET_SEQUENCE_KEYS
from .source_crawler import (
    ElaboratedMemberFact,
    ElaboratedPortFact,
    SourceCrawlError,
    SourceCrawler,
    source_tree_hash,
)

COMPONENT_PROFILE_SCHEMA = "component_profile.v1"
COMPOSITION_REQUEST_SCHEMA = "composition_request.v1"

COMPONENT_KINDS = ("cpu", "peripheral", "memory")
PORT_ACTION_KINDS = ("functional", "constant", "fuzz", "observe", "unconnected", "external")
DISPOSITION_KINDS = PORT_ACTION_KINDS
DRIVE_STRATEGIES = ("cycle_value", "reset_sampled", "pulse", "hold")
INTERRUPT_TRIGGERS = ("level", "pulse", "rising_edge", "falling_edge", "both_edges")

#: Triggers the controller consumes with no converter in front of it.  A
#: ``pulse`` source is a bounded same-domain pulse of at least one clock, which
#: the controller's per-cycle sampling captures into a pending bit; ``level`` is
#: sampled directly and follows its input.
INTERRUPT_TRIGGERS_DIRECT = ("level", "pulse")
#: Triggers that describe a source *holding* an edge-shaped condition.  Wiring
#: one directly would re-pend it one sampling edge after every COMPLETE, so the
#: renderer inserts ``soc_irq_edge_detect`` in front of the controller.
INTERRUPT_TRIGGERS_EDGE_DETECTED = ("rising_edge", "falling_edge", "both_edges")
#: ``trigger -> EDGE`` parameter of ``soc_irq_edge_detect``.
INTERRUPT_EDGE_PARAMETER = {"rising_edge": 0, "falling_edge": 1, "both_edges": 2}
POLARITIES = ("active_high", "active_low")
INITIALIZATION_POLICIES = ("preload", "on_demand", "rom", "alias")

#: Interface functions and the field directions they require.
#: ``protocol`` means "take the direction from the referenced protocol plugin".
FUNCTION_DIRECTIONS: dict[str, str] = {
    "clock": "input",
    "reset": "input",
    "configuration": "input",
    "observation": "output",
    "interrupt_source": "output",
    "interrupt_entry": "input",
    "external_pins": "declared",
    "mmio_slave": "protocol",
    "processor_memory_master": "protocol-inverted",
    "instruction_memory_master": "protocol-inverted",
    "data_memory_master": "protocol-inverted",
    "memory_master": "protocol-inverted",
    "memory_slave": "protocol",
    "debug_slave": "protocol",
    "clock_reset": "input",
}

#: Keys that would turn a declaration into a program.  They are rejected by
#: name so an unsupported profile fails loudly instead of being ignored.
_FORBIDDEN_KEYS = frozenset((
    "python", "script", "callback", "hook", "plugin", "code", "exec", "eval",
    "module_path", "callable", "lambda", "import", "source_code", "patch",
))
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SIGNAL = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
#: A human-facing identifier that may contain ``-``, ``.`` or ``_``.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")


class ComponentProfileError(ValueError):
    """A profile, request or binding is unsafe, unpinned or inconsistent."""


def _error(reason: str) -> None:
    raise ComponentProfileError(reason)


def _mapping(value: object, reason: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _error(reason)
    return value


def _sequence(value: object, reason: str) -> list:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        _error(reason)
    return list(value)


def _text(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value:
        _error(reason)
    return value


def _identifier(value: object, reason: str) -> str:
    text = _text(value, reason)
    if _IDENTIFIER.fullmatch(text) is None:
        _error(reason)
    return text


def _token(value: object, reason: str) -> str:
    text = _text(value, reason)
    if _TOKEN.fullmatch(text) is None:
        _error(reason)
    return text


def _integer(value: object, reason: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _error(reason)
    if minimum is not None and value < minimum:
        _error(reason)
    return value


def _boolean(value: object, reason: str) -> bool:
    if not isinstance(value, bool):
        _error(reason)
    return value


def _reject_programming_keys(value: object, pointer: str) -> None:
    """Reject any declaration that tries to embed behaviour in a profile."""
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in _FORBIDDEN_KEYS:
                _error(f"profile-embedded-program:{pointer}/{key}")
            _reject_programming_keys(item, f"{pointer}/{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, item in enumerate(value):
            _reject_programming_keys(item, f"{pointer}/{index}")


# ---------------------------------------------------------------------------
# profile records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProfileField:
    """A semantic role bound to a real port / member path / bit segment.

    A physical port that is a *struct* or *array* carries many semantic roles at
    once (CVA6 packs its whole AXI4 master into the two struct ports
    ``noc_req_o``/``noc_resp_i``; OpenTitan packs TL-UL into ``tl_i``/``tl_o``),
    so one role is selected by exactly one of three exclusive selectors:

    * ``physical.member_path``: a member of the elaborated struct, named by its
      full path.  It may name a leaf member (``aw.id``) or an intermediate
      packed struct (``a_user``), whose span is the union of the elaborated
      leaves below it.  ``member_bits`` may additionally *declare* the inclusive
      ``[lo, hi]`` span the member is expected to occupy; the binding then
      proves that claim against the elaborated layout instead of trusting it;
    * ``bit_range``: an inclusive ``[lo, hi]`` slice of a plain (non-aggregate)
      vector port, named by a single alias;
    * ``aliases`` alone: the whole port.

    Two roles on one port are legal exactly when their selected bit spans are
    disjoint.  Overlapping, duplicate, out-of-range and direction-inconsistent
    declarations are refused by name, and the port-disposition ledger still
    requires every bit of every elaborated port to be classified, so a partial
    declaration of a struct port leaves undisposed bits and is refused.
    """

    role: str
    direction: str | None = None
    width: int | None = None
    aliases: tuple[str, ...] = ()
    physical: PhysicalSelector | None = None
    required: bool = True
    randomizable: bool = False
    #: Inclusive ``[lo, hi]`` slice of a plain vector port, declared as
    #: ``bit_range`` in the document, in the port's own bit numbering (bit 0 is
    #: the port's least significant bit).  Mutually exclusive with ``physical``.
    #: A member's own ``bit_range`` is a *proof* of its elaborated offset, so the
    #: keyword means "these bits" in both places.
    bit_range: tuple[int, int] | None = None
    #: Inclusive ``[lo, hi]`` span the selected member is *declared* to occupy.
    #: Only meaningful together with ``physical.member_path``; the elaboration
    #: must agree or the binding fails with ``member-offset-conflict``.
    member_bits: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if self.physical is not None and self.aliases:
            _error("physical-aliases-mutually-exclusive")
        if self.physical is not None and self.bit_range is not None:
            _error("profile-field-selector-ambiguous")
        if self.member_bits is not None and (self.physical is None
                                             or not self.physical.member_path):
            _error("member-bits-without-a-member-path")
        if self.direction is not None and self.direction not in ("input", "output", "inout"):
            _error("invalid-field-direction")
        if self.width is not None and self.width <= 0:
            _error("invalid-field-width")
        for name, span in (("bits", self.bit_range), ("member-bits", self.member_bits)):
            if span is None:
                continue
            if (not isinstance(span, (tuple, list)) or len(span) != 2
                    or any(isinstance(item, bool) or not isinstance(item, int)
                           for item in span)):
                _error(f"invalid-profile-field-{name}")
            low, high = int(span[0]), int(span[1])
            if low < 0 or high < low:
                _error(f"invalid-profile-field-{name}")
            object.__setattr__(self, "bit_range" if name == "bits" else "member_bits",
                               (low, high))


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """One semantic interface of a component."""

    endpoint_id: str
    function: str
    protocol: tuple[str, str] | None = None
    fields: tuple[ProfileField, ...] = ()
    clock: str | None = None
    reset: str | None = None
    required: bool = True


@dataclass(frozen=True, slots=True)
class ClockBinding:
    port: str
    domain: str
    frequency_hz: int


@dataclass(frozen=True, slots=True)
class ResetBinding:
    port: str
    domain: str
    polarity: str
    synchronous: bool
    release: str = ""
    #: Declared release dependency: another instance or port this reset must be
    #: released after.  The composer builds one simultaneously released reset
    #: domain, so a declared dependency is refused with
    #: ``reset-sequence-unsupported`` instead of being flattened into the single
    #: reset net.
    sequence_after: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InterruptSource:
    endpoint_id: str
    role: str
    polarity: str
    clock_domain: str
    hold: str
    clear: str
    trigger: str = "level"
    source_id: str = ""
    bit: int | None = None
    #: ``pulse`` trigger only: the declared width in clocks of the source's own
    #: pulse.  It is the capture contract the controller's per-cycle sampling
    #: relies on, so it is required and must be >= 1.
    pulse_width_cycles: int | None = None
    #: Edge triggers only: the width in clocks of the pulse the renderer's
    #: ``soc_irq_edge_detect`` emits.  The default of 1 is what the controller's
    #: pending bit needs.
    detect_pulse_cycles: int = 1
    #: Optional profile-declared MMIO bits that must be set before the source's
    #: raise path is exercised (for example a UART receiver-enable bit).  The
    #: generator only implements the generic ``set_bits`` operation; it never
    #: invents a component-specific prerequisite.
    prerequisites: tuple[Mapping[str, object], ...] = ()
    #: Ordered MMIO stores that cause this source to raise after its peer has
    #: been armed.  Values are profile facts; the generator only writes them.
    raise_actions: tuple[Mapping[str, object], ...] = ()


#: Side effects whose declared meaning is "the declared access clears state".
#: Only these two carry a clearing contract a generated program can re-read.
CLEARING_SIDE_EFFECTS = ("read_clears", "write_1_to_clear")


@dataclass(frozen=True, slots=True)
class RegisterSpec:
    """One declared register of a component's address map.

    ``name`` / ``offset`` / ``width`` / ``access`` / ``side_effect`` are the
    original declared facts.  The three optional fields below sharpen a check
    without inventing a semantic:

    * ``reset_value``: the value the register holds after reset, as declared by
      the profile.  Software initialisation writes it back and a generated
      check can compare a read against it.  ``None`` means "not declared" and
      the generator then makes no claim about the value.
    * ``writable_bits``: the declared mask of the bits a write really stores.
      A register may be declared wider than the bits its RTL implements (an
      eight-bit port inside a 32-bit register), so a read-back comparison is
      only honest against the declared mask.  ``None`` means "every bit below
      ``width`` is stored".
    * ``clears_register``: for a register whose ``side_effect`` is
      ``read_clears`` or ``write_1_to_clear``, the declared register of the
      same address map whose value proves the clearing access took effect
      (itself for a self-clearing register).  ``None`` means the declared
      clear is not observable through the declared register map; the generator
      then records that as a coverage note instead of guessing a probe.
    """

    name: str
    offset: int
    width: int
    access: str
    side_effect: str = "none"
    reset_value: int | None = None
    writable_bits: int | None = None
    clears_register: str | None = None


@dataclass(frozen=True, slots=True)
class AddressSpec:
    window_size: int
    alignment: int
    registers: tuple[RegisterSpec, ...] = ()


@dataclass(frozen=True, slots=True)
class PortAction:
    """An explicit disposition for a port or a bit segment of a port."""

    port: str
    action: str
    member_path: tuple[str, ...] = ()
    bits: tuple[int, ...] = ()
    value: int | None = None
    reason: str = ""
    strategy: str | None = None
    protocol: tuple[str, str] | None = None
    role: str | None = None
    drive: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.action not in PORT_ACTION_KINDS:
            _error("invalid-port-action")
        if self.action == "constant" and self.value is None:
            _error("constant-port-action-requires-value")
        if self.action != "constant" and self.value is not None:
            _error("port-action-value-only-for-constant")
        if self.strategy is not None and self.strategy not in DRIVE_STRATEGIES:
            _error("invalid-drive-strategy")
        if self.strategy is not None and self.action != "fuzz":
            _error("drive-strategy-only-for-fuzz")
        if not self.reason:
            _error("port-action-requires-reason")
        if self.member_path and self.bits:
            _error("port-action-selector-ambiguous")
        if any(bit < 0 for bit in self.bits):
            _error("invalid-port-action-bits")
        if self.bits:
            if len(set(self.bits)) != len(self.bits):
                _error("duplicate-port-action-bits")
            object.__setattr__(self, "bits", tuple(sorted(self.bits)))
        if self.drive:
            object.__setattr__(self, "drive", MappingProxyType(dict(self.drive)))
            _validate_drive_parameters(self.action, self.strategy, self.drive)


#: Declared timing knobs a drive strategy may carry.  Only these exist: a
#: profile describes a finite, checkable timing contract, it does not embed a
#: program that could produce arbitrary behaviour.
_PULSE_KEYS = ("pulse_cycles", "min_gap_cycles")
_HOLD_KEYS = ("handshake",)


def _validate_drive_parameters(action: str, strategy: str | None,
                               drive: Mapping[str, object]) -> None:
    if action != "fuzz":
        _error(f"drive-parameters-only-for-fuzz:{action}")
    if strategy is None:
        _error("drive-parameters-require-a-strategy")
    allowed = {
        "pulse": _PULSE_KEYS,
        "hold": _HOLD_KEYS,
        "cycle_value": (),
        "reset_sampled": (),
    }[strategy]
    unknown = sorted(set(drive) - set(allowed))
    if unknown:
        _error(f"unsupported-drive-parameter:{strategy}:{','.join(unknown)}")
    for name, value in drive.items():
        if name in ("pulse_cycles", "min_gap_cycles"):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                _error(f"invalid-drive-parameter:{name}")
            if name == "pulse_cycles" and value < 1:
                _error("invalid-drive-parameter:pulse_cycles")
        elif name == "handshake":
            if not isinstance(value, bool):
                _error("invalid-drive-parameter:handshake")


@dataclass(frozen=True, slots=True)
class CpuContract:
    family: str
    xlen: int
    extensions: tuple[str, ...]
    reset_vector: int
    master_endpoints: tuple[str, ...]
    irq_entry_endpoint: str | None = None
    irq_entry_role: str | None = None
    irq_entry_polarity: str = "active_high"
    irq_semantics: str | None = None
    boot_address_required: bool = True


@dataclass(frozen=True, slots=True)
class ComponentProfile:
    component_id: str
    kind: str
    source: SourceLocator
    endpoints: tuple[EndpointSpec, ...]
    clocks: tuple[ClockBinding, ...]
    resets: tuple[ResetBinding, ...]
    capabilities: Mapping[str, object]
    port_actions: tuple[PortAction, ...]
    description: str = ""
    address: AddressSpec | None = None
    interrupts: tuple[InterruptSource, ...] = ()
    cpu: CpuContract | None = None
    evidence: Mapping[str, object] = field(default_factory=dict)
    source_document: Mapping[str, object] = field(default_factory=dict, repr=False,
                                                  compare=False)

    def endpoint(self, endpoint_id: str) -> EndpointSpec:
        for item in self.endpoints:
            if item.endpoint_id == endpoint_id:
                return item
        raise ComponentProfileError(f"unknown-endpoint:{endpoint_id}")

    def capability(self, name: str, default: object = None) -> object:
        return self.capabilities.get(name, default)

    def as_interface_description(self) -> InterfaceDescription:
        """Project the endpoint vocabulary onto the existing description type."""
        endpoints = []
        for endpoint in self.endpoints:
            fields = []
            for item in endpoint.fields:
                fields.append(FieldHint(
                    role=item.role,
                    aliases=item.aliases,
                    required=item.required,
                    physical=item.physical,
                    randomizable=item.randomizable,
                ))
            endpoints.append(EndpointDescription(
                endpoint_id=endpoint.endpoint_id,
                function=endpoint.function,
                required=endpoint.required,
                protocol=endpoint.protocol,
                fields=tuple(fields),
            ))
        return InterfaceDescription(source=self.source, endpoints=tuple(endpoints))


# ---------------------------------------------------------------------------
# request records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ComponentInstance:
    instance_id: str
    profile: ComponentProfile
    parameters: Mapping[str, object] = field(default_factory=dict)
    address: int | None = None

    def parameter(self, name: str, default: object = None) -> object:
        return self.parameters.get(name, default)


@dataclass(frozen=True, slots=True)
class PeerAttachmentRequest:
    """One declared peer attachment for an ``external_pins`` endpoint.

    The record never names a peer model: which implemented model drives the
    interface is decided from the endpoint's declared roles
    (``soc_peer_plan.match_models``), so a request cannot select a peer by name
    and cannot slip a wrong peer past the role check.  ``attach=False`` is the
    explicit "this interface stays external" declaration; the parameters are the
    peer model's own configuration and are only meaningful when attaching.
    """

    instance_id: str
    endpoint_id: str
    attach: bool = True
    parameters: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    region_id: str
    component_id: str
    base: int
    size: int
    permissions: Mapping[str, bool]
    physical_memory_id: str
    initialization_policy: str
    image: str | None = None


@dataclass(frozen=True, slots=True)
class AddressPolicy:
    mmio_base: int
    mmio_limit: int
    alignment: int


@dataclass(frozen=True, slots=True)
class CompositionRequest:
    request_id: str
    cpu: ComponentInstance
    peripherals: tuple[ComponentInstance, ...]
    memory: tuple[MemoryRegion, ...]
    address_policy: AddressPolicy
    clock_domain: str
    clock_frequency_hz: int
    reset_domain: str
    reset_polarity: str
    reset_synchronous: bool
    test_modes: tuple[str, ...]
    provenance: Mapping[str, object] = field(default_factory=dict)
    #: Declared peer attachments.  An ``external_pins`` endpoint that is not
    #: named here keeps the behaviour the profile path always had: it is
    #: exported to the generated top and driven by the environment.
    peers: tuple[PeerAttachmentRequest, ...] = ()
    #: Declared reset release order, captured from ``reset.sequence`` and its
    #: synonyms.  A non-empty sequence is refused by name
    #: (``reset-sequence-unsupported``): only one simultaneously released reset
    #: domain is composed.
    reset_sequence: tuple[str, ...] = ()

    def instances(self) -> tuple[ComponentInstance, ...]:
        return (self.cpu, *self.peripherals)


# ---------------------------------------------------------------------------
# loaders
# ---------------------------------------------------------------------------


def _document(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return value
    if isinstance(value, (str, PathLike)):
        with Path(value).open(encoding="utf-8") as source:
            loaded = json.load(source)
        if isinstance(loaded, Mapping):
            return loaded
    _error("document-must-be-object-or-path")


def _strings(value: object, reason: str) -> tuple[str, ...]:
    items = _sequence(value, reason)
    return tuple(_text(item, reason) for item in items)


def _protocol(value: object, reason: str) -> tuple[str, str]:
    items = _sequence(value, reason)
    if len(items) != 2:
        _error(reason)
    return (_text(items[0], reason), _text(items[1], reason))


def _elaboration(value: object) -> ElaborationSettings | None:
    if value is None:
        return None
    document = _mapping(value, "invalid-elaboration")
    frontend = document.get("frontend", "verilator-json")
    if frontend != "verilator-json":
        _error("unsupported-elaboration-frontend")

    def pairs(name: str) -> tuple[tuple[str, str], ...]:
        records = _sequence(document.get(name, []), "invalid-elaboration")
        result = []
        for record in records:
            item = _mapping(record, "invalid-elaboration")
            result.append((str(item.get("name")), str(item.get("value"))))
        return tuple(result)

    return ElaborationSettings(
        frontend=frontend,
        defines=pairs("defines"),
        parameters=pairs("parameters"),
        warning_policy=str(document.get("warning_policy", "fatal")),
    )


def _top_port_selection(document: Mapping[str, object]) -> str:
    selection = str(document.get("top_port_selection", "all"))
    if selection not in ("all", "declared"):
        _error(f"unsupported-top-port-selection:{selection}")
    return selection


def _declared_top_ports(profile: ComponentProfile) -> tuple[str, ...]:
    """Every physical port the profile binds, used for a bounded elaboration."""
    names: set[str] = set()
    for endpoint in profile.endpoints:
        for item in endpoint.fields:
            if item.physical is not None:
                names.add(item.physical.port)
            names.update(item.aliases)
    names.update(binding.port for binding in profile.clocks)
    names.update(binding.port for binding in profile.resets)
    # Port actions are part of the declaration by definition: a port that only
    # appears in a port_action is exactly the port the selection must keep.
    names.update(action.port for action in profile.port_actions)
    return tuple(sorted(names))


def _source_locator(value: object) -> SourceLocator:
    document = _mapping(value, "invalid-source")
    revision = _text(document.get("revision"), "invalid-source-revision")
    if re.fullmatch(r"(?:git:[0-9a-f]{40}|sha256:[0-9a-f]{64})", revision) is None:
        _error("invalid-source-revision")
    repositories = []
    for item in _sequence(document.get("repositories", []), "invalid-source-repositories"):
        record = _mapping(item, "invalid-source-repositories")
        repositories.append(RepositoryPin(str(record.get("path")), str(record.get("revision"))))
    variables = []
    for item in _sequence(document.get("filelist_variables", []), "invalid-filelist-variables"):
        record = _mapping(item, "invalid-filelist-variables")
        variables.append((str(record.get("name")), str(record.get("value"))))
    _top_port_selection(document)
    return SourceLocator(
        source_root=_text(document.get("root"), "invalid-source-root"),
        revision=revision,
        top_module=_identifier(document.get("top_module"), "invalid-source-top-module"),
        files=_strings(document.get("files", []), "invalid-source-files"),
        filelist=document.get("filelist"),  # type: ignore[arg-type]
        include_roots=_strings(document.get("include_roots", []), "invalid-source-include-roots"),
        elaboration=_elaboration(document.get("elaboration")),
        repositories=tuple(repositories),
        filelist_variables=tuple(variables),
    )


def _physical(value: object, reason: str) -> tuple[PhysicalSelector, tuple[int, int] | None]:
    """A member selector plus the inclusive bit span it declares, if any."""
    document = _mapping(value, reason)
    member_path = _strings(document.get("member_path", []), reason)
    if not member_path:
        _error(reason)
    span = _declared_span(document.get("bit_range"),
                          "invalid-profile-field-member-bits")
    return (PhysicalSelector(port=_identifier(document.get("port"), reason),
                             member_path=member_path), span)


def _declared_span(value: object, reason: str) -> tuple[int, int] | None:
    """An inclusive ``[lo, hi]`` span declared by a profile."""
    if value is None:
        return None
    items = _sequence(value, reason)
    if len(items) != 2:
        _error(reason)
    low = _integer(items[0], reason, minimum=0)
    high = _integer(items[1], reason, minimum=0)
    if high < low:
        _error(reason)
    return (low, high)


def _field(value: object) -> ProfileField:
    document = _mapping(value, "invalid-profile-field")
    role = _identifier(document.get("role"), "invalid-profile-field-role")
    direction = document.get("direction")
    if direction is not None and direction not in ("input", "output", "inout"):
        _error("invalid-profile-field-direction")
    width = document.get("width")
    if width is not None:
        width = _integer(width, "invalid-profile-field-width", minimum=1)
    physical_value = document.get("physical")
    bit_range = _declared_span(document.get("bit_range"),
                               "invalid-profile-field-bit-range")
    if physical_value is not None and bit_range is not None:
        # One selector per role: a member path and a plain-port slice cannot both
        # decide which bits the role owns.
        _error("profile-field-selector-ambiguous")
    physical, member_bits = (None, None)
    if physical_value is not None:
        physical, member_bits = _physical(physical_value, "invalid-profile-field-physical")
    return ProfileField(
        role=role,
        direction=direction,  # type: ignore[arg-type]
        width=width,  # type: ignore[arg-type]
        aliases=_strings(document.get("aliases", []), "invalid-profile-field-aliases"),
        physical=physical,
        required=_boolean(document.get("required", True), "invalid-profile-field-required"),
        randomizable=_boolean(document.get("randomizable", False), "invalid-profile-randomizable"),
        bit_range=bit_range,
        member_bits=member_bits,
    )


def _endpoint(value: object) -> EndpointSpec:
    document = _mapping(value, "invalid-endpoint")
    function = _text(document.get("function"), "invalid-endpoint-function")
    if function not in FUNCTION_DIRECTIONS:
        _error(f"unsupported-endpoint-function:{function}")
    protocol_value = document.get("protocol")
    protocol = _protocol(protocol_value, "invalid-endpoint-protocol") if protocol_value is not None else None
    if FUNCTION_DIRECTIONS[function] in ("protocol", "protocol-inverted") and protocol is None:
        _error("endpoint-protocol-required")
    fields = tuple(_field(item) for item in _sequence(document.get("fields", []), "invalid-endpoint-fields"))
    roles = [item.role for item in fields]
    if len(set(roles)) != len(roles):
        _error("duplicate-endpoint-field-role")
    return EndpointSpec(
        endpoint_id=_text(document.get("endpoint_id"), "invalid-endpoint-id"),
        function=function,
        protocol=protocol,
        fields=fields,
        clock=document.get("clock"),  # type: ignore[arg-type]
        reset=document.get("reset"),  # type: ignore[arg-type]
        required=_boolean(document.get("required", True), "invalid-endpoint-required"),
    )


def _port_action(value: object) -> PortAction:
    document = _mapping(value, "invalid-port-action-record")
    bits_value = document.get("bits")
    bits: tuple[int, ...] = ()
    if bits_value is not None:
        bits = tuple(_integer(item, "invalid-port-action-bits", minimum=0)
                     for item in _sequence(bits_value, "invalid-port-action-bits"))
        if len(set(bits)) != len(bits):
            _error("duplicate-port-action-bits")
        bits = tuple(sorted(bits))
    action = _text(document.get("action"), "invalid-port-action")
    value_field = document.get("value")
    if value_field is not None:
        value_field = _integer(value_field, "invalid-port-action-value", minimum=0)
    strategy = document.get("strategy")
    if strategy is not None:
        strategy = _text(strategy, "invalid-drive-strategy")
    protocol_value = document.get("protocol")
    return PortAction(
        port=_identifier(document.get("port"), "invalid-port-action-port"),
        action=action,
        member_path=_strings(document.get("member_path", []), "invalid-port-action-member-path"),
        bits=bits,
        value=value_field,  # type: ignore[arg-type]
        reason=_text(document.get("reason"), "port-action-requires-reason"),
        strategy=strategy,  # type: ignore[arg-type]
        protocol=_protocol(protocol_value, "invalid-port-action-protocol")
        if protocol_value is not None else None,
        role=document.get("role"),  # type: ignore[arg-type]
        drive=dict(_mapping(document.get("drive", {}), "invalid-port-action-drive")),
    )


def _clock(value: object) -> ClockBinding:
    document = _mapping(value, "invalid-clock-binding")
    return ClockBinding(
        port=_identifier(document.get("port"), "invalid-clock-port"),
        domain=_identifier(document.get("domain"), "invalid-clock-domain"),
        frequency_hz=_integer(document.get("frequency_hz"), "invalid-clock-frequency", minimum=1),
    )


def _reset(value: object) -> ResetBinding:
    document = _mapping(value, "invalid-reset-binding")
    polarity = _text(document.get("polarity"), "invalid-reset-polarity")
    if polarity not in POLARITIES:
        _error("invalid-reset-polarity")
    # A declared release dependency is captured, never ignored: the composer
    # builds one simultaneously released reset domain and refuses an ordered one
    # by name (soc_scope.reset-sequence-unsupported).
    after: list[str] = []
    for key in RESET_SEQUENCE_KEYS:
        if key not in document:
            continue
        declared = document[key]
        if isinstance(declared, str):
            after.append(_token(declared, "invalid-reset-sequence"))
        else:
            after.extend(_token(item, "invalid-reset-sequence")
                         for item in _sequence(declared, "invalid-reset-sequence"))
    return ResetBinding(
        port=_identifier(document.get("port"), "invalid-reset-port"),
        domain=_identifier(document.get("domain"), "invalid-reset-domain"),
        polarity=polarity,
        synchronous=_boolean(document.get("synchronous"), "invalid-reset-synchronous"),
        release=str(document.get("release", "")),
        sequence_after=tuple(after),
    )


def _interrupt(value: object) -> InterruptSource:
    document = _mapping(value, "invalid-interrupt-source")
    trigger = document.get("trigger", "level")
    if trigger not in INTERRUPT_TRIGGERS:
        _error(f"unsupported-interrupt-trigger:{trigger}")
    polarity = _text(document.get("polarity"), "invalid-interrupt-polarity")
    if polarity not in POLARITIES:
        _error("invalid-interrupt-polarity")
    source_id = document.get("source_id", "")
    if source_id != "":
        source_id = _identifier(source_id, "invalid-interrupt-source-id")
    bit = document.get("bit")
    if bit is not None:
        bit = _integer(bit, "invalid-interrupt-bit", minimum=0)
    # ``pulse_width_cycles`` is the declared capture contract of a pulse source
    # and is meaningless for the others, so it is required exactly when it
    # applies instead of being accepted and ignored.
    pulse_width = document.get("pulse_width_cycles")
    if pulse_width is not None:
        pulse_width = _integer(pulse_width, "invalid-interrupt-pulse-width", minimum=1)
    detect_width = document.get("detect_pulse_cycles", 1)
    detect_width = _integer(detect_width, "invalid-interrupt-detect-pulse-width", minimum=1)
    if trigger == "pulse" and pulse_width is None:
        _error("interrupt-pulse-width-required")
    if trigger != "pulse" and pulse_width is not None:
        _error(f"interrupt-pulse-width-only-for-pulse-trigger:{trigger}")
    if trigger not in INTERRUPT_TRIGGERS_EDGE_DETECTED and \
            document.get("detect_pulse_cycles") is not None:
        _error(f"interrupt-detect-pulse-width-only-for-edge-trigger:{trigger}")
    prerequisites: list[Mapping[str, object]] = []
    for index, item in enumerate(_sequence(document.get("prerequisites", []),
                                            "invalid-interrupt-prerequisites")):
        row = _mapping(item, "invalid-interrupt-prerequisite")
        operation = row.get("operation", "set_bits")
        if operation != "set_bits":
            _error(f"unsupported-interrupt-prerequisite-operation:{operation}")
        register = _identifier(row.get("register"),
                               f"invalid-interrupt-prerequisite-register:{index}")
        offset = _integer(row.get("offset"),
                          f"invalid-interrupt-prerequisite-offset:{index}", minimum=0)
        mask = _integer(row.get("mask"),
                        f"invalid-interrupt-prerequisite-mask:{index}", minimum=1)
        reason = _text(row.get("reason"),
                       f"invalid-interrupt-prerequisite-reason:{index}")
        prerequisites.append({"register": register, "offset": offset, "mask": mask,
                              "reason": reason, "operation": "set_bits"})
    raise_actions: list[Mapping[str, object]] = []
    for index, item in enumerate(_sequence(document.get("raise_actions", []),
                                            "invalid-interrupt-raise-actions")):
        row = _mapping(item, "invalid-interrupt-raise-action")
        operation = row.get("operation", "write_value")
        if operation != "write_value":
            _error(f"unsupported-interrupt-raise-operation:{operation}")
        register = _identifier(row.get("register"),
                               f"invalid-interrupt-raise-register:{index}")
        offset = _integer(row.get("offset"),
                          f"invalid-interrupt-raise-offset:{index}", minimum=0)
        value = _integer(row.get("value"),
                         f"invalid-interrupt-raise-value:{index}", minimum=0)
        reason = _text(row.get("reason"),
                       f"invalid-interrupt-raise-reason:{index}")
        raise_actions.append({"register": register, "offset": offset, "value": value,
                              "reason": reason, "operation": "write_value"})
    return InterruptSource(
        endpoint_id=_text(document.get("endpoint_id"), "invalid-interrupt-endpoint"),
        role=_identifier(document.get("role"), "invalid-interrupt-role"),
        polarity=polarity,
        clock_domain=_identifier(document.get("clock_domain"), "invalid-interrupt-domain"),
        hold=_text(document.get("hold"), "interrupt-hold-required"),
        clear=_text(document.get("clear"), "interrupt-clear-required"),
        trigger=trigger,
        source_id=source_id,
        bit=bit,
        pulse_width_cycles=pulse_width,
        detect_pulse_cycles=detect_width,
        prerequisites=tuple(prerequisites),
        raise_actions=tuple(raise_actions),
    )


def _register(value: object) -> RegisterSpec:
    document = _mapping(value, "invalid-register")
    access = _text(document.get("access"), "invalid-register-access")
    if access not in ("ro", "rw", "wo"):
        _error("invalid-register-access")
    name = _identifier(document.get("name"), "invalid-register-name")
    width = _integer(document.get("width", 32), "invalid-register-width", minimum=1)
    side_effect = str(document.get("side_effect", "none"))
    reset_value = document.get("reset_value")
    if reset_value is not None:
        reset_value = _integer(reset_value, "invalid-register-reset-value", minimum=0)
        if reset_value >= (1 << width):
            _error(f"register-reset-value-exceeds-width:{name}")
    writable_bits = document.get("writable_bits")
    if writable_bits is not None:
        writable_bits = _integer(writable_bits, "invalid-register-writable-bits", minimum=0)
        if writable_bits >= (1 << width):
            _error(f"register-writable-bits-exceed-width:{name}")
        if writable_bits == 0:
            _error(f"register-writable-bits-empty:{name}")
        if access == "ro":
            _error(f"writable-bits-on-read-only-register:{name}")
    clears_register = document.get("clears_register")
    if clears_register is not None:
        clears_register = _identifier(clears_register, "invalid-clears-register")
        if side_effect not in CLEARING_SIDE_EFFECTS:
            _error(f"clears-register-without-a-clearing-side-effect:{name}:{side_effect}")
    return RegisterSpec(
        name=name,
        offset=_integer(document.get("offset"), "invalid-register-offset", minimum=0),
        width=width,
        access=access,
        side_effect=side_effect,
        reset_value=reset_value,
        writable_bits=writable_bits,
        clears_register=clears_register,
    )


def _check_register_clears_addresses(registers: Sequence[RegisterSpec]) -> None:
    """Every declared ``clears_register`` must name a register of this map.

    The probe is a declared fact of the same address map, so a name that does
    not resolve is a declaration error, never a silent fallback to the
    register itself.
    """
    names = {register.name for register in registers}
    for register in registers:
        if register.clears_register is None:
            continue
        if register.clears_register not in names:
            _error(f"unknown-clears-register:{register.name}:{register.clears_register}")
        probe = next(item for item in registers if item.name == register.clears_register)
        if probe.access not in ("ro", "rw"):
            _error(f"clears-register-not-readable:{register.name}:{probe.name}")


def _address(value: object) -> AddressSpec:
    document = _mapping(value, "invalid-address-spec")
    window_size = _integer(document.get("window_size"), "invalid-address-window")
    alignment = _integer(document.get("alignment"), "invalid-address-alignment")
    if window_size <= 0 or window_size & (window_size - 1):
        _error("address-window-not-power-of-two")
    if alignment <= 0 or alignment & (alignment - 1):
        _error("address-alignment-not-power-of-two")
    registers = tuple(_register(item) for item in _sequence(document.get("registers", []),
                                                            "invalid-register-list"))
    _check_register_clears_addresses(registers)
    return AddressSpec(
        window_size=window_size,
        alignment=alignment,
        registers=registers,
    )


def _cpu(value: object) -> CpuContract:
    document = _mapping(value, "invalid-cpu-contract")
    family = _text(document.get("family"), "invalid-cpu-family")
    xlen = _integer(document.get("xlen"), "invalid-cpu-xlen", minimum=1)
    polarity = document.get("irq_entry_polarity", "active_high")
    if polarity not in POLARITIES:
        _error("invalid-cpu-irq-entry-polarity")
    return CpuContract(
        family=family,
        xlen=xlen,
        extensions=_strings(document.get("extensions", []), "invalid-cpu-extensions"),
        reset_vector=_integer(document.get("reset_vector"), "invalid-cpu-reset-vector", minimum=0),
        master_endpoints=_strings(document.get("master_endpoints", []), "invalid-cpu-master-endpoints"),
        irq_entry_endpoint=document.get("irq_entry_endpoint"),  # type: ignore[arg-type]
        irq_entry_role=document.get("irq_entry_role"),  # type: ignore[arg-type]
        irq_entry_polarity=polarity,
        irq_semantics=document.get("irq_semantics"),  # type: ignore[arg-type]
        boot_address_required=_boolean(document.get("boot_address_required", True),
                                       "invalid-cpu-boot-address"),
    )


def load_component_profile(document_or_path: object) -> ComponentProfile:
    """Load and structurally validate one component profile."""
    document = _document(document_or_path)
    _reject_programming_keys(document, "profile")
    version = document.get("schema_version")
    if version != COMPONENT_PROFILE_SCHEMA:
        _error(f"unsupported-profile-schema:{version}")
    kind = document.get("kind")
    if kind not in COMPONENT_KINDS:
        _error(f"unsupported-component-kind:{kind}")
    endpoints = tuple(_endpoint(item) for item in _sequence(document.get("endpoints", []),
                                                            "invalid-endpoints"))
    endpoint_ids = [item.endpoint_id for item in endpoints]
    if len(set(endpoint_ids)) != len(endpoint_ids):
        _error("duplicate-endpoint-id")
    clocks = tuple(_clock(item) for item in _sequence(document.get("clocks", []), "invalid-clocks"))
    resets = tuple(_reset(item) for item in _sequence(document.get("resets", []), "invalid-resets"))
    if not clocks:
        _error("profile-clock-required")
    if not resets:
        _error("profile-reset-required")
    capabilities = dict(_mapping(document.get("capabilities", {}), "invalid-capabilities"))
    address = _address(document["address"]) if document.get("address") is not None else None
    interrupts = tuple(_interrupt(item) for item in _sequence(document.get("interrupts", []),
                                                             "invalid-interrupts"))
    cpu = _cpu(document["cpu"]) if document.get("cpu") is not None else None
    if kind == "cpu" and cpu is None:
        _error("cpu-profile-requires-cpu-contract")
    if kind == "peripheral" and address is None:
        _error("peripheral-profile-requires-address")
    if kind == "cpu" and address is not None:
        _error("cpu-profile-must-not-declare-mmio-address")
    port_actions = tuple(_port_action(item) for item in
                         _sequence(document.get("port_actions", []), "invalid-port-actions"))
    keys = [(item.port, item.member_path, item.bits) for item in port_actions]
    if len(set(keys)) != len(keys):
        _error("duplicate-port-action")
    profile = ComponentProfile(
        component_id=_identifier(document.get("component_id"), "invalid-component-id"),
        kind=kind,  # type: ignore[arg-type]
        source=_source_locator(document.get("source")),
        endpoints=endpoints,
        clocks=clocks,
        resets=resets,
        capabilities=capabilities,
        port_actions=port_actions,
        description=str(document.get("description", "")),
        address=address,
        interrupts=interrupts,
        cpu=cpu,
        evidence=dict(_mapping(document.get("evidence", {}), "invalid-evidence")),
        source_document=dict(_mapping(document.get("source"), "invalid-source")),
    )
    _validate_profile_self_consistency(profile)
    return profile


#: A declared role selector, from least to most specific: the whole port, a
#: plain vector slice, or a member path (which may name an intermediate struct).
_SELECTOR_WHOLE = "whole"
_SELECTOR_BITS = "bits"
_SELECTOR_MEMBER = "member"


def _field_selector(item: ProfileField) -> tuple[str, str, object] | None:
    """``(kind, port, key)`` for a field, or ``None`` when the port is a choice.

    A field with several aliases names no single port at load time, exactly as
    before: which alias exists is an elaboration question.  Every other field
    names one port and one selector, which is what the overlap check needs.
    """
    if item.physical is not None:
        return (_SELECTOR_MEMBER, item.physical.port, item.physical.member_path)
    if len(item.aliases) != 1:
        return None
    name = item.aliases[0]
    if item.bit_range is not None:
        return (_SELECTOR_BITS, name, item.bit_range)
    return (_SELECTOR_WHOLE, name, None)


def _selectors_overlap(first: tuple[str, str, object],
                       second: tuple[str, str, object]) -> bool:
    """Whether two declared selectors on one port can own a common bit.

    Member paths are checked by the prefix rule, which is the only sound answer
    before elaboration: ``aw`` and ``aw.id`` overlap, ``aw.id`` and ``aw.addr``
    do not.  An intermediate struct member and its own leaves therefore overlap,
    which is what makes a "declare the whole struct and one of its members"
    profile a reported error rather than a second driver on those bits.
    """
    first_kind, _first_port, first_key = first
    second_kind, _second_port, second_key = second
    if first_kind == _SELECTOR_WHOLE or second_kind == _SELECTOR_WHOLE:
        return True
    if first_kind == _SELECTOR_BITS and second_kind == _SELECTOR_BITS:
        first_lo, first_hi = first_key  # type: ignore[misc]
        second_lo, second_hi = second_key  # type: ignore[misc]
        return first_lo <= second_hi and second_lo <= first_hi
    if first_kind == _SELECTOR_BITS or second_kind == _SELECTOR_BITS:
        # A bit slice of a port that another role reads as a struct: the bit
        # numbering of a struct member is only known after elaboration, so the
        # pair is refused instead of being assumed disjoint.
        return True
    first_path, second_path = first_key, second_key  # type: ignore[misc]
    shorter = min(len(first_path), len(second_path))
    return tuple(first_path[:shorter]) == tuple(second_path[:shorter])


def _validate_profile_self_consistency(profile: ComponentProfile) -> None:
    endpoint_ids = {item.endpoint_id for item in profile.endpoints}
    by_port: dict[str, list[str]] = {}
    selectors: dict[str, list[tuple[str, tuple[str, str, object]]]] = {}
    for endpoint in profile.endpoints:
        for item in endpoint.fields:
            selector = _field_selector(item)
            if selector is None:
                continue
            kind, port, _key = selector
            owner = f"{endpoint.endpoint_id}:{item.role}"
            selectors.setdefault(port, []).append((owner, (kind, port, selector[2])))
    for port, owners in selectors.items():
        for index, (owner, selector) in enumerate(owners):
            for other_owner, other in owners[:index]:
                if selector[2] == other[2] and selector[0] == other[0]:
                    _error(f"duplicate-port-binding:{port}:{owner},{other_owner}")
                if _selectors_overlap(selector, other):
                    _error(f"overlapping-port-binding:{port}:{owner}+{other_owner}")
    for port, owners in selectors.items():
        by_port[port] = [owner for owner, _selector in owners]
    for binding in profile.clocks:
        if binding.port not in by_port:
            by_port[binding.port] = []
    for item in profile.interrupts:
        if item.endpoint_id not in endpoint_ids:
            _error(f"interrupt-endpoint-unknown:{item.endpoint_id}")
        endpoint = profile.endpoint(item.endpoint_id)
        if endpoint.function != "interrupt_source":
            _error(f"interrupt-endpoint-not-a-source:{item.endpoint_id}")
        if item.role not in {field.role for field in endpoint.fields}:
            _error(f"interrupt-role-unknown:{item.endpoint_id}:{item.role}")
        if item.clock_domain not in {clock.domain for clock in profile.clocks}:
            _error(f"interrupt-clock-domain-unknown:{item.clock_domain}")
    if profile.cpu is not None:
        if not profile.cpu.master_endpoints:
            _error("cpu-master-endpoints-required")
        for endpoint_id in profile.cpu.master_endpoints:
            if endpoint_id not in endpoint_ids:
                _error(f"cpu-master-endpoint-unknown:{endpoint_id}")
            function = profile.endpoint(endpoint_id).function
            if FUNCTION_DIRECTIONS[function] != "protocol-inverted":
                _error(f"cpu-master-endpoint-not-a-master:{endpoint_id}")
    if profile.address is not None:
        registers_by_name = {item.name: item for item in profile.address.registers}
        for register in profile.address.registers:
            if register.offset + register.width // 8 > profile.address.window_size:
                _error(f"register-outside-window:{register.name}")
        for source in profile.interrupts:
            for prerequisite in source.prerequisites:
                name = str(prerequisite["register"])
                register = registers_by_name.get(name)
                if register is None:
                    _error(f"interrupt-prerequisite-register-unknown:{name}")
                if str(register.access) != "rw":
                    _error(f"interrupt-prerequisite-register-not-writable:{name}")
                if int(prerequisite["offset"]) != int(register.offset):
                    _error(f"interrupt-prerequisite-offset-mismatch:{name}:"
                           f"{prerequisite['offset']}!={register.offset}")
                mask = int(prerequisite["mask"])
                if mask >= (1 << int(register.width)):
                    _error(f"interrupt-prerequisite-mask-outside-register:{name}:{mask}")
            for action in source.raise_actions:
                name = str(action["register"])
                register = registers_by_name.get(name)
                if register is None:
                    _error(f"interrupt-raise-register-unknown:{name}")
                if str(register.access) not in ("rw", "wo"):
                    _error(f"interrupt-raise-register-not-writable:{name}")
                if int(action["offset"]) != int(register.offset):
                    _error(f"interrupt-raise-offset-mismatch:{name}:"
                           f"{action['offset']}!={register.offset}")
                if int(action["value"]) >= (1 << int(register.width)):
                    _error(f"interrupt-raise-value-outside-register:{name}")
    else:
        for source in profile.interrupts:
            if source.prerequisites:
                _error("interrupt-prerequisites-require-address")
            if source.raise_actions:
                _error("interrupt-raise-actions-require-address")
    for action in profile.port_actions:
        if action.action == "unconnected" and action.protocol is None:
            _error(f"unconnected-requires-contract:{action.port}")


# ---------------------------------------------------------------------------
# composition request
# ---------------------------------------------------------------------------


def _memory_region(value: object) -> MemoryRegion:
    document = _mapping(value, "invalid-memory-region")
    permissions = _mapping(document.get("permissions"), "invalid-memory-permissions")
    policy = _text(document.get("initialization_policy"), "invalid-initialization-policy")
    if policy not in INITIALIZATION_POLICIES:
        _error(f"unsupported-initialization-policy:{policy}")
    return MemoryRegion(
        region_id=_identifier(document.get("region_id"), "invalid-region-id"),
        component_id=_identifier(document.get("component_id", document.get("region_id")),
                                 "invalid-region-component-id"),
        base=_integer(document.get("base"), "invalid-region-base", minimum=0),
        size=_integer(document.get("size"), "invalid-region-size", minimum=1),
        permissions={
            "read": _boolean(permissions.get("read"), "invalid-memory-permissions"),
            "write": _boolean(permissions.get("write"), "invalid-memory-permissions"),
            "execute": _boolean(permissions.get("execute"), "invalid-memory-permissions"),
        },
        physical_memory_id=_identifier(document.get("physical_memory_id"), "invalid-physical-memory"),
        initialization_policy=policy,
        image=document.get("image"),  # type: ignore[arg-type]
    )


def _instance(value: object, profiles: Mapping[str, ComponentProfile], kind: str) -> ComponentInstance:
    document = _mapping(value, "invalid-instance")
    reference = _text(document.get("profile"), "instance-profile-required")
    profile = profiles.get(reference)
    if profile is None:
        # A request may name either the profile file it was loaded from or the
        # component id the profile declares.
        profile = next((item for key, item in profiles.items()
                        if item.component_id == reference or Path(key).name == Path(reference).name),
                       None)
    if profile is None:
        _error(f"unknown-profile:{reference}")
    if profile.kind != kind:
        _error(f"profile-kind-mismatch:{reference}:{profile.kind}!={kind}")
    address_value = document.get("address")
    address = None
    if address_value is not None and address_value != "auto":
        address = _integer(address_value, "invalid-instance-address", minimum=0)
    parameters = dict(_mapping(document.get("parameters", {}), "invalid-instance-parameters"))
    return ComponentInstance(
        instance_id=_identifier(document.get("instance_id"), "invalid-instance-id"),
        profile=profile,
        parameters=parameters,
        address=address,
    )


def _peer_attachment(value: object) -> PeerAttachmentRequest:
    """One declared peer attachment: interface, attach flag and peer parameters."""
    reason = "invalid-peer-models"
    document = _mapping(value, reason)
    unknown = sorted(str(key) for key in document
                     if str(key) not in ("instance_id", "endpoint_id", "attach", "parameters"))
    if unknown:
        _error(f"unsupported-peer-request-key:{','.join(unknown)}")
    attach = _boolean(document.get("attach", True), reason)
    declared = dict(_mapping(document.get("parameters", {}), reason))
    if not attach and declared:
        _error("peer-parameters-without-attachment")
    parameters: dict[str, object] = {}
    for name, item in declared.items():
        if not isinstance(name, str) or not name.isidentifier():
            _error(f"invalid-peer-parameter:{name}")
        parameters[name] = _integer(item, f"invalid-peer-parameter-value:{name}")
    return PeerAttachmentRequest(
        instance_id=_identifier(document.get("instance_id"), reason),
        # An endpoint id is a profile token ("uart.pins"), not an identifier.
        endpoint_id=_token(document.get("endpoint_id"), reason),
        attach=attach,
        parameters=parameters,
    )


def _validate_peer_attachments(request: CompositionRequest) -> None:
    """Every attachment names a declared external interface exactly once."""
    instances = {item.instance_id: item for item in request.instances()}
    seen: set[tuple[str, str]] = set()
    for item in request.peers:
        instance = instances.get(item.instance_id)
        if instance is None:
            _error(f"peer-instance-unknown:{item.instance_id}")
        endpoint = next((entry for entry in instance.profile.endpoints
                         if entry.endpoint_id == item.endpoint_id), None)
        if endpoint is None:
            _error(f"peer-endpoint-unknown:{item.instance_id}:{item.endpoint_id}")
        if endpoint.function != "external_pins":
            _error(f"peer-endpoint-not-external:{item.instance_id}:{item.endpoint_id}:"
                   f"{endpoint.function}")
        key = (item.instance_id, item.endpoint_id)
        if key in seen:
            _error(f"duplicate-peer-attachment:{item.instance_id}:{item.endpoint_id}")
        seen.add(key)


def load_composition_request(document_or_path: object, *,
                             profiles: Mapping[str, ComponentProfile]) -> CompositionRequest:
    """Load a composition request against already loaded profiles."""
    document = _document(document_or_path)
    _reject_programming_keys(document, "request")
    version = document.get("schema_version")
    if version != COMPOSITION_REQUEST_SCHEMA:
        _error(f"unsupported-request-schema:{version}")
    cpu = _instance(document.get("cpu"), profiles, "cpu")
    peripherals = tuple(_instance(item, profiles, "peripheral")
                        for item in _sequence(document.get("peripherals", []), "invalid-peripherals"))
    identifiers = [cpu.instance_id] + [item.instance_id for item in peripherals]
    if len(set(identifiers)) != len(identifiers):
        _error("duplicate-instance-id")
    memory = tuple(_memory_region(item) for item in
                   _sequence(document.get("memory", []), "invalid-memory"))
    region_ids = [item.region_id for item in memory]
    if len(set(region_ids)) != len(region_ids):
        _error("duplicate-region-id")
    if not memory:
        _error("memory-regions-required")
    policy_document = _mapping(document.get("address_policy", {}), "invalid-address-policy")
    alignment = _integer(policy_document.get("alignment", 4096), "invalid-address-alignment",
                         minimum=1)
    if alignment & (alignment - 1):
        _error("address-alignment-not-power-of-two")
    address_policy = AddressPolicy(
        mmio_base=_integer(policy_document.get("mmio_base"), "invalid-mmio-base", minimum=0),
        mmio_limit=_integer(policy_document.get("mmio_limit"), "invalid-mmio-limit", minimum=1),
        alignment=alignment,
    )
    clock = _mapping(document.get("clock", {}), "invalid-clock")
    reset = _mapping(document.get("reset", {}), "invalid-reset")
    polarity = str(reset.get("polarity", "active_low"))
    if polarity not in POLARITIES:
        _error("invalid-reset-polarity")
    modes = _strings(document.get("test_modes", ["cpu_only", "mmio_only", "mixed"]),
                     "invalid-test-modes")
    if not modes:
        _error("test-modes-required")
    for mode in modes:
        if mode not in ("cpu_only", "mmio_only", "mixed"):
            _error(f"unsupported-test-mode:{mode}")
    request = CompositionRequest(
        request_id=_token(document.get("request_id"), "invalid-request-id"),
        cpu=cpu,
        peripherals=peripherals,
        memory=memory,
        address_policy=address_policy,
        clock_domain=_identifier(clock.get("domain", "core"), "invalid-clock-domain"),
        clock_frequency_hz=_integer(clock.get("frequency_hz", 50000000), "invalid-clock-frequency",
                                    minimum=1),
        reset_domain=_identifier(reset.get("domain", "sys_rst"), "invalid-reset-domain"),
        reset_polarity=polarity,
        reset_synchronous=_boolean(reset.get("synchronous", True), "invalid-reset-synchronous"),
        test_modes=tuple(modes),
        provenance=dict(_mapping(document.get("provenance", {}), "invalid-provenance")),
        peers=tuple(_peer_attachment(item) for item in
                    _sequence(document.get("peer_models", []), "invalid-peer-models")),
        reset_sequence=_declared_reset_sequence(reset),
    )
    _validate_request_consistency(request)
    _validate_peer_attachments(request)
    return request


def _declared_reset_sequence(reset: Mapping[str, object]) -> tuple[str, ...]:
    """Capture a declared reset release order instead of ignoring it.

    ``reset.sequence`` and its synonyms are the request-level spelling of "these
    resets are not released together".  The composer builds one simultaneously
    released reset domain, so the declaration is carried into the request and
    refused by name in ``soc_scope`` rather than silently dropped.
    """
    order: list[str] = []
    for key in RESET_SEQUENCE_KEYS:
        if key not in reset:
            continue
        declared = reset[key]
        if isinstance(declared, str):
            order.append(_token(declared, "invalid-reset-sequence"))
        else:
            order.extend(_token(item, "invalid-reset-sequence")
                         for item in _sequence(declared, "invalid-reset-sequence"))
    return tuple(order)


def _validate_request_consistency(request: CompositionRequest) -> None:
    for instance in request.instances():
        for binding in instance.profile.clocks:
            if binding.domain != request.clock_domain:
                _error(f"cross-domain-unsupported:{instance.instance_id}:{binding.domain}")
        for binding in instance.profile.resets:
            if binding.domain != request.reset_domain:
                _error(f"cross-reset-domain-unsupported:{instance.instance_id}:{binding.domain}")
            if binding.polarity != request.reset_polarity:
                _error(f"reset-polarity-mismatch:{instance.instance_id}")
            if binding.synchronous != request.reset_synchronous:
                _error(f"reset-synchrony-mismatch:{instance.instance_id}")
    for region in request.memory:
        if region.initialization_policy == "rom" and region.permissions["write"]:
            _error(f"writable-rom:{region.region_id}")
    ordered = sorted(request.memory, key=lambda item: (item.base, item.region_id))
    for left, right in zip(ordered, ordered[1:]):
        if right.base < left.base + left.size:
            _error(f"overlapping-memory-regions:{left.region_id}+{right.region_id}")
    limit = 1 << 64
    for region in request.memory:
        if region.base + region.size > limit:
            _error(f"address-out-of-range:{region.region_id}")
    if not request.cpu.profile.cpu.master_endpoints:
        _error("cpu-master-endpoints-required")


def load_profiles(paths: Sequence[object]) -> dict[str, ComponentProfile]:
    """Load profiles into a mapping keyed by their own ``component_id``."""
    profiles: dict[str, ComponentProfile] = {}
    for path in paths:
        profile = load_component_profile(path)
        if profile.component_id in profiles:
            _error(f"duplicate-profile-component-id:{profile.component_id}")
        profiles[profile.component_id] = profile
    return profiles


def profile_pin(profile: ComponentProfile, *, base_dir: Path) -> str:
    """Return the source-tree hash a profile should record as its revision."""
    root = (base_dir / profile.source.source_root).resolve()
    if not root.is_dir():
        _error(f"source-root-missing:{profile.source.source_root}")
    patterns = profile.source.files or ()
    files: list[Path] = []
    for name in patterns:
        candidate = (root / name).resolve()
        if candidate.is_file():
            files.append(candidate)
        else:
            files.extend(sorted(candidate.rglob("*.sv")))
            files.extend(sorted(candidate.rglob("*.v")))
    if not files:
        for suffix in ("*.sv", "*.v", "*.svh"):
            files.extend(sorted(root.rglob(suffix)))
    if not files:
        _error("source-files-missing")
    return source_tree_hash(root, files)


# ---------------------------------------------------------------------------
# physical facts and binding
# ---------------------------------------------------------------------------


def _closure_names(root: Path, files: Sequence[Path]) -> tuple[str, ...]:
    """The declared-closure names of the files an elaboration actually read."""
    names: list[str] = []
    for path in files:
        relative = path.resolve().relative_to(root).as_posix()
        if relative not in names:
            names.append(relative)
    return tuple(names)


@dataclass(frozen=True, slots=True)
class PhysicalFacts:
    """The elaboration result of one component's declared source closure."""

    top_module: str
    ports: tuple[ElaboratedPortFact, ...]
    content_hash: str
    revision: str
    modules: tuple[str, ...] = ()
    warning_count: int = 0
    #: "all" when the elaboration returned every top-level port, "declared"
    #: when the profile asked for a bounded selection because the top has
    #: aggregate ports this frontend cannot represent.  A selection is a real
    #: coverage limitation and is reported as unknown, never as verified.
    selection: str = "all"
    #: Every HDL file the elaboration actually read, relative to the profile's
    #: source root, in the order the frontend received them.  A closure declared
    #: as a *filelist* publishes no explicit file list, and the compiled source
    #: list the audit re-elaborates must still be the whole closure rather than
    #: only the file that happens to declare the top module.
    files: tuple[str, ...] = ()

    def port(self, name: str) -> ElaboratedPortFact | None:
        for item in self.ports:
            if item.name == name:
                return item
        return None


@dataclass(frozen=True, slots=True)
class ResolvedField:
    endpoint_id: str
    role: str
    port: str
    member_path: tuple[str, ...]
    direction: str
    width: int
    raw_lo: int
    raw_hi: int
    signed: bool
    source_file: str
    line: int
    #: The whole port's width.  ``width`` is the selected span, so the two are
    #: equal for a whole-port role and differ for a member or a bit slice; the
    #: net naming and the ledger read both.  ``0`` means "not recorded" and is
    #: treated as the port being exactly the selected span.
    port_width: int = 0

    @property
    def key(self) -> str:
        return f"{self.endpoint_id}:{self.role}"

    @property
    def whole_port(self) -> bool:
        """Whether this role owns every bit of its port."""
        container = self.port_width or self.width
        return (self.raw_lo, self.raw_hi) == (0, container - 1)


@dataclass(frozen=True, slots=True)
class ResolvedEndpoint:
    endpoint_id: str
    function: str
    protocol: tuple[str, str] | None
    fields: tuple[ResolvedField, ...]


@dataclass(frozen=True, slots=True)
class ProfileBinding:
    """A profile bound to real elaborated ports, with no silent repairs."""

    component_id: str
    kind: str
    facts: PhysicalFacts
    endpoints: tuple[ResolvedEndpoint, ...]
    clocks: tuple[tuple[ClockBinding, ResolvedField], ...]
    resets: tuple[tuple[ResetBinding, ResolvedField], ...]
    binding_hash: str

    def endpoint(self, endpoint_id: str) -> ResolvedEndpoint:
        for item in self.endpoints:
            if item.endpoint_id == endpoint_id:
                return item
        raise ComponentProfileError(f"unknown-endpoint:{endpoint_id}")

    def field(self, endpoint_id: str, role: str) -> ResolvedField:
        for item in self.endpoint(endpoint_id).fields:
            if item.role == role:
                return item
        raise ComponentProfileError(f"unknown-endpoint-field:{endpoint_id}:{role}")

    def all_fields(self) -> tuple[ResolvedField, ...]:
        return tuple(item for endpoint in self.endpoints for item in endpoint.fields)


def _width_expression(expression: str, capabilities: Mapping[str, object]) -> int | None:
    """Resolve the literal / symbol width expressions the plugin vocabulary uses."""
    text = expression.strip()
    if re.fullmatch(r"[0-9]+", text):
        return int(text)
    symbol = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)(?:\s*/\s*([0-9]+))?", text)
    if symbol is None:
        return None
    value = capabilities.get(symbol.group(1))
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    divisor = int(symbol.group(2)) if symbol.group(2) else 1
    if divisor <= 0 or value % divisor:
        return None
    return value // divisor


def _protocol_field_directions(protocol: tuple[str, str]) -> dict[str, str]:
    from myfuzz.protocols.catalog import load_builtin_protocol

    try:
        plugin = load_builtin_protocol(protocol[0], protocol[1])
    except Exception as error:  # pragma: no cover - catalog errors are configuration errors
        raise ComponentProfileError(f"unknown-protocol:{protocol[0]}@{protocol[1]}") from error
    directions: dict[str, str] = {}
    for item in plugin.fields:
        if item.direction == "host_to_device":
            directions[item.field_id] = "input"
        elif item.direction == "device_to_host":
            directions[item.field_id] = "output"
    return directions


def _protocol_field_widths(protocol: tuple[str, str],
                           capabilities: Mapping[str, object]) -> dict[str, int]:
    from myfuzz.protocols.catalog import load_builtin_protocol

    plugin = load_builtin_protocol(protocol[0], protocol[1])
    widths: dict[str, int] = {}
    for item in plugin.fields:
        width = _width_expression(item.width_expression, capabilities)
        if width is not None:
            widths[item.field_id] = width
    return widths


def _adapter_field_directions(protocol: tuple[str, str]) -> dict[str, str]:
    """Adapter-perspective directions for the roles of a processor-side adapter.

    ``source_ports`` describes the adapter's own ports (OBI ``req_i`` is an
    input it samples).  Recording them in the adapter's convention lets the
    caller invert them exactly once for a CPU-side master endpoint, which is
    how extension roles such as OBI ``be`` / ``error`` or the AXI4 sidebands get
    a checked direction instead of being guessed.
    """
    from .processor_adapters import _ADAPTERS

    adapter = _ADAPTERS.get(protocol)
    if adapter is None:
        return {}
    return {role: direction for role, _port, direction in adapter.source_ports}



def supervisor_available() -> tuple[bool, str]:
    """Report whether this host can run the supervised (RSS-bounded) subprocess.

    The campaign supervisor refuses to launch when it cannot read its own
    process group, which is the case inside restricted sandboxes.  That is a
    host capability fact, not a policy decision, so it is reported explicitly
    instead of being turned into a silent downgrade.
    """
    try:
        from myfuzz.integration.campaign import _verify_process_group_support
    except Exception as error:  # pragma: no cover - import failure is an environment fault
        return False, f"supervisor-import-failed:{type(error).__name__}"
    try:
        _verify_process_group_support()
    except Exception as error:
        return False, f"process-group-unavailable:{error}"
    return True, ""


def _direct_elaboration(profile: ComponentProfile, *, base_dir: Path,
                        selected_top_ports: tuple[str, ...] | None = None) -> PhysicalFacts:
    """One-shot bounded Verilator elaboration without the RSS supervisor.

    Used only when :func:`supervisor_available` reports that the host cannot own
    a process group.  The command is still explicit, shell-free, path-contained
    and time-limited, and the source closure is re-hashed afterwards.
    """
    import hashlib
    import subprocess
    import tempfile

    from myfuzz.composition.source_crawler import _content_hash, _declared_files
    from myfuzz.composition.source_elaboration import (
        ElaborationError,
        extract_physical_ports,
    )

    locator = profile.source
    root = (Path(base_dir) / locator.source_root).resolve()
    if not root.is_dir():
        _error(f"source-root-missing:{locator.source_root}")
    contents: dict[str, bytes] = {}

    def read(path: Path) -> bytes:
        relative = path.resolve().relative_to(root).as_posix()
        if relative not in contents:
            if not path.is_file():
                _error(f"source-file-missing:{relative}")
            contents[relative] = path.read_bytes()
        return contents[relative]

    try:
        files, include_roots, filelist_defines = _declared_files(root, locator, read)
    except SourceCrawlError as error:
        raise ComponentProfileError(f"elaboration-failed:{profile.component_id}:{error}") from error
    if locator.elaboration is not None and filelist_defines:
        _error(f"elaboration-filelist-defines-unsupported:{profile.component_id}")
    content_hash = _content_hash(contents)
    if locator.revision.startswith("sha256:") and locator.revision != content_hash:
        _error(f"content-hash-mismatch:{profile.component_id}")
    if not files:
        _error(f"source-files-missing:{profile.component_id}")
    settings = locator.elaboration
    defines = () if settings is None else settings.defines
    parameters = () if settings is None else settings.parameters
    warning_policy = "fatal" if settings is None else settings.warning_policy
    tool = shutil.which("verilator")
    if tool is None:
        _error(f"elaboration-tool-missing:{profile.component_id}")
    selected = None
    if selected_top_ports is not None:
        if any(not isinstance(item, str) or _IDENTIFIER.fullmatch(item) is None
               for item in selected_top_ports) or len(set(selected_top_ports)) != len(selected_top_ports):
            _error("selected-top-ports-invalid")
        selected = tuple(sorted(selected_top_ports))
    with tempfile.TemporaryDirectory(prefix=".myfuzz-elaboration-", dir=root) as temporary:
        tree_path = Path(temporary) / "ports.tree.json"
        meta_path = Path(temporary) / "ports.meta.json"
        command = [
            "/usr/bin/nice", "-n15", tool, "--json-only", "--no-std-package",
            *(() if warning_policy == "fatal" else ("-Wno-fatal",)),
            "--json-only-output", tree_path.as_posix(),
            "--json-only-meta-output", meta_path.as_posix(),
            "--top-module", locator.top_module,
            *(f"-I{(root / item).as_posix()}" for item in include_roots),
            *(f"-D{name}={value}" for name, value in sorted(defines)),
            *(f"-G{name}={value}" for name, value in sorted(parameters)),
            *(path.as_posix() for path in files),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False,
                                    timeout=_DIRECT_ELABORATION_TIMEOUT_SECONDS, cwd=root.as_posix())
        except subprocess.TimeoutExpired as error:
            raise ComponentProfileError(
                f"elaboration-timeout:{profile.component_id}") from error
        except OSError as error:
            raise ComponentProfileError(
                f"elaboration-launch-failed:{profile.component_id}:{error}") from error
        diagnostics = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0 or not tree_path.is_file():
            raise ComponentProfileError(
                f"elaboration-frontend-error:{profile.component_id}:"
                f"{diagnostics.strip()[:2000]}")
        try:
            tree = json.loads(tree_path.read_text(encoding="utf-8"))
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ComponentProfileError(
                f"elaboration-output-malformed:{profile.component_id}") from error
        mapping = {path.resolve().as_posix(): path.resolve().relative_to(root).as_posix()
                   for path in files}
        try:
            evidence = extract_physical_ports(tree, metadata, top_module=locator.top_module,
                                              source_files=mapping, selected_top_ports=selected)
        except ElaborationError as error:
            raise ComponentProfileError(
                f"elaboration-evidence-error:{profile.component_id}:{error}") from error
        if _content_hash({name: read(root / name) for name in sorted(contents)}) != content_hash:
            _error(f"elaboration-source-changed:{profile.component_id}")
    ports = tuple(
        ElaboratedPortFact(
            item["name"], item["direction"], item["width"], item["signed"],
            item["source"]["file"], item["source"]["line"], item["source"]["column"],
            tuple(ElaboratedMemberFact(tuple(member["path"]), member["width"], member["raw_lo"],
                                       member["raw_hi"], member["signed"],
                                       member["source"]["file"], member["source"]["line"],
                                       member["source"]["column"],
                                       str(member.get("enum_type", "")))
                  for member in item["members"]),
        )
        for item in evidence["ports"]
    )
    warnings = len([line for line in diagnostics.splitlines() if "%Warning" in line])
    return PhysicalFacts(
        top_module=locator.top_module,
        ports=ports,
        content_hash=content_hash,
        revision=locator.revision,
        modules=(),
        warning_count=warnings,
        files=_closure_names(root, files),
    )


#: Bound for the supervisor-free elaboration path.  Verilator JSON on a large
#: closure is slow, but an unbounded wait would make a stuck frontend look like
#: a hung generator instead of a diagnosed failure.
_DIRECT_ELABORATION_TIMEOUT_SECONDS = 600


def elaborate_rtl_module(*, base_dir: Path, source_root: str, top_module: str,
                         files: Sequence[str], include_roots: Sequence[str] = (),
                         defines: Sequence[tuple[str, str]] = (),
                         parameters: Sequence[tuple[str, str]] = (),
                         warning_policy: str = "fatal",
                         revision: str | None = None) -> PhysicalFacts:
    """Elaborate one project-owned RTL module and return its real port facts.

    This is the bounded, supervisor-free frontend used for the environment
    modules the generator instantiates itself (protocol adapters, the interrupt
    controller, the memory model).  Those modules are part of the generator, not
    user components, so they carry no profile and no source pin; the caller
    passes the exact parameter set it is about to render, which is what makes
    the returned widths the widths of the generated instance.
    """
    import subprocess
    import tempfile
    from myfuzz.composition.source_elaboration import ElaborationError, extract_physical_ports

    root = (Path(base_dir) / source_root).resolve()
    if not root.is_dir():
        _error(f"source-root-missing:{source_root}")
    if _IDENTIFIER.fullmatch(top_module) is None:
        _error(f"invalid-top-module:{top_module}")
    resolved = []
    for name in files:
        candidate = (root / name).resolve()
        try:
            candidate.relative_to(root)
        except ValueError as error:
            raise ComponentProfileError(f"source-path-escape:{name}") from error
        if not candidate.is_file():
            _error(f"source-file-missing:{name}")
        resolved.append(candidate)
    if not resolved:
        _error(f"source-files-missing:{top_module}")
    include_dirs = []
    for item in include_roots:
        candidate = (root / item).resolve()
        if not candidate.is_dir():
            _error(f"include-root-missing:{item}")
        include_dirs.append(candidate)
    if warning_policy not in ("fatal", "recorded-nonfatal"):
        _error("unsupported-elaboration-warning-policy")
    tool = shutil.which("verilator")
    if tool is None:
        _error(f"elaboration-tool-missing:{top_module}")
    with tempfile.TemporaryDirectory(prefix=".myfuzz-elaboration-", dir=root) as temporary:
        tree_path = Path(temporary) / "ports.tree.json"
        meta_path = Path(temporary) / "ports.meta.json"
        command = [
            "/usr/bin/nice", "-n15", tool, "--json-only", "--no-std-package",
            *(() if warning_policy == "fatal" else ("-Wno-fatal",)),
            "--json-only-output", tree_path.as_posix(),
            "--json-only-meta-output", meta_path.as_posix(),
            "--top-module", top_module,
            *(f"-I{path.as_posix()}" for path in include_dirs),
            *(f"-D{name}={value}" for name, value in sorted(defines)),
            *(f"-G{name}={value}" for name, value in sorted(parameters)),
            *(path.as_posix() for path in resolved),
        ]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False,
                                    timeout=_DIRECT_ELABORATION_TIMEOUT_SECONDS,
                                    cwd=root.as_posix())
        except subprocess.TimeoutExpired as error:
            raise ComponentProfileError(f"elaboration-timeout:{top_module}") from error
        except OSError as error:
            raise ComponentProfileError(
                f"elaboration-launch-failed:{top_module}:{error}") from error
        diagnostics = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0 or not tree_path.is_file():
            raise ComponentProfileError(
                f"elaboration-frontend-error:{top_module}:{diagnostics.strip()[:2000]}")
        try:
            tree = json.loads(tree_path.read_text(encoding="utf-8"))
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise ComponentProfileError(
                f"elaboration-output-malformed:{top_module}") from error
        mapping = {path.as_posix(): path.relative_to(root).as_posix() for path in resolved}
        try:
            evidence = extract_physical_ports(tree, metadata, top_module=top_module,
                                              source_files=mapping)
        except ElaborationError as error:
            raise ComponentProfileError(
                f"elaboration-evidence-error:{top_module}:{error}") from error
    ports = tuple(
        ElaboratedPortFact(
            item["name"], item["direction"], item["width"], item["signed"],
            item["source"]["file"], item["source"]["line"], item["source"]["column"],
            tuple(ElaboratedMemberFact(tuple(member["path"]), member["width"], member["raw_lo"],
                                       member["raw_hi"], member["signed"],
                                       member["source"]["file"], member["source"]["line"],
                                       member["source"]["column"],
                                       str(member.get("enum_type", "")))
                  for member in item["members"]),
        )
        for item in evidence["ports"]
    )
    warnings = len([line for line in diagnostics.splitlines() if "%Warning" in line])
    return PhysicalFacts(
        top_module=top_module,
        ports=ports,
        content_hash=revision or "",
        revision=revision or "",
        modules=(),
        warning_count=warnings,
        files=_closure_names(root, resolved),
    )


def elaborate_profile(profile: ComponentProfile, *, base_dir: Path,
                      selected_top_ports: tuple[str, ...] | None = None,
                      mode: str = "auto") -> PhysicalFacts:
    """Elaborate the profile's declared source closure and return real port facts.

    ``mode`` selects the execution path: ``supervised`` requires the RSS-bounded
    campaign supervisor, ``direct`` uses the bounded one-shot fallback, and
    ``auto`` prefers the supervisor and falls back only when the host provably
    cannot own a process group.
    """
    if mode not in ("auto", "supervised", "direct"):
        _error(f"invalid-elaboration-mode:{mode}")
    available, reason = supervisor_available()
    if mode == "supervised" and not available:
        _error(f"elaboration-supervisor-unavailable:{profile.component_id}:{reason}")
    selection = _top_port_selection(_document(profile.source_document)) \
        if getattr(profile, "source_document", None) is not None else "all"
    if selection == "declared" and selected_top_ports is None:
        selected_top_ports = _declared_top_ports(profile)
    if mode == "direct" or (mode == "auto" and not available):
        facts = _direct_elaboration(profile, base_dir=Path(base_dir),
                                    selected_top_ports=selected_top_ports)
        if selection == "declared":
            facts = replace(facts, selection="declared")
        return facts
    crawler = SourceCrawler()
    try:
        snapshot = crawler.crawl(profile.source, base_dir=Path(base_dir),
                                 selected_top_ports=selected_top_ports)
    except SourceCrawlError as error:
        raise ComponentProfileError(f"elaboration-failed:{profile.component_id}:{error}") from error
    if snapshot.elaborated_top_module != profile.source.top_module:
        _error(f"elaboration-top-mismatch:{profile.component_id}")
    if not snapshot.elaborated_ports:
        _error(f"elaboration-no-ports:{profile.component_id}")
    warning_count = 0
    if profile.source.elaboration is not None and snapshot.elaboration_evidence:
        try:
            document = json.loads(snapshot.elaboration_evidence.decode("utf-8"))
            summary = document.get("warning_summary") or {}
            warning_count = int(summary.get("warning_count", 0))
        except (ValueError, UnicodeDecodeError, AttributeError, TypeError):
            warning_count = 0
    published = (tuple(getattr(snapshot, "compiled_files", ()) or snapshot.files)
                 or tuple(sorted({port.source_file
                                  for port in snapshot.elaborated_ports})))
    return PhysicalFacts(
        top_module=profile.source.top_module,
        ports=tuple(snapshot.elaborated_ports),
        content_hash=snapshot.content_hash,
        revision=snapshot.revision,
        modules=tuple(sorted(set(snapshot.modules))),
        warning_count=warning_count,
        selection=selection,
        files=published,
    )


def _member_leaves(fact: ElaboratedPortFact,
                   member_path: tuple[str, ...]) -> tuple[ElaboratedMemberFact, ...] | None:
    """The elaborated leaves a declared member path selects, or ``None``.

    An exact leaf match returns that one member.  A path that is a strict prefix
    of one or more leaves names an intermediate packed struct and returns the
    leaves below it in the frontend's own (most significant first) order.
    """
    exact = tuple(entry for entry in fact.members if entry.path == member_path)
    if exact:
        return exact
    return tuple(entry for entry in fact.members
                 if entry.path[:len(member_path)] == member_path) or None


def _resolve_field(profile: ComponentProfile, endpoint: EndpointSpec, item: ProfileField,
                   facts: PhysicalFacts, *, protocol_directions: Mapping[str, str],
                   protocol_widths: Mapping[str, int]) -> ResolvedField:
    names: list[str]
    if item.physical is not None:
        names = [item.physical.port]
    else:
        names = list(item.aliases)
    if not names:
        _error(f"endpoint-field-unbound:{endpoint.endpoint_id}:{item.role}")
    present = [name for name in names if facts.port(name) is not None]
    if not present:
        if not item.required:
            _error(f"optional-field-must-be-declared-unconnected:{endpoint.endpoint_id}:{item.role}")
        _error(f"port-missing:{endpoint.endpoint_id}:{item.role}:{names[0]}")
    if len(present) > 1:
        _error(f"ambiguous-port-alias:{endpoint.endpoint_id}:{item.role}:{','.join(sorted(present))}")
    name = present[0]
    fact = facts.port(name)
    assert fact is not None
    member_path = item.physical.member_path if item.physical is not None else ()
    width = fact.width
    raw_lo, raw_hi = 0, fact.width - 1
    if member_path:
        leaves = _member_leaves(fact, member_path)
        if leaves is None:
            _error(f"member-missing:{endpoint.endpoint_id}:{item.role}:"
                   f"{name}.{'.'.join(member_path)}")
        # A member path may name an intermediate packed struct ("a_user"), whose
        # span is the union of the elaborated leaves below it.  The frontend
        # emits those leaves MSB-first and contiguously, so the union is one
        # contiguous span; anything else is refused rather than approximated.
        raw_hi = max(leaf.raw_hi for leaf in leaves)
        raw_lo = min(leaf.raw_lo for leaf in leaves)
        width = raw_hi - raw_lo + 1
        if width != sum(leaf.width for leaf in leaves):
            _error(f"member-span-not-contiguous:{endpoint.endpoint_id}:{item.role}:"
                   f"{name}.{'.'.join(member_path)}")
        if item.member_bits is not None and item.member_bits != (raw_lo, raw_hi):
            _error(f"member-offset-conflict:{endpoint.endpoint_id}:{item.role}:"
                   f"{name}.{'.'.join(member_path)}:"
                   f"[{raw_hi}:{raw_lo}]!=[{item.member_bits[1]}:{item.member_bits[0]}]")
    elif item.bit_range is not None:
        if len(item.aliases) != 1:
            _error(f"bit-range-requires-single-port-alias:{endpoint.endpoint_id}:{item.role}")
        raw_lo, raw_hi = item.bit_range
        if raw_hi >= fact.width:
            _error(f"bit-range-outside-port:{endpoint.endpoint_id}:{item.role}:"
                   f"{name}:{raw_hi}>=width{fact.width}")
        width = raw_hi - raw_lo + 1
    expected = FUNCTION_DIRECTIONS[endpoint.function]
    if expected == "declared":
        if item.direction is None:
            _error(f"external-field-requires-direction:{endpoint.endpoint_id}:{item.role}")
        direction = item.direction
    elif expected in ("protocol", "protocol-inverted"):
        if item.role not in protocol_directions:
            _error(f"role-not-in-protocol:{endpoint.endpoint_id}:{item.role}:"
                   f"{endpoint.protocol[0]}@{endpoint.protocol[1]}")
        direction = protocol_directions[item.role]
        if expected == "protocol-inverted":
            direction = "output" if direction == "input" else "input"
    elif expected == "inout":
        direction = "inout"
    else:
        direction = expected
    if item.direction is not None and item.direction != direction:
        _error(f"field-direction-conflicts-with-function:{endpoint.endpoint_id}:"
               f"{item.role}:{item.direction}!={direction}")
    # The physical fact may not contradict the semantic requirement.  A profile
    # that names an input as an output-side role is a binding conflict, not a
    # reason to invert the wiring.
    if fact.direction not in ("inout",) and direction != fact.direction:
        _error(f"binding-direction-conflict:{endpoint.endpoint_id}:{item.role}:"
               f"{name}:{fact.direction}!={direction}")
    if item.width is not None and item.width != width:
        _error(f"binding-width-conflict:{endpoint.endpoint_id}:{item.role}:"
               f"{name}:{width}!={item.width}")
    declared_width = protocol_widths.get(item.role)
    if declared_width is not None and declared_width != width:
        _error(f"protocol-width-conflict:{endpoint.endpoint_id}:{item.role}:"
               f"{name}:{width}!={declared_width}")
    return ResolvedField(
        endpoint_id=endpoint.endpoint_id,
        role=item.role,
        port=name,
        member_path=member_path,
        direction=direction,
        width=width,
        raw_lo=raw_lo,
        raw_hi=raw_hi,
        signed=fact.signed,
        source_file=fact.source_file,
        line=fact.line,
        port_width=fact.width,
    )


def bind_profile(profile: ComponentProfile, facts: PhysicalFacts) -> ProfileBinding:
    """Bind every declared role to a real elaborated port or fail closed."""
    capabilities = profile.capabilities
    protocol_cache: dict[tuple[str, str], tuple[dict[str, str], dict[str, int]]] = {}
    endpoints: list[ResolvedEndpoint] = []
    # A port may carry several roles (a struct port's members, or disjoint slices
    # of a vector), so what is unique is the *bit*, never the port: overlapping
    # spans are a second driver and are refused, an exact duplicate is refused
    # with its own name, and the port-disposition ledger still requires every bit
    # of every elaborated port to end up classified.
    covered: dict[str, list[tuple[int, int, str]]] = {}

    def claim(field: ResolvedField) -> None:
        spans = covered.setdefault(field.port, [])
        for low, high, owner in spans:
            if field.raw_lo <= high and low <= field.raw_hi:
                if (low, high) == (field.raw_lo, field.raw_hi):
                    _error(f"duplicate-physical-binding:{field.port}:{field.key}+{owner}")
                _error(f"overlapping-physical-binding:{field.port}:"
                       f"[{field.raw_hi}:{field.raw_lo}]+{owner}:[{high}:{low}]")
        spans.append((field.raw_lo, field.raw_hi, field.key))

    for endpoint in sorted(profile.endpoints, key=lambda item: item.endpoint_id):
        directions: Mapping[str, str] = {}
        widths: Mapping[str, int] = {}
        if endpoint.protocol is not None:
            key = endpoint.protocol
            if key not in protocol_cache:
                directions = dict(_protocol_field_directions(key))
                widths = _protocol_field_widths(key, capabilities)
                if FUNCTION_DIRECTIONS[endpoint.function] == "protocol-inverted":
                    directions.update(_adapter_field_directions(key))
                protocol_cache[key] = (directions, widths)
            directions, widths = protocol_cache[key]
        fields = []
        for item in sorted(endpoint.fields, key=lambda entry: entry.role):
            try:
                resolved = _resolve_field(profile, endpoint, item, facts,
                                          protocol_directions=directions,
                                          protocol_widths=widths)
            except ComponentProfileError as error:
                # Every binding diagnostic names the component it came from, so a
                # multi-component request can be located without guessing.
                raise ComponentProfileError(
                    f"{profile.component_id}:{error}") from error
            claim(resolved)
            fields.append(resolved)
        endpoints.append(ResolvedEndpoint(endpoint.endpoint_id, endpoint.function,
                                          endpoint.protocol, tuple(fields)))

    def bind_special(binding: object, name: str, *, expected: str) -> ResolvedField:
        port = getattr(binding, "port")
        fact = facts.port(port)
        if fact is None:
            _error(f"{profile.component_id}:{name}-port-missing:{port}")
        if fact.direction not in ("inout", expected):
            _error(f"{profile.component_id}:{name}-direction-conflict:"
                   f"{port}:{fact.direction}!={expected}")
        resolved = ResolvedField(endpoint_id=name, role=name, port=port, member_path=(),
                                 direction=expected, width=fact.width, raw_lo=0,
                                 raw_hi=fact.width - 1, signed=fact.signed,
                                 source_file=fact.source_file, line=fact.line,
                                 port_width=fact.width)
        claim(resolved)
        return resolved

    clocks = tuple((item, bind_special(item, "clock", expected="input")) for item in profile.clocks)
    resets = tuple((item, bind_special(item, "reset", expected="input")) for item in profile.resets)

    # Interrupt sources must be real outputs of the component.
    for source in profile.interrupts:
        role = next((field for field in endpoints for field in field.fields
                     if field.endpoint_id == source.endpoint_id and field.role == source.role), None)
        if role is None:
            _error(f"interrupt-field-unbound:{source.endpoint_id}:{source.role}")
        if role.direction != "output":
            _error(f"interrupt-field-not-an-output:{source.endpoint_id}:{source.role}")

    payload = {
        "component_id": profile.component_id,
        "kind": profile.kind,
        "content_hash": facts.content_hash,
        "top_module": facts.top_module,
        "clocks": [(item.port, item.domain, field.port) for item, field in clocks],
        "resets": [(item.port, item.domain, item.polarity, item.synchronous, field.port)
                   for item, field in resets],
        "selection": facts.selection,
        "endpoints": [
            {"endpoint_id": endpoint.endpoint_id, "function": endpoint.function,
             "protocol": list(endpoint.protocol) if endpoint.protocol else None,
             "fields": [{"role": field.role, "port": field.port,
                         "member_path": list(field.member_path),
                         "direction": field.direction, "width": field.width,
                         "raw_lo": field.raw_lo, "raw_hi": field.raw_hi}
                        for field in endpoint.fields]}
            for endpoint in endpoints
        ],
    }
    from myfuzz.contracts import canonical_bytes
    import hashlib

    binding_hash = "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return ProfileBinding(component_id=profile.component_id, kind=profile.kind, facts=facts,
                          endpoints=tuple(endpoints), clocks=clocks, resets=resets,
                          binding_hash=binding_hash)


__all__ = [
    "COMPONENT_PROFILE_SCHEMA",
    "COMPOSITION_REQUEST_SCHEMA",
    "COMPONENT_KINDS",
    "DISPOSITION_KINDS",
    "DRIVE_STRATEGIES",
    "FUNCTION_DIRECTIONS",
    "PORT_ACTION_KINDS",
    "AddressPolicy",
    "AddressSpec",
    "ClockBinding",
    "ComponentInstance",
    "ComponentProfile",
    "ComponentProfileError",
    "CompositionRequest",
    "CpuContract",
    "EndpointSpec",
    "InterruptSource",
    "MemoryRegion",
    "PhysicalFacts",
    "PeerAttachmentRequest",
    "PortAction",
    "ProfileBinding",
    "ProfileField",
    "RegisterSpec",
    "ResolvedEndpoint",
    "ResolvedField",
    "ResetBinding",
    "bind_profile",
    "elaborate_profile",
    "load_component_profile",
    "load_composition_request",
    "load_profiles",
    "profile_pin",
]
