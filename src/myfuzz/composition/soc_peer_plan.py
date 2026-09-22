"""Declare and resolve the external peer models a profile-driven SoC instantiates.

A profile may declare an ``external_pins`` endpoint whose roles describe a
non-MMIO interface (a serial link, a chip-to-chip bus, a set of bidirectional
pins).  Those pins are either exported to the generated top - the behaviour the
composition path always had - or driven by one of the implemented *peer models*
under ``src/myfuzz/protocols/rtl``.

Selection is never by component, instance, model or port name.  The declared
interface is reduced to its **role signature**: the exact set of
``(role, direction)`` pairs the profile bound to real elaborated ports.  A peer
model is a candidate when its own declared role signature is that same set; the
interfaces whose signature matches no implemented model are reported (and, when
the request demanded an attached peer, refused) instead of being approximated.

Each peer model also declares what it needs from the component to be meaningful:

* the peer RTL parameters, with their admitted range, so an out-of-range value
  is refused instead of rounded;
* which of those parameters must equal a parameter the component's own instance
  declares (a peer that samples at another divisor than the transmitter it
  listens to is not a test of anything);
* minimum values of component parameters the peer's own timing assumptions
  require (the SPI peer oversamples ``sck_i`` with ``clk_i`` and cannot honour a
  clock whose level is shorter than two ``clk_i`` cycles);
* the stimulus slots the environment may schedule, each with the payload width
  it carries and the minimum spacing the peer can accept.

Everything a plan records here is re-read from the elaborated RTL by
``soc_structure_audit``; nothing in this module is trusted by the audit.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

PEER_PLAN_SCHEMA = "soc_peer_plan.v1"

#: The endpoint function a peer may bind to.  A peer never touches an MMIO,
#: interrupt, clock or observation endpoint.
PEER_ENDPOINT_FUNCTION = "external_pins"

#: How a model's declared roles constrain the widths the profile bound.
#: ``unit`` means every role is a single wire (serial lines, SCK/CS/MOSI/MISO);
#: ``common`` means every role has the same width, which becomes the model's own
#: pin-count parameter.
WIDTH_UNIT = "unit"
WIDTH_COMMON = "common"


class PeerPlanError(ValueError):
    """The declared interface and the implemented peer models cannot be joined."""


def _error(reason: str) -> None:
    raise PeerPlanError(reason)


# ---------------------------------------------------------------------------
# model contract records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PeerParameterSpec:
    """One peer RTL parameter, its admitted range and what it must agree with."""

    name: str
    default: int
    minimum: int
    maximum: int
    basis: str
    matches_component: str | None = None
    derived_from_roles: bool = False


@dataclass(frozen=True, slots=True)
class PeerRequirement:
    """A minimum the component's own declared parameter must satisfy."""

    component_parameter: str
    minimum: int
    rationale: str


@dataclass(frozen=True, slots=True)
class PeerSignalSpec:
    """One peer port a stimulus slot drives.

    ``source`` is one of ``pulse`` (asserted for exactly the declared cycle),
    ``payload`` (the whole payload), ``payload_low``/``payload_high`` (one half
    of a two-field payload such as a GPIO drive and its valid mask).  The width
    is ``None`` when it is the slot's own payload width.
    """

    peer_port: str
    source: str
    width: int | None = None


@dataclass(frozen=True, slots=True)
class PeerSlotSpec:
    """One schedulable stimulus slot of a peer model."""

    slot: str
    kind: str
    signals: tuple[PeerSignalSpec, ...]
    description: str
    #: Resolved parameters -> the payload width one event of this slot carries.
    payload_width: Callable[[Mapping[str, int]], int]
    #: Resolved parameters -> the minimum spacing between two events, in clk_i cycles.
    minimum_gap: Callable[[Mapping[str, int]], int]


@dataclass(frozen=True, slots=True)
class PeerObservationSpec:
    """One peer output the plan observes, and whether it is a counter.

    ``width`` is either a fixed bit count or the name of the peer parameter the
    port is as wide as (``DATA_WIDTH``, ``BITS``, ``PINS``); a name the peer does
    not resolve is a plan-time error rather than a silently truncated export.
    """

    peer_port: str
    counter: bool
    description: str
    width: int | str = 1


@dataclass(frozen=True, slots=True)
class PeerModel:
    """One implemented peer model, declared by roles rather than by name."""

    peer_id: str
    protocol: tuple[str, str]
    module: str
    source: str
    roles: tuple[tuple[str, str], ...]
    bindings: tuple[tuple[str, str], ...]
    width_rule: str
    parameters: tuple[PeerParameterSpec, ...]
    requirements: tuple[PeerRequirement, ...]
    slots: tuple[PeerSlotSpec, ...]
    observations: tuple[PeerObservationSpec, ...]
    derived_parameter: str | None = None

    def role_map(self) -> dict[str, str]:
        return dict(self.roles)

    def parameter(self, name: str) -> PeerParameterSpec | None:
        for item in self.parameters:
            if item.name == name:
                return item
        return None

    def binding_map(self) -> dict[str, str]:
        return dict(self.bindings)


# ---------------------------------------------------------------------------
# implemented models
# ---------------------------------------------------------------------------


def _uart_payload_width(parameters: Mapping[str, int]) -> int:
    return int(parameters["DATA_WIDTH"])


def _uart_minimum_gap(parameters: Mapping[str, int]) -> int:
    """One full frame plus one idle cycle between two offered bytes."""
    frame = (1 + int(parameters["DATA_WIDTH"]) + int(parameters["STOP_BITS"])) \
        * int(parameters["BAUD_DIV"])
    return frame + 1


def _spi_payload_width(parameters: Mapping[str, int]) -> int:
    return int(parameters["BITS"])


def _spi_minimum_gap(parameters: Mapping[str, int]) -> int:
    """The arm register holds one byte, so two arms need two clock edges."""
    return 2


def _gpio_payload_width(parameters: Mapping[str, int]) -> int:
    return 2 * int(parameters["PINS"])


def _gpio_minimum_gap(parameters: Mapping[str, int]) -> int:
    return 1


UART_PEER = PeerModel(
    peer_id="uart",
    protocol=("uart", "1"),
    module="soc_uart_peer",
    source="src/myfuzz/protocols/rtl/soc_uart_peer.sv",
    roles=(("rx", "input"), ("tx", "output")),
    bindings=(("rx", "serial_tx_o"), ("tx", "serial_rx_i")),
    width_rule=WIDTH_UNIT,
    parameters=(
        PeerParameterSpec(
            "DATA_WIDTH", 8, 1, 32,
            "the frozen peer accepts any data width >= 1 (no parity, start/data/stop only)",
            matches_component="SERIAL_WIDTH"),
        PeerParameterSpec(
            "BAUD_DIV", 1, 1, 1 << 24,
            "clk_i cycles per bit period; >= 1 is the peer's own contract",
            matches_component="BAUD_DIV"),
        PeerParameterSpec(
            "STOP_BITS", 1, 1, 8,
            "stop bit periods per frame; >= 1 is the peer's own contract",
            matches_component="STOP_BITS"),
        PeerParameterSpec(
            "IDLE_LEVEL", 1, 0, 1,
            "line level between frames, 0 or 1; it must be the component's idle level",
            matches_component="IDLE_LEVEL"),
        PeerParameterSpec(
            "TIMEOUT_BITS", 16, 1, 1 << 20,
            "idle bit periods per timeout event; >= 1 is the peer's own contract"),
    ),
    requirements=(),
    slots=(
        PeerSlotSpec(
            slot="uart.tx_byte",
            kind="pulse_byte",
            signals=(
                PeerSignalSpec("tx_request_valid_i", "pulse", 1),
                PeerSignalSpec("tx_request_data_i", "payload"),
            ),
            description="offer one byte for transmission; the peer drops an offer that "
                        "arrives while it is still sending",
            payload_width=_uart_payload_width,
            minimum_gap=_uart_minimum_gap),
    ),
    observations=(
        PeerObservationSpec("tx_sent_count_o", True,
                            "frames fully driven onto serial_tx_o", 32),
        PeerObservationSpec("tx_drop_count_o", True, "offers dropped while busy", 32),
        PeerObservationSpec("rx_data_o", False, "byte sampled from serial_rx_i",
                            "DATA_WIDTH"),
        PeerObservationSpec("rx_count_o", True, "bytes reported from serial_rx_i", 32),
        PeerObservationSpec("framing_error_count_o", True,
                            "stop bit periods sampled at the start level", 32),
        PeerObservationSpec("timeout_count_o", True,
                            "idle windows that expired without a start bit", 32),
    ),
)

SPI_PEER = PeerModel(
    peer_id="spi",
    protocol=("spi", "1"),
    module="soc_spi_peer",
    source="src/myfuzz/protocols/rtl/soc_spi_peer.sv",
    roles=(("cs", "output"), ("miso", "input"), ("mosi", "output"), ("sck", "output")),
    bindings=(("sck", "sck_i"), ("cs", "cs_i"), ("mosi", "mosi_i"), ("miso", "miso_o")),
    width_rule=WIDTH_UNIT,
    parameters=(
        PeerParameterSpec(
            "BITS", 8, 1, 32,
            "bits per transferred byte; >= 1 is the peer's own contract",
            matches_component="BITS"),
        PeerParameterSpec(
            "CPOL", 0, 0, 1,
            "idle sck_i level; it selects which edge is the leading one",
            matches_component="CPOL"),
        PeerParameterSpec(
            "CPHA", 0, 0, 1,
            "sample/shift edge selection; it must be the master's own mode",
            matches_component="CPHA"),
        PeerParameterSpec(
            "CS_ACTIVE_LOW", 1, 0, 1,
            "chip-select polarity; 1 = cs_i active low"),
    ),
    requirements=(
        PeerRequirement(
            "SCK_HALF_DIV", 2,
            "the peer oversamples sck_i with clk_i, so every sck_i level must be held "
            "for at least two clk_i cycles or the pulse can be missed"),
        PeerRequirement(
            "CS_SETUP", 1,
            "cs_i must be asserted at least one clk_i cycle before the first leading "
            "edge so a CPHA=0 selection can present its first bit"),
    ),
    slots=(
        PeerSlotSpec(
            slot="spi.arm_byte",
            kind="pulse_byte",
            signals=(
                PeerSignalSpec("tx_request_valid_i", "pulse", 1),
                PeerSignalSpec("tx_request_data_i", "payload"),
            ),
            description="arm one byte for the next selection; an arm that arrives while "
                        "the register is full is dropped and counted",
            payload_width=_spi_payload_width,
            minimum_gap=_spi_minimum_gap),
    ),
    observations=(
        PeerObservationSpec("tx_armed_o", False, "an armed byte waits for a selection", 1),
        PeerObservationSpec("tx_drop_count_o", True,
                            "arms dropped while the register was full", 32),
        PeerObservationSpec("rx_data_o", False, "byte assembled from mosi_i", "BITS"),
        PeerObservationSpec("rx_count_o", True, "bytes completed on mosi_i", 32),
        PeerObservationSpec("bit_count_o", False,
                            "bits sampled since the last completed byte", 32),
        PeerObservationSpec("clock_count_o", True,
                            "sck_i transitions observed while selected", 32),
        PeerObservationSpec("deselected_clock_count_o", True,
                            "sck_i transitions observed while deselected", 32),
        PeerObservationSpec("deselected_clock_error_o", False,
                            "sticky flag for a clock transition while deselected", 1),
        PeerObservationSpec("incomplete_count_o", True,
                            "selections that ended with a partial byte", 32),
        PeerObservationSpec("incomplete_error_o", False,
                            "sticky flag for a partial-byte selection", 1),
        PeerObservationSpec("selected_o", False, "registered chip-select state", 1),
    ),
)

GPIO_PEER = PeerModel(
    peer_id="gpio",
    protocol=("gpio", "1"),
    module="soc_gpio_peer",
    source="src/myfuzz/protocols/rtl/soc_gpio_peer.sv",
    roles=(("dir", "output"), ("in", "input"), ("out", "output")),
    bindings=(("in", "pin_o"), ("out", "component_out_i"), ("dir", "component_dir_i")),
    width_rule=WIDTH_COMMON,
    derived_parameter="PINS",
    parameters=(
        PeerParameterSpec(
            "PINS", 1, 1, 64,
            "pin count; it is the width the profile declared for this interface",
            derived_from_roles=True),
        PeerParameterSpec(
            "DEFAULT_INPUT_LEVEL", 0, 0, 1,
            "level of a pin nobody drives; it is the peer's own environment choice"),
        PeerParameterSpec(
            "CONTENTION_IS_ERROR", 0, 0, 1,
            "1 = a contention event also raises the sticky contention_error_o flag"),
    ),
    requirements=(),
    slots=(
        PeerSlotSpec(
            slot="gpio.drive",
            kind="level_drive",
            signals=(
                PeerSignalSpec("peer_drive_value_i", "payload_low"),
                PeerSignalSpec("peer_drive_valid_i", "payload_high"),
            ),
            description="drive value and drive-valid mask of every pin; the pair is held "
                        "until the next event of this slot",
            payload_width=_gpio_payload_width,
            minimum_gap=_gpio_minimum_gap),
    ),
    observations=(
        PeerObservationSpec("pin_value_o", False,
                            "resolved line registered on clk_i", "PINS"),
        PeerObservationSpec("direction_o", False,
                            "component_dir_i registered on clk_i", "PINS"),
        PeerObservationSpec("contention_o", False, "per-pin contention flag", "PINS"),
        PeerObservationSpec("contention_count_o", True, "contention events entered", 32),
        PeerObservationSpec("contention_error_o", False,
                            "sticky flag set on the first contention event when declared", 1),
    ),
)

#: Every implemented peer model.  The tuple order is the only tie-break a
#: caller may rely on; an ambiguous role signature is refused, not ordered.
PEER_MODELS: tuple[PeerModel, ...] = (UART_PEER, SPI_PEER, GPIO_PEER)


def peer_models() -> Mapping[str, PeerModel]:
    return {item.peer_id: item for item in PEER_MODELS}


# ---------------------------------------------------------------------------
# resolved plan records
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PeerRoleBinding:
    """One declared interface role and the peer port that owns it."""

    role: str
    component_port: str
    component_direction: str
    peer_port: str
    width: int

    @property
    def net(self) -> str:
        return self.component_port

    def document(self) -> dict[str, object]:
        return {"role": self.role, "component_port": self.component_port,
                "component_direction": self.component_direction,
                "peer_port": self.peer_port, "width": self.width}


@dataclass(frozen=True, slots=True)
class PeerSignal:
    """One top-level stimulus port of a resolved slot."""

    peer_port: str
    top_port: str
    width: int
    source: str

    def document(self) -> dict[str, object]:
        return {"peer_port": self.peer_port, "top_port": self.top_port,
                "width": self.width, "source": self.source}


@dataclass(frozen=True, slots=True)
class PeerStimulusSlot:
    """One schedulable slot of a resolved peer: what an event may carry."""

    slot: str
    kind: str
    width: int
    instance_id: str
    peer_id: str
    signals: tuple[PeerSignal, ...]
    minimum_gap_cycles: int
    description: str

    def document(self) -> dict[str, object]:
        return {"slot": self.slot, "kind": self.kind, "width": self.width,
                "instance_id": self.instance_id, "peer_id": self.peer_id,
                "signals": [item.document() for item in self.signals],
                "minimum_gap_cycles": self.minimum_gap_cycles,
                "description": self.description}


@dataclass(frozen=True, slots=True)
class PeerObservation:
    """One observed peer output, exported at the generated top."""

    peer_port: str
    top_port: str
    width: int
    counter: bool
    description: str

    def document(self) -> dict[str, object]:
        return {"peer_port": self.peer_port, "top_port": self.top_port,
                "width": self.width, "counter": self.counter,
                "description": self.description}


@dataclass(frozen=True, slots=True)
class PeerParameter:
    """One resolved peer parameter with the constraint it satisfied."""

    name: str
    value: int
    minimum: int
    maximum: int
    constraint: str
    basis: str

    def document(self) -> dict[str, object]:
        return {"name": self.name, "value": self.value, "minimum": self.minimum,
                "maximum": self.maximum, "constraint": self.constraint,
                "basis": self.basis}


@dataclass(frozen=True, slots=True)
class PeerRequirementCheck:
    """One component-parameter minimum the resolved peer required."""

    component_parameter: str
    minimum: int
    value: int
    rationale: str

    def document(self) -> dict[str, object]:
        return {"component_parameter": self.component_parameter,
                "minimum": self.minimum, "value": self.value,
                "rationale": self.rationale}


@dataclass(frozen=True, slots=True)
class PeerPlan:
    """A peer instance bound to one declared external interface.

    Every field is derived from the profile's declared roles, the request's
    declared parameters and the peer model's own contract; the renderer and the
    runtime consume exactly this record and the audit re-reads it from the RTL.
    """

    instance_id: str
    component_id: str
    endpoint_id: str
    peer_id: str
    protocol: tuple[str, str]
    module: str
    source: str
    roles: tuple[tuple[str, str], ...]
    bindings: tuple[PeerRoleBinding, ...]
    parameters: tuple[PeerParameter, ...]
    requirements: tuple[PeerRequirementCheck, ...]
    slots: tuple[PeerStimulusSlot, ...]
    observations: tuple[PeerObservation, ...]
    reason: str

    @property
    def instance(self) -> str:
        """The peer instance name inside the generated top."""
        return f"u_{self.instance_id}_peer"

    @property
    def top_ports(self) -> tuple[str, ...]:
        """Every top-level port this peer adds to the generated SoC."""
        return tuple(signal.top_port for slot in self.slots for signal in slot.signals) \
            + tuple(item.top_port for item in self.observations)

    @property
    def parameter_values(self) -> dict[str, int]:
        return {item.name: item.value for item in self.parameters}

    @property
    def counters(self) -> tuple[PeerObservation, ...]:
        return tuple(item for item in self.observations if item.counter)

    def binding(self, role: str) -> PeerRoleBinding:
        for item in self.bindings:
            if item.role == role:
                return item
        _error(f"peer-role-not-bound:{self.instance_id}:{role}")

    def document(self) -> dict[str, object]:
        return {
            "schema_version": PEER_PLAN_SCHEMA,
            "instance_id": self.instance_id,
            "component_id": self.component_id,
            "endpoint_id": self.endpoint_id,
            "peer_id": self.peer_id,
            "protocol": list(self.protocol),
            "module": self.module,
            "source": self.source,
            "peer_instance": self.instance,
            "roles": [{"role": role, "direction": direction} for role, direction in self.roles],
            "bindings": [item.document() for item in self.bindings],
            "parameters": [item.document() for item in self.parameters],
            "requirements": [item.document() for item in self.requirements],
            "slots": [item.document() for item in self.slots],
            "observations": [item.document() for item in self.observations],
            "counters": [item.top_port for item in self.counters],
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# role-signature matching
# ---------------------------------------------------------------------------


def role_signature(fields: Sequence[object]) -> tuple[tuple[str, str], ...]:
    """The declared ``(role, direction)`` signature of one interface.

    The signature is read from the bound fields only: a role id and the
    direction the profile declared for it.  No port name, component id or
    instance id takes part in the match.
    """
    pairs = []
    for item in fields:
        role = getattr(item, "role", None)
        direction = getattr(item, "direction", None)
        if not isinstance(role, str) or direction not in ("input", "output"):
            _error(f"peer-role-unsupported-signature:{role}:{direction}")
        pairs.append((role, str(direction)))
    return tuple(sorted(pairs))


def match_models(fields: Sequence[object]) -> tuple[PeerModel, ...]:
    """Every implemented model whose role signature is exactly this interface."""
    signature = role_signature(fields)
    return tuple(model for model in PEER_MODELS if tuple(sorted(model.roles)) == signature)


def _unit_widths(model: PeerModel, fields: Sequence[object]) -> None:
    for item in fields:
        if int(getattr(item, "width")) != 1:
            _error(f"peer-role-width-unsupported:{model.peer_id}:"
                   f"{getattr(item, 'role')}:{getattr(item, 'width')}!=1")


def _common_width(model: PeerModel, fields: Sequence[object]) -> int:
    widths = {int(getattr(item, "width")) for item in fields}
    if len(widths) != 1:
        declared = ",".join("%s=%s" % (getattr(item, "role"), getattr(item, "width"))
                            for item in fields)
        _error(f"peer-role-width-conflict:{model.peer_id}:{declared}")
    width = widths.pop()
    spec = model.parameter(str(model.derived_parameter))
    assert spec is not None
    if width < spec.minimum or width > spec.maximum:
        _error(f"peer-role-width-unsupported:{model.peer_id}:{width}"
               f"!<={spec.maximum}")
    return width


def _resolved_parameters(model: PeerModel, fields: Sequence[object], *,
                         declared: Mapping[str, object],
                         component_parameters: Mapping[str, object],
                         ) -> tuple[tuple[PeerParameter, ...], dict[str, int]]:
    """Resolve, range-check and cross-check every peer parameter.

    A parameter the component also declares must be declared, and must agree:
    a peer that listens at another divisor or samples in another SPI mode is a
    configuration the model cannot honour, so it is refused here instead of
    being rounded to something the test would then report as passing.
    """
    known = {item.name for item in model.parameters}
    unknown = sorted(str(name) for name in declared if str(name) not in known)
    if unknown:
        _error(f"peer-parameter-unknown:{model.peer_id}:{','.join(unknown)}")
    derived = int(_common_width(model, fields)) if model.width_rule == WIDTH_COMMON else 0
    values: dict[str, int] = {}
    records: list[PeerParameter] = []
    for spec in model.parameters:
        if spec.derived_from_roles:
            if spec.name in declared:
                value = _integer(declared[spec.name],
                                 f"peer-parameter-invalid:{model.peer_id}:{spec.name}")
                if value != derived:
                    _error(f"peer-parameter-derived-mismatch:{model.peer_id}:{spec.name}:"
                           f"declared={value}:roles={derived}")
            else:
                value = derived
            constraint = f"derived from the declared interface width {derived}"
        elif spec.name in declared:
            value = _integer(declared[spec.name],
                             f"peer-parameter-invalid:{model.peer_id}:{spec.name}")
            constraint = "declared by the request"
        else:
            value = spec.default
            constraint = f"model default {spec.default}"
        if value < spec.minimum or value > spec.maximum:
            _error(f"peer-parameter-out-of-range:{model.peer_id}:{spec.name}:{value}"
                   f"!<={spec.maximum}&&>={spec.minimum}")
        if spec.matches_component is not None:
            component = component_parameters.get(spec.matches_component)
            if component is None:
                _error(f"peer-component-parameter-missing:{model.peer_id}:{spec.name}:"
                       f"the component declares no {spec.matches_component}")
            component_value = _integer(
                component, f"peer-component-parameter-invalid:{model.peer_id}:"
                           f"{spec.matches_component}")
            if component_value != value:
                _error(f"peer-timing-mismatch:{model.peer_id}:{spec.name}:"
                       f"peer={value}:component={spec.matches_component}={component_value}")
            constraint = f"matches the component parameter {spec.matches_component}={value}"
        values[spec.name] = value
        records.append(PeerParameter(spec.name, value, spec.minimum, spec.maximum,
                                     constraint, spec.basis))
    return tuple(records), values


def _resolved_requirements(model: PeerModel, values: Mapping[str, int], *,
                           component_parameters: Mapping[str, object],
                           ) -> tuple[PeerRequirementCheck, ...]:
    records: list[PeerRequirementCheck] = []
    for item in model.requirements:
        component = component_parameters.get(item.component_parameter)
        if component is None:
            _error(f"peer-component-parameter-missing:{model.peer_id}:"
                   f"{item.component_parameter}: the peer requires this declared parameter")
        value = _integer(component, f"peer-component-parameter-invalid:{model.peer_id}:"
                                    f"{item.component_parameter}")
        if value < item.minimum:
            _error(f"peer-timing-unsupported:{model.peer_id}:{item.component_parameter}:"
                   f"{value}<{item.minimum}")
        records.append(PeerRequirementCheck(item.component_parameter, item.minimum, value,
                                            item.rationale))
    return tuple(records)


def _integer(value: object, reason: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        _error(reason)
    return int(value)


def _signal_width(signal: PeerSignalSpec, payload_width: int) -> int:
    """The width of one stimulus top-level port.

    A ``pulse`` port is one bit, a whole-``payload`` port carries the slot's
    payload, and the two halves of a split payload (a GPIO drive and its valid
    mask) are half of it.  The declaration is checked against the slot rather
    than trusted, so a model whose halves do not add up is refused here.
    """
    if signal.source == "pulse":
        width = 1
    elif signal.source == "payload":
        width = payload_width
    elif signal.source in ("payload_low", "payload_high"):
        if payload_width % 2:
            _error(f"peer-slot-odd-split-payload:{signal.peer_port}:{payload_width}")
        width = payload_width // 2
    else:
        _error(f"peer-slot-unknown-signal-source:{signal.peer_port}:{signal.source}")
    if signal.width is not None and int(signal.width) != width:
        _error(f"peer-slot-signal-width-conflict:{signal.peer_port}:"
               f"declared={signal.width}:expected={width}")
    return width


def plan_peer(*, instance_id: str, component_id: str, endpoint_id: str,
              fields: Sequence[object], declared: Mapping[str, object],
              component_parameters: Mapping[str, object]) -> PeerPlan:
    """Resolve one declared interface to exactly one implemented peer model.

    The match is by role signature; an interface no model implements is a
    refused attachment (the caller decides whether that is fatal), never a
    silently smaller peer.
    """
    candidates = match_models(fields)
    signature = role_signature(fields)
    if not candidates:
        _error(f"peer-role-unsupported:{instance_id}:{endpoint_id}:"
               f"{','.join(f'{role}:{direction}' for role, direction in signature)}")
    if len(candidates) != 1:
        _error(f"peer-role-ambiguous:{instance_id}:{endpoint_id}:"
               f"{','.join(item.peer_id for item in candidates)}")
    model = candidates[0]
    if model.width_rule == WIDTH_UNIT:
        _unit_widths(model, fields)
    parameters, values = _resolved_parameters(
        model, fields, declared=declared, component_parameters=component_parameters)
    requirements = _resolved_requirements(model, values,
                                          component_parameters=component_parameters)
    bindings = tuple(
        PeerRoleBinding(
            role=role,
            component_port=str(getattr(field, "port")),
            component_direction=str(getattr(field, "direction")),
            peer_port=model.binding_map()[role],
            width=int(getattr(field, "width")))
        for role, _direction in model.roles
        for field in (next(item for item in fields if getattr(item, "role") == role),))
    slots = tuple(
        PeerStimulusSlot(
            slot=item.slot,
            kind=item.kind,
            width=int(item.payload_width(values)),  # type: ignore[operator]
            instance_id=instance_id,
            peer_id=model.peer_id,
            signals=tuple(
                PeerSignal(
                    peer_port=signal.peer_port,
                    top_port=f"{instance_id}__{signal.peer_port}",
                    width=_signal_width(signal, int(item.payload_width(values))),  # type: ignore[operator]
                    source=signal.source)
                for signal in item.signals),
            minimum_gap_cycles=int(item.minimum_gap(values)),  # type: ignore[operator]
            description=item.description)
        for item in model.slots)
    observations = tuple(
        PeerObservation(
            peer_port=item.peer_port,
            top_port=f"{instance_id}__{item.peer_port}",
            width=_observation_width(item, values),
            counter=item.counter,
            description=item.description)
        for item in model.observations)
    return PeerPlan(
        instance_id=instance_id,
        component_id=component_id,
        endpoint_id=endpoint_id,
        peer_id=model.peer_id,
        protocol=model.protocol,
        module=model.module,
        source=model.source,
        roles=model.roles,
        bindings=bindings,
        parameters=parameters,
        requirements=requirements,
        slots=slots,
        observations=observations,
        reason=(f"the declared roles {','.join(f'{role}:{direction}' for role, direction in signature)} "
                f"are exactly the {model.peer_id} peer's contract, so the interface is driven by "
                f"{model.module} instead of being exported"))


def _observation_width(spec: PeerObservationSpec, values: Mapping[str, int]) -> int:
    """The width of one observed peer output, from the model's own declaration."""
    if isinstance(spec.width, int):
        return int(spec.width)
    if spec.width not in values:
        _error(f"peer-observation-width-unresolved:{spec.peer_port}:{spec.width}")
    return int(values[spec.width])


def export_reason(fields: Sequence[object]) -> str:
    """Why an interface with this signature stays exported."""
    signature = role_signature(fields)
    rendered = ",".join(f"{role}:{direction}" for role, direction in signature)
    return (f"no peer model implements the declared roles {rendered}, so the pins stay "
            f"exported to the top and the environment drives them")

__all__ = [
    "GPIO_PEER",
    "PEER_ENDPOINT_FUNCTION",
    "PEER_MODELS",
    "PEER_PLAN_SCHEMA",
    "SPI_PEER",
    "UART_PEER",
    "PeerModel",
    "PeerObservation",
    "PeerObservationSpec",
    "PeerParameter",
    "PeerParameterSpec",
    "PeerPlan",
    "PeerPlanError",
    "PeerRequirement",
    "PeerRequirementCheck",
    "PeerRoleBinding",
    "PeerSignal",
    "PeerSignalSpec",
    "PeerSlotSpec",
    "PeerStimulusSlot",
    "export_reason",
    "match_models",
    "peer_models",
    "plan_peer",
    "role_signature",
]
