"""Per-port and per-bit-segment disposition ledger for a generated SoC.

Every physical port of every instance must end up with exactly one recorded
destination, and every bit of every port must be covered.  The five classes are
the ones the assurance plan freezes:

``functional``
    Bound to a real interface role and consumed by the SoC (fabric target,
    processor adapter, interrupt controller, clock/reset distribution).
``constant``
    A justified fixed value, with a width and a reason.
``fuzz``
    A special input the profile explicitly allows the environment to drive; the
    port is exported to the SoC top and receives a raw-input bit segment.
``observe``
    A component output exported to the SoC top for passive monitoring only.
``unconnected``
    Explicitly left open, allowed only when a contract reference says so.

``external``
    A non-MMIO interface (UART/SPI/GPIO pins) exported to the SoC top because
    the composition request did not name an internal peer.  An external input is
    *not* a random input: the test environment must drive it through its own
    protocol model.

``peer``
    A non-MMIO interface driven by an implemented peer model instantiated from
    the plan (``soc_peer_plan``).  The pin is functional - the peer is the other
    end of the link inside the generated top - and it is therefore *not*
    exported: exporting it as well would put two drivers on one net.

The ledger is derived from the elaboration facts and the profile binding, never
from port names.  A port nobody classified is an error, and so is a second
driver for the same bit, a random-driven output, or a constant written onto a
component output.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .component_profile import ProfileBinding, PortAction, ResolvedField
from .soc_scope import inout_port_refusal

DISPOSITION_SCHEMA = "soc_port_dispositions.v1"

#: Which SoC block owns a functionally connected interface role.
FUNCTION_TARGETS: dict[str, str] = {
    "clock": "clock_reset",
    "reset": "clock_reset",
    "clock_reset": "clock_reset",
    "mmio_slave": "fabric_target",
    "memory_slave": "fabric_target",
    "debug_slave": "fabric_target",
    "processor_memory_master": "processor_adapter",
    "instruction_memory_master": "processor_adapter",
    "data_memory_master": "processor_adapter",
    "memory_master": "processor_adapter",
    "interrupt_source": "interrupt_controller",
    "interrupt_entry": "interrupt_controller",
    "external_pins": "soc_top",
    "observation": "soc_top",
}

#: Endpoint functions whose physical ports are exported to the SoC boundary.
EXPORTED_FUNCTIONS = frozenset(("external_pins",))
#: Endpoint functions whose outputs are passive observations.
OBSERVED_FUNCTIONS = frozenset(("observation",))


class PortDispositionError(ValueError):
    """A port, bit or driver is unclassified, duplicated or illegal."""


def _error(reason: str) -> None:
    raise PortDispositionError(reason)


@dataclass(frozen=True, slots=True)
class DispositionEntry:
    instance_id: str
    component_id: str
    port: str
    bit_lo: int
    bit_hi: int
    direction: str
    width: int
    disposition: str
    target: str | None
    endpoint_id: str | None
    role: str | None
    value: int | None
    strategy: str | None
    drive: Mapping[str, object] = field(default_factory=dict)
    clock_domain: str = "core"
    reset_domain: str = "sys_rst"
    reason: str = ""
    evidence: str = ""
    coverage_loss: str | None = None

    @property
    def key(self) -> str:
        span = "" if (self.bit_lo, self.bit_hi) == (0, self.width - 1) else \
            f"[{self.bit_hi}:{self.bit_lo}]"
        return f"{self.instance_id}:{self.port}{span}"

    def document(self) -> dict[str, object]:
        record: dict[str, object] = {
            "instance_id": self.instance_id,
            "component_id": self.component_id,
            "port": self.port,
            "bits": {"lo": self.bit_lo, "hi": self.bit_hi},
            "direction": self.direction,
            "port_width": self.width,
            "disposition": self.disposition,
            "target": self.target,
            "clock_domain": self.clock_domain,
            "reset_domain": self.reset_domain,
            "reason": self.reason,
            "evidence": self.evidence,
        }
        if self.endpoint_id is not None:
            record["endpoint_id"] = self.endpoint_id
        if self.role is not None:
            record["role"] = self.role
        if self.value is not None:
            record["value"] = self.value
        if self.strategy is not None:
            record["strategy"] = self.strategy
        if self.drive:
            record["drive"] = {str(name): value for name, value in sorted(self.drive.items())}
        if self.coverage_loss is not None:
            record["coverage_loss"] = self.coverage_loss
        return record


def _field_entry(instance_id: str, binding: ProfileBinding, endpoint_function: str,
                 field: ResolvedField, clock_domain: str, reset_domain: str,
                 peers: Mapping[str, str] | None = None) -> DispositionEntry:
    peer_id = (peers or {}).get(field.endpoint_id)
    if peer_id is not None:
        disposition = "peer"
        target = f"peer:{peer_id}"
        reason = (f"profile declares role {field.role} of external interface "
                  f"{field.endpoint_id} and the composition bound the {peer_id} peer model "
                  f"to it, so the pin is driven inside the generated top and is not exported")
        evidence = "soc_peer_plan.endpoints[%s]" % field.endpoint_id
    elif endpoint_function in EXPORTED_FUNCTIONS:
        disposition = "external"
        target = "soc_top"
        reason = ("profile declares a non-MMIO external interface and the composition request "
                  "names no internal peer, so the pin is exported to the SoC top")
        evidence = "component_profile.endpoints[%s]" % field.endpoint_id
    elif endpoint_function in OBSERVED_FUNCTIONS:
        disposition = "observe"
        target = "soc_top"
        reason = "profile declares a passive observation output; it is exported, never driven"
        evidence = "component_profile.endpoints[%s]" % field.endpoint_id
    else:
        disposition = "functional"
        target = FUNCTION_TARGETS.get(endpoint_function)
        if target is None:
            _error(f"unsupported-endpoint-function:{endpoint_function}")
        reason = f"bound to interface {field.endpoint_id} role {field.role}"
        evidence = "elaborated_ports[%s]" % field.port
    return DispositionEntry(
        instance_id=instance_id,
        component_id=binding.component_id,
        port=field.port,
        bit_lo=field.raw_lo,
        bit_hi=field.raw_hi,
        direction=field.direction,
        # The recorded width is the PORT's, not the role's: a member of a struct
        # port occupies a span of a much wider port, and the whole-port test, the
        # exported top-port name and the rendered segment order all read it.
        width=field.port_width or field.width,
        disposition=disposition,
        target=target,
        endpoint_id=field.endpoint_id,
        role=field.role,
        value=None,
        strategy=None,
        clock_domain=clock_domain,
        reset_domain=reset_domain,
        reason=reason,
        evidence=evidence,
    )


def _action_span(entry: PortAction, port_width: int, members: Mapping[tuple[str, ...], tuple[int, int]]) -> tuple[int, int]:
    if entry.member_path:
        span = members.get(entry.member_path)
        if span is None:
            _error(f"port-action-member-missing:{entry.port}:{'.'.join(entry.member_path)}")
        return span
    if entry.bits:
        if any(bit >= port_width for bit in entry.bits):
            _error(f"port-action-bits-outside-port:{entry.port}")
        if entry.bits != tuple(range(entry.bits[0], entry.bits[-1] + 1)):
            _error(f"port-action-bits-not-contiguous:{entry.port}")
        return (entry.bits[0], entry.bits[-1])
    return (0, port_width - 1)


def _action_entry(instance_id: str, binding: ProfileBinding, entry: PortAction, fact: object,
                  span: tuple[int, int], clock_domain: str, reset_domain: str) -> DispositionEntry:
    direction = getattr(fact, "direction")
    port_width = getattr(fact, "width")
    bit_lo, bit_hi = span
    width = bit_hi - bit_lo + 1
    action = entry.action
    if action in ("fuzz", "constant") and direction != "input":
        _error(f"{action}-action-on-non-input:{entry.port}:{direction}")
    if action == "observe" and direction != "output":
        _error(f"observe-action-on-non-output:{entry.port}:{direction}")
    if action == "external" and entry.protocol is None:
        _error(f"external-action-requires-interface-contract:{entry.port}")
    if action == "fuzz" and entry.strategy is None:
        _error(f"fuzz-action-requires-drive-strategy:{entry.port}")
    value = entry.value
    if action == "constant":
        assert value is not None
        if value >= (1 << width):
            _error(f"constant-action-out-of-range:{entry.port}:{value}!<{1 << width}")
    target = {
        "constant": "const",
        "fuzz": "soc_top",
        "observe": "soc_top",
        "external": "soc_top",
        "unconnected": None,
        "functional": FUNCTION_TARGETS.get("mmio_slave"),
    }[action]
    coverage_loss = None
    if action == "unconnected":
        coverage_loss = ("port is left open under the declared contract; behaviour reachable only "
                         "through this port is not exercised")
    elif action == "constant":
        coverage_loss = ("port is held at a fixed value; behaviour reachable only through other "
                         "values of this port is not exercised")
    return DispositionEntry(
        instance_id=instance_id,
        component_id=binding.component_id,
        port=entry.port,
        bit_lo=bit_lo,
        bit_hi=bit_hi,
        direction=direction,
        width=port_width,
        disposition=action,
        target=target,
        endpoint_id=None,
        role=entry.role,
        value=value,
        strategy=entry.strategy,
        drive=dict(entry.drive),
        clock_domain=clock_domain,
        reset_domain=reset_domain,
        reason=entry.reason,
        evidence="component_profile.port_actions[%s]" % entry.port,
        coverage_loss=coverage_loss,
    )


def build_port_dispositions(instance_id: str, binding: ProfileBinding, *,
                            clock_domain: str, reset_domain: str,
                            profile_port_actions: Sequence[PortAction] = (),
                            peer_endpoints: Mapping[str, str] | None = None,
                            ) -> tuple[DispositionEntry, ...]:
    """Classify every port and bit of one instance, or fail closed.

    ``peer_endpoints`` maps a declared ``external_pins`` endpoint id to the peer
    model that was bound to it; those pins become ``peer`` dispositions instead
    of being exported.  The mapping is empty for a composition that attaches no
    peer, which leaves every disposition exactly as it was.

    A port the elaboration reports as ``inout`` is refused before anything is
    classified: the ledger assigns one direction and one driver per bit, so a
    bidirectional port has no unambiguous disposition and is never half-driven.
    """
    if not isinstance(binding, ProfileBinding):
        _error("binding-required")
    for fact in binding.facts.ports:
        if fact.direction == "inout":
            _error(inout_port_refusal(fact.name))
    endpoint_functions = {endpoint.endpoint_id: endpoint.function
                          for endpoint in binding.endpoints}
    entries: list[DispositionEntry] = []
    for endpoint in binding.endpoints:
        function = endpoint_functions[endpoint.endpoint_id]
        for field in endpoint.fields:
            entries.append(_field_entry(instance_id, binding, function, field,
                                        clock_domain, reset_domain, peer_endpoints))
    for _binding_record, field in binding.clocks:
        entries.append(DispositionEntry(
            instance_id=instance_id, component_id=binding.component_id, port=field.port,
            bit_lo=0, bit_hi=field.width - 1, direction="input", width=field.width,
            disposition="functional", target="clock_reset", endpoint_id=None, role="clock",
            value=None, strategy=None, clock_domain=clock_domain, reset_domain=reset_domain,
            reason="clock port distributed from the SoC clock input",
            evidence="component_profile.clocks[%s]" % field.port))
    for _binding_record, field in binding.resets:
        entries.append(DispositionEntry(
            instance_id=instance_id, component_id=binding.component_id, port=field.port,
            bit_lo=0, bit_hi=field.width - 1, direction="input", width=field.width,
            disposition="functional", target="clock_reset", endpoint_id=None, role="reset",
            value=None, strategy=None, clock_domain=clock_domain, reset_domain=reset_domain,
            reason="reset port distributed from the SoC reset input",
            evidence="component_profile.resets[%s]" % field.port))

    members: dict[str, dict[tuple[str, ...], tuple[int, int]]] = {}
    for fact in binding.facts.ports:
        members[fact.name] = {member.path: (member.raw_lo, member.raw_hi)
                              for member in fact.members}
    seen_actions: set[tuple[str, tuple[str, ...], tuple[int, ...]]] = set()
    for action in profile_port_actions:
        fact = binding.facts.port(action.port)
        if fact is None:
            _error(f"port-action-unknown-port:{action.port}")
        key = (action.port, action.member_path, action.bits)
        if key in seen_actions:
            _error(f"duplicate-port-action:{action.port}")
        seen_actions.add(key)
        span = _action_span(action, getattr(fact, "width"), members[action.port])
        entries.append(_action_entry(instance_id, binding, action, fact, span,
                                     clock_domain, reset_domain))

    _validate_coverage(instance_id, binding, entries)
    return tuple(sorted(entries, key=lambda item: (item.port, item.bit_lo, item.disposition)))


def _validate_coverage(instance_id: str, binding: ProfileBinding,
                       entries: Sequence[DispositionEntry]) -> None:
    by_port: dict[str, list[DispositionEntry]] = {}
    for entry in entries:
        by_port.setdefault(entry.port, []).append(entry)
    for fact in binding.facts.ports:
        covered: dict[int, DispositionEntry] = {}
        for entry in by_port.get(fact.name, []):
            if entry.direction != fact.direction and fact.direction != "inout":
                _error(f"disposition-direction-mismatch:{instance_id}:{fact.name}")
            for bit in range(entry.bit_lo, entry.bit_hi + 1):
                if bit in covered:
                    _error(f"bit-multiple-dispositions:{instance_id}:{fact.name}[{bit}]:"
                           f"{covered[bit].disposition}+{entry.disposition}")
                covered[bit] = entry
        missing = [bit for bit in range(fact.width) if bit not in covered]
        if missing:
            ranges = _ranges(missing)
            _error(f"undisposed-port-bits:{instance_id}:{fact.name}:"
                   f"{','.join(f'{hi}:{lo}' for lo, hi in ranges)}")
        if fact.direction == "input":
            drivers = {entry.key for entry in by_port.get(fact.name, [])
                       if entry.disposition in ("functional", "constant", "fuzz", "external",
                                                "peer")}
            if not drivers:
                _error(f"input-without-driver:{instance_id}:{fact.name}")
        if fact.direction == "output":
            for entry in by_port.get(fact.name, []):
                if entry.disposition == "fuzz":
                    _error(f"output-randomly-driven:{instance_id}:{fact.name}")


def _ranges(bits: Sequence[int]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    start = previous = bits[0]
    for bit in bits[1:]:
        if bit == previous + 1:
            previous = bit
            continue
        result.append((start, previous))
        start = previous = bit
    result.append((start, previous))
    return result


def disposition_summary(entries: Sequence[DispositionEntry]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for entry in entries:
        summary[entry.disposition] = summary.get(entry.disposition, 0) + 1
    return dict(sorted(summary.items()))


def dispositions_document(entries: Sequence[DispositionEntry], *,
                          instances: Mapping[str, Sequence[DispositionEntry]] | None = None,
                          provenance: Mapping[str, object] | None = None) -> dict[str, object]:
    """Return the versioned ledger document, including explicit coverage losses."""
    losses = [
        {"instance_id": entry.instance_id, "port": entry.port,
         "bits": {"lo": entry.bit_lo, "hi": entry.bit_hi},
         "disposition": entry.disposition, "loss": entry.coverage_loss}
        for entry in entries if entry.coverage_loss is not None
    ]
    document: dict[str, object] = {
        "schema_version": DISPOSITION_SCHEMA,
        "entries": [entry.document() for entry in entries],
        "summary": disposition_summary(entries),
        "coverage_losses": losses,
        "rules": {
            "input_driver": "exactly one of functional/constant/fuzz/external/peer per bit",
            "output_driver": "only the component itself; observe/unconnected/functional/"
                             "external/peer",
            "unclassified": "rejected",
        },
    }
    if instances is not None:
        document["instances"] = {
            name: [entry.document() for entry in group]
            for name, group in sorted(instances.items())
        }
    if provenance is not None:
        document["provenance"] = dict(provenance)
    return document


def exported_ports(entries: Sequence[DispositionEntry]) -> tuple[DispositionEntry, ...]:
    """Top-level ports the generated SoC must declare."""
    return tuple(entry for entry in entries
                 if entry.disposition in ("fuzz", "external", "observe"))


def fuzz_ports(entries: Sequence[DispositionEntry]) -> tuple[DispositionEntry, ...]:
    """Special inputs the profile explicitly allows the environment to drive."""
    return tuple(entry for entry in entries if entry.disposition == "fuzz")


# ---------------------------------------------------------------------------
# segment naming and struct-port assembly
#
# A physical port that carries several semantic roles (a struct or array port
# bound member by member, or a plain vector sliced by bit range) is rendered as
# ONE connection whose leaves are the individual roles' nets.  The renderer, the
# plan record and the independent audit therefore have to agree on two things:
# the name of each segment's net, and the order the segments appear in.  Both
# rules live here so there is exactly one declaration of each, while the audit
# still derives its expectation from the profile binding and this ledger rather
# than from the renderer's output.
# ---------------------------------------------------------------------------

#: The reference designator of the interrupt notification net.  The renderer
#: declares it, the CPU entry consumes it, and the plan records it.
IRQ_NOTIFY_NET = "irq_notify"


def top_port_name(entry: DispositionEntry) -> str:
    """The exported top-level port name of one disposition segment."""
    span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
        f"_{entry.bit_hi}_{entry.bit_lo}"
    return f"{entry.instance_id}__{entry.port}{span}"


def driven_net(entry: DispositionEntry) -> str:
    """The net a declared special-input driver produces for one segment."""
    span = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else \
        f"_{entry.bit_hi}_{entry.bit_lo}"
    return f"{entry.instance_id}__{entry.port}{span}__driven"


def segment_net(entry: DispositionEntry) -> str:
    """The instance-unique net one functional/peer segment is wired on.

    A whole-port segment keeps the historical ``{instance}__{port}`` net, so
    every existing composition renders exactly as before.  A segment of a
    multi-role port is qualified by its role, which is unique inside its
    endpoint; a segment that has no role (a constant, a fuzz or an observation
    segment) is qualified by its disposition and span.
    """
    if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1):
        return f"{entry.instance_id}__{entry.port}"
    label = entry.role or ""
    if not label:
        label = f"{entry.disposition}_{entry.bit_hi}_{entry.bit_lo}"
    return f"{entry.instance_id}__{entry.port}__{label}"


def field_net(instance_id: str, field: object) -> str:
    """The net one resolved role is wired on, from the binding itself."""
    port = str(getattr(field, "port"))
    whole = bool(getattr(field, "whole_port", False))
    role = str(getattr(field, "role"))
    return f"{instance_id}__{port}" if whole else f"{instance_id}__{port}__{role}"


def constant_expression(entry: DispositionEntry) -> str:
    """The literal a constant segment is driven with."""
    width = entry.bit_hi - entry.bit_lo + 1
    return f"{width}'d{int(entry.value or 0)}"


def cpu_entry_expression(interrupt_document: Mapping[str, object]) -> str | None:
    """The expression the CPU's declared interrupt entry is connected to.

    With a controller the entry is the controller's notification (inverted when
    the profile declares an active-high entry and the controller notifies low).
    Without one the plan records that the entry is disabled by contract, so the
    entry is held at its inactive literal - never left floating and never driven
    by a net no module declares.
    """
    entry = interrupt_document.get("cpu_entry")
    if not isinstance(entry, Mapping):
        return None
    controller = interrupt_document.get("controller")
    present = bool(isinstance(controller, Mapping) and controller.get("present"))
    inverted = bool(entry.get("inversion"))
    if present:
        return f"~{IRQ_NOTIFY_NET}" if inverted else IRQ_NOTIFY_NET
    return "1'b1" if inverted else "1'b0"


def functional_expression(entry: DispositionEntry, *, bridged_roles: frozenset[str],
                          interrupt_document: Mapping[str, object] | None = None,
                          cpu_entry: Mapping[str, object] | None = None) -> str:
    """The expression one functional segment is connected to.

    Three cases exist and nothing else: a role a resolved target bridge owns is
    the bridge's own role net; the CPU's declared interrupt entry is the
    controller notification (or its declared inactive literal); every other role
    is the component net named by its own span.
    """
    if cpu_entry is not None and entry.endpoint_id == cpu_entry.get("endpoint_id") \
            and entry.role == cpu_entry.get("role"):
        expression = cpu_entry_expression(interrupt_document or {})
        if expression is not None:
            return expression
    if entry.role is not None and str(entry.role) in bridged_roles:
        return f"{entry.instance_id}__{entry.role}"
    return segment_net(entry)


def segment_expression(entry: DispositionEntry, *, bridged_roles: frozenset[str] = frozenset(),
                       interrupt_document: Mapping[str, object] | None = None,
                       cpu_entry: Mapping[str, object] | None = None) -> str | None:
    """The connection expression of one disposition segment, or ``None``.

    ``None`` means the segment is deliberately left open (``unconnected`` under a
    declared contract) and therefore contributes no connection at all.
    """
    if entry.disposition == "unconnected":
        return None
    if entry.disposition == "constant":
        return constant_expression(entry)
    if entry.disposition == "fuzz":
        return driven_net(entry)
    if entry.disposition in ("external", "observe"):
        return top_port_name(entry)
    if entry.disposition == "peer":
        return f"{entry.instance_id}__{entry.port}"
    if entry.disposition == "functional":
        return functional_expression(entry, bridged_roles=bridged_roles,
                                     interrupt_document=interrupt_document,
                                     cpu_entry=cpu_entry)
    _error(f"unsupported-disposition:{entry.instance_id}:{entry.port}:{entry.disposition}")


@dataclass(frozen=True, slots=True)
class MemberNode:
    """One node of a port's elaborated member tree.

    ``name`` is the member name (empty at the port root), ``leaves`` the plain
    members directly below it as ``(path, bit_lo, bit_hi)`` triples and
    ``children`` the intermediate packed structs.  A packed struct may declare an
    intermediate struct before *or* after a plain member, so the two kinds cannot
    be walked one after the other; :meth:`items` merges them by span, most
    significant first, which is the order the frontend emits them in.
    """

    name: str
    bit_lo: int
    bit_hi: int
    leaves: tuple[tuple[tuple[str, ...], int, int], ...] = ()
    children: tuple["MemberNode", ...] = ()

    def items(self) -> tuple[tuple[int, object], ...]:
        merged: list[tuple[int, object]] = [(child.bit_hi, child) for child in self.children]
        merged.extend((high, (path, low, high)) for path, low, high in self.leaves)
        return tuple(sorted(merged, key=lambda item: -item[0]))


def _leaf_span(members: Sequence[object], path: tuple[str, ...]) -> tuple[int, int]:
    for member in members:
        if tuple(str(part) for part in getattr(member, "path")) == path:
            return (int(getattr(member, "raw_lo")), int(getattr(member, "raw_hi")))
    _error(f"member-missing:{'.'.join(path)}")


def member_tree(members: Sequence[object], width: int) -> MemberNode:
    """Rebuild the member tree a flattened member list came from.

    The frontend flattens nested packed structs into leaves with full paths, in
    most-significant-first order, and exposes a packed array as one aggregate
    leaf (a single-element path).  Rebuilding the tree therefore only has to
    group the leaves by their common path prefix; every node's span is the union
    of the leaves below it.
    """
    spans: dict[tuple[str, ...], list[int]] = {}
    parents: dict[tuple[str, ...], tuple[str, ...]] = {}
    leaves: dict[tuple[str, ...], list[tuple[tuple[str, ...], int, int]]] = {}
    for member in members:
        path = tuple(str(part) for part in getattr(member, "path"))
        if not path:
            _error("member-path-missing")
        low, high = int(getattr(member, "raw_lo")), int(getattr(member, "raw_hi"))
        leaves.setdefault(path[:-1], []).append((path, low, high))
        for depth in range(1, len(path)):
            prefix = path[:depth]
            if prefix not in spans:
                spans[prefix] = [low, high]
                parents[prefix] = prefix[:-1]
            else:
                spans[prefix][0] = min(spans[prefix][0], low)
                spans[prefix][1] = max(spans[prefix][1], high)
    children: dict[tuple[str, ...], list[tuple[str, ...]]] = {}
    for prefix in spans:
        children.setdefault(parents[prefix], []).append(prefix)

    def build(prefix: tuple[str, ...]) -> MemberNode:
        below = sorted(children.get(prefix, ()), key=lambda item: -spans[item][1])
        return MemberNode(
            name=prefix[-1], bit_lo=spans[prefix][0], bit_hi=spans[prefix][1],
            leaves=tuple(sorted(leaves.get(prefix, ()), key=lambda item: -item[2])),
            children=tuple(build(item) for item in below))

    root_children = sorted(children.get((), ()), key=lambda item: -spans[item][1])
    return MemberNode(name="", bit_lo=0, bit_hi=max(0, width - 1),
                      leaves=tuple(sorted(leaves.get((), ()), key=lambda item: -item[2])),
                      children=tuple(build(item) for item in root_children))


def port_segments(entries: Sequence[DispositionEntry]) -> dict[str, tuple[DispositionEntry, ...]]:
    """Disposition entries grouped by port, most significant bit first."""
    grouped: dict[str, list[DispositionEntry]] = {}
    for entry in entries:
        grouped.setdefault(entry.port, []).append(entry)
    return {port: tuple(sorted(items, key=lambda item: (-item.bit_hi, item.bit_lo)))
            for port, items in grouped.items()}


def port_is_aggregated(entries: Sequence[DispositionEntry]) -> bool:
    """Whether a port is rendered as one assembled connection.

    Exactly one entry covering the whole port is the historical single-connection
    case; anything else is a multi-role port.
    """
    if len(entries) != 1:
        return True
    entry = entries[0]
    return (entry.bit_lo, entry.bit_hi) != (0, entry.width - 1)


def aligned_segments(entries: Sequence[DispositionEntry], members: Sequence[object], width: int
                     ) -> tuple[tuple[int, int, tuple[str, ...], DispositionEntry], ...]:
    """The segments of one port in the order the rendered expression emits them.

    Each returned item is ``(bit_lo, bit_hi, member_path, entry)``.  The segment
    set must tile the port exactly, and on a port with an elaborated member
    layout it must also align with that layout: every member is either covered by
    exactly one segment or partitioned by its own children.  A slice that
    straddles two members cannot be expressed as an assignment pattern, so it is
    refused by name instead of being reordered silently.
    """
    instance, port = entries[0].instance_id, entries[0].port
    ordered = tuple(sorted(entries, key=lambda item: (-item.bit_hi, item.bit_lo)))
    cursor = width - 1
    for entry in ordered:
        if entry.bit_hi > cursor:
            _error(f"port-segment-overlap:{instance}:{port}:[{entry.bit_hi}:{entry.bit_lo}]")
        if entry.bit_hi != cursor:
            _error(f"port-segment-gap:{instance}:{port}:{cursor}")
        cursor = entry.bit_lo - 1
    if cursor != -1:
        _error(f"port-segment-gap:{instance}:{port}:{cursor}")
    spans: dict[tuple[int, int], DispositionEntry] = {}
    for entry in ordered:
        if (entry.bit_lo, entry.bit_hi) in spans:
            _error(f"port-segment-duplicate-span:{instance}:{port}:"
                   f"[{entry.bit_hi}:{entry.bit_lo}]")
        spans[(entry.bit_lo, entry.bit_hi)] = entry
    if not members:
        return tuple((entry.bit_lo, entry.bit_hi, (), entry) for entry in ordered)
    whole = spans.get((0, width - 1))
    if whole is not None and len(ordered) == 1:
        # One role owns the whole aggregate: it is connected as one value, which
        # is exactly the single-connection case and needs no member assembly.
        return ((0, width - 1, (), whole),)

    resolved: list[tuple[int, int, tuple[str, ...], DispositionEntry]] = []
    unmatched: list[str] = []

    def walk(node: MemberNode, path: tuple[str, ...]) -> None:
        covering = spans.get((node.bit_lo, node.bit_hi))
        if covering is not None:
            resolved.append((node.bit_lo, node.bit_hi, path, covering))
            return
        if not node.children and not node.leaves:
            unmatched.append(".".join(path))
            return
        for _high, item in node.items():
            if isinstance(item, MemberNode):
                walk(item, path + (item.name,))
                continue
            leaf_path, low, high = item  # type: ignore[misc]
            leaf = spans.get((low, high))
            if leaf is None:
                unmatched.append(".".join(leaf_path))
                continue
            resolved.append((low, high, tuple(leaf_path), leaf))

    tree = member_tree(members, width)
    for _high, item in tree.items():
        if isinstance(item, MemberNode):
            walk(item, (item.name,))
        else:
            leaf_path, low, high = item  # type: ignore[misc]
            leaf = spans.get((low, high))
            if leaf is None:
                unmatched.append(".".join(leaf_path))
                continue
            resolved.append((low, high, tuple(leaf_path), leaf))
    if unmatched or len(resolved) != len(ordered):
        _error(f"struct-port-segment-mismatch:{instance}:{port}:"
               f"{','.join(sorted(unmatched)) or f'{len(resolved)}!={len(ordered)}'}")
    return tuple(resolved)


__all__ = [
    "DISPOSITION_SCHEMA",
    "EXPORTED_FUNCTIONS",
    "FUNCTION_TARGETS",
    "OBSERVED_FUNCTIONS",
    "DispositionEntry",
    "PortDispositionError",
    "build_port_dispositions",
    "disposition_summary",
    "dispositions_document",
    "exported_ports",
    "fuzz_ports",
    "IRQ_NOTIFY_NET",
    "MemberNode",
    "aligned_segments",
    "constant_expression",
    "cpu_entry_expression",
    "driven_net",
    "field_net",
    "functional_expression",
    "member_tree",
    "port_is_aggregated",
    "port_segments",
    "segment_expression",
    "segment_net",
    "top_port_name",
]
