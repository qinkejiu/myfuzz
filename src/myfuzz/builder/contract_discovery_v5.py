"""Behavior-backed compose-v5 contract hypothesis discovery.

The code here is deliberately conservative.  It consumes elaborated port facts
and frontend behavior facts, then proposes local interface hypotheses without
matching module names, port names, or protocol-specific aliases.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

from .contract_v5 import (
    CONTRACT_V5_AMBIGUITY_SCHEMA,
    CONTRACT_V5_GRAMMAR_VERSION,
    ContractV5AmbiguityReport,
    ContractV5Event,
    ContractV5Hypothesis,
    ContractV5Predicate,
    ContractV5SignalRef,
    contract_v5_hypothesis_digest,
)
from .contracts.experiment import content_digest
from .frontend_v5 import (
    FrontendV5Expression,
    FrontendV5ModuleBehavior,
    FrontendV5Process,
    FrontendV5Transition,
)
from .input_model import InputValidationError, PortDirection
from .rtl_analysis import EvidenceState, RTLModule, RTLPort


CONTRACT_V5_DISCOVERY_SCHEMA = "myfuzz.contract-discovery/v5"


@dataclass(frozen=True)
class ContractV5DiscoveryResult:
    module: str
    original_module: str
    hypotheses: tuple[ContractV5Hypothesis, ...]
    ambiguity: ContractV5AmbiguityReport
    rejected_reasons: tuple[str, ...]
    evidence: Mapping[str, object]
    digest: str
    schema: str = CONTRACT_V5_DISCOVERY_SCHEMA
    grammar_version: str = CONTRACT_V5_GRAMMAR_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.module, str) or not self.module:
            raise InputValidationError("Contract v5 discovery module must be a non-empty string")
        if not isinstance(self.original_module, str) or not self.original_module:
            raise InputValidationError("Contract v5 discovery original_module must be non-empty")
        if not isinstance(self.hypotheses, tuple):
            raise InputValidationError("Contract v5 discovery hypotheses must be a tuple")
        if not isinstance(self.ambiguity, ContractV5AmbiguityReport):
            raise InputValidationError("Contract v5 discovery ambiguity must be a report")
        if not isinstance(self.rejected_reasons, tuple):
            raise InputValidationError("Contract v5 discovery rejected reasons must be a tuple")
        if not isinstance(self.evidence, Mapping):
            raise InputValidationError("Contract v5 discovery evidence must be an object")
        if self.digest != content_digest(self.payload_dict()):
            raise InputValidationError("Contract v5 discovery digest mismatch")

    def payload_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "grammar_version": self.grammar_version,
            "module": self.module,
            "original_module": self.original_module,
            "hypotheses": [_hypothesis_payload(item) for item in self.hypotheses],
            "ambiguity": self.ambiguity.to_dict(),
            "rejected_reasons": list(self.rejected_reasons),
            "evidence": dict(self.evidence),
        }

    def to_dict(self) -> dict[str, object]:
        value = self.payload_dict()
        value["digest"] = self.digest
        return value


def discover_contract_v5_module(
    module: RTLModule,
    behavior: FrontendV5ModuleBehavior,
) -> ContractV5DiscoveryResult:
    """Discover conservative local contract hypotheses for one elaborated module.

    Port names are used only as stable frontend signal identifiers.  No branch
    in this function checks for a specific module, port, or protocol name.
    """

    if not isinstance(module, RTLModule):
        raise InputValidationError("Contract v5 discovery requires an RTLModule")
    if not isinstance(behavior, FrontendV5ModuleBehavior):
        raise InputValidationError("Contract v5 discovery requires frontend module behavior")
    module_ids = {module.name, module.original_name}
    behavior_ids = {behavior.name, behavior.original_name}
    if module_ids.isdisjoint(behavior_ids):
        raise InputValidationError("Contract v5 discovery module and behavior facts do not match")

    ports = {port.name: port for port in module.ports}
    rejected: list[str] = []
    if any(port.direction is PortDirection.INOUT for port in module.ports):
        rejected.append("module has inout ports; first compose-v5 discovery slice rejects inout")
    if any(port.evidence.state is EvidenceState.NON_PROVABLE for port in module.ports):
        rejected.append("module has non-provable port evidence")
    if rejected:
        ambiguity = _discovery_ambiguity([])
        evidence = {
            "frontend_module": behavior.name,
            "process_count": len(behavior.processes),
            "candidate_count": 0,
            "surviving_count": 0,
            "discovery_rule": (
                "edge sensitivity for clock/reset plus guarded opposite-direction one-bit "
                "port pair for request accept"
            ),
            "name_policy": "signal identifiers are references only; no module/port/protocol-name matching",
        }
        payload = {
            "schema": CONTRACT_V5_DISCOVERY_SCHEMA,
            "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
            "module": module.name,
            "original_module": module.original_name,
            "hypotheses": [],
            "ambiguity": ambiguity.to_dict(),
            "rejected_reasons": list(tuple(sorted(rejected))),
            "evidence": evidence,
        }
        return ContractV5DiscoveryResult(
            module=module.name,
            original_module=module.original_name,
            hypotheses=(),
            ambiguity=ambiguity,
            rejected_reasons=tuple(sorted(rejected)),
            evidence=evidence,
            digest=content_digest(payload),
        )

    raw_candidates: list[tuple[ContractV5Hypothesis, str]] = []
    for process in behavior.processes:
        if not _is_edge_process(process):
            continue
        clock = _unique_clock_candidate(process, ports)
        if clock is None:
            rejected.append(f"process {process.index}: no unique edge clock candidate")
            continue
        reset = _reset_candidate(process, ports, clock)
        for transition in process.transitions:
            raw_candidates.extend(
                _hypotheses_from_transition(module, process, transition, ports, clock, reset)
            )

    valid: list[tuple[ContractV5Hypothesis, str, str]] = []
    for hypothesis, binding_signature in raw_candidates:
        try:
            digest = contract_v5_hypothesis_digest(hypothesis)
        except InputValidationError as exc:
            rejected.append(f"candidate rejected: {exc}")
            continue
        valid.append((hypothesis, digest, binding_signature))

    hypotheses = tuple(item[0] for item in valid)
    ambiguity = _discovery_ambiguity(valid)
    evidence = {
        "frontend_module": behavior.name,
        "process_count": len(behavior.processes),
        "candidate_count": len(raw_candidates),
        "surviving_count": len(valid),
        "discovery_rule": (
            "edge sensitivity for clock/reset plus guarded opposite-direction one-bit "
            "port pair for request accept"
        ),
        "name_policy": "signal identifiers are references only; no module/port/protocol-name matching",
    }
    payload = {
        "schema": CONTRACT_V5_DISCOVERY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "module": module.name,
        "original_module": module.original_name,
        "hypotheses": [_hypothesis_payload(item) for item in hypotheses],
        "ambiguity": ambiguity.to_dict(),
        "rejected_reasons": list(tuple(sorted(rejected))),
        "evidence": evidence,
    }
    return ContractV5DiscoveryResult(
        module=module.name,
        original_module=module.original_name,
        hypotheses=hypotheses,
        ambiguity=ambiguity,
        rejected_reasons=tuple(sorted(rejected)),
        evidence=evidence,
        digest=content_digest(payload),
    )


def _hypotheses_from_transition(
    module: RTLModule,
    process: FrontendV5Process,
    transition: FrontendV5Transition,
    ports: Mapping[str, RTLPort],
    clock: RTLPort,
    reset: RTLPort | None,
) -> list[tuple[ContractV5Hypothesis, str]]:
    guard_signals = _signals_in_transition_guards(transition)
    one_bit_ports = tuple(
        ports[signal] for signal in sorted(guard_signals)
        if signal in ports and ports[signal].width == 1
        and ports[signal].direction in {PortDirection.INPUT, PortDirection.OUTPUT}
        and signal != clock.name and (reset is None or signal != reset.name)
    )
    candidates: list[tuple[ContractV5Hypothesis, str]] = []
    for first in one_bit_ports:
        for second in one_bit_ports:
            if first.name >= second.name:
                continue
            if first.direction is second.direction:
                continue
            for request_valid, request_ready, interface_role, payload_ports in (
                _directional_interpretations(transition, ports, first, second, clock, reset)
            ):
                hypothesis = _build_request_hypothesis(
                    module, process, transition, clock, reset, request_valid,
                    request_ready, payload_ports, interface_role,
                )
                candidates.append((hypothesis, _binding_signature(hypothesis)))
    return candidates


def _directional_interpretations(
    transition: FrontendV5Transition,
    ports: Mapping[str, RTLPort],
    first: RTLPort,
    second: RTLPort,
    clock: RTLPort,
    reset: RTLPort | None,
) -> tuple[tuple[RTLPort, RTLPort, str, tuple[RTLPort, ...]], ...]:
    payload_by_direction = {
        direction: _payload_ports_for_transition(
            transition, ports, direction, clock, reset, excluded={first.name, second.name},
        )
        for direction in (PortDirection.INPUT, PortDirection.OUTPUT)
    }
    payload_directions = tuple(
        direction for direction, payload in payload_by_direction.items() if payload
    )
    if len(payload_directions) == 1:
        valid_direction = payload_directions[0]
        request_valid = first if first.direction is valid_direction else second
        request_ready = second if request_valid is first else first
        return ((
            request_valid,
            request_ready,
            "initiator" if valid_direction is PortDirection.OUTPUT else "target",
            payload_by_direction[valid_direction],
        ),)

    first_as_valid = (
        first,
        second,
        "initiator" if first.direction is PortDirection.OUTPUT else "target",
        payload_by_direction[first.direction],
    )
    second_as_valid = (
        second,
        first,
        "initiator" if second.direction is PortDirection.OUTPUT else "target",
        payload_by_direction[second.direction],
    )
    return (first_as_valid, second_as_valid)


def _build_request_hypothesis(
    module: RTLModule,
    process: FrontendV5Process,
    transition: FrontendV5Transition,
    clock: RTLPort,
    reset: RTLPort | None,
    request_valid: RTLPort,
    request_ready: RTLPort,
    payload_ports: tuple[RTLPort, ...],
    interface_role: str,
) -> ContractV5Hypothesis:
    signals = [
        _signal(module, clock, "clock", "edge"),
        _signal(
            module, request_valid, "request_valid",
            "level",
        ),
        _signal(
            module, request_ready, "request_ready",
            "level",
        ),
    ]
    if reset is not None:
        signals.append(_signal(module, reset, "reset", _reset_polarity(reset, process)))
    for payload in payload_ports:
        signals.append(_signal(module, payload, "payload", "data"))
    event = ContractV5Event(
        name=f"p{process.index}_t{_transition_index(process, transition)}_accept",
        kind="request_accept",
        guard=ContractV5Predicate(
            "and",
            children=(
                ContractV5Predicate("signal_nonzero", signal=_source_id(module, request_valid)),
                ContractV5Predicate("signal_nonzero", signal=_source_id(module, request_ready)),
            ),
        ),
        payload_signals=tuple(_source_id(module, item) for item in payload_ports),
    )
    return ContractV5Hypothesis(
        interface_kind="guarded_bit_level",
        interface_role=interface_role,
        signals=tuple(signals),
        events=(event,),
        source_evidence={
            "frontend_module": module.name,
            "process_index": process.index,
            "transition_kind": transition.kind,
            "transition_targets": tuple(sorted(transition.targets)),
            "source": "compose-v5 behavior discovery",
        },
    )


def _discovery_ambiguity(
    valid: list[tuple[ContractV5Hypothesis, str, str]],
) -> ContractV5AmbiguityReport:
    if not valid:
        return _ambiguity_report(
            status="empty",
            surviving_count=0,
            canonical_class_count=0,
            canonical_digests=(),
            selected_digest=None,
            reason="no behavior-backed contract hypotheses survived",
        )
    canonical_digests = tuple(sorted({item[1] for item in valid}))
    binding_signatures = tuple(sorted({item[2] for item in valid}))
    if len(binding_signatures) > 1:
        return _ambiguity_report(
            status="ambiguous",
            surviving_count=len(valid),
            canonical_class_count=len(canonical_digests),
            canonical_digests=canonical_digests,
            selected_digest=None,
            reason="multiple physical signal bindings survived behavior discovery",
        )
    if len(canonical_digests) > 1:
        return _ambiguity_report(
            status="ambiguous",
            surviving_count=len(valid),
            canonical_class_count=len(canonical_digests),
            canonical_digests=canonical_digests,
            selected_digest=None,
            reason="multiple non-equivalent canonical contracts survived behavior discovery",
        )
    return _ambiguity_report(
        status="unique",
        surviving_count=len(valid),
        canonical_class_count=1,
        canonical_digests=canonical_digests,
        selected_digest=canonical_digests[0],
        reason="one physical binding and one canonical contract survived behavior discovery",
    )


def _ambiguity_report(
    *,
    status: str,
    surviving_count: int,
    canonical_class_count: int,
    canonical_digests: tuple[str, ...],
    selected_digest: str | None,
    reason: str,
) -> ContractV5AmbiguityReport:
    payload: dict[str, object] = {
        "schema": CONTRACT_V5_AMBIGUITY_SCHEMA,
        "grammar_version": CONTRACT_V5_GRAMMAR_VERSION,
        "status": status,
        "surviving_count": surviving_count,
        "canonical_class_count": canonical_class_count,
        "canonical_digests": canonical_digests,
        "selected_digest": selected_digest,
        "reason": reason,
    }
    return ContractV5AmbiguityReport(**payload, digest=content_digest(payload))


def _payload_ports_for_transition(
    transition: FrontendV5Transition,
    ports: Mapping[str, RTLPort],
    payload_direction: PortDirection,
    clock: RTLPort,
    reset: RTLPort | None,
    *,
    excluded: set[str],
) -> tuple[RTLPort, ...]:
    referenced = set(transition.sources)
    referenced.update(_signals_in_expression(transition.value_expression))
    referenced.update(_signals_in_expression(transition.target_expression))
    referenced.difference_update(excluded)
    referenced.discard(clock.name)
    if reset is not None:
        referenced.discard(reset.name)
    return tuple(
        sorted(
            (
                ports[name] for name in referenced
                if name in ports
                and ports[name].direction is payload_direction
                and ports[name].width > 1
            ),
            key=lambda port: (port.width, port.direction.value, port.name),
        )
    )


def _unique_clock_candidate(
    process: FrontendV5Process,
    ports: Mapping[str, RTLPort],
) -> RTLPort | None:
    reset_names = {
        signal for signal in _signals_in_process_guards(process)
        if signal in ports and ports[signal].width == 1 and ports[signal].direction is PortDirection.INPUT
    }
    edge_ports = tuple(
        ports[signal] for sensitivity in process.sensitivities
        if sensitivity.edge in {"posedge", "negedge"}
        for signal in sensitivity.signals
        if signal in ports
        and ports[signal].direction is PortDirection.INPUT
        and ports[signal].width == 1
        and signal not in reset_names
    )
    unique = _unique_by_name(edge_ports)
    return unique[0] if len(unique) == 1 else None


def _reset_candidate(
    process: FrontendV5Process,
    ports: Mapping[str, RTLPort],
    clock: RTLPort,
) -> RTLPort | None:
    guard_names = _signals_in_process_guards(process)
    edge_ports = tuple(
        ports[signal] for sensitivity in process.sensitivities
        if sensitivity.edge in {"posedge", "negedge"}
        for signal in sensitivity.signals
        if signal in ports
        and signal != clock.name
        and signal in guard_names
        and ports[signal].direction is PortDirection.INPUT
        and ports[signal].width == 1
    )
    unique = _unique_by_name(edge_ports)
    if len(unique) > 1:
        return None
    return unique[0] if unique else None


def _reset_polarity(reset: RTLPort, process: FrontendV5Process) -> str:
    for sensitivity in process.sensitivities:
        if reset.name in sensitivity.signals:
            if sensitivity.edge == "negedge":
                return "active_low"
            if sensitivity.edge == "posedge":
                return "active_high"
    return "level"


def _is_edge_process(process: FrontendV5Process) -> bool:
    return any(item.edge in {"posedge", "negedge"} for item in process.sensitivities)


def _signals_in_process_guards(process: FrontendV5Process) -> set[str]:
    result: set[str] = set()
    for transition in process.transitions:
        result.update(_signals_in_transition_guards(transition))
    return result


def _signals_in_transition_guards(transition: FrontendV5Transition) -> set[str]:
    result: set[str] = set()
    for guard in transition.guards:
        result.update(_signals_in_expression(guard.expression))
    return result


def _signals_in_expression(expression: FrontendV5Expression | None) -> set[str]:
    if expression is None:
        return set()
    result = {expression.signal} if expression.signal is not None else set()
    for child in expression.children:
        result.update(_signals_in_expression(child))
    return result


def _unique_by_name(ports: Iterable[RTLPort]) -> tuple[RTLPort, ...]:
    by_name: dict[str, RTLPort] = {}
    for port in ports:
        by_name[port.name] = port
    return tuple(by_name[name] for name in sorted(by_name))


def _signal(module: RTLModule, port: RTLPort, role: str, polarity: str) -> ContractV5SignalRef:
    return ContractV5SignalRef(
        source_id=_source_id(module, port),
        module=module.name,
        port=port.name,
        direction=port.direction.value,
        width=port.width,
        role=role,
        polarity=polarity,
    )


def _source_id(module: RTLModule, port: RTLPort) -> str:
    return f"{module.name}.{port.name}"


def _transition_index(process: FrontendV5Process, transition: FrontendV5Transition) -> int:
    for index, item in enumerate(process.transitions):
        if item is transition:
            return index
    return 0


def _binding_signature(hypothesis: ContractV5Hypothesis) -> str:
    payload = tuple(
        sorted(
            tuple(sorted({
                "role": signal.role,
                "direction": signal.direction,
                "width": signal.width,
                "source_id": signal.source_id,
            }.items()))
            for signal in hypothesis.signals
            if signal.role in {"request_valid", "request_ready", "payload"}
        )
    )
    return content_digest({"binding": payload})


def _hypothesis_payload(hypothesis: ContractV5Hypothesis) -> dict[str, object]:
    return {
        "interface_kind": hypothesis.interface_kind,
        "interface_role": hypothesis.interface_role,
        "signals": [
            {
                "source_id": signal.source_id,
                "module": signal.module,
                "port": signal.port,
                "direction": signal.direction,
                "width": signal.width,
                "role": signal.role,
                "polarity": signal.polarity,
            }
            for signal in hypothesis.signals
        ],
        "events": [
            {
                "name": event.name,
                "kind": event.kind,
                "guard": _predicate_payload(event.guard),
                "payload_signals": list(event.payload_signals),
            }
            for event in hypothesis.events
        ],
        "invariants": [_predicate_payload(item) for item in hypothesis.invariants],
        "ordering": [
            {"before": item.before, "after": item.after, "relation": item.relation}
            for item in hypothesis.ordering
        ],
        "source_evidence": dict(hypothesis.source_evidence),
    }


def _predicate_payload(predicate: ContractV5Predicate) -> dict[str, object]:
    return {
        "kind": predicate.kind,
        "signal": predicate.signal,
        "value": predicate.value,
        "children": [_predicate_payload(item) for item in predicate.children],
    }
