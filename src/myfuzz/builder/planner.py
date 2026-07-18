"""Integrated protocol-driven planning from normalized inputs and RTL facts."""

from __future__ import annotations

from dataclasses import dataclass

from .addressing import AddressIntent, AddressPlan, allocate_addresses
from .builtin_profiles import builtin_profile_registry
from .classification import ModuleClassification, classify_modules
from .discovery import DiscoveredModule, DiscoveredPort, DiscoveryResult
from .graph import (
    ConnectionKind,
    ConnectionRequest,
    ConstraintKind,
    EndpointRef,
    SignalConstraint,
    SignalEndpoint,
    SystemGraph,
    build_system_graph,
)
from .input_model import AddressMode, AddressRequest, InputValidationError, PortDirection, SystemSpec
from .profiles import InterfaceRole, ProfileRegistry, ProtocolProfile
from .unknown_ports import (
    DecisionStatus,
    UnknownInputRequest,
    UnknownPortAction,
    UnknownPortDecision,
    decide_unknown_port,
)


@dataclass(frozen=True)
class PortBinding:
    module: str
    port: str
    direction: PortDirection
    width: int
    semantic: str
    interface: str | None
    source: str
    reason: str
    confidence: str


@dataclass(frozen=True)
class InterfaceBinding:
    module: str
    name: str
    protocol: str
    role: InterfaceRole
    profile: str
    ports: tuple[PortBinding, ...]


@dataclass(frozen=True)
class SystemPlan:
    name: str
    classifications: tuple[ModuleClassification, ...]
    port_bindings: tuple[PortBinding, ...]
    interfaces: tuple[InterfaceBinding, ...]
    unknown_ports: tuple[UnknownPortDecision, ...]
    address_plan: AddressPlan
    graph: SystemGraph
    virtual_modules: tuple[str, ...]
    validation_issues: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.validation_issues


def plan_system(
    spec: SystemSpec,
    discovery: DiscoveryResult,
    registry: ProfileRegistry | None = None,
    *,
    address_width: int = 32,
) -> SystemPlan:
    registry = registry or builtin_profile_registry()
    discovered = {module.name: module for module in discovery.modules}
    declared = {module.name: module for module in spec.modules}
    missing = sorted(set(declared) - set(discovered))
    if missing:
        raise InputValidationError(f"declared module(s) not found by discovery: {', '.join(missing)}")

    bindings: list[PortBinding] = []
    interfaces: list[InterfaceBinding] = []
    issues: list[str] = []
    for module_spec in spec.modules:
        module = discovered[module_spec.name]
        by_name = {port.name: port for port in module.ports}
        module_bindings: dict[str, PortBinding] = {}
        for port_name, annotation in module_spec.ports.items():
            fact = by_name.get(port_name)
            if fact is None:
                issues.append(f"{module.name}.{port_name}: user-annotated port was not found in RTL")
                continue
            width = annotation.width if annotation.width is not None else fact.width
            if width is None:
                issues.append(f"{module.name}.{port_name}: width could not be resolved")
                continue
            if annotation.direction is not fact.direction:
                issues.append(
                    f"{module.name}.{port_name}: user direction {annotation.direction.value} "
                    f"conflicts with RTL direction {fact.direction.value}"
                )
            module_bindings[port_name] = PortBinding(
                module.name, port_name, annotation.direction, width, annotation.port_type,
                None, "user", "user-provided port type is authoritative", "declared",
            )

        for interface in module_spec.interfaces:
            profiles = registry.query(interface.protocol, interface.role)
            if not profiles:
                issues.append(
                    f"{module.name}.{interface.name}: no profile for {interface.protocol}/{interface.role}"
                )
                continue
            profile = profiles[0]
            interface_ports: dict[str, PortBinding] = {}
            for semantic_name, physical_name in interface.ports.items():
                semantic = _semantic(profile, semantic_name)
                fact = by_name.get(physical_name)
                if fact is None:
                    issues.append(f"{module.name}.{interface.name}: port {physical_name!r} was not found in RTL")
                    continue
                existing = module_bindings.get(physical_name)
                if existing is not None:
                    binding = existing
                else:
                    rule = next((rule for rule in profile.ports if rule.semantic == semantic), None)
                    if rule is None:
                        issues.append(
                            f"{module.name}.{interface.name}: semantic {semantic_name!r} is not in profile {profile.name}"
                        )
                        continue
                    width = _resolved_width(fact, module.name)
                    binding = PortBinding(
                        module.name, physical_name, fact.direction, width, semantic, interface.name,
                        "user", "explicit interface binding", "declared",
                    )
                    module_bindings[physical_name] = binding
                interface_ports[binding.semantic] = binding

            for fact in module.ports:
                if fact.name in module_bindings:
                    continue
                resolution = registry.resolve_port(
                    protocol=interface.protocol,
                    interface_role=interface.role,
                    port_name=fact.name,
                    direction=fact.direction,
                )
                if resolution.annotation is None:
                    continue
                width = _resolved_width(fact, module.name)
                binding = PortBinding(
                    module.name, fact.name, fact.direction, width, resolution.annotation.port_type,
                    interface.name, resolution.source.value, resolution.reason, resolution.confidence,
                )
                module_bindings[fact.name] = binding
                interface_ports[binding.semantic] = binding

            for rule in profile.ports:
                if rule.required and rule.semantic not in interface_ports:
                    issues.append(
                        f"{module.name}.{interface.name}: required profile signal {rule.semantic} is missing"
                    )
            interfaces.append(InterfaceBinding(
                module.name, interface.name, profile.protocol, profile.interface_role, profile.name,
                tuple(sorted(interface_ports.values(), key=lambda item: item.semantic)),
            ))
        bindings.extend(module_bindings.values())

    unknown = _decide_unknowns(spec, discovery, bindings, issues)
    address_plan = _plan_addresses(spec, interfaces, registry, address_width)
    graph, virtual_modules = _plan_graph(spec, discovery, bindings, interfaces, unknown)
    issues.extend(
        f"{decision.module}.{decision.port}: {decision.reason}"
        for decision in unknown
        if decision.status is not DecisionStatus.PLANNED
    )
    return SystemPlan(
        name=spec.name,
        classifications=classify_modules(spec, discovery),
        port_bindings=tuple(sorted(bindings, key=lambda item: (item.module, item.port))),
        interfaces=tuple(sorted(interfaces, key=lambda item: (item.protocol, item.module, item.name))),
        unknown_ports=tuple(sorted(unknown, key=lambda item: (item.module, item.port))),
        address_plan=address_plan,
        graph=graph,
        virtual_modules=virtual_modules,
        validation_issues=tuple(issues),
    )


def _decide_unknowns(
    spec: SystemSpec,
    discovery: DiscoveryResult,
    bindings: list[PortBinding],
    issues: list[str],
) -> list[UnknownPortDecision]:
    bound = {(binding.module, binding.port) for binding in bindings}
    declared = {module.name: module for module in spec.modules}
    decisions: list[UnknownPortDecision] = []
    for module in discovery.modules:
        module_spec = declared.get(module.name)
        if module_spec is None:
            continue
        for port in module.ports:
            if (module.name, port.name) in bound:
                continue
            width = port.width
            if width is None:
                issues.append(f"{module.name}.{port.name}: width could not be resolved")
                continue
            policy = module_spec.unknown_ports.get(port.name) if module_spec else None
            request = None
            if policy is not None:
                try:
                    action = UnknownPortAction(policy.action)
                except ValueError:
                    issues.append(f"{module.name}.{port.name}: unknown policy action {policy.action!r}")
                    continue
                request = UnknownInputRequest(
                    action=action, reason=policy.reason, tieoff_value=policy.value,
                    constraint=policy.constraint, reset_behavior=policy.reset_behavior,
                    connect_to=policy.connect_to,
                )
            decisions.append(decide_unknown_port(
                module=module.name, port=port.name, direction=port.direction, width=width,
                input_request=request,
            ))
    return decisions


def _plan_addresses(
    spec: SystemSpec,
    interfaces: list[InterfaceBinding],
    registry: ProfileRegistry,
    address_width: int,
) -> AddressPlan:
    declared = {module.name: module for module in spec.modules}
    intents: list[AddressIntent] = []
    target_modules = sorted({interface.module for interface in interfaces if interface.role is InterfaceRole.TARGET})
    for module_name in target_modules:
        module = declared[module_name]
        request = module.address
        if request is None:
            interface = next(item for item in interfaces if item.module == module_name and item.role is InterfaceRole.TARGET)
            profile = registry.query(interface.protocol, InterfaceRole.TARGET)[0]
            rule = profile.address_rule
            if rule and rule.requires_window:
                request = AddressRequest(
                    AddressMode.AUTO, rule.default_size or 4096, None, rule.alignment,
                )
        if request is not None:
            intents.append(AddressIntent(module_name, request))
    return allocate_addresses(intents, address_width=address_width)


def _plan_graph(
    spec: SystemSpec,
    discovery: DiscoveryResult,
    bindings: list[PortBinding],
    interfaces: list[InterfaceBinding],
    unknown: list[UnknownPortDecision],
) -> tuple[SystemGraph, tuple[str, ...]]:
    declared_modules = {module.name for module in spec.modules}
    endpoints = [
        SignalEndpoint(EndpointRef(module.name, port.name), port.direction, _resolved_width(port, module.name))
        for module in discovery.modules if module.name in declared_modules
        for port in module.ports if port.width is not None
    ]
    requests: list[ConnectionRequest] = []
    constraints: list[SignalConstraint] = []
    virtual: list[str] = []

    for protocol in sorted({interface.protocol for interface in interfaces}):
        group = [interface for interface in interfaces if interface.protocol == protocol]
        initiators = [item for item in group if item.role is InterfaceRole.INITIATOR]
        targets = [item for item in group if item.role is InterfaceRole.TARGET]
        if not initiators or not targets:
            continue
        if len(initiators) == len(targets) == 1 and not _requires_address_adapter(
            initiators[0], targets[0]
        ):
            _connect_interface_pair(initiators[0], targets[0], requests)
        else:
            fabric = f"__fabric_{protocol}"
            virtual.append(fabric)
            for interface in initiators + targets:
                for binding in interface.ports:
                    suffix = "in" if binding.direction is PortDirection.OUTPUT else "out"
                    fabric_ref = EndpointRef(fabric, f"{binding.module}__{binding.port}__{suffix}")
                    fabric_direction = (
                        PortDirection.INPUT if binding.direction is PortDirection.OUTPUT else PortDirection.OUTPUT
                    )
                    endpoints.append(SignalEndpoint(fabric_ref, fabric_direction, binding.width, binding.semantic))
                    source, target = (
                        (EndpointRef(binding.module, binding.port), fabric_ref)
                        if binding.direction is PortDirection.OUTPUT
                        else (fabric_ref, EndpointRef(binding.module, binding.port))
                    )
                    requests.append(_request(source, target, ConnectionKind.PROTOCOL, "virtual fabric channel"))
            by_semantic: dict[str, list[PortBinding]] = {}
            for interface in initiators + targets:
                for binding in interface.ports:
                    by_semantic.setdefault(binding.semantic, []).append(binding)
            for semantic, semantic_bindings in by_semantic.items():
                widths = {binding.width for binding in semantic_bindings}
                if len(widths) > 1 and _is_address_semantic(semantic):
                    system_width = max(widths)
                    for binding in semantic_bindings:
                        if (binding.direction is PortDirection.INPUT and binding.width < system_width
                                and _is_address_semantic(semantic)):
                            constraints.append(SignalConstraint(
                                EndpointRef(binding.module, binding.port), ConstraintKind.EXPRESSION,
                                f"window decode then use low {binding.width} of {system_width} address bits",
                                "target exposes a narrower local address port", "profile", "profile",
                            ))

    for interface in interfaces:
        for binding in interface.ports:
            if binding.semantic.endswith(".request") and binding.direction is PortDirection.INPUT:
                constraints.append(SignalConstraint(
                    EndpointRef(binding.module, binding.port), ConstraintKind.HANDSHAKE,
                    "request is valid for the complete transfer decision cycle",
                    "protocol profile request-channel rule", "profile", "profile",
                ))

    binding_by_port = {(item.module, item.port): item for item in bindings}
    for domain in spec.clock_domains:
        source = EndpointRef(f"__clock_{domain.name}", "out")
        endpoints.append(SignalEndpoint(source, PortDirection.OUTPUT, 1, "clock"))
        virtual.append(source.module)
        for binding in bindings:
            module_spec = next((module for module in spec.modules if module.name == binding.module), None)
            if module_spec and module_spec.clock_domain == domain.name and binding.semantic == "clock":
                requests.append(_request(source, EndpointRef(binding.module, binding.port), ConnectionKind.CLOCK_RESET, "clock domain"))
    for domain in spec.reset_domains:
        semantic = "reset_active_low" if domain.active_low else "reset_active_high"
        source = EndpointRef(f"__reset_{domain.name}", "out")
        endpoints.append(SignalEndpoint(source, PortDirection.OUTPUT, 1, semantic))
        virtual.append(source.module)
        for binding in bindings:
            module_spec = next((module for module in spec.modules if module.name == binding.module), None)
            if module_spec and module_spec.reset_domain == domain.name and binding.semantic == semantic:
                requests.append(_request(source, EndpointRef(binding.module, binding.port), ConnectionKind.CLOCK_RESET, "reset domain"))

    for decision in unknown:
        target = EndpointRef(decision.module, decision.port)
        if decision.action is UnknownPortAction.TIEOFF:
            constraints.append(SignalConstraint(
                target, ConstraintKind.CONSTANT, decision.constraint or "", decision.reason,
                decision.evidence_source, "declared",
            ))
        elif decision.action is UnknownPortAction.CONSTRAINED_RANDOM:
            constraints.append(SignalConstraint(
                target, ConstraintKind.EXPRESSION, decision.constraint or "", decision.reason,
                decision.evidence_source, "declared",
            ))
        elif decision.action is UnknownPortAction.CONNECT:
            if "." not in decision.resulting_action:
                continue
            driver = decision.resulting_action.removeprefix("connect to ")
            module, port = driver.rsplit(".", 1)
            requests.append(_request(EndpointRef(module, port), target, ConnectionKind.UNKNOWN_POLICY, decision.reason))
    return build_system_graph(endpoints, requests, constraints), tuple(sorted(set(virtual)))


def _requires_address_adapter(initiator: InterfaceBinding, target: InterfaceBinding) -> bool:
    """Return true when a legal target-local address projection needs a fabric."""
    initiator_ports = {binding.semantic: binding for binding in initiator.ports}
    target_ports = {binding.semantic: binding for binding in target.ports}
    mismatches = [
        semantic for semantic in set(initiator_ports) & set(target_ports)
        if initiator_ports[semantic].width != target_ports[semantic].width
    ]
    return bool(mismatches) and all(_is_address_semantic(semantic) for semantic in mismatches)


def _is_address_semantic(semantic: str) -> bool:
    suffix = semantic.rsplit(".", 1)[-1]
    return suffix in {"address", "awaddr", "araddr", "paddr"}


def _connect_interface_pair(
    initiator: InterfaceBinding,
    target: InterfaceBinding,
    requests: list[ConnectionRequest],
) -> None:
    init_ports = {binding.semantic: binding for binding in initiator.ports}
    target_ports = {binding.semantic: binding for binding in target.ports}
    for semantic in sorted(set(init_ports) & set(target_ports)):
        left, right = init_ports[semantic], target_ports[semantic]
        if left.direction is PortDirection.OUTPUT and right.direction is PortDirection.INPUT:
            source, destination = left, right
        elif right.direction is PortDirection.OUTPUT and left.direction is PortDirection.INPUT:
            source, destination = right, left
        else:
            raise InputValidationError(f"{semantic}: interfaces do not provide one output and one input")
        requests.append(_request(
            EndpointRef(source.module, source.port), EndpointRef(destination.module, destination.port),
            ConnectionKind.PROTOCOL, f"matched {semantic} through protocol profile",
        ))


def _request(source: EndpointRef, target: EndpointRef, kind: ConnectionKind, reason: str) -> ConnectionRequest:
    return ConnectionRequest(source, target, kind, reason, "profile", "profile")


def _semantic(profile: ProtocolProfile, name: str) -> str:
    canonical = name.strip().lower()
    if any(rule.semantic == canonical for rule in profile.ports):
        return canonical
    prefixed = f"{profile.protocol}.{canonical}"
    return prefixed


def _resolved_width(port: DiscoveredPort, module: str) -> int:
    if port.width is None:
        raise InputValidationError(f"{module}.{port.name}: width could not be resolved")
    return port.width
