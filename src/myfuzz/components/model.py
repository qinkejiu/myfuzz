"""Immutable records used by the peripheral capability catalog."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


class ComponentDefinitionError(ValueError):
    """Raised when a peripheral profile cannot be used safely."""


@dataclass(frozen=True, slots=True)
class EndpointSpec:
    """A CPU-independent semantic endpoint exposed by a component."""

    endpoint_id: str
    role: str
    function: str
    protocols: tuple[tuple[str, str], ...] = ()
    required: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "protocols",
            tuple((protocol_id, version) for protocol_id, version in self.protocols),
        )


@dataclass(frozen=True, slots=True)
class ProtocolFeatureSpec:
    """Capabilities a component expects from a protocol profile."""

    protocol: tuple[str, str]
    features: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "protocol", tuple(self.protocol))
        object.__setattr__(self, "features", tuple(self.features))


@dataclass(frozen=True, slots=True)
class ExternalPinSpec:
    """A generic external connection, independent of a CPU port name."""

    pin_id: str
    role: str
    direction: str
    width: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class DependencySpec:
    """A component, clock, reset, or address-domain dependency."""

    kind: str
    name: str
    required: bool = True


@dataclass(frozen=True, slots=True)
class ParameterSpec:
    """A parameter domain used when selecting a reusable component."""

    name: str
    parameter_type: str
    default: object
    limits: tuple[int, int] | None = None

    def __post_init__(self) -> None:
        if self.limits is not None:
            object.__setattr__(self, "limits", (self.limits[0], self.limits[1]))


@dataclass(frozen=True, slots=True)
class PeripheralProfile:
    component_type: str
    module_name: str
    protocols: tuple[tuple[str, str], ...]
    address_alignment: int
    default_size: int
    irq_capable: bool
    requires: tuple[str, ...]
    source_status: str
    source_paths: tuple[str, ...]
    implemented: bool
    parameter_limits: Mapping[str, tuple[int, int]]
    endpoints: tuple[EndpointSpec, ...] = ()
    protocol_features: Mapping[tuple[str, str], tuple[str, ...]] = field(default_factory=dict)
    external_pins: tuple[ExternalPinSpec, ...] = ()
    dependencies: tuple[DependencySpec, ...] = ()
    parameters: Mapping[str, ParameterSpec] | None = None

    def __post_init__(self) -> None:
        """Copy collection inputs so the frozen record is transitively stable."""
        object.__setattr__(
            self,
            "protocols",
            tuple((protocol_id, version) for protocol_id, version in self.protocols),
        )
        object.__setattr__(self, "requires", tuple(self.requires))
        object.__setattr__(self, "source_paths", tuple(self.source_paths))
        object.__setattr__(
            self,
            "parameter_limits",
            MappingProxyType(
                {
                    name: (bounds[0], bounds[1])
                    for name, bounds in self.parameter_limits.items()
                }
            ),
        )
        object.__setattr__(self, "endpoints", tuple(self.endpoints))
        object.__setattr__(
            self,
            "protocol_features",
            MappingProxyType(
                {
                    (protocol_id, version): tuple(features)
                    for (protocol_id, version), features in self.protocol_features.items()
                }
            ),
        )
        object.__setattr__(self, "external_pins", tuple(self.external_pins))
        object.__setattr__(self, "dependencies", tuple(self.dependencies))
        parameters = self.parameters
        if parameters is None:
            parameters = {
                name: ParameterSpec(
                    name=name,
                    parameter_type="integer",
                    default=bounds[0],
                    limits=bounds,
                )
                for name, bounds in self.parameter_limits.items()
            }
        object.__setattr__(self, "parameters", MappingProxyType(dict(parameters)))

    @property
    def protocol_feature_records(self) -> tuple[ProtocolFeatureSpec, ...]:
        """Return protocol features as deterministic typed records."""
        return tuple(
            ProtocolFeatureSpec(protocol, features)
            for protocol, features in sorted(self.protocol_features.items())
        )

    @property
    def parameter_specs(self) -> Mapping[str, ParameterSpec]:
        """Alias that makes the parameter metadata explicit to callers."""
        assert self.parameters is not None
        return self.parameters

    @property
    def endpoint_roles(self) -> tuple[str, ...]:
        """Return the semantic roles declared by the component endpoints."""
        return tuple(endpoint.role for endpoint in self.endpoints)

    @property
    def protocol_capabilities(self) -> Mapping[tuple[str, str], tuple[str, ...]]:
        """Alias for callers that use capability terminology."""
        return self.protocol_features


# Short aliases keep the data model easy to discover for catalog clients.
PeripheralEndpoint = EndpointSpec
ProtocolFeature = ProtocolFeatureSpec
ExternalPin = ExternalPinSpec
Dependency = DependencySpec
Parameter = ParameterSpec


__all__ = [
    "ComponentDefinitionError",
    "Dependency",
    "DependencySpec",
    "EndpointSpec",
    "ExternalPin",
    "ExternalPinSpec",
    "Parameter",
    "ParameterSpec",
    "PeripheralEndpoint",
    "PeripheralProfile",
    "ProtocolFeature",
    "ProtocolFeatureSpec",
]
