"""Closed peripheral capability and dependency catalog."""

from .catalog import (
    ComponentCatalog,
    load_builtin_component_catalog,
    load_component_catalog,
    load_real_component_catalog,
)
from .model import (
    ComponentDefinitionError,
    Dependency,
    DependencySpec,
    EndpointSpec,
    ExternalPin,
    ExternalPinSpec,
    Parameter,
    ParameterSpec,
    PeripheralEndpoint,
    PeripheralProfile,
    ProtocolFeature,
    ProtocolFeatureSpec,
)

__all__ = [
    "ComponentCatalog",
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
    "load_builtin_component_catalog",
    "load_component_catalog",
    "load_real_component_catalog",
]
