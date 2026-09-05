"""Closed peripheral capability and dependency catalog."""

from .catalog import ComponentCatalog, load_builtin_component_catalog, load_component_catalog
from .model import ComponentDefinitionError, PeripheralProfile

__all__ = [
    "ComponentCatalog",
    "ComponentDefinitionError",
    "PeripheralProfile",
    "load_builtin_component_catalog",
    "load_component_catalog",
]
