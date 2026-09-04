"""Declared protocol plugin compiler."""

from .bridge import (
    Apb4BridgeModel,
    Axi4LiteBridgeModel,
    BridgeCycle,
    MmioRequest,
    MmioResponse,
    TileLinkUlBridgeModel,
)
from .catalog import ProtocolCatalog, load_builtin_protocol, load_protocol_catalog
from .compiler import (
    ProtocolCompilationError,
    compile_protocol,
    compile_runtime_protocol,
    protocol_input_fields,
)
from .model import (
    ProjectionActionSpec,
    ProtocolDefinitionError,
    ProtocolPlugin,
    TemporalRuleSpec,
)

__all__ = [
    "Apb4BridgeModel",
    "Axi4LiteBridgeModel",
    "BridgeCycle",
    "MmioRequest",
    "MmioResponse",
    "ProtocolCatalog",
    "ProtocolCompilationError",
    "ProtocolDefinitionError",
    "ProtocolPlugin",
    "ProjectionActionSpec",
    "TemporalRuleSpec",
    "TileLinkUlBridgeModel",
    "compile_protocol",
    "compile_runtime_protocol",
    "load_builtin_protocol",
    "load_protocol_catalog",
    "protocol_input_fields",
]
