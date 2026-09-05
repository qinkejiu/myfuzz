"""Name-independent declarative composition primitives."""

from .auto import (
    AutoCompositionError,
    AutoCompositionPlan,
    AutoCompositionRequest,
    plan_auto_composition,
    write_auto_composition_manifest,
)
from .declarations import DeclarationError, DeclarationSet, load_declarations
from .facts import HdlFacts, normalize_facts
from .ids import canonical_id
from .ir import composition_ir
from .manifest import candidate_manifest
from .protocol_composer import (
    CompositionArtifact,
    compose_protocol_composition,
    write_protocol_composition,
)
from .protocol_manifest import (
    CompositionComponent,
    ProtocolCompositionError,
    ProtocolCompositionManifest,
    load_protocol_composition,
    validate_protocol_composition,
)
from .registry import ComponentRegistration, ComponentRegistry, default_component_registry
from .search import CompositionCandidate, compose_topk

__all__ = [
    "AutoCompositionError",
    "AutoCompositionPlan",
    "AutoCompositionRequest",
    "DeclarationError",
    "DeclarationSet",
    "HdlFacts",
    "CompositionCandidate",
    "CompositionArtifact",
    "CompositionComponent",
    "ComponentRegistration",
    "ComponentRegistry",
    "ProtocolCompositionError",
    "ProtocolCompositionManifest",
    "candidate_manifest",
    "canonical_id",
    "compose_topk",
    "compose_protocol_composition",
    "composition_ir",
    "default_component_registry",
    "load_declarations",
    "load_protocol_composition",
    "normalize_facts",
    "plan_auto_composition",
    "validate_protocol_composition",
    "write_protocol_composition",
    "write_auto_composition_manifest",
]
