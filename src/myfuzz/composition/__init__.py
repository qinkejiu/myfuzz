"""Name-independent declarative composition primitives."""

from .auto import (
    AutoCompositionError,
    AutoCompositionPlan,
    AutoCompositionRequest,
    GenericCompositionPlan,
    GenericCompositionRequest,
    plan_auto_composition,
    plan_generic_composition,
    write_auto_composition_manifest,
)
from .declarations import DeclarationError, DeclarationSet, load_declarations
from .endpoint_capabilities import (
    AdapterCapability,
    EndpointCapability,
    EndpointCapabilityError,
    EndpointFieldFact,
    SourceReference,
    TimingFact,
    match_endpoint_pair,
    normalize_annotations,
    validate_protocol_fingerprint,
)
from .facts import HdlFacts, normalize_facts
from .interface_description import (
    ElaborationSettings,
    EndpointDescription,
    FieldHint,
    InterfaceDescription,
    SourceLocator,
    interface_description_document,
    load_interface_description,
)
from .source_crawler import (
    ElaboratedMemberFact,
    ElaboratedPortFact,
    SourceCrawler,
    SourceCrawlError,
    SourcePortFact,
    SourceSnapshot,
    TimingObservation,
    annotate_interfaces,
    source_tree_hash,
)
from .ids import canonical_id
from .input_layout import InputLayout, InputLayoutError, LayoutField, build_input_layout, input_layout_document
from .ir import composition_ir
from .manifest import candidate_manifest
from .protocol_composer import (
    CompositionArtifact,
    compose_protocol_composition,
    write_generic_composition,
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
    "GenericCompositionPlan",
    "GenericCompositionRequest",
    "AdapterCapability",
    "DeclarationError",
    "DeclarationSet",
    "HdlFacts",
    "EndpointDescription",
    "ElaborationSettings",
    "ElaboratedMemberFact",
    "ElaboratedPortFact",
    "EndpointCapability",
    "EndpointCapabilityError",
    "EndpointFieldFact",
    "SourceReference",
    "TimingFact",
    "FieldHint",
    "InterfaceDescription",
    "InputLayout",
    "InputLayoutError",
    "LayoutField",
    "SourceLocator",
    "SourceCrawler",
    "SourceCrawlError",
    "SourcePortFact",
    "SourceSnapshot",
    "TimingObservation",
    "CompositionCandidate",
    "CompositionArtifact",
    "CompositionComponent",
    "ComponentRegistration",
    "ComponentRegistry",
    "ProtocolCompositionError",
    "ProtocolCompositionManifest",
    "candidate_manifest",
    "build_input_layout",
    "annotate_interfaces",
    "canonical_id",
    "compose_topk",
    "compose_protocol_composition",
    "composition_ir",
    "default_component_registry",
    "interface_description_document",
    "input_layout_document",
    "load_declarations",
    "load_interface_description",
    "match_endpoint_pair",
    "normalize_annotations",
    "load_protocol_composition",
    "normalize_facts",
    "plan_auto_composition",
    "plan_generic_composition",
    "source_tree_hash",
    "validate_protocol_composition",
    "validate_protocol_fingerprint",
    "write_protocol_composition",
    "write_generic_composition",
    "write_auto_composition_manifest",
]
