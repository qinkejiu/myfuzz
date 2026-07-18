"""Versioned contracts for the protocol-driven builder."""

from .conflicts import ConflictDecision, ConflictOutcome, PortFacts, resolve_port_conflict
from .ir import (
    CONTRACT_SCHEMAS,
    ConstraintIR,
    CoverageABI,
    ProtocolBackend,
    SystemIR,
    validate_contract,
)
from .legacy_adapter import adapt_legacy_plan
from .experiment import (
    AccessRecord, CpuExecutionProfile, CoverageABIV2, ExperimentManifest, ExperimentResult,
    ExperimentVariant, RecordTerminalAck, RomInstallBackend, RomInstallKind, TerminalStatus,
    VariantName, build_experiment_manifest, canonical_json, content_digest, sorted_objects,
    coverage_abi_v2_from_dict,
)
from .rfuzz_dependency import (
    RFuzzDependencyManifest, TransactionServerContract, verify_rfuzz_dependency,
)
from .manifest import (
    ElaborationLimits,
    ElaborationManifest,
    ManifestError,
    ResolvedFile,
    build_elaboration_manifest,
    derive_elaboration_manifest,
    derive_rewritten_elaboration_manifest,
)
from .versioned import (
    ControlPlaneIRV1, ExperimentManifestV2, RegisterModelIRV1, SoCIRV2,
    TemporalConstraintIRV2, seal_contract,
)

__all__ = [
    "CONTRACT_SCHEMAS", "ConflictDecision", "ConflictOutcome", "ConstraintIR",
    "CoverageABI", "ElaborationLimits", "ElaborationManifest", "ManifestError",
    "PortFacts", "ProtocolBackend", "ResolvedFile", "SystemIR", "adapt_legacy_plan",
    "build_elaboration_manifest", "derive_elaboration_manifest",
    "derive_rewritten_elaboration_manifest", "resolve_port_conflict",
    "validate_contract", "AccessRecord", "CpuExecutionProfile", "CoverageABIV2",
    "ExperimentManifest", "ExperimentResult", "ExperimentVariant", "RecordTerminalAck",
    "RomInstallBackend", "RomInstallKind", "TerminalStatus", "VariantName",
    "build_experiment_manifest", "canonical_json", "content_digest", "sorted_objects",
    "coverage_abi_v2_from_dict",
    "RFuzzDependencyManifest", "TransactionServerContract", "verify_rfuzz_dependency",
    "ControlPlaneIRV1", "ExperimentManifestV2", "RegisterModelIRV1", "SoCIRV2",
    "TemporalConstraintIRV2", "seal_contract",
]
