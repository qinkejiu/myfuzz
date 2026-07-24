"""Contract-only orchestration between composition and runtime subsystems."""

from .experiment_matrix import (
    BuildJobResult,
    ExperimentMatrixError,
    ExperimentRunner,
    FuzzJobResult,
    ResourceCheckpointEvent,
    ResourceTerminatedError,
    RunnerResult,
    run_experiment_matrix,
)
from .pipeline import GenerationRequest, RuntimeRequest, run_candidate_pipeline
from .reference_adapter import (
    GeneratorCommand,
    GeneratorFlag,
    GeneratorPathArgument,
    GeneratorPathSyntax,
    ReferenceAdapter,
    assert_reference_not_in_generator_argv,
)
from .semantic_projection import (
    assert_semantic_rename_invariant,
    semantic_projection,
)

__all__ = [
    "BuildJobResult",
    "ExperimentMatrixError",
    "ExperimentRunner",
    "FuzzJobResult",
    "GenerationRequest",
    "GeneratorCommand",
    "GeneratorFlag",
    "GeneratorPathArgument",
    "GeneratorPathSyntax",
    "ReferenceAdapter",
    "ResourceCheckpointEvent",
    "ResourceTerminatedError",
    "RunnerResult",
    "RuntimeRequest",
    "assert_semantic_rename_invariant",
    "assert_reference_not_in_generator_argv",
    "run_candidate_pipeline",
    "run_experiment_matrix",
    "semantic_projection",
]
