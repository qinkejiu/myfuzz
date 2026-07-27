"""Contract-only orchestration between composition and runtime subsystems."""

from .experiment_matrix import (
    BuildJobResult,
    ExperimentMatrixError,
    ExperimentRunner,
    FuzzJobResult,
    ResourceCheckpointEvent,
    ResourceTerminatedError,
    RunnerResult,
    matrix_promotion_pairs,
    run_experiment_matrix,
)
from .pipeline import GenerationRequest, RuntimeRequest, run_candidate_pipeline
from .rfuzz_runner import RfuzzExperimentRunner
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
    "RfuzzExperimentRunner",
    "ResourceCheckpointEvent",
    "ResourceTerminatedError",
    "RunnerResult",
    "RuntimeRequest",
    "assert_semantic_rename_invariant",
    "assert_reference_not_in_generator_argv",
    "matrix_promotion_pairs",
    "run_candidate_pipeline",
    "run_experiment_matrix",
    "semantic_projection",
]
