"""Contract-only orchestration between composition and runtime subsystems."""

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
    "GenerationRequest",
    "GeneratorCommand",
    "GeneratorFlag",
    "GeneratorPathArgument",
    "GeneratorPathSyntax",
    "ReferenceAdapter",
    "RuntimeRequest",
    "assert_semantic_rename_invariant",
    "assert_reference_not_in_generator_argv",
    "run_candidate_pipeline",
    "semantic_projection",
]
