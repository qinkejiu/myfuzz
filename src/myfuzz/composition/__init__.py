"""Name-independent declarative composition primitives."""

from .declarations import DeclarationError, DeclarationSet, load_declarations
from .facts import HdlFacts, normalize_facts
from .ids import canonical_id
from .ir import composition_ir
from .manifest import candidate_manifest
from .search import CompositionCandidate, compose_topk

__all__ = [
    "DeclarationError",
    "DeclarationSet",
    "HdlFacts",
    "CompositionCandidate",
    "candidate_manifest",
    "canonical_id",
    "compose_topk",
    "composition_ir",
    "load_declarations",
    "normalize_facts",
]
