"""Name-independent declarative composition primitives."""

from .declarations import DeclarationError, DeclarationSet, load_declarations
from .facts import HdlFacts, normalize_facts
from .ids import canonical_id

__all__ = [
    "DeclarationError",
    "DeclarationSet",
    "HdlFacts",
    "canonical_id",
    "load_declarations",
    "normalize_facts",
]
