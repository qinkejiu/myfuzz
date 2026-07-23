"""Validation for deterministic, portable emitted JSON metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping

from myfuzz.contracts import content_hash


_HOST_SPECIFIC_STRING = re.compile(
    r"(?:/(?!(?:/))[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?|[A-Za-z]:[\\/](?=\S)|\\\\[^\\/\s]+[\\/](?=\S)|\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:Z|[+-]\d{2}:?\d{2})?|\b(?:object|process|pointer)\s+(?:at\s+)?0x[0-9a-fA-F]+\b|\b(?:pid|process\s+id)\s*(?:[=:]\s*|\s+)\d+\b)",
    re.IGNORECASE,
)


def sanitize_metadata(value: object, *, context: str) -> object:
    """Return canonical JSON-like metadata or reject host-specific values."""
    if isinstance(value, Mapping):
        sanitized: dict[str, object] = {}
        for key, item in sorted(value.items(), key=lambda pair: str(pair[0])):
            if isinstance(key, str) and _HOST_SPECIFIC_STRING.search(key):
                raise ValueError(f"{context}:host-specific")
            sanitized_key = str(key)
            if _HOST_SPECIFIC_STRING.search(sanitized_key):
                raise ValueError(f"{context}:host-specific")
            sanitized[sanitized_key] = sanitize_metadata(item, context=context)
        return sanitized
    if isinstance(value, tuple):
        return [sanitize_metadata(item, context=context) for item in value]
    if isinstance(value, list):
        return [sanitize_metadata(item, context=context) for item in value]
    if isinstance(value, str) and _HOST_SPECIFIC_STRING.search(value):
        raise ValueError(f"{context}:host-specific")
    return value


def semantic_content_hash(value: object, *, context: str) -> str:
    """Hash canonical composition data only after portable-metadata validation."""
    return content_hash(sanitize_metadata(value, context=context))


__all__ = ["sanitize_metadata", "semantic_content_hash"]
