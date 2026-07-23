"""Validation for deterministic, portable emitted JSON metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping

from myfuzz.contracts import content_hash


_HOST_SPECIFIC_STRING = re.compile(
    r"(?:/(?!(?:/))[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?|[A-Za-z]:[\\/](?=\S)|\\\\[^\\/\s]+[\\/](?=\S)|\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:Z|[+-]\d{2}:?\d{2})?|\b(?:object|process|pointer)\s+(?:at\s+)?0x[0-9a-fA-F]+\b|\b(?:pid|process\s+id)\s*(?:[=:]\s*|\s+)\d+\b)",
    re.IGNORECASE,
)

_SOURCE_HOST_SPECIFIC_STRING = re.compile(
    r"(?:/(?!/)[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*/?|[A-Za-z]:[\\/](?=\S)|\\\\[^\\/\s]+[\\/](?=\S)|\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:Z|[+-]\d{2}:?\d{2})?|\b(?:object|process|pointer)\s+(?:at\s+)?0x[0-9a-fA-F]+\b|\b(?:pid|process\s+id)\s*(?:[=:]\s*|\s+)\d+\b)",
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


def semantic_source_hash(source_text: str, *, context: str) -> str:
    """Hash Verilog source after source-aware host-specific validation."""
    for match in _SOURCE_HOST_SPECIFIC_STRING.finditer(source_text):
        if match.group().startswith("/") and _is_systemverilog_division(source_text, match.start()):
            continue
        raise ValueError(f"{context}:host-specific")
    return content_hash({"source_text": source_text})


def _is_systemverilog_division(source_text: str, slash_index: int) -> bool:
    """Recognize a slash following an expression operand, not a path prefix."""
    if slash_index == 0:
        return False
    previous = source_text[slash_index - 1]
    if previous.isalnum() or previous in ")]}":
        return True
    if not previous.isspace():
        return False
    before_slash = source_text[:slash_index].rstrip()
    return bool(before_slash) and (before_slash[-1].isalnum() or before_slash[-1] in ")]}")


__all__ = ["sanitize_metadata", "semantic_content_hash", "semantic_source_hash"]
