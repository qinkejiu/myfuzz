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
    r"(?:/(?![/*])[^\x00\s/\"']+(?:/[^\x00\s/\"']+)*|[A-Za-z]:[\\/](?=\S)|\\\\[^\\/\s]+[\\/](?=\S)|\b\d{4}-\d{2}-\d{2}[T ][0-2]\d:[0-5]\d:[0-5]\d(?:Z|[+-]\d{2}:?\d{2})?|\b(?:object|process|pointer)\s+(?:at\s+)?0x[0-9a-fA-F]+\b|\b(?:pid|process\s+id)\s*(?:[=:]\s*|\s+)\d+\b)",
    re.IGNORECASE,
)


def sanitize_metadata(value: object, *, context: str) -> object:
    """Return canonical JSON-like metadata or reject host-specific values."""
    if isinstance(value, Mapping):
        sanitized_items: list[tuple[str, object]] = []
        seen_keys: set[str] = set()
        for key, item in value.items():
            if isinstance(key, str) and _HOST_SPECIFIC_STRING.search(key):
                raise ValueError(f"{context}:host-specific")
            sanitized_key = str(key)
            if _HOST_SPECIFIC_STRING.search(sanitized_key):
                raise ValueError(f"{context}:host-specific")
            if sanitized_key in seen_keys:
                raise ValueError(f"{context}:duplicate-key")
            seen_keys.add(sanitized_key)
            sanitized_items.append((sanitized_key, sanitize_metadata(item, context=context)))
        return dict(sorted(sanitized_items))
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
    states, previous_tokens = _scan_source_context(source_text)
    for match in _SOURCE_HOST_SPECIFIC_STRING.finditer(source_text):
        if (
            match.group().startswith("/")
            and states[match.start()] == "code"
            and previous_tokens[match.start()] == "operand"
        ):
            continue
        raise ValueError(f"{context}:host-specific")
    return content_hash({"source_text": source_text})


def _scan_source_context(source_text: str) -> tuple[list[str], list[str | None]]:
    """Track lexical context and the preceding significant token kind."""
    states = ["code"] * len(source_text)
    previous_tokens: list[str | None] = [None] * len(source_text)
    state = "code"
    last_token: str | None = None
    index = 0
    while index < len(source_text):
        states[index] = state
        previous_tokens[index] = last_token
        if state == "line_comment":
            if source_text[index] in "\r\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if source_text.startswith("*/", index):
                state = "code"
                index += 2
            else:
                index += 1
            continue
        if state == "string":
            if source_text[index] == "\\":
                if index + 1 < len(source_text):
                    states[index + 1] = state
                    previous_tokens[index + 1] = last_token
                    index += 2
                else:
                    index += 1
            elif source_text[index] == '"':
                state = "code"
                index += 1
            else:
                index += 1
            continue
        if source_text.startswith("//", index):
            state = "line_comment"
            index += 1
            continue
        if source_text.startswith("/*", index):
            state = "block_comment"
            index += 1
            continue
        if source_text[index] == '"':
            state = "string"
            index += 1
            continue
        character = source_text[index]
        if character.isalnum() or character in "_$":
            last_token = "operand"
        elif character in ")]}":
            last_token = "operand"
        elif not character.isspace():
            last_token = "operator"
        index += 1
    return states, previous_tokens


__all__ = ["sanitize_metadata", "semantic_content_hash", "semantic_source_hash"]
