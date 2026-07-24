"""Stable opaque identifiers for the composition core."""

from __future__ import annotations

import hashlib


def canonical_id(kind: str, declared_id: str) -> int:
    """Return a deterministic integer for an opaque user-declared identifier.

    The inputs are length-delimited before hashing.  The function deliberately
    does not split, normalize, or otherwise inspect the identifier text.
    """
    if not isinstance(kind, str) or not kind:
        raise ValueError("kind must be a non-empty string")
    if not isinstance(declared_id, str) or not declared_id:
        raise ValueError("declared_id must be a non-empty string")
    encoded_kind = kind.encode("utf-8")
    encoded_id = declared_id.encode("utf-8")
    digest = hashlib.sha256(
        len(encoded_kind).to_bytes(4, "big")
        + encoded_kind
        + len(encoded_id).to_bytes(4, "big")
        + encoded_id
    ).digest()
    return int.from_bytes(digest[:8], "big")
