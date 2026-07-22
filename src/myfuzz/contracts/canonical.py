from __future__ import annotations

import hashlib
import json


def canonical_bytes(document: object) -> bytes:
    """Return deterministic UTF-8 JSON without host-specific data."""
    return (json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def content_hash(document: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()
