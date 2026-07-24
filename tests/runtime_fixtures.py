from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_FIXTURES = ROOT / "tests" / "fixtures" / "runtime"


def load_runtime_documents() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    names = (
        "hdl_facts.v2.runtime.json",
        "composition_ir.v1.runtime.json",
        "candidate_manifest.v1.runtime.json",
    )
    documents = tuple(
        json.loads((RUNTIME_FIXTURES / name).read_text(encoding="utf-8"))
        for name in names
    )
    assert all(isinstance(document, dict) for document in documents)
    return documents  # type: ignore[return-value]
