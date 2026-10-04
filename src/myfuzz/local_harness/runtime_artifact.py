"""The frozen identity container consumed by later local runtime stages."""
from __future__ import annotations
from dataclasses import dataclass
from .plan import LocalHarnessPlan
from .renderer import RenderedLocalHarness


@dataclass(frozen=True, slots=True)
class LocalRuntimeArtifact:
    plan: LocalHarnessPlan
    structural: RenderedLocalHarness
    source_verification: dict[str, object]
    runtime_sv: str
    cpp_text: str
    runtime_document: dict[str, object]
