"""Validated, stable property map for the Ibex/PULP checker feedback bus."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from myfuzz.contracts import canonical_bytes

from .soc_composition import CompositionPlan


SCHEMA = "soc_checker_profile.v1"
REQUEST_ID = "ibex-pulp-gpio-spi"
MANIFEST_PATH = "configs/soc/checkers/ibex_pulp_gpio_spi.json"
PROPERTY_COUNT = 50
OWNERS = frozenset({"cpu0", "fabric", "gpio0", "spi0"})
BASIS_KINDS = frozenset({"standard", "independent_reference", "source_derived"})
_BINDING = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_PROPERTY_ID = re.compile(r"[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)+")


class CheckerProfileError(ValueError):
    """The checker profile cannot safely identify a feedback bit."""


@dataclass(frozen=True, slots=True)
class CheckerProperty:
    bit: int
    property_id: str
    status: str
    owner: str | None
    binding: str | None
    basis_kind: str | None
    basis: str
    reason: str | None


@dataclass(frozen=True, slots=True)
class CheckerProfile:
    schema_version: str
    request_id: str
    properties: tuple[CheckerProperty, ...]
    profile_hash: str


def _text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def load_checker_profile(document: Mapping[str, object],
                         plan: CompositionPlan) -> CheckerProfile:
    """Validate the fixed 50-bit map against one composition plan."""
    if not isinstance(document, Mapping):
        raise CheckerProfileError("checker-document-required")
    if not isinstance(plan, CompositionPlan):
        raise CheckerProfileError("composition-plan-required")
    if document.get("schema_version") != SCHEMA:
        raise CheckerProfileError("checker-schema-version")
    if document.get("request_id") != REQUEST_ID or plan.request_id != REQUEST_ID:
        raise CheckerProfileError("request-id-mismatch")
    feedback = document.get("feedback")
    if not isinstance(feedback, Mapping) or any(
            type(feedback.get(name)) is not int or feedback[name] != PROPERTY_COUNT
            for name in ("eval_width", "fail_width")):
        raise CheckerProfileError("checker-bus-width")
    entries = document.get("properties")
    if not isinstance(entries, list) or len(entries) != PROPERTY_COUNT:
        raise CheckerProfileError("property-count")
    present = {instance.instance_id for instance in plan.instances}
    if not OWNERS - {"fabric"} <= present:
        raise CheckerProfileError("checker-targets-not-composed")
    bits: set[int] = set()
    ids: set[str] = set()
    properties: list[CheckerProperty] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise CheckerProfileError("property-record-invalid")
        bit = entry.get("bit")
        if type(bit) is not int:
            raise CheckerProfileError("property-bit-invalid")
        if bit in bits:
            raise CheckerProfileError(f"property-bit-duplicate:{bit}")
        bits.add(bit)
        property_id = entry.get("property_id")
        if not isinstance(property_id, str) or not _PROPERTY_ID.fullmatch(property_id):
            raise CheckerProfileError("property-id-invalid")
        if property_id in ids:
            raise CheckerProfileError(f"property-id-duplicate:{property_id}")
        ids.add(property_id)
        status = entry.get("status")
        if status not in {"active", "not_assessed"}:
            raise CheckerProfileError("property-status-invalid")
        owner = entry.get("owner")
        if owner not in OWNERS:
            raise CheckerProfileError(f"property-owner-invalid:{owner}")
        basis_kind = entry.get("basis_kind")
        if basis_kind is not None and basis_kind not in BASIS_KINDS:
            raise CheckerProfileError(f"basis-kind-invalid:{basis_kind}")
        basis = entry.get("basis", "")
        if not isinstance(basis, str):
            raise CheckerProfileError("property-basis-invalid")
        binding = entry.get("binding")
        reason = entry.get("reason")
        if status == "active":
            if not isinstance(binding, str) or not _BINDING.fullmatch(binding):
                raise CheckerProfileError(f"active-binding-invalid:{property_id}")
            if basis_kind is None or not _text(basis):
                raise CheckerProfileError(f"active-basis-missing:{property_id}")
            if reason is not None:
                raise CheckerProfileError(f"active-reason-unexpected:{property_id}")
        else:
            if binding is not None:
                raise CheckerProfileError(f"not-assessed-binding:{property_id}")
            if not _text(reason):
                raise CheckerProfileError(f"not-assessed-reason:{property_id}")
        properties.append(CheckerProperty(bit, property_id, status, owner, binding,
                                          basis_kind, basis, reason))
    if bits != set(range(PROPERTY_COUNT)):
        raise CheckerProfileError("property-bits-not-contiguous")
    properties.sort(key=lambda item: item.bit)
    digest = "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()
    return CheckerProfile(SCHEMA, REQUEST_ID, tuple(properties), digest)


def load_default_checker_profile(plan: CompositionPlan, *,
                                 base_dir: Path | None = None) -> CheckerProfile:
    """Load the repository-owned checker map for this target composition."""
    root = Path(base_dir) if base_dir is not None else Path(__file__).resolve().parents[3]
    return load_checker_profile(
        json.loads((root / MANIFEST_PATH).read_text(encoding="utf-8")), plan)
