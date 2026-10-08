"""Immutable explicit source admissions; no graph or runtime source inference."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from .genome import DIRECTIONS


_ADMISSION_SCHEMA = "source_admission.v1"
_REGISTRY_SCHEMA = "source_admission_registry.v1"
_MATERIAL_FIELDS = frozenset(("case_id", "case_index", "source_id", "path_id",
                              "direction", "component", "action_id", "role",
                              "input_kind", "input_sha256"))
_DOCUMENT_FIELDS = _MATERIAL_FIELDS | {"schema_version", "admission_id"}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _nonempty_string(value: object, name: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")


def _validate_material(material: dict) -> None:
    for name in _MATERIAL_FIELDS - {"case_index"}:
        _nonempty_string(material[name], name)
    index = material["case_index"]
    if type(index) is not int or index < 0:
        raise ValueError("case_index must be a nonnegative integer")
    if material["direction"] not in DIRECTIONS:
        raise ValueError("unsupported admission direction")
    if material["role"] not in {"fuzz_source", "fixed_support", "bootstrap"}:
        raise ValueError("unsupported admission role")
    if material["input_kind"] not in {"instruction", "source_event"}:
        raise ValueError("unsupported admission input_kind")
    if _DIGEST.fullmatch(material["input_sha256"]) is None:
        raise ValueError("input_sha256 must be a lowercase SHA-256 digest")


def _admission_digest(material: dict) -> str:
    raw = json.dumps({"schema_version": _ADMISSION_SCHEMA, **material},
                     sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                     allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True, slots=True)
class SourceAdmission:
    """Validated immutable identity of bytes admitted for one declared action.

    ``admission_id`` hashes canonical UTF-8 JSON of the versioned document with
    the admission_id field omitted. Bytes and their source are supplied by the
    caller; this record never reads or reconstructs them.
    """

    admission_id: str
    case_id: str
    case_index: int
    source_id: str
    path_id: str
    direction: str
    component: str
    action_id: str
    role: str
    input_kind: str
    input_sha256: str

    def __post_init__(self) -> None:
        material = {name: getattr(self, name) for name in _MATERIAL_FIELDS}
        _validate_material(material)
        _nonempty_string(self.admission_id, "admission_id")
        if self.admission_id != _admission_digest(material):
            raise ValueError("admission_id does not match canonical admission material")

    @classmethod
    def create(cls, *, case_id: str, case_index: int, source_id: str,
               path_id: str, direction: str, component: str, action_id: str,
               role: str, input_kind: str, input_sha256: str) -> SourceAdmission:
        material = dict(case_id=case_id, case_index=case_index, source_id=source_id,
                        path_id=path_id, direction=direction, component=component,
                        action_id=action_id, role=role, input_kind=input_kind,
                        input_sha256=input_sha256)
        _validate_material(material)
        return cls(admission_id=_admission_digest(material), **material)

    def document(self) -> dict:
        return {"schema_version": _ADMISSION_SCHEMA, **asdict(self)}

    @classmethod
    def from_document(cls, document: object) -> SourceAdmission:
        if type(document) is not dict or set(document) != _DOCUMENT_FIELDS:
            raise ValueError("source admission has unknown or missing fields")
        if document["schema_version"] != _ADMISSION_SCHEMA:
            raise ValueError("unsupported source admission schema_version")
        return cls(**{name: value for name, value in document.items()
                      if name != "schema_version"})


class AdmissionRegistry:
    """Admissions keyed by action, preserving first-registration order."""

    def __init__(self) -> None:
        self._by_action: dict[str, SourceAdmission] = {}

    def register(self, admission: SourceAdmission) -> SourceAdmission:
        if type(admission) is not SourceAdmission:
            raise ValueError("registry requires a SourceAdmission")
        admission.__post_init__()
        previous = self._by_action.get(admission.action_id)
        if previous is not None:
            if previous != admission:
                raise ValueError(f"conflicting admission for action_id {admission.action_id}")
            return previous
        self._by_action[admission.action_id] = admission
        return admission

    def get(self, action_id: str) -> SourceAdmission | None:
        _nonempty_string(action_id, "action_id")
        return self._by_action.get(action_id)

    def resolve(self, action_ids: Iterable[str]) -> tuple[SourceAdmission, ...]:
        """Resolve explicit IDs, deduplicated and ordered by admission identity.

        Unknown actions fail closed. Neither a lookup nor failed resolution
        changes registry state.
        """
        if isinstance(action_ids, (str, bytes)):
            raise ValueError("action_ids must be an iterable of action IDs")
        try:
            iterator = iter(action_ids)
        except TypeError as exc:
            raise ValueError("action_ids must be an iterable of action IDs") from exc
        records = {}
        for action_id in iterator:
            admission = self.get(action_id)
            if admission is None:
                raise ValueError(f"unknown admission action_id {action_id}")
            records[admission.admission_id] = admission
        return tuple(records[identity] for identity in sorted(records))

    def document(self) -> dict:
        return {"schema_version": _REGISTRY_SCHEMA,
                "admissions": [record.document() for record in self._by_action.values()]}

    @classmethod
    def from_document(cls, document: object) -> AdmissionRegistry:
        if type(document) is not dict or set(document) != {"schema_version", "admissions"}:
            raise ValueError("source admission registry has unknown or missing fields")
        if document["schema_version"] != _REGISTRY_SCHEMA:
            raise ValueError("unsupported source admission registry schema_version")
        if type(document["admissions"]) is not list:
            raise ValueError("registry admissions must be a list")
        registry = cls()
        for row in document["admissions"]:
            record = SourceAdmission.from_document(row)
            if record.action_id in registry._by_action:
                raise ValueError("duplicate action_id in source admission registry")
            registry.register(record)
        return registry


__all__ = ["SourceAdmission", "AdmissionRegistry"]
