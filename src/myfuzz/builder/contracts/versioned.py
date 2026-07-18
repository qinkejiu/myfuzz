"""Strict content-addressed contracts for the protocol-driven v2 system path."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from typing import Any, Mapping

from ..input_model import InputValidationError
from .experiment import canonical_json, content_digest


def _objects(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, (tuple, list)):
        raise InputValidationError(f"{path}: expected an array")
    result = tuple(value)
    if any(not isinstance(item, Mapping) for item in result):
        raise InputValidationError(f"{path}: every item must be an object")
    return result


def _canonical_objects(value: object, path: str) -> tuple[Mapping[str, object], ...]:
    return tuple(sorted((dict(item) for item in _objects(value, path)), key=canonical_json))


def _digest(value: object, path: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise InputValidationError(f"{path}: expected a lowercase SHA-256 digest")
    return value


def _text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputValidationError(f"{path}: expected a non-empty string")
    return value


def _provenance(value: object, path: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not value:
        raise InputValidationError(f"{path}: expected a non-empty object")
    return dict(value)


class _ContentAddressed:
    digest: str

    def payload(self) -> dict[str, object]:
        value = asdict(self)
        value.pop("digest")
        return value

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    def canonical_bytes(self) -> bytes:
        return canonical_json(self.to_dict())

    def _validate_digest(self) -> None:
        if self.digest and self.digest != content_digest(self.payload()):
            raise InputValidationError(f"{self.schema}: content digest mismatch")


@dataclass(frozen=True)
class SoCIRV2(_ContentAddressed):
    name: str
    logical_modules: tuple[Mapping[str, object], ...]
    instances: tuple[Mapping[str, object], ...]
    endpoints: tuple[Mapping[str, object], ...]
    port_bindings: tuple[Mapping[str, object], ...]
    protocol_edges: tuple[Mapping[str, object], ...]
    address_views: tuple[Mapping[str, object], ...]
    clock_domains: tuple[Mapping[str, object], ...]
    reset_domains: tuple[Mapping[str, object], ...]
    interrupt_edges: tuple[Mapping[str, object], ...]
    external_boundaries: tuple[Mapping[str, object], ...]
    service_nodes: tuple[Mapping[str, object], ...]
    adapters: tuple[Mapping[str, object], ...]
    unknown_port_decisions: tuple[Mapping[str, object], ...]
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.soc-ir/v2"

    def __post_init__(self) -> None:
        _text(self.name, "SoCIRV2.name")
        for field in (
            "logical_modules", "instances", "endpoints", "port_bindings", "protocol_edges",
            "address_views", "clock_domains", "reset_domains", "interrupt_edges",
            "external_boundaries", "service_nodes", "adapters", "unknown_port_decisions",
        ):
            object.__setattr__(self, field, _canonical_objects(getattr(self, field), f"SoCIRV2.{field}"))
        object.__setattr__(self, "provenance", dict(_provenance(self.provenance, "SoCIRV2.provenance")))
        _digest(self.digest, "SoCIRV2.digest", allow_empty=True)
        self._validate_digest()


@dataclass(frozen=True)
class RegisterModelIRV1(_ContentAddressed):
    name: str
    blocks: tuple[Mapping[str, object], ...]
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.register-model-ir/v1"

    def __post_init__(self) -> None:
        _text(self.name, "RegisterModelIRV1.name")
        object.__setattr__(self, "blocks", _canonical_objects(self.blocks, "RegisterModelIRV1.blocks"))
        object.__setattr__(self, "provenance", dict(_provenance(self.provenance, "RegisterModelIRV1.provenance")))
        _digest(self.digest, "RegisterModelIRV1.digest", allow_empty=True)
        self._validate_digest()


@dataclass(frozen=True)
class ControlPlaneIRV1(_ContentAddressed):
    soc_digest: str
    cpu_profile_digest: str
    register_model_digests: tuple[Mapping[str, object], ...]
    fields: tuple[Mapping[str, object], ...]
    operations: tuple[Mapping[str, object], ...]
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.control-plane-ir/v1"

    def __post_init__(self) -> None:
        _digest(self.soc_digest, "ControlPlaneIRV1.soc_digest")
        _digest(self.cpu_profile_digest, "ControlPlaneIRV1.cpu_profile_digest")
        for field in ("register_model_digests", "fields", "operations"):
            object.__setattr__(self, field, _canonical_objects(getattr(self, field), f"ControlPlaneIRV1.{field}"))
        object.__setattr__(self, "provenance", dict(_provenance(self.provenance, "ControlPlaneIRV1.provenance")))
        _digest(self.digest, "ControlPlaneIRV1.digest", allow_empty=True)
        self._validate_digest()


@dataclass(frozen=True)
class TemporalConstraintIRV2(_ContentAddressed):
    rawbits_layout_digest: str
    soc_digest: str
    specification_digest: str
    constraints: tuple[Mapping[str, object], ...]
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.temporal-constraint-ir/v2"

    def __post_init__(self) -> None:
        _digest(self.rawbits_layout_digest, "TemporalConstraintIRV2.rawbits_layout_digest")
        _digest(self.soc_digest, "TemporalConstraintIRV2.soc_digest")
        _digest(self.specification_digest, "TemporalConstraintIRV2.specification_digest")
        object.__setattr__(self, "constraints", _canonical_objects(self.constraints, "TemporalConstraintIRV2.constraints"))
        object.__setattr__(self, "provenance", dict(_provenance(self.provenance, "TemporalConstraintIRV2.provenance")))
        _digest(self.digest, "TemporalConstraintIRV2.digest", allow_empty=True)
        self._validate_digest()


@dataclass(frozen=True)
class ExperimentManifestV2(_ContentAddressed):
    experiment_id: str
    cpu_profile_digest: str
    soc_digest: str
    control_plane_digest: str
    constraint_digest: str
    rawbits_layout_digest: str
    rom_digest: str
    coverage_abi_digest: str
    variants: tuple[Mapping[str, object], ...]
    components: tuple[Mapping[str, object], ...]
    provenance: Mapping[str, object]
    digest: str = ""
    schema: str = "myfuzz.experiment-manifest/v2"

    def __post_init__(self) -> None:
        _text(self.experiment_id, "ExperimentManifestV2.experiment_id")
        for field in (
            "cpu_profile_digest", "soc_digest", "control_plane_digest", "constraint_digest",
            "rawbits_layout_digest", "rom_digest", "coverage_abi_digest",
        ):
            _digest(getattr(self, field), f"ExperimentManifestV2.{field}")
        object.__setattr__(self, "variants", _canonical_objects(self.variants, "ExperimentManifestV2.variants"))
        object.__setattr__(self, "components", _canonical_objects(self.components, "ExperimentManifestV2.components"))
        object.__setattr__(self, "provenance", dict(_provenance(self.provenance, "ExperimentManifestV2.provenance")))
        _digest(self.digest, "ExperimentManifestV2.digest", allow_empty=True)
        self._validate_digest()


def seal_contract(value: _ContentAddressed) -> _ContentAddressed:
    """Return an immutable contract carrying the digest of its canonical payload."""
    if value.digest:
        value._validate_digest()
        return value
    return replace(value, digest=content_digest(value.payload()))
