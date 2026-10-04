"""Strict declarative requests for one local component harness."""

from collections.abc import Mapping
from dataclasses import dataclass
import re
import hashlib
import json

from .tuning import LocalHarnessTuning, load_local_harness_tuning


_SCHEMA = "local_harness.v1"
_FIELDS = frozenset({
    "schema_version", "profile_path", "instance_id", "reset_assert_ticks",
    "reset_release_ticks", "max_wait_cycles",
})


@dataclass(frozen=True)
class LocalHarnessRequest:
    profile_path: str
    instance_id: str
    reset_assert_ticks: int
    reset_release_ticks: int
    max_wait_cycles: int

    def document(self) -> dict[str, object]:
        return {
            "schema_version": _SCHEMA,
            "profile_path": self.profile_path,
            "instance_id": self.instance_id,
            "reset_assert_ticks": self.reset_assert_ticks,
            "reset_release_ticks": self.reset_release_ticks,
            "max_wait_cycles": self.max_wait_cycles,
        }


@dataclass(frozen=True)
class LocalHarnessRequestV2:
    """Parsed configuration; existing planner deliberately rejects this type."""
    profile_path: str
    instance_id: str
    reset_assert_ticks: int
    reset_release_ticks: int
    max_wait_cycles: int
    tuning: LocalHarnessTuning

    def document(self) -> dict[str, object]:
        return {
            "schema_version": "local_harness.v2",
            "profile_path": self.profile_path, "instance_id": self.instance_id,
            "reset_assert_ticks": self.reset_assert_ticks,
            "reset_release_ticks": self.reset_release_ticks,
            "max_wait_cycles": self.max_wait_cycles,
            "tuning": self.tuning.document(),
        }

    @property
    def identity_sha256(self) -> str:
        raw = json.dumps(self.document(), sort_keys=True, separators=(',', ':')).encode()
        return hashlib.sha256(raw).hexdigest()


def load_local_harness_request(document: Mapping[str, object]) -> LocalHarnessRequest | LocalHarnessRequestV2:
    """Parse strict v1 or explicit v2 configuration without interpreting code."""
    if not isinstance(document, Mapping):
        raise ValueError("invalid-request-document")
    if document.get("schema_version") == "local_harness.v2" and "tuning" in document:
        if set(document) != _FIELDS | {"tuning"}:
            raise ValueError("unexpected-or-missing-request-fields")
        common = {key: value for key, value in document.items() if key != "tuning"}
        common["schema_version"] = _SCHEMA
        v1 = load_local_harness_request(common)
        tuning = load_local_harness_tuning(document["tuning"])
        return LocalHarnessRequestV2(v1.profile_path, v1.instance_id, v1.reset_assert_ticks,
                                     v1.reset_release_ticks, v1.max_wait_cycles, tuning)
    keys = set(document)
    if keys - _FIELDS:
        raise ValueError("unexpected-request-fields")
    if _FIELDS - keys:
        raise ValueError("missing-request-fields")
    if document["schema_version"] != _SCHEMA:
        raise ValueError("invalid-schema-version")

    profile_path = document["profile_path"]
    if not isinstance(profile_path, str):
        raise ValueError("invalid-profile-path")
    segments = profile_path.split("/")
    if (len(segments) < 2 or segments[0] != "configs"
            or (segments[-1] != "component_profile.json" and
                profile_path != "configs/peripherals/pulp_spi/local_component_profile.json")
            or any(segment in ("", ".", "..") for segment in segments)
            or "\\" in profile_path or "\x00" in profile_path):
        raise ValueError("invalid-profile-path")

    instance_id = document["instance_id"]
    if not isinstance(instance_id, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", instance_id) is None:
        raise ValueError("invalid-instance-id")

    timings = {}
    for field, minimum in (("reset_assert_ticks", 1), ("reset_release_ticks", 0), ("max_wait_cycles", 1)):
        value = document[field]
        if type(value) is not int or not minimum <= value <= 1024:
            raise ValueError("invalid-" + field.replace("_", "-"))
        timings[field] = value
    return LocalHarnessRequest(profile_path=profile_path, instance_id=instance_id, **timings)
