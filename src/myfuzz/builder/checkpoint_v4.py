"""Content-addressed, two-phase campaign checkpoint storage for v4."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping

from .input_model import InputValidationError


class CampaignCheckpointStoreV4:
    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.commit_root = self.root / "checkpoint.json"
        self.objects.mkdir(parents=True, exist_ok=True)

    def commit(self, state: Mapping[str, object], objects: Mapping[str, bytes] = ()) -> str:
        if not isinstance(state, Mapping):
            raise InputValidationError("checkpoint state must be an object")
        published: dict[str, str] = {}
        for name, payload in dict(objects).items():
            if not isinstance(name, str) or not isinstance(payload, bytes):
                raise InputValidationError("checkpoint objects must be named bytes")
            digest = hashlib.sha256(payload).hexdigest()
            self._publish_object(digest, payload)
            published[name] = digest
        state_bytes = _canonical_json(dict(state))
        state_digest = hashlib.sha256(state_bytes).hexdigest()
        self._publish_object(state_digest, state_bytes)
        root = {
            "schema": "myfuzz.campaign-checkpoint-root/v4",
            "state_digest": state_digest,
            "objects": published,
        }
        self._atomic_write(self.commit_root, _canonical_json(root))
        return state_digest

    def load(self) -> tuple[dict[str, object], dict[str, bytes]]:
        try:
            root = json.loads(self.commit_root.read_text())
            if not isinstance(root, dict):
                raise ValueError("root")
            if root.get("schema") != "myfuzz.campaign-checkpoint-root/v4":
                raise ValueError("schema")
            state_digest = str(root["state_digest"])
            state_bytes = self._read_object(state_digest)
            state = json.loads(state_bytes)
            if not isinstance(state, dict):
                raise ValueError("state")
            raw_objects = root.get("objects", {})
            if not isinstance(raw_objects, dict):
                raise ValueError("objects")
            objects = {
                str(name): self._read_object(str(digest))
                for name, digest in raw_objects.items()
            }
            return state, objects
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise InputValidationError("campaign checkpoint is missing or corrupt") from exc

    def commit_controller(self, controller: object) -> str:
        from .controller_v4 import V4Controller
        if not isinstance(controller, V4Controller):
            raise InputValidationError("campaign checkpoint requires a v4 controller")
        state, objects = controller.decision_checkpoint_bundle()
        return self.commit(state, objects)

    def commit_campaign(
        self, controller: object, progress: Mapping[str, object],
    ) -> str:
        from .controller_v4 import V4Controller
        if not isinstance(controller, V4Controller):
            raise InputValidationError("campaign checkpoint requires a v4 controller")
        if not isinstance(progress, Mapping):
            raise InputValidationError("campaign checkpoint progress must be an object")
        state, objects = controller.decision_checkpoint_bundle()
        state = {**state, "campaign_progress": dict(progress)}
        return self.commit(state, objects)

    def load_controller(self, layout: object, *, limits: object = None):
        from .controller_v4 import V4Controller
        from .rawbits_v4 import RawBitsV4Layout, RawBitsV4Limits
        if not isinstance(layout, RawBitsV4Layout):
            raise InputValidationError("campaign checkpoint requires a RawBits v4 layout")
        resolved_limits = RawBitsV4Limits() if limits is None else limits
        if not isinstance(resolved_limits, RawBitsV4Limits):
            raise InputValidationError("campaign checkpoint limits are invalid")
        state, objects = self.load()
        return V4Controller.from_decision_checkpoint_bundle(
            layout, state, objects, limits=resolved_limits,
        )

    def load_campaign(self, layout: object, *, limits: object = None):
        from .controller_v4 import V4Controller
        from .rawbits_v4 import RawBitsV4Layout, RawBitsV4Limits
        if not isinstance(layout, RawBitsV4Layout):
            raise InputValidationError("campaign checkpoint requires a RawBits v4 layout")
        resolved_limits = RawBitsV4Limits() if limits is None else limits
        if not isinstance(resolved_limits, RawBitsV4Limits):
            raise InputValidationError("campaign checkpoint limits are invalid")
        state, objects = self.load()
        progress = state.get("campaign_progress")
        if not isinstance(progress, Mapping):
            raise InputValidationError("campaign checkpoint lacks campaign progress")
        controller = V4Controller.from_decision_checkpoint_bundle(
            layout, state, objects, limits=resolved_limits,
        )
        return controller, dict(progress)

    def _read_object(self, digest: str) -> bytes:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise InputValidationError("checkpoint object digest is invalid")
        path = self.objects / digest
        payload = path.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest:
            raise InputValidationError("checkpoint object digest mismatch")
        return payload

    def _publish_object(self, digest: str, payload: bytes) -> None:
        path = self.objects / digest
        if path.exists():
            self._read_object(digest)
            return
        self._atomic_write(path, payload)

    @staticmethod
    def _atomic_write(path: Path, payload: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)


def _canonical_json(value: Mapping[str, object]) -> bytes:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise InputValidationError("checkpoint state is not canonical JSON") from exc
    return (encoded + "\n").encode("utf-8")
