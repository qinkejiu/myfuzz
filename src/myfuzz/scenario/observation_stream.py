"""Bounded observation issuance; tokens establish live ownership, not authority.

Binding digests hash the canonical binding document. Content digests hash the
canonical envelope with only ``content_digest`` omitted. Both byte budgets count
UTF-8 encoded canonical envelopes *including* the content digest. Since canonical
JSON escapes non-ASCII text, these bytes are also ASCII.
"""
from __future__ import annotations

from collections import deque
from copy import deepcopy
import hashlib
import json
import math
import re


_BINDING_KEYS = frozenset({
    "schema_version", "session_id", "observer_stream_id", "source_component",
    "artifact_digest", "observer_contract",
})
_KINDS = frozenset({"begin_scope", "end_scope", "receipt", "seal"})


def _validate_json(value: object) -> None:
    """Reject coercions accepted by json.dumps, including tuples and int keys."""
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float:
        if math.isfinite(value):
            return
    elif type(value) is list:
        for item in value:
            _validate_json(item)
        return
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("JSON dictionary keys must be strings")
            _validate_json(item)
        return
    raise ValueError("value must be strict finite JSON")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


class ObservationStreamSource:
    """Issue immutable copies under bounded, lifetime-scoped bookkeeping.

    Invalid issue requests poison the source before raising ValueError; a later
    issue raises RuntimeError. Lookup/ACK mistakes reject without modifying the
    queue. Pending evidence remains readable and ACKable after seal or poison.
    No reset, serialization, or identity export creates a live issuance token.
    """

    def __init__(self, *, binding: dict, max_operations: int = 100000,
                 max_pending_operations: int = 1024,
                 max_pending_bytes: int = 8388608,
                 max_operation_bytes: int = 1048576):
        for limit in (max_operations, max_pending_operations,
                      max_pending_bytes, max_operation_bytes):
            if type(limit) is not int or limit <= 0:
                raise ValueError("issuance limits must be positive integers")
        try:
            _validate_json(binding)
            if type(binding) is not dict or binding.keys() != _BINDING_KEYS:
                raise ValueError("binding must contain exactly the v1 fields")
            if binding["schema_version"] != "observation_stream_binding.v1":
                raise ValueError("unsupported binding schema")
            for key in ("session_id", "observer_stream_id", "source_component"):
                if type(binding[key]) is not str or not binding[key]:
                    raise ValueError("binding identities must be nonempty strings")
            digest = binding["artifact_digest"]
            if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError("artifact digest must be lowercase SHA-256")
            if type(binding["observer_contract"]) is not dict or not binding["observer_contract"]:
                raise ValueError("observer contract must be a nonempty JSON dictionary")
            self._binding = deepcopy(binding)
            self._binding_digest = hashlib.sha256(_canonical(self._binding)).hexdigest()
        except (RecursionError, OverflowError) as error:
            raise ValueError("binding must be finite JSON") from error
        self._max_operations = max_operations
        self._max_pending_operations = max_pending_operations
        self._max_pending_bytes = max_pending_bytes
        self._max_operation_bytes = max_operation_bytes
        self._operations = 0
        self._next_record = 1
        self._pending_bytes = 0
        self._queue: deque[object] = deque()
        self._issued: dict[int, tuple[object, dict, int]] = {}
        self._sealed = False
        self._poison_reason: str | None = None

    def issue(self, kind: str, payload: dict, observations: list[dict]) -> object:
        if self._sealed or self._poison_reason is not None:
            raise RuntimeError("observation stream is sealed or poisoned")
        try:
            if type(kind) is not str or kind not in _KINDS:
                raise ValueError("unsupported operation kind")
            if type(payload) is not dict or type(observations) is not list:
                raise ValueError("payload/observations must be dictionary/list")
            if any(type(record) is not dict for record in observations):
                raise ValueError("each observation must be a dictionary")
            _validate_json(payload)
            _validate_json(observations)
            if self._operations >= self._max_operations:
                raise ValueError("lifetime operation limit exceeded")
            if len(self._queue) >= self._max_pending_operations:
                raise ValueError("pending operation limit exceeded")
            envelope = {
                "schema_version": "observation_stream_operation.v1",
                "binding_digest": self._binding_digest,
                "operation_index": self._operations + 1,
                "kind": kind,
                "payload": deepcopy(payload),
                "observations": deepcopy(observations),
                "first_record_index": self._next_record,
                "record_count": len(observations),
            }
            envelope["content_digest"] = hashlib.sha256(_canonical(envelope)).hexdigest()
            size = len(_canonical(envelope))
            if size > self._max_operation_bytes:
                raise ValueError("individual operation byte limit exceeded")
            if self._pending_bytes + size > self._max_pending_bytes:
                raise ValueError("pending operation byte limit exceeded")
        except (ValueError, RecursionError, OverflowError) as error:
            self.poison("issue failed")
            raise ValueError(str(error)) from error
        token = object()
        self._issued[id(token)] = (token, envelope, size)
        self._queue.append(token)
        self._operations += 1
        self._next_record += len(observations)
        self._pending_bytes += size
        if kind == "seal":
            self._sealed = True
        return token

    @property
    def state(self) -> str:
        """Terminal state for consumer admission checks; poison outranks seal."""
        if self._poison_reason is not None:
            return "poisoned"
        return "sealed" if self._sealed else "active"

    def pending(self) -> tuple[object, ...]:
        return tuple(self._queue)

    def _entry(self, token: object) -> tuple[object, dict, int]:
        entry = self._issued.get(id(token))
        if entry is None or entry[0] is not token:
            raise KeyError("unknown, foreign, or acknowledged operation token")
        return entry

    def lookup(self, token: object) -> dict:
        return deepcopy(self._entry(token)[1])

    def ack(self, token: object) -> None:
        entry = self._entry(token)
        if self._queue[0] is not token:
            raise ValueError("operation acknowledgement must be FIFO")
        self._queue.popleft()
        del self._issued[id(token)]
        self._pending_bytes -= entry[2]

    def poison(self, reason: str) -> None:
        if type(reason) is not str:
            raise ValueError("poison reason must be a string")
        if self._poison_reason is None:
            self._poison_reason = reason[:512]

    def identity_document(self) -> dict:
        return deepcopy(self._binding)
