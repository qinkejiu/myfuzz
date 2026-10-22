"""Contract tests for bounded, live source issuance (no session authority)."""
import hashlib
import json

import pytest

from myfuzz.scenario.observation_stream import ObservationStreamSource


def binding():
    return dict(schema_version="observation_stream_binding.v1", session_id="s",
                observer_stream_id="stream1", source_component="source",
                artifact_digest="a" * 64, observer_contract={"protocol": "reduced_axi"})


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def source(**limits):
    return ObservationStreamSource(binding=binding(), **limits)


def operation_size():
    s = source()
    return len(encoded(s.lookup(s.issue("receipt", {}, []))))


def test_ordinals_empty_operations_and_canonical_digests():
    s = source()
    a = s.issue("begin_scope", {"z": "汉", "a": 2}, [])
    b = s.issue("receipt", {}, [{"raw": True}, {"other": 3}])
    c = s.issue("end_scope", {}, [])
    assert s.pending() == (a, b, c)
    for token, index, first, count in [(a, 1, 1, 0), (b, 2, 1, 2), (c, 3, 3, 0)]:
        op = s.lookup(token)
        assert op["schema_version"] == "observation_stream_operation.v1"
        assert (op["operation_index"], op["first_record_index"], op["record_count"]) == (index, first, count)
        assert op["binding_digest"] == hashlib.sha256(encoded(binding())).hexdigest()
        digest = op.pop("content_digest")
        assert digest == hashlib.sha256(encoded(op)).hexdigest()


def test_inputs_and_exports_are_detached():
    b = binding()
    s = ObservationStreamSource(binding=b)
    payload = {"x": [1]}
    observations = [{"a": [2]}]
    token = s.issue("receipt", payload, observations)
    b["observer_contract"]["protocol"] = "changed"
    payload["x"].append(9)
    observations[0]["a"].append(9)
    exported = s.lookup(token)
    exported["payload"]["x"].append(8)
    exported["observations"].clear()
    identity = s.identity_document()
    identity["observer_contract"].clear()
    assert s.lookup(token)["payload"] == {"x": [1]}
    assert s.lookup(token)["observations"] == [{"a": [2]}]
    assert s.identity_document() == binding()


def test_tokens_are_live_source_owned_and_ack_is_fifo():
    s, other = source(), source()
    a, b = s.issue("receipt", {}, []), s.issue("receipt", {}, [])
    assert a is not b
    for token in (object(), other.issue("receipt", {}, []), {"operation_index": 1}, 1):
        with pytest.raises(KeyError):
            s.lookup(token)
        with pytest.raises(KeyError):
            s.ack(token)
    with pytest.raises(ValueError):
        s.ack(b)
    assert s.pending() == (a, b)
    s.ack(a)
    with pytest.raises(KeyError):
        s.ack(a)
    with pytest.raises(KeyError):
        s.lookup(a)
    assert s.pending() == (b,)
    s.ack(b)
    assert s.pending() == ()


def test_seal_and_poison_are_terminal_but_pending_is_readable():
    for terminal in ("seal", "poison"):
        s = source()
        a = s.issue("receipt", {}, [])
        if terminal == "seal":
            s.issue("seal", {}, [])
        else:
            s.poison("x" * 100000)
            s.poison("second reason")
        with pytest.raises(RuntimeError):
            s.issue("receipt", {}, [])
        assert s.lookup(a)["operation_index"] == 1
        s.ack(a)


@pytest.mark.parametrize("name", ["max_operations", "max_pending_operations", "max_pending_bytes", "max_operation_bytes"])
@pytest.mark.parametrize("value", [False, True, 1.0, 0, -1, "2", None])
def test_limits_require_positive_exact_integers(name, value):
    with pytest.raises(ValueError):
        source(**{name: value})


@pytest.mark.parametrize("change", [{"session_id": ""}, {"observer_stream_id": 1},
    {"source_component": False}, {"observer_contract": "protocol"},
    {"observer_contract": {}}, {"artifact_digest": "A" * 64},
    {"artifact_digest": "a" * 63}, {"schema_version": "wrong"}, {"extra": "x"}])
def test_binding_validation(change):
    b = binding()
    b.update(change)
    with pytest.raises(ValueError):
        ObservationStreamSource(binding=b)


@pytest.mark.parametrize("kind,payload,observations", [
    ("bad", {}, []), (True, {}, []), ("receipt", [], []),
    ("receipt", {}, {}), ("receipt", {}, [1]),
    ("receipt", {1: "x"}, []), ("receipt", {"x": (1, 2)}, []),
    ("receipt", {"x": float("nan")}, []), ("receipt", {"x": float("inf")}, []),
    ("receipt", {"x": object()}, []), ("receipt", {}, [{"x": (1,)}]),
])
def test_invalid_issue_is_atomic_and_poisoning(kind, payload, observations):
    s = source()
    a = s.issue("receipt", {}, [])
    with pytest.raises(ValueError):
        s.issue(kind, payload, observations)
    assert s.pending() == (a,)
    with pytest.raises(RuntimeError):
        s.issue("receipt", {}, [])


@pytest.mark.parametrize("limit_name", ["max_operations", "max_pending_operations"])
@pytest.mark.parametrize("count", [1, 2, 3])
def test_count_boundaries(limit_name, count):
    s = source(**{limit_name: 2})
    for _ in range(min(count, 2)):
        s.issue("receipt", {}, [])
    if count == 3:
        with pytest.raises(ValueError):
            s.issue("receipt", {}, [])
    assert len(s.pending()) == min(count, 2)


@pytest.mark.parametrize("limit_name", ["max_operation_bytes", "max_pending_bytes"])
@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_full_encoded_envelope_byte_boundaries(limit_name, delta):
    # A fixed ASCII digest is part of the exact serialized operation size.
    size = operation_size()
    s = source(**{limit_name: size + delta})
    if delta == -1:
        with pytest.raises(ValueError):
            s.issue("receipt", {}, [])
        assert s.pending() == ()
    else:
        token = s.issue("receipt", {}, [])
        assert len(encoded(s.lookup(token))) == size


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_cumulative_pending_bytes_boundaries(delta):
    size = operation_size()
    s = source(max_pending_bytes=2 * size + delta)
    s.issue("receipt", {}, [])
    if delta == -1:
        with pytest.raises(ValueError):
            s.issue("receipt", {}, [])
        assert len(s.pending()) == 1
    else:
        s.issue("receipt", {}, [])
        assert len(s.pending()) == 2


def test_ack_releases_pending_budgets_but_preserves_lifetime_ordinals_and_limit():
    s = source(max_operations=2, max_pending_operations=1, max_pending_bytes=2000)
    a = s.issue("receipt", {}, [{"raw": 1}])
    s.ack(a)
    b = s.issue("receipt", {}, [{"raw": 2}])
    assert s.lookup(b)["operation_index"] == 2
    assert s.lookup(b)["first_record_index"] == 2
    s.ack(b)
    with pytest.raises(ValueError):
        s.issue("receipt", {}, [])
    assert s.pending() == ()


def test_ack_releases_exact_pending_bytes():
    size = operation_size()
    s = source(max_pending_bytes=size)
    s.ack(s.issue("receipt", {}, []))
    assert s.lookup(s.issue("receipt", {}, []))["operation_index"] == 2


def test_state_is_read_only_and_poison_takes_precedence():
    s = source()
    assert s.state == "active"
    token = s.issue("receipt", {}, [])
    assert s.state == "active"
    s.ack(token)
    assert s.state == "active"
    seal = s.issue("seal", {}, [])
    assert s.state == "sealed"
    s.ack(seal)
    assert s.state == "sealed"
    s.poison("consumer failure")
    assert s.state == "poisoned"
    with pytest.raises(AttributeError):
        s.state = "active"
    assert s.state == "poisoned"


def test_failed_issue_exposes_poisoned_state():
    s = source(max_operations=1)
    s.issue("receipt", {}, [])
    with pytest.raises(ValueError):
        s.issue("receipt", {}, [])
    assert s.state == "poisoned"
