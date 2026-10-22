import hashlib
import json
from unittest.mock import Mock

import pytest

from myfuzz.integration.scenario_rfuzz_live import _fresh_runtime_source_names


def test_dma_bound_source_identity_includes_every_new_binding_helper():
    ordinary = _fresh_runtime_source_names(dma_bound=False)
    bound = _fresh_runtime_source_names(dma_bound=True)

    endpoint_links = "src/myfuzz/local_harness/dma_artifact_endpoint_links.py"
    route_intent = "src/myfuzz/scenario/dma_route_intent.py"
    assert endpoint_links not in ordinary
    assert endpoint_links in bound
    assert route_intent not in ordinary
    assert route_intent in bound


def test_fresh_replay_checks_outer_binding_identity_before_factory(tmp_path):
    from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
    from tests.integration.test_dma_intent_binding_replay import encode_fixture

    encoded, payload, _declaration, _rows = encode_fixture("fresh_run_identity")
    outer = json.loads(encoded)
    expected_identity = outer["identity_sha256"]
    outer["binding_compilations"][0]["credential"]["topology_sha256"] = "0" * 64
    (tmp_path / "run_identity.json").write_text(
        json.dumps(outer), encoding="utf-8")
    (tmp_path / "report.json").write_text(json.dumps({
        "execution_mode": "corpus",
        "run_identity_schema": "p7_dma_bound_payload.v1",
        "run_identity_inner_schema": "scenario_fresh_run_identity.v1",
        "run_identity_sha256": expected_identity,
        "run_identity_payload_sha256": hashlib.sha256(payload).hexdigest(),
    }), encoding="utf-8")
    factory = Mock(side_effect=AssertionError("factory reached"))

    with pytest.raises(ValueError, match="identity|digest"):
        replay_scenario_rfuzz_corpus(tmp_path, factory)

    factory.assert_not_called()
