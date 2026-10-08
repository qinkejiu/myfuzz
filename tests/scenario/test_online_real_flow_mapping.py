"""Real online profiles explicitly classify their declared runtime targets."""

import json

from myfuzz.scenario.online_case_decoder import OnlineCaseDecoder
from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_online_decoder,
)
from myfuzz.scenario.ibex_uart_online import (
    make_ibex_uart_online_bootstrap, make_ibex_uart_online_decoder,
)


def profiles():
    yield (make_ibex_pulp_dual_source_online_decoder,
           {'cpu_to_ip_to_cpu.closed_loop': 'F4',
            'ip_to_cpu_to_ip.closed_loop': 'F5'})
    yield (lambda: make_ibex_uart_online_decoder(
        bootstrap=make_ibex_uart_online_bootstrap()),
           {'cpu_to_uart_tx': 'F4', 'uart_rx_to_cpu': 'F5'})


def test_real_profile_manifest_declares_exact_flow_targets():
    for factory, expected in profiles():
        decoder = factory()
        document = decoder.document()
        assert document['schema_version'] == 'online_case_decoder.v3'
        assert document['flow_by_target'] == expected
        assert set(document['flow_by_target']) == {
            row['target'] for row in document['path_mapping']}


def test_real_profile_flow_and_path_identity_repeat_across_factory_builds():
    for factory, expected in profiles():
        first, second = factory(), factory()
        assert json.dumps(first.document(), sort_keys=True) == json.dumps(
            second.document(), sort_keys=True)
        for path_byte in (0, 1):
            raw = bytes((0, path_byte, 255, 7, 0, 0, 0, 0))
            case, replayed = first.decode(raw), second.decode(raw)
            assert case.path_id == replayed.path_id
            assert first.decision_metadata(case) == second.decision_metadata(replayed)
            metadata = first.decision_metadata(case)
            assert metadata['flow_id'] == expected[metadata['target_id']]
            assert metadata['path_id'] in {
                row['path_id'] for row in first.document()['path_mapping']}


def test_pulp_v3_manifest_reconstructs_same_decoded_decisions():
    trusted = make_ibex_pulp_dual_source_online_decoder()
    saved = json.loads(json.dumps(trusted.document()))
    restored = OnlineCaseDecoder.from_document(saved)
    assert json.loads(json.dumps(restored.document())) == saved
    assert restored.from_document_replay_only
    for path_byte in (0, 1):
        raw = bytes((0, path_byte, 255, 7, 0, 0, 0, 0))
        case, replayed = trusted.decode(raw), restored.decode(raw)
        assert case == replayed
        assert trusted.decision_metadata(case) == restored.decision_metadata(replayed)
