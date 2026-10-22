"""The generated ZipCPU UART passively exposes its native Wishbone bus."""
from pathlib import Path

from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_driver,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_WIDTHS = {
    'cyc': 1, 'stb': 1, 'we': 1, 'adr': 2,
    'dat_w': 32, 'sel': 4, 'ack': 1,
}


def _artifact():
    request = load_local_harness_request({
        'schema_version': 'local_harness.v1',
        'profile_path': 'configs/peripherals/zipcpu_uart/component_profile.json',
        'instance_id': 'uart_trace',
        'reset_assert_ticks': 2,
        'reset_release_ticks': 2,
        'max_wait_cycles': 16,
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def test_zipcpu_uart_artifact_exposes_passive_wishbone_trace_and_keeps_pins():
    artifact = _artifact()
    document = artifact.runtime_document
    trace = document['base_protocol_trace']

    assert document['kind'] == 'wishbone_uart'
    assert trace['protocol'] == 'wishbone'
    assert trace['endpoint_id'] == 'uart.bus'
    assert trace['signal_widths'] == EXPECTED_WIDTHS
    assert set(trace['signals']) == set(EXPECTED_WIDTHS)
    assert trace['clock_domain'] == 'core'
    assert trace['max_wait_cycles'] == document['effective_max_wait_cycles'] == 16
    assert trace['sampling'] == 'pre_post'
    assert trace['sample_group'] == 'backend'

    expected_signals = {role: 'trace_' + role for role in EXPECTED_WIDTHS}
    assert trace['signals'] == expected_signals
    backend = {row['name']: row for row in document['backend_ports']}
    for role, name in expected_signals.items():
        assert backend[name] == {
            'name': name, 'direction': 'output', 'width': EXPECTED_WIDTHS[role],
            'role': role, 'channel': 'ip_protocol_trace',
        }
        assert name in artifact.cpp_text
        assert f'assign {name} =' in artifact.runtime_sv

    exports = document['physical_exports']
    pin_roles = {
        row['endpoint_id']: {item['role'] for item in exports
                             if item['endpoint_id'] == row['endpoint_id']}
        for row in exports if row['endpoint_id'] in ('uart.pins', 'uart.interrupts')
    }
    assert pin_roles == {
        'uart.pins': {'rx', 'tx', 'cts_n', 'rts_n'},
        'uart.interrupts': {'rx', 'rxfifo', 'tx', 'txfifo'},
    }
