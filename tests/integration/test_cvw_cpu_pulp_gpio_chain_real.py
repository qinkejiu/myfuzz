"""Real CVW aligned LSU accesses reach real PULP GPIO, with no D-cache.

Static initial image and bounded directed execution only; no online/campaign or
retirement claim. Run explicitly with MYFUZZ_SCENARIO_REAL=1.
"""
import copy
from dataclasses import asdict
import json
import os
from pathlib import Path

import pytest

from myfuzz.scenario.cvw_gpio_example import BOOT_BASE, RESULT, make_cvw_gpio_chain

pytestmark = pytest.mark.skipif(os.environ.get('MYFUZZ_SCENARIO_REAL') != '1',
                               reason='set MYFUZZ_SCENARIO_REAL=1 for real CVW/PULP RTL')
BASE = 0xCFFF0000
EXPECTED = [(0, True, 0xFFFFFFFF), (4, True, 0xFFFFFFFF),
            (12, True, 0x35), (12, False, 0x35),
            (12, True, 0x6A), (12, False, 0x6A)]


def _physical(artifact, state):
    values = {}
    for row in artifact.runtime_document['physical_exports']:
        raw = state['physical'][row['runtime_name']]
        value = int(raw, 16) if isinstance(raw, str) else raw
        values[row['physical_port']] = values.get(row['physical_port'], 0) | value << row['bit_lo']
    return values


def _run(cache, *, base=BASE, limit=6000):
    cpu, gpio, router, memory = make_cvw_gpio_chain(cache_dir=cache, gpio_base=base)
    cpu.prepare_local()
    gpio.prepare_local()
    records, apb, gpio_samples, outputs = [], [], [], []
    try:
        gpio.begin_case('cvw-gpio-directed')
        cpu.begin_case('cvw-gpio-directed')
        executions = (cpu._execution, gpio._execution)
        for _ in range(limit):
            output = cpu.step_local({})
            sample, = cpu.last_samples
            records.append(copy.deepcopy(sample))
            if output['data_req_accepted']:
                outputs.append({k: output[k] for k in (
                    'data_addr', 'data_write', 'data_wdata', 'data_be')})
            if output['data_rsp_consumed']:
                outputs.append({k: output[k] for k in (
                    'data_rsp_rdata', 'data_rsp_source_sequence')})
            samples = gpio.drain_tick_samples()
            gpio_samples.extend(samples)
            trace = gpio.artifact.runtime_document['base_protocol_trace']
            for row in samples:
                signals = {role: row['pre']['backend'][name]
                           for role, name in trace['signals'].items()}
                if signals['psel'] and signals['penable'] and signals['pready']:
                    assert signals['pslverr'] == 0
                    apb.append((signals['paddr'], bool(signals['pwrite']),
                                signals['pwdata'] if signals['pwrite'] else signals['prdata']))
            writes = [event for event in cpu.service.events
                      if event.get('kind') == 'memory_write' and event['address'] == RESULT+8]
            if writes:
                break
        final = gpio.step_local({})
        physical_requests = []
        for sample in records:
            pre = sample['pre']['backend']
            if pre['m_req_valid'] and pre['m_req_ready']:
                phys = _physical(cpu.artifact, sample['pre'])
                physical_requests.append({'source_sequence': len(physical_requests)+1, 'address': pre['m_req_addr'],
                    'write': pre['m_req_write'], 'value': pre['m_req_wdata'],
                    'be': pre['m_req_be'], 'physical': phys})
        result = [memory.read(RESULT+n, 4, transaction_id=f'check-{n}').value
                  for n in (0, 4, 8)]
        return {'result': result, 'requests': physical_requests, 'cpu_samples': records,
            'cpu_outputs': outputs, 'gpio_samples': gpio_samples, 'apb': apb,
            'deliveries': [{**row, 'source_transaction': asdict(row['source_transaction'])}
                           for row in router.deliveries],
            'ram_events': copy.deepcopy(cpu.service.events),
            'final': final, 'executions': executions,
            'cpu_identity': cpu.identity_document(), 'gpio_identity': gpio.identity_document(),
            'memory_identity': memory.identity_document(),
            'gpio_output_runtime_names': [row['runtime_name'] for row in gpio.artifact.runtime_document['physical_exports'] if row['physical_port'] == 'gpio_out'],
            'artifact_hashes': (cpu.artifact.runtime_document['artifact_digest'], gpio.artifact.runtime_document['artifact_digest'])}
    finally:
        cpu.end_case()
        gpio.end_case()


def _assert_chain(run):
    assert run['result'] == [0x35, 0x6A, 1], 'CPU readbacks/branch-dependent RAM success absent'
    assert [(r['offset'], r['write'], r['write_value'] if r['write'] else r['read_value'])
            for r in run['deliveries']] == EXPECTED
    assert run['apb'] == EXPECTED, 'exactly one real APB effect per intended access; no adjacent spill'
    assert all(r['byte_enable'] == 15 and r['beat_bytes'] == 4 for r in run['deliveries'])
    keys = [tuple(r['source_transaction'].values()) for r in run['deliveries']]
    assert len(keys) == len(set(keys)) == 6
    mmio = [r for r in run['requests'] if BASE <= r['address'] < BASE+0x1000]
    assert [(r['address']-BASE, bool(r['write']), r['value'] if r['write'] else None)
            for r in mmio] == [(a, w, v if w else None) for a, w, v in EXPECTED]
    assert [r['source_sequence'] for r in mmio] == [
        d['source_transaction']['source_sequence'] for d in run['deliveries']]
    for delivery in run['deliveries']:
        if not delivery['write']:
            responses = [r for r in run['cpu_outputs'] if
                r.get('data_rsp_source_sequence') == delivery['source_transaction']['source_sequence']]
            assert len(responses) == 1
            assert responses[0]['data_rsp_rdata'] == delivery['read_value']
    for request in mmio:
        physical = request['physical']
        assert physical['HSELEXT'] == 1
        assert physical['HPROT'] & 1 == 1, 'MMIO must be LSU data, never I-cache fetch'
        assert physical['HADDR'] == request['address']
        assert physical['HWRITE'] == request['write']
        assert request['be'] == 15
        if request['write']:
            assert physical['HWDATA'] == request['value']
            assert physical['HWSTRB'] == 15
    assert run['requests'][0]['address'] == BOOT_BASE
    assert run['final']['gpio_dir'] == 0xFFFFFFFF
    assert run['final']['gpio_out'] == 0x6A
    # Both outputs must appear in real sampled device pins, not only router rows.
    # The functional member exports the GPIO pins in each APB command sample.
    samples = run['gpio_samples']
    assert samples
    assert run['gpio_output_runtime_names']
    for value in (0x35, 0x6A):
        assert any(value == sample['post']['physical'].get(name)
                   for sample in samples for name in run['gpio_output_runtime_names'])


def test_real_cpu_gpio_readback_branch_and_fresh_isolated_replay(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_CVW_GPIO_CACHE', str(tmp_path/'cache')))
    first = _run(cache)
    second = _run(cache)
    evidence = Path(os.environ.get('MYFUZZ_CVW_GPIO_EVIDENCE', str(tmp_path/'evidence')))
    evidence.mkdir(parents=True, exist_ok=True)
    for name, run in (('first', first), ('fresh', second)):
        (evidence/f'{name}.json').write_text(json.dumps(run, sort_keys=True, indent=2)+'\n')
    _assert_chain(first)
    _assert_chain(second)
    assert first['executions'] != second['executions']
    for key in ('cpu_samples', 'cpu_outputs', 'gpio_samples', 'requests', 'apb',
                'deliveries', 'ram_events', 'result', 'final', 'artifact_hashes',
                'cpu_identity', 'gpio_identity', 'memory_identity'):
        assert first[key] == second[key], f'fresh isolated directed replay differs: {key}'


def test_old_zero_window_cannot_reach_external_gpio(tmp_path):
    old = _run(Path(os.environ.get('MYFUZZ_CVW_GPIO_CACHE', str(tmp_path/'cache'))),
               base=0, limit=2000)
    assert old['deliveries'] == []
    assert old['apb'] == []
    assert old['result'][2] == 0
    assert old['final']['gpio_out'] == 0
    assert not any(r['address'] < 0x1000 for r in old['requests'])
