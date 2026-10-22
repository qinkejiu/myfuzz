"""Real Ibex-configured wbdmac → PULP PADOUT → Ibex ISR with fresh replay."""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path

import pytest

from myfuzz.scenario.ibex_dma_example import DMA_BASE, ISR, RESULT, SOURCE
from myfuzz.scenario.ibex_dma_pulp_gpio_runner import (
    TESTCASE_ID, make_ibex_dma_pulp_gpio_runner,
)
from myfuzz.scenario.ibex_dma_pulp_gpio_example import PADOUT_ADDRESS
from myfuzz.scenario.pulp_gpio_dma_paths import GPIO_PADOUT_OFFSET
from myfuzz.scenario.replay_normalize import (
    first_gpio_dma_replay_difference,
    normalize_gpio_dma_execution_identities,
)

MAX_ROUNDS = 2000
ROUND = ('dma', 'cpu', 'gpio')
SOURCE_VALUE = 0x5AA55AA5


def _plain(value):
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, dict):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _save_json(root, name, value):
    root.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(_plain(value), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')
    (root / (name + '.json.gz')).write_bytes(gzip.compress(payload, mtime=0))


def _settings(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_IBEX_PULP_DMA_CACHE',
        tmp_path / 'cache'))
    evidence = Path(os.environ.get('MYFUZZ_IBEX_PULP_DMA_EVIDENCE',
        tmp_path / 'evidence'))
    cache.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    return cache, evidence


def _execution_ids(runner):
    result = {name: session._execution for name, session in runner.sessions.items()}
    result['runner'] = runner.execution_id
    return result


def _run_case(cache_dir, *, destination=PADOUT_ADDRESS, source_value=SOURCE_VALUE,
        negative=False, schedule_prefix=None):
    runner, paths = make_ibex_dma_pulp_gpio_runner(cache_dir=cache_dir,
        source_value=source_value, destination_address=destination)
    cpu, dma, gpio = (runner.sessions[name] for name in ('cpu', 'dma', 'gpio'))
    provider_calls = []
    native_pre_samples = []
    original_provider = gpio.dma_master_target_access
    original_command = dma.command

    def counted_provider(*args, **kwargs):
        provider_calls.append(True)
        return original_provider(*args, **kwargs)

    def capture_pre(op, fields):
        receipt = original_command(op, fields)
        if op == 'STEP_WB_DMA':
            native_pre_samples.append(_plain(receipt.payload['pre_backend']))
        return receipt

    gpio.dma_master_target_access = counted_provider
    if negative:
        dma.command = capture_pre

    schedule = []
    failure = None
    process_handles = {}
    evidence = {}
    try:
        runner.begin_test(TESTCASE_ID)
        process_handles = {name: session.process
            for name, session in runner.sessions.items()}
        if schedule_prefix is not None:
            # Fresh replay consumes the reference's exact recorded component
            # schedule, including every step after the success marker.
            component_schedule = tuple(schedule_prefix)
            if (not component_schedule or len(component_schedule) > 3 * MAX_ROUNDS
                    or any(component not in runner.sessions
                           for component in component_schedule)):
                raise ValueError('invalid recorded replay schedule')
            for component in component_schedule:
                schedule.append(component)
                try:
                    runner.step(component)
                except Exception as error:
                    failure = {'type': type(error).__name__, 'message': str(error)}
                    break
        else:
            for _ in range(MAX_ROUNDS):
                for component in ROUND:
                    schedule.append(component)
                    try:
                        runner.step(component)
                    except Exception as error:
                        failure = {'type': type(error).__name__, 'message': str(error)}
                        break
                if failure is not None:
                    break
                marker = cpu.memory.read(RESULT + 16, 4,
                    transaction_id='ibex-pulp-success-poll').value
                if marker in (1, 0xFFFFFFFF):
                    break

        if negative:
            try:
                gpio_probe = gpio.step_local({}).get('gpio_out')
            except BaseException as error:
                gpio_probe = {'error': type(error).__name__, 'message': str(error)}
        else:
            gpio_probe = next((event.get('outputs', {}).get('gpio_out')
                for event in reversed(list(runner.events))
                if event.get('component') == 'gpio'), None)

        result = [cpu.memory.read(RESULT + offset, 4,
            transaction_id=f'ibex-pulp-result-{offset}').value
            for offset in (0, 4, 8, 12, 16)]
        binding, = runner.bindings
        execution_ids = _execution_ids(runner)
        process_ids = {name: None if proc is None else proc.pid
            for name, proc in process_handles.items()}
        identities = {name: session.identity_document()
            for name, session in runner.sessions.items()}
        irq_events = list(runner._irq_pulses[binding].events)
        router_deliveries = [{**row,
            'source_transaction': _plain(row['source_transaction'])}
            for row in cpu.router.deliveries]
        evidence = {
            'schema_version': 'ibex_wbdmac_pulp_gpio_isr_run.v1',
            'testcase_id': TESTCASE_ID,
            'source_address': SOURCE,
            'source_value': source_value,
            'destination_address': destination,
            'schedule': schedule,
            'round_bound': MAX_ROUNDS,
            'completed_rounds': len(schedule) // len(ROUND),
            'failure': failure,
            'result': result,
            'gpio_probe_value': gpio_probe,
            'provider_call_count': len(provider_calls),
            'native_pre_samples': native_pre_samples,
            'process_ids': process_ids,
            'path': paths.document(),
            'ownership': runner.ownership.document(),
            'events': list(runner.events),
            'cpu_events': list(cpu.cpu_events),
            'cpu_memory': list(cpu.service.events),
            'dma_events': list(dma.events),
            'dma_memory': list(dma.memory_service.events),
            'gpio_events': list(gpio.gpio_events),
            'irq_events': irq_events,
            'router_deliveries': router_deliveries,
            'identities': identities,
            'execution_ids': execution_ids,
            'admission_state': paths.admission.state,
        }
    finally:
        try:
            cpu.end_case()
        finally:
            try:
                dma.end_case()
            finally:
                gpio.end_case()
    evidence['process_returncodes'] = {
        name: None if proc is None else proc.returncode
        for name, proc in process_handles.items()}
    return evidence


def _semantic_payload(evidence):
    return {key: evidence[key] for key in (
        'schema_version', 'testcase_id', 'source_address', 'source_value',
        'destination_address', 'schedule', 'round_bound', 'completed_rounds',
        'failure', 'result', 'gpio_probe_value', 'provider_call_count',
        'path', 'ownership', 'events', 'cpu_events', 'cpu_memory',
        'dma_events', 'dma_memory', 'gpio_events', 'irq_events',
        'router_deliveries', 'identities', 'admission_state',
        'process_returncodes')}


def _assert_positive(evidence):
    assert evidence['failure'] is None
    assert evidence['result'] == [0x8000000B, 0, SOURCE_VALUE,
        SOURCE_VALUE, 1]
    assert evidence['provider_call_count'] == 1
    assert evidence['process_returncodes'] == {
        'cpu': 0, 'dma': 0, 'gpio': 0}
    assert evidence['admission_state'] == 'complete'

    deliveries = evidence['router_deliveries']
    assert [(row['offset'], row['write_value']) for row in deliveries
            if row['device_id'] == 'dma' and row['write']] == [
                (8, SOURCE), (12, PADOUT_ADDRESS), (4, 1),
                (0, 0x0FED0001)]
    accepted = [row['accepted'] for row in evidence['dma_events']
        if type(row.get('accepted')) is dict]
    assert [(row['address'], row['write']) for row in accepted] == [
        (SOURCE, False), (PADOUT_ADDRESS, True)]
    read_key, write_key = (row['transaction'] for row in accepted)
    assert read_key != write_key
    assert read_key['source_component'] == write_key['source_component'] == 'dma'
    assert (read_key['source_sequence'], write_key['source_sequence']) == (1, 2)
    for key in (read_key, write_key):
        assert key['execution_id'] == evidence['execution_ids']['dma']
        assert key['testcase_id'] == evidence['testcase_id']
    assert accepted[1]['value'] == SOURCE_VALUE

    reads = [row for row in evidence['dma_memory']
        if row.get('kind') == 'memory_read' and row.get('address') == SOURCE]
    assert len(reads) == 1
    assert reads[0]['transaction'] == read_key
    assert reads[0]['value'] == SOURCE_VALUE
    responses = [row['response'] for row in evidence['dma_events']
        if type(row.get('response')) is dict]
    response_by_key = {json.dumps(row['transaction'], sort_keys=True): row
        for row in responses}
    read_response = response_by_key[json.dumps(read_key, sort_keys=True)]
    write_response = response_by_key[json.dumps(write_key, sort_keys=True)]
    assert (read_response['rdata'], read_response['error']) == (SOURCE_VALUE, 0)
    assert (write_response['error'], write_response['rdata']) == (0, 0)

    target_delivery = accepted[1]['target_delivery']
    assert target_delivery['source_transaction'] == write_key
    assert (target_delivery['target_component'], target_delivery['address'],
        target_delivery['offset'], target_delivery['value'],
        target_delivery['byte_enable']) == (
            'gpio', PADOUT_ADDRESS, GPIO_PADOUT_OFFSET, SOURCE_VALUE, 15)
    provider = target_delivery['target_provider_receipt']
    assert provider['source_transaction'] == write_key
    assert provider['status'] == 'observed'
    effect = provider['target_effect']
    assert (effect['status'], effect['register'], effect['offset'],
        effect['accepted_value'], effect['post_probe_value']) == (
            'observed', 'PADOUT', GPIO_PADOUT_OFFSET,
            SOURCE_VALUE, SOURCE_VALUE)

    gpio_events = evidence['gpio_events']
    provider_access_id = provider['target_access_id']
    for kind in ('target_request', 'gpio_apb_access', 'target_response'):
        matched = [row for row in gpio_events
            if row.get('kind') == kind
            and row.get('access_id') == provider_access_id]
        assert len(matched) == 1
        assert matched[0]['source_transaction'] == write_key
    dma_apb_write = next(row for row in gpio_events
        if row.get('kind') == 'gpio_apb_access'
        and row.get('access_id') == provider_access_id)
    assert dma_apb_write['write'] is True
    assert dma_apb_write['wdata'] == SOURCE_VALUE
    assert dma_apb_write['post']['gpio_out'] == SOURCE_VALUE

    cpu_gpio_reads = [row for row in deliveries
        if row['device_id'] == 'gpio' and row['offset'] == GPIO_PADOUT_OFFSET
        and not row['write']]
    assert len(cpu_gpio_reads) == 1
    assert cpu_gpio_reads[0]['read_value'] == SOURCE_VALUE
    cpu_read_transaction = cpu_gpio_reads[0]['source_transaction']
    apb_readbacks = [row for row in gpio_events
        if row.get('kind') == 'gpio_apb_access' and row.get('write') is False]
    assert len(apb_readbacks) == 1
    assert apb_readbacks[0]['source_transaction'] == cpu_read_transaction
    assert apb_readbacks[0]['read_rdata'] == SOURCE_VALUE

    physical_name = evidence['identities']['dma'][
        'scenario_dma_interface']['irq_runtime_name']
    irq_edge = [row for row in evidence['dma_events']
        if row.get('kind') == 'dma_edge'
        and row.get('payload', {}).get('observations', {}).get('physical', {}).get(
            physical_name) == 1]
    assert irq_edge
    assert any(row.get('kind') == 'cpu_external_irq_taken'
        for row in evidence['cpu_events'])
    assert any(row.get('kind') == 'cpu_irq_taken'
        for row in evidence['irq_events'])
    retired_loads = [row for row in evidence['cpu_events']
        if row.get('kind') == 'cpu_retire'
        and row.get('pc_rdata') in (ISR + 12, ISR + 40, ISR + 56)]
    assert [(row['pc_rdata'], row['mem_addr'], row['mem_rmask'],
             row['mem_wmask'], row['mem_rdata']) for row in retired_loads] == [
        (ISR + 12, DMA_BASE, 15, 0, 0),
        (ISR + 40, PADOUT_ADDRESS, 15, 0, SOURCE_VALUE),
        (ISR + 56, SOURCE, 15, 0, SOURCE_VALUE),
    ]
    assert any(row.get('kind') == 'cpu_retire'
        and ISR <= row.get('pc_rdata', 0) < ISR + 256
        for row in evidence['cpu_events'])
    isr_writes = [row for row in evidence['cpu_memory']
        if row.get('kind') == 'memory_write'
        and row.get('address') in (RESULT, RESULT + 4, RESULT + 8,
                                   RESULT + 12, RESULT + 16)]
    assert [(row['address'], row['value']) for row in isr_writes] == [
        (RESULT, 0x8000000B), (RESULT + 4, 0),
        (RESULT + 8, SOURCE_VALUE), (RESULT + 12, SOURCE_VALUE),
        (RESULT + 16, 1)]
    assert evidence['gpio_probe_value'] == SOURCE_VALUE


@pytest.mark.skipif(os.environ.get('MYFUZZ_IBEX_PULP_DMA_REAL') != '1',
    reason='explicit native Ibex/DMA/PULP GPIO gate')
def test_real_ibex_dma_pulp_gpio_irq_isr_and_typed_fresh_replay(tmp_path):
    cache, evidence_dir = _settings(tmp_path)
    reference = _run_case(cache)
    fresh = _run_case(cache, schedule_prefix=reference['schedule'])
    _save_json(evidence_dir, 'reference', reference)
    _save_json(evidence_dir, 'fresh', fresh)
    _assert_positive(reference)
    _assert_positive(fresh)
    assert reference['identities'] == fresh['identities']
    assert reference['schedule'] == fresh['schedule']
    assert len(reference['schedule']) <= 3 * MAX_ROUNDS
    assert set(reference['execution_ids']) == {'cpu', 'dma', 'gpio', 'runner'}
    assert all(type(pid) is int and pid > 0 for pid in reference['process_ids'].values())
    assert all(type(pid) is int and pid > 0 for pid in fresh['process_ids'].values())
    assert len(set(reference['process_ids'].values())) == len(reference['process_ids'])
    assert len(set(fresh['process_ids'].values())) == len(fresh['process_ids'])
    assert set(reference['process_ids'].values()).isdisjoint(
        set(fresh['process_ids'].values()))
    for role in reference['execution_ids']:
        assert reference['execution_ids'][role] != fresh['execution_ids'][role]
    difference = first_gpio_dma_replay_difference(
        _semantic_payload(reference), _semantic_payload(fresh),
        reference_execution_ids=reference['execution_ids'],
        actual_execution_ids=fresh['execution_ids'])
    normalized_reference = normalize_gpio_dma_execution_identities(
        _semantic_payload(reference), reference['execution_ids'])
    normalized_fresh = normalize_gpio_dma_execution_identities(
        _semantic_payload(fresh), fresh['execution_ids'])
    comparison = {
        'schema_version': 'ibex_pulp_gpio_typed_fresh_replay.v1',
        'equal': difference is None,
        'difference': difference,
        'reference_schedule_steps': len(reference['schedule']),
        'fresh_schedule_steps': len(fresh['schedule']),
        'normalized_reference_sha256': hashlib.sha256(json.dumps(
            normalized_reference, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
        'normalized_fresh_sha256': hashlib.sha256(json.dumps(
            normalized_fresh, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
        'normalizer': 'typed CPU/DMA/GPIO/Runner field-level execution identity rules',
    }
    (evidence_dir / 'comparison.json').write_text(json.dumps(comparison,
        sort_keys=True, indent=2), encoding='utf-8')
    assert difference is None, difference


@pytest.mark.skipif(os.environ.get('MYFUZZ_IBEX_PULP_DMA_REAL') != '1',
    reason='explicit native wrong-offset PULP DMA refusal gate')
def test_real_ibex_dma_wrong_padout_offset_refuses_before_provider(tmp_path):
    cache, evidence_dir = _settings(tmp_path)
    wrong = _run_case(cache, destination=PADOUT_ADDRESS + 4, negative=True)
    _save_json(evidence_dir, 'wrong-offset-refusal', wrong)
    assert wrong['failure'] is not None
    assert wrong['failure']['type'] == 'ValueError'
    assert 'declared PADOUT window' in wrong['failure']['message']
    assert wrong['provider_call_count'] == 0
    assert wrong['admission_state'] == 'expect_write'
    attempted = [row for row in wrong['native_pre_samples']
        if row.get('mwb_cyc') == 1 and row.get('mwb_stb') == 1
        and row.get('mwb_we') == 1
        and (row.get('mwb_adr', -1) << 2) == PADOUT_ADDRESS + 4]
    assert len(attempted) == 1
    assert not any(row.get('kind') in ('target_request', 'target_response',
        'gpio_apb_access') for row in wrong['gpio_events'])
    assert wrong['gpio_probe_value'] == 0
    assert wrong['result'][4] == 0
    assert wrong['process_returncodes'] == {'cpu': 0, 'dma': 0, 'gpio': 0}
