"""Opt-in real ZipCPU DMA RAM-to-PULP PADOUT gate with fresh replay.

Run with ``MYFUZZ_DMA_PULP_REAL=1`` and operation-local cache/evidence paths.
This is a transaction-level composition of independent native RTL processes;
it does not claim a physical Wishbone-to-APB bridge or CPU consumption.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from myfuzz.local_harness import GeneratedLocalSession
from myfuzz.scenario.boom_gpio_example import _gpio_artifact
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.pulp_gpio_dma_paths import (
    GPIO_PADOUT_OFFSET, PulpGpioD4RouteAdmission,
    prepare_pulp_gpio_dma_runtime_paths)


ROOT = Path(__file__).resolve().parents[2]
RAM_BASE = 0x10000
RAM_SIZE = 0x20000
SOURCE_ADDRESS = RAM_BASE + 0x100
GPIO_BASE = 0x40001000
GPIO_SIZE = 0x1000
PADOUT_ADDRESS = GPIO_BASE + GPIO_PADOUT_OFFSET
SOURCE_WORD = 0x5AA55AA5
TESTCASE_ID = 'pulp-dma-single-word'
START_WORD = (0xFED << 16) | 1


def _settings(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_DMA_PULP_CACHE', tmp_path / 'cache'))
    evidence = Path(os.environ.get('MYFUZZ_DMA_PULP_EVIDENCE',
        tmp_path / 'evidence'))
    return cache, evidence


def _save_json(root, name, value):
    root.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')
    (root / (name + '.json.gz')).write_bytes(gzip.compress(payload, mtime=0))


def _normalize_execution_ids(value):
    if type(value) is dict:
        return {key: ('<execution>' if key == 'execution_id' else
                _normalize_execution_ids(item)) for key, item in value.items()}
    if type(value) is list:
        return [_normalize_execution_ids(item) for item in value]
    if type(value) is tuple:
        return [_normalize_execution_ids(item) for item in value]
    return value


def _native_d3_wiring(tmp_path):
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_pulp_gpio_dma_route_d2_d3)

    _d2_wiring, request, compiled = _generate_pulp_gpio_dma_route_d2_d3(
        tmp_path / 'pulp-d2-d3', ram_base=RAM_BASE, ram_size=RAM_SIZE)
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    if f6['status'] != 'unsupported':
        raise AssertionError('PULP D2/D3 fixture unexpectedly enabled F6')
    return request.wiring


def _make_pair(cache_dir, d3_wiring):
    from unittest.mock import patch

    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        CPU_PROFILE, _local_artifact, _pulp_d4_declaration,
        _select_dma_read_write_routes)
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    memory = PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=0x5a, max_initialized_bytes=RAM_SIZE)
    memory.preload(SOURCE_ADDRESS, SOURCE_WORD.to_bytes(4, 'little'))
    gpio = GeneratedPulpGpioSession(_gpio_artifact(ROOT), base_dir=ROOT,
        cache_dir=cache_dir, command_timeout_seconds=30)
    linked_dma = generated_instance('dma')
    dma = GeneratedWishboneDmaSession(linked_dma.artifact,
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(MasterTargetWindow('gpio', GPIO_BASE, GPIO_SIZE,
            gpio, (GPIO_PADOUT_OFFSET,), (SOURCE_WORD,)),),
        command_timeout_seconds=30)
    cpu = GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir)
    cpu.memory = memory
    artifact_links = {'dma': linked_dma.endpoint_links_document()}
    runner = SimpleNamespace(sessions={
        'cpu': cpu, 'dma': dma, 'gpio': gpio},
        ownership=SimpleNamespace(_bits={}), bindings=())
    paths = prepare_pulp_gpio_dma_runtime_paths(runner,
        image_id='dma_payload', image_address=SOURCE_ADDRESS)
    declaration = _pulp_d4_declaration(d3_wiring, paths.prepared,
                                       artifact_links)
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound = bind_dma_intent_topology(declaration, runner,
                                         artifact_links=artifact_links)
    if len(bound_objects) != 1 or bound_objects[0] is not paths.prepared:
        raise AssertionError('PULP D4 did not bind the exact prepared graph once')
    read_route, write_route = _select_dma_read_write_routes(paths.prepared)
    admission = PulpGpioD4RouteAdmission(paths.admission, bound,
        path_id=paths.path_id, read_route=read_route, write_route=write_route)
    dma.configure_dma_route_admission(admission)
    paths = replace(paths, compiled=bound.runtime_compilation)
    d4_evidence = {
        'binding': bound.document(),
        'bind_count': len(bound_objects),
        'same_prepared_object': bound_objects[0] is paths.prepared,
        'd3_wiring': d3_wiring.document,
    }
    genome = ScenarioGenome(TESTCASE_ID, 'CPU_TO_IP', paths.path_id,
        ('cpu', 'dma', 'gpio'), 1, (), initial_images=(MemoryImage(
            'dma_payload', 'cpu', SOURCE_ADDRESS,
            SOURCE_WORD.to_bytes(4, 'little').hex()),))
    paths.validate_source_genomes((genome,))
    return dma, gpio, memory, paths, d4_evidence


def _run_unselected_destination(cache_dir, d3_wiring):
    """Observe a native DMA write to PADOUT+4 being refused before GPIO APB."""
    dma, gpio, memory, paths, d4_evidence = _make_pair(cache_dir, d3_wiring)
    native_pre_samples = []
    original_command = dma.command

    def capture_native_pre(op, fields):
        receipt = original_command(op, fields)
        if op == 'STEP_WB_DMA':
            native_pre_samples.append(dict(receipt.payload['pre_backend']))
        return receipt

    dma.command = capture_native_pre
    testcase_id = TESTCASE_ID + '-unselected-offset'
    try:
        dma.begin_case(testcase_id)
        gpio.begin_case(testcase_id)
        dma.write_register(8, SOURCE_ADDRESS)
        dma.write_register(12, PADOUT_ADDRESS + 4)
        dma.write_register(4, 1)
        dma.write_register(0, START_WORD)

        refusal = None
        for _ in range(4000):
            try:
                dma.step_local()
            except ValueError as error:
                refusal = str(error)
                break
        if refusal is None:
            raise AssertionError('unselected PADOUT offset was not refused')
        if 'DMA route match' not in refusal:
            raise AssertionError(f'unexpected DMA refusal: {refusal}')

        attempted = [row for row in native_pre_samples
            if row.get('mwb_cyc') == 1 and row.get('mwb_stb') == 1
            and row.get('mwb_we') == 1
            and (row.get('mwb_adr', -1) << 2) == PADOUT_ADDRESS + 4]
        if len(attempted) != 1:
            raise AssertionError('native unselected Wishbone request was not uniquely observed')

        target_events = [event for event in gpio.gpio_events
            if event.get('kind') in ('gpio_apb_access', 'target_request',
                                     'target_response')]
        post_refusal_probe_value = gpio.step_local({})['gpio_out']
        padout_value = post_refusal_probe_value
        provider_activity = [event for event in gpio.gpio_events
            if event.get('kind') in ('gpio_target_receipt', 'gpio_apb_access',
                'gpio_access_terminal', 'gpio_dma_target_terminal',
                'target_request', 'target_response')]
        if target_events or provider_activity or padout_value != 0:
            raise AssertionError('refused native request changed PULP GPIO PADOUT')

        memory_reads = [event for event in dma.memory_service.events
            if event.get('kind') == 'memory_read']
        if (len(memory_reads) != 1 or memory_reads[0].get('address') != SOURCE_ADDRESS
                or memory_reads[0].get('value') != SOURCE_WORD):
            raise AssertionError('unselected case did not use the declared RAM word')
        return {
            'schema_version': 'pulp_dma_unselected_destination_refusal.v1',
            'testcase_id': testcase_id,
            'native_request_observed': True,
            'native_address': PADOUT_ADDRESS + 4,
            'selected_address': PADOUT_ADDRESS,
            'refusal': refusal,
            'refusal_before_target_provider': not provider_activity,
            'provider_dispatch_observed': bool(provider_activity),
            'provider_activity_event_count': len(provider_activity),
            'apb_access_count': len([event for event in gpio.gpio_events
                if event.get('kind') == 'gpio_apb_access']),
            'target_request_count': len([event for event in gpio.gpio_events
                if event.get('kind') == 'target_request']),
            'target_response_count': len([event for event in gpio.gpio_events
                if event.get('kind') == 'target_response']),
            'padout_value': padout_value,
            'post_refusal_probe_value': post_refusal_probe_value,
            'admission_state': dma._dma_route_admission.state,
            'route_matches': dma._dma_route_admission.route_matches,
            'd4_binding': d4_evidence,
            'ram_read': memory_reads[0],
            'scope': 'native DMA request was refused by the selected route admission before PULP provider dispatch',
        }
    finally:
        try:
            dma.close()
        finally:
            gpio.end_case()


def _run_one(cache_dir, d3_wiring):
    dma, gpio, memory, paths, d4_evidence = _make_pair(cache_dir, d3_wiring)
    try:
        dma.begin_case(TESTCASE_ID)
        gpio.begin_case(TESTCASE_ID)
        dma.write_register(8, SOURCE_ADDRESS)
        dma.write_register(12, PADOUT_ADDRESS)
        dma.write_register(4, 1)
        dma.write_register(0, START_WORD)

        for _ in range(4000):
            dma.step_local()
            accepted = [event['accepted'] for event in dma.events
                if type(event.get('accepted')) is dict]
            if len(accepted) >= 2:
                keys = {json.dumps(event['transaction'], sort_keys=True)
                    for event in accepted}
                responded = {json.dumps(event['response']['transaction'],
                    sort_keys=True) for event in dma.events
                    if type(event.get('response')) is dict}
                if keys <= responded and dma.pending_responses == 0:
                    break
        else:
            raise TimeoutError('real DMA-to-PULP transfer exceeded 4000 edges')

        accepted_events = [event for event in dma.events
            if type(event.get('accepted')) is dict]
        if len(accepted_events) != 2:
            raise AssertionError(f'expected exactly two DMA beats, got {len(accepted_events)}')
        read_event = next(event for event in accepted_events
            if not event['accepted']['write'])
        write_event = next(event for event in accepted_events
            if event['accepted']['write'])
        read_key = read_event['accepted']['transaction']
        write_key = write_event['accepted']['transaction']
        memory_reads = [event for event in dma.memory_service.events
            if event.get('kind') == 'memory_read'
            and event.get('transaction') == read_key]
        if len(memory_reads) != 1:
            raise AssertionError('DMA RAM read lacks one keyed MemoryService event')
        memory_read = memory_reads[0]
        if (memory_read['address'] != SOURCE_ADDRESS
                or memory_read['value'] != SOURCE_WORD
                or read_event['accepted']['address'] != SOURCE_ADDRESS
                or write_event['accepted']['address'] != PADOUT_ADDRESS
                or write_event['accepted']['byte_enable'] != 15
                or write_event['accepted']['value'] != SOURCE_WORD):
            raise AssertionError('DMA write value did not come from the selected RAM word')
        target_delivery = write_event.get('target_delivery')
        if type(target_delivery) is not dict:
            raise AssertionError('DMA PADOUT write lacks target delivery evidence')
        provider_receipt = target_delivery.get('target_provider_receipt')
        if (type(provider_receipt) is not dict
                or provider_receipt.get('target_effect', {}).get('post_probe_value')
                    != SOURCE_WORD):
            raise AssertionError('PULP PADOUT provider lacks a matching native effect')
        response_events = [event['response'] for event in dma.events
            if type(event.get('response')) is dict]
        response_by_key = {json.dumps(row['transaction'], sort_keys=True): row
            for row in response_events}
        read_response = response_by_key.get(json.dumps(read_key, sort_keys=True))
        write_response = response_by_key.get(json.dumps(write_key, sort_keys=True))
        if (read_response is None or write_response is None
                or read_response.get('rdata') != SOURCE_WORD
                or read_response.get('error') != 0
                or write_response.get('error') != 0):
            raise AssertionError('native DMA read/write response join is incomplete')
        route_matches = getattr(dma._dma_route_admission, 'route_matches', ())
        assert len(route_matches) == 2
        assert {tuple(row['edge_key']) for row in route_matches} == {
            (0, 0), (2, 0)}
        assert {json.dumps(row['transaction'], sort_keys=True)
                for row in route_matches} == {
            json.dumps(read_key, sort_keys=True),
            json.dumps(write_key, sort_keys=True)}
        assert dma._dma_route_admission.identity_document()['schema_version'] == \
            'dma_master_route_admission.v1'
        matches_by_edge = {tuple(row['edge_key']): row
                           for row in route_matches}
        read_match = matches_by_edge[(0, 0)]
        write_match = matches_by_edge[(2, 0)]
        if (read_match['transaction'] != read_key
                or write_match['transaction'] != write_key
                or memory_read.get('transaction') != read_match['transaction']
                or response_by_key[json.dumps(read_key, sort_keys=True)]
                    .get('transaction') != read_match['transaction']):
            raise AssertionError('D4 read route did not join the exact RAM read and response')
        if (target_delivery.get('source_transaction') != write_match['transaction']
                or provider_receipt.get('source_transaction') != write_match['transaction']
                or provider_receipt.get('target_effect', {}).get('source_transaction')
                    != write_match['transaction']
                or response_by_key[json.dumps(write_key, sort_keys=True)]
                    .get('transaction') != write_match['transaction']):
            raise AssertionError('D4 write route did not join the APB effect and response')
        if (d4_evidence['bind_count'] != 1
                or d4_evidence['same_prepared_object'] is not True):
            raise AssertionError('PULP D4 binding did not use the prepared object exactly once')

        typed = {
            'path': paths.document(),
            'd4_binding': d4_evidence,
            'dma_identity': dma.identity_document(),
            'gpio_identity': gpio.identity_document(),
            'source_binding': [vars(item) for item in paths.source_bindings.entries],
            'ram_read': memory_read,
            'dma_beats': [read_event, write_event],
            'dma_responses': [read_response, write_response],
            'dma_route_matches': route_matches,
            'gpio_events': list(gpio.gpio_events),
            'provider_receipt': provider_receipt,
            'admission_state': dma._dma_route_admission.state,
        }
        return typed
    finally:
        try:
            dma.close()
        finally:
            gpio.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_PULP_REAL') != '1',
    reason='explicit native DMA-to-PULP PADOUT gate')
def test_real_dma_to_pulp_padout_and_independent_fresh_replay(tmp_path):
    cache, evidence = _settings(tmp_path)
    cache.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    d3_wiring = _native_d3_wiring(tmp_path)
    reference = _run_one(cache, d3_wiring)
    fresh = _run_one(cache, d3_wiring)
    normalized_reference = _normalize_execution_ids(reference)
    normalized_fresh = _normalize_execution_ids(fresh)
    comparison = dict(schema_version='pulp_dma_fresh_comparison.v1',
        equal=normalized_reference == normalized_fresh,
        normalized_reference_sha256=hashlib.sha256(
            json.dumps(normalized_reference, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest(),
        normalized_fresh_sha256=hashlib.sha256(
            json.dumps(normalized_fresh, sort_keys=True,
                separators=(',', ':')).encode()).hexdigest())
    _save_json(evidence, 'reference', reference)
    _save_json(evidence, 'fresh', fresh)
    (evidence / 'comparison.json').write_text(json.dumps(comparison,
        sort_keys=True, indent=2), encoding='utf-8')
    (evidence / 'manifest.json').write_text(json.dumps({
        'schema_version': 'pulp_dma_real_gate.v1',
        'testcase_id': TESTCASE_ID,
        'source_address': SOURCE_ADDRESS,
        'source_value': SOURCE_WORD,
        'destination_address': PADOUT_ADDRESS,
        'runtime_proof_scope': 'native Wishbone requests/responses plus '
            'measured APB request/access/response and gpio_probe_out effect',
        'limitations': ['transaction-level process composition',
            'no physical Wishbone-to-APB bridge claim',
            'no CPU control/consume/retirement claim',
            'does not close P7 F6 or other IP providers'],
    }, sort_keys=True, indent=2), encoding='utf-8')
    assert comparison['equal'] is True


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_PULP_REAL') != '1',
    reason='explicit native DMA-to-PULP PADOUT refusal gate')
def test_real_unselected_padout_offset_is_refused_before_gpio_effect(tmp_path):
    cache, evidence = _settings(tmp_path)
    cache.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    d3_wiring = _native_d3_wiring(tmp_path)
    refusal = _run_unselected_destination(cache, d3_wiring)
    _save_json(evidence, 'unselected-offset-refusal', refusal)
    assert refusal['native_request_observed'] is True
    assert refusal['refusal_before_target_provider'] is True
    assert refusal['provider_dispatch_observed'] is False
    assert refusal['apb_access_count'] == 0
    assert refusal['padout_value'] == 0
    assert refusal['post_refusal_probe_value'] == 0
    assert len(refusal['route_matches']) == 1
    assert {tuple(row['edge_key']) for row in refusal['route_matches']} == {(0, 0)}
