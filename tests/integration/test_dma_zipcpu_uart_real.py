"""Opt-in ZipCPU wbdmac RAM to wbuart TXREG DMA gate.

This joins a real generated Wishbone DMA master request to the pinned native
wbuart Wishbone target and its decoded physical TX pin. It does not model a
physical Wishbone bridge or claim CPU consumption.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from dataclasses import asdict, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.local_harness import (GeneratedWishboneUartSession,
    load_local_harness_request, plan_local_harness, render_local_harness,
    render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.zipcpu_uart_dma_paths import (TXREG_OFFSET,
    prepare_zipcpu_uart_dma_runtime_paths)
from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission


ROOT = Path(__file__).resolve().parents[2]
RAM_BASE = 0x10000
RAM_SIZE = 0x20000
SOURCE_ADDRESS = RAM_BASE + 0x100
UART_BASE = 0x40003000
UART_SIZE = 0x10
TXREG_ADDRESS = UART_BASE + TXREG_OFFSET
UNSELECTED_ADDRESS = UART_BASE + 8
SOURCE_WORD = 0x41
TESTCASE_ID = 'zipcpu-dma-uart-txreg'
START_WORD = (0xFED << 16) | 1
STARTUP_WRITES = ((0, 25, 15),)


def _settings(tmp_path):
    cache = Path(os.environ.get('MYFUZZ_DMA_ZIPCPU_UART_CACHE',
        tmp_path / 'cache'))
    evidence = Path(os.environ.get('MYFUZZ_DMA_ZIPCPU_UART_EVIDENCE',
        tmp_path / 'evidence'))
    return cache, evidence


def _uart_artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipcpu_uart/component_profile.json',
        instance_id='uart', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _save_json(root, name, value):
    root.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')
    (root / (name + '.json.gz')).write_bytes(gzip.compress(payload, mtime=0))


def _normalize_execution_ids(value, execution_ids):
    if type(value) is dict:
        return {key: ('<execution>' if key in ('execution', 'execution_id')
                else _normalize_execution_ids(item, execution_ids))
                for key, item in value.items()}
    if type(value) is list:
        return [_normalize_execution_ids(item, execution_ids)
                for item in value]
    if type(value) is tuple:
        return [_normalize_execution_ids(item, execution_ids)
                for item in value]
    if type(value) is str:
        if value in execution_ids:
            return '<execution>'
        for execution_id in execution_ids:
            value = value.replace(execution_id, '<execution>')
    return value


def _native_d3_wiring(tmp_path):
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_zipcpu_uart_dma_route_d2_d3)

    _d2_wiring, request, compiled = _generate_zipcpu_uart_dma_route_d2_d3(
        tmp_path / 'zipcpu-d2-d3', ram_base=RAM_BASE, ram_size=RAM_SIZE)
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    if f6['status'] != 'unsupported':
        raise AssertionError('ZipCPU D2/D3 fixture unexpectedly enabled F6')
    return request.wiring


def _make_pair(cache_dir, d3_wiring):
    from unittest.mock import patch

    from myfuzz.local_harness import GeneratedLocalSession
    memory = PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=0x5a, max_initialized_bytes=RAM_SIZE)
    memory.preload(SOURCE_ADDRESS, SOURCE_WORD.to_bytes(4, 'little'))
    uart_artifact = _uart_artifact()
    uart = GeneratedWishboneUartSession(uart_artifact, base_dir=ROOT,
        cache_dir=cache_dir, source=b'', startup_writes=STARTUP_WRITES,
        command_timeout_seconds=30)
    from tests.scenario.test_dma_intent_topology_binding import generated_instance
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        CPU_PROFILE, _local_artifact, _zipcpu_uart_d4_declaration,
        _select_dma_read_write_routes)
    from myfuzz.scenario.dma_intent_topology_binding import bind_dma_intent_topology
    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract

    linked_dma = generated_instance('dma')
    dma = GeneratedWishboneDmaSession(linked_dma.artifact,
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(MasterTargetWindow('uart', UART_BASE, UART_SIZE,
            uart, (TXREG_OFFSET,), range(256), byte_enable=15),),
        command_timeout_seconds=30)
    cpu = GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir)
    cpu.memory = memory
    artifact_links = {'dma': linked_dma.endpoint_links_document()}
    runner = SimpleNamespace(sessions={
        'cpu': cpu, 'dma': dma, 'uart': uart},
        ownership=SimpleNamespace(_bits={}), bindings=())
    paths = prepare_zipcpu_uart_dma_runtime_paths(runner,
        image_id='uart_payload', image_address=SOURCE_ADDRESS)
    declaration = _zipcpu_uart_d4_declaration(
        d3_wiring, paths.prepared, artifact_links)
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound = bind_dma_intent_topology(declaration, runner,
            artifact_links=artifact_links)
    if len(bound_objects) != 1 or bound_objects[0] is not paths.prepared:
        raise AssertionError('ZipCPU D4 did not bind the exact prepared graph once')
    read_route, write_route = _select_dma_read_write_routes(paths.prepared)
    admission = DmaMasterRouteAdmission(paths.admission, bound,
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
        ('cpu', 'dma', 'uart'), 1, (), initial_images=(MemoryImage(
            'uart_payload', 'cpu', SOURCE_ADDRESS,
            SOURCE_WORD.to_bytes(4, 'little').hex()),))
    paths.validate_source_genomes((genome,))
    return dma, uart, memory, paths, uart_artifact, d4_evidence


def _start_dma(dma, destination):
    dma.write_register(8, SOURCE_ADDRESS)
    dma.write_register(12, destination)
    dma.write_register(4, 1)
    dma.write_register(0, START_WORD)


def _run_unselected_destination(cache_dir, d3_wiring):
    dma, uart, _memory, _paths, _artifact, d4_evidence = _make_pair(
        cache_dir, d3_wiring)
    native_step_samples = []
    original_command = dma.command

    def capture_native_step(operation, fields):
        receipt = original_command(operation, fields)
        if operation == 'STEP_WB_DMA':
            native_step_samples.append({
                'operation': operation, 'fields': list(fields),
                'status': receipt.status, 'execution': receipt.execution,
                'sequence': receipt.sequence, 'tick_before': receipt.tick_before,
                'tick_after': receipt.tick_after, 'new_ticks': receipt.new_ticks,
                'pre_backend': dict(receipt.payload['pre_backend']),
            })
        return receipt

    dma.command = capture_native_step
    testcase_id = TESTCASE_ID + '-unselected-address'
    try:
        uart.begin_case(testcase_id)
        dma.begin_case(testcase_id)
        # This applies SETUP=25 to the native UART before DMA starts.
        uart.step_local({})
        ticks_before = uart.local_ticks
        tx_count_before = len(uart.peer.captured)
        provider_events_before = len(uart._dma_target_events)
        _start_dma(dma, UNSELECTED_ADDRESS)

        refusal = None
        for _ in range(4000):
            try:
                dma.step_local()
            except ValueError as error:
                refusal = str(error)
                break
        if refusal is None:
            raise AssertionError('native DMA request to an unselected UART register offset was not refused')
        attempted = [row for row in native_step_samples
            if row['pre_backend'].get('mwb_cyc') == 1
            and row['pre_backend'].get('mwb_stb') == 1
            and row['pre_backend'].get('mwb_we') == 1
            and (row['pre_backend'].get('mwb_adr', -1) << 2)
                == UNSELECTED_ADDRESS]
        if len(attempted) != 1:
            raise AssertionError('unselected native Wishbone request was not uniquely observed')
        attempted = attempted[0]
        pre = attempted['pre_backend']
        if (attempted['status'] != 'result' or attempted['new_ticks'] != 1
                or pre.get('mwb_dat_w') != SOURCE_WORD
                or pre.get('mwb_cyc') != 1 or pre.get('mwb_stb') != 1
                or pre.get('mwb_we') != 1):
            raise AssertionError('unselected native Wishbone request payload was not exact')
        transaction = TransactionKey(dma._execution, testcase_id,
            dma.source_component, dma.reset_epoch, 'dma-memory',
            dma._source_sequence)
        provider_call_count = len(uart._dma_target_events) - provider_events_before
        if (uart.local_ticks != ticks_before
                or len(uart.peer.captured) != tx_count_before
                or provider_call_count):
            raise AssertionError('refused DMA route reached the UART target provider')
        return {
            'schema_version': 'zipcpu_uart_dma_unselected_target_refusal.v1',
            'testcase_id': testcase_id,
            'native_request_observed': True,
            'native_address': UNSELECTED_ADDRESS,
            'selected_address': TXREG_ADDRESS,
            'refusal': refusal,
            'provider_call_count': provider_call_count,
            'uart_local_ticks_before': ticks_before,
            'uart_local_ticks_after': uart.local_ticks,
            'serial_tx_count_before': tx_count_before,
            'serial_tx_count_after': len(uart.peer.captured),
            'route_admission_state': dma._dma_route_admission.state,
            'route_matches': dma._dma_route_admission.route_matches,
            'd4_binding': d4_evidence,
            'attempted_native_request': {
                **attempted, 'transaction': asdict(transaction)},
            'scope': 'native DMA request refused before the ZipCPU UART target provider command',
        }
    finally:
        try:
            dma.close()
        finally:
            uart.end_case()


def _run_one(cache_dir, d3_wiring):
    dma, uart, memory, paths, uart_artifact, d4_evidence = _make_pair(
        cache_dir, d3_wiring)
    try:
        uart.begin_case(TESTCASE_ID)
        dma.begin_case(TESTCASE_ID)
        # Apply the pinned UART setup before admitting any DMA target access.
        uart.step_local({})
        if uart.read_register(0) & 0xffffff != 25:
            raise AssertionError('real UART SETUP did not hold 25 clocks per bit')
        _start_dma(dma, TXREG_ADDRESS)

        for _ in range(4000):
            dma.step_local()
            accepted = [event['accepted'] for event in dma.events
                if type(event.get('accepted')) is dict]
            responses = {json.dumps(event['response']['transaction'], sort_keys=True)
                for event in dma.events if type(event.get('response')) is dict}
            keys = {json.dumps(event['transaction'], sort_keys=True)
                for event in accepted}
            if len(accepted) == 2 and keys <= responses and dma.pending_responses == 0:
                break
        else:
            raise TimeoutError('real DMA-to-ZipCPU UART TXREG transfer exceeded 4000 edges')

        beats = [event for event in dma.events
                 if type(event.get('accepted')) is dict]
        if len(beats) != 2:
            raise AssertionError(f'expected one RAM read and one UART TXREG write, got {len(beats)} beats')
        read_event = next(event for event in beats
                          if not event['accepted']['write'])
        write_event = next(event for event in beats
                           if event['accepted']['write'])
        read_key = read_event['accepted']['transaction']
        write_key = write_event['accepted']['transaction']
        response_by_key = {json.dumps(event['response']['transaction'], sort_keys=True):
            event['response'] for event in dma.events
            if type(event.get('response')) is dict}
        read_response = response_by_key.get(json.dumps(read_key, sort_keys=True))
        write_response = response_by_key.get(json.dumps(write_key, sort_keys=True))
        memory_reads = [event for event in dma.memory_service.events
            if event.get('kind') == 'memory_read'
            and event.get('transaction') == read_key]
        if (len(memory_reads) != 1
                or memory_reads[0].get('address') != SOURCE_ADDRESS
                or memory_reads[0].get('value') != SOURCE_WORD
                or read_event['accepted']['address'] != SOURCE_ADDRESS
                or read_response is None
                or read_response.get('rdata') != SOURCE_WORD
                or read_response.get('error') != 0
                or write_event['accepted']['address'] != TXREG_ADDRESS
                or write_event['accepted']['value'] != SOURCE_WORD
                or write_event['accepted']['byte_enable'] != 15
                or write_response is None or write_response.get('error') != 0):
            raise AssertionError('DMA RAM byte did not reach the selected UART TXREG')
        target_delivery = write_event.get('target_delivery')
        provider_receipt = (target_delivery.get('target_provider_receipt')
            if type(target_delivery) is dict else None)
        effect = provider_receipt.get('target_effect') if type(provider_receipt) is dict else None
        if (type(effect) is not dict or effect.get('serial_byte') != SOURCE_WORD
                or effect.get('source_transaction') != write_key
                or effect.get('access_id') != provider_receipt.get('target_access_id')
                or effect.get('status') != 'observed'):
            raise AssertionError('UART DMA provider lacks a joined native serial byte effect')
        if uart.peer.captured != [SOURCE_WORD]:
            raise AssertionError('physical UART TX pin did not decode exactly the DMA source byte')
        if (provider_receipt.get('source_transaction') != write_key
                or provider_receipt.get('status') != 'observed'
                or provider_receipt.get('target_request', {}).get('status') != 'observed'
                or provider_receipt.get('target_response', {}).get('status') != 'observed'):
            raise AssertionError('DMA provider receipt is not a complete native request/ACK join')
        route_matches = dma._dma_route_admission.route_matches
        if (len(route_matches) != 2
                or {tuple(row['edge_key']) for row in route_matches}
                    != {(0, 0), (2, 0)}
                or {json.dumps(row['transaction'], sort_keys=True)
                    for row in route_matches}
                    != {json.dumps(read_key, sort_keys=True),
                        json.dumps(write_key, sort_keys=True)}):
            raise AssertionError('native DMA beats did not consume both selected D4 routes')
        return {
            'execution_ids': {
                'dma': dma._execution, 'uart': uart._execution,
                'testcase_id': TESTCASE_ID,
            },
            'path': paths.document(),
            'd4_binding': d4_evidence,
            'route_admission_identity': dma._dma_route_admission.identity_document(),
            'route_matches': route_matches,
            'dma_identity': dma.identity_document(),
            'uart_identity': uart.identity_document(),
            'uart_artifact_digest': uart_artifact.runtime_document['artifact_digest'],
            'ram_read': memory_reads[0],
            'dma_beats': beats,
            'dma_responses': [read_response, write_response],
            'provider_receipts': list(uart._dma_target_events),
            'serial_bytes': list(uart.peer.captured),
            'serial_tx_count': len(uart.peer.captured),
            'uart_local_ticks': uart.local_ticks,
            'admission_state': dma._dma_route_admission.state,
        }
    finally:
        try:
            dma.close()
        finally:
            uart.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_ZIPCPU_UART_REAL') != '1',
    reason='explicit real ZipCPU UART DMA gate')
def test_real_dma_to_zipcpu_uart_txreg_serial_fresh_and_refusal(tmp_path):
    cache, evidence = _settings(tmp_path)
    d3_wiring = _native_d3_wiring(tmp_path)
    first = _run_one(cache, d3_wiring)
    refusal = _run_unselected_destination(cache, d3_wiring)
    fresh = _run_one(cache, d3_wiring)
    assert first['execution_ids']['dma'] != fresh['execution_ids']['dma']
    assert first['execution_ids']['uart'] != fresh['execution_ids']['uart']
    ids = {first['execution_ids']['dma'], first['execution_ids']['uart'],
           fresh['execution_ids']['dma'], fresh['execution_ids']['uart']}
    assert _normalize_execution_ids(first, ids) == _normalize_execution_ids(fresh, ids)
    assert first['serial_bytes'] == [SOURCE_WORD]
    assert fresh['serial_bytes'] == first['serial_bytes']
    assert first['d4_binding']['bind_count'] == 1
    assert first['d4_binding']['same_prepared_object'] is True
    assert refusal['provider_call_count'] == 0
    assert len(refusal['route_matches']) == 1
    assert {tuple(row['edge_key']) for row in refusal['route_matches']} == {(0, 0)}
    assert refusal['attempted_native_request']['pre_backend']['mwb_dat_w'] == SOURCE_WORD
    assert refusal['uart_local_ticks_before'] == refusal['uart_local_ticks_after']
    assert refusal['serial_tx_count_before'] == refusal['serial_tx_count_after']
    ids = {first['execution_ids']['dma'], first['execution_ids']['uart'],
           fresh['execution_ids']['dma'], fresh['execution_ids']['uart']}
    normalized_first = _normalize_execution_ids(first, ids)
    normalized_fresh = _normalize_execution_ids(fresh, ids)
    comparison = {
        'schema_version': 'zipcpu_uart_d4_fresh_comparison.v1',
        'equal': normalized_first == normalized_fresh,
        'normalized_reference_sha256': hashlib.sha256(json.dumps(
            normalized_first, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'normalized_fresh_sha256': hashlib.sha256(json.dumps(
            normalized_fresh, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
    }
    assert comparison['equal'] is True
    _save_json(evidence, 'descriptor', first)
    _save_json(evidence, 'fresh', fresh)
    _save_json(evidence, 'native-refusal', refusal)
    (evidence / 'comparison.json').write_text(json.dumps(comparison,
        sort_keys=True, indent=2), encoding='utf-8')
    (evidence / 'manifest.json').write_text(json.dumps({
        'schema_version': 'zipcpu_uart_d4_real_gate.v1',
        'testcase_id': TESTCASE_ID,
        'ram_source_address': SOURCE_ADDRESS,
        'source_value': SOURCE_WORD,
        'txreg_address': TXREG_ADDRESS,
        'route_identity': 'D2/D3 selected route rows consumed through one D4 bind per execution',
        'runtime_proof_scope': 'native Wishbone DMA read/write requests and responses, UART provider request/ACK/effect, and decoded serial TX byte',
        'limitations': ['no physical bridge to another protocol',
            'no CPU programming/consumption/retirement claim',
            'F6 remains unsupported',
            'does not close other IP families or P6/P7/P8'],
    }, sort_keys=True, indent=2), encoding='utf-8')

