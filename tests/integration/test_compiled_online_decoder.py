"""Pure tests for the compiled F4 RFuzz bridge.

Everything here runs without a native build or RTL process: the decoder tests
consume real D2/D3 declarations, and the executor tests use a small runtime
double that only records what the executor asked it to submit.  The real
fresh-prefix replay is a separate frozen-source gate and is not claimed here.
"""
from __future__ import annotations

import ast
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import struct

import pytest

from myfuzz.integration import compiled_f4 as compiled_f4_module
from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
from myfuzz.integration.compiled_f4 import normalized_semantic_sha256
from myfuzz.integration.compiled_rfuzz import (
    COMPILED_WIRE_CYCLES,
    CompiledRfuzzExecutor,
    compiled_commit_targets,
    fresh_verification_document,
    join_compiled_receipts,
    parse_compiled_input_buffer,
)
from myfuzz.integration.rfuzz_wire import INPUT_MAGIC, InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.local_harness.auto_harness_test import (
    build_path_compile_request,
    load_composition,
)
from myfuzz.local_harness.generated_artifact_admission import load_generated_artifacts
from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
from myfuzz.scenario.compiled_online_decoder import (
    CompiledCandidateRefused,
    CompiledOnlineDecoder,
    compiled_document_sha256,
    project_wire_record,
)
from myfuzz.scenario.compiled_paths import compile_paths, load_path_compile_request
from tests.integration.test_compiled_f4 import loaded as gpio_loaded

ROOT = Path(__file__).resolve().parents[2]
TIMER = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
WIRE = 8


def _timer_inputs(tmp_path):
    generated = tmp_path / 'generated'
    compose = load_compose(TIMER / 'compose.json', base_dir=ROOT)
    generate_harness_set(compose, base_dir=ROOT, compose_base=TIMER,
                         output_root=generated)
    composition = load_composition(TIMER / 'compose.json', base_dir=ROOT)
    document, _ = build_path_compile_request(
        composition, wiring_path=generated / 'wiring_contract.json',
        ip_capabilities=[TIMER / 'test_capability.json'])
    request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(request)
    return request, compiled


@pytest.fixture(scope='module')
def gpio(tmp_path_factory):
    artifacts, inputs = gpio_loaded(tmp_path_factory.mktemp('gpio'))
    path = next(row for row in inputs['compiled']['paths']
                if row['flow_id'] == 'F4' and row['status'] == 'executable')
    return artifacts, inputs, path


@pytest.fixture(scope='module')
def timer(tmp_path_factory):
    request, compiled = _timer_inputs(tmp_path_factory.mktemp('timer'))
    path = next(row for row in compiled['paths']
                if row['flow_id'] == 'F4' and row['status'] == 'executable')
    return request, compiled, path


def _decoder(inputs, path, *, result_address=0x3fffc, compiled_sha256=None):
    return CompiledOnlineDecoder.from_request(
        request=inputs['request'], compiled=inputs['compiled'], path=path,
        run_id='compiled-rfuzz-test', cpu_id='processor',
        schedule=('processor', 'peripheral'), rounds=4,
        instruction_start=0x10000, instruction_end=0x40000,
        result_address=result_address, compiled_sha256=compiled_sha256)


class _Ticks:
    def __init__(self):
        self.local_ticks = {'processor': 0, 'peripheral': 0}


class _RuntimeDouble:
    """The `from_runtime` surface, with the same compiled digest the real
    CompiledF4Runtime computes (compiled_f4._digest), without RTL."""

    def __init__(self, inputs, path):
        self.inputs = inputs
        self.path = path
        self.layout = compile_candidate_layout(path)
        self.compiled_digest = compiled_f4_module._digest(inputs['compiled'])
        self.run_id = 'compiled-rfuzz-runtime'
        self.cpu_id = 'processor'
        self.rounds = 4
        self.start = 0x10000
        self.end = 0x40000
        self.result = 0x3fffc
        self.cursor = 0x10000
        self.runner = _Ticks()
        self.runner.sessions = {'processor': object(),
                                'peripheral': object()}


def _has_non_ascii(value):
    if isinstance(value, str):
        return any(ord(character) > 127 for character in value)
    if isinstance(value, dict):
        return any(_has_non_ascii(key) or _has_non_ascii(item)
                   for key, item in value.items())
    if isinstance(value, (list, tuple)):
        return any(_has_non_ascii(item) for item in value)
    return False


class _FakeRuntime:
    """The compiled runtime surface the executor really uses, without RTL."""

    def __init__(self, path, compiled, *, max_cases=4, result=0x3fffc):
        self.layout = compile_candidate_layout(path)
        self.path = path
        self.compiled_digest = compiled_document_sha256(compiled)
        self.cursor = 0x10000
        self.result = result
        self.records = []
        self.max_cases = max_cases
        self.runner = _Ticks()
        self.session = None
        self.submits = []

    def submit(self, candidate_bytes):
        value = int.from_bytes(candidate_bytes[:4], 'little')
        self.runner.local_ticks['processor'] += 10
        self.runner.local_ticks['peripheral'] += 20
        self.cursor += 48
        self.records.append({'raw': candidate_bytes.hex()})
        self.submits.append(candidate_bytes)
        return {'schema_version': 'compiled_F4_chain.v1', 'status': 'certified',
                'path_id': self.path['path_id'], 'commit': {'before': 0,
                                                            'after': value}}


def _executor(inputs, path, runtime):
    decoder = _decoder(inputs, path, compiled_sha256=runtime.compiled_digest)
    return CompiledRfuzzExecutor(runtime=runtime, decoder=decoder,
                                 targets=compiled_commit_targets(path),
                                 run_id='compiled-rfuzz-test')


def _batch(*raws, buffer_id=1):
    return InputBatch(buffer_id, WIRE, tuple((raw,) for raw in raws))


def _wire(*tests):
    """One RFuzz input-buffer frame: each test is a tuple of 8-byte records."""
    header = struct.pack('>IIHHHH', INPUT_MAGIC, 1, len(tests), 0, 0, 0)
    body = b''.join(struct.pack('>Q', len(records)) + b''.join(records)
                    for records in tests)
    return header + body


def _high_byte_records(count):
    return tuple(bytes([0, 0, 0, 0x80 if index % 2 else 0x01]) + bytes(4)
                 for index in range(count))


def test_decoder_document_records_the_exact_compiled_path_and_source_ids(gpio):
    _, inputs, path = gpio
    decoder = _decoder(inputs, path)
    document = decoder.document()
    stream = next(row for row in path['sources']
                  if row['kind'] == 'cpu_mmio_stream')
    assert document['schema_version'] == 'compiled_online_decoder.v1'
    assert document['path_id'] == path['path_id']
    assert document['source_id'] == stream['source_id']
    assert document['register'] == stream['register']
    assert document['compiled_sha256'] == compiled_document_sha256(
        inputs['compiled'])
    assert document['candidate_layout']['digest'] == decoder.layout.digest
    assert document['candidate_bytes'] == 8
    raw = bytes.fromhex('78563412ddccbbaa')
    candidate = decoder.decode_candidate(raw, cursor=0x10000, case_index=0)
    identity = candidate.document()
    assert identity['path_id'] == path['path_id']
    assert identity['source_id'] == stream['source_id']
    assert identity['register'] == stream['register']
    assert identity['value'] == 0x12345678
    assert identity['compiled_sha256'] == document['compiled_sha256']
    assert identity['layout_digest'] == decoder.layout.digest
    assert identity['candidate_bytes_hex'] == raw.hex()


def test_a_narrow_compiled_candidate_consumes_the_declared_wire_prefix(timer):
    request, compiled, path = timer
    decoder = _decoder({'request': request, 'compiled': compiled}, path)
    document = decoder.document()
    assert document['candidate_bytes'] == 4
    assert document['wire_record_bytes'] == 8
    assert document['unbound_wire_bytes'] == 4
    raw = bytes.fromhex('5500000012345678')
    candidate = decoder.decode_candidate(raw, cursor=0x10000, case_index=0)
    assert candidate.candidate_bytes == bytes.fromhex('55000000')
    assert candidate.value == 0x55
    assert candidate.unbound_bytes == bytes.fromhex('12345678')
    assert candidate.document()['raw_sha256'] == sha256(raw).hexdigest()


def test_a_real_non_ascii_compiled_document_binds_from_the_runtime(gpio):
    """Regression: the decoder must use the runtime's canonical digest form.

    The compiled document carries non-ASCII declaration text.  The runtime
    binds it with ``compiled_f4._digest`` (ASCII-escaped JSON); a decoder that
    used a different JSON spelling produced a different digest for the same
    document and refused the real gate before RTL.
    """
    _, inputs, path = gpio
    compiled = inputs['compiled']
    assert _has_non_ascii(compiled), 'the fixture must exercise non-ASCII text'
    assert compiled_document_sha256(compiled) == compiled_f4_module._digest(
        compiled)
    runtime = _RuntimeDouble(inputs, path)
    decoder = CompiledOnlineDecoder.from_runtime(runtime)
    assert decoder.compiled_sha256 == runtime.compiled_digest
    candidate = decoder.decode_candidate(bytes.fromhex('78563412ddccbbaa'),
                                         cursor=runtime.cursor, case_index=0)
    assert candidate.source_id == 'peripheral.GPIOEN.value.mmio'

    # A tampered document claiming the original runtime digest still refuses.
    edited_inputs = {'request': inputs['request'],
                     'compiled': deepcopy(compiled)}
    edited_inputs['compiled']['identity']['cpu']['instance_id'] = 'edited'
    tampered = _RuntimeDouble(edited_inputs, path)
    tampered.compiled_digest = runtime.compiled_digest
    with pytest.raises(CompiledCandidateRefused,
                       match='compiled-document-mismatch'):
        CompiledOnlineDecoder.from_runtime(tampered)

    # A document edited after construction is refused on the next decode.
    live_inputs = {'request': inputs['request'],
                   'compiled': deepcopy(compiled)}
    live = _RuntimeDouble(live_inputs, path)
    live_decoder = CompiledOnlineDecoder.from_runtime(live)
    live_inputs['compiled']['identity']['cpu']['instance_id'] = 'edited-live'
    with pytest.raises(CompiledCandidateRefused,
                       match='compiled-digest-identity-changed'):
        live_decoder.decode_candidate(bytes.fromhex('78563412ddccbbaa'),
                                      cursor=live.cursor, case_index=0)


def test_forged_layout_or_edited_compiled_doc_never_admits(gpio):
    _, inputs, path = gpio
    # An edited compiled document is refused before any layout is issued.
    tampered = deepcopy(inputs['compiled'])
    edited_path = next(row for row in tampered['paths']
                       if row['flow_id'] == 'F4')
    edited_path['sources'][1]['register_access']['address'] ^= 4
    with pytest.raises(CompiledCandidateRefused,
                       match='compiled-document-mismatch'):
        CompiledOnlineDecoder.from_request(
            request=inputs['request'], compiled=tampered, path=path,
            run_id='r', cpu_id='processor',
            schedule=('processor', 'peripheral'), rounds=4,
            instruction_start=0x10000, instruction_end=0x40000,
            result_address=0x3fffc)
    # A layout that was not issued for this path is refused by identity.
    other = deepcopy(path)
    other['sources'][-1]['width'] = 3
    other['sources'][-1]['mask'] = 7
    other['constraints']['source_constraints'][-1]['width'] = 3
    other['constraints']['source_constraints'][-1]['mask'] = 7
    other_layout = compile_candidate_layout(other)
    with pytest.raises(CompiledCandidateRefused,
                       match='layout-not-issued-for-path'):
        CompiledOnlineDecoder(
            request=inputs['request'], compiled=inputs['compiled'], path=path,
            layout=other_layout, run_id='r', cpu_id='processor',
            schedule=('processor', 'peripheral'), rounds=4,
            instruction_start=0x10000, instruction_end=0x40000,
            result_address=0x3fffc)
    # A table that is not the D3 executable F4 path is refused.
    with pytest.raises(CompiledCandidateRefused,
                       match='compiled-path-mismatch'):
        Edited = deepcopy(path)
        Edited['path_id'] = 'F4:edited'
        CompiledOnlineDecoder(
            request=inputs['request'], compiled=inputs['compiled'],
            path=Edited, layout=compile_candidate_layout(Edited),
            run_id='r', cpu_id='processor',
            schedule=('processor', 'peripheral'), rounds=4,
            instruction_start=0x10000, instruction_end=0x40000,
            result_address=0x3fffc)


def _pin_layout(gpio, *, width, mask, bounds, alignment):
    _, inputs, path = gpio
    edited = deepcopy(path)
    for row in (edited['sources'][-1],
                edited['constraints']['source_constraints'][-1]):
        row.update(width=width, mask=mask, range=bounds, alignment=alignment)
    return compile_candidate_layout(edited)


@pytest.mark.parametrize('mask,bounds,alignment,pin,code', [
    (1, [0, 3], 1, 2, 'value-mask'),
    (3, [1, 2], 1, 0, 'value-range'),
    (3, [0, 3], 2, 1, 'value-alignment'),
])
def test_decoded_value_outside_mask_range_or_alignment_refuses(
        gpio, mask, bounds, alignment, pin, code):
    layout = _pin_layout(gpio, width=2, mask=mask, bounds=bounds,
                         alignment=alignment)
    raw = b'\x00\x00\x00\x00' + bytes([pin]) + b'\x00\x00\x00'
    with pytest.raises(CompiledCandidateRefused) as caught:
        project_wire_record(layout, raw)
    assert caught.value.code == code
    assert caught.value.pointer == layout.slices[-1].source_id


def test_a_record_that_is_not_sized_by_the_wire_is_refused(gpio):
    layout = _pin_layout(gpio, width=2, mask=3, bounds=[0, 3], alignment=1)
    for raw in (b'', b'\x00' * 7, b'\x00' * 9):
        with pytest.raises(CompiledCandidateRefused, match='record-length'):
            project_wire_record(layout, raw)
    with pytest.raises(CompiledCandidateRefused, match='wire-record-size'):
        project_wire_record(layout, b'\x00' * 8, wire_bytes=4)


def test_mapped_receipt_carries_real_source_path_status_and_coverage(gpio):
    _, inputs, path = gpio
    stream = next(row for row in path['sources']
                  if row['kind'] == 'cpu_mmio_stream')
    runtime = _FakeRuntime(path, inputs['compiled'])
    executor = _executor(inputs, path, runtime)
    raw = bytes.fromhex('00000080' + '00000000')  # value bit 31 set
    coverages = executor.execute_batch(_batch(raw))
    assert len(runtime.submits) == 1
    assert len(coverages) == 1 and int(coverages[0].hex(), 16) != 0
    receipt = executor.receipts[0]
    assert receipt.status == 'certified'
    assert receipt.path_id == path['path_id']
    assert receipt.online_case['source']['source_id'] == stream['source_id']
    assert receipt.online_case['source']['value'] == 0x80000000
    assert receipt.local_ticks == {'processor': 10, 'peripheral': 20}
    decision = executor._online_decisions_by_slot[(1, 0)]
    assert decision['path_id'] == path['path_id']
    assert decision['source_id'] == stream['source_id']
    assert decision['flow_id'] == 'F4'
    assert decision['candidate_disposition_reason'] == 'rtl_case_committed'


def test_receipt_source_and_path_join_detects_a_tampered_row(tmp_path, timer):
    _, compiled, path = timer
    stream = next(row for row in path['sources']
                  if row['kind'] == 'cpu_mmio_stream')
    row = {'path_id': path['path_id'], 'source_id': stream['source_id'],
           'flow_id': 'F4', 'status': 'certified', 'case_id': 'r:0'}
    good = tmp_path / 'good.jsonl'
    good.write_text(json.dumps(row) + '\n' + json.dumps(row) + '\n',
                    encoding='utf-8')
    joined = join_compiled_receipts(good, compiled)
    assert joined['status'] == 'ok'
    assert joined['rows'] == 2
    assert joined['path_id'] == path['path_id']
    assert joined['source_id'] == stream['source_id']
    assert joined['compiled_sha256'] == compiled_f4_module._digest(compiled)
    bad_source = tmp_path / 'bad-source.jsonl'
    bad_source.write_text(json.dumps({**row, 'source_id': 'other.source'}) + '\n',
                          encoding='utf-8')
    with pytest.raises(ValueError, match='compiled-receipt-source-mismatch'):
        join_compiled_receipts(bad_source, compiled)
    bad_path = tmp_path / 'bad-path.jsonl'
    bad_path.write_text(json.dumps({**row, 'path_id': 'F4:other'}) + '\n',
                        encoding='utf-8')
    with pytest.raises(ValueError, match='compiled-receipt-path-mismatch'):
        join_compiled_receipts(bad_path, compiled)
    empty = tmp_path / 'empty.jsonl'
    empty.write_text('', encoding='utf-8')
    with pytest.raises(ValueError, match='compiled-receipt-join-empty'):
        join_compiled_receipts(empty, compiled)


def test_max_cases_refuses_before_a_command(gpio):
    _, inputs, path = gpio
    runtime = _FakeRuntime(path, inputs['compiled'], max_cases=1)
    executor = _executor(inputs, path, runtime)
    raw = bytes.fromhex('01000000' + '00000000')
    executor.execute_batch(_batch(raw, bytes.fromhex('02000000' + '00000000')))
    assert len(runtime.submits) == 1
    assert len(runtime.records) == 1
    refused = executor.receipts[1]
    assert refused.status == 'input_invalid'
    assert 'case-budget-exhausted' in (refused.error or '')
    assert executor._session_stop_reason == 'case-budget-exhausted'


def test_slot_budget_refuses_before_a_command(gpio):
    _, inputs, path = gpio
    runtime = _FakeRuntime(path, inputs['compiled'])
    decoder = _decoder(inputs, path, result_address=0x10000 + 40,
                       compiled_sha256=runtime.compiled_digest)
    executor = CompiledRfuzzExecutor(runtime=runtime, decoder=decoder,
                                     targets=compiled_commit_targets(path),
                                     run_id='compiled-rfuzz-test')
    executor.execute_batch(_batch(bytes.fromhex('01000000' + '00000000')))
    assert runtime.submits == []
    receipt = executor.receipts[0]
    assert receipt.status == 'input_invalid'
    assert 'slot-budget-exhausted' in (receipt.error or '')
    assert executor._session_stop_reason == 'slot-budget-exhausted'


def _events(execution):
    return ({'event_id': 1, 'kind': 'memory_read',
             'target_access_id': f'apb-storage:{execution}:13', 'data_hex': '00'},
            {'event_id': 2, 'kind': 'register_commit',
             'target_access_id': f'apb-storage:{execution}:17', 'data_hex': '01'})


def test_two_different_execution_uuids_still_replay_identically():
    ticks = {'processor': 4, 'peripheral': 9}
    first = _events('42765f21-1111-4111-8111-111111111111')
    second = _events('d9470689-2222-4222-8222-222222222222')
    assert normalized_semantic_sha256('running', first, ticks) == \
        normalized_semantic_sha256('running', second, ticks)
    first_raw = sha256(json.dumps(list(first), sort_keys=True).encode()).hexdigest()
    second_raw = sha256(json.dumps(list(second), sort_keys=True).encode()).hexdigest()
    assert first_raw != second_raw
    assert normalized_semantic_sha256('running', first, ticks) != \
        normalized_semantic_sha256('running', _events(
            '42765f21-1111-4111-8111-111111111111')[:-1] + (
            {**_events('x')[1], 'data_hex': '02'},), ticks)


def test_the_decoder_never_branches_on_a_component_name():
    source = (ROOT / 'src/myfuzz/scenario/compiled_online_decoder.py').read_text(
        encoding='utf-8')
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        if not any(isinstance(op, (ast.Eq, ast.NotEq))
                   for op in node.ops):
            continue
        targets = [node.left, *node.comparators]
        for item in targets:
            if (isinstance(item, ast.Attribute)
                    and item.attr == 'component'
                    and any(isinstance(other, ast.Constant)
                            and isinstance(other.value, str)
                            for other in targets if other is not item)):
                raise AssertionError(
                    'compiled decoder compares component to a literal name')


def test_fresh_verification_scope_comes_from_the_full_prefix_replay():
    plan = {'semantic_hash': 'a' * 64, 'records': [{'raw': '00'}]}
    envelope = {'matches': True, 'first_difference': None,
                'scope': 'full_fresh_prefix_real_RTL_and_live_register_prerequisites',
                'expected_semantic_hash': 'a' * 64,
                'actual_semantic_hash': 'a' * 64,
                'actual_prefix': {'records': [{'raw': '00'}]},
                'actual_events': [{}, {}],
                'execution_audit': {'identities': {'processor': {'pid': 7}}}}
    document = fresh_verification_document(envelope, plan, session_dir='/s')
    assert document['schema_version'] == 'fresh_verification.v1'
    assert document['matches'] is True
    assert document['first_difference'] is None
    assert document['verification_scope'] == 'full'
    assert document['record_count'] == 1
    assert document['event_count'] == 2
    difference = fresh_verification_document(
        {**envelope, 'matches': False, 'first_difference': '/semantic_hash'},
        plan)
    assert difference['matches'] is False
    assert difference['first_difference'] == '/semantic_hash'
    absent = fresh_verification_document({}, plan)
    assert absent['matches'] is False


def test_the_compiled_wire_cycle_limit_matches_the_scenario_fields():
    from myfuzz.integration.scenario_rfuzz_live import _DECISION_FIELDS
    assert COMPILED_WIRE_CYCLES == len(_DECISION_FIELDS) == 8


def test_one_and_eight_cycle_tests_parse_and_more_is_refused():
    one = parse_compiled_input_buffer(_wire((bytes(8),)))
    assert len(one.tests) == 1
    assert one.tests[0] == (bytes(8),)

    records = _high_byte_records(8)
    eight = parse_compiled_input_buffer(_wire(records))
    assert len(eight.tests) == 1
    assert eight.tests[0] == records

    nine = _wire(tuple(bytes(8) for _ in range(9)))
    with pytest.raises(ValueError, match='test cycle count outside bound'):
        parse_compiled_input_buffer(nine)


def test_an_eight_cycle_test_executes_every_record_with_one_receipt(gpio):
    _, inputs, path = gpio
    runtime = _FakeRuntime(path, inputs['compiled'], max_cases=16)
    executor = _executor(inputs, path, runtime)
    records = _high_byte_records(8)
    coverages = executor.execute_batch(InputBatch(5, WIRE, (records,)))
    assert len(runtime.submits) == 8
    assert len(runtime.records) == 8
    assert len(coverages) == 1 and int(coverages[0].hex(), 16) != 0
    assert len(executor.receipts) == 1
    receipt = executor.receipts[0]
    assert receipt.status == 'certified'
    assert receipt.path_id == path['path_id']
    assert receipt.total_local_ticks == 8 * 30
    assert receipt.local_ticks == {'processor': 80, 'peripheral': 160}
    source = receipt.online_case['source']
    assert source['schema_version'] == 'compiled_online_sequence.v1'
    assert source['candidate_count'] == 8
    assert source['values'] == [int.from_bytes(record[:4], 'little')
                                for record in records]
    decision = executor._online_decisions_by_slot[(5, 0)]
    assert decision['cycle_count'] == 8
    assert decision['candidate_count'] == 8
    assert decision['candidate_disposition_reason'] == 'rtl_case_committed'
    assert decision['source_id'] == 'peripheral.GPIOEN.value.mmio'


def test_an_eight_cycle_test_over_max_cases_refuses_before_any_submit(gpio):
    _, inputs, path = gpio
    runtime = _FakeRuntime(path, inputs['compiled'], max_cases=4)
    executor = _executor(inputs, path, runtime)
    records = _high_byte_records(8)
    executor.execute_batch(InputBatch(6, WIRE, (records,)))
    assert runtime.submits == []
    assert runtime.records == []
    receipt = executor.receipts[0]
    assert receipt.status == 'input_invalid'
    assert 'case-budget-exhausted' in (receipt.error or '')
    assert executor._session_stop_reason == 'case-budget-exhausted'


def test_the_compiled_executor_overrides_the_one_cycle_wire_parser():
    assert (CompiledRfuzzExecutor.process_owned_pair
            is not ScenarioRfuzzExecutor.process_owned_pair)


def test_the_compiled_session_helper_refuses_rounds_outside_1_to_4096(tmp_path):
    from myfuzz.integration.compiled_rfuzz import run_compiled_f4_rfuzz_session
    with pytest.raises(ValueError,
                       match='compiled-rfuzz-rounds-per-case-invalid'):
        run_compiled_f4_rfuzz_session(
            artifacts=None, compiled_inputs=None, base_dir=ROOT,
            cache_dir=tmp_path, run_id='rounds', session_dir=tmp_path / 's',
            output_dir=tmp_path / 'o', client_binary=ROOT / 'kfuzz',
            budget_seconds=1, max_tests=1, search_seed=None,
            max_runs_per_batch=1, rounds_per_case=0)
