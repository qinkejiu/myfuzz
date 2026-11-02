"""Opt-in, directed real-RTL F2 transport controls, separate from client gates.

The missing-store injector below removes one observation from a copied observer
view. It never removes a DUT store, changes native authority, or replaces a
checker. Its result is a controlled observation failure, not a natural RTL bug.
The frozen gate supervisor owns command/process/input-map evidence.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path

import pytest

from myfuzz.integration.compiled_execution_files import (
    _worker_lock, prepare_compiled_execution_files)
from myfuzz.integration.compiled_f2 import CompiledF2Runtime
from myfuzz.integration.compiled_f2_rfuzz import (
    build_compiled_f2_rfuzz_executor, f2_seed_record)
from myfuzz.integration.rfuzz_wire import InputBatch


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
OPT_IN = 'MYFUZZ_RUN_NATIVE_F2_RFUZZ=1'
pytestmark = pytest.mark.skipif(
    os.environ.get('MYFUZZ_RUN_NATIVE_F2_RFUZZ') != '1',
    reason='real RTL F2 RFuzz controls require ' + OPT_IN)
CONTROL_NAMES = frozenset({
    'test_native_two_legal_records_share_continuous_runtime',
    'test_native_invalid_second_address_refuses_without_effects_original_and_fresh',
    'test_native_nine_records_refuse_without_clipping',
    'test_native_suffix_lanes_do_not_change_program_feedback_or_result',
    'test_native_controlled_missing_dependent_store_has_missing_assertion_and_zero_feedback',
})
_INITIAL_OUTPUT_HASHES = {}


def _save(path, value):
    """Retain the first bytes; the supervisor independently inventories outputs."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b'\n'
    with path.open('xb') as stream:
        stream.write(raw)
    assert path.read_bytes() == raw
    digest = sha256(raw).hexdigest()
    _INITIAL_OUTPUT_HASHES[path.resolve()] = digest
    return digest


def _assert_closed(audit):
    assert audit['closed'] is True
    assert audit['exits'] and set(audit['exits']) == set(audit['identities'])
    assert all(row == {'returncode': 0, 'reaped': True}
               for row in audit['exits'].values())


def _distinct_processes(original, fresh):
    assert set(original['identities']) == set(fresh['identities'])
    for name, row in original['identities'].items():
        other = fresh['identities'][name]
        assert row['pid'] != other['pid']
        assert row['execution_nonce'] != other['execution_nonce']
        for field in ('artifact_digest', 'build_digest', 'binary_sha256',
                      'built_receipt_sha256', 'observed_executable_sha256'):
            assert row[field] == other[field]


@pytest.fixture(scope='module', autouse=True)
def native_suite(request, tmp_path_factory):
    """One real worker; subset selection is deliberately not the acceptance gate."""
    selected = [item for item in request.session.items
                if Path(str(item.path)).resolve() == Path(__file__).resolve()]
    assert len(selected) == 5 and {item.name for item in selected} == CONTROL_NAMES
    supplied = os.environ.get('MYFUZZ_COMPILED_F2_RFUZZ_NATIVE_EVIDENCE')
    root = ((Path(supplied) / 'controls') if supplied else
            tmp_path_factory.mktemp('compiled-f2-rfuzz-native') / 'controls')
    root.mkdir(parents=True, exist_ok=False)
    cache = Path(os.environ.get('MYFUZZ_COMPILED_F2_RFUZZ_NATIVE_CACHE',
        str(ROOT / '.superpowers/cache/compiled-f2-rfuzz-entry-20261023')))
    with _worker_lock(ROOT / '.superpowers/sdd/stage2-heavy-worker.lock'):
        cache.mkdir(parents=True, exist_ok=True)
        (root / 'inputs').mkdir()
        artifacts, inputs, support = prepare_compiled_execution_files(
            base_dir=ROOT, compose_path=CONFIG / 'compose.json',
            capability_paths=(CONFIG / 'test_capability.json',),
            supplement_path=CONFIG / 'execution_supplement.json',
            generated_dir=root / 'inputs/generated', flow='F2')
        _save(root / 'support.json', support)
        assert support['execution_supported'] == 1
        generated_pins = {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest()
                          for path in sorted((root / 'inputs').rglob('*')) if path.is_file()}
        _save(root / 'generated-input-sha256.json', generated_pins)
        _save(root / 'selection.json', dict(
            nodes=[item.nodeid for item in selected], opt_in=OPT_IN,
            scope='directed real-runtime transport controls; real client is a separate gate',
            useful_search_benefit='not_claimed', heavy_lock=str(
                ROOT / '.superpowers/sdd/stage2-heavy-worker.lock')))
        try:
            yield dict(root=root, cache=cache, artifacts=artifacts, inputs=inputs)
        finally:
            initial = {str(path.relative_to(root.resolve())): digest
                       for path, digest in _INITIAL_OUTPUT_HASHES.items()
                       if path.is_relative_to(root.resolve())}
            final = {name: sha256((root / name).read_bytes()).hexdigest()
                     for name in initial}
            _save(root / 'output-integrity.json', dict(initial_sha256=initial,
                final_sha256=final, generated_input_sha256=generated_pins))
            assert initial == final
            assert generated_pins == {
                name: sha256((root / name).read_bytes()).hexdigest() for name in generated_pins}


@contextmanager
def _runtime(suite, name):
    """Close actual children and attempt every terminal export on any failure."""
    directory = suite['root'] / name
    directory.mkdir()
    runtime = executor = None
    primary = None
    startup = []
    try:
        runtime = CompiledF2Runtime(artifacts=suite['artifacts'],
            compiled_inputs=suite['inputs'], base_dir=ROOT,
            cache_dir=suite['cache'], run_id='native-f2-rfuzz-' + name,
            rounds_per_case=128, max_cases=16,
            build_audit_sink=lambda value: startup.append(deepcopy(value)))
        executor = build_compiled_f2_rfuzz_executor(runtime,
            run_id=runtime.run_id, evidence_dir=directory / 'executor-failures')
        yield runtime, executor, directory
    except BaseException as error:
        primary = error
        raise
    finally:
        failures = []
        if runtime is not None and not runtime.finished:
            try:
                runtime.finish()
            except BaseException as error:
                failures.append(('cleanup', error))
        if runtime is not None:
            try:
                _assert_closed(runtime.execution_audit())
            except BaseException as error:
                failures.append(('native-terminal', error))
        exports = [('startup-build.json', lambda: startup)]
        if runtime is not None:
            exports.extend([
                ('events.json', lambda: list(runtime.runner.events_since(0))),
                ('attempts.json', lambda: runtime.attempts),
                ('records.json', lambda: runtime.records),
                ('assertions.json', runtime.assertion_results),
                ('assertion-case-evidence.json', runtime.assertion_case_evidence),
                ('execution-audit.json', runtime.execution_audit),
                ('build-audit.json', runtime.build_audit_snapshot),
                ('session-manifest.json', lambda: runtime.session.manifest_document),
                ('session-plan.json', lambda: json.loads(runtime.session.encode_plan())),
                ('finish-diagnostic.json', lambda: runtime.finish_diagnostic),
            ])
        if executor is not None:
            exports.extend([
                ('receipts.json', lambda: [asdict(row) for row in executor.receipts]),
                ('decisions.json', lambda: executor.online_decisions),
            ])
        pins = {}
        for filename, capture in exports:
            try:
                pins[filename] = _save(directory / filename, capture())
            except BaseException as error:
                failures.append((filename, error))
        try:
            _save(directory / 'terminal.json', dict(
                primary=None if primary is None else repr(primary),
                export_errors=[dict(stage=stage, error=repr(error))
                               for stage, error in failures],
                initial_output_sha256=pins))
        except BaseException as error:
            failures.append(('terminal.json', error))
        if primary is not None:
            for stage, error in failures:
                primary.add_note('native control cleanup/export ' + stage + ': ' + repr(error))
        elif failures:
            first = failures[0][1]
            for stage, error in failures[1:]:
                first.add_note('native control cleanup/export ' + stage + ': ' + repr(error))
            raise first


def _batch(records, *, buffer_id=1):
    return InputBatch(buffer_id, 8, (tuple(records),))


def _no_effect_snapshot(runtime):
    """Read-only state, including RAM/slots and native command/version history."""
    target = runtime.runner.sessions[runtime.target_id]
    memory = runtime.runner.sessions[runtime.cpu_id].memory
    return deepcopy(dict(cursor=runtime.cursor, attempts=runtime.attempts,
        records=runtime.records, ticks=runtime.runner.local_ticks,
        events=list(runtime.runner.events_since(0)),
        memory=memory.state_summary(), memory_identity=memory.identity_document(),
        register_writes=runtime.authority.writes(),
        target_commands=list(target.native_reset_observation_commands()),
        target_sequence=target._sequence, target_reset_epoch=target.reset_epoch,
        manifest=runtime.session.manifest_document,
        plan=json.loads(runtime.session.encode_plan())))


def _finish_and_replay(runtime, directory):
    plan = runtime.finish()
    _save(directory / 'prefix.json', plan)
    _assert_closed(runtime.execution_audit())
    envelopes = []
    primary = None
    try:
        replay = runtime.replay(plan, audit_sink=lambda value: envelopes.append(value))
    except BaseException as error:
        primary = error
        raise
    finally:
        # The real replay callback retains actual fresh events even on failure.
        export_errors = []
        for index, envelope in enumerate(envelopes):
            try:
                _save(directory / f'fresh-replay-{index}.json', envelope)
            except BaseException as error:
                export_errors.append(error)
        if primary is not None:
            for error in export_errors:
                primary.add_note('native control replay export: ' + repr(error))
        elif export_errors:
            first = export_errors[0]
            for error in export_errors[1:]:
                first.add_note('native control replay export: ' + repr(error))
            raise first
    assert replay['matches'] is True and replay['first_difference'] is None
    assert replay['verification_scope'] == 'full'
    _assert_closed(replay['execution_audit'])
    _distinct_processes(runtime.execution_audit(), replay['execution_audit'])
    assert replay['actual_prefix']['assertions'] == plan['assertions']
    assert len(replay['actual_prefix']['records']) == len(runtime.records)
    return plan, replay


def _assert_certified(runtime, executor, vectors, count):
    assert len(runtime.attempts) == len(runtime.records) == count
    assert all(receipt.status == 'certified' for receipt in executor.receipts)
    assert all(vector == bytes([1] * len(executor.targets)) for vector in vectors)
    cases = runtime.assertion_results()['cases']
    assert len(cases) == count
    assert all(row['status'] == 'passed' for case in cases for row in case['assertions'])
    for record in runtime.records:
        exact = record['certificate']['exact_hops']
        assert len(exact['edges']) == 3 and exact['instruction_hops']
        assert len(exact['data_hops']) == 1
        assert exact['ram_write_hop']['memory_write_event'] > (
            exact['data_hops'][0]['native_response_event'])


def test_native_two_legal_records_share_continuous_runtime(native_suite):
    with _runtime(native_suite, 'two-legal-records') as (runtime, executor, directory):
        raw = f2_seed_record(runtime.path)
        start = runtime.cursor
        identities = runtime.execution_audit()['identities']
        planned = executor.online_decoder.decode_sequence(
            (raw, raw), cursor=start, case_index=0)
        vectors = executor.execute_batch(_batch((raw, raw)))
        _assert_certified(runtime, executor, vectors, 2)
        assert len(executor.receipts) == 1
        assert runtime.execution_audit()['identities'] == identities
        assert [row['instruction_address'] for row in runtime.attempts] == [
            candidate.case.source.address for candidate in planned]
        assert planned[1].case.source.address == start + len(bytes.fromhex(
            planned[0].declaration['code_hex']))
        assert runtime.cursor == start + sum(len(bytes.fromhex(
            candidate.declaration['code_hex'])) for candidate in planned)
        assert executor.online_decisions[0]['case_ids'] == [
            row['case_id'] for row in runtime.attempts]
        _save(directory / 'control.json', dict(raw_records_hex=[raw.hex(), raw.hex()],
            planned=[candidate.document() for candidate in planned],
            continuous_identities=identities, coverage=[v.hex() for v in vectors]))
        _finish_and_replay(runtime, directory)


def test_native_invalid_second_address_refuses_without_effects_original_and_fresh(native_suite):
    audits = []
    raw_sequences = []
    for label in ('invalid-second-original', 'invalid-second-independent-fresh'):
        with _runtime(native_suite, label) as (runtime, executor, directory):
            raw = f2_seed_record(runtime.path)
            invalid = (int.from_bytes(raw[:4], 'little') ^ 4).to_bytes(4, 'little') + raw[4:]
            assert not runtime.layout.classify(invalid[:4]).accepted
            records = (raw, invalid)
            before = _no_effect_snapshot(runtime)
            vectors = executor.execute_batch(_batch(records))
            after = _no_effect_snapshot(runtime)
            assert before == after
            assert vectors == (bytes(len(executor.targets)),)
            assert executor.receipts[0].status == 'input_invalid'
            assert executor.online_decisions[0]['case_ids'] == []
            assert executor.online_decisions[0]['raw_records_hex'] == [r.hex() for r in records]
            _save(directory / 'control.json', dict(raw_records_hex=[r.hex() for r in records],
                before=before, after=after, coverage=[v.hex() for v in vectors]))
            runtime.finish()
            audits.append(runtime.execution_audit())
            _assert_closed(audits[-1])
            raw_sequences.append(records)
    assert raw_sequences[0] == raw_sequences[1]
    _distinct_processes(*audits)


def test_native_nine_records_refuse_without_clipping(native_suite):
    with _runtime(native_suite, 'nine-record-refusal') as (runtime, executor, directory):
        raw = f2_seed_record(runtime.path)
        records = tuple(raw[:4] + index.to_bytes(4, 'little') for index in range(9))
        before = _no_effect_snapshot(runtime)
        vectors = executor.execute_batch(_batch(records))
        after = _no_effect_snapshot(runtime)
        assert before == after
        assert vectors == (bytes(len(executor.targets)),)
        receipt = executor.receipts[0]
        assert receipt.status == 'input_invalid'
        assert receipt.rejection['code'] == 'sequence-count'
        decision = executor.online_decisions[0]
        assert decision['raw_records_hex'] == [row.hex() for row in records]
        assert decision['wire_cycle_count'] == 9 and decision['case_ids'] == []
        assert receipt.raw_sha256 == sha256(b''.join(records)).hexdigest()
        _save(directory / 'control.json', dict(raw_records_hex=[r.hex() for r in records],
            before=before, after=after, coverage=[v.hex() for v in vectors]))


def test_native_suffix_lanes_do_not_change_program_feedback_or_result(native_suite):
    with _runtime(native_suite, 'suffix-unbound') as (runtime, executor, directory):
        seed = f2_seed_record(runtime.path)
        records = (seed[:4] + b'\x01\x23\x45\x67', seed[:4] + b'\xfe\xdc\xba\x98')
        candidates = executor.online_decoder.decode_sequence(
            records, cursor=runtime.cursor, case_index=0)
        assert records[0] != records[1]
        assert candidates[0].candidate_bytes == candidates[1].candidate_bytes == seed[:4]
        assert candidates[0].declaration == candidates[1].declaration
        assert candidates[0].case.source.data_hex == candidates[1].case.source.data_hex
        vectors = executor.execute_batch(InputBatch(1, 8, ((records[0],), (records[1],))))
        _assert_certified(runtime, executor, vectors, 2)
        assert vectors[0] == vectors[1]
        assert executor.receipts[0].raw_sha256 != executor.receipts[1].raw_sha256
        assert executor.receipts[0].genome_sha256 == executor.receipts[1].genome_sha256
        first, second = [record['certificate'] for record in runtime.records]
        assert first['instruction_sha256'] == second['instruction_sha256']
        assert first['exact_hops']['ram_write_hop']['value'] == second['exact_hops']['ram_write_hop']['value']
        assert first['exact_hops']['data_hops'][0]['native_obi']['rdata'] == second['exact_hops']['data_hops'][0]['native_obi']['rdata']
        _save(directory / 'control.json', dict(raw_records_hex=[r.hex() for r in records],
            candidates=[candidate.document() for candidate in candidates],
            coverage=[v.hex() for v in vectors],
            native_result_values=[cert['exact_hops']['ram_write_hop']['value']
                                  for cert in (first, second)]))
        _finish_and_replay(runtime, directory)


def test_native_controlled_missing_dependent_store_has_missing_assertion_and_zero_feedback(native_suite, monkeypatch):
    with _runtime(native_suite, 'controlled-missing-store') as (runtime, executor, directory):
        raw = f2_seed_record(runtime.path)
        real_events_since = runtime.runner.events_since
        removed = {}

        def controlled_observation_view(index):
            actual = real_events_since(index)
            # Case receipts use their nonzero start index and remain untouched.
            # Only the full-journal observer used by the exact-hop checker loses
            # the actual dependent-store row. Native execution is unchanged.
            if index != 0:
                return actual
            visible = []
            for event in actual:
                if (event.get('kind') == 'memory_write'
                        and event.get('component') == runtime.cpu_id
                        and event.get('address') == runtime.result):
                    removed[event['event_id']] = deepcopy(event)
                else:
                    visible.append(event)
            return tuple(visible)

        with monkeypatch.context() as observation_fault:
            observation_fault.setattr(runtime.runner, 'events_since', controlled_observation_view)
            vectors = executor.execute_batch(_batch((raw,)))
        assert len(removed) == 1
        assert all(event in real_events_since(0) for event in removed.values())
        assert vectors == (bytes(len(executor.targets)),)
        assert len(runtime.attempts) == 1 and runtime.records == []
        assert executor.receipts[0].status == 'environment_error'
        assert executor.online_decisions[0]['committed'] is False
        assert executor.online_decisions[0]['case_ids'] == [runtime.attempts[0]['case_id']]
        rows = {row['expectation_id']: row for row in runtime.assertion_results()['cases'][0]['assertions']}
        assert rows['cross_component.declared_edge_hops']['status'] == 'missing'
        assert rows['protocol_checker.receipt_violations']['status'] == 'failed'
        assert runtime.attempts[0]['checker_error'] == dict(
            error_type='F2ObservationMissing', error='compiled-F2-result-RAM-hop-missing')
        primary = deepcopy(runtime.attempts[0]['error'])
        assert primary['error'] in executor.receipts[0].error
        with pytest.raises(ValueError, match='compiled-F2-failed-attempt:') as terminal:
            runtime.finish()
        _assert_closed(runtime.execution_audit())
        assert runtime.attempts[0]['error'] == primary
        failure = json.loads((directory / 'executor-failures/compiled-f2-failure-1-0.json').read_bytes())
        assert failure['attempts'][0]['error'] == primary
        assert failure['decision']['status'] == 'environment_error'
        _save(directory / 'controlled-injector.json', dict(
            schema_version='compiled_F2_controlled_observation_fault.v1',
            classification='controlled_missing_dependent_store_observation',
            natural_RTL_failure=False, scope='copied full-journal observer view only',
            native_authority_and_checkers='unmodified',
            removed_observation_rows=list(removed.values()),
            primary_submission_error=primary, terminal_error=str(terminal.value),
            completed=False, fresh_verification='not_completed',
            raw_records_hex=[raw.hex()], coverage=[v.hex() for v in vectors]))
