"""Opt-in source-backed controls for the compiled native F6 gate.

The gate supervisor owns the child process and the saved-output audit. Tests in
this module may create native evidence only when the exact opt-in is present;
they never read the supervisor's invocation ledger or call its saved auditor.
"""
from contextlib import contextmanager, nullcontext
from copy import deepcopy
from collections.abc import Mapping
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
from dataclasses import replace

import pytest


ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / '.superpowers/sdd/compiled-f6-20261024/gates/inputs/f6-ram'
CPU_PROFILE = ROOT / 'configs/cpus/ibex_rvfi_local/component_profile.json'
DMA_PROFILE = ROOT / 'configs/peripherals/zipcpu_wbdmac/component_profile.json'
RFUZZ_CLIENT = ROOT / 'third_party/rfuzz/upstream/rfuzz_reference/fuzzer/target/release/kfuzz'
OPT_IN = 'MYFUZZ_RUN_NATIVE_F6=1'
pytestmark = pytest.mark.skipif(
    os.environ.get('MYFUZZ_RUN_NATIVE_F6') != '1',
    reason='frozen native F6 controls require ' + OPT_IN)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False)


def _digest(value):
    return sha256(_canonical(value).encode('utf-8')).hexdigest()


def _json_plain(value):
    """Recursively copy immutable JSON-shaped values into plain containers."""
    if isinstance(value, Mapping):
        return {key: _json_plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_plain(item) for item in value]
    return value


def _required_path(name):
    value = os.environ.get(name)
    if type(value) is not str or not value.strip():
        pytest.fail('native F6 gate must provide ' + name)
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve()


def _control_evidence_path(name):
    root = _required_path('MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE')
    if not root.is_dir():
        pytest.fail('native F6 control evidence root is missing: ' + str(root))
    return root / (name + '.json')


def _write_control_evidence(name, document):
    path = _control_evidence_path(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = (json.dumps(document, sort_keys=True, indent=2,
        ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    try:
        with path.open('xb') as stream:
            stream.write(raw)
    except FileExistsError as error:
        raise AssertionError('refusing to replace native control evidence: '
            + str(path)) from error
    return path


def _source_backed_runtime_inputs(tmp_path):
    """Reopen the retained D2/D3 source fixture without regenerating it."""
    base = INPUTS / 'base'
    for path in (base / 'path_compile_request.json',
                 base / 'compiled_paths.json', base / 'generated'):
        if not path.exists():
            pytest.fail('prepared source-backed F6 fixture is incomplete: '
                + str(path))

    from myfuzz.local_harness.auto_harness_test import load_compiled_session_inputs
    from myfuzz.scenario.compiled_paths import (
        compile_paths, load_path_compile_request)

    request_document = json.loads((base / 'path_compile_request.json').read_bytes())
    request = load_path_compile_request(request_document, base_dir=ROOT)
    compiled = compile_paths(request)
    saved_compiled = json.loads((base / 'compiled_paths.json').read_bytes())
    if _canonical(compiled) != _canonical(saved_compiled):
        raise ValueError('prepared F6 D3 differs from source-backed recompilation')

    generated_root = tmp_path / 'generated'
    shutil.copytree(base / 'generated', generated_root, symlinks=False)
    artifacts, compiled_inputs = load_compiled_session_inputs(
        generated_root=generated_root, base_dir=ROOT, request=request,
        compiled=compiled, flow='F6')
    return artifacts, compiled_inputs


@contextmanager
def _opened_native_runtime(tmp_path, *, run_id, response_fault=None,
                           max_cases=1):
    """Own one actual runtime and always finalize/release its D2 credentials."""
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.local_harness.generated_artifact_admission import (
        release_f6_provider_credentials)

    artifacts = None
    runtime = None
    primary = None
    try:
        artifacts, compiled_inputs = _source_backed_runtime_inputs(tmp_path)
        cache_dir = _required_path('MYFUZZ_COMPILED_F6_NATIVE_CACHE')
        if not cache_dir.is_dir():
            pytest.fail('native F6 build cache is missing: ' + str(cache_dir))
        runtime = CompiledF6Runtime(artifacts=artifacts,
            compiled_inputs=compiled_inputs, base_dir=ROOT,
            cache_dir=cache_dir, run_id=run_id, rounds_per_case=4096,
            max_cases=max_cases, response_fault=response_fault)
        yield runtime
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_error = None
        if runtime is not None and not runtime.finished:
            try:
                runtime.finish()
            except BaseException as error:
                # A preflight-only runtime intentionally has no admitted case.
                # finish() still closes its native sessions, then records this
                # known incomplete-prefix condition in the finish document.
                expected_empty_close = (not runtime.attempts
                    and runtime.finished
                    and type(getattr(runtime, '_finish_document', None)) is dict)
                if not expected_empty_close:
                    cleanup_error = error
        if artifacts is not None:
            try:
                release_f6_provider_credentials(artifacts)
            except BaseException as error:
                if cleanup_error is None:
                    cleanup_error = error
                elif cleanup_error is not error:
                    cleanup_error.add_note('F6 provider credential release: '
                        + repr(error))
        if cleanup_error is not None:
            if primary is not None:
                primary.add_note('native F6 runtime cleanup: ' + repr(cleanup_error))
            else:
                raise cleanup_error


def _effect_state(runtime):
    return dict(cursor=runtime.cursor, record_count=len(runtime.records),
        attempt_count=len(runtime.attempts),
        cpu_event_count=len(runtime.cpu.cpu_events),
        dma_event_count=len(runtime.dma.events),
        cpu_service_event_count=len(runtime.cpu.service.events),
        dma_service_event_count=len(runtime.dma.memory_service.events),
        observer_row_count=len(runtime.observer_view),
        memory=runtime.memory.state_summary(),
        local_ticks=deepcopy(runtime.runner.local_ticks))


def _read_raw_control(name):
    path = INPUTS / 'raw-controls' / name
    if not path.is_file() or path.is_symlink():
        pytest.fail('prepared F6 raw control is missing or unsafe: ' + str(path))
    return path.read_bytes()


def _assert_preflight_refusal(tmp_path, *, control, raw_name, error_code):
    with _opened_native_runtime(tmp_path,
            run_id='task8-f6-preflight-' + control) as runtime:
        before = _effect_state(runtime)
        raw = _read_raw_control(raw_name)
        with pytest.raises(ValueError, match=error_code):
            runtime.submit(raw)
        after = _effect_state(runtime)
        assert before == after
        assert runtime.records == []
        assert runtime.attempts == []
        assert runtime.cursor == 0

        cleanup = None
        try:
            cleanup = runtime.finish()
        except ValueError as error:
            # A zero-attempt prefix is intentionally not a completed F6 run.
            assert runtime.finished and runtime._finish_document is not None
            cleanup = dict(status='closed_without_admitted_case',
                error_type=type(error).__name__, error=str(error))
        assert runtime.finished
        _write_control_evidence('preflight-' + control, dict(
            schema_version='compiled_F6_native_preflight_control.v1',
            control_id=control, raw8_sha256=sha256(raw).hexdigest(),
            expected_refusal=error_code, effect_state_before=before,
            effect_state_after=after, admitted_attempts=runtime.attempts,
            records=runtime.records, cleanup=cleanup))


def test_preconstruction_refuses_source_incompatible_dma_provider_before_runtime_construction(
        tmp_path, monkeypatch):
    """A same-endpoint declaration with an unpinned RTL revision is refused."""
    import subprocess

    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    from myfuzz.local_harness.generated_artifact_admission import (
        release_f6_provider_credentials)
    from myfuzz.scenario.f6_execution_contract import (
        F6ContractRefused, compile_f6_execution_contract)

    artifacts, compiled_inputs = _source_backed_runtime_inputs(tmp_path)
    request = compiled_inputs['request']
    dma = request.devices[0]
    original_source_document = _json_plain(dma.profile.source_document)
    original_revision = dma.profile.source.revision
    incompatible_revision = 'git:0000000000000000000000000000000000000000'
    changed_source_document = deepcopy(original_source_document)
    changed_source_document['revision'] = incompatible_revision
    changed_profile = replace(dma.profile,
        source=replace(dma.profile.source, revision=incompatible_revision),
        source_document=changed_source_document)
    changed_dma = replace(dma, profile=changed_profile)
    from myfuzz.scenario.compiled_paths import _profile_endpoint_sha256
    route_bindings = []
    for route, original_binding in zip(request.wiring.dma_master_routes,
            request.wiring.dma_master_route_bindings):
        binding = _json_plain(original_binding)
        binding['initiator']['profile_endpoint_sha256'] = (
            _profile_endpoint_sha256(changed_dma, route.initiator_endpoint_id))
        route_bindings.append(binding)
    changed_wiring = replace(request.wiring,
        dma_master_route_bindings=tuple(route_bindings))
    changed_request = replace(request, devices=(changed_dma,),
        wiring=changed_wiring)

    launches = []
    original_popen = subprocess.Popen

    def reject_native_process(argv, *args, **kwargs):
        command = [str(part) for part in argv]
        launches.append(command)
        if Path(command[0]).name != 'git':
            raise AssertionError('source-shape refusal attempted a process: '
                + repr(command))
        return original_popen(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, 'Popen', reject_native_process)
    monkeypatch.setattr(CompiledF6Runtime, '__init__',
        lambda *args, **kwargs: pytest.fail(
            'source-incompatible provider reached runtime construction'))
    try:
        with pytest.raises(F6ContractRefused) as caught:
            compile_f6_execution_contract(changed_request, base_dir=ROOT)
        assert caught.value.code == 'f6-source-provider-unsupported'
        assert caught.value.pointer == '/artifacts'
        assert not launches
        _write_control_evidence('source-shape-refusal', dict(
            schema_version='compiled_F6_native_source_shape_refusal.v1',
            control_id='f6-source-shape-refusal',
            refusal=dict(code=caught.value.code, pointer=caught.value.pointer,
                detail=str(caught.value.detail)),
            source_profile='configs/peripherals/zipcpu_wbdmac/component_profile.json',
            source_profile_sha256=sha256(DMA_PROFILE.read_bytes()).hexdigest(),
            prepared_request_sha256=sha256((INPUTS / 'base'
                / 'path_compile_request.json').read_bytes()).hexdigest(),
            original_revision=original_revision,
            incompatible_revision=incompatible_revision,
            profile_endpoints_unchanged=(changed_profile.endpoints
                == dma.profile.endpoints),
            d2_artifacts_loaded=True, runtime_constructed=False,
            native_processes_started=False, launches=launches,
            case_ids=[], replay=None))
    finally:
        release_f6_provider_credentials(artifacts)


def test_preflight_refuses_reserved_operand_before_effects(tmp_path):
    _assert_preflight_refusal(tmp_path, control='reserved-operand',
        raw_name='reserved-bit.raw8', error_code='compiled-F6-layout-reserved-bits')


def test_preflight_refuses_duplicate_operands_before_effects(tmp_path):
    _assert_preflight_refusal(tmp_path, control='duplicate-operands',
        raw_name='duplicate-operands.raw8', error_code='compiled-F6-layout-duplicate-word')


def test_preflight_refuses_two_records_before_effects(tmp_path):
    _assert_preflight_refusal(tmp_path, control='two-records',
        raw_name='two-records.raw8', error_code='compiled-F6-layout-record-length')


_MISSING_CONTROLS = {
    'read_snapshot': dict(reference='read_snapshots', owner='dma',
        kind='memory_read', index=1,
        expectation='dma.word_transfer_join'),
    'destination_commit': dict(reference='word_commits', owner='dma',
        kind='memory_write_commit', index=1,
        expectation='dma.word_transfer_join'),
    'irq': dict(reference='irq', owner='cpu',
        kind='cpu_external_irq_taken', index=None,
        expectation='dma.irq_isr_completion'),
    'mret': dict(reference='return', owner='cpu',
        kind='native_f6_isr_return.v1', index=None,
        expectation='dma.irq_isr_completion'),
    'successor': dict(reference='next_fetch', owner='cpu',
        kind='native_fetch_boundary', index=None,
        expectation='dma.irq_isr_completion'),
}


def _arm_copied_observation_omission(monkeypatch, control):
    """Remove one event from runtime.observer_view after source-backed copying.

    The live CPU, DMA, service, and firmware issuers remain the actual runtime
    owners. Only the runtime's already-copied observation view is changed.
    """
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime

    specification = _MISSING_CONTROLS[control]
    original = CompiledF6Runtime._attempt_references

    def omit_one_copied_row(runtime, attempt, *, start_event_id):
        original(runtime, attempt, start_event_id=start_event_id)
        value = attempt.get(specification['reference'])
        if specification['reference'] == 'next_fetch':
            value = value.get('event_id') if type(value) is dict else None
        elif specification['index'] is not None:
            value = (value[specification['index']]
                if type(value) is list
                and len(value) > specification['index'] else None)
        if type(value) is not int:
            raise AssertionError('source-backed F6 observation was not produced: '
                + control)
        component = (runtime.dma_id if specification['owner'] == 'dma'
            else runtime.cpu_id)
        rows = [row for row in runtime.observer_view
            if row.get('event_id') == value
            and row.get('component') == component]
        rows = [row for row in rows if row.get('kind') == specification['kind']]
        if len(rows) != 1:
            raise AssertionError('copied F6 observation is not unique: '
                + control + ':' + str(len(rows)))
        selected = rows[0]
        copied = deepcopy(selected)
        runtime.observer_view[:] = [row for row in runtime.observer_view
            if row is not selected]
        runtime._task8_removed_copied_observation = dict(
            control=control, component=selected['component'],
            event_id=selected['event_id'], kind=selected['kind'],
            sha256=_digest(copied), row=copied)
        if any(row.get('event_id') == value
                and row.get('component') == selected['component']
                for row in runtime.observer_view):
            raise AssertionError('copied F6 observation survived deliberate omission')

    monkeypatch.setattr(CompiledF6Runtime, '_attempt_references',
        omit_one_copied_row)


def _assert_missing_observation(tmp_path, monkeypatch, *, control):
    specification = _MISSING_CONTROLS[control]
    _arm_copied_observation_omission(monkeypatch, control)
    valid_path = INPUTS / 'raw-controls' / 'valid-record.json'
    if not valid_path.is_file() or valid_path.is_symlink():
        pytest.fail('prepared valid F6 raw record is missing: ' + str(valid_path))
    raw_document = json.loads(valid_path.read_bytes())
    raw = bytes.fromhex(raw_document['raw8_hex'])
    with _opened_native_runtime(tmp_path,
            run_id='task8-f6-missing-' + control) as runtime:
        result = runtime.submit(raw)
        attempt = runtime.attempts[-1]
        assert runtime.records and runtime.cursor == 1
        assert attempt['status_kind'] == 'failed'
        assert attempt['feedback'] == [0] * 5
        assert result['feedback'] == [0] * 5
        observation = attempt['case_material']['observations'][
            specification['expectation']]
        assert observation['status'] == 'missing'
        assert observation['evidence_refs']
        removed = runtime._task8_removed_copied_observation
        assert removed['control'] == control
        assert removed['kind'] == specification['kind']
        prefix = runtime.finish()
        assert prefix['status'] == 'partial'
        assert prefix['attempts'][-1]['status_kind'] == 'failed'
        assert prefix['trace_status'] == 'complete'
        _write_control_evidence('missing-' + control, dict(
            schema_version='compiled_F6_native_missing_observation_control.v1',
            control_id=control, removed_copied_observation=removed,
            original_native_attempt=attempt,
            terminal_prefix=dict(status=prefix['status'], scope=prefix['scope'],
                completed=prefix['completed'], feedback=prefix['feedback']),
            attempted_case_count=len(prefix['attempts'])))


def test_copied_observation_missing_read_snapshot_marks_attempt_and_zero_feedback(
        tmp_path, monkeypatch):
    _assert_missing_observation(tmp_path, monkeypatch, control='read_snapshot')


def test_copied_observation_missing_destination_commit_marks_attempt_and_zero_feedback(
        tmp_path, monkeypatch):
    _assert_missing_observation(tmp_path, monkeypatch, control='destination_commit')


def test_copied_observation_missing_irq_marks_attempt_and_zero_feedback(
        tmp_path, monkeypatch):
    _assert_missing_observation(tmp_path, monkeypatch, control='irq')


def test_copied_observation_missing_mret_marks_attempt_and_zero_feedback(
        tmp_path, monkeypatch):
    _assert_missing_observation(tmp_path, monkeypatch, control='mret')


def test_copied_observation_missing_successor_marks_attempt_and_zero_feedback(
        tmp_path, monkeypatch):
    _assert_missing_observation(tmp_path, monkeypatch, control='successor')


def _fault_declaration(operation):
    from myfuzz.local_harness.f6_dma_response_fault import (
        F6ResponseFaultDeclaration)

    path = INPUTS / 'fault-selectors' / ('middle-' + operation + '.json')
    document = json.loads(path.read_bytes())
    if set(document) != {'case_index', 'operation', 'word_index'}:
        raise AssertionError('prepared response-fault declaration must have its '
            'exact three production fields')
    declaration = F6ResponseFaultDeclaration(**document)
    if declaration.document() != document:
        raise AssertionError('production response-fault declaration changed')
    return declaration


def _require_supervisor_heavy_lock():
    """Fail closed unless the gate supervisor already owns the shared lock."""
    import fcntl

    path = ROOT / '.superpowers/sdd/stage2-heavy-worker.lock'
    if path.is_symlink() or not path.is_file():
        pytest.fail('shared native lock file is missing or unsafe: ' + str(path))
    with path.open('a+b') as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return dict(path=path.relative_to(ROOT).as_posix(),
                supervisor_lock_contended=True)
        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        pytest.fail('native F6 supervisor did not hold the shared heavy lock')


def _run_faulted_unified_attempt(operation, monkeypatch):
    """Run one real unified F6 attempt through the production D1–D4 path."""
    output = _required_path('MYFUZZ_COMPILED_F6_NATIVE_OUTPUT')
    cache = _required_path('MYFUZZ_COMPILED_F6_NATIVE_CACHE')
    evidence = _required_path('MYFUZZ_COMPILED_F6_NATIVE_EVIDENCE')
    if output.exists():
        pytest.fail('native F6 attempt output already exists: ' + str(output))
    if not cache.is_dir():
        pytest.fail('native F6 build cache is missing: ' + str(cache))
    if not RFUZZ_CLIENT.is_file() or RFUZZ_CLIENT.is_symlink():
        pytest.fail('frozen RFuzz client is missing or unsafe: ' + str(RFUZZ_CLIENT))
    if not evidence.is_dir():
        pytest.fail('native F6 evidence root is missing: ' + str(evidence))
    lock_evidence = _require_supervisor_heavy_lock()

    declaration = _fault_declaration(operation)
    import myfuzz.integration.compiled_f6_rfuzz_session as rfuzz_session
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime
    import myfuzz.local_harness.auto_harness_test as auto_harness_test

    original_runtime_type = CompiledF6Runtime

    def faulted_runtime(**kwargs):
        if 'response_fault' in kwargs:
            raise AssertionError('runtime caller already supplied a response fault')
        # The runtime installs the sealed selector and derives its actual
        # execution binding from the admitted D2/D3 topology itself.
        return original_runtime_type(**kwargs, response_fault=declaration)

    monkeypatch.setattr(rfuzz_session, 'CompiledF6Runtime', faulted_runtime)
    # The supervisor holds the repository-wide native lock around this pytest
    # child; do not recursively acquire the same flock from inside the child.
    monkeypatch.setattr(auto_harness_test, '_heavy_worker_lock',
        lambda _base: nullcontext())
    run_id = 'compiled-f6-task8-err-' + operation
    summary = auto_harness_test.run_auto_harness_test(
        cpu=CPU_PROFILE, ips=(DMA_PROFILE,), compose=INPUTS / 'compose.json',
        output=output, base_dir=ROOT, client_binary=RFUZZ_CLIENT,
        cache_dir=cache, budget_seconds=30, max_tests=1, search_seed=1,
        max_runs_per_batch=1, skip_session=False, label=run_id,
        ip_capabilities=(INPUTS / 'test_capability.json',),
        executor='compiled-f6-rfuzz', rounds_per_case=4096,
        f6_execution=INPUTS / 'f6_execution.json',
        f6_deliveries=INPUTS / 'f6_deliveries.json')

    assert summary['label'] == run_id
    assert summary['stages']['session']['scope'] == 'failed_prefix_full'
    assert summary['stages']['session']['completed'] is False
    assert summary['executor']['code'] == 'compiled-f6-expected-error-prefix'
    assert summary['exit_code'] == 1
    prefix_path = output / 'compiled_f6_prefix.json'
    assert prefix_path.is_file()
    prefix = json.loads(prefix_path.read_bytes())
    assert prefix['status'] == 'expected_error'
    assert prefix['scope'] == 'failed_prefix_full'
    assert prefix['completed'] is False
    assert prefix['execution_binding_sha256'] == prefix['binding_sha256']
    assert len(prefix['attempts']) == 1
    assert prefix['feedback'] == [0] * 5
    attempt = prefix['attempts'][0]
    assert attempt['status_kind'] == 'expected_error'
    assert attempt['expected_error'] is True
    assert attempt['feedback'] == [0] * 5

    fault_receipts = []
    for evidence_row in attempt['case_material']['evidence_inventory'].values():
        details = evidence_row.get('details', {})
        for row in details.get('raw_evidence', []):
            receipt = row.get('environment_error_receipt')
            if type(receipt) is dict:
                fault_receipts.append((row, receipt))
    assert len(fault_receipts) == 1
    selected_row, receipt = fault_receipts[0]
    assert receipt['target_effect'] is False
    assert receipt['execution_binding_sha256'] == prefix['execution_binding_sha256']
    assert receipt['selector'] == declaration.document()
    transaction = receipt['source_transaction']
    assert selected_row['accepted']['transaction'] == transaction
    response_rows = []
    for evidence_row in attempt['case_material']['evidence_inventory'].values():
        details = evidence_row.get('details', {})
        for row in details.get('raw_evidence', []):
            if (row.get('kind') == 'dma_edge'
                    and row.get('response', {}).get('transaction') == transaction):
                response_rows.append(row)
    assert len(response_rows) == 1
    assert response_rows[0]['response']['error'] == 1
    assert response_rows[0]['response']['transaction'] == transaction
    assert selected_row.get('kind') == 'dma_edge'
    assert receipt['selector'] == dict(case_index=0, operation=operation,
        word_index=1)
    if operation == 'read':
        assert attempt['read_snapshots'][0] is not None
        assert attempt['read_snapshots'][1] is None
        assert attempt['read_snapshots'][2:] == [None, None]
        assert attempt['word_commits'] == [None] * 4
    else:
        assert all(value is not None for value in attempt['read_snapshots'])
        assert attempt['word_commits'][0] is not None
        assert attempt['word_commits'][1] is None
        assert attempt['word_commits'][2:] == [None, None]
    assert not attempt['readbacks'] and not attempt['results']
    irq = attempt['case_material']['observations']['dma.irq_isr_completion']
    irq_evidence = attempt['case_material']['evidence_inventory'][irq['evidence_refs'][0]]
    completion = irq_evidence['details']['error_completion']
    assert completion['terminal_marker'] == 2
    assert completion['next_address'] == (
        prefix['execution_binding']['runtime_path_admission']['logical_path']
            ['execution_contract']['program_contract']['slot_base'] + 128)

    fresh = json.loads((output / 'compiled_f6_replay.json').read_bytes())
    fresh_prefix = json.loads((output / 'compiled_f6_fresh_prefix.json').read_bytes())
    verification = json.loads((output / 'fresh-verification.json').read_bytes())
    assert fresh['matches'] is True
    assert fresh['verification_scope'] == 'failed_prefix_full'
    assert verification['matches'] is True
    assert verification['verification_scope'] == 'failed_prefix_full'
    assert fresh_prefix['execution_binding_sha256'] == prefix['execution_binding_sha256']
    original_identities = prefix['original_execution_audit']['identities']
    fresh_identities = fresh_prefix['original_execution_audit']['identities']
    assert set(original_identities) == set(fresh_identities)
    assert {row['pid'] for row in original_identities.values()}.isdisjoint(
        {row['pid'] for row in fresh_identities.values()})
    assert {row['execution_nonce'] for row in original_identities.values()}.isdisjoint(
        {row['execution_nonce'] for row in fresh_identities.values()})
    assert (output / 'compiled_f6_fresh_execution_audit.json').is_file()
    assert (output / 'compiled_f6_build_join.v1.json').is_file()
    assert (output / 'compiled_f6_receipt_join.v1.json').is_file()
    assert (output / 'compiled_assertion_results.v1.json').is_file()
    assert (output / 'compiled_assertion_evidence.v1.json').is_file()
    assert (output / 'session' / 'receipts.jsonl').is_file()
    _write_control_evidence('controlled-err-' + operation + '-lock', dict(
        schema_version='compiled_F6_supervisor_lock_observation.v1',
        control_id='f6-controlled-err-middle-' + operation,
        **lock_evidence))
    # The saved auditor runs in the supervisor only, after terminal.json exists.


def test_controlled_read_err_persists_failed_prefix_for_supervisor_audit(monkeypatch):
    _run_faulted_unified_attempt('read', monkeypatch)


def test_controlled_write_err_persists_failed_prefix_for_supervisor_audit(monkeypatch):
    _run_faulted_unified_attempt('write', monkeypatch)
