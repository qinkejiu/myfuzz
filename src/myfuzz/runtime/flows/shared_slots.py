"""Public descriptor adapter for the existing joint CPU/storage/DMA runtime.

This adapter owns no CPU, memory or runner. Each choice is lowered and consumed
before the selector is asked for another choice; fresh replay uses the sealed
flow ledger and the runtime's original native evidence contracts.
"""
from pathlib import Path
import json
import time


class SharedSlotFlowKernel:
    kernel_id = 'typed_online_storage_DMA_slots.v1'

    def __init__(self, runtime):
        from ...integration.compiled_f6 import CompiledF6Runtime
        if type(runtime) is not CompiledF6Runtime or 'shared_slots' not in runtime.contract['program_contract']:
            raise ValueError('shared-slot-kernel-requires-joint-runtime')
        self.runtime = runtime

    def submit(self, record):
        if type(record) is not str or ':' not in record:
            raise ValueError('shared-slot-record-required')
        flow, raw = record.split(':', 1)
        if flow not in self.runtime.contract['program_contract']['shared_slots']['enabled_flows']:
            raise ValueError('shared-slot-flow-unsupported')
        return self.runtime.submit(bytes.fromhex(raw), flow=flow)


def _shared_elaboration_mode(mode, case_root):
    """Select once, or reuse the accepting original's declared frontend."""
    from ...composition.component_profile import supervisor_available
    if mode == 'fresh':
        original = Path(case_root) / 'original'
        try:
            summary = json.loads((original / 'summary.json').read_text())
            recorded = json.loads((original / 'elaboration-mode.json').read_text())
        except (OSError, ValueError) as error:
            raise ValueError('shared-slot-original-elaboration-mode-missing') from error
        selected = summary.get('effective_elaboration_mode')
        if summary.get('shared_slots') is not True or selected not in ('direct', 'supervised'):
            raise ValueError('shared-slot-original-elaboration-mode-missing')
        if recorded.get('effective_elaboration_mode') != selected:
            raise ValueError('shared-slot-original-elaboration-mode-mismatch')
        if selected == 'supervised':
            available, reason = supervisor_available()
            if not available:
                raise ValueError('shared-slot-elaboration-supervisor-unavailable:' + reason)
        return selected
    if mode != 'original':
        raise ValueError('shared-slot-elaboration-mode-invalid')
    return 'supervised' if supervisor_available()[0] else 'direct'


def _finish_failed_runtime(runtime, error):
    """Retain the real campaign failure while exporting its completed trace."""
    if getattr(runtime, '_terminal_error', None) is None:
        runtime._terminal_error = error
    try:
        runtime.finish()
    except BaseException:
        pass
    return getattr(runtime, '_finish_document', None)


def run_shared_slot_descriptor(descriptor, *, cases, mode, case_root, base, cache,
        rounds, capacity, execution_mode, max_wall_seconds, record_selector,
        selected_count, expected_records, command_trace):
    from ..generic_campaign import _json, _requires_replay, _verification
    from ..preparation import create_preparation
    from ...integration.compiled_f6 import CompiledF6Runtime
    from ...local_harness.build import host_source_discovery_scope, harness_validation_scope
    from ...local_harness.execution_validation import execution_validation_scope
    from ...composition.component_profile import elaboration_mode_scope
    out = Path(case_root) / mode
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'prefix.json').exists():
        raise ValueError('shared-slot-output-exists')
    capabilities = descriptor.capability if isinstance(descriptor.capability, tuple) else (descriptor.capability,)
    runtime = preparation = None
    stage = 'elaboration_mode'
    effective_mode = None
    started = time.monotonic()
    executed = []
    last_result = None
    requested = selected_count if record_selector is not None else len(cases)
    if not 1 <= capacity <= 16 or not 1 <= requested <= capacity:
        raise ValueError('shared-slot-case-capacity')
    try:
        effective_mode = _shared_elaboration_mode(mode, case_root)
        _json(dict(schema_version='shared_slot_elaboration_mode.v1',
            effective_elaboration_mode=effective_mode), out / 'elaboration-mode.json')
        stage = 'preparation'
        # The frontend choice must outlive execution validation's exit callbacks.
        with elaboration_mode_scope(effective_mode), host_source_discovery_scope(reuse_nested=True), harness_validation_scope(), execution_validation_scope():
            preparation = create_preparation(base_dir=base, compose_path=descriptor.compose,
                capability_paths=capabilities, supplement_path=descriptor.supplement,
                generated_dir=out / 'generated', flow_ids=descriptor.flow_ids)
            preparation.assert_current()
            stage = 'constructor'
            runtime = CompiledF6Runtime(artifacts=dict(preparation.artifacts),
                compiled_inputs=preparation.compiled_inputs(), base_dir=base, cache_dir=cache,
                run_id=descriptor.scenario_id+'-mixed', rounds_per_case=rounds,
                max_cases=capacity, defer_begin=True)
            observation_only = getattr(runtime, '_custom_online', False)
            if observation_only and (record_selector is not None or command_trace is not None):
                raise ValueError('shared-slot-custom-observation-selector-and-command-audit-not-integrated')
            if runtime.contract['program_contract']['slot_count'] < capacity:
                raise ValueError('shared-slot-program-capacity')
            prepared = runtime.session._runtime_prepared
            preparation.attach_runtime(runner=runtime.runner, sessions=dict(runtime.runner.sessions))
            preparation.register_prepared_paths(prepared=prepared,
                runtime_paths=prepared.runtime_paths, graph=prepared.graph)
            _json(runtime.execution_binding, out / 'binding.json')
            kernel = SharedSlotFlowKernel(runtime)
            if record_selector is not None and callable(getattr(record_selector, 'attach_runtime', None)):
                record_selector.attach_runtime(runtime)
            stage = 'begin'
            runtime.begin()
            execution_started = time.monotonic()
            if callable(getattr(record_selector, 'start_search_clock', None)):
                record_selector.start_search_clock(time.monotonic, execution_started)
            for index in range(requested):
                if executed and max_wall_seconds is not None and time.monotonic()-execution_started >= max_wall_seconds:
                    break
                record = (record_selector.choose() if record_selector is not None
                    else cases[index][0]+':'+cases[index][1])
                if expected_records is not None and record != expected_records[index]:
                    raise ValueError('shared-slot-replay-choice-mismatch')
                preparation.assert_current()
                stage = 'submit:'+str(index)
                certificate = kernel.submit(record)
                last_result = certificate
                accepted = (not observation_only and certificate.get('status') in ('passed', 'certified'))
                observed = (observation_only and certificate.get('status') == 'observed'
                    and certificate.get('next_fetch_observed') is True
                    and certificate.get('certificate') == 'not_granted'
                    and certificate.get('reward_eligible') is False)
                if not (accepted or observed):
                    raise ValueError('shared-slot-case-not-certified')
                executed.append(record)
                _json(dict(records=executed), out / 'case_sequence.actual.json')
                if record_selector is not None:
                    record_selector.settle(record)
            if callable(getattr(record_selector, 'finish_search_clock', None)):
                record_selector.finish_search_clock()
            execution_seconds = max(0, time.monotonic()-execution_started)
            finish_export_started = time.monotonic()
            stage = 'finish'
            prefix = runtime.finish()
            # compiled_f6_prefix.json is the byte-identical duplicate of the
            # prefix document, so it is published from the same render.  The
            # rendered text is dropped once both files exist: the replay below
            # needs the memory more than the 200 MB string.
            prefix_bytes = _json(prefix, out / 'prefix.json')
            _json(prefix, out / 'compiled_f6_prefix.json', rendered=prefix_bytes)
            prefix_bytes = None
            _json(getattr(runtime, 'shared_storage_raw', {}), out / 'shared_storage_raw.json')
            _json(getattr(runtime, 'shared_read_raw', {}), out / 'shared_read_raw.json')
            finish_export_seconds = max(0, time.monotonic()-finish_export_started)
            replay = None
            replay_seconds = 0
            if _requires_replay(execution_mode, mode):
                replay_started = time.monotonic()
                stage = 'fresh_replay'
                # replay() hands its final envelope to this sink before it
                # returns the same envelope.  Publish it once without keeping
                # the large rendered string alive through the replay return.
                audited = False

                def publish_audit(value):
                    nonlocal audited
                    _json(value, out / 'replay.json')
                    audited = True

                replay = runtime.replay(prefix, audit_sink=publish_audit)
                if not audited:
                    _json(replay, out / 'replay.json')
                replay_seconds = max(0, time.monotonic()-replay_started)
                if replay.get('matches') is not True:
                    raise ValueError('shared-slot-fresh-mismatch')
            matches = replay.get('matches') if replay else None
            summary = dict(scenario=descriptor.scenario_id, flow='mixed', mode=mode,
                backend=kernel.kernel_id, execution_mode=execution_mode, shared_slots=True,
                effective_elaboration_mode=effective_mode,
                f6_case_count=(sum(row['flow']=='F6' for row in prefix['flow_records'])
                    if observation_only else len(prefix['records'])),
                f4_case_count=sum(row['flow']=='F4' for row in prefix['flow_records']),
                flow_case_counts={flow:sum(row['flow']==flow for row in prefix['flow_records'])
                    for flow in descriptor.flow_ids},
                verification=_verification(matches, mode), replay_matches=matches,
                replay_scope='within_invocation' if replay is not None else 'not-requested', evidence_dir=str(out),
                plan_identity_sha256=runtime.execution_binding_sha256,
                execution_case_capacity=capacity, case_count=len(executed),
                requested_case_count=requested, budget_ended=len(executed)<requested,
                first_case_always_admitted=True, max_wall_seconds=max_wall_seconds,
                execution_seconds=execution_seconds, rounds_per_case=rounds,
                finish_export_seconds=finish_export_seconds, replay_seconds=replay_seconds,
                wall_budget_overrun_seconds=max(0, execution_seconds-max_wall_seconds) if max_wall_seconds is not None else 0,
                execution_timing_scope='campaign_loop_only',
                finish_export_timing_scope='finish_prefix_and_command_trace_exports',
                replay_timing_scope='within_invocation_replay_and_replay_export',
                wall_timing_scope='entry_through_scope_exit_and_preparation_close')
            if observation_only:
                summary.update(evidence_status='unknown',certificate='not_granted',
                    reward_eligible=False,verification_scope='replay_only')
            export_started = time.monotonic()
            if command_trace is not None:
                from ..recorded_commands import recorded_command_documents
                identities = {'original': prefix['original_execution_audit']['identities']}
                if replay:
                    identities['fresh'] = replay['execution_audit']['identities']
                docs = recorded_command_documents(command_trace.export_sessions(), scope='mixed',
                    audited=True, executions=identities)
                for name, doc in docs.items():
                    filename = 'local_commands.json' if name == 'original' else name+'_local_commands.json'
                    _json(doc, out / filename)
            summary['finish_export_seconds'] += max(0, time.monotonic()-export_started)
    except BaseException as error:
        failure = dict(stage=stage, error_type=type(error).__name__, error=str(error),
            records=executed, actual_result=last_result, effective_elaboration_mode=effective_mode,
            observations=(last_result.get('observations') if isinstance(last_result, dict) else None))
        if hasattr(error, 'timeout_diagnostic'):
            failure['timeout_diagnostic'] = error.timeout_diagnostic
        if runtime is not None:
            runner = runtime.runner
            failure.update(failure_status=runner.failure_status,
                events=list(runner.events_since(max(0, runner.event_count-40))))
            partial = _finish_failed_runtime(runtime, error)
            if partial is not None:
                _json(partial, out / 'partial_prefix.json')
        _json(failure, out / 'failure.json')
        raise
    finally:
        if preparation is not None:
            preparation.close()
    summary['wall_seconds'] = max(0, time.monotonic()-started)
    _json(summary, out / 'summary.json')
    return summary
