#!/usr/bin/env python3
"""Run one same-preparation CPU/storage/DMA session and a full fresh replay."""
import argparse
import json
from pathlib import Path
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def failure_diagnostic(runtime):
    runner = runtime.runner
    count = runner.event_count
    return dict(failure_status=runner.failure_status,
        runner_status=runner._status, local_ticks=dict(runner.local_ticks),
        event_count=count, events=list(runner.events_since(max(0, count-40))))


def execute_original_fresh(runtime, records, output, checkpoint):
    checkpoint('original_begin')
    runtime.begin()
    for index, raw in enumerate(records):
        checkpoint('original_submit', record_index=index)
        runtime.submit(bytes.fromhex(raw))
    checkpoint('original_finish')
    prefix = runtime.finish()
    # Preserve the completed original before any fresh execution can fail.
    write_json(output / 'prefix.json', prefix)
    write_json(output / 'storage_support_raw.json', getattr(runtime, 'storage_support_raw', {}))
    checkpoint('fresh_replay')
    replay = runtime.replay(prefix, audit_sink=lambda envelope: write_json(output / 'replay.json', envelope))
    write_json(output / 'replay.json', replay)
    if replay.get('matches') is not True:
        raise RuntimeError('fresh replay mismatch: ' + str(replay.get('first_difference')))
    return prefix, replay


def run(args, state, checkpoint):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.integration.compiled_f6 import CompiledF6Runtime, _f6_runner_ownership
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.integration.shared_f6_assembly import build_f6_assembly
    root, output = args.root.resolve(), args.output.resolve()
    cache = args.cache.resolve() if args.cache is not None else output / 'cache'
    config = root / 'configs/scenarios/compiled-f6-ibex-wbdmac-storage'
    case = json.loads((config / 'assembly_case.json').read_text())
    preparation = None
    runtime = None
    try:
        checkpoint('preparation')
        preparation = create_preparation(base_dir=root, compose_path=config / case['compose'],
            capability_paths=tuple(root / path for path in case['capabilities']),
            supplement_path=config / case['supplement'], generated_dir=output / 'generated', flow_ids=('F6',))
        preparation.assert_current()
        inputs, artifacts = preparation.compiled_inputs(), dict(preparation.artifacts)
        checkpoint('assembly')
        admission = admit_compiled_f6_runtime_path(artifacts=artifacts, compiled_inputs=inputs, base_dir=root)
        contract = admission['execution_contract']
        ownership = _f6_runner_ownership(inputs['ownership'], cpu_id=contract['cpu']['instance_id'],
            dma_id=contract['dma']['instance_id'])
        assembly = build_f6_assembly(contract=contract, artifacts=artifacts, request=inputs['request'],
            ownership=ownership, base_dir=root, cache_dir=cache)
        state.update(components=sorted(assembly.runner.sessions),
            evidence_scope='fixed_CPU_storage_support_and_F6_not_dynamic_F4_F6_selector',
            cross_case_relation='not_claimed')
        if not args.native:
            state.update(native_executed=False)
            return
        checkpoint('constructor')
        runtime = CompiledF6Runtime(artifacts=artifacts, compiled_inputs=inputs,
            base_dir=root, cache_dir=cache, run_id='f6-storage-shared',
            rounds_per_case=case['rounds'], max_cases=case['max_cases'],
            shared_assembly=assembly, defer_begin=True)
        assert runtime.runner is assembly.runner and runtime.cpu is assembly.cpu
        assert runtime.memory is assembly.memory and runtime.dma.memory_service.memory is assembly.memory
        prefix, replay = execute_original_fresh(runtime, case['records'], output, checkpoint)
        phases = prefix.get('storage_support', {}).get('phases', {})
        if set(phases) != {'before', 'after'} or any(row.get('status') != 'verified' for row in phases.values()):
            raise RuntimeError('both fixed CPU storage phases must be verified')
        state.update(native_executed=True, injected_owners_used=True,
            original_status=prefix['status'], fresh_matches=replay['matches'],
            storage_values={phase: row['value'] for phase, row in phases.items()})
    except BaseException:
        if runtime is not None:
            try:
                write_json(output / 'partial_execution.json', dict(
                    records=getattr(runtime, 'records', []), attempts=getattr(runtime, 'attempts', []),
                    finish_document=getattr(runtime, '_finish_document', None),
                    storage_support=getattr(runtime, 'storage_support_evidence', {}),
                    runner_diagnostic=failure_diagnostic(runtime)))
            except BaseException as export_error:
                state['partial_export_error'] = str(export_error)
        raise
    finally:
        if runtime is not None and not runtime.finished:
            try:
                runtime.session.finish()
            except BaseException as cleanup:
                state['cleanup_error'] = dict(type=type(cleanup).__name__, message=str(cleanup))
        if preparation is not None:
            preparation.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, help='Reuse an existing build cache (default: output/cache).')
    parser.add_argument('--native', action='store_true')
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    state = dict(schema_version='shared_f6_storage_run.v1', status='running', stage='created')
    def checkpoint(stage, **fields):
        state.update(stage=stage, **fields)
        write_json(args.output / 'summary.json', state)
    checkpoint('created')
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    try:
        with host_source_discovery_scope(reuse_nested=True), harness_validation_scope(), execution_validation_scope():
            run(args, state, checkpoint)
        state.update(status='complete', validation='verified')
        checkpoint('complete')
    except BaseException as error:
        state.update(status='failed', failed_stage=state['stage'],
            error=dict(type=type(error).__name__, message=str(error)))
        write_json(args.output / 'summary.json', state)
        (args.output / 'failure.txt').write_text(traceback.format_exc())
        raise
    print(json.dumps(state, sort_keys=True))


if __name__ == '__main__':
    main()
