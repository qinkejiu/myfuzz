"""F2 live/fresh orchestration; runtime objects retain all execution authority."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path


def f2_fresh_verification(replay, plan):
    if (type(replay) is not dict or replay.get('matches') is not True
            or replay.get('first_difference', 'absent') is not None
            or replay.get('verification_scope') != 'full'):
        raise ValueError('compiled-F2-rfuzz-full-fresh-required')
    if (type(replay.get('actual_prefix')) is not dict
            or type(replay.get('actual_events')) is not list
            or type(replay.get('execution_audit')) is not dict
            or replay['execution_audit'].get('closed') is not True):
        raise ValueError('compiled-F2-rfuzz-fresh-material-required')
    if (type(replay.get('scope')) is not str or not replay['scope']
            or replay.get('actual_semantic_hash') != plan.get('semantic_hash')):
        raise ValueError('compiled-F2-rfuzz-full-fresh-identity-required')
    return dict(schema_version='fresh_verification.v1', matches=replay['matches'],
        first_difference=replay['first_difference'],
        verification_scope=replay['verification_scope'], verification_scope_basis=replay['scope'],
        expected_semantic_hash=replay.get('expected_semantic_hash'),
        actual_semantic_hash=replay['actual_semantic_hash'], semantic_sha256=plan['semantic_hash'],
        record_count=len(plan['records']), event_count=len(replay['actual_events']),
        fresh_process_identities=deepcopy(replay['execution_audit'].get('identities')),
        original_process_identities=deepcopy(replay.get('original_execution_audit', {}).get('identities')),
        replay_entry='myfuzz.integration.compiled_f2_rfuzz:run_compiled_f2_rfuzz_session',
        replayed_from={'compiled_prefix': 'compiled_f2_prefix.json'},
        transport_scope='raw8 is retained transport evidence; projected4 selects admitted RTL cases')


def pin_f2_session_files(session_dir):
    session = Path(session_dir)
    required = ('seed.bin', 'receipts.jsonl', 'online_session_manifest.json', 'online_plan.json')
    for name in required:
        if not (session / name).is_file():
            raise ValueError('compiled-F2-rfuzz-transport-file-required:' + name)
    if not any((session / name).is_file() for name in
               ('online_final_trace.json', 'online_events.jsonl', 'online_events.zlib')):
        raise ValueError('compiled-F2-rfuzz-transport-file-required:original-trace')
    return {str(path): sha256(path.read_bytes()).hexdigest()
            for path in sorted(session.rglob('*')) if path.is_file()}


from .compiled_f2 import CompiledF2Runtime
from .compiled_f2_rfuzz import build_compiled_f2_rfuzz_executor, f2_seed_record
from .compiled_f2_build_join import build_compiled_f2_build_join, verify_compiled_f2_build_join
from .compiled_process_audit import diagnostic_build_snapshot
from .compiled_runtime_report import capture_f2_report_material
from .compiled_f2_saved_outputs import write_pinned_json, expected_f2_documents, save_f2_replay_outputs
from .scenario_rfuzz_live import run_scenario_rfuzz_live
from myfuzz.scenario.compiled_paths import compiled_document_sha256


def join_compiled_f2_receipts(*args, **kwargs):
    from .compiled_f2_receipts import join_compiled_f2_receipts as join
    return join(*args, **kwargs)


def run_f2_live_and_fresh(*, artifacts, compiled_inputs, base_dir, cache_dir,
        run_id, session_dir, output_dir, client_binary, budget_seconds, max_tests,
        search_seed, max_runs_per_batch, rounds_per_case=128):
    """Run one admitted runtime, then a distinct full fresh replay.

    The driver owns the heavy-worker lock. Constructor failures retain only
    diagnostics actually supplied by the construction sink, without a binding.
    """
    if type(rounds_per_case) is not int or not 1 <= rounds_per_case <= 4096:
        raise ValueError('compiled-F2-rfuzz-rounds-per-case-invalid')
    if type(max_tests) is not int or max_tests < 1:
        raise ValueError('compiled-F2-rfuzz-max-tests-invalid')
    cache, output, session = Path(cache_dir), Path(output_dir), Path(session_dir)
    if not cache.is_dir():
        raise ValueError('compiled-F2-rfuzz-build-cache-required')
    runtime = None
    primary = None
    snapshots = {'original': {}, 'fresh': {}}
    pins = {}
    def save_original(snapshot):
        snapshots['original'] = deepcopy(snapshot)
    def make_join(error=None):
        binding = None
        if runtime is not None:
            try:
                binding = runtime.execution_binding.document()
            except BaseException as export_error:
                if error is None:
                    raise
                error.add_note('compiled-F2 binding diagnostic: ' + repr(export_error))
            try:
                snapshots['original'] = diagnostic_build_snapshot(runtime,
                    previous=snapshots['original'], error=error)
            except BaseException as export_error:
                if error is None:
                    raise
                error.add_note('compiled-F2 build diagnostic: ' + repr(export_error))
        return build_compiled_f2_build_join(artifacts=artifacts,
            execution_binding=binding,
            compiled_document_sha256=compiled_document_sha256(compiled_inputs['compiled']),
            runtime_path_id=binding.get('runtime_path_id') if binding else None,
            logical_path_id=binding.get('path_id') if binding else None,
            original=snapshots['original'], fresh=snapshots['fresh'], error=error)
    def save_fresh(envelope):
        for source, destination in (('original_build', 'original'), ('fresh_build', 'fresh')):
            if envelope.get(source) is not None:
                snapshots[destination] = deepcopy(envelope[source])
        save_f2_replay_outputs(output, envelope, pins)
    try:
        runtime = CompiledF2Runtime(artifacts=artifacts, compiled_inputs=compiled_inputs,
            base_dir=Path(base_dir), cache_dir=cache, run_id=run_id,
            rounds_per_case=rounds_per_case, max_cases=min(max_tests * 8 + 8, 65536),
            build_audit_sink=save_original)
        executor = build_compiled_f2_rfuzz_executor(runtime, run_id=run_id)
        live = run_scenario_rfuzz_live(executor=executor, client_binary=Path(client_binary),
            output_dir=session, duration_seconds=budget_seconds,
            seed_records=(f2_seed_record(runtime.path),), max_tests=max_tests,
            search_seed=search_seed, max_runs_per_batch=max_runs_per_batch)
        verify_f2_live_commitment(session, executor=executor)
        validate_f2_session_material(session, runtime=runtime, seed_record=f2_seed_record(runtime.path))
        transport_pins = pin_f2_session_files(session)
        if live.client_returncode != 0:
            raise ValueError('compiled-F2-rfuzz-client-failed')
        plan = runtime.finish()
        write_pinned_json(output/'compiled_f2_prefix.json', plan, pins)
        replay = runtime.replay(plan, audit_sink=save_fresh)
        verification = f2_fresh_verification(replay, plan)
        join = join_compiled_f2_receipts(session/'receipts.jsonl',
            compiled_inputs=compiled_inputs, runtime=runtime, executor=executor,
            plan=plan, replay=replay)
        build_join = make_join()
        verify_compiled_f2_build_join(build_join, artifacts=artifacts,
            execution_binding=runtime.execution_binding.document(),
            original=snapshots['original'], fresh=snapshots['fresh'])
        harness_set = json.loads((output/'generated/harness_set.json').read_bytes())
        material = capture_f2_report_material(compiled=compiled_inputs['compiled'],
            runtime=runtime, harness_set=harness_set, fresh_verification=verification)
        outcome = dict(live=live, plan=plan, replay=replay, verification=verification,
            join=join, executor=executor, runtime=runtime, build_join=build_join,
            assertion_material=material, saved_output_hashes=pins,
            transport_files=transport_pins)
        for name, value in expected_f2_documents(outcome).items():
            if name not in pins:
                write_pinned_json(output/name, value, pins)
        # Check original session bytes again after replay and exports.
        for filename, digest in transport_pins.items():
            if sha256(Path(filename).read_bytes()).hexdigest() != digest:
                raise ValueError('compiled-F2-rfuzz-transport-bytes-changed:' + filename)
        return outcome
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_only = None
        if runtime is not None and not runtime.finished:
            try:
                runtime.finish()
            except BaseException as cleanup:
                if primary is None:
                    primary = cleanup
                    cleanup_only = cleanup
                else:
                    primary.add_note('compiled-F2 runtime cleanup: ' + repr(cleanup))
        if primary is not None:
            # Every exporter is independent; failures must not suppress the rest.
            exports = [('compiled_f2_build_join.v1.json', lambda:make_join(primary))]
            if runtime is not None:
                exports += [
                    ('compiled_f2_partial_events.json', lambda:list(runtime.runner.events_since(0))),
                    ('compiled_assertion_results.v1.json', lambda:runtime.assertion_results()),
                    ('compiled_assertion_evidence.v1.json', lambda:dict(
                        execution_binding=runtime.execution_binding.document(),
                        path_id=runtime.path['path_id'], run_id=runtime.run_id,
                        cases=runtime.assertion_case_evidence())),
                    ('compiled_f2_execution_audit.json', lambda:runtime.execution_audit())]
            for name, capture in exports:
                try:
                    write_pinned_json(output/name, capture(), pins)
                except BaseException as export_error:
                    primary.add_note('compiled-F2 failure export: ' + repr(export_error))

        if cleanup_only is not None:
            raise cleanup_only


from .scenario_rfuzz_live import _verify_online_run_identity as verify_online_run_identity


def validate_f2_session_material(session_dir, *, runtime, seed_record):
    """Compare saved live inputs and original trace to their same-call sources."""
    from itertools import zip_longest
    from myfuzz.scenario.event_journal import canonical_json_chunks, JsonlEventView, ZlibChunkEventView
    session = Path(session_dir)
    canonical = lambda value:json.dumps(value, sort_keys=True, separators=(',', ':'),
                                        ensure_ascii=False, allow_nan=False).encode()
    if (session/'seed.bin').read_bytes() != seed_record:
        raise ValueError('compiled-F2-rfuzz-same-call-seed-mismatch')
    if canonical(json.loads((session/'online_session_manifest.json').read_bytes())) != canonical(runtime.session.manifest_document):
        raise ValueError('compiled-F2-rfuzz-same-call-manifest-mismatch')
    if (session/'online_plan.json').read_bytes() != runtime.session.encode_plan():
        raise ValueError('compiled-F2-rfuzz-same-call-plan-mismatch')
    trace = runtime.trace
    json_path = session/'online_final_trace.json'
    if json_path.is_file():
        saved = json.loads(json_path.read_bytes())
        digest = sha256()
        for fragment in canonical_json_chunks(trace):
            digest.update(fragment.encode())
        if sha256(canonical(saved)).digest() != digest.digest():
            raise ValueError('compiled-F2-rfuzz-same-call-trace-mismatch')
        trace_path = json_path
    else:
        trace_path = session/'online_final_trace.meta.json'
        metadata = json.loads(trace_path.read_bytes())
        if any(metadata.get(key) != getattr(trace, key) for key in
               ('genome_sha256', 'status', 'local_ticks', 'semantic_sha256', 'manifest_sha256')):
            raise ValueError('compiled-F2-rfuzz-same-call-trace-metadata-mismatch')
        if metadata.get('event_count') != len(trace.events):
            raise ValueError('compiled-F2-rfuzz-same-call-trace-count-mismatch')
        kind = metadata.get('schema_version')
        if kind == 'online_trace_jsonl.v1':
            events = JsonlEventView(session/'online_events.jsonl', len(trace.events))
        elif kind == 'online_trace_zlib_chunks.v1':
            events = ZlibChunkEventView(session/'online_events.zlib', len(trace.events))
        else:
            raise ValueError('compiled-F2-rfuzz-same-call-trace-format-unsupported')
        missing = object()
        for actual, saved in zip_longest(trace.events, events, fillvalue=missing):
            if actual is missing or saved is missing or canonical(actual) != canonical(saved):
                raise ValueError('compiled-F2-rfuzz-same-call-trace-event-mismatch')
    if verify_online_run_identity(session, plan_path=session/'online_plan.json',
                                  trace_path=trace_path, trace=trace) is None:
        raise ValueError('compiled-F2-rfuzz-same-call-run-identity-required')


def verify_f2_live_commitment(session_dir, *, executor):
    """Require the live writer's in-memory byte commitments before first pins."""
    context = getattr(executor, '_live_context', None)
    commitment = context.get('online_artifact_commitment') if type(context) is dict else None
    if type(commitment) is not dict or type(commitment.get('artifacts')) is not dict:
        raise ValueError('compiled-F2-rfuzz-live-initial-bytes-required')
    session = Path(session_dir)
    expected = dict(commitment['artifacts'])
    expected['online_run_identity.json'] = commitment.get('identity_file_sha256')
    for name, digest in expected.items():
        path = session/name
        if (Path(name).is_absolute() or '..' in Path(name).parts
                or path.is_symlink() or not path.resolve().is_relative_to(session.resolve())
                or not path.is_file() or sha256(path.read_bytes()).hexdigest() != digest):
            raise ValueError('compiled-F2-rfuzz-live-initial-bytes-changed:' + str(name))
