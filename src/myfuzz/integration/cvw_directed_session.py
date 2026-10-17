"""Run one real directed CVW session and its fresh isolated replay.

This is the CLI-facing half of the CVW session assembly
(:mod:`myfuzz.scenario.cvw_session`).  It starts the real generated CVW and PULP
GPIO harnesses through the assembly's runner factory, boots the core from the
declared boot image over the AHB-Lite memory service, and drives a bounded
directed program that performs real CPU→IP transactions:

1. write ``PADDIR`` and ``GPIOEN`` (full-word APB3 writes),
2. write ``PADOUT = 0x35`` and read it back through the real GPIO RTL,
3. write ``PADOUT = 0x6a`` and read it back,
4. read ``PADIN`` (the externally driven ``gpio_in = 0xa5``) and store it,
5. store the branch-gated success flag.

Every step is the real chain the family declares: CVW's EBU drives its AHB-Lite
external bus, the generated subordinate answers on its beat face, the
``DataflowRouter`` delivers into the real PULP GPIO target's APB3 register
access, and the CPU consumes the target's real read response.  Nothing in this
module synthesizes a device value or a coverage result.

The fresh replay re-runs the same declared assembly on fresh RTL processes and
compares the complete projection (accepted CPU beats, router deliveries, RAM
commits, result words, final target state, instruction-source evidence and the
component identities).  It is a *directed* session, not an RFuzz online campaign:
the saved documents say so, and the capability report is given only the one F4
receipt this run really produced.
"""
from __future__ import annotations

from dataclasses import asdict, is_dataclass
import hashlib
import json
import time
from pathlib import Path

from myfuzz.scenario.cvw_session import (ASSEMBLY_SCHEMA, RESULT_BYTES,
                                         CvwSessionAssembly,
                                         make_cvw_session_assembly)

#: Version of the session report this module writes.
REPORT_SCHEMA = 'cvw_directed_session_report.v1'
#: Version of the single real receipt this session writes beside the report.
RECEIPT_SCHEMA = 'cvw_directed_session_receipt.v1'
#: Version of the complete saved session document.
SESSION_SCHEMA = 'cvw_directed_session.v1'
#: Version of the fresh replay conclusion (the driver's own schema, verbatim).
FRESH_VERIFICATION_SCHEMA = 'fresh_verification.v1'

#: The external pin value the program reads through ``PADIN``.
EXTERNAL_PIN_VALUE = 0xA5
#: The execution bound of one directed run.  The real static chain reaches its
#: success marker in a few thousand CPU steps; the bound is generous but finite.
DEFAULT_MAX_STEPS = 20000
MAX_STEPS = 200000
#: The success/failure words the program writes at ``RESULT + 8``.
SUCCESS_FLAG = 1
FAILURE_FLAG = 0xFFFFFFFF

#: What this session does not claim.  Copied into the report and the session
#: document so a saved run cannot be read as more than it is.
NOT_CLAIMED = (
    'no RFuzz online campaign: no OnlineCaseDecoder, no per-case reserved '
    'instruction window, no coverage-guided search and no mutation feedback',
    'no interrupt consumer (F5) and no DMA provider (F6)',
    'no retirement observation or native IRQ receipt: the AHB-Lite boundary '
    'exports no RVFI port',
    'no persistent multi-case session: one directed case per run',
)

F4_FLOW_ID = 'F4'


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _sha256_text(value) -> str:
    return 'sha256:' + hashlib.sha256(_canonical(value).encode('utf-8')).hexdigest()


def _jsonable(value):
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _compiled_f4_path_id(compiled_document):
    if not isinstance(compiled_document, dict):
        return None
    rows = [row for row in compiled_document.get('paths', ())
            if isinstance(row, dict) and row.get('flow_id') == F4_FLOW_ID
            and row.get('status') == 'executable']
    return rows[0]['path_id'] if len(rows) == 1 else None


def _delivery_rows(router) -> list:
    rows = []
    for row in router.deliveries:
        source = row.get('source_transaction')
        if is_dataclass(source) and not isinstance(source, type):
            source = asdict(source)
        rows.append({
            'device_id': row.get('device_id'),
            'address': row.get('address'),
            'offset': row.get('offset'),
            'write': row.get('write'),
            'byte_enable': row.get('byte_enable'),
            'write_value': row.get('write_value'),
            'read_value': row.get('read_value'),
            'source_sequence': row.get('source_sequence'),
            'source_transaction': _jsonable(source),
        })
    return rows


def _cpu_projection(cpu) -> dict:
    service = getattr(cpu, 'service', None)
    events = list(getattr(service, 'events', ())) if service is not None else []
    writes = [{'address': event.get('address'), 'value': event.get('value'),
               'byte_enable': event.get('byte_enable'),
               'width_bytes': event.get('width_bytes')}
              for event in events if event.get('kind') == 'memory_write']
    return {'accepted_addresses': list(getattr(cpu, 'accepted_addresses', ())),
            'memory_writes': writes,
            'pending_responses': cpu.pending_responses,
            'mmio_write_count': getattr(cpu, 'mmio_write_count', 0),
            'mmio_read_count': getattr(cpu, 'mmio_read_count', 0),
            'instruction_hold_ticks': cpu.instruction_hold_ticks,
            'instruction_hold_addresses': list(cpu.instruction_hold_addresses)}


def _success_state(cpu, result_base: int):
    """Read the program's own termination words from committed RAM.

    The program writes ``RESULT + 0/4/12`` for the two readbacks and the input
    read, and ``RESULT + 8`` for the branch-gated flag (1 success, -1 failure).
    These are the CPU's committed stores, read back through the same persistent
    memory service; no device value is recomputed here.
    """
    values = [cpu.memory.read(result_base + offset, 4,
                              transaction_id=f'cvw-directed-check-{offset}').value
              for offset in (0, 4, 8, 12)]
    flag = values[2]
    state = ('success' if flag == SUCCESS_FLAG else
             'failure' if flag == FAILURE_FLAG else 'incomplete')
    return values, state


def _run_once(*, factory, run_id: str, case_id: str, max_steps: int,
              budget_seconds: float) -> dict:
    """One bounded directed run on fresh RTL; always tears its processes down."""
    runner = factory()
    cpu = runner.sessions['cpu']
    gpio = runner.sessions['gpio']
    source = cpu.instruction_source
    # The assembly object the runner carries is the one declaration of where the
    # program writes its results; the CPU artifact only names the boot base.
    result_base = runner.cvw_boot_image.result
    accepted = []
    started = time.monotonic()
    error = None
    steps = 0
    final = None
    try:
        runner.begin_test(case_id)
        runner.inject_source('gpio', 'gpio_in', EXTERNAL_PIN_VALUE,
                             direction='IP_TO_CPU',
                             action_id='cvw-directed:external-pins')
        for step in range(1, max_steps + 1):
            if time.monotonic() - started > budget_seconds:
                raise TimeoutError(
                    f'directed CVW session exceeded {budget_seconds:.1f}s at step {step}')
            outputs = runner.step('cpu')
            runner.step('gpio')
            steps = step
            if outputs.get('data_req_accepted'):
                accepted.append({'step': step,
                                 'address': outputs.get('data_addr'),
                                 'write': bool(outputs.get('data_write')),
                                 'value': outputs.get('data_wdata'),
                                 'byte_enable': outputs.get('data_be')})
            writes = [event for event in cpu.service.events
                      if event.get('kind') == 'memory_write'
                      and event.get('address') == result_base + 8]
            if writes and cpu.pending_responses == 0:
                break
        else:
            raise RuntimeError(
                'directed CVW session did not commit the success flag within '
                f'{max_steps} CPU steps')
        # One more target clock so the final STEP_GPIO report is the settled state
        # after the last delivered access.
        final = runner.step('gpio')
        values, state = _success_state(cpu, result_base)
        if state != 'success':
            raise RuntimeError(f'directed CVW program terminated {state}: {values!r}')
    except BaseException as exc:
        error = f'{type(exc).__name__}: {exc}'
        raise
    finally:
        runner.finalize()
    elapsed = time.monotonic() - started
    deliveries = _delivery_rows(cpu.router)
    evidence = {
        'run_id': run_id,
        'case_id': case_id,
        'case_kind': 'directed_fixed_image',
        'flow_id': F4_FLOW_ID,
        'direction': 'CPU_TO_IP',
        'elapsed_seconds': elapsed,
        'cpu_steps': steps,
        'local_ticks': dict(runner.local_ticks),
        'result_words': values,
        'result_state': state,
        'external_pin_value': EXTERNAL_PIN_VALUE,
        'final_target_state': {key: final.get(key) for key in
                               ('gpio_out', 'gpio_dir', 'gpio_in_sync', 'rdata')},
        'accepted_beats': accepted,
        'accepted_beat_count': len(accepted),
        'deliveries': deliveries,
        'delivery_count': len(deliveries),
        'cpu': _cpu_projection(cpu),
        'instruction_source': source.evidence(),
        'artifact_digests': {
            'cpu': cpu.artifact.runtime_document.get('artifact_digest'),
            'gpio': gpio.artifact.runtime_document.get('artifact_digest')},
        'identities': {
            'cpu': cpu.identity_document(),
            'gpio': gpio.identity_document(),
            'memory': cpu.memory.identity_document()},
        'error': error,
    }
    return evidence


def _assert_interaction(evidence) -> None:
    """The directed run must really have delivered real CPU→IP transactions."""
    deliveries = evidence['deliveries']
    if not deliveries:
        raise RuntimeError('directed CVW session delivered no CPU→IP transaction')
    if evidence['result_state'] != 'success':
        raise RuntimeError('directed CVW program did not terminate successfully')
    values = evidence['result_words']
    if values[0] != 0x35 or values[1] != 0x6A or values[3] != EXTERNAL_PIN_VALUE:
        raise RuntimeError(f'directed CVW result words are not the declared '
                           f'readbacks: {values!r}')
    writes = [(row['offset'], row['write'],
               row['write_value'] if row['write'] else row['read_value'])
              for row in deliveries]
    expected = [(0, True, 0xFFFFFFFF), (4, True, 0xFFFFFFFF),
                (12, True, 0x35), (12, False, 0x35),
                (12, True, 0x6A), (12, False, 0x6A), (8, False, 0xA5)]
    if writes != expected:
        raise RuntimeError(f'directed CVW delivery sequence differs: {writes!r}')
    if evidence['final_target_state']['gpio_out'] != 0x6A:
        raise RuntimeError('real GPIO target output is not the last PADOUT value')
    if evidence['final_target_state']['gpio_dir'] != 0xFFFFFFFF:
        raise RuntimeError('real GPIO target direction is not the written PADDIR')
    source = evidence['instruction_source']
    if not source['delivered']:
        raise RuntimeError('the declared instruction source never supplied the boot word')
    if source['first_measured_fetch_address'] != evidence['identities']['cpu'][
            'runtime_artifact']['boot_contract']['configured_boot_base']:
        raise RuntimeError('the first measured fetch was not the declared reset vector')
    if source['hold_ticks_before_delivery'] is None:
        raise RuntimeError('the boot word was never held for a measured fetch')


#: Fields that identify *this* run rather than the observed behaviour.  A fresh
#: replay must reproduce the projection below without them.
_VOLATILE_IDENTITY_KEYS = frozenset((
    'execution_id', 'testcase_id', 'process_sequence', 'pid', 'nonce',
    'run_id', 'case_id', 'started_utc', 'finished_utc'))


def _observable_projection(evidence) -> dict:
    def scrub(value):
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()
                    if key not in _VOLATILE_IDENTITY_KEYS}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value
    return {'case_kind': evidence['case_kind'],
            'flow_id': evidence['flow_id'],
            'direction': evidence['direction'],
            'local_ticks': evidence['local_ticks'],
            'result_words': evidence['result_words'],
            'result_state': evidence['result_state'],
            'external_pin_value': evidence['external_pin_value'],
            'final_target_state': evidence['final_target_state'],
            'accepted_beats': scrub(evidence['accepted_beats']),
            'deliveries': scrub(evidence['deliveries']),
            'cpu': {'accepted_addresses': scrub(evidence['cpu']['accepted_addresses']),
                    'memory_writes': scrub(evidence['cpu']['memory_writes']),
                    'mmio_write_count': evidence['cpu']['mmio_write_count'],
                    'mmio_read_count': evidence['cpu']['mmio_read_count'],
                    'instruction_hold_ticks': evidence['cpu']['instruction_hold_ticks'],
                    'instruction_hold_addresses':
                        evidence['cpu']['instruction_hold_addresses']},
            'instruction_source': scrub(evidence['instruction_source']),
            'artifact_digests': evidence['artifact_digests'],
            'identities': scrub(evidence['identities'])}


def _compare(first, fresh) -> dict:
    reference = _observable_projection(first)
    actual = _observable_projection(fresh)
    first_difference = None
    context = None
    if reference != actual:
        for key in reference:
            if reference[key] != actual.get(key):
                first_difference = key
                context = {
                    'first': json.dumps(_jsonable(reference[key]), sort_keys=True,
                                        default=repr)[:4000],
                    'fresh': json.dumps(_jsonable(actual.get(key)), sort_keys=True,
                                        default=repr)[:4000]}
                break
        else:  # pragma: no cover - dict inequality implies a differing key
            first_difference = 'projection'
    events = (len(first['accepted_beats']) + len(first['deliveries'])
              + len(first['cpu']['memory_writes'])
              + len(first['instruction_source']['accepted_beats']) + 1)
    return {'matches': first_difference is None,
            'first_difference': first_difference,
            'difference_context': context,
            'event_count': events,
            'semantic_sha256': _sha256_text(actual),
            'manifest_sha256': _sha256_text(reference),
            'projection': actual}


def _receipt(evidence, *, path_id, assembly_document) -> dict:
    deliveries = evidence['deliveries']
    features = []
    for row in deliveries:
        suffix = ('write' if row['write'] else 'read')
        token = f'cpu:gpio:apb{row["offset"]:02x}_{suffix}'
        if token not in features:
            features.append(token)
    return {
        'schema_version': RECEIPT_SCHEMA,
        'case_kind': evidence['case_kind'],
        'run_id': evidence['run_id'],
        'case_id': evidence['case_id'],
        'flow_id': evidence['flow_id'],
        'direction': evidence['direction'],
        'target_id': 'gpio',
        'path_id': path_id,
        'status': 'complete',
        'candidate_disposition': 'admitted',
        'candidate_disposition_reason': 'rtl_case_committed',
        'local_ticks': dict(evidence['local_ticks']),
        'total_local_ticks': sum(evidence['local_ticks'].values()),
        'coverage_hex': None,
        'violations': [],
        'interaction_new_features': features,
        'interaction_feature_deltas': {token: 1 for token in features},
        'evidence': {
            'accepted_beat_count': evidence['accepted_beat_count'],
            'delivery_count': evidence['delivery_count'],
            'result_words': evidence['result_words'],
            'final_target_state': evidence['final_target_state'],
            'first_measured_fetch_address':
                evidence['instruction_source']['first_measured_fetch_address'],
            'boot_hold_ticks':
                evidence['instruction_source']['hold_ticks_before_delivery'],
            'assembly_sha256': _sha256_text(assembly_document),
        },
    }


def _report(evidence, *, receipt, assembly_document, first_elapsed,
            fresh_elapsed, comparison) -> dict:
    return {
        'schema_version': REPORT_SCHEMA,
        'execution_mode': 'directed_fixed_image',
        'execution_status': 'complete',
        'session_status': 'complete',
        'run_id': evidence['run_id'],
        'tests': 1,
        'statuses': {'complete': 1},
        'elapsed_seconds': first_elapsed + fresh_elapsed,
        'effective_search_seconds': 0.0,
        'mutation_hint_updates': 0,
        'completed_feedback_exchanges': 0,
        'runtime_path_status': 'directed_fixed_image',
        'record_semantics': {
            'case_kind': evidence['case_kind'],
            'candidate_disposition_reason': 'rtl_case_committed',
            'receipt': 'receipts.jsonl',
            'flow_id': evidence['flow_id'],
            'direction': evidence['direction'],
            'search': 'directed fixed-image program; no mutation or coverage feedback'},
        'total_local_ticks_semantics': (
            'the runner\'s per-component local tick counts at the committed '
            'success marker'),
        'clock_model': {
            'cpu': 'generated AHB-Lite CPU driver local tick',
            'gpio': 'generated PULP GPIO APB driver local tick'},
        'assembly': assembly_document,
        'evidence': {
            'cpu_steps': evidence['cpu_steps'],
            'accepted_beat_count': evidence['accepted_beat_count'],
            'delivery_count': evidence['delivery_count'],
            'result_words': evidence['result_words'],
            'final_target_state': evidence['final_target_state'],
            'first_measured_fetch_address':
                evidence['instruction_source']['first_measured_fetch_address'],
            'boot_hold_ticks':
                evidence['instruction_source']['hold_ticks_before_delivery'],
            'artifact_digests': evidence['artifact_digests'],
        },
        'fresh_replay': {'matches': comparison['matches'],
                         'first_difference': comparison['first_difference'],
                         'event_count': comparison['event_count']},
        'receipt': receipt,
        'not_claimed': list(NOT_CLAIMED),
        'generated': True,
    }


def _write_json(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_jsonable(value), sort_keys=True, indent=2,
                               ensure_ascii=False, allow_nan=False) + '\n',
                    encoding='utf-8')
    return path


def run_cvw_directed_session(*, cache_dir, run_id: str, session_dir,
                             generated_artifacts=None, compiled_document=None,
                             budget_seconds: float = 300.0,
                             max_steps: int = DEFAULT_MAX_STEPS) -> dict:
    """Start one real directed CVW→GPIO session, then replay it fresh.

    The caller (the P7-E driver) supplies the D2 generated artifacts it already
    validated; this entry admits them through the assembly's declared
    selection, runs the bounded directed case, re-runs it on fresh processes and
    writes the session directory.  It starts real RTL and must be called inside
    the repository's heavy-worker lock.
    """
    if type(run_id) is not str or not run_id.strip():
        raise ValueError('CVW directed session needs a nonempty run id')
    if type(max_steps) is not int or not 1 <= max_steps <= MAX_STEPS:
        raise ValueError(f'CVW directed session max_steps must be 1..{MAX_STEPS}')
    if type(budget_seconds) not in (int, float) or not 0 < budget_seconds <= 3600:
        raise ValueError('CVW directed session budget must be 0..3600 seconds')
    session_dir = Path(session_dir)
    session_dir.mkdir(parents=True, exist_ok=False)
    assembly: CvwSessionAssembly = make_cvw_session_assembly(
        cache_dir=Path(cache_dir), generated_artifacts=generated_artifacts)
    assembly_document = assembly.document()
    path_id = _compiled_f4_path_id(compiled_document)
    case_id = f'cvw-directed-f4:{run_id}'

    started = time.monotonic()
    first = _run_once(factory=assembly.factory, run_id=run_id, case_id=case_id,
                      max_steps=max_steps, budget_seconds=budget_seconds)
    first_elapsed = time.monotonic() - started
    _assert_interaction(first)

    started = time.monotonic()
    fresh = _run_once(factory=assembly.factory, run_id=run_id,
                      case_id=case_id, max_steps=max_steps,
                      budget_seconds=budget_seconds)
    fresh_elapsed = time.monotonic() - started
    _assert_interaction(fresh)
    comparison = _compare(first, fresh)
    if not comparison['matches']:
        raise RuntimeError(
            'fresh directed CVW replay differs at '
            f'{comparison["first_difference"]}: '
            f'{comparison["difference_context"]}')

    receipt = _receipt(first, path_id=path_id, assembly_document=assembly_document)
    report = _report(first, receipt=receipt, assembly_document=assembly_document,
                     first_elapsed=first_elapsed, fresh_elapsed=fresh_elapsed,
                     comparison=comparison)
    verification = {
        'schema_version': FRESH_VERIFICATION_SCHEMA,
        'matches': comparison['matches'],
        'first_difference': comparison['first_difference'],
        'difference_context': comparison['difference_context'],
        'verification_scope': 'full',
        'event_count': comparison['event_count'],
        'semantic_sha256': comparison['semantic_sha256'],
        'manifest_sha256': comparison['manifest_sha256'],
        'replay_entry': ('myfuzz.integration.cvw_directed_session:'
                         'run_cvw_directed_session'),
        'replayed_from': {'session': str(session_dir),
                          'mode': 'fresh isolated directed re-run'},
        'not_a_substitute_for': (
            'a fresh replay of the directed case is not a new search and '
            'confirms nothing the first run did not record'),
    }
    session_document = {
        'schema_version': SESSION_SCHEMA,
        'run_id': run_id,
        'case_id': case_id,
        'assembly': assembly_document,
        'first': first,
        'fresh': fresh,
        'comparison': {key: value for key, value in comparison.items()
                       if key != 'projection'},
        'elapsed_seconds': {'first': first_elapsed, 'fresh': fresh_elapsed},
        'not_claimed': list(NOT_CLAIMED),
    }

    _write_json(session_dir / 'report.json', report)
    (session_dir / 'receipts.jsonl').write_text(
        json.dumps(_jsonable(receipt), sort_keys=True, ensure_ascii=False,
                   allow_nan=False) + '\n', encoding='utf-8')
    session_path = _write_json(session_dir / 'directed-session.json',
                               session_document)
    return {'schema_version': SESSION_SCHEMA,
            'session_dir': str(session_dir),
            'report': report,
            'receipt': receipt,
            'fresh_verification': verification,
            'assembly': assembly_document,
            'session_document': str(session_path),
            'first': first,
            'fresh': fresh,
            'comparison': {key: value for key, value in comparison.items()
                           if key != 'projection'},
            'tests': 1,
            'elapsed_seconds': {'first': first_elapsed,
                                'fresh': fresh_elapsed}}


__all__ = [
    'DEFAULT_MAX_STEPS', 'EXTERNAL_PIN_VALUE', 'F4_FLOW_ID', 'MAX_STEPS',
    'NOT_CLAIMED', 'REPORT_SCHEMA', 'RECEIPT_SCHEMA', 'SESSION_SCHEMA',
    'run_cvw_directed_session']
