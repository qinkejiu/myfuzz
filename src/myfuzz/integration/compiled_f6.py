"""Persistent same-call CPU-programmed F6 runtime and scope coordinator."""

from copy import deepcopy
from dataclasses import asdict
from hashlib import sha256
import json
import math
import re
from contextlib import contextmanager
from contextvars import ContextVar

_TOPOLOGY_VALIDATION_MODE = ContextVar('f6_topology_validation_mode', default='boundary')


@contextmanager
def f6_topology_validation_scope(mode):
    """Same-source A/B selection; never changes proof or workload documents."""
    if mode not in ('legacy', 'boundary'):
        raise ValueError('F6 topology mode must be legacy or boundary')
    token = _TOPOLOGY_VALIDATION_MODE.set(mode)
    try:
        yield
    finally:
        _TOPOLOGY_VALIDATION_MODE.reset(token)


from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.integration.compiled_f4 import _borrow_events
from myfuzz.integration.compiled_process_audit import (
    BuiltProcessAudit, capture_build_construction, diagnostic_build_snapshot)
from myfuzz.integration.compiled_f6_irq import f6_dma_irq_runtime_name

_F6_OBSERVER_KINDS = frozenset({
    'cpu_external_irq_sample', 'cpu_external_irq_taken', 'cpu_irq_notification',
    'cpu_retire', 'data_accept', 'data_response', 'instr_response',
    'memory_read', 'memory_read_issuance', 'memory_write',
    'memory_write_commit', 'mmio_acceptance', 'mmio_delivery', 'dma_edge',
    'instruction_source', 'compiled_F6_instruction_fetch_completion',
})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False)


def _digest(value):
    return sha256(_canonical(value).encode('utf-8')).hexdigest()


def _documents_equal(left, right):
    """Canonical equality of two prefix documents, compared per top section.

    ``_canonical`` equality of the whole document is defined key by key, so
    comparing the rendered sections produces the same verdict while never
    holding two 200 MB render strings at once; a differing section stops the
    comparison at the same first-key position the whole-document render would
    have shown as different.
    """
    if type(left) is not dict or type(right) is not dict:
        return _canonical(left) == _canonical(right)
    if left is right:
        # The common replay entry passes finish()'s exact owned document back
        # to finish().  Validate every section once (including NaN and JSON
        # shape failures), without encoding the same object a second time.
        for name in sorted(left):
            _canonical(left[name])
        return True
    if set(left) != set(right):
        return False
    return all(_canonical(left[name]) == _canonical(right[name])
        for name in sorted(left))


def _compiled_f6_case_advances(cpu_id, dma_id, rounds, *, schedule_order=None):
    """Keep CPU-before-DMA order with a stop/failure boundary after each step."""
    from myfuzz.scenario.batch import BatchAdvance

    if (type(cpu_id) is not str or not cpu_id
            or type(dma_id) is not str or not dma_id or cpu_id == dma_id
            or type(rounds) is not int or rounds < 1):
        raise ValueError('compiled-F6-case-advance-schedule-invalid')
    order = (cpu_id, dma_id) if schedule_order is None else schedule_order
    if (type(order) is not tuple or len(set(order)) != len(order)
            or cpu_id not in order or dma_id not in order):
        raise ValueError('compiled-F6-case-advance-schedule-invalid')
    return tuple(BatchAdvance((component,))
        for _ in range(rounds) for component in order)


def _f6_runtime_case_advances(runtime):
    return _compiled_f6_case_advances(runtime.cpu_id, runtime.dma_id,
        runtime.rounds_per_case, schedule_order=runtime.session.template.schedule_order)


def _f6_session_template(*, run_id, cpu_id, path_id, program, rounds_per_case, runner):
    from myfuzz.scenario.genome import ScenarioGenome, MemoryImage
    return ScenarioGenome(testcase_id=run_id + ':native', direction='CPU_TO_IP',
        path_id=path_id, schedule_order=tuple(runner.sessions),
        max_steps=rounds_per_case * len(runner.sessions), actions=(),
        initial_images=tuple(MemoryImage(image_id=f'f6-initial-{index}', component=cpu_id,
            address=address, data_hex=data.hex()) for index, (address, data)
            in enumerate(sorted(program.initial_images.items()))))


def _assemble_f6_protocol_checker_case_report(runner, component, *,
        checker_snapshot, attempt, run_id, execution_binding_sha256):
    """Join the live checker delta to this attempt's exact Runner event slice."""
    start = attempt.get('_runner_event_start') if type(attempt) is dict else None
    event_count = getattr(runner, 'event_count', None)
    read = getattr(runner, 'events_since', None)
    if (type(start) is not int or start < 0 or type(event_count) is not int
            or event_count < start or not callable(read)):
        raise RuntimeError('compiled-F6-protocol-runner-slice-unavailable')
    report = runner.protocol_checker_report(component, since=checker_snapshot)
    if (type(report) is not dict or report.get('schema_version')
            != 'wishbone_dma_protocol_checker_report.v1'
            or type(report.get('endpoints')) is not list
            or len(report['endpoints']) != 2
            or type(report.get('findings')) is not list):
        raise RuntimeError('compiled-F6-protocol-checker-report-unavailable')
    report['case_id'] = attempt['case_id']
    report['case_index'] = attempt['case_index']
    report['run_id'] = run_id
    report['execution_binding_sha256'] = execution_binding_sha256
    report['runner_event_start'] = start
    report['runner_event_end'] = event_count
    # Case slice, borrowed: the report pins start/end to this attempt, and only
    # event ids and int-valued backend fields survive the loop below.
    case_events = _borrow_events(runner, start)
    if (type(case_events) not in (tuple, list)
            or len(case_events) != event_count - start):
        raise RuntimeError('compiled-F6-protocol-runner-slice-unavailable')
    for index, row in enumerate(case_events, start=start + 1):
        if type(row) is not dict or row.get('event_id') != index:
            raise RuntimeError('compiled-F6-protocol-runner-slice-identity-invalid')
    endpoint_ids = set()
    for endpoint_report in report['endpoints']:
        if type(endpoint_report) is not dict:
            raise RuntimeError('compiled-F6-protocol-checker-endpoint-invalid')
        endpoint_id = endpoint_report.get('endpoint_id')
        trace = endpoint_report.get('trace')
        signals = trace.get('signals') if type(trace) is dict else None
        if (type(endpoint_id) is not str or not endpoint_id
                or endpoint_id in endpoint_ids or type(signals) is not dict):
            raise RuntimeError('compiled-F6-protocol-checker-endpoint-invalid')
        endpoint_ids.add(endpoint_id)
        signal_names = tuple(signals.values())
        sample_ids = []
        for row in case_events:
            if (row.get('kind') != 'local_tick_sample'
                    or row.get('component') != component
                    or row.get('phase') != 'pre'):
                continue
            backend = row.get('outputs', {}).get('backend')
            if (type(backend) is not dict
                    or any(name not in backend or type(backend[name]) is not int
                           or backend[name] < 0 for name in signal_names)):
                raise RuntimeError('compiled-F6-protocol-sample-scope-invalid')
            sample_ids.append(row['event_id'])
        if len(sample_ids) != endpoint_report.get('pre_sample_count'):
            raise RuntimeError('compiled-F6-protocol-sample-count-mismatch')
        endpoint_report['sample_event_ids'] = sample_ids
    if len(endpoint_ids) != 2:
        raise RuntimeError('compiled-F6-protocol-checker-endpoint-invalid')
    violation_event_ids = []
    for finding in report['findings']:
        endpoint = finding.get('endpoint_id') if type(finding) is dict else None
        raw_event_id = finding.get('raw_event_id') if type(finding) is dict else None
        payload = finding.get('payload') if type(finding) is dict else None
        code = payload.get('violation_code') if type(payload) is dict else None
        matches = [row for row in case_events
            if row.get('kind') == 'protocol_violation'
            and row.get('endpoint_id') == endpoint
            and raw_event_id in row.get('raw_event_refs', [])
            and row.get('payload', {}).get('violation_code') == code]
        if len(matches) != 1:
            raise RuntimeError('compiled-F6-protocol-finding-runner-join-invalid')
        violation_event_ids.append(matches[0]['event_id'])
    report['runner_violation_event_ids'] = violation_event_ids
    return report


def _first_difference(expected, actual, path='$'):
    if type(expected) is not type(actual):
        return dict(path=path, expected=expected, actual=actual)
    if type(expected) is dict:
        keys = sorted(set(expected) | set(actual))
        for key in keys:
            if key not in expected or key not in actual:
                return dict(path=path + '.' + str(key),
                    expected=expected.get(key, '<missing>'),
                    actual=actual.get(key, '<missing>'))
            difference = _first_difference(expected[key], actual[key],
                path + '.' + str(key))
            if difference is not None:
                return difference
        return None
    if type(expected) in (list, tuple):
        if len(expected) != len(actual):
            return dict(path=path + '.length', expected=len(expected),
                actual=len(actual))
        for index, (left, right) in enumerate(zip(expected, actual)):
            difference = _first_difference(left, right,
                path + '[' + str(index) + ']')
            if difference is not None:
                return difference
        return None
    return None if expected == actual else dict(path=path,
        expected=expected, actual=actual)


def _normalized_f6_prefix(document, *, execution_history=None):
    """Normalize only process-local execution identity in a closed prefix."""
    import ast
    from dataclasses import asdict
    from myfuzz.scenario.ledger import TransactionKey

    from myfuzz.integration.compiled_f4 import _normalize_target_access_id, _project_process_local
    audit = document.get('original_execution_audit')
    identities = audit.get('identities', {}) if type(audit) is dict else {}
    execution_tokens = {}
    execution_owners = {}
    execution_epochs = {}
    commit_ids = {}
    for component, row in identities.items():
        nonce = row.get('execution_nonce') if type(row) is dict else None
        if type(nonce) is str and nonce:
            role = 'cpu' if row.get('role') == 'cpu' else 'dma'
            execution_tokens[nonce] = '<' + role + '-execution>'
            if nonce in execution_owners:
                execution_owners[nonce] = None
            else:
                execution_owners[nonce] = (component if row.get('component') == component
                    and row.get('role') in ('cpu', 'bound_target') else None)

    if execution_history is not None:
        execution_tokens.clear()
        execution_owners.clear()
        for component, launches in execution_history.items():
            for epoch, nonce in enumerate(launches):
                if nonce in execution_tokens:
                    raise ValueError('compiled-F6-replay-execution-identity-reused')
                execution_tokens[nonce] = f'<{component}-execution-epoch-{epoch}>'
                execution_owners[nonce] = component
                execution_epochs[nonce] = epoch

    #: Digests the reduced-AXI observation-stream exporter derives from an
    #: envelope that itself contains the per-launch execution nonce.  Only rows
    #: whose ``kind`` starts with ``reduced_axi`` are touched, and only these
    #: derived digests are replaced: every other field of the operation (address,
    #: data, length, tick, record count, payload) stays and is compared field by
    #: field by ``project`` below, so a real content difference is still caught.
    #: Every digest the reduced-AXI stream derives from an envelope that holds
    #: the per-launch nonce: operation envelopes (``content_digest``), journal
    #: sidecars (``observation_sha256``) and the accumulated chain/seal digests.
    process_local_digest_keys = ('content_digest', 'operation_digest',
                                 'observation_sha256', 'prior_operation_chain_sha256',
                                 'operation_chain_sha256', 'chain_sha256')
    #: Digests that identify the artifact or the admitted contract, not the
    #: process: they must keep comparing, so they are never replaced.
    deterministic_digest_keys = ('artifact_digest', 'binding_digest',
                                 'contract_sha256', 'source_sha256',
                                 'profile_sha256')

    def normalize_stream(value, in_reduced_axi=False):
        """Replace process-local nonce and the digests derived only from it."""
        if type(value) is dict:
            kind = value.get('kind')
            reduced = in_reduced_axi or (
                type(kind) is str and kind.startswith('reduced_axi'))
            row = {name: normalize_stream(item, reduced)
                   for name, item in value.items()}
            if reduced:
                for name in list(row):
                    item = row[name]
                    derived = (name in process_local_digest_keys
                               or name in ('sha256', 'digest')
                               or name.endswith('_sha256')
                               or name.endswith('_digest'))
                    if (derived and name not in deterministic_digest_keys
                            and type(item) is str
                            and re.fullmatch(r'[0-9a-f]{64}', item) is not None):
                        row[name] = '<process-local-derivation>'
                    elif type(item) is str and any(nonce in item
                                                   for nonce in execution_tokens):
                        for nonce, token in execution_tokens.items():
                            item = item.replace(nonce, token)
                        row[name] = item
            return row
        if type(value) in (list, tuple):
            return [normalize_stream(item, in_reduced_axi) for item in value]
        return value

    def transaction_text(value):
        # StateDependencyTracker and memory snapshots store TransactionKey's
        # dataclass repr, not a structured key. Parse that exact representation
        # without executing code; every non-execution field stays unchanged.
        if not value.startswith('TransactionKey(') or len(value) > 4096:
            return value
        try:
            node = ast.parse(value, mode='eval').body
            if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name)
                    or node.func.id != 'TransactionKey' or node.args):
                return value
            names = ('execution_id', 'testcase_id', 'source_component',
                     'source_epoch', 'channel_id', 'source_sequence')
            if tuple(item.arg for item in node.keywords) != names:
                return value
            fields = {item.arg: ast.literal_eval(item.value) for item in node.keywords}
            if (any(type(fields[name]) is not str or not fields[name]
                    for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                    or any(type(fields[name]) is not int or fields[name] < 0
                           for name in ('source_epoch', 'source_sequence'))):
                return value
            key = TransactionKey(**fields)
            if (str(key) != value or execution_owners.get(key.execution_id) != key.source_component
                    or execution_history is not None and execution_epochs.get(key.execution_id) != key.source_epoch):
                return value
            fields = asdict(key)
            fields['execution_id'] = execution_tokens[key.execution_id]
            return str(TransactionKey(**fields))
        except (SyntaxError, ValueError, TypeError):
            return value

    def project(value, key=None, process_local=True):
        if process_local and key == 'target_access_id':
            value = _normalize_target_access_id(value)
            # The original process-local projection leaves non-string values
            # below this key untouched before the F6 projection visits them.
            process_local = False
        if key == 'evidence_refs' and type(value) in (list, tuple):
            return ['<evidence-reference>'] * len(value)
        if type(value) is dict or process_local and isinstance(value, dict):
            if key == 'evidence_inventory' and all(
                    type(row) is dict or process_local and isinstance(row, dict)
                    for row in value.values()):
                rows = [project(row, process_local=process_local) for row in value.values()]
                return sorted(rows, key=lambda row: (row.get('kind', ''),
                    row.get('outcome', ''), _canonical(row.get('details', {}))))
            return {name: project(item, name, process_local) for name, item in value.items()
                if name not in ('original_build', 'original_execution_audit',
                    'semantic_hash', 'execution_audit')}
        if type(value) in (list, tuple) or process_local and isinstance(value, (list, tuple)):
            return [project(item, process_local=process_local) for item in value]
        if key in ('commit_id', 'destination_commit_id'):
            if type(value) is not str or value not in commit_ids:
                raise ValueError('compiled-F6-replay-commit-reference-unresolved')
            return commit_ids[value]
        if type(value) is str and value in execution_tokens:
            return execution_tokens[value]
        if type(value) is str:
            return transaction_text(value)
        return value

    # Authenticate each raw commit before projecting any reference.  A digest
    # can be rewritten only from the complete document that produced it.
    documents = {}
    pending = [document]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            if item.get('schema_version') == 'memory_write_commit_receipt.v1':
                raw_id = item.get('commit_id')
                body = _project_process_local({name: value for name, value in item.items()
                                               if name != 'commit_id'})
                encoded = json.dumps(body, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()
                if type(raw_id) is not str or sha256(encoded).hexdigest() != raw_id:
                    raise ValueError('compiled-F6-replay-commit-digest-invalid')
                key = item.get('fullkey')
                if type(key) is not dict:
                    raise ValueError('compiled-F6-replay-commit-key-invalid')
                nonce = key.get('execution_id')
                if (nonce in execution_owners and (execution_owners[nonce] != key.get('source_component')
                        or execution_history is not None and execution_epochs[nonce] != key.get('source_epoch'))):
                    raise ValueError('compiled-F6-replay-commit-owner-invalid')
                previous = documents.get(raw_id)
                if previous is not None and previous != encoded:
                    raise ValueError('compiled-F6-replay-commit-id-ambiguous')
                documents[raw_id] = encoded
                projected = project(body)
                normalized = json.dumps(projected, sort_keys=True, separators=(',', ':'),
                                        allow_nan=False).encode()
                commit_ids[raw_id] = sha256(normalized).hexdigest()
            pending.extend(value for value in item.values() if type(value) in (dict, list, tuple))
        elif type(item) in (list, tuple):
            pending.extend(value for value in item if type(value) in (dict, list, tuple))
    return project(normalize_stream(document))


def _f6_replay_execution_history(runtime, prefix):
    """Pin every epoch to the actual built-process launches and final audit."""
    identities = prefix['original_execution_audit']['identities']
    sessions = runtime._build_sessions
    reset_count = len(prefix['online_plan'].get('reset_operations', []))
    if set(identities) != set(sessions):
        raise ValueError('compiled-F6-replay-epoch-history-components')
    result = {}
    seen_nonces, seen_pids = set(), set()
    fields = ('artifact_digest','build_digest','binary_sha256','built_receipt_sha256',
              'observed_executable_sha256','ready_artifact_digest')
    for component, local in sessions.items():
        identity = identities[component]
        launches = local.built_executable_launch_observations()
        if (len(launches) != reset_count + 1 or local.reset_epoch != reset_count
                or identity.get('component') != component):
            raise ValueError('compiled-F6-replay-epoch-history-shape')
        nonces = []
        for row in launches:
            nonce, pid = row.get('execution_nonce'), row.get('pid')
            if (any(row.get(key) != identity.get(key) for key in fields)
                    or type(nonce) is not str or not nonce or nonce in seen_nonces
                    or type(pid) is not int or pid <= 0 or pid in seen_pids
                    or row.get('failure_stage') is not None
                    or row.get('returncode') != 0 or row.get('reaped') is not True):
                raise ValueError('compiled-F6-replay-epoch-history-unverified')
            seen_nonces.add(nonce);seen_pids.add(pid);nonces.append(nonce)
        if (nonces[-1] != identity.get('execution_nonce')
                or launches[-1]['pid'] != identity.get('pid')):
            raise ValueError('compiled-F6-replay-epoch-history-final-mismatch')
        result[component] = tuple(nonces)
    return result


def _require_fresh_execution_identity(original, fresh):
    reference = original._process_identities
    actual = fresh._process_identities
    if not reference or set(reference) != set(actual):
        raise ValueError('compiled-F6-fresh-process-shape')
    original_pids = {row.get('pid') for row in reference.values()}
    original_nonces = {row.get('execution_nonce') for row in reference.values()}
    previous = getattr(original, '_replay_identities', [])
    pids = set()
    nonces = set()
    for component, row in actual.items():
        prior = reference[component]
        if (any(row.get(key) != prior.get(key)
                for key in ('component', 'role', 'artifact_digest',
                    'build_digest', 'binary_sha256', 'built_receipt_sha256'))
                or type(row.get('pid')) is not int or row['pid'] <= 0
                or type(row.get('execution_nonce')) is not str
                or not row['execution_nonce']):
            raise ValueError('compiled-F6-fresh-process-shape')
        if row['pid'] in pids or row['execution_nonce'] in nonces:
            raise ValueError('compiled-F6-fresh-process-identity-reused')
        pids.add(row['pid'])
        nonces.add(row['execution_nonce'])
    old_runs = [reference, *previous]
    if any(pids & {row['pid'] for row in run.values()}
            or nonces & {row['execution_nonce'] for row in run.values()}
            for run in old_runs):
        raise ValueError('compiled-F6-fresh-process-identity-reused')
    previous.append(deepcopy(actual))
    original._replay_identities = previous


def _build_f6_assertion_material(runtime):
    from myfuzz.scenario.f6_assertion_evidence import build_f6_assertion_material
    return build_f6_assertion_material(runtime)


def _replay_f6_flow_timeline(runtime, flows, reset_operations):
    """Replay shared slots and their measured reset boundaries in a fresh owner."""
    from myfuzz.scenario.genome import MemoryImage
    if (type(reset_operations) is not list or any(type(op) is not dict
            or set(op) - {'after_cases', 'policy', 'image', 'advances'}
            or not {'after_cases', 'policy', 'image'} <= set(op)
            or type(op['after_cases']) is not int or op['after_cases'] < 1
            or op['policy'] not in ('warm_all', 'cold_all')
            or type(op['image']) is not dict for op in reset_operations)):
        raise ValueError('compiled-F6-replay-reset-timeline-invalid')
    reset_index = 0
    for slot_index, row in enumerate(flows, 1):
        runtime.submit(bytes.fromhex(row['raw_hex']), flow=row['flow'])
        case_count = len(runtime.session.cases)
        if reset_index < len(reset_operations) and reset_operations[reset_index]['after_cases'] < case_count:
            raise ValueError('compiled-F6-replay-reset-boundary-unreachable')
        while reset_index < len(reset_operations) and reset_operations[reset_index]['after_cases'] == case_count:
            operation = reset_operations[reset_index]
            image = MemoryImage(**operation['image'])
            start = runtime.runner.event_count
            runtime.session.reset(operation['policy'], image=image)
            barriers = [event for event in runtime.runner.events_since(start)
                        if event.get('kind') == 'reset_barrier'
                        and event.get('policy') == operation['policy']]
            if len(barriers) != 1:
                raise ValueError('compiled-F6-replay-reset-barrier-unavailable')
            runtime.rebind_reset_epoch(reset_policy=operation['policy'],
                barrier_event_id=barriers[0]['event_id'],
                expected_epoch=runtime.runner.command_epoch, next_slot=slot_index)
            actual = runtime.session._encoded_reset_operations()[-1]
            if _canonical(actual) != _canonical(operation):
                raise ValueError('compiled-F6-replay-reset-advance-mismatch')
            reset_index += 1
    if reset_index != len(reset_operations):
        raise ValueError('compiled-F6-replay-reset-boundary-unreachable')


def _f6_expected_online_plan(runtime):
    """Reproject the live F6 input state including any measured reset timeline."""
    from myfuzz.scenario.genome import GenomeCodec
    from myfuzz.scenario.session_runtime import (BoundOnlineInstruction, OnlineInstruction,
                                                _RESET_RESUME_SERIALIZER)

    session, runner = runtime.session, runtime.runner
    if (getattr(session, '_runtime_prepared', None) is None
            or not getattr(runner, 'provenance_enabled', False)):
        raise ValueError('F6 plan requires prepared paths and provenance')
    runtime_paths = session.runtime_path_document
    provenance = runner.provenance_configuration
    admissions = runner.source_admissions
    image_bindings = session.instruction_image_binding_documents
    if (type(runtime_paths) is not dict or type(provenance) is not dict
            or type(admissions) is not dict or type(image_bindings) not in (tuple, list)
            or not image_bindings):
        raise ValueError('F6 plan runtime bindings are incomplete')

    cases = []
    for case in session._cases:
        declared_advances = [list(item.schedule) for item in case.advances]
        from .shared_f6_slots import auxiliary_case
        auxiliary = auxiliary_case(runtime,case.case_id) if 'shared_slots' in runtime.contract['program_contract'] else None
        canonical_advances = ([[auxiliary['component']]] if auxiliary is not None else
            [list(item.schedule) for item in _f6_runtime_case_advances(runtime)])
        if declared_advances != canonical_advances:
            raise ValueError('F6 case advance declaration is not canonical')
        prefixes = getattr(session, '_case_advance_prefixes', None)
        if type(prefixes) is not dict:
            raise ValueError('F6 case advance prefix map is unavailable')
        advance_count = prefixes.get(case.case_id, len(declared_advances))
        if (type(advance_count) is not int or advance_count < 1
                or advance_count > len(declared_advances)):
            raise ValueError('F6 case executed advance prefix is invalid')
        source = asdict(case.source)
        source['kind'] = ('bound_instruction'
            if isinstance(case.source, BoundOnlineInstruction)
            else 'instruction' if isinstance(case.source, OnlineInstruction)
            else 'source_event')
        scheduled = getattr(session, '_source_schedule_ticks', {}).get(
            case.source.action_id)
        if scheduled is not None:
            source['scheduled_local_tick'] = scheduled
        row = dict(case_id=case.case_id, direction=case.direction,
            path_id=case.path_id, source=source,
            support_instructions=[asdict(item) for item in case.support_instructions],
            advances=declared_advances[:advance_count],
            source_role=session._case_source_roles[case.case_id])
        cases.append(row)

    terminal = getattr(session, '_terminal_failure', None)
    resets = session._reset_operations
    if (session._uncertain_reset or session._uncertain_reset_advance
            or runner.command_epoch != len(resets)):
        raise ValueError('F6 reset timeline is uncertain or unrecorded')
    schema = ((27 if terminal is not None else 26) if resets
              else (25 if terminal is not None else 24))
    document = dict(schema_version=schema,
        template=json.loads(GenomeCodec.encode(session.template)),
        instruction_slots=[list(item) for item in session._instruction_slots],
        warmup_advances=[list(item.schedule) for item in session._warmup_advances],
        cases=cases, runtime_paths=runtime_paths,
        provenance_configuration=provenance, source_admissions=admissions,
        instruction_image_bindings=list(image_bindings))
    if resets:
        document['reset_operations'] = _RESET_RESUME_SERIALIZER(session)
    if terminal is not None:
        document['terminal_failure'] = deepcopy(terminal)
    return document


def _f6_preparation_failure(runtime, component, row):
    fields = {'schema_version', 'outcome', 'compiled_this_invocation',
        'compile_seconds', 'compile_seconds_reason', 'actual_build_argv',
        'failure_stage', 'manifest_path', 'manifest_sha256',
        'preparation_seconds'}
    if (type(row) is not dict or set(row) != fields
            or row.get('schema_version') != 'local_harness_build_preparation.v1'
            or row.get('outcome') not in (
                'cache_hit', 'compiled_race_reused', 'compiled_published')
            or type(row.get('compiled_this_invocation')) is not bool
            or row.get('failure_stage') is not None
            or type(row.get('manifest_path')) is not str
            or not row['manifest_path'] or row['manifest_path'].strip() != row['manifest_path']
            or type(row.get('manifest_sha256')) is not str
            or re.fullmatch('[0-9a-f]{64}', row['manifest_sha256']) is None
            or type(row.get('preparation_seconds')) not in (int, float)
            or not math.isfinite(row['preparation_seconds'])
            or row['preparation_seconds'] < 0):
        return 'build-preparation-shape-or-failure'
    outcome = row['outcome']
    if outcome == 'cache_hit':
        if (row['compiled_this_invocation'] is not False
                or row['compile_seconds'] is not None
                or row['compile_seconds_reason'] != 'not_compiled_this_invocation'
                or row['actual_build_argv'] is not None):
            return 'build-preparation-cache-hit-branch'
    elif (row['compiled_this_invocation'] is not True
            or type(row['compile_seconds']) not in (int, float)
            or not math.isfinite(row['compile_seconds'])
            or row['compile_seconds'] < 0
            or row['compile_seconds_reason'] is not None
            or type(row['actual_build_argv']) is not list
            or not row['actual_build_argv']
            or any(type(part) is not str or not part for part in row['actual_build_argv'])):
        return 'build-preparation-compiled-branch'

    sessions = getattr(runtime, '_build_sessions', None)
    if type(sessions) is not dict or set(sessions) != set(runtime.artifacts):
        return 'build-preparation-session-owners'
    local = sessions.get(component)
    try:
        pin = local._built_pin()
        result = pin[0]
        expected_path = str(result.binary_path.parent / 'manifest.json')
        expected_sha256 = result._manifest_sha256
    except (AttributeError, IndexError, TypeError, ValueError):
        return 'build-preparation-manifest-pin'
    if row['manifest_path'] != expected_path or row['manifest_sha256'] != expected_sha256:
        return 'build-preparation-manifest-join'
    return None


def _f6_export_failure(runtime, name, value, *, execution_audit=None):
    """Return a reason when a mandatory F6 finish export is absent or malformed."""
    artifacts = getattr(runtime, 'artifacts', None)
    if type(artifacts) is not dict or not artifacts:
        return 'artifact-components'
    components = set(artifacts)
    attempts = getattr(runtime, 'attempts', None)
    shared = 'shared_slots' in runtime.contract['program_contract']
    if type(attempts) is not list or (not attempts and not shared):
        return 'attempts'
    case_ids = [row.get('case_id') if type(row) is dict else None
        for row in attempts]
    if any(type(case_id) is not str or not case_id for case_id in case_ids):
        return 'case-identities'

    if name == 'online_plan':
        if 'shared_slots' in runtime.contract['program_contract']:
            from .shared_f6_slots import flow_records,session_case_ids
            case_ids = session_case_ids(runtime,admitted_only=True)
        try:
            expected_plan = _f6_expected_online_plan(runtime)
        except (AttributeError, KeyError, TypeError, ValueError):
            return 'online-plan-live-state'
        try:
            valid = (type(value) is dict
                and value.get('schema_version') in (24, 25, 26, 27)
                and _canonical(value) == _canonical(expected_plan)
                and len(expected_plan['cases']) == len(case_ids)
                and [row['case_id'] for row in expected_plan['cases']] == case_ids)
        except (TypeError, ValueError, RecursionError):
            return 'online-plan-shape-or-cases'
        if not valid:
            return 'online-plan-shape-or-cases'
        return None

    if name == 'assertion_material':
        if type(value) is not dict:
            return 'assertion-material-shape'
        try:
            from myfuzz.scenario.f6_assertion_evidence import (
                _scope, validate_f6_assertion_evidence)
            inventory = _case_inventory(runtime)
            if (type(inventory) is not list
                    or [row.get('case_id') if type(row) is dict else None
                        for row in inventory] != case_ids
                    or any(type(row) is not dict
                        or type(row.get('observations')) is not dict
                        or not row['observations']
                        or type(row.get('evidence_inventory')) is not dict
                        or not row['evidence_inventory'] for row in inventory)):
                return 'assertion-material-independent-inventory'
            validate_f6_assertion_evidence(value,
                execution_binding=_scope(runtime), case_inventory=inventory)
        except (AttributeError, KeyError, TypeError, ValueError):
            return 'assertion-material-typed-evidence-or-scope'
        return None

    if name == 'events':
        if (type(value) is not list or not value
                or any(type(row) is not dict or not row for row in value)):
            return 'event-list-shape'
        event_ids = [row.get('event_id') for row in value]
        expected_count = getattr(getattr(runtime, 'runner', None),
            'event_count', None)
        def has_row_identity(row):
            if any(type(row.get(field)) is str and row[field].strip()
                    for field in ('kind', 'schema_version')):
                return True
            # Runner step samples intentionally have no event kind: their
            # identity is the component/tick plus the sampled I/O mapping.
            return (type(row.get('component')) is str
                and bool(row['component'].strip())
                and type(row.get('local_tick')) is int
                and row['local_tick'] > 0
                and type(row.get('inputs')) is dict
                and type(row.get('outputs')) is dict)
        if (any(type(event_id) is not int or event_id <= 0
                for event_id in event_ids)
                or len(set(event_ids)) != len(event_ids)
                or event_ids != list(range(1, len(value) + 1))
                or (type(expected_count) is int
                    and expected_count != len(value))
                or any(not has_row_identity(row) for row in value)
                or any('component' in row and (type(row['component']) is not str
                    or not row['component'].strip()) for row in value)):
            return 'event-list-identity'
        return None

    if name == 'execution_audit':
        expected_identity = getattr(runtime, '_process_identities', None)
        if (type(value) is not dict
                or set(value) != {'schema_version', 'identities', 'exits', 'closed'}
                or value.get('schema_version') != getattr(runtime, '_audit_schema', None)
                or value.get('closed') is not True
                or type(expected_identity) is not dict
                or set(expected_identity) != components
                or value.get('identities') != expected_identity
                or type(value.get('exits')) is not dict
                or set(value['exits']) != components):
            return 'execution-audit-shape-or-process-join'
        for component, identity in expected_identity.items():
            if (type(identity) is not dict
                    or identity.get('component') != component
                    or identity.get('role') != ('cpu' if component == getattr(runtime, 'cpu_id', None)
                        else 'bound_target')
                    or type(identity.get('pid')) is not int or identity['pid'] <= 0
                    or type(identity.get('execution_nonce')) is not str
                    or not identity['execution_nonce']
                    or any(type(identity.get(name)) is not str
                        or len(identity[name]) != 64
                        or any(ch not in '0123456789abcdef' for ch in identity[name])
                        for name in ('artifact_digest', 'build_digest', 'binary_sha256',
                            'built_receipt_sha256', 'observed_executable_sha256',
                            'ready_artifact_digest'))):
                return 'execution-audit-identity-row'
            exit_row = value['exits'][component]
            if (type(exit_row) is not dict
                    or set(exit_row) != {'returncode', 'reaped'}
                    or type(exit_row.get('returncode')) is not int
                    or exit_row.get('returncode') != 0
                    or exit_row.get('reaped') is not True):
                return 'execution-audit-exit-row'
        return None

    if name == 'build_audit':
        if (type(value) is not dict
                or set(value) != {'receipts', 'preparation_observations',
                    'execution_audit', 'unavailable'}
                or type(value.get('unavailable')) is not dict
                or value['unavailable']):
            return 'build-audit-shape-or-unavailable'
        receipts = value.get('receipts')
        if (type(receipts) is not dict or set(receipts) != components
                or receipts != getattr(runtime, '_built_receipts', None)):
            return 'build-audit-receipts'
        try:
            from myfuzz.integration.compiled_build_join import validate_built_receipts
            validate_built_receipts(artifacts, receipts)
        except BaseException:
            return 'build-audit-receipts'
        preparation = value.get('preparation_observations')
        if (type(preparation) is not dict or set(preparation) != components
                or any(_f6_preparation_failure(runtime, component, row) is not None
                    for component, row in preparation.items())):
            return 'build-audit-preparation'
        audit = value.get('execution_audit')
        expected_identity = getattr(runtime, '_process_identities', None)
        if (type(audit) is not dict
                or set(audit) != {'identities', 'exits', 'closed'}
                or audit.get('closed') is not True
                or type(audit.get('identities')) is not dict
                or set(audit['identities']) != components
                or type(audit.get('exits')) is not dict
                or set(audit['exits']) != components
                or type(expected_identity) is not dict
                or set(expected_identity) != components):
            return 'build-audit-process-shape'
        joined_fields = ('component', 'role', 'pid', 'execution_nonce',
            'artifact_digest', 'build_digest', 'binary_sha256',
            'built_receipt_sha256', 'observed_executable_sha256',
            'ready_artifact_digest')
        for component, expected in expected_identity.items():
            observed = audit['identities'][component]
            exit_row = audit['exits'][component]
            if (type(observed) is not dict
                    or any(observed.get(field) != expected.get(field)
                        for field in joined_fields)
                    or type(exit_row) is not dict
                    or set(exit_row) != {'returncode', 'reaped'}
                    or type(exit_row.get('returncode')) is not int
                    or exit_row.get('returncode') != 0
                    or exit_row.get('reaped') is not True):
                return 'build-audit-process-join'
            top_identity = (execution_audit.get('identities', {}).get(component)
                if type(execution_audit) is dict
                and type(execution_audit.get('identities')) is dict else None)
            if (type(top_identity) is not dict
                    or any(top_identity.get(field) != observed.get(field)
                        for field in joined_fields)
                    or type(execution_audit.get('exits')) is not dict
                    or execution_audit['exits'].get(component) != exit_row):
                return 'build-audit-top-level-join'
        if (type(execution_audit) is not dict
                or execution_audit.get('closed') is not True
                or audit.get('closed') is not True
                or type(execution_audit.get('exits')) is not dict
                or audit['exits'] != execution_audit['exits']):
            return 'build-audit-top-level-join'
        return None

    return 'unknown-export'


_F6_TERMINAL_TRACE_FAILURE_STATUSES = frozenset((
    'budget_exhausted', 'environment_error', 'finding', 'protocol_violation',
    'runner_failed', 'uncertain_effect', 'unsupported_irq_overrun'))


def _journal_matches_trace_events(trace, events):
    """Canonical equality of the session trace rows and the captured journal.

    Computed once per finish for the two consumers that need the same answer
    (the trace gate and the prefix's ``trace_events_source``); ``None`` when
    either sequence cannot be read, which makes the gate recompute it.  The
    trace snapshot detaches every row it iterates, which is pure waste for a
    read-only canonical comparison, so the borrowed iterator is used when the
    owner exposes one; the compared values are the same rows.
    """
    try:
        if type(events) is not list:
            return None
        return _canonical(list(_borrowed_trace_events(trace))) == _canonical(events)
    except BaseException:
        return None


def _borrowed_trace_events(trace):
    """Iterate the session trace rows without detaching them.

    ``EventJournalSnapshot`` exists to hand callers detached values; the
    read-only finish checks only serialise the rows, so they use its documented
    internal borrowed iterator when present and fall back to the public one.
    """
    snapshot = getattr(trace, 'events', None)
    borrowed = getattr(snapshot, '_iter_borrowed', None)
    return borrowed() if callable(borrowed) else snapshot


def _f6_trace_failure(runtime, trace, runner_events=None, events_equal=None):
    """Refuse an export whose trace cannot be reconstructed from real owner state.

    ``runner_events`` is the journal snapshot already captured for the prefix
    export.  The journal is append-only and frozen once the session finished, so
    the caller may pass that exact sequence instead of detaching the whole
    journal a second time; every check below runs on the same rows.
    ``events_equal`` is that snapshot's canonical comparison with the session
    trace, computed once by the caller for the same two sequences; ``None``
    recomputes it here.
    """
    from collections.abc import Sequence
    from myfuzz.scenario.replay import ScenarioTrace
    if type(trace) is not ScenarioTrace:
        return 'trace-missing-or-incomplete'
    if type(trace.status) is not str:
        return 'trace-status-shape'
    session = getattr(runtime, 'session', None)
    runner = getattr(runtime, 'runner', None)
    if getattr(session, '_finished', None) is not True:
        return 'trace-session-not-finished'
    runner_failure = getattr(runner, 'failure_status', None)
    halt_reason = getattr(session, '_halt_reason', None)
    if trace.status == 'complete':
        if runner_failure is not None or halt_reason is not None:
            return 'trace-complete-status-owner-mismatch'
    elif (trace.status not in _F6_TERMINAL_TRACE_FAILURE_STATUSES
            or trace.status != (runner_failure or halt_reason)):
        return 'trace-terminal-status-owner-mismatch'
    if (not isinstance(trace.events, Sequence) or not trace.events
            or any(type(row) is not dict for row in _borrowed_trace_events(trace))
            or type(trace.local_ticks) is not dict
            or set(trace.local_ticks) != set(runtime.runner.sessions)
            or any(type(ticks) is not int or ticks < 0
                for ticks in trace.local_ticks.values())):
        return 'trace-event-or-clock-shape'
    for name in ('genome_sha256', 'semantic_sha256', 'manifest_sha256'):
        value = getattr(trace, name, None)
        if (type(value) is not str or len(value) != 64
                or any(ch not in '0123456789abcdef' for ch in value)):
            return 'trace-digest-shape'
    try:
        event_snapshot = (runner.events_since(0) if runner_events is None
            else runner_events)
        runner_ticks = runner.local_ticks
        if type(event_snapshot) not in (tuple, list):
            return 'trace-runner-events-unavailable'
        if (type(getattr(runner, 'event_count', None)) is not int
                or runner.event_count != len(event_snapshot)):
            return 'trace-runner-event-count-mismatch'
        if any(type(row) is not dict or type(row.get('event_id')) is not int
                or row.get('event_id') != index
                for index, row in enumerate(event_snapshot, start=1)):
            return 'trace-runner-event-identity-mismatch'
        if events_equal is None:
            events_equal = (_canonical(list(_borrowed_trace_events(trace)))
                == _canonical(list(event_snapshot)))
        if not events_equal:
            return 'trace-runner-events-mismatch'
        if (type(runner_ticks) is not dict
                or set(runner_ticks) != set(runner.sessions)
                or any(type(ticks) is not int or ticks < 0
                    for ticks in runner_ticks.values())
                or trace.local_ticks != runner_ticks):
            return 'trace-runner-ticks-mismatch'
        from myfuzz.scenario.session_runtime import _trace_semantic_sha256
        if trace.semantic_sha256 != _trace_semantic_sha256(
                trace.status, trace.events, trace.local_ticks):
            return 'trace-semantic-hash-mismatch'
        plan_bytes = session.encode_plan()
        if type(plan_bytes) is not bytes:
            return 'trace-genome-owner-unavailable'
        if trace.genome_sha256 != sha256(plan_bytes).hexdigest():
            return 'trace-genome-owner-mismatch'
        manifest_sha256 = getattr(session, '_manifest_sha256', None)
        if (type(manifest_sha256) is not str or len(manifest_sha256) != 64
                or any(ch not in '0123456789abcdef' for ch in manifest_sha256)
                or trace.manifest_sha256 != manifest_sha256):
            return 'trace-manifest-owner-mismatch'
    except BaseException:
        return 'trace-owner-snapshot-unavailable'
    return None


def _f6_finish_state_failure(runtime, *, online_plan, assertion_material,
        feedback, final_dma_case_id):
    """Refuse a full/error-prefix claim if frozen case state no longer joins."""
    attempts = getattr(runtime, 'attempts', None)
    records = getattr(runtime, 'records', None)
    shared = 'shared_slots' in runtime.contract['program_contract']
    if shared:
        from .shared_f6_slots import flow_records,session_case_ids
        flows = flow_records(runtime)
        if not flows or any(row['status'] != 'passed' for row in flows):
            return 'shared-case-prefix-not-passed'
        if (type(online_plan) is not dict or [row['case_id'] for row in online_plan.get('cases',[])]
                != session_case_ids(runtime)):
            return 'shared-case-plan-prefix'
        if not attempts:
            if records != [] or feedback != [0]*5 or runtime.policy.records or runtime.route_admission.route_matches:
                return 'shared-unused-DMA-subledger'
            return None
    if type(attempts) is not list or not attempts:
        return 'case-prefix-missing'
    if type(records) is not list or len(records) != len(attempts):
        return 'case-record-attempt-count'
    statuses = [row.get('status_kind') if type(row) is dict else None
        for row in attempts]
    successful_prefix = all(value == 'passed' for value in statuses)
    expected_error_prefix = (statuses[-1:] == ['expected_error']
        and all(value == 'passed' for value in statuses[:-1]))
    if not (successful_prefix or expected_error_prefix):
        return None
    if (type(online_plan) is not dict
            or online_plan.get('schema_version') not in (24, 26)
            or 'terminal_failure' in online_plan):
        return 'case-terminal-online-plan-not-accepted'

    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    try:
        inventory = _case_inventory(runtime)
    except (AttributeError, KeyError, TypeError, ValueError):
        return 'case-independent-inventory-unavailable'
    case_ids = [row.get('case_id') for row in attempts]
    if (type(inventory) is not list
            or [row.get('case_id') if type(row) is dict else None
                for row in inventory] != case_ids):
        return 'case-independent-inventory-prefix'
    freezes = getattr(runtime, '_f6_case_freezes', None)
    if type(freezes) is not dict or set(freezes) != set(case_ids):
        return 'case-freeze-prefix'
    runtime_cases = assertion_material.get('assertion_evidence', {}).get('cases')
    if (type(runtime_cases) is not list
            or [row.get('case_id') if type(row) is dict else None
                for row in runtime_cases] != case_ids):
        return 'case-assertion-prefix'
    plan_cases = online_plan.get('cases') if type(online_plan) is dict else None
    if 'shared_slots' in runtime.contract['program_contract']:
        from .shared_f6_slots import flow_records,session_case_ids
        flows = flow_records(runtime)
        if not isinstance(plan_cases, list) or [row['case_id'] for row in plan_cases] != session_case_ids(runtime):
            return 'shared-flow-online-plan-prefix'
        plan_cases = [row for row in plan_cases if row['case_id'] in case_ids]
    if (type(plan_cases) is not list
            or [row.get('case_id') if type(row) is dict else None
                for row in plan_cases] != case_ids):
        return 'case-online-plan-prefix'

    for index, (attempt, record, case, frozen, planned_case) in enumerate(zip(
            attempts, records, inventory, (freezes.get(cid) for cid in case_ids),
            plan_cases)):
        if (type(attempt) is not dict or type(record) is not dict
                or type(case) is not dict or type(frozen) is not dict
                or frozen.get('attempt_case_index') != index
                or attempt.get('case_index') != index
                or frozen.get('attempt_sha256') != _digest(_attempt_for_freeze(attempt))
                or frozen.get('inventory_sha256') != _digest(case)
                or type(frozen.get('dma_case_id')) is not str
                or not frozen['dma_case_id']
                or type(frozen.get('route_matches')) is not list
                or type(frozen.get('policy_records')) is not list
                or _canonical(attempt.get('case_material')) != _canonical(case)):
            return 'case-freeze-identity-or-material'
        frozen_scope = _f6_scope_snapshot_document(frozen)
        if (frozen.get('scope_snapshot_sha256') != _digest(frozen_scope)
                or _f6_scope_snapshot_failure(runtime, attempt,
                    frozen_scope) is not None):
            return 'case-freeze-scope-snapshot'
        if (case.get('case_id') != attempt.get('case_id')
                or type(case.get('observations')) is not dict
                or set(case['observations']) != set(EXPECTATION_IDS)):
            return 'case-frozen-observations'
        for field in ('case_id', 'case_index', 'raw8_hex', 'words',
                'instruction_address'):
            if record.get(field) != attempt.get(field):
                return 'case-record-attempt-join'
        if (record.get('status') != attempt.get('status_kind')
                or record.get('prefix_hex') != attempt.get('prefix_hex')
                or record.get('feedback') != attempt.get('feedback')
                or type(attempt.get('result')) is not dict
                or attempt['result'].get('status') != attempt.get('status_kind')
                or attempt['result'].get('case_id') != attempt.get('case_id')
                or attempt['result'].get('case_index') != index
                or attempt['result'].get('prefix_hex') != attempt.get('prefix_hex')
                or attempt['result'].get('feedback') != attempt.get('feedback')):
            return 'case-result-record-join'
        raw_hex = attempt.get('raw8_hex')
        prefix_hex = attempt.get('prefix_hex')
        try:
            if (type(raw_hex) is not str or len(raw_hex) != 16
                    or type(prefix_hex) is not str or not prefix_hex
                    or len(prefix_hex) % 2):
                return 'case-canonical-input-shape'
            raw = bytes.fromhex(raw_hex)
            prefix = bytes.fromhex(prefix_hex)
            candidate = runtime.layout.decode(raw)
            expected_prefix = runtime.program.prefix(candidate, case_index=index)
        except (AttributeError, TypeError, ValueError):
            return 'case-canonical-input-decode'
        from .shared_f6_slots import f6_slot
        expected_slot = (runtime.contract['program_contract']['slot_base']
            + 256 * f6_slot(runtime, attempt))
        if (raw.hex() != raw_hex or candidate.raw != raw
                or list(candidate.words) != attempt.get('words')
                or prefix != expected_prefix
                or attempt.get('instruction_address') != expected_slot):
            return 'case-raw-operand-prefix-join'
        source_id = runtime.contract['instruction_source_id']
        try:
            canonical_advances = [list(item.schedule) for item in
                _f6_runtime_case_advances(runtime)]
            session_cases = runtime.session._cases
            if (type(session_cases) not in (tuple, list)
                    or index >= len(session_cases)):
                return 'case-online-plan-advance-prefix'
            declared_case = session_cases[attempt.get('session_case_index', index)]
            declared_advances = [list(item.schedule)
                for item in declared_case.advances]
            advance_prefixes = runtime.session._case_advance_prefixes
            if type(advance_prefixes) is not dict:
                return 'case-online-plan-advance-prefix'
            executed_advance_count = advance_prefixes.get(
                attempt['case_id'], len(declared_advances))
        except (AttributeError, IndexError, KeyError, TypeError, ValueError):
            return 'case-online-plan-advance-prefix'
        planned_advances = (planned_case.get('advances')
            if type(planned_case) is dict else None)
        if (type(planned_case) is not dict
                or planned_case.get('direction') != 'CPU_TO_IP'
                or planned_case.get('path_id') !=
                    runtime.runtime_path_admission['runtime_path_ids'][1]
                or planned_case.get('source_role') != 'fuzz_source'
                or planned_case.get('source') != dict(
                    action_id=f'{source_id}:{index}',
                    component=runtime.cpu_id, address=expected_slot,
                    data_hex=prefix_hex, source_id=source_id,
                    kind='bound_instruction')
                or planned_case.get('support_instructions') != []
                or declared_advances != canonical_advances
                or type(executed_advance_count) is not int
                or not 1 <= executed_advance_count <= len(canonical_advances)
                or type(planned_advances) is not list
                or len(planned_advances) != executed_advance_count
                or planned_advances != canonical_advances[:executed_advance_count]):
            return 'case-online-plan-source-path-advance-join'

        if statuses[index] == 'passed':
            observations = case['observations']
            if any(observations[eid].get('status') != 'passed'
                    for eid in EXPECTATION_IDS):
                return 'passed-case-evidence-not-all-passed'
            if attempt.get('expected_error') is not False or attempt.get('feedback') != [1]*5:
                return 'passed-case-feedback-or-error-flag'
        else:
            if (index != len(attempts) - 1
                    or attempt.get('expected_error') is not True
                    or attempt.get('feedback') != [0]*5
                    or feedback != [0]*5):
                return 'expected-error-feedback-or-position'
            irq_id = 'dma.irq_isr_completion'
            irq = case['observations'][irq_id]
            if irq.get('status') != 'failed':
                return 'expected-error-irq-status'
            refs = irq.get('evidence_refs')
            evidences = case.get('evidence_inventory')
            if type(refs) is not list or type(evidences) is not dict:
                return 'expected-error-irq-evidence'
            if not any(type(evidences.get(reference)) is dict
                    and evidences[reference].get('kind') == irq_id
                    and evidences[reference].get('outcome') == 'failed'
                    and type(evidences[reference].get('details')) is dict
                    and type(evidences[reference]['details'].get('error_completion')) is dict
                    and evidences[reference]['details']['error_completion'].get(
                        'terminal_marker') == 2 for reference in refs):
                return 'expected-error-terminal-marker'

        if index + 1 < len(attempts):
            next_case = attempts[index + 1]
            expected_transition = dict(previous_case_id=frozen['dma_case_id'],
                testcase_id=f'{runtime.run_id}:dma:{index + 1}',
                case_id=f'{runtime.run_id}:case:{index + 1}',
                case_index=index + 1)
            if (attempt.get('route_match_history') != frozen['route_matches']
                    or attempt.get('policy_records') != frozen['policy_records']
                    or attempt.get('scope_transition') != expected_transition
                    or freezes[next_case['case_id']].get('dma_case_id')
                        != expected_transition['testcase_id']):
                return 'case-transition-history-join'
        elif any(name in attempt for name in (
                'route_match_history', 'policy_records', 'scope_transition')):
            return 'last-case-has-fabricated-transition'

    final = freezes[case_ids[-1]]
    if (final_dma_case_id != final['dma_case_id']
            or getattr(getattr(runtime, 'route_admission', None), 'route_matches', None)
                != final['route_matches']
            or getattr(getattr(runtime, 'policy', None), 'records', None)
                != final['policy_records']):
        return 'last-case-live-scope-drift'
    return None


def _attempt_for_freeze(attempt):
    return {key: value for key, value in attempt.items()
        if key not in ('route_match_history', 'policy_records',
                       'scope_transition')}


def _f6_scope_snapshot_document(frozen):
    return dict(dma_case_id=frozen.get('dma_case_id'),
        route_matches=frozen.get('route_matches'),
        policy_records=frozen.get('policy_records'))


def _f6_scope_snapshot_failure(runtime, attempt, snapshot):
    """Validate the frozen route/policy prefix for this logical DMA case."""
    from myfuzz.scenario.ledger import TransactionKey

    dma = getattr(runtime, 'dma', None)
    contract = getattr(runtime, 'contract', None)
    if (type(snapshot) is not dict
            or set(snapshot) != {'dma_case_id', 'route_matches', 'policy_records'}
            or type(snapshot.get('dma_case_id')) is not str
            or not snapshot['dma_case_id']
            or type(snapshot.get('route_matches')) is not list
            or type(snapshot.get('policy_records')) is not list):
        return 'scope-snapshot-shape'
    routes, records = snapshot['route_matches'], snapshot['policy_records']
    if (not routes or len(routes) != len(records)
            or any(type(row) is not dict for row in routes)
            or any(type(row) is not dict for row in records)):
        return 'scope-snapshot-empty-or-count'
    if (type(contract) is not dict
            or type(contract.get('program_contract')) is not dict
            or type(attempt) is not dict):
        return 'scope-snapshot-contract'

    status = attempt.get('status_kind')
    expected_error = attempt.get('expected_error') is True
    if status == 'passed' and not expected_error:
        if len(records) != 8:
            return 'scope-snapshot-success-count'
        expected_errors = [0] * 8
    elif status == 'failed' and attempt.get('expected_error') is False:
        # A source-observation failure can be discovered after the real
        # successful DMA prefix has fully completed. Preserve that complete
        # scope so the failed assertion evidence remains auditable; partial
        # DMA prefixes do not receive this snapshot.
        if len(records) != 8:
            return 'scope-snapshot-failed-prefix-count'
        expected_errors = [0] * 8
    elif status == 'expected_error' and expected_error:
        if not 1 <= len(records) <= 8:
            return 'scope-snapshot-error-count'
        expected_errors = [0] * (len(records) - 1) + [1]
    else:
        return 'scope-snapshot-attempt-status'

    program = contract['program_contract']
    admission = getattr(runtime, 'route_admission', None)
    last_sequence = -1
    route_fields = {'route_sha256', 'edge_key', 'source_node_id',
        'target_node_id', 'path_id', 'initiator_component', 'endpoint_id',
        'target_kind', 'target_component', 'target_id', 'base', 'size',
        'operation', 'address', 'byte_enable', 'transaction',
        'target_identity_sha256'}
    policy_fields = {'transaction', 'address', 'write', 'value',
        'byte_enable', 'word_index', 'rdata', 'error'}
    for index, (route, record, expected_error_bit) in enumerate(zip(
            routes, records, expected_errors)):
        expected_operation = 'read' if index < 4 else 'write'
        word_index = index if index < 4 else index - 4
        expected_address = (program['source_address'] if expected_operation == 'read'
            else program['destination_address']) + 4 * word_index
        transaction = record.get('transaction')
        route_transaction = route.get('transaction')
        try:
            if (type(transaction) is not dict
                    or set(transaction) != set(TransactionKey.__dataclass_fields__)
                    or route_transaction != transaction):
                return 'scope-snapshot-transaction-shape'
            key = TransactionKey(**transaction)
        except (TypeError, ValueError):
            return 'scope-snapshot-transaction-shape'
        expected_write = expected_operation == 'write'
        if (set(route) != route_fields or set(record) != policy_fields
                or key.execution_id != getattr(dma, '_execution', None)
                or key.testcase_id != snapshot['dma_case_id']
                or key.source_component != getattr(dma, 'source_component', None)
                or key.source_epoch != getattr(dma, 'reset_epoch', None)
                or key.channel_id != 'dma-memory'
                or key.source_sequence != index + 1
                or key.source_sequence <= last_sequence
                or route.get('operation') != expected_operation
                or route.get('path_id') != getattr(admission, '_path_id', None)
                or route.get('address') != expected_address
                or route.get('byte_enable') != 15
                or type(record.get('write')) is not bool
                or record.get('write') is not expected_write
                or record.get('address') != expected_address
                or record.get('byte_enable') != 15
                or record.get('word_index') != word_index
                or type(record.get('value')) is not int
                or not 0 <= record['value'] < 2**32
                or expected_write and (type(attempt.get('words')) is not list
                    or len(attempt['words']) != 4
                    or record['value'] != attempt['words'][word_index])
                or type(record.get('rdata')) is not int
                or type(record.get('error')) is not int
                or record.get('error') != expected_error_bit):
            return 'scope-snapshot-beat-order-or-scope'
        selected_route = (getattr(admission, '_read_route', None)
            if expected_operation == 'read'
            else getattr(admission, '_write_route', None))
        if (selected_route is None
                or route.get('route_sha256') != selected_route.identity_sha256):
            return 'scope-snapshot-route-identity'
        last_sequence = key.source_sequence
    return None


def _case_inventory(runtime):
    from myfuzz.scenario.f6_assertion_evidence import _case_inventory as collect
    return collect(runtime)


def _freeze_f6_case(runtime, attempt, material):
    """Freeze the attempt bytes, Task5 inventory, and DMA evidence at capture."""
    if type(attempt) is not dict or type(material) is not dict:
        raise ValueError('compiled-F6-case-freeze-input')
    attempts = getattr(runtime, 'attempts', None)
    if type(attempts) is list and (not attempts or attempts[-1] is not attempt):
        raise ValueError('compiled-F6-case-freeze-not-latest-attempt')
    case_id = attempt.get('case_id')
    inventory = _case_inventory(runtime)
    rows = [row for row in inventory if row.get('case_id') == case_id]
    if len(rows) != 1 or _canonical(rows[0]) != _canonical(material):
        raise ValueError('compiled-F6-case-freeze-inventory-mismatch')
    registry = getattr(runtime, '_f6_case_freezes', None)
    if registry is None:
        registry = {}
        runtime._f6_case_freezes = registry
    if type(registry) is not dict or case_id in registry:
        raise ValueError('compiled-F6-case-freeze-duplicate')
    admission = runtime.route_admission
    policy = runtime.policy
    snapshot = dict(dma_case_id=runtime.dma._case_id,
        route_matches=deepcopy(admission.route_matches),
        policy_records=deepcopy(policy.records))
    if _f6_scope_snapshot_failure(runtime, attempt, snapshot) is not None:
        raise ValueError('compiled-F6-case-freeze-scope-snapshot-invalid')
    frozen = dict(attempt_sha256=_digest(_attempt_for_freeze(attempt)),
        inventory_sha256=_digest(rows[0]),
        attempt_case_index=attempt.get('case_index'),
        **snapshot, scope_snapshot_sha256=_digest(snapshot))
    registry[case_id] = frozen
    return deepcopy(frozen)


def _freeze_matches(runtime, attempt, frozen):
    if _digest(_attempt_for_freeze(attempt)) != frozen['attempt_sha256']:
        raise ValueError('F6 independent case inventory is immutable')
    rows = [row for row in _case_inventory(runtime)
        if row.get('case_id') == attempt.get('case_id')]
    if (len(rows) != 1 or _digest(rows[0]) != frozen['inventory_sha256']
            or type(attempt.get('case_index')) is not int
            or attempt['case_index'] != frozen['attempt_case_index']):
        raise ValueError('F6 independent case inventory is immutable')
    snapshot = _f6_scope_snapshot_document(frozen)
    if (frozen.get('scope_snapshot_sha256') != _digest(snapshot)
            or _f6_scope_snapshot_failure(runtime, attempt, snapshot) is not None):
        raise ValueError('F6 independent case inventory is immutable')
    if (runtime.route_admission.route_matches != frozen['route_matches']
            or runtime.policy.records != frozen['policy_records']
            or runtime.dma._case_id != frozen['dma_case_id']):
        raise ValueError('F6 independent case inventory is immutable')
    return rows[0]


def _process_live(session, expected_process, expected_pid):
    if (expected_process is None or session._process is not expected_process
            or expected_pid is None or type(expected_pid) is not int
            or expected_pid < 1 or getattr(expected_process, 'pid', None) != expected_pid):
        return False
    try:
        return expected_process.poll() is None
    except BaseException:
        return False


def _observer_row(runtime, event_id):
    if type(event_id) is not int or type(runtime.observer_view) is not list:
        return None
    rows = [row for row in runtime.observer_view
        if type(row) is dict and row.get('event_id') == event_id]
    return rows[0] if len(rows) == 1 else None


def _validate_success_boundary(runtime, attempt, inventory):
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS

    observations = inventory.get('observations')
    if (type(observations) is not dict
            or set(observations) != set(EXPECTATION_IDS)
            or any(type(row) is not dict or row.get('status') != 'passed'
                for row in observations.values())):
        raise ValueError('f6-case-boundary-not-successful')

    cpu = runtime.cpu
    attempt_id = attempt.get('case_id')
    irq = observations.get('dma.irq_isr_completion')
    if type(irq) is not dict or len(irq.get('evidence_refs', ())) != 1:
        raise ValueError('f6-case-boundary-not-successful')
    ref = irq['evidence_refs'][0]
    row = inventory.get('evidence_inventory', {}).get(ref)
    details = row.get('details') if type(row) is dict else None
    if type(details) is not dict:
        raise ValueError('f6-case-boundary-not-successful')

    next_fetch = _observer_row(runtime, details.get('next_fetch'))
    expiry = _observer_row(runtime, details.get('irq_expiry_sample'))
    live_fetch = next_fetch
    if 'shared_slots' in runtime.contract['program_contract'] and next_fetch is not None:
        from .shared_f6_slots import current_boundary_after
        live_fetch = current_boundary_after(runtime, attempt, next_fetch)
    request = cpu._request_evidence.get('instr')
    if (next_fetch is None or next_fetch.get('kind') != 'native_fetch_boundary'
            or next_fetch.get('native_testcase_id') != runtime._f6_original_cpu_case_id
            or next_fetch.get('execution') != runtime._f6_original_cpu_execution
            or next_fetch.get('reset_epoch') != runtime._f6_original_cpu_reset_epoch
            or next_fetch.get('transaction') is None
            or type(request) is not dict
            or request.get('transaction') != live_fetch.get('transaction')
            or request.get('address') != live_fetch.get('address')
            or request.get('acceptance_tick') != live_fetch.get('local_tick')
            or cpu._waiting_instr is None
            or asdict(cpu._waiting_instr[0]) != live_fetch['transaction']
            or cpu._waiting_instr[1] != live_fetch['address']
            or cpu.waiting_instruction_address != live_fetch['address']
            or cpu._pending_instr is not None or cpu._pending_data is not None
            or getattr(cpu, '_queued_mmio', None)
            or cpu.pending_responses != 1
            or expiry is None or expiry.get('kind') != 'cpu_external_irq_sample'
            or expiry.get('actual_pre_input') != 0
            or expiry.get('actual_post_input') != 0
            or type(expiry.get('local_tick')) is not int
            or cpu.local_ticks < expiry['local_tick']
            or next_fetch.get('local_tick', 0) < expiry.get('local_tick', 0)):
        raise ValueError('f6-case-boundary-not-successful')

    issuer = getattr(cpu, '_f6_isr_return', None)
    from myfuzz.scenario.native_f6_isr_return import _issuer_state
    try:
        state = _issuer_state(issuer)
    except (TypeError, ValueError) as error:
        raise ValueError('f6-case-boundary-not-successful') from error
    expected_irq_key = [cpu.source_component, cpu.reset_epoch,
        cpu._native_irq_take_sequence + 1]
    if (state['active'] is not None
            or state['last_index'] != attempt.get('case_index')
            or attempt_id in state['case_ids'] and state['last_index'] != attempt.get('case_index')
            or tuple(expected_irq_key) in state['used_keys']
            or state['campaign_scope'] != (cpu._execution, cpu.reset_epoch,
                cpu._case_id)):
        raise ValueError('f6-case-boundary-not-successful')
    return dict(next_fetch=deepcopy(next_fetch), irq_expiry=deepcopy(expiry),
        next_irq_take_key=expected_irq_key)


def advance_f6_dma_logical_scope(runtime, attempt, *, next_case_index):
    """Advance the same DMA process to its next logical transaction scope."""
    if (type(next_case_index) is not int or type(attempt) is not dict
            or type(attempt.get('case_index')) is not int
            or next_case_index != attempt['case_index'] + 1
            or type(getattr(runtime, 'attempts', None)) is not list
            or not runtime.attempts or runtime.attempts[-1] is not attempt
            or next_case_index != len(runtime.attempts)
            or next_case_index >= getattr(runtime, 'max_cases', 0)):
        raise ValueError('f6-case-index')
    if getattr(runtime, 'finished', False):
        raise ValueError('f6-case-runtime-finished')

    case_ids = [row.get('case_id') for row in runtime.attempts
        if type(row) is dict]
    if (len(case_ids) != len(runtime.attempts)
            or any(type(item) is not str or not item for item in case_ids)
            or len(set(case_ids)) != len(case_ids)):
        raise ValueError('f6-case-testcase-id-reused')
    new_testcase_id = f'{runtime.run_id}:dma:{next_case_index}'
    used_ids = getattr(runtime, '_f6_used_dma_case_ids', None)
    if type(used_ids) is not set:
        raise ValueError('f6-case-testcase-ledger-invalid')
    if new_testcase_id in used_ids:
        raise ValueError('f6-case-testcase-id-reused')

    cpu, dma, runner = runtime.cpu, runtime.dma, runtime.runner
    cpu_id = runtime.contract['cpu']['instance_id']
    dma_id = runtime.contract['dma']['instance_id']
    if (getattr(runner, 'sessions', {}).get(cpu_id) is not cpu
            or getattr(runner, 'sessions', {}).get(dma_id) is not dma
            or cpu._process is None or dma._process is None
            or not _process_live(cpu, runtime._f6_original_cpu_process,
                runtime._f6_original_cpu_process_id)
            or not _process_live(dma, runtime._f6_original_dma_process,
                runtime._f6_original_dma_process_id)
            or cpu._execution != runtime._f6_original_cpu_execution
            or dma._execution != runtime._f6_original_dma_execution
            or cpu.reset_epoch != runtime._f6_original_cpu_reset_epoch
            or dma.reset_epoch != runtime._f6_original_dma_reset_epoch
            or cpu._case_id != runtime._f6_original_cpu_case_id):
        raise ValueError('f6-case-native-identity-drift')

    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    from myfuzz.local_harness.wishbone_dma_session import (
        GeneratedWishboneDmaSession, _F6_SCOPE_TRANSITION_ISSUER,
        _F6_SCOPE_TRANSITION_METHOD, _f6_dma_session_type_allowlist,
        _verify_f6_dma_route_validator)
    dma_session_types = _f6_dma_session_type_allowlist()
    if (type(dma) not in dma_session_types
            or type(runtime.route_admission) is not DmaMasterRouteAdmission
            or dma._dma_route_admission is not runtime.route_admission
            or type(runtime.policy) is not F6RamDmaPolicy
            or runtime.route_admission._beat_policy is not runtime.policy):
        raise ValueError('f6-case-owner-method-drift')
    try:
        _verify_f6_dma_route_validator(dma, admission=runtime.route_admission)
    except ValueError as error:
        raise ValueError('f6-case-owner-method-drift') from error

    from myfuzz.scenario.native_f6_isr_return import _issuer_state
    from myfuzz.scenario.f6_execution_contract import EXPECTATION_IDS
    from myfuzz.local_harness.f6_dma_response_fault import (
        _validate_f6_response_fault)
    from myfuzz.local_harness.wishbone_dma_session import (
        _F6_SCOPE_ADMISSION_BEGIN, _F6_SCOPE_POLICY_BEGIN,
        _F6_SCOPE_ISR_BEGIN, _F6_SCOPE_FAULT_BEGIN)
    admission, policy = runtime.route_admission, runtime.policy
    fault = _validate_f6_response_fault(dma)
    if (getattr(type(dma), '_advance_f6_logical_case', None) is not
            _F6_SCOPE_TRANSITION_METHOD
            or _F6_SCOPE_TRANSITION_METHOD.__code__ is not
                GeneratedWishboneDmaSession._advance_f6_logical_case.__code__
            or '_advance_f6_logical_case' in vars(dma)
            or type(admission).begin_case is not _F6_SCOPE_ADMISSION_BEGIN
            or type(admission).begin_case.__code__ is not _F6_SCOPE_ADMISSION_BEGIN.__code__
            or 'begin_case' in getattr(admission, '__dict__', {})
            or F6RamDmaPolicy.begin_case is not _F6_SCOPE_POLICY_BEGIN
            or F6RamDmaPolicy.begin_case.__code__ is not _F6_SCOPE_POLICY_BEGIN.__code__
            or 'begin_case' in vars(policy)
            or type(dma)._validate_dma_route_topology is not
                GeneratedWishboneDmaSession._validate_dma_route_topology
            or type(cpu._f6_isr_return).begin_case is not _F6_SCOPE_ISR_BEGIN
            or type(cpu._f6_isr_return).begin_case.__code__ is not
                _F6_SCOPE_ISR_BEGIN.__code__
            or _f6_response_fault_begin_mismatch(fault, _F6_SCOPE_FAULT_BEGIN)):
        raise ValueError('f6-case-owner-method-drift')

    frozen = getattr(runtime, '_f6_case_freezes', {}).get(attempt['case_id'])
    if type(frozen) is not dict:
        raise ValueError('F6 independent case inventory is immutable')
    inventory = _freeze_matches(runtime, attempt, frozen)
    if (type(inventory.get('observations')) is not dict
            or set(inventory['observations']) != set(EXPECTATION_IDS)
            or any(inventory['observations'][eid].get('status') != 'passed'
                for eid in EXPECTATION_IDS)):
        raise ValueError('f6-case-boundary-not-successful')
    boundary = _validate_success_boundary(runtime, attempt, inventory)

    previous_index = attempt['case_index']
    previous_dma_id = dma._case_id
    if (type(used_ids) is not set or previous_dma_id not in used_ids
            or len(used_ids) != len(set(used_ids))):
        raise ValueError('f6-case-testcase-ledger-invalid')
    if (policy._scope != (dma._execution, previous_dma_id)
            or policy.state != 'complete' or policy._pending is not None
            or policy._read != 4 or policy._write != 4
            or len(policy.records) != 8 or len(admission.route_matches) != 8
            or dma._pending is not None or dma.pending_responses
            or dma.memory_service.ledger.pending_keys
            or dma.memory_service.ledger.unresolved_keys):
        raise ValueError('f6-case-boundary-not-successful')
    if (fault is not None and (fault._selected is not None
            or fault._active is not None or fault._case_index != previous_index)):
        raise ValueError('f6-case-boundary-not-successful')

    issuer = cpu._f6_isr_return
    try:
        issuer_state = _issuer_state(issuer)
    except (TypeError, ValueError) as error:
        raise ValueError('f6-case-boundary-not-successful') from error
    case_id = f'{runtime.run_id}:case:{next_case_index}'
    take_key = boundary['next_irq_take_key']
    if (issuer_state['active'] is not None
            or issuer_state['last_index'] != previous_index
            or case_id in issuer_state['case_ids']
            or tuple(take_key) in issuer_state['used_keys']):
        raise ValueError('f6-case-boundary-not-successful')

    # Snapshot immutable Task5 evidence before the DMA-only scope transition.
    route_snapshot = deepcopy(admission.route_matches)
    policy_snapshot = deepcopy(policy.records)
    transition = dma._advance_f6_logical_case(
        testcase_id=new_testcase_id, case_index=next_case_index,
        previous_case_index=previous_index, expected_case_id=previous_dma_id,
        used_testcase_ids=tuple(sorted(used_ids)),
        expected_process=runtime._f6_original_dma_process,
        expected_process_id=runtime._f6_original_dma_process_id,
        expected_execution=runtime._f6_original_dma_execution,
        expected_reset_epoch=runtime._f6_original_dma_reset_epoch,
        route_matches_snapshot=route_snapshot,
        policy_records_snapshot=policy_snapshot,
        _issuer=_F6_SCOPE_TRANSITION_ISSUER)

    try:
        issuer.begin_case(case_id, case_index=next_case_index,
            irq_take_key=take_key)
    except BaseException as error:
        runtime._f6_terminal_error = error
        raise
    attempt['route_match_history'] = route_snapshot
    attempt['policy_records'] = policy_snapshot
    attempt['scope_transition'] = dict(previous_case_id=previous_dma_id,
        testcase_id=new_testcase_id, case_id=case_id,
        case_index=next_case_index)
    used_ids.add(new_testcase_id)
    runtime._f6_last_dma_case_index = next_case_index
    transition.update(status='advanced', previous_case_id=previous_dma_id,
        testcase_id=new_testcase_id, case_id=case_id)
    return transition


def _f6_response_fault_begin_mismatch(fault, expected):
    if fault is None:
        return False
    from myfuzz.local_harness.f6_dma_response_fault import F6ResponseFault
    method = getattr(F6ResponseFault, 'begin_case', None)
    return (type(fault) is not F6ResponseFault or method is not expected
        or getattr(method, '__code__', None) is not expected.__code__)


def _f6_runner_ownership(existing, *, cpu_id, dma_id):
    """Preserve declared owners and add the static one-bit DMA IRQ route."""
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    if not hasattr(existing, '_bits') or type(existing._bits) is not dict:
        raise ValueError('compiled-F6-ownership-required')
    fields = [InputField(component, port, len(bits))
        for (component, port), bits in existing._bits.items()]
    owners = [InputOwner(**row) for row in existing.document()['owners']]
    key = (cpu_id, 'irq')
    expected = InputOwner(cpu_id, 'irq', 0, 1, 'bound', f'{dma_id}.irq')
    prior = existing._bits.get(key)
    if prior is None:
        fields.append(InputField(cpu_id, 'irq', 1))
        owners.append(expected)
    elif len(prior) != 1 or prior[0] != expected:
        raise ValueError('compiled-F6-IRQ-ownership-mismatch')
    return compile_ownership(tuple(fields), tuple(owners))


def _f6_configuration_values(contract):
    p=contract['program_contract'];dma=contract['dma']
    length=16 if dma.get('behavior',{}).get('length_unit')=='bytes' else 4
    return [p['source_address'],p['destination_address'],length,dma['csr']['start_word']]


def _f6_level_clear_tick(runtime, delivery, journal, observer_start):
    """Find a sampled CPU low after an observed DMA clear, never an expiry."""
    group=runtime.runner.irq_group_for(runtime._irq_binding)
    if group is None:return None
    rows=[r for r in runtime.observer_view if r.get('event_id',0)>observer_start]
    takes=[r for r in rows if r.get('kind')=='cpu_external_irq_taken'
        and r.get('component')==runtime.cpu_id and r.get('reset_epoch')==runtime.cpu.reset_epoch
        and r.get('binding_delivery_event_id')==delivery['event_id']
        and r.get('source_output_key')==delivery['source_output_key']]
    if len(takes)!=1:return None
    take=takes[0]; frames=[r for r in journal if r.get('kind')=='irq_group_delivery'
        and r.get('group_id')==group.group_id and r.get('group_sha256')==group.identity_sha256
        and r.get('target_epoch')==runtime.cpu.reset_epoch]
    if not any(f.get('native_take_event_id')==take.get('runner_event_id')
            and f.get('cpu_tick')==take.get('local_tick')
            and f.get('unique_source')==runtime.dma_id+'.irq' for f in frames):return None
    clear=runtime.contract['dma']['behavior']['irq_clear']
    address=runtime.contract['control']['base']+clear['offset']
    accepts=[r for r in rows if r.get('kind')=='data_accept' and r.get('component')==runtime.cpu_id
        and r.get('address')==address and r.get('write')==1 and r.get('wdata')==clear['value']
        and r.get('event_id')>take['event_id']]
    if clear.get('method')!='write' or len(accepts)!=1:return None
    key=accepts[0].get('transaction')
    if (type(key) is not dict or key.get('source_component')!=runtime.cpu_id
            or key.get('source_epoch')!=runtime.cpu.reset_epoch or key.get('testcase_id')!=runtime.cpu._case_id
            or key.get('execution_id')!='local-execution'):return None
    deliveries=[r for r in rows if r.get('kind')=='mmio_delivery' and r.get('component')==runtime.cpu_id
        and r.get('source_transaction')==key and r.get('device_id')==runtime.contract['control']['device_id']
        and r.get('address')==address and r.get('write') is True]
    responses=[r for r in rows if r.get('kind')=='data_response' and r.get('component')==runtime.cpu_id
        and r.get('transaction')==key and r.get('address')==address and r.get('write')==1]
    if len(deliveries)!=1 or len(responses)!=1:return None
    receipt=deliveries[0].get('dma_control_receipt')
    expected=dict(source_transaction=key,address=address,offset=clear['offset'],write=True,
        value=clear['value'],byte_enable=clear['byte_enable'])
    if type(receipt) is not dict or any(receipt.get(k)!=v for k,v in expected.items()):return None
    ticks=receipt.get('edge_ticks')
    if type(ticks) is not list or not ticks or any(type(t) is not int for t in ticks):return None
    by_id={r.get('event_id'):r for r in journal}
    for frame in frames:
        if frame.get('value')!=0 or type(frame.get('cpu_tick')) is not int or frame['cpu_tick']<=take['local_tick']:
            continue
        members=frame.get('members'); sample=by_id.get(frame.get('native_sample_event_id'))
        if type(members) is not list or not members:continue
        member=next((m for m in members if m.get('source_id')==runtime.dma_id+'.irq'),None)
        ref=member.get('latest_native_source') if type(member) is dict else None
        raw=by_id.get(ref.get('event_id')) if type(ref) is dict else None
        if (member is None or member.get('mode')!='level' or member.get('value')!=0
                or type(raw) is not dict or raw.get('kind')!='local_tick_sample'
                or raw.get('component')!=runtime.dma_id or raw.get('reset_epoch')!=runtime.dma.reset_epoch
                or raw.get('local_tick')!=ref.get('local_tick') or raw.get('phase')!='post'
                or raw.get('phase')!=ref.get('phase')
                or type(raw.get('local_tick')) is not int or raw['local_tick']<ticks[0]
                or type(raw.get('event_id')) is not int or type(take.get('runner_event_id')) is not int
                or raw['event_id']<=take['runner_event_id']
                or raw.get('outputs',{}).get('irq')!=0
                or raw.get('outputs',{}).get('physical',{}).get(runtime.dma._irq_runtime_name)!=0
                or type(sample) is not dict or sample.get('kind')!='cpu_external_irq_sample'
                or sample.get('component')!=runtime.cpu_id or sample.get('reset_epoch')!=runtime.cpu.reset_epoch
                or type(sample.get('event_id')) is not int or sample['event_id']<=raw['event_id']
                or sample.get('local_tick')!=frame['cpu_tick']
                or any(sample.get(k)!=0 for k in ('expected_input','actual_pre_input','actual_post_input'))):continue
        return frame['cpu_tick']
    return None


def _f6_actual_irq_binding(runner, *, dma_id, cpu_id, cpu_port, irq_contract=None):
    """The installed DMA->CPU IRQ binding, including its real target bit.

    A CPU whose external interrupt is a bit-slice of a wider vector input
    declares a non-zero target bit; the runner's group membership and pulse map
    are keyed by that actual binding, so guessing ``Binding(..., 1)`` would
    silently address the wrong bit (and miss the pulse entirely).
    """
    from myfuzz.scenario.runner import Binding
    candidates = [b for b in runner.bindings
        if b.source_component == dma_id and b.source_port == 'irq'
        and b.target_component == cpu_id and b.target_port == cpu_port
        and b.width == 1 and b.source_bit_offset == 0]
    if not candidates:
        raise ValueError('compiled-F6-DMA-IRQ-binding-unavailable')
    if len(candidates) != 1:
        raise ValueError('compiled-F6-DMA-IRQ-binding-ambiguous')
    binding = candidates[0]
    group = runner.irq_group_for(binding)
    if group is not None:
        members = [(m,b) for m,b in zip(group.members, group.member_bindings())
            if (m.source_component,m.source_port) == (dma_id,'irq')]
        if (len(members) != 1 or members[0][1] != binding
                or group.target_component != cpu_id or group.target_port != cpu_port
                or group.target_bit_offset != binding.target_bit_offset):
            raise ValueError('compiled-F6-DMA-IRQ-group-member-mismatch')
    level = (type(irq_contract) is dict and irq_contract.get('delivery_policy')=='level'
        and irq_contract.get('target_local_ticks')==0 and irq_contract.get('clear_policy')=='software_write')
    if level:
        if (group is None or members[0][0].mode!='level' or binding in runner._irq_pulses):
            raise ValueError('compiled-F6-DMA-IRQ-level-unavailable')
    elif binding not in runner._irq_pulses:
        raise ValueError('compiled-F6-DMA-IRQ-pulse-unavailable')
    return binding


def _validate_epoch_boot_image(runtime, *, reset_policy, barrier_event_id, expected_epoch, next_slot):
    """Bind a resumed program to the actual reset event and installed memory."""
    from .compiled_f6_firmware import render_epoch_program
    from hashlib import sha256
    runner = runtime.runner
    barrier = runner._event_ref_by_id(barrier_event_id)
    if (type(barrier) is not dict or barrier.get('kind') != 'reset_barrier'
            or barrier.get('policy') != reset_policy):
        raise ValueError('compiled-F6-epoch-program-unbound')
    rendered = render_epoch_program(runtime.contract, reset_epoch=expected_epoch, slot=next_slot)
    address = runtime.contract['program_contract']['boot_address']
    original, current = runtime.program.initial_images, rendered['program'].initial_images
    if set(original) != set(current) or any(original[a] != current[a] for a in original if a != address):
        raise ValueError('compiled-F6-epoch-program-unbound')
    expected = current[address]
    events = [event for event in runner._event_refs_since(barrier_event_id, stop=runner.event_count)
        if event.get('kind') == 'reset_image' and event.get('reset_event_id') == barrier_event_id
        and event.get('component') == runtime.cpu_id and event.get('address') == address]
    if len(events) != 1 or events[0].get('data_hex') != expected.hex():
        raise ValueError('compiled-F6-epoch-program-unbound')
    event_id = events[0]['event_id']
    if len(expected) % 4:
        raise ValueError('compiled-F6-epoch-program-unbound')
    for offset in range(0, len(expected), 4):
        snapshot = runtime.memory.read(address + offset, 4,
                                       transaction_id=f'epoch-image:{event_id}:{offset}')
        if (snapshot.data != expected[offset:offset + 4]
                or snapshot.writer_kinds != ('RESET_IMAGE',) * 4
                or snapshot.writer_event_ids != (f'reset-image:{event_id}',) * 4):
            raise ValueError('compiled-F6-epoch-program-unbound')
    return dict(entry=rendered['entry'], manifest_sha256=rendered['program'].manifest_sha256,
                image_event_id=event_id, boot_sha256=sha256(expected).hexdigest(),
                barrier_event_id=barrier_event_id, reset_epoch=expected_epoch)


def _f6_epoch_execution_receipt(runtime, result):
    """Project real reset-image, retired boot jump and first admitted slot fetch.

    No certificate is returned when any part is absent. Fetch authority remains
    with the installed issuer; a slot address or rendered program alone is not
    evidence that the reset program executed.
    """
    from myfuzz.scenario.f6_instruction_fetch_receipt import (
        f6_instruction_fetch_receipts, validate_f6_instruction_fetch)
    try:
        epoch=runtime._f6_epoch_program;cpu=runtime.cpu;runner=runtime.runner
        entry=epoch['entry']['entry_address'];barrier=epoch['barrier_event_id']
        image_id=epoch['image_event_id'];reset_epoch=epoch['reset_epoch']
        if (result.get('status')!='passed' or result.get('instruction_address')!=entry
                or cpu.reset_epoch!=reset_epoch):return None
        prefix=bytes.fromhex(result['prefix_hex'])
        events=runner._event_refs_since(barrier,stop=runner.event_count)
        def one(rows):
            return rows[0] if len(rows)==1 else None
        image=one([e for e in events if e.get('kind')=='reset_image'
            and e.get('event_id')==image_id and e.get('reset_event_id')==barrier
            and e.get('component')==runtime.cpu_id])
        if image is None:return None
        data=bytes.fromhex(image['data_hex'])
        if len(data)<4 or len(data)%4 or sha256(data).hexdigest()!=epoch['boot_sha256']:return None
        address=image['address']+len(data)-4;word=int.from_bytes(data[-4:],'little')
        immediate=(((word>>31)&1)<<20 | ((word>>21)&0x3ff)<<1
                   | ((word>>20)&1)<<11 | ((word>>12)&0xff)<<12)
        if immediate&(1<<20):immediate-=1<<21
        if word&0xfff!=0x6f or (address+immediate)&0xffffffff!=entry:return None
        reads=[e for e in events if e.get('kind')=='memory_read'
            and e.get('component')==runtime.cpu_id and e.get('address')==address
            and e.get('data_hex')==data[-4:].hex()
            and list(e.get('writer_event_ids',()))==[f'reset-image:{image_id}']*4
            and e.get('transaction',{}).get('source_epoch')==reset_epoch
            and e.get('transaction',{}).get('source_component')==runtime.cpu_id
            and e.get('transaction',{}).get('channel_id')=='instr']
        read=one(reads)
        if read is None:return None
        response=one([e for e in events if e.get('kind')=='instr_response'
            and e.get('component')==runtime.cpu_id and e.get('address')==address
            and e.get('transaction')==read['transaction'] and e.get('rdata')==word
            and e.get('error')==0])
        if response is None:return None
        response_step=runner._event_ref_by_id(response.get('producer_event_id'))
        outputs=response_step.get('outputs',{}) if isinstance(response_step,dict) else {}
        if (response_step is None or response_step.get('component')!=runtime.cpu_id
                or response_step.get('local_tick')!=response.get('response_tick')
                or outputs.get('instr_rsp_consumed')!=1
                or outputs.get('instr_rsp_source_epoch')!=reset_epoch
                or outputs.get('instr_rsp_source_sequence')!=read['transaction']['source_sequence']
                or outputs.get('instr_rsp_rdata')!=word):return None
        retire=one([e for e in events if e.get('kind')=='cpu_retire'
            and e.get('schema_version')=='cpu_retire.v2' and e.get('component')==runtime.cpu_id
            and e.get('pc_rdata')==address and e.get('insn')==word and e.get('valid')==1
            and e.get('command_scope',{}).get('reset_epoch')==reset_epoch])
        if retire is None or retire.get('local_tick',-1)<response.get('response_tick',0):return None
        step=runner._event_ref_by_id(retire.get('producer_event_id'))
        samples=step.get('outputs',{}).get('driver_samples') if isinstance(step,dict) else None
        if (not isinstance(step,dict) or step.get('component')!=runtime.cpu_id
                or step.get('local_tick')!=retire.get('local_tick')
                or not isinstance(samples,(tuple,list)) or len(samples)!=1):return None
        physical=cpu._physical_outputs({'observations':samples[0]['post']})
        observed=retire['observation']['physical']
        if (any(physical.get(name)!=value for name,value in observed.items())
                or observed.get('rvfi_valid')!=1 or observed.get('rvfi_pc_rdata')!=address
                or observed.get('rvfi_insn')!=word):return None
        receipts=[r for r in f6_instruction_fetch_receipts(cpu)
            if r.case_id==result['case_id'] and r.address==entry
            and r.reset_epoch==reset_epoch and r.execution==cpu._execution]
        receipt=one(receipts)
        if receipt is None:return None
        validate_f6_instruction_fetch(cpu,receipt)
        if (receipt.acceptance.address!=entry or receipt.acceptance.data!=prefix
                or receipt.snapshot.data!=prefix[:4]):return None
        completion=one([e for e in events if e.get('kind')=='compiled_F6_instruction_fetch_completion'
            and e.get('component')==runtime.cpu_id and e.get('case_id')==result['case_id']
            and e.get('address')==entry and e.get('reset_epoch')==reset_epoch
            and e.get('execution')==cpu._execution and e.get('key')==asdict(receipt.key)])
        if (completion is None or not image_id<read['event_id']<response['event_id']<retire['event_id']
                or completion['event_id']<=image_id):return None
        return dict(manifest_sha256=epoch['manifest_sha256'],entry=deepcopy(epoch['entry']),
            evidence=dict(image_event_id=image_id,boot_read_event_id=read['event_id'],
                boot_response_event_id=response['event_id'],boot_retirement_event_id=retire['event_id'],
                slot_fetch_event_id=completion['event_id']))
    except (AttributeError,KeyError,TypeError,ValueError,RuntimeError,OverflowError):
        return None


class CompiledF6Runtime(BuiltProcessAudit):
    """One continuous CPU/DMA process pair for the compiled F6 contract."""

    _audit_error_prefix = 'compiled-F6'
    _audit_schema = 'compiled_F6_execution_audit.v1'

    @staticmethod
    def run_custom_irq_observation(*, artifacts, compiled_inputs, base_dir, cache_dir,
                                   raw, output_dir, max_steps=4096):
        """Execute one custom-IRQ CPU/DMA case without issuing F6 certificates.

        This bounded observation path uses actual independent sessions and the
        same F6 candidate/firmware generators. It does not replace the shared
        online F1-F6 executor and does not infer IRQ source or retirement.
        """
        from myfuzz.scenario.f6_execution_contract import compile_f6_execution_contract
        from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
        from myfuzz.integration.compiled_f6_layout import F6Candidate
        from myfuzz.integration.shared_f6_assembly import build_f6_custom_irq_cpu
        from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
        from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
        from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
        from myfuzz.scenario.memory_service import MemoryService
        from myfuzz.scenario.ledger import TransactionLedger
        from myfuzz.scenario.router import DataflowRouter, DeviceWindow
        from myfuzz.scenario.runner import ScenarioRunner
        from myfuzz.scenario.genome import ScenarioGenome, MemoryImage
        from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
        from myfuzz.scenario.contracts import ResourceBudget
        if type(compiled_inputs) is not dict or 'request' not in compiled_inputs:
            raise ValueError('compiled-F6-custom-observation-inputs-required')
        contract=compile_f6_execution_contract(compiled_inputs['request'],base_dir=base_dir)
        program=contract['program_contract']; custom=program.get('custom_irq')
        if custom is None or 'gpio_irq' in program or 'declared_irq' in program:
            raise ValueError('compiled-F6-custom-observation-single-DMA-required')
        cpu_id=contract['cpu']['instance_id']; dma_id=contract['dma']['instance_id']
        if type(artifacts) is not dict or set(artifacts)!={cpu_id,dma_id}:
            raise ValueError('compiled-F6-custom-observation-artifacts-required')
        cpu_art=artifacts[cpu_id]; dma_art=artifacts[dma_id]
        verify_custom_irq_artifact(cpu_art,base_dir=base_dir)
        if (cpu_art.plan.profile.profile_fingerprint != contract['cpu']['profile_fingerprint']
                or dma_art.plan.profile.profile_fingerprint != contract['dma']['profile_fingerprint']
                or cpu_art.plan.request.instance_id != cpu_id or dma_art.plan.request.instance_id != dma_id
                or dma_art.runtime_document.get('kind') != 'wishbone_dma'):
            raise ValueError('compiled-F6-custom-observation-artifact-mismatch')
        if type(raw) is not bytes or len(raw)!=8 or type(max_steps) is not int or not 1<=max_steps<=65536:
            raise ValueError('compiled-F6-custom-observation-case-invalid')
        value=int.from_bytes(raw,'little')
        candidate=F6Candidate(raw,tuple((value>>(11*i))&0x7ff for i in range(4)))
        firmware=build_f6_firmware(contract)
        resource=contract['memory']['resource']; control=contract['control']
        def factory():
            memory=PersistentMemory(regions=(MemoryRegion(resource['resource_id'],resource['base'],
                resource['size'],readable=resource['read'],writable=resource['write']),),
                initialization_seed=0,max_initialized_bytes=resource['size'])
            service=MemoryService(memory,TransactionLedger(),include_writer_kinds=True)
            dma=GeneratedWishboneDmaScenarioSession(dma_art,base_dir=base_dir,cache_dir=cache_dir,
                memory_service=service,source_component=dma_id,max_control_edges=32,max_events=10000)
            router=DataflowRouter((DeviceWindow(control['device_id'],control['base'],control['size'],dma),))
            shared=build_f6_custom_irq_cpu(artifact=cpu_art,base_dir=base_dir,cache_dir=cache_dir,
                memory=memory,router=router,irq_sources=((dma_id,'irq',custom['irq_bit']),))
            boundary=(program['slot_base']+program['slot_bytes'] if program['slot_count']>1
                      else program['park_address'])
            shared.cpu.declare_instruction_slots(boundary,1)
            binding=shared.bindings[0]
            pulses={binding:16} if contract['irq']['delivery_policy']=='IrqPulseDelivery' else None
            runner=ScenarioRunner(sessions={cpu_id:shared.cpu,dma_id:dma},ownership=shared.ownership,
                                  bindings=shared.bindings,irq_pulses=pulses)
            runner.configure_memory_dependency_evidence(runtime_contract_sha256=_digest(contract))
            return runner
        images=tuple(MemoryImage('firmware-'+str(i),cpu_id,address,data.hex())
                     for i,(address,data) in enumerate(firmware.initial_images.items()))
        images+=(MemoryImage('candidate',cpu_id,program['slot_base'],firmware.prefix(candidate,case_index=0).hex()),)
        case=ScenarioGenome(testcase_id='custom-f6-observation',direction='CPU_TO_IP_TO_CPU',
            path_id=contract['path_id'],schedule_order=(dma_id,cpu_id),max_steps=max_steps,
            actions=(),initial_images=images)
        trace=save_evidence_bundle(case,factory,output_dir,budget=ResourceBudget(
            max_wall_time_ms=120000,max_materialized_bytes_per_memory=resource['size']))
        replay=replay_evidence_bundle(output_dir,factory)
        events=getattr(trace,'events',())
        cpu_samples=[event.get('outputs',{}).get('custom_irq_observation') for event in events
                     if event.get('component')==cpu_id and isinstance(event.get('outputs'),dict)]
        cpu_samples=[row for row in cpu_samples if type(row) is dict]
        dma_levels=[event.get('outputs',{}).get('irq') for event in events
                    if event.get('component')==dma_id and isinstance(event.get('outputs'),dict)
                    and type(event.get('outputs',{}).get('irq')) is int]
        return dict(schema_version='compiled_custom_F6_observation.v1',trace_status=trace.status,
            fresh_matches=replay.matches,observation_scope='actual_CPU_DMA_and_custom_IRQ_inputs',
            observed_irq_input_high=any(row['irq_pre'] & (1<<custom['irq_bit']) for row in cpu_samples),
            observed_eoi_high=any(row['eoi_post'] & (1<<custom['irq_bit']) for row in cpu_samples),
            observed_dma_irq_high=any(value==1 for value in dma_levels),
            irq_source_attribution='unknown',retirement='unknown',f6_certificate='not_granted',
            feedback='unknown')

    @capture_build_construction
    def __init__(self, *, artifacts, compiled_inputs, base_dir, cache_dir,
                 run_id='compiled-f6', rounds_per_case=4096, max_cases=16,
                 build_audit_sink=None, response_fault=None, defer_begin=False,
                 shared_assembly=None):
        if (type(rounds_per_case) is not int or not 1 <= rounds_per_case <= 65536
                or type(max_cases) is not int or not 1 <= max_cases <= 16):
            raise ValueError('compiled-F6-budget-invalid')
        if type(run_id) is not str or not run_id or run_id.strip() != run_id:
            raise ValueError('compiled-F6-run-id-invalid')
        if build_audit_sink is not None and not callable(build_audit_sink):
            raise ValueError('compiled-F6-build-audit-sink-invalid')
        if type(defer_begin) is not bool:
            raise ValueError('compiled-F6-defer-begin-invalid')

        from pathlib import Path
        from myfuzz.integration.compiled_f6_runtime_path import (
            admit_compiled_f6_runtime_path, restore_prepared_runtime_paths,
            _artifact_link_document)
        from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
        from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
        from myfuzz.scenario.compiled_paths import compiled_document_sha256
        from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
        from myfuzz.scenario.memory_service import MemoryService
        from myfuzz.scenario.ledger import TransactionLedger
        from myfuzz.scenario.router import DataflowRouter, DeviceWindow
        from myfuzz.scenario.genome import ScenarioGenome, MemoryImage
        from myfuzz.scenario.session_runtime import ScenarioSession
        from myfuzz.scenario.dma_intent_topology_binding import PreparedDmaIntentBinding
        from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
        from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
        from myfuzz.local_harness.cpu_session import GeneratedCve2Session
        from myfuzz.local_harness.wishbone_dma_scenario_session import (
            GeneratedWishboneDmaScenarioSession)
        from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
        from myfuzz.scenario.f6_execution_binding import (
            build_f6_execution_binding, validate_f6_execution_binding)
        from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return
        from myfuzz.local_harness.f6_dma_response_fault import (
            F6ResponseFaultDeclaration, install_f6_response_fault)

        self.base_dir = Path(base_dir)
        self.cache_dir = Path(cache_dir)
        self.run_id = run_id
        self.rounds_per_case = rounds_per_case
        self.max_cases = max_cases
        self._build_audit_sink = build_audit_sink
        self.response_fault = response_fault
        self._caller_artifacts = artifacts
        self._caller_compiled_inputs = compiled_inputs
        self.artifacts = artifacts

        request = compiled_inputs['request']
        cpu_id = request.cpu.instance_id
        dma_ids = {route.initiator_instance
            for route in request.wiring.dma_master_routes}
        if len(dma_ids) != 1:
            raise ValueError('compiled-F6-DMA-instance-required')
        dma_id, = dma_ids
        # D2/D3 admission and the execution binding consume the caller's
        # compiled-input ownership verbatim. The runtime adds only its static
        # IRQ wiring to a separate Runner ownership map after admission.
        # The top-level map is the mutable caller boundary. Nested request and
        # compiled capability objects are immutable (some contain mappingproxy)
        # and cannot be deep-copied; retain those identities while detaching
        # the map itself before runtime-owned IRQ ownership is added below.
        self.compiled_inputs = dict(compiled_inputs)
        self.runtime_path_admission = admit_compiled_f6_runtime_path(
            artifacts=artifacts, compiled_inputs=self.compiled_inputs,
            base_dir=self.base_dir)
        self.path = deepcopy(self.runtime_path_admission['logical_path'])
        self.contract = deepcopy(self.path['execution_contract'])
        if 'custom_irq' in self.contract['program_contract']:
            self._init_custom_online(shared_assembly=shared_assembly, defer_begin=defer_begin)
            return
        ownership = _f6_runner_ownership(self.compiled_inputs['ownership'],
            cpu_id=cpu_id, dma_id=dma_id)
        self.runner_ownership = ownership
        from .shared_f6_assembly import shared_irq_ownership
        ownership = shared_irq_ownership(ownership,self.contract,artifacts,base_dir=self.base_dir)
        self.runner_ownership = ownership
        self.compiled_document_sha256 = compiled_document_sha256(
            self.compiled_inputs['compiled'])
        self.layout = compile_f6_candidate_layout(self.path)
        self.program = build_f6_firmware(self.contract)
        declared_irq=self.contract['program_contract'].get('declared_irq')
        if declared_irq is not None:
            from .shared_f6_assembly import shared_irq_group
            group=shared_irq_group(self.contract,artifacts,base_dir=self.base_dir)
            candidates=[row for row in self.compiled_inputs['compiled']['paths']
                        if row.get('flow_id')=='F5' and row.get('status')=='executable'
                        and row.get('direction')=='CPU_TO_IP']
            dispatcher=self.program.document().get('irq_dispatch',{}).get('declared_firmware')
            member=declared_irq['irq_group_member']
            if (len(candidates)!=1 or type(dispatcher) is not dict or group is None
                    or sum(m.source_component==member['source_component']
                           and m.source_port==member['source_port']
                           and m.source_bit_offset==member['source_bit_offset']
                           and m.source_adapter==member['source_adapter']
                           for m in group.members)!=1
                    or dispatcher.get('target_base')!=declared_irq['target_window']['base']
                    or dispatcher.get('status_offsets')!=declared_irq['status_offsets']
                    or dispatcher.get('result_address')!=declared_irq['result_address']):
                raise ValueError('compiled-F6-declared-IRQ-slot-and-ISR-not-integrated')
        if max_cases > self.contract['program_contract']['slot_count']:
            raise ValueError('compiled-F6-budget-invalid')

        self.records = []
        self.attempts = []
        self.cursor = 0
        self.trace = None
        self.finished = False
        self.observer_view = []
        self.checker_findings = lambda: []
        self.protocol_checker_case_report = None
        self._observer_offsets = {}
        self._runner_observer_cursor = None
        self._issuer_event_count = 0
        self._observer_raw_event_ids = {}
        self._observer_commit_ids = set()
        self._active_f6_irq_delivery = None
        self._f6_pending_fetch_sample = None
        self._f6_pending_fetch_sample_conflict = False
        self._f6_last_irq_source_event = None
        self._f6_used_dma_case_ids = set()
        self._f6_last_dma_case_index = 0
        self._f6_case_freezes = {}
        self._f6_terminal_error = None
        self._replay_material = None
        self._replay_identities = []
        self._stop_after_expected_error = False
        self._terminal_error = None
        self._finish_document = None
        self._finish_started = False
        self._session_finish_called = False

        resource = self.contract['memory']['resource']
        from myfuzz.integration.shared_f6_assembly import F6Assembly, build_f6_assembly
        assembly_inputs = dict(contract=self.contract, artifacts=artifacts,
            ownership=ownership, base_dir=self.base_dir, cache_dir=self.cache_dir, request=request)
        if shared_assembly is None:
            assembly = build_f6_assembly(**assembly_inputs)
        else:
            if type(shared_assembly) is not F6Assembly:
                raise ValueError('compiled-F6-shared-assembly-type')
            assembly = shared_assembly.validate(**assembly_inputs)
        self.assembly = assembly
        cpu, dma, memory = assembly.cpu, assembly.dma, assembly.memory
        self.runner = assembly.runner
        self._irq_binding = _f6_actual_irq_binding(self.runner,
            dma_id=dma_id, cpu_id=cpu_id, cpu_port=cpu.irq_input_port,
            irq_contract=self.contract['irq'])
        dma_protocol_checker = self.runner.install_protocol_checker(dma_id)
        if (not callable(getattr(dma_protocol_checker, 'snapshot', None))
                or not callable(getattr(dma_protocol_checker, 'report', None))):
            raise ValueError('compiled-F6-dual-endpoint-protocol-checker-required')
        # The Runner's commit hook receives both CPU stores and DMA RAM writes.
        # Pin each real service and its one transaction channel explicitly;
        # the CPU source writer remains data-only and the DMA mover remains
        # dma-memory-only. Task5's own consumer still validates the four-word
        # snapshots and destination commits against their respective services.
        from myfuzz.scenario.ibex_pulp_dual_source import (
            install_host_ram_commit_journal)
        install_host_ram_commit_journal(self.runner,
            services={cpu_id: cpu.service, dma_id: dma.service},
            channel_ids={cpu_id: 'data', dma_id: 'dma-memory'})
        # Measured shared GPIO/ISR slots reach 6207 journal events. Preserve
        # the issuer's absolute 65536 ceiling; beyond it state stays unknown.
        shared = self.contract['program_contract'].get('shared_slots', {})
        ram_feedback = {'F1','F3'} <= set(shared.get('enabled_flows', ()))
        memory_feedback_gap = (min(65536,8192*self.contract['program_contract']['slot_count'])
            if ram_feedback else 4096)
        self.runner.configure_memory_dependency_evidence(
            runtime_contract_sha256=_digest(self.contract),max_event_gap=memory_feedback_gap)
        self._build_sessions = dict(self.runner.sessions)
        for local in self._build_sessions.values():
            local.configure_built_executable_receipt()
        # The session manifest asks each opted-in local session for its
        # built-executable receipt. Prepare both binaries before begin() so
        # that identity capture is backed by the receipt that will be used by
        # the subsequent native launch.
        for name, local in sorted(self._build_sessions.items()):
            local.prepare_local()
        self._built_receipts = {name: local.validate_built_executable_receipt()
            for name, local in sorted(self._build_sessions.items())}
        from myfuzz.integration.compiled_build_join import validate_built_receipts
        validate_built_receipts(self.artifacts, self._built_receipts)

        prepared = restore_prepared_runtime_paths(self.runtime_path_admission)
        declaration = PreparedDmaIntentBinding.from_document(
            self.runtime_path_admission['dma_intent_binding'],
            prepared_runtime_paths=prepared)
        instruction_path_id = self.runtime_path_admission['runtime_path_ids'][1]
        instruction_binding = InstructionImageSourceBinding(
            path_id=instruction_path_id, direction='CPU_TO_IP',
            source_id=self.contract['instruction_source_id'],
            logical_source_id=self.contract['instruction_source_id'],
            component=cpu_id, memory_id=resource['resource_id'],
            base=resource['base'], size=resource['size'],
            readable=resource['read'], writable=resource['write'])
        instruction_bindings = [instruction_binding]
        if 'shared_flow_paths' in self.runtime_path_admission:
            from .shared_slot_consumers import instruction_bindings as instruction_bindings_for_runtime
            instruction_bindings.extend(binding for flow,binding in
                instruction_bindings_for_runtime(self.runtime_path_admission).items() if flow != 'F6')
        template = _f6_session_template(run_id=run_id, cpu_id=cpu_id,
            path_id=instruction_path_id, program=self.program,
            rounds_per_case=rounds_per_case, runner=self.runner)
        self.session = ScenarioSession(template, self.runner,
            checker_configuration_only=True)
        for address, count in self.program.instruction_slots:
            self.session.declare_instruction_slots(cpu_id, address, count)
        self.session.configure_runtime_paths(prepared.graph, prepared.contract,
            prepared.runtime_paths, source_ownership=ownership,
            dma_intent_binding=declaration,
            boundary_static_validation=_TOPOLOGY_VALIDATION_MODE.get() == 'boundary',
            dma_artifact_links={dma_id: _artifact_link_document(artifacts[dma_id])},
            instruction_image_bindings=tuple(instruction_bindings))
        if 'gpio_irq' in self.contract['program_contract']:
            gpio = self.contract['program_contract']['gpio_irq']
            self.runner.configure_gpio_irq_dependency_evidence(
                source_component=gpio['component'],target_component=cpu_id,pin=gpio['pin'],
                runtime_contract_sha256=prepared.contract.identity_sha256)
        self.bound_topology = self.session.bound_dma_topology
        routes = {route.operation: route
            for route in prepared.contract.dma_master_routes}
        self.policy = F6RamDmaPolicy(self.contract)
        self.route_admission = DmaMasterRouteAdmission(self.policy,
            self.bound_topology, path_id=self.runtime_path_admission['runtime_path_ids'][0],
            read_route=routes['read'], write_route=routes['write'])
        dma.configure_dma_route_admission(self.route_admission)

        self.execution_binding = build_f6_execution_binding(
            contract=self.contract, artifacts=artifacts,
            compiled_inputs=self.compiled_inputs, base_dir=self.base_dir,
            run_id=run_id, program=self.program, runner=self.runner,
            bound_topology=self.bound_topology)
        self.binding_sha256 = self.execution_binding['binding_sha256']
        self.execution_binding_sha256 = self.binding_sha256
        self.cpu, self.dma, self.memory = cpu, dma, memory
        self.cpu_id, self.dma_id = cpu_id, dma_id
        self._f6_irq_runtime_name = f6_dma_irq_runtime_name(
            dma, self.contract['irq'])
        self.inputs = self.compiled_inputs
        self._f6_isr_return = install_f6_isr_return(cpu,
            contract=self.contract,
            execution_binding_sha256=self.execution_binding_sha256)
        from myfuzz.scenario.f6_instruction_fetch_receipt import install_f6_instruction_fetch
        self._f6_instruction_fetch = install_f6_instruction_fetch(cpu, self.session,
            contract=self.contract, run_id=run_id,
            execution_binding_sha256=self.execution_binding_sha256, max_cases=max_cases)
        if 'shared_slots' in self.contract['program_contract']:
            from .shared_f6_slots import install_slot_ledger
            install_slot_ledger(self)
        if response_fault is not None:
            if type(response_fault) is not F6ResponseFaultDeclaration:
                raise ValueError('compiled-F6-response-fault-invalid')
            if response_fault.case_index >= max_cases:
                raise ValueError('compiled-F6-response-fault-outside-budget')
            install_f6_response_fault(dma, declaration=response_fault,
                execution_binding_sha256=self.execution_binding_sha256)
        if defer_begin:
            validate_f6_execution_binding(self.execution_binding,
                contract=self.contract, artifacts=artifacts,
                compiled_inputs=self.compiled_inputs, base_dir=self.base_dir,
                run_id=run_id, program=self.program, runner=self.runner,
                bound_topology=self.bound_topology)

        self._deferred_begin = defer_begin
        self._begin_state = 'created'
        self._begun = False
        if not defer_begin:
            self.begin()

    def _init_custom_online(self, *, shared_assembly, defer_begin):
        """Use the shared assembler and online session with observation-only evidence."""
        from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
        from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
        from myfuzz.integration.shared_f6_assembly import F6Assembly, build_f6_assembly
        from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
        from myfuzz.scenario.session_runtime import ScenarioSession
        if self.response_fault is not None:
            raise ValueError('compiled-F6-custom-response-fault-not-integrated')
        cpu_id=self.contract['cpu']['instance_id']; dma_id=self.contract['dma']['instance_id']
        bit=self.contract['program_contract']['custom_irq']['irq_bit']
        gpio=self.contract['program_contract'].get('gpio_irq')
        sources={bit:dma_id+'.irq'}
        if gpio is not None:
            outputs=[row for row in self.artifacts[gpio['component']].runtime_document['physical_exports']
                     if row.get('role')=='irq' and row.get('direction')=='output'
                     and row.get('width')==1 and row.get('bit_lo')==row.get('bit_hi')==0]
            if len(outputs)!=1:
                raise ValueError('compiled-F6-custom-gpio-IRQ-export')
            sources[gpio['irq_bit']]=gpio['component']+'.'+outputs[0]['physical_port']
        original=self.compiled_inputs['ownership'].document()
        prior=self.compiled_inputs['ownership']._bits.get((cpu_id,'irq'))
        if prior is not None and len(prior)!=32:
            raise ValueError('compiled-F6-custom-IRQ-owner-width')
        gpio_producer=None
        if gpio is not None:
            rows=[r for r in self.compiled_inputs['compiled']['paths']
                  if r['flow_id']=='F5' and r['status']=='executable']
            producers=[b for row in rows for b in row['bound_inputs']
                       if b['kind']=='ip_irq' and b['component']==gpio['component']]
            if len(producers)!=1:
                raise ValueError('compiled-F6-custom-gpio-source-owner')
            gpio_producer=producers[0]['input_id']
            for source,expected_bit in ((dma_id,bit),(gpio['component'],gpio['irq_bit'])):
                routes=[d for d in self.compiled_inputs['request'].wiring.deliveries
                    if d.producer_instance==source and d.consumer_instance==cpu_id]
                if len(routes)!=1 or getattr(routes[0],'consumer_bit_offset',None)!=expected_bit:
                    raise ValueError('compiled-F6-custom-IRQ-delivery-bit')
        fields=[InputField(**row) for row in original['fields']
                if (row['component_id'],row['port'])!=(cpu_id,'irq')]+[InputField(cpu_id,'irq',32)]
        owners=[InputOwner(**row) for row in original['owners']
                if (row['component_id'],row['port'])!=(cpu_id,'irq')]
        for i in range(32):
            old=prior[i] if prior is not None else None
            if i==bit:
                if old is not None and (old.kind!='fixed' or old.producer_ref not in ('constant_zero','inactive')):
                    raise ValueError('compiled-F6-custom-DMA-IRQ-owner')
                kind,producer='bound',sources[i]
            elif gpio is not None and i==gpio['irq_bit']:
                if old is not None and (old.kind!='bound' or old.producer_ref!=gpio_producer):
                    raise ValueError('compiled-F6-custom-gpio-IRQ-owner')
                kind,producer='bound',sources[i]
            else:
                if old is not None and (old.kind!='fixed' or old.producer_ref not in ('constant_zero','inactive')):
                    raise ValueError('compiled-F6-custom-IRQ-inactive-owner')
                kind,producer='fixed',old.producer_ref if old is not None else 'inactive'
            owners.append(InputOwner(cpu_id,'irq',i,1,kind,producer))
        self.runner_ownership=compile_ownership(tuple(fields),tuple(owners))
        self.layout=compile_f6_candidate_layout(self.path)
        self.program=build_f6_firmware(self.contract)
        if self.max_cases>self.contract['program_contract']['slot_count']:
            raise ValueError('compiled-F6-budget-invalid')
        kwargs=dict(contract=self.contract,artifacts=self.artifacts,ownership=self.runner_ownership,
            base_dir=self.base_dir,cache_dir=self.cache_dir,request=self.compiled_inputs['request'])
        if shared_assembly is None:
            self.assembly=build_f6_assembly(**kwargs)
        elif type(shared_assembly) is F6Assembly:
            self.assembly=shared_assembly.validate(**kwargs)
        else:
            raise ValueError('compiled-F6-shared-assembly-type')
        self.cpu,self.dma,self.memory,self.runner=(self.assembly.cpu,self.assembly.dma,
            self.assembly.memory,self.assembly.runner)
        self.cpu_id,self.dma_id=cpu_id,dma_id
        self.runner.configure_memory_dependency_evidence(runtime_contract_sha256=_digest(self.contract))
        self._build_sessions=dict(self.runner.sessions)
        for local in self._build_sessions.values():
            local.configure_built_executable_receipt()
        for _,local in sorted(self._build_sessions.items()):
            local.prepare_local()
        self._built_receipts={name:local.validate_built_executable_receipt()
                              for name,local in sorted(self._build_sessions.items())}
        from myfuzz.integration.compiled_build_join import validate_built_receipts
        validate_built_receipts(self.artifacts,self._built_receipts)
        template=_f6_session_template(run_id=self.run_id,cpu_id=cpu_id,
            path_id=self.contract['path_id'],program=self.program,
            rounds_per_case=self.rounds_per_case,runner=self.runner)
        self.session=ScenarioSession(template,self.runner,checker_configuration_only=True)
        for address,count in self.program.instruction_slots:
            self.session.declare_instruction_slots(cpu_id,address,count)
        from .compiled_f6_runtime_path import restore_prepared_runtime_paths, _artifact_link_document
        from myfuzz.scenario.dma_intent_topology_binding import PreparedDmaIntentBinding
        from myfuzz.scenario.instruction_image_binding import InstructionImageSourceBinding
        prepared=restore_prepared_runtime_paths(self.runtime_path_admission)
        declaration=PreparedDmaIntentBinding.from_document(
            self.runtime_path_admission['dma_intent_binding'],prepared_runtime_paths=prepared)
        self._custom_dma_declaration=declaration
        resource=self.contract['memory']['resource']
        image=InstructionImageSourceBinding(path_id=self.runtime_path_admission['runtime_path_ids'][1],
            direction='CPU_TO_IP',source_id=self.contract['instruction_source_id'],
            logical_source_id=self.contract['instruction_source_id'],component=cpu_id,
            memory_id=resource['resource_id'],base=resource['base'],size=resource['size'],
            readable=resource['read'],writable=resource['write'])
        bindings=[image]
        if 'shared_flow_paths' in self.runtime_path_admission:
            from .shared_slot_consumers import instruction_bindings
            bindings.extend(binding for flow,binding in instruction_bindings(self.runtime_path_admission).items()
                            if flow!='F6')
        self.session.configure_runtime_paths(prepared.graph,prepared.contract,prepared.runtime_paths,
            source_ownership=self.runner_ownership,dma_intent_binding=declaration,
            boundary_static_validation=_TOPOLOGY_VALIDATION_MODE.get()=='boundary',
            dma_artifact_links={dma_id:_artifact_link_document(self.artifacts[dma_id])},
            instruction_image_bindings=tuple(bindings))
        self.bound_topology=self.session.bound_dma_topology
        self.execution_binding=dict(schema_version='custom_irq_online_observation_binding.v1',
            contract_sha256=_digest(self.contract),admission_sha256=self.runtime_path_admission['admission_sha256'],
            evidence='observation_only',retirement='unknown',source_attribution='unknown')
        self.execution_binding_sha256=_digest(self.execution_binding)
        self.binding_sha256=self.execution_binding_sha256
        self.records=[]; self.attempts=[]; self.cursor=0; self.finished=False
        self._finish_document=None; self._terminal_error=None
        self._custom_online=True; self._begin_state='created'; self._begun=False
        self._deferred_begin=defer_begin
        if not defer_begin:
            self.begin()

    def _begin_custom_online(self):
        self.session.begin()
        target=self.contract['program_contract']['slot_base']
        schedule=tuple(self.runner.sessions)
        for _ in range(self.rounds_per_case):
            if self.cpu.waiting_instruction_address==target:
                return
            self.session.advance_initial(schedule)
            if self.runner.failure_status:
                break
        raise RuntimeError('compiled-F6-custom-bootstrap-boundary-not-observed')

    def _submit_custom_online(self, raw, flow):
        from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
        from myfuzz.scenario.session_runtime import OnlineCase, BoundOnlineInstruction, OnlineInstruction
        if self.cursor>=self.max_cases:
            raise ValueError('compiled-F6-case-budget-exhausted')
        p=self.contract['program_contract']; index=self.cursor
        allowed=p.get('shared_slots',{}).get('enabled_flows',['F6'])
        if flow not in allowed:
            raise ValueError('compiled-F6-unsupported-flow')
        if flow=='F6':
            candidate=self.layout.decode(raw)
            code=self.program.prefix(candidate,case_index=index)
            path_id=self.runtime_path_admission['runtime_path_ids'][1]; direction='CPU_TO_IP'
            source_id=self.contract['instruction_source_id']
        elif flow in ('F1','F2','F3','F4'):
            from .shared_slot_consumers import declare_slot
            declaration=declare_slot(self.compiled_inputs,p['shared_slots'],self.runtime_path_admission,
                flow=flow,raw=raw,slot_index=index,instruction_isa=self.memory.instruction_isa)
            code=bytes.fromhex(declaration['code_hex'])
            path=self.runtime_path_admission['shared_flow_paths'][flow]
            path_id=path['path_id']; direction='CPU_TO_IP'
            source_id=path['source_id']
        elif flow=='F5' and 'gpio_irq' in p:
            from .shared_f5_slots import declare_shared_pin
            declaration=declare_shared_pin(self.compiled_inputs,p['shared_slots'],self.runtime_path_admission,
                raw=raw,slot_index=index)
            code=bytes.fromhex(declaration['code_hex'])
            path_id=declaration['path_id'];direction=declaration['direction']
        else:
            raise ValueError('compiled-F6-custom-flow-not-integrated:'+str(flow))
        slot=p['slot_base']+p['slot_bytes']*index
        if self.cpu.waiting_instruction_address!=slot:
            raise RuntimeError('compiled-F6-custom-slot-boundary-not-observed')
        following=slot+p['slot_bytes'] if index+1<p['slot_count'] else p['park_address']
        case_id=self.run_id+':'+flow+':'+str(index)
        advances=tuple(BatchAdvance((name,)) for _ in range(self.rounds_per_case)
                       for name in self.runner.sessions)
        if flow=='F5':
            pin=BatchSourceEvent(case_id+':pin',declaration['component'],declaration['port'],
                declaration['value'],declaration['bit_offset'],declaration['width'])
            support=OnlineInstruction(case_id+':fixed-support',self.cpu_id,slot,code.hex())
            case=OnlineCase(case_id,direction,path_id,pin,advances,(support,))
        else:
            instruction=BoundOnlineInstruction(case_id+':instruction',self.cpu_id,slot,code.hex(),source_id)
            case=OnlineCase(case_id,direction,path_id,instruction,advances)
        receipt=self.session.submit_case(case,stop_on_runner_failure=True,
            stop_after_advance=lambda _:self.cpu.waiting_instruction_address==following)
        reached=(self.cpu.waiting_instruction_address==following
                 and receipt.status=='running' and not receipt.violations)
        result=dict(case_id=case_id,flow=flow,slot_index=index,raw8_hex=raw.hex(),
            status='observed' if reached else 'unknown',next_fetch_observed=reached,
            irq_source_attribution='unknown',retirement='unknown',certificate='not_granted',
            feedback='unknown',reward_eligible=False,event_start=receipt.event_start,
            event_end=receipt.event_end)
        if flow in ('F1','F2','F3','F4','F5','F6'):
            from .custom_irq_observations import project_custom_irq_events
            gpio=p.get('gpio_irq'); gpio_exports=[]
            if gpio is not None:
                gpio_exports=[row for row in self.artifacts[gpio['component']].runtime_document['physical_exports']
                    if row.get('role')=='irq' and row.get('direction')=='output' and row.get('width')==1]
            gpio_export=gpio_exports[0] if len(gpio_exports)==1 else {}
            result['observations']=project_custom_irq_events(receipt.events,cpu_id=self.cpu_id,
                dma_id=self.dma_id,dma_irq_name=self.dma._irq_runtime_name,
                dma_irq_bit=p['custom_irq']['irq_bit'],gpio_id=gpio['component'] if gpio else None,
                gpio_irq_name=gpio_export.get('runtime_name'),gpio_irq_port=gpio_export.get('physical_port'),
                gpio_irq_bit=gpio['irq_bit'] if gpio else None,
                transfer_contract=self.contract if flow=='F6' else None,
                transfer_words=candidate.words if flow=='F6' else None,flow=flow)
        self.records.append(result); self.attempts.append(result); self.cursor+=1
        if not reached:
            self._terminal_error=RuntimeError('compiled-F6-custom-next-boundary-not-observed')
        return deepcopy(result)

    def begin(self):
        """Start the prepared CPU/DMA pair exactly once and observe first fetch."""
        if self._begin_state == 'begun':
            raise ValueError('compiled-F6-already-begun')
        if self._begin_state != 'created':
            raise ValueError('compiled-F6-begin-failed')
        self._begin_state = 'starting'
        try:
            if getattr(self,'_custom_online',False):
                self._begin_custom_online()
            else:
                self._begin_once()
            self._begun = True
            self._begin_state = 'begun'
        except BaseException as error:
            self._begin_state = 'failed'
            self._terminal_error = error
            if getattr(self.session, '_begun', False) and not getattr(self.session, '_finished', False):
                try:
                    self.session.finish()
                except BaseException as cleanup:
                    error.add_note('compiled-F6 session cleanup: ' + repr(cleanup))
            # A local begin can fail after launching a child but before the
            # ScenarioSession has recorded its begin. Reap every local owner.
            for local in self._build_sessions.values():
                try:
                    local.end_case()
                except BaseException as cleanup:
                    error.add_note('compiled-F6 startup cleanup: ' + repr(cleanup))
            self.finished = True
            if self._deferred_begin and self._build_audit_sink is not None:
                try:
                    self._build_audit_sink(diagnostic_build_snapshot(self, closed=True, error=error))
                except BaseException as audit_error:
                    error.add_note('compiled-F6 partial build audit: ' + repr(audit_error))
            raise

    def _begin_once(self):
        from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding

        if (set(self._caller_compiled_inputs) != set(self.compiled_inputs)
                or any(self._caller_compiled_inputs[key] is not value
                       for key, value in self.compiled_inputs.items())):
            raise ValueError('compiled-F6-input-owner-changed')
        validate_f6_execution_binding(self.execution_binding,
            contract=self.contract, artifacts=self.artifacts,
            compiled_inputs=self.compiled_inputs, base_dir=self.base_dir,
            run_id=self.run_id, program=self.program, runner=self.runner,
            bound_topology=self.bound_topology)
        self._validated_built_receipts()
        cpu, dma, run_id = self.cpu, self.dma, self.run_id
        self.session.begin()
        self._runner_observer_cursor = self.runner.event_count
        self._native_processes = {name: local.process
            for name, local in self.runner.sessions.items()}
        self._process_identities = self._validated_build_process_identities()
        startup_build = self.build_audit_snapshot()
        if self._build_audit_sink is not None:
            self._build_audit_sink(deepcopy(startup_build))
        self._f6_original_cpu_process = cpu.process
        self._f6_original_dma_process = dma.process
        self._f6_original_cpu_process_id = cpu.process.pid
        self._f6_original_dma_process_id = dma.process.pid
        self._f6_original_cpu_execution = cpu._execution
        self._f6_original_dma_execution = dma._execution
        self._f6_original_cpu_reset_epoch = cpu.reset_epoch
        self._f6_original_dma_reset_epoch = dma.reset_epoch
        self._f6_original_cpu_case_id = cpu._case_id
        self._f6_used_dma_case_ids.add(dma._case_id)
        if set(self.contract['program_contract']) & {'gpio_irq','declared_irq'}:
            from .shared_f6_assembly import shared_irq_group
            group = shared_irq_group(self.contract,self.artifacts,base_dir=self.base_dir)
            self.session.advance_initial(tuple(dict.fromkeys(member.source_component for member in group.members)))
        if 'shared_slots' not in self.contract['program_contract']:
            self._f6_isr_return.begin_case(run_id + ':case:0', case_index=0,
                irq_take_key=[cpu.source_component, cpu.reset_epoch,
                    cpu._native_irq_take_sequence + 1])
        from .f6_storage_support import capture_support_start, capture_support_phase
        capture_support_start(self)
        self._bootstrap_to_first_slot()
        capture_support_phase(self, 'before')

    def rebind_reset_epoch(self, *, reset_policy, barrier_event_id, expected_epoch,
                           next_slot):
        """Resume a shared-slot CPU from a measured, installed epoch boot image."""
        from .compiled_process_audit import bind_reset_epoch_launch
        from .shared_f6_slots import rebind_slot_scope
        from myfuzz.scenario.f6_instruction_fetch_receipt import install_f6_instruction_fetch
        if (type(next_slot) is not int
                or not 1 <= next_slot < self.contract['program_contract']['slot_count']):
            raise ValueError('compiled-F6-reset-rebind-slot')
        cpu, dma = self.cpu, self.dma
        if (self.finished or self._begin_state != 'begun' or self._terminal_error is not None
                or type(expected_epoch) is not int
                or expected_epoch != self._f6_original_cpu_reset_epoch + 1
                or cpu.reset_epoch != expected_epoch or dma.reset_epoch != expected_epoch
                or cpu._case_id != self._f6_original_cpu_case_id
                or cpu.process is self._f6_original_cpu_process
                or dma.process is self._f6_original_dma_process
                or cpu.process is None or cpu.process.poll() is not None
                or dma.process is None or dma.process.poll() is not None):
            raise ValueError('compiled-F6-reset-rebind-identity-mismatch')
        epoch = _validate_epoch_boot_image(self, reset_policy=reset_policy,
            barrier_event_id=barrier_event_id, expected_epoch=expected_epoch, next_slot=next_slot)
        operations = self.session._reset_operations
        image = operations[-1].get('image') if operations else None
        if (self.runner.command_epoch != len(operations) or type(image) is not dict
                or image.get('address') != self.contract['program_contract']['boot_address']
                or image.get('component') != self.cpu_id
                or sha256(bytes.fromhex(image.get('data_hex', ''))).hexdigest() != epoch['boot_sha256']):
            raise ValueError('compiled-F6-epoch-program-not-replayable')
        prior_binding = getattr(self, '_epoch_launch', None)
        if prior_binding is None or prior_binding.get('reset_epoch') != expected_epoch:
            bind_reset_epoch_launch(self, reset_epoch=expected_epoch,
                barrier_event_id=barrier_event_id, policy=reset_policy)
        elif (prior_binding.get('barrier_event_id') != barrier_event_id
                or prior_binding.get('policy') != reset_policy
                or self._validated_build_process_identities() != self._process_identities):
            raise ValueError('compiled-F6-built-process-identity-changed')
        self._f6_epoch_program = epoch
        try:
            rebind_slot_scope(self, barrier_event_id=barrier_event_id, next_slot=next_slot)
            self._f6_original_cpu_process, self._f6_original_dma_process = cpu.process, dma.process
            self._f6_original_cpu_process_id, self._f6_original_dma_process_id = cpu.process.pid, dma.process.pid
            self._f6_original_cpu_execution, self._f6_original_dma_execution = cpu._execution, dma._execution
            self._f6_original_cpu_reset_epoch, self._f6_original_dma_reset_epoch = cpu.reset_epoch, dma.reset_epoch
            self._f6_pending_fetch_sample = None
            self._f6_pending_fetch_sample_conflict = False
            self._f6_instruction_fetch = install_f6_instruction_fetch(cpu, self.session,
                contract=self.contract, run_id=self.run_id,
                execution_binding_sha256=self.execution_binding_sha256, max_cases=self.max_cases)
            if set(self.contract['program_contract']) & {'gpio_irq','declared_irq'}:
                # A reset invalidates every IRQ source sample. As during initial
                # startup, observe each real source before the CPU consumes the OR.
                # The session records these steps for fresh reset replay.
                from .shared_f6_assembly import shared_irq_group
                group = shared_irq_group(self.contract,self.artifacts,base_dir=self.base_dir)
                schedule = tuple(dict.fromkeys(member.source_component for member in group.members))
                receipt = self.session.advance_after_reset(schedule)
                if receipt.violations or receipt.status not in ('running', 'complete'):
                    raise RuntimeError('compiled-F6-reset-IRQ-source-sampling-failed')
            self._bootstrap_to_first_slot(entry_address=epoch['entry']['entry_address'])
        except BaseException as error:
            self._terminal_error = error
            raise
        return deepcopy(epoch)

    def _bootstrap_to_first_slot(self, *, entry_address=None):
        cpu_id = self.contract['cpu']['instance_id']
        dma_id = self.contract['dma']['instance_id']
        first_slot = self.contract['program_contract']['slot_base'] if entry_address is None else entry_address
        for _ in range(self.rounds_per_case):
            receipt = (self.session.advance_initial(self.session.template.schedule_order)
                if entry_address is None else self.session.advance_after_reset(self.session.template.schedule_order))
            self._drain_observer_view()
            if receipt.violations or receipt.status not in ('running', 'complete'):
                raise RuntimeError('compiled-F6-bootstrap-stopped')
            if self.cpu.waiting_instruction_address == first_slot:
                self._first_fetch = dict(address=first_slot,
                    transaction=deepcopy(self.cpu._request_evidence['instr']['transaction']),
                    acceptance_tick=self.cpu._request_evidence['instr']['acceptance_tick'])
                return
        raise RuntimeError('compiled-F6-first-slot-not-pending')

    @staticmethod
    def _jsonable(value):
        if hasattr(value, '__dataclass_fields__'):
            return CompiledF6Runtime._jsonable(asdict(value))
        if type(value) is dict:
            return {key: CompiledF6Runtime._jsonable(item)
                    for key, item in value.items()}
        if type(value) in (list, tuple):
            return [CompiledF6Runtime._jsonable(item) for item in value]
        return deepcopy(value)

    def _append_observer(self, row, component, *, runner_event_id=None):
        document = self._jsonable(row)
        if type(document) is not dict:
            return None
        document['component'] = component
        if runner_event_id is not None:
            document['runner_event_id'] = runner_event_id
        document['event_id'] = len(self.observer_view) + 1
        self.observer_view.append(document)
        self._observer_raw_event_ids[id(row)] = document['event_id']
        self._observer_raw_event_ids[id(document)] = document['event_id']
        return document['event_id']

    def _validated_f6_irq_runtime_name(self):
        runtime_name = f6_dma_irq_runtime_name(self.dma, self.contract['irq'])
        pinned = getattr(self, '_f6_irq_runtime_name', None)
        if type(pinned) is not str or pinned != runtime_name:
            raise ValueError('compiled-F6-DMA-IRQ-runtime-export-drift')
        return runtime_name

    def _raw_dma_irq_edge(self):
        runtime_name = self._validated_f6_irq_runtime_name()
        dma_id = self.contract['dma']['instance_id']
        for event in reversed(getattr(self, 'observer_view', ())):
            if (event.get('component') != dma_id
                    or event.get('kind') != 'dma_edge'):
                continue
            physical = (event.get('payload', {}).get('observations', {})
                        .get('physical', {}))
            if runtime_name in physical:
                value = physical.get(runtime_name)
                return event if type(value) is int and value == 1 else None
        for event in reversed(self.dma.events):
            physical = (event.get('payload', {}).get('observations', {})
                        .get('physical', {}))
            if runtime_name in physical:
                value = physical.get(runtime_name)
                return event if type(value) is int and value == 1 else None
        return None

    def _publish_f6_irq_delivery(self, _event=None):
        if getattr(self, '_active_f6_irq_delivery', None) is not None:
            return
        level = self.contract['irq'].get('delivery_policy') == 'level'
        if level:
            group=self.runner.irq_group_for(self._irq_binding)
            state=self.runner._irq_group_states[group.group_id]
            sample=state.samples.get(self._irq_binding)
            origin=sample.get('pulse_origin') if sample and sample.get('value')==1 else None
            if origin is None:return
            runtime_name=self._validated_f6_irq_runtime_name()
            candidates=[row for row in self.observer_view if row.get('kind')=='dma_edge'
                and row.get('component')==self.contract['dma']['instance_id']
                and row.get('tick')==origin['local_tick'] and row.get('reset_epoch')==origin['reset_epoch']
                and row.get('payload',{}).get('observations',{}).get('physical',{}).get(runtime_name)==1]
            source=candidates[0] if len(candidates)==1 else None
        else:
            source = self._raw_dma_irq_edge()
        if (source is None
                or source is getattr(self, '_f6_last_irq_source_event', None)):
            return
        self._f6_last_irq_source_event = source
        source_tick = source.get('tick')
        source_epoch = source.get('reset_epoch')
        if (type(source_tick) is not int or source_tick < 1
                or type(source_epoch) is not int
                or source_epoch != self.dma.reset_epoch):
            raise ValueError('compiled-F6-DMA-IRQ-source-scope-invalid')
        source_id = self._observer_raw_event_ids.get(id(source))
        if source_id is None:
            return
        dma_id = self.contract['dma']['instance_id']
        cpu_id = self.contract['cpu']['instance_id']
        source_port = self.contract['irq']['producer_port']
        source_key = [dma_id, source_epoch, source_port, source_tick]
        output_id = self._append_observer(dict(kind='source_start',
            source_output_key=source_key, source=[dma_id, 'irq'],
            target=[cpu_id, 'irq'], producer_event_id=source_id,
            source_event_id=source_id), dma_id)
        if level:
            start,end=self.cpu.local_ticks+1,None
        else:
            pulse = self.runner._irq_pulses[self._irq_binding]
            if (type(output_id) is not int or type(pulse._pulse_start) is not int
                    or type(pulse._pulse_end) is not int
                    or pulse._pulse_end - pulse._pulse_start != 16):
                raise ValueError('compiled-F6-IRQ-pulse-interval-invalid')
            start,end=pulse._pulse_start,pulse._pulse_end
        delivery_id = self._append_observer(dict(kind='binding_delivery',
            source_event_id=output_id, source_output_key=source_key,
            delivery_id=self.contract['irq']['delivery_id'],
            target_component=cpu_id, target_epoch=self.cpu.reset_epoch,
            start_local_tick=start, end_local_tick=end), cpu_id)
        self._active_f6_irq_delivery = dict(
            output_id=output_id, delivery_id=delivery_id,
            source_output_key=source_key,
            start_local_tick=start, end_local_tick=end)

    def _arm_native_irq_context(self):
        delivery = getattr(self, '_active_f6_irq_delivery', None)
        next_tick = self.cpu.local_ticks + 1
        if self.contract['irq'].get('delivery_policy')=='level':
            group=self.runner.irq_group_for(self._irq_binding)
            state=self.runner._irq_group_states[group.group_id]
            sample=state.samples.get(self._irq_binding)
            active=(delivery is not None and sample is not None and sample['value']==1
                and sample['pulse_origin'] is not None
                and sample['pulse_origin']['local_tick']==delivery['source_output_key'][3]
                and sample['pulse_origin']['reset_epoch']==delivery['source_output_key'][1])
            if active:
                self.cpu.set_next_irq_input_context(dict(
                    schema_version='native_irq_input_context.v1',
                    binding_delivery_event_id=delivery['delivery_id'],expected_input=1,
                    source_output_key=deepcopy(delivery['source_output_key']),
                    target_component=self.cpu.source_component,target_epoch=self.cpu.reset_epoch))
            else:self.cpu.set_next_irq_input_context(None)
            return
        if (delivery is not None and delivery['start_local_tick'] <= next_tick
                < delivery['end_local_tick']):
            self.cpu.set_next_irq_input_context(dict(
                schema_version='native_irq_input_context.v1',
                binding_delivery_event_id=delivery['delivery_id'],
                expected_input=1,
                source_output_key=deepcopy(delivery['source_output_key']),
                target_component=self.cpu.source_component,
                target_epoch=self.cpu.reset_epoch))
        else:
            self.cpu.set_next_irq_input_context(None)

    def _start_transfer_from_cpu_source(self, attempt):
        from myfuzz.local_harness.f6_dma_response_fault import (
            F6ResponseFaultDeclaration)
        source = self.contract['program_contract']['source_address']
        source_versions = []
        for index in range(4):
            address = source + 4 * index
            snapshot = self.cpu.memory.read(address, 4,
                transaction_id=f'compiled-F6-policy:{attempt["case_id"]}:{index}')
            source_versions.append(dict(address=address, value=snapshot.value,
                memory_id=snapshot.memory_id, generation=snapshot.generation,
                byte_offset=snapshot.byte_offset,
                versions=[list(value) for value in snapshot.versions],
                writer_event_ids=list(snapshot.writer_event_ids),
                writer_kinds=list(snapshot.writer_kinds)))
        fault = self.response_fault
        if (type(fault) is not F6ResponseFaultDeclaration
                or fault.case_index != attempt['case_index']):
            fault = None
        self.policy.begin_transfer(case_id=attempt['case_id'],
            source_versions=source_versions, fault=fault)

    def _drain_observer_view(self):
        cpu_id = self.contract['cpu']['instance_id']
        dma_id = self.contract['dma']['instance_id']
        event_count = getattr(self.runner, 'event_count', None)
        events_since = getattr(self.runner, 'events_since', None)
        # The tail rows are copied into the observer view by ``_append_observer``
        # before anything retains them, and ``id(row)`` is only a lookup key into
        # the append-only journal, so the detaching ``events_since`` copy is not
        # needed here; the borrowed reader returns the same rows in the same
        # order without copying the tail for every component step.
        refs_since = getattr(self.runner, '_event_refs_since', None)
        if type(event_count) is int and callable(events_since):
            cursor = getattr(self, '_runner_observer_cursor', None)
            if cursor is None:
                cursor = 0
            if type(cursor) is not int or not 0 <= cursor <= event_count:
                raise RuntimeError('compiled-F6-runner-event-cursor-invalid')
            records = (refs_since(cursor) if callable(refs_since)
                else events_since(cursor))
            if (type(records) not in (tuple, list)
                    or len(records) != event_count - cursor):
                raise RuntimeError('compiled-F6-runner-event-prefix-incomplete')
            for runner_event_id, row in enumerate(records, start=cursor + 1):
                if type(row) is not dict:
                    raise RuntimeError('compiled-F6-runner-event-record-invalid')
                component = row.get('component')
                kind = row.get('kind', row.get('schema_version'))
                if (type(row.get('event_id')) is not int
                        or row['event_id'] != runner_event_id):
                    raise RuntimeError('compiled-F6-runner-event-identity-invalid')
                if (component in (cpu_id, dma_id)
                        and kind in _F6_OBSERVER_KINDS):
                    self._append_observer(row, component,
                        runner_event_id=runner_event_id)
            self._runner_observer_cursor = event_count
        else:
            streams = ((cpu_id, self.cpu.cpu_events), (cpu_id, self.cpu.service.events),
                (cpu_id, self.cpu.router.acceptances), (cpu_id, self.cpu.router.deliveries),
                (dma_id, self.dma.events), (dma_id, self.dma.memory_service.events),
                )
            for owner, stream in streams:
                offset = self._observer_offsets.get(id(stream), 0)
                for row in stream[offset:]:
                    self._append_observer(row, owner)
                self._observer_offsets[id(stream)] = len(stream)

        if self._active_f6_irq_delivery is None:
            self._publish_f6_irq_delivery(None)

        if not (type(event_count) is int and callable(events_since)):
            for owner, service in ((cpu_id, self.cpu.service),
                                   (dma_id, self.dma.memory_service)):
                for row in service.drain_commit_events():
                    if (owner, row.get('commit_id')) in getattr(self,
                            '_observer_commit_ids', set()):
                        continue
                    self._observer_commit_ids = getattr(self,
                        '_observer_commit_ids', set())
                    self._observer_commit_ids.add((owner, row.get('commit_id')))
                    self._append_observer(row, owner)

        events = self._f6_isr_return.events
        for row in events[self._issuer_event_count:]:
            self._append_observer(row, cpu_id)
        self._issuer_event_count = len(events)

    def _on_component_step(self, attempt, component, _outputs):
        self._drain_observer_view()
        if component == self.cpu.source_component:
            self._capture_f6_pending_fetch_sample(attempt)
        if component == self.cpu.source_component and self.cpu._queued_mmio:
            control = self.contract['control']
            control_offset = self.contract['dma']['csr']['offsets']['control']
            request = self.cpu._request_evidence.get('data', {})
            if (self.policy.state == 'ready'
                    and request.get('address') == control['base'] + control_offset
                    and request.get('write') == 1
                    and request.get('wdata') == _f6_configuration_values(self.contract)[3]):
                self._start_transfer_from_cpu_source(attempt)
        if component == self.dma.source_component:
            self._arm_native_irq_context()

    def _capture_f6_pending_fetch_sample(self, attempt):
        """Latch one actual PRE handshake for the still-pending F6 boundary fetch.

        This is private scheduling state only. Task5's source-backed consumer
        remains the authority for the completed boundary and its evidence.
        """
        if (type(attempt) is not dict or type(attempt.get('case_id')) is not str
                or type(attempt.get('case_index')) is not int
                or getattr(self, '_f6_pending_fetch_sample_conflict', False)):
            return False
        cpu = self.cpu
        issuer = getattr(self, '_f6_isr_return',
            getattr(cpu, '_f6_isr_return', None))
        return_events = getattr(issuer, 'events', None)
        if type(return_events) not in (tuple, list):
            return False
        returns = [event for event in return_events
            if type(event) is dict and event.get('case_id') == attempt['case_id']
            and event.get('case_index') == attempt['case_index']]
        if len(returns) != 1:
            return False

        request = cpu._request_evidence.get('instr')
        waiting = cpu._waiting_instr
        if (type(request) is not dict or type(request.get('address')) is not int
                or type(request.get('acceptance_tick')) is not int
                or request['acceptance_tick'] != cpu.local_ticks
                or request.get('transaction') is None or waiting is None
                or type(waiting) not in (tuple, list) or len(waiting) != 2):
            return False
        transaction = CompiledF6Runtime._jsonable(request['transaction'])
        if (CompiledF6Runtime._jsonable(waiting[0]) != transaction
                or waiting[1] != request['address']
                or cpu.waiting_instruction_address != request['address']
                or cpu.pending_responses != 1):
            return False

        samples = (*getattr(cpu, '_last_drained_physical_tick_samples', ()),
            *getattr(cpu, '_physical_tick_samples', ()))
        at_tick = [row for row in samples
            if type(row) is dict and row.get('local_tick') == request['acceptance_tick']]
        unique = {_canonical(row): row for row in at_tick}
        if len(unique) != 1:
            return False
        sample = next(iter(unique.values()))
        backend = sample.get('pre', {}).get('backend', {})
        if (type(backend) is not dict
                or any(type(backend.get(name)) is not int
                    for name in ('i_req_valid', 'i_req_ready', 'i_req_addr'))
                or backend.get('i_req_valid') != 1
                or backend.get('i_req_ready') != 1
                or backend.get('i_req_addr') != request['address']):
            return False

        scope = dict(case_id=attempt['case_id'], case_index=attempt['case_index'],
            execution=cpu._execution, native_testcase_id=cpu._case_id,
            reset_epoch=cpu.reset_epoch, transaction=transaction,
            address=request['address'], local_tick=request['acceptance_tick'])
        latched = dict(scope=scope, sample=deepcopy(sample))
        previous = getattr(self, '_f6_pending_fetch_sample', None)
        if previous is not None:
            if _canonical(previous) == _canonical(latched):
                return True
            self._f6_pending_fetch_sample = None
            self._f6_pending_fetch_sample_conflict = True
            return False
        self._f6_pending_fetch_sample = latched
        return True

    @property
    def admitted_attempts(self):
        return tuple(self.attempts)

    def preflight(self, raw):
        if self.finished:
            raise ValueError('compiled-F6-runtime-finished')
        if getattr(self, '_stop_after_expected_error', False):
            raise ValueError('compiled-F6-expected-error-stops-campaign')
        if getattr(self, '_terminal_error', None) is not None:
            raise ValueError('compiled-F6-runtime-failed')
        if type(self.cursor) is not int or self.cursor < 0 or self.cursor >= self.max_cases:
            raise ValueError('compiled-F6-slot-exhausted')
        if type(self.records) is not list or len(self.records) != self.cursor:
            raise ValueError('compiled-F6-record-cursor-drift')
        return self.layout.decode(raw)

    def _verify_live_owner(self):
        """Revalidate same-call object owners and the launched build pair."""
        from myfuzz.scenario.f6_execution_binding import (
            validate_f6_execution_binding)

        if self.finished or self.runner._status != 'running':
            raise ValueError('compiled-F6-runtime-not-live')
        validate_f6_execution_binding(self.execution_binding,
            contract=self.contract, artifacts=self.artifacts,
            compiled_inputs=self.compiled_inputs, base_dir=self.base_dir,
            run_id=self.run_id, program=self.program, runner=self.runner,
            bound_topology=self.bound_topology)
        identities = self._validated_build_process_identities()
        if identities != self._process_identities:
            raise ValueError('compiled-F6-built-process-identity-changed')
        for name, process in self._native_processes.items():
            if (process is None or process.poll() is not None
                    or self.runner.sessions[name].process is not process):
                raise ValueError('compiled-F6-native-process-not-live')
        return True

    def _attempt_references(self, attempt, *, start_event_id):
        """Select documentary refs from this case's newly observed raw rows.

        Task5 independently resolves every reference against the original CPU,
        DMA, service, and router owners. This projection only associates rows
        with their expected word/address slots.
        """
        rows = [row for row in self.observer_view
            if type(row) is dict and row.get('event_id', 0) > start_event_id]
        cpu_id, dma_id = self.cpu_id, self.dma_id
        p = self.contract['program_contract']
        base = self.contract['control']['base']
        offsets = self.contract['dma']['csr']['offsets']
        from .shared_f6_slots import f6_slot
        slot = p['slot_base'] + 256 * f6_slot(self, attempt)

        def component_rows(owner, kind):
            return [row for row in rows if row.get('component') == owner
                and row.get('kind', row.get('schema_version')) == kind]

        def one(owner, kind, predicate):
            found = [row for row in component_rows(owner, kind) if predicate(row)]
            return found[0]['event_id'] if len(found) == 1 else None

        def many4(owner, kind, predicate):
            result = []
            for index in range(4):
                found = [row for row in component_rows(owner, kind)
                    if predicate(row, index)]
                result.append(found[0]['event_id'] if len(found) == 1 else None)
            return result

        words = attempt['words']
        operand_offsets = p['operand_instruction_offsets']
        attempt['operands'] = many4(cpu_id, 'instr_response',
            lambda row, i: row.get('address') == slot + operand_offsets[i])
        attempt['sources'] = many4(cpu_id, 'memory_write',
            lambda row, i: row.get('address') == p['source_address'] + 4*i
                and row.get('value') == words[i])
        attempt['source_commits'] = many4(cpu_id, 'memory_write_commit',
            lambda row, i: row.get('transaction') == self._transaction_for_ref(
                attempt['sources'][i]))
        names = self.contract['control']['configuration_order']
        values = _f6_configuration_values(self.contract)
        control_addresses = [base + offsets[name] for name in names]
        attempt['configuration'] = many4(cpu_id, 'data_accept',
            lambda row, i: row.get('address') == control_addresses[i]
                and row.get('write') == 1 and row.get('wdata') == values[i])
        attempt['deliveries'] = many4(cpu_id, 'mmio_delivery',
            lambda row, i: row.get('address') == control_addresses[i]
                and row.get('write') is True and row.get('write_value') == values[i])

        def accepted_address(row, operation, index):
            accepted = row.get('accepted')
            return (type(accepted) is dict
                and accepted.get('address') == (p['source_address']
                    if operation == 'read' else p['destination_address']) + 4*index
                and accepted.get('write') is (operation == 'write'))

        def dma_accepts(operation):
            found = [row for row in component_rows(dma_id, 'dma_edge')
                if type(row.get('accepted')) is dict
                and row['accepted'].get('write') is (operation == 'write')]
            return sorted(found, key=lambda row: row.get('tick', 0))

        read_accepts = dma_accepts('read')
        write_accepts = dma_accepts('write')
        attempt['reads'] = [next((row['event_id'] for row in read_accepts
            if accepted_address(row, 'read', i)), None) for i in range(4)]
        attempt['writes'] = [next((row['event_id'] for row in write_accepts
            if accepted_address(row, 'write', i)), None) for i in range(4)]

        def response_refs(accepts):
            result = []
            for index in range(4):
                acceptance = next((row for row in accepts
                    if type(row.get('accepted')) is dict
                    and row['accepted'].get('address') in (
                        p['source_address'] + 4*index,
                        p['destination_address'] + 4*index)), None)
                key = acceptance.get('accepted', {}).get('transaction') if acceptance else None
                matching = [row for row in component_rows(dma_id, 'dma_edge')
                    if type(row.get('response')) is dict
                    and row['response'].get('transaction') == key]
                result.append(matching[0]['event_id'] if len(matching) == 1 else None)
            return result

        def response_refs_by_operation(accepts, operation):
            result = []
            for index in range(4):
                accepted = next((row.get('accepted') for row in accepts
                    if accepted_address(row, operation, index)), None)
                key = accepted.get('transaction') if accepted else None
                matching = [row for row in component_rows(dma_id, 'dma_edge')
                    if type(row.get('response')) is dict
                    and row['response'].get('transaction') == key]
                result.append(matching[0]['event_id'] if len(matching) == 1 else None)
            return result

        attempt['read_responses'] = response_refs_by_operation(read_accepts, 'read')
        attempt['write_responses'] = response_refs_by_operation(write_accepts, 'write')
        attempt['read_snapshots'] = many4(dma_id, 'memory_read',
            lambda row, i: row.get('address') == p['source_address'] + 4*i)
        attempt['word_commits'] = many4(dma_id, 'memory_write_commit',
            lambda row, i: any(row.get('transaction') ==
                accept.get('accepted', {}).get('transaction')
                for accept in write_accepts
                if accepted_address(accept, 'write', i)))
        attempt['readbacks'] = many4(cpu_id, 'data_response',
            lambda row, i: row.get('address') == p['destination_address'] + 4*i
                and row.get('write') == 0)
        attempt['results'] = many4(cpu_id, 'memory_write',
            lambda row, i: row.get('address') == p['result_base']
                + 24*attempt['case_index'] + 4 + 4*i)
        if getattr(self, '_case_has_expected_error', False):
            attempt['readbacks'] = []
            attempt['results'] = []
        attempt['status'] = one(cpu_id, 'data_response',
            lambda row: row.get('address') == base + offsets['control'] and row.get('write') == 0)
        attempt['status_store'] = one(cpu_id, 'memory_write',
            lambda row: row.get('address') == p['result_base']
                + 24*attempt['case_index'])
        attempt['terminal'] = one(cpu_id, 'memory_write',
            lambda row: row.get('address') == p['result_base']
                + 24*attempt['case_index'] + 20)
        attempt['irq'] = one(cpu_id, 'cpu_external_irq_taken',
            lambda _row: True)
        delivery = getattr(self, '_active_f6_irq_delivery', None)
        attempt['irq_output'] = None if delivery is None else delivery['output_id']
        attempt['irq_delivery'] = None if delivery is None else delivery['delivery_id']
        attempt['return'] = one(cpu_id, 'native_f6_isr_return.v1',
            lambda row: row.get('case_id') == attempt['case_id'])

        request = self.cpu._request_evidence.get('instr')
        waiting = self.cpu._waiting_instr
        if (type(request) is dict and waiting is not None
                and type(request.get('address')) is int
                and request.get('transaction') is not None):
            boundary = self._append_observer(dict(kind='native_fetch_boundary',
                address=request['address'], execution=self.cpu._execution,
                reset_epoch=self.cpu.reset_epoch,
                native_testcase_id=self.cpu._case_id,
                transaction=self._jsonable(request['transaction']),
                local_tick=request.get('acceptance_tick'),
                boundary=('error_current_island'
                    if getattr(self, '_case_has_expected_error', False)
                    else 'next_prefix_or_park')), cpu_id)
            attempt['next_fetch'] = boundary
        else:
            attempt['next_fetch'] = None

    def _transaction_for_ref(self, reference):
        row = _observer_row(self, reference)
        return None if row is None else row.get('transaction')

    def _case_boundary_stop_ready(self, attempt):
        """Return true only when this F6 case has reached its full live stop edge.

        This is a scheduling predicate, not an acceptance credential. The
        complete Task5 consumer and boundary validator still run after the
        session returns and remain authoritative for passed/error status.
        """
        from myfuzz.local_harness.f6_dma_response_fault import (
            F6ResponseFaultDeclaration, _validate_f6_response_fault)
        from myfuzz.scenario.native_f6_isr_return import _issuer_state

        if (type(attempt) is not dict
                or type(attempt.get('case_index')) is not int
                or type(attempt.get('case_id')) is not str
                or not attempt['case_id']
                or getattr(self.runner, '_status', None) != 'running'
                or type(getattr(self, 'observer_view', None)) is not list):
            return False
        index = attempt['case_index']
        contract = self.contract
        program = contract['program_contract']
        cpu, dma = self.cpu, self.dma
        cpu_id, dma_id = self.cpu_id, self.dma_id
        irq_runtime_name = self._validated_f6_irq_runtime_name()
        start_event_id = attempt.get('_observer_event_start', 0)
        if type(start_event_id) is not int or start_event_id < 0:
            return False

        def rows(kind, component):
            return [row for row in self.observer_view
                if type(row) is dict and type(row.get('event_id')) is int
                and row['event_id'] > start_event_id
                and row.get('component') == component
                and row.get('kind', row.get('schema_version')) == kind]

        def scoped_cpu(row):
            transaction = row.get('transaction')
            return (type(transaction) is dict
                and transaction.get('execution_id') == 'local-execution'
                and transaction.get('testcase_id') == cpu._case_id
                and transaction.get('source_component') == cpu_id
                and transaction.get('source_epoch') == cpu.reset_epoch)

        if (cpu._execution != getattr(self, '_f6_original_cpu_execution', None)
                or cpu.reset_epoch != getattr(self, '_f6_original_cpu_reset_epoch', None)
                or cpu._case_id != getattr(self, '_f6_original_cpu_case_id', None)):
            return False

        # A boundary fetch is necessary for completion. Until it is latched,
        # avoid scanning the growing event history on every component advance.
        if (getattr(self, '_f6_pending_fetch_sample_conflict', False)
                or type(getattr(self, '_f6_pending_fetch_sample', None)) is not dict):
            return False

        deliveries = [row for row in rows('binding_delivery', cpu_id)
            if row.get('delivery_id') == contract['irq']['delivery_id']
            and row.get('target_component') == cpu_id]
        if len(deliveries) != 1:
            return False
        delivery = deliveries[0]
        source_output_id = delivery.get('source_event_id')
        outputs = [row for row in rows('source_start', dma_id)
            if row.get('event_id') == source_output_id]
        level = contract['irq'].get('delivery_policy') == 'level'
        if (len(outputs) != 1 or type(delivery.get('start_local_tick')) is not int
                or (not level and (type(delivery.get('end_local_tick')) is not int
                    or delivery['end_local_tick'] != delivery['start_local_tick'] + 16))
                or (level and delivery.get('end_local_tick') is not None)
                or delivery.get('target_epoch') != cpu.reset_epoch
                or type(delivery.get('source_output_key')) is not list
                or outputs[0].get('source_output_key') != delivery['source_output_key']):
            return False
        raw_sources = [row for row in rows('dma_edge', dma_id)
            if row.get('event_id') == outputs[0].get('producer_event_id')]
        raw_source = raw_sources[0] if len(raw_sources) == 1 else None
        raw_payload = raw_source.get('payload') if type(raw_source) is dict else None
        source_key = outputs[0].get('source_output_key')
        source_port = contract['irq']['producer_port']
        raw_tick = raw_source.get('tick') if type(raw_source) is dict else None
        raw_epoch = raw_source.get('reset_epoch') if type(raw_source) is dict else None
        if (len(raw_sources) != 1
                or type(raw_payload) is not dict
                or type(raw_tick) is not int or raw_tick < 1
                or type(raw_epoch) is not int or raw_epoch != dma.reset_epoch
                or type(source_key) is not list or len(source_key) != 4
                or type(source_key[0]) is not str
                or type(source_key[1]) is not int
                or type(source_key[2]) is not str
                or type(source_key[3]) is not int
                or source_key != [dma_id, raw_epoch, source_port, raw_tick]
                or type(raw_payload.get('observations', {}).get('physical', {})
                    .get(irq_runtime_name)) is not int
                or raw_payload.get('observations', {}).get('physical', {})
                    .get(irq_runtime_name) != 1):
            return False
        active_delivery = getattr(self, '_active_f6_irq_delivery', None)
        if (type(active_delivery) is not dict
                or active_delivery.get('output_id') != source_output_id
                or active_delivery.get('delivery_id') != delivery.get('event_id')
                or active_delivery.get('source_output_key') != delivery.get('source_output_key')
                or active_delivery.get('start_local_tick') != delivery.get('start_local_tick')
                or active_delivery.get('end_local_tick') != delivery.get('end_local_tick')):
            return False

        start_tick, end_tick = (delivery['start_local_tick'],
            delivery['end_local_tick'])
        if not level and cpu.local_ticks < end_tick:
            return False
        # CPU input samples are drained from the producer stream after the
        # Runner has journaled them.  Read that authoritative journal here;
        # observer_view is only a projection and can be missing rows after a
        # stream drain or projection failure.
        runner = self.runner
        events_since = getattr(runner, 'events_since', None)
        runner_event_start = attempt.get('_runner_event_start')
        if (not callable(events_since) or type(runner_event_start) is not int
                or runner_event_start < 0):
            return False
        try:
            # Only the rows after this attempt's start are used and they are
            # never retained: read that case tail borrowed and validate just it
            # instead of pinning/scanning the whole growing archive on every
            # boundary check.
            journal = _borrow_events(runner, runner_event_start)
        except BaseException:
            return False
        if type(journal) not in (tuple, list):
            return False
        for event_id, row in enumerate(journal, start=runner_event_start + 1):
            if (type(row) is not dict or type(row.get('event_id')) is not int
                    or row['event_id'] != event_id):
                return False
        source_scopes = getattr(runner, '_source_transport_scopes', None)
        cpu_scopes = (source_scopes.get(cpu_id)
            if type(source_scopes) is dict else None)
        normalized_execution = (cpu_scopes.get(cpu._execution)
            if type(cpu_scopes) is dict else None)
        if type(normalized_execution) is not str or not normalized_execution:
            return False
        if level:
            end_tick = _f6_level_clear_tick(self, delivery, journal, start_event_id)
            if end_tick is None:
                return False
        else:
            irq_samples = [row for row in journal
                if row.get('component') == cpu_id
                and row.get('kind') == 'cpu_external_irq_sample'
                and row.get('schema_version') == 'cpu_external_irq_sample.v1']
            expiry = None
            previous_sequence = 0
            for tick in range(start_tick, end_tick + 1):
                at_tick = [row for row in irq_samples
                    if row.get('local_tick') == tick
                    and row.get('reset_epoch') == cpu.reset_epoch]
                if len(at_tick) != 1:
                    return False
                sample = at_tick[0]
                if (type(sample.get('local_tick')) is not int
                        or type(sample.get('reset_epoch')) is not int):
                    return False
                command_scope = sample.get('command_scope')
                receipt_id = sample.get('receipt_id')
                if (type(command_scope) is not dict
                        or set(command_scope) != {'component', 'reset_epoch', 'command_sequence'}
                        or command_scope.get('component') != cpu_id
                        or type(command_scope.get('reset_epoch')) is not int
                        or command_scope['reset_epoch'] != cpu.reset_epoch
                        or type(command_scope.get('command_sequence')) is not int
                        or command_scope['command_sequence'] <= previous_sequence
                        or type(receipt_id) is not dict
                        or set(receipt_id) != {'execution', 'sequence'}
                        or receipt_id.get('execution') != normalized_execution
                        or type(receipt_id.get('sequence')) is not int
                        or receipt_id['sequence'] != command_scope['command_sequence']):
                    return False
                previous_sequence = command_scope['command_sequence']
                expected = int(tick < end_tick)
                if any(type(sample.get(name)) is not int or sample[name] != expected
                        for name in ('expected_input', 'actual_pre_input',
                                     'actual_post_input')):
                    return False
                if expected:
                    context = sample.get('input_context')
                    if (sample.get('binding_delivery_event_id') != delivery['event_id']
                            or sample.get('source_output_key') != delivery['source_output_key']
                            or type(context) is not dict
                            or context.get('binding_delivery_event_id') != delivery['event_id']
                            or context.get('source_output_key') != delivery['source_output_key']
                            or context.get('target_component') != cpu_id
                            or context.get('target_epoch') != cpu.reset_epoch):
                        return False
                else:
                    expiry = sample

        status_rows = [row for row in rows('data_response', cpu_id)
            if row.get('address') == contract['control']['base'] + contract['dma']['csr']['offsets']['control']
            and row.get('write') == 0 and scoped_cpu(row)]
        if len(status_rows) != 1 or type(status_rows[0].get('rdata')) is not int:
            return False
        status = status_rows[0]
        selected_fault = _validate_f6_response_fault(dma)
        declaration = getattr(self, 'response_fault', None)
        if declaration is not None and type(declaration) is not F6ResponseFaultDeclaration:
            return False
        declared_here = (declaration is not None
            and declaration.case_index == index)
        selected_here = (selected_fault is not None
            and selected_fault._selected is not None
            and selected_fault._case_index == index)
        has_error = bool(status['rdata']
            & contract['dma']['csr']['status_error_mask'])
        if (has_error != selected_here or declared_here != selected_here
                or selected_fault is not None and selected_fault._active is not None):
            return False

        from .shared_f6_slots import f6_slot
        physical_index = f6_slot(self, attempt)
        if selected_here:
            if (self.policy.state != 'expected_response_fault_pending'
                    or selected_fault._scope is None
                    or selected_fault._selected.testcase_id != dma._case_id):
                return False
            ledger_entry = dma.memory_service.ledger._entries.get(
                selected_fault._selected)
            error_rows = [row for row in rows('dma_edge', dma_id)
                if type(row.get('response')) is dict
                and row['response'].get('transaction') ==
                    asdict(selected_fault._selected)
                and row['response'].get('error') == 1]
            if (ledger_entry is None or ledger_entry.status != 'complete'
                    or ledger_entry.receipt is None
                    or ledger_entry.receipt.get('target_effect') is not False
                    or len(error_rows) != 1):
                return False
            expected_address = (program['slot_base'] + 256 * physical_index + 128)
            terminal_value = 2
        else:
            if (self.policy.state != 'complete' or self.policy._pending is not None
                    or self.policy._read != 4 or self.policy._write != 4
                    or len(self.policy.records) != 8
                    or len(self.route_admission.route_matches) != 8):
                return False
            next_index = physical_index + 1
            expected_address = (program['slot_base'] + 256 * next_index
                if next_index < program['slot_count'] else program['park_address'])
            terminal_value = 1

        if (dma._pending is not None or dma.pending_responses
                or dma.memory_service.ledger.pending_keys
                or dma.memory_service.ledger.unresolved_keys
                or cpu._pending_instr is not None or cpu._pending_data is not None
                or getattr(cpu, '_queued_mmio', None)
                or cpu._waiting_instr is None or cpu.pending_responses != 1):
            return False
        request = cpu._request_evidence.get('instr')
        waiting_key, waiting_address = cpu._waiting_instr
        transaction = request.get('transaction') if type(request) is dict else None
        if (type(request) is not dict or type(transaction) is not dict
                or set(transaction) != {'execution_id', 'testcase_id',
                    'source_component', 'source_epoch', 'channel_id',
                    'source_sequence'}
                or transaction.get('execution_id') != 'local-execution'
                or transaction.get('testcase_id') != cpu._case_id
                or transaction.get('source_component') != cpu_id
                or type(transaction.get('source_epoch')) is not int
                or transaction.get('source_epoch') != cpu.reset_epoch
                or transaction.get('channel_id') != 'instr'
                or type(transaction.get('source_sequence')) is not int
                or transaction.get('source_sequence') < 1
                or asdict(waiting_key) != (asdict(request['transaction'])
                    if hasattr(request['transaction'], '__dataclass_fields__')
                    else request['transaction'])
                or request.get('address') != expected_address
                or waiting_address != expected_address
                or cpu.waiting_instruction_address != expected_address
                or type(request.get('acceptance_tick')) is not int
                or request.get('acceptance_tick') < end_tick
                or request.get('acceptance_tick') > cpu.local_ticks):
            return False
        fetch_latch = getattr(self, '_f6_pending_fetch_sample', None)
        expected_fetch_scope = dict(case_id=attempt['case_id'], case_index=index,
            execution=cpu._execution, native_testcase_id=cpu._case_id,
            reset_epoch=cpu.reset_epoch,
            transaction=CompiledF6Runtime._jsonable(request['transaction']),
            address=expected_address, local_tick=request['acceptance_tick'])
        if (getattr(self, '_f6_pending_fetch_sample_conflict', False)
                or type(fetch_latch) is not dict
                or set(fetch_latch) != {'scope', 'sample'}
                or _canonical(fetch_latch.get('scope'))
                    != _canonical(expected_fetch_scope)):
            return False
        handshake = fetch_latch.get('sample')
        backend = (handshake.get('pre', {}).get('backend', {})
            if type(handshake) is dict else {})
        if (type(handshake) is not dict
                or handshake.get('local_tick') != request['acceptance_tick']
                or type(backend) is not dict
                or any(type(backend.get(name)) is not int
                    for name in ('i_req_valid', 'i_req_ready', 'i_req_addr'))
                or backend.get('i_req_valid') != 1
                or backend.get('i_req_ready') != 1
                or backend.get('i_req_addr') != expected_address):
            return False

        terminal_rows = [row for row in rows('memory_write', cpu_id)
            if row.get('address') == program['result_base'] + 24 * index + 20
            and row.get('value') == terminal_value and scoped_cpu(row)]
        if len(terminal_rows) != 1:
            return False
        returns = [row for row in rows('native_f6_isr_return.v1', cpu_id)
            if row.get('case_id') == attempt['case_id']
            and row.get('case_index') == index]
        if len(returns) != 1 or terminal_rows[0]['event_id'] >= returns[0]['event_id']:
            return False
        if level and (type(returns[0].get('local_tick')) is not int
                or returns[0]['local_tick']<=end_tick):
            return False
        issuer = getattr(cpu, '_f6_isr_return', None)
        state = _issuer_state(issuer)
        sealed_return = {key: value for key, value in returns[0].items()
            if key != 'event_id'}
        if (state['active'] is not None or state['last_index'] != index
                or attempt['case_id'] not in state['case_ids']
                or sum(_canonical(event) == _canonical(sealed_return)
                    for event in issuer.events) != 1):
            return False
        return True

    def _execute_case(self, candidate, index, attempt):
        from myfuzz.scenario.session_runtime import (
            BoundOnlineInstruction, OnlineCase)
        from myfuzz.integration.compiled_f6_consumer import capture_f6_case
        from myfuzz.scenario.f6_assertion_evidence import f6_case_feedback
        from myfuzz.local_harness.f6_dma_response_fault import (
            _validate_f6_response_fault)

        cpu_id, dma_id = self.cpu_id, self.dma_id
        from .shared_f6_slots import f6_slot
        slot = self.contract['program_contract']['slot_base'] + 256*f6_slot(self, attempt)
        if index == 0 and 'shared_slots' in self.contract['program_contract']:
            self._f6_isr_return.begin_case(attempt['case_id'], case_index=0,
                irq_take_key=[self.cpu.source_component, self.cpu.reset_epoch,
                    self.cpu._native_irq_take_sequence + 1])
        prefix = self.program.prefix(candidate, case_index=index)
        self.program.validate_prefix(prefix, candidate, case_index=index)
        attempt.update(case_id=f'{self.run_id}:case:{index}', case_index=index,
            raw8_hex=candidate.raw.hex(), words=list(candidate.words),
            instruction_address=slot, prefix_hex=prefix.hex(),
            operands=[], sources=[], source_commits=[], configuration=[],
            deliveries=[], reads=[], read_snapshots=[], read_responses=[],
            writes=[], word_commits=[], write_responses=[], readbacks=[],
            results=[], irq_output=None, irq_delivery=None, irq=None,
            **{'return': None, 'status': None, 'status_store': None,
                'terminal': None},
            next_fetch=None, status_kind='admitted')
        if index and self.attempts[index-1].get('status_kind') != 'passed':
            raise ValueError('compiled-F6-next-case-requires-passed-boundary')
        if self.cpu.waiting_instruction_address != slot:
            raise ValueError('compiled-F6-next-native-fetch-required')
        if index and getattr(self, '_active_f6_irq_delivery', None) is not None:
            self._active_f6_irq_delivery = None
        self._f6_pending_fetch_sample = None
        self._f6_pending_fetch_sample_conflict = False

        instruction_path_id = self.runtime_path_admission['runtime_path_ids'][1]
        source_id = self.contract['instruction_source_id']
        case = OnlineCase(attempt['case_id'], 'CPU_TO_IP', instruction_path_id,
            BoundOnlineInstruction(source_id + f':{index}', cpu_id, slot,
                prefix.hex(), source_id),
            _f6_runtime_case_advances(self))
        event_start = len(self.observer_view)
        attempt['_observer_event_start'] = event_start
        runner_event_start = getattr(self.runner, 'event_count', None)
        if type(runner_event_start) is not int or runner_event_start < 0:
            raise RuntimeError('compiled-F6-runner-event-cursor-unavailable')
        attempt['_runner_event_start'] = runner_event_start
        self._case_has_expected_error = False
        self._case_checker_findings = []
        checker_snapshot = self.runner.protocol_checker_snapshot(self.dma_id)
        if type(checker_snapshot) is not dict:
            raise RuntimeError('compiled-F6-protocol-checker-snapshot-unavailable')
        self.protocol_checker_case_report = None
        receipt = self.session.submit_case(case,
            step_observer=lambda component, outputs:
                self._on_component_step(attempt, component, outputs),
            stop_after_advance=lambda _advance_index:
                self._case_boundary_stop_ready(attempt),
            stop_on_runner_failure=True)
        self._drain_observer_view()
        checker_report = _assemble_f6_protocol_checker_case_report(
            self.runner, self.dma_id, checker_snapshot=checker_snapshot,
            attempt=attempt, run_id=self.run_id,
            execution_binding_sha256=self.execution_binding_sha256)
        self.protocol_checker_case_report = checker_report
        if type(receipt.violations) is tuple:
            self._case_checker_findings = list(receipt.violations)
        elif receipt.violations:
            self._case_checker_findings = [str(value) for value in receipt.violations]
        self._case_checker_findings.extend(checker_report['findings'])

        # Determine expected failure only from the installed one-shot selector,
        # its actual selected key, the policy's native ERR state, and Task5's
        # independently checked error ISR/current-island receipt.
        fault = _validate_f6_response_fault(self.dma)
        declared_here = (self.response_fault is not None
            and self.response_fault.case_index == index)
        self._case_has_expected_error = bool(declared_here and fault is not None
            and fault._selected is not None
            and self.policy.state == 'expected_response_fault_pending')
        self._attempt_references(attempt, start_event_id=event_start)
        self.checker_findings = lambda: list(self._case_checker_findings)
        material = capture_f6_case(self, attempt)
        attempt['case_material'] = material
        observations = material['observations']
        all_passed = all(row.get('status') == 'passed'
            for row in observations.values())
        irq_row = observations.get('dma.irq_isr_completion', {})
        irq_details = None
        refs = irq_row.get('evidence_refs', [])
        if refs:
            irq_details = material['evidence_inventory'].get(refs[0], {}).get('details')
        completed_error = (self._case_has_expected_error
            and type(irq_details) is dict
            and type(irq_details.get('error_completion')) is dict
            and irq_details['error_completion'].get('terminal_marker') == 2)
        if completed_error:
            attempt['status_kind'] = 'expected_error'
            attempt['expected_error'] = True
            self._stop_after_expected_error = True
        elif all_passed and not receipt.violations and receipt.status == 'running':
            attempt['status_kind'] = 'passed'
            attempt['expected_error'] = False
        else:
            attempt['status_kind'] = 'failed'
            attempt['expected_error'] = False
            self._stop_after_expected_error = True
        attempt['feedback'] = (list(f6_case_feedback(material,
            case_ids=(attempt['case_id'],)))
            if attempt['status_kind'] == 'passed' else [0] * 5)
        result = dict(status=attempt['status_kind'], case_id=attempt['case_id'],
            case_index=index, raw8_hex=attempt['raw8_hex'],
            words=list(candidate.words), instruction_address=slot,
            prefix_hex=prefix.hex(), observations=deepcopy(observations),
            feedback=list(attempt['feedback']))
        attempt['result'] = deepcopy(result)
        _freeze_f6_case(self, attempt, material)
        self._f6_last_dma_case_index = index
        self._case_has_expected_error = completed_error
        if self._active_f6_irq_delivery is not None:
            self._active_f6_irq_delivery['case_index'] = index
        self._f6_pending_fetch_sample = None
        self._f6_pending_fetch_sample_conflict = False
        return result

    def submit(self, raw, *, flow='F6'):
        """Admit one legal eight-byte record, then execute its canonical slot."""
        if getattr(self, '_begin_state', 'begun') == 'created':
            raise ValueError('compiled-F6-runtime-not-begun')
        if self.finished:
            raise ValueError('compiled-F6-runtime-finished')
        if getattr(self, '_stop_after_expected_error', False):
            raise ValueError('compiled-F6-expected-error-stops-campaign')
        if getattr(self, '_terminal_error', None) is not None:
            raise ValueError('compiled-F6-runtime-failed')
        if getattr(self,'_custom_online',False):
            try:
                return self._submit_custom_online(raw,flow)
            except BaseException as error:
                if getattr(self.session,'_halted',False):
                    self._terminal_error=error
                raise
        shared = 'shared_slots' in self.contract['program_contract']
        allowed = (self.contract['program_contract']['shared_slots']['enabled_flows'] if shared else ['F6'])
        if flow not in allowed:
            raise ValueError('compiled-F6-unsupported-flow')
        if shared and flow != 'F6':
            from .shared_f6_slots import reserve_case, submit_writer,next_slot_index
            from .shared_slot_consumers import declare_slot,submit_non_dma
            self._verify_live_owner()
            declaration = declare_slot(self.compiled_inputs,self.contract['program_contract']['shared_slots'],
                self.runtime_path_admission,flow=flow,raw=raw,slot_index=next_slot_index(self),
                instruction_isa=getattr(self.memory, 'instruction_isa', None))
            mapping = reserve_case(self, flow, raw)
            try:
                return (submit_writer(self, raw, mapping) if flow=='F4'
                    else submit_non_dma(self,raw,mapping,declaration))
            except BaseException as error:
                self._terminal_error = error
                self._stop_after_expected_error = True
                raise
        candidate = self.preflight(raw)
        if self.cursor >= self.max_cases:
            raise ValueError('compiled-F6-case-budget-exhausted')
        self._verify_live_owner()
        index = self.cursor
        mapping = None
        if shared:
            from .shared_f6_slots import reserve_case
            mapping = reserve_case(self, 'F6', candidate.raw)
        if index:
            previous = self.attempts[index-1]
            try:
                advance_f6_dma_logical_scope(self, previous,
                    next_case_index=index)
                self._verify_live_owner()
            except BaseException as error:
                self._terminal_error = getattr(self, '_f6_terminal_error', None) or error
                self._stop_after_expected_error = True
                raise

        case_id = f'{self.run_id}:case:{index}'
        slot_index = mapping['slot_index'] if mapping else index
        slot = self.contract['program_contract']['slot_base'] + 256*slot_index
        record = dict(case_id=case_id, case_index=index,
            raw8_hex=candidate.raw.hex(), words=list(candidate.words),
            instruction_address=slot, status='admitted')
        attempt = dict(case_id=case_id, case_index=index,
            raw8_hex=candidate.raw.hex(), words=list(candidate.words),
            instruction_address=slot, status_kind='admitted')
        if mapping is not None:
            for row in (record, attempt):
                row.update(slot_index=mapping['slot_index'],
                    session_case_index=mapping['session_case_index'])
        # A case becomes an attempt before any source instruction is issued.
        self.records.append(record)
        self.attempts.append(attempt)
        self.cursor += 1
        try:
            result = self._execute_case(candidate, index, attempt)
            record.update(status=result['status'],
                prefix_hex=result['prefix_hex'], feedback=result['feedback'])
            attempt['result'] = deepcopy(result)
            self._drain_observer_view()
            if shared:
                from .shared_f6_slots import seal_case
                if result['status'] == 'passed':
                    seal_case(self, case_id, result, _observer_row(self, attempt['next_fetch']))
            if index + 1 == self.contract['program_contract']['slot_count']:
                from .f6_storage_support import capture_support_phase
                capture_support_phase(self, 'after')
            returned = deepcopy(result)
            if result['status'] == 'passed' and getattr(self, '_f6_epoch_program', None) is not None:
                epoch_receipt = _f6_epoch_execution_receipt(self, result)
                if epoch_receipt is not None:
                    returned['epoch_program'] = epoch_receipt
            return returned
        except BaseException as error:
            self._f6_pending_fetch_sample = None
            self._f6_pending_fetch_sample_conflict = False
            attempt['status_kind'] = 'failed'
            attempt['feedback'] = [0] * 5
            if type(attempt.get('result')) is dict:
                attempt['result']['feedback'] = [0] * 5
            attempt['error'] = dict(error_type=type(error).__name__,
                error=str(error))
            record.update(status='failed',
                error=dict(error_type=type(error).__name__, error=str(error)))
            if 'feedback' in record:
                record['feedback'] = [0] * 5
            self._terminal_error = error
            self._stop_after_expected_error = True
            # Preserve the first failure while still trying to inventory any
            # facts already emitted by native/service observers.
            try:
                from myfuzz.integration.compiled_f6_consumer import capture_f6_case
                material = capture_f6_case(self, attempt)
                attempt['case_material'] = material
            except BaseException as export_error:
                error.add_note('compiled-F6 partial case inventory: '
                    + repr(export_error))
            raise

    def _finish_once(self):
        self._f6_pending_fetch_sample = None
        self._f6_pending_fetch_sample_conflict = False
        primary = getattr(self, '_terminal_error', None)
        # ScenarioRunner.finalize() calls end_case(), which clears a session's
        # live case ID. Preserve the final logical DMA scope before teardown so
        # the frozen case owner can still be checked after export collection.
        final_dma_case_id = getattr(getattr(self, 'dma', None), '_case_id', None)
        self._finish_started = True
        try:
            from myfuzz.scenario.f6_execution_binding import validate_f6_execution_binding
            validate_f6_execution_binding(self.execution_binding,
                contract=self.contract, artifacts=self.artifacts,
                compiled_inputs=self.compiled_inputs, base_dir=self.base_dir,
                run_id=self.run_id, program=self.program, runner=self.runner,
                bound_topology=self.bound_topology)
        except BaseException as error:
            if primary is None:
                primary = error
                self._terminal_error = error
            else:
                primary.add_note('compiled-F6 finish boundary: ' + repr(error))
        if not getattr(self, '_session_finish_called', False):
            self._session_finish_called = True
            try:
                self.trace = self.session.finish()
            except BaseException as error:
                if primary is None:
                    primary = error
                    self._terminal_error = error
                else:
                    primary.add_note('compiled-F6 session finish: ' + repr(error))
                try:
                    snapshot = getattr(self.session, 'trace', None)
                    if callable(snapshot):
                        self.trace = snapshot()
                except BaseException as snapshot_error:
                    self._trace_snapshot_error = snapshot_error
                    primary.add_note('compiled-F6 partial trace snapshot: '
                        + repr(snapshot_error))
        self.finished = True

        unavailable = {}
        trace_snapshot_error = getattr(self, '_trace_snapshot_error', None)
        if trace_snapshot_error is not None:
            unavailable['trace_snapshot'] = dict(
                error_type=type(trace_snapshot_error).__name__,
                error=str(trace_snapshot_error))
        exports = {}
        export_errors = {}
        captures = (
            ('online_plan', lambda: json.loads(self.session.encode_plan())),
            ('assertion_material', lambda:_build_f6_assertion_material(self)),
            ('events', lambda:list(self.runner.events_since(0))),
            ('execution_audit', lambda:BuiltProcessAudit.execution_audit(self)),
            ('build_audit', lambda:diagnostic_build_snapshot(
                self, closed=True, error=primary)),
        )
        for name, capture in captures:
            try:
                exports[name] = capture()
            except BaseException as error:
                export_errors[name] = error
                unavailable[name] = dict(error_type=type(error).__name__,
                    error=str(error))

        failures = []
        for name, _capture in captures:
            if name in unavailable:
                failures.append((name, export_errors.get(name),
                    unavailable[name].get('error', 'export capture failed')))
                continue
            try:
                reason = _f6_export_failure(self, name, exports.get(name),
                    execution_audit=exports.get('execution_audit'))
            except BaseException as error:
                export_errors[name] = error
                unavailable[name] = dict(error_type=type(error).__name__,
                    error=str(error))
                failures.append((name, error, 'validator-raised'))
                continue
            if reason is not None:
                error = ValueError('compiled-F6-mandatory-export-unavailable:'
                    + name + ':' + reason)
                unavailable[name] = dict(error_type=type(error).__name__,
                    error=str(error))
                failures.append((name, error, reason))

        events_match_trace = _journal_matches_trace_events(
            self.trace, exports.get('events'))
        trace_reason = _f6_trace_failure(self, self.trace,
            exports.get('events'), events_match_trace)
        if trace_reason is not None:
            error = ValueError('compiled-F6-mandatory-export-unavailable:trace:'
                + trace_reason)
            unavailable['trace'] = dict(error_type=type(error).__name__,
                error=str(error))
            failures.append(('trace', error, trace_reason))

        if failures and primary is None:
            _name, first_error, reason = failures[0]
            primary = (first_error if isinstance(first_error, BaseException)
                else ValueError('compiled-F6-mandatory-export-unavailable:'
                    + _name + ':' + str(reason)))
            self._terminal_error = primary
        if primary is not None:
            for name, failure, reason in failures:
                detail = failure if failure is not None else reason
                primary.add_note('compiled-F6 partial export ' + name + ': '
                    + repr(detail))

        case_ids = tuple(attempt['case_id'] for attempt in self.attempts)
        feedback_valid = True
        if ('assertion_material' in exports
                and _f6_export_failure(self, 'assertion_material',
                    exports['assertion_material']) is None):
            try:
                from myfuzz.scenario.f6_assertion_evidence import f6_case_feedback
                feedback = list(f6_case_feedback(exports['assertion_material'],
                    case_ids=case_ids)) if case_ids else [0]*5
                if (type(feedback) is not list or len(feedback) != 5
                        or any(type(value) is not int or value not in (0, 1)
                            for value in feedback)):
                    raise ValueError('compiled-F6-feedback-shape')
            except BaseException as error:
                feedback_valid = False
                unavailable['assertion_feedback'] = dict(
                    error_type=type(error).__name__, error=str(error))
                if primary is None:
                    primary = error
                    self._terminal_error = error
                else:
                    primary.add_note('compiled-F6 partial export assertion_feedback: '
                        + repr(error))
                feedback = [0]*5
        else:
            feedback_valid = False
            feedback = [0]*5
        case_state_reason = None
        case_state_error = None
        if feedback_valid and 'assertion_material' in exports:
            try:
                case_state_reason = _f6_finish_state_failure(self,
                    online_plan=exports.get('online_plan'),
                    assertion_material=exports['assertion_material'], feedback=feedback,
                    final_dma_case_id=final_dma_case_id)
            except BaseException as error:
                case_state_error = error
                case_state_reason = 'case-state-revalidation-raised'
        if case_state_reason is not None:
            error = (case_state_error if case_state_error is not None else
                ValueError('compiled-F6-mandatory-export-unavailable:case_state:'
                    + case_state_reason))
            unavailable['case_state'] = dict(error_type=type(error).__name__,
                error=str(error))
            failures.append(('case_state', error, case_state_reason))
            if primary is None:
                primary = error
                self._terminal_error = error
            else:
                primary.add_note('compiled-F6 partial export case_state: '
                    + repr(error))
        trace_complete = (trace_reason is None
            and getattr(self.trace, 'status', None) == 'complete')
        if not trace_complete:
            feedback = [0] * 5
        shared_passed = False
        if 'shared_slots' in self.contract['program_contract']:
            from .shared_f6_slots import flow_records,session_case_ids
            flows = flow_records(self)
            shared_passed = bool(flows) and all(row['status']=='passed' for row in flows)
        all_passed = ((bool(self.attempts) or shared_passed)
            and all(attempt.get('status_kind') == 'passed'
                for attempt in self.attempts)
            and trace_complete and not failures and feedback_valid
            and case_state_reason is None
            and primary is None)
        expected_error = (primary is None and bool(self.attempts)
            and self.attempts[-1].get('status_kind') == 'expected_error'
            and all(attempt.get('status_kind') == 'passed'
                for attempt in self.attempts[:-1])
            and trace_complete and not failures and feedback_valid
            and case_state_reason is None)
        status = ('expected_error' if expected_error else
            'complete' if all_passed and not primary else 'partial')
        if status != 'complete':
            feedback = [0] * 5
        scope = 'failed_prefix_full' if expected_error else ('full' if all_passed else 'partial')
        artifact_digests = {name: artifact.runtime_document['artifact_digest']
            for name, artifact in sorted(self.artifacts.items())}
        raw_trace_status = getattr(self.trace, 'status', None)
        trace_status = (raw_trace_status if type(raw_trace_status) is str
            else 'unavailable')
        raw_trace_ticks = getattr(self.trace, 'local_ticks', None)
        trace_local_ticks = (deepcopy(raw_trace_ticks)
            if type(raw_trace_ticks) is dict else None)
        trace_genome_sha256 = getattr(self.trace, 'genome_sha256', None)
        if type(trace_genome_sha256) is not str:
            trace_genome_sha256 = None
        trace_manifest_sha256 = getattr(self.trace, 'manifest_sha256', None)
        if type(trace_manifest_sha256) is not str:
            trace_manifest_sha256 = None
        trace_semantic_sha256 = getattr(self.trace, 'semantic_sha256', None)
        if type(trace_semantic_sha256) is not str:
            trace_semantic_sha256 = None
        trace_events = None
        trace_events_source = 'unavailable'
        try:
            actual_events = exports.get('events')
            if type(actual_events) is list and events_match_trace is True:
                # The journal already is the trace material (the gate above
                # proved it row for row), so the 15-38k event snapshot does not
                # need a second detached copy just to be discarded again.
                trace_events_source = 'actual_events'
            else:
                trace_events = deepcopy(list(_borrowed_trace_events(self.trace)))
                trace_events_source = 'trace_material'
        except BaseException:
            pass
        # Every section below is built by this runtime, is not held by anything
        # else, and is only read afterwards (the exporter serialises it, the
        # replay compares it).  Handing the objects over instead of defensive
        # deep copies keeps one copy of the 200 MB prefix in memory; the
        # detached journal snapshot is already this runtime's own copy.
        result = dict(schema_version='compiled_F6_prefix.v1', status=status,
            scope=scope, completed=all_passed and not expected_error and primary is None,
            run_id=self.run_id,
            compiled_document_sha256=self.compiled_document_sha256,
            binding_sha256=self.binding_sha256,
            execution_binding_sha256=self.execution_binding_sha256,
            execution_binding=self.execution_binding,
            runtime_path_admission=self.runtime_path_admission,
            artifact_digests=artifact_digests,
            rounds_per_case=self.rounds_per_case, max_cases=self.max_cases,
            records=self.records, attempts=self.attempts,
            feedback=feedback, trace_status=trace_status,
            trace_local_ticks=trace_local_ticks,
            trace_genome_sha256=trace_genome_sha256,
            trace_manifest_sha256=trace_manifest_sha256,
            trace_events=trace_events,
            trace_events_source=trace_events_source,
            semantic_hash=trace_semantic_sha256,
            original_build=exports.get('build_audit'),
            original_execution_audit=exports.get('execution_audit'),
            online_plan=exports.get('online_plan'),
            assertion_material=exports.get('assertion_material'),
            actual_events=exports.get('events'),
            unavailable=unavailable,
            error=(None if primary is None else dict(
                error_type=type(primary).__name__, error=str(primary))))
        if 'storage_support' in self.contract['program_contract']:
            result['storage_support'] = dict(
                scope='fixed_firmware_support_not_dynamic_F4_F6_selection',
                phases=deepcopy(getattr(self, 'storage_support_evidence', {})))
        if 'shared_slots' in self.contract['program_contract']:
            from .shared_f6_slots import flow_records,session_case_ids
            result['flow_records'] = flow_records(self)
        self._finish_document = result
        if primary is not None:
            raise primary
        return result

    def finish(self):
        """Finalize once and return the cached original/fresh comparison input.

        The cached document is owned by this runtime and is read-only for
        callers: the exporter serialises it and ``replay`` compares it.  It is
        returned by reference so the 200 MB prefix is not copied per call; a
        caller that mutated it would change its own finished evidence, which is
        the same failure a private copy would have hidden.
        """
        if getattr(self, '_begin_state', 'begun') == 'created':
            raise ValueError('compiled-F6-runtime-not-begun')
        if getattr(self,'_custom_online',False):
            if self._finish_document is None:
                from hashlib import sha256
                plan,trace=self.session.finish_export()
                from myfuzz.scenario.dma_binding_replay import encode_dma_bound_payload
                self._custom_plan=encode_dma_bound_payload(plan,payload_kind='online_session_plan',
                    declaration=self._custom_dma_declaration,
                    binding_compilations={'session':self.session.dma_binding_compilation_document()})
                self._custom_trace=trace
                import json
                self._custom_plan_identity=json.loads(self._custom_plan)['identity_sha256']
                self._finish_document=dict(schema_version='compiled_F6_custom_online.v1',
                    status='observed' if self._terminal_error is None else 'unknown',
                    records=deepcopy(self.records),flow_records=deepcopy(self.records),
                    plan_sha256=sha256(self._custom_plan).hexdigest(),
                    trace_status=trace.status,source_attribution='unknown',retirement='unknown',
                    feedback='unknown',certificate='not_granted',reward_eligible=False,
                    replay='not_verified')
                self.finished=True
            return self._finish_document
        cached = getattr(self, '_finish_document', None)
        if cached is not None:
            primary = getattr(self, '_terminal_error', None)
            if primary is not None:
                raise primary
            return cached
        try:
            result = self._finish_once()
        except BaseException:
            if getattr(self, '_finish_document', None) is not None:
                raise
            raise
        if getattr(self, '_finish_document', None) is None:
            self._finish_document = result
            self.finished = True
        return self._finish_document

    def execution_audit(self):
        return BuiltProcessAudit.execution_audit(self)

    def replay(self, prefix, *, audit_sink=None):
        """Rebuild the same declaration and compare a complete fresh prefix.

        Documents are handed over by reference, not defensively copied: the
        original prefix is the runtime's own finished document, the fresh
        document belongs to the temporary fresh runtime, and the envelope below
        is written once by the caller.  ``audit_sink`` receives that same final
        envelope and must serialise it without retaining or mutating it.
        """
        if getattr(self,'_custom_online',False):
            from myfuzz.integration.shared_f6_assembly import build_f6_assembly
            from myfuzz.scenario.session_runtime import replay_online_session
            expected=self.finish()
            if type(prefix) is not dict or not _documents_equal(prefix,expected):
                raise ValueError('compiled-F6-prefix-mismatch')
            def factory():
                assembly=build_f6_assembly(contract=self.contract,artifacts=self.artifacts,
                    ownership=self.runner_ownership,base_dir=self.base_dir,cache_dir=self.cache_dir,
                    request=self.compiled_inputs['request'])
                runner=assembly.runner
                runner.configure_memory_dependency_evidence(runtime_contract_sha256=_digest(self.contract))
                for local in runner.sessions.values():
                    local.configure_built_executable_receipt()
                    local.prepare_local()
                    local.validate_built_executable_receipt()
                return runner
            comparison=replay_online_session(self._custom_plan,factory,self._custom_trace,
                expected_dma_binding_identity_sha256=self._custom_plan_identity,
                dma_reference_execution=(self.dma_id,self.dma._execution),max_differences=16)
            result=dict(scope='online_observation',matches=comparison.matches,
                first_difference=comparison.first_difference,source_attribution='unknown',
                retirement='unknown',certificate='not_granted',reward_eligible=False)
            if not comparison.matches:
                result.update(expected_event=comparison.expected_event,
                    actual_event=comparison.actual_event,
                    difference_context=comparison.difference_context,
                    differences=list(comparison.differences))
            if audit_sink is not None:
                audit_sink(deepcopy(result))
            return result
        expected = self.finish()
        if type(prefix) is not dict or not _documents_equal(prefix, expected):
            raise ValueError('compiled-F6-prefix-mismatch')
        if expected.get('status') not in ('complete', 'expected_error'):
            raise ValueError('compiled-F6-replay-material-incomplete')

        expected_error = expected['status'] == 'expected_error'
        scope = 'failed_prefix_full' if expected_error else 'full'
        envelope = dict(scope=scope, completed=False if expected_error else True,
            matches=False, first_difference=None, actual_prefix=None,
            actual_events=[], original_execution_audit=expected.get(
                'original_execution_audit'),
            execution_audit=None,
            original_build=expected.get('original_build'),
            fresh_build=None)
        fresh = None
        actual = None
        events_reused = False
        primary = None
        try:
            fresh = type(self)(artifacts=self.artifacts,
                compiled_inputs=self.compiled_inputs, base_dir=self.base_dir,
                cache_dir=self.cache_dir, run_id=self.run_id,
                rounds_per_case=self.rounds_per_case, max_cases=self.max_cases,
                response_fault=self.response_fault,
                build_audit_sink=lambda snapshot:envelope.update(
                    fresh_build=deepcopy(snapshot)))
            envelope['fresh_build'] = diagnostic_build_snapshot(fresh,
                previous=envelope.get('fresh_build'))
            _require_fresh_execution_identity(self, fresh)
            raw_records = [record['raw8_hex'] for record in expected['records']]
            if len(raw_records) != len(expected['attempts']):
                raise ValueError('compiled-F6-replay-record-attempt-count')
            if 'shared_slots' in self.contract['program_contract']:
                from .shared_f6_slots import flow_records,session_case_ids
                flows = flow_records(self)
                if expected.get('flow_records') != flows:
                    raise ValueError('compiled-F6-replay-flow-ledger')
                _replay_f6_flow_timeline(fresh, flows,
                    expected['online_plan'].get('reset_operations', []))
            else:
                if expected['online_plan'].get('reset_operations'):
                    raise ValueError('compiled-F6-replay-reset-shared-slots-required')
                for raw_hex in raw_records:
                    fresh.submit(bytes.fromhex(raw_hex))
            actual = fresh.finish()
            envelope['actual_prefix'] = actual
            envelope['actual_events'] = actual.get('actual_events') or []
            events_reused = type(actual.get('actual_events')) is list
            from myfuzz.integration.compiled_f6_build_join import (
                build_compiled_f6_build_join, verify_compiled_f6_build_join)
            if (type(expected.get('original_build')) is not dict
                    or type(actual.get('original_build')) is not dict):
                raise ValueError('compiled-F6-fresh-build-snapshot-required')
            build_join = build_compiled_f6_build_join(artifacts=self.artifacts,
                execution_binding=self.execution_binding,
                original=expected['original_build'],
                fresh=actual['original_build'])
            verify_compiled_f6_build_join(build_join,
                artifacts=self.artifacts, execution_binding=self.execution_binding,
                original=expected['original_build'], fresh=actual['original_build'])
            envelope['build_join'] = build_join
            # Compare digests of the complete normalized documents first: an
            # equal pair (the accepted case) never needs the recursive walk,
            # and only one normalized copy of the 200 MB prefix is resident at
            # a time.  A real difference still falls back to the same
            # ``_first_difference`` result the code produced before.
            has_reset = bool(expected['online_plan'].get('reset_operations'))
            original_history = _f6_replay_execution_history(self, expected) if has_reset else None
            fresh_history = _f6_replay_execution_history(fresh, actual) if has_reset else None
            if has_reset and ({nonce for rows in original_history.values() for nonce in rows}
                    & {nonce for rows in fresh_history.values() for nonce in rows}):
                raise ValueError('compiled-F6-fresh-epoch-execution-identity-reused')
            expected_normalized_sha = _digest(_normalized_f6_prefix(
                expected, execution_history=original_history))
            normalized_actual = _normalized_f6_prefix(actual, execution_history=fresh_history)
            difference = None
            if expected_normalized_sha != _digest(normalized_actual):
                difference = _first_difference(
                    _normalized_f6_prefix(expected, execution_history=original_history), normalized_actual)
            normalized_actual = None
            envelope.update(matches=difference is None, first_difference=difference,
                verification_scope=scope)
            if difference is not None:
                raise ValueError('compiled-F6-fresh-prefix-mismatch')
        except BaseException as error:
            primary = error
            envelope.update(error_type=type(error).__name__, error=str(error))
            raise
        finally:
            errors = []
            if fresh is not None:
                if not fresh.finished:
                    try:
                        fresh.finish()
                    except BaseException as error:
                        errors.append(error)
                        envelope['cleanup_failure'] = dict(
                            error_type=type(error).__name__, error=str(error))
                for key, capture in (
                        ('fresh_build', lambda:diagnostic_build_snapshot(fresh,
                            previous=envelope.get('fresh_build'), error=primary)),
                        ('execution_audit', fresh.execution_audit),
                        ('actual_events', lambda:(envelope['actual_events']
                            if events_reused
                            else list(fresh.runner.events_since(0))))):
                    try:
                        envelope[key] = capture()
                    except BaseException as error:
                        errors.append(error)
                        envelope.setdefault('audit_failures', []).append(dict(
                            stage=key, error_type=type(error).__name__,
                            error=str(error)))
            if fresh is not None and 'shared_slots' in self.contract['program_contract']:
                envelope['fresh_shared_storage_raw'] = deepcopy(getattr(fresh, 'shared_storage_raw', {}))
                envelope['fresh_shared_read_raw'] = deepcopy(getattr(fresh, 'shared_read_raw', {}))
            if audit_sink is not None:
                try:
                    audit_sink(envelope)
                except BaseException as error:
                    errors.append(error)
            if primary is not None:
                for error in errors:
                    primary.add_note('compiled-F6 replay cleanup/audit: '
                        + repr(error))
            elif errors:
                first = errors[0]
                for error in errors[1:]:
                    first.add_note('compiled-F6 replay cleanup/audit: '
                        + repr(error))
                raise first
        return envelope


# Installation authority belongs to this original decorated constructor body.
from myfuzz.scenario.f6_instruction_fetch_receipt import _seal_f6_fetch_provider
_seal_f6_fetch_provider(CompiledF6Runtime, ('__init__',))
