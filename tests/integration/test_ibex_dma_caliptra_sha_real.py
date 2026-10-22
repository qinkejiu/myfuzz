"""Opt-in native Ibex → ZipCPU DMA → Caliptra SHA256 → Ibex ISR gate.

Run the native checks with ``MYFUZZ_IBEX_CALIPTRA_SHA_DMA_REAL=1``. Evidence
and build caches are kept under the task-local evidence directory unless
operation-local paths are supplied through the matching environment variables.
The gate uses independent native processes and transaction-level providers; it
does not claim a physical Wishbone-to-AHB bridge or shared physical SRAM.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, is_dataclass
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from collections.abc import Mapping
from unittest.mock import patch

import pytest

from myfuzz.scenario.caliptra_sha256_dma_paths import (
    CaliptraSha256DmaBeatAdmission, SHA_CTRL_OFFSET,
    SHA_CTRL_START_VALUE,
)
from myfuzz.scenario.compiled_f6_runtime_path import (
    DmaTransferRoutePair, DmaTransferSourceWord,
    bind_compiled_f6_runtime_path, prepare_compiled_f6_runtime_path,
)
from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
from myfuzz.scenario.ibex_dma_caliptra_sha_example import (
    SHA_DIGEST0, SHA_STATUS,
)
from myfuzz.scenario.ibex_dma_caliptra_sha_runner import (
    RAM_BASE, RAM_SIZE, SHA_BASE, SHA_SIZE, SHA_START_ADDRESS,
    make_ibex_dma_caliptra_sha_runner,
)
from myfuzz.scenario.ibex_dma_example import DMA_BASE, ISR, MAIN, RESULT, SOURCE
from myfuzz.scenario.ledger import TransactionKey


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = ROOT / (
    'docs/reports/evidence/ibex-caliptra-sha-dma-isr-20261021')
TESTCASE_ID = 'ibex-wbdmac-caliptra-sha-dma-isr'
SOURCE_VALUE = SHA_CTRL_START_VALUE
START_KEY = 0xFED
START_WORD = (START_KEY << 16) | 1
DESTINATION = SHA_START_ADDRESS
WRONG_DESTINATION = SHA_START_ADDRESS + 4
SHA_SETUP_BASE = 0x80
SHA_BLOCK_WORDS = tuple(
    int.from_bytes(b'abc\x80', 'big') if index == 0 else
    24 if index == 15 else 0
    for index in range(16))
ROUND = ('dma', 'cpu', 'sha')
MAX_ROUNDS = 4000
_HEARTBEAT_SEQUENCE = 0
_TRANSACTION_KEY_FIELDS = {
    'execution_id', 'testcase_id', 'source_component', 'source_epoch',
    'channel_id', 'source_sequence',
}
_TRANSACTION_TYPE_NAME = 'myfuzz.scenario.ledger.TransactionKey'
_UUID_HEX = re.compile(r'[0-9a-f]{32}\Z')
_STATE_DEPENDENCY_FIELDS = frozenset((
    'kind', 'event_id', 'producer_event_id', 'edge_kind', 'memory_id',
    'generation', 'byte_offset', 'version', 'source', 'target'))


def _plain(value):
    if is_dataclass(value):
        return _plain(asdict(value))
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


def _canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _save_json(root, name, value):
    root.mkdir(parents=True, exist_ok=True)
    (root / (name + '.json.gz')).write_bytes(
        gzip.compress(_canonical_bytes(_plain(value)), mtime=0))


def _settings():
    cache = Path(os.environ.get('MYFUZZ_IBEX_CALIPTRA_SHA_DMA_CACHE',
        EVIDENCE_ROOT / 'cache-native'))
    evidence = Path(os.environ.get('MYFUZZ_IBEX_CALIPTRA_SHA_DMA_EVIDENCE',
        EVIDENCE_ROOT))
    boundary = EVIDENCE_ROOT.resolve()
    for label, path in (('cache', cache), ('evidence', evidence)):
        try:
            path.resolve().relative_to(boundary)
        except ValueError as error:
            raise ValueError(
                f'Caliptra native {label} path must stay under {EVIDENCE_ROOT}') from error
    cache.mkdir(parents=True, exist_ok=True)
    evidence.mkdir(parents=True, exist_ok=True)
    return cache, evidence


def _normalize_ahb_access_id(value, *, sha_execution_id, context):
    if type(value) is not str:
        raise AssertionError(f'{context} is not a Caliptra AHB access ID')
    if (type(sha_execution_id) is not str
            or _UUID_HEX.fullmatch(sha_execution_id) is None):
        raise AssertionError(f'{context} has an invalid SHA execution ID')
    prefix = f'caliptra-ahb:{sha_execution_id}:'
    if not value.startswith(prefix):
        raise AssertionError(f'{context} has a foreign Caliptra AHB session ID')
    sequence = value[len(prefix):]
    if (not sequence.isdecimal() or int(sequence) <= 0
            or str(int(sequence)) != sequence):
        raise AssertionError(f'{context} has an invalid Caliptra AHB sequence')
    return f'caliptra-ahb:<execution:sha>:{sequence}'


def _validated_execution_role_tokens(execution_ids, *, sha_execution_id):
    roles = {'cpu', 'dma', 'sha', 'runner'}
    if type(execution_ids) is not dict or set(execution_ids) != roles:
        raise AssertionError('execution identities are not the exact four replay roles')
    if any(type(identifier) is not str or _UUID_HEX.fullmatch(identifier) is None
            for identifier in execution_ids.values()):
        raise AssertionError('execution role identity is not a lowercase 32-hex UUID')
    if len(set(execution_ids.values())) != len(roles):
        raise AssertionError('execution role identities are not unique within the run')
    if sha_execution_id != execution_ids['sha']:
        raise AssertionError('Caliptra SHA execution identity differs from the SHA role')
    return {identifier: f'<execution:{role}>'
        for role, identifier in execution_ids.items()}


def _checked_transaction_document(value, *, context):
    if type(value) is not dict or set(value) != _TRANSACTION_KEY_FIELDS:
        raise AssertionError(f'{context} is not a closed TransactionKey document')
    if (any(type(value[name]) is not str or not value[name]
            for name in ('execution_id', 'testcase_id', 'source_component',
                         'channel_id'))
            or any(type(value[name]) is not int or value[name] < 0
                   for name in ('source_epoch', 'source_sequence'))):
        raise AssertionError(f'{context} has invalid TransactionKey field types')
    try:
        transaction = TransactionKey(**value)
    except (TypeError, ValueError) as error:
        raise AssertionError(f'{context} is not a valid TransactionKey') from error
    if asdict(transaction) != value:
        raise AssertionError(f'{context} changed while validating TransactionKey')
    return transaction


def _canonical_transaction_repr(value, *, context):
    """Return only a canonical TransactionKey repr; leave other text intact."""
    if type(value) is not str or not value.startswith('TransactionKey('):
        return None
    try:
        expression = ast.parse(value, mode='eval').body
        if (type(expression) is not ast.Call
                or type(expression.func) is not ast.Name
                or expression.func.id != 'TransactionKey'
                or expression.args or not expression.keywords
                or any(keyword.arg is None for keyword in expression.keywords)):
            return None
        fields = {}
        for keyword in expression.keywords:
            if keyword.arg in fields:
                return None
            fields[keyword.arg] = ast.literal_eval(keyword.value)
        transaction = _checked_transaction_document(fields, context=context)
    except (AssertionError, SyntaxError, TypeError, ValueError, RecursionError):
        return None
    return transaction if repr(transaction) == value else None


def _canonical_state_dependency_edge(value):
    if (type(value) is not dict or set(value) != _STATE_DEPENDENCY_FIELDS
            or value.get('kind') != 'state_dependency'):
        return False
    if (any(type(value[field]) is not str or not value[field]
            for field in ('edge_kind', 'memory_id', 'source', 'target'))
            or any(type(value[field]) is not int or value[field] < 0
                   for field in ('event_id', 'producer_event_id', 'generation',
                                 'byte_offset'))):
        return False
    version = value['version']
    return (version is None or (type(version) is list and len(version) == 2
        and all(type(item) is int and item >= 0 for item in version)))


def _normalize_state_dependency_endpoint(value, *, role_tokens, context):
    transaction = _canonical_transaction_repr(value, context=context)
    if transaction is None:
        return value
    role_token = role_tokens.get(transaction.execution_id)
    if role_token is None:
        return value
    prefix = f"TransactionKey(execution_id='{transaction.execution_id}', "
    if not value.startswith(prefix):
        raise AssertionError(f'{context} lost its canonical TransactionKey prefix')
    return f"TransactionKey(execution_id='{role_token}', {value[len(prefix):]}"


def _sha_typed_projection(value, *, execution_ids, sha_execution_id,
                          context='event', inside_provider=False,
                          normalize_runner_state_edges=False,
                          _inside_runner_events=False, _role_tokens=None):
    """Normalize declared role IDs, typed keys, SHA AHB IDs, and state edges."""
    role_tokens = (_validated_execution_role_tokens(execution_ids,
        sha_execution_id=sha_execution_id) if _role_tokens is None else _role_tokens)
    if type(value) is dict:
        provider_scope = inside_provider or value.get('schema_version') in (
            'dma_master_target_access.v1',
            'caliptra_sha256_dma_target_provider.v1')
        state_edge = (_inside_runner_events
            and _canonical_state_dependency_edge(value))
        if set(value) == _TRANSACTION_KEY_FIELDS:
            transaction = _checked_transaction_document(value, context=context)
            row = asdict(transaction)
            row['execution_id'] = role_tokens.get(
                transaction.execution_id, transaction.execution_id)
            return row
        projected = {}
        for key, item in value.items():
            child_context = f'{context}.{key}'
            if state_edge and key in ('source', 'target'):
                projected[key] = _normalize_state_dependency_endpoint(
                    item, role_tokens=role_tokens, context=child_context)
            elif key in ('access_id', 'target_access_id'):
                if provider_scope or (type(item) is str
                        and item.startswith('caliptra-ahb:')):
                    projected[key] = _normalize_ahb_access_id(
                        item, sha_execution_id=sha_execution_id,
                        context=child_context)
                else:
                    projected[key] = item
            elif key in ('execution', 'execution_id') and type(item) is str:
                projected[key] = role_tokens.get(item, item)
            else:
                projected[key] = _sha_typed_projection(
                    item, execution_ids=execution_ids,
                    sha_execution_id=sha_execution_id,
                    context=child_context, inside_provider=provider_scope,
                    normalize_runner_state_edges=normalize_runner_state_edges,
                    _inside_runner_events=(normalize_runner_state_edges
                        and key == 'runner_events'),
                    _role_tokens=role_tokens)
        return projected
    if type(value) in (tuple, list):
        return [_sha_typed_projection(item, execution_ids=execution_ids,
                    sha_execution_id=sha_execution_id,
                    context=f'{context}[{index}]',
                    inside_provider=inside_provider,
                    normalize_runner_state_edges=normalize_runner_state_edges,
                    _inside_runner_events=_inside_runner_events,
                    _role_tokens=role_tokens)
                for index, item in enumerate(value)]
    return value


def _execution_ids(runner):
    result = {name: session._execution
              for name, session in runner.sessions.items()}
    result['runner'] = runner.execution_id
    return result


def _native_d3_material(output_root):
    """Generate the existing route fixture with the live Ibex RVFI profile."""
    from unittest.mock import patch

    from myfuzz.scenario.compiled_paths import (
        PathWiring, compiled_document_sha256, load_path_wiring)
    from tests.integration import test_p7b_p7c_dma_route_intent as route_fixture

    rvfi_profile = 'configs/cpus/ibex_rvfi_local/component_profile.json'
    with patch.object(route_fixture, 'CPU_PROFILE', rvfi_profile):
        d2_wiring_document, request, compiled = (
            route_fixture._generate_caliptra_sha256_dma_route_d2_d3(
                output_root / 'caliptra-d2-d3',
                ram_base=RAM_BASE, ram_size=RAM_SIZE,
                ram_executable=True))
    if request.cpu.profile.component_id != 'ibex_rvfi_local':
        raise AssertionError('Caliptra D3 request is not pinned to Ibex RVFI')
    parsed_d2_wiring = load_path_wiring(d2_wiring_document)
    if (not isinstance(request.wiring, PathWiring)
            or parsed_d2_wiring != request.wiring
            or parsed_d2_wiring.document != request.wiring.document):
        raise AssertionError(
            'D2 wiring document and D3 compile request wiring identity differ')
    f6, = [row for row in compiled['paths'] if row.get('flow_id') == 'F6']
    if (f6.get('status') != 'unsupported'
            or f6.get('reason', {}).get('code')
                != 'dma-route-live-topology-binding-required'
            or f6.get('runtime_path_identity') is not None
            or compiled['identity']['wiring']['dma_master_routes_sha256']
                != request.wiring.dma_master_routes_sha256):
        raise AssertionError('RVFI-pinned static D3 unexpectedly enabled F6')
    compile_request_path = (output_root / 'caliptra-d2-d3'
        / 'caliptra_path_compile_request.json')
    digest = compiled_document_sha256(compiled)
    return (request.wiring, request, compiled, compile_request_path, digest,
            dict(d2_wiring_document))


def _save_compile_inputs(root, compile_request_path):
    request = json.loads(compile_request_path.read_text(encoding='utf-8'))
    inputs = [(request['wiring']['source'], Path('compile-inputs/wiring_contract.json'),
               'wiring')]
    for index, device in enumerate(request['devices']):
        source = device.get('test_capability')
        if source is not None:
            inputs.append((source, Path('compile-inputs/test-capabilities')
                / f'{index}.json', device['instance_id']))
    manifest = []
    for original, relative, role in inputs:
        payload = Path(original).read_bytes()
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        manifest.append({'role': role, 'original_path': str(original),
            'evidence_path': relative.as_posix(), 'size_bytes': len(payload),
            'sha256': hashlib.sha256(payload).hexdigest()})
    _save_json(root, 'compile-input-manifest', {
        'schema_version': 'compiled_f6_compile_inputs.v1', 'inputs': manifest})


class _ObservedCaliptraBeatAdmission(CaliptraSha256DmaBeatAdmission):
    """Retain completed beats with their original typed transaction keys."""

    __slots__ = ('completion_receipts', 'completion_transaction_types')

    def begin_case(self, execution_id, testcase_id):
        super().begin_case(execution_id, testcase_id)
        self.completion_receipts = []
        self.completion_transaction_types = []

    def completed(self, key, *, rdata, error):
        super().completed(key, rdata=rdata, error=error)
        if type(key) is not TransactionKey:
            raise AssertionError('Caliptra completion lost its TransactionKey type')
        self.completion_transaction_types.append(
            type(key).__module__ + '.' + type(key).__qualname__)
        self.completion_receipts.append({'transaction': asdict(key),
            'rdata': rdata, 'error': error, 'state_after': self.state})


def _install_d4(runner, dma_endpoint_links, d3_wiring, compiled_paths):
    from unittest.mock import patch

    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract

    source = DmaTransferSourceWord('cpu', 'ram', 'sha_ctrl_start', SOURCE,
        4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
        'same_word_value')
    artifact_links = {'dma': dma_endpoint_links['dma']}
    runtime_path = prepare_compiled_f6_runtime_path(
        compiled_paths, d3_wiring, runner, source=source,
        transfer_pair=pair, artifact_links=artifact_links)
    prepared = runtime_path.prepared_runtime_paths
    bound_calls = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared_object, *args, **kwargs):
        bound_calls.append(prepared_object)
        return original_bind(prepared_object, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound_path = bind_compiled_f6_runtime_path(
            runtime_path, runner, artifact_links=artifact_links)
    bound_handoff = bound_path.bound_handoff
    references = (
        runtime_path.prepared_runtime_paths,
        runtime_path.handoff._declaration._prepared_runtime_paths,
        bound_path.prepared_runtime_paths,
        bound_handoff._handoff._declaration._prepared_runtime_paths,
    )
    same_prepared = (len(bound_calls) == 1
        and all(item is prepared for item in references)
        and bound_calls[0] is prepared)
    if not same_prepared:
        raise AssertionError('D4 did not bind the exact prepared path once')
    bound_handoff.validate_topology()

    routes_by_key = {route.key: route for route in prepared.contract.dma_master_routes}
    pair_links = {row['route_id']: row for row in
        runtime_path.handoff.document()['declaration']['route_links']}
    read_key = (pair_links[pair.read_route_id]['rule_index'],
                pair_links[pair.read_route_id]['prerequisite_index'])
    write_key = (pair_links[pair.write_route_id]['rule_index'],
                 pair_links[pair.write_route_id]['prerequisite_index'])
    read_route, write_route = routes_by_key[read_key], routes_by_key[write_key]
    policy = _ObservedCaliptraBeatAdmission(
        image_address=source.address,
        window=runner.sessions['dma'].master_targets[0])
    admission = DmaMasterRouteAdmission(policy, bound_handoff,
        path_id=prepared.path_ids[0], read_route=read_route,
        write_route=write_route)
    runner.sessions['dma'].configure_dma_route_admission(admission)

    d3_digest = __import__(
        'myfuzz.scenario.compiled_paths', fromlist=['compiled_document_sha256']
        ).compiled_document_sha256(compiled_paths)
    unbound_document = runtime_path.document()
    handoff_document = runtime_path.handoff.document()
    bound_document = bound_handoff.document()
    d4 = {
        'compiled_paths': dict(compiled_paths),
        'compiled_paths_sha256': d3_digest,
        'd3_wiring': d3_wiring.document,
        'source': runtime_path.source.document(),
        'transfer_pair': runtime_path.transfer_pair.document(),
        'compiled_f6_runtime_path': unbound_document,
        'compiled_f6_runtime_path_sha256': runtime_path.identity_sha256,
        'compiled_f6_handoff': handoff_document,
        'compiled_f6_handoff_sha256': runtime_path.handoff.identity_sha256,
        'bound_wrapper': bound_document,
        'bound_handoff_sha256': bound_handoff.identity_sha256,
        'bind_count': len(bound_calls),
        'same_prepared_object': same_prepared,
    }
    owners = {
        'runner': runner,
        'cpu_session': runner.sessions['cpu'],
        'dma_session': runner.sessions['dma'],
        'sha_session': runner.sessions['sha'],
        'memory': runner.sessions['cpu'].memory,
        'runtime_path': runtime_path,
        'prepared_runtime_paths': prepared,
        'unbound_handoff': runtime_path.handoff,
        'bound_runtime_path': bound_path,
        'bound_handoff': bound_handoff,
    }
    return d4, admission, policy, owners


def _prepare_sha_block(sha):
    setup_rows = []
    setup_samples = []
    receipts = []
    instance_state = sha.__dict__
    had_instance_command = 'command' in instance_state
    previous_instance_command = instance_state.get('command')
    original_command = sha.command

    def capture_command(operation, fields):
        receipt = original_command(operation, fields)
        if operation == sha.access_operation:
            receipts.append({
                'operation': operation,
                'fields': list(fields),
                'status': receipt.status,
                'execution': receipt.execution,
                'sequence': receipt.sequence,
                'tick_before': receipt.tick_before,
                'tick_after': receipt.tick_after,
                'new_ticks': receipt.new_ticks,
            })
        return receipt

    sha.command = capture_command
    try:
        for index, value in enumerate(SHA_BLOCK_WORDS):
            offset = SHA_SETUP_BASE + index * 4
            tick_before = sha.local_ticks
            receipt_count_before = len(receipts)
            sha.write_register(offset, value)
            if len(receipts) != receipt_count_before + 1:
                raise AssertionError('host AHB setup write lacks one command receipt')
            receipt = receipts[-1]
            samples = _plain(sha.drain_tick_samples())
            tick_after = sha.local_ticks
            if tick_after <= tick_before or not samples:
                raise AssertionError('host AHB block write lacks actual phase samples')
            if (receipt.get('status') != 'result'
                    or receipt.get('new_ticks') != tick_after - tick_before
                    or receipt.get('tick_after') <= receipt.get('tick_before')
                    or receipt.get('execution') != sha._execution
                    or receipt.get('sequence') != sha._sequence):
                raise AssertionError('host AHB setup command receipt is not exact')
            if any(type(row) is not dict or 'pre' not in row or 'post' not in row
                    for row in samples):
                raise AssertionError('host AHB setup sample is missing a measured phase')
            setup_rows.append({'ordinal': index + 1, 'offset': offset,
                'write_value': value, 'byte_enable': 15,
                'tick_before': tick_before, 'tick_after': tick_after,
                'receipt': receipt, 'sample_count': len(samples),
                'sample_local_ticks': [row['local_tick'] for row in samples]})
            setup_samples.extend(samples)
    finally:
        if had_instance_command:
            sha.command = previous_instance_command
        else:
            # Restore the class method lookup. Assigning the bound method back
            # would leave a shadow in __dict__, which the sealed provider guard
            # correctly treats as a topology change.
            instance_state.pop('command', None)
    if (len(setup_rows) != 16 or len(setup_samples) < 16
            or len(receipts) != 16
            or len({row['sequence'] for row in receipts}) != 16):
        raise AssertionError('padded abc setup did not execute all sixteen AHB writes')
    return setup_rows, setup_samples


def _profile_sha_provider_call(sha, observations, operation):
    """Observe calls to the sealed provider without changing its identity."""
    from myfuzz.local_harness.ahb_lite_register_session import (
        GeneratedAhbLiteRegisterSession)

    provider_code = GeneratedAhbLiteRegisterSession.dma_master_target_access.__code__
    prior_profile = sys.getprofile()

    def profile(frame, event, arg):
        if event == 'call' and frame.f_code is provider_code:
            local_values = frame.f_locals
            if local_values.get('self') is sha:
                transaction = local_values.get('source_transaction')
                observations.append({
                    'source_transaction': asdict(transaction)
                        if type(transaction) is TransactionKey
                        else _plain(transaction),
                    'address': local_values.get('address'),
                    'offset': local_values.get('offset'),
                    'write': local_values.get('write'),
                    'value': local_values.get('value'),
                    'byte_enable': local_values.get('byte_enable'),
                })
        if prior_profile is not None:
            prior_profile(frame, event, arg)

    sys.setprofile(profile)
    try:
        return operation()
    finally:
        sys.setprofile(prior_profile)


def _append_schedule_heartbeat(path, *, testcase_id, phase, round_index,
                               schedule, marker, runner, cpu, dma, sha,
                               provider_method_calls, process_handles):
    if path is None:
        return
    pending_targets = runner._pending_target_requests()
    row = {
        'schema_version': 'ibex_caliptra_sha_schedule_heartbeat.v1',
        'testcase_id': testcase_id,
        'phase': phase,
        'round_index': round_index,
        'schedule_steps': len(schedule),
        'marker': marker,
        'component_local_ticks': {
            'cpu': cpu.local_ticks,
            'dma': dma.local_ticks,
            'sha': sha.local_ticks,
        },
        'pending_responses': {
            'cpu': cpu.pending_responses,
            'dma': dma.pending_responses,
        },
        'pending_target_requests': dict(pending_targets),
        'runner_event_count': runner.event_count,
        'component_event_counts': {
            'cpu': len(cpu.cpu_events),
            'dma': len(dma.events),
            'sha_provider_receipts': len(sha._dma_target_events),
            'dma_provider_method_entries': len(provider_method_calls),
        },
        'processes': {
            name: {'pid': process.pid, 'returncode': process.poll()}
            for name, process in process_handles.items()
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')
        stream.flush()


def _assert_schedule_heartbeat_complete(run):
    path = run.get('schedule_heartbeat_path')
    if path is None:
        return
    try:
        rows = [json.loads(line) for line in Path(path).read_text(
            encoding='utf-8').splitlines() if line]
    except (OSError, json.JSONDecodeError) as error:
        raise AssertionError('schedule heartbeat is missing or malformed') from error
    if (not rows or rows[0].get('phase') != 'after_host_setup'
            or rows[0].get('round_index') != 0
            or rows[0].get('schedule_steps') != 0):
        raise AssertionError('schedule heartbeat lacks the host setup checkpoint')
    rounds = run.get('completed_rounds')
    schedule = run.get('schedule')
    if (type(rounds) is not int or rounds <= 0 or type(schedule) is not list
            or len(schedule) != rounds * len(ROUND)):
        raise AssertionError('schedule heartbeat run has an incomplete round schedule')
    expected_rounds = list(range(10, rounds, 10))
    if not expected_rounds or expected_rounds[-1] != rounds:
        expected_rounds.append(rounds)
    actual_rounds = [row.get('round_index') for row in rows
        if row.get('phase') == 'round']
    if actual_rounds != expected_rounds:
        raise AssertionError(
            'schedule heartbeat lacks the terminal round checkpoint or cadence')
    for row in rows[1:]:
        if (row.get('phase') != 'round'
                or row.get('schedule_steps') != row.get('round_index') * len(ROUND)):
            raise AssertionError('schedule heartbeat round checkpoint is malformed')
    if rows[-1].get('marker') != run.get('result', [None])[-1]:
        raise AssertionError('schedule heartbeat terminal marker differs from run result')


def _run_case(cache_dir, d3_wiring, compiled_paths, *, destination=DESTINATION,
              schedule_prefix=None, keep_alive=False):
    fixture = make_ibex_dma_caliptra_sha_runner(cache_dir=cache_dir,
        source_value=SOURCE_VALUE, destination_address=destination)
    runner = fixture.runner
    cpu, dma, sha = (runner.sessions[name] for name in ('cpu', 'dma', 'sha'))
    d4, admission, policy, owners = _install_d4(
        runner, fixture.dma_endpoint_links, d3_wiring, compiled_paths)
    native_pre_capture = (_capture_wrong_native_pre(dma)
        if destination == WRONG_DESTINATION else None)
    native_pre_requests = (native_pre_capture['requests']
        if native_pre_capture is not None else None)
    provider_method_calls = []
    identity_docs = {
        'runner': runner.identity_document(),
        'sessions': {name: session.identity_document()
                     for name, session in runner.sessions.items()},
    }
    retained = False
    process_handles = {}
    schedule = []
    failure = None
    failure_step_observation = None
    evidence = {}
    testcase_id = TESTCASE_ID if destination == DESTINATION else TESTCASE_ID + '-wrong-offset'
    heartbeat_path = None
    if os.environ.get('MYFUZZ_IBEX_CALIPTRA_SHA_DMA_HEARTBEAT') == '1':
        global _HEARTBEAT_SEQUENCE
        _HEARTBEAT_SEQUENCE += 1
        _, heartbeat_root = _settings()
        heartbeat_path = heartbeat_root / (
            f'schedule-heartbeat-{os.getpid()}-{_HEARTBEAT_SEQUENCE}.jsonl')
    try:
        runner.begin_test(testcase_id)
        process_handles = {name: session.process
            for name, session in runner.sessions.items()}

        # Host-side AHB setup is a measured prelude. Drain its phase samples
        # before the first scheduled step so the Runner cannot attribute them
        # to a later CPU/DMA/Caliptra scheduler command.
        host_setup, host_setup_samples = _prepare_sha_block(sha)
        sha_ticks_after_setup = sha.local_ticks
        _append_schedule_heartbeat(heartbeat_path,
            testcase_id=testcase_id, phase='after_host_setup', round_index=0,
            schedule=schedule, marker=None, runner=runner, cpu=cpu, dma=dma,
            sha=sha, provider_method_calls=provider_method_calls,
            process_handles=process_handles)

        def step_component(component):
            nonlocal failure_step_observation
            before = {
                'sha_local_ticks': sha.local_ticks,
                'sha_provider_receipts': len(sha._dma_target_events),
                'sha_command_sequence': sha._sequence,
                'runner_event_count': runner.event_count,
            }
            try:
                return _profile_sha_provider_call(
                    sha, provider_method_calls, lambda: runner.step(component))
            except Exception:
                after = {
                    'sha_local_ticks': sha.local_ticks,
                    'sha_provider_receipts': len(sha._dma_target_events),
                    'sha_command_sequence': sha._sequence,
                    'runner_event_count': runner.event_count,
                }
                event_slice = _plain(runner.events_since(
                    before['runner_event_count']))
                failure_step_observation = {
                    'component': component,
                    'sha_observation_before': before,
                    'sha_observation_after': after,
                    'sha_provider_receipt_delta': (
                        after['sha_provider_receipts'] - before['sha_provider_receipts']),
                    'sha_command_sequence_delta': (
                        after['sha_command_sequence'] - before['sha_command_sequence']),
                    'sha_local_tick_delta': (
                        after['sha_local_ticks'] - before['sha_local_ticks']),
                    'runner_event_delta': event_slice,
                    'sha_tick_samples_during_failed_step': [row for row in event_slice
                        if row.get('kind') == 'local_tick_sample'
                        and row.get('component') == 'sha'],
                }
                raise

        if schedule_prefix is not None:
            component_schedule = tuple(schedule_prefix)
            if (not component_schedule
                    or len(component_schedule) > len(ROUND) * MAX_ROUNDS
                    or len(component_schedule) % len(ROUND) != 0
                    or any(component not in runner.sessions
                           for component in component_schedule)):
                raise ValueError('invalid recorded Caliptra replay schedule')
            for schedule_index, component in enumerate(component_schedule):
                schedule.append(component)
                try:
                    step_component(component)
                except Exception as error:
                    failure = {'type': type(error).__name__, 'message': str(error)}
                    _append_schedule_heartbeat(heartbeat_path,
                        testcase_id=testcase_id, phase='step_failure',
                        round_index=(len(schedule) + len(ROUND) - 1) // len(ROUND),
                        schedule=schedule, marker=None, runner=runner, cpu=cpu,
                        dma=dma, sha=sha,
                        provider_method_calls=provider_method_calls,
                        process_handles=process_handles)
                    break
                if (schedule_index + 1) % len(ROUND) == 0:
                    round_index = (schedule_index + 1) // len(ROUND)
                    marker = cpu.memory.read(RESULT + 40, 4,
                        transaction_id='ibex-caliptra-marker-poll').value
                    terminal = (marker in (1, 0xffffffff)
                            and cpu.pending_responses == 0
                            and dma.pending_responses == 0
                            and not runner._pending_target_requests().get('dma', 0)
                            and not runner._pending_target_requests().get('sha', 0))
                    if (round_index % 10 == 0 or terminal
                            or schedule_index + 1 == len(component_schedule)
                            or round_index == MAX_ROUNDS):
                        _append_schedule_heartbeat(heartbeat_path,
                            testcase_id=testcase_id, phase='round',
                            round_index=round_index, schedule=schedule,
                            marker=marker, runner=runner, cpu=cpu, dma=dma,
                            sha=sha,
                            provider_method_calls=provider_method_calls,
                            process_handles=process_handles)
        else:
            for round_index in range(1, MAX_ROUNDS + 1):
                for component in ROUND:
                    schedule.append(component)
                    try:
                        step_component(component)
                    except Exception as error:
                        failure = {'type': type(error).__name__, 'message': str(error)}
                        break
                if failure is not None:
                    _append_schedule_heartbeat(heartbeat_path,
                        testcase_id=testcase_id, phase='step_failure',
                        round_index=round_index, schedule=schedule, marker=None,
                        runner=runner, cpu=cpu, dma=dma, sha=sha,
                        provider_method_calls=provider_method_calls,
                        process_handles=process_handles)
                    break
                marker = cpu.memory.read(RESULT + 40, 4,
                    transaction_id='ibex-caliptra-marker-poll').value
                terminal = (marker in (1, 0xffffffff)
                        and cpu.pending_responses == 0
                        and dma.pending_responses == 0
                        and not runner._pending_target_requests().get('dma', 0)
                        and not runner._pending_target_requests().get('sha', 0))
                if (round_index % 10 == 0 or terminal
                        or round_index == MAX_ROUNDS):
                    _append_schedule_heartbeat(heartbeat_path,
                        testcase_id=testcase_id, phase='round',
                        round_index=round_index, schedule=schedule,
                        marker=marker, runner=runner, cpu=cpu, dma=dma, sha=sha,
                        provider_method_calls=provider_method_calls,
                        process_handles=process_handles)
                if terminal:
                    break

        result = [cpu.memory.read(RESULT + offset, 4,
            transaction_id=f'ibex-caliptra-result-{offset}').value
            for offset in range(0, 44, 4)]
        binding, = runner.bindings
        process_ids = {name: None if process is None else process.pid
            for name, process in process_handles.items()}
        provider_events = _plain(list(sha._dma_target_events))
        evidence = {
            'schema_version': 'ibex_wbdmac_caliptra_sha_isr_run.v1',
            'testcase_id': testcase_id,
            'source_address': SOURCE,
            'source_value': SOURCE_VALUE,
            'destination_address': destination,
            'selected_destination_address': DESTINATION,
            'schedule': list(schedule),
            'round_bound': MAX_ROUNDS,
            'completed_rounds': len(schedule) // len(ROUND),
            'failure': failure,
            'failure_step_observation': failure_step_observation,
            'result': result,
            'host_sha_block_setup': host_setup,
            'host_sha_block_setup_samples': host_setup_samples,
            'sha_ticks_after_host_setup': sha_ticks_after_setup,
            'sha_ticks_after_schedule': sha.local_ticks,
            'schedule_heartbeat_path': (None if heartbeat_path is None
                else str(heartbeat_path)),
            'identity_documents': _plain(identity_docs),
            'd4_binding': d4,
            'route_admission_identity': dma._dma_route_admission.identity_document(),
            'route_matches': _plain(admission.route_matches),
            'policy_completions': _plain(policy.completion_receipts),
            'typed_transaction_evidence': {
                'schema_version': 'compiled_f6_typed_transaction_evidence.v1',
                'transaction_type': _TRANSACTION_TYPE_NAME,
                'completion_types': list(policy.completion_transaction_types),
                'transactions': [row['transaction']
                    for row in policy.completion_receipts],
            },
            'execution_ids': _execution_ids(runner),
            'process_ids': process_ids,
            'ownership': _plain(runner.ownership.document()),
            'binding': asdict(binding),
            'runner_events': _plain(list(runner.events)),
            'cpu_events': _plain(list(cpu.cpu_events)),
            'cpu_memory_events': _plain(list(cpu.service.events)),
            'dma_events': _plain(list(dma.events)),
            'dma_memory_events': _plain(list(dma.memory_service.events)),
            'router_acceptances': _plain(list(cpu.router.acceptances)),
            'router_deliveries': _plain(list(cpu.router.deliveries)),
            'irq_events': _plain(list(runner._irq_pulses[binding].events)),
            'irq_state': runner._irq_pulses[binding].state_document(),
            'provider_receipts': provider_events,
            'dma_target_provider_method_calls': _plain(provider_method_calls),
            'admission_state': admission.state,
            'process_returncodes': {name: None for name in process_handles},
        }
        if native_pre_requests is not None:
            if len(native_pre_requests) != 1:
                raise AssertionError(
                    'wrong-offset run did not retain exactly one pre-backend request')
            attempted = native_pre_requests[0]
            rejected_key = TransactionKey(
                dma._execution, testcase_id, dma.source_component,
                dma.reset_epoch, 'dma-memory',
                attempted['source_sequence_before_acceptance'] + 1)
            if rejected_key.source_sequence != dma._source_sequence:
                raise AssertionError(
                    'captured wrong-offset request does not identify the refused sequence')
            evidence['attempted_native_request'] = attempted
            evidence['rejected_transaction'] = asdict(rejected_key)
        if keep_alive:
            retained = True
            return evidence, owners
        _close_owners(owners)
        evidence['process_returncodes'] = {
            name: process.returncode for name, process in process_handles.items()}
        return evidence
    finally:
        if native_pre_capture is not None:
            dma.command = native_pre_capture['original_command']
        if not retained and any(session.process is not None
                for session in runner.sessions.values()):
            _close_owners(owners)


def _close_owners(owners):
    runner = owners['runner']
    runner.finalize()


def _complete_kept_run(evidence, owners):
    processes = {name: session.process
        for name, session in owners['runner'].sessions.items()}
    if any(process is None for process in processes.values()):
        raise AssertionError('kept native session lost its process handle before finalize')
    try:
        _close_owners(owners)
    finally:
        evidence['process_returncodes'] = {
            name: process.returncode for name, process in processes.items()}


def _raw_artifact_comparison(first, fresh, first_d3_digest, fresh_d3_digest):
    if first_d3_digest != fresh_d3_digest:
        raise AssertionError('fresh D3 static compilation differs before projection')
    first_d4, fresh_d4 = first['d4_binding'], fresh['d4_binding']
    for name in ('compiled_paths', 'd3_wiring', 'source', 'transfer_pair',
                 'compiled_f6_runtime_path', 'compiled_f6_handoff',
                 'bound_wrapper'):
        if _canonical_bytes(first_d4[name]) != _canonical_bytes(fresh_d4[name]):
            raise AssertionError(f'fresh raw D4 artifact differs before projection: {name}')
    for digest_key in ('compiled_paths_sha256',
            'compiled_f6_runtime_path_sha256', 'compiled_f6_handoff_sha256',
            'bound_handoff_sha256'):
        if first_d4[digest_key] != fresh_d4[digest_key]:
            raise AssertionError(f'fresh D4 identity digest differs: {digest_key}')
    if first_d4['bind_count'] != 1 or fresh_d4['bind_count'] != 1:
        raise AssertionError('each positive run must perform one D4 bind')
    if first['identity_documents'] != fresh['identity_documents']:
        raise AssertionError('raw CPU/DMA/SHA Runner artifact identities changed')
    return {
        'schema_version': 'ibex_caliptra_sha_fresh_artifact_comparison.v1',
        'raw_documents_equal_before_event_projection': True,
        'd3_compiled_paths_sha256': first_d3_digest,
        'compiled_f6_runtime_path_sha256':
            first_d4['compiled_f6_runtime_path_sha256'],
        'compiled_f6_handoff_sha256': first_d4['compiled_f6_handoff_sha256'],
        'bound_handoff_sha256': first_d4['bound_handoff_sha256'],
        'raw_identity_documents_equal': True,
    }


def _owner_distinctness(first, fresh, first_owners, fresh_owners):
    object_names = ('runner', 'cpu_session', 'dma_session', 'sha_session',
        'memory', 'runtime_path', 'prepared_runtime_paths', 'unbound_handoff',
        'bound_runtime_path', 'bound_handoff')
    first_objects = {name: id(first_owners[name]) for name in object_names}
    fresh_objects = {name: id(fresh_owners[name]) for name in object_names}
    for label, objects in (('first', first_objects), ('fresh', fresh_objects)):
        if len(set(objects.values())) != len(objects):
            raise AssertionError(f'{label} run aliases distinct owner objects')
    for name in object_names:
        if first_objects[name] == fresh_objects[name]:
            raise AssertionError(f'fresh replay reused first {name} owner')
    all_process_ids = [first['process_ids'][name] for name in ('cpu', 'dma', 'sha')]
    all_process_ids += [fresh['process_ids'][name] for name in ('cpu', 'dma', 'sha')]
    if any(type(pid) is not int or pid <= 0 for pid in all_process_ids):
        raise AssertionError('fresh replay process PID evidence is incomplete')
    if len(set(all_process_ids)) != len(all_process_ids):
        raise AssertionError('first/fresh native process PIDs are not distinct')
    for name in ('cpu', 'dma', 'sha', 'runner'):
        if first['execution_ids'][name] == fresh['execution_ids'][name]:
            raise AssertionError(f'fresh replay reused the {name} execution ID')
    return {
        'schema_version': 'ibex_caliptra_sha_fresh_owner_distinctness.v1',
        'object_names': list(object_names),
        'first_object_ids': first_objects,
        'fresh_object_ids': fresh_objects,
        'native_process_pids_all_distinct': True,
        'execution_ids_all_distinct_across_runs': True,
    }


def _event_projection(run):
    fields = (
        'schema_version', 'testcase_id', 'source_address', 'source_value',
        'destination_address', 'selected_destination_address', 'schedule',
        'round_bound', 'completed_rounds', 'failure', 'result',
        'host_sha_block_setup', 'host_sha_block_setup_samples',
        'sha_ticks_after_host_setup', 'sha_ticks_after_schedule',
        'ownership', 'binding', 'runner_events', 'cpu_events',
        'cpu_memory_events', 'dma_events', 'dma_memory_events',
        'router_acceptances', 'router_deliveries', 'irq_events', 'irq_state',
        'provider_receipts', 'dma_target_provider_method_calls',
        'route_matches', 'policy_completions',
        'typed_transaction_evidence', 'admission_state',
    )
    return _sha_typed_projection({key: run[key] for key in fields},
        execution_ids=run['execution_ids'],
        sha_execution_id=run['execution_ids']['sha'],
        context='ibex_caliptra_sha_event_projection',
        normalize_runner_state_edges=True)


def _json_pointer_child(path, key):
    token = str(key).replace('~', '~0').replace('/', '~1')
    return f'{path}/{token}'


def _projection_preview(value):
    if value is _MISSING_PROJECTION_VALUE:
        return '<missing>'
    try:
        rendered = json.dumps(value, sort_keys=True, ensure_ascii=False,
            separators=(',', ':'), allow_nan=False)
    except (TypeError, ValueError):
        rendered = repr(value)
    return rendered if len(rendered) <= 240 else rendered[:237] + '...'


_MISSING_PROJECTION_VALUE = object()


def _projection_difference(path, reason, reference, fresh):
    return {
        'schema_version': 'ibex_caliptra_sha_projection_difference.v1',
        'path': path or '',
        'reason': reason,
        'reference_type': ('missing' if reference is _MISSING_PROJECTION_VALUE
                           else type(reference).__name__),
        'fresh_type': ('missing' if fresh is _MISSING_PROJECTION_VALUE
                       else type(fresh).__name__),
        'reference_preview': _projection_preview(reference),
        'fresh_preview': _projection_preview(fresh),
    }


def _first_json_difference(reference, fresh, path=''):
    if type(reference) is dict and type(fresh) is dict:
        for key in sorted(set(reference) | set(fresh)):
            child_path = _json_pointer_child(path, key)
            if key not in reference:
                return _projection_difference(child_path, 'missing_reference_key',
                    _MISSING_PROJECTION_VALUE, fresh[key])
            if key not in fresh:
                return _projection_difference(child_path, 'missing_fresh_key',
                    reference[key], _MISSING_PROJECTION_VALUE)
            difference = _first_json_difference(reference[key], fresh[key],
                child_path)
            if difference is not None:
                return difference
        return None
    if type(reference) is list and type(fresh) is list:
        if len(reference) != len(fresh):
            return _projection_difference(path, 'list_length',
                reference, fresh)
        for index, (left, right) in enumerate(zip(reference, fresh)):
            difference = _first_json_difference(left, right,
                _json_pointer_child(path, index))
            if difference is not None:
                return difference
        return None
    if type(reference) is not type(fresh):
        return _projection_difference(path, 'type', reference, fresh)
    if reference != fresh:
        return _projection_difference(path, 'value', reference, fresh)
    return None


def _assert_dma_control_retirement_join(run):
    expected = [(8, SOURCE), (12, DESTINATION), (4, 1), (0, START_WORD)]
    deliveries = [row for row in run['router_deliveries']
        if row.get('device_id') == 'dma' and row.get('write') is True]
    observed = [(row['offset'], row['write_value']) for row in deliveries]
    if observed != expected:
        raise AssertionError(f'CPU DMA register programming order differs: {observed!r}')
    accepts = [row for row in run['cpu_events']
        if row.get('kind') == 'data_accept']
    retires = [row for row in run['cpu_events']
        if row.get('kind') == 'cpu_retire' and row.get('mem_wmask') == 15]
    joins = []
    previous_order = -1
    for offset, value in expected:
        address = DMA_BASE + offset
        candidates = [row for row in deliveries
            if row.get('offset') == offset and row.get('write_value') == value]
        if len(candidates) != 1:
            raise AssertionError('DMA control delivery is not unique')
        delivery = candidates[0]
        transaction = _plain(delivery.get('source_transaction'))
        matching_accepts = [row for row in accepts
            if row.get('transaction') == transaction
            and row.get('address') == address and row.get('write') == 1
            and row.get('wdata') == value]
        if len(matching_accepts) != 1:
            raise AssertionError('DMA register delivery lacks its CPU OBI acceptance')
        retired = [row for row in retires
            if row.get('mem_addr') == address and row.get('mem_wdata') == value]
        if len(retired) != 1:
            raise AssertionError('DMA register write lacks one actual RVFI retire receipt')
        receipt = retired[0]
        # CpuSession emits rvfi_order as the normalized event field `order`.
        order = receipt.get('order')
        if (receipt.get('schema_version') != 'cpu_retire.v2'
                or receipt.get('phase') != 'post'
                or receipt.get('receipt_ticks', {}).get('new_ticks') != 1
                or type(order) is not int
                or order <= previous_order
                or not MAIN <= receipt.get('pc_rdata', -1) < ISR):
            raise AssertionError('DMA control write retirement receipt is malformed or unordered')
        previous_order = order
        control_receipt = delivery.get('dma_control_receipt')
        if (type(control_receipt) is not dict
                or control_receipt.get('source_transaction') != transaction
                or control_receipt.get('offset') != offset
                or control_receipt.get('value') != value):
            raise AssertionError('DMA control access lacks its typed OBI-to-control receipt')
        joins.append({'offset': offset, 'address': address, 'value': value,
            'source_transaction': transaction,
            'obi_acceptance': matching_accepts[0],
            'dma_control_receipt': control_receipt,
            'rvfi_retire_receipt': receipt})
    return joins


def _assert_irq_and_isr_join(run):
    dma_identity = run['identity_documents']['sessions']['dma']
    irq_name = dma_identity['scenario_dma_interface']['irq_runtime_name']
    dma_edges = [row for row in run['dma_events'] if row.get('kind') == 'dma_edge']
    high_edges = [row for row in dma_edges
        if row.get('payload', {}).get('observations', {}).get('physical', {}).get(
            irq_name) == 1]
    if not high_edges:
        raise AssertionError('native DMA completion IRQ was never observed high')
    rises = []
    prior = 0
    for row in dma_edges:
        level = row.get('payload', {}).get('observations', {}).get(
            'physical', {}).get(irq_name)
        if type(level) is not int or level not in (0, 1):
            raise AssertionError('native DMA IRQ edge lacks a one-bit physical observation')
        if level == 1 and prior == 0:
            rises.append(row)
        prior = level
    if len(rises) != 1:
        raise AssertionError(f'expected one native DMA IRQ rise, got {len(rises)}')
    runner_irq_events = [row for row in run['runner_events']
        if row.get('kind') in ('source_start', 'pulse_start', 'cpu_irq_taken')]
    pulse_starts = [row for row in runner_irq_events
        if row.get('kind') == 'pulse_start']
    source_starts = [row for row in runner_irq_events
        if row.get('kind') == 'source_start']
    pulse_takes = [row for row in runner_irq_events
        if row.get('kind') == 'cpu_irq_taken']
    cpu_takes = [row for row in run['cpu_events']
        if row.get('kind') == 'cpu_external_irq_taken']
    if (len(source_starts) != 1 or len(pulse_starts) != 1
            or len(pulse_takes) != 1 or len(cpu_takes) != 1):
        raise AssertionError('native DMA IRQ did not join one pulse to one Ibex take')
    source = source_starts[0]
    pulse = pulse_starts[0]
    taken = pulse_takes[0]
    cpu_take = cpu_takes[0]
    expected_binding = {
        'source_component': 'dma', 'source_port': 'irq',
        'target_component': 'cpu', 'target_port': 'irq', 'width': 1,
        'source_bit_offset': 0, 'target_bit_offset': 0,
    }
    pulse_configuration = run['identity_documents']['runner'].get('irq_pulses', [])
    if (run['binding'] != expected_binding
            or len(pulse_configuration) != 1
            or pulse_configuration[0].get('binding') != expected_binding
            or pulse_configuration[0].get('width_cpu_ticks') != 16
            or source.get('source') != ['dma', 'irq']
            or source.get('target') != ['cpu', 'irq']
            or pulse.get('source') != ['dma', 'irq']
            or pulse.get('target') != ['cpu', 'irq']
            or source.get('source_tick') != rises[0].get('tick')
            or source.get('source_event_id') != pulse.get('source_event_id')
            or pulse.get('source_event_id') != taken.get('source_event_id')
            or pulse.get('end_cpu_tick_exclusive')
                - pulse.get('start_cpu_tick') != 16
            or not pulse['start_cpu_tick'] <= taken['cpu_tick']
                < pulse['end_cpu_tick_exclusive']
            or cpu_take.get('local_tick') != taken.get('cpu_tick')
            or cpu_take.get('irq_taken_pre') != 1
            or cpu_take.get('actual_pre_input') != 1):
        raise AssertionError('Ibex did not take the DMA IRQ inside its fixed pulse')
    step_takes = [row for row in run['runner_events']
        if row.get('component') == 'cpu'
        and row.get('local_tick') == taken.get('cpu_tick')
        and row.get('outputs', {}).get('irq_taken_pre') == 1]
    if len(step_takes) != 1:
        raise AssertionError('runner CPU step receipt differs from the actual IRQ take')

    deliveries = run['router_deliveries']
    dma_status_reads = [row for row in deliveries
        if row.get('device_id') == 'dma' and row.get('offset') == 0
        and row.get('write') is False]
    if len(dma_status_reads) != 1 or dma_status_reads[0].get('read_value') != 0:
        raise AssertionError('Ibex ISR did not read successful DMA status exactly once')
    sha_status_reads = [row for row in deliveries
        if row.get('device_id') == 'sha'
        and row.get('offset') == SHA_STATUS and row.get('write') is False]
    sha_digest_reads = [row for row in deliveries
        if row.get('device_id') == 'sha'
        and SHA_DIGEST0 <= row.get('offset', -1) < SHA_DIGEST0 + 32
        and row.get('write') is False]
    if len(sha_status_reads) < 1:
        raise AssertionError('Ibex ISR never polled Caliptra SHA STATUS')
    if [(row['offset'], row.get('read_value')) for row in sha_digest_reads] != [
            (SHA_DIGEST0 + index * 4,
             int.from_bytes(hashlib.sha256(b'abc').digest()[index * 4:index * 4 + 4], 'big'))
            for index in range(8)]:
        raise AssertionError('Ibex ISR digest reads do not match all eight SHA words')
    if any(row.get('write') is True for row in deliveries
            if row.get('device_id') == 'sha'):
        raise AssertionError('Ibex CPU directly wrote Caliptra during measured schedule')

    sha_load_retires = [row for row in run['cpu_events']
        if row.get('kind') == 'cpu_retire' and row.get('mem_wmask') == 0
        and row.get('mem_rmask') == 15
        and (row.get('mem_addr') == SHA_BASE + SHA_STATUS
            or SHA_BASE + SHA_DIGEST0 <= row.get('mem_addr', -1)
                < SHA_BASE + SHA_DIGEST0 + 32)]
    expected_sha_reads = [row.get('read_value') for row in sha_status_reads]
    expected_sha_reads += [row.get('read_value') for row in sha_digest_reads]
    actual_sha_reads = [row.get('mem_rdata') for row in sha_load_retires]
    if actual_sha_reads != expected_sha_reads:
        raise AssertionError('CPU retired SHA reads differ from router responses')

    digest = hashlib.sha256(b'abc').digest()
    digest_words = [int.from_bytes(digest[index * 4:index * 4 + 4], 'big')
                    for index in range(8)]
    expected_writes = [(RESULT, 0x8000000B), (RESULT + 4, 0)] + [
        (RESULT + 8 + index * 4, word)
        for index, word in enumerate(digest_words)] + [(RESULT + 40, 1)]
    isr_writes = [row for row in run['cpu_memory_events']
        if row.get('kind') == 'memory_write'
        and RESULT <= row.get('address', -1) <= RESULT + 40]
    if [(row.get('address'), row.get('value')) for row in isr_writes] != expected_writes:
        raise AssertionError('ISR RAM result writes do not match the SHA-256 abc digest')
    isr_store_retires = [row for row in run['cpu_events']
        if row.get('kind') == 'cpu_retire' and row.get('mem_wmask') == 15
        and RESULT <= row.get('mem_addr', -1) <= RESULT + 40]
    if ([(row.get('mem_addr'), row.get('mem_wdata'))
            for row in isr_store_retires] != expected_writes
            or any(not ISR <= row.get('pc_rdata', -1) < SOURCE
                for row in isr_store_retires)):
        raise AssertionError('ISR result writes lack ordered real Ibex retire receipts')
    return {
        'dma_irq_rise': rises[0],
        'irq_source_start': source,
        'pulse_start': pulse,
        'pulse_take': taken,
        'cpu_irq_take_receipt': cpu_take,
        'runner_cpu_take_step': step_takes[0],
        'dma_status_read': dma_status_reads[0],
        'sha_status_reads': sha_status_reads,
        'sha_digest_reads': sha_digest_reads,
        'sha_load_retirements': sha_load_retires,
        'isr_result_writes': isr_writes,
        'isr_result_store_retirements': isr_store_retires,
        'saved_digest': digest.hex(),
    }


def _assert_positive(run):
    if run['failure'] is not None:
        raise AssertionError(f'native positive schedule failed: {run["failure"]!r}')
    expected_digest = hashlib.sha256(b'abc').digest()
    expected_words = [int.from_bytes(expected_digest[index * 4:index * 4 + 4], 'big')
                      for index in range(8)]
    expected_result = [0x8000000B, 0, *expected_words, 1]
    if run['result'] != expected_result:
        raise AssertionError(f'Ibex ISR result differs: {run["result"]!r}')
    if run['admission_state'] != 'complete' or len(run['route_matches']) != 2:
        raise AssertionError('D4 did not admit exactly one DMA read and one write')
    if len(run['policy_completions']) != 2 or len(run['provider_receipts']) != 1:
        raise AssertionError('Caliptra F6 transfer lacks one read/write/provider join')
    if run['d4_binding']['bind_count'] != 1:
        raise AssertionError('positive run did not bind D4 exactly once')
    if run['process_returncodes'] != {'cpu': None, 'dma': None, 'sha': None}:
        raise AssertionError('kept native sessions unexpectedly exited before comparison')
    read_match, write_match = run['route_matches']
    read_key, write_key = read_match['transaction'], write_match['transaction']
    if (read_key == write_key
            or (read_match['address'], read_match['operation']) != (SOURCE, 'read')
            or (write_match['address'], write_match['operation']) !=
                (DESTINATION, 'write')):
        raise AssertionError('D4 route matches lack the exact RAM read/CTRL write pair')
    memory_reads = [row for row in run['dma_memory_events']
        if row.get('kind') == 'memory_read' and row.get('address') == SOURCE
        and row.get('transaction') == read_key]
    if len(memory_reads) != 1 or memory_reads[0].get('value') != SOURCE_VALUE:
        raise AssertionError('DMA read did not consume the declared source RAM word')
    beats = [row.get('accepted') for row in run['dma_events']
        if type(row.get('accepted')) is dict]
    beat_shape = [(row['address'], row['write']) for row in beats]
    if beat_shape != [(SOURCE, False), (DESTINATION, True)]:
        raise AssertionError(
            f'native DMA beat stream is not the selected one-word transfer: '
            f'{beat_shape!r}')
    if ([row.get('transaction') for row in beats] != [read_key, write_key]
            or any(row.get('byte_enable') != 15 for row in beats)):
        raise AssertionError('native DMA beats lack the keyed full-word route joins')
    # On a read, accepted.value is the native Wishbone write-data pin, not the
    # returned RAM word. The keyed memory-read and response rows below prove
    # that read value; only the accepted write beat carries the source word.
    if beats[1].get('value') != SOURCE_VALUE:
        raise AssertionError('native DMA write beat did not carry the source word')
    responses = [row.get('response') for row in run['dma_events']
        if type(row.get('response')) is dict]
    responses_by_key = {json.dumps(row['transaction'], sort_keys=True): row
                        for row in responses}
    read_response = responses_by_key.get(json.dumps(read_key, sort_keys=True))
    write_response = responses_by_key.get(json.dumps(write_key, sort_keys=True))
    if (read_response is None or (read_response.get('rdata'), read_response.get('error'))
            != (SOURCE_VALUE, 0)
            or write_response is None
            or (write_response.get('rdata'), write_response.get('error')) != (0, 0)):
        raise AssertionError('native DMA read/write responses do not join to accepted beats')
    completion_types = run['typed_transaction_evidence']['completion_types']
    if completion_types != [_TRANSACTION_TYPE_NAME, _TRANSACTION_TYPE_NAME]:
        raise AssertionError('D4 completion policy lost typed transaction identities')
    provider = run['provider_receipts'][0]
    provider_call = run['dma_target_provider_method_calls']
    if provider_call != [{
            'source_transaction': write_key,
            'address': DESTINATION, 'offset': SHA_CTRL_OFFSET,
            'write': True, 'value': SOURCE_VALUE, 'byte_enable': 15}]:
        raise AssertionError(
            'Caliptra provider method entry does not exactly join the DMA CTRL write')
    if (provider.get('source_transaction') != write_key
            or provider.get('request') != {
                'address': DESTINATION, 'offset': SHA_CTRL_OFFSET,
                'value': SHA_CTRL_START_VALUE, 'write': True, 'byte_enable': 15}
            or provider.get('response') != {'rdata': 0, 'error': 0}
            or provider.get('status') != 'observed'):
        raise AssertionError('Caliptra provider receipt does not match the DMA CTRL write')
    target_request = provider.get('target_request', {})
    target_response = provider.get('target_response', {})
    target_effect = provider.get('target_effect', {})
    access_id = provider.get('target_access_id')
    if (target_request.get('source_transaction') != write_key
            or target_response.get('source_transaction') != write_key
            or target_effect.get('source_transaction') != write_key
            or target_request.get('access_id') != access_id
            or target_response.get('access_id') != access_id
            or target_effect.get('access_id') != access_id
            or target_request.get('backend', {}).get('hwdata') != SOURCE_VALUE
            or target_request.get('backend', {}).get('hwrite') != 1
            or target_response.get('error') != 0
            or target_effect.get('physical_write_data') != SOURCE_VALUE):
        raise AssertionError('Caliptra AHB phase witnesses do not join to DMA transaction')
    config_joins = _assert_dma_control_retirement_join(run)
    irq_isr = _assert_irq_and_isr_join(run)
    if run['result'][2:10] != expected_words:
        raise AssertionError('saved digest words do not equal SHA-256(abc)')
    return {'cpu_dma_register_write_retirements': config_joins,
            'irq_and_isr': irq_isr}


def _run_wrong_offset(cache_dir, d3_wiring, compiled_paths):
    run, owners = _run_case(cache_dir, d3_wiring, compiled_paths,
        destination=WRONG_DESTINATION, keep_alive=True)
    try:
        dma = owners['dma_session']
        sha = owners['sha_session']
        cpu = owners['cpu_session']
        failed_step = run.get('failure_step_observation')
        captured_steps = [row for row in run['runner_events']
            if row.get('kind') == 'harness_failure' and row.get('component') == 'dma']
        if (run['failure'] is None or run['failure']['type'] != 'ValueError'
                or run['failure']['message']
                    != 'DMA route match does not exactly match the selected route'
                or len(captured_steps) != 1 or type(failed_step) is not dict
                or failed_step.get('component') != 'dma'):
            raise AssertionError('wrong-offset native transfer did not fail at D4 admission')
        dma_identity = run['execution_ids']['dma']
        attempted = run.get('attempted_native_request')
        if type(attempted) is not dict:
            raise AssertionError('wrong-offset pre-backend request was not retained')
        pre = attempted.get('pre_backend', {})
        if (attempted.get('operation') != 'STEP_WB_DMA'
                or attempted.get('status') != 'result'
                or attempted.get('new_ticks') != 1
                or pre.get('mwb_cyc') != 1 or pre.get('mwb_stb') != 1
                or pre.get('mwb_we') != 1
                or (pre.get('mwb_adr', -1) << 2) != WRONG_DESTINATION
                or pre.get('mwb_dat_w') != SOURCE_VALUE):
            raise AssertionError('wrong-offset pre-backend Wishbone request is inexact')
        rejected = run.get('rejected_transaction')
        key = _checked_transaction_document(rejected,
            context='wrong-offset native DMA request')
        if (key.execution_id != dma_identity or key.testcase_id != run['testcase_id']
                or key.source_component != 'dma' or key.channel_id != 'dma-memory'
                or key.source_sequence != attempted['source_sequence_before_acceptance'] + 1
                or key.source_sequence != dma._source_sequence):
            raise AssertionError('wrong-offset native request lost its typed DMA key')
        before = failed_step['sha_observation_before']
        after = failed_step['sha_observation_after']
        if (failed_step.get('sha_provider_receipt_delta') != 0
                or failed_step.get('sha_command_sequence_delta') != 0
                or failed_step.get('sha_local_tick_delta') != 0
                or failed_step.get('sha_tick_samples_during_failed_step')
                or after.get('sha_local_ticks') != sha.local_ticks
                or after.get('sha_provider_receipts') != len(sha._dma_target_events)
                or run['provider_receipts']
                or sha._dma_target_events):
            raise AssertionError('wrong-offset D4 refusal reached the Caliptra AHB provider')
        if (run['route_matches'] and any(row.get('transaction') == rejected
                for row in run['route_matches'])):
            raise AssertionError('refused CTRL+4 transaction was admitted by D4')
        if any(event.get('accepted', {}).get('transaction') == rejected
                for event in run['dma_events'] if type(event.get('accepted')) is dict):
            raise AssertionError('refused CTRL+4 transaction was recorded as accepted')
        if (any(row.get('kind') == 'source_start' for row in run['irq_events'])
                or any(row.get('kind') in ('source_start', 'pulse_start', 'cpu_irq_taken')
                    for row in run['runner_events'])
                or any(row.get('kind') == 'cpu_external_irq_taken'
                    for row in run['cpu_events'])
                or cpu.memory.read(RESULT + 40, 4,
                    transaction_id='ibex-caliptra-negative-marker').value != 0):
            raise AssertionError('wrong-offset request caused completion IRQ or ISR success')
        if run['d4_binding']['bind_count'] != 1:
            raise AssertionError('wrong-offset run did not bind D4 exactly once')
        run['rejected_transaction'] = asdict(key)
        run['negative_native_edges'] = [attempted]
        run['negative_dma_failure_events'] = captured_steps
        run['provider_receipt_count'] = len(sha._dma_target_events)
        run['provider_receipt_count_before_refused_write'] = before[
            'sha_provider_receipts']
        run['provider_receipt_count_delta_for_refused_write'] = failed_step[
            'sha_provider_receipt_delta']
        run['ahb_effect_count_delta_for_refused_write'] = (
            failed_step['sha_provider_receipt_delta']
            + len(failed_step['sha_tick_samples_during_failed_step']))
        run['ahb_command_sequence_delta_for_refused_write'] = failed_step[
            'sha_command_sequence_delta']
        run['ahb_ticks_before_refused_write'] = before['sha_local_ticks']
        run['ahb_ticks_after_refused_write'] = after['sha_local_ticks']
        run['refusal_scope'] = (
            'native DMA CTRL+4 request retained as typed transaction and refused '
            'before Caliptra AHB provider command')
        return run, owners
    except BaseException:
        _close_owners(owners)
        raise


def _capture_wrong_native_pre(dma):
    captured = []
    original = dma.command

    def capture(operation, fields):
        sequence_before = dma._source_sequence
        receipt = original(operation, fields)
        if operation == 'STEP_WB_DMA':
            pre = dict(receipt.payload['pre_backend'])
            if (pre.get('mwb_cyc') == 1 and pre.get('mwb_stb') == 1
                    and pre.get('mwb_we') == 1
                    and (pre.get('mwb_adr', -1) << 2) == WRONG_DESTINATION):
                captured.append({
                    'operation': operation,
                    'fields': list(fields),
                    'status': receipt.status,
                    'execution': receipt.execution,
                    'sequence': receipt.sequence,
                    'tick_before': receipt.tick_before,
                    'tick_after': receipt.tick_after,
                    'new_ticks': receipt.new_ticks,
                    'source_sequence_before_acceptance': sequence_before,
                    'pre_backend': pre,
                })
        return receipt

    dma.command = capture
    return {'requests': captured, 'original_command': original}


def _event_projection_for_compare(reference, fresh, *, projections=None,
                                 evidence_root=None):
    # Compare the exact artifacts and hardware/session identities before any
    # execution-identity projection is allowed.
    if (_canonical_bytes(reference['identity_documents'])
            != _canonical_bytes(fresh['identity_documents'])):
        raise AssertionError('fresh raw artifact identity documents differ')
    if projections is None:
        first, actual = _event_projection(reference), _event_projection(fresh)
    else:
        first, actual = projections
    if _canonical_bytes(first) != _canonical_bytes(actual):
        difference = _first_json_difference(first, actual)
        if evidence_root is not None:
            _save_json(evidence_root, 'fresh-event-semantic-difference',
                difference)
        raise AssertionError('typed SHA-specific fresh event projection differs '
            f'at {difference["path"] or "/"} ({difference["reason"]}): '
            f'reference={difference["reference_preview"]}; '
            f'fresh={difference["fresh_preview"]}')
    digest = lambda payload: hashlib.sha256(_canonical_bytes(payload)).hexdigest()
    return first, actual, {
        'schema_version': 'ibex_caliptra_sha_typed_fresh_replay.v1',
        'equal': True,
        'reference_schedule_steps': len(reference['schedule']),
        'fresh_schedule_steps': len(fresh['schedule']),
        'normalized_reference_sha256': digest(first),
        'normalized_fresh_sha256': digest(actual),
        'normalizer': {
            'execution_identity_fields': ['execution', 'execution_id',
                                          'typed TransactionKey.execution_id'],
            'execution_roles': ['cpu', 'dma', 'sha', 'runner'],
            'caliptra_access_fields': ['access_id', 'target_access_id'],
            'caliptra_access_format':
                'caliptra-ahb:<32-lowercase-hex-sha-session>:<positive-decimal-sequence>',
            'access_sequence_preserved': True,
            'runner_state_edge_collection': 'runner_events',
            'runner_state_edge_endpoint_fields': ['source', 'target'],
            'runner_state_edge_requires_closed_canonical_row': True,
            'unknown_state_edge_execution_ids_retained': True,
            'raw_identity_documents_compared_before_projection': True,
        },
    }


def test_sha_replay_normalizer_checks_and_projects_caliptra_access_ids():
    ids = {'cpu': '1' * 32, 'dma': '2' * 32,
           'sha': '3' * 32, 'runner': '4' * 32}
    event = {
        'execution_id': ids['dma'],
        'transaction': {
            'execution_id': ids['dma'], 'testcase_id': TESTCASE_ID,
            'source_component': 'dma', 'source_epoch': 0,
            'channel_id': 'dma-memory', 'source_sequence': 2,
        },
        'target_provider_receipt': {
            'schema_version': 'dma_master_target_access.v1',
            'target_access_id': f'caliptra-ahb:{ids["sha"]}:17',
            'target_access': {'access_id': f'caliptra-ahb:{ids["sha"]}:17'},
        },
        'payload': f'opaque-{ids["sha"]}',
    }
    projected = _sha_typed_projection(event, execution_ids=ids,
        sha_execution_id=ids['sha'])
    assert projected['execution_id'] == '<execution:dma>'
    assert projected['transaction']['execution_id'] == '<execution:dma>'
    assert projected['target_provider_receipt']['target_access_id'] == \
        'caliptra-ahb:<execution:sha>:17'
    assert projected['payload'] == event['payload']


@pytest.mark.parametrize('bad_access_id', [
    'caliptra-ahb:foreign-session:1',
    'caliptra-ahb:' + ('a' * 32) + ':0',
    'caliptra-ahb:' + ('a' * 32) + ':01',
])
def test_sha_replay_normalizer_rejects_malformed_provider_access_ids(bad_access_id):
    ids = {'cpu': '1' * 32, 'dma': '2' * 32,
           'sha': '3' * 32, 'runner': '4' * 32}
    with pytest.raises(AssertionError):
        _sha_typed_projection({'schema_version': 'dma_master_target_access.v1',
            'target_access_id': bad_access_id}, execution_ids=ids,
            sha_execution_id=ids['sha'])


@pytest.mark.parametrize('bad_access_id', [None, 1, True])
def test_sha_replay_normalizer_rejects_untyped_provider_access_ids(bad_access_id):
    ids = {'cpu': '1' * 32, 'dma': '2' * 32,
           'sha': '3' * 32, 'runner': '4' * 32}
    with pytest.raises(AssertionError):
        _sha_typed_projection({'schema_version': 'dma_master_target_access.v1',
            'target_access_id': bad_access_id}, execution_ids=ids,
            sha_execution_id=ids['sha'])


@pytest.mark.parametrize('bad_ids', [
    {'cpu': '1' * 32, 'dma': '2' * 32, 'sha': '3' * 32},
    {'cpu': '1' * 32, 'dma': '2' * 32, 'sha': '3' * 32, 'runner': '3' * 32},
    {'cpu': '1' * 32, 'dma': '2' * 32, 'sha': 'g' * 32, 'runner': '4' * 32},
])
def test_sha_replay_normalizer_rejects_inexact_execution_role_identities(bad_ids):
    with pytest.raises(AssertionError):
        _sha_typed_projection({}, execution_ids=bad_ids,
            sha_execution_id=bad_ids.get('sha'))


def _sha_state_edge(*, execution_id, source='initial-image', target_sequence=2,
                    byte_offset=0, version=(1, 1)):
    target = TransactionKey(execution_id=execution_id,
        testcase_id=TESTCASE_ID, source_component='dma', source_epoch=0,
        channel_id='dma-memory', source_sequence=target_sequence)
    return {
        'kind': 'state_dependency',
        'event_id': 7,
        'producer_event_id': 6,
        'edge_kind': 'RAW',
        'memory_id': 'ibex-ram',
        'generation': 1,
        'byte_offset': byte_offset,
        'version': list(version) if version is not None else None,
        'source': source,
        'target': repr(target),
    }


def test_sha_replay_normalizer_projects_only_canonical_runner_state_edge_ids():
    first_ids = {'cpu': '1' * 32, 'dma': '2' * 32,
                 'sha': '3' * 32, 'runner': '4' * 32}
    fresh_ids = {'cpu': '5' * 32, 'dma': '6' * 32,
                 'sha': '7' * 32, 'runner': '8' * 32}
    first_edge = _sha_state_edge(execution_id=first_ids['dma'])
    fresh_edge = _sha_state_edge(execution_id=fresh_ids['dma'])
    first = _sha_typed_projection({'runner_events': [first_edge]},
        execution_ids=first_ids, sha_execution_id=first_ids['sha'],
        normalize_runner_state_edges=True)
    fresh = _sha_typed_projection({'runner_events': [fresh_edge]},
        execution_ids=fresh_ids, sha_execution_id=fresh_ids['sha'],
        normalize_runner_state_edges=True)
    assert first == fresh
    assert first['runner_events'][0]['target'].startswith(
        "TransactionKey(execution_id='<execution:dma>', ")
    assert first['runner_events'][0]['version'] == [1, 1]
    assert first['runner_events'][0]['byte_offset'] == 0

    changed = _sha_state_edge(execution_id=fresh_ids['dma'],
        target_sequence=3, byte_offset=1, version=(1, 2))
    changed_projection = _sha_typed_projection({'runner_events': [changed]},
        execution_ids=fresh_ids, sha_execution_id=fresh_ids['sha'],
        normalize_runner_state_edges=True)
    assert changed_projection != first


def test_sha_replay_normalizer_leaves_noncanonical_state_edge_references_exact():
    ids = {'cpu': '1' * 32, 'dma': '2' * 32,
           'sha': '3' * 32, 'runner': '4' * 32}
    edge = _sha_state_edge(execution_id=ids['dma'])
    unknown = _sha_state_edge(execution_id='a' * 32)
    malformed = dict(edge, target=(edge['target'] + ' trailing'))
    partial = dict(edge)
    partial.pop('generation')
    nested = {'kind': 'diagnostic', 'detail': edge}
    projected = _sha_typed_projection({'runner_events': [unknown, malformed,
        partial, nested], 'payload': edge['target']}, execution_ids=ids,
        sha_execution_id=ids['sha'], normalize_runner_state_edges=True)
    assert projected['runner_events'][0]['target'] == unknown['target']
    assert projected['runner_events'][1]['target'] == malformed['target']
    assert projected['runner_events'][2]['target'] == partial['target']
    assert projected['runner_events'][3]['detail']['target'] == edge['target']
    assert projected['payload'] == edge['target']


def test_sha_projection_difference_reports_first_json_pointer_and_values():
    difference = _first_json_difference(
        {'runner_events': [{'target': 'reference-id', 'byte_offset': 0}]},
        {'runner_events': [{'target': 'fresh-id', 'byte_offset': 0}]})
    assert difference['path'] == '/runner_events/0/target'
    assert difference['reason'] == 'value'
    assert difference['reference_type'] == 'str'
    assert difference['fresh_type'] == 'str'
    assert 'reference-id' in difference['reference_preview']
    assert 'fresh-id' in difference['fresh_preview']


def test_sha_projection_difference_preserves_json_scalar_types():
    difference = _first_json_difference({'value': True}, {'value': 1})
    assert difference['path'] == '/value'
    assert difference['reason'] == 'type'
    assert difference['reference_type'] == 'bool'
    assert difference['fresh_type'] == 'int'


def test_sha_fresh_compare_checks_raw_identity_documents_with_json_types():
    with patch.object(sys.modules[__name__], '_event_projection') as project:
        with pytest.raises(AssertionError,
                match='fresh raw artifact identity documents differ'):
            _event_projection_for_compare(
                {'identity_documents': {'native': True}},
                {'identity_documents': {'native': 1}})
    project.assert_not_called()


def test_schedule_heartbeat_requires_terminal_round_checkpoint(tmp_path):
    heartbeat = tmp_path / 'schedule.jsonl'
    heartbeat.write_text(json.dumps({
        'phase': 'after_host_setup', 'round_index': 0,
        'schedule_steps': 0, 'marker': None,
    }) + '\n', encoding='utf-8')
    run = {
        'schedule_heartbeat_path': str(heartbeat),
        'schedule': list(ROUND) * 2,
        'completed_rounds': 2,
        'failure': None,
        'result': [0] * 10 + [1],
    }
    with pytest.raises(AssertionError,
            match='schedule heartbeat lacks the terminal round checkpoint'):
        _assert_schedule_heartbeat_complete(run)


def test_sha_kept_run_captures_process_objects_before_runner_finalizes():
    class Process:
        returncode = None

    class Session:
        process = Process()

    session = Session()
    process = session.process

    class Runner:
        sessions = {'cpu': session}

        def finalize(self):
            process.returncode = 0
            session.process = None

    evidence = {}
    _complete_kept_run(evidence, {'runner': Runner()})
    assert evidence['process_returncodes'] == {'cpu': 0}


@pytest.mark.skipif(os.environ.get('MYFUZZ_IBEX_CALIPTRA_SHA_DMA_REAL') != '1',
    reason='explicit native Ibex/DMA/Caliptra SHA positive and fresh replay gate')
def test_real_ibex_dma_caliptra_sha_irq_isr_and_typed_fresh_replay(tmp_path):
    from myfuzz.scenario.compiled_paths import (
        compiled_document_sha256, load_path_compile_request, compile_paths)

    cache, evidence = _settings()
    (d3_wiring, _request, compiled_paths, compile_request_path, d3_digest,
     d2_wiring_document) = (
        _native_d3_material(tmp_path / 'd3-first'))
    first = fresh = None
    first_owners = fresh_owners = None
    try:
        first, first_owners = _run_case(cache, d3_wiring, compiled_paths,
            keep_alive=True)
        _assert_schedule_heartbeat_complete(first)
        positive_joins = _assert_positive(first)
        _save_json(evidence, 'first-run', first)
        _save_json(evidence, 'first-joins', positive_joins)
        first_projection = _event_projection(first)
        _save_json(evidence, 'first-event-semantic-projection',
            first_projection)

        fresh_request = load_path_compile_request(compile_request_path,
            base_dir=ROOT)
        fresh_compiled_paths = compile_paths(fresh_request)
        fresh_d3_digest = compiled_document_sha256(fresh_compiled_paths)
        if fresh_compiled_paths is compiled_paths or fresh_d3_digest != d3_digest:
            raise AssertionError('fresh D3 compilation differs from the RVFI-pinned request')
        fresh, fresh_owners = _run_case(cache, fresh_request.wiring,
            fresh_compiled_paths, schedule_prefix=first['schedule'], keep_alive=True)
        _assert_schedule_heartbeat_complete(fresh)
        _save_json(evidence, 'fresh-run', fresh)
        if fresh['schedule'] != first['schedule']:
            raise AssertionError('fresh run did not consume the exact positive schedule')
        fresh_joins = _assert_positive(fresh)
        _save_json(evidence, 'fresh-joins', fresh_joins)
        fresh_projection = _event_projection(fresh)
        _save_json(evidence, 'fresh-event-semantic-projection',
            fresh_projection)
        raw_artifacts = _raw_artifact_comparison(
            first, fresh, d3_digest, fresh_d3_digest)
        owner_evidence = _owner_distinctness(
            first, fresh, first_owners, fresh_owners)
        first_projection, fresh_projection, comparison = (
            _event_projection_for_compare(first, fresh,
                projections=(first_projection, fresh_projection),
                evidence_root=evidence))
        if _canonical_bytes(positive_joins) != _canonical_bytes(fresh_joins):
            # The nested physical receipts contain process identities; their
            # semantic form has already been compared by the typed projection.
            projected_joins = _sha_typed_projection(positive_joins,
                execution_ids=first['execution_ids'],
                sha_execution_id=first['execution_ids']['sha'])
            projected_fresh_joins = _sha_typed_projection(fresh_joins,
                execution_ids=fresh['execution_ids'],
                sha_execution_id=fresh['execution_ids']['sha'])
            if (_canonical_bytes(projected_joins)
                    != _canonical_bytes(projected_fresh_joins)):
                raise AssertionError('fresh join receipts differ after typed projection')
        comparison['raw_artifact_comparison'] = raw_artifacts
        comparison['owner_distinctness'] = owner_evidence
        _save_json(evidence, 'fresh-artifact-comparison', raw_artifacts)
        _save_json(evidence, 'owner-distinctness', owner_evidence)
        _save_json(evidence, 'first-event-semantic-projection', first_projection)
        _save_json(evidence, 'fresh-event-semantic-projection', fresh_projection)
        _save_json(evidence, 'fresh-event-semantic-comparison', comparison)
        _save_json(evidence, 'compile-request', json.loads(
            compile_request_path.read_text(encoding='utf-8')))
        _save_json(evidence, 'fresh-compile-request', json.loads(
            compile_request_path.read_text(encoding='utf-8')))
        _save_json(evidence, 'd2-generated-wiring-contract', d2_wiring_document)
        _save_compile_inputs(evidence, compile_request_path)

        _complete_kept_run(fresh, fresh_owners)
        fresh_owners = None
        _complete_kept_run(first, first_owners)
        first_owners = None
        for run in (first, fresh):
            if run['process_returncodes'] != {'cpu': 0, 'dma': 0, 'sha': 0}:
                raise AssertionError('positive native sessions did not all return cleanly')
        _save_json(evidence, 'first-run', first)
        _save_json(evidence, 'fresh-run', fresh)

    finally:
        if fresh_owners is not None:
            _close_owners(fresh_owners)
        if first_owners is not None:
            _close_owners(first_owners)


@pytest.mark.skipif(os.environ.get('MYFUZZ_IBEX_CALIPTRA_SHA_DMA_REAL') != '1',
    reason='explicit native wrong-offset Ibex/DMA/Caliptra refusal gate')
def test_real_ibex_dma_caliptra_sha_wrong_offset_refuses_before_ahb(tmp_path):
    from myfuzz.scenario.compiled_paths import (
        compiled_document_sha256, compile_paths, load_path_compile_request)

    cache, evidence = _settings()
    (d3_wiring, _request, compiled_paths, compile_request_path, _,
     d2_wiring_document) = (
        _native_d3_material(tmp_path / 'd3-negative'))
    _save_json(evidence, 'negative-d2-generated-wiring-contract',
        d2_wiring_document)
    _save_json(evidence, 'negative-compile-request', json.loads(
        compile_request_path.read_text(encoding='utf-8')))
    _save_compile_inputs(evidence, compile_request_path)
    # Independently load and recompile this D3 material before the native
    # negative route is prepared; static F6 remains unsupported here too.
    independent_request = load_path_compile_request(compile_request_path,
        base_dir=ROOT)
    independent_paths = compile_paths(independent_request)
    if (independent_paths is compiled_paths
            or compiled_document_sha256(independent_paths)
                != compiled_document_sha256(compiled_paths)):
        raise AssertionError('negative fresh D3 compilation changed its static identity')
    run, owners = _run_wrong_offset(cache, independent_request.wiring,
        independent_paths)
    try:
        _save_json(evidence, 'wrong-offset-refusal', run)
        if (run.get('provider_receipt_count') != 0
                or run.get('dma_target_provider_method_calls')):
            raise AssertionError('wrong-offset refusal reached the Caliptra provider')
        if (run.get('provider_receipt_count_delta_for_refused_write') != 0
                or run.get('ahb_effect_count_delta_for_refused_write') != 0):
            raise AssertionError('wrong-offset refusal caused a Caliptra provider receipt/effect')
        if run.get('ahb_command_sequence_delta_for_refused_write') != 0:
            raise AssertionError('wrong-offset refusal issued a Caliptra AHB command')
        if run.get('ahb_ticks_before_refused_write') != \
                run.get('ahb_ticks_after_refused_write'):
            raise AssertionError('wrong-offset refusal advanced Caliptra AHB ticks')
        if run['d4_binding']['compiled_paths_sha256'] != \
                compiled_document_sha256(independent_paths):
            raise AssertionError('wrong-offset evidence does not retain its D3 identity')
    finally:
        _complete_kept_run(run, owners)
        _save_json(evidence, 'wrong-offset-refusal', run)
    assert run['process_returncodes'] == {'cpu': 0, 'dma': 0, 'sha': 0}
