"""Opt-in real ZipCPU DMA to Caliptra AHB-Lite CTRL-start gate.

Run with ``MYFUZZ_DMA_CALIPTRA_REAL=1`` and operation-local cache/evidence
paths. The gate joins an accepted DMA RAM read and write to independent native
RTL processes; it does not claim a physical Wishbone-to-AHB bridge or CPU use.
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

from myfuzz.local_harness import (GeneratedLocalSession, load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver,
    verify_local_source_lock)
from myfuzz.local_harness.ahb_lite_register_session import (
    GeneratedAhbLiteRegisterSession)
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.caliptra_sha256_dma_paths import (
    CaliptraSha256DmaBeatAdmission, CaliptraSha256DmaRuntimePaths,
    SHA_CTRL_OFFSET, SHA_CTRL_START_VALUE)
from myfuzz.scenario.compiled_f6_runtime_path import (
    DmaTransferSourceWord, DmaTransferRoutePair,
    prepare_compiled_f6_runtime_path, bind_compiled_f6_runtime_path)
from myfuzz.scenario.dependency import SourceBinding, SourceBindings
from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = ROOT / 'docs/reports/evidence/p7-f6-runtime-path-caliptra-20261021'
RAM_BASE = 0x10000
RAM_SIZE = 0x20000
SOURCE_ADDRESS = RAM_BASE + 0x100
SHA_BASE = 0x40002000
SHA_SIZE = 0x1000
SHA_START_ADDRESS = SHA_BASE + SHA_CTRL_OFFSET
TESTCASE_ID = 'dma-caliptra-ctrl-start'
START_WORD = (0xFED << 16) | 1
_TRANSACTION_KEY_FIELDS = {
    'execution_id', 'testcase_id', 'source_component', 'source_epoch',
    'channel_id', 'source_sequence',
}
_EVENT_PROJECTION_FIELDS = (
    'route_matches', 'policy_completions', 'typed_transaction_evidence',
    'ram_read', 'dma_beats', 'dma_responses', 'provider_receipts',
    'sha_status', 'sha_digest', 'sha_expected_digest', 'admission_state',
)
_TRANSACTION_TYPE_NAME = 'myfuzz.scenario.ledger.TransactionKey'


def _settings(tmp_path):
    del tmp_path  # Native outputs and their D3 scratch stay in the task evidence tree.
    cache = Path(os.environ.get('MYFUZZ_DMA_CALIPTRA_CACHE',
        EVIDENCE_ROOT / 'cache-task3'))
    evidence = Path(os.environ.get('MYFUZZ_DMA_CALIPTRA_EVIDENCE', EVIDENCE_ROOT))
    evidence_root = EVIDENCE_ROOT.resolve()
    for label, path in (('cache', cache), ('evidence', evidence)):
        try:
            path.resolve().relative_to(evidence_root)
        except ValueError as error:
            raise ValueError(
                f'Caliptra native {label} path must stay under {EVIDENCE_ROOT}') from error
    return cache, evidence


def _caliptra_artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path='configs/peripherals/caliptra_sha256/component_profile.json',
        instance_id='sha', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16, tuning={'endpoint_policies': [dict(
            endpoint_id='sha256.bus', template_id='target.ahb-lite',
            template_version='1', variant_id='full-word-single',
            max_outstanding=1)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,
        render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)


def _save_json(root, name, value):
    root.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')
    (root / (name + '.json.gz')).write_bytes(gzip.compress(payload, mtime=0))


def _save_compile_inputs(root, compile_request_path):
    """Archive raw request dependencies with original paths and byte digests."""
    request = json.loads(compile_request_path.read_text(encoding='utf-8'))
    inputs = [(request['wiring']['source'], Path('compile-inputs/wiring_contract.json'),
               'wiring')]
    for index, device in enumerate(request['devices']):
        path = device.get('test_capability')
        if path is not None:
            inputs.append((path, Path('compile-inputs/test-capabilities')
                / f'{index}.json', device['instance_id']))
    manifest = []
    for source_path, evidence_path, role in inputs:
        source = Path(source_path)
        payload = source.read_bytes()
        destination = root / evidence_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        manifest.append({
            'role': role,
            'original_path': str(source),
            'evidence_path': evidence_path.as_posix(),
            'size_bytes': len(payload),
            'sha256': hashlib.sha256(payload).hexdigest(),
        })
    _save_json(root, 'compile-input-manifest', {
        'schema_version': 'compiled_f6_compile_inputs.v1',
        'inputs': manifest,
    })


def _checked_transaction_key(document, *, context):
    if type(document) is not dict or set(document) != _TRANSACTION_KEY_FIELDS:
        raise AssertionError(f'{context} is not a closed TransactionKey document')
    if (any(type(document[name]) is not str or not document[name]
            for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
            or any(type(document[name]) is not int or document[name] < 0
                   for name in ('source_epoch', 'source_sequence'))):
        raise AssertionError(f'{context} has invalid TransactionKey field types')
    try:
        key = TransactionKey(**document)
    except (TypeError, ValueError) as error:
        raise AssertionError(f'{context} is not a valid TransactionKey') from error
    if asdict(key) != document:
        raise AssertionError(f'{context} changed while validating its TransactionKey')
    return key


def _canonical_document_bytes(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'),
        ensure_ascii=False, allow_nan=False).encode('utf-8')


def _normalize_ahb_access_id(value, *, sha_execution_id, context):
    if type(value) is not str:
        raise AssertionError(f'{context} is not a Caliptra AHB access ID')
    if (type(sha_execution_id) is not str or len(sha_execution_id) != 32
            or any(char not in '0123456789abcdef' for char in sha_execution_id)):
        raise AssertionError(f'{context} has an invalid Caliptra AHB session ID')
    prefix = f'caliptra-ahb:{sha_execution_id}:'
    if not value.startswith(prefix):
        raise AssertionError(f'{context} has an unexpected Caliptra AHB session ID')
    sequence = value[len(prefix):]
    if (not sequence.isdecimal() or not sequence
            or int(sequence) <= 0 or str(int(sequence)) != sequence):
        raise AssertionError(f'{context} has an invalid Caliptra AHB sequence')
    return f'caliptra-ahb:<sha-session>:{sequence}'


def _event_semantic_value(value, *, sha_execution_id, context='event'):
    """Normalize only typed transaction keys and named AHB access-ID fields."""
    if type(value) is dict:
        if set(value) == _TRANSACTION_KEY_FIELDS:
            transaction = _checked_transaction_key(value, context=context)
            return {**asdict(transaction), 'execution_id': '<transaction-execution>'}
        projected = {}
        for key, item in value.items():
            if key in ('access_id', 'target_access_id'):
                projected[key] = _normalize_ahb_access_id(
                    item, sha_execution_id=sha_execution_id,
                    context=f'{context}.{key}')
            else:
                projected[key] = _event_semantic_value(
                    item, sha_execution_id=sha_execution_id,
                    context=f'{context}.{key}')
        return projected
    if type(value) in (list, tuple):
        return [_event_semantic_value(item, sha_execution_id=sha_execution_id,
                    context=f'{context}[{index}]')
                for index, item in enumerate(value)]
    return value


def _event_semantic_projection(run):
    """Project transaction observations only; owner and artifact identity stay out."""
    sha_execution_id = run['execution_ids']['sha']
    return {
        'schema_version': 'compiled_f6_event_semantic_projection.v1',
        'event_fields': list(_EVENT_PROJECTION_FIELDS),
        'normalization': {
            'transaction_key': {
                'schema': _TRANSACTION_TYPE_NAME,
                'field': 'execution_id',
                'replacement': '<transaction-execution>',
            },
            'caliptra_ahb_access_id': {
                'fields': ['access_id', 'target_access_id'],
                'format': 'caliptra-ahb:<32-lowercase-hex-session>:<positive-decimal-sequence>',
                'normalized_session': '<sha-session>',
            },
        },
        'events': {
            key: _event_semantic_value(run[key],
                sha_execution_id=sha_execution_id, context=key)
            for key in _EVENT_PROJECTION_FIELDS
        },
    }


def _contains_transaction_document(value, target):
    if type(value) is dict:
        if set(value) == _TRANSACTION_KEY_FIELDS:
            return value == target
        return any(_contains_transaction_document(item, target)
                   for item in value.values())
    if type(value) in (list, tuple):
        return any(_contains_transaction_document(item, target) for item in value)
    return False


def _close_positive_owners(owners):
    dma = owners['dma_session']
    sha = owners['sha_session']
    try:
        dma.close()
    finally:
        sha.end_case()


def _owner_identity_document(run, owners):
    sessions = {
        'cpu': owners['cpu_session'],
        'dma': owners['dma_session'],
        'sha': owners['sha_session'],
    }
    processes = {}
    if (owners['runner'].sessions.get('cpu') is not owners['cpu_session']
            or owners['runner'].sessions.get('dma') is not owners['dma_session']
            or owners['runner'].sessions.get('sha') is not owners['sha_session']):
        raise AssertionError('Runner does not retain the captured session objects')
    for name in ('dma', 'sha'):
        process = sessions[name].process
        if process is None or process.poll() is not None or process.pid is None:
            raise AssertionError(f'{name} native process is not live for owner comparison')
        if sessions[name]._execution != run['execution_ids'][name]:
            raise AssertionError(f'{name} live session execution ID changed')
        processes[name] = {'pid': process.pid, 'live': True}
    identity = {
        'python_objects': {
            name: {'id': id(value),
                   'type': type(value).__module__ + '.' + type(value).__qualname__}
            for name, value in (
                ('runner', owners['runner']),
                ('cpu_session', owners['cpu_session']),
                ('dma_session', owners['dma_session']),
                ('sha_session', owners['sha_session']),
                ('memory', owners['memory']),
                ('prepared_runtime_paths', owners['prepared_runtime_paths']),
                ('runtime_path', owners['runtime_path']),
                ('unbound_handoff', owners['unbound_handoff']),
                ('bound_runtime_path', owners['bound_runtime_path']),
                ('bound_handoff', owners['bound_handoff']),
            )
        },
        'native_processes': processes,
        'execution_ids': dict(run['execution_ids']),
    }
    return identity


def _assert_raw_artifacts_match(first, fresh, compiled_document_sha256):
    first_d4, fresh_d4 = first['d4_binding'], fresh['d4_binding']
    first_d3, fresh_d3 = first_d4['compiled_paths'], fresh_d4['compiled_paths']
    first_d3_digest = compiled_document_sha256(first_d3)
    fresh_d3_digest = compiled_document_sha256(fresh_d3)
    if (first_d3_digest != fresh_d3_digest
            or _canonical_document_bytes(first_d3)
                != _canonical_document_bytes(fresh_d3)):
        raise AssertionError('fresh D3 result differs before event projection')
    for document_key, digest_key, label in (
            ('compiled_f6_runtime_path', 'compiled_f6_runtime_path_sha256',
             'runtime path'),
            ('compiled_f6_handoff', 'compiled_f6_handoff_sha256',
             'unbound D4 handoff'),
            ('bound_wrapper', 'bound_handoff_sha256', 'bound wrapper')):
        if (_canonical_document_bytes(first_d4[document_key])
                != _canonical_document_bytes(fresh_d4[document_key])
                or first_d4[digest_key] != fresh_d4[digest_key]
                or first_d4[document_key]['identity_sha256']
                    != fresh_d4[document_key]['identity_sha256']):
            raise AssertionError(f'fresh {label} differs before event projection')
    for key in ('source', 'transfer_pair', 'd3_wiring'):
        if (_canonical_document_bytes(first_d4[key])
                != _canonical_document_bytes(fresh_d4[key])):
            raise AssertionError(f'fresh {key} differs before event projection')
    if first_d3_digest != first_d4['compiled_paths_sha256']:
        raise AssertionError('first D3 digest differs from its D4 handoff identity')
    if fresh_d3_digest != fresh_d4['compiled_paths_sha256']:
        raise AssertionError('fresh D3 digest differs from its D4 handoff identity')
    return {
        'schema_version': 'compiled_f6_fresh_artifact_comparison.v1',
        'raw_documents_equal_before_event_projection': True,
        'first': {
            'compiled_paths_sha256': first_d3_digest,
            'compiled_f6_runtime_path_sha256':
                first_d4['compiled_f6_runtime_path_sha256'],
            'compiled_f6_handoff_sha256': first_d4['compiled_f6_handoff_sha256'],
            'bound_handoff_sha256': first_d4['bound_handoff_sha256'],
        },
        'fresh': {
            'compiled_paths_sha256': fresh_d3_digest,
            'compiled_f6_runtime_path_sha256':
                fresh_d4['compiled_f6_runtime_path_sha256'],
            'compiled_f6_handoff_sha256': fresh_d4['compiled_f6_handoff_sha256'],
            'bound_handoff_sha256': fresh_d4['bound_handoff_sha256'],
        },
    }


def _assert_owner_distinctness(first, fresh, first_owners, fresh_owners):
    first_identity = _owner_identity_document(first, first_owners)
    fresh_identity = _owner_identity_document(fresh, fresh_owners)
    object_names = (
        'runner', 'cpu_session', 'dma_session', 'sha_session', 'memory',
        'prepared_runtime_paths', 'runtime_path', 'unbound_handoff',
        'bound_runtime_path', 'bound_handoff',
    )
    for name in object_names:
        if (first_identity['python_objects'][name]['id']
                == fresh_identity['python_objects'][name]['id']):
            raise AssertionError(f'fresh run reused the first {name} object')
    for identity, label in ((first_identity, 'first'), (fresh_identity, 'fresh')):
        object_ids = [identity['python_objects'][name]['id'] for name in object_names]
        if len(set(object_ids)) != len(object_ids):
            raise AssertionError(f'{label} run aliases distinct owner objects')
    process_pids = [identity['native_processes'][name]['pid']
                    for identity in (first_identity, fresh_identity)
                    for name in ('dma', 'sha')]
    if len(set(process_pids)) != len(process_pids):
        raise AssertionError('first/fresh native process PIDs are not distinct')
    execution_ids = [identity['execution_ids'][name]
                     for identity in (first_identity, fresh_identity)
                     for name in ('dma', 'sha')]
    if len(set(execution_ids)) != len(execution_ids):
        raise AssertionError('first/fresh native execution IDs are not distinct')
    return {
        'schema_version': 'compiled_f6_fresh_owner_distinctness.v1',
        'all_distinct_while_both_runs_live': True,
        'object_names': list(object_names),
        'first': first_identity,
        'fresh': fresh_identity,
        'native_process_pids_all_distinct': True,
        'native_execution_ids_all_distinct': True,
    }


class _ObservedCaliptraSha256DmaBeatAdmission(CaliptraSha256DmaBeatAdmission):
    """Record only completions accepted by the real Caliptra beat policy."""

    __slots__ = ('completion_receipts', 'completion_transaction_types')

    def begin_case(self, execution_id, testcase_id):
        super().begin_case(execution_id, testcase_id)
        self.completion_receipts = []
        self.completion_transaction_types = []

    def completed(self, key, *, rdata, error):
        super().completed(key, rdata=rdata, error=error)
        if type(key) is not TransactionKey:
            raise AssertionError('Caliptra beat completion did not retain a typed TransactionKey')
        self.completion_transaction_types.append(
            type(key).__module__ + '.' + type(key).__qualname__)
        self.completion_receipts.append({
            'transaction': asdict(key), 'rdata': rdata, 'error': error,
            'state_after': self.state,
        })


def _native_d3_wiring(tmp_path):
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        _generate_caliptra_sha256_dma_route_d2_d3)

    _d2_wiring, request, compiled = _generate_caliptra_sha256_dma_route_d2_d3(
        tmp_path / 'caliptra-d2-d3', ram_base=RAM_BASE, ram_size=RAM_SIZE,
        ram_executable=True)
    f6 = next(row for row in compiled['paths'] if row['flow_id'] == 'F6')
    if (f6['status'] != 'unsupported'
            or f6['reason']['code'] != 'dma-route-live-topology-binding-required'
            or f6['runtime_path_identity'] is not None
            or compiled['identity']['wiring']['dma_master_routes_sha256']
                != request.wiring.dma_master_routes_sha256):
        raise AssertionError('Caliptra D2/D3 fixture unexpectedly enabled F6')
    return request.wiring, compiled, tmp_path / 'caliptra-d2-d3' / \
        'caliptra_path_compile_request.json'


def _make_pair(cache_dir, d3_wiring, compiled_paths):
    from unittest.mock import patch

    from myfuzz.scenario.runtime_path_contract import PreparedRuntimePathContract
    from tests.integration.test_p7b_p7c_dma_route_intent import (
        CPU_PROFILE, _local_artifact)
    from tests.scenario.test_dma_intent_topology_binding import generated_instance

    memory = PersistentMemory(
        regions=(MemoryRegion('ram', RAM_BASE, RAM_SIZE),),
        initialization_seed=0x5a, max_initialized_bytes=RAM_SIZE)
    memory.preload(SOURCE_ADDRESS, SHA_CTRL_START_VALUE.to_bytes(4, 'little'))
    sha_artifact = _caliptra_artifact()
    sha = GeneratedAhbLiteRegisterSession(sha_artifact, base_dir=ROOT,
        cache_dir=cache_dir, command_timeout_seconds=30)
    issued = generated_instance('dma')
    dma = GeneratedWishboneDmaSession(issued.artifact,
        base_dir=ROOT, cache_dir=cache_dir, memory=memory,
        master_targets=(MasterTargetWindow('sha', SHA_BASE, SHA_SIZE, sha,
            (SHA_CTRL_OFFSET,), (SHA_CTRL_START_VALUE,)),),
        command_timeout_seconds=30)
    cpu = GeneratedLocalSession(_local_artifact(CPU_PROFILE, 'cpu'),
        base_dir=ROOT, cache_dir=cache_dir)
    cpu.memory = memory
    artifact_links = {'dma': issued.endpoint_links_document()}
    runner = SimpleNamespace(sessions={
        'cpu': cpu, 'dma': dma, 'sha': sha},
        ownership=SimpleNamespace(_bits={}), bindings=())
    source = DmaTransferSourceWord('cpu', 'ram', 'sha_ctrl_start',
                                   SOURCE_ADDRESS, 4, 15, 'CPU_TO_IP')
    pair = DmaTransferRoutePair('route.ram-read', 'route.caliptra-ctrl',
                                'same_word_value')
    runtime_path = prepare_compiled_f6_runtime_path(
        compiled_paths, d3_wiring, runner, source=source,
        transfer_pair=pair, artifact_links=artifact_links)
    prepared = runtime_path.prepared_runtime_paths
    graph, contract = prepared.graph, prepared.contract
    path, = graph.edge_paths_to('sha.ctrl_start_effect', direction='CPU_TO_IP')
    paths = CaliptraSha256DmaRuntimePaths(
        graph=graph, contract=contract, direction='CPU_TO_IP', path=path,
        path_id=prepared.path_ids[0], prepared=prepared, compiled=None,
        sha_base=SHA_BASE, sha_size=SHA_SIZE, memory_component='cpu',
        resource_id='ram', image_address=SOURCE_ADDRESS,
        image_id='sha_ctrl_start', admission=None,
        source_bindings=SourceBindings((SourceBinding(
            'ram.source_word', 'memory_image', 'cpu', 'sha_ctrl_start', 0,
            32, 'initial_image:cpu:sha_ctrl_start', SOURCE_ADDRESS),)),
        _target_window=dma.master_targets[0])
    bound_objects = []
    original_bind = PreparedRuntimePathContract.bind

    def bind_spy(prepared, *args, **kwargs):
        bound_objects.append(prepared)
        return original_bind(prepared, *args, **kwargs)

    with patch.object(PreparedRuntimePathContract, 'bind', bind_spy):
        bound_path = bind_compiled_f6_runtime_path(
            runtime_path, runner, artifact_links=artifact_links)
    bound_handoff = bound_path.bound_handoff
    prepared_refs = (
        runtime_path.prepared_runtime_paths,
        runtime_path.handoff._declaration._prepared_runtime_paths,
        bound_path.prepared_runtime_paths,
        bound_handoff._handoff._declaration._prepared_runtime_paths,
        paths.prepared,
    )
    same_prepared_object = (len(bound_objects) == 1
        and all(value is prepared_refs[0] for value in prepared_refs)
        and bound_objects[0] is prepared_refs[0])
    if not same_prepared_object:
        raise AssertionError('Caliptra D4 did not bind the exact prepared graph once')
    bound_handoff.validate_topology()
    policy = _ObservedCaliptraSha256DmaBeatAdmission(
        image_address=paths.image_address, window=paths._target_window)
    routes_by_key = {route.key: route for route in prepared.contract.dma_master_routes}
    route_links = {row['route_id']: row for row in
                   runtime_path.handoff.document()['declaration']['route_links']}
    read_key = (route_links[pair.read_route_id]['rule_index'],
                route_links[pair.read_route_id]['prerequisite_index'])
    write_key = (route_links[pair.write_route_id]['rule_index'],
                 route_links[pair.write_route_id]['prerequisite_index'])
    read_route, write_route = routes_by_key[read_key], routes_by_key[write_key]
    admission = DmaMasterRouteAdmission(policy, bound_handoff, path_id=paths.path_id,
        read_route=read_route, write_route=write_route)
    dma.configure_dma_route_admission(admission)
    paths = replace(paths, compiled=bound_handoff.topology_binding.runtime_compilation,
        admission=policy)
    compiled_f6_runtime_path = runtime_path.document()
    compiled_f6_handoff = runtime_path.handoff.document()
    bound_wrapper = bound_handoff.document()
    d4_evidence = {
        'compiled_paths': dict(compiled_paths),
        'compiled_paths_sha256': compiled_f6_handoff['compiled_paths_sha256'],
        'd3_wiring': d3_wiring.document,
        'source': runtime_path.source.document(),
        'transfer_pair': runtime_path.transfer_pair.document(),
        'compiled_f6_runtime_path': compiled_f6_runtime_path,
        'compiled_f6_runtime_path_sha256': runtime_path.identity_sha256,
        'compiled_f6_handoff': compiled_f6_handoff,
        'compiled_f6_handoff_sha256': runtime_path.handoff.identity_sha256,
        'bound_wrapper': bound_wrapper,
        'bound_handoff_sha256': bound_handoff.identity_sha256,
        'bind_count': len(bound_objects),
        'same_prepared_object': same_prepared_object,
        # Retain the previous field name used by existing gate evidence readers.
        'binding': bound_wrapper,
    }
    genome = ScenarioGenome(TESTCASE_ID, 'CPU_TO_IP', paths.path_id,
        ('cpu', 'dma', 'sha'), 1, (), initial_images=(MemoryImage(
            'sha_ctrl_start', 'cpu', SOURCE_ADDRESS,
            SHA_CTRL_START_VALUE.to_bytes(4, 'little').hex()),))
    paths.validate_source_genomes((genome,))
    owners = {
        'runner': runner,
        'cpu_session': cpu,
        'dma_session': dma,
        'sha_session': sha,
        'memory': memory,
        'runtime_path': runtime_path,
        'prepared_runtime_paths': runtime_path.prepared_runtime_paths,
        'unbound_handoff': runtime_path.handoff,
        'bound_runtime_path': bound_path,
        'bound_handoff': bound_handoff,
    }
    return dma, sha, memory, paths, sha_artifact, d4_evidence, owners


def _start_dma(dma, address):
    dma.write_register(8, SOURCE_ADDRESS)
    dma.write_register(12, address)
    dma.write_register(4, 1)
    dma.write_register(0, START_WORD)


def _save_run_artifacts(evidence, name, run):
    d4 = run['d4_binding']
    _save_json(evidence, name + '-run', run)
    for suffix, key in (
            ('d3-compiled-paths', 'compiled_paths'),
            ('d3-wiring', 'd3_wiring'),
            ('source', 'source'),
            ('transfer-pair', 'transfer_pair'),
            ('compiled-f6-runtime-path', 'compiled_f6_runtime_path'),
            ('compiled-f6-unbound-handoff', 'compiled_f6_handoff'),
            ('compiled-f6-bound-wrapper', 'bound_wrapper')):
        _save_json(evidence, name + '-' + suffix, d4[key])
    _save_json(evidence, name + '-artifact-identities', {
        'schema_version': 'compiled_f6_run_artifact_identities.v1',
        'compiled_paths_sha256': d4['compiled_paths_sha256'],
        'compiled_f6_runtime_path_sha256':
            d4['compiled_f6_runtime_path_sha256'],
        'compiled_f6_handoff_sha256': d4['compiled_f6_handoff_sha256'],
        'bound_handoff_sha256': d4['bound_handoff_sha256'],
        'bind_count': d4['bind_count'],
        'same_prepared_object': d4['same_prepared_object'],
    })


def _run_unselected_destination(cache_dir, d3_wiring, compiled_paths):
    dma, sha, _memory, paths, _artifact, d4_evidence, _owners = _make_pair(
        cache_dir, d3_wiring, compiled_paths)
    native_step_samples = []
    original_command = dma.command

    def capture_native_pre(operation, fields):
        receipt = original_command(operation, fields)
        if operation == 'STEP_WB_DMA':
            native_step_samples.append({
                'operation': operation,
                'fields': list(fields),
                'status': receipt.status,
                'execution': receipt.execution,
                'sequence': receipt.sequence,
                'tick_before': receipt.tick_before,
                'tick_after': receipt.tick_after,
                'new_ticks': receipt.new_ticks,
                'source_sequence_before_acceptance': dma._source_sequence,
                'pre_backend': dict(receipt.payload['pre_backend']),
            })
        return receipt

    dma.command = capture_native_pre
    testcase_id = TESTCASE_ID + '-unselected-address'
    try:
        sha.begin_case(testcase_id)
        dma.begin_case(testcase_id)
        for index in range(16):
            value = int.from_bytes(
                (b'abc\x80' if index == 0 else (24).to_bytes(4, 'big')
                 if index == 15 else bytes(4)), 'big')
            sha.write_register(0x80 + index * 4, value)
        status_before = sha.read_register(0x18)
        ticks_before = sha.local_ticks
        _start_dma(dma, SHA_START_ADDRESS + 4)

        refusal = None
        for _ in range(4000):
            try:
                dma.step_local()
            except ValueError as error:
                refusal = str(error)
                break
        if refusal is None:
            raise AssertionError('native DMA request outside selected CTRL route was not refused')
        if refusal != 'DMA route match does not exactly match the selected route':
            raise AssertionError(f'unexpected D4 refusal: {refusal}')
        attempted = [row for row in native_step_samples
            if row['pre_backend'].get('mwb_cyc') == 1
            and row['pre_backend'].get('mwb_stb') == 1
            and row['pre_backend'].get('mwb_we') == 1
            and (row['pre_backend'].get('mwb_adr', -1) << 2)
                == SHA_START_ADDRESS + 4]
        if len(attempted) != 1:
            raise AssertionError('unselected native Wishbone request was not uniquely observed')
        attempted = attempted[0]
        pre = attempted['pre_backend']
        if (attempted['operation'] != 'STEP_WB_DMA'
                or attempted['status'] != 'result'
                or attempted['new_ticks'] != 1
                or pre.get('mwb_dat_w') != SHA_CTRL_START_VALUE
                or pre.get('mwb_cyc') != 1 or pre.get('mwb_stb') != 1
                or pre.get('mwb_we') != 1):
            raise AssertionError('unselected native Wishbone request payload was not exact')
        transaction = TransactionKey(dma._execution, testcase_id,
            dma.source_component, dma.reset_epoch, 'dma-memory',
            attempted['source_sequence_before_acceptance'] + 1)
        rejected_key = asdict(transaction)
        if transaction.source_sequence != dma._source_sequence:
            raise AssertionError('captured native write did not identify the rejected key')
        rejected_memory_effects = [event for event in dma.memory_service.events
            if _contains_transaction_document(event, rejected_key)]
        rejected_ledger_entry = transaction in dma.memory_service.ledger._entries
        if (type(rejected_memory_effects) is not list
                or any(type(event) is not dict
                    or not _contains_transaction_document(event, rejected_key)
                    for event in rejected_memory_effects)
                or type(rejected_ledger_entry) is not bool):
            raise AssertionError('rejected CTRL+4 memory effect evidence is malformed')
        if rejected_memory_effects or rejected_ledger_entry:
            raise AssertionError('rejected CTRL+4 write changed the DMA memory service')
        route_matches = dma._dma_route_admission.route_matches
        completions = paths.admission.completion_receipts
        read_matches = [row for row in route_matches
            if tuple(row['edge_key']) == (0, 0)]
        memory_reads = [event for event in dma.memory_service.events
            if event.get('kind') == 'memory_read']
        responses = [event['response'] for event in dma.events
            if type(event.get('response')) is dict]
        if (dma._dma_route_admission.state != 'expect_write'
                or len(route_matches) != 1 or len(read_matches) != 1
                or len(completions) != 1
                or completions[0]['transaction'] != read_matches[0]['transaction']
                or completions[0]['rdata'] != SHA_CTRL_START_VALUE
                or completions[0]['error'] != 0
                or len(memory_reads) != 1
                or memory_reads[0]['transaction'] != read_matches[0]['transaction']
                or len(responses) != 1
                or responses[0]['transaction'] != read_matches[0]['transaction']
                or responses[0]['rdata'] != SHA_CTRL_START_VALUE
                or responses[0]['error'] != 0):
            raise AssertionError('D4 refusal did not retain only the completed RAM read')
        provider_events = list(sha._dma_target_events)
        rejected_runtime_effects = {
            'dma_events': [event for event in dma.events
                if _contains_transaction_document(event, rejected_key)],
            'route_matches': [row for row in route_matches
                if _contains_transaction_document(row, rejected_key)],
            'policy_completions': [row for row in completions
                if _contains_transaction_document(row, rejected_key)],
            'provider_events': [event for event in provider_events
                if _contains_transaction_document(event, rejected_key)],
        }
        expected_effect_lists = {
            'dma_events', 'route_matches', 'policy_completions', 'provider_events'}
        if (type(rejected_runtime_effects) is not dict
                or set(rejected_runtime_effects) != expected_effect_lists
                or any(type(rows) is not list for rows in
                    rejected_runtime_effects.values())):
            raise AssertionError('rejected CTRL+4 runtime effect evidence is malformed')
        if any(rejected_runtime_effects.values()):
            raise AssertionError('rejected CTRL+4 key appeared in runtime effect evidence')
        if sha.local_ticks != ticks_before or provider_events:
            raise AssertionError('refused DMA route reached the Caliptra AHB target')
        return {
            'schema_version': 'caliptra_dma_unselected_target_refusal.v1',
            'testcase_id': testcase_id,
            'native_request_observed': True,
            'native_address': SHA_START_ADDRESS + 4,
            'selected_address': SHA_START_ADDRESS,
            'refusal': refusal,
            'provider_receipt_count': len(provider_events),
            'provider_events': provider_events,
            'rejected_key_effects': {
                'schema_version': 'caliptra_dma_rejected_key_effects.v1',
                'sampled_after_refusal': True,
                'memory_service_events': rejected_memory_effects,
                'memory_ledger_entry': rejected_ledger_entry,
                **rejected_runtime_effects,
            },
            'ahb_local_ticks_before': ticks_before,
            'ahb_local_ticks_after': sha.local_ticks,
            'sha_status_before': status_before,
            'route_admission_state': dma._dma_route_admission.state,
            'route_matches': route_matches,
            'policy_completions': list(completions),
            'typed_transaction_evidence': {
                'transaction_type': _TRANSACTION_TYPE_NAME,
                'completed_types': list(paths.admission.completion_transaction_types),
            },
            'ram_read': memory_reads[0],
            'dma_responses': responses,
            'rejected_transaction': rejected_key,
            'rejected_memory_effects': rejected_memory_effects,
            'd4_binding': d4_evidence,
            'attempted_native_request': {
                **attempted,
                'transaction': rejected_key,
            },
            'scope': 'native DMA request refused before the Caliptra AHB provider command',
        }
    finally:
        try:
            dma.close()
        finally:
            sha.end_case()


def _run_one(cache_dir, d3_wiring, compiled_paths, *, keep_alive=False):
    dma, sha, memory, paths, sha_artifact, d4_evidence, owners = _make_pair(
        cache_dir, d3_wiring, compiled_paths)
    retained = False
    try:
        sha.begin_case(TESTCASE_ID)
        dma.begin_case(TESTCASE_ID)

        # Prepare the pinned padded "abc" input through ordinary AHB accesses.
        # The DMA's one RAM word is the real CTRL start write that launches it.
        block = [int.from_bytes(b'abc\x80', 'big')] + [0] * 14 + [24]
        for index, value in enumerate(block):
            sha.write_register(0x80 + index * 4, value)
        _start_dma(dma, SHA_START_ADDRESS)

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
            raise TimeoutError('real DMA-to-Caliptra CTRL start exceeded 4000 edges')

        beats = [event for event in dma.events
                 if type(event.get('accepted')) is dict]
        if len(beats) != 2:
            raise AssertionError(f'expected one RAM read and one CTRL write, got {len(beats)} beats')
        read_event = next(event for event in beats
                          if not event['accepted']['write'])
        write_event = next(event for event in beats
                           if event['accepted']['write'])
        read_key = read_event['accepted']['transaction']
        write_key = write_event['accepted']['transaction']
        read_transaction = _checked_transaction_key(
            read_key, context='RAM read transaction')
        write_transaction = _checked_transaction_key(
            write_key, context='Caliptra CTRL write transaction')
        if (read_transaction.testcase_id != TESTCASE_ID
                or write_transaction.testcase_id != TESTCASE_ID
                or read_transaction.channel_id != 'dma-memory'
                or write_transaction.channel_id != 'dma-memory'
                or read_transaction.execution_id != dma._execution
                or write_transaction.execution_id != dma._execution):
            raise AssertionError('native DMA transactions do not match their live session')
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
                or memory_reads[0].get('value') != SHA_CTRL_START_VALUE
                or read_event['accepted']['address'] != SOURCE_ADDRESS
                or read_response is None
                or read_response.get('rdata') != SHA_CTRL_START_VALUE
                or read_response.get('error') != 0
                or write_event['accepted']['address'] != SHA_START_ADDRESS
                or write_event['accepted']['value'] != SHA_CTRL_START_VALUE
                or write_event['accepted']['byte_enable'] != 15
                or write_response is None or write_response.get('error') != 0):
            raise AssertionError('DMA RAM value did not reach the declared Caliptra CTRL word')
        target_delivery = write_event.get('target_delivery')
        provider_receipt = (target_delivery.get('target_provider_receipt')
            if type(target_delivery) is dict else None)
        if (type(provider_receipt) is not dict
                or provider_receipt.get('target_effect', {}).get('physical_write_data')
                    != SHA_CTRL_START_VALUE):
            raise AssertionError('Caliptra DMA provider lacks its joined AHB effect')

        route_matches = dma._dma_route_admission.route_matches
        completions = list(paths.admission.completion_receipts)
        if (len(route_matches) != 2 or len(completions) != 2
                or {tuple(row['edge_key']) for row in route_matches}
                    != {(0, 0), (2, 0)}):
            raise AssertionError('native DMA did not consume both D4 routes')
        matches = {tuple(row['edge_key']): row for row in route_matches}
        read_match, write_match = matches[(0, 0)], matches[(2, 0)]
        if (read_match['transaction'] != read_key
                or read_match['operation'] != 'read'
                or read_match['address'] != SOURCE_ADDRESS
                or write_match['transaction'] != write_key
                or write_match['operation'] != 'write'
                or write_match['address'] != SHA_START_ADDRESS
                or read_key == write_key
                or {json.dumps(row['transaction'], sort_keys=True)
                    for row in route_matches}
                    != {json.dumps(row['accepted']['transaction'], sort_keys=True)
                        for row in beats}):
            raise AssertionError('D4 route matches lack exact native beat identities')
        read_completion, write_completion = completions
        completion_types = list(paths.admission.completion_transaction_types)
        if (read_completion != {'transaction': read_key,
                    'rdata': SHA_CTRL_START_VALUE, 'error': 0,
                    'state_after': 'expect_write'}
                or write_completion != {'transaction': write_key,
                    'rdata': 0, 'error': 0, 'state_after': 'complete'}
                or completion_types != [_TRANSACTION_TYPE_NAME,
                    _TRANSACTION_TYPE_NAME]
                or memory_reads[0]['transaction'] != read_key
                or read_response['transaction'] != read_key
                or write_response['transaction'] != write_key):
            raise AssertionError('Caliptra policy and native responses lack keyed completions')
        ahb_request = provider_receipt.get('target_request', {})
        ahb_response = provider_receipt.get('target_response', {})
        effect = provider_receipt['target_effect']
        if (len(sha._dma_target_events) != 1
                or sha._dma_target_events[0] != provider_receipt
                or target_delivery.get('source_transaction') != write_key
                or provider_receipt.get('source_transaction') != write_key
                or provider_receipt.get('request') != {
                    'address': SHA_START_ADDRESS, 'offset': SHA_CTRL_OFFSET,
                    'value': SHA_CTRL_START_VALUE, 'write': True,
                    'byte_enable': 15}
                or provider_receipt.get('response') != {'rdata': 0, 'error': 0}
                or ahb_request.get('source_transaction') != write_key
                or ahb_request.get('backend', {}).get('hwdata')
                    != SHA_CTRL_START_VALUE
                or ahb_request.get('backend', {}).get('hwrite') != 1
                or ahb_response.get('source_transaction') != write_key
                or ahb_response.get('error') != 0
                or effect.get('source_transaction') != write_key
                or effect.get('physical_write_data') != SHA_CTRL_START_VALUE):
            raise AssertionError('D4 CTRL route lacks matching AHB provider effect')
        if (d4_evidence['bind_count'] != 1
                or d4_evidence['same_prepared_object'] is not True):
            raise AssertionError('Caliptra D4 binding did not use the prepared object once')

        for _ in range(128):
            status = sha.read_register(0x18)
            if status & 2:
                break
        else:
            raise AssertionError('Caliptra SHA256 did not report VALID after DMA CTRL start')
        digest = b''.join(sha.read_register(0x100 + index * 4).to_bytes(4, 'big')
                          for index in range(8))
        expected = hashlib.sha256(b'abc').digest()
        if digest != expected:
            raise AssertionError('Caliptra SHA256 digest differs from known answer')

        result = {
            'execution_ids': {
                'dma': dma._execution, 'sha': sha._execution,
                'testcase_id': TESTCASE_ID,
            },
            'path': paths.document(),
            'd4_binding': d4_evidence,
            'route_admission_identity': dma._dma_route_admission.identity_document(),
            'route_matches': route_matches,
            'policy_completions': completions,
            'typed_transaction_evidence': {
                'schema_version': 'compiled_f6_typed_transaction_evidence.v1',
                'transaction_type': _TRANSACTION_TYPE_NAME,
                'completions': [
                    {'operation': 'ram_word_read',
                     'transaction': asdict(read_transaction),
                     'type': completion_types[0],
                     'value': memory_reads[0]['value']},
                    {'operation': 'caliptra_ctrl_write',
                     'transaction': asdict(write_transaction),
                     'type': completion_types[1],
                     'value': write_event['accepted']['value']},
                ],
            },
            'dma_identity': dma.identity_document(),
            'sha_identity': sha.identity_document(),
            'sha_artifact_digest': sha_artifact.runtime_document['artifact_digest'],
            'ram_read': memory_reads[0],
            'dma_beats': beats,
            'dma_responses': [read_response, write_response],
            'provider_receipts': list(sha._dma_target_events),
            'sha_status': status,
            'sha_digest': digest.hex(),
            'sha_expected_digest': expected.hex(),
            'admission_state': dma._dma_route_admission.state,
        }
        if keep_alive:
            retained = True
            return result, owners
        return result
    finally:
        if not retained:
            _close_positive_owners(owners)


@pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_CALIPTRA_REAL') != '1',
    reason='explicit real Caliptra DMA gate')
def test_real_dma_ctrl_start_matches_caliptra_sha256_and_fresh_replay(tmp_path):
    cache, evidence = _settings(tmp_path)
    from myfuzz.scenario.compiled_paths import (
        compile_paths, compiled_document_sha256, load_path_compile_request)
    evidence.mkdir(parents=True, exist_ok=True)
    first_owners = fresh_owners = None
    try:
        d3_wiring, compiled_paths, compile_request_path = _native_d3_wiring(
            evidence / 'd3-first')
        first, first_owners = _run_one(
            cache, d3_wiring, compiled_paths, keep_alive=True)
        refusal = _run_unselected_destination(cache, d3_wiring, compiled_paths)

        fresh_request = load_path_compile_request(compile_request_path, base_dir=ROOT)
        fresh_compiled_paths = compile_paths(fresh_request)
        if (fresh_compiled_paths is compiled_paths
                or compiled_document_sha256(fresh_compiled_paths)
                    != compiled_document_sha256(compiled_paths)):
            raise AssertionError(
                'fresh D3 compilation differs from the original request result')
        fresh = None
        fresh, fresh_owners = _run_one(
            cache, fresh_request.wiring, fresh_compiled_paths, keep_alive=True)

        raw_artifact_comparison = _assert_raw_artifacts_match(
            first, fresh, compiled_document_sha256)
        owner_distinctness = _assert_owner_distinctness(
            first, fresh, first_owners, fresh_owners)
        first_projection = _event_semantic_projection(first)
        fresh_projection = _event_semantic_projection(fresh)
        if first_projection != fresh_projection:
            raise AssertionError(
                'fresh event-only semantic projection differs from first run')
        if (first['sha_digest'] != hashlib.sha256(b'abc').hexdigest()
                or fresh['sha_digest'] != first['sha_digest']):
            raise AssertionError('Caliptra SHA256 abc known answer differs')
        if (refusal['provider_receipt_count'] != 0
                or refusal['provider_events'] != []
                or refusal['attempted_native_request']['pre_backend'].get('mwb_dat_w')
                    != SHA_CTRL_START_VALUE
                or refusal['ahb_local_ticks_before']
                    != refusal['ahb_local_ticks_after']
                or refusal['rejected_key_effects']['memory_service_events']
                or refusal['rejected_key_effects']['memory_ledger_entry']
                or any(refusal['rejected_key_effects'][key]
                    for key in ('dma_events', 'route_matches',
                                'policy_completions', 'provider_events'))):
            raise AssertionError(
                'CTRL+4 refusal reached a provider or caused a rejected-key effect')
        if (refusal['d4_binding']['bind_count'] != 1
                or refusal['d4_binding']['same_prepared_object'] is not True):
            raise AssertionError('CTRL+4 refusal did not perform one exact D4 bind')

        _save_json(evidence, 'compile-request', json.loads(
            compile_request_path.read_text(encoding='utf-8')))
        _save_json(evidence, 'fresh-compile-request', json.loads(
            compile_request_path.read_text(encoding='utf-8')))
        _save_compile_inputs(evidence, compile_request_path)
        _save_run_artifacts(evidence, 'first', first)
        _save_run_artifacts(evidence, 'fresh', fresh)
        _save_json(evidence, 'fresh-artifact-comparison', raw_artifact_comparison)
        _save_json(evidence, 'owner-distinctness', owner_distinctness)
        _save_json(evidence, 'first-event-semantic-projection', first_projection)
        _save_json(evidence, 'fresh-event-semantic-projection', fresh_projection)
        _save_json(evidence, 'fresh-event-semantic-comparison', {
            'schema_version': 'compiled_f6_event_semantic_comparison.v1',
            'equal': True,
            'compared_event_fields': list(_EVENT_PROJECTION_FIELDS),
            'owner_identity_comparison_file': 'owner-distinctness.json.gz',
            'raw_artifact_comparison_file': 'fresh-artifact-comparison.json.gz',
        })
        _save_json(evidence, 'native-refusal', refusal)
    finally:
        if fresh_owners is not None:
            _close_positive_owners(fresh_owners)
        if first_owners is not None:
            _close_positive_owners(first_owners)
