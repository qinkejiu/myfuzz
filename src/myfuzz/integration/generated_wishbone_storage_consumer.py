"""Consume the actual compiled-F4 Wishbone storage chain for the G8.1 row.

The chain is: CPU data acceptance -> Router delivery -> native Wishbone
pre/post sample (registered ACK, CYC held, ``stall == 0``, ``sel == 15`` for the
write) -> ``WishboneStorageRegisterVersionAuthority.consume`` opaque token ->
CPU readback/RAM.  A caller document, a serialized write record, a readback or
the current register value is never a substitute for that token.

The token is single-use and owned by the process-local issuer.  Until a native
Wishbone producer hook exists the issuer refuses before any token lookup, so
this module cannot manufacture a positive: the pure controls only exercise the
event/journal join and always fail closed at the token boundary.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import inspect
import json
import re
from pathlib import Path

from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.local_harness.wishbone_storage_probe_contract import (
    AUTHORITY_FLAGS, ROLES, SAMPLE_GROUP, SCHEMA_VERSION, SCOPE, SELECTION_KEYS,
    wishbone_probe_widths)
from myfuzz.local_harness.wishbone_storage_probe_verification import (
    verified_wishbone_storage_observation)
from myfuzz.local_harness.wishbone_storage_source_contract import (
    validate_wishbone_storage_source_contract, wishbone_setup_matches,
    wishbone_word_index)
from myfuzz.scenario.wishbone_storage_register_version import (
    HISTORY_SCOPE, WISHBONE_STORAGE_CONTEXT_KEYS,
    WISHBONE_STORAGE_VERSION_SCHEMA, WITNESS_KEYS,
    WishboneStorageRegisterVersionAuthority, wishbone_storage_version_basis,
    validate_routed_context)

CONSUMER_QUALNAME = ('myfuzz.integration.generated_wishbone_storage_consumer.'
                     'check_wishbone_storage_observation')
SUPPORT_SCHEMA = 'compiled_F4_wishbone_storage_consumer_support.v1'
OBSERVATION_SCHEMA = 'compiled_F4_wishbone_storage_observation.v1'
VERSION_SCHEMA = WISHBONE_STORAGE_VERSION_SCHEMA
COMMIT_SCHEMA = 'wishbone_storage_commit.v1'
TOKEN_SCHEMA = 'wishbone_storage_register_version_token.v1'
ROW_GENERIC_WISHBONE_STORAGE = 'generic_wishbone_storage_abi'
RECEIPT_ELEMENTS = ('cpu_acceptance', 'router_delivery',
                    'native_wishbone_pre_sample', 'version_token')
ELEMENT_BASIS = {
    'cpu_acceptance':
        'in-row consumer joins the actual CPU data acceptance',
    'router_delivery':
        'typed TransactionKey/address/offset/byte_enable/device is joined to '
        'the actual Router delivery',
    'native_wishbone_pre_sample':
        'native Wishbone pre/ACK storage_probes with word-index ADR, '
        'registered ACK, CYC held, stall=0 and reset levels',
    'version_token':
        'opaque single-use WishboneStorageRegisterVersionAuthority token '
        'consumed in-process',
}
TRACE_ROLES = frozenset(ROLES)
FULL_MASK = 0xffffffff
CONTEXT_KEYS = frozenset(WISHBONE_STORAGE_CONTEXT_KEYS)
TRANSACTION_KEYS = frozenset({
    'execution_id', 'testcase_id', 'source_component', 'source_epoch',
    'channel_id', 'source_sequence'})
COMMIT_KEYS = frozenset({
    'tick', 'raw_address', 'before', 'after', 'sample_index', 'phase',
    'command_sequence', 'context', 'raw_reference'})
RAW_REFERENCE_KEYS = frozenset({
    'execution', 'sequence', 'sample_index', 'phase'})
STABLE_VERSION_KEYS = (
    'register', 'reset_epoch', 'value', 'local_tick', 'command_sequence',
    'field_version', 'write_count', 'artifact_digest', 'source_contract_digest',
    'probe_digest', 'version_basis', 'history_scope',
    'reset_waveform_observed', 'grants_reset_prerequisite',
    'routed_context_authenticated')
READ_SELECTS = (0, 15)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def _digest(value):
    return sha256(_canonical(value).encode()).hexdigest()


def _hex64(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _qualified(value):
    return value.__module__ + '.' + value.__qualname__


def _digest_source(value):
    try:
        path = inspect.getsourcefile(value)
        if path is None:
            raise OSError('no source file')
        return sha256(Path(path).read_bytes()).hexdigest()
    except (OSError, TypeError) as error:
        raise ValueError(
            'compiled-F4-wishbone-storage-source-identity-unavailable'
        ) from error


def stable_wishbone_storage_version(witness):
    """Stable certificate projection: volatile process fields stay in evidence.

    PID, driver execution nonce, build identity and the write-history digest
    include process-local values or opaque receipt references.  They are
    validated against the live witness but cannot enter a fresh-prefix
    comparison; every declared version fact is retained here.
    """
    if not isinstance(witness, dict) or set(witness) != WITNESS_KEYS:
        raise ValueError('compiled-F4-wishbone-storage-witness-shape')
    document = {key: deepcopy(witness[key]) for key in STABLE_VERSION_KEYS}
    document['schema_version'] = VERSION_SCHEMA
    document['certificate_projection'] = (
        'stable_fields_only_process_fields_validated_live')
    return document


def _single_endpoint(target_artifact):
    endpoints = [endpoint for endpoint in target_artifact.plan.binding.endpoints
                 if endpoint.protocol is not None]
    if (len(endpoints) != 1
            or tuple(endpoints[0].protocol) != ('wishbone', 'classic')
            or endpoints[0].function != 'mmio_slave'):
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch')
    return endpoints[0]


def _check_observation(observation, target_artifact, *, register, base_dir):
    """Validate the probe document, contract, endpoint and Wishbone trace."""
    if (not isinstance(observation, dict)
            or observation.get('schema_version') != SCHEMA_VERSION
            or observation.get('scope') != SCOPE
            or observation.get('sample_group') != SAMPLE_GROUP
            or any(observation.get(key) is not False
                   for key in AUTHORITY_FLAGS)):
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch')
    try:
        contract = validate_wishbone_storage_source_contract(
            observation.get('source_contract'), target_artifact.plan.profile,
            base_dir=base_dir)
    except ValueError as error:
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch'
        ) from error
    if (contract.get('scope') != 'source_reviewed_wishbone_storage_row'
            or any(contract.get(key) is not False for key in (
                'authority', 'source_authority', 'native_verified',
                'hierarchy_verified', 'reset_authority', 'version_authority'))
            or not isinstance(contract.get('register'), dict)
            or contract['register'].get('name') != register
            or contract['register'].get('width') != 32
            or contract['register'].get('write_mask') != 0x7fffffff
            or not isinstance(contract.get('decode'), dict)
            or contract['decode'].get('address_units') != 'word'
            or contract['decode'].get('host_alignment_bytes') != 4):
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch')
    widths = wishbone_probe_widths(contract)
    ports = observation.get('ports')
    if (not isinstance(ports, list) or len(ports) != len(widths)
            or any(not isinstance(row, dict) or row.get('name') not in widths
                   or row.get('width') != widths[row['name']]
                   or row.get('direction') != 'output' for row in ports)
            or {row['name'] for row in ports} != set(widths)):
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch')
    try:
        # Prospective (false) observations pass with no evidence.  A flag flip
        # or a tampered digest/port/contract/trace is refused here.
        verified_wishbone_storage_observation(
            observation, target_artifact, base_dir=base_dir)
    except ValueError as error:
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch'
        ) from error
    endpoint = _single_endpoint(target_artifact)
    selection = observation.get('selection')
    if (not isinstance(selection, dict) or set(selection) != SELECTION_KEYS
            or selection.get('endpoint_id') != endpoint.endpoint_id
            or selection.get('contract_id') != contract['contract_id']
            or selection.get('register') != contract['register']['name']):
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch')
    trace = target_artifact.runtime_document.get('base_protocol_trace')
    signals = trace.get('signals') if isinstance(trace, dict) else None
    if (not isinstance(trace, dict) or trace.get('protocol') != 'wishbone'
            or trace.get('endpoint_id') != endpoint.endpoint_id
            or not isinstance(signals, dict) or set(signals) != set(TRACE_ROLES)
            or 'err' in signals
            or (trace.get('signal_widths') or {}) != {
                role: widths['storage_' + role] for role in ROLES}):
        raise ValueError(
            'compiled-F4-wishbone-storage-observation-contract-mismatch')
    return contract, signals, widths


def _check_declaration(declaration, *, target_artifact, register, contract):
    if (not isinstance(declaration, dict)
            or declaration.get('schema_version')
            != 'generated_register_writer.v1'):
        raise ValueError('compiled-F4-wishbone-storage-declaration-required')
    candidate = declaration.get('candidate')
    access = candidate.get('access') if isinstance(candidate, dict) else None
    value = candidate.get('value') if isinstance(candidate, dict) else None
    result = declaration.get('result_address')
    if (not isinstance(access, dict) or type(value) is not int
            or type(result) is not int or result % 4
            or not 0 <= result <= 0xfffffffc):
        raise ValueError('compiled-F4-wishbone-storage-declaration-required')
    window_base = access.get('window_base')
    window = access.get('window_size')
    offset = access.get('register_offset')
    word_index = access.get('word_index')
    if (type(window_base) is not int or not 0 <= window_base < 1 << 32
            or type(window) is not int or not 4 <= window <= 4096
            or window % 4 or window_base + window > 1 << 32
            or type(offset) is not int or not 0 <= offset < window
            or offset % 4
            or type(word_index) is not int):
        raise ValueError('compiled-F4-wishbone-storage-declaration-geometry')
    if (access.get('register') != register
            or access.get('operation') != 'write'
            or access.get('value_origin') != 'cpu_transaction_wdata'
            or access.get('register_origin') != 'bound_target_register_commit'
            or access.get('width_bytes') != contract['register']['width'] // 8
            or access.get('allowed_byte_enables') != [15]
            or access.get('byte_enable_domain') != 'target_word_lanes'
            or access.get('access_alignment') != 4
            or access.get('value_mask') != contract['register']['write_mask']
            or not 0 <= value <= contract['register']['write_mask']
            or wishbone_setup_matches(contract, offset) is not True
            or word_index != wishbone_word_index(offset)
            or word_index != contract['register']['word_index']
            or access.get('address') != window_base + offset
            or type(access.get('source_component')) is not str
            or type(access.get('target_component')) is not str
            or type(access.get('device_id')) is not str
            or access.get('device_id') != access.get('target_component')
            or type(access.get('source_endpoint')) is not str):
        raise ValueError('compiled-F4-wishbone-storage-declaration-geometry')
    if target_artifact.plan.request.instance_id != access['target_component']:
        raise ValueError('compiled-F4-wishbone-storage-target-instance-mismatch')
    return access, value, word_index


def _check_before(before, *, prior_writes, register):
    if not isinstance(before, dict) or set(before) != WITNESS_KEYS:
        raise ValueError('compiled-F4-wishbone-storage-before-witness-required')
    if (any(type(before[key]) is not int or before[key] < 0 for key in
            ('value', 'local_tick', 'field_version', 'write_count',
             'reset_epoch', 'command_sequence', 'pid'))
            or before['value'] > FULL_MASK
            or before['write_count'] != prior_writes
            or before['field_version'] != prior_writes
            or before['register'] != register
            or not _hex64(before['write_history_sha256'])
            or not _hex64(before['build_identity_sha256'])
            or not _hex64(before['producer_source_sha256'])
            or not _hex64(before['artifact_digest'])
            or not _hex64(before['source_contract_digest'])
            or not _hex64(before['probe_digest'])
            or type(before['execution']) is not str
            or before['version_basis'] != wishbone_storage_version_basis(register)
            or before['history_scope'] != HISTORY_SCOPE
            or type(before['reset_waveform_observed']) is not bool
            or before['grants_reset_prerequisite'] is not False
            or before['routed_context_authenticated'] is not False):
        raise ValueError('compiled-F4-wishbone-storage-before-witness-required')


def _join_delivery(events, *, delivery, component, device, address, offset,
                   write):
    if (delivery.get('device_id') != device
            or delivery.get('address') != address
            or delivery.get('offset') != offset
            or delivery.get('write') is not write
            or delivery.get('byte_enable') != 15):
        raise ValueError('compiled-F4-wishbone-storage-delivery-geometry')
    accepted = [event for event in events
                if event.get('kind') == 'mmio_acceptance'
                and event.get('component') == component
                and event.get('source_transaction')
                == delivery.get('source_transaction')
                and event.get('address') == address
                and event.get('write') is write
                and event.get('event_id', 0) < delivery.get('event_id', 0)]
    if len(accepted) != 1:
        raise ValueError('compiled-F4-wishbone-storage-CPU-acceptance-join')
    transaction = delivery.get('source_transaction')
    if (not isinstance(transaction, dict) or set(transaction) != TRANSACTION_KEYS
            or any(type(transaction[key]) is not str or not transaction[key]
                   for key in ('execution_id', 'testcase_id',
                               'source_component', 'channel_id'))
            or any(type(transaction[key]) is not int or transaction[key] < 0
                   for key in ('source_epoch', 'source_sequence'))
            or transaction['channel_id'] != 'data'
            or transaction['source_epoch'] != 0):
        raise ValueError('compiled-F4-wishbone-storage-transaction-shape')
    return accepted[0]


@dataclass(frozen=True, slots=True)
class _Transfer:
    pre: dict
    post: dict
    ack: dict
    probes_pre: dict
    probes_post: dict
    probes_ack: dict


def _accept_probes(observed, widths, phase):
    if not isinstance(observed, dict) or set(observed) != set(widths):
        raise ValueError(
            f'compiled-F4-wishbone-storage-{phase}-sample-missing')
    for name, width in widths.items():
        if (type(observed[name]) is not int
                or not 0 <= observed[name] < 1 << width):
            raise ValueError(
                'compiled-F4-wishbone-storage-storage-probe-width')
    return observed


def _check_trace(observed, backend, signals, widths, *, phase):
    if not isinstance(backend, dict):
        raise ValueError(
            f'compiled-F4-wishbone-storage-{phase}-sample-mismatch')
    for role in ROLES:
        name = 'storage_' + role
        value = backend.get(signals[role])
        if (type(value) is not int or not 0 <= value < 1 << widths[name]):
            raise ValueError(
                f'compiled-F4-wishbone-storage-{phase}-sample-mismatch')
        if observed[name] != value:
            raise ValueError(
                'compiled-F4-wishbone-storage-storage-probe-trace-mismatch')


def _sample_row(event, *, component, reset_epoch, phase, widths):
    """Structural acceptance of one observed tick phase; never trusted alone."""
    if (event.get('phase') not in ('pre', 'post')
            or event.get('phase') != phase
            or event.get('kind') != 'local_tick_sample'
            or event.get('component') != component
            or event.get('reset_epoch') != reset_epoch
            or type(event.get('local_tick')) is not int
            or event['local_tick'] < 1
            or type(event.get('event_id')) is not int
            or event['event_id'] < 1
            or event.get('observation_schema_version') != 'ip_raw_observation.v1'
            or not isinstance(event.get('outputs'), dict)
            or not isinstance(event['outputs'].get('backend'), dict)
            or not isinstance(event['outputs'].get('storage_probes'), dict)):
        raise ValueError(
            f'compiled-F4-wishbone-storage-{phase}-sample-missing')
    probes = _accept_probes(event['outputs']['storage_probes'], widths, phase)
    return probes, event['outputs']['backend']


def _transfer_samples(events, *, delivery, component, signals, expected_write,
                      word_index, value, reset_epoch, widths):
    """Find the exact accepted Wishbone pre/post/ACK triple of one delivery."""
    rows = [event for event in events
            if event.get('kind') == 'local_tick_sample'
            and event.get('component') == component
            and event.get('producer_event_id') == delivery.get('producer_event_id')]
    requests = []
    for event in rows:
        if event.get('phase') != 'pre':
            continue
        outputs = event.get('outputs')
        if not isinstance(outputs, dict):
            continue
        backend = outputs.get('backend')
        if not isinstance(backend, dict):
            continue
        # Address, select and hangshake levels are *named* refusals below, not
        # search keys, so a tampered sample fails with its own reason.
        if (backend.get(signals['cyc']) != 1
                or backend.get(signals['stb']) != 1
                or backend.get(signals['we']) != int(expected_write)):
            continue
        requests.append(event)
    if len(requests) != 1:
        raise ValueError(
            'compiled-F4-wishbone-storage-native-transfer-missing')
    pre = requests[0]
    probes_pre, backend_pre = _sample_row(
        pre, component=component, reset_epoch=reset_epoch, phase='pre',
        widths=widths)
    _check_trace(probes_pre, backend_pre, signals, widths, phase='pre')
    if (probes_pre['storage_cyc'] != 1 or probes_pre['storage_stb'] != 1
            or probes_pre['storage_we'] != int(expected_write)
            or probes_pre['storage_ack'] != 0
            or probes_pre['storage_stall'] != 0):
        raise ValueError('compiled-F4-wishbone-storage-protocol-mismatch')
    if probes_pre['storage_adr'] != word_index:
        raise ValueError('compiled-F4-wishbone-storage-word-index-mismatch')
    select = probes_pre['storage_sel']
    if expected_write and select != 15 or not expected_write and (
            select not in READ_SELECTS):
        raise ValueError('compiled-F4-wishbone-storage-select-mismatch')
    if probes_pre['storage_reset'] not in (0, 1):
        raise ValueError('compiled-F4-wishbone-storage-reset-level')
    if probes_pre['storage_reset'] != 0:
        raise ValueError('compiled-F4-wishbone-storage-reset-level')
    if expected_write and probes_pre['storage_dat_w'] != value:
        raise ValueError(
            'compiled-F4-wishbone-storage-native-write-value-mismatch')
    # A stalled accept is a protocol failure, never a delivered transaction.
    if backend_pre.get(signals['stall']) != 0:
        raise ValueError('compiled-F4-wishbone-storage-protocol-mismatch')
    posts = [event for event in rows
             if event.get('phase') == 'post'
             and event.get('local_tick') == pre['local_tick']
             and event.get('reset_epoch') == reset_epoch]
    if len(posts) != 1:
        raise ValueError(
            'compiled-F4-wishbone-storage-native-post-sample-missing')
    post = posts[0]
    probes_post, backend_post = _sample_row(
        post, component=component, reset_epoch=reset_epoch, phase='post',
        widths=widths)
    if (post.get('event_id') is None
            or type(post.get('event_id')) is not int
            or post['event_id'] <= pre['event_id']):
        raise ValueError(
            'compiled-F4-wishbone-storage-native-post-sample-mismatch')
    _check_trace(probes_post, backend_post, signals, widths, phase='post')
    if (probes_post['storage_cyc'] != 1 or probes_post['storage_stb'] != 0
            or probes_post['storage_stall'] != 0
            or probes_post['storage_ack'] != 0):
        raise ValueError('compiled-F4-wishbone-storage-protocol-mismatch')
    if probes_post['storage_reset'] != probes_pre['storage_reset']:
        raise ValueError('compiled-F4-wishbone-storage-reset-level')
    # ACK is registered: it cannot appear in the request cycle or the cycle
    # immediately after it, and CYC must stay asserted until it is observed.
    later = sorted(
        (event for event in rows
         if event.get('local_tick') > pre['local_tick']
         and event.get('reset_epoch') == reset_epoch),
        key=lambda event: (event['local_tick'],
                           event.get('phase') != 'pre'))
    held = []
    acks = []
    for event in later:
        probes, backend = _sample_row(
            event, component=component, reset_epoch=reset_epoch,
            phase=event['phase'], widths=widths)
        _check_trace(probes, backend, signals, widths, phase=event['phase'])
        if probes['storage_stall'] != 0:
            raise ValueError('compiled-F4-wishbone-storage-protocol-mismatch')
        if probes['storage_ack'] == 1:
            acks.append((event, probes))
            break
        held.append(probes)
    if not acks:
        raise ValueError('compiled-F4-wishbone-storage-missing-ack')
    ack_event, probes_ack = acks[0]
    if (probes_ack['storage_cyc'] != 1 or probes_ack['storage_stb'] != 0
            or probes_ack['storage_stall'] != 0
            or probes_ack['storage_reset'] != 0):
        raise ValueError('compiled-F4-wishbone-storage-protocol-mismatch')
    if any(probes['storage_cyc'] != 1 for probes in held):
        raise ValueError('compiled-F4-wishbone-storage-protocol-mismatch')
    if expected_write:
        if probes_ack['storage_value'] != value:
            raise ValueError(
                'compiled-F4-wishbone-storage-storage-transition-mismatch')
    else:
        if probes_ack['storage_dat_r'] != value:
            raise ValueError(
                'compiled-F4-wishbone-storage-native-read-value-mismatch')
        if probes_ack['storage_value'] != value:
            raise ValueError(
                'compiled-F4-wishbone-storage-storage-transition-mismatch')
    return _Transfer(pre, post, ack_event, deepcopy(probes_pre),
                     deepcopy(probes_post), deepcopy(probes_ack))


def _check_commit(commit, *, before, access, value, word_index, writes_all,
                  delivery, transfer, target, contract):
    if (not isinstance(commit, dict) or set(commit) != COMMIT_KEYS
            or not isinstance(commit.get('context'), dict)
            or not isinstance(commit.get('raw_reference'), dict)):
        raise ValueError('compiled-F4-wishbone-storage-commit-shape')
    context = commit['context']
    reference = commit['raw_reference']
    if (set(context) != CONTEXT_KEYS
            or set(reference) != RAW_REFERENCE_KEYS
            or any(type(commit[key]) is not int for key in
                   ('tick', 'raw_address', 'before', 'after', 'sample_index',
                    'command_sequence'))
            or not 0 <= commit['before'] <= FULL_MASK
            or not 0 <= commit['after'] <= FULL_MASK
            or commit['phase'] != 'pre'
            or commit['sample_index'] < 0
            or commit['command_sequence'] < 1
            or type(reference['execution']) is not str
            or type(reference['sequence']) is not int
            or type(reference['sample_index']) is not int
            or reference['phase'] != 'pre'
            or type(context['write']) is not bool
            or context['write'] is not True
            or type(context['source_authenticated']) is not bool
            or context['source_authenticated'] is not False
            or context['schema_version'] != (
                'wishbone_storage_routed_context.v1')):
        raise ValueError('compiled-F4-wishbone-storage-commit-shape')
    try:
        validate_routed_context(
            context, operation='ACCESS_WB_REG',
            fields=(1, access['register_offset'], value, 15),
            sequence=commit['command_sequence'], execution=target._execution,
            epoch=before['reset_epoch'], window=access['window_size'])
    except ValueError as error:
        raise ValueError(
            'compiled-F4-wishbone-storage-commit-context-mismatch') from error
    transaction = context['source_transaction']
    if (not isinstance(transaction, dict)
            or set(transaction) != TRANSACTION_KEYS
            or transaction != delivery.get('source_transaction')):
        raise ValueError('compiled-F4-wishbone-storage-commit-context-mismatch')
    if (context['device_id'] != access['device_id']
            or context['window_base'] != access['window_base']
            or context['window_size'] != access['window_size']
            or context['address'] != access['address']
            or context['offset'] != access['register_offset']
            or context['word_index'] != word_index
            or context['value'] != value or context['byte_enable'] != 15):
        raise ValueError('compiled-F4-wishbone-storage-commit-context-mismatch')
    if context['reset_epoch'] != before['reset_epoch']:
        raise ValueError('compiled-F4-wishbone-storage-commit-epoch-mismatch')
    if context['execution'] != target._execution:
        raise ValueError('compiled-F4-wishbone-storage-commit-process-mismatch')
    if reference['execution'] != context['execution']:
        raise ValueError('compiled-F4-wishbone-storage-commit-process-mismatch')
    if (context['command_sequence'] != commit['command_sequence']
            or reference['sequence'] != commit['command_sequence']
            or reference['sample_index'] != commit['sample_index']):
        raise ValueError(
            'compiled-F4-wishbone-storage-commit-sequence-mismatch')
    if (commit['tick'] != transfer.pre['local_tick']
            or transfer.post['local_tick'] != commit['tick']
            or context['tick'] != commit['tick']):
        raise ValueError('compiled-F4-wishbone-storage-commit-tick-mismatch')
    if (commit['raw_address'] != word_index
            or commit['raw_address'] != contract['register']['word_index']
            or commit['raw_address'] != transfer.probes_pre['storage_adr']):
        raise ValueError('compiled-F4-wishbone-storage-commit-word-index-mismatch')
    if (commit['before'] != before['value']
            or commit['after'] != value
            or commit['before'] != transfer.probes_pre['storage_value']
            or commit['after'] != transfer.probes_post['storage_value']):
        raise ValueError('compiled-F4-wishbone-storage-commit-value-mismatch')
    if commit is not writes_all[-1]:
        raise ValueError('compiled-F4-wishbone-storage-commit-identity-mismatch')
    return deepcopy(commit)


def check_wishbone_storage_observation(declaration, receipt, *,
                                       target_artifact, authority, token,
                                       register, reset_epoch, before,
                                       prior_writes):
    """Consume one actual generic Wishbone storage F4 chain, or refuse by name.

    The event chain and the process-owned write journal are checked before the
    opaque token is consumed.  A serialized witness, a readback or the current
    register value can never replace it.
    """
    _check_pins()
    if type(authority) is not WishboneStorageRegisterVersionAuthority:
        raise ValueError('compiled-F4-wishbone-storage-authority-required')
    if type(token) is not object:
        raise ValueError('compiled-F4-wishbone-storage-token-required')
    if (type(register) is not str or not register
            or type(reset_epoch) is not int or reset_epoch < 0
            or type(prior_writes) is not int or prior_writes < 0):
        raise ValueError('compiled-F4-wishbone-storage-argument-required')
    if not isinstance(target_artifact, LocalRuntimeArtifact):
        raise ValueError('compiled-F4-wishbone-storage-artifact-required')
    target = getattr(authority, 'target', None)
    if target is None or getattr(target, 'artifact', None) is not target_artifact:
        raise ValueError(
            'compiled-F4-wishbone-storage-authority-artifact-mismatch')
    base_dir = Path(target.base_dir)
    document = target_artifact.runtime_document
    if document.get('kind') != 'wishbone_register_observe':
        raise ValueError('compiled-F4-wishbone-storage-artifact-kind-required')
    observation = document.get('storage_observation')
    contract, signals, widths = _check_observation(
        observation, target_artifact, register=register, base_dir=base_dir)
    access, value, word_index = _check_declaration(
        declaration, target_artifact=target_artifact, register=register,
        contract=contract)
    if target.reset_epoch != reset_epoch:
        raise ValueError('compiled-F4-wishbone-storage-epoch-mismatch')
    _check_before(before, prior_writes=prior_writes, register=register)
    if (before['reset_epoch'] != reset_epoch
            or before['artifact_digest'] != document.get('artifact_digest')
            or before['source_contract_digest'] != contract.get('digest')
            or before['probe_digest'] != observation.get('digest')):
        raise ValueError(
            'compiled-F4-wishbone-storage-before-witness-mismatch')
    receipt_events = getattr(receipt, 'events', None)
    case_id = getattr(receipt, 'case_id', None)
    if (not isinstance(receipt_events, (list, tuple)) or not receipt_events
            or any(not isinstance(row, dict) for row in receipt_events)
            or type(case_id) is not str or not case_id):
        raise ValueError('compiled-F4-wishbone-storage-receipt-required')
    source = access['source_component']
    target_component = access['target_component']
    address = access['address']
    offset = access['register_offset']
    deliveries = [event for event in receipt_events
                  if event.get('kind') == 'mmio_delivery'
                  and event.get('component') == source
                  and event.get('device_id') == access['device_id']
                  and event.get('address') == address]
    writes = [event for event in deliveries if event.get('write') is True
              and event.get('write_value') == value
              and event.get('byte_enable') == 15]
    if len(writes) != 1:
        raise ValueError('compiled-F4-wishbone-storage-delivery-count')
    write_delivery = writes[0]
    reads = [event for event in deliveries if event.get('write') is False
             and event.get('read_value') == value
             and event.get('event_id', 0) > write_delivery['event_id']]
    if len(reads) != 1:
        raise ValueError('compiled-F4-wishbone-storage-delivery-count')
    read_delivery = reads[0]
    write_acceptance = _join_delivery(
        receipt_events, delivery=write_delivery, component=source,
        device=access['device_id'], address=address, offset=offset, write=True)
    read_acceptance = _join_delivery(
        receipt_events, delivery=read_delivery, component=source,
        device=access['device_id'], address=address, offset=offset, write=False)
    if ((write_delivery['source_transaction'].get('source_sequence') or 0) + 1
            != read_delivery['source_transaction'].get('source_sequence')):
        raise ValueError('compiled-F4-wishbone-storage-sequence-mismatch')
    for key in ('execution_id', 'testcase_id', 'source_component',
                'source_epoch'):
        if (write_delivery['source_transaction'].get(key)
                != read_delivery['source_transaction'].get(key)):
            raise ValueError('compiled-F4-wishbone-storage-sequence-mismatch')
    write_transfer = _transfer_samples(
        receipt_events, delivery=write_delivery, component=target_component,
        signals=signals, expected_write=True,
        word_index=word_index, value=value, reset_epoch=reset_epoch,
        widths=widths)
    read_transfer = _transfer_samples(
        receipt_events, delivery=read_delivery, component=target_component,
        signals=signals, expected_write=False,
        word_index=word_index, value=value, reset_epoch=reset_epoch,
        widths=widths)
    if write_transfer.pre['local_tick'] >= read_transfer.pre['local_tick']:
        raise ValueError('compiled-F4-wishbone-storage-sequence-mismatch')
    if write_transfer.ack['event_id'] >= read_acceptance['event_id']:
        raise ValueError('compiled-F4-wishbone-storage-sequence-mismatch')
    if (write_transfer.probes_pre['storage_value'] != before['value']
            or write_transfer.probes_post['storage_value'] != value
            or read_transfer.probes_pre['storage_value'] != value
            or read_transfer.probes_post['storage_value'] != value
            or read_transfer.probes_ack['storage_value'] != value):
        raise ValueError(
            'compiled-F4-wishbone-storage-storage-transition-mismatch')
    ram = [event for event in receipt_events if event.get('kind') == 'memory_write'
           and event.get('component') == source
           and event.get('address') == declaration['result_address']
           and event.get('value') == value and event.get('byte_enable') == 15
           and event.get('event_id', 0) > read_delivery['event_id']]
    if len(ram) != 1:
        raise ValueError('compiled-F4-wishbone-storage-readback-RAM-mismatch')
    writes_all = authority.writes()
    if (not isinstance(writes_all, list)
            or len(writes_all) != prior_writes + 1
            or any(not isinstance(row, dict) for row in writes_all)):
        raise ValueError('compiled-F4-wishbone-storage-commit-count')
    if (before['write_history_sha256'] != _digest(writes_all[:prior_writes])
            or before['write_count'] != prior_writes):
        raise ValueError('compiled-F4-wishbone-storage-before-history-mismatch')
    commit = _check_commit(
        writes_all[prior_writes], before=before, access=access, value=value,
        word_index=word_index, writes_all=writes_all, delivery=write_delivery,
        transfer=write_transfer, target=target, contract=contract)
    witness = authority.consume(token)
    if not isinstance(witness, dict) or set(witness) != WITNESS_KEYS:
        raise ValueError('compiled-F4-wishbone-storage-witness-shape')
    if (witness['register'] != register
            or witness['reset_epoch'] != reset_epoch
            or witness['value'] != value
            or witness['write_count'] != prior_writes + 1
            or witness['field_version'] != prior_writes + 1
            or witness['version_basis'] != wishbone_storage_version_basis(register)
            or witness['history_scope'] != HISTORY_SCOPE
            or witness['write_history_sha256'] != _digest(writes_all)
            or witness['grants_reset_prerequisite'] is not False
            or witness['routed_context_authenticated'] is not False
            or type(witness['reset_waveform_observed']) is not bool
            or not _hex64(witness['build_identity_sha256'])
            or not _hex64(witness['artifact_digest'])
            or not _hex64(witness['source_contract_digest'])
            or not _hex64(witness['probe_digest'])
            or not _hex64(witness['producer_source_sha256'])
            or type(witness['pid']) is not int or witness['pid'] < 1
            or type(witness['execution']) is not str
            or type(witness['local_tick']) is not int
            or type(witness['command_sequence']) is not int):
        raise ValueError('compiled-F4-wishbone-storage-witness-mismatch')
    if (target.process is None or target.process.poll() is not None
            or witness['pid'] != target.process.pid):
        raise ValueError(
            'compiled-F4-wishbone-storage-witness-process-mismatch')
    if (witness['execution'] != target._execution
            or witness['local_tick'] != target.local_ticks
            or witness['command_sequence'] != target._sequence):
        raise ValueError('compiled-F4-wishbone-storage-witness-scope-mismatch')
    if witness['command_sequence'] <= commit['command_sequence']:
        raise ValueError(
            'compiled-F4-wishbone-storage-witness-sequence-mismatch')
    if witness['local_tick'] <= read_transfer.ack['local_tick']:
        raise ValueError('compiled-F4-wishbone-storage-witness-tick-mismatch')
    if (witness['artifact_digest'] != document['artifact_digest']
            or witness['source_contract_digest'] != contract.get('digest')
            or witness['probe_digest'] != observation.get('digest')
            or witness['producer_source_sha256']
            != _digest_source(WishboneStorageRegisterVersionAuthority)):
        raise ValueError('compiled-F4-wishbone-storage-witness-source-mismatch')
    if (before['pid'] != witness['pid']
            or before['execution'] != witness['execution']):
        raise ValueError(
            'compiled-F4-wishbone-storage-witness-process-mismatch')
    if before['build_identity_sha256'] != witness['build_identity_sha256']:
        raise ValueError(
            'compiled-F4-wishbone-storage-witness-build-identity-mismatch')
    joins = [
        dict(delivery_event=write_delivery['event_id'],
             acceptance_event=write_acceptance['event_id'],
             native_wishbone_event=write_transfer.pre['event_id'],
             native_ack_event=write_transfer.ack['event_id'],
             source_transaction=deepcopy(
                 write_delivery['source_transaction']),
             write=True, tick=write_transfer.pre['local_tick']),
        dict(delivery_event=read_delivery['event_id'],
             acceptance_event=read_acceptance['event_id'],
             native_wishbone_event=read_transfer.pre['event_id'],
             native_ack_event=read_transfer.ack['event_id'],
             source_transaction=deepcopy(
                 read_delivery['source_transaction']),
             write=False, tick=read_transfer.pre['local_tick'])]
    public_commit = dict(
        schema_version=COMMIT_SCHEMA, tick=commit['tick'],
        before=commit['before'], after=commit['after'],
        epoch=commit['context']['reset_epoch'],
        command_sequence=commit['command_sequence'],
        raw_address=commit['raw_address'], word_index=word_index,
        sample_index=commit['sample_index'], phase=commit['phase'],
        context={key: deepcopy(commit['context'][key]) for key in (
            'source_transaction', 'device_id', 'window_base', 'window_size',
            'address', 'offset', 'word_index', 'write', 'value', 'read_value',
            'byte_enable', 'tick', 'reset_epoch', 'command_sequence',
            'schema_version', 'source_authenticated')},
        raw_reference={key: deepcopy(commit['raw_reference'][key]) for key in
                       ('sequence', 'sample_index', 'phase')},
        field_version=witness['field_version'],
        write_count=witness['write_count'],
        version_basis=witness['version_basis'])
    after = stable_wishbone_storage_version(witness)
    observed = dict(
        schema_version=OBSERVATION_SCHEMA, case_id=case_id, value=value,
        address=address, offset=offset, word_index=word_index,
        register=register, runtime_admitted=False,
        proof_scope=('CPU_data_acceptance_router_delivery_native_wishbone_'
                     'pre_ack_live_storage_version_and_CPU_readback_RAM'),
        joins=joins, commit=deepcopy(public_commit),
        native_samples=dict(
            write=dict(accepted_event=write_transfer.pre['event_id'],
                       ack_event=write_transfer.ack['event_id'],
                       tick=write_transfer.pre['local_tick'],
                       ack_tick=write_transfer.ack['local_tick'],
                       word_index=word_index, byte_enable=15,
                       value_before=write_transfer.probes_pre['storage_value'],
                       value_after=write_transfer.probes_post['storage_value']),
            read=dict(accepted_event=read_transfer.pre['event_id'],
                      ack_event=read_transfer.ack['event_id'],
                      tick=read_transfer.pre['local_tick'],
                      ack_tick=read_transfer.ack['local_tick'],
                      value_observed=read_transfer.probes_ack['storage_value'],
                      rdata=read_transfer.probes_ack['storage_dat_r'])),
        storage_probes=dict(
            write=dict(pre=write_transfer.probes_pre,
                       post=write_transfer.probes_post,
                       ack=write_transfer.probes_ack),
            read=dict(pre=read_transfer.probes_pre,
                      post=read_transfer.probes_post,
                      ack=read_transfer.probes_ack)),
        RAM_event=ram[0]['event_id'],
        version_witness=deepcopy(witness),
        token=dict(schema_version=TOKEN_SCHEMA, consumed=True,
                   single_use=True, opaque=True,
                   issuer=_qualified(WishboneStorageRegisterVersionAuthority),
                   register=register, reset_epoch=reset_epoch,
                   write_count=prior_writes + 1))
    return observed, public_commit, after


def wishbone_storage_consumer_support(*, binding, artifacts):
    """Source-level completeness of the four receipt joins of the generic row.

    Every element is a code/declaration identity fact.  The live token itself
    can only be obtained from an actual native Wishbone producer, so this
    report never grants runtime admission.
    """
    _check_pins()
    document = binding.document() if callable(
        getattr(binding, 'document', None)) else None
    if not isinstance(document, dict):
        raise ValueError(
            'compiled-F4-wishbone-storage-consumer-binding-required')
    if document.get('row') != ROW_GENERIC_WISHBONE_STORAGE:
        raise ValueError('compiled-F4-wishbone-storage-consumer-row-required')
    producer = document.get('producer') if isinstance(
        document.get('producer'), dict) else {}
    bound = document.get('bound_input')
    register = document.get('register') if isinstance(
        document.get('register'), dict) else {}
    target = document.get('target_component')
    endpoint = document.get('endpoint_id')
    consumer_ok = (
        producer.get('commit_consumer') == CONSUMER_QUALNAME
        and producer.get('commit_consumer_source_sha256')
        == _digest_source(check_wishbone_storage_observation)
        and _CONSUMER_PIN[0] is check_wishbone_storage_observation
        and _CONSUMER_PIN[1] is check_wishbone_storage_observation.__code__)
    artifact = (artifacts.get(target)
                if isinstance(artifacts, Mapping) else None)
    runtime = (artifact.runtime_document
               if isinstance(artifact, LocalRuntimeArtifact) else {})
    probe = runtime.get('storage_observation')
    trace = runtime.get('base_protocol_trace')
    ports = runtime.get('storage_probe_ports')
    probe_widths = None
    if (isinstance(probe, dict)
            and isinstance(probe.get('source_contract'), dict)
            and isinstance(probe['source_contract'].get('register'), dict)
            and isinstance(probe['source_contract'].get('decode'), dict)):
        try:
            probe_widths = wishbone_probe_widths(probe['source_contract'])
        except ValueError:
            probe_widths = None
    probe_ok = (
        isinstance(artifact, LocalRuntimeArtifact)
        and runtime.get('kind') == 'wishbone_register_observe'
        and runtime.get('artifact_digest') == document.get('target_artifact_digest')
        and isinstance(probe, dict)
        and isinstance(document.get('probe'), dict)
        and probe.get('digest') == document['probe'].get('digest')
        and isinstance(probe.get('source_contract'), dict)
        and probe['source_contract'].get('digest')
        == document['probe'].get('source_contract_digest')
        and isinstance(trace, dict) and trace.get('protocol') == 'wishbone'
        and set(trace.get('signals') or {}) == set(TRACE_ROLES)
        and 'err' not in (trace.get('signals') or {})
        and isinstance(ports, list) and probe_widths is not None
        and len(ports) == len(probe_widths)
        and {row.get('name') for row in ports if isinstance(row, dict)}
        == set(probe_widths)
        and all(row.get('width') == probe_widths[row['name']]
                for row in ports if row.get('name') in probe_widths)
        and isinstance(probe['source_contract'].get('register'), dict)
        and probe['source_contract']['register'].get('name')
        == register.get('name')
        and probe['source_contract']['register'].get('word_index')
        == register.get('word_index'))
    delivery_ok = (
        consumer_ok and isinstance(bound, dict)
        and bound.get('kind') == 'ip_register_commit'
        and bound.get('component') == target
        and bound.get('endpoint_id') == endpoint
        and bound.get('input_id')
        == f'{target}.{endpoint}.register.{register.get("name")}.value'
        and type(register.get('address')) is int
        and document.get('protocol') == ['wishbone', 'classic']
        and document.get('template') == {
            'template_id': 'target.wishbone', 'template_version': '1',
            'variant_id': 'word-addressed-registered-ack'}
        and document.get('target_artifact_kind') == 'wishbone_register_observe')
    token_ok = (
        producer.get('issuer_class')
        == _qualified(WishboneStorageRegisterVersionAuthority)
        and producer.get('issuer_source_sha256')
        == _digest_source(WishboneStorageRegisterVersionAuthority)
        and producer.get('version_issuance')
        == 'WishboneStorageRegisterVersionAuthority.issue/consume/writes'
        and producer.get('live_token_scope')
        == 'actual_initial_samples_required_not_claimed'
        and producer.get('grants_reset_prerequisite') is False
        and isinstance(document.get('prerequisite'), dict)
        and document['prerequisite'].get('allowed_kinds')
        == ['ip_register_version']
        and document['prerequisite'].get('expected', {}).get('kind')
        == 'ip_register_version'
        and document['prerequisite'].get('expected', {}).get('subject') == {
            'component': target, 'register': register.get('name'),
            'reset_epoch': 0})
    states = {'cpu_acceptance': consumer_ok,
              'router_delivery': delivery_ok,
              'native_wishbone_pre_sample': probe_ok,
              'version_token': token_ok}
    bases = dict(ELEMENT_BASIS)
    if probe_ok:
        address = probe['source_contract']['decode'].get('address_width')
        if type(address) is int and address > 0:
            bases['native_wishbone_pre_sample'] = (
                'native Wishbone pre/ACK storage_probes with word-index '
                f'ADR[{address - 1}:0], registered ACK, CYC held, stall=0 '
                'and reset levels')
    refusals = [dict(code='compiled-F4-wishbone-storage-receipt-join-incomplete',
                     element=name) for name in RECEIPT_ELEMENTS
                if not states[name]]
    complete = not refusals
    return dict(schema_version=SUPPORT_SCHEMA, complete=complete,
        disposition=('supported_requires_actual_native_wishbone' if complete
                     else 'unsupported'),
        row=document.get('row'), consumer=CONSUMER_QUALNAME,
        receipt_elements=list(RECEIPT_ELEMENTS),
        elements={name: dict(present=bool(states[name]), basis=bases[name])
                  for name in RECEIPT_ELEMENTS},
        refusals=refusals, runtime_admitted=False,
        authority_scope=('source_code_identity_only_live_token_requires_'
                         'actual_native_wishbone'))


_PINNED_VERIFY = (verified_wishbone_storage_observation,
                  verified_wishbone_storage_observation.__code__)
_PINNED_ISSUER = (WishboneStorageRegisterVersionAuthority,
                  WishboneStorageRegisterVersionAuthority.consume.__code__,
                  WishboneStorageRegisterVersionAuthority.issue.__code__)
_CONSUMER_PIN = (check_wishbone_storage_observation,
                 check_wishbone_storage_observation.__code__)
_SUPPORT_PIN = (wishbone_storage_consumer_support,
                wishbone_storage_consumer_support.__code__)
_SOURCE_PINS = {function.__name__: (function, function.__code__)
                for function in (
                    validate_wishbone_storage_source_contract,
                    wishbone_setup_matches, wishbone_word_index,
                    wishbone_storage_version_basis, validate_routed_context)}


def _check_pins():
    import myfuzz.local_harness.wishbone_storage_probe_verification as verify_module
    import myfuzz.local_harness.wishbone_storage_source_contract as source_module
    import myfuzz.scenario.wishbone_storage_register_version as version_module
    if (_CONSUMER_PIN[0] is not check_wishbone_storage_observation
            or _CONSUMER_PIN[1] is not check_wishbone_storage_observation.__code__
            or _SUPPORT_PIN[0] is not wishbone_storage_consumer_support
            or _SUPPORT_PIN[1] is not wishbone_storage_consumer_support.__code__
            or _PINNED_VERIFY[0] is not verified_wishbone_storage_observation
            or _PINNED_VERIFY[1]
            is not verified_wishbone_storage_observation.__code__
            or verify_module.verified_wishbone_storage_observation
            is not _PINNED_VERIFY[0]
            or getattr(version_module,
                       'WishboneStorageRegisterVersionAuthority',
                       None) is not _PINNED_ISSUER[0]
            or _PINNED_ISSUER[0].consume.__code__ is not _PINNED_ISSUER[1]
            or _PINNED_ISSUER[0].issue.__code__ is not _PINNED_ISSUER[2]
            or any(globals().get(name) is not function
                   or function.__code__ is not code
                   or getattr(
                       version_module if name in (
                           'wishbone_storage_version_basis',
                           'validate_routed_context') else source_module,
                       name) is not function
                   for name, (function, code) in _SOURCE_PINS.items())):
        raise ValueError('compiled-F4-wishbone-storage-consumer-drift')
