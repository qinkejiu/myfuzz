"""Consume the actual compiled-F4 storage chain for the generic APB producer row.

The chain is: CPU data acceptance -> Router delivery -> native APB pre/post
sample -> ``ApbStorageRegisterVersionAuthority.consume`` opaque token ->
CPU readback/RAM.  A caller document, a serialized write record, a readback or
the current register value is never a substitute for that token.

The token is single-use and owned by the native C issuer.  Without an actual
native build/process eligibility the issuer refuses before any token lookup, so
this module cannot manufacture a positive: the pure controls only exercise the
event/journal join and always fail closed at the token boundary.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import inspect
import json
import re
from pathlib import Path

from myfuzz.local_harness.apb_storage_probe_verification import (
    verified_storage_observation)
from myfuzz.local_harness.native_physical_observation import (
    verify_apb_register_trace)
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.scenario.apb_storage_register_version import (
    ApbStorageRegisterVersionAuthority)

CONSUMER_QUALNAME = (
    'myfuzz.integration.generated_storage_consumer.check_storage_observation')
SUPPORT_SCHEMA = 'compiled_F4_storage_consumer_support.v1'
OBSERVATION_SCHEMA = 'compiled_F4_storage_observation.v1'
VERSION_SCHEMA = 'apb_storage_register_version.v1'
COMMIT_SCHEMA = 'apb_storage_commit.v1'
RECEIPT_ELEMENTS = ('cpu_acceptance', 'router_delivery',
                    'native_apb_pre_sample', 'version_token')
ELEMENT_BASIS = {
    'cpu_acceptance':
        'in-row consumer joins the actual CPU data acceptance',
    'router_delivery':
        'typed TransactionKey/address/offset/be/device is joined to the actual '
        'Router delivery',
    'native_apb_pre_sample':
        'native APB pre/post storage_probes with PADDR[4:2] alias and reset levels',
    'version_token':
        'opaque single-use ApbStorageRegisterVersionAuthority token consumed '
        'in-process',
}
PROBE_WIDTHS = {
    'storage_value': 32, 'storage_reset': 1, 'storage_paddr': 12,
    'storage_psel': 1, 'storage_penable': 1, 'storage_pwrite': 1,
    'storage_pwdata': 32, 'storage_prdata': 32, 'storage_pready': 1,
    'storage_pslverr': 1,
}
TRACE_ROLES = frozenset({'paddr', 'psel', 'penable', 'pwrite', 'pwdata',
                         'pready', 'prdata', 'pslverr'})
ALIAS_MASK = 0x1c
ALIAS_VALUE = 0x4
FULL_MASK = 0xffffffff
VERSION_BASIS = 'all_measured_CTRL_alias_writes_since_first_command'
HISTORY_SCOPE = ('complete_commands_since_first_measured_state_'
                 'not_unobserved_startup')
WITNESS_KEYS = frozenset({
    'register', 'value', 'local_tick', 'write_history_sha256', 'field_version',
    'write_count', 'version_basis', 'reset_epoch', 'command_sequence', 'pid',
    'execution', 'build_identity_sha256', 'producer_source_sha256',
    'artifact_digest', 'source_contract_digest', 'probe_digest',
    'reset_waveform_observed', 'grants_reset_prerequisite', 'history_scope',
    'routed_context_authenticated'})
CONTEXT_KEYS = frozenset({
    'source_transaction', 'device_id', 'window_base', 'window_size', 'address',
    'offset', 'write', 'value', 'be', 'execution', 'reset_epoch',
    'command_sequence', 'schema_version', 'source_authenticated'})
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
            'compiled-F4-storage-source-identity-unavailable') from error


def stable_storage_version(witness):
    """Stable certificate projection: volatile process fields stay in evidence.

    PID, driver execution nonce, build identity and the write-history digest
    include process-local values or opaque receipt references.  They are
    validated against the live witness but cannot enter a fresh-prefix
    comparison; every declared version fact is retained here.
    """
    if not isinstance(witness, dict) or set(witness) != WITNESS_KEYS:
        raise ValueError('compiled-F4-storage-witness-shape')
    document = {key: deepcopy(witness[key]) for key in STABLE_VERSION_KEYS}
    document['schema_version'] = VERSION_SCHEMA
    document['certificate_projection'] = (
        'stable_fields_only_process_fields_validated_live')
    return document


def _check_declaration(declaration, *, target_artifact, register):
    if (not isinstance(declaration, dict)
            or declaration.get('schema_version')
            != 'generated_register_writer.v1'):
        raise ValueError('compiled-F4-storage-declaration-required')
    candidate = declaration.get('candidate')
    access = candidate.get('access') if isinstance(candidate, dict) else None
    value = candidate.get('value') if isinstance(candidate, dict) else None
    result = declaration.get('result_address')
    if (not isinstance(access, dict) or type(value) is not int
            or type(result) is not int or result % 4
            or not 0 <= result <= 0xfffffffc):
        raise ValueError('compiled-F4-storage-declaration-required')
    window_base = access.get('window_base')
    window = access.get('window_size')
    offset = access.get('register_offset')
    if (type(window_base) is not int or not 0 <= window_base < 1 << 32
            or type(window) is not int or window <= 0 or window % 4
            or window_base + window > 1 << 32
            or type(offset) is not int or not 0 <= offset < window
            or offset % 4):
        raise ValueError('compiled-F4-storage-declaration-geometry')
    if (access.get('register') != register
            or access.get('operation') != 'write'
            or access.get('value_origin') != 'cpu_transaction_wdata'
            or access.get('register_origin') != 'bound_target_register_commit'
            or access.get('width_bytes') != 4
            or access.get('allowed_byte_enables') != [15]
            or access.get('byte_enable_domain') != 'target_word_lanes'
            or access.get('access_alignment') != 4
            or access.get('value_mask') != FULL_MASK
            or not 0 <= value <= FULL_MASK
            or offset & ALIAS_MASK != ALIAS_VALUE
            or access.get('address') != window_base + offset
            or type(access.get('source_component')) is not str
            or type(access.get('target_component')) is not str
            or type(access.get('device_id')) is not str
            or access.get('device_id') != access.get('target_component')
            or type(access.get('source_endpoint')) is not str):
        raise ValueError('compiled-F4-storage-declaration-geometry')
    if target_artifact.plan.request.instance_id != access['target_component']:
        raise ValueError('compiled-F4-storage-target-instance-mismatch')
    return access, value


def _check_before(before, *, prior_writes, register):
    if not isinstance(before, dict) or set(before) != WITNESS_KEYS:
        raise ValueError('compiled-F4-storage-before-witness-required')
    if (any(type(before[key]) is not int or before[key] < 0 for key in
            ('value', 'local_tick', 'field_version', 'write_count',
             'reset_epoch', 'command_sequence', 'pid'))
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
            or before['version_basis'] != VERSION_BASIS
            or before['history_scope'] != HISTORY_SCOPE
            or type(before['reset_waveform_observed']) is not bool
            or before['grants_reset_prerequisite'] is not False
            or before['routed_context_authenticated'] is not False):
        raise ValueError('compiled-F4-storage-before-witness-required')


def _join_delivery(events, *, delivery, component, device, address, offset,
                   write):
    if (delivery.get('device_id') != device
            or delivery.get('address') != address
            or delivery.get('offset') != offset
            or delivery.get('write') is not write
            or delivery.get('byte_enable') != 15):
        raise ValueError('compiled-F4-storage-delivery-geometry')
    accepted = [e for e in events
                if e.get('kind') == 'mmio_acceptance'
                and e.get('component') == component
                and e.get('source_transaction')
                == delivery.get('source_transaction')
                and e.get('address') == address
                and e.get('write') is write
                and e.get('event_id', 0) < delivery.get('event_id', 0)]
    if len(accepted) != 1:
        raise ValueError('compiled-F4-storage-CPU-acceptance-join')
    transaction = delivery.get('source_transaction')
    if (not isinstance(transaction, dict) or set(transaction) != TRANSACTION_KEYS
            or any(type(transaction[key]) is not str or not transaction[key]
                   for key in ('execution_id', 'testcase_id',
                               'source_component', 'channel_id'))
            or any(type(transaction[key]) is not int or transaction[key] < 0
                   for key in ('source_epoch', 'source_sequence'))
            or transaction['channel_id'] != 'data'
            or transaction['source_epoch'] != 0):
        raise ValueError('compiled-F4-storage-transaction-shape')
    return accepted[0]


def _transfer_samples(events, *, delivery, component, signals, expected_write,
                      offset, value, reset_epoch):
    """Find the exact accepted native APB pre/post pair of one delivery."""
    rows = [e for e in events if e.get('kind') == 'local_tick_sample'
            and e.get('component') == component
            and e.get('producer_event_id') == delivery.get('producer_event_id')]
    accepted = []
    for event in rows:
        if event.get('phase') != 'pre':
            continue
        outputs = event.get('outputs')
        if not isinstance(outputs, dict):
            continue
        backend = outputs.get('backend')
        observed = outputs.get('storage_probes')
        if not isinstance(backend, dict) or not isinstance(observed, dict):
            continue
        if set(observed) != set(PROBE_WIDTHS):
            continue
        if (backend.get(signals['psel']) != 1
                or backend.get(signals['penable']) != 1
                or backend.get(signals['pready']) != 1):
            continue
        if (backend.get(signals['pwrite']) != int(expected_write)
                or backend.get(signals['paddr']) != offset):
            continue
        accepted.append(event)
    if len(accepted) != 1:
        raise ValueError('compiled-F4-storage-native-transfer-missing')
    pre = accepted[0]
    backend = pre['outputs']['backend']
    observed = pre['outputs']['storage_probes']
    if (type(pre.get('local_tick')) is not int or pre['local_tick'] < 1
            or pre.get('reset_epoch') != reset_epoch
            or pre.get('observation_schema_version') != 'ip_raw_observation.v1'):
        raise ValueError('compiled-F4-storage-native-transfer-mismatch')
    for name, width in PROBE_WIDTHS.items():
        if (type(observed[name]) is not int
                or not 0 <= observed[name] < 1 << width):
            raise ValueError('compiled-F4-storage-storage-probe-width')
    if (backend.get(signals['pslverr']) != 0
            or observed['storage_pslverr'] != 0
            or observed['storage_pready'] != 1):
        raise ValueError('compiled-F4-storage-native-transfer-mismatch')
    for role in ('paddr', 'psel', 'penable', 'pwrite', 'pwdata', 'prdata',
                 'pready', 'pslverr'):
        if observed['storage_' + role] != backend.get(signals[role]):
            raise ValueError(
                'compiled-F4-storage-storage-probe-trace-mismatch')
    if observed['storage_paddr'] & ALIAS_MASK != ALIAS_VALUE:
        raise ValueError('compiled-F4-storage-alias-mismatch')
    if observed['storage_paddr'] % 4:
        raise ValueError('compiled-F4-storage-alias-mismatch')
    if observed['storage_reset'] not in (0, 1):
        raise ValueError('compiled-F4-storage-reset-level')
    if expected_write:
        if observed['storage_pwdata'] != value:
            raise ValueError(
                'compiled-F4-storage-native-write-value-mismatch')
    else:
        if observed['storage_prdata'] != value:
            raise ValueError(
                'compiled-F4-storage-native-read-value-mismatch')
    posts = [e for e in rows if e.get('phase') == 'post'
             and e.get('local_tick') == pre['local_tick']
             and e.get('reset_epoch') == reset_epoch
             and isinstance(e.get('outputs'), dict)
             and isinstance(e['outputs'].get('storage_probes'), dict)
             and set(e['outputs']['storage_probes']) == set(PROBE_WIDTHS)]
    if len(posts) != 1:
        raise ValueError('compiled-F4-storage-native-post-sample-missing')
    post = posts[0]
    if post['outputs']['storage_probes']['storage_reset'] != observed['storage_reset']:
        raise ValueError('compiled-F4-storage-reset-level')
    return pre, post, deepcopy(observed), deepcopy(
        post['outputs']['storage_probes'])


def _check_commit(commit, *, before, access, value, writes_all, delivery, pre,
                  post, probes_pre, probes_post, target):
    if (not isinstance(commit, dict) or set(commit) != COMMIT_KEYS
            or not isinstance(commit.get('context'), dict)
            or not isinstance(commit.get('raw_reference'), dict)):
        raise ValueError('compiled-F4-storage-commit-shape')
    context = commit['context']
    reference = commit['raw_reference']
    if (set(context) != CONTEXT_KEYS
            or set(reference) != RAW_REFERENCE_KEYS
            or any(type(commit[key]) is not int for key in
                   ('tick', 'raw_address', 'before', 'after', 'sample_index',
                    'command_sequence'))
            or any(not 0 <= commit[key] <= FULL_MASK
                   for key in ('before', 'after'))
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
            or context['schema_version']
            != 'apb_storage_routed_context.v1'):
        raise ValueError('compiled-F4-storage-commit-shape')
    transaction = context['source_transaction']
    if (not isinstance(transaction, dict)
            or set(transaction) != TRANSACTION_KEYS
            or transaction != delivery.get('source_transaction')):
        raise ValueError('compiled-F4-storage-commit-context-mismatch')
    if (context['device_id'] != access['device_id']
            or context['window_base'] != access['window_base']
            or context['window_size'] != access['window_size']
            or context['address'] != access['address']
            or context['offset'] != access['register_offset']
            or context['value'] != value or context['be'] != 15):
        raise ValueError('compiled-F4-storage-commit-context-mismatch')
    if context['reset_epoch'] != before['reset_epoch']:
        raise ValueError('compiled-F4-storage-commit-epoch-mismatch')
    if context['execution'] != target._execution:
        raise ValueError('compiled-F4-storage-commit-process-mismatch')
    if reference['execution'] != context['execution']:
        raise ValueError('compiled-F4-storage-commit-process-mismatch')
    if (context['command_sequence'] != commit['command_sequence']
            or reference['sequence'] != commit['command_sequence']
            or reference['sample_index'] != commit['sample_index']):
        raise ValueError('compiled-F4-storage-commit-sequence-mismatch')
    if commit['tick'] != pre['local_tick'] or post['local_tick'] != commit['tick']:
        raise ValueError('compiled-F4-storage-commit-tick-mismatch')
    if (commit['raw_address'] & ALIAS_MASK != ALIAS_VALUE
            or commit['raw_address'] % 4
            or not 0 <= commit['raw_address'] < access['window_size']
            or commit['raw_address'] != probes_pre['storage_paddr']):
        raise ValueError('compiled-F4-storage-commit-alias-mismatch')
    if (commit['before'] != before['value']
            or commit['after'] != value
            or commit['before'] != probes_pre['storage_value']
            or commit['after'] != probes_post['storage_value']):
        raise ValueError('compiled-F4-storage-commit-value-mismatch')
    if commit is not writes_all[-1]:
        raise ValueError('compiled-F4-storage-commit-identity-mismatch')
    return deepcopy(commit)


def check_storage_observation(declaration, receipt, *, target_artifact, authority,
                              token, register, reset_epoch, before, prior_writes):
    """Consume one actual generic APB storage F4 chain, or refuse by name.

    The event chain and the C-owned write journal are checked before the
    opaque token is consumed.  A serialized witness, a readback or the current
    register value can never replace it.
    """
    _check_pins()
    if type(authority) is not ApbStorageRegisterVersionAuthority:
        raise ValueError('compiled-F4-storage-authority-required')
    if type(token) is not object:
        raise ValueError('compiled-F4-storage-token-required')
    if (type(register) is not str or not register
            or type(reset_epoch) is not int or reset_epoch < 0
            or type(prior_writes) is not int or prior_writes < 0):
        raise ValueError('compiled-F4-storage-argument-required')
    if not isinstance(target_artifact, LocalRuntimeArtifact):
        raise ValueError('compiled-F4-storage-artifact-required')
    target = getattr(authority, 'target', None)
    if target is None or getattr(target, 'artifact', None) is not target_artifact:
        raise ValueError('compiled-F4-storage-authority-artifact-mismatch')
    document = target_artifact.runtime_document
    if document.get('kind') != 'apb3_register_observe':
        raise ValueError('compiled-F4-storage-artifact-kind-required')
    observation = document.get('storage_observation')
    ports = document.get('storage_probe_ports')
    if (not isinstance(observation, dict)
            or observation.get('schema_version') != 'apb_storage_probe.v1'
            or observation.get('scope')
            != 'generated_expression_source_mapped'
            or observation.get('sample_group') != 'storage_probes'
            or any(observation.get(key) is not False for key in
                   ('reset_authority', 'version_authority',
                    'source_authority'))
            or not isinstance(observation.get('source_contract'), dict)
            or not isinstance(ports, list) or len(ports) != len(PROBE_WIDTHS)
            or any(not isinstance(row, dict)
                   or row.get('name') not in PROBE_WIDTHS
                   or row.get('width') != PROBE_WIDTHS[row['name']]
                   or row.get('direction') != 'output' for row in ports)
            or {row['name'] for row in ports} != set(PROBE_WIDTHS)):
        raise ValueError(
            'compiled-F4-storage-observation-contract-mismatch')
    contract = observation['source_contract']
    if (contract.get('contract_id')
            != observation.get('selection', {}).get('contract_id')
            or contract.get('scope') != 'source_reviewed_contract'
            or any(contract.get(key) is not False for key in
                   ('authority', 'source_authority', 'native_verified',
                    'hierarchy_verified', 'reset_authority',
                    'version_authority'))
            or not isinstance(contract.get('register'), dict)
            or contract['register'].get('name') != register
            or contract['register'].get('width') != 32
            or contract['register'].get('canonical_offset') != ALIAS_VALUE
            or contract['register'].get('write_mask') != FULL_MASK
            or not isinstance(contract.get('decode'), dict)
            or contract['decode'].get('mask') != ALIAS_MASK
            or contract['decode'].get('value') != ALIAS_VALUE):
        raise ValueError(
            'compiled-F4-storage-observation-contract-mismatch')
    try:
        # Prospective (false) observations pass with no evidence.  Verified
        # observations must carry a digest-bound native hierarchy proof; a
        # bare flag flip or a tampered evidence reference is refused here.
        verified_storage_observation(observation,
            runtime_sv=target_artifact.runtime_sv,
            wrapper_sha256=(document.get('structural_build') or {}).get(
                'wrapper_sha256'),
            base_dir=Path(__file__).resolve().parents[3])
    except ValueError as error:
        raise ValueError(
            'compiled-F4-storage-observation-contract-mismatch') from error
    access, value = _check_declaration(
        declaration, target_artifact=target_artifact, register=register)
    if target.reset_epoch != reset_epoch:
        raise ValueError('compiled-F4-storage-epoch-mismatch')
    _check_before(before, prior_writes=prior_writes, register=register)
    if (before['reset_epoch'] != reset_epoch
            or before['artifact_digest'] != document.get('artifact_digest')
            or before['source_contract_digest'] != contract.get('digest')
            or before['probe_digest'] != observation.get('digest')):
        raise ValueError('compiled-F4-storage-before-witness-mismatch')
    if verify_apb_register_trace(target_artifact) is not True:
        raise ValueError(
            'compiled-F4-storage-native-APB-observation-required')
    trace = document.get('base_protocol_trace')
    signals = trace.get('signals') if isinstance(trace, dict) else None
    if (not isinstance(trace, dict) or trace.get('protocol') != 'apb3'
            or not isinstance(signals, dict) or set(signals) != TRACE_ROLES
            or trace.get('signal_widths', {}).get('paddr')
            != PROBE_WIDTHS['storage_paddr']):
        raise ValueError(
            'compiled-F4-storage-native-APB-observation-required')
    receipt_events = getattr(receipt, 'events', None)
    case_id = getattr(receipt, 'case_id', None)
    # OnlineCaseReceipt.events is a tuple in real runs; a plain list is also
    # accepted.  Membership and per-event content are still checked.
    if (not isinstance(receipt_events, (list, tuple)) or not receipt_events
            or any(not isinstance(row, dict) for row in receipt_events)
            or type(case_id) is not str or not case_id):
        raise ValueError('compiled-F4-storage-receipt-required')
    source = access['source_component']
    target_component = access['target_component']
    address = access['address']
    offset = access['register_offset']
    deliveries = [e for e in receipt_events
                  if e.get('kind') == 'mmio_delivery'
                  and e.get('component') == source
                  and e.get('device_id') == access['device_id']
                  and e.get('address') == address]
    writes = [e for e in deliveries if e.get('write') is True
              and e.get('write_value') == value
              and e.get('byte_enable') == 15]
    if len(writes) != 1:
        raise ValueError('compiled-F4-storage-delivery-count')
    write_delivery = writes[0]
    reads = [e for e in deliveries if e.get('write') is False
             and e.get('read_value') == value
             and e.get('event_id', 0) > write_delivery['event_id']]
    if len(reads) != 1:
        raise ValueError('compiled-F4-storage-delivery-count')
    read_delivery = reads[0]
    write_acceptance = _join_delivery(
        receipt_events, delivery=write_delivery, component=source,
        device=access['device_id'], address=address, offset=offset, write=True)
    read_acceptance = _join_delivery(
        receipt_events, delivery=read_delivery, component=source,
        device=access['device_id'], address=address, offset=offset, write=False)
    if (write_delivery['source_transaction'].get('source_sequence') + 1
            != read_delivery['source_transaction'].get('source_sequence')):
        raise ValueError('compiled-F4-storage-sequence-mismatch')
    for key in ('execution_id', 'testcase_id', 'source_component',
                'source_epoch'):
        if (write_delivery['source_transaction'].get(key)
                != read_delivery['source_transaction'].get(key)):
            raise ValueError('compiled-F4-storage-sequence-mismatch')
    write_pre, write_post, write_probes, write_post_probes = _transfer_samples(
        receipt_events, delivery=write_delivery, component=target_component,
        signals=signals, expected_write=True, offset=offset, value=value,
        reset_epoch=reset_epoch)
    read_pre, read_post, read_probes, read_post_probes = _transfer_samples(
        receipt_events, delivery=read_delivery, component=target_component,
        signals=signals, expected_write=False, offset=offset, value=value,
        reset_epoch=reset_epoch)
    if write_pre['local_tick'] >= read_pre['local_tick']:
        raise ValueError('compiled-F4-storage-sequence-mismatch')
    if write_post['event_id'] >= read_acceptance['event_id']:
        raise ValueError('compiled-F4-storage-sequence-mismatch')
    if (write_probes['storage_value'] != before['value']
            or write_post_probes['storage_value'] != value
            or read_probes['storage_value'] != value
            or read_post_probes['storage_value'] != value):
        raise ValueError(
            'compiled-F4-storage-storage-transition-mismatch')
    ram = [e for e in receipt_events if e.get('kind') == 'memory_write'
           and e.get('component') == source
           and e.get('address') == declaration['result_address']
           and e.get('value') == value and e.get('byte_enable') == 15
           and e.get('event_id', 0) > read_delivery['event_id']]
    if len(ram) != 1:
        raise ValueError('compiled-F4-storage-readback-RAM-mismatch')
    writes_all = authority.writes()
    if (not isinstance(writes_all, list)
            or len(writes_all) != prior_writes + 1
            or any(not isinstance(row, dict) for row in writes_all)):
        raise ValueError('compiled-F4-storage-commit-count')
    if (before['write_history_sha256'] != _digest(writes_all[:prior_writes])
            or before['write_count'] != prior_writes):
        raise ValueError('compiled-F4-storage-before-history-mismatch')
    commit = _check_commit(writes_all[prior_writes], before=before,
        access=access, value=value, writes_all=writes_all,
        delivery=write_delivery, pre=write_pre, post=write_post,
        probes_pre=write_probes, probes_post=write_post_probes, target=target)
    witness = authority.consume(token)
    if not isinstance(witness, dict) or set(witness) != WITNESS_KEYS:
        raise ValueError('compiled-F4-storage-witness-shape')
    if (witness['register'] != register
            or witness['reset_epoch'] != reset_epoch
            or witness['value'] != value
            or witness['write_count'] != prior_writes + 1
            or witness['field_version'] != prior_writes + 1
            or witness['version_basis'] != VERSION_BASIS
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
        raise ValueError('compiled-F4-storage-witness-mismatch')
    if (target.process is None or target.process.poll() is not None
            or witness['pid'] != target.process.pid):
        raise ValueError(
            'compiled-F4-storage-witness-process-mismatch')
    if (witness['execution'] != target._execution
            or witness['local_tick'] != target.local_ticks
            or witness['command_sequence'] != target._sequence):
        raise ValueError('compiled-F4-storage-witness-scope-mismatch')
    if witness['command_sequence'] <= commit['command_sequence']:
        raise ValueError(
            'compiled-F4-storage-witness-sequence-mismatch')
    if witness['local_tick'] <= read_pre['local_tick']:
        raise ValueError('compiled-F4-storage-witness-tick-mismatch')
    if (witness['artifact_digest'] != document['artifact_digest']
            or witness['source_contract_digest'] != contract.get('digest')
            or witness['probe_digest'] != observation.get('digest')
            or witness['producer_source_sha256']
            != _digest_source(ApbStorageRegisterVersionAuthority)):
        raise ValueError('compiled-F4-storage-witness-source-mismatch')
    if (before['pid'] != witness['pid']
            or before['execution'] != witness['execution']):
        raise ValueError('compiled-F4-storage-witness-process-mismatch')
    joins = [
        dict(delivery_event=write_delivery['event_id'],
             acceptance_event=write_acceptance['event_id'],
             native_APB_event=write_pre['event_id'],
             native_post_event=write_post['event_id'],
             source_transaction=deepcopy(
                 write_delivery['source_transaction']),
             write=True, tick=write_pre['local_tick']),
        dict(delivery_event=read_delivery['event_id'],
             acceptance_event=read_acceptance['event_id'],
             native_APB_event=read_pre['event_id'],
             native_post_event=read_post['event_id'],
             source_transaction=deepcopy(
                 read_delivery['source_transaction']),
             write=False, tick=read_pre['local_tick'])]
    public_commit = dict(schema_version=COMMIT_SCHEMA,
        tick=commit['tick'], before=commit['before'], after=commit['after'],
        epoch=commit['context']['reset_epoch'],
        command_sequence=commit['command_sequence'],
        raw_address=commit['raw_address'],
        sample_index=commit['sample_index'], phase=commit['phase'],
        context={key: deepcopy(commit['context'][key]) for key in (
            'source_transaction', 'device_id', 'window_base', 'window_size',
            'address', 'offset', 'write', 'value', 'be', 'reset_epoch',
            'command_sequence', 'schema_version', 'source_authenticated')},
        raw_reference={key: deepcopy(commit['raw_reference'][key]) for key in
                       ('sequence', 'sample_index', 'phase')},
        field_version=witness['field_version'],
        write_count=witness['write_count'],
        version_basis=witness['version_basis'])
    after = stable_storage_version(witness)
    observed = dict(schema_version=OBSERVATION_SCHEMA, case_id=case_id,
        value=value, address=address, offset=offset, register=register,
        runtime_admitted=False,
        proof_scope=('CPU_data_acceptance_router_delivery_native_APB_pre_'
                     'live_storage_version_and_CPU_readback_RAM'),
        joins=joins, commit=deepcopy(public_commit),
        native_samples=dict(
            write=dict(accepted_event=write_pre['event_id'],
                       post_event=write_post['event_id'],
                       tick=write_pre['local_tick'],
                       value_before=write_probes['storage_value'],
                       value_after=write_post_probes['storage_value']),
            read=dict(accepted_event=read_pre['event_id'],
                      post_event=read_post['event_id'],
                      tick=read_pre['local_tick'],
                      value_observed=read_probes['storage_value'])),
        storage_probes=dict(
            write=dict(pre=write_probes, post=write_post_probes),
            read=dict(pre=read_probes, post=read_post_probes)),
        RAM_event=ram[0]['event_id'],
        version_witness=deepcopy(witness),
        token=dict(schema_version='apb_storage_register_version_token.v1',
                   consumed=True, single_use=True, opaque=True,
                   issuer=_qualified(ApbStorageRegisterVersionAuthority),
                   register=register, reset_epoch=reset_epoch,
                   write_count=prior_writes + 1))
    return observed, public_commit, after


def storage_consumer_support(*, binding, artifacts):
    """Source-level completeness of the four receipt joins of the generic row.

    Every element is a code/declaration identity fact.  The live token itself
    can only be obtained from an actual native build, so this report never
    grants runtime admission.
    """
    _check_pins()
    from myfuzz.integration.compiled_storage_producer import (
        AdmittedStorageProducerBinding, ROW_GENERIC_APB_STORAGE)
    if type(binding) is not AdmittedStorageProducerBinding:
        raise ValueError('compiled-F4-storage-consumer-binding-required')
    document = binding.document()
    if document.get('row') != ROW_GENERIC_APB_STORAGE:
        raise ValueError('compiled-F4-storage-consumer-row-required')
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
        == _digest_source(check_storage_observation)
        and _CONSUMER_PIN[0] is check_storage_observation
        and _CONSUMER_PIN[1] is check_storage_observation.__code__)
    artifact = artifacts.get(target) if isinstance(artifacts, dict) else None
    runtime = (artifact.runtime_document
               if isinstance(artifact, LocalRuntimeArtifact) else {})
    probe = runtime.get('storage_observation')
    trace = runtime.get('base_protocol_trace')
    ports = runtime.get('storage_probe_ports')
    probe_ok = (
        isinstance(artifact, LocalRuntimeArtifact)
        and runtime.get('kind') == 'apb3_register_observe'
        and runtime.get('artifact_digest')
        == document.get('target_artifact_digest')
        and isinstance(probe, dict)
        and isinstance(document.get('probe'), dict)
        and probe.get('digest') == document['probe'].get('digest')
        and isinstance(probe.get('source_contract'), dict)
        and probe['source_contract'].get('digest')
        == document['probe'].get('source_contract_digest')
        and isinstance(trace, dict) and trace.get('protocol') == 'apb3'
        and set(trace.get('signals') or {}) == TRACE_ROLES
        and isinstance(ports, list) and len(ports) == len(PROBE_WIDTHS)
        and {row.get('name') for row in ports if isinstance(row, dict)}
        == set(PROBE_WIDTHS)
        and all(row.get('width') == PROBE_WIDTHS[row['name']]
                for row in ports)
        and isinstance(probe['source_contract'].get('register'), dict)
        and probe['source_contract']['register'].get('name')
        == register.get('name')
        and probe['source_contract']['register'].get('canonical_offset')
        == register.get('offset'))
    delivery_ok = (
        consumer_ok and isinstance(bound, dict)
        and bound.get('kind') == 'ip_register_commit'
        and bound.get('component') == target
        and bound.get('endpoint_id') == endpoint
        and bound.get('input_id')
        == f'{target}.{endpoint}.register.{register.get("name")}.value'
        and type(register.get('address')) is int
        and document.get('protocol') == ['apb', '3']
        and document.get('template') == {
            'template_id': 'target.apb3', 'template_version': '1',
            'variant_id': 'full-word'}
        and document.get('target_artifact_kind') == 'apb3_register_observe')
    token_ok = (
        producer.get('issuer_class')
        == _qualified(ApbStorageRegisterVersionAuthority)
        and producer.get('issuer_source_sha256')
        == _digest_source(ApbStorageRegisterVersionAuthority)
        and producer.get('version_issuance')
        == 'ApbStorageRegisterVersionAuthority.issue/consume/writes'
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
              'native_apb_pre_sample': probe_ok,
              'version_token': token_ok}
    refusals = [dict(code='compiled-F4-storage-receipt-join-incomplete',
                     element=name) for name in RECEIPT_ELEMENTS
                if not states[name]]
    complete = not refusals
    return dict(schema_version=SUPPORT_SCHEMA, complete=complete,
        disposition=('supported_requires_actual_startup' if complete
                     else 'unsupported'),
        row=document.get('row'), consumer=CONSUMER_QUALNAME,
        receipt_elements=list(RECEIPT_ELEMENTS),
        elements={name: dict(present=bool(states[name]),
                             basis=ELEMENT_BASIS[name])
                  for name in RECEIPT_ELEMENTS},
        refusals=refusals, runtime_admitted=False,
        authority_scope=('source_code_identity_only_live_token_requires_'
                         'actual_startup'))


_PINNED_VERIFY = (verify_apb_register_trace,
                  verify_apb_register_trace.__code__)
_PINNED_ISSUER = (ApbStorageRegisterVersionAuthority,
                  ApbStorageRegisterVersionAuthority.consume.__code__,
                  ApbStorageRegisterVersionAuthority.issue.__code__)
_CONSUMER_PIN = (check_storage_observation, check_storage_observation.__code__)
_SUPPORT_PIN = (storage_consumer_support, storage_consumer_support.__code__)


def _check_pins():
    import myfuzz.local_harness.native_physical_observation as observation_module
    import myfuzz.scenario.apb_storage_register_version as version_module
    if (_CONSUMER_PIN[0] is not check_storage_observation
            or _CONSUMER_PIN[1] is not check_storage_observation.__code__
            or _SUPPORT_PIN[0] is not storage_consumer_support
            or _SUPPORT_PIN[1] is not storage_consumer_support.__code__
            or _PINNED_VERIFY[0] is not verify_apb_register_trace
            or _PINNED_VERIFY[1] is not verify_apb_register_trace.__code__
            or observation_module.verify_apb_register_trace
            is not _PINNED_VERIFY[0]
            or getattr(version_module, 'ApbStorageRegisterVersionAuthority',
                       None) is not _PINNED_ISSUER[0]
            or _PINNED_ISSUER[0].consume.__code__ is not _PINNED_ISSUER[1]
            or _PINNED_ISSUER[0].issue.__code__ is not _PINNED_ISSUER[2]):
        raise ValueError('compiled-F4-storage-consumer-drift')
