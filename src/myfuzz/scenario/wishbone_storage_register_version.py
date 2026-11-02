"""Process-local, single-use Wishbone storage version witnesses.

Sibling of :mod:`myfuzz.scenario.apb_storage_register_version` for the G8.1
Wishbone row.  A pure reducer, a serialized write record, a bus readback or the
current register value are never a version: only an opaque token issued here,
in this process, may be consumed once.

The row is ``zipcpu-wbuart.setup.storage.v1``: word index 0 of a 16-byte
window, full-word accesses only (``sel == 15``).  The routed context is a
``wishbone_storage_routed_context.v1`` record whose source transaction,
address, word index, write, byte enable, read value and tick are all checked
against the command that carried it.

The native producer hook now exists for the routed path: a real
``GeneratedWishboneRegisterSession`` calls ``_actual_begin``/``_actual_command``
around every generated command, the first actual command binds the exact built
executable receipt, and every ``ACCESS_WB_REG`` is reduced from all of its
native pre/post ``storage_probes`` samples (cross-checked against the same-tick
``backend`` trace signals).  An access that carries no routed context is still
an ordinary target command: its measured state is tracked but it never enters
the commit journal, and because the declared write history would then be
incomplete ``issue`` refuses with
``wishbone-storage-version-history-incomplete``.  ``issue``/``consume`` still
fail closed at ``wishbone-storage-version-actual-native-build-required`` when
no such build was bound.  This module never grants reset, source or runtime
admission.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from types import MappingProxyType
from weakref import WeakKeyDictionary

from myfuzz.local_harness import (
    wishbone_storage_source_contract as _source_contract_module)
from myfuzz.local_harness.wishbone_storage_probe_contract import (
    AUTHORITY_FLAGS, ROLES, SAMPLE_GROUP, SCHEMA_VERSION, SCOPE,
    wishbone_probe_widths, wishbone_storage_probe_digest)
from myfuzz.local_harness.wishbone_storage_source_contract import (
    validate_wishbone_storage_source_contract)

WISHBONE_STORAGE_CONTEXT_SCHEMA = 'wishbone_storage_routed_context.v1'
WISHBONE_STORAGE_VERSION_SCHEMA = 'wishbone_storage_register_version.v1'
HISTORY_SCOPE = ('complete_commands_since_first_measured_state_'
                 'not_unobserved_startup')
ACCESS_OPERATION = 'ACCESS_WB_REG'
STEP_OPERATION = 'STEP_WB_REG'
SOURCE_OPERATION = 'SOURCE_WB_REG'
BIND_OPERATION = 'BIND_WB_REG'
_ACTUAL_OPERATIONS = frozenset({ACCESS_OPERATION, STEP_OPERATION,
                                SOURCE_OPERATION, BIND_OPERATION})
_BUILT_RECEIPT_SCHEMA = 'local_harness_built_receipt.v1'
_BUILD_KEYS = frozenset({'build_digest', 'artifact_digest', 'binary_sha256'})
_PROBE_NAMES = frozenset({'storage_value', 'storage_reset'}) | frozenset(
    'storage_' + role for role in ROLES)
_READ_SELECTS = (0, 15)
_TRANSACTION_KEYS = frozenset({
    'execution_id', 'testcase_id', 'source_component', 'source_epoch',
    'channel_id', 'source_sequence'})
WISHBONE_STORAGE_CONTEXT_KEYS = frozenset({
    'source_transaction', 'device_id', 'window_base', 'window_size', 'address',
    'offset', 'word_index', 'write', 'value', 'read_value', 'byte_enable',
    'tick', 'execution', 'reset_epoch', 'command_sequence', 'schema_version',
    'source_authenticated'})
#: A routed command can state every field but the measured sample ``tick``.
_PENDING_CONTEXT_KEYS = frozenset(WISHBONE_STORAGE_CONTEXT_KEYS - {'tick'})
WITNESS_KEYS = frozenset({
    'register', 'value', 'local_tick', 'write_history_sha256', 'field_version',
    'write_count', 'version_basis', 'reset_epoch', 'command_sequence', 'pid',
    'execution', 'build_identity_sha256', 'producer_source_sha256',
    'artifact_digest', 'source_contract_digest', 'probe_digest',
    'reset_waveform_observed', 'grants_reset_prerequisite', 'history_scope',
    'routed_context_authenticated'})

_SOURCE_FUNCTIONS = MappingProxyType({
    name: (getattr(_source_contract_module, name),
           getattr(_source_contract_module, name).__code__)
    for name in ('validate_wishbone_storage_source_contract',
                 '_require_registered_document', '_registered_document')})


@dataclass(frozen=True, slots=True)
class _StorageFacts:
    digest: str
    register: str
    width: int
    reset_value: int
    write_mask: int
    word_index: int
    address_width: int
    decode_mask: int
    decode_value: int
    window_bytes: int
    host_alignment: int


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def _digest(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _source_facts(document=None):
    """Pure closed-registry facts; this never grants native authority."""
    if document is None:
        document = _SOURCE_FUNCTIONS['_registered_document'][0]()
    contract = _SOURCE_FUNCTIONS['_require_registered_document'][0](document)
    register, decode = contract['register'], contract['decode']
    return _StorageFacts(
        contract['digest'], register['name'], register['width'],
        register['reset_value'], register['write_mask'], register['word_index'],
        decode['address_width'], decode['mask'], decode['value'],
        decode['window_bytes'], decode['host_alignment_bytes'])


def wishbone_storage_version_basis(register):
    return (f'all_measured_{register.rsplit("_", 1)[-1]}_word_writes_'
            'since_first_command')


_HEX64 = re.compile(r'[0-9a-f]{64}\Z')


def _hex64(value):
    return type(value) is str and _HEX64.fullmatch(value) is not None


@dataclass(frozen=True, slots=True)
class _WishboneTransfer:
    request_index: int
    request_tick: int
    request: dict
    post: dict
    ack: dict
    ack_post: dict


def _probe_row(sample, phase, widths, signals):
    """One observed phase: eleven probes, each equal to its same-phase trace."""
    observed = sample.get(phase) if type(sample) is dict else None
    if type(observed) is not dict:
        raise ValueError('wishbone-storage-version-sample-shape')
    probes = observed.get('storage_probes')
    backend = observed.get('backend')
    if (type(probes) is not dict or set(probes) != set(widths)
            or type(backend) is not dict):
        raise ValueError('wishbone-storage-version-sample-shape')
    for name, width in widths.items():
        value = probes[name]
        if type(value) is not int or not 0 <= value < 1 << width:
            raise ValueError('wishbone-storage-version-probe-width')
    for role in ROLES:
        name = 'storage_' + role
        traced = backend.get(signals[role])
        if (type(traced) is not int or not 0 <= traced < 1 << widths[name]
                or probes[name] != traced):
            raise ValueError('wishbone-storage-version-probe-trace-mismatch')
    return probes


def _analyse_wishbone_transfer(samples, *, first_tick, write, word_index,
                               value, rdata, signals, widths):
    """Recompute one registered-ACK word transfer from every native sample.

    The request first appears in a ``post`` phase, so only ``pre`` phases are
    searched for the accepted request (exactly one) and for the sustained ACK
    (exactly one).  A stalled accept, a missing or duplicate ACK pulse, a
    foreign word index/select, a reset level or a probe/trace disagreement is a
    named refusal, never a pass.
    """
    if (type(samples) is not list or not samples or type(write) is not bool
            or type(first_tick) is not int or first_tick < 1
            or any(type(number) is not int
                   for number in (word_index, value, rdata))
            or not 0 <= value <= 0xffffffff or not 0 <= rdata <= 0xffffffff
            or type(signals) is not dict or set(signals) != set(ROLES)
            or type(widths) is not dict or set(widths) != _PROBE_NAMES):
        raise ValueError('wishbone-storage-version-sample-shape')
    rows = []
    for index, sample in enumerate(samples):
        tick = sample.get('local_tick') if type(sample) is dict else None
        if type(tick) is not int or tick < 1:
            raise ValueError('wishbone-storage-version-sample-shape')
        if rows:
            if tick != rows[-2][1] + 1:
                raise ValueError('wishbone-storage-version-sample-tick')
        elif tick != first_tick:
            raise ValueError('wishbone-storage-version-sample-tick')
        rows.append((index, tick, 'pre',
                     _probe_row(sample, 'pre', widths, signals)))
        rows.append((index, tick, 'post',
                     _probe_row(sample, 'post', widths, signals)))
    requests = [row for row in rows
                if row[2] == 'pre' and row[3]['storage_cyc'] == 1
                and row[3]['storage_stb'] == 1
                and row[3]['storage_we'] == int(write)]
    if len(requests) != 1:
        raise ValueError('wishbone-storage-version-native-transfer-missing')
    request_index, request_tick, _, request = requests[0]
    if request['storage_stall'] != 0:
        raise ValueError('wishbone-storage-version-stall-observed')
    if request['storage_ack'] != 0 or request['storage_reset'] != 0:
        raise ValueError('wishbone-storage-version-protocol-mismatch')
    if request['storage_adr'] != word_index:
        raise ValueError('wishbone-storage-version-word-index-mismatch')
    if (request['storage_sel'] != 15 if write
            else request['storage_sel'] not in _READ_SELECTS):
        raise ValueError('wishbone-storage-version-select-mismatch')
    if write and request['storage_dat_w'] != value:
        raise ValueError('wishbone-storage-version-native-write-value-mismatch')
    posts = [row for row in rows
             if row[2] == 'post' and row[1] == request_tick]
    if len(posts) != 1:
        raise ValueError('wishbone-storage-version-native-post-sample-missing')
    post = posts[0][3]
    if post['storage_stall'] != 0:
        raise ValueError('wishbone-storage-version-stall-observed')
    if (post['storage_cyc'] != 1 or post['storage_stb'] != 0
            or post['storage_ack'] != 0 or post['storage_reset'] != 0):
        raise ValueError('wishbone-storage-version-protocol-mismatch')
    # ACK is registered and deasserts inside the same command: exactly one
    # contiguous assertion across the ordered phase stream.  A missing, a
    # duplicated or a never-released ACK is a refusal, never a pass.
    level = 0
    rises = falls = 0
    for row in rows:
        current = row[3]['storage_ack']
        if level == 0 and current == 1:
            rises += 1
        elif level == 1 and current == 0:
            falls += 1
        level = current
    if rises != 1:
        raise ValueError('wishbone-storage-version-duplicate-ack' if rises
                         else 'wishbone-storage-version-missing-ack')
    if falls != 1:
        raise ValueError('wishbone-storage-version-ack-release-missing')
    acked = [row for row in rows
             if row[2] == 'pre' and row[1] > request_tick
             and row[3]['storage_ack'] == 1]
    if not acked:
        raise ValueError('wishbone-storage-version-missing-ack')
    if len(acked) != 1:
        raise ValueError('wishbone-storage-version-duplicate-ack')
    _, ack_tick, _, ack = acked[0]
    if ack['storage_stall'] != 0:
        raise ValueError('wishbone-storage-version-stall-observed')
    if (ack['storage_cyc'] != 1 or ack['storage_stb'] != 0
            or ack['storage_reset'] != 0):
        raise ValueError('wishbone-storage-version-protocol-mismatch')
    for row in rows:
        if request_tick < row[1] < ack_tick and (
                row[3]['storage_cyc'] != 1 or row[3]['storage_stall'] != 0):
            raise ValueError('wishbone-storage-version-protocol-mismatch')
    ack_posts = [row for row in rows
                 if row[2] == 'post' and row[1] == ack_tick]
    if len(ack_posts) != 1:
        raise ValueError('wishbone-storage-version-native-post-sample-missing')
    ack_post = ack_posts[0][3]
    if ack_post['storage_stall'] != 0:
        raise ValueError('wishbone-storage-version-stall-observed')
    if write:
        if (post['storage_value'] != value or ack['storage_value'] != value
                or ack_post['storage_value'] != value):
            raise ValueError(
                'wishbone-storage-version-storage-transition-mismatch')
    else:
        if post['storage_value'] != request['storage_value']:
            raise ValueError(
                'wishbone-storage-version-storage-transition-mismatch')
        if (ack['storage_dat_r'] != rdata
                or ack['storage_value'] != rdata):
            raise ValueError(
                'wishbone-storage-version-native-read-value-mismatch')
    return _WishboneTransfer(request_index, request_tick, deepcopy(request),
                             deepcopy(post), deepcopy(ack),
                             deepcopy(ack_post))


def validate_wishbone_storage_scope(state, scope, *, process, execution, epoch,
                                    tick_base, sequence, tick,
                                    allow_initial=False):
    """Pure consistency guard, not native eligibility or an issuance API."""
    if (type(allow_initial) is not bool or process is None
            or type(execution) is not str or not execution
            or any(type(value) is not int or value < 0
                   for value in (epoch, tick_base, sequence, tick))):
        raise ValueError('wishbone-storage-version-scope-types')
    current = (process, execution, epoch, tick_base)
    if state is None:
        if (not allow_initial or scope is not None or sequence != 0
                or tick != tick_base):
            raise ValueError('wishbone-storage-version-history-unavailable')
        return
    if (type(state) is not dict or type(scope) is not tuple or len(scope) != 4
            or scope[0] is not process or scope != current
            or state.get('sequence') != sequence or state.get('tick') != tick):
        raise ValueError('wishbone-storage-version-current-scope-drift')


def validate_routed_context(context, *, operation, fields, sequence, execution,
                            epoch, window):
    """Typed correlation only, never proof of a Router/ledger source producer.

    A step carries no bus access and therefore no context.  An access must
    carry exactly the ``wishbone_storage_routed_context.v1`` record that the
    command fields imply: the same write/offset/value/``sel=15``, the same
    byte-address window, the derived word index, the same source transaction,
    and the same execution/epoch/command sequence.  Anything malformed or
    foreign is refused by name rather than partially accepted.
    """
    if context is None:
        if operation != STEP_OPERATION:
            raise ValueError('wishbone-storage-context-required')
        return None
    if operation != ACCESS_OPERATION:
        raise ValueError('wishbone-storage-context-command-mismatch')
    if (type(context) is not dict
            or set(context) != WISHBONE_STORAGE_CONTEXT_KEYS):
        raise ValueError('wishbone-storage-context-shape')
    transaction = context['source_transaction']
    if (type(transaction) is not dict or set(transaction) != _TRANSACTION_KEYS
            or any(type(transaction[key]) is not str or not transaction[key]
                   for key in ('execution_id', 'testcase_id',
                               'source_component', 'channel_id'))
            or any(type(transaction[key]) is not int or transaction[key] < 0
                   for key in ('source_epoch', 'source_sequence'))):
        raise ValueError('wishbone-storage-context-transaction-types')
    if type(sequence) is not int or sequence < 0 or type(epoch) is not int \
            or epoch < 0 or type(window) is not int or not 4 <= window <= 4096 \
            or window % 4:
        raise ValueError('wishbone-storage-context-command-mismatch')
    if (type(fields) is not tuple or len(fields) != 4
            or any(type(value) is not int for value in fields)
            or fields[0] not in (0, 1) or fields[3] != 15):
        raise ValueError('wishbone-storage-context-command-mismatch')
    write = bool(fields[0])
    if (type(context['write']) is not bool or context['write'] is not write
            or type(context['device_id']) is not str or not context['device_id']
            or context['schema_version'] != WISHBONE_STORAGE_CONTEXT_SCHEMA
            or context['source_authenticated'] is not False):
        raise ValueError('wishbone-storage-context-command-mismatch')
    integers = ('window_base', 'window_size', 'address', 'offset', 'word_index',
                'value', 'read_value', 'byte_enable', 'tick', 'reset_epoch',
                'command_sequence')
    if any(type(context[key]) is not int for key in integers):
        raise ValueError('wishbone-storage-context-command-mismatch')
    if (context['window_size'] != window or context['offset'] != fields[1]
            or context['value'] != fields[2]
            or context['byte_enable'] != fields[3]
            or not 0 <= context['window_base'] < 1 << 32
            or context['window_base'] + window > 1 << 32
            or not 0 <= context['offset'] < window or context['offset'] % 4
            or context['address'] != context['window_base'] + context['offset']
            or context['word_index'] != context['offset'] >> 2
            or not 0 <= context['word_index'] < window // 4
            or not 0 <= context['value'] <= 0xffffffff
            or not 0 <= context['read_value'] <= 0xffffffff
            or (context['read_value'] != 0 if write
                else context['value'] != 0)
            or context['tick'] < 0
            or context['execution'] != execution
            or type(context['execution']) is not str
            or context['reset_epoch'] != epoch
            or context['command_sequence'] != sequence):
        raise ValueError('wishbone-storage-context-command-mismatch')
    return deepcopy(context)


def validate_pending_routed_context(context, *, fields, sequence, execution,
                                    epoch, window):
    """Validate the routed context a command can know before its bus access.

    The measured ``tick`` of the accepted ``pre`` sample only exists after the
    command, so the pending record deliberately omits it.  Every other field is
    the same typed correlation :func:`validate_routed_context` enforces; a zero
    placeholder carries the tick (it is only required to be a non-negative
    integer) and is discarded again, so the placeholder can never be mistaken
    for a measurement.
    """
    if type(context) is not dict or set(context) != _PENDING_CONTEXT_KEYS:
        raise ValueError('wishbone-storage-context-shape')
    candidate = deepcopy(context)
    candidate['tick'] = 0
    validated = validate_routed_context(
        candidate, operation=ACCESS_OPERATION, fields=fields,
        sequence=sequence, execution=execution, epoch=epoch, window=window)
    validated.pop('tick')
    return validated


_ROUTED_VALIDATOR = (validate_routed_context, validate_routed_context.__code__)
_PENDING_VALIDATOR = (validate_pending_routed_context,
                      validate_pending_routed_context.__code__)
_TRANSFER = (_analyse_wishbone_transfer, _analyse_wishbone_transfer.__code__)
_SCOPE_VALIDATOR = (validate_wishbone_storage_scope,
                    validate_wishbone_storage_scope.__code__)
_FACT_FUNCTIONS = MappingProxyType({
    name: (value, value.__code__) for name, value in (
        ('_hex64', _hex64),
        ('_source_facts', _source_facts),
        ('wishbone_storage_version_basis', wishbone_storage_version_basis))})

_AUTHORITIES = WeakKeyDictionary()
_LIVE = WeakKeyDictionary()
_TOKENS = WeakKeyDictionary()
_REGISTRIES = (_AUTHORITIES, _LIVE, _TOKENS)


def wishbone_storage_authority(owner):
    """The exact registered issuer of this session object, or ``None``.

    The class identity is checked here so a caller never has to import a
    registry (and never the sibling APB module's registry) to route a command.
    """
    try:
        authority = _AUTHORITIES.get(owner)
    except TypeError as error:
        raise ValueError(
            'wishbone-storage-version-authority-owner-required') from error
    if authority is None:
        return None
    if type(authority) is not _TYPE:
        raise ValueError('wishbone-storage-version-authority-class-drift')
    return authority


def revoke_wishbone_storage_authority(owner):
    """Permanently poison the exact registered issuer of this session, if any."""
    authority = wishbone_storage_authority(owner)
    if authority is not None:
        authority._revoke()
    return authority


_LOOKUP_FUNCTIONS = MappingProxyType({
    name: (value, value.__code__) for name, value in (
        ('wishbone_storage_authority', wishbone_storage_authority),
        ('revoke_wishbone_storage_authority',
         revoke_wishbone_storage_authority))})


class WishboneStorageRegisterVersionAuthority:
    """One live, process-local issuer for a fresh Wishbone register session."""

    def __init__(self, target, *, max_samples=65536, max_writes=4096,
                 max_tokens=16):
        from myfuzz.local_harness.wishbone_register_session import (
            GeneratedWishboneRegisterSession)
        if (type(target) is not GeneratedWishboneRegisterSession
                or target.process is not None or target._case_id is not None
                or target._execution or target.reset_epoch
                or target in _AUTHORITIES
                or target._storage_active_context is not None
                or target._storage_last_access is not None
                or any(type(value) is not int or value != 0 for value in (
                    target._sequence, target.local_ticks, target._tick_base))
                or any(type(value) is not int or not 1 <= value <= 65536
                       for value in (max_samples, max_writes, max_tokens))):
            raise ValueError(
                'wishbone-storage-version-fresh-exact-producer-required')
        self.target = target
        self.artifact = target.artifact
        contract = self._contract_from(self._source_document())
        _AUTHORITIES[target] = self
        _TOKENS[self] = {}
        _LIVE[self] = dict(
            bad=False, state=None, scope=None, pending=None, writes=[],
            samples=0, unrouted_writes=0,
            limits=(max_samples, max_writes, max_tokens),
            build_digest=None, build_identity=None, last_wire_sequence=0,
            source_contract=_canonical(contract),
            source_facts=_source_facts(contract),
            probe_widths=wishbone_probe_widths(contract),
            trace_signals=deepcopy(
                target._artifact_document['base_protocol_trace']['signals']),
            source_base=str(target.base_dir.absolute()),
            probe_digest=self._source_document()['digest'])
        try:
            self._validate()
        except BaseException:
            _AUTHORITIES.pop(target, None)
            _LIVE.pop(self, None)
            _TOKENS.pop(self, None)
            raise

    def _endpoint(self):
        endpoints = [endpoint for endpoint in self.artifact.plan.binding.endpoints
                     if endpoint.protocol is not None]
        if (len(endpoints) != 1
                or tuple(endpoints[0].protocol) != ('wishbone', 'classic')
                or endpoints[0].function != 'mmio_slave'):
            raise ValueError(
                'wishbone-storage-version-source-contract-required')
        return endpoints[0]

    def _source_document(self):
        target = self.target
        if (target.artifact.runtime_document != target._artifact_document):
            raise ValueError('wishbone-storage-version-source-contract-drift')
        document = target._artifact_document.get('storage_observation')
        if type(document) is not dict:
            raise ValueError(
                'wishbone-storage-version-source-contract-required')
        return document

    def _contract_from(self, document):
        contract = validate_wishbone_storage_source_contract(
            document.get('source_contract'), self.artifact.plan.profile,
            base_dir=self.target.base_dir)
        selection = document.get('selection')
        endpoint = self._endpoint()
        if (type(selection) is not dict
                or selection.get('contract_id') != contract['contract_id']
                or selection.get('register') != contract['register']['name']
                or selection.get('endpoint_id') != endpoint.endpoint_id):
            raise ValueError('wishbone-storage-version-source-contract-drift')
        return contract

    def _validate(self, *, native=False):
        if (type(self) is not _TYPE
                or any(left is not right for left, right in zip(
                    (_AUTHORITIES, _LIVE, _TOKENS), _REGISTRIES))
                or _AUTHORITIES.get(self.target) is not self
                or self not in _LIVE or self not in _TOKENS
                or _LIVE[self]['bad'] or self.target.artifact is not self.artifact
                or any(type(value) is not int or value < 0 for value in (
                    self.target.reset_epoch, self.target._sequence,
                    self.target.local_ticks, self.target._tick_base))
                or any(name in vars(self) or getattr(_TYPE, name) is not method
                       or method.__code__ is not code
                       for name, (method, code) in _METHODS.items())
                or validate_routed_context is not _ROUTED_VALIDATOR[0]
                or validate_routed_context.__code__ is not _ROUTED_VALIDATOR[1]
                or validate_pending_routed_context is not _PENDING_VALIDATOR[0]
                or validate_pending_routed_context.__code__
                is not _PENDING_VALIDATOR[1]
                or _analyse_wishbone_transfer is not _TRANSFER[0]
                or _analyse_wishbone_transfer.__code__ is not _TRANSFER[1]
                or validate_wishbone_storage_scope is not _SCOPE_VALIDATOR[0]
                or validate_wishbone_storage_scope.__code__ is not _SCOPE_VALIDATOR[1]
                or any(globals().get(name) is not value
                       or value.__code__ is not code
                       for name, (value, code) in _LOOKUP_FUNCTIONS.items())
                or any(globals().get(name) is not value
                       or value.__code__ is not code
                       for name, (value, code) in _FACT_FUNCTIONS.items())
                or any(getattr(_source_contract_module, name) is not value
                       or value.__code__ is not code
                       for name, (value, code) in _SOURCE_FUNCTIONS.items())):
            raise ValueError(
                'wishbone-storage-version-authority-drift-or-revoked')
        document = self._source_document()
        contract = self._contract_from(document)
        live = _LIVE[self]
        trace = self._trace()
        widths = wishbone_probe_widths(contract)
        if (_canonical(contract) != live['source_contract']
                or _source_facts(contract) != live['source_facts']
                or widths != live['probe_widths']
                or trace['signals'] != live['trace_signals']
                or trace.get('signal_widths')
                != {role: widths['storage_' + role] for role in ROLES}
                or str(self.target.base_dir.absolute()) != live['source_base']
                or self.artifact.runtime_document.get('kind')
                != 'wishbone_register_observe'
                or document.get('schema_version') != SCHEMA_VERSION
                or document.get('scope') != SCOPE
                or document.get('sample_group') != SAMPLE_GROUP
                or any(document.get(flag) is not False
                       for flag in AUTHORITY_FLAGS)
                or document.get('digest') != wishbone_storage_probe_digest(
                    document)
                or live.get('probe_digest') != document.get('digest')
                or self.target._artifact_document.get(
                    'storage_probe_ports') != document.get('ports')
                or type(live.get('last_wire_sequence')) is not int
                or live['last_wire_sequence'] < 0
                or type(live.get('samples')) is not int or live['samples'] < 0
                or type(live.get('unrouted_writes')) is not int
                or live['unrouted_writes'] < 0
                or not (live.get('build_digest') is None
                        or _hex64(live['build_digest']))
                or not (live.get('build_identity') is None
                        or (type(live['build_identity']) is dict
                            and set(live['build_identity']) == _BUILD_KEYS
                            and live['build_identity'].get('build_digest')
                            == live['build_digest']
                            and _hex64(live['build_identity'].get(
                                'artifact_digest'))
                            and _hex64(live['build_identity'].get(
                                'binary_sha256'))))):
            raise ValueError('wishbone-storage-version-source-contract-drift')
        if native and live.get('build_digest') is None:
            raise ValueError(
                'wishbone-storage-version-actual-native-build-required')

    def _trace(self):
        trace = self.target._artifact_document.get('base_protocol_trace')
        if (type(trace) is not dict or trace.get('protocol') != 'wishbone'
                or type(trace.get('signals')) is not dict
                or set(trace['signals']) != set(ROLES)):
            raise ValueError('wishbone-storage-version-probe-trace-required')
        return trace

    def _revoke(self):
        if self in _TOKENS:
            _TOKENS[self].clear()
        if self in _LIVE:
            # A revoked issuer has no live command scope: never keep a pending
            # context or a usable journal after any inconsistency.
            _LIVE[self]['pending'] = None
            _LIVE[self]['bad'] = True

    def _live_state(self):
        self._validate(native=True)
        target = self.target
        live = _LIVE[self]
        state = live['state']
        scope = (target.process, target._execution, target.reset_epoch,
                 target._tick_base)
        if (type(state) is not dict or live['pending'] is not None
                or target.process is None or target.process.poll() is not None
                or state.get('sequence') != target._sequence
                or live['scope'] != scope):
            raise ValueError('wishbone-storage-version-stale-scope')
        _SCOPE_VALIDATOR[0](
            state, live['scope'], process=target.process,
            execution=target._execution, epoch=target.reset_epoch,
            tick_base=target._tick_base, sequence=target._sequence,
            tick=target.local_ticks)
        return state, live

    def _bind_build_identity(self, target, live):
        """Bind the exact built executable receipt once, before any command."""
        if live['build_digest'] is None:
            try:
                receipt = target.built_executable_receipt_document()
            except ValueError as error:
                raise ValueError(
                    'wishbone-storage-version-actual-native-build-required'
                ) from error
            artifact_digest = target._artifact_document.get('artifact_digest')
            if (type(receipt) is not dict
                    or receipt.get('schema_version') != _BUILT_RECEIPT_SCHEMA
                    or not _hex64(receipt.get('build_digest'))
                    or not _hex64(receipt.get('artifact_digest'))
                    or not _hex64(receipt.get('binary_sha256'))
                    or receipt['artifact_digest'] != artifact_digest):
                raise ValueError(
                    'wishbone-storage-version-actual-native-build-required')
            live['build_digest'] = receipt['build_digest']
            live['build_identity'] = dict(
                build_digest=receipt['build_digest'],
                artifact_digest=receipt['artifact_digest'],
                binary_sha256=receipt['binary_sha256'])
            return
        identity = live['build_identity']
        if (type(identity) is not dict or set(identity) != _BUILD_KEYS
                or identity.get('build_digest') != live['build_digest']
                or any(not _hex64(identity.get(name))
                       for name in ('artifact_digest', 'binary_sha256'))):
            raise ValueError(
                'wishbone-storage-version-actual-native-build-required')

    def _actual_begin(self, target, operation, fields):
        """Producer hook: refuse before the command unless it is fully scoped."""
        try:
            self._validate()
            live = _LIVE[self]
            if target is not self.target:
                raise ValueError(
                    'wishbone-storage-version-actual-target-required')
            if operation not in _ACTUAL_OPERATIONS:
                raise ValueError(
                    'wishbone-storage-version-actual-operation-required')
            if live['pending'] is not None:
                raise ValueError('wishbone-storage-version-pending-command')
            if live['last_wire_sequence'] != target._sequence:
                raise ValueError(
                    'wishbone-storage-version-wire-sequence-drift')
            if (type(target._execution) is not str or not target._execution
                    or type(target._case_id) is not str or not target._case_id
                    or target.process is None
                    or target.process.poll() is not None):
                raise ValueError('wishbone-storage-version-live-scope-required')
            self._bind_build_identity(target, live)
            scope = (target.process, target._execution, target.reset_epoch,
                     target._tick_base)
            if live['scope'] is None:
                live['scope'] = scope
            elif live['scope'] != scope:
                raise ValueError(
                    'wishbone-storage-version-current-scope-drift')
            context = None
            if operation == ACCESS_OPERATION:
                # An ordinary target access issues no routed context; only a
                # routed call carries one (the session builds it before the
                # command, so a routed call can never arrive here without it).
                if target._storage_active_context is not None:
                    context = _PENDING_VALIDATOR[0](
                        target._storage_active_context, fields=fields,
                        sequence=target._sequence + 1,
                        execution=target._execution, epoch=target.reset_epoch,
                        window=target._window)
            elif target._storage_active_context is not None:
                raise ValueError(
                    'wishbone-storage-version-context-command-mismatch')
            if live['state'] is not None:
                _SCOPE_VALIDATOR[0](
                    live['state'], live['scope'], process=target.process,
                    execution=target._execution, epoch=target.reset_epoch,
                    tick_base=target._tick_base, sequence=target._sequence,
                    tick=target.local_ticks)
            live['pending'] = (operation, fields, target._sequence + 1,
                               target.local_ticks, context)
        except BaseException:
            self._revoke()
            raise

    def _actual_command(self, target, operation, fields, receipt):
        """Producer hook: reduce the actual receipt of the pending command.

        The generated session commits ``_sequence``/``local_ticks`` before this
        post-reply hook runs, so the pending command sequence is checked against
        the session's committed position and against the recorded pre-command
        tick (``pending[3]``) instead of the pre-command counters.
        """
        try:
            self._validate(native=True)
            live = _LIVE[self]
            pending = live['pending']
            if (target is not self.target
                    or type(pending) is not tuple or len(pending) != 5
                    or pending[0] != operation or pending[1] != fields
                    or target._sequence != pending[2]
                    or live['scope'] != (target.process, target._execution,
                                         target.reset_epoch, target._tick_base)
                    or live['last_wire_sequence'] != pending[2] - 1
                    or receipt.execution != target._execution
                    or receipt.sequence != pending[2]
                    or receipt.status != 'result' or receipt.payload is None):
                raise ValueError(
                    'wishbone-storage-version-receipt-mismatch')
            payload = receipt.payload
            if (type(receipt.tick_before) is not int
                    or type(receipt.tick_after) is not int
                    or receipt.tick_before != pending[3] - target._tick_base
                    or target.local_ticks
                    != target._tick_base + receipt.tick_after
                    or type(payload.get('samples')) is not list
                    or receipt.tick_after - receipt.tick_before
                    != len(payload['samples'])
                    or payload.get('error') != 0
                    or type(payload.get('rdata')) is not int):
                raise ValueError(
                    'wishbone-storage-version-receipt-mismatch')
            if operation == ACCESS_OPERATION:
                self._complete_access(target, fields, receipt, pending, live)
            else:
                state = live['state']
                if state is not None:
                    state['sequence'] = receipt.sequence
                    state['tick'] = target._tick_base + receipt.tick_after
            live['last_wire_sequence'] = receipt.sequence
            live['pending'] = None
        except BaseException:
            self._revoke()
            raise

    def _complete_access(self, target, fields, receipt, pending, live):
        """Journal one measured word access, or refuse by name and poison."""
        facts = live['source_facts']
        write = bool(fields[0])
        transfer = _TRANSFER[0](
            receipt.payload['samples'],
            first_tick=receipt.tick_before + 1, write=write,
            word_index=fields[1] >> 2, value=fields[2],
            rdata=receipt.payload['rdata'], signals=live['trace_signals'],
            widths=live['probe_widths'])
        if live['samples'] + len(receipt.payload['samples']) > live['limits'][0]:
            raise ValueError('wishbone-storage-version-sample-capacity')
        tick = target._tick_base + transfer.request_tick
        before = transfer.request['storage_value']
        state = live['state']
        if state is None:
            if live['writes']:
                raise ValueError(
                    'wishbone-storage-version-initial-state-required')
            if before != facts.reset_value:
                raise ValueError(
                    'wishbone-storage-version-initial-state-mismatch')
        elif type(state) is not dict or before != state.get('value'):
            raise ValueError(
                'wishbone-storage-version-storage-transition-mismatch')
        context = None
        if pending[4] is not None:
            context = deepcopy(pending[4])
            context['tick'] = tick
            context['read_value'] = (0 if write
                                     else receipt.payload['rdata'])
            context = _ROUTED_VALIDATOR[0](
                context, operation=ACCESS_OPERATION, fields=fields,
                sequence=receipt.sequence, execution=target._execution,
                epoch=target.reset_epoch, window=target._window)
        after = transfer.post['storage_value']
        if write:
            if context is None:
                # A measured write outside the routed path is real state, but
                # it is not a routed commit: the journal can never claim it.
                live['unrouted_writes'] += 1
            else:
                if len(live['writes']) + 1 > live['limits'][1]:
                    raise ValueError(
                        'wishbone-storage-version-write-capacity')
                live['writes'].append(dict(
                    tick=tick, raw_address=transfer.request['storage_adr'],
                    before=before, after=after,
                    sample_index=transfer.request_index, phase='pre',
                    command_sequence=receipt.sequence, context=context,
                    raw_reference=dict(
                        execution=target._execution, sequence=receipt.sequence,
                        sample_index=transfer.request_index, phase='pre')))
        live['samples'] += len(receipt.payload['samples'])
        live['state'] = dict(tick=target._tick_base + receipt.tick_after,
                             value=after, sequence=receipt.sequence,
                             reset_waveform_observed=False)

    def issue(self, *, register, reset_epoch):
        try:
            target = self.target
            state, live = self._live_state()
            facts = live['source_facts']
            if (register != facts.register or type(reset_epoch) is not int
                    or reset_epoch != target.reset_epoch):
                raise ValueError(
                    'wishbone-storage-version-current-state-unavailable')
            if live['build_digest'] is not None and not (
                    type(live['build_digest']) is str
                    and len(live['build_digest']) == 64):
                raise ValueError(
                    'wishbone-storage-version-actual-native-build-required')
            if live['unrouted_writes']:
                # A measured write outside the routed path cannot be journalled,
                # so the declared complete write history would be false.
                raise ValueError(
                    'wishbone-storage-version-history-incomplete')
            if len(_TOKENS[self]) >= live['limits'][2]:
                raise ValueError('wishbone-storage-version-token-capacity')
            document = self._source_document()
            artifact_document = self.target._artifact_document
            token = object()
            _TOKENS[self][token] = dict(
                register=register, value=state['value'],
                local_tick=state['tick'],
                write_history_sha256=_digest(live['writes']),
                field_version=len(live['writes']),
                write_count=len(live['writes']),
                version_basis=wishbone_storage_version_basis(facts.register),
                reset_epoch=reset_epoch, command_sequence=state['sequence'],
                pid=target.process.pid, execution=target._execution,
                build_identity_sha256=live['build_digest'],
                producer_source_sha256=hashlib.sha256(
                    Path(__file__).read_bytes()).hexdigest(),
                artifact_digest=artifact_document['artifact_digest'],
                source_contract_digest=facts.digest,
                probe_digest=document['digest'],
                reset_waveform_observed=state['reset_waveform_observed'],
                grants_reset_prerequisite=False,
                history_scope=HISTORY_SCOPE,
                routed_context_authenticated=False)
            return token
        except BaseException:
            self._revoke()
            raise

    def consume(self, token):
        try:
            state, live = self._live_state()
            if type(token) is not object:
                raise ValueError('wishbone-storage-version-token-invalid')
            witness = _TOKENS[self].pop(token, None)
            if witness is None:
                raise ValueError('wishbone-storage-version-token-invalid')
            facts = live['source_facts']
            if (witness.get('register') != facts.register
                    or witness.get('value') != state['value']
                    or witness.get('local_tick') != state['tick']
                    or witness.get('command_sequence') != state['sequence']
                    or witness.get('reset_epoch') != self.target.reset_epoch
                    or witness.get('source_contract_digest') != facts.digest
                    or witness.get('probe_digest') != live['probe_digest']
                    or witness.get('build_identity_sha256')
                    != live['build_digest']):
                raise ValueError('wishbone-storage-version-token-invalid')
            return deepcopy(witness)
        except BaseException:
            self._revoke()
            raise

    def writes(self):
        try:
            self._validate()
            return deepcopy(_LIVE[self]['writes'])
        except BaseException:
            # A detected drift is permanent: no later read may look healthy.
            self._revoke()
            raise


_TYPE = WishboneStorageRegisterVersionAuthority
_METHODS = MappingProxyType({
    name: (method, method.__code__)
    for name, method in vars(_TYPE).items() if hasattr(method, '__code__')})
