"""Live native instruction bus completion, issued only at the verified PRE edge."""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import asdict
import sys
from weakref import ref

from .ledger import TransactionKey
from .memory import ReadSnapshot
from .memory_service import _VALIDATE_ISSUED_READ
from .native_cpu_events import NativeBusObserver, _NATIVE_OBSERVER_PRODUCER
from .native_instruction_source_binding import (
    NativeInstructionSourceBinding, lookup_issued_source_for_read,
    validate_issued_binding)


@dataclass(frozen=True, slots=True)
class NativeInstructionBusCompletion:
    key: TransactionKey
    snapshot: ReadSnapshot
    binding: NativeInstructionSourceBinding
    address: int
    data: bytes
    reset_epoch: int
    accepted_scope: tuple[str, int, int, int]
    response_scope: tuple[str, int, int, int]
    completion_scope: tuple[str, int, int, int]
    native_pre: tuple[int, int, int, int, int, int]
    schema_version: str = 'native_instruction_bus_completion.v1'
    proof_scope: str = 'native_instruction_bus_transfer_completed'
    grants_source_authority: bool = False


def _scope_tuple(scope):
    if (type(scope) is not dict
            or set(scope) != {'execution', 'command_sequence', 'reset_epoch', 'local_tick'}
            or type(scope['execution']) is not str or not scope['execution']
            or any(type(scope[name]) is not int or scope[name] < 0 for name in
                   ('command_sequence', 'reset_epoch', 'local_tick'))):
        raise ValueError('native_source_completion_refused')
    return (scope['execution'], scope['command_sequence'],
            scope['reset_epoch'], scope['local_tick'])


def _scopes_share_execution(accepted, response, completion):
    return accepted[0] == response[0] and response[0] == completion[0]


def _completion_material(completion):
    return tuple(getattr(completion, name) for name in (
        'address', 'data', 'reset_epoch', 'accepted_scope', 'response_scope',
        'completion_scope', 'native_pre', 'schema_version', 'proof_scope',
        'grants_source_authority'))


def _key_material(key):
    return tuple(getattr(key, name) for name in TransactionKey.__dataclass_fields__)


def _completion_registry():
    method, code = _NATIVE_OBSERVER_PRODUCER()
    issued = {}

    def owner_records(observer):
        row = issued.get(id(observer))
        return row[1] if row is not None and row[0]() is observer else None

    def issue(observer, pending, native_pre, scope):
        frame = sys._getframe(1)
        owner = observer.session
        service = owner.service
        memory = owner.memory
        key = pending.get('key') if type(pending) is dict else None
        snapshot = pending.get('read_snapshot') if type(pending) is dict else None
        handle = pending.get('read_handle') if type(pending) is dict else None
        if (type(observer) is not NativeBusObserver
                or NativeBusObserver.observe is not method or method.__code__ is not code
                or frame.f_code is not code or frame.f_globals is not method.__globals__
                or frame.f_locals.get('self') is not observer
                or observer.pending is not pending
                or type(key) is not TransactionKey or type(snapshot) is not ReadSnapshot
                or handle is None or pending.get('completion_issued')
                or pending.get('state') != 'response'
                or type(native_pre) is not dict
                or any(native_pre.get(name) != expected for name, expected in
                       (('valid', 1), ('ready', 1), ('instruction', 1), ('wstrb', 0)))
                or type(native_pre.get('addr')) is not int
                or native_pre['addr'] % 4 or native_pre['addr'] != pending['native']['addr']
                or pending.get('backend_be') != 15
                or type(snapshot.data) is not bytes or len(snapshot.data) != 4
                or snapshot.value != native_pre.get('rdata')
                or pending.get('response') != native_pre.get('rdata')
                or pending.get('transaction') != asdict(key)
                or key.source_epoch != owner.reset_epoch
                or pending.get('response_tick') is None
                or scope.get('local_tick') != pending['response_scope']['local_tick'] + 1):
            raise ValueError('native_source_completion_refused')
        accepted_scope = _scope_tuple(pending['accepted_scope'])
        response_scope = _scope_tuple(pending['response_scope'])
        completion_scope = _scope_tuple(scope)
        if (not _scopes_share_execution(accepted_scope, response_scope,
                                        completion_scope)
                or any(item[2] != owner.reset_epoch for item in
                       (accepted_scope, response_scope, completion_scope))):
            raise ValueError('native_source_completion_refused')
        _VALIDATE_ISSUED_READ(service, memory, key, snapshot, handle)
        source_session = owner._native_source_completion_session
        binding = lookup_issued_source_for_read(source_session, service, memory,
                                                key, snapshot, native_pre['addr'],
                                                owner.reset_epoch)
        if binding is None:
            return None
        if type(binding) is not NativeInstructionSourceBinding:
            raise ValueError('native_source_completion_refused')
        records = owner_records(observer)
        if records is None:
            observer_id = id(observer)

            def expired(reference):
                row = issued.get(observer_id)
                if row is not None and row[0] is reference:
                    issued.pop(observer_id)

            records = {}
            issued[observer_id] = (ref(observer, expired), records)
        if len(records) >= 256:
            raise ValueError('native_source_completion_capacity')
        completion = NativeInstructionBusCompletion(key, snapshot, binding,
            native_pre['addr'], snapshot.data, owner.reset_epoch,
            accepted_scope, response_scope, completion_scope,
            tuple(native_pre[name] for name in
                  ('valid', 'ready', 'addr', 'wstrb', 'rdata', 'instruction')))
        records[id(completion)] = (completion, owner, service, memory, source_session,
            tuple(getattr(snapshot, name) for name in ReadSnapshot.__dataclass_fields__),
            key, snapshot, binding, _completion_material(completion),
            _key_material(key))
        pending['completion_issued'] = True
        return completion

    def validate(observer, completion):
        records = owner_records(observer)
        row = records.get(id(completion)) if records is not None else None
        if (type(observer) is not NativeBusObserver
                or type(completion) is not NativeInstructionBusCompletion
                or row is None or row[0] is not completion
                or observer.session is not row[1]
                or row[1].service is not row[2] or row[1].memory is not row[3]
                or row[1]._native_source_completion_session is not row[4]
                or completion.key is not row[6]
                or _key_material(completion.key) != row[10]
                or completion.snapshot is not row[7]
                or completion.binding is not row[8]
                or _completion_material(completion) != row[9]
                or completion.reset_epoch != row[1].reset_epoch
                or tuple(getattr(completion.snapshot, name) for name in
                         ReadSnapshot.__dataclass_fields__) != row[5]
                or completion.data != completion.snapshot.data
                or completion.schema_version != 'native_instruction_bus_completion.v1'
                or completion.proof_scope != 'native_instruction_bus_transfer_completed'
                or completion.grants_source_authority is not False):
            raise ValueError('native completion is not an unchanged issued object')
        validate_issued_binding(row[4], completion.binding)
        return completion

    def revoke(observer):
        row = issued.get(id(observer))
        if row is not None and row[0]() is observer:
            issued.pop(id(observer))

    return issue, validate, revoke


(_ISSUE_NATIVE_COMPLETION, validate_issued_native_completion,
 revoke_native_completions) = _completion_registry()
