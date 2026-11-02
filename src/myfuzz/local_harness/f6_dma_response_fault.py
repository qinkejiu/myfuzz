"""Closed, preinstalled F6 response fault; selection grants no target authority.

The public declaration contains logical coordinates only. The actual DMA step
arms selection after its native PRE acceptance and live route admission.
"""
from dataclasses import asdict, dataclass
from weakref import WeakKeyDictionary, ref

from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission


@dataclass(frozen=True, slots=True)
class F6ResponseFaultDeclaration:
    case_index: int
    operation: str
    word_index: int

    def __post_init__(self):
        if (type(self.case_index) is not int or not 0 <= self.case_index < 16
                or type(self.operation) is not str
                or self.operation not in ('read', 'write')
                or type(self.word_index) is not int or not 0 <= self.word_index < 4):
            raise ValueError('invalid closed F6 response fault selector')

    def document(self):
        return asdict(self)


_ISSUER = object()


class F6ResponseFault:
    """Sealed one-shot selector owned by one original generated DMA session."""
    __slots__ = ('_session', '_declaration', '_selector_pin', '_binding',
                 '_case_index', '_scope', '_counts', '_selected', '_active')

    def __init__(self, session, declaration, binding, *, _issuer=None):
        if _issuer is not _ISSUER:
            raise ValueError('F6 response fault requires prestartup installation')
        object.__setattr__(self, '_session', ref(session))
        object.__setattr__(self, '_declaration', declaration)
        object.__setattr__(self, '_selector_pin', (declaration.case_index,
            declaration.operation, declaration.word_index))
        object.__setattr__(self, '_binding', binding)
        object.__setattr__(self, '_case_index', None)
        object.__setattr__(self, '_scope', None)
        object.__setattr__(self, '_counts', (0, 0))
        object.__setattr__(self, '_selected', None)
        object.__setattr__(self, '_active', None)

    def __setattr__(self, name, value):
        raise AttributeError('F6 response fault is sealed')

    def begin_case(self, index):
        session = self._session()
        _validate_f6_response_fault(session)
        scope = (session._execution, session._case_id,
                 session.source_component, session.reset_epoch)
        if (type(index) is not int or not 0 <= index < 16
                or index != (0 if self._case_index is None else self._case_index + 1)
                or self._selected is not None or self._active is not None
                or session.pending_responses or session.memory_service.ledger.unresolved_keys
                or type(session._execution) is not str or not session._execution
                or type(session._case_id) is not str or not session._case_id):
            raise ValueError('F6 response fault requires the next live case')
        if self._scope is not None and scope == self._scope:
            raise ValueError('F6 response fault requires a new native testcase scope')
        object.__setattr__(self, '_case_index', index)
        object.__setattr__(self, '_scope', scope)
        object.__setattr__(self, '_counts', (0, 0))

    def select(self, key, *, operation, word_index):
        session = self._session()
        _validate_f6_response_fault(session)
        if (type(key) is not TransactionKey or self._active is None
                or key is not self._active[0]
                or type(operation) is not str or operation not in ('read', 'write')
                or type(word_index) is not int or not 0 <= word_index < 4
                or (operation, word_index) != self._active[1:]
                or (key.execution_id, key.testcase_id, key.source_component,
                    key.source_epoch) != self._scope
                or any(type(getattr(key, name)) is not str or not getattr(key, name)
                    for name in ('execution_id', 'testcase_id', 'source_component', 'channel_id'))
                or type(key.source_epoch) is not int or key.source_epoch < 0
                or key.channel_id != 'dma-memory'
                or type(key.source_sequence) is not int
                or key.source_sequence != session._source_sequence):
            raise ValueError('F6 response fault requires the actual native accepted key')
        if self._selected is not None:
            return False
        if (self._case_index, operation, word_index) != (
                self._declaration.case_index, self._declaration.operation,
                self._declaration.word_index):
            return False
        object.__setattr__(self, '_selected', key)
        return True

    def document(self):
        return dict(schema_version='f6_dma_response_fault.v1',
            selector=dict(zip(('case_index', 'operation', 'word_index'), self._selector_pin)),
            execution_binding_sha256=self._binding,
            timing='before_target_effect', one_shot=True,
            selected_transaction=(asdict(self._selected)
                if self._selected is not None else None))


def _make_installation_registry():
    sessions = WeakKeyDictionary()
    original = None
    fault_methods = tuple((name, value, value.__code__)
        for name, value in vars(F6ResponseFault).items() if callable(value)
        and hasattr(value, '__code__'))

    def seal(cls):
        nonlocal original
        if original is not None:
            raise ValueError('original F6 DMA methods are already sealed')
        methods = []
        for name, descriptor in vars(cls).items():
            method = (descriptor.__func__
                if isinstance(descriptor, (classmethod, staticmethod))
                else descriptor)
            if callable(method) and hasattr(method, '__code__'):
                methods.append((name, descriptor, method, method.__code__))
        original = (cls, tuple(methods))

    def check_methods(session):
        if original is None:
            raise ValueError('F6 response fault requires original generated DMA session')
        # F6 installs its issuers on the exact base class or the pinned
        # ScenarioRunner subclass. The subclass may override scheduler methods,
        # so authenticate that class through the base module's captured
        # allowlist while checking the base implementation from its own class
        # dictionary below. In particular, looking up __init_subclass__ through
        # the subclass binds a different classmethod and falsely reports drift.
        from myfuzz.local_harness.wishbone_dma_session import (
            _f6_dma_session_type_allowlist)
        allowed = _f6_dma_session_type_allowlist()
        if allowed[0] is not original[0] or type(session) not in allowed:
            raise ValueError('F6 response fault requires original generated DMA session')
        for name, descriptor, method, code in original[1]:
            current_descriptor = vars(original[0]).get(name)
            current_method = (current_descriptor.__func__
                if isinstance(current_descriptor, (classmethod, staticmethod))
                else current_descriptor)
            if (name in vars(session) or current_descriptor is not descriptor
                    or current_method is not method
                    or getattr(current_method, '__code__', None) is not code):
                raise ValueError('F6 DMA original method drift: ' + name)
        for name, method, code in fault_methods:
            if getattr(F6ResponseFault, name) is not method or method.__code__ is not code:
                raise ValueError('sealed F6 response fault method drift: ' + name)

    def validate(session):
        fault = sessions.get(session)
        if fault is None:
            if getattr(session, '_f6_response_fault', None) is not None:
                raise ValueError('F6 response fault was not installed')
            return None
        check_methods(session)
        if (getattr(session, '_f6_response_fault', None) is not fault
                or type(fault) is not F6ResponseFault
                or fault._session() is not session
                or type(fault._declaration.case_index) is not int
                or type(fault._declaration.operation) is not str
                or type(fault._declaration.word_index) is not int
                or (fault._declaration.case_index, fault._declaration.operation,
                    fault._declaration.word_index) != fault._selector_pin):
            raise ValueError('sealed F6 response fault declaration or owner drift')
        if type(session._dma_route_admission) is not DmaMasterRouteAdmission:
            raise ValueError('F6 response fault requires live DMA route admission')
        return fault

    def install(session, *, declaration, execution_binding_sha256):
        check_methods(session)
        if (type(declaration) is not F6ResponseFaultDeclaration
                or type(execution_binding_sha256) is not str
                or len(execution_binding_sha256) != 64
                or any(ch not in '0123456789abcdef' for ch in execution_binding_sha256)):
            raise ValueError('F6 response fault requires a closed declaration and binding SHA256')
        # Recheck even an object whose frozen fields were bypassed externally.
        F6ResponseFaultDeclaration(**declaration.document())
        if (session in sessions or getattr(session, '_f6_response_fault', None) is not None
                or session._prepare_attempted or session._start_attempted
                or session._execution or session._process is not None
                or session._case_id is not None or session.local_ticks
                or session.events or session._source_sequence or session._pending is not None):
            raise ValueError('F6 response fault must be installed once before startup')
        if type(session._dma_route_admission) is not DmaMasterRouteAdmission:
            raise ValueError('F6 response fault requires live DMA route admission')
        session._validate_dma_route_topology()
        fault = F6ResponseFault(session, declaration, execution_binding_sha256,
            _issuer=_ISSUER)
        sessions[session] = fault
        session._f6_response_fault = fault
        return fault

    def select_accepted(session, key, *, operation):
        fault = validate(session)
        if fault is None:
            return False
        if (fault._scope is None
                or (session._execution, session._case_id, session.source_component,
                    session.reset_epoch) != fault._scope):
            raise ValueError('F6 response fault case was not begun for this native key')
        # Route matching is a separate authority and must already have succeeded.
        if not any(row['transaction'] == asdict(key)
                   for row in session._dma_route_admission.route_matches):
            raise ValueError('F6 response fault key has no live admitted route')
        counter = int(operation == 'write')
        index = fault._counts[counter]
        object.__setattr__(fault, '_active', (key, operation, index))
        try:
            selected = fault.select(key, operation=operation, word_index=index)
        finally:
            object.__setattr__(fault, '_active', None)
        counts = list(fault._counts)
        counts[counter] += 1
        object.__setattr__(fault, '_counts', tuple(counts))
        return selected

    return seal, validate, install, select_accepted


(_seal_f6_dma_session, _validate_f6_response_fault,
 install_f6_response_fault, _select_f6_response_fault) = _make_installation_registry()
