"""Exact historical GPIO write -> APB read observations, never authority.

Document validation is deliberately separate from the live report entry point.
Only an opaque installation handle can produce reward-eligible observations.
IRQ generation, delivery, acceptance and ISR consumption remain unknown.
"""
from copy import deepcopy
from hashlib import sha256
from weakref import WeakKeyDictionary

from myfuzz.scenario.session_runtime import ScenarioSession as _CaseSession

from .model import canonical

_CASE_RECEIPT_READER = _CaseSession.case_receipt
_CASE_RECEIPT_CODE = _CASE_RECEIPT_READER.__code__
_CASES_PROPERTY = _CaseSession.cases
_CASES_GETTER_CODE = _CASES_PROPERTY.fget.__code__


def _positive(value):
    return type(value) is int and value > 0


def validate_gpio_relation_documentary(report, *, component, register, bit_lo, width, epoch):
    """Validate complete exact resources; saved reports never earn credit."""
    from myfuzz.scenario.retirement_delivery import _key
    if (type(report) is not dict
            or report.get('schema_version') != 'gpio_register_evidence_report.v1'
            or report.get('journal_integrity') is not True
            or report.get('awaiting_native_reset') is not False
            or report.get('register_status') != 'verified'
            or type(bit_lo) is not int or type(width) is not int
            or width <= 0 or bit_lo < 0 or type(epoch) is not int or epoch < 0):
        return ()
    result = []
    for c in report.get('certificates', ()):
        try:
            if (c['proof_scope'] != 'register_version'
                    or (c['component'], c['register'], c['bit_lo'], c['width'], c['reset_epoch'])
                    != (component, register, bit_lo, width, epoch)):
                continue
            resources, ids = c['bit_resources'], c['writer_event_ids']
            transactions = c['write_transactions']
            if (type(resources) is not list or len(resources) != width
                    or type(ids) is not list or not ids or ids != sorted(set(ids))
                    or not all(_positive(v) for v in ids)
                    or not _positive(c['read_event_id']) or max(ids) >= c['read_event_id']
                    or len(transactions) != len(ids) or len(c['write_accesses']) != len(ids)
                    or _key(c['read_transaction']) is None
                    or any(_key(t) is None for t in transactions)):
                continue
            writers = dict(zip(ids, transactions))
            for bit, r in enumerate(resources, bit_lo):
                if ((r['component'], r['register'], r['reset_epoch'], r['bit'])
                        != (component, register, epoch, bit)
                        or not _positive(r['version'])
                        or type(r['value']) is not int or r['value'] not in (0, 1)
                        or r['observation_event_id'] not in writers
                        or r['transaction'] != writers[r['observation_event_id']]
                        or _key(r['transaction']) == _key(c['read_transaction'])):
                    raise ValueError('inexact resource')
            if (set(r['observation_event_id'] for r in resources) != set(ids)
                    or len({r['version'] for r in resources}) != width
                    or any(t['execution_id'] != c['read_transaction']['execution_id']
                           for t in transactions)):
                continue
            offsets = {'dir': 0, 'gpioen': 4, 'out': 12, 'inten': 24,
                       'inttype': 32 if bit_lo >= 32 else 28}
            if (c['read_access']['decoded_offset'] != offsets[register]
                    or (c['read_access']['read_value'] >> (bit_lo % 32)) & ((1 << width) - 1)
                       != sum(r['value'] << i for i, r in enumerate(resources))):
                continue
            # Keep each original per-bit version and transaction: no synthesized
            # whole-register version based on values or history length.
            result.append(dict(component=component, register=register, bit_lo=bit_lo,
                width=width, reset_epoch=epoch, bit_resources=deepcopy(resources),
                writer_event_ids=deepcopy(ids), writer_transactions=deepcopy(transactions),
                read_event_id=c['read_event_id'], read_transaction=deepcopy(c['read_transaction']),
                evidence_id=c['evidence_id'], relation_id='gpio-read:' + sha256(canonical(dict(
                    component=component, register=register, bit_lo=bit_lo, width=width,
                    values=[r['value'] for r in resources]))).hexdigest(),
                status='verified', reward_eligible=False, native_authority=False,
                irq_status='unknown', isr_status='unknown'))
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(result)


def attribute_gpio_relation_documentary(relation, events_by_id, *, observed_cases=None):
    """Observed runner case attribution only; documents cannot grant credit.

    Native CPU TransactionKey.testcase_id may stay constant across search cases
    and therefore never substitutes for observed case provenance or receipt
    attribution. Optional mappings are documentary here and grant no authority.
    """
    row = dict(deepcopy(relation), writer_case_ids=[], read_case_id=None,
        cross_testcase=None, attribution='unattributed', reward_eligible=False)

    def case(event_id, transaction, write):
        event = events_by_id.get(event_id)
        if (type(event) is not dict or event.get('event_id') != event_id
                or event.get('kind') != 'gpio_apb_access'
                or event.get('component') != relation['component']
                or event.get('reset_epoch') != relation['reset_epoch']
                or event.get('write') is not write
                or event.get('source_transaction') != transaction):
            return None
        if observed_cases is not None:
            observed = observed_cases.get(event_id)
        else:
            provenance = event.get('provenance')
            observed = provenance.get('observed_case') if type(provenance) is dict else None
        if (type(observed) is not dict
                or type(observed.get('case_id')) is not str
                or not observed['case_id'] or len(observed['case_id']) > 256
                or observed['case_id'].strip() != observed['case_id']
                or type(observed.get('case_index')) is not int
                or observed['case_index'] < 0):
            return None
        return observed['case_id']

    try:
        row['writer_case_ids'] = [case(event_id, transaction, True)
            for event_id, transaction in zip(relation['writer_event_ids'],
                                             relation['writer_transactions'], strict=True)]
        row['read_case_id'] = case(relation['read_event_id'], relation['read_transaction'], False)
        if (row['writer_case_ids'] and all(row['writer_case_ids'])
                and row['read_case_id'] is not None):
            row['attribution'] = 'attributed'
            row['cross_testcase'] = all(v != row['read_case_id'] for v in row['writer_case_ids'])
    except (KeyError, TypeError, ValueError, AttributeError):
        pass
    return row


def _bind_case_session(session, runner):
    """Pin public readers of the exact session already bound to this runner."""
    from myfuzz.scenario.session_runtime import ScenarioSession
    if type(session) is not ScenarioSession or session.runner is not runner:
        raise ValueError('actual session bound to the same runner required')
    if 'case_receipt' in vars(session) or 'cases' in vars(session):
        raise ValueError('session reader drift')
    if (ScenarioSession.case_receipt is not _CASE_RECEIPT_READER
            or ScenarioSession.case_receipt.__code__ is not _CASE_RECEIPT_CODE
            or ScenarioSession.cases is not _CASES_PROPERTY
            or ScenarioSession.cases.fget.__code__ is not _CASES_GETTER_CODE):
        raise ValueError('session reader drift')
    reader, getter = ScenarioSession.case_receipt, ScenarioSession.cases.fget
    return dict(session=session, reader=reader, getter=getter,
                reader_code=reader.__code__, getter_code=getter.__code__)


def _read_case_attribution(binding, runner, readers, needed):
    """Read completed case boundaries without receipt ingestion or execution.

    No caller-provided case bounds enter this path. Public receipt projections
    are read only from the pinned actual session and cross-checked against the
    same actual runner journal. The caller still authenticates native evidence.
    """
    from myfuzz.scenario.session_runtime import ScenarioSession, OnlineCaseReceipt
    session = binding['session']
    if (type(session) is not ScenarioSession or session.runner is not runner
            or 'case_receipt' in vars(session) or 'cases' in vars(session)
            or ScenarioSession.case_receipt is not binding['reader']
            or ScenarioSession.cases.fget is not binding['getter']
            or binding['reader'].__code__ is not binding['reader_code']
            or binding['getter'].__code__ is not binding['getter_code']):
        raise ValueError('session receipt reader drift')
    cases, result, previous_end = session.cases, {}, 0
    for index, case in enumerate(cases):
        receipt = session.case_receipt(case.case_id)
        if receipt is None:
            continue
        if (type(receipt) is not OnlineCaseReceipt or receipt.case_id != case.case_id
                or type(receipt.event_start) is not int
                or type(receipt.event_end) is not int
                or not previous_end <= receipt.event_start <= receipt.event_end <= runner.event_count
                or type(receipt.events) is not tuple):
            raise ValueError('session receipt boundary drift')
        actual = readers['events_since'](runner, receipt.event_start, stop=receipt.event_end)
        if receipt.events != actual:
            raise ValueError('session receipt journal drift')
        previous_end = receipt.event_end
        for event in actual:
            event_id = event.get('event_id')
            if event_id in needed:
                if event_id in result:
                    raise ValueError('overlapping session receipt boundaries')
                result[event_id] = dict(case_id=case.case_id, case_index=index)
    if session.cases != cases:
        raise ValueError('session cases drift')
    return result


def validate_gpio_field_horizon(document, witness):
    """Pure documentary comparison, never a witness authenticator.

    Only the installed live reader may supply its actual authority witness.
    Equal values or epochs alone cannot establish a current observation horizon.
    """
    if type(document) is not dict or type(witness) is not dict:
        return False
    for key in ('reset_epoch', 'local_tick', 'command_sequence'):
        left, right = document.get(key), witness.get(key)
        if (type(left) is not int or type(right) is not int or left != right
                or left < (0 if key == 'reset_epoch' else 1)):
            return False
    return document.get('status') == 'observed'


class _Installation:
    @property
    def configuration(self):
        return deepcopy(_INSTALLATIONS[self]['configuration'])

    def report(self):
        return read_gpio_relations(self)

    def irq_report(self):
        return read_gpio_irq_relations(self)

    def field_state(self, *, expected_epoch):
        from .gpio_fields import _unknown, GpioFieldDocuments
        self.report()  # Authenticate and drain the same complete stream.
        state = _INSTALLATIONS[self]
        current = state.get('live_current')
        witness = state.get('live_witness')
        if (current is None or witness is None
                or type(state['consumer']) is not GpioFieldDocuments):
            return _unknown('live_field_scope_unavailable')
        document = state['consumer'].documentary_state(expected_epoch=expected_epoch)
        scope = state['scope']
        if (not validate_gpio_field_horizon(document, witness)
                or current.epoch != expected_epoch
                or document['reset_epoch'] != expected_epoch
                or document['value'] != (current.value >> scope['bit_lo']) & ((1 << scope['width']) - 1)):
            return _unknown('live_field_identity_mismatch')
        writer_case_ids = [None] * len(document['bit_resources'])
        binding = state.get('case_session')
        if binding is not None:
            runner = state['runner']
            count = runner.event_count
            needed = {r['observation_event_id'] for r in document['bit_resources']}
            observed = _read_case_attribution(binding, runner, state, needed)
            writer_case_ids = [observed.get(r['observation_event_id'], {}).get('case_id')
                               for r in document['bit_resources']]
            if runner.event_count != count:
                return _unknown('live_field_journal_changed_during_attribution')
        return dict(document, live_observer=True, execution_authority=False,
                    writer_case_ids=writer_case_ids,
                    writer_attributed=bool(writer_case_ids) and all(
                        v is not None for v in writer_case_ids))


_INSTALLATIONS = WeakKeyDictionary()


def install_gpio_relation_consumer(runner, authority, *, target_id, register,
                                   bit_lo, width, runtime_contract_sha256,
                                   session=None):
    """Install before begin; reports pull only this runner's live event stream.

    No host register writes, tick stepping or journal mutation is performed.
    The bound GPIOEN authority validates the process scope even if the chosen
    documentary register slice is another supported GPIO register.
    """
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.gpio_register_evidence import GpioRegisterEvidenceConsumer
    target = runner.sessions.get(target_id) if type(runner) is ScenarioRunner else None
    if (type(runner) is not ScenarioRunner or runner._status != 'created'
            or runner.event_count != 0
            or type(target) is not GeneratedPulpGpioSession
            or type(authority) is not GpioRegisterVersionAuthority
            or authority.target is not target):
        raise ValueError('unused actual runner and bound GPIO authority required')
    if register == 'gpioen':
        from .gpio_fields import GpioFieldDocuments
        consumer = GpioFieldDocuments(component=target_id, bit_lo=bit_lo,
            width=width, runtime_contract_sha256=runtime_contract_sha256)
    else:
        consumer = GpioRegisterEvidenceConsumer(component=target_id, register=register,
            bit_lo=bit_lo, width=width, runtime_contract_sha256=runtime_contract_sha256)
    binding = None if session is None else _bind_case_session(session, runner)
    if session is not None and session.cases:
        raise ValueError('unused actual session required')
    handle = _Installation()
    _INSTALLATIONS[handle] = dict(runner=runner, authority=authority, target=target,
        consumer=consumer, cursor=0,
        events_since=ScenarioRunner.events_since,
        event_by_id=ScenarioRunner.event_by_id,
        case_session=binding,
        configuration=dict(provider='gpio_register_version.v1',
            runtime_contract_sha256=runtime_contract_sha256,
            parameters=dict(component=target_id, register=register, bit_lo=bit_lo, width=width)),
        scope=dict(component=target_id, register=register,
                                             bit_lo=bit_lo, width=width))
    return handle


def read_gpio_relations(handle):
    """Authenticated live consumer report; arbitrary dicts stay unknown."""
    unknown = dict(status='unknown', relations=(), reward_eligible=False,
        native_authority=False, irq_status='unknown', isr_status='unknown')
    if type(handle) is not _Installation or handle not in _INSTALLATIONS:
        return dict(unknown, reason='missing-live-consumer-installation')
    from .gpio import read_gpio_current
    state = _INSTALLATIONS[handle]
    runner, target = state['runner'], state['target']
    state['live_current'] = None
    state['live_witness'] = None
    try:
        from myfuzz.scenario.runner import ScenarioRunner
        if ('events_since' in vars(runner)
                or ScenarioRunner.events_since is not state['events_since']
                or runner.events_since.__func__ is not state['events_since']
                or 'event_by_id' in vars(runner)
                or ScenarioRunner.event_by_id is not state['event_by_id']
                or runner.event_by_id.__func__ is not state['event_by_id']
                or runner._status != 'running'
                or runner.sessions.get(state['scope']['component']) is not target):
            raise ValueError('live runner changed')
        before = read_gpio_current(state['authority'], target)
        # Public single-use tokens validate the actual command horizon. Keep
        # these witness documents inside this live query; saved reports cannot
        # substitute for the installation or grant authority.
        witness_before = state['authority'].consume(state['authority'].issue(
            register='GPIOEN', reset_epoch=target.reset_epoch))
        count = runner.event_count
        events = state['events_since'](runner, state['cursor'])
        for event in events:
            state['consumer'].consume(event)
        state['cursor'] = count
        report = state['consumer'].report()
        witness_after = state['authority'].consume(state['authority'].issue(
            register='GPIOEN', reset_epoch=target.reset_epoch))
        after = read_gpio_current(state['authority'], target)
        if (before != after or witness_before != witness_after
                or runner.event_count != count):
            raise ValueError('live state changed during report')
        relations = validate_gpio_relation_documentary(report,
            **state['scope'], epoch=target.reset_epoch)
        binding = state.get('case_session')
        needed = {v for row in relations
                  for v in row['writer_event_ids'] + [row['read_event_id']]}
        observed_cases = (None if binding is None else
            _read_case_attribution(binding, runner, state, needed))
        attributed = []
        for row in relations:
            ids = row['writer_event_ids'] + [row['read_event_id']]
            source_events = {v: state['event_by_id'](runner, v) for v in ids}
            observed = attribute_gpio_relation_documentary(row, source_events,
                observed_cases=observed_cases)
            attributed.append(dict(observed, reward_eligible=observed['cross_testcase'] is True))
        relations = tuple(attributed)
        if runner.event_count != count:
            raise ValueError('live journal changed during attribution')
        state['live_current'] = after
        state['live_witness'] = witness_after
        return dict(unknown, status='verified' if relations else 'unknown',
                    relations=relations, reward_eligible=any(r['reward_eligible'] for r in relations),
                    reason='live-exact-apb-read' if relations else 'no-exact-read')
    except (ValueError, TypeError, RuntimeError, AttributeError):
        return dict(unknown, reason='live-consumer-scope-unavailable')


def read_gpio_irq_relations(handle):
    """Authenticate live journal and exact public session receipt boundaries.

    The endpoint is native GPIO configuration consumption only. Input admission,
    CPU delivery and ISR execution are neither required nor inferred here.
    """
    unknown = dict(status='unknown', relations=(), reward_eligible=False,
                   native_authority=False, irq_status='unknown', isr_status='unknown')
    if type(handle) is not _Installation or handle not in _INSTALLATIONS:
        return dict(unknown, reason='missing-live-consumer-installation')
    handle.report()  # Same pinned authority authentication and complete drain.
    state = _INSTALLATIONS[handle]
    from .gpio_fields import GpioFieldDocuments
    if (state.get('live_current') is None or state.get('live_witness') is None
            or type(state['consumer']) is not GpioFieldDocuments
            or state.get('case_session') is None):
        return dict(unknown, reason='missing-live-irq-scope-or-session')
    try:
        runner = state['runner']
        count = runner.event_count
        document = state['consumer'].documentary_irq_report()
        rows = document['relations'] if document['journal_integrity'] is True else ()
        needed = {v for row in rows for v in
                  row['writer_event_ids'] + [row['consumer_event_id']]}
        cases = _read_case_attribution(state['case_session'], runner, state, needed)
        result = []
        for row in rows:
            ids = row['writer_event_ids']
            resources = row['bit_resources']
            consumer_id = row['consumer_event_id']
            event = state['event_by_id'](runner, consumer_id)
            if (row['reset_epoch'] != state['target'].reset_epoch
                    or row['endpoint'] != 'native_gpio_irq_configuration_consumption'
                    or len(resources) != 1 or len(ids) != 1
                    or not _positive(ids[0]) or not ids[0] < consumer_id
                    or event.get('kind') not in ('gpio_tick_observation', 'gpio_apb_access')
                    or event.get('component') != row['component']
                    or event.get('reset_epoch') != row['reset_epoch']):
                continue
            writer = state['event_by_id'](runner, ids[0])
            r = resources[0]
            if (r['observation_event_id'] != ids[0] or r['value'] != 1
                    or r['register'] != 'gpioen' or r['bit'] != 8
                    or r['reset_epoch'] != row['reset_epoch']
                    or not _positive(r['version'])
                    or writer.get('kind') != 'gpio_apb_access'
                    or writer.get('write') is not True
                    or writer.get('decoded_offset') != 4
                    or writer.get('component') != row['component']
                    or writer.get('reset_epoch') != row['reset_epoch']
                    or writer.get('source_transaction') != r['transaction']
                    or row['writer_transactions'] != [r['transaction']]):
                continue
            writer_cases = [cases.get(v, {}).get('case_id') for v in ids]
            consumer_case = cases.get(consumer_id, {}).get('case_id')
            attributed = all(writer_cases) and consumer_case is not None
            cross = (all(v != consumer_case for v in writer_cases)
                     if attributed else None)
            relation_id = 'gpio-irq:' + sha256(canonical(dict(
                component=row['component'], register='gpioen', bit_lo=8, width=1,
                values=[1], endpoint=row['endpoint']))).hexdigest()
            result.append(dict(row, writer_case_ids=writer_cases,
                consumer_case_id=consumer_case, cross_testcase=cross,
                attribution='attributed' if attributed else 'unattributed',
                relation_id=relation_id, reward_eligible=cross is True))
        if runner.event_count != count:
            raise ValueError('live journal changed during IRQ attribution')
        return dict(unknown, status='verified' if result else 'unknown',
                    relations=tuple(result),
                    reward_eligible=any(r['reward_eligible'] for r in result),
                    irq_status='configuration_consumed' if result else 'unknown',
                    reason='live-exact-native-irq-configuration' if result else 'no-exact-irq-consumption')
    except (KeyError, ValueError, TypeError, RuntimeError, AttributeError):
        return dict(unknown, reason='live-irq-scope-unavailable')
