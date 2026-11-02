"""Source-verified fixed-ISR MRET issuance from original parsed CPU callbacks.

The exported event is evidence, never an input that can recreate live authority.
The registry owns the actual take independently of the latest sample receipt.
"""
from copy import deepcopy
from hashlib import sha256
import json
import re
import sys
from weakref import WeakKeyDictionary, ref

from myfuzz.local_harness.native_irq_receipt_contract import (
    native_irq_receipt_contract, verify_native_irq_receipt_artifact,native_irq_retirement_diverted)
from .irq_return_successor import (
    FULL_RVFI_AUTHORITY, PC_INSN_ORDER_ONLY_AUTHORITY, retirement_authority)


_RETIREMENT_FIELDS = ('rvfi_valid', 'rvfi_order', 'rvfi_insn', 'rvfi_pc_rdata')
_REDIRECT_KIND = 'cpu_native_exception_redirect'
_ACCEPTANCE_KEYS = ('ack_probe', 'id_probe', 'source_id', 'entry_pc_probe')


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _require(condition, message):
    if not condition:
        raise ValueError('F6 ISR return: ' + message)


def _decision_acceptance(provider):
    """Validate the pre-edge acceptance declaration of a limited CPU."""
    value = provider.get('decision_acceptance')
    _require(type(value) is dict and all(type(value.get(key)) is int
            for key in ('source_id',)) and all(
            type(value.get(key)) is str and value[key] for key in
            ('ack_probe', 'id_probe', 'entry_pc_probe')),
            'limited authority requires a typed decision_acceptance')
    if 'id_width' in value:
        _require(type(value['id_width']) is int and 0 < value['id_width'] <= 64,
                 'decision_acceptance id_width must be a bit count')
    return dict(value)


def _limited_retirement_scope(provider, session):
    """Bind the declared PC/order/insn-only stream to the actual artifact."""
    fields = provider.get('retirement_fields')
    _require(type(fields) in (list, tuple)
             and all(type(name) is str for name in fields),
             'limited authority requires retirement_fields')
    normalized = {name if name.startswith('rvfi_') else 'rvfi_' + name for name in fields}
    _require(set(_RETIREMENT_FIELDS) <= normalized
             and normalized <= set(session._rvfi_contract['fields']),
             'declared retirement fields are not the actual observed stream')
    unobserved = provider.get('unobserved_retirement_fields')
    _require(type(unobserved) in (list, tuple)
             and all(type(name) is str and name for name in unobserved)
             and not normalized & {name if name.startswith('rvfi_') else 'rvfi_' + name
                                   for name in unobserved},
             'unobserved retirement fields must be declared and disjoint')
    diversion = provider.get('retirement_diversion_fields', [])
    _require(type(diversion) in (list, tuple) and not diversion,
             'limited authority cannot claim per-retirement diversion fields')
    _require(provider.get('retirement_diversion_scope') == 'unobservable',
             'limited authority cannot claim retirement diversion absence')
    return dict(fields=list(fields), unobserved=list(unobserved))


def _acceptance_probe(session, name):
    rows = [row for row in session._artifact_document['physical_exports']
            if row.get('physical_port') in (name, 'probe_' + name)]
    _require(len(rows) == 1 and rows[0].get('direction') == 'output'
             and type(rows[0].get('width')) is int and 0 < rows[0]['width'] <= 64,
             'limited authority requires the actual pre-edge export: ' + name)
    return rows[0]['physical_port']


def _take_pre_edge(take, acceptance):
    """Detached real pre-edge decision values of one authenticated take."""
    names = (acceptance['ack_probe'], acceptance['id_probe'],
             acceptance['entry_pc_probe'])
    detached = {name: take[name] for name in names if name in take}
    detached['accepted_source_id'] = acceptance['source_id']
    for name in ('irq_taken_pre', 'irq_redirect_pre', 'irq_redirect_cause'):
        if take.get(name) is not None:
            detached[name] = take[name]
    return detached


def _limited_take_accepted(take, acceptance):
    """The take must carry the declared real ack/id/entry pre-edge values."""
    if type(take) is not dict:
        return False
    source = acceptance['source_id']
    width = acceptance.get('id_width')
    identifier = take.get(acceptance['id_probe'])
    taken = take.get('irq_taken_pre', 1)
    return (take.get(acceptance['ack_probe']) == 1
            and type(identifier) is int and identifier == source
            and (width is None or 0 <= identifier < (1 << width))
            and type(take.get(acceptance['entry_pc_probe'])) is int
            and take[acceptance['entry_pc_probe']] % 4 == 0
            and take.get('irq_redirect_pre', 0) in (0, None)
            and taken == 1)


def _redirect_ticks(state, *, since):
    rows = [row for row in state['redirects']
            if type(row.get('local_tick')) is int and row['local_tick'] >= since]
    return rows


def _allow_shared_gpio_mret(session, state, physical):
    """Observe a typed F5 GPIO return without issuing any F6 credential.

    The native callback still owns the parsed retirement. This exception only
    prevents the independent DMA issuer from rejecting another declared ISR.
    """
    from myfuzz.integration.shared_f6_slots import _CPU_OWNERS, _state, case_mapping, fixed_support_case_mapping
    from .session_runtime import ScenarioSession
    from .f6_instruction_fetch_receipt import validate_shared_fixed_support
    dispatch=state['dispatch'];program=state['program']
    _require(state['active'] is None and dispatch is not None
        and 'F5' in program.get('shared_slots',{}).get('enabled_flows',()),
        'shared GPIO MRET requires declared fixed support')
    stage_name='declared_target' if 'declared_irq' in program else 'gpio'
    gpio=dispatch['stages'][stage_name];pc=physical.get('rvfi_pc_rdata')
    provider=native_irq_receipt_contract(session.artifact)
    limited=retirement_authority(provider)==PC_INSN_ORDER_ONLY_AUTHORITY
    if limited:
        # This CPU drives no intr/trap/mode field.  Their absence is the honest
        # observation; requiring a zero here would be a fabricated claim.
        _require(physical.get('rvfi_valid')==1 and physical.get('rvfi_insn')==0x30200073
            and pc in gpio['mret_addresses']
            and 'rvfi_intr' not in physical and 'rvfi_trap' not in physical
            and 'rvfi_mode' not in physical
            and not native_irq_retirement_diverted(provider,physical),
            'shared GPIO MRET must be its fixed native retirement')
    else:
        _require(physical.get('rvfi_valid')==1 and physical.get('rvfi_insn')==0x30200073
            and pc in gpio['mret_addresses'] and physical.get('rvfi_trap')==0
            and physical.get('rvfi_intr')==0 and physical.get('rvfi_mode')==3
            and not native_irq_retirement_diverted(provider,physical),
            'shared GPIO MRET must be its fixed native retirement')
    owner=_CPU_OWNERS.get(session);runtime=owner() if owner is not None else None
    _require(runtime is not None,'shared GPIO MRET requires actual slot owner')
    slots=_state(runtime);scenario=slots['session']
    _require(runtime.cpu is session and runtime.execution_binding_sha256==state['binding']
        and _canonical(runtime.contract['program_contract'])==_canonical(program)
        and type(scenario) is ScenarioSession and scenario.runner is runtime.runner,
        'shared GPIO MRET owner/binding differs')
    method,code=_GPIO_SESSION_EXECUTE
    _require(ScenarioSession._execute_case is method and method.__code__ is code
        and '_execute_case' not in vars(scenario),'shared GPIO session method drift')
    frame=sys._getframe(1)
    while frame is not None and not (frame.f_code is code and frame.f_locals.get('self') is scenario):
        frame=frame.f_back
    _require(frame is not None,'shared GPIO MRET requires actual executing case')
    case=frame.f_locals.get('case');index=len(scenario._cases)-1
    _require(index>=0 and scenario._cases[index] is case and case.case_id not in scenario._receipts,
        'shared GPIO MRET requires current pending case')
    mapping=case_mapping(runtime,case.case_id)
    _require(mapping['flow']=='F5' and mapping['status']=='reserved'
        and mapping['session_case_index']==index,'shared GPIO MRET requires actual F5 mapping')
    if stage_name == 'gpio':
        _require(len(case.support_instructions)==1,'shared GPIO MRET requires fixed support')
        support=case.support_instructions[0]
        fixed_support_case_mapping(runtime,scenario,case,index,support)
        bound=validate_shared_fixed_support(session,case_id=case.case_id)
        _require(bound['slot_index']==mapping['slot_index'] and bound['session_case_index']==index
            and bound['role']=='fixed_support' and bound['F6_authority'] is False
            and bound['fuzz_authority'] is False,'shared GPIO MRET requires original support acceptance')
    else:
        from myfuzz.integration.shared_f6_slots import instruction_case_mapping
        from .session_runtime import BoundOnlineInstruction
        source=case.source
        _require(type(source) is BoundOnlineInstruction and not case.support_instructions,
            'shared declared MRET requires actual typed instruction source')
        resolved=instruction_case_mapping(runtime,scenario,case,index)
        admission=scenario.runner._provenance.registry.get(source.action_id)
        _require(resolved['flow']=='F5' and admission is not None
            and admission.case_id==case.case_id and admission.action_id==source.action_id
            and admission.component==session.source_component and admission.input_kind=='instruction',
            'shared declared MRET requires original source admission')
        rows=[event for event in scenario.runner._event_refs_since(0)
            if event.get('kind')=='instruction_source' and event.get('component')==session.source_component
            and event.get('source_event_id')==source.action_id]
        _require(len(rows)==1 and rows[0].get('address')==source.address
            and rows[0].get('data_hex')==source.data.hex()
            and rows[0].get('f6_acceptance_anchor',{}).get('source_event_id')==source.action_id,
            'shared declared MRET requires original instruction acceptance')
        snapshots=[session.memory.read(source.address+i,4,transaction_id='shared-declared-ISR:'+case.case_id+':'+str(i))
                   for i in range(0,len(source.data),4)]
        _require(b''.join(row.data for row in snapshots)==source.data
            and all(row.writer_kinds==('INSTRUCTION_SOURCE',)*4
                    and row.writer_event_ids==(source.action_id,)*4 for row in snapshots),
            'shared declared MRET instruction source changed')
    start=gpio['address'];length=gpio['length'];offset=start-state['isr']['address']
    expected=state['isr_bytes'][offset:offset+length]
    actual=[session.memory.read(start+i,4,transaction_id='shared-GPIO-MRET:'+case.case_id+':'+str(i))
        for i in range(0,length,4)]
    _require(len(expected)==length and sha256(expected).hexdigest()==gpio['sha256']
        and expected[pc-start:pc-start+4]==b'\x73\x00\x20\x30'
        and b''.join(row.data for row in actual)==expected
        and all(row.writer_kinds==('INITIAL_IMAGE',)*4
            and row.writer_event_ids==('initial-image',)*4 for row in actual),
        'shared GPIO MRET fixed stage bytes changed')
    return True


from .session_runtime import ScenarioSession as _GPIO_CASE_SESSION
_GPIO_SESSION_EXECUTE=(_GPIO_CASE_SESSION._execute_case,_GPIO_CASE_SESSION._execute_case.__code__)


_SEAL = object()


class F6IsrReturnIssuer:
    """Detached observations from one sealed original generated CPU session."""
    __slots__ = ('_owner',)

    def __init__(self, session, *, _seal=None):
        _require(_seal is _SEAL, 'requires registered installation')
        object.__setattr__(self, '_owner', ref(session))

    def __setattr__(self, name, value):
        raise AttributeError('F6 ISR return issuer is sealed')

    def begin_case(self, case_id, *, case_index, irq_take_key):
        _begin_f6_case(self, case_id, case_index=case_index, irq_take_key=irq_take_key)

    def document(self):
        return json.loads(_issuer_state(self)['document'])

    @property
    def events(self):
        return tuple(json.loads(row) for row in _issuer_state(self)['events'])


def _registry():
    from myfuzz.integration.shared_f6_slots import f6_slot_for_cpu as shared_slot_for_cpu
    sessions = WeakKeyDictionary()
    original = None
    issuer_methods = tuple((name, method, method.__code__)
        for name, method in vars(F6IsrReturnIssuer).items()
        if callable(method) and hasattr(method, '__code__'))

    def seal(cls):
        nonlocal original
        _require(original is None, 'CPU provider already sealed')
        names = ('_retire', '_native_retirement_receipt', '_native_irq_facts',
                 '_step_local', '_cpu_event', '_physical_outputs',
                 '_serial_observation', 'identity_document', '_serve', '_freeze_snapshot',
                 '_key', '_resume_instruction')
        original = (cls, tuple((name, getattr(cls, name), getattr(cls, name).__code__)
                               for name in names))

    def check_original(session):
        _require(original is not None and type(session) is original[0],
                 'requires exact registered CPU session')
        for name, method, code in original[1]:
            _require(name not in vars(session) and getattr(type(session), name) is method
                     and method.__code__ is code, 'original CPU method drift: ' + name)
        for name, method, code in issuer_methods:
            _require(getattr(F6IsrReturnIssuer, name) is method and method.__code__ is code,
                     'issuer method drift: ' + name)

    def state_for(session):
        state = sessions.get(session)
        if state is None:
            _require(getattr(session, '_f6_isr_return', None) is None, 'unregistered issuer')
            return None
        check_original(session)
        _require(getattr(session, '_f6_isr_return', None) is state['issuer']
                 and type(state['issuer']) is F6IsrReturnIssuer
                 and state['issuer']._owner() is session
                 and session.native_irq_receipts_enabled
                 and session.source_component == state['component']
                 and session.source_component == session.artifact.plan.request.instance_id,
                 'issuer owner/provider/component drift')
        _require(_canonical(session._artifact_document) == state['artifact']
                 and _canonical(session.artifact.runtime_document) == state['artifact'],
                 'registered artifact drift')
        _require(session.service is state['service'] and session.memory is state['memory']
                 and session.service.memory is state['memory']
                 and session.service.ledger is state['ledger'], 'CPU service/ledger owner drift')
        return state

    def issuer_state(issuer):
        _require(type(issuer) is F6IsrReturnIssuer, 'unregistered issuer type')
        session = issuer._owner()
        _require(session is not None, 'CPU session expired')
        state = state_for(session)
        _require(state is not None and state['issuer'] is issuer, 'unregistered issuer')
        return state

    def install(session, *, contract, execution_binding_sha256):
        from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
        from .f6_execution_contract import CONTRACT_KEYS, EXPECTATION_IDS, SCHEMA_VERSION
        check_original(session)
        _require(session not in sessions and getattr(session, '_f6_isr_return', None) is None,
                 'installation is once only')
        _require(session.source_component == session.artifact.plan.request.instance_id,
                 'CPU logical instance differs from registered artifact')
        _require(session.native_irq_receipts_enabled and session._rvfi_enabled,
                 'native IRQ/RVFI provider required')
        _require(type(execution_binding_sha256) is str
                 and re.fullmatch('[0-9a-f]{64}', execution_binding_sha256) is not None,
                 'execution binding SHA256 required')
        verify_native_irq_receipt_artifact(session.artifact, base_dir=session.base_dir)
        _require(_canonical(session._artifact_document) == _canonical(session.artifact.runtime_document),
                 'source artifact differs from session')
        _require(type(contract) is dict and set(contract) == CONTRACT_KEYS
                 and contract['schema_version'] == SCHEMA_VERSION and contract['flow_id'] == 'F6'
                 and contract['termination'] == 'native_dma_irq_then_cpu_isr_readback'
                 and contract['expectation_ids'] == list(EXPECTATION_IDS), 'complete F6 contract required')
        cpu, irq = contract['cpu'], contract['irq']
        provider = native_irq_receipt_contract(session.artifact)
        authority = retirement_authority(provider)
        limited = authority == PC_INSN_ORDER_ONLY_AUTHORITY
        acceptance = _decision_acceptance(provider) if limited else None
        retirement_scope = (_limited_retirement_scope(provider, session)
                            if limited else None)
        _require(type(cpu) is dict and type(irq) is dict
                 and cpu.get('instance_id') == session.source_component
                 and cpu.get('profile_fingerprint') == session.artifact.plan.profile.profile_fingerprint
                 and cpu.get('artifact_kind') == 'obi_cpu'
                 and cpu.get('source_verification_sha256') == sha256(_canonical(
                     session._artifact_document['source_verification']).encode()).hexdigest()
                 and _canonical(cpu.get('native_irq_provider')) == _canonical(provider)
                 and _canonical(irq.get('native_take_provider')) == _canonical(provider)
                 and irq.get('consumer_instance') == session.source_component
                 and irq.get('consumer_port') == provider['input_port']
                 and irq.get('isr_return_schema') == 'native_f6_isr_return.v1',
                 'contract does not bind registered source provider')
        if limited:
            # No serial token exists on this CPU. The real pre-edge acceptance
            # probes are the only decision observation; their exports must be
            # actual physical outputs of the registered artifact.
            for name in (acceptance['ack_probe'], acceptance['id_probe'],
                         acceptance['entry_pc_probe']):
                _acceptance_probe(session, name)
        else:
            for port in ('irq_decision_serial', 'irq_retirement_serial'):
                rows = [row for row in session._artifact_document['physical_exports']
                        if row['physical_port'] == port]
                _require(len(rows) == 1 and rows[0]['direction'] == 'output'
                         and type(rows[0]['width']) is int and rows[0]['width'] == 64
                         and rows[0]['bit_lo'] == 0, 'actual serial export required: ' + port)
        firmware = build_f6_firmware(contract)
        p, fw = contract['program_contract'], firmware.document()
        _require(_canonical(p['initial_image']) == _canonical(firmware.initial_segment_manifest)
                 and p['initial_image_sha256'] == firmware.manifest_sha256,
                 'final sparse manifest/hash required')
        isr = fw['isr']
        data = firmware.initial_images[p['isr_address']]
        sites = [p['isr_address']+offset for offset in range(0, len(data), 4)
                 if data[offset:offset+4] == b'\x73\x00\x20\x30']
        dispatch=fw.get('irq_dispatch')
        other_stage=('declared_target' if 'declared_irq' in p else 'gpio')
        expected_sites=(sorted(dispatch['stages']['dma']['mret_addresses']+dispatch['stages'][other_stage]['mret_addresses'])
            if dispatch is not None else isr['mret_addresses'])
        _require(isr['address'] == p['isr_address'] and isr['length'] == len(data)
                 and isr['sha256'] == sha256(data).hexdigest()
                 and sites == expected_sites and len(isr['mret_addresses']) == 2
                 and (dispatch is None or isr['mret_addresses']==dispatch['stages']['dma']['mret_addresses']),
                 'canonical success/error ISR MRET bytes required')
        issuer = F6IsrReturnIssuer(session, _seal=_SEAL)
        document = dict(schema_version='native_f6_isr_return_issuer.v1',
            provider=provider, component=session.source_component,
            artifact_digest=session._artifact_document['artifact_digest'],
            contract_sha256=sha256(_canonical(contract).encode()).hexdigest(),
            execution_binding_sha256=execution_binding_sha256,
            initial_image_sha256=firmware.manifest_sha256, isr=isr,
            **(dict(irq_dispatch=dispatch) if dispatch is not None else {}),
            scope=('canonical_fixed_ISR_MRET_only' if not limited else
                   'canonical_fixed_ISR_MRET_only_pc_insn_order_only_retirement'),
            irq_serial_join=(('take_decision_to_first_ISR_retirement' if not limited else
                'take_pre_edge_decision_to_first_retirement_at_irq_entry_pc')),
            return_target_source=('first_subsequent_valid_RVFI_pc_rdata_with_instruction_response'
                if not limited else 'first_subsequent_valid_retirement_pc'),
            return_target_authority='inferred_architectural_successor_after_MRET',
            **({} if not limited else dict(
                retirement_authority=authority,
                unobserved_fields=list(retirement_scope['unobserved']),
                retirement_diversion_scope='unobservable',
                decision_acceptance=deepcopy(acceptance))))
        sessions[session] = dict(issuer=issuer, component=session.source_component,
            document=_canonical(document),
            artifact=_canonical(session._artifact_document), program=deepcopy(p),
            service=session.service, memory=session.memory, ledger=session.service.ledger,
            binding=execution_binding_sha256, isr=deepcopy(isr), isr_bytes=data, dispatch=deepcopy(dispatch), active=None,
            last_index=-1, case_ids=set(), used_keys=set(), events=(), last_receipt=None, campaign_scope=None,
            authority=authority, acceptance=deepcopy(acceptance),
            unobserved=(list(retirement_scope['unobserved']) if retirement_scope is not None else None),
            redirects=[], redirect_pins=set())
        session._f6_isr_return = issuer
        return issuer

    def begin(issuer, case_id, *, case_index, irq_take_key):
        state = issuer_state(issuer)
        session = issuer._owner()
        _require(type(case_id) is str and case_id and case_id.strip() == case_id
                 and case_id not in state['case_ids']
                 and type(case_index) is int and case_index == state['last_index']+1
                 and 0 <= case_index < state['program']['slot_count']
                 and state['active'] is None, 'requires next unique logical case')
        _require(type(irq_take_key) in (tuple, list) and len(irq_take_key) == 3
                 and type(irq_take_key[0]) is str and irq_take_key[0] == session.source_component
                 and type(irq_take_key[1]) is int and irq_take_key[1] == session.reset_epoch
                 and type(irq_take_key[2]) is int
                 and irq_take_key[2] == session._native_irq_take_sequence+1
                 and tuple(irq_take_key) not in state['used_keys'], 'requires next current IRQ take key')
        _require(type(session._execution) is str
                 and re.fullmatch('[0-9a-f]{32}', session._execution) is not None
                 and type(session._case_id) is str and session._case_id,
                 'requires live native execution/testcase scope')
        scope = (session._execution, session.reset_epoch, session._case_id)
        _require(state['campaign_scope'] in (None, scope), 'campaign process/epoch/testcase changed')
        state['campaign_scope'] = scope
        state['active'] = dict(case_id=case_id, case_index=case_index,
            key=list(irq_take_key), scope=(session._execution, session.reset_epoch, session._case_id),
            sequence_floor=session._sequence, take=None, take_pin=None,
            order_floor=session._last_retire_order, entry=None, invalid=False, pending_mret=None, responses=[],
            dispatch_progress=0,dma_stage_entered=False,dispatch_retirements=[],pre_entry_retirements=[],
            last_order=(session._last_retire_order[1] if session._last_retire_order else None))
        if 'shared_slots' in state['program']:
            state['active']['slot_index'] = shared_slot_for_cpu(session, case_index, case_id)
        state['last_index'] = case_index
        state['case_ids'].add(case_id)

    def capture_receipt(session, receipt, physical):
        state = state_for(session)
        if state is None:
            return
        # A saved receipt, a generic event, or an arbitrary caller cannot open
        # this seam. The original _retire and _step_local frames own its inputs.
        frame = sys._getframe(2)
        parent = frame.f_back
        methods = {name: code for name, _, code in original[1]}
        _require(frame.f_code is methods['_retire'] and frame.f_locals.get('self') is session
                 and frame.f_locals.get('receipt') is receipt
                 and frame.f_locals.get('physical') is physical
                 and parent is not None and parent.f_code is methods['_step_local']
                 and parent.f_locals.get('self') is session
                 and parent.f_locals.get('receipt') is receipt,
                 'requires original parsed native retirement callback')
        limited = state['authority'] == PC_INSN_ORDER_ONLY_AUTHORITY
        # The Runner journals and clears producer events after every step. This
        # callback runs inside the original step, so every redirect emitted in
        # this step is still visible here and can be pinned for the whole case.
        for redirect in session.cpu_events:
            if redirect.get('kind') != _REDIRECT_KIND:
                continue
            pin = _canonical(redirect)
            if pin in state['redirect_pins']:
                continue
            state['redirect_pins'].add(pin)
            state['redirects'].append(deepcopy(redirect))
        active = state['active']
        current = (session._execution, session.reset_epoch, session._case_id)
        identity = (session.reset_epoch, receipt.execution, receipt.sequence, receipt.tick_after)
        previous = state['last_receipt']
        _require(previous is None or identity[:2] != previous[:2]
                 or identity[2] == previous[2]+1 and identity[3] == previous[3]+1,
                 'native receipt reused or regressed')
        state['last_receipt'] = identity
        if active is None:
            if physical.get('rvfi_valid') and physical.get('rvfi_insn')==0x30200073:
                _allow_shared_gpio_mret(session,state,physical)
            return
        _require(not active['invalid'] and current == active['scope'],
                 'conflicting observation or native execution/epoch/testcase changed')
        if not limited and native_irq_retirement_diverted(
                native_irq_receipt_contract(session.artifact),physical):
            active['invalid'] = True
            raise ValueError('F6 ISR return: actual debug/halt diversion')
        # Every authenticated take is captured at its own actual parsed receipt,
        # even if that edge retires no instruction. Later samples cannot replace it.
        taken = [event for event in session.cpu_events
                 if event.get('kind') == 'cpu_external_irq_taken'
                 and event.get('take_key') == active['key']]
        receipt_id = {'execution': receipt.execution, 'sequence': receipt.sequence}
        current_takes = [event for event in session.cpu_events
                         if event.get('kind') == 'cpu_external_irq_taken'
                         and event.get('receipt_id') == receipt_id]
        if current_takes and (len(current_takes) != 1 or current_takes[0].get('take_key') != active['key']
                              or active['take'] is not None):
            active['invalid'] = True
            raise ValueError('F6 ISR return: conflicting new or duplicate IRQ take')
        for event in taken:
            if event.get('receipt_id') == receipt_id:
                _require(active['take'] is None and len(taken) == 1
                         and receipt.sequence > active['sequence_floor'], 'duplicate/stale IRQ take')
                sample = receipt.payload['samples'][0]
                accept = state['acceptance']
                if limited:
                    # The real pre-edge ack/id/entry values of this CPU, never
                    # an inferred or zero-filled decision.
                    _require(_limited_take_accepted(event, accept)
                             and type(event.get('local_tick')) is int
                             and event.get('source_epoch') == session.reset_epoch
                             and event.get('command_scope') == dict(component=session.source_component,
                                 reset_epoch=session.reset_epoch, command_sequence=receipt.sequence),
                             'take is not the actual native pre-edge observation')
                    _require(event[accept['entry_pc_probe']] == state['isr']['address'],
                             'actual IRQ entry PC differs from the declared ISR address')
                    _require(not _redirect_ticks(state, since=event['local_tick']),
                             'actual IRQ take is followed by an exception/debug redirect')
                else:
                    _require(sample['pre']['physical'].get('probe_irq_taken_pre') == 1
                             and event.get('source_epoch') == session.reset_epoch
                             and event.get('command_scope') == dict(component=session.source_component,
                                 reset_epoch=session.reset_epoch, command_sequence=receipt.sequence),
                             'take is not the actual native observation')
                active['take'] = event
                active['take_pin'] = _canonical(event)
        # Capture only responses produced by this original _step_local frame's
        # actual consumed handshake. Saved instr_response dictionaries do not
        # enter this registry and cannot certify the resumed instruction.
        if parent.f_locals.get('iconsumed'):
            response = parent.f_locals['ipending']
            rows = [event for event in session.cpu_events if event.get('kind') == 'instr_response'
                    and event.get('response_tick') == session.local_ticks]
            pre = receipt.payload['pre_backend']
            _require(len(rows) == 1 and response is not None
                     and pre['i_rsp_valid'] == pre['i_rsp_ready'] == 1
                     and pre['i_rsp_rdata'] == response[0] and pre['i_rsp_error'] == response[1]
                     and rows[0].get('rdata') == response[0] and rows[0].get('error') == response[1]
                     and rows[0]['transaction']['execution_id'] == 'local-execution'
                     and rows[0]['transaction']['testcase_id'] == session._case_id
                     and rows[0]['transaction']['source_component'] == session.source_component
                     and rows[0]['transaction']['source_epoch'] == session.reset_epoch
                     and rows[0]['transaction']['channel_id'] == 'instr'
                     and type(rows[0]['transaction']['source_sequence']) is int
                     and 0 < rows[0]['transaction']['source_sequence'] == response[2]
                     and response[2] <= session._sequences['instr']
                     and type(rows[0].get('acceptance_tick')) is int
                     and rows[0]['acceptance_tick'] <= session.local_ticks,
                     'instruction response is not the actual consumed native handshake')
            active['responses'].append((rows[0], _canonical(rows[0]), deepcopy(receipt_id)))

        # Invalid RVFI cycles can retain arbitrary stale instruction and PC
        # fields. They carry no retirement or handler-entry meaning.
        if not physical.get('rvfi_valid'):
            return
        pc, instruction = physical.get('rvfi_pc_rdata'), physical.get('rvfi_insn')
        order = physical.get('rvfi_order')
        if limited:
            # trap/debug/NMI are not driven by this CPU. They are neither read
            # nor asserted; the redirect-event window below is the only
            # diversion observation this authority can make.
            if (type(order) is not int or order <= 0
                    or active['last_order'] is not None and order != active['last_order']+1):
                active['invalid'] = True
                raise ValueError('F6 ISR return: nonincreasing actual retirement order')
        elif (physical.get('rvfi_trap') != 0 or type(order) is not int or order <= 0
                or active['last_order'] is not None and order != active['last_order']+1
                or physical.get('rvfi_mode') != 3
                or native_irq_retirement_diverted(native_irq_receipt_contract(session.artifact),physical)):
            active['invalid'] = True
            raise ValueError('F6 ISR return: trap or nonincreasing actual RVFI order')
        active['last_order'] = order
        serial = None if limited else session._serial_observation(physical, physical,
            sampling='post_rising', decision_phase='post', retirement_phase='post')
        take = active['take']
        def authentic_take():
            take_receipt = take.get('receipt_id') if type(take) is dict else None
            same_receipt = (type(take_receipt) is dict
                and take_receipt.get('execution') == receipt.execution
                and take_receipt.get('sequence') == receipt.sequence)
            prior_receipt = (type(take_receipt) is dict
                and take_receipt.get('execution') == receipt.execution
                and type(take_receipt.get('sequence')) is int
                and take_receipt['sequence'] < receipt.sequence
                and type(take.get('local_tick')) is int
                and take['local_tick'] < session.local_ticks)
            visible_take_is_pinned = not taken or (len(taken) == 1 and taken[0] is take)
            same_receipt_pre_post = (same_receipt
                and type(take.get('local_tick')) is int
                and take['local_tick'] == session.local_ticks
                and (_limited_take_accepted(take, state['acceptance']) if limited else
                     receipt.payload['samples'][0]['pre']['physical'].get(
                         'probe_irq_taken_pre') == 1)
                and len(taken) == 1 and taken[0] is take)
            _require(take is not None and _canonical(take) == active['take_pin']
                     and take.get('take_key') == active['key']
                     and take.get('source_epoch') == session.reset_epoch
                     and take_receipt is not None
                     and take_receipt.get('execution') == receipt.execution
                     and (same_receipt_pre_post or prior_receipt and visible_take_is_pinned),
                     'missing/altered/cross-receipt IRQ take')
        if limited:
            if active['take'] is None:
                # No external take has been observed in this case yet.  Ordinary
                # program retirements carry no entry meaning, but a retirement
                # at the declared ISR address or an MRET without any acceptance
                # is a contradiction and must be refused.
                if pc == state['isr']['address'] or instruction == 0x30200073:
                    active['invalid'] = True
                    raise ValueError('F6 ISR return: return evidence without an observed take')
                return
            accept = state['acceptance']
            entry_pc = active['take'].get(accept['entry_pc_probe'])
            if active['entry'] is None:
                _require(type(entry_pc) is int and entry_pc % 4 == 0
                         and entry_pc == state['isr']['address'],
                         'actual IRQ entry PC is unavailable or differs from the declared ISR')
                if pc == entry_pc:
                    authentic_take()
                    _require(instruction == int.from_bytes(state['isr_bytes'][:4], 'little'),
                             'first retirement at the actual IRQ entry PC has the wrong instruction')
                    _require(not _redirect_ticks(state, since=take['local_tick']),
                             'handler entry follows an actual exception/debug redirect')
                    if state['dispatch'] is not None:
                        active['dispatch_progress'] = 1
                        active['dispatch_retirements'].append(dict(pc=pc, instruction=instruction,
                            rvfi_order=order, receipt_id=deepcopy(receipt_id)))
                    active['entry'] = dict(receipt_id=receipt_id, local_tick=session.local_ticks,
                        rvfi_order=order, pc_rdata=pc, instruction=instruction,
                        take_pre_edge_observation=_take_pre_edge(take, accept))
                    return
                # Drain retirements before the redirect actually reaches the
                # handler are recorded, never silently skipped.
                active['pre_entry_retirements'].append(dict(pc=pc, instruction=instruction,
                    rvfi_order=order, receipt_id=deepcopy(receipt_id)))
                return
            if pc == entry_pc:
                active['invalid'] = True
                raise ValueError('F6 ISR return: intervening handler entry')
        elif physical.get('rvfi_intr') == 1 or pc == state['isr']['address']:
            if active['entry'] is not None:
                active['invalid'] = True
                raise ValueError('F6 ISR return: intervening handler entry')
            authentic_take()
            decision = take['irq_serial_observation']['decision']
            retirement = serial['retirement']
            _require(physical.get('rvfi_intr') == 1 and pc == state['isr']['address']
                     and instruction == int.from_bytes(state['isr_bytes'][:4], 'little')
                     and decision['status'] == retirement['status'] == 'observed'
                     and type(decision['value']) is int and decision['value'] > 0
                     and decision['value'] == retirement['value'],
                     'first ISR retirement does not join actual IRQ take')
            if state['dispatch'] is not None:
                active['dispatch_progress']=1
                active['dispatch_retirements'].append(dict(pc=pc,instruction=instruction,rvfi_order=order,receipt_id=deepcopy(receipt_id)))
            active['entry'] = dict(receipt_id=receipt_id, local_tick=session.local_ticks,
                rvfi_order=order, pc_rdata=pc, instruction=instruction,
                irq_serial_observation=serial)
            return
        if state['dispatch'] is not None and active['entry'] is not None and not active['dma_stage_entered']:
            dispatch=state['dispatch'];path=dispatch['stages']['dma_dispatch_path']
            position=active['dispatch_progress']
            expected_pc=path[position] if position<len(path) else dispatch['stages']['dma']['address']
            offset=expected_pc-state['isr']['address']
            expected_word=int.from_bytes(state['isr_bytes'][offset:offset+4],'little')
            if (pc!=expected_pc or instruction!=expected_word
                    or (not limited and physical.get('rvfi_intr')!=0)):
                active['invalid']=True
                raise ValueError('F6 ISR return: actual dispatcher did not enter the DMA stage')
            active['dispatch_retirements'].append(dict(pc=pc,instruction=instruction,rvfi_order=order,receipt_id=deepcopy(receipt_id)))
            active['dispatch_progress']+=1
            if position<len(path):return
            active['dma_stage_entered']=True
        if active['pending_mret'] is not None:
            event = json.loads(active['pending_mret'])
            p = state['program']
            slot = p['slot_base']+active.get('slot_index', active['case_index'])*p['slot_bytes']
            from .irq_return_successor import validate_return_successor
            successor_fields = dict(order=order, local_tick=session.local_ticks,
                receipt_id=dict(execution=receipt.execution, sequence=receipt.sequence),
                pc_rdata=pc)
            if not limited:
                successor_fields.update(intr=physical.get('rvfi_intr'),
                    irq_serial_observation=serial)
            try:
                validate_return_successor(dict(order=event['rvfi_order'],
                    local_tick=event['local_tick'], receipt_id=event['return_receipt_id']),
                    successor_fields,
                    start=slot, end=slot+p['online_prefix_bytes']+8,
                    authority=state['authority'])
            except ValueError as error:
                active['invalid'] = True
                raise ValueError('F6 ISR return: first actual successor is not the current slot return') from error
            authentic_take()
            if limited:
                _require(not _redirect_ticks(state, since=take['local_tick']),
                         'actual exception/debug redirect occurred before the MRET successor')
            responses = [(row, pin, rid) for row, pin, rid in active['responses']
                         if row.get('address') == pc and row.get('rdata') == instruction
                         and type(row.get('error')) is int and row['error'] == 0
                         and row['response_tick'] <= session.local_ticks]
            _require(responses, 'actual successor has no matching error-free instruction response')
            response, pin, response_receipt = responses[-1]
            response_sequence = (response_receipt.get('sequence')
                                 if type(response_receipt) is dict else None)
            response_tick = response.get('response_tick')
            same_response_receipt = (type(response_receipt) is dict
                and set(response_receipt) == {'execution', 'sequence'}
                and response_receipt.get('execution') == receipt.execution == session._execution
                and type(response_sequence) is int and response_sequence > 0
                and response_sequence <= receipt.sequence
                and type(response_tick) is int and response_tick <= session.local_ticks
                and ((response_sequence == receipt.sequence
                      and response_tick == session.local_ticks)
                     or (response_sequence < receipt.sequence
                         and response_tick < session.local_ticks)))
            _require(same_response_receipt,
                     'actual successor instruction response receipt is outside this execution/order')
            _require(_canonical(response) == pin,
                     'pinned actual successor instruction response was altered')
            # The Runner journals and clears producer events after each CPU
            # step. A pinned response may therefore be absent by the time the
            # next RVFI retirement arrives. If a response for this exact
            # local tick is still visible, it must be the original unique row;
            # a copied, replaced, or duplicated row is not the issuer's pin.
            visible_responses = [row for row in session.cpu_events
                if row.get('kind') == 'instr_response' and row.get('response_tick') == response_tick]
            _require(not visible_responses
                     or len(visible_responses) == 1 and visible_responses[0] is response,
                     'visible successor instruction response was replaced or duplicated')
            event.update(successor_receipt_id=receipt_id, successor_rvfi_order=order,
                successor_local_tick=session.local_ticks, successor_pc_rdata=pc,
                successor_instruction=instruction,
                **({} if limited else {'successor_irq_serial_observation': serial}),
                successor_instruction_response=json.loads(pin),
                successor_instruction_response_receipt_id=response_receipt,
                return_target=pc,
                return_target_source=('first_subsequent_valid_RVFI_pc_rdata_with_instruction_response'
                    if not limited else 'first_subsequent_valid_retirement_pc'),
                return_target_authority='inferred_architectural_successor_after_MRET',
                **({} if not limited else dict(retirement_authority=state['authority'],
                    unobserved_fields=deepcopy(state['unobserved']))))
            state['events'] += (_canonical(event),)
            state['used_keys'].add(tuple(active['key']))
            state['active'] = None
            return
        at_site = pc in state['isr']['mret_addresses']
        if instruction != 0x30200073 and not at_site:
            return
        target = physical.get('rvfi_pc_wdata')
        order = physical.get('rvfi_order')
        _require(physical.get('rvfi_valid') == 1
                 and instruction == 0x30200073 and at_site
                 and type(order) is int and order > 0
                 and (limited or physical.get('rvfi_trap') == 0)
                 and (active['order_floor'] is None or order > active['order_floor'][1])
                 and (session._last_retire_order is None or order > session._last_retire_order[1]),
                 'invalid fixed ISR MRET')
        authentic_take()
        entry = active['entry']
        _require((state['dispatch'] is None or active['dma_stage_entered'])
                 and entry is not None and entry['receipt_id']['sequence'] < receipt.sequence
                 and entry['local_tick'] < session.local_ticks and entry['rvfi_order'] < order,
                 'MRET requires an earlier source-joined handler entry')
        if limited:
            _require(not _redirect_ticks(state, since=take['local_tick']),
                     'MRET occurs after an actual exception/debug redirect')
        else:
            _require(serial['retirement']['status'] == 'observed'
                     and serial['retirement']['value'] == 0,
                     'MRET must preserve its actual zero/no-lineage retirement serial')
        entry_blob = dict(event_id=None, pc=entry['pc_rdata'], insn=entry['instruction'],
            order=entry['rvfi_order'], local_tick=entry['local_tick'],
            receipt_id=deepcopy(entry['receipt_id']))
        event = dict(schema_version='native_f6_isr_return.v1',
            component=session.source_component, execution=receipt.execution,
            reset_epoch=session.reset_epoch, case_id=active['case_id'], case_index=active['case_index'],
            native_testcase_id=session._case_id, irq_take_key=deepcopy(active['key']),
            take_receipt_id=deepcopy(take['receipt_id']),
            **({} if limited else {'take_irq_serial_observation':deepcopy(take['irq_serial_observation'])}),
            handler_entry_receipt_id=deepcopy(entry['receipt_id']),
            handler_entry_rvfi_order=entry['rvfi_order'],
            handler_entry_pc_rdata=entry['pc_rdata'],
            **({} if limited else {'handler_entry_irq_serial_observation':deepcopy(entry['irq_serial_observation'])}),
            return_receipt_id=dict(execution=receipt.execution, sequence=receipt.sequence),
            return_receipt_ticks=dict(tick_before=receipt.tick_before, tick_after=receipt.tick_after,
                new_ticks=receipt.new_ticks, local_tick_base=session._tick_base),
            local_tick=session.local_ticks, phase='post', rvfi_order=order,
            instruction=instruction, pc_rdata=pc,
            **({} if limited else {'pc_wdata': target, 'irq_serial_observation': serial}),
            isr_sha256=state['isr']['sha256'],
            **(dict(dispatcher_stage_sha256=state['dispatch']['identity_sha256'],
                dispatcher_retirements=deepcopy(active['dispatch_retirements']),
                dma_stage_address=state['dispatch']['stages']['dma']['address']) if state['dispatch'] is not None else {}),
            execution_binding_sha256=state['binding'],
            **({} if not limited else dict(retirement_authority=state['authority'],
                unobserved_fields=deepcopy(state['unobserved']),
                entry=entry_blob, mret_pc=pc,
                mret=dict(event_id=None, pc=pc, insn=instruction, order=order,
                          local_tick=session.local_ticks,
                          receipt_id=dict(execution=receipt.execution, sequence=receipt.sequence)),
                retirement_diversion_scope='unobservable',
                take_pre_edge_observation=_take_pre_edge(take, state['acceptance']),
                pre_entry_retirements=deepcopy(active['pre_entry_retirements']))))
        # pc_wdata is retained verbatim only for full-RVFI CPUs. The pinned
        # Ibex source does not establish it as MRET's architectural return
        # target, and a PC/order/insn-only CPU does not drive it at all.
        # Issuance waits for a separately source-proven actual successor.
        _require(active['pending_mret'] is None, 'duplicate pending MRET')
        active['pending_mret'] = _canonical(event)

    def capture(session, receipt, physical):
        try:
            return capture_receipt(session, receipt, physical)
        except Exception:
            # A caller cannot repair contradictory native evidence by restoring
            # a mutable event and continuing with later receipt/order numbers.
            state = sessions.get(session)
            if state is not None and state['active'] is not None:
                state['active']['invalid'] = True
            raise

    def document(session):
        state = state_for(session)
        return None if state is None else json.loads(state['document'])

    return seal, install, issuer_state, begin, capture, document


(_seal_f6_cpu_session, install_f6_isr_return, _issuer_state, _begin_f6_case,
 _capture_f6_native_retirement, _f6_isr_return_document) = _registry()
