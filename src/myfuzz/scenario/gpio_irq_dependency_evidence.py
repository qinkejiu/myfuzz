"""Bounded GPIO native IRQ/pulse/CPU receipt joins; no policy authority.

Configured by the actual runner after component/physical-port verification.
Documentary replay tests exercise the reducer, never install a live provider.
Delivery, acceptance and exact serial retirement are separate historical facts;
none authenticates ISR MMIO or awards source credit.
"""
from collections import OrderedDict
from copy import deepcopy
import re

from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
from myfuzz.local_harness.native_irq_receipt_contract import validate_native_irq_receipt_contract
from .gpio_consumption import is_authenticated_gpio_tick
from .irq_serial_certificates import IrqSerialCertificates
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession as _GPIO_SESSION

_GPIO_PROJECTION = _GPIO_SESSION._normalized_physical
_GPIO_PROJECTION_CODE = _GPIO_PROJECTION.__code__


def _uint(value):
    return type(value) is int and 0 <= value < 1 << 64


class GpioNativeIrqEvidenceConsumer:
    def __init__(self, *, source_component, target_component, pin, source_port,
                 target_port, runtime_contract_sha256, pulse_width_ticks=4,
                 max_records=256, max_pending=256, max_event_gap=4096,
                 observation_contract=None, target_bit_offset=0):
        if (any(type(x) is not str or not x.strip() or len(x)>256 for x in
                (source_component,target_component,source_port,target_port))
                or source_component==target_component or type(pin) is not int or not 0<=pin<32
                or type(runtime_contract_sha256) is not str
                or re.fullmatch('[0-9a-f]{64}',runtime_contract_sha256) is None
                or type(target_bit_offset) is not int or not 0<=target_bit_offset<64
                or any(type(x) is not int or not 1<=x<=65536 for x in
                       (pulse_width_ticks,max_records,max_pending,max_event_gap))):
            raise ValueError('invalid GPIO native IRQ evidence configuration')
        self.source, self.target, self.pin = source_component,target_component,pin
        self._observation_contract = deepcopy(ibex_irq_receipt_contract()
            if observation_contract is None else observation_contract)
        validate_native_irq_receipt_contract(self._observation_contract)
        self.provider = ('native_gpio_ibex_irq.v1' if self._observation_contract == ibex_irq_receipt_contract()
                         else 'native_gpio_cpu_irq.v1')
        self.source_port,self.target_port=source_port,target_port
        # The declared CPU input bit this physical port drives. A one-bit
        # endpoint that is a real bit-slice of a wider vector carries its
        # physical bit, so every join below compares the actual offset.
        self.target_bit_offset=target_bit_offset
        self.runtime_contract_sha256=runtime_contract_sha256
        self.width=pulse_width_ticks;self.limit=max_pending;self.gap=max_event_gap;self.capacity=max_records
        self._last=0;self._events=OrderedDict();self._sources=OrderedDict();self._native=OrderedDict()
        self._accepted=OrderedDict();self._serial_pending=OrderedDict();self._records=[];self._saturated=False
        self._serial=IrqSerialCertificates(max_pending=max_pending,max_event_gap=max_event_gap)

    def _put(self, table, key, value):
        table[key]=value
        while len(table)>self.limit: table.popitem(last=False)

    def _endpoint(self,event):
        return (event.get('source') in ((self.source,self.source_port),[self.source,self.source_port])
            and event.get('target') in ((self.target,self.target_port),[self.target,self.target_port])
            and all(type(event.get(k)) is int and event[k]==v for k,v in
                    (('source_bit_offset',0),
                     ('target_bit_offset',self.target_bit_offset),('width',1))))

    def _record(self,scope,fields):
        if len(self._records)>=self.capacity:
            self._saturated=True;return
        self._records.append(deepcopy(dict(proof_scope=scope,status='observed',
            source_component=self.source,target_component=self.target,pin=self.pin,
            reward_eligible=False,**fields)))

    def _clear(self):
        for table in (self._events,self._sources,self._native,self._accepted,self._serial_pending):table.clear()

    def consume(self,event):
        if type(event) is not dict or type(event.get('event_id')) is not int or event['event_id']!=self._last+1:
            raise ValueError('GPIO IRQ evidence requires contiguous actual journal')
        self._last=event['event_id'];kind=event.get('kind')
        for table in (self._events,self._sources,self._native,self._accepted,self._serial_pending):
            while table and self._last-next(iter(table.values()))['born']>self.gap:
                table.popitem(last=False)
        if kind in ('reset_barrier','gpio_reset','gpio_reset_resource','cpu_reset'):
            self._clear()
        elif ((kind=='gpio_tick_observation' and event.get('component')==self.source
               and is_authenticated_gpio_tick(event))
              or (kind in ('gpio_irq_trigger','local_tick_sample') and event.get('component')==self.source)
              or (kind is None and event.get('component')==self.target and 'inputs' in event)
              or (kind=='cpu_external_irq_sample' and self._valid_sample(event))
              or (kind=='cpu_external_irq_taken' and event.get('component')==self.target)):
            cached=event
            if kind is None:
                # Only these measured fields participate in the boundary join;
                # retaining full driver samples would duplicate the journal.
                cached=dict(event_id=event['event_id'],component=self.target,
                    local_tick=event.get('local_tick'),inputs={self.target_port:event['inputs'].get(self.target_port)},
                    outputs={'irq_taken_pre':event.get('outputs',{}).get('irq_taken_pre')})
            elif kind=='local_tick_sample':
                cached={k:event.get(k) for k in ('event_id','kind','component','reset_epoch','local_tick','phase')}
                cached['outputs']={self.source_port:event.get('outputs',{}).get(self.source_port)}
            self._put(self._events,self._last,dict(born=self._last,event=deepcopy(cached)))
            if kind=='cpu_external_irq_sample':
                self._put(self._native,event['producer_event_id'],dict(born=self._last,sample=deepcopy(event)))
            elif kind=='cpu_external_irq_taken':self._take(event)
        elif kind=='source_start':self._source(event)
        elif kind=='pulse_start':self._pulse(event)
        elif kind=='cpu_irq_input':self._input(event)
        elif kind=='cpu_irq_taken':self._accept(event)
        elif kind in ('irq_overrun','pulse_cancelled_by_reset','pulse_expired','expired_masked'):
            self._sources.pop(event.get('source_event_id'),None)
            if kind=='irq_overrun':self._sources.pop(event.get('active_source_event_id'),None)
        for serial in self._serial.ingest((event,)):
            key=serial['take_identity'].get('take_key')
            if (type(key) is list and len(key)==3 and key[0]==self.target):
                self._put(self._serial_pending,tuple(key),dict(born=self._last,certificate=serial))
        for key,value in tuple(self._serial_pending.items()):
            acceptance=self._accepted.get(key)
            serial=value['certificate']
            if (acceptance is not None and serial['take_identity_event_id']==acceptance['native_take_event_id']
                    and serial['reset_epoch']==acceptance['target_epoch']):
                self._record('cpu_retirement_serial',dict(acceptance=acceptance,
                    serial_certificate=serial,trigger_id=acceptance['trigger_id']))
                self._serial_pending.pop(key);self._accepted.pop(key)

    def _event(self,key):return self._events.get(key,{}).get('event')

    def _valid_sample(self,e):
        scope=e.get('command_scope');step=self._event(e.get('producer_event_id'))
        return (e.get('component')==self.target and e.get('observation_contract')==self._observation_contract
            and type(scope) is dict and set(scope)=={'component','reset_epoch','command_sequence'}
            and scope['component']==self.target and _uint(scope['reset_epoch'])
            and type(scope['command_sequence']) is int and scope['command_sequence']>0
            and _uint(e.get('reset_epoch')) and e['reset_epoch']==scope['reset_epoch'] and _uint(e.get('local_tick'))
            and type(e.get('execution_id')) is str and bool(e['execution_id'])
            and type(e.get('receipt_id')) is dict and type(e['receipt_id'].get('sequence')) is int
            and e['receipt_id']['sequence']==scope['command_sequence']
            and type(e['receipt_id'].get('execution')) is str and bool(e['receipt_id']['execution'])
            and all(type(e.get(k)) is int and e[k]==1 for k in
                    ('expected_input','actual_pre_input','actual_post_input'))
            and type(step) is dict and step.get('local_tick')==e['local_tick']
            and type(step.get('inputs',{}).get(self.target_port)) is int
            and step['inputs'][self.target_port]==1<<self.target_bit_offset)

    def _take(self,e):
        state=self._native.get(e.get('producer_event_id'));sample=state.get('sample') if state else None
        key=e.get('take_key')
        fields=('component','execution_id','reset_epoch','local_tick','producer_event_id','command_scope',
                'receipt_id','receipt_ticks','expected_input','actual_pre_input','actual_post_input',
                'irq_taken_pre','observation_contract','irq_serial_observation')
        if (sample is None or e.get('sample_event_id')!=sample['event_id']
                or e.get('sample_ref')!={'command_scope':sample['command_scope'],'local_tick':sample['local_tick']}
                or any(e.get(k)!=sample.get(k) for k in fields)
                or type(e.get('irq_taken_pre')) is not int or e['irq_taken_pre']!=1
                or type(key) is not list or len(key)!=3 or key[:2]!=[self.target,sample['reset_epoch']]
                or type(key[2]) is not int or key[2]<1):return
        state['take']=deepcopy(e)

    def _source(self,e):
        if not self._endpoint(e):return
        ref=e.get('source_trigger');source_id=e.get('source_event_id')
        if (type(ref) is not dict or set(ref)!={'trigger_id','trigger_event_id','observation_event_id','sample_event_id'}
                or type(source_id) is not int or source_id<1):return
        raw=self._event(ref.get('observation_event_id'));trigger=self._event(ref.get('trigger_event_id'))
        sample=self._event(ref.get('sample_event_id'))
        if (raw is None or trigger is None or sample is None or not is_authenticated_gpio_tick(raw)
                or trigger.get('kind')!='gpio_irq_trigger' or trigger.get('status')!='observed'
                or trigger.get('trigger_id')!=ref['trigger_id'] or trigger.get('observation_event_id')!=raw['event_id']
                or trigger.get('reset_epoch')!=raw['reset_epoch'] or trigger.get('local_tick')!=raw['local_tick']
                or type(trigger.get('mask')) is not int or not trigger['mask']&(1<<self.pin)
                or sample.get('kind')!='local_tick_sample' or sample.get('phase')!=trigger.get('phase')
                or sample.get('local_tick')!=raw['local_tick'] or sample.get('reset_epoch')!=raw['reset_epoch']
                or type(sample.get('outputs',{}).get(self.source_port)) is not int
                or sample['outputs'][self.source_port]!=1
                or raw.get(trigger.get('phase'),{}).get('gpio_probe_native_irq')!=1
                or raw[trigger['phase']].get('gpio_probe_irq_trigger_mask')!=trigger['mask']
                or not raw['event_id']<trigger['event_id']<sample['event_id']<e['event_id']
                or not _uint(e.get('source_tick')) or e['source_tick']!=raw['local_tick']
                or not _uint(e.get('cpu_tick'))):return
        if source_id in self._sources:
            self._sources.pop(source_id);return
        self._put(self._sources,source_id,dict(born=e['event_id'],ref=deepcopy(ref),epoch=raw['reset_epoch'],
            source_start_event_id=e['event_id'],source_cpu_tick=e['cpu_tick'],
            source_origin_status=trigger.get('origin_status','unknown'),
            pin_causes=deepcopy([c for c in trigger.get('causes',[]) if c.get('pin')==self.pin])))

    def _pulse(self,e):
        state=self._sources.get(e.get('source_event_id'))
        if state is None:return
        if (not self._endpoint(e) or e.get('source_trigger')!=state['ref']
                or e.get('start_cpu_tick')!=state['source_cpu_tick']+1
                or e.get('end_cpu_tick_exclusive')!=state['source_cpu_tick']+1+self.width):
            self._sources.pop(e.get('source_event_id'));return
        state.update(start=e['start_cpu_tick'],end=e['end_cpu_tick_exclusive'],pulse_event_id=e['event_id'])

    def _input(self,e):
        state=self._sources.get(e.get('source_event_id'));native=self._native.get(e.get('cpu_step_event_id'))
        if state is None or native is None:return
        sample=native['sample'];tick=e.get('cpu_tick')
        if (not self._endpoint(e) or e.get('source_trigger')!=state['ref']
                or type(e.get('value')) is not int or e['value']!=1 or not _uint(tick)
                or not state.get('start',-1)<=tick<state.get('end',-1) or tick!=sample['local_tick']):return
        state['input']=dict(born=e['event_id'],event_id=e['event_id'],step=e['cpu_step_event_id'],tick=tick)
        self._record('irq_delivery',dict(trigger_id=state['ref']['trigger_id'],source_trigger=state['ref'],
            source_epoch=state['epoch'],target_epoch=sample['reset_epoch'],
            source_origin_status=state['source_origin_status'],pin_causes=state['pin_causes'],
            source_start_event_id=state['source_start_event_id'],pulse_start_event_id=state['pulse_event_id'],
            input_event_id=e['event_id'],native_sample_event_id=sample['event_id']))

    def _accept(self,e):
        state=self._sources.get(e.get('source_event_id'));native=self._native.get(e.get('cpu_step_event_id'))
        if state is None or native is None or 'take' not in native or 'input' not in state:return
        inp=state['input'];take=native['take'];step=self._event(inp['step'])
        if (not self._endpoint(e) or e.get('source_trigger')!=state['ref']
                or e.get('cpu_step_event_id')!=inp['step'] or e.get('cpu_tick')!=inp['tick']
                or step is None or type(step.get('outputs',{}).get('irq_taken_pre')) is not int
                or step['outputs']['irq_taken_pre']!=1):return
        key=tuple(take['take_key'])
        acceptance=dict(born=e['event_id'],trigger_id=state['ref']['trigger_id'],source_trigger=state['ref'],
            source_epoch=state['epoch'],target_epoch=take['reset_epoch'],input_event_id=inp['event_id'],
            source_origin_status=state['source_origin_status'],pin_causes=state['pin_causes'],
            taken_event_id=e['event_id'],native_take_event_id=take['event_id'],take_key=list(key))
        self._put(self._accepted,key,deepcopy(acceptance));self._record('irq_acceptance',acceptance)
        self._sources.pop(e['source_event_id'])

    def report(self):
        counts={k:sum(r['proof_scope']==k for r in self._records)
                for k in ('irq_delivery','irq_acceptance','cpu_retirement_serial')}
        return deepcopy(dict(schema_version='gpio_native_irq_dependency_evidence.v1',provider=self.provider,
            source_component=self.source,target_component=self.target,pin=self.pin,
            source_port=self.source_port,target_port=self.target_port,runtime_contract_sha256=self.runtime_contract_sha256,
            counts=counts,certificates=self._records,historical=True,
            layers={k:dict(status='observed' if count else 'unknown',count=count,scope='historical') for k,count in counts.items()},
            status='incomplete' if self._saturated else 'observed' if any(counts.values()) else 'unknown',
            isr_mmio='unknown',irq_consumption='unknown',reward_eligible=False,grants_prerequisites=False,
            native_authority=False,limits=dict(max_records=self.capacity,max_pending=self.limit,max_event_gap=self.gap)))


def gpio_irq_runtime_port(session):
    """Resolve the actual causal GPIO IRQ export; never guess port aliases."""
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.native_physical_observation import verify_native_physical_observation
    if (type(session) is not GeneratedPulpGpioSession or not session.routed_register_access_enabled
            or not verify_native_physical_observation(session.artifact)):
        raise ValueError('actual native causal GPIO IRQ adapter required')
    artifact=session.artifact
    exports=[r for r in artifact.runtime_document['physical_exports']
        if r.get('role')=='irq' and r.get('direction')=='output'
        and r.get('bit_lo')==0 and r.get('bit_hi')==0 and r.get('width')==1]
    if len(exports)!=1:raise ValueError('unique native GPIO IRQ physical export required')
    export=exports[0]
    names=('physical_port','endpoint_id','role','direction','bit_lo','bit_hi','width')
    abi=[r for r in artifact.structural.abi_document['ports'] if all(r.get(k)==export.get(k) for k in names)]
    if len(abi)!=1 or type(export.get('runtime_name')) is not str or not export['runtime_name']:
        raise ValueError('native GPIO IRQ ABI/export mismatch')
    # The driver wire name is generated (for example rt_lh_p_16_0_0).
    # Runner samples/bindings use the session's normalized physical port.
    from myfuzz.local_harness.gpio_session import _GPIO_FIELDS
    physical=export['physical_port']
    if (session._artifact_document != artifact.runtime_document
            or '_normalized_physical' in vars(session)
            or GeneratedPulpGpioSession._normalized_physical is not _GPIO_PROJECTION
            or _GPIO_PROJECTION.__code__ is not _GPIO_PROJECTION_CODE
            or physical not in _GPIO_FIELDS
            or _GPIO_PROJECTION(session, {'physical': {export['runtime_name']: 1}}) != {physical: 1}):
        raise ValueError('native GPIO IRQ session projection mismatch')
    return physical
