"""Explicit host OR delivery for one CPU IRQ bit; no interrupt controller.

Declarations describe delivery only. Observed member levels/pulses and parsed
CPU input receipts authenticate each group sample. Joint activation carries no
single-source acceptance authority.
"""
from dataclasses import asdict, dataclass
from copy import deepcopy
from hashlib import sha256
import json


def _text(v):return type(v) is str and bool(v.strip()) and v.strip()==v


@dataclass(frozen=True)
class IrqDeliveryMember:
    source_component: str
    source_port: str
    mode: str = 'pulse'
    pulse_width_ticks: int | None = None
    source_bit_offset: int = 0
    source_adapter: str | None = None

    def __post_init__(self):
        if self.mode=='pulse' and self.pulse_width_ticks is None:
            object.__setattr__(self,'pulse_width_ticks',4)
        if (not _text(self.source_component) or not _text(self.source_port)
                or self.source_adapter not in (None,'declared-output.v1')
                or self.mode not in ('pulse','level') or type(self.source_bit_offset) is not int
                or not 0 <= self.source_bit_offset < 64
                or self.mode=='pulse' and (type(self.pulse_width_ticks) is not int or not 1<=self.pulse_width_ticks<=4096)
                or self.mode=='level' and self.pulse_width_ticks is not None):
            raise ValueError('invalid IRQ delivery group member')

    @property
    def source_id(self):return self.source_component+'.'+self.source_port


@dataclass(frozen=True)
class IrqDeliveryGroup:
    group_id: str
    target_component: str
    target_port: str
    members: tuple[IrqDeliveryMember, ...]
    target_bit_offset: int = 0
    operation: str = 'or'
    #: DUT bit index of host bit 0 of the target input field, i.e. the verified
    #: export row's ``bit_lo``. 0 when the host field starts at the port's bit 0
    #: (whole port or an ABI row at bit 0); 11 for ``irq_i[11]``. Behaviour uses
    #: ``target_bit_offset`` (port-local); the runtime path contract records the
    #: DUT bit, so this maps one coordinate system onto the other.
    target_input_bit_lo: int = 0

    def __post_init__(self):
        # The offset is the CPU input bit this group drives inside its declared
        # host input field. A one-bit endpoint that is a real bit-slice of a
        # wider port therefore carries its physical bit, not a fabricated zero.
        if (not all(_text(v) for v in (self.group_id,self.target_component,self.target_port))
                or self.operation!='or' or type(self.target_bit_offset) is not int
                or not 0<=self.target_bit_offset<64
                or type(self.target_input_bit_lo) is not int
                or not 0<=self.target_input_bit_lo<1<<16
                or type(self.members) is not tuple or not 1<=len(self.members)<=16
                or any(type(m) is not IrqDeliveryMember or m.source_component==self.target_component for m in self.members)
                or len({m.source_id for m in self.members})!=len(self.members)):
            raise ValueError('invalid host IRQ delivery group')

    @property
    def owner_ref(self):return 'irq-group:'+self.group_id

    def document(self):
        document=dict(schema_version='host_irq_delivery_group.v1',**asdict(self))
        # Keep every offset-zero document byte-identical: the documentary DUT
        # base only appears when it differs from the port's bit zero.
        if not document['target_input_bit_lo']:document.pop('target_input_bit_lo')
        for member in document['members']:
            if member['source_adapter'] is None:member.pop('source_adapter')
        return document

    @classmethod
    def from_document(cls, document):
        keys={'schema_version','group_id','target_component','target_port','members',
              'target_bit_offset','operation'}
        if (type(document) is not dict or set(document) not in (keys,keys|{'target_input_bit_lo'})
                or document['schema_version']!='host_irq_delivery_group.v1'
                or type(document['members']) not in (list,tuple)):
            raise ValueError('invalid IRQ delivery group document')
        values={k:v for k,v in document.items() if k!='schema_version'}
        values['members']=tuple(IrqDeliveryMember(**m) for m in values['members'])
        return cls(**values)

    @property
    def identity_sha256(self):
        return sha256(json.dumps(self.document(),sort_keys=True,separators=(',',':')).encode()).hexdigest()

    def member_bindings(self):
        from .runner import Binding
        return tuple(Binding(m.source_component,m.source_port,self.target_component,self.target_port,
            1,m.source_bit_offset,self.target_bit_offset) for m in self.members)


class IrqDeliveryGroupState:
    """Pure bounded delivery reducer; installation is the runner's job."""
    def __init__(self,group,pulses):
        self.group=group;self.pulses=pulses;self.samples={};self.active_frame=None;self.last_delivery=None

    def reset(self):
        self.samples.clear();self.active_frame=None;self.last_delivery=None

    def observe(self,binding,value,reference):
        if binding not in self.group.member_bindings() or type(value) is not int or value not in (0,1):
            raise ValueError('IRQ group undeclared or invalid source')
        if (type(reference) is not dict or reference.get('component')!=binding.source_component
                or type(reference.get('event_id')) is not int or reference['event_id']<1
                or type(reference.get('reset_epoch')) is not int or reference['reset_epoch']<0
                or type(reference.get('local_tick')) is not int or reference['local_tick']<0
                or reference.get('phase') not in ('pre','post')):
            raise ValueError('IRQ group native member reference required')
        previous=self.samples.get(binding)
        rising=reference if value==1 and (previous is None or previous['value']==0) else (previous or {}).get('pulse_origin')
        self.samples[binding]=dict(value=value,reference=deepcopy(reference),pulse_origin=deepcopy(rising))
        return previous is None or previous['value']!=value

    def frame(self,tick):
        rows=[]
        for member,binding in zip(self.group.members,self.group.member_bindings()):
            sample=self.samples.get(binding)
            if sample is None:raise ValueError('IRQ group member native state unavailable')
            value=self.pulses[binding].input_at(tick) if member.mode=='pulse' else sample['value']
            rows.append(dict(source_id=member.source_id,mode=member.mode,value=value,
                native_source=deepcopy(sample['pulse_origin'] if value else sample['reference']),
                latest_native_source=deepcopy(sample['reference']),
                pulse=(self.pulses[binding].state_document() if member.mode=='pulse' else None)))
        active=[r['source_id'] for r in rows if r['value']==1]
        return dict(group_id=self.group.group_id,group_sha256=self.group.identity_sha256,
            target_component=self.group.target_component,target_port=self.group.target_port,
            cpu_tick=tick,value=int(bool(active)),members=rows,active_sources=active,
            attribution_status='unique' if len(active)==1 else 'joint' if active else 'unknown',
            unique_source=active[0] if len(active)==1 else None)

    def begin_step(self,tick):
        if self.active_frame is not None:raise ValueError('IRQ group CPU step still active')
        self.active_frame=self.frame(tick)

    def native(self,event):
        frame=self.active_frame
        if frame is None or event.get('component')!=self.group.target_component:return
        kind=event.get('kind')
        if kind=='cpu_external_irq_sample':
            if (event.get('local_tick')!=frame['cpu_tick']
                    or any(type(event.get(k)) is not int or event[k]!=frame['value'] for k in
                           ('expected_input','actual_pre_input','actual_post_input'))
                    or 'native_sample_event_id' in frame):
                raise ValueError('IRQ group parsed CPU input does not match OR')
            frame.update(native_sample_event_id=event['event_id'],cpu_step_event_id=event['producer_event_id'],
                target_epoch=event['reset_epoch'],receipt_id=deepcopy(event['receipt_id']))
        elif kind=='cpu_external_irq_taken':
            if (event.get('sample_event_id')!=frame.get('native_sample_event_id')
                    or event.get('producer_event_id')!=frame.get('cpu_step_event_id')
                    or event.get('local_tick')!=frame['cpu_tick']):
                raise ValueError('IRQ group native acceptance receipt mismatch')
            frame.update(native_take_event_id=event['event_id'],take_key=deepcopy(event.get('take_key')),
                irq_serial_observation=deepcopy(event.get('irq_serial_observation')))

    def finish_step(self,step_event_id):
        frame=self.active_frame
        if frame is None or frame.get('cpu_step_event_id')!=step_event_id:
            raise ValueError('IRQ group parsed CPU input receipt missing')
        self.last_delivery=deepcopy(frame);self.active_frame=None
        return deepcopy(frame)


def verify_group_sessions(group,sessions):
    """One adapter check per IP, independent of which other IPs share its CPU."""
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
    from .gpio_irq_dependency_evidence import gpio_irq_runtime_port
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.local_harness.pulp_timer_irq_contract import timer_irq_runtime_mapping
    cpu=sessions.get(group.target_component)
    if (type(cpu) is not GeneratedCve2Session or not cpu.native_irq_receipts_enabled
            or group.target_port!=cpu.irq_input_port):
        raise ValueError('IRQ group requires actual native CPU input adapter')
    result={}
    for member,binding in zip(group.members,group.member_bindings()):
        source=sessions.get(member.source_component);artifact=getattr(source,'artifact',None)
        if member.source_adapter=='declared-output.v1':
            from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
            result[binding]=declared_irq_runtime_mapping(source,physical_port=member.source_port,source_bit_offset=member.source_bit_offset)
            continue
        if type(source) is GeneratedApb3RegisterSession:
            mapping=timer_irq_runtime_mapping(source)
            if (member.source_port!=mapping['physical_port']
                    or member.source_bit_offset>=mapping['source_width']
                    or member.mode!='pulse'
                    or artifact.plan.request.instance_id!=member.source_component):
                raise ValueError('IRQ group Timer native pulse mapping mismatch')
            result[binding]=mapping
            continue
        if member.source_bit_offset != 0:
            raise ValueError('IRQ group scalar source bit mismatch')
        if type(source) is GeneratedPulpGpioSession:
            if member.source_port!=gpio_irq_runtime_port(source):raise ValueError('IRQ group GPIO output mapping mismatch')
            adapter='pulp_gpio.causal-native-irq.v1'
        elif type(source) is GeneratedWishboneDmaScenarioSession:
            if member.source_port!='irq':raise ValueError('IRQ group DMA output mapping mismatch')
            profile=artifact.plan.profile
            if artifact.source_verification.get('schema_version')=='zipdma_selected_profile_contract.v1':
                from myfuzz.local_harness.zipdma_profile_session import verify_zipdma_profile
                verified=verify_zipdma_profile(profile,base_dir=source.base_dir)
                if (artifact.source_verification!=verified
                        or artifact.runtime_document.get('source_verification')!=verified):
                    raise ValueError('IRQ group DMA source verification mismatch')
                adapter='zipcpu.zipdma.native-irq.v1'
            elif (profile.source_document.get('top_module')=='wbdmac'
                    and 'f6_dma' not in profile.evidence):
                adapter='zipcpu.wbdmac.native-irq.v1'
            else:
                from myfuzz.local_harness.source_lock import verify_local_source_lock
                verified=verify_local_source_lock(profile,base_dir=source.base_dir)
                if (artifact.source_verification!=verified
                        or artifact.runtime_document.get('source_verification')!=verified):
                    raise ValueError('IRQ group DMA source verification mismatch')
                adapter='declared.wishbone-dma.native-irq.v1'
        else:raise ValueError('IRQ group native source adapter unsupported')
        exports=[r for r in artifact.runtime_document['physical_exports'] if r.get('role')=='irq'
            and r.get('direction')=='output' and r.get('width')==1 and r.get('disposition')=='functional']
        if len(exports)!=1:raise ValueError('IRQ group source export not unique')
        export=exports[0]
        names=('physical_port','endpoint_id','role','direction','bit_lo','bit_hi','width')
        if sum(all(r.get(k)==export.get(k) for k in names) for r in artifact.structural.abi_document['ports'])!=1:
            raise ValueError('IRQ group source ABI mismatch')
        if type(source) is GeneratedWishboneDmaScenarioSession and source._irq_runtime_name!=export['runtime_name']:
            raise ValueError('IRQ group DMA native output mapping drift')
        result[binding]=dict(adapter_id=adapter,physical_port=export['physical_port'],runtime_name=export['runtime_name'])
    return result
