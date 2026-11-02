"""AHB CPU ABI binding over existing sessions; no IRQ or retirement authority."""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.scenario.ahb_cpu_events import bind_ahb_trace,SHAPE
from ..contracts import AdapterSelection,VerifiedComponent,GenericRuntimeRefused,canonical_json_bytes

CPU_ADAPTER_ID='ahb-lite.cpu.v1'
CPU_ADAPTER_VERSION='1'
AHB_CPU_PROTOCOL=('ahb-lite','1')
AHB_CPU_TEMPLATE=('cpu.ahb-lite','1','cvw-external-bus')
AHB_CPU_SEMANTIC_KIND='cpu.ahb-lite.v1'
AHB_CPU_COMPLETION='address_phase_then_ready_completion'
_ROOT=Path(__file__).resolve().parents[4]
_FILES=('src/myfuzz/runtime/adapters/ahb_cpu.py','src/myfuzz/local_harness/ahb_lite_session.py',
    'src/myfuzz/local_harness/native_session.py','src/myfuzz/local_harness/session.py',
    'src/myfuzz/scenario/ahb_cpu_events.py','src/myfuzz/local_harness/ahb_manager_domain.py',
    'src/myfuzz/local_harness/ahb_startup.py')
_MODULE_DIGESTS={name:sha256((_ROOT/name).read_bytes()).hexdigest() for name in _FILES}
_CLASS=GeneratedAhbMemorySession
_METHODS={name:(getattr(_CLASS,name),getattr(_CLASS,name).__code__) for name in
    ('step_local','begin_case','reset_local','accept_instructions','identity_document','_service_accepted_request')}


def _digest(value):return sha256(canonical_json_bytes(value)).hexdigest()


def _require(value,reason):
    if not value:raise GenericRuntimeRefused('generic-binding-drift','/ahb_cpu',{'reason':reason})


def ahb_cpu_surface_document(artifact):
    document=artifact.runtime_document
    if document.get('kind')!='ahb_lite_cpu':raise ValueError('AHB CPU artifact required')
    endpoint,signals,trace=bind_ahb_trace(document)
    rows=[e for e in artifact.plan.binding.endpoints if e.endpoint_id==endpoint]
    if len(rows)!=1 or rows[0].protocol!=AHB_CPU_PROTOCOL or rows[0].function!='memory_master':
        raise ValueError('AHB unified memory endpoint required')
    boot=document.get('boot_contract',{});base=boot.get('configured_boot_base')
    if type(base) is not int or not 0<=base<1<<SHAPE['haddr'] or base%4:
        raise ValueError('AHB configured boot base required')
    capabilities=artifact.plan.profile.capabilities
    if (capabilities.get('address_width'),capabilities.get('data_width'),capabilities.get('byte_enable'),
            capabilities.get('max_outstanding'),capabilities.get('error_response'))!=(34,32,True,1,True):
        raise ValueError('AHB declared widths/completion capabilities changed')
    return dict(schema_version='ahb_cpu_execution_surface.v1',kind=AHB_CPU_SEMANTIC_KIND,
        instance_id=artifact.plan.request.instance_id,endpoint_id=endpoint,protocol=list(AHB_CPU_PROTOCOL),
        template=list(AHB_CPU_TEMPLATE),roles=dict(SHAPE),signals=signals,trace_binding=trace,
        boot_contract=deepcopy(boot),source_sha256=_digest(artifact.source_verification),
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,artifact_sha256=document['artifact_digest'],
        address_width=34,data_width=32,address_units='byte',byte_enable_width=4,max_outstanding=1,
        completion_kind=AHB_CPU_COMPLETION,instruction_identity='accepted_manager_address_phase.hprot[0]',
        instruction_retirement='unknown',native_IRQ='unsupported')


@dataclass(frozen=True)
class AhbCpuAbiFacts:
    endpoint_id:str
    boot_base:int
    address_width:int=34
    data_width:int=32
    address_units:str='byte'
    protocol:tuple=AHB_CPU_PROTOCOL
    template:tuple=AHB_CPU_TEMPLATE

    def document(self):
        from dataclasses import asdict
        return asdict(self)


class AhbCpuDriver:
    """Describe the admitted CPU; Runner remains the sole execution coordinator."""
    def __init__(self,session,artifact,surface,implementation_pin):
        self._session,self._artifact=session,artifact
        self._surface=canonical_json_bytes(surface)
        self._implementation_pin=implementation_pin;self._closed=False
        self.facts=AhbCpuAbiFacts(surface['endpoint_id'],surface['boot_contract']['configured_boot_base'])

    def assert_current(self):
        from ..registry import registrations
        _require(not self._closed,'closed')
        _require(all(sha256((_ROOT/name).read_bytes()).hexdigest()==digest for name,digest in _MODULE_DIGESTS.items()),'module-source')
        _require(type(self._session) is _CLASS and self._session.artifact is self._artifact,'session-owner')
        _require(all(name not in vars(self._session) and getattr(_CLASS,name) is method
            and method.__code__ is code for name,(method,code) in _METHODS.items()),'session-method')
        registrations_for_cpu=[r for r in registrations() if r.adapter_id==CPU_ADAPTER_ID]
        _require(len(registrations_for_cpu)==1 and registrations_for_cpu[0].implementation_sha256()==self._implementation_pin,'implementation')
        _require(canonical_json_bytes(ahb_cpu_surface_document(self._artifact))==self._surface,'artifact-ABI')

    def program_slots(self):
        self.assert_current()
        return {'instruction.boot':dict(kind='instruction_image',boot_base=self.facts.boot_base,
            first_fetch_verification='runtime_observation_required',endpoints=[self.facts.endpoint_id],
            instruction_identity='accepted_manager_address_phase.hprot[0]',address_width=34,instr_width=32,address_units='byte')}

    def local_step_map(self):
        self.assert_current()
        return dict(schema_version='ahb_cpu_local_step_map.v1',
            max_local_ticks_per_step=self._session.max_local_ticks_per_step,
            max_transaction_events_per_step=self._session.max_transaction_events_per_step,
            defer_mmio=self._session.defer_mmio,pending_responses=self._session.pending_responses,
            address_units='byte',completion_kind=AHB_CPU_COMPLETION)

    def close(self):self._closed=True


class BoundAhbCpuAdapter:
    def __init__(self,component,session,selection,surface,implementation_pin):
        self.component_instance_id=component.instance_id;self.endpoint_id=surface['endpoint_id']
        self.adapter_id=CPU_ADAPTER_ID;self.adapter_version='1';self.protocol=AHB_CPU_PROTOCOL
        self.template=AHB_CPU_TEMPLATE;self.semantic_kind=AHB_CPU_SEMANTIC_KIND;self.address_units='byte'
        self.implementation_sha256=implementation_pin
        self.driver=AhbCpuDriver(session,session.artifact,surface,implementation_pin);self.abi_facts=self.driver.facts
        self.binding_sha256=_digest(dict(component=component.artifact_sha256,semantic=component.semantic_contract_sha256,
            selection=selection.sha256(),session_object=id(session),implementation_sha256=implementation_pin))

    @property
    def drives_cpu(self):return False
    @property
    def program_slots(self):return self.driver.program_slots()
    @property
    def local_step_map(self):return self.driver.local_step_map()
    def assert_current(self):self.driver.assert_current()
    def close(self):self.driver.close()


def bind_ahb_cpu_adapter(*,component,session,selection,preparation,endpoint_id=None):
    from ..registry import registrations
    _require(type(component) is VerifiedComponent and type(selection) is AdapterSelection,'typed-component-selection')
    _require(type(session) is _CLASS and session.artifact.plan.request.instance_id==component.instance_id,'session-class')
    rows=[r for r in registrations() if r.adapter_id==CPU_ADAPTER_ID]
    _require(len(rows)==1,'registration')
    pin=rows[0].implementation_sha256()
    _require(selection.adapter_id==CPU_ADAPTER_ID and selection.adapter_version=='1'
        and selection.implementation_sha256==pin and selection.component_artifact_sha256==component.artifact_sha256
        and selection.semantic_contract_sha256==component.semantic_contract_sha256,'selection')
    surface=ahb_cpu_surface_document(session.artifact)
    _require(component.artifact_sha256==surface['artifact_sha256']
        and component.semantic_contract_sha256==_digest(surface),'surface')
    endpoints=[e for e in component.endpoints() if e['role']=='cpu']
    _require(len(endpoints)==1 and endpoints[0]['endpoint_id']==surface['endpoint_id']
        and tuple(endpoints[0]['protocol'])==AHB_CPU_PROTOCOL and endpoints[0]['semantic_kind']==AHB_CPU_SEMANTIC_KIND
        and tuple(endpoints[0]['template'])==AHB_CPU_TEMPLATE and endpoints[0]['address_width']==34
        and endpoints[0]['data_width']==32 and endpoints[0]['address_units']=='byte','descriptor-ABI')
    _require(endpoint_id is None or endpoint_id==surface['endpoint_id'],'declared-endpoint')
    result=BoundAhbCpuAdapter(component,session,selection,surface,pin);result.assert_current();return result
