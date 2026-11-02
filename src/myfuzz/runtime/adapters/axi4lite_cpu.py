"""AXI4-Lite CPU ABI binding over the existing memory session; no IRQ or retirement authority."""
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
from ..contracts import AdapterSelection,VerifiedComponent,GenericRuntimeRefused,canonical_json_bytes

CPU_ADAPTER_ID='axi4-lite.cpu.v1'
CPU_ADAPTER_VERSION='1'
AXI4LITE_CPU_PROTOCOL=('axi4-lite','1')
AXI4LITE_CPU_TEMPLATE=('cpu.axi4-lite','1','no-response-code')
AXI4LITE_CPU_SEMANTIC_KIND='cpu.axi4-lite.v1'
#: AXI4-Lite completes an access when B (write) or R (read) appears; the two
#: channels are independent, which is what the generated template contract
#: already declares as ``completion='independent_channels_response'``.
AXI4LITE_CPU_COMPLETION='independent_channels_response'
AXI4LITE_CPU_WRITE_ROLES=('awvalid','awready','awaddr','awprot','wvalid','wready','wdata',
    'wstrb','bvalid','bready')
AXI4LITE_CPU_READ_ROLES=('arvalid','arready','araddr','arprot','rvalid','rready','rdata')
AXI4LITE_CPU_DATA_FUNCTIONS=frozenset({'memory_master','processor_memory_master'})
#: Roles this pinned CPU really has no pin for.  Declaring one is a different
#: ABI (AXI4, or a CPU whose AXI4-Lite slave/monitor shows response codes), not
#: this adapter's, so an artifact that declares one is refused instead of being
#: silently widened.
AXI4LITE_CPU_ABSENT_ROLES=('bresp','rresp','bid','rid','wid','awid','arid','awlen','arlen',
    'awsize','arsize','awburst','arburst','awcache','arcache','awlock','arlock','awqos',
    'arqos','awregion','arregion','awuser','aruser','wuser','buser','ruser')
_WIDE_ROLES={'awvalid':1,'awready':1,'awprot':3,'wvalid':1,'wready':1,'bvalid':1,'bready':1,
    'arvalid':1,'arready':1,'arprot':3,'rvalid':1,'rready':1}
#: What the bound session can and cannot observe.  Every value restates a fact of
#: the generated harness/executor, never a capability claim.
AXI4LITE_CPU_CAPABILITY_LIMITS={
    'mmio_beats':'supported:routed_beat_queued_at_the_CPU_and_drained_at_the_declared_target',
    'ram_read_write':'supported:persistent_memory_service',
    'deferred_mmio':'supported:queued_acceptance_joined_at_the_declared_target_step',
    # AXI4-Lite has no read strobe: a read transfers the whole addressed word,
    # the sampled wstrb is 0 (picorv32.v:2777 asserts ARVALID only while
    # mem_wstrb == 0), and the routed request carries the declared four-lane
    # access.  The sampled value stays in the beat sample and in the protocol
    # taps; ``local_harness/axi_lite_session.READ_TRANSFER_DECLARATION`` is the
    # single machine-readable statement of this policy.
    'byte_enable':'write_only:four_lane_wstrb_reads_present_zero_and_transfer_the_whole_addressed_word',
    'instruction_identity':'sampled:declared_arprot_bit2_of_the_admitted_cpu_protocol_trace_no_physical_export',
    'instruction_slots':'supported:declared_fetch_slot_parked_until_the_bound_source_materialises_it',
    'instruction_retirement':'unknown:no_rvfi_and_ENABLE_TRACE_0',
    'native_IRQ':'unsupported:ENABLE_IRQ_0_and_irq_held_at_its_inactive_value',
    'error_response':'unsupported:this_axi4_lite_top_has_no_bresp_or_rresp_pin',
    'storage_version':'unsupported:no_storage_provider_on_this_boundary',
    'F5':'unsupported:no_IRQ_or_pin_delivery_route',
    'F6':'unsupported:no_shared_slot_or_DMA_provider',
}
_ROOT=Path(__file__).resolve().parents[4]
_FILES=('src/myfuzz/runtime/adapters/axi4lite_cpu.py','src/myfuzz/local_harness/axi_lite_session.py',
    'src/myfuzz/local_harness/native_session.py','src/myfuzz/local_harness/session.py')
_MODULE_DIGESTS={name:sha256((_ROOT/name).read_bytes()).hexdigest() for name in _FILES}
_CLASS=GeneratedAxiLiteMemorySession
_METHODS={name:(getattr(_CLASS,name),getattr(_CLASS,name).__code__) for name in
    ('step_local','begin_case','reset_local','accept_instructions','identity_document',
     '_service_accepted_request')}


def _digest(value):return sha256(canonical_json_bytes(value)).hexdigest()


def _require(value,reason):
    if not value:raise GenericRuntimeRefused('generic-binding-drift','/axi4lite_cpu',{'reason':reason})


def _executor_rows(document):
    selected=document.get('selected_template')
    executor=selected.get('executor') if isinstance(selected,dict) else None
    binding=executor.get('binding') if isinstance(executor,dict) else None
    if not isinstance(binding,dict) or not isinstance(binding.get('endpoints'),list):
        raise ValueError('AXI4-Lite generated executor binding required')
    return binding


def axi4lite_cpu_data_endpoint(artifact):
    """The single declared AXI4-Lite CPU memory endpoint of one artifact."""
    document=artifact.runtime_document
    if not isinstance(document,dict) or document.get('kind')!='axi4_lite_cpu':
        raise ValueError('AXI4-Lite CPU artifact required')
    rows=[endpoint for endpoint in artifact.plan.binding.endpoints
        if tuple(endpoint.protocol)==AXI4LITE_CPU_PROTOCOL
        and endpoint.function in AXI4LITE_CPU_DATA_FUNCTIONS]
    if len(rows)!=1:
        raise ValueError('one AXI4-Lite CPU data endpoint required')
    return rows[0]


def axi4lite_cpu_roles(artifact,endpoint_id):
    """Measured role/width/direction rows of the declared endpoint."""
    rows=[row for row in _executor_rows(artifact.runtime_document)['endpoints']
        if isinstance(row,dict) and row.get('endpoint_id')==endpoint_id]
    if len(rows)!=1:raise ValueError('one declared endpoint row required')
    declared={}
    for row in rows[0].get('roles') or ():
        role=row.get('role')
        if type(role) is not str or not role or role in declared:
            raise ValueError('unique declared role required')
        if role in AXI4LITE_CPU_ABSENT_ROLES:
            raise ValueError('role not present on this AXI4-Lite CPU: '+role)
        declared[role]=[row.get('direction'),row.get('width'),row.get('physical_port')]
    required=AXI4LITE_CPU_WRITE_ROLES+AXI4LITE_CPU_READ_ROLES
    missing=[role for role in required if role not in declared]
    if missing:raise ValueError('incomplete AXI4-Lite CPU ABI: '+','.join(missing))
    extra=sorted(set(declared)-set(required))
    if extra:raise ValueError('undeclared role not in this ABI: '+','.join(extra))
    for role,width in _WIDE_ROLES.items():
        if declared[role][1]!=width:raise ValueError('declared role width changed: '+role)
    if declared['wdata'][1]!=declared['rdata'][1]:
        raise ValueError('AXI4-Lite read/write data widths differ')
    if declared['wstrb'][1]!=declared['wdata'][1]//8:
        raise ValueError('AXI4-Lite strobe width is not data_width/8')
    if declared['awaddr'][1]!=declared['araddr'][1]:
        raise ValueError('AXI4-Lite write/read address widths differ')
    return declared


def axi4lite_cpu_surface_document(artifact):
    """Derive the certified AXI4-Lite CPU execution surface of one artifact.

    The document is a pure function of the generated artifact: the declared
    endpoint row, its measured role rows, the template contract, the profile's
    declared facts and the boot contract.  It claims only what the bound
    :class:`~myfuzz.local_harness.axi_lite_session.GeneratedAxiLiteMemorySession`
    can really observe, and names every capability it cannot.
    """
    document=artifact.runtime_document
    endpoint=axi4lite_cpu_data_endpoint(artifact)
    roles=axi4lite_cpu_roles(artifact,endpoint.endpoint_id)
    contract=document['selected_template'].get('contract') or {}
    if (contract.get('template_id'),contract.get('template_version'),
            contract.get('variant_id'))!=AXI4LITE_CPU_TEMPLATE:
        raise ValueError('AXI4-Lite CPU template contract changed')
    if contract.get('protocol')!=list(AXI4LITE_CPU_PROTOCOL):
        raise ValueError('AXI4-Lite CPU template protocol changed')
    capabilities=artifact.plan.profile.capabilities
    facts=_executor_rows(document).get('declared_profile_facts')
    if not isinstance(facts,dict):
        raise ValueError('AXI4-Lite declared profile facts required')
    if (capabilities.get('address_width'),capabilities.get('data_width'),
            capabilities.get('byte_enable'),capabilities.get('max_outstanding'),
            capabilities.get('error_response'))!=(32,32,True,1,False):
        raise ValueError('AXI4-Lite declared widths/completion capabilities changed')
    if (facts.get('address_width'),facts.get('data_width'),facts.get('byte_enable'),
            facts.get('max_outstanding'),facts.get('error_response'))!=(32,32,True,1,False):
        raise ValueError('AXI4-Lite declared profile facts changed')
    if roles['awaddr'][1]!=32 or roles['araddr'][1]!=32 or roles['wdata'][1]!=32:
        raise ValueError('AXI4-Lite measured widths do not match the declared ones')
    boot=document.get('boot_contract') or {}
    base=boot.get('configured_boot_base')
    if type(base) is not int or not 0<=base<1<<32 or base%4:
        raise ValueError('AXI4-Lite configured boot base required')
    return dict(schema_version='axi4lite_cpu_execution_surface.v1',kind=AXI4LITE_CPU_SEMANTIC_KIND,
        instance_id=artifact.plan.request.instance_id,endpoint_id=endpoint.endpoint_id,
        protocol=list(AXI4LITE_CPU_PROTOCOL),template=list(AXI4LITE_CPU_TEMPLATE),
        function=endpoint.function,
        roles=[[role,*roles[role][:2]] for role in sorted(roles)],
        signals={role:roles[role][2] for role in sorted(roles)},
        boot_contract=deepcopy(boot),source_sha256=_digest(artifact.source_verification),
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        artifact_sha256=document['artifact_digest'],
        address_width=32,data_width=32,address_units='byte',byte_enable_width=roles['wstrb'][1],
        max_outstanding=1,completion_kind=AXI4LITE_CPU_COMPLETION,
        write_channels=['aw','w','b'],read_channels=['ar','r'],
        instruction_identity='unsupported',instruction_retirement='unknown',native_IRQ='unsupported',
        first_fetch_observation='unavailable_through_bound_session',error_observed=False,
        capability_limits=dict(AXI4LITE_CPU_CAPABILITY_LIMITS))


@dataclass(frozen=True)
class Axi4LiteCpuAbiFacts:
    endpoint_id:str
    boot_base:int
    address_width:int=32
    data_width:int=32
    address_units:str='byte'
    protocol:tuple=AXI4LITE_CPU_PROTOCOL
    template:tuple=AXI4LITE_CPU_TEMPLATE

    def document(self):
        from dataclasses import asdict
        return asdict(self)


class Axi4LiteCpuDriver:
    """Describe the admitted CPU; Runner remains the sole execution coordinator."""
    def __init__(self,session,artifact,surface,implementation_pin):
        self._session,self._artifact=session,artifact
        self._surface=canonical_json_bytes(surface)
        self._implementation_pin=implementation_pin;self._closed=False
        self.facts=Axi4LiteCpuAbiFacts(surface['endpoint_id'],
            surface['boot_contract']['configured_boot_base'])

    def assert_current(self):
        from ..registry import registrations
        _require(not self._closed,'closed')
        _require(all(sha256((_ROOT/name).read_bytes()).hexdigest()==digest
            for name,digest in _MODULE_DIGESTS.items()),'module-source')
        _require(type(self._session) is _CLASS and self._session.artifact is self._artifact,
            'session-owner')
        _require(all(name not in vars(self._session) and getattr(_CLASS,name) is method
            and method.__code__ is code for name,(method,code) in _METHODS.items()),'session-method')
        registrations_for_cpu=[r for r in registrations() if r.adapter_id==CPU_ADAPTER_ID]
        _require(len(registrations_for_cpu)==1
            and registrations_for_cpu[0].implementation_sha256()==self._implementation_pin,
            'implementation')
        _require(canonical_json_bytes(axi4lite_cpu_surface_document(self._artifact))==self._surface,
            'artifact-ABI')

    def program_slots(self):
        self.assert_current()
        return {'instruction.boot':dict(kind='instruction_image',boot_base=self.facts.boot_base,
            first_fetch_verification='runtime_observation_required',
            first_fetch_observation='unavailable_through_bound_session',
            endpoints=[self.facts.endpoint_id],instruction_identity='unsupported',
            address_width=32,instr_width=32,address_units='byte',
            source='artifact_boot_contract_no_online_instruction_slot')}

    def local_step_map(self):
        self.assert_current()
        return dict(schema_version='axi4lite_cpu_local_step_map.v1',
            max_local_ticks_per_step=self._session.max_local_ticks_per_step,
            max_transaction_events_per_step=self._session.max_transaction_events_per_step,
            mmio_service='queued_routed_target_response',
            defer_mmio=True,pending_responses=self._session.pending_responses,
            max_mmio_target_accesses_per_step=self._session.max_mmio_target_accesses_per_step,
            read_byte_enable='zero',error_observation='not_exposed_to_cpu_boundary',
            address_units='byte',completion_kind=AXI4LITE_CPU_COMPLETION)

    def close(self):self._closed=True


class BoundAxi4LiteCpuAdapter:
    def __init__(self,component,session,selection,surface,implementation_pin):
        self.component_instance_id=component.instance_id;self.endpoint_id=surface['endpoint_id']
        self.adapter_id=CPU_ADAPTER_ID;self.adapter_version='1'
        self.protocol=AXI4LITE_CPU_PROTOCOL
        self.template=AXI4LITE_CPU_TEMPLATE;self.semantic_kind=AXI4LITE_CPU_SEMANTIC_KIND
        self.address_units='byte';self.completion_kind=AXI4LITE_CPU_COMPLETION
        self.implementation_sha256=implementation_pin
        self.driver=Axi4LiteCpuDriver(session,artifact=session.artifact,surface=surface,
            implementation_pin=implementation_pin)
        self.abi_facts=self.driver.facts
        self.binding_sha256=_digest(dict(component=component.artifact_sha256,
            semantic=component.semantic_contract_sha256,selection=selection.sha256(),
            session_object=id(session),implementation_sha256=implementation_pin))

    @property
    def drives_cpu(self):return False
    @property
    def program_slots(self):return self.driver.program_slots()
    @property
    def local_step_map(self):return self.driver.local_step_map()
    def assert_current(self):self.driver.assert_current()
    def close(self):self.driver.close()


def bind_axi4lite_cpu_adapter(*,component,session,selection,preparation=None,endpoint_id=None):
    from ..registry import registrations
    _require(type(component) is VerifiedComponent and type(selection) is AdapterSelection,
        'typed-component-selection')
    _require(type(session) is _CLASS,'exact-GeneratedAxiLiteMemorySession-required')
    _require(session.artifact.plan.request.instance_id==component.instance_id,'session-class')
    rows=[r for r in registrations() if r.adapter_id==CPU_ADAPTER_ID]
    _require(len(rows)==1,'registration')
    pin=rows[0].implementation_sha256()
    _require(selection.adapter_id==CPU_ADAPTER_ID and selection.adapter_version=='1'
        and selection.implementation_sha256==pin
        and selection.component_artifact_sha256==component.artifact_sha256
        and selection.semantic_contract_sha256==component.semantic_contract_sha256,'selection')
    try:
        surface=axi4lite_cpu_surface_document(session.artifact)
    except ValueError as error:
        # The shared binding layer already converts a ValueError into this same
        # refusal; raising it here keeps the direct call typed as well.
        raise GenericRuntimeRefused('generic-binding-drift','/axi4lite_cpu',
            {'reason':'artifact-ABI','detail':str(error)[:160]}) from error
    _require(component.artifact_sha256==surface['artifact_sha256']
        and component.semantic_contract_sha256==_digest(surface),'surface')
    endpoints=[e for e in component.endpoints() if e['role']=='cpu']
    _require(len(endpoints)==1,'one-cpu-endpoint-required')
    endpoint=endpoints[0]
    _require(endpoint['endpoint_id']==surface['endpoint_id']
        and tuple(endpoint['protocol'])==AXI4LITE_CPU_PROTOCOL
        and endpoint['semantic_kind']==AXI4LITE_CPU_SEMANTIC_KIND
        and tuple(endpoint['template'])==AXI4LITE_CPU_TEMPLATE
        and endpoint['address_width']==32 and endpoint['data_width']==32
        and endpoint['address_units']=='byte' and endpoint['completion_kind']==AXI4LITE_CPU_COMPLETION
        and endpoint['byte_enable'] is True,'descriptor-ABI')
    if endpoint_id is not None:
        _require(endpoint_id==surface['endpoint_id'],'declared-endpoint')
    result=BoundAxi4LiteCpuAdapter(component,session,selection,surface,pin)
    result.assert_current();return result
