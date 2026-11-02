"""CPU-protocol selection independent of the routed target protocol or IP."""
from dataclasses import dataclass
from .compiled_f4 import _cpu_traces,_cpu_error_policy,_native_steps
from .compiled_wishbone_f4 import wishbone_cpu_traces,_wishbone_cpu_policy,wishbone_native_beats
from .native_obi_hops import collect_native_obi_beats
from ..local_harness.cpu_session import GeneratedCve2Session
from ..local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession


@dataclass(frozen=True)
class MmioCpuAdapter:
    protocol:str
    session_type:type
    traces:dict
    policy:dict
    instruction_granule:int=4
    #: How the generated session names its native transactions.  ``unified``
    #: means one request channel and one sequence counter shared by instruction
    #: fetches and data beats (the AHB and AXI4-Lite memory sessions, whose keys
    #: carry channel id ``memory``); ``split`` means the OBI/Wishbone rows, whose
    #: fetches and data beats have their own channel id and sequence.
    channel_model:str='split'
    #: Whether this row's ``unified`` session really implements the host-RAM
    #: commit stream and the writer-aware read receipts the independent F1/F3
    #: memory flows need.  Declared by the adapter, never inferred: the shared
    #: unified sessions do not have them, so the executor keeps F1/F3 off for
    #: every row that does not say ``True`` here (default ``False``).
    memory_receipts_on_unified:bool=False

    def prepare_declaration(self,declaration,*,address):
        from copy import deepcopy
        from hashlib import sha256
        granule=self.instruction_granule
        if address%granule:raise ValueError('MMIO-instruction-fetch-alignment')
        result=deepcopy(declaration);code=bytes.fromhex(result['code_hex'])
        padding=(-len(code))%granule
        if padding:
            if padding%4:raise ValueError('MMIO-instruction-padding-word')
            code+=bytes.fromhex('13000000')*(padding//4)
            result.update(code_hex=code.hex(),code_sha256=sha256(code).hexdigest(),
                fixed_padding=dict(bytes=padding,instruction='RV32I_NOP',fetch_granule=granule))
        return result

    def first_fetch(self,events,cpu):
        if self.protocol=='ahb-lite':
            from .native_ahb_beats import collect_ahb_cpu_beats
            return collect_ahb_cpu_beats(events,cpu,self.traces)[1]
        if self.protocol=='wishbone':
            return [(e['event_id'],e['address']) for e in wishbone_native_beats(events,cpu,self.traces,require_resolved=False)
                if e['kind']=='acceptance' and e['channel']=='instr']
        if self.protocol=='axi4-lite':
            from .axil_cpu_protocol_observations import collect_axi4lite_cpu_fetches
            return collect_axi4lite_cpu_fetches(events,cpu=cpu,observation=self.traces['observation'])
        signals=self.traces['instr']
        return [(event['event_id'],taps[signals['addr']]) for event,taps in _native_steps(events,cpu)
            if taps.get(signals['req'])==1 and taps.get(signals['gnt'])==1]

    def completed_beats(self,events,cpu):
        if self.protocol=='ahb-lite':
            from .native_ahb_beats import collect_ahb_cpu_beats
            return collect_ahb_cpu_beats(events,cpu,self.traces)[0]
        if self.protocol=='axi4-lite':
            from .axil_cpu_protocol_observations import collect_axi4lite_cpu_beats
            return collect_axi4lite_cpu_beats(events,cpu=cpu,observation=self.traces['observation'])
        if self.protocol=='obi':return collect_native_obi_beats(events,cpu=cpu,traces=self.traces,error_policy=self.policy)
        pending={};completed={}
        for event in wishbone_native_beats(events,cpu,self.traces,require_resolved=False):
            key=(event['channel'],event['sequence'])
            if event['kind']=='acceptance':pending[key]=event
            else:
                accepted=pending.pop(key)
                completed[key]=dict(accepted,response_event=event['event_id'],rdata=event['rdata'])
        return completed


def select_mmio_cpu(artifact,image,stream,*,base_dir=None):
    from .extension_plugins import cpu_adapter as _extension_cpu
    extended=_extension_cpu(artifact,image,stream,base_dir=base_dir)
    if extended is not None:return extended
    kind=artifact.runtime_document.get('kind')
    if kind=='obi_cpu':
        return MmioCpuAdapter('obi',GeneratedCve2Session,_cpu_traces(artifact,image,stream),_cpu_error_policy(artifact,image,stream))
    if kind=='ahb_lite_cpu':
        from ..local_harness.ahb_lite_session import GeneratedAhbMemorySession
        from ..local_harness.cvw_contract import cvw_instruction_fetch_granule
        from pathlib import Path
        from ..scenario.ahb_cpu_events import bind_ahb_trace
        from ..local_harness.ahb_startup import configure_observer_startup
        from ..scenario.ahb_cpu_events import AhbCpuObserver
        from .profile_cpu_fetch import profile_fetch_granule
        endpoint,signals,binding=bind_ahb_trace(artifact.runtime_document)
        observer=AhbCpuObserver(component_id=artifact.plan.request.instance_id,endpoint_id=endpoint)
        startup=configure_observer_startup(observer,artifact.runtime_document)
        root=base_dir or Path(__file__).resolve().parents[3]
        granule=profile_fetch_granule(artifact.plan.profile,base_dir=root)
        if granule is None:
            granule=cvw_instruction_fetch_granule(artifact.plan.profile,base_dir=root)
        return MmioCpuAdapter('ahb-lite',GeneratedAhbMemorySession,
            dict(signals=signals,endpoint_id=endpoint,manager_domain=startup['manager_domain'],
                startup={k:v for k,v in startup.items() if k!='manager_domain'}),
            dict(native_error_observation=True),
            granule,
            'unified')
    if kind=='wishbone_cpu':
        return MmioCpuAdapter('wishbone',GeneratedWishboneCpuSession,wishbone_cpu_traces(artifact,image,stream),_wishbone_cpu_policy(artifact,image,stream))
    if kind=='axi4_lite_cpu':
        from .axil_cpu_protocol_observations import select_axi4lite_cpu_protocol
        return select_axi4lite_cpu_protocol(artifact,image,stream)
    raise ValueError('MMIO-CPU-adapter-unsupported:'+str(kind))


def native_cpu_protocol(runtime_document):
    """Name the actual native CPU boundary, independent of target protocol."""
    protocol={'obi_cpu':'obi','wishbone_cpu':'wishbone','ahb_lite_cpu':'ahb-lite',
              'axi4_lite_cpu':'axi4-lite',
              'tilelink_coherent_cpu':'tilelink-coherent'}.get(runtime_document.get('kind'))
    if protocol is None:raise ValueError('MMIO-CPU-adapter-unsupported')
    return protocol


def collect_native_cpu_beats(events,component,*,runtime_document,traces,error_policy):
    """Pure replay view of existing native parsers; never grants live authority."""
    protocol=native_cpu_protocol(runtime_document)
    return MmioCpuAdapter(protocol,object,traces,error_policy).completed_beats(events,component)
