"""Directed CPU writer projection; never a compiled-path execution licence.

The CPU executes the generated SW/LW. Readback observes a value after the write;
it does not authenticate the prerequisite's hardware register version or retire
an instruction. Keep those missing grants explicit even after a successful run.
"""
from dataclasses import replace
from hashlib import sha256
import json

from myfuzz.scenario.register_source_access import validate_register_candidate
from myfuzz.scenario.rv32i_sources import Rv32iInstruction, fragment_bytes, _split_address


def declare_writer(request, compiled, *, source_id, value, result_address=0x30000):
    sources=[s for p in compiled['paths'] if p['flow_id']=='F4' and p['status']=='executable'
             for s in p['sources'] if s['source_id']==source_id and s['kind']=='cpu_mmio_stream']
    if len(sources)!=1:
        raise ValueError('generated-writer-F4-source-missing')
    source=sources[0]; access=source['register_access']
    candidate=validate_register_candidate(request,compiled,source_id=source_id,
        source_component=access['source_component'],source_endpoint=access['source_endpoint'],
        target_component=access['target_component'],address=access['address'],
        write=True,value=value,byte_enable=15)
    cpu=request.component(access['source_component']).profile.cpu
    if cpu is None or cpu.xlen!=32 or 'I' not in {e.upper() for e in cpu.extensions}:
        raise ValueError('generated-writer-RV32I-required')
    if type(result_address) is not int or not 0<=result_address<=0xfffffffc or result_address%4:
        raise ValueError('generated-writer-result-address-invalid')
    resources=[r for r in request.wiring.resources if r.component_instance==access['source_component']
               and r.write is True and r.base is not None and r.size is not None
               and r.base<=result_address and result_address+4<=r.base+r.size]
    if len(resources)!=1:raise ValueError('generated-writer-result-RAM-undeclared')
    if any(w.base<=result_address<w.base+w.size for w in request.wiring.windows):
        raise ValueError('generated-writer-result-overlaps-MMIO')
    address_high,address_low=_split_address(access['address'])
    value_high,value_low=_split_address(value)
    result_high,result_low=_split_address(result_address)
    code=fragment_bytes((Rv32iInstruction('LUI',rd=1,immediate=address_high),
        Rv32iInstruction('ADDI',rd=1,rs1=1,immediate=address_low),
        Rv32iInstruction('LUI',rd=2,immediate=value_high),
        Rv32iInstruction('ADDI',rd=2,rs1=2,immediate=value_low),
        Rv32iInstruction('SW',rs1=1,rs2=2),
        Rv32iInstruction('LW',rd=3,rs1=1),
        Rv32iInstruction('LUI',rd=4,immediate=result_high),
        Rv32iInstruction('SW',rs1=4,rs2=3,immediate=result_low),
        *(Rv32iInstruction('NOP') for _ in range(4))))
    return dict(schema_version='generated_register_writer.v1',candidate=candidate,
        result_address=result_address,code_hex=code.hex(),code_sha256=sha256(code).hexdigest(),
        compiled_sha256=sha256(json.dumps(compiled,sort_keys=True).encode()).hexdigest(),
        runtime_admitted=False,scope='directed_CPU_writer_and_readback_only',
        unsupported_flows=['F1','F2','F3'],
        refusals=['ip-register-version-prerequisite-not-authenticated',
                  'compiled-chain-certificate-checker-not-installed'])


def writer_case(runtime, declaration, *, request, compiled):
    """Project bytes into a declared CPU instruction slot of this live runtime.

    This is a directed diagnostic, separate from decoder/search admission. A
    caller must not commit this modified proposal to the original decoder.
    """
    if declaration.get('schema_version')!='generated_register_writer.v1':
        raise ValueError('generated-writer-declaration-invalid')
    candidate=declaration['candidate']; access=candidate['access']
    if declaration!=declare_writer(request,compiled,source_id=candidate['source_id'],value=candidate['value'],
                                   result_address=declaration['result_address']):
        raise ValueError('generated-writer-declaration-mismatch')
    source=next((s for s in runtime.decoder.sources if s.kind=='instruction'
                 and s.component==access['source_component']),None)
    if source is None:raise ValueError('generated-writer-runtime-owner-mismatch')
    for name in (access['source_component'],access['target_component']):
        live=runtime.session.runner.sessions.get(name)
        if live is None or live.artifact.plan.profile.profile_fingerprint!=request.component(name).profile.profile_fingerprint:
            raise ValueError('generated-writer-D2-profile-mismatch')
    cpu_artifact=runtime.session.runner.sessions[access['source_component']].artifact
    target_artifact=runtime.session.runner.sessions[access['target_component']].artifact
    if (cpu_artifact.runtime_document.get('kind')!='obi_cpu'
            or target_artifact.runtime_document.get('kind') not in ('apb_gpio','apb3_register_observe')):
        raise ValueError('generated-writer-runtime-protocol-unsupported')
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    target=runtime.session.runner.sessions[access['target_component']]
    if verify_apb_register_trace(target.artifact) is not True:
        raise ValueError('generated-writer-native-APB-observation-required')
    router=runtime.session.runner.sessions[access['source_component']].router
    # Actual immutable routing declarations, never profile-name inference.
    windows=getattr(router,'windows',None)
    if windows is None:raise ValueError('generated-writer-runtime-route-unavailable')
    routes=[w for w in windows if (w.device_id,w.base,w.size)==
            (access['device_id'],access['window_base'],access['window_size'])
            and w.target is runtime.session.runner.sessions.get(access['target_component'])]
    if len(routes)!=1:raise ValueError('generated-writer-runtime-route-mismatch')
    for salt in range(256):
        case=runtime.decoder.decode(bytes((salt,0,0,0,0,0,0,0)))
        if case.source.component==source.component and hasattr(case.source,'data_hex'):break
    else:raise ValueError('generated-writer-instruction-slot-unavailable')
    if runtime.decoder.instruction_start<=declaration['result_address']<runtime.decoder.instruction_end:
        raise ValueError('generated-writer-result-overlaps-instruction-slots')
    code=bytes.fromhex(declaration['code_hex'])
    if sha256(code).hexdigest()!=declaration['code_sha256']:
        raise ValueError('generated-writer-code-mismatch')
    if case.source.address+len(code)>runtime.decoder.instruction_end:
        raise ValueError('generated-writer-slot-overflow')
    return replace(case,source=replace(case.source,data_hex=code.hex()))


def check_writer_observation(declaration, receipt, *, target_artifact):
    """Join accepted CPU data requests to actual routed write/read deliveries.

    This event check is diagnostic, not a live receipt registry or a storage
    version authority. It intentionally cannot make runtime_admitted true.
    """
    from myfuzz.local_harness.native_physical_observation import verify_apb_register_trace
    if verify_apb_register_trace(target_artifact) is not True:
        raise ValueError('generated-writer-native-APB-observation-required')
    trace=target_artifact.runtime_document.get('base_protocol_trace',{})
    if trace.get('protocol')!='apb3':raise ValueError('generated-writer-native-APB-protocol-mismatch')
    signals=trace['signals']
    access=declaration['candidate']['access']; value=declaration['candidate']['value']
    events=receipt.events
    matches=[e for e in events if e.get('kind')=='mmio_delivery'
        and e.get('component')==access['source_component']
        and e.get('device_id')==access['device_id'] and e.get('address')==access['address']]
    writes=[e for e in matches if e.get('write') and e.get('write_value')==value
            and e.get('byte_enable')==15]
    if len(writes)!=1:raise ValueError('generated-writer-actual-write-mismatch')
    write=writes[0]
    reads=[e for e in matches if e.get('write') is False and e.get('read_value')==value
           and e['event_id']>write['event_id']]
    if len(reads)!=1:raise ValueError('generated-writer-actual-readback-mismatch')
    joined=[]
    for delivery in (write,reads[0]):
        accepted=[e for e in events if e.get('kind')=='mmio_acceptance'
            and e.get('source_transaction')==delivery.get('source_transaction')
            and e.get('address')==access['address'] and e.get('write')==delivery['write']
            and e['event_id']<delivery['event_id']]
        if len(accepted)!=1:raise ValueError('generated-writer-CPU-acceptance-join-mismatch')
        physical=[]
        for e in events:
            if e.get('kind')!='local_tick_sample' or e.get('component')!=access['target_component'] or e.get('phase')!='pre' or e.get('producer_event_id')!=delivery.get('producer_event_id'):continue
            b=e['outputs']['backend']
            expected=dict(psel=1,penable=1,pready=1,pwrite=int(delivery['write']),
                          paddr=access['register_offset'],pslverr=0)
            expected['pwdata' if delivery['write'] else 'prdata']=value
            if all(b.get(signals[k])==v for k,v in expected.items()):physical.append(e)
        if len(physical)!=1:raise ValueError('generated-writer-native-APB-transfer-mismatch')
        joined.append(dict(native_APB_event=physical[0]['event_id'],acceptance_event=accepted[0]['event_id'],
            delivery_event=delivery['event_id'],source_transaction=delivery['source_transaction']))
    ram=[e for e in events if e.get('kind')=='memory_write' and e.get('component')==access['source_component']
         and e.get('address')==declaration['result_address'] and e.get('value')==value
         and e.get('byte_enable')==15 and e['event_id']>reads[0]['event_id']]
    if len(ram)!=1:raise ValueError('generated-writer-CPU-readback-RAM-mismatch')
    return dict(schema_version='generated_register_writer_observation.v1',
        RAM_event=ram[0]['event_id'],RAM_transaction=ram[0]['transaction'],
        runtime_admitted=False,proof_scope='CPU_data_acceptance_route_and_readback_observation',
        case_id=receipt.case_id,value=value,address=access['address'],joins=joined,
        register_version_authenticated=False,refusals=declaration['refusals'])
