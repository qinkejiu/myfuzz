"""Explicitly synthetic native journal support; never a native gate fixture.

The original source-backed CPU/DMA service, route and ISR issuers execute.
Transport responses and the resulting physical observations are synthetic.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import importlib.util
import json
from types import SimpleNamespace

import pytest

from tests.integration.test_compiled_f6_contract import source_inputs, f6, digest, ROOT


@pytest.fixture(scope='module')
def inputs():
    request, compiled, artifacts = source_inputs()
    from myfuzz.integration.compiled_f6_runtime_path import admit_compiled_f6_runtime_path
    from myfuzz.scenario.ownership import compile_ownership
    compiled_inputs = dict(request=request, compiled=compiled,
        ownership=compile_ownership((), ()), physical_port_map={})
    runtime_path_admission = admit_compiled_f6_runtime_path(
        artifacts=artifacts, compiled_inputs=compiled_inputs, base_dir=ROOT)
    return f6(compiled), compiled, artifacts, compiled_inputs, runtime_path_admission


def source_versions(contract):
    p = contract['program_contract']
    return [dict(address=p['source_address']+4*i, value=w, memory_id='ram',
        generation=0, byte_offset=p['source_address']+4*i,
        versions=[[0,i+1]]*4, writer_event_ids=['source'+str(i)]*4,
        writer_kinds=['STORE']*4) for i,w in enumerate((11,22,33,44))]


@pytest.fixture
def consumer_case(inputs, tmp_path, monkeypatch):
    assert importlib.util.find_spec('myfuzz.integration.compiled_f6_consumer') is not None, 'Task5 actual F6 consumer is missing'
    return make_case(inputs, tmp_path, monkeypatch)


def make_case(inputs, tmp_path, monkeypatch, fault=None, status_word=0,
        response_cycle=True, mret_site=None, dma_session_type=None):
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    from myfuzz.integration.compiled_f6_layout import compile_f6_candidate_layout
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
    from myfuzz.local_harness.wishbone_dma_scenario_session import GeneratedWishboneDmaScenarioSession
    from myfuzz.local_harness.wire import DriverReceipt
    from myfuzz.local_harness.f6_dma_response_fault import F6ResponseFaultDeclaration, install_f6_response_fault
    from myfuzz.scenario.f6_ram_dma_policy import F6RamDmaPolicy
    from myfuzz.scenario.dma_route_admission import DmaMasterRouteAdmission
    from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runtime_path_contract import DmaMasterRouteContract
    from myfuzz.scenario.native_f6_isr_return import install_f6_isr_return
    from tests.integration.test_compiled_f6_response_fault import Topology
    from tests.integration.test_compiled_f6_isr_return import take, enter_isr, return_mret, mutation
    from tests.local_harness.test_cpu_native_irq_receipt import CpuNativeIrqReceiptTests

    path, compiled, artifacts, compiled_inputs, runtime_path_admission = inputs
    contract = path['execution_contract']; p = contract['program_contract']
    firmware = build_f6_firmware(contract)
    memory = PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),), initialization_seed=3, max_initialized_bytes=0x30000)
    for address,data in firmware.initial_images.items():memory.preload(address,data)
    for address,count in firmware.instruction_slots:memory.declare_instruction_slots(address,count)
    service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True, commit_stream_capacity=64)
    if dma_session_type is None:
        dma_session_type = GeneratedWishboneDmaSession
    if dma_session_type not in (GeneratedWishboneDmaSession,
            GeneratedWishboneDmaScenarioSession):
        raise ValueError('unsupported synthetic F6 DMA session type')
    dma = dma_session_type(artifacts['dma'], base_dir=ROOT, cache_dir=tmp_path,
        memory_service=service, max_control_edges=32, max_events=10000)
    irq_exports = [row for row in artifacts['dma'].runtime_document['physical_exports']
        if row.get('physical_port') == contract['irq']['producer_port']
        and row.get('endpoint_id') == contract['irq']['producer_endpoint_id']
        and row.get('direction') == 'output' and row.get('role') == 'irq'
        and row.get('width') == 1 and row.get('disposition') == 'functional']
    assert len(irq_exports) == 1
    irq_runtime_name = irq_exports[0]['runtime_name']
    # The base session used by this synthetic fixture does not parse an IRQ
    # output itself. Keep the same admitted export identity as the production
    # ScenarioSession so raw event payloads exercise the runtime alias.
    dma._irq_runtime_name = irq_runtime_name
    policy = F6RamDmaPolicy(contract)
    routes = tuple(DmaMasterRouteContract.from_document(row)
        for row in runtime_path_admission['selected_dma_routes'])
    routes_by_operation = {route.operation: route for route in routes}
    read_route, write_route = routes_by_operation['read'], routes_by_operation['write']
    topology = Topology(routes, [])
    admission = DmaMasterRouteAdmission(policy,topology,
        path_id=runtime_path_admission['runtime_path_ids'][0],
        read_route=read_route,write_route=write_route)
    dma.configure_dma_route_admission(admission)
    queue=[];irq_level=[0];dma_receipts=[]; regs={0:0,4:4,8:p['source_address']>>2,12:p['destination_address']>>2}
    def command(op, fields):
        pre=dict(mwb_cyc=0,mwb_stb=0,mwb_we=0,mwb_adr=0,mwb_dat_w=0,
            swb_cyc=fields[0],swb_stb=fields[1],swb_we=fields[2],swb_adr=fields[3],
            swb_dat_w=fields[4],swb_stall=0,swb_ack=int(bool(fields[0] and not fields[1])),
            swb_dat_r=regs[fields[3]*4])
        if fields[1] and fields[2]:regs[fields[3]*4]=fields[4]
        if queue:pre.update(queue.pop(0))
        if dma._pending is not None:
            pre['mwb_cyc']=int(response_cycle)
        pre.update(mwb_stall=fields[5],mwb_ack=fields[6],mwb_dat_r=fields[7],mwb_err=fields[8])
        dma.local_ticks+=1; dma._sequence+=1
        payload=dict(pre_backend=pre,
            observations=dict(backend={'mwb_stb':0},physical={irq_runtime_name:irq_level[0]}))
        if type(dma) is GeneratedWishboneDmaScenarioSession:
            physical = {dma._irq_runtime_name: irq_level[0]}
            sample = dict(local_tick=dma.local_ticks,
                pre=dict(backend=deepcopy(pre), physical=deepcopy(physical)),
                post=dict(backend=deepcopy(pre), physical=deepcopy(physical)))
            payload['samples'] = [sample]
        receipt=DriverReceipt('result',dma._execution,dma._sequence,dma.local_ticks-1,dma.local_ticks,1,
            payload=payload)
        dma_receipts.append(receipt);return receipt
    monkeypatch.setattr(dma,'command',command)
    declaration = F6ResponseFaultDeclaration(0,*fault) if fault else None
    selector = install_f6_response_fault(dma,declaration=declaration,execution_binding_sha256='b'*64) if fault else None
    dma._execution='d'*32;dma._case_id='stream';admission.begin_case(dma._execution,'stream')
    if selector:selector.begin_case(0)
    cpu = GeneratedCve2Session(artifacts['cpu'],base_dir=ROOT,cache_dir=tmp_path,memory=memory,
        router=DataflowRouter((DeviceWindow('dma',contract['control']['base'],16,dma),)),
        native_irq_receipts=True,memory_commit_receipts=True,physical_tick_samples=True)
    cpu._execution='a'*32;cpu._case_id='stream'
    helper=CpuNativeIrqReceiptTests()
    original_step=helper.step;irq_interval=[None]
    def sampled_irq_step(session,*,irq=0,**kwargs):
        interval=irq_interval[0]
        if interval is not None:
            start,end,delivery_id,source_output_key=interval
            irq=int(start<=session.local_ticks+1<end)
            session.set_next_irq_input_context(dict(schema_version='native_irq_input_context.v1',
                binding_delivery_event_id=delivery_id,expected_input=1,
                source_output_key=source_output_key,
                target_component='cpu',target_epoch=0) if irq else None)
        return original_step(session,irq=irq,**kwargs)
    helper.step=sampled_irq_step
    raw=sum(w<<(11*i) for i,w in enumerate((11,22,33,44))).to_bytes(8,'little')
    candidate=compile_f6_candidate_layout(path).decode(raw)
    prefix=firmware.prefix(candidate,case_index=0)
    source_event_id=contract['instruction_source_id']+':0'
    cpu.service.accept_instructions(p['slot_base'],prefix,source_event_id=source_event_id)
    issuer=install_f6_isr_return(cpu,contract=contract,execution_binding_sha256='b'*64)
    issuer.begin_case('case0',case_index=0,irq_take_key=['cpu',0,1])

    class Runtime:
        def _validated_f6_irq_runtime_name(self):
            from myfuzz.integration.compiled_f6 import CompiledF6Runtime
            return CompiledF6Runtime._validated_f6_irq_runtime_name(self)

        def evidence_binding(self):
            return dict(compiled_document_sha256=self.compiled_document_sha256,
                binding_sha256=self.binding_sha256,path_sha256=digest(self.path),
                path_id=self.path['path_id'],run_id=self.run_id,
                execution_binding_sha256=self.execution_binding_sha256)

        @property
        def case_inventory(self):
            from myfuzz.scenario.f6_assertion_evidence import _case_inventory
            return _case_inventory(self)

        def actual_read_results(self):
            from myfuzz.scenario.memory_service import _f6_dma_read_results
            return _f6_dma_read_results(self.dma)

        def corrupt(self,mode,attempt):
            rows={e['event_id']:e for e in self.observer_view}
            def row(section,i=0):
                ref=attempt[section];return rows[ref[i] if type(ref) is list else ref]
            if mode.startswith('snapshot_'):
                result=self.actual_read_results()[0];key,snapshot,handle=result
                if mode=='snapshot_version':object.__setattr__(snapshot,'versions',((0,999),)*4)
                elif mode=='snapshot_writer':object.__setattr__(snapshot,'writer_event_ids',('other',)*4)
                elif mode=='snapshot_key':object.__setattr__(snapshot,'transaction_id','other')
                else:self.dma.memory_service=MemoryService(self.cpu.memory,TransactionLedger())
            elif mode in ('unarmed_snapshot','saved_json'):
                self.dma.memory_service=MemoryService(self.cpu.memory,TransactionLedger())
                for i in range(4):self.dma.memory_service.read(TransactionKey('d'*32,'stream','dma',0,'dma-memory',i+1),p['source_address']+4*i,width_bytes=4)
            elif mode=='route':self.route_admission._route_matches[next(iter(self.route_admission._route_matches))]['address']+=4
            elif mode=='route_key':self.route_admission._route_matches[next(iter(self.route_admission._route_matches))]['transaction']['source_epoch']=1
            elif mode=='read_response':row('read_responses')['response']['rdata']+=1
            elif mode=='write_response':row('write_responses')['response']['error']=1
            elif mode=='commit_version':row('word_commits')['commit_document']['version']=[0,999]
            elif mode=='commit_key':row('word_commits')['transaction']['source_component']='cpu'
            elif mode=='commit_cells':row('word_commits')['commit_document']['enabled_byte_cells'][0]['value']^=1
            elif mode=='word_order':attempt['reads'][0],attempt['reads'][1]=attempt['reads'][1],attempt['reads'][0]
            elif mode=='operand':row('operands')['rdata']^=1<<20
            elif mode=='prefix':attempt['prefix_hex']='00'*128
            elif mode=='delivery':row('deliveries')['source_transaction']['source_sequence']+=100
            elif mode=='status':row('status')['rdata']=1<<30
            elif mode=='readback':row('readbacks')['rdata']+=1
            elif mode=='result':row('results')['value']+=1
            elif mode=='irq_delivery':row('irq_delivery')['target_epoch']=1
            elif mode=='irq_output':row('irq_output')['source_output_key'][1]=1
            elif mode=='duplicate_commit':self.observer_view.append(dict(deepcopy(row('word_commits')),event_id=len(rows)+1))
            elif mode=='duplicate_read_response':self.observer_view.append(dict(deepcopy(row('read_responses')),event_id=len(rows)+1))

        def probe_bridge(self,mode):
            from myfuzz.scenario.memory_service import _validate_f6_dma_read, _arm_f6_dma_read, _complete_f6_dma_read
            key,snapshot,handle=self.actual_read_results()[0]
            if mode=='unarmed':snapshot=self.cpu.memory.read(p['source_address'],4,transaction_id=str(key))
            elif mode=='wrong_key_identity':key=replace(key)
            elif mode=='wrong_owner':return _validate_f6_dma_read(self.cpu,self.cpu.service,key,snapshot,handle)
            elif mode=='copied_snapshot':snapshot=deepcopy(snapshot)
            elif mode=='copied_handle':handle=object()
            elif mode=='duplicate_delivery':return _complete_f6_dma_read(self.dma,{},None)
            elif mode=='override_read':self.dma.memory_service.read=lambda *a,**k:snapshot
            elif mode=='direct_arm':return _arm_f6_dma_read(self.dma,key)
            elif mode=='response_receipt':
                receipt=next(r for r in dma_receipts if r.tick_after==14)
                receipt.payload['pre_backend']['mwb_adr']+=1
            elif mode=='epoch':self.dma.reset_epoch+=1
            elif mode=='testcase':self.dma._case_id='other'
            elif mode=='execution':self.dma._execution='f'*32
            elif mode=='ledger_entry':
                self.dma.memory_service.ledger._entries[key]=deepcopy(self.dma.memory_service.ledger._entries[key])
            elif mode=='callback_event':
                next(e for e in self.dma.memory_service.events if e.get('kind')=='memory_read')['value']+=1
            elif mode=='bool_key':object.__setattr__(key,'source_epoch',False)
            return _validate_f6_dma_read(self.dma,self.dma.memory_service,key,snapshot,handle)

    from myfuzz.scenario.session_runtime import BoundOnlineInstruction, OnlineCase
    from myfuzz.integration.compiled_f6 import _compiled_f6_case_advances
    instruction_case=OnlineCase('case0','CPU_TO_IP',runtime_path_admission['runtime_path_ids'][1],
        BoundOnlineInstruction(source_event_id,'cpu',p['slot_base'],prefix.hex(),contract['instruction_source_id']),
        _compiled_f6_case_advances('cpu','dma',2))
    runtime=Runtime();runtime.contract=contract;runtime.path=path;runtime.cpu=cpu;runtime.dma=dma
    runtime.runtime_path_admission=runtime_path_admission
    runtime.execution_binding=dict(runtime_path_admission=deepcopy(runtime_path_admission),
        runtime_path_admission_sha256=runtime_path_admission['admission_sha256'])
    runtime.compiled_inputs=compiled_inputs;runtime.artifacts=artifacts;runtime.base_dir=ROOT
    runtime.session=SimpleNamespace(_cases=[instruction_case])
    runtime.policy=policy;runtime.route_admission=admission;runtime.observer_view=[]
    runtime.compiled_document_sha256=digest(compiled);runtime.binding_sha256='e'*64
    runtime.execution_binding_sha256='b'*64;runtime.run_id='synthetic-run'
    runtime.checker_findings=lambda:[]
    attempt=dict(case_id='case0',case_index=0,raw8_hex=raw.hex(),prefix_hex=prefix.hex(),
        operands=[],sources=[],source_commits=[],configuration=[],deliveries=[],reads=[],read_snapshots=[],
        read_responses=[],writes=[],word_commits=[],write_responses=[],readbacks=[],results=[])
    offsets={}
    def add(row,component):
        record=deepcopy(row);record.update(component=component,event_id=len(runtime.observer_view)+1)
        runtime.observer_view.append(record);return record['event_id']
    def drain():
        streams=[('cpu',cpu.cpu_events),('cpu',cpu.service.events),('cpu',cpu.router.acceptances),
            ('cpu',cpu.router.deliveries),('dma',dma.events),('dma',service.events)]
        for owner,stream in streams:
            start=offsets.get(id(stream),0)
            for row in stream[start:]:
                normalized=deepcopy(row)
                if hasattr(normalized.get('source_transaction'),'source_sequence'):normalized['source_transaction']=asdict(normalized['source_transaction'])
                if stream is cpu.router.acceptances:normalized['kind']='mmio_acceptance'
                if stream is cpu.router.deliveries:normalized['kind']='mmio_delivery'
                add(normalized,owner)
            offsets[id(stream)]=len(stream)
        for owner,svc in [('cpu',cpu.service),('dma',service)]:
            for event in svc.drain_commit_events():
                if not any(e.get('commit_id')==event['commit_id'] for e in runtime.observer_view):add(event,owner)
    def last(kind,owner='cpu'):
        return next(e['event_id'] for e in reversed(runtime.observer_view) if e['kind']==kind and e['component']==owner)
    def bus(address,write,value=0,channel='data'):
        def request(payload,irq):
            pre=payload['pre_backend'];tag='i' if channel=='instr' else 'd'
            pre.update({tag+'_req_valid':1,tag+'_req_write':int(write),tag+'_req_addr':address,
                tag+'_req_wdata':value,tag+'_req_be':15})
        helper.step(cpu,irq=0,mutation=request)
        if cpu._queued_mmio:cpu.router.drain_one('dma')
        def response(payload,irq):payload['pre_backend'][('i' if channel=='instr' else 'd')+'_rsp_ready']=1
        helper.step(cpu,irq=0,mutation=response);drain()
        return last('instr_response' if channel=='instr' else 'data_response')

    for i,w in enumerate(candidate.words):
        attempt['operands'].append(bus(p['slot_base']+40+8*i,False,channel='instr'))
        bus(p['source_address']+4*i,True,w)
        attempt['sources'].append(last('memory_write'));attempt['source_commits'].append(last('memory_write_commit'))
    # Firmware writes byte addresses into the CSR. The RTL selects the word
    # address bits internally when loading cfg_raddr/cfg_waddr.
    for name,value in [('source',p['source_address']),('destination',p['destination_address']),('length',4),('control',0x0fed0004)]:
        bus(contract['control']['base']+contract['dma']['csr']['offsets'][name],True,value)
        attempt['configuration'].append(last('data_accept'));attempt['deliveries'].append(last('mmio_delivery'))
    drain()
    versions=[]
    for i in range(4):
        event=next(e for e in runtime.observer_view if e['event_id']==attempt['source_commits'][i]);doc=event['commit_document']
        versions.append(dict(address=p['source_address']+4*i,value=candidate.words[i],memory_id=doc['memory_id'],
            generation=doc['generation'],byte_offset=doc['byte_offset'],versions=[doc['version']]*4,
            writer_event_ids=[str(TransactionKey(**doc['fullkey']))]*4,writer_kinds=['STORE']*4))
    policy.begin_transfer(case_id='case0',source_versions=versions,fault=declaration)
    for operation in ('read','write'):
        for i,w in enumerate(candidate.words):
            address=p['source_address' if operation=='read' else 'destination_address']+4*i
            queue.append(dict(mwb_cyc=1,mwb_stb=1,mwb_we=int(operation=='write'),mwb_adr=address>>2,mwb_dat_w=w if operation=='write' else 0))
            dma.step_local();drain()
            attempt['reads' if operation=='read' else 'writes'].append(last('dma_edge','dma'))
            selected=fault==(operation,i)
            if not selected:
                if operation=='read':attempt['read_snapshots'].append(last('memory_read','dma'))
                else:attempt['word_commits'].append(last('memory_write_commit','dma'))
            while dma._pending is not None:dma.step_local()
            drain();attempt['read_responses' if operation=='read' else 'write_responses'].append(last('dma_edge','dma'))
            if selected:break
        if fault and policy.state=='expected_response_fault_pending':break
    irq_level[0]=1;dma.step_local()
    irq_edge=dma.events[-1]
    irq_edge.update(reset_epoch=dma.reset_epoch)
    drain()
    irq_source_key=['dma',dma.reset_epoch,contract['irq']['producer_port'],irq_edge['tick']]
    output=add(dict(kind='source_start',source_output_key=irq_source_key,source=['dma','irq'],target=['cpu','irq'],producer_event_id=last('dma_edge','dma')), 'dma')
    delivery=add(dict(kind='binding_delivery',source_event_id=output,source_output_key=irq_source_key,
        delivery_id=contract['irq']['delivery_id'],target_component='cpu',target_epoch=0,start_local_tick=cpu.local_ticks+1,end_local_tick=cpu.local_ticks+17), 'cpu')
    irq_interval[0]=(cpu.local_ticks+1,cpu.local_ticks+17,delivery,irq_source_key)
    cpu.set_next_irq_input_context(dict(schema_version='native_irq_input_context.v1',binding_delivery_event_id=delivery,
        expected_input=1,source_output_key=irq_source_key,target_component='cpu',target_epoch=0))
    take(cpu,helper);enter_isr(contract,cpu,helper);drain();attempt['irq']=last('cpu_external_irq_taken')
    attempt['irq_output']=output;attempt['irq_delivery']=delivery
    regs[0]=(1<<30) if fault else status_word
    attempt['status']=bus(contract['control']['base'],False)
    bus(p['result_base'],True,regs[0]);attempt['status_store']=last('memory_write')
    if not fault:
        for i,w in enumerate(candidate.words):
            attempt['readbacks'].append(bus(p['destination_address']+4*i,False))
            bus(p['result_base']+4+4*i,True,w);attempt['results'].append(last('memory_write'))
    bus(p['result_base']+20,True,2 if fault else 1);attempt['terminal']=last('memory_write')
    site=firmware.document()['isr']['mret_addresses'][int(bool(fault)) if mret_site is None else mret_site]
    return_mret(contract,cpu,helper,rvfi_pc_rdata=site)
    address=p['slot_base']+128
    cpu._pending_instr=cpu._serve('instr',0,address,0,15)
    word=cpu._pending_instr[0]
    helper.step(cpu,irq=0,mutation=mutation(cpu,rvfi_valid=1,rvfi_order=3,
        rvfi_pc_rdata=address,rvfi_pc_wdata=address,rvfi_insn=word,rvfi_intr=0,
        rvfi_trap=0,return_serial=0,consume_instruction=True));drain()
    attempt['return']=add(issuer.events[0],'cpu')
    next_address=p['slot_base']+128 if fault else (p['slot_base']+256 if p['slot_count']>1 else p['park_address'])
    # Even the shorter error ISR runs the declared input pulse to fixed expiry.
    while cpu.local_ticks<irq_interval[0][1]:
        helper.step(cpu,irq=0);drain()
    def boundary_request(payload,irq):
        payload['pre_backend'].update(i_req_valid=1,i_req_write=0,i_req_addr=next_address,i_req_wdata=0,i_req_be=15)
    helper.step(cpu,irq=0,mutation=boundary_request);drain()
    request_key=cpu._request_evidence['instr']['transaction']
    attempt['next_fetch']=add(dict(kind='native_fetch_boundary',address=next_address,
        execution=cpu._execution,reset_epoch=cpu.reset_epoch,native_testcase_id=cpu._case_id,
        transaction=request_key,local_tick=cpu.local_ticks,
        boundary='error_current_island' if fault else 'next_prefix_or_park'),'cpu')
    runtime.admitted_attempts=(deepcopy(attempt),)
    return runtime,attempt
