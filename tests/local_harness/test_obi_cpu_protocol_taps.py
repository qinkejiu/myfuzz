"""Actual CPU-side OBI taps, separate from the adapter beat backend."""
import copy
import json
import os
from dataclasses import replace
from pathlib import Path
import pytest
from myfuzz.local_harness import (load_local_harness_request,plan_local_harness,
    render_local_harness,render_local_runtime,render_local_driver,verify_local_source_lock)
from myfuzz.local_harness.native_physical_observation import verify_cpu_obi_protocol_traces
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.scenario.memory import MemoryRegion,PersistentMemory
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_evidence import IpProtocolEvidenceConsumer

ROOT=Path(__file__).resolve().parents[2]


def artifact():
    req=load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/ibex_obi_local/component_profile.json',instance_id='cpu',
        reset_assert_ticks=12,reset_release_ticks=8,max_wait_cycles=32))
    plan=plan_local_harness(req,base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)


def test_passive_taps_are_bound_before_adapter_and_not_beat_exports():
    a=artifact();assert verify_cpu_obi_protocol_traces(a)
    traces=a.runtime_document['base_protocol_traces']
    assert traces['schema_version']=='ip_protocol_trace_set.v1'
    assert len(traces['traces'])==2
    backend={r['name'] for r in a.runtime_document['backend_ports']}
    for p in a.runtime_document['protocol_tap_ports']:
        assert p['name'] not in backend
        assert p['source_wire'].startswith('link_')
        assert f"assign {p['name']} = {p['source_wire']};" in a.runtime_sv
    assert '"protocol_taps"' in a.cpp_text
    corrupted=copy.deepcopy(a.runtime_document)
    corrupted['base_protocol_traces']['traces'][0]['signals']['req']='i_req_valid'
    with pytest.raises(ValueError):
        verify_cpu_obi_protocol_traces(replace(a,runtime_document=corrupted))


def project(a,samples,*,tamper=False):
    configurations={}
    for index,trace in enumerate(a.runtime_document['base_protocol_traces']['traces']):
        configurations['endpoint-'+str(index)]=dict(component_id=a.plan.profile.component_id,
            instance_id='cpu',protocol_trace=trace)
    normalizers={k:IpProtocolEventNormalizer(**c) for k,c in configurations.items()}
    checkers={k:IpProtocolChecker(**c) for k,c in configurations.items()}
    proof=IpProtocolEvidenceConsumer(configurations,runtime_contract_sha256=a.runtime_document['artifact_digest'],max_event_gap=4096)
    journal=[];violations=[];corrupted=False
    for sample in samples:
        for alias in configurations:
            raw=dict(event_id=len(journal)+1,kind='local_tick_sample',component=alias,
                local_tick=sample['local_tick'],phase='pre',reset_epoch=0,
                observation_schema_version='ip_raw_observation.v1',
                outputs={'backend':copy.deepcopy(sample['pre']['protocol_taps'])})
            journal.append(raw);proof.consume(raw)
            violations.extend(checkers[alias].consume_local_tick(raw,reset_epoch=0))
            for row in normalizers[alias].consume_local_tick(raw,reset_epoch=0):
                row['kind']=row['event_type'];row['event_id']=len(journal)+1
                if tamper and not corrupted and row['event_type']=='transaction_response':
                    row['payload']['value'] ^= 1;corrupted=True
                journal.append(row);proof.consume(row)
    return dict(report=proof.report(),journal=journal,violations=violations,configurations=configurations)


def exercise(a,cache):
    memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),
        initialization_seed=0,max_initialized_bytes=0x30000)
    words=(0x000200b7,0x10008093,0x03500113,0x0020a023,0x0000a183,0x00118213,0x0040a223,0x0000006f)
    memory.preload(0x10080,b''.join(w.to_bytes(4,'little') for w in words))
    class UnusedMmioGuard:
        def read_register(self,*args,**kwargs):
            raise AssertionError('RAM-only test attempted MMIO')
        def write_register(self,*args,**kwargs):
            raise AssertionError('RAM-only test attempted MMIO')
    router=DataflowRouter((DeviceWindow('unused-mmio-guard',0x40000000,4096,UnusedMmioGuard()),))
    cpu=GeneratedCve2Session(a,base_dir=ROOT,cache_dir=cache,memory=memory,router=router,
        command_timeout_seconds=120)
    samples=[]
    try:
        cpu.begin_case('ibex-raw-obi')
        for _ in range(100):
            cpu.step_local({'irq':0});samples.extend(copy.deepcopy(cpu.last_samples))
        assert memory.read(0x20100,4,transaction_id='verify0').value==53
        assert memory.read(0x20104,4,transaction_id='verify1').value==54
        assert not router.acceptances and not router.deliveries
        result=project(a,samples)
        assert not result['violations']
        assert not result['report']['diagnostics']
        assert result['report']['counts']['verified']>=11
        assert sum(c['evidence']['source'].endswith(':processor.data:request')
                   for c in result['report']['certificates'])==3
        tampered=project(a,samples,tamper=True)
        assert tampered['report']['diagnostics']['projection_mismatch']>=1
        assert tampered['report']['counts']['verified']<result['report']['counts']['verified']
        return dict(identity=cpu.identity_document(),execution=cpu._execution,
            samples=samples,projection=result,tampered_report=tampered['report'])
    finally:cpu.end_case()


@pytest.mark.skipif(os.environ.get('MYFUZZ_OBI_TAPS_REAL')!='1',reason='explicit real Ibex RTL gate')
def test_real_ibex_two_endpoint_raw_protocol_certificates_and_tamper(tmp_path):
    a=artifact();cache=Path(os.environ.get('MYFUZZ_OBI_TAPS_CACHE',str(tmp_path/'cache')))
    first=exercise(a,cache);fresh=exercise(a,cache)
    assert first['execution']!=fresh['execution']
    assert first['identity']==fresh['identity'] and first['samples']==fresh['samples']
    assert first['projection']==fresh['projection']
    if 'MYFUZZ_OBI_TAPS_EVIDENCE' in os.environ:
        out=Path(os.environ['MYFUZZ_OBI_TAPS_EVIDENCE']);out.mkdir(parents=True,exist_ok=True)
        for name,value in [('first',first),('fresh',fresh),('artifact',a.runtime_document)]:
            (out/(name+'.json')).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def test_normal_build_admission_rejects_rehashed_tap_metadata():
    from myfuzz.local_harness.build import local_build_identity,LocalHarnessBuildError
    from myfuzz.local_harness.renderer import _sha
    a=artifact()
    forged=copy.deepcopy(a.runtime_document)
    forged['base_protocol_traces']['traces'][0]['signals']['req']='i_req_valid'
    forged['artifact_digest']=_sha({k:v for k,v in forged.items() if k!='artifact_digest'})
    with pytest.raises(LocalHarnessBuildError,match='artifact-runtime-identity-mismatch'):
        local_build_identity(replace(a,runtime_document=forged),base_dir=ROOT)
