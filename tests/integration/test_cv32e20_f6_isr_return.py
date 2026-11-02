"""Real E20 artifact/provider with synthetic parsed receipts, never RTL execution."""
from copy import deepcopy
from pathlib import Path
from hashlib import sha256
from unittest.mock import patch
import pytest
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.native_irq_receipt_contract import native_irq_receipt_contract
from myfuzz.scenario.memory import PersistentMemory,MemoryRegion
from myfuzz.scenario.router import DataflowRouter,DeviceWindow
from tests.local_harness.test_cpu_session import Target,NAMES
from tests.integration import test_compiled_f6_isr_return as original
ROOT=Path(__file__).resolve().parents[2]


class ActualE20ParsedReceipts:
    def step(self,cpu,*,irq=1,taken=0,masked=0,irq_valid=0,mutation=None):
        def command(op,values):
            physical={r['runtime_name']:('0'*r['hex_digits'] if r['width']>64 else 0)
                for r in cpu._artifact_document['physical_exports']}
            physical[cpu._irq_runtime_name]=values[0]
            physical.update(probe_irq_taken_pre=taken,probe_irq_masked_pre=masked)
            post=deepcopy(physical)
            backend=dict.fromkeys(NAMES,0)
            backend.update(zip(('i_req_ready','i_rsp_valid','i_rsp_rdata','i_rsp_error',
                'd_req_ready','d_rsp_valid','d_rsp_rdata','d_rsp_error'),values[1:]))
            tick=cpu.local_ticks-cpu._tick_base+1;sequence=cpu._sequence+1
            payload=dict(kind='obi_cpu',pre_backend=backend,observations=dict(backend=backend,physical=post),
                samples=[dict(local_tick=tick,pre=dict(backend=backend,physical=physical),
                    post=dict(backend=backend,physical=post))],rdata=0,error=0)
            if mutation:mutation(payload,cpu._irq_runtime_name)
            receipt=DriverReceipt('result',cpu._execution,sequence,tick-1,tick,1,payload)
            cpu._sequence=sequence;cpu.local_ticks=cpu._tick_base+tick
            return receipt
        with patch.object(cpu,'command',side_effect=command):return cpu.step_local({'irq':irq})


@pytest.fixture(scope='module')
def actual_inputs():
    from tests.local_harness.test_cv32e20_native_irq_session import artifact as actual_artifact
    from tests.integration.test_compiled_f6_contract import source_inputs,f6
    from myfuzz.integration.compiled_f6_firmware import build_f6_firmware
    from myfuzz.scenario.native_f6_isr_return import _canonical
    _,compiled,_=source_inputs();contract=deepcopy(f6(compiled)['execution_contract'])
    artifact=actual_artifact.__wrapped__()
    provider=native_irq_receipt_contract(artifact)
    contract['cpu'].update(profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        source_verification_sha256=sha256(_canonical(artifact.runtime_document['source_verification']).encode()).hexdigest(),
        native_irq_provider=provider)
    contract['irq']['native_take_provider']=deepcopy(provider)
    contract['program_contract'].update(boot_address=0x10000,initial_image=[],initial_image_sha256=None)
    program=build_f6_firmware(contract)
    contract['program_contract'].update(initial_image=list(program.initial_segment_manifest),initial_image_sha256=program.manifest_sha256)
    return contract,artifact


@pytest.fixture
def setup(actual_inputs,tmp_path,monkeypatch):
    monkeypatch.setattr('myfuzz.local_harness.session.local_build_identity',lambda *a,**k:{'software_test_boundary':True})
    contract,artifact=actual_inputs
    cpu=GeneratedCve2Session(artifact,base_dir=ROOT,cache_dir=tmp_path,
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,0x30000),),initialization_seed=3,max_initialized_bytes=0x30000),
        router=DataflowRouter((DeviceWindow('target',0x40000000,0x1000,Target()),)),native_irq_receipts=True)
    cpu._case_id='stream';cpu._execution='a'*32
    return deepcopy(contract),cpu,ActualE20ParsedReceipts()


def test_actual_E20_native_take_entry_MRET_and_versioned_successor_are_required(setup):
    contract,cpu,helper,issuer=original.install(setup)
    original.take_and_enter(contract,cpu,helper)
    original.return_and_resume(contract,cpu,helper)
    event,=issuer.events
    assert event['take_irq_serial_observation']['schema_version']=='cpu_irq_serial_observation.v1'
    assert event['irq_serial_observation']['retirement']['value']==0
    assert event['successor_pc_rdata']==0x11080
    taken=next(e for e in cpu.cpu_events if e.get('kind')=='cpu_external_irq_taken')
    assert taken['observation_contract']==native_irq_receipt_contract(cpu.artifact)
    assert not any(r['physical_port']=='rvfi_ext_debug_mode' for r in cpu._artifact_document['physical_exports'])


@pytest.mark.parametrize('change',[dict(return_serial=0),dict(rvfi_ext_nmi=1),dict(response_word=0x93)])
def test_E20_zero_entry_lineage_NMI_and_wrong_actual_resume_bytes_refuse(setup,change):
    contract,cpu,helper,issuer=original.install(setup)
    if 'return_serial' in change:
        with pytest.raises(ValueError):original.take_and_enter_one_receipt(contract,cpu,helper,**change)
    else:
        original.take_and_enter(contract,cpu,helper)
        original.return_mret(contract,cpu,helper)
        with pytest.raises(ValueError):original.resume(cpu,helper,**change)
    assert issuer.events==()
