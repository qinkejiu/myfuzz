"""Actual AHB artifact declaration only; no SHA calculation or native launch."""
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
CONFIG=ROOT/'configs/peripherals/sha_declared_irq/smoke.json'


def test_SHA_declared_software_trigger_uses_existing_fullword_AHB_target(tmp_path):
    from myfuzz.local_harness import load_local_harness_request,plan_local_harness,render_local_harness,render_local_runtime,verify_local_source_lock
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
    from myfuzz.local_harness.declared_irq_output import declared_irq_runtime_mapping
    config=json.loads(CONFIG.read_text())
    assert (config['source_adapter'],config['source_port'],config['source_bit_offset'])==('declared-output.v1','error_intr',0)
    assert config['trigger_writes']==[[0x800,1],[0x804,1],[0x81c,1]]
    request=load_local_harness_request(json.loads((ROOT/config['source_request']).read_text()))
    plan=plan_local_harness(request,base_dir=ROOT)
    assert plan.profile.component_id=='caliptra_sha256'
    assert plan.profile.address.window_size==4096
    artifact=render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)
    assert artifact.runtime_document['kind']=='ahb_lite_register_observe'
    assert len(artifact.runtime_document['clock_schedule']['resets'])==2
    session=GeneratedAhbLiteRegisterSession(artifact,base_dir=ROOT,cache_dir=tmp_path)
    mapping=declared_irq_runtime_mapping(session,physical_port=config['source_port'],source_bit_offset=0)
    assert mapping['source_width']==1 and mapping['transport_only'] is True
    assert mapping['cause']==mapping['internal_version']==mapping['case_origin']=='unknown'
    assert not mapping['reward_eligible'] and not mapping['grants_prerequisites']
    assert session.process is None


def test_SHA_program_materializes_all_large_byte_addresses_without_signed_SW_wrap():
    from scripts.run_timer_irq_smoke import timer_program
    from scripts.run_cv32e20_irq_smoke import fixed_program
    config=json.loads(CONFIG.read_text());assert config['cpu_profile']=='configs/cpus/cv32e20/component_profile.json'
    program=timer_program(0x10000,config['active_base'],trigger_writes=config['trigger_writes'],window_size=4096)
    prefix=bytes.fromhex(fixed_program(0x10000)['images'][str(0x10000)])[:-4]
    code=bytes.fromhex(program['images'][str(0x10000)]);assert code.startswith(prefix)
    registers=[0]*32;stores=[]
    for offset in range(len(prefix),len(code)-4,4):
        word=int.from_bytes(code[offset:offset+4],'little');rd=word>>7&31;rs=word>>15&31
        if word&127==0x37:registers[rd]=word&0xfffff000
        elif word&127==0x13:
            imm=word>>20;imm=imm-4096 if imm&0x800 else imm
            registers[rd]=(registers[rs]+imm)&0xffffffff
        elif word&127==0x23:
            assert word>>12&7==2
            imm=(word>>25<<5)|(word>>7&31);imm=imm-4096 if imm&0x800 else imm
            stores.append(((registers[rs]+imm)&0xffffffff,registers[word>>20&31]))
        else:raise AssertionError('unexpected IRQ trigger opcode')
    assert stores==[(0x40001800,1),(0x40001804,1),(0x4000181c,1)]
    assert program['images'][str(program['handler'])]==fixed_program(0x10000)['images'][str(program['handler'])]
