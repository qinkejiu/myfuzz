"""Shared F5 maps physical vector bits without inventing CPU IRQ evidence."""
from types import SimpleNamespace
import pytest
from myfuzz.integration.shared_f5_runtime import shared_f5_irq_host_offset, shared_f5_ownership_document


def test_vector_bit_is_mapped_in_cpu_port_coordinates():
    artifact=SimpleNamespace(runtime_document={'physical_exports':[{'physical_port':'irq',
        'direction':'input','width':32,'bit_lo':0,'bit_hi':31}]})
    assert shared_f5_irq_host_offset(artifact,port='irq',dut_offset=3)==3
    with pytest.raises(ValueError):shared_f5_irq_host_offset(artifact,port='irq',dut_offset=32)


def test_irq_owner_rewrites_one_line_and_keeps_fixed_other_bits():
    document={'fields':[{'component_id':'cpu','port':'irq','width':32}], 'owners':[
        {'component_id':'cpu','port':'irq','bit_offset':0,'width':3,'kind':'fixed','producer_ref':'inactive'},
        {'component_id':'cpu','port':'irq','bit_offset':3,'width':1,'kind':'bound','producer_ref':'F5.ip_irq'},
        {'component_id':'cpu','port':'irq','bit_offset':4,'width':28,'kind':'fixed','producer_ref':'inactive'}]}
    actual=shared_f5_ownership_document(document,cpu_id='cpu',port='irq',host_offset=3,
        expected_producer_ref='F5.ip_irq',producer_ref='gpio.irq')
    assert actual['owners'][1]['producer_ref']=='gpio.irq'
    assert actual['owners'][0]==document['owners'][0] and actual['owners'][2]==document['owners'][2]
    assert document['owners'][1]['producer_ref']=='F5.ip_irq'


def test_custom_dispatcher_keeps_real_q_register_abi_and_unknown_lineage():
    from myfuzz.integration.shared_irq_dispatcher import build_custom_irq_dispatcher
    dispatch=build_custom_irq_dispatcher(address=0x100,routes=((3,0x400),(4,0x500)))
    words=[int.from_bytes(bytes.fromhex(dispatch['data_hex'])[i:i+4],'little')
           for i in range(0,len(bytes.fromhex(dispatch['data_hex'])),4)]
    assert words[0] & 0xfe00707f == 0x0200200b  # setq
    assert words[2] & 0xfe00707f == 0x0000400b  # getq
    assert 0x0400000b in words
    assert dispatch['source_attribution']=='unknown'
    assert dispatch['simultaneous_pending']=='unknown'
    with pytest.raises(ValueError):
        build_custom_irq_dispatcher(address=0x100,routes=((3,0x400),(3,0x500)))


def test_shared_f6_custom_cpu_allocates_real_session_and_distinct_irq_lines(tmp_path):
    from pathlib import Path
    from myfuzz.integration.shared_f6_assembly import build_f6_custom_irq_cpu
    from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
    from myfuzz.scenario.router import DataflowRouter
    from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE
    root=Path(__file__).resolve().parents[2]
    art=artifact(PROFILE,'cpu_irq')
    memory=PersistentMemory(regions=(MemoryRegion('ram',0,8192),),
        initialization_seed=0,max_initialized_bytes=8192)
    shared=build_f6_custom_irq_cpu(artifact=art,base_dir=root,cache_dir=tmp_path,
        memory=memory,router=DataflowRouter(()),irq_sources=(('gpio','irq',3),('dma','irq',4)))
    assert [b.target_bit_offset for b in shared.bindings]==[3,4]
    assert shared.ownership.binding_producer('cpu_irq','irq',3,1)=='gpio.irq'
    assert shared.ownership.binding_producer('cpu_irq','irq',4,1)=='dma.irq'
    assert shared.cpu.memory is memory and shared.cpu._custom_irq_contract is not None
    assert shared.contract['retirement']=='unknown' and shared.contract['f5_f6_certificate']=='not_granted'
    with pytest.raises(ValueError,match='source-declaration'):
        build_f6_custom_irq_cpu(artifact=art,base_dir=root,cache_dir=tmp_path,
            memory=memory,router=DataflowRouter(()),irq_sources=(('gpio','irq',3),('dma','irq',3)))
