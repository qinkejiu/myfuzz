"""CPU phase dispatch selects target/DMA handling without proving IRQ source."""
from myfuzz.integration.shared_irq_dispatcher import build_declared_phase_irq_firmware
from myfuzz.integration.declared_irq_consumption import firmware_code
from tests.integration.test_compiled_f6_firmware import model


def test_phase_dispatch_and_declared_isr_operation_metadata():
    d={'schema_version':'shared_declared_irq_contract.v1','phase_address':0x25000,
       'scratch_address':0x25100,'result_address':0x25200,'dma_handler_address':0x102a0,
       'target_handler_address':0x10380,'target_window':{'base':0x40003000,'size':4096},
       'status_offsets':[4,8],'clear_writes':[[12,1]]}
    dma=(0x30200073).to_bytes(4,'little')*2
    built=build_declared_phase_irq_firmware(entry_address=0x1022c,dma_isr_bytes=dma,declaration=d)
    doc=built['document']; fw=doc['declared_firmware']; code=firmware_code(fw)
    assert [(pc,code[pc]) for pc,_ in fw['retirement_path']]==[tuple(row) for row in fw['retirement_path']]
    assert [op['kind'] for op in fw['memory_operations']]==['read','write','read','write','write']
    images={built['address']:built['data']}
    memory={0x25000:1,0x40003004:0x22,0x40003008:0x33,'mepc':0x30000}
    _,_,ram,stores,loads,returns,_=model(images,0x1022c,ram=memory,
        csr_values={0x340:0x25100},stop=(0x30000,))
    assert ram[0x25200]==0x22 and ram[0x25204]==0x33 and ram[0x4000300c]==0x33
    assert returns==[fw['mret_pc']]
    assert doc['source_attribution']=='unknown' and doc['phase_semantics']=='cpu_written_dispatch_intent_only'
    memory[0x25000]=0
    _,_,_,_,_,returns,_=model(images,0x1022c,ram=memory,
        csr_values={0x340:0x25100},stop=(0x30000,))
    assert returns==[0x102a0]
