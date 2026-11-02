from copy import deepcopy
import pytest
from myfuzz.integration.shared_irq_dispatcher import build_common_irq_firmware
from tests.integration.test_compiled_f6_firmware import contract,model
from myfuzz.integration.compiled_f6_firmware import build_f6_firmware


def declaration():
    return dict(schema_version='shared_gpio_IRQ_dispatch.v1',component='peripheral',pin=8,group_id='shared-external',
        gpio_base=0x40001000,dma_handler_address=0x102a0,gpio_handler_address=0x10320,
        scratch_address=0x26000,result_address=0x26040,type_offset=28,type_value=2<<16,
        status_offset=36,status_ack='read_clear_unless_new_trigger',source_contract_digest='a'*64)


@pytest.mark.parametrize('status,target',[(0,'dma_handler_address'),(0x100,'gpio_handler_address')])
def test_fixed_dispatch_uses_real_status_and_preserves_interrupted_registers(status,target):
    c=contract();old=build_f6_firmware(c);d=declaration()
    shared=build_common_irq_firmware(entry_address=c['program_contract']['isr_address'],
        dma_isr_bytes=old.initial_images[c['program_contract']['isr_address']],declaration=d)
    regs=list(range(32));regs[31]=0x1234
    pc,after,ram,stores,loads,returns,csrs=model({shared['address']:shared['data']},shared['address'],
        registers=regs,ram={d['gpio_base']+36:status},csr_values={0x340:d['scratch_address']},stop=(d[target],))
    assert pc==d[target] and after==regs and csrs[0x340]==d['scratch_address']
    assert d['gpio_base']+36 in loads
    if status:assert ram[d['result_address']+4]==status
    assert len(shared['document']['stages']['dma']['mret_addresses'])==2
    assert len(shared['document']['stages']['gpio']['mret_addresses'])==1


def test_optional_firmware_retains_default_DMA_bytes_and_explicit_stage_MRET_scopes():
    c=contract();original=build_f6_firmware(c)
    c['program_contract']['gpio_irq']=declaration();combined=build_f6_firmware(c);doc=combined.document()
    stage=doc['irq_dispatch']['stages']['dma'];offset=stage['address']-c['program_contract']['isr_address']
    assert combined.initial_images[c['program_contract']['isr_address']][offset:offset+stage['length']]==original.initial_images[c['program_contract']['isr_address']]
    assert doc['isr']['mret_addresses']==stage['mret_addresses']
    assert doc['irq_dispatch']['stages']['gpio']['mret_addresses'][0] not in doc['isr']['mret_addresses']
    assert build_f6_firmware(contract()).initial_images==original.initial_images


def test_dispatcher_refuses_overlapping_code_or_scratch():
    old=build_f6_firmware(contract());data=old.initial_images[0x1022c]
    for bad in ({'gpio_handler_address':0x102a4},{'scratch_address':0x10230}):
        with pytest.raises(ValueError):build_common_irq_firmware(entry_address=0x1022c,dma_isr_bytes=data,declaration=declaration()|bad)
