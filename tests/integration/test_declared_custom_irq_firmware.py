"""Shared declared target operations use CPU-specific IRQ ABI envelopes."""
import pytest

from myfuzz.integration.declared_irq_consumption import build_declared_irq_firmware
from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
from tests.local_harness.test_wishbone_cpu_irq import artifact, PROFILE, ROOT


def contract():
    return verify_custom_irq_artifact(artifact(PROFILE, 'cpu_irq'), base_dir=ROOT)


def build(abi):
    return build_declared_irq_firmware(image_start=0, image_end=0x2000, first_fetch=0,
        target_base=0x40000000, status_offsets=(4, 8), result_address=0xc40,
        clear_writes=((12, 1),), irq_abi=abi, irq_bit=3)


def test_custom_abi_uses_same_target_operations_without_machine_csrs():
    fw = build(contract())
    assert fw['irq_abi'] == 'picorv32_custom0'
    assert [r['kind'] for r in fw['memory_operations']] == ['read', 'write', 'read', 'write', 'write']
    assert fw['return_word'] == 0x0400000b
    words = [int.from_bytes(bytes.fromhex(s['data_hex'])[i:i+4], 'little')
             for s in fw['segments'] for i in range(0,len(bytes.fromhex(s['data_hex'])),4)]
    assert not any(word & 0x7f == 0x73 for word in words)
    assert any(word & 0xfe00707f == 0x0600600b for word in words)  # maskirq
    assert any(s['name'] == 'vector_custom' and s['address'] == 16 for s in fw['segments'])
    assert fw['retirement_authority'] == 'unknown'


def test_custom_abi_rejects_internal_irq_bits():
    with pytest.raises(ValueError, match='custom-IRQ-line'):
        build_declared_irq_firmware(image_start=0,image_end=0x2000,first_fetch=0,
            target_base=0x40000000,status_offsets=(4,),result_address=0xc40,
            irq_abi=contract(),irq_bit=2)


def test_profile_selected_factory_binds_source_and_irq_contract():
    from myfuzz.integration.declared_irq_consumption import build_profile_custom_irq_firmware
    cpu = artifact(PROFILE, 'cpu_irq')
    fw = build_profile_custom_irq_firmware(cpu, base_dir=ROOT, image_start=0,
        image_end=0x2000, first_fetch=0, target_base=0x40000000,
        status_offsets=(0,), result_address=0xc40, irq_bit=3)
    assert fw['irq_abi'] == 'picorv32_custom0'
    assert fw['source_attribution'] == 'unknown'


def test_profile_firmware_uses_shared_dispatcher_and_checks_overlap():
    from myfuzz.integration.declared_irq_consumption import build_profile_custom_irq_firmware
    cpu=artifact(PROFILE,'cpu_irq')
    args=dict(base_dir=ROOT,image_start=0,image_end=0x2000,first_fetch=0,
              target_base=0x40000000,status_offsets=(0,),result_address=0xc40,irq_bit=3)
    fw=build_profile_custom_irq_firmware(cpu,dispatcher_address=0x100,**args)
    assert fw['custom_dispatcher']['routes']==[{'irq_bit':3,'handler_address':fw['handler']}]
    assert fw['entry_pcs']==[16,0x100,fw['handler']]
    with pytest.raises(ValueError,match='dispatcher-overlap'):
        build_profile_custom_irq_firmware(cpu,dispatcher_address=0x400,**args)


def test_profile_custom_firmware_supports_distinct_interrupt_handlers():
    from myfuzz.integration.declared_irq_consumption import build_profile_custom_irq_firmware
    cpu=artifact(PROFILE,'cpu_irq')
    fw=build_profile_custom_irq_firmware(cpu,base_dir=ROOT,image_start=0,image_end=0x2000,
        first_fetch=0,target_base=0x40000000,status_offsets=(0,),result_address=0xc40,
        irq_bit=3,dispatcher_address=0x100,extra_irq_routes=((4,0x800),))
    assert fw['irq_bits']==[3,4]
    assert fw['custom_dispatcher']['routes']==[{'irq_bit':3,'handler_address':0x400},
                                                 {'irq_bit':4,'handler_address':0x800}]
    assert fw['custom_dispatcher']['simultaneous_pending']=='unknown'
