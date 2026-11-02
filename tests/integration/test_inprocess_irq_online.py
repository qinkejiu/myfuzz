from pathlib import Path
import json

from myfuzz.composition.component_profile import load_component_profile
from scripts.run_inprocess_irq import build_case, build_online_program


def test_online_program_polls_data_mailbox_and_keeps_trigger_offsets():
    root=Path(__file__).resolve().parents[2]
    config=json.loads((root/'configs/scenarios/inprocess-irq-pulp-timer-profile.json').read_text())
    cpu=load_component_profile(root/config['cpu_profile'])
    ip=load_component_profile(root/config['source_profile'])
    _,prefix=build_case(config,cpu,ip,boot=0x10080)
    program=build_online_program(prefix['firmware'],config)
    code=bytes.fromhex(program['images'][str(program['case_entry'])])
    words=[int.from_bytes(code[i:i+4],'little') for i in range(0,len(code),4)]
    assert program['mailbox'] >= program['case_entry']+len(code)
    assert program['mailbox']+4*(1+len(config['trigger_writes'])) <= config['image_end']
    assert any((word & 0x7f)==0x63 for word in words)  # CPU polls flag with branch
    stores=[word for word in words if (word & 0x7f)==0x23]
    assert len(stores)==1+len(config['trigger_writes'])  # flag clear + MMIO writes
    assert words[-1] & 0x7f == 0x6f  # branch back to the immutable polling code


def test_online_mailbox_is_bounded_and_does_not_overlap_result():
    import pytest
    root=Path(__file__).resolve().parents[2]
    config=json.loads((root/'configs/scenarios/inprocess-irq-pulp-timer-profile.json').read_text())
    cpu=load_component_profile(root/config['cpu_profile'])
    ip=load_component_profile(root/config['source_profile'])
    _,prefix=build_case(config,cpu,ip,boot=0x10080)
    firmware=dict(prefix['firmware'],image_end=prefix['firmware']['dynamic_start']+0x800)
    with pytest.raises(ValueError,match='mailbox'):
        build_online_program(firmware,config)
