"""The partial E40 observer changes only CPU configuration, not I2C semantics."""
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
OLD=ROOT/'configs/scenarios/compiled-f2-f4-obi-apb-i2c-cv32e40p'
NEW=ROOT/'configs/scenarios/compiled-f2-f4-obi-apb-i2c-cv32e40p-rvfi'


def test_E40_partial_RVFI_configuration_reuses_every_IP_contract():
    from myfuzz.runtime.generic_campaign import load_descriptor
    old=load_descriptor(OLD/'generic_scenario.json',base_dir=ROOT)
    new=load_descriptor(NEW/'generic_scenario.json',base_dir=ROOT)
    assert new.capability==old.capability and new.supplement==old.supplement
    assert new.flow_ids==old.flow_ids and new.executors==old.executors
    read=lambda path:json.loads(path.read_text())
    assert read(NEW/'compose.json')==read(OLD/'compose.json')
    before,after=read(OLD/'requests/processor.json'),read(NEW/'requests/processor.json')
    assert after.pop('profile_path')=='configs/cpus/cv32e40p_rvfi_local/component_profile.json'
    before.pop('profile_path');assert after==before
