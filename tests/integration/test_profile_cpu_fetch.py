import json
from pathlib import Path
import pytest

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.integration.profile_cpu_fetch import profile_axil_fetch_observation,profile_fetch_granule

ROOT=Path(__file__).resolve().parents[2]
PROFILE=ROOT/'configs/cpus/picorv32_axi/component_profile.json'


def test_axil_fetch_requires_explicit_source_backed_declaration():
    document=json.loads(PROFILE.read_text());profile=load_component_profile(document)
    fetch=profile_axil_fetch_observation(profile,base_dir=ROOT)
    assert fetch['role']=='arprot' and fetch['bit']==2
    document['evidence'].pop('axi4_lite_fetch_observation')
    assert profile_axil_fetch_observation(load_component_profile(document),base_dir=ROOT) is None


def test_source_backed_fetch_rejects_mismatched_bytes_and_invalid_granule():
    document=json.loads(PROFILE.read_text())
    declaration=document['evidence']['axi4_lite_fetch_observation']
    declaration['source_files']['picorv32.v']='0'*64
    with pytest.raises(ValueError,match='CPU-fetch-source-mismatch'):
        profile_axil_fetch_observation(load_component_profile(document),base_dir=ROOT)
    declaration['source_files']['picorv32.v']='0836050971b3c6cdd28ac3b1e5719a67fb645161912bef1e472e63995ceb0622'
    document['evidence']['instruction_fetch_granule']={'schema_version':'cpu_fetch_granule.v1',
        'bytes':8,'source_files':declaration['source_files']}
    assert profile_fetch_granule(load_component_profile(document),base_dir=ROOT)==8
    document['evidence']['instruction_fetch_granule']['bytes']=12
    with pytest.raises(ValueError,match='granule-declaration-invalid'):
        profile_fetch_granule(load_component_profile(document),base_dir=ROOT)


def test_axi_trace_never_invents_fetch_identity_without_profile_declaration():
    from myfuzz.local_harness.runtime_renderer import _expose_cpu_axil_trace,_AXI_LITE
    wires={role:'wire_'+role for role in _AXI_LITE};ports=[];statements=[];taps=[];traces=[]
    _expose_cpu_axil_trace('cpu.memory','clk',wires,ports,statements,taps,traces)
    assert 'fetch_observation' not in traces[0]
    declared=profile_axil_fetch_observation(load_component_profile(PROFILE),base_dir=ROOT)
    traces=[]
    _expose_cpu_axil_trace('cpu.memory','clk',wires,[],[],[],traces,fetch_observation=declared)
    assert traces[0]['fetch_observation']==declared
