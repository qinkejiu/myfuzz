"""One protocol-selected CPU session can drive MMIO and RAM flow records."""
import json
import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from myfuzz.integration.compiled_mmio import CompiledMmioRuntime
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.runtime.generic_campaign import load_descriptor, select_case_records
from myfuzz.runtime.preparation import create_preparation
from scripts.generate_mmio_scenario import generate_scenario

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT/'configs/scenarios/mmio-profile-examples/spi-picorv32-wb-compact.json'


def descriptor(path):
    generated=generate_scenario(json.loads(BASE.read_text()),base_dir=ROOT,
                                output=path.parent/'scenario')
    doc = json.loads(generated.read_text())
    doc['flow_ids'] = ['F1','F2','F3','F4']
    doc['executors'] = {name:'compiled_mmio' for name in doc['flow_ids']}
    doc['f1_records'] = ['03200000']
    doc['f3_records'] = ['55000000']
    path.write_text(json.dumps(doc))
    return load_descriptor(path, base_dir=ROOT)


def test_mixed_profile_accepts_ram_and_mmio_cases():
    with TemporaryDirectory(prefix='mmio-memory-',dir=ROOT/'runs') as directory:
        desc=descriptor(Path(directory)/'descriptor.json')
        cases=['F3:55000000','F1:03200000','F4:55000000','F2:08100040']
        assert select_case_records(desc,flow='mixed',records=cases)==tuple(tuple(row.split(':')) for row in cases)


def test_generator_opt_in_emits_shared_ram_and_mmio_sequence():
    with TemporaryDirectory(prefix='mmio-memory-',dir=ROOT/'runs') as directory:
        declaration=json.loads(BASE.read_text()); declaration['memory_flows']=True
        path=generate_scenario(declaration,base_dir=ROOT,output=Path(directory)/'scenario')
        desc=load_descriptor(path,base_dir=ROOT)
        records=json.loads((path.parent/'acceptance_sequence.json').read_text())
        assert desc.flow_ids==('F1','F2','F3','F4')
        assert records[:2]==['F3:55000000','F1:03200000']
        assert len(select_case_records(desc,flow='mixed',records=records))==6


def test_same_preparation_binds_wishbone_ram_and_mmio_without_irq():
    with TemporaryDirectory(prefix='mmio-memory-',dir=ROOT/'runs') as directory:
        folder=Path(directory);desc=descriptor(folder/'descriptor.json')
        prep=create_preparation(base_dir=ROOT,compose_path=desc.compose,
            capability_paths=(desc.capability,),supplement_path=desc.supplement,
            generated_dir=folder/'generated',flow_ids=desc.flow_ids)
        try:
            runtime=CompiledMmioRuntime(artifacts=prep.artifacts,compiled_inputs=prep.compiled_inputs(),
                base_dir=ROOT,cache_dir=folder/'cache',run_id='wb-memory-profile',
                max_cases=4,defer_begin=True,mixed_flows=True,memory_flows=True)
            cpu=runtime.runner.sessions[runtime.cpu_id]
            assert type(cpu) is GeneratedWishboneCpuSession
            assert cpu.memory_commit_receipts_enabled and cpu.memory_readback_receipts_enabled
            assert set(runtime.memory_bindings)=={'F1','F3'}
            assert set(runtime.paths)=={'F2','F4'}
            assert not hasattr(cpu,'_native_irq_contract')
        finally:
            prep.close()


@pytest.mark.parametrize('config,protocol',[
    ('spi-cvw-ahb.json','ahb-lite'),('spi-picorv32-axi.json','axi4-lite')])
def test_unified_cpu_profiles_bind_ram_and_mmio_in_same_runtime(config,protocol):
    with TemporaryDirectory(prefix='mmio-unified-memory-',dir=ROOT/'runs') as directory:
        folder=Path(directory)
        declaration=json.loads((BASE.parent/config).read_text());declaration['memory_flows']=True
        desc=load_descriptor(generate_scenario(declaration,base_dir=ROOT,output=folder/'scenario'),base_dir=ROOT)
        prep=create_preparation(base_dir=ROOT,compose_path=desc.compose,
            capability_paths=(desc.capability,),supplement_path=desc.supplement,
            generated_dir=folder/'generated',flow_ids=desc.flow_ids)
        try:
            runtime=CompiledMmioRuntime(artifacts=prep.artifacts,compiled_inputs=prep.compiled_inputs(),
                base_dir=ROOT,cache_dir=folder/'cache',run_id='unified-memory-profile',
                max_cases=4,defer_begin=True,mixed_flows=True,memory_flows=True)
            assert runtime.cpu_adapter.protocol==protocol and runtime.cpu_adapter.channel_model=='unified'
            assert set(runtime.memory_bindings)=={'F1','F3'} and set(runtime.paths)=={'F2','F4'}
            assert runtime.runner._memory_dependency_consumer is None
            assert all(session.process is None for session in runtime.runner.sessions.values())
        finally:
            prep.close()
