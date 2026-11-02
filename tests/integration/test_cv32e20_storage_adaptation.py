"""Actual CPU-profile/adapter preparation; no native process is started."""
from pathlib import Path
from contextlib import closing
import pytest

ROOT=Path(__file__).resolve().parents[2]

@pytest.mark.parametrize('ip',['spi','timer'])
def test_cv32e20_uses_common_obi_storage_executor(tmp_path,ip):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.compiled_execution_projection import assess_compiled_f2_support,assess_compiled_f4_support
    from myfuzz.integration.compiled_f4 import _cpu_traces
    descriptor=load_descriptor(ROOT/f'configs/scenarios/compiled-f4-obi-apb-{ip}-cv32e20/generic_scenario.json',base_dir=ROOT)
    assert descriptor.flow_ids==('F2','F4')
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True),execution_validation_scope():
        with closing(create_preparation(base_dir=ROOT,compose_path=descriptor.compose,capability_paths=(descriptor.capability,),
                supplement_path=descriptor.supplement,generated_dir=tmp_path/'generated',flow_ids=descriptor.flow_ids)) as preparation:
            inputs=preparation.compiled_inputs();artifacts=dict(preparation.artifacts)
            cpu=artifacts['processor']
            assert cpu.plan.profile.component_id=='cv32e20'
            assert cpu.runtime_document['kind']=='obi_cpu'
            for assess in (assess_compiled_f2_support,assess_compiled_f4_support):
                support=assess(artifacts=artifacts,compiled_inputs=inputs,base_dir=ROOT)
                assert support['execution_supported']==1,support
            path=next(row for row in inputs['compiled']['paths'] if row['flow_id']=='F4')
            image=next(row for row in path['sources'] if row['kind']=='instruction_image')
            stream=next(row for row in path['sources'] if row['kind']=='cpu_mmio_stream')
            assert set(_cpu_traces(cpu,image,stream))=={'instr','data'}
