"""A third APB IP uses protocol admission with no storage source whitelist."""
from pathlib import Path
from contextlib import closing
import pytest
ROOT=Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('configuration',['compiled-f2-f4-obi-apb-i2c-ibex','compiled-f2-f4-wb-apb-i2c-picorv32','compiled-f2-f4-ahb-apb-i2c-cvw'])
def test_actual_i2c_preparation_admits_mmio_plan_without_storage_probe(tmp_path,configuration):
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.runtime.compiler import plan_bindings,requirement_for_binding,compile_execution_plan
    from myfuzz.runtime.admission import verify_component
    from myfuzz.runtime.registry import select_adapter
    descriptor=load_descriptor(ROOT/f'configs/scenarios/{configuration}/generic_scenario.json',base_dir=ROOT)
    with elaboration_mode_scope('direct'),host_source_discovery_scope(reuse_nested=True):
        with closing(create_preparation(base_dir=ROOT,compose_path=descriptor.compose,
            capability_paths=(descriptor.capability,),supplement_path=descriptor.supplement,
            generated_dir=tmp_path/'generated',flow_ids=descriptor.flow_ids)) as context:
            bindings=plan_bindings(context);components={};selections=[];requirements=[]
            for binding in bindings:
                component=components.setdefault(binding.instance_id,None)
                if component is None:
                    component=verify_component(context.artifact(binding.instance_id),preparation=context,base_dir=ROOT)
                    components[binding.instance_id]=component
                requirement=requirement_for_binding(component,binding)
                selections.append(select_adapter(component,requirement,preparation=context));requirements.append(requirement)
            plan=compile_execution_plan(context,components=tuple(components.values()),selections=tuple(selections),requirements=tuple(requirements))
            target=components['peripheral'].document()
            assert target['endpoints'][0]['semantic_kind']=='mmio.register-bank.v1'
            assert {p['flow_id'] for p in plan.document()['paths']}=={'F2','F4'}
            assert context.artifact('peripheral').runtime_document.get('storage_observation') is None
            from myfuzz.integration.compiled_mmio import CompiledMmioRuntime
            from myfuzz.runtime.binding import bind_execution_plan
            runtime=CompiledMmioRuntime(artifacts=context.artifacts,compiled_inputs=context.compiled_inputs(),
                base_dir=ROOT,cache_dir=tmp_path/'cache',run_id='MMIO-prestart',defer_begin=True)
            assert all(local.process is None for local in runtime.runner.sessions.values())
            context.attach_runtime(runner=runtime.runner,sessions=dict(runtime.runner.sessions))
            prepared=runtime.session._runtime_prepared
            context.register_prepared_paths(prepared=prepared,runtime_paths=prepared.runtime_paths,graph=prepared.graph)
            bound=bind_execution_plan(plan,preparation=context,sessions=dict(runtime.runner.sessions),prepared_paths=prepared,runner=runtime.runner)
            bound.assert_current()
            from myfuzz.runtime.flows.mixed import MixedStorageKernel
            prepared_kernel=MixedStorageKernel().prepare(bound,None)
            assert set(prepared_kernel.flows)=={'F2','F4'}
            assert runtime.authority is None
            assert runtime.cpu_adapter.protocol==('ahb-lite' if 'cvw' in configuration else 'wishbone' if 'picorv32' in configuration else 'obi')
            if runtime.cpu_adapter.protocol=='ahb-lite':
                cpu=runtime.runner.sessions[runtime.cpu_id]
                assert cpu.defer_mmio is True and cpu.hold_declared_instructions is True
                assert runtime.cpu_adapter.instruction_granule==64
            from myfuzz.integration.generated_register_writer import declare_writer
            stream=runtime.streams['F4']
            declaration=declare_writer(context.compiled_inputs()['request'],context.compiled_inputs()['compiled'],
                source_id=stream['source_id'],value=0x55,result_address=runtime.result)
            code=bytes.fromhex(declaration['code_hex'])
            assert declaration['candidate']['value']==0x55 and declaration['candidate']['byte_enable']==15
            assert int.from_bytes(code[16:20],'little') & 0x7f == 0x23  # SW before any read
            assert int.from_bytes(code[20:24],'little') & 0x7f == 0x03  # readback, not RMW


