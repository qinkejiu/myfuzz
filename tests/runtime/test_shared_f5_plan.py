from pathlib import Path
import pytest


@pytest.fixture(scope='module',params=[False,True])
def prepared(tmp_path_factory,request):
    from myfuzz.runtime.preparation import create_preparation
    root=Path(__file__).resolve().parents[2]
    config=root/'configs/scenarios/compiled-f1-f5-ibex-gpio-shared'
    context=create_preparation(base_dir=root,compose_path=config/'compose.json',
        capability_paths=(root/'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json',),
        supplement_path=config/'execution_supplement.json',
        generated_dir=tmp_path_factory.mktemp('shared-plan')/'generated',
        flow_ids=('F1','F2','F3','F4','F5') if request.param else ('F1','F3','F4','F5'))
    yield context
    context.close()


def test_shared_plan_derives_f5_without_fake_irq_bus_capability(prepared):
    from myfuzz.runtime.compiler import plan_bindings
    bindings=plan_bindings(prepared)
    cpu=next(b for b in bindings if b.role=='cpu')
    target=next(b for b in bindings if b.role=='target')
    assert set(cpu.flows)==set(prepared.flow_ids)
    assert target.flows==(('F2','F4') if 'F2' in prepared.flow_ids else ('F4',))
    assert target.semantic_kind=='gpio.register-bank.v1'
    assert target.template==('pulp.gpio.causal','1','pulp_gpio_causal_v1')


@pytest.fixture(scope='module')
def planning(prepared):
    from tests.runtime.test_plan_compiler import compile_from_context
    return compile_from_context(prepared)


def test_shared_actual_preparation_compiles_registered_gpio_and_f5(prepared,planning):
    assert any(s.adapter_id=='gpio.causal-storage.v1' for s in planning.selections)
    rows={p['flow_id']:p for p in planning.plan.document()['paths']}
    assert set(rows)==set(prepared.flow_ids)
    assert {b['role'] for b in rows['F5']['bindings']}=={'cpu'}
    assert {e['provider']['kind'] for e in rows['F5']['edges']}=={'physical_source','irq_delivery'}


def test_shared_actual_bound_plan_and_kernel_lower_all_declared_inputs(prepared,planning,tmp_path):
    from tests.runtime.test_plan_compiler import compile_from_context
    from tests.integration.test_shared_f5_runtime import world
    from myfuzz.scenario.gpio_register_version import GpioRegisterVersionAuthority
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from myfuzz.integration.compiled_f4_runtime_path import admit_compiled_f4_runtime_path
    from myfuzz.runtime.flows.memory import prepare_memory_paths
    from myfuzz.runtime.binding import bind_execution_plan
    from myfuzz.runtime.flows.mixed import MixedStorageKernel
    from myfuzz.runtime.generic_campaign import case_sequence_for_plan
    pin,runner=world(prepared,tmp_path)
    authority=GpioRegisterVersionAuthority(runner.sessions['peripheral'])
    inputs=prepared.compiled_inputs()
    f4=admit_compiled_f4_runtime_path(request=inputs['request'],compiled=inputs['compiled'])
    memory,bindings=prepare_memory_paths(request=inputs['request'],compiled=inputs['compiled'])
    paths=f4.prepared.runtime_paths+memory.runtime_paths+pin.prepared.runtime_paths
    session=ScenarioSession(ScenarioGenome('software','CPU_TO_IP',f4.runtime_path_id,
        tuple(runner.sessions),1024,()),runner)
    session.declare_instruction_slots('processor',0x10000,64)
    session.configure_runtime_paths(f4.prepared.graph,f4.prepared.contract,paths,
        source_ownership=inputs['ownership'],instruction_image_bindings=(f4.instruction_binding,)+bindings)
    prepared.attach_runtime(runner=runner,sessions=runner.sessions)
    admitted=session._runtime_prepared
    prepared.register_prepared_paths(prepared=admitted,runtime_paths=admitted.runtime_paths,graph=admitted.graph)
    bound=bind_execution_plan(planning.plan,preparation=prepared,sessions=runner.sessions,
        prepared_paths=admitted,runner=runner)
    try:
        kernel=MixedStorageKernel(flow_ids=prepared.flow_ids)
        context=kernel.prepare(bound,'mixed')
        cases=(('F1','13000000'),('F3','55000000'),('F4','0001000000'),('F5','0000000100000000'))
        if 'F2' in prepared.flow_ids:cases += (('F2','08100040'),)
        sequence=case_sequence_for_plan(scenario_id='shared',plan_document=planning.plan.document(),
            plan_sha256=planning.plan.identity_sha256,cases=cases)
        assert [kernel.lower(context,row).flow_id for row in sequence['cases']]==[flow for flow,_ in cases]
        assert authority.target is runner.sessions['peripheral']
    finally:
        bound.close()
