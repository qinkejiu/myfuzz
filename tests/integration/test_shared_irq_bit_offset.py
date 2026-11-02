"""A real bit-slice CPU IRQ input binds at its port-local host bit.

Everything here is software-level: real plans/artifacts/sessions are admitted and
constructed, but no DUT process is started and no RTL is simulated. Expectations
are read from the pinned profile/request/config inputs (the declared
``bit_range``, the ABI/runtime export rows, the declared group declaration),
never from the code under test's own output.

Two coordinate systems stay separate:

* the DUT line (CV32E40P ``irq_i[11]``) is *documentary* evidence: the profile's
  ``bit_range``, the verified export row and the CPU IRQ contract's
  ``input_bit_offset``;
* host coordinates are *port-local*: the host field is the ABI input row, so the
  host offset is ``declared_bit - abi_bit_lo`` and is zero for a one-bit slice.
  A Wishbone-style CPU whose ABI row is the whole 32-bit vector keeps a real
  non-zero host offset.
"""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]

CPU_PROFILE = 'configs/cpus/cv32e40p_rvfi_local/component_profile.json'
CPU_REQUEST = 'configs/scenarios/compiled-f1-f6-cv32e40p-rvfi-gpio-dma-shared/requests/cpu.json'
IBEX_REQUEST = 'configs/scenarios/compiled-f6-ibex-wbdmac-storage/requests/cpu.json'
E20_REQUEST = 'configs/scenarios/compiled-f1-f6-cv32e20-gpio-dma-shared/requests/cpu.json'
GPIO_REQUEST = 'configs/scenarios/compiled-f4-obi-apb-ibex/requests/peripheral.json'
DMA_REQUEST = 'configs/scenarios/compiled-f6-ibex-wbdmac-storage/requests/dma.json'
F6_SUPPLEMENT = 'configs/scenarios/compiled-f1-f6-cv32e40p-rvfi-gpio-dma-shared/execution_supplement.json'
PIN = 8
# A real wide-vector IRQ host offset: a documented Wishbone CPU route declares
# bit 3 of its 32-bit `irq` input as the GPIO-driven line.
WIDE_VECTOR_OFFSET = 3


def _read(relative):
    return json.loads((ROOT / relative).read_text())


def declared_irq_port(profile_path=CPU_PROFILE):
    """The alias and inclusive DUT bit span the profile itself declares."""
    document = _read(profile_path)
    cpu = document['cpu']
    endpoints = [e for e in document['endpoints']
                 if e.get('endpoint_id') == cpu['irq_entry_endpoint']]
    assert len(endpoints) == 1
    fields = [f for f in endpoints[0]['fields'] if f.get('role') == cpu['irq_entry_role']]
    assert len(fields) == 1
    assert fields[0]['direction'] == 'input' and fields[0]['width'] == 1
    alias, = fields[0]['aliases']
    return alias, tuple(fields[0]['bit_range'])


def gpio_irq_declaration():
    return _read(F6_SUPPLEMENT)['request_supplements']['f6_execution']['gpio_irq']


def _artifact(request_relative, instance):
    """Admitted driver artifact for one real request; no process is created."""
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    request = load_local_harness_request(dict(_read(request_relative), instance_id=instance))
    plan = plan_local_harness(request, base_dir=ROOT)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan), verified, base_dir=ROOT)
    return plan, render_local_driver(runtime, base_dir=ROOT)


def cpu_irq_contract_registered():
    """True once the code-owned CV32E40P native IRQ adapter is registered."""
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract_for_profile)
    try:
        native_irq_receipt_contract_for_profile(load_component_profile(ROOT / CPU_PROFILE))
    except ValueError:
        return False
    return True


def _require_cpu_irq_contract():
    if not cpu_irq_contract_registered():
        pytest.skip('cv32e40p native IRQ receipt contract not registered yet')


def _host_offset(artifact):
    """Port-local host offset derived from the profile and the export row."""
    from myfuzz.integration.shared_f6_assembly import (
        _declared_field_span, verified_shared_cpu_irq_input)
    from myfuzz.local_harness.native_irq_receipt_contract import (
        verify_native_irq_receipt_artifact)
    profile = artifact.plan.profile
    wire = verify_native_irq_receipt_artifact(artifact, base_dir=ROOT)
    export = verified_shared_cpu_irq_input(artifact, wire)
    bit_lo, _ = _declared_field_span(artifact, endpoint_id=profile.cpu.irq_entry_endpoint,
        role=profile.cpu.irq_entry_role, direction='input', width=1)
    return export, bit_lo - export['bit_lo']


def test_real_cv32e40p_irq_input_export_is_the_declared_dut_bit_slice():
    from tests.local_harness.test_renderer import real_plan
    from myfuzz.local_harness import (render_local_harness, render_local_runtime,
        verify_local_source_lock)
    plan = real_plan(CPU_PROFILE, 'cpu')
    artifact = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    alias, (bit_lo, bit_hi) = declared_irq_port()
    assert (bit_lo, bit_hi) == (11, 11)

    exports = [e for e in artifact.runtime_document['physical_exports']
               if e['direction'] == 'input' and e['physical_port'] == alias]
    assert len(exports) == 1
    export, = exports
    assert (export['bit_lo'], export['bit_hi'], export['width']) == (bit_lo, bit_hi, 1)
    assert export['endpoint_id'] == plan.profile.cpu.irq_entry_endpoint
    assert export['role'] == plan.profile.cpu.irq_entry_role
    assert export['disposition'] == 'functional'

    # The host-facing port is the one-bit ABI slice, not the 32-bit core port:
    # the host input key is the ABI port name and the host field is one bit.
    ports = [r for r in artifact.structural.abi_document['ports']
             if r['physical_port'] == alias and r['direction'] == 'input']
    assert len(ports) == 1
    assert (ports[0]['bit_lo'], ports[0]['bit_hi'], ports[0]['width']) == (bit_lo, bit_hi, 1)
    runtime_ports = {row['name']: row for row in artifact.runtime_document['runtime_ports']}
    assert runtime_ports[export['runtime_name']]['direction'] == 'input'
    assert runtime_ports[export['runtime_name']]['width'] == 1
    fact = plan.facts.port(alias)
    assert (fact.direction, fact.width) == ('input', 32)

    _require_cpu_irq_contract()
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract, verify_native_irq_receipt_artifact)
    assert verify_native_irq_receipt_artifact(artifact, base_dir=ROOT) == export['runtime_name']
    # The DUT line stays documentary evidence in the registered contract.
    contract = native_irq_receipt_contract(artifact)
    assert contract['input_port'] == alias
    assert contract['input_bit_offset'] == bit_lo
    # Port-local host coordinate: declared bit minus the ABI row's bit_lo.
    assert bit_lo - export['bit_lo'] == 0


@pytest.fixture(scope='module')
def real_irq_world(tmp_path_factory):
    """Real admitted artifacts for the shared CPU/DMA/GPIO group; no DUT run."""
    _require_cpu_irq_contract()
    cache = tmp_path_factory.mktemp('shared-irq-bit-offset')
    _, cpu = _artifact(CPU_REQUEST, 'cpu')
    _, gpio = _artifact(GPIO_REQUEST, 'peripheral')
    _, dma = _artifact(DMA_REQUEST, 'dma')
    return SimpleNamespace(cache=cache, cpu=cpu, gpio=gpio, dma=dma,
        artifacts={'cpu': cpu, 'peripheral': gpio, 'dma': dma})


def _shared_irq_state(real_irq_world):
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    from myfuzz.integration.shared_f6_assembly import (
        shared_irq_group, shared_irq_ownership)
    from myfuzz.scenario.ownership import compile_ownership
    declaration = gpio_irq_declaration()
    contract = {'cpu': {'instance_id': 'cpu'}, 'dma': {'instance_id': 'dma'},
        'program_contract': {'gpio_irq': declaration}}
    group = shared_irq_group(contract, real_irq_world.artifacts, base_dir=ROOT)
    declared = _f6_runner_ownership(compile_ownership((), ()), cpu_id='cpu', dma_id='dma')
    ownership = shared_irq_ownership(declared, contract, real_irq_world.artifacts,
        base_dir=ROOT)
    return contract, declaration, group, declared, ownership


def test_cv32e40p_group_and_ownership_are_port_local(real_irq_world):
    _, declaration, group, _, ownership = _shared_irq_state(real_irq_world)
    alias, (dut_bit, _) = declared_irq_port()
    gpio_exports = [e for e in real_irq_world.gpio.runtime_document['physical_exports']
                    if e.get('role') == 'irq' and e.get('direction') == 'output']
    assert len(gpio_exports) == 1
    gpio_port = gpio_exports[0]['physical_port']

    # Behavioural host coordinate: the declared bit is bit 0 of the one-bit
    # ABI slice, so no offset is fabricated and no session shift is needed.
    assert group.group_id == declaration['group_id']
    assert (group.target_component, group.target_port) == ('cpu', alias)
    assert group.target_bit_offset == 0
    assert [(m.source_component, m.source_port, m.mode) for m in group.members] == [
        ('dma', 'irq', 'pulse'), (declaration['component'], gpio_port, 'pulse')]
    assert [b.target_bit_offset for b in group.member_bindings()] == [0, 0]

    document = ownership.document()
    assert document == {
        'fields': [{'component_id': 'cpu', 'port': alias, 'width': 1}],
        'owners': [{'component_id': 'cpu', 'port': alias, 'bit_offset': 0, 'width': 1,
                    'kind': 'bound', 'producer_ref': group.owner_ref}]}
    assert ownership.binding_producer('cpu', alias, 0, 1) == group.owner_ref
    assert ownership.irq_group_owner('cpu', alias, 0, 1) == group.group_id

    # The same facts are stable when recomputed, and the placeholder host
    # alias the F6 caller declares is replaced by the real physical port.
    _, _, again_group, _, again = _shared_irq_state(real_irq_world)
    assert again_group == group and again.document() == document
    assert ('cpu', 'irq') not in {(r['component_id'], r['port'])
        for r in document['fields']}

    # Documentary DUT coordinate: the real line is still the declared/verified
    # 11, in the profile, the verified export row, the group document and the
    # CPU contract. Only the mapping base is recorded, never a behaviour offset.
    export, host_offset = _host_offset(real_irq_world.cpu)
    assert (export['bit_lo'], export['bit_hi']) == (dut_bit, dut_bit) == (11, 11)
    assert host_offset == group.target_bit_offset == 0
    assert group.target_input_bit_lo == dut_bit
    assert group.document()['target_input_bit_lo'] == dut_bit
    assert group.document()['target_bit_offset'] == 0
    from myfuzz.local_harness.native_irq_receipt_contract import (
        native_irq_receipt_contract)
    contract = native_irq_receipt_contract(real_irq_world.cpu)
    assert contract['input_bit_offset'] == dut_bit
    # The recorded DUT base plus the host offset is exactly the named line.
    assert group.target_input_bit_lo + group.target_bit_offset == dut_bit
    assert contract['input_bit_offset'] == group.target_input_bit_lo


@pytest.mark.parametrize('request_path, alias', [
    (IBEX_REQUEST, 'irq_external_i'), (E20_REQUEST, 'irq_external_i')])
def test_bit_zero_cpus_keep_byte_identical_group_and_ownership(request_path, alias):
    """Ibex and CV32E20 declare a whole one-bit port; nothing may move."""
    from myfuzz.integration.compiled_f6 import _f6_runner_ownership
    from myfuzz.integration.shared_f6_assembly import (
        shared_irq_group, shared_irq_ownership)
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup
    from myfuzz.scenario.ownership import compile_ownership
    artifacts = {'cpu': _artifact(request_path, 'cpu')[1],
                 'peripheral': _artifact(GPIO_REQUEST, 'peripheral')[1]}
    contract = {'cpu': {'instance_id': 'cpu'}, 'dma': {'instance_id': 'dma'},
        'program_contract': {'gpio_irq': gpio_irq_declaration()}}
    group = shared_irq_group(contract, artifacts, base_dir=ROOT)
    assert (group.target_port, group.target_bit_offset) == (alias, 0)
    assert group.target_input_bit_lo == 0
    # No documentary DUT base is emitted, so the group document keeps exactly
    # the historical seven keys and its historical sha256.
    legacy = {'schema_version': 'host_irq_delivery_group.v1',
        'group_id': gpio_irq_declaration()['group_id'], 'target_component': 'cpu',
        'target_port': alias, 'members': [
            {'source_component': 'dma', 'source_port': 'irq', 'mode': 'pulse',
             'pulse_width_ticks': 16, 'source_bit_offset': 0},
            {'source_component': gpio_irq_declaration()['component'],
             'source_port': group.members[1].source_port, 'mode': 'pulse',
             'pulse_width_ticks': 4, 'source_bit_offset': 0}],
        'target_bit_offset': 0, 'operation': 'or'}
    document = group.document()
    assert set(document) == set(legacy)   # exactly the historical seven keys
    assert json.loads(json.dumps(document)) == legacy
    assert IrqDeliveryGroup.from_document(document) == group
    assert [b.target_bit_offset for b in group.member_bindings()] == [0, 0]
    ownership = shared_irq_ownership(
        _f6_runner_ownership(compile_ownership((), ()), cpu_id='cpu', dma_id='dma'),
        contract, artifacts, base_dir=ROOT)
    assert ownership.document() == {
        'fields': [{'component_id': 'cpu', 'port': alias, 'width': 1}],
        'owners': [{'component_id': 'cpu', 'port': alias, 'bit_offset': 0,
                    'width': 1, 'kind': 'bound', 'producer_ref': group.owner_ref}]}


@pytest.fixture(scope='module')
def cv32e40p_runtime_artifact():
    from tests.local_harness.test_renderer import real_plan
    from myfuzz.local_harness import (render_local_harness, render_local_runtime,
        verify_local_source_lock)
    plan = real_plan(CPU_PROFILE, 'cpu')
    artifact = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return plan, artifact


@pytest.mark.parametrize('mutation, reason', [
    ('ambiguous', 'verified-CPU-IRQ-export'),
    ('bit_zero', 'verified-CPU-IRQ-export'),
    ('wrong_role', 'verified-CPU-IRQ-export'),
    ('excludes_declared_bit', 'verified-CPU-IRQ-export'),
    ('no_abi_row', 'verified-CPU-IRQ-ABI'),
])
def test_selector_refuses_anything_but_the_single_declared_export(
        cv32e40p_runtime_artifact, mutation, reason):
    from myfuzz.integration.shared_f6_assembly import verified_shared_cpu_irq_input
    plan, artifact = cv32e40p_runtime_artifact
    alias, _ = declared_irq_port()
    wire, = [e['runtime_name'] for e in artifact.runtime_document['physical_exports']
             if e['direction'] == 'input' and e['physical_port'] == alias]
    exports = deepcopy(artifact.runtime_document['physical_exports'])
    structural = artifact.structural
    if mutation == 'ambiguous':
        exports.append(dict([e for e in exports if e['runtime_name'] == wire][0]))
    elif mutation == 'bit_zero':
        # A CPU whose interrupt really is a bit-slice must never accept a
        # bit-zero export in its place.
        for row in exports:
            if row['runtime_name'] == wire:
                row.update(bit_lo=0, bit_hi=0)
    elif mutation == 'wrong_role':
        for row in exports:
            if row['runtime_name'] == wire:
                row['role'] = 'custom'
    elif mutation == 'excludes_declared_bit':
        for row in exports:
            if row['runtime_name'] == wire:
                row.update(bit_lo=10, bit_hi=10)
    else:
        structural = SimpleNamespace(abi_document={'ports': []})
    candidate = SimpleNamespace(plan=plan, runtime_document={'physical_exports': exports},
        structural=structural)
    with pytest.raises(ValueError, match=reason):
        verified_shared_cpu_irq_input(candidate, wire)


def _shifted_gpio_trace(offset, target_port):
    """The existing offset-zero documented trace moved to a wide-vector bit."""
    from tests.scenario.test_gpio_irq_dependency_evidence import trace
    events = deepcopy(trace())
    for event in events:
        if event.get('target') == ['core', 'irq']:
            event['target'] = ['core', target_port]
        if 'target_bit_offset' in event:
            event['target_bit_offset'] = offset
    step = events[5]
    assert set(step['inputs']) == {'irq'}
    step['inputs'] = {target_port: 1 << offset}
    return events


def _gpio_consumer(**kwargs):
    from myfuzz.scenario.gpio_irq_dependency_evidence import GpioNativeIrqEvidenceConsumer
    target_port = kwargs.pop('target_port', 'irq')
    return GpioNativeIrqEvidenceConsumer(source_component='device', target_component='core',
        pin=3, source_port='interrupt', target_port=target_port,
        runtime_contract_sha256='a'*64, **kwargs)


def test_wide_vector_host_offset_is_declared_by_a_real_route():
    from myfuzz.scenario.picorv32_wb_two_gpio_example import (
        CPU_IRQ_CPU_ROUND1, pico_wb_bindings)
    assert CPU_IRQ_CPU_ROUND1 == WIDE_VECTOR_OFFSET
    assert any(b.target_port == 'irq' and b.target_bit_offset == WIDE_VECTOR_OFFSET
        for b in pico_wb_bindings())


def test_gpio_evidence_consumer_accepts_a_wide_vector_host_offset():
    consumer = _gpio_consumer(target_bit_offset=WIDE_VECTOR_OFFSET)
    for event in _shifted_gpio_trace(WIDE_VECTOR_OFFSET, 'irq'):
        consumer.consume(event)
    report = consumer.report()
    assert report['counts'] == {'irq_delivery':1, 'irq_acceptance':1,
        'cpu_retirement_serial':1}
    assert report['target_port'] == 'irq' and report['target_component'] == 'core'
    assert report['provider'] == 'native_gpio_ibex_irq.v1'
    assert report['reward_eligible'] is False and report['grants_prerequisites'] is False


def test_gpio_evidence_consumer_refuses_a_mismatched_target_bit():
    cases = (
        (_gpio_consumer(target_bit_offset=WIDE_VECTOR_OFFSET - 1),
         _shifted_gpio_trace(WIDE_VECTOR_OFFSET, 'irq')),
        (_gpio_consumer(target_bit_offset=WIDE_VECTOR_OFFSET),
         _shifted_gpio_trace(WIDE_VECTOR_OFFSET - 1, 'irq')),
        (_gpio_consumer(target_port='irq_i', target_bit_offset=WIDE_VECTOR_OFFSET),
         _shifted_gpio_trace(WIDE_VECTOR_OFFSET, 'irq')),
    )
    for consumer, events in cases:
        for event in events:
            consumer.consume(event)
        assert consumer.report()['counts'] == {'irq_delivery':0, 'irq_acceptance':0,
            'cpu_retirement_serial':0}
    with pytest.raises(ValueError, match='configuration'):
        _gpio_consumer(target_bit_offset=-1)


def test_gpio_evidence_consumer_default_offset_zero_is_unchanged():
    from tests.scenario.test_gpio_irq_dependency_evidence import trace
    consumer = _gpio_consumer()
    assert consumer.target_bit_offset == 0
    for event in trace():
        consumer.consume(event)
    report = consumer.report()
    assert report['counts'] == {'irq_delivery':1, 'irq_acceptance':1,
        'cpu_retirement_serial':1}
    assert report['target_port'] == 'irq'


def test_cv32e40p_shared_six_flow_preparation_keeps_the_port_local_target(
        tmp_path_factory):
    """The real E40 six-flow preparation reaches the explicit F5 group hop.

    The runtime path contract keeps DUT coordinates (the CPU IRQ node is
    ``irq_i`` bit 11); the installed group is port-local (bit 0). Both facts
    must survive one real preparation and its saved re-derivation.
    """
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.integration.compiled_f6_runtime_path import (
        admit_compiled_f6_runtime_path)
    from myfuzz.integration.shared_f6_assembly import shared_irq_group
    from myfuzz.integration.shared_slot_paths import validate_shared_flow_admission
    from myfuzz.local_harness.build import host_source_discovery_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.scenario.runtime_path_contract import RuntimePathContract
    scenario = ROOT / 'configs/scenarios/compiled-f1-f6-cv32e40p-rvfi-gpio-dma-shared'
    descriptor = load_descriptor(scenario / 'generic_scenario.json', base_dir=ROOT)
    alias, (dut_bit, _) = declared_irq_port()
    with (elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True),
          execution_validation_scope()):
        preparation = create_preparation(base_dir=ROOT, compose_path=descriptor.compose,
            capability_paths=descriptor.capability, supplement_path=descriptor.supplement,
            generated_dir=tmp_path_factory.mktemp('e40-six') / 'generated',
            flow_ids=descriptor.flow_ids)
        try:
            artifacts = dict(preparation.artifacts)
            inputs = preparation.compiled_inputs()
            admission = admit_compiled_f6_runtime_path(artifacts=artifacts,
                compiled_inputs=inputs, base_dir=ROOT)
            contract = admission['execution_contract']
            assert set(admission['shared_flow_paths']) == {'F1','F2','F3','F4','F5','F6'}
            group = shared_irq_group(contract, artifacts, base_dir=ROOT)
            assert (group.target_component, group.target_port,
                    group.target_bit_offset) == ('cpu', alias, 0)
            assert group.target_input_bit_lo == dut_bit == 11
            f5 = admission['shared_flow_paths']['F5']
            assert f5['irq_group']['target_bit_offset'] == 0
            assert f5['irq_group']['target_input_bit_lo'] == dut_bit
            assert f5['cpu_component'] == 'cpu' and f5['pin']['bit_offset'] == PIN
            # The contract still records the real DUT line, not the host bit.
            runtime_contract = RuntimePathContract.from_document(
                admission['runtime_contract'])
            assert ('cpu', alias, dut_bit) in {(node.component, node.port,
                node.bit_offset) for node in runtime_contract.nodes if node.port}
            provider = contract['irq']['native_take_provider']
            assert (provider['input_port'], provider['input_bit_offset']) == (
                alias, dut_bit)
            # The saved re-derivation (same JSON group document) agrees.
            validate_shared_flow_admission(admission)
        finally:
            preparation.close()


@pytest.fixture(scope='module')
def unstarted_irq_runner(real_irq_world):
    """A real CPU/DMA/GPIO runner with the real delivery group installed."""
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.local_harness.wishbone_dma_scenario_session import (
        GeneratedWishboneDmaScenarioSession)
    from myfuzz.scenario.ledger import TransactionLedger
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.memory_service import MemoryService
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.runner import ScenarioRunner
    _, _, group, _, ownership = _shared_irq_state(real_irq_world)
    alias, _ = declared_irq_port()
    memory = PersistentMemory(regions=(MemoryRegion('shared_ram', 0x10000, 0x20000),),
        initialization_seed=0, max_initialized_bytes=0x20000)
    service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True,
        commit_stream_capacity=256)
    cpu = GeneratedCve2Session(real_irq_world.cpu, base_dir=ROOT,
        cache_dir=real_irq_world.cache, memory=memory, router=DataflowRouter(()),
        defer_mmio=True, native_irq_receipts=True, irq_input_port=alias)
    dma = GeneratedWishboneDmaScenarioSession(real_irq_world.dma, base_dir=ROOT,
        cache_dir=real_irq_world.cache, memory_service=service, source_component='dma',
        max_control_edges=32, max_events=10000)
    gpio = GeneratedPulpGpioSession(real_irq_world.gpio, base_dir=ROOT,
        cache_dir=real_irq_world.cache)
    sessions = {'cpu': cpu, 'dma': dma, 'peripheral': gpio}
    runner = ScenarioRunner(sessions=sessions, ownership=ownership,
        bindings=group.member_bindings(), irq_delivery_groups=(group,))
    return SimpleNamespace(group=group, runner=runner, sessions=sessions,
        ownership=ownership)


def _configured_runner(unstarted_irq_runner):
    """Fresh runner plus the once-only GPIO IRQ provider configuration."""
    from myfuzz.scenario.runner import ScenarioRunner
    world = unstarted_irq_runner
    contract_sha = 'b' * 64
    runner = ScenarioRunner(sessions=dict(world.sessions), ownership=world.ownership,
        bindings=world.group.member_bindings(), irq_delivery_groups=(world.group,))
    # Only the two provenance *owners* are doubled here; every port, binding,
    # ownership and session fact the search uses is the real one.
    runner._provenance = SimpleNamespace(
        edge_index=SimpleNamespace(document=lambda: {'contract_sha256': contract_sha}))
    runner._gpio_consumption_tracker = SimpleNamespace()
    return runner, contract_sha


def test_runner_group_search_uses_the_real_binding_offset(unstarted_irq_runner):
    """The GPIO provider search may not require a zero target bit."""
    alias, _ = declared_irq_port()
    group = unstarted_irq_runner.group
    runner, contract_sha = _configured_runner(unstarted_irq_runner)
    runner.configure_gpio_irq_dependency_evidence(source_component='peripheral',
        target_component='cpu', pin=PIN, runtime_contract_sha256=contract_sha)
    configuration = runner._gpio_irq_dependency_configuration
    assert configuration['target_port'] == alias
    assert configuration['target_bit_offset'] == group.target_bit_offset == 0
    assert configuration['irq_delivery_group']['target_bit_offset'] == 0
    consumer = runner._gpio_irq_dependency_consumer
    assert (consumer.target_port, consumer.target_bit_offset) == (alias, 0)
    assert consumer.source_port == group.members[1].source_port
    assert consumer.width == group.members[1].pulse_width_ticks == 4


def test_runner_group_search_refuses_a_missing_physical_binding(unstarted_irq_runner,
        monkeypatch):
    runner, contract_sha = _configured_runner(unstarted_irq_runner)
    monkeypatch.setattr(runner, 'bindings', ())
    with pytest.raises(ValueError, match='exact physical binding'):
        runner.configure_gpio_irq_dependency_evidence(source_component='peripheral',
            target_component='cpu', pin=PIN, runtime_contract_sha256=contract_sha)
    assert runner._gpio_irq_dependency_consumer is None


def test_runner_group_delivery_sets_exactly_the_declared_vector_bit(unstarted_irq_runner):
    """The runner's own group search/OR helpers place the value on that bit."""
    alias, _ = declared_irq_port()
    group = unstarted_irq_runner.group
    runner, _ = _configured_runner(unstarted_irq_runner)
    _prime_group(runner, group, active=True)
    inputs = runner._effective_inputs('cpu')
    assert inputs == {alias: 1}
    _prime_group(runner, group, active=False)
    assert runner._effective_inputs('cpu') == {alias: 0}


def _prime_group(runner, group, *, active, cpu_tick=0):
    """Observe real member levels and drive the DMA member's native pulse."""
    state = runner._irq_group_states[group.group_id]
    for member, binding in zip(group.members, group.member_bindings()):
        epoch = getattr(runner.sessions[member.source_component], 'reset_epoch', None)
        state.observe(binding, 0, dict(event_id=1, component=member.source_component,
            reset_epoch=epoch, local_tick=cpu_tick, phase='post'))
    pulse = runner._irq_pulses[group.member_bindings()[0]]
    pulse.reset(cpu_tick=cpu_tick)
    if active:
        pulse.observe_source(1, source_tick=cpu_tick, cpu_tick=cpu_tick)
    return pulse


def test_wide_vector_group_delivery_sets_the_declared_host_bit(monkeypatch):
    """Port-local offsets stay meaningful for a real 32-bit irq input vector."""
    from myfuzz.scenario.irq import IrqPulseDelivery
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.runner import Binding, ScenarioRunner
    group = IrqDeliveryGroup('shared-external', 'core', 'irq', (
        IrqDeliveryMember('dma', 'irq', pulse_width_ticks=16),
        IrqDeliveryMember('gpio', 'interrupt', pulse_width_ticks=4)),
        target_bit_offset=WIDE_VECTOR_OFFSET)
    owners = compile_ownership((InputField('core', 'irq', 32),), (
        InputOwner('core', 'irq', 0, WIDE_VECTOR_OFFSET, 'fixed', 'constant_zero'),
        InputOwner('core', 'irq', WIDE_VECTOR_OFFSET, 1, 'bound', group.owner_ref),
        InputOwner('core', 'irq', WIDE_VECTOR_OFFSET + 1, 32 - WIDE_VECTOR_OFFSET - 1,
                   'fixed', 'constant_zero')))
    sessions = {name: SimpleNamespace(reset_epoch=0)
        for name in ('core', 'dma', 'gpio')}
    monkeypatch.setattr('myfuzz.scenario.irq_delivery_group.verify_group_sessions',
        lambda local_group, local_sessions: {})
    runner = ScenarioRunner(sessions=sessions, ownership=owners,
        bindings=group.member_bindings(), irq_delivery_groups=(group,))
    pulse = _prime_group(runner, group, active=True)
    assert pulse.input_at(1) == 1
    assert runner._effective_inputs('core') == {'irq': 1 << WIDE_VECTOR_OFFSET}
    assert runner.irq_group_for(group.member_bindings()[0]) is group
    assert runner.ownership.irq_group_owner('core', 'irq',
        WIDE_VECTOR_OFFSET, 1) == group.group_id


def test_compiled_f6_derives_the_binding_instead_of_guessing_zero(unstarted_irq_runner):
    from myfuzz.integration.compiled_f6 import _f6_actual_irq_binding
    alias, _ = declared_irq_port()
    group = unstarted_irq_runner.group
    runner = unstarted_irq_runner.runner
    binding = _f6_actual_irq_binding(runner, dma_id='dma', cpu_id='cpu', cpu_port=alias)
    assert binding == group.member_bindings()[0]
    assert binding.target_bit_offset == 0
    assert runner._irq_pulses[binding].width_ticks == 16
    assert runner.irq_group_for(binding) is group

    # A runner without the matching binding/pulse refuses instead of falling
    # back to an offset-zero binding.
    with pytest.raises(ValueError, match='binding-unavailable'):
        _f6_actual_irq_binding(runner, dma_id='dma', cpu_id='cpu', cpu_port='irq')
    pulse_free = SimpleNamespace(bindings=(binding,), _irq_pulses={},
        irq_group_for=lambda local: None)
    with pytest.raises(ValueError, match='pulse-unavailable'):
        _f6_actual_irq_binding(pulse_free, dma_id='dma', cpu_id='cpu', cpu_port=alias)
    foreign = SimpleNamespace(bindings=(binding, binding), _irq_pulses={binding: object()},
        irq_group_for=lambda local: None)
    with pytest.raises(ValueError, match='binding-ambiguous'):
        _f6_actual_irq_binding(foreign, dma_id='dma', cpu_id='cpu', cpu_port=alias)


def test_compiled_f6_derives_a_wide_vector_binding_offset():
    """A Wishbone-style CPU keeps its real non-zero host offset."""
    from myfuzz.integration.compiled_f6 import _f6_actual_irq_binding
    from myfuzz.scenario.runner import Binding
    wide = Binding('dma', 'irq', 'core', 'irq', 1, target_bit_offset=WIDE_VECTOR_OFFSET)
    stub = SimpleNamespace(bindings=(wide,), _irq_pulses={wide: object()},
        irq_group_for=lambda local: None)
    assert _f6_actual_irq_binding(stub, dma_id='dma', cpu_id='core',
        cpu_port='irq') == wide


def test_compiled_f6_offset_zero_binding_is_byte_identical():
    """An offset-zero CPU still derives exactly the old hardcoded binding."""
    from myfuzz.integration.compiled_f6 import _f6_actual_irq_binding
    from myfuzz.scenario.runner import Binding
    zero = Binding('dma', 'irq', 'cpu', 'irq_external_i', 1)
    stub = SimpleNamespace(bindings=(zero,), _irq_pulses={zero: object()},
        irq_group_for=lambda local: None)
    assert _f6_actual_irq_binding(stub, dma_id='dma', cpu_id='cpu',
        cpu_port='irq_external_i') == zero


def test_irq_delivery_group_accepts_only_a_real_bit_offset():
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    members = (IrqDeliveryMember('dma', 'irq', pulse_width_ticks=16),
               IrqDeliveryMember('gpio', 'interrupt', pulse_width_ticks=4))
    for offset in (0, WIDE_VECTOR_OFFSET, 11):
        group = IrqDeliveryGroup('g', 'cpu', 'irq', members, target_bit_offset=offset)
        assert IrqDeliveryGroup.from_document(group.document()) == group
        assert [b.target_bit_offset for b in group.member_bindings()] == [offset, offset]
    for bad in (-1, 64, True, 11.0, '11'):
        with pytest.raises(ValueError, match='IRQ delivery group'):
            IrqDeliveryGroup('g', 'cpu', 'irq', members, target_bit_offset=bad)
    # The documentary DUT base is optional and omitted while it is zero; a
    # sliced target records it and round-trips it verbatim.
    legacy = set(IrqDeliveryGroup('g', 'cpu', 'irq', members).document())
    assert 'target_input_bit_lo' not in legacy
    sliced = IrqDeliveryGroup('g', 'cpu', 'irq', members, target_input_bit_lo=11)
    assert sliced.document()['target_input_bit_lo'] == 11
    assert IrqDeliveryGroup.from_document(sliced.document()) == sliced
    for bad in (-1, True, 11.0, '11'):
        with pytest.raises(ValueError, match='IRQ delivery group'):
            IrqDeliveryGroup('g', 'cpu', 'irq', members, target_input_bit_lo=bad)


def _saved_group_world(*, member_epoch, target_epoch=0):
    """One documented saved group frame plus its raw member samples."""
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember
    group = IrqDeliveryGroup('shared-external', 'cpu', 'irq_i', (
        IrqDeliveryMember('dma', 'irq', pulse_width_ticks=16),
        IrqDeliveryMember('peripheral', 'interrupt', pulse_width_ticks=4)))
    raw = {
        1: dict(event_id=1, kind='local_tick_sample', component='dma',
                reset_epoch=member_epoch, local_tick=1, phase='post',
                outputs={'irq': 1, 'physical': {'dma_irq_wire': 1}}),
        2: dict(event_id=2, kind='local_tick_sample', component='peripheral',
                reset_epoch=member_epoch, local_tick=1, phase='post',
                outputs={'interrupt': 0, 'physical': {'gpio_irq_wire': 0}}),
    }

    def ref(row, wire):
        return dict(event_id=row['event_id'], component=row['component'],
            reset_epoch=member_epoch, local_tick=1, phase='post', runtime_name=wire)

    sample = dict(event_id=5, kind='cpu_external_irq_sample', component='cpu',
        reset_epoch=target_epoch, local_tick=2, producer_event_id=4,
        receipt_id={'execution': 'native', 'sequence': 1},
        expected_input=1, actual_pre_input=1, actual_post_input=1)
    frame = dict(kind='irq_group_delivery', event_id=7, group_id=group.group_id,
        group_sha256=group.identity_sha256, target_component='cpu',
        target_port=group.target_port, target_epoch=target_epoch, cpu_tick=2, value=1,
        native_sample_event_id=5, cpu_step_event_id=4,
        receipt_id={'execution': 'native', 'sequence': 1},
        members=[dict(source_id='dma.irq', mode='pulse', value=1,
                      native_source=ref(raw[1], 'dma_irq_wire')),
                 dict(source_id='peripheral.interrupt', mode='pulse', value=0,
                      native_source=ref(raw[2], 'gpio_irq_wire'))],
        active_sources=['dma.irq'], unique_source='dma.irq', attribution_status='unique')
    events = [frame, dict(kind='pulse_start', event_id=3, source=['dma', 'irq'],
        target=['cpu', group.target_port], start_cpu_tick=2, end_cpu_tick_exclusive=18)]
    runner = SimpleNamespace(get=lambda event_id: raw.get(event_id))
    return group, sample, events, runner


def test_saved_frame_requires_member_samples_from_the_frame_epoch():
    from myfuzz.integration.saved_irq_group import frame_for_sample
    group, sample, events, runner = _saved_group_world(member_epoch=0)
    frame = frame_for_sample(group, sample, events, runner)
    assert frame['unique_source'] == 'dma.irq'
    # An old-epoch member sample may not authenticate a fresh-epoch frame even
    # though its own reference agrees with it.
    group, sample, events, runner = _saved_group_world(member_epoch=1, target_epoch=0)
    events[0]['members'][1]['native_source']['reset_epoch'] = 1
    with pytest.raises(ValueError, match='epoch differs from the frame target epoch'):
        frame_for_sample(group, sample, events, runner)
    # A mismatched raw sample/reference pair keeps its own precise refusal.
    group, sample, events, runner = _saved_group_world(member_epoch=0)
    events[0]['members'][1]['native_source']['reset_epoch'] = 3
    with pytest.raises(ValueError, match='member native sample/epoch mismatch'):
        frame_for_sample(group, sample, events, runner)


def test_saved_group_rederivation_reads_the_bound_target_offset():
    """Saved groups rebuild from the raw binding rows, not from bit zero."""
    from hashlib import sha256
    from myfuzz.integration.saved_irq_group import rebuild_group
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryGroup, IrqDeliveryMember

    def build(offset, dut_base=0):
        members = (IrqDeliveryMember('dma', 'irq', pulse_width_ticks=16),
                   IrqDeliveryMember('peripheral', 'interrupt', pulse_width_ticks=4))
        group = IrqDeliveryGroup('shared-external', 'cpu', 'irq', members,
            target_bit_offset=offset, target_input_bit_lo=dut_base)
        bindings = [{'source_component': b.source_component, 'source_port': b.source_port,
                     'target_component': b.target_component, 'target_port': b.target_port,
                     'width': b.width, 'source_bit_offset': b.source_bit_offset,
                     'target_bit_offset': b.target_bit_offset}
                    for b in group.member_bindings()]
        owners = [{'component_id': 'cpu', 'port': 'irq', 'bit_offset': bit,
                   'width': 1, 'kind': 'bound' if bit == offset else 'fixed',
                   'producer_ref': group.owner_ref if bit == offset else 'constant_zero'}
                  for bit in range(32)]
        topology = {'components': ['cpu', 'dma', 'peripheral'], 'bindings': bindings,
            'ownership_inputs': [{'component': 'cpu', 'port': 'irq', 'owners': owners}],
            'routers': [], 'resources': [],
            'irq_delivery_groups': [group.document()]}
        digest = sha256(json.dumps(topology, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        contract = {'cpu': {'instance_id': 'cpu'}, 'dma': {'instance_id': 'dma'},
            'irq': {'native_take_provider': {'input_port': 'irq', 'input_width': 1,
                                             'input_bit_offset': dut_base}},
            'program_contract': {'gpio_irq': gpio_irq_declaration()}}
        saved = {'runtime_topology': topology,
                 'topology_binding': {'topology_sha256': digest}}
        return contract, saved, group, topology

    def reseal(topology):
        digest = sha256(json.dumps(topology, sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        return {'runtime_topology': topology,
                'topology_binding': {'topology_sha256': digest}}

    for offset, dut_base in ((WIDE_VECTOR_OFFSET, 0), (0, 0), (0, 11)):
        contract, saved, group, topology = build(offset, dut_base)
        assert rebuild_group(contract, saved, 'irq') == group

        # The raw rows are the authority: a group document that disagrees with
        # the bound target bit is refused although every member row matches.
        forged = deepcopy(topology)
        forged['irq_delivery_groups'][0]['target_bit_offset'] = offset + 1
        with pytest.raises(ValueError, match='membership/mode'):
            rebuild_group(contract, reseal(forged), 'irq')
        # A missing bound owner at the declared bit is refused.
        forged = deepcopy(topology)
        forged['ownership_inputs'][0]['owners'][offset].update(kind='fixed')
        with pytest.raises(ValueError, match='owner'):
            rebuild_group(contract, reseal(forged), 'irq')
        # A missing member row is refused (the offset cannot be read from it).
        forged = deepcopy(topology)
        forged['bindings'] = forged['bindings'][1:]
        with pytest.raises(ValueError, match='bound member'):
            rebuild_group(contract, reseal(forged), 'irq')
        # The documentary DUT base is derived from the pinned CPU IRQ contract,
        # so a group document that relabels it is refused.
        if dut_base:
            assert group.document()['target_input_bit_lo'] == dut_base
            forged = deepcopy(topology)
            forged['irq_delivery_groups'][0]['target_input_bit_lo'] = dut_base + 1
            with pytest.raises(ValueError, match='membership/mode'):
                rebuild_group(contract, reseal(forged), 'irq')
        else:
            assert 'target_input_bit_lo' not in group.document()
