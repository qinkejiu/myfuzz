from dataclasses import replace

from myfuzz.local_harness.wishbone_dma_fields import (DMA_SELECTED_CONTROL_SHAPE,
    DMA_SELECTED_MASTER_SHAPE, DMA_SELECTED_STEP_PORTS, selected_dma_edge_contract)
from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
from myfuzz.local_harness.wire import DriverReceipt
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from test_wishbone_dma_transport import artifact, ROOT


def test_selected_contract_exposes_physical_byte_lanes():
    assert DMA_SELECTED_CONTROL_SHAPE['sel'] == ('input', 4)
    assert DMA_SELECTED_MASTER_SHAPE['sel'] == ('output', 4)
    assert 'swb_sel' in DMA_SELECTED_STEP_PORTS
    doc = selected_dma_edge_contract()
    assert doc['master_byte_enable_signal'] == 'mwb_sel'
    assert 'master_fixed_byte_enable' not in doc


def test_selected_session_forwards_real_master_sel(artifact, tmp_path, monkeypatch):
    runtime = dict(artifact.runtime_document)
    runtime['dma_edge_contract'] = selected_dma_edge_contract()
    session = GeneratedWishboneDmaSession(replace(artifact, runtime_document=runtime),
        base_dir=ROOT, cache_dir=tmp_path,
        memory=PersistentMemory(initialization_seed=0, max_initialized_bytes=16,
            regions=(MemoryRegion('ram', 0x1000, 16),)))
    session._execution = 'software-contract'; session._case_id = 'selected'
    calls = []
    def command(op, fields):
        calls.append((op, fields))
        return DriverReceipt('result', 'software-contract', 1, 0, 1, 1,
            payload={'pre_backend': {'mwb_cyc': 1, 'mwb_stb': 1, 'mwb_we': 1,
                'mwb_adr': 0x400, 'mwb_dat_w': 0xaabbccdd, 'mwb_sel': 5},
                'observations': {'backend': {'mwb_stb': 1}}})
    monkeypatch.setattr(session, 'command', command)
    session.step_local(cyc=1, stb=1, we=1, adr=1, data=0x12345678, sel=3)
    assert calls[0][0] == 'STEP_WB_DMA_SEL'
    assert calls[0][1][5] == 3
    assert session.events[-1]['accepted']['byte_enable'] == 5
    assert session.memory_service.events[-1]['byte_enable'] == 5
    assert session.memory_service.memory.read(0x1000, 4, transaction_id='assert').data[::2] == bytes.fromhex('ddbb')


def test_selected_policy_uses_both_real_select_pins(artifact):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.wishbone_dma_template import dma_edge_policy
    profile = load_component_profile(ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json')
    endpoints = []
    for endpoint in artifact.plan.binding.endpoints:
        if endpoint.function in ('mmio_slave', 'memory_master'):
            data = next(f for f in endpoint.fields if f.role == 'dat_w')
            select = replace(data, role='sel', port='i_swb_sel' if endpoint.function == 'mmio_slave' else 'o_mwb_sel',
                             width=4, raw_lo=0, raw_hi=3, port_width=4)
            endpoint = replace(endpoint, fields=(*endpoint.fields, select))
        endpoints.append(endpoint)
    binding = replace(artifact.plan.binding, endpoints=tuple(endpoints))
    plan = replace(artifact.plan, profile=profile, binding=binding)
    control, master, irq, contracts = dma_edge_policy(plan)
    assert {c['contract']['variant_id'] for c in contracts} == {'dma-selected'}
    assert any(f.role == 'sel' for f in control.fields)
    assert any(f.role == 'sel' for f in master.fields)


def test_selected_renderer_projects_two_real_sel_wires_without_native(artifact, monkeypatch):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness import load_local_harness_request, plan_local_harness, render_local_harness
    from myfuzz.local_harness.source_lock import verify_local_source_lock
    from myfuzz.local_harness.runtime_renderer import render_local_runtime
    from myfuzz.local_harness.driver_renderer import render_local_driver
    import myfuzz.local_harness.plan as plan_module
    import myfuzz.local_harness.runtime_renderer as runtime_module
    profile = load_component_profile(ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json')
    old = artifact.plan.facts
    source_port = next(p for p in old.ports if p.name == 'i_swb_data')
    master_port = next(p for p in old.ports if p.name == 'o_mwb_data')
    select = (replace(source_port, name='i_swb_sel', width=4),
              replace(master_port, name='o_mwb_sel', width=4))
    facts = replace(old, top_module='zipdma', ports=(*old.ports, *select),
                    revision=profile.source.revision, files=profile.source.files)
    monkeypatch.setattr(plan_module, 'elaborate_profile', lambda *args, **kw: facts)
    monkeypatch.setattr(runtime_module, 'elaborate_profile', lambda *args, **kw: facts)
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/peripherals/zipdma_smoke/component_profile.json',
        instance_id='dma', reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    driver = render_local_driver(runtime, base_dir=ROOT)
    ports = {p['name']: p for p in runtime.runtime_document['backend_ports']}
    assert (ports['swb_sel']['direction'], ports['swb_sel']['width']) == ('input', 4)
    assert (ports['mwb_sel']['direction'], ports['mwb_sel']['width']) == ('output', 4)
    assert 'STEP_WB_DMA_SEL' in driver.cpp_text
    assert 'dut.swb_sel = command.fields[5]' in driver.cpp_text
    assert runtime.runtime_document['dma_edge_contract']['master_byte_enable_signal'] == 'mwb_sel'
    from myfuzz.scenario.ip_protocol_checker import WishboneDmaProtocolChecker
    checker = WishboneDmaProtocolChecker(component_id=profile.component_id, instance_id='dma',
        trace_set=runtime.runtime_document['protocol_checker_trace_set'])
    assert checker.report()['status'] == 'incomplete'
    from myfuzz.integration.compiled_f6_runtime_path import _artifact_link_document, _dma_endpoint_identity
    from myfuzz.local_harness.dma_artifact_endpoint_links import validate_dma_artifact_endpoint_links
    assert validate_dma_artifact_endpoint_links(_artifact_link_document(driver), driver)
    assert _dma_endpoint_identity(driver, 'dma')['byte_enable'] == 'mwb_sel'
    from myfuzz.scenario.runner import ScenarioRunner
    from myfuzz.scenario.ownership import compile_ownership
    from types import SimpleNamespace
    runner = ScenarioRunner(sessions={'dma': SimpleNamespace(artifact=driver)},
        ownership=compile_ownership((), ()), bindings=())
    checker = runner.install_protocol_checker('dma')
    assert checker.report()['installed_endpoint_ids'] == ['dma.control', 'dma.memory']
    backend = {row['name']: 0 for row in runtime.runtime_document['backend_ports']}
    backend.update(mwb_cyc=1, mwb_stb=1, mwb_we=1, mwb_adr=64,
                   mwb_dat_w=7, mwb_sel=5, mwb_stall=1)
    def sample(event_id, tick, values):
        return {'event_id': event_id, 'kind': 'local_tick_sample', 'component': 'dma',
                'local_tick': tick, 'phase': 'pre', 'outputs': {'backend': values}}
    assert checker.consume_local_tick(sample(1, 1, backend), reset_epoch=0) == ()
    findings = checker.consume_local_tick(sample(2, 2, {**backend, 'mwb_sel': 15}), reset_epoch=0)
    assert any(row['payload']['violation_code'] == 'wishbone_request_changed_while_stalled'
               for row in findings)
    import pytest
    from copy import deepcopy
    from myfuzz.local_harness.renderer import _sha
    altered = deepcopy(driver.runtime_document)
    altered['protocol_checker_trace_set']['traces'][1]['byte_enable'] = {'signal': 'absent', 'partial_write': False}
    unsigned = dict(altered); unsigned.pop('artifact_digest')
    altered['artifact_digest'] = _sha(unsigned)
    runner = ScenarioRunner(sessions={'dma': SimpleNamespace(artifact=replace(driver, runtime_document=altered))},
        ownership=compile_ownership((), ()), bindings=())
    with pytest.raises(ValueError, match='byte-enable-contract-mismatch'):
        runner.install_protocol_checker('dma')
    tampered_source = deepcopy(driver.source_verification)
    tampered_source['profile_fingerprint'] = 'other'
    runner = ScenarioRunner(sessions={'dma': SimpleNamespace(artifact=replace(driver, source_verification=tampered_source))},
        ownership=compile_ownership((), ()), bindings=())
    with pytest.raises(ValueError, match='artifact-contract-mismatch'):
        runner.install_protocol_checker('dma')
