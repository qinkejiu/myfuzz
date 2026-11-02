import copy
import json
from pathlib import Path

import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.zipdma_profile_session import create_zipdma_session, verify_zipdma_profile
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'configs/peripherals/zipdma_smoke/component_profile.json'


def test_profile_is_source_verified_and_preserves_real_select():
    profile = load_component_profile(PROFILE)
    result = verify_zipdma_profile(profile, base_dir=ROOT)
    assert result['behavior']['length_unit'] == 'bytes'
    assert result['control_select'] == 'i_swb_sel'
    assert result['master_select'] == 'o_mwb_sel'
    assert result['scope'] == 'source-backed independent session; no generated runtime or F6 admission'


def test_profile_rejects_mismatched_select_or_register_contract():
    document = json.loads(PROFILE.read_text())
    document['endpoints'][0]['fields'][5]['aliases'] = ['fabricated_sel']
    with pytest.raises(ValueError, match='endpoint'):
        verify_zipdma_profile(load_component_profile(document), base_dir=ROOT)
    document = json.loads(PROFILE.read_text())
    document['address']['registers'][3]['offset'] = 0
    with pytest.raises(ValueError):
        verify_zipdma_profile(load_component_profile(document), base_dir=ROOT)


def test_factory_registers_one_session_and_shared_memory_without_native(tmp_path):
    profile = load_component_profile(PROFILE)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    service = MemoryService(memory, TransactionLedger())
    session = create_zipdma_session(profile, binary=tmp_path / 'harness',
                                    memory_service=service, base_dir=ROOT,
                                    source_component='peripheral_dma')
    assert session.service is service and session.memory is memory
    assert session.source_component == 'peripheral_dma'
    assert session.routed_register_access_enabled
    assert session.source_contract['master_select'] == 'o_mwb_sel'
    assert session.driver is None


def test_registered_session_forwards_observed_select_to_router_and_memory(monkeypatch, tmp_path):
    from myfuzz.local_harness import zipdma_smoke
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.ledger import TransactionKey

    class Driver:
        def __init__(self, binary, bridge):
            self.bridge = bridge
            self.ticks = 0
            self.calls = []
        def step(self, **kw):
            self.ticks += 1
            self.calls.append(kw)
            return {'control_stall': 0, 'control_ack': 1, 'control_data': 0,
                    'irq_pre': 0, 'irq': 0}
        def close(self): pass

    monkeypatch.setattr(zipdma_smoke, 'ZipDmaDriver', Driver)
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    service = MemoryService(memory, TransactionLedger())
    session = create_zipdma_session(load_component_profile(PROFILE), binary=tmp_path / 'dma',
                                    memory_service=service, base_dir=ROOT)
    session.begin_case('case')
    router = DataflowRouter((DeviceWindow('dma', 0x40001000, 16, session),))
    router.transact(TransactionLedger(), TransactionKey('exec', 'case', 'cpu', 0, 'data', 1),
                    address=0x40001004, write=True, wdata=0x12345678, be=5, beat_bytes=4)
    assert session.driver.calls[-1]['sel'] == 5
    session._bridge.accept({'cyc': 1, 'stb': 1, 'we': 1, 'addr': 0x80,
                            'data': 0xaabbccdd, 'sel': 5})
    assert session._bridge.events[-1]['sel'] == 5
    assert memory.read(0x200, 4, transaction_id='check').data[::2] == bytes.fromhex('ddbb')
    session.end_case()


def test_registered_session_reports_source_identity_and_actual_master_events(monkeypatch, tmp_path):
    from myfuzz.local_harness import zipdma_smoke
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.runner import ScenarioRunner

    class Proc:
        pid = 123
        returncode = None
        def poll(self): return self.returncode
    class Driver:
        def __init__(self, binary, bridge):
            self.bridge, self.ticks, self.process = bridge, 0, Proc()
        def step(self, **kw):
            self.ticks += 1
            if self.ticks == 4:
                self.bridge.accept({'cyc': 1, 'stb': 1, 'we': 1, 'addr': 0x80,
                                    'data': 0xaabbccdd, 'sel': 5})
            return {'control_stall': 0, 'control_ack': 1, 'control_data': 0,
                    'irq_pre': 0, 'irq': 0}
        def close(self): self.process.returncode = 0

    monkeypatch.setattr(zipdma_smoke, 'ZipDmaDriver', Driver)
    binary = tmp_path / 'dma'; binary.write_bytes(b'example')
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    session = create_zipdma_session(load_component_profile(PROFILE), binary=binary,
                                    memory_service=MemoryService(memory, TransactionLedger()), base_dir=ROOT)
    identity = session.identity_document()
    assert identity['source_contract']['profile_fingerprint'] == session.component_profile.profile_fingerprint
    runner = ScenarioRunner(sessions={'dma': session}, ownership=compile_ownership((), ()), bindings=())
    runner.begin_test('case'); runner.step('dma')
    events = [e for e in runner.events if e.get('kind') == 'wishbone_dma_master_accepted']
    assert len(events) == 1
    assert (events[0]['address'], events[0]['sel'], events[0]['local_tick']) == (0x200, 5, 1)
    assert events[0]['source_component'] == 'dma'
    assert session.execution_identity()['pid'] == 123
    runner.finalize()
    assert session.lifecycle_receipt()['returncode'] == 0
    assert session.lifecycle_receipt()['reaped'] is True
