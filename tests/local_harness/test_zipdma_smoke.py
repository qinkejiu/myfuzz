import hashlib
import json
from pathlib import Path
import pytest
from myfuzz.local_harness.zipdma_smoke import (ZipDmaMemoryBridge, ZipDmaTargetSession,
                                              zipdma_behavior, verify_sources)
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService


def test_observed_wishbone_transfer_uses_real_select_and_returns_read():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    memory.preload(0x100, bytes.fromhex('11223344'))
    bridge = ZipDmaMemoryBridge(MemoryService(memory, TransactionLedger()))
    assert bridge.response() == (0, 0, 0, 0)
    bridge.accept({'cyc': 1, 'stb': 1, 'we': 0, 'addr': 0x40, 'data': 0, 'sel': 15})
    assert bridge.response() == (1, 1, 0x44332211, 0)
    bridge.complete()
    bridge.accept({'cyc': 1, 'stb': 1, 'we': 1, 'addr': 0x80,
                   'data': 0xaabbccdd, 'sel': 5})
    assert bridge.response() == (1, 1, 0, 0)
    bridge.complete()
    assert memory.read(0x200, 4, transaction_id='check').data[::2] == bytes.fromhex('ddbb')
    assert [event['sel'] for event in bridge.events] == [15, 5]
    assert [event['address'] for event in bridge.events] == [0x100, 0x200]


def test_no_transfer_without_cyc_and_stb():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    bridge = ZipDmaMemoryBridge(MemoryService(memory, TransactionLedger()))
    bridge.accept({'cyc': 1, 'stb': 0, 'we': 1, 'addr': 0x80, 'data': 0, 'sel': 15})
    assert bridge.response() == (0, 0, 0, 0)
    assert bridge.events == []


def test_memory_bridge_preserves_configured_transaction_scope():
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    service = MemoryService(memory, TransactionLedger())
    bridge = ZipDmaMemoryBridge(service, execution_id='run-a', testcase_id='case-b',
                                source_component='my-dma', source_epoch=2)
    bridge.accept({'cyc': 1, 'stb': 1, 'we': 1, 'addr': 1, 'data': 7, 'sel': 15})
    transaction = service.events[-1]['transaction']
    assert (transaction['execution_id'], transaction['testcase_id'],
            transaction['source_component'], transaction['source_epoch']) == ('run-a', 'case-b', 'my-dma', 2)


def test_source_closure_detects_changed_rtl(tmp_path):
    source = tmp_path / 'dma.v'
    source.write_bytes(b'module dma; endmodule\n')
    profile = {'sources': {'dma.v': hashlib.sha256(source.read_bytes()).hexdigest()}}
    assert verify_sources(profile, tmp_path) == (source,)
    source.write_bytes(b'module other; endmodule\n')
    with pytest.raises(ValueError, match='source mismatch'):
        verify_sources(profile, tmp_path)


def test_checked_in_profile_matches_real_source():
    root = Path(__file__).resolve().parents[2]
    profile = json.loads((root / 'configs/peripherals/zipdma_smoke/profile.json').read_text())
    assert len(verify_sources(profile, root / 'third_party/soc-zipcpu')) == 9
    assert zipdma_behavior(profile, root / 'third_party/soc-zipcpu')['length_unit'] == 'bytes'
    profile['control']['clear_interrupt'] = 0
    with pytest.raises(ValueError, match='ZipDMA behavior'):
        zipdma_behavior(profile, root / 'third_party/soc-zipcpu')


def test_target_session_is_a_router_mmio_target_and_preserves_byte_enable():
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.ledger import TransactionKey
    class FakeDriver:
        def __init__(self): self.calls = []; self.ticks = 0
        def step(self, **kwargs):
            self.calls.append(kwargs)
            self.ticks += 1
            return {'control_stall': 0, 'control_ack': 1,
                    'control_data': 0x89abcdef, 'irq': 1}
    driver = FakeDriver()
    target = ZipDmaTargetSession(driver)
    router = DataflowRouter((DeviceWindow('dma', 0x40001000, 16, target),))
    ledger = TransactionLedger()
    key1 = TransactionKey('e', 'case', 'cpu', 0, 'data', 1)
    key2 = TransactionKey('e', 'case', 'cpu', 0, 'data', 2)
    assert router.transact(ledger, key1, address=0x40001004, write=True,
                           wdata=0x12345678, be=5, beat_bytes=4) == (0, 0)
    assert router.transact(ledger, key2, address=0x40001000, write=False,
                           wdata=0, be=15, beat_bytes=4) == (0x89abcdef, 0)
    assert driver.calls[0] == {'cyc': 1, 'stb': 1, 'we': 1, 'addr': 1, 'data': 0x12345678, 'sel': 5}
    assert driver.calls[1] == {'cyc': 1, 'stb': 1, 'we': 0, 'addr': 0, 'data': 0, 'sel': 15}
    assert target.irq == 1
    assert [e['write'] for e in target.control_events] == [True, False]
    receipt = router.deliveries[0]['dma_control_receipt']
    assert receipt['source_transaction']['source_component'] == 'cpu'
    assert receipt['edge_ticks'] == [1] and receipt['byte_enable'] == 5


def test_scenario_lifecycle_preserves_indirect_tick_and_irq_samples(monkeypatch, tmp_path):
    from myfuzz.local_harness import zipdma_smoke as dma
    from myfuzz.scenario.ownership import compile_ownership
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import ScenarioRunner

    class Process:
        pid = 789
        def poll(self): return None
    class FakeDriver:
        def __init__(self, binary, bridge):
            self.process = Process(); self.ticks = 0; self.closed = False
        def step(self, **kwargs):
            self.ticks += 1
            event = {'control_stall': 0, 'control_ack': 1, 'control_data': 0,
                     'irq_pre': 0, 'irq': int(kwargs.get('cyc', 0) == 1)}
            return event
        def close(self): self.closed = True; return 0
    class Cpu:
        def __init__(self, target):
            self.router = DataflowRouter((DeviceWindow('dma', 0x40001000, 16, target),))
            self.ledger = TransactionLedger(); self.local_ticks = 0
        def begin_case(self, testcase_id): pass
        def step_local(self, inputs):
            from myfuzz.scenario.ledger import TransactionKey
            self.local_ticks += 1
            self.router.transact(self.ledger, TransactionKey('cpu', 'case', 'cpu', 0, 'data', 1),
                address=0x40001004, write=True, wdata=0x100, be=15, beat_bytes=4)
            return {}
        def end_case(self): pass
        def reset_local(self): return {'cancelled_responses': 0}
    monkeypatch.setattr(dma, 'ZipDmaDriver', FakeDriver)
    binary = tmp_path / 'harness'; binary.write_bytes(b'binary')
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    target = dma.ZipDmaScenarioSession(binary, MemoryService(memory, TransactionLedger()))
    cpu = Cpu(target)
    runner = ScenarioRunner(sessions={'cpu': cpu, 'dma': target},
                            ownership=compile_ownership((), ()), bindings=())
    runner.begin_test('case')
    assert len(target.startup_samples) == 3
    runner.step('cpu')
    samples = [e for e in runner.events if e.get('kind') == 'local_tick_sample' and e['component'] == 'dma']
    assert [(e['local_tick'], e['phase'], e['outputs']['irq']) for e in samples] == [(1, 'pre', 0), (1, 'post', 1)]
    assert runner.local_ticks['dma'] == target.local_ticks == 1
    assert cpu.router.deliveries[0]['dma_control_receipt']['edge_ticks'] == [1]
    assert target.execution_identity()['pid'] == 789
    before = target._execution
    target._bridge.accept({'cyc': 1, 'stb': 1, 'we': 0, 'addr': 1, 'data': 0, 'sel': 15})
    reset = runner.reset_all('warm_all')
    assert reset.cancelled_responses['dma'] == 1 and target.pending_responses == 0
    assert target.reset_epoch == 1 and target._execution == before
    assert len(target.reset_samples) == 3
    target._bridge.accept({'cyc': 1, 'stb': 1, 'we': 1, 'addr': 1, 'data': 42, 'sel': 15})
    assert target.service.events[-1]['transaction']['source_epoch'] == 1
    assert target.local_ticks > 1
    driver = target.driver
    runner.finalize()
    assert driver.closed


def test_smoke_programs_length_and_clears_observed_interrupt(monkeypatch):
    from scripts import run_zipdma_smoke as smoke
    class Process:
        def poll(self):
            return None
    class FakeDriver:
        def __init__(self, binary, bridge):
            self.bridge, self.process, self.ticks = bridge, Process(), 0
            self.started, self.irq = False, False
            self.data = []
            self.control_writes = []
            self.transfer = 0
            instances.append(self)
        def step(self, **kwargs):
            self.ticks += 1
            if kwargs.get('cyc'):
                if kwargs.get('we'):
                    self.control_writes.append((kwargs['addr'], kwargs['data']))
                    if kwargs['addr'] == 0 and kwargs['data'] == 0:
                        self.started = True
                    elif kwargs['addr'] == 0 and kwargs['data'] == 0x80000000:
                        self.irq = False
                        self.started = False
                return {'control_stall': 0, 'control_ack': 1,
                        'control_data': 0, 'irq': int(self.irq)}
            if self.started and not self.irq:
                i = self.transfer
                if i < 4:
                    self.bridge.accept({'cyc': 1, 'stb': 1, 'we': 0, 'addr': (0x100 + 4*i) >> 2,
                                        'data': 0, 'sel': 15})
                    self.data.append(self.bridge.pending)
                else:
                    j = i - 4
                    self.bridge.accept({'cyc': 1, 'stb': 1, 'we': 1, 'addr': (0x200 + 4*j) >> 2,
                                        'data': self.data[j], 'sel': 15})
                self.bridge.complete()
                self.transfer += 1
                self.irq = self.transfer == 8
            return {'irq': int(self.irq)}
        def close(self):
            self.closed = True
    instances = []
    monkeypatch.setattr(smoke, 'Driver', FakeDriver)
    profile = json.loads(smoke.PROFILE.read_text())
    result = smoke.run(Path('/unused'), profile)
    assert result['words'] == [1, 2, 3, 4]
    assert result['irq_observed'] and result['irq_cleared']
    assert instances[0].control_writes == [(1, 0x100), (2, 0x200), (3, 16), (0, 0), (0, 0x80000000)]
    assert instances[0].closed
