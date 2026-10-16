from pathlib import Path
import pytest
from myfuzz.local_harness.wishbone_dma_session import (
    GeneratedWishboneDmaSession, MasterTargetWindow)
from myfuzz.scenario.memory import PersistentMemory, MemoryRegion
from test_wishbone_dma_transport import artifact

ROOT = Path(__file__).resolve().parents[2]


def test_partial_or_unaligned_control_rejected_before_transport(artifact, tmp_path):
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT, cache_dir=tmp_path,
        memory=PersistentMemory(initialization_seed=1,max_initialized_bytes=8192,regions=(MemoryRegion('ram',0x1000,0x2000),)))
    for offset, lanes in [(1,15),(16,15),(0,1)]:
        with pytest.raises(ValueError):
            session.write_register(offset,1,byte_enable=lanes)
    assert session.local_ticks == 0
    assert session.pending_responses == 0


def test_real_pinned_dma_four_word_transfer(artifact, tmp_path):
    import os, json, shutil
    if os.environ.get('MYFUZZ_DMA_REAL') != '1':
        pytest.skip('set MYFUZZ_DMA_REAL=1 for actual pinned RTL simulation')
    if shutil.which('verilator') is None:
        pytest.skip('Verilator unavailable')
    words = [0x12345678,0x89abcdef,0x0badcafe,0xf00dba5e]
    traces = []
    for run in range(2):
        memory = PersistentMemory(initialization_seed=1,max_initialized_bytes=8192,
            regions=(MemoryRegion('ram',0x1000,0x2000),))
        memory.preload(0x1000,b''.join(w.to_bytes(4,'little') for w in words))
        memory.preload(0x2000,bytes(16))
        session = GeneratedWishboneDmaSession(artifact,base_dir=ROOT,
            cache_dir=os.environ.get('MYFUZZ_DMA_CACHE',str(tmp_path/'cache')),
            memory=memory,command_timeout_seconds=30)
        try:
            session.begin_case('four-word')
            for offset,value in [(4,4),(8,0x1000),(12,0x2000),(0,0x0fed0004)]:
                session.write_register(offset,value)
            for _ in range(400):
                receipt = session.step_local()
                if any(receipt.payload['observations']['physical'].values()):
                    break
            else:
                Path('/tmp/dma-no-irq.json').write_text(json.dumps(session.events,indent=2))
                pytest.fail('no native DMA interrupt')
            accepted = [e['accepted'] for e in session.events if 'accepted' in e]
            reads = [e for e in accepted if not e['write']]
            writes = [e for e in accepted if e['write']]
            assert [e['address'] for e in reads] == list(range(0x1000,0x1010,4))
            assert [e['address'] for e in writes] == list(range(0x2000,0x2010,4))
            assert [e['value'] for e in writes] == words
            assert [memory.read(0x2000+i*4,4,transaction_id='assert').value for i in range(4)] == words
            assert len([e for e in session.memory_service.events if e['kind']=='memory_write']) == 4
            irq = [e for e in session.events if any(e['payload']['observations']['physical'].values())]
            assert len(irq) == 1
            assert irq[0]['response']['transaction'] == writes[-1]['transaction']
            assert irq[0]['response']['error'] == 0
            assert session.pending_responses == 0
            assert all(e['tick'] == i+1 for i,e in enumerate(session.events))
            normalized = json.loads(json.dumps(session.events))
            for edge in normalized:
                for field in ('accepted','response'):
                    if field in edge:
                        edge[field]['transaction'].pop('execution_id')
            traces.append(normalized)
            evidence = dict(identity=session.identity_document(),events=session.events,
                memory_events=session.memory_service.events,words=words)
            evidence_dir = Path(os.environ.get('MYFUZZ_DMA_EVIDENCE',str(tmp_path)))
            evidence_dir.mkdir(parents=True,exist_ok=True)
            (evidence_dir/f'run-{run}.json').write_text(json.dumps(evidence,indent=2))
        finally:
            session.close()
    assert traces[0] == traces[1], 'fresh actual RTL executions must match every measured edge'


def test_one_edge_service_uses_observed_write_and_delivers_once(artifact,tmp_path,monkeypatch):
    from myfuzz.local_harness.wire import DriverReceipt
    memory = PersistentMemory(initialization_seed=1,max_initialized_bytes=16,
        regions=(MemoryRegion('ram',0x1000,16),))
    session = GeneratedWishboneDmaSession(artifact,base_dir=ROOT,cache_dir=tmp_path,memory=memory)
    session._execution = 'software-contract'
    session._case_id = 'once'
    commands = []
    def command(op,fields):
        commands.append(fields)
        return DriverReceipt('result','software-contract',len(commands),len(commands)-1,len(commands),1,
            payload={'observations':{'backend':{'mwb_stb':0}},'pre_backend':dict(mwb_cyc=1,mwb_stb=1,mwb_we=1,mwb_adr=0x400,mwb_dat_w=0x76543210)})
    monkeypatch.setattr(session,'command',command)
    session.step_local()
    assert session.pending_responses == 1
    assert memory.read(0x1000,4,transaction_id='assert').value == 0x76543210
    session.begin_quiesce()
    session.step_local()
    assert commands[1][5:] == (1,0,0,0)
    assert session.pending_responses == 1
    session.step_local()
    assert commands[2][5:] == (1,1,0,0)
    assert session.pending_responses == 0
    session.step_local()
    assert commands[3][5:] == (1,0,0,0)
    assert len([e for e in session.memory_service.events if e['kind']=='memory_write']) == 1


def test_invalid_resource_yields_real_error_input_without_ram_commit(artifact,tmp_path,monkeypatch):
    from myfuzz.local_harness.wire import DriverReceipt
    memory = PersistentMemory(initialization_seed=1,max_initialized_bytes=16,
        regions=(MemoryRegion('ram',0x1000,16),))
    session = GeneratedWishboneDmaSession(artifact,base_dir=ROOT,cache_dir=tmp_path,memory=memory)
    session._execution = 'software-contract'
    session._case_id = 'error'
    commands = []
    def command(op,fields):
        commands.append(fields)
        return DriverReceipt('result','software-contract',len(commands),len(commands)-1,len(commands),1,
            payload={'observations':{'backend':{'mwb_stb':1}},'pre_backend':dict(
                mwb_cyc=1,mwb_stb=1,mwb_we=0,mwb_adr=0x800,mwb_dat_w=0)})
    monkeypatch.setattr(session,'command',command)
    session.step_local()
    session.step_local()
    assert commands[1][5:] == (1,0,0,1)
    assert session.pending_responses == 0
    assert session.memory_service.events == []


def test_master_target_delivery_preserves_native_step_receipt(artifact, tmp_path, monkeypatch):
    from myfuzz.local_harness.wire import DriverReceipt

    class Target:
        local_ticks = 0
        uart_events = ()

        def write_register(self, offset, value, *, be):
            assert (offset, value, be) == (0x1c, 0xa5, 15)
            self.local_ticks += 1
            self.uart_events = ({'tick': self.local_ticks},)

        def identity_document(self):
            return {'component': 'test-target'}

    target = Target()
    memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=16,
        regions=(MemoryRegion('ram', 0x1000, 16),))
    window = MasterTargetWindow('uart', 0x50000000, 0x1000, target,
        (0x1c,), range(256))
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=memory, master_targets=(window,))
    session._execution = 'software-contract'
    session._case_id = 'target'
    payload = {'observations': {'backend': {'mwb_stb': 0}},
        'pre_backend': dict(mwb_cyc=1, mwb_stb=1, mwb_we=1,
            mwb_adr=0x5000001c >> 2, mwb_dat_w=0xa5)}
    native = DriverReceipt('result', 'software-contract', 1, 0, 1, 1,
        payload=payload)
    monkeypatch.setattr(session, 'command', lambda op, fields: native)

    returned = session.step_local()

    assert returned is native
    assert returned.status == 'result' and returned.new_ticks == 1
    assert returned.payload['pre_backend']['mwb_adr'] == 0x5000001c >> 2
    assert session.events[0]['accepted']['target_delivery']['target_event_range'] == [0, 1]
    assert session.events[0]['target_delivery']['target_tick_after'] == 1
    assert session.pending_responses == 1
    assert session.memory_service.events == []


def test_master_uart_rdata_uses_target_receipt_as_actual_ack_data(artifact, tmp_path, monkeypatch):
    from myfuzz.local_harness.wire import DriverReceipt
    from myfuzz.scenario.ledger import TransactionKey

    class Target:
        local_ticks = 0
        uart_events = ()

        def read_register(self, offset):
            assert offset == 0x18
            self.local_ticks = 3
            observation = {'kind': 'uart_rdata_access',
                'access_id': 'uart-read-1', 'status': 'observed',
                'source_transaction': None, 'read_value': 0x5a,
                'read_capture': {'pre': {'probe_uart_fifo_rvalid': 1,
                    'probe_uart_fifo_rdata_re': 1,
                    'probe_uart_fifo_under_rst': 0}}}
            self.uart_events = (observation,)
            return 0x5a

        def write_register(self, offset, value, *, be):
            raise AssertionError('DMA read must not write UART')

        def identity_document(self):
            return {'component': 'test-target'}

    memory = PersistentMemory(initialization_seed=1, max_initialized_bytes=16,
        regions=(MemoryRegion('ram', 0x1000, 16),))
    target = Target()
    with pytest.raises(ValueError, match='invalid DMA master target window'):
        MasterTargetWindow('uart', 0x50000000, 0x1000, target,
            (), (), readable_offsets=(0x20,))
    window = MasterTargetWindow('uart', 0x50000000, 0x1000, target,
        (), (), readable_offsets=(0x18,))
    session = GeneratedWishboneDmaSession(artifact, base_dir=ROOT,
        cache_dir=tmp_path, memory=memory, master_targets=(window,))
    session._execution = 'software-contract'
    session._case_id = 'rdata'
    fields_seen = []
    payload = {'observations': {'backend': {'mwb_stb': 0}},
        'pre_backend': dict(mwb_cyc=1, mwb_stb=1, mwb_we=0,
            mwb_adr=0x50000018 >> 2, mwb_dat_w=0)}

    def command(op, fields):
        fields_seen.append(fields)
        return DriverReceipt('result', 'software-contract', len(fields_seen),
            len(fields_seen)-1, len(fields_seen), 1, payload=payload)

    monkeypatch.setattr(session, 'command', command)
    returned = session.step_local()
    assert returned.status == 'result' and returned.new_ticks == 1
    delivery = session.events[0]['accepted']['target_delivery']
    assert delivery['write'] is False and delivery['value'] == 0x5a
    assert delivery['target_access_id'] == 'uart-read-1'
    assert delivery['source_transaction'] == session.events[0]['accepted']['transaction']
    assert delivery['target_uart_access']['source_transaction'] is None
    assert session.pending_responses == 1
    session.step_local()
    assert fields_seen[1][6:9] == (1, 0x5a, 0)
    assert session.memory_service.events == []
    next_key = TransactionKey('software-contract', 'rdata', 'dma', 0,
        'dma-memory', 2)
    session.memory_service.write(next_key, 0x1000, 0x5a,
        width_bytes=4, byte_enable=15)
    assert memory.read(0x1000, 4, transaction_id='assert').value == 0x5a


def test_routed_access_retains_cpu_identity_and_actual_edge_range(artifact,tmp_path,monkeypatch):
    from myfuzz.scenario.ledger import TransactionKey
    memory = PersistentMemory(initialization_seed=1,max_initialized_bytes=16,
        regions=(MemoryRegion('ram',0x1000,16),))
    session = GeneratedWishboneDmaSession(artifact,base_dir=ROOT,cache_dir=tmp_path,memory=memory)
    key = TransactionKey('cpu-run','case','cpu',0,'data',7)
    calls = []
    def access(offset,value,write,byte_enable):
        calls.append((offset,value,write,byte_enable))
        session.events.extend([{'tick':1},{'tick':2}])
        return 0x55
    monkeypatch.setattr(session,'_access_register',access)
    result = session.routed_register_access(key,address=0x40000008,offset=8,
        write=True,value=0x22000,be=15,delivery_context={'source_transaction':{'source_sequence':7}})
    assert calls == [(8,0x22000,True,15)]
    assert result['rdata'] == 0x55
    assert result['dma_control_receipt']['source_transaction']['source_sequence'] == 7
    assert result['dma_control_receipt']['edge_ticks'] == [1,2]
