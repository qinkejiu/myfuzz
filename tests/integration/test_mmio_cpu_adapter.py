from types import SimpleNamespace
import pytest
from myfuzz.integration.mmio_cpu_adapter import select_mmio_cpu


def test_unknown_cpu_protocol_is_explicitly_unsupported():
    artifact=SimpleNamespace(runtime_document={'kind':'axi4_cpu'})
    with pytest.raises(ValueError,match='MMIO-CPU-adapter-unsupported'):select_mmio_cpu(artifact,None,None)


def synthetic_wb_events():
    roles=('cyc','stb','we','adr','dat_w','sel','ack','dat_r')
    signals={r:'wb_'+r for r in roles};events=[]
    for tick,(channel,consumed,address,value) in enumerate((('instr',0,0,0),('instr',1,0,0x13),
            ('data',0,0x40001000,0),('data',1,0x40001000,0x55)),1):
        pre=dict(zip(signals.values(),(1,1,0,address,0,0,consumed,value)))
        outputs={}
        for c in ('instr','data'):
            outputs.update({c+'_req_valid':int(c==channel),c+'_req_accepted':int(c==channel and not consumed),
                c+'_rsp_consumed':int(c==channel and consumed),c+'_addr':address if c==channel else 0})
        outputs.update(data_write=0,data_wdata=0,data_be=0,data_rsp_rdata=value if channel=='data' and consumed else 0,
            data_rsp_source_epoch=0,data_rsp_source_sequence=int(channel=='data' and consumed),
            driver_samples=[dict(local_tick=tick,pre={'backend':pre},post={'backend':pre})])
        events.append(dict(event_id=tick,component='cpu',local_tick=tick,outputs=outputs))
    return events,{'instr':signals,'data':signals}


def test_WB_native_accept_response_are_normalized_without_OBI_relabel():
    from myfuzz.integration.mmio_cpu_adapter import MmioCpuAdapter
    events,traces=synthetic_wb_events()
    adapter=MmioCpuAdapter('wishbone',object,traces,{})
    completed=adapter.completed_beats(events,'cpu')
    assert adapter.protocol=='wishbone'
    assert completed[('instr',1)]['rdata']==0x13
    assert completed[('data',1)]['rdata']==0x55
    assert completed[('data',1)]['byte_enable']==0  # Native WB read SEL, not invented APB lanes.
    assert completed[('data',1)]['acceptance_event']==3
    assert completed[('data',1)]['response_event']==4


def test_WB_native_wrong_response_sequence_still_refuses():
    from myfuzz.integration.mmio_cpu_adapter import MmioCpuAdapter
    events,traces=synthetic_wb_events()
    events[-1]['outputs']['data_rsp_source_sequence']=2
    with pytest.raises(ValueError):MmioCpuAdapter('wishbone',object,traces,{}).completed_beats(events,'cpu')


@pytest.mark.parametrize('protocol',['wishbone','ahb-lite'])
def test_common_MMIO_hops_use_native_CPU_namespace_and_actual_read_value(protocol):
    from tests.integration.test_compiled_execution_files import exact_hop_fixture
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats
    from myfuzz.integration.native_mmio_hops import check_native_mmio_hops
    from myfuzz.scenario.memory import ReadSnapshot
    from myfuzz.scenario.ledger import TransactionKey
    fixture=exact_hop_fixture();events=fixture['events'];by_id={e['event_id']:e for e in events}
    for join in fixture['joins']:
        delivery=by_id[join['delivery_event']];accept=by_id[join['acceptance_event']]
        accept['source_transaction']=delivery['source_transaction'];delivery['byte_enable']=15
        join.update(write=delivery['write'],value=85)
    completed=collect_native_obi_beats(events,cpu='processor',traces=fixture['traces'],error_policy={'native_error_observation':True})
    ram=by_id[fixture['ram_event_id']]
    snapshot=ReadSnapshot('result','ram',0,ram['byte_offset'],(85).to_bytes(4,'little'),((0,2),)*4,
        (str(TransactionKey(**ram['transaction'])),)*4,writer_kinds=('STORE',)*4)
    if protocol=='ahb-lite':
        for event in events:
            for field in ('transaction','source_transaction'):
                if isinstance(event.get(field),dict):event[field]['channel_id']='memory'
        # Unified bus sequences include intervening instruction fetches.
        old_sequence=ram['transaction']['source_sequence']
        ram['transaction']['source_sequence']=30
        completed[('data',30)]=completed.pop(('data',old_sequence))
        snapshot=ReadSnapshot('result','ram',0,ram['byte_offset'],(85).to_bytes(4,'little'),((0,2),)*4,
            (str(TransactionKey(**ram['transaction'])),)*4,writer_kinds=('STORE',)*4)
    adapter=SimpleNamespace(protocol=protocol,completed_beats=lambda *args:completed)
    arguments={k:v for k,v in fixture.items() if k not in ('traces','declared_edges')}
    proof=check_native_mmio_hops(**arguments,result_snapshot=snapshot,cpu_adapter=adapter,flow='F4')
    assert proof['native_protocol']==protocol
    assert 'native_cpu' in proof['ram_write_hop'] and 'native_obi' not in proof['ram_write_hop']
    assert all('native_obi' not in hop for hop in proof['data_hops'])
    completed[('data',2)]['rdata']=99
    with pytest.raises(ValueError,match='data-route'):
        check_native_mmio_hops(**arguments,result_snapshot=snapshot,cpu_adapter=adapter,flow='F4')


def test_protocol_metadata_uses_actual_kind_not_CPU_or_target_name():
    from myfuzz.integration.mmio_cpu_adapter import native_cpu_protocol
    assert native_cpu_protocol({'kind':'ahb_lite_cpu'})=='ahb-lite'
    assert native_cpu_protocol({'kind':'wishbone_cpu'})=='wishbone'
    with pytest.raises(ValueError):native_cpu_protocol({'kind':'unsupported'})


def test_unified_CPU_memory_keys_keep_real_channel_for_fetch_join():
    from tests.integration.test_compiled_execution_files import exact_hop_fixture
    from myfuzz.integration.native_obi_hops import collect_native_obi_beats,verify_instruction_fetches
    f=exact_hop_fixture();events=f['events'];source=next(e for e in events if e.get('kind')=='instruction_source')
    completed=collect_native_obi_beats(events,cpu='processor',traces=f['traces'],error_policy={'native_error_observation':True})
    for event in events:
        if event.get('kind')=='memory_read':event['transaction']['channel_id']='memory'
    route=next(e for e in events if e['event_id']==f['joins'][0]['delivery_event'])['source_transaction']
    hops=verify_instruction_fetches(events=events,cpu='processor',address=f['address'],
        code=bytes.fromhex(f['declaration']['code_hex']),source_event_id=f['source_event_id'],source=source,
        route_transaction=route,instruction_snapshots=f['instruction_snapshots'],completed=completed,image=f['image'],
        functional_offsets=tuple(range(0,32,4)),transaction_channel='memory')
    assert len(hops)==8


def test_AHB_native_response_uses_pending_HPROT_and_memory_sequence():
    from myfuzz.integration.native_ahb_beats import collect_ahb_cpu_beats
    from myfuzz.local_harness.ahb_manager_domain import software_manager_domain_contract
    from myfuzz.local_harness.ahb_startup import startup_contract
    from tests.local_harness.ahb_domain_support import startup_record
    from myfuzz.scenario.ahb_cpu_events import SHAPE
    from copy import deepcopy
    domain=software_manager_domain_contract();signals={r:r for r in SHAPE}
    startup=[startup_record(1,bus_reset_n=0,asserted=1),startup_record(2,bus_reset_n=1,manager_ready=1,
        hsel=1,htrans=2,haddr=0xc0000000,hprot=0,hsize=2)]
    def physicalize(sample):
        for phase in ('pre','post'):
            sample[phase]['physical']={domain['roles'][r]['runtime_name']:v for r,v in sample[phase].pop('domain').items()}
        return sample
    for record in startup:physicalize(record['sample'])
    events=[]
    for tick,ready,rsp in ((1,0,0),(2,1,0),(3,0,1)):
        taps=dict.fromkeys(SHAPE,0);taps.update(hsel=1,htrans=2,haddr=0xc0010000,hprot=1,hready=rsp,hrdata=0x13)
        backend=dict(m_req_valid=int(not rsp),m_req_ready=ready,m_req_addr=0xc0000000,m_req_write=0,
            m_req_be=15,m_req_wdata=0,m_rsp_valid=rsp,m_rsp_ready=rsp,m_rsp_rdata=0x13,m_rsp_error=0)
        phase=dict(protocol_taps=taps,physical={domain['roles']['manager_ready']['runtime_name']:rsp,
            domain['roles']['bus_reset_n']['runtime_name']:1},backend=backend)
        outputs=dict(driver_samples=[dict(local_tick=tick,pre=deepcopy(phase),post=deepcopy(phase))],
            data_req_accepted=ready,data_rsp_consumed=rsp,data_rsp_source_sequence=rsp,data_rsp_source_epoch=0)
        if tick==1:outputs['ahb_startup_samples']=startup
        events.append(dict(event_id=tick,component='cpu',local_tick=tick,outputs=outputs))
    traces=dict(signals=signals,endpoint_id='bus',manager_domain=domain,
        startup=startup_contract(assert_ticks=1,release_ticks=1,snapshot_max={}))
    completed,fetches=collect_ahb_cpu_beats(events,'cpu',traces)
    assert fetches[0]==(1,0xc0000000)
    assert completed[('instr',1)]['address']==0xc0000000
    assert completed[('instr',1)]['response_event']==3
    assert completed[('instr',1)]['rdata']==0x13
    events[-1]['outputs']['data_rsp_source_sequence']=7
    with pytest.raises(ValueError):collect_ahb_cpu_beats(events,'cpu',traces)


def test_source_backed_AHB_fetch_granule_pads_only_current_declaration():
    from pathlib import Path
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.local_harness.cvw_contract import cvw_instruction_fetch_granule
    from myfuzz.integration.mmio_cpu_adapter import MmioCpuAdapter
    from hashlib import sha256
    root=Path(__file__).resolve().parents[2]
    profile=load_component_profile(root/'configs/cpus/cvw/component_profile.json')
    granule=cvw_instruction_fetch_granule(profile,base_dir=root)
    assert granule==64
    original=dict(code_hex=('13000000'*11),code_sha256='original')
    padded=MmioCpuAdapter('ahb-lite',object,{}, {},granule).prepare_declaration(original,address=0xc0000000)
    assert original['code_hex']=='13000000'*11
    assert bytes.fromhex(padded['code_hex'])==bytes.fromhex('13000000'*16)
    assert padded['code_sha256']==sha256(bytes.fromhex(padded['code_hex'])).hexdigest()
    assert padded['fixed_padding']['bytes']==20
    with pytest.raises(ValueError,match='alignment'):
        MmioCpuAdapter('ahb-lite',object,{}, {},granule).prepare_declaration(original,address=0xc0000004)
