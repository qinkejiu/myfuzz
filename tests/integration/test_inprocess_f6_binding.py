"""F6 spike must not silently reinterpret mismatched clocks or SEL roles."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from scripts.inprocess_f6_firmware import write_binding


def artifacts():
    cpu_ports = []
    for channel in ('i', 'd'):
        for role, direction, width in (
            ('req_valid','output',1), ('req_ready','input',1), ('req_write','output',1),
            ('req_addr','output',32), ('req_wdata','output',32), ('req_be','output',4),
            ('rsp_valid','input',1), ('rsp_ready','output',1), ('rsp_rdata','input',32), ('rsp_error','input',1)):
            cpu_ports.append(dict(channel=channel,role=role,name=channel+'_'+role,direction=direction,width=width))
    dma_ports=[]
    for channel, rows in (('swb', [('cyc','input',1),('stb','input',1),('we','input',1),('adr','input',2),
            ('dat_w','input',32),('stall','output',1),('ack','output',1),('dat_r','output',32),('sel','input',4)]),
        ('mwb',[('cyc','output',1),('stb','output',1),('we','output',1),('adr','output',30),
            ('dat_w','output',32),('stall','input',1),('ack','input',1),('dat_r','input',32),('err','input',1),('sel','output',4)])):
        for role,direction,width in rows:
            dma_ports.append(dict(channel=channel,role=role,name=channel+'_'+role,direction=direction,width=width))
    def base(kind,hz,ports,irq_port,irq_ep,irq_dir):
        return dict(kind=kind,module_name='local_runtime_test', plan={'profile_path':'fake.json'},
            clock_schedule={'clocks':[dict(signal='clk',half_period_fast_ticks=1,frequency_hz=hz,
                ratio=1,first_rising_fast_tick=1)]},
            backend_ports=ports, runtime_ports=[],driver_reset={'reset_assert_ticks':2,'reset_release_ticks':3},
            physical_exports=[dict(physical_port=irq_port,endpoint_id=irq_ep,direction=irq_dir,width=1,runtime_name='irq_signal')])
    cpu=base('obi_cpu',50,cpu_ports,'irq_i','cpu.irq','input')
    dma=base('wishbone_dma',1,dma_ports,'irq_o','dma.irq','output')
    dma['dma_edge_contract']=dict(master_address_units='word',master_address_shift=2,environment_max_outstanding=1,
        same_edge_accept_and_complete=False,control_byte_enable_signal='swb_sel',master_byte_enable_signal='mwb_sel')
    contract=dict(irq=dict(consumer_endpoint_id='cpu.irq',consumer_port='irq_i',producer_endpoint_id='dma.irq',
        producer_port='irq_o',delivery_policy='level',target_local_ticks=0),
        dma={'behavior':{'irq_clear':{'method':'write','offset':0,'value':0x80000000}}},
        program_contract=dict(source_address=0x200,destination_address=0x300,result_base=0x400,
                              slot_count=8,slot_base=0x100,slot_bytes=256,online_prefix_bytes=128),
        memory={'resource':dict(base=0,size=0x1000)},control=dict(base=0x1000,size=16))
    return cpu,dma,contract


def test_binding_requires_explicit_lockstep_and_records_it(tmp_path, monkeypatch):
    monkeypatch.setattr('scripts.inprocess_f6_firmware.load_component_profile', lambda _: SimpleNamespace(capabilities={}))
    cpu,dma,contract=artifacts()
    with pytest.raises(ValueError, match='assume-lockstep'):
        write_binding(tmp_path/'binding.h',contract,cpu,dma)
    write_binding(tmp_path/'binding.h',contract,cpu,dma,assume_lockstep=True)
    text=(tmp_path/'binding.h').read_text()
    assert '#define F6_ASSUMED_LOCKSTEP 1' in text
    assert '#define F6_CPU_DECLARED_HZ 50' in text
    assert '#define F6_DMA_DECLARED_HZ 1' in text
    assert 'F6_WORD_' not in text


def test_binding_rejects_renamed_or_silently_missing_sel(tmp_path, monkeypatch):
    monkeypatch.setattr('scripts.inprocess_f6_firmware.load_component_profile', lambda _: SimpleNamespace(capabilities={}))
    cpu,dma,contract=artifacts()
    for variant in ('renamed','missing'):
        bad=deepcopy(dma)
        sel=next(r for r in bad['backend_ports'] if r['channel']=='mwb' and r['role']=='sel')
        if variant=='renamed': sel['name']='other_select'
        else: bad['backend_ports'].remove(sel)
        with pytest.raises(ValueError, match='SEL role mismatch'):
            write_binding(tmp_path/'binding.h',contract,cpu,bad,assume_lockstep=True)
