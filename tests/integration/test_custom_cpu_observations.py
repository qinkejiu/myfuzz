from myfuzz.integration.custom_cpu_observations import (project_custom_cpu_events,
    project_custom_cpu_case_events, CustomCpuCaseObserver)
import pytest


def _sample(event_id, *, accepted, consumed, response=0):
    backend = dict(cyc=1, stb=1, we=1, adr=0x200, dat_w=85, sel=15, ack=consumed, dat_r=response)
    outputs = dict(driver_samples=[dict(local_tick=event_id, pre={'backend': backend}, post={})],
        instr_req_accepted=0, instr_req_valid=0, instr_rsp_consumed=0, instr_addr=0,
        data_req_accepted=accepted, data_req_valid=1, data_rsp_consumed=consumed,
        data_addr=0x200, data_write=1, data_wdata=85, data_be=15,
        data_rsp_rdata=response, data_rsp_source_epoch=0, data_rsp_source_sequence=1)
    return dict(event_id=event_id, component='cpu', local_tick=event_id, outputs=outputs)


def test_wishbone_and_ram_facts_are_actual_bounded_observations():
    traces = {channel: {role: role for role in ('cyc','stb','we','adr','dat_w','sel','ack','dat_r')}
              for channel in ('instr','data')}
    events = [_sample(1, accepted=1, consumed=0),
              dict(event_id=2, component='cpu', kind='memory_write', address=0x200,
                   value=85, width_bytes=4, version=[0, 1]),
              _sample(3, accepted=0, consumed=1)]
    result = project_custom_cpu_events(events, cpu_id='cpu', traces=traces,
        event_start=0, event_end=3, flow='F3')
    assert result['counts']['wishbone_acceptances'] == 1
    assert result['counts']['wishbone_responses'] == 1
    assert result['facts']['wishbone_acceptances'][0]['address'] == 0x200
    assert result['facts']['memory_writes'][0]['value'] == 85
    assert result['retirement'] == result['source_attribution'] == 'unknown'
    assert result['certificate'] == 'not_granted' and result['reward_eligible'] is False


def test_mmio_observations_preserve_real_events_and_case_window():
    traces = {channel: {role: role for role in ('cyc','stb','we','adr','dat_w','sel','ack','dat_r')}
              for channel in ('instr','data')}
    events = [_sample(1, accepted=1, consumed=0),
              dict(event_id=2, component='cpu', kind='mmio_delivery', address=0x4000,
                   device_id='target', write=True, write_value=85),
              _sample(3, accepted=0, consumed=1)]
    result = project_custom_cpu_events(events, cpu_id='cpu', traces=traces,
        event_start=1, event_end=3, flow='F4')
    assert result['counts']['wishbone_acceptances'] == 0
    assert result['counts']['wishbone_responses'] == 1
    assert result['facts']['mmio_deliveries'][0]['write_value'] == 85
    assert result['case_causality'] == 'unknown'


def test_rejects_mismatched_cpu_sample_instead_of_inventing_bus_fact():
    traces = {channel: {role: role for role in ('cyc','stb','we','adr','dat_w','sel','ack','dat_r')}
              for channel in ('instr','data')}
    bad = _sample(1, accepted=1, consumed=0)
    bad['outputs']['driver_samples'][0]['pre']['backend']['adr'] = 0x204
    with pytest.raises(ValueError, match='acceptance-level-mismatch'):
        project_custom_cpu_events([bad], cpu_id='cpu', traces=traces,
            event_start=0, event_end=1, flow='F3')


def test_case_only_mode_keeps_raw_samples_and_does_not_reconstruct_sequence():
    event = _sample(7, accepted=0, consumed=1, response=85)
    delivery = dict(event_id=8, kind='mmio_delivery', component='cpu', device_id='target',
                    address=0x4000, write=False, read_value=85)
    output = project_custom_cpu_case_events((event, delivery), cpu_id='cpu', flow='F2')
    sample, = output['facts']['wishbone_samples']
    assert sample['event_id'] == 7
    assert sample['outputs']['data_rsp_consumed'] == 1
    assert sample['outputs']['driver_samples'][0]['pre']['backend']['dat_r'] == 85
    assert output['facts']['mmio_deliveries'][0]['read_value'] == 85
    assert 'wishbone_acceptances' not in output['facts']
    assert output['retirement'] == output['case_causality'] == 'unknown'
    assert output['certificate'] == 'not_granted' and output['reward_eligible'] is False


def test_case_only_mode_bounds_samples_and_excludes_other_components():
    events = [dict(event_id=i, kind='memory_write', component='cpu', value=i) for i in range(4)]
    events.append(dict(event_id=5, kind='memory_write', component='dma', value=99))
    output = project_custom_cpu_case_events(events, cpu_id='cpu', flow='F3', limit=2)
    assert output['counts']['memory_writes'] == 4
    assert output['truncated']['memory_writes'] is True
    assert [row['value'] for row in output['facts']['memory_writes']] == [0, 1]
    output['facts']['memory_writes'][0]['value'] = 10
    assert events[0]['value'] == 0


def test_streaming_observer_matches_case_projection():
    events = [_sample(1, accepted=1, consumed=0),
              dict(event_id=2, kind='memory_write', component='cpu', value=85)]
    observer = CustomCpuCaseObserver(cpu_id='cpu', flow='F3', limit=1)
    for event in events:
        observer.observe(event)
    assert observer.result == project_custom_cpu_case_events(events, cpu_id='cpu', flow='F3', limit=1)
