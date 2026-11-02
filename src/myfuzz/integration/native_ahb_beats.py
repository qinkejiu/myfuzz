"""Recompute real AHB address/data phases and native memory handshakes.

The existing observer owns manager-vs-external READY and measured-reset rules.
Normalized channel names classify HPROT; source transaction keys stay `memory`.
This pure consumer issues no source, retirement, or IRQ authority.
"""
from copy import deepcopy
from ..scenario.ahb_cpu_events import AhbCpuObserver
from ..local_harness.ahb_manager_domain import measured_domain_rows


def collect_ahb_cpu_beats(events,component,traces):
    observer=AhbCpuObserver(component_id=component,endpoint_id=traces['endpoint_id'])
    signals=traces['signals'];domain=traces['manager_domain']
    def rows(sample):
        return {**{phase:{role:sample[phase]['protocol_taps'][name] for role,name in signals.items()}
            for phase in ('pre','post')},'domain':measured_domain_rows(sample,domain)}
    started=False;sequence=0;pending=None;completed={};fetches=[]
    for event in events:
        if event.get('component')!=component or 'local_tick' not in event:continue
        outputs=event.get('outputs',{});samples=outputs.get('driver_samples')
        if not samples:continue
        if len(samples)!=1 or samples[0].get('local_tick')!=event['local_tick']:raise ValueError('MMIO-AHB-native-sample-count')
        sample=samples[0];pre=sample['pre']['backend'];event_id=event['event_id']
        if not started:
            startup=outputs.get('ahb_startup_samples')
            if not startup:raise ValueError('MMIO-AHB-startup-evidence-missing')
            observer.begin_scope(execution_id='saved-native',testcase_id='saved-native',reset_epoch=0)
            observer.begin_startup({**traces['startup'],'manager_domain':domain})
            for record in startup:observer.observe_startup(record,rows=rows(record['sample']))
            observer.finish_startup();started=True
        elif outputs.get('ahb_startup_samples'):
            raise ValueError('MMIO-AHB-startup-duplicate')
        before=deepcopy(observer.pending);start=len(observer.events)
        observer.observe(sample,rows=rows(sample))
        accepted=int(bool(pre['m_req_valid'] and pre['m_req_ready']))
        consumed=int(bool(pre['m_rsp_valid'] and pre['m_rsp_ready']))
        if outputs.get('data_req_accepted')!=accepted or outputs.get('data_rsp_consumed')!=consumed:
            raise ValueError('MMIO-AHB-native-handshake-mismatch')
        if before is not None and not before['write'] and not before['controls']['hprot']&1 and pre['m_req_valid']:
            if pre['m_req_addr']!=before['address']:raise ValueError('MMIO-AHB-fetch-address-mismatch')
            fetches.append((event_id,before['address']))
        if accepted:
            if pending is not None or before is None:raise ValueError('MMIO-AHB-unowned-acceptance')
            if (before['address']!=pre['m_req_addr'] or before['write']!=pre['m_req_write']
                or before['controls']['hsize']!=2 or before['controls']['hmastlock']!=0
                or (before['write'] and (before['wdata']!=pre['m_req_wdata'] or before['wstrb']!=pre['m_req_be']))
                or (not before['write'] and pre['m_req_be']!=15)):
                raise ValueError('MMIO-AHB-native-request-mismatch')
            sequence+=1
            pending=dict(sequence=sequence,channel='data' if before['controls']['hprot']&1 else 'instr',
                address=before['address'],write=before['write'],value=pre['m_req_wdata'],byte_enable=pre['m_req_be'],
                acceptance_event=event_id,ahb_observation_id=before['observation_id'],
                ahb_address_ref=before['address_ref'],hprot=before['controls']['hprot'])
        phases=[row for row in observer.events[start:] if row['kind']=='ahb_complete']
        if bool(phases)!=bool(consumed) or len(phases)>1:raise ValueError('MMIO-AHB-native-completion-mismatch')
        if consumed:
            if pending is None:raise ValueError('MMIO-AHB-unowned-response')
            phase=phases[0]
            if (phase['observation_id']!=pending['ahb_observation_id'] or phase['hresp']!=pre['m_rsp_error']
                or pre['m_rsp_error']!=0 or phase['rdata']!=pre['m_rsp_rdata']
                or outputs.get('data_rsp_source_sequence')!=sequence or outputs.get('data_rsp_source_epoch')!=0):
                raise ValueError('MMIO-AHB-native-response-mismatch')
            completed[(pending['channel'],sequence)]=dict(pending,response_event=event_id,
                rdata=phase['rdata'],error=phase['hresp'],ahb_completion_ref=phase['completion_ref'])
            pending=None
    return completed,fetches
