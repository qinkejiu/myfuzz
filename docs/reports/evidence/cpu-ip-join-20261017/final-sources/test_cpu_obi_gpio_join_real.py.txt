"""One current-build real CPU/OBI/adapter/router/APB chain; explicit gate."""
import copy
import json
import os
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[2]


@pytest.mark.skipif(os.environ.get('MYFUZZ_OBI_GPIO_JOIN_REAL')!='1',reason='explicit same-run real CPU/IP gate')
def test_real_cpu_obi_router_apb_associations_and_mutation(tmp_path):
    from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_factory
    cache=Path(os.environ.get('MYFUZZ_OBI_GPIO_JOIN_CACHE',str(tmp_path/'cache')))
    factory=make_ibex_pulp_dual_source_factory(cache,physical_observations=True)
    runner=factory();cpu=runner.sessions['cpu']
    program=(0x400010b7,0x03500113,0x0020a623,0x00c0a183,0x00020237,0x00322023,0x0000006f)
    cpu.memory.preload(0x10080,b''.join(w.to_bytes(4,'little') for w in program))
    for target in ('gpio_a','gpio_b'):
        runner.sessions[target].configure_ordinary_apb_access_receipts(max_records=8)
    runner.install_ordinary_apb_access_evidence(max_records=8)
    try:
        runner.begin_test('same-run-obi-gpio-join')
        for _ in range(70):
            for component in ('cpu','gpio_a','gpio_b'):runner.step(component)
        assert cpu.memory.read(0x20000,4,transaction_id='verify-gpio-readback').value==53
        joined=runner.cpu_ip_protocol_joins(max_records=8)
        assert not joined['gaps'], joined
        assert len(joined['records'])==2
        assert all(r['status']=='actual_protocol_handoff_associated' for r in joined['records'])
        assert not joined['grants_verified'] and not joined['grants_functional']
        # Mutate only the router's journal key; the live seal and native raw
        # evidence retain the original key. Address/timing similarity is useless.
        records=runner._events._records
        delivery=next(r for r in records if r.get('kind')=='mmio_delivery')
        original=copy.deepcopy(delivery['source_transaction'])
        delivery['source_transaction']['source_sequence']+=100
        rejected=runner.cpu_ip_protocol_joins(max_records=8)
        assert len(rejected['records'])==1 and rejected['gaps']
        delivery['source_transaction']=original
        assert runner.cpu_ip_protocol_joins(max_records=8)==joined
        target_raw=next(r for r in records if r.get('kind')=='local_tick_sample'
            and r.get('ordinary_apb_access_ref'))
        original_outputs=copy.deepcopy(target_raw['outputs'])
        target_raw['outputs']['backend']['trace_pwdata'] ^= 1
        target_rejected=runner.cpu_ip_protocol_joins(max_records=8)
        assert target_rejected['gaps']
        target_raw['outputs']=original_outputs
        controls={}
        for field in ('execution_id','source_epoch','source_sequence'):
            old=copy.deepcopy(delivery['source_transaction'])
            delivery['source_transaction'][field]=('another-run' if field=='execution_id' else old[field]+1)
            controls[field]=runner.cpu_ip_protocol_joins(max_records=8)
            assert controls[field]['gaps'] and len(controls[field]['records'])<2
            delivery['source_transaction']=old
        cpu_raw=next(r for r in records if r['event_id']==joined['records'][0]['cpu_obi_raw_event_ref'])
        cpu_raw['outputs']['protocol_taps']['trace_obi_d_gnt']=0
        controls['cpu_grant']=runner.cpu_ip_protocol_joins(max_records=8)
        assert controls['cpu_grant']['gaps']
        cpu_raw['outputs']['protocol_taps']['trace_obi_d_gnt']=1
        read_response=next(r for r in records if r['event_id']==joined['records'][1]['cpu_obi_response_raw_event_ref'])
        read_response['outputs']['protocol_taps']['trace_obi_d_rdata'] ^= 1
        controls['cpu_response_data']=runner.cpu_ip_protocol_joins(max_records=8)
        assert controls['cpu_response_data']['gaps'] and len(controls['cpu_response_data']['records'])==1
        read_response['outputs']['protocol_taps']['trace_obi_d_rdata'] ^= 1
        read_response['outputs']['protocol_taps']['trace_obi_d_error']=1
        controls['cpu_response_error']=runner.cpu_ip_protocol_joins(max_records=8)
        assert controls['cpu_response_error']['gaps']
        read_response['outputs']['protocol_taps']['trace_obi_d_error']=0
        records.append(copy.deepcopy(cpu_raw))
        controls['duplicate_event']=runner.cpu_ip_protocol_joins(max_records=8)
        assert not controls['duplicate_event']['records'] and controls['duplicate_event']['gaps']
        records.pop()
        assert runner.cpu_ip_protocol_joins(max_records=8)==joined
        if 'MYFUZZ_OBI_GPIO_JOIN_EVIDENCE' in os.environ:
            out=Path(os.environ['MYFUZZ_OBI_GPIO_JOIN_EVIDENCE']);out.mkdir(parents=True,exist_ok=True)
            values=dict(journal=list(runner.events),joined=joined,key_mutation=rejected,
                target_raw_mutation=target_rejected,adversarial_controls=controls,protocol_reports=runner.protocol_trace_set_reports(),
                ordinary=runner.ordinary_apb_access_evidence_snapshot(),
                identities={name:session.identity_document() for name,session in runner.sessions.items()})
            (out/'same-run.json').write_text(json.dumps(values,indent=2,sort_keys=True)+'\n')
    finally:
        for session in runner.sessions.values():session.end_case()
