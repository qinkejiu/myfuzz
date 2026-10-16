"""Genuine CPU-written DMA configuration and DMA-produced RAM/IRQ evidence."""
import json
import os
from dataclasses import asdict
from pathlib import Path

import pytest

from myfuzz.scenario.ibex_dma_example import (make_ibex_dma_chain,advance_ibex_dma,
    SOURCE,DESTINATION,RESULT,DMA_BASE,MAIN,ISR,WORDS)

pytestmark=pytest.mark.skipif(os.environ.get('MYFUZZ_DMA_CPU_REAL')!='1',
    reason='set MYFUZZ_DMA_CPU_REAL=1 for pinned Ibex + DMA RTL')


def _read(memory,address):
    return memory.read(address,4,transaction_id='test-observation').value


def test_ibex_configures_dma_and_native_interrupt_runs_real_isr(tmp_path):
    traces=[]
    for run in range(2):
        cpu,dma,router,memory=make_ibex_dma_chain(cache_dir=Path(os.environ.get(
            'MYFUZZ_DMA_CPU_CACHE',str(tmp_path/'cache'))))
        schedule=[]
        irq_latch={}
        try:
            dma.begin_case('ibex-dma-isr')
            cpu.begin_case('ibex-dma-isr')
            for step in range(1600):
                schedule.append(advance_ibex_dma(cpu,dma,router,step=step,irq_latch=irq_latch))
                if _read(memory,RESULT+24):
                    break
            evidence=dict(schedule=schedule,dma_events=dma.events,
                cpu_events=cpu.cpu_events,cpu_memory=cpu.service.events,
                dma_memory=dma.memory_service.events,
                router_deliveries=[{**e,'source_transaction':asdict(e['source_transaction'])}
                    for e in router.deliveries],
                cpu_identity=cpu.identity_document(),dma_identity=dma.identity_document())
            directory=Path(os.environ.get('MYFUZZ_DMA_CPU_EVIDENCE',str(tmp_path)))
            directory.mkdir(parents=True,exist_ok=True)
            (directory/f'run-{run}.json').write_text(json.dumps(evidence,indent=2))
            assert _read(memory,RESULT+24)==1, 'real CPU ISR did not commit success'
            assert _read(memory,RESULT)==0x8000000b
            assert [_read(memory,RESULT+8+i*4) for i in range(4)]==list(WORDS)
            assert [_read(memory,DESTINATION+i*4) for i in range(4)]==list(WORDS)
            deliveries=router.deliveries
            writes=[e for e in deliveries if e['write']]
            assert [(e['offset'],e['write_value']) for e in writes]==[
                (8,SOURCE),(12,DESTINATION),(4,4),(0,0x0fed0004)]
            assert len([e for e in deliveries if not e['write'] and e['offset']==0])==1
            physical=[e for e in cpu.cpu_events if e['kind']=='data_accept']
            for delivery in writes:
                match=[e for e in physical if e['transaction']['source_sequence']==delivery['source_sequence']]
                assert len(match)==1
                assert match[0]['address']==DMA_BASE+delivery['offset']
                assert match[0]['wdata']==delivery['write_value']
                control=delivery['dma_control_receipt']
                assert control['source_transaction']==asdict(delivery['source_transaction'])
                edges=[e for e in dma.events if e['tick'] in control['edge_ticks']]
                assert sum(e['payload']['pre_backend']['swb_stb'] for e in edges)==1
                assert any(e['payload']['pre_backend']['swb_ack'] for e in edges)
            accepted=[e['accepted'] for e in dma.events if 'accepted'in e]
            reads=[e for e in accepted if not e['write']]
            master_writes=[e for e in accepted if e['write']]
            assert [e['address'] for e in reads]==[SOURCE+i*4 for i in range(4)]
            assert [(e['address'],e['value']) for e in master_writes]==[
                (DESTINATION+i*4,w) for i,w in enumerate(WORDS)]
            source_commits=[e for e in cpu.service.events if e['kind']=='memory_write' and SOURCE<=e['address']<SOURCE+16]
            assert [e['value'] for e in source_commits]==list(WORDS)
            snapshots=[e for e in dma.memory_service.events if e['kind']=='memory_read']
            assert [e['value'] for e in snapshots]==list(WORDS)
            for snapshot,commit in zip(snapshots,source_commits):
                assert snapshot['versions']==[commit['version']]*4 or tuple(snapshot['versions'])==(commit['version'],)*4
                assert all('source_component=\'cpu\'' in writer for writer in snapshot['writer_event_ids'])
            assert not any(e['kind']=='memory_write' and DESTINATION<=e['address']<DESTINATION+16 for e in cpu.service.events)
            assert len([e for e in dma.memory_service.events if e['kind']=='memory_write'])==4
            binding=[e for e in schedule if e['cpu_irq_input']]
            assert len(binding)>=1
            assert sum(bool(e['dma_native_irq_ticks']) for e in binding)==1
            assert sum(e['irq_latch_cleared_by_actual_take'] for e in binding)==1
            assert binding[-1]['irq_latch_after']==[]
            irq_sample=[e for e in cpu.cpu_events if e['kind']=='cpu_external_irq_sample' and e['expected_input']==1]
            assert len(irq_sample)==len(binding)
            assert all(e['actual_pre_input']==e['actual_post_input']==1 for e in irq_sample)
            assert any(e['kind']=='cpu_external_irq_taken' for e in cpu.cpu_events)
            assert any(e['kind']=='cpu_retire' and ISR<=e.get('pc_rdata',0)<ISR+128 for e in cpu.cpu_events)
            # Compare all actual commands/physical samples and effect order; UUID
            # is the sole intentionally fresh identity excluded from equality.
            normalized=json.loads(json.dumps(evidence))
            normalized.pop('cpu_identity');normalized.pop('dma_identity')
            def strip_uuid(value):
                if isinstance(value,dict):
                    return {k:strip_uuid(v) for k,v in value.items()}
                if isinstance(value,list):return [strip_uuid(v) for v in value]
                if isinstance(value,str):
                    return value.replace(cpu._execution,'fresh-cpu').replace(dma._execution,'fresh-dma')
                return value
            traces.append(strip_uuid(normalized))
        finally:
            cpu.end_case();dma.close()
    assert traces[0]==traces[1]
