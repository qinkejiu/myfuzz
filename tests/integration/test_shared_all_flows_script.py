from types import SimpleNamespace
import pytest


def test_all_flow_choice_waits_for_real_completion_and_GPIO_ISR(monkeypatch):
    from scripts.run_shared_all_flows import AllFlowWitness,RECORDS
    import myfuzz.integration.shared_f6_slots as slots
    rows=[];monkeypatch.setattr(slots,'flow_records',lambda runtime:rows)
    witness=AllFlowWitness();witness.attach_runtime(SimpleNamespace())
    for raw in RECORDS:
        assert witness.choose()==raw
        flow,record=raw.split(':')
        rows.append(dict(flow=flow,raw_hex=record,status='reserved',certificate={}))
        with pytest.raises(ValueError):witness.choose()
        rows[-1]['status']='passed'
        if flow=='F5':
            rows[-1]['certificate']['irq_isr']={'status':'unknown'}
            with pytest.raises(ValueError):witness.settle(raw)
            rows[-1]['certificate']['irq_isr']['status']='verified'
        witness.settle(raw)
    with pytest.raises(ValueError):witness.choose()


@pytest.mark.parametrize('witness_type', ['subset','all','bench'])
def test_declared_irq_witness_requires_actual_unique_consumption(monkeypatch,witness_type):
    from scripts.run_shared_slot_subset import SubsetWitness
    from scripts.run_shared_all_flows import AllFlowWitness
    from scripts.bench_shared_flow_ab import SequenceWitness
    import myfuzz.integration.shared_f6_slots as slots
    record='F5:0000000100000000'
    observation=dict(status='verified',irq_consumption='verified',
        transport=dict(status='observed',attribution='unique'),
        consumption=dict(status='verified',irq_consumption='verified'),
        unknown=dict(internal_ip_cause='unknown'),reward_eligible=False)
    certificate=dict(schema_version='compiled_shared_declared_F5_slot_case.v1',
        status='certified',observation=observation,reward_eligible=False)
    rows=[dict(flow='F5',raw_hex=record.split(':')[1],status='passed',certificate=certificate)]
    monkeypatch.setattr(slots,'flow_records',lambda runtime:rows)
    witness=({'subset':lambda:SubsetWitness([record]),'all':AllFlowWitness,
              'bench':lambda:SequenceWitness([record])}[witness_type])()
    witness.attach_runtime(SimpleNamespace())
    observation['transport']['attribution']='ambiguous'
    with pytest.raises(ValueError,match='IRQ ISR'):
        witness.settle(record)
    observation['transport']['attribution']='unique'
    observation['consumption']['irq_consumption']='unknown'
    with pytest.raises(ValueError,match='IRQ ISR'):
        witness.settle(record)
    observation['consumption']['irq_consumption']='verified'
    witness.settle(record)
    assert witness.done==1 and observation['unknown']['internal_ip_cause']=='unknown'
