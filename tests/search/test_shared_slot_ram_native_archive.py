"""Offline original native evidence; no installed authority is reconstructed."""
import json
from pathlib import Path
from copy import deepcopy
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]
from myfuzz.search import shared_slot_ram as module


def archive():
    prefix=json.loads((ROOT/'research/input-strategy-audit-20261027/runs/shared-consumption-20261029/ram-v1/original/partial_prefix.json').read_text())
    row=prefix['flow_records'][0];events={e['event_id']:e for e in prefix['actual_events'] if 'event_id' in e}
    commit,=[e for e in events.values() if e.get('kind')=='memory_write_commit' and e['commit_document']['byte_offset']==86012]
    cells=commit['commit_document']['enabled_byte_cells']
    resources=[dict(byte_offset=c['byte_offset'],version=c['version'],value=c['value'],observation_event_id=commit['event_id']) for c in cells]
    s=dict(runtime=SimpleNamespace(cpu_id='cpu'),cpu=SimpleNamespace(reset_epoch=0),runner=object(),address=151548,
        image={'port':'shared_ram','range':[65536,196607]},methods=(None,lambda runner,i:events.get(i)))
    return s,row,resources,events,commit


def test_real_native_store_and_commit_are_distinct_but_exactly_joined():
    s,row,resources,events,commit=archive()
    assert row['certificate']['memory_store_observation']['memory_write_event']==2912
    assert commit['event_id']==2913
    assert all(module._matches_f3_commit(s,r,row) for r in resources)


@pytest.mark.parametrize('change',['producer','transaction','memory','offset','version','data','byte_enable','response','case'])
def test_native_join_rejects_crossed_or_incomplete_evidence(change):
    s,row,resources,events,commit=archive()
    if change=='producer':commit['producer_event_id']+=1
    elif change=='transaction':commit['transaction']=dict(commit['transaction'],source_sequence=9)
    elif change=='memory':commit['commit_document']['memory_id']='other'
    elif change=='offset':commit['commit_document']['byte_offset']+=4
    elif change=='version':commit['commit_document']['version']=[0,8]
    elif change=='data':commit['commit_document']['enabled_byte_cells'][0]['value']^=1
    elif change=='byte_enable':commit['commit_document']['byte_enable']=7
    elif change=='response':row['certificate']['memory_store_observation']['response_event']=2913
    elif change=='case':row['certificate']['case_id']='other'
    assert not module._matches_f3_commit(s,resources[0],row)
