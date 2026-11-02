"""Pure projection of genuine RAMv2 F1 archive; no live trust from disk."""
import json
from pathlib import Path
from copy import deepcopy
import pytest
from myfuzz.search import shared_slot_ram as module
ROOT=Path(__file__).resolve().parents[2]

def archive():
 p=ROOT/'research/input-strategy-audit-20261027/runs/shared-consumption-20261029/ram-v2/original'
 steps=json.loads((p/'consumption-diagnostic.json').read_text())['steps']
 prefix=json.loads((p/'partial_prefix.json').read_text())
 return steps[1]['before']['RAM'],prefix['flow_records'][1]['certificate']['memory_read_observation']

def test_real_F1_byte_certificates_use_integer_write_event_not_transaction_text():
 current,observation=archive()
 assert observation['byte_relations'][0]['write_event_id']==2913
 assert isinstance(observation['byte_relations'][0]['writer_event_id'],str)
 assert module.match_current_read(current,observation)

@pytest.mark.parametrize('change',['write_event','version','offset','value','missing_lane','transaction_as_event'])
def test_real_read_matching_rejects_inexact_byte_identity(change):
 current,observation=archive();row=observation['byte_relations'][0]
 if change=='write_event':row['write_event_id']+=1
 elif change=='version':row['byte_version']=[0,8]
 elif change=='offset':row['byte_offset']+=4
 elif change=='value':row['value']^=1
 elif change=='missing_lane':observation['byte_relations'].pop()
 elif change=='transaction_as_event':row['write_event_id']=row['writer_event_id']
 assert not module.match_current_read(current,observation)
