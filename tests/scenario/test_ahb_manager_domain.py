"""Saved native bytes replayed in software; this never starts a model."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import pytest
from myfuzz.scenario.ahb_cpu_events import AhbCpuObserver, bind_ahb_trace
from myfuzz.local_harness.ahb_startup import contract_from_document

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'docs/reports/evidence/cvw-ahb-native-20261017/run--first.json.gz'
SHA='2707e1ddba05ce4c92c159b04de752c2572039e42258cb7979a072b8fbf79849'


def saved():
 raw=SAVED.read_bytes();assert hashlib.sha256(raw).hexdigest()==SHA
 document=json.loads(gzip.decompress(raw))
 records=document['driver_receipts'][0]['receipt']['payload']['observations']['ahb_startup']['records']
 assert len(records)==16
 return document,records


def prepared():
 document,records=saved();endpoint,mapping,_=bind_ahb_trace(document['artifact'])
 observer=AhbCpuObserver(component_id='cpu',endpoint_id=endpoint)
 observer.begin_scope(execution_id=document['native_execution'],testcase_id='saved-replay',reset_epoch=0)
 observer.begin_startup(contract_from_document(document['artifact']))
 return observer,mapping,records


def rows(record,mapping,*,domain=True):
 sample=record['sample']
 result={p:{r:sample[p]['protocol_taps'][name] for r,name in mapping.items()} for p in ('pre','post')}
 if domain:
  # Historical ABI/source evidence is pinned in the archived attempt report.
  # These are existing measured physical outputs, not generated new tap data.
  result['domain']={p:dict(manager_ready=sample[p]['physical']['rt_lh_p_6_0_0'],
                         bus_reset_n=sample[p]['physical']['rt_lh_p_8_0_0']) for p in ('pre','post')}
 return result


def test_historical_external_ready_interpretation_reproduces_failure():
 observer,mapping,records=prepared()
 with pytest.raises(ValueError,match='address_hold'):
  for record in records:observer.observe_startup(record,rows=rows(record,mapping,domain=False))
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==11


def test_saved_all_sixteen_edges_use_measured_manager_and_bus_reset():
 observer,mapping,records=prepared()
 for record in records:observer.observe_startup(record,rows=rows(record,mapping))
 observer.finish_startup()
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==16
 addresses=[e for e in observer.events if e['kind']=='ahb_address']
 assert [(e['local_tick'],e['address']) for e in addresses]==[(11,0xc0000000)]
 assert observer.pending['address']==0xc0000000
 assert observer.counts['completed']==0
 assert not observer.measured_reset_to_command_prefix
 assert all(e['authority']=='observation_only' for e in observer.events)
