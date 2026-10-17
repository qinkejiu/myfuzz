"""Saved native bytes replayed in software; this never starts a model."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import pytest
from myfuzz.scenario.ahb_cpu_events import AhbCpuObserver, bind_ahb_trace
from myfuzz.local_harness.ahb_startup import contract_from_document
from myfuzz.local_harness.ahb_manager_domain import project_saved_manager_domain

ROOT=Path(__file__).resolve().parents[2]
SAVED=ROOT/'docs/reports/evidence/cvw-ahb-native-20261017/run--first.json.gz'
SHA='2707e1ddba05ce4c92c159b04de752c2572039e42258cb7979a072b8fbf79849'
PROFILE=ROOT/'configs/cpus/cvw/component_profile.json'


def saved():
 raw=SAVED.read_bytes();assert hashlib.sha256(raw).hexdigest()==SHA
 document=json.loads(gzip.decompress(raw))
 records=document['driver_receipts'][0]['receipt']['payload']['observations']['ahb_startup']['records']
 assert len(records)==16
 return document,records


def projected(document=None):
 document=document or saved()[0]
 return project_saved_manager_domain(document['artifact'],PROFILE)


def prepared(artifact=None):
 document,records=saved()
 artifact=artifact or projected(document)
 endpoint,mapping,_=bind_ahb_trace(artifact)
 observer=AhbCpuObserver(component_id='cpu',endpoint_id=endpoint)
 observer.begin_scope(execution_id=document['native_execution'],testcase_id='saved-replay',reset_epoch=0)
 observer.begin_startup(contract_from_document(artifact))
 return artifact,observer,mapping,records


def rows(record,mapping,artifact,*,legacy=False):
 sample=record['sample']
 result={p:{r:sample[p]['protocol_taps'][name] for r,name in mapping.items()} for p in ('pre','post')}
 if legacy:
  # Historical interpretation only: the external subordinate's HREADYEXT is
  # substituted for manager acceptance, with a nominal bus-reset release so the
  # reproduction reaches the address-phase checks instead of staying unknown.
  reset_n=0 if record['startup_edge_index']<=2 else 1
  result['domain']={p:dict(manager_ready=result[p]['hready'],bus_reset_n=reset_n)
                    for p in ('pre','post')}
 else:
  # Existing measured physical outputs (HREADY/HRESETn), named by the declared
  # and authenticated domain contract; no new tap data is generated.
  roles=artifact['manager_domain']['roles']
  result['domain']={p:{role:sample[p]['physical'][spec['runtime_name']]
                       for role,spec in roles.items()} for p in ('pre','post')}
 return result


def test_historical_external_ready_interpretation_reproduces_failure():
 artifact,observer,mapping,records=prepared()
 with pytest.raises(ValueError,match='address_hold'):
  for record in records:observer.observe_startup(record,rows=rows(record,mapping,artifact,legacy=True))
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==11


def test_saved_all_sixteen_edges_use_measured_manager_and_bus_reset():
 artifact,observer,mapping,records=prepared()
 for record in records:observer.observe_startup(record,rows=rows(record,mapping,artifact))
 observer.finish_startup()
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==16
 addresses=[e for e in observer.events if e['kind']=='ahb_address']
 assert [(e['local_tick'],e['address']) for e in addresses]==[(11,0xc0000000)]
 assert addresses[0]['acceptance_ready']=='manager_ready'
 assert addresses[0]['external_ready_at_accept']==0
 assert observer.pending['address']==0xc0000000
 assert observer.counts['completed']==0
 assert observer.counts['accepted']==1 and observer.counts['reads']==1
 assert not observer.measured_reset_to_command_prefix
 assert all(e['authority']=='observation_only' for e in observer.events)
 resets=[e for e in observer.events if e['kind']=='ahb_bus_reset']
 assert [(e['asserted'],e['local_tick']) for e in resets]==[(True,3),(False,11)]
 raw=[e for e in observer.events if e['kind']=='ahb_raw']
 assert all(e['measured_domain']['pre']['bus_reset_n']==records[i]['sample']['pre']['physical']['rt_lh_p_8_0_0']
            for i,e in enumerate(raw))
 assert all(e['raw_sample']==records[i]['sample'] for i,e in enumerate(raw))


def test_projection_preserves_frozen_bytes_and_labels_provenance():
 document,records=saved()
 artifact=projected(document)
 assert artifact['domain_projection']['source_artifact_digest']==document['artifact']['artifact_digest']
 assert artifact['domain_projection']['source_profile_sha256']==document['artifact']['plan']['profile_sha256']
 assert artifact['domain_projection']['domain_profile_sha256']==hashlib.sha256(PROFILE.read_bytes()).hexdigest()
 assert artifact['domain_projection']['domain_profile_sha256']!=document['artifact']['plan']['profile_sha256']
 assert artifact['domain_projection']['provenance']=='saved_native_artifact_software_projection'
 # Raw native samples and the external reset metadata are untouched.
 for saved_record,artifact_record in zip(records,
         document['driver_receipts'][0]['receipt']['payload']['observations']['ahb_startup']['records']):
  assert saved_record==artifact_record
 assert artifact['domain_projection']['note'].startswith('declared current-profile')
