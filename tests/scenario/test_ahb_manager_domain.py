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
 assert 'manager_domain' not in document['artifact']


# ---------------------------------------------------------------------------
# Negative controls: the binding, the measured rows and the identity are all
# fail-closed.  Every case mutates only metadata of the saved projection; the
# frozen native bytes are never rewritten.
# ---------------------------------------------------------------------------

from myfuzz.local_harness.ahb_manager_domain import (ROLES,SCHEMA,
    software_manager_domain_contract)
from myfuzz.local_harness.ahb_startup import startup_contract
from myfuzz.scenario.ahb_cpu_events import SHAPE
from tests.local_harness.ahb_domain_support import (command_sample,domain_values,
    start_measured_prefix,startup_record)
from tests.local_harness.test_ahb_cpu_contract import generated


def mutated_artifact(mutation):
 artifact=projected()
 mutation(artifact)
 return artifact


def _swap_profile_endpoint(artifact):
 fields=artifact['manager_domain']['profile_endpoint']['fields']
 ports=[field['physical_port'] for field in fields]
 for field,port in zip(fields,reversed(ports)):field['physical_port']=port


DOMAIN_CASES = {
 'missing-contract':lambda a:a.pop('manager_domain'),
 'absent-role':lambda a:a['manager_domain']['roles'].pop('manager_ready'),
 'duplicated-role':lambda a:a['manager_domain']['roles'].update(
     weird=copy.deepcopy(a['manager_domain']['roles']['manager_ready'])),
 'swapped-roles':lambda a:a['manager_domain']['roles'].update(
     manager_ready=a['manager_domain']['roles']['bus_reset_n'],
     bus_reset_n=a['manager_domain']['roles']['manager_ready']),
 'wrong-width':lambda a:a['manager_domain']['roles']['manager_ready'].update(width=2),
 'wrong-direction':lambda a:a['manager_domain']['roles']['bus_reset_n'].update(direction='input'),
 'wrong-source-wire':lambda a:a['manager_domain']['roles']['manager_ready'].update(source_wire='guessed'),
 'wrong-physical-port':lambda a:a['manager_domain']['roles']['manager_ready'].update(
     physical_port='HREADYEXT'),
 'duplicate-runtime-wire':lambda a:a['manager_domain']['roles']['bus_reset_n'].update(
     runtime_name=a['manager_domain']['roles']['manager_ready']['runtime_name']),
 'clock-provenance':lambda a:a['manager_domain']['clock'].update(domain='other'),
 'reset-bus-polarity':lambda a:a['manager_domain']['reset']['bus'].update(polarity='active_high'),
 'reset-external-proxy':lambda a:a['manager_domain']['reset']['external_command'].update(port='HRESETn'),
 'profile-endpoint-swap':lambda a:_swap_profile_endpoint(a),
 'profile-endpoint-clock':lambda a:a['manager_domain']['profile_endpoint'].update(clock='other'),
 'profile-endpoint-reset':lambda a:a['manager_domain']['profile_endpoint'].update(reset='other'),
 'abi-role':lambda a:next(r for r in a['structural_abi']['ports']
     if r['physical_port']=='HREADY').update(role='hready'),
 'export-endpoint':lambda a:next(r for r in a['physical_exports']
     if r['physical_port']=='HREADY').update(endpoint_id='cpu.external_bus'),
 'plan-endpoint':lambda a:next(r for r in a['plan']['ports']
     if r['port']=='HREADY').pop('endpoint_id'),
 'duplicate-abi-row':lambda a:a['structural_abi']['ports'].append(
     copy.deepcopy(next(r for r in a['structural_abi']['ports'] if r['physical_port']=='HREADY'))),
 'sampling-fallback':lambda a:a['manager_domain']['sampling'].update(
     address_acceptance='external_hready'),
 'scope-aggregate':lambda a:a['manager_domain']['scope'].update(aggregate_hresp_exported=True),
 'external-ready-fallback':lambda a:a['manager_domain'].update(external_ready_role='hready2'),
 'authority':lambda a:a['manager_domain'].update(authority='transaction'),
 'projection-digest':lambda a:a['domain_projection'].update(source_artifact_digest='other'),
 'projection-source':lambda a:a['manager_domain'].update(source='generated_profile_binding'),
}


@pytest.mark.parametrize('name',sorted(DOMAIN_CASES))
def test_manager_domain_binding_rejects(name):
 with pytest.raises(ValueError):
  bind_ahb_trace(mutated_artifact(DOMAIN_CASES[name]))


def test_old_artifact_without_domain_metadata_is_refused():
 document,_records=saved()
 for action in (lambda:bind_ahb_trace(document['artifact']),
                lambda:contract_from_document(document['artifact'])):
  with pytest.raises(ValueError,match='manager-domain'):action()


def test_absent_actual_reset_assertion_fails_closed_and_keeps_sixteen_raw():
 artifact,observer,mapping,records=prepared()
 for record in records:
  r=rows(record,mapping,artifact)
  for phase in ('pre','post'):r['domain'][phase]['bus_reset_n']=1
  observer.observe_startup(record,rows=r)
 with pytest.raises(ValueError,match='bus_reset_prefix_unmeasured'):
  observer.finish_startup()
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==16
 assert not observer.measured_reset_to_command_prefix
 assert observer.counts['accepted']==0
 assert all(e['authority']=='observation_only' for e in observer.events)


def test_tampered_measured_reset_sample_is_refused_with_raw_retained():
 artifact,observer,mapping,records=prepared()
 for record in records:
  r=rows(record,mapping,artifact)
  if record['startup_edge_index']==3:
   r['domain']['pre']['bus_reset_n']=2
  if record['startup_edge_index']>3:break
  try:observer.observe_startup(record,rows=r)
  except ValueError as error:
   assert 'domain_row' in str(error)
   break
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==3
 assert observer.events[-1]['kind']=='ahb_failure'
 assert observer.events[0]['raw_sample']==records[0]['sample']


def test_true_global_stall_with_owned_external_phase_and_changed_address_refused():
 observer=AhbCpuObserver(component_id='cpu',endpoint_id='bus')
 observer.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 contract=startup_contract(assert_ticks=1,release_ticks=3,snapshot_max={})
 observer.begin_startup({**contract,'manager_domain':software_manager_domain_contract()})
 sequence=[startup_record(1,bus_reset_n=0,asserted=1),
           startup_record(2,bus_reset_n=1,manager_ready=1,hsel=1,htrans=2,haddr=0x100),
           startup_record(3,bus_reset_n=1,manager_ready=0,hsel=1,htrans=2,haddr=0x200),
           startup_record(4,bus_reset_n=1,manager_ready=0,hsel=1,htrans=2,haddr=0x204)]
 with pytest.raises(ValueError,match='address_hold'):
  for record in sequence:
   observer.observe_startup(record,rows={
       'pre':record['sample']['pre']['protocol_taps'],
       'post':record['sample']['post']['protocol_taps'],
       'domain':{'pre':record['sample']['pre']['domain'],
                 'post':record['sample']['post']['domain']}})
 assert observer.pending['address']==0x100
 assert len([e for e in observer.events if e['kind']=='ahb_raw'])==4


def test_inconsistent_external_global_completion_refused():
 observer=AhbCpuObserver(component_id='cpu',endpoint_id='bus')
 observer.begin_scope(execution_id='e',testcase_id='c',reset_epoch=0)
 contract=startup_contract(assert_ticks=1,release_ticks=2,snapshot_max={})
 observer.begin_startup({**contract,'manager_domain':software_manager_domain_contract()})
 sequence=[startup_record(1,bus_reset_n=0,asserted=1),
           startup_record(2,bus_reset_n=1,manager_ready=1,hsel=1,htrans=2,haddr=0x100),
           startup_record(3,bus_reset_n=1,manager_ready=1,hready=0)]
 with pytest.raises(ValueError,match='external_completion'):
  for record in sequence:
   observer.observe_startup(record,rows={
       'pre':record['sample']['pre']['protocol_taps'],
       'post':record['sample']['post']['protocol_taps'],
       'domain':{'pre':record['sample']['pre']['domain'],
                 'post':record['sample']['post']['domain']}})
 assert observer.events[-1]['trusted_projection'] is True


def test_new_runtime_document_declares_and_exports_the_domain(generated):
 artifact,cpu=generated;document=artifact.runtime_document
 domain=document['manager_domain']
 assert domain['schema_version']==SCHEMA and domain['source']=='generated_profile_binding'
 assert set(domain['roles'])==set(ROLES)
 exports={row['runtime_name']:row for row in document['physical_exports']}
 for role,spec in domain['roles'].items():
  row=exports[spec['runtime_name']]
  assert (row['endpoint_id'],row['role'],row['width'],row['direction'],
          row['disposition'])==(domain['endpoint_id'],role,1,'output','observe')
 hclk=next(row for row in document['physical_exports'] if row['physical_port']=='HCLK')
 assert hclk['endpoint_id'] is None and hclk['role'] is None
 identity=cpu.identity_document()['ahb_observation_contract']
 assert identity['observer_version']==3
 assert identity['domain_contract']==domain
 assert identity['startup_capture']==document['ahb_startup_contract']
 tap=next(row for row in document['protocol_tap_ports'] if row['role']=='hready')
 assert tap['source_wire']!='HREADY'
 assert domain['roles']['manager_ready']['source_wire']=='HREADY'
 assert domain['roles']['bus_reset_n']['source_wire']=='HRESETn'
 assert 'domain_projection' not in document


def test_identity_reconstruction_rejects_domain_substitution(generated):
 from myfuzz.scenario.contracts import _verify_generated_session
 artifact,cpu=generated
 substitutions=[
  lambda d:d['ahb_observation_contract'].update(observer_version=2),
  lambda d:d['ahb_observation_contract'].pop('domain_contract'),
  lambda d:d['ahb_observation_contract'].update(
      domain_contract=software_manager_domain_contract(protocol_endpoint_id='cpu.external_bus')),
  lambda d:d['ahb_observation_contract']['domain_contract']['roles'].update(
      manager_ready=d['ahb_observation_contract']['domain_contract']['roles']['bus_reset_n']),
  lambda d:d['ahb_observation_contract']['trace_binding']['manager_domain'].update(
      endpoint_id='cpu.other_domain'),
 ]
 for mutate in substitutions:
  identity=copy.deepcopy(cpu.identity_document());mutate(identity)
  with pytest.raises(ValueError):_verify_generated_session(identity)


def test_command_budget_poisons_and_runner_drains_raw_refs_once(generated):
 from myfuzz.scenario.ownership import compile_ownership
 from myfuzz.scenario.runner import ScenarioRunner
 artifact,cpu=generated;observer=cpu._ahb_observer
 observer.begin_scope(execution_id='issued',testcase_id='case',reset_epoch=0)
 start_measured_prefix(observer)
 observer._limits=(2,observer._limits[1],observer._limits[2],observer._limits[3])
 with pytest.raises(ValueError,match='budget'):
  observer.observe(command_sample(1,manager_ready=1,hready=1,hsel=1,htrans=2,haddr=0x100))
 raw=[e for e in observer.events if e['kind']=='ahb_raw']
 assert len(raw)==3 and raw[-1]['tick_namespace']=='command'
 assert all(e['authority']=='observation_only' for e in observer.events)
 runner=ScenarioRunner(sessions={'cpu':cpu},ownership=compile_ownership((),()),bindings=())
 before=len(runner.events);runner._append_external_events('cpu',before)
 imported=list(runner.events)
 assert [{k:v for k,v in e.items() if k not in ('component','event_id','producer_event_id')}
         for e in imported]==observer.events
 runner._append_external_events('cpu',before);assert list(runner.events)==imported
 with pytest.raises(ValueError):observer.observe(command_sample(2,manager_ready=1))
 assert list(runner.events)==imported
