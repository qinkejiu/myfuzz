"""Software-only reproduction of frozen 893d255 AXI journal reference reuse."""
import copy
import hashlib
import json
import subprocess
from types import SimpleNamespace
from myfuzz.local_harness.cva6_axi4_fields import CVA6_AXI_SHAPE
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.event_journal import EventJournal

source=subprocess.check_output(['git','show','893d255:src/myfuzz/scenario/full_axi_events.py'])
namespace={'__name__':'frozen_full_axi_reference_reproduction'}
exec(compile(source,'893d255/full_axi_events.py','exec'),namespace)
observer=namespace['BoundedFullAxiObserver'](component_id='cpu')
observer.begin_scope(execution_id='software_exec',testcase_id='model',reset_epoch=0)
def sample(tick,**values):
 row={'axi_'+r:0 for r in CVA6_AXI_SHAPE};row.update({'axi_'+r:v for r,v in values.items()})
 return dict(local_tick=tick,pre=dict(backend=row),post=dict(backend=copy.deepcopy(row)))
runner=ScenarioRunner(sessions={'cpu':SimpleNamespace(runtime_events=observer.events)},
 ownership=compile_ownership((),()),bindings=())
runner._events._records=EventJournal(chunk_size=2)
observer.observe(sample(1,arvalid=1,arready=1,araddr=0x100,arburst=1,arsize=3))
runner._append_external_events('cpu',0)
assert observer.events==[]
observer.observe(sample(2,rvalid=1,rready=1,rlast=1,rdata=42))
runner._append_external_events('cpu',0)
rows=list(runner._events);raw=[e for e in rows if e['kind']=='full_axi_raw']
assert len(raw)==2 and raw[0]['raw_event_ref']==raw[1]['raw_event_ref']==1
print(json.dumps({'software_model_only':True,'native_run':False,'frozen_observer_commit':'893d255',
 'frozen_observer_sha256':hashlib.sha256(source).hexdigest(),
 'raw_ref_values':[r['raw_event_ref'] for r in raw],
 'raw_local_ticks':[r['raw_sample']['local_tick'] for r in raw],
 'runner_events':rows},sort_keys=True,indent=2))
