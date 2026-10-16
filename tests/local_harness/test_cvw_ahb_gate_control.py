"""Local temporary-directory controller controls; never a DUT or remote run."""
import importlib.util
import json
from pathlib import Path
import subprocess
import pytest
SCRIPT=Path(__file__).parents[2]/'scripts/cvw_ahb_gate_control.py'

def control():
 spec=importlib.util.spec_from_file_location('cvw_control',SCRIPT)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def test_default_plan_is_source_only_and_never_executes(monkeypatch,tmp_path):
 def refuse(*a,**kw):raise AssertionError('no child/tool/remote')
 monkeypatch.setattr(subprocess,'Popen',refuse)
 c=control();path=tmp_path/'plan.json'
 assert c.main(['--write-plan',str(path)])==0
 plan=json.loads(path.read_text())
 assert plan['native_run'] is False
 assert plan['canonical_heavy_lock']=='/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock'
 assert plan['lock_owner']=='gate_only_once_nonblocking'
 assert plan['snapshot']['hardlinks_allowed'] is False

def test_snapshot_map_rejects_symlink_and_hardlink_and_detects_exact_bytes(tmp_path):
 import os
 c=control();source=tmp_path/'source';source.mkdir();(source/'a').write_text('A')
 rows=c.source_map(source);assert rows['a']['sha256']==c.sha(b'A')
 (source/'b').symlink_to('/etc/passwd')
 with pytest.raises(ValueError):c.source_map(source)
 (source/'b').unlink();os.link(source/'a',source/'b')
 with pytest.raises(ValueError):c.source_map(source)
 (source/'b').unlink();(source/'a').write_text('B')
 with pytest.raises(ValueError):c.verify_source_map(source,rows)

def test_one_shot_claim_refuses_repeat_and_symlink(tmp_path):
 c=control();path=tmp_path/'state.json'
 c.claim_state(path,{'controller_pid':123,'phase':'claimed'})
 with pytest.raises(FileExistsError):c.claim_state(path,{'controller_pid':456})
 assert json.loads(path.read_text())['controller_pid']==123
 path2=tmp_path/'link';path2.symlink_to(path)
 with pytest.raises(ValueError):c.claim_state(path2,{})

def test_source_first_environment_is_exact(tmp_path):
 c=control();base=tmp_path;project=base/'project';(base/'tmp').mkdir()
 env={'PYTHONPATH':f'{project}/src:{project}:/root/fanzehui/system-20261016/pythonlib',
      'PYTHONOPTIMIZE':'0','PYTHONDONTWRITEBYTECODE':'1','TMPDIR':str(base/'tmp')}
 c.validate_environment(base,env)
 for key,value in [('PYTHONOPTIMIZE','1'),('PYTHONPATH',f'/other:{project}/src:{project}'),('TMPDIR','/tmp')]:
  with pytest.raises(ValueError):c.validate_environment(base,dict(env,**{key:value}))

def test_internal_link_is_documented_without_following_external_target(tmp_path):
 c=control();(tmp_path/'data').write_bytes(b'known');(tmp_path/'alias').symlink_to('data')
 rows=c.source_map(tmp_path)
 assert rows['alias']['kind']=='symlink' and rows['alias']['target']=='data'
 assert rows['data']['sha256']==c.sha(b'known')

def test_git_metadata_is_self_contained_and_no_alternates(tmp_path):
 c=control();project=tmp_path/'project';project.mkdir()
 for name in ('.git','third_party/cvw_upstream_reference/.git','third_party/caliptra_upstream_reference/.git'):
  git=project/name;(git/'objects/info').mkdir(parents=True);(git/'HEAD').write_text('ref: refs/heads/main\n')
 c.validate_git_metadata(project)
 (project/'.git/objects/info/alternates').write_text('/outside/objects\n')
 with pytest.raises(ValueError):c.validate_git_metadata(project)

def test_actual_small_software_child_pid_exit_and_one_shot(tmp_path):
 import os,sys
 c=control();command=[sys.executable,'-c','import sys;print("software-only-control");sys.exit(7)']
 receipt=c.run_child_once(tmp_path,command,cwd=tmp_path,environment=dict(os.environ))
 assert receipt['child_pid']>0 and receipt['child_pid']!=os.getpid()
 assert receipt['actual_exit']==7 and receipt['poll_after_wait']==7
 assert receipt['command']==command
 assert (tmp_path/'child.stdout').read_text()=='software-only-control\n'
 with pytest.raises(FileExistsError):c.run_child_once(tmp_path,command,cwd=tmp_path,environment=dict(os.environ))
 assert json.loads((tmp_path/'controller.claim.json').read_text())['controller_pid']==os.getpid()

def test_failed_spawn_records_terminal_without_fake_pid(tmp_path):
 import os
 c=control()
 with pytest.raises(OSError):c.run_child_once(tmp_path,['/nonexistent/software-control'],cwd=tmp_path,environment=dict(os.environ))
 terminal=json.loads((tmp_path/'controller.terminal.json').read_text())
 assert terminal['child_pid'] is None and terminal['actual_exit'] is None
 assert terminal['status']=='spawn_failed'

def test_allowed_tool_hashes_never_read_system_dependency(tmp_path,monkeypatch):
 c=control();wrapper=tmp_path/'bin/c++';wrapper.parent.mkdir();wrapper.write_bytes(b'wrapper')
 original=Path.read_bytes
 def guarded(path):
  if str(path).startswith('/usr/'):raise AssertionError('system dependency must not be read')
  return original(path)
 monkeypatch.setattr(Path,'read_bytes',guarded)
 rows=c.tool_file_map([str(wrapper),'/usr/bin/x86_64-linux-gnu-ar'],allowed_root=tmp_path)
 assert rows[str(wrapper)]['sha256']==c.sha(b'wrapper')
 assert rows['/usr/bin/x86_64-linux-gnu-ar']=={'grade':'environment_dependency_only','file_not_read':True}

def test_before_after_code_changes_reject_but_git_delta_is_retained():
 c=control();before={'code.py':{'sha256':'a'},'.git/index':{'sha256':'one'}}
 after={'code.py':{'sha256':'a'},'.git/index':{'sha256':'two'}}
 assert c.source_differences(before,after)==['.git/index']
 after['code.py']['sha256']='b'
 with pytest.raises(ValueError):c.require_code_unchanged(before,after)

def test_preflight_failure_has_terminal_and_no_child_and_cannot_retry(tmp_path,monkeypatch):
 c=control();base=tmp_path/'base';(base/'project').mkdir(parents=True);(base/'control').mkdir()
 monkeypatch.setattr(c,'ALLOWED_ROOT',tmp_path)  # local controller boundary fixture only
 def refuse(*a,**kw):raise AssertionError('preflight must not spawn')
 monkeypatch.setattr(subprocess,'Popen',refuse)
 with pytest.raises(ValueError):c.execute_controller(base,freeze_sha256='bad',source_map_sha256='bad')
 terminal=json.loads((base/'control/operation.terminal.json').read_text())
 assert terminal['status']=='failed' and terminal['child'] is None
 assert terminal['error']['type']=='ValueError'
 with pytest.raises(FileExistsError):c.execute_controller(base,freeze_sha256='bad',source_map_sha256='bad')

def test_controller_keeps_actual_software_child_exit_and_after_maps(tmp_path,monkeypatch):
 """Controller wiring fixture; gate admission mocked, no native claim possible."""
 import os,sys
 from types import SimpleNamespace
 import scripts
 c=control();monkeypatch.setattr(c,'ALLOWED_ROOT',tmp_path)
 base=tmp_path/'base';project=base/'project';control_dir=base/'control'
 control_dir.mkdir(parents=True);(base/'tmp').mkdir();(project/'scripts').mkdir(parents=True)
 (project/'scripts/verify_cvw_ahb_startup.py').write_text('# software controller fixture\n')
 for name in ('.git','third_party/cvw_upstream_reference/.git','third_party/caliptra_upstream_reference/.git'):
  git=project/name;(git/'objects/info').mkdir(parents=True);(git/'HEAD').write_text('fixture-head\n')
 freeze=c.encoded({'software_fixture':True});(control_dir/'source-freeze.json').write_bytes(freeze)
 mapping=c.encoded(c.source_map(project));(control_dir/'source-map.json').write_bytes(mapping)
 monkeypatch.setenv('PYTHONPATH',f'{project}/src:{project}:/root/fanzehui/system-20261016/pythonlib')
 monkeypatch.setenv('PYTHONOPTIMIZE','0');monkeypatch.setenv('PYTHONDONTWRITEBYTECODE','1');monkeypatch.setenv('TMPDIR',str(base/'tmp'))
 monkeypatch.setattr(scripts,'verify_cvw_ahb_startup',SimpleNamespace(
   __file__=str(project/'scripts/verify_cvw_ahb_startup.py'),verify_freeze=lambda *a:None),raising=False)
 monkeypatch.setattr(c,'tool_file_map',lambda *a,**kw:{'explicit_software_tool_fixture':{}})
 monkeypatch.setattr(c,'profile_read_set',lambda *a,**kw:{'explicit_software_profile_fixture':'not_native'})
 real_child=c.run_child_once
 def only_software_child(directory,command,**kwargs):
  return real_child(directory,[sys.executable,'-c','import sys;sys.exit(7)'],**kwargs)
 monkeypatch.setattr(c,'run_child_once',only_software_child)
 with pytest.raises(ValueError,match='nonzero'):
  c.execute_controller(base,freeze_sha256=c.sha(freeze),source_map_sha256=c.sha(mapping))
 terminal=json.loads((control_dir/'operation.terminal.json').read_text())
 assert terminal['child']['child_pid']>0 and terminal['child']['actual_exit']==7
 assert terminal['status']=='failed' and terminal['collection_errors']==[]
 assert (control_dir/'before-source-map.json.gz').is_file()
 assert (control_dir/'after-source-map.json.gz').is_file()
 assert (control_dir/'output-map.json.gz').is_file()

def test_observation_timeout_waits_same_handle_without_kill_or_restart(tmp_path,monkeypatch):
 from types import SimpleNamespace
 c=control();instances=[]
 class Process:
  pid=123;returncode=None
  def __init__(self,args,**kw):self.args=args;self.waits=0;instances.append(self)
  def wait(self,timeout=None):
   self.waits+=1
   if self.waits==1:raise subprocess.TimeoutExpired(self.args,timeout)
   self.returncode=0;return 0
  def poll(self):return self.returncode
 def no_kill(*a,**kw):raise AssertionError('observation cannot kill actual child')
 monkeypatch.setattr(c,'subprocess',SimpleNamespace(Popen=Process,TimeoutExpired=subprocess.TimeoutExpired))
 monkeypatch.setattr(c.os,'killpg',no_kill)
 receipt=c.run_child_once(tmp_path,['software-model-child'],cwd=tmp_path,environment={})
 assert len(instances)==1 and instances[0].waits==2
 assert receipt['child_pid']==123 and receipt['actual_exit']==0
 assert receipt['observation_timeouts']==1
 live=json.loads((tmp_path/'child.observation-0001.json').read_text())
 assert live['child_pid']==123 and live['phase']=='still_live' and live['actual_exit'] is None


def test_started_receipt_failure_preserves_exception_and_waits_same_child(tmp_path,monkeypatch):
 from types import SimpleNamespace
 c=control();instances=[];failure=OSError('software receipt write fault')
 class Process:
  pid=456;returncode=None
  def __init__(self,args,**kw):self.args=args;self.waits=0;instances.append(self)
  def wait(self,timeout=None):self.waits+=1;self.returncode=7;return 7
  def poll(self):return self.returncode
 original=c.claim_state
 def claim(path,document):
  if path.name=='child.started.json':raise failure
  return original(path,document)
 monkeypatch.setattr(c,'claim_state',claim)
 monkeypatch.setattr(c,'subprocess',SimpleNamespace(Popen=Process,TimeoutExpired=subprocess.TimeoutExpired))
 monkeypatch.setattr(c.os,'killpg',lambda *a:pytest.fail('receipt failure cannot kill'))
 with pytest.raises(OSError) as caught:c.run_child_once(tmp_path,['software-model-child'],cwd=tmp_path,environment={})
 assert caught.value is failure and len(instances)==1 and instances[0].waits==1
 receipt=json.loads((tmp_path/'controller.terminal.json').read_text())
 assert receipt['child_pid']==456 and receipt['actual_exit']==7

def test_gate_archive_integrity_is_separate_from_child_exit(tmp_path):
 c=control();(tmp_path/'first.json.gz').write_bytes(b'first archive fixture')
 (tmp_path/'fresh.json.gz').write_bytes(b'fresh archive fixture')
 receipt=dict(schema_version='cvw_ahb_startup_gate_pass.v1',grade='actual_generated_native_observation_only',
   source_authority=False,retirement_verified=False,protocol_completion_certified=False,
   first_sha256=c.sha((tmp_path/'first.json.gz').read_bytes()),fresh_sha256=c.sha((tmp_path/'fresh.json.gz').read_bytes()))
 (tmp_path/'pass.json').write_bytes(c.encoded(receipt));c.validate_gate_archive(tmp_path)
 receipt['fresh_sha256']='wrong';(tmp_path/'pass.json').write_bytes(c.encoded(receipt))
 with pytest.raises(ValueError):c.validate_gate_archive(tmp_path)

def test_profile_readset_includes_real_caliptra_license_not_just_rtl():
 c=control();root=SCRIPT.parents[1]
 rows=c.profile_read_set(root,'configs/peripherals/caliptra_sha256/component_profile.json')
 assert rows['third_party/caliptra_upstream_reference/LICENSE']=='cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30'
 assert 'third_party/caliptra_upstream_reference/src/sha256/rtl/sha256_ctrl.sv' in rows

def test_real_cvw_include_readset_keeps_bounded_internal_links():
 c=control();rows=c.profile_read_set(SCRIPT.parents[1],'configs/cpus/cvw/component_profile.json')
 assert 'third_party/cvw_upstream_reference/config/rv32gc/act/link.ld' in rows
 assert 'configs/cpus/cvw/cvw_ahb_cpu_top.sv' in rows
