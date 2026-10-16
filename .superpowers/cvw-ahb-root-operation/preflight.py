import sys
sys.dont_write_bytecode=True
import hashlib,json,importlib.util,fcntl,os
from pathlib import Path
base=Path('/root/fanzehui/cvw-ahb-observer-20261017-attempt1');control=base/'control';project=base/'project'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(control/'ready.json')=='5cff1fcf5c9ea37821e273c25aa6857eb3dad18db6ec26c097b931b95d04b105'
ready=json.loads((control/'ready.json').read_bytes())
assert ready['source_map_sha256']=='75244d6c7b7e6490ece1c70c20d3e143f9791804dd8f2a247f6e4d088af0dce9'
assert ready['source_freeze_sha256']=='c02134412a742eccde99746af5487f81c2f77f09a7cf20250ce37f2077762e8f'
assert ready['operation_state']=='unused' and ready['prepared_pid']==272111
assert all(ready[k] is False for k in ('constructor_called','frontend_run','tool_version_query','build_run','model_run','native_run'))
assert ready['source_before_after_equal'] and ready['control_before_after_equal'] and ready['tools_before_after_equal']
assert ready['control_before']==ready['control_after']
assert sha(control/'cvw_ahb_gate_control.py')=='bb1b121327b52ae26e4b64d57d5b5cd5676c7ae3f1a208d891a3009e622f9ebd'
assert sha(control/'run-controlled.sh')=='ce931d7ba7ffe2391b3fc155056402d95178349078a764d5168e873801867a1f'
spec=importlib.util.spec_from_file_location('reviewed_cvw_control',control/'cvw_ahb_gate_control.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
actual=c.source_map(control);del actual['ready.json'];assert actual==ready['control_before']
assert sha(control/'source-map.json')==ready['source_map_sha256']
assert sha(control/'source-freeze.json')==ready['source_freeze_sha256']
expected=json.loads((control/'source-map.json').read_bytes());c.verify_source_map(project,expected);c.validate_git_metadata(project)
freeze=json.loads((control/'source-freeze.json').read_bytes());assert len(freeze['files'])==335
for n,h in freeze['files'].items():assert sha(project/n)==h,n
for name,expected_readset in ready['profile_readsets'].items():assert c.profile_read_set(project,name)==expected_readset
for name,info in ready['tools'].items():assert sha(Path(name))==info['sha256']
assert not (base/'run').exists()
for n in ('operation.claim.json','operation.terminal.json','controller.claim.json','child.started.json','controller.terminal.json','child.stdout','child.stderr','launcher.log','launcher-PID'):
 p=control/n;assert not p.exists() and not p.is_symlink(),n
with Path(ready['canonical_heavy_lock']).open('rb') as stream:
 fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print(json.dumps(dict(root_preflight='pass',ready_sha256=sha(control/'ready.json'),source_entries=len(expected),host_pins=len(freeze['files']),control_pins=len(actual),full_source_bytes_modes_links_match=True,profile_readsets={n:len(v) for n,v in ready['profile_readsets'].items()},native_operation_unused=True,canonical_lock_nonblocking_probe=0)))
