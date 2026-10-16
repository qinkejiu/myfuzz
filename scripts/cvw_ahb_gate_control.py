"""Source-only CVW AHB snapshot/controller plan; execution requires explicit GO.

The controller never obtains the heavy lock: the reviewed native gate is the
single lock owner. No remote connection, model or tool query occurs by default.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

SCHEMA='cvw_ahb_startup_controller_plan.v1'
ALLOWED_ROOT=Path('/root/fanzehui')
BASE=ALLOWED_ROOT/'cvw-ahb-observer-20261017-attempt1'
LOCK='/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock'
ENVIRONMENT='/root/fanzehui/system-20261016/environment.sh'


def sha(data):return hashlib.sha256(data).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def _no_links(path):
 path=Path(path).absolute()
 if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('controller path contains symlink')
 return path

def source_map(root):
 """Full independent snapshot map; bounded internal links are documentary."""
 root=_no_links(root);result={}
 def link(path):
  try:target=path.resolve(strict=True)
  except (OSError,RuntimeError) as error:raise ValueError('source link unresolved') from error
  if not target.is_relative_to(root):raise ValueError('source link escapes snapshot')
  return dict(kind='symlink',target=os.readlink(path),resolved=target.relative_to(root).as_posix())
 for directory,dirs,files in os.walk(root,followlinks=False):
  for name in dirs:
   path=Path(directory)/name
   if path.is_symlink():result[path.relative_to(root).as_posix()]=link(path)
  for name in files:
   path=Path(directory)/name;key=path.relative_to(root).as_posix()
   if path.is_symlink():result[key]=link(path);continue
   if not path.is_file():raise ValueError('source special file')
   stat=path.stat()
   if stat.st_nlink!=1:raise ValueError('source hardlink shares mutable storage')
   result[key]=dict(kind='file',sha256=sha(path.read_bytes()),bytes=stat.st_size,mode=stat.st_mode&0o777)
 return dict(sorted(result.items()))

def verify_source_map(root,expected):
 if source_map(root)!=expected:raise ValueError('exact independent source snapshot differs')

def claim_state(path,document):
 path=_no_links(path)
 with path.open('xb') as stream:
  stream.write(encoded(document));stream.flush();os.fsync(stream.fileno())


def validate_environment(base,environment):
 base=_no_links(base);project=base/'project'
 expected=f'{project}/src:{project}:/root/fanzehui/system-20261016/pythonlib'
 if (environment.get('PYTHONPATH')!=expected or environment.get('PYTHONOPTIMIZE')!='0'
     or environment.get('PYTHONDONTWRITEBYTECODE')!='1' or sys.flags.optimize!=0
     or environment.get('TMPDIR')!=str(base/'tmp') or not (base/'tmp').is_dir()):
  raise ValueError('source-first nonoptimized gate environment differs')
 _no_links(base/'tmp')


def profile_read_set(repo,profile_path):
 """Source-only copy read set includes selected lock artifacts, e.g. LICENSE."""
 repo=_no_links(repo);profile=json.loads((repo/profile_path).read_bytes());source=profile['source']
 root=repo/source['root']
 if not root.resolve().is_relative_to(repo):raise ValueError('profile root escapes independent source')
 paths={root/name for name in source['files']}
 for name in source['include_roots']:
  directory=_no_links(root/name)
  paths.update(path for path in directory.rglob('*') if path.is_file())
 lock=json.loads((repo/'configs/soc/sources.lock.json').read_bytes())
 selected=[row for row in lock['components'] if row['source'].get('root')==source['root']
           and row['source'].get('top_module')==source['top_module']]
 if len(selected)>1:raise ValueError('ambiguous selected profile lock')
 locked={}
 if selected:
  for artifact in selected[0]['artifacts']:
   path=root/artifact['path'];paths.add(path);locked[path]=artifact['sha256']
 result={}
 for path in sorted(paths):
  try:resolved=path.resolve(strict=True)
  except (OSError,RuntimeError) as error:raise ValueError('profile input link unresolved') from error
  if not path.is_relative_to(repo) or not resolved.is_relative_to(repo):
   raise ValueError('profile input escapes source snapshot')
  digest=sha(path.read_bytes())
  if path in locked and locked[path]!=digest:raise ValueError('selected source-lock artifact bytes differ')
  result[path.relative_to(repo).as_posix()]=digest
 return result


def validate_git_metadata(project):
 for name in ('.git','third_party/cvw_upstream_reference/.git','third_party/caliptra_upstream_reference/.git'):
  git=_no_links(Path(project)/name)
  if not git.is_dir() or not (git/'HEAD').is_file() or not (git/'objects').is_dir():
   raise ValueError('independent self-contained Git directory required')
  alternates=git/'objects/info/alternates'
  if alternates.exists() and alternates.read_text().strip():raise ValueError('Git alternates share external object storage')


def prepare_plan():
 return dict(schema_version=SCHEMA,source_only=True,native_run=False,
   base=str(BASE),project=str(BASE/'project'),control=str(BASE/'control'),tmp=str(BASE/'tmp'),
   canonical_heavy_lock=LOCK,lock_owner='gate_only_once_nonblocking',environment=ENVIRONMENT,
   source_freeze_status='requires_shared_source_stable_then_regeneration_and_review',
   snapshot=dict(hardlinks_allowed=False,git_preserved=True,
     nested_git=['third_party/cvw_upstream_reference','third_party/caliptra_upstream_reference'],
     strategy='independent Git metadata/file copies (or --no-hardlinks clones) plus exact reviewed working-tree overlays',
     validation='full no-link source map plus generated host/profile/closure freeze; clone HEAD alone is insufficient'),
   controller=dict(one_shot='exclusive state creation before any child',actual_child_pid=True,
     actual_exit=True,launch_environment='source-first imports; PYTHONOPTIMIZE=0',
     source_maps='full before and after, including Git metadata; differences are retained',
     archives=['original startup pages','all original CPU thirteen-role samples','all target receipts/raw',
       'observer and Runner once-only stream','first/fresh full prefixes','both binary/cache identities',
       'actual process READY/close/reap','allowed-wrapper tool hashes']),
   authorization=dict(remote_preparation=False,tool_query=False,build=False,elaboration=False,model=False,native=False))


def run_child_once(control,command,*,cwd,environment,observation_timeout_seconds=60):
 """Observe one actual child to exit; observation errors never kill/restart it."""
 control=_no_links(control);_no_links(cwd)
 if not control.is_dir():raise ValueError('control directory must already exist')
 names=('controller.claim.json','child.started.json','controller.terminal.json','child.stdout','child.stderr')
 for name in names:
  path=control/name
  if path.exists() or path.is_symlink():raise FileExistsError(str(path))
 claim_state(control/'controller.claim.json',dict(schema_version='one_shot_child_claim.v1',
   controller_pid=os.getpid(),command=command,cwd=str(cwd),phase='claimed',
   environment_sha256=sha(encoded(environment))))
 process=None;error=None;collection_errors=[];timeouts=0;observation=0
 def note(name,document):
  nonlocal error
  try:claim_state(control/name,document)
  except BaseException as exc:
   if error is None:error=exc
   collection_errors.append(dict(stage=name,type=type(exc).__name__,detail=str(exc)))
 with (control/'child.stdout').open('xb') as output,(control/'child.stderr').open('xb') as errors:
  try:process=subprocess.Popen(command,cwd=cwd,env=environment,stdout=output,stderr=errors,start_new_session=True)
  except BaseException as exc:error=exc
  if process is not None:
   note('child.started.json',dict(controller_pid=os.getpid(),child_pid=process.pid,
       command=list(process.args),phase='started'))
   def observed_poll():
    nonlocal error
    try:return process.poll()
    except BaseException as exc:
     if error is None:error=exc
     collection_errors.append(dict(stage='child_poll',type=type(exc).__name__,detail=str(exc)))
     return None
   while process.returncode is None:
    try:process.wait(timeout=observation_timeout_seconds)
    except subprocess.TimeoutExpired:
     timeouts+=1;observation+=1
     observed_exit=observed_poll()
     note(f'child.observation-{observation:04d}.json',dict(controller_pid=os.getpid(),
        child_pid=process.pid,phase='still_live' if observed_exit is None else 'exited_during_observation',actual_exit=observed_exit,
        observation_timeouts=timeouts,action='continue_observing_same_handle'))
    except BaseException as exc:
     if error is None:error=exc
     observation+=1
     note(f'child.observation-{observation:04d}.json',dict(controller_pid=os.getpid(),
        child_pid=process.pid,phase='observation_error',actual_exit=observed_poll(),
        error_type=type(exc).__name__,detail=str(exc),action='continue_observing_same_handle'))
 terminal=dict(schema_version='one_shot_child_terminal.v1',grade='child_lifecycle_only',
     controller_pid=os.getpid(),child_pid=None if process is None else process.pid,
     actual_exit=None if process is None else process.returncode,
     poll_after_wait=None if process is None else observed_poll(),command=command,
     status='spawn_failed' if process is None else 'exited_collection_error' if error is not None else 'exited',
     observation_timeouts=timeouts,collection_errors=collection_errors,
     error=None if error is None else dict(type=type(error).__name__,detail=str(error)))
 claim_state(control/'controller.terminal.json',terminal)
 if error is not None:raise error
 return terminal


def tool_file_map(paths,*,allowed_root=Path('/root/fanzehui')):
 allowed_root=_no_links(allowed_root);result={}
 for name in paths:
  path=Path(name)
  if not path.is_absolute() or not path.is_relative_to(allowed_root):
   result[name]=dict(grade='environment_dependency_only',file_not_read=True);continue
  path=_no_links(path)
  if not path.is_file():raise ValueError('allowed wrapper/tool file missing')
  result[name]=dict(grade='allowed_wrapper_file_hash',sha256=sha(path.read_bytes()),bytes=path.stat().st_size)
 return result


def source_differences(before,after):
 return sorted(name for name in set(before)|set(after) if before.get(name)!=after.get(name))


def require_code_unchanged(before,after):
 changes=source_differences(before,after)
 git_prefixes=('.git/','third_party/cvw_upstream_reference/.git/',
               'third_party/caliptra_upstream_reference/.git/')
 if any(not name.startswith(git_prefixes) for name in changes):
  raise ValueError('source code changed during actual gate')
 return changes


def _write_gzip(path,document):
 import gzip
 path=_no_links(path)
 with path.open('xb') as stream:
  with gzip.GzipFile(fileobj=stream,mode='wb',mtime=0) as output:output.write(encoded(document))
 return sha(path.read_bytes())


def validate_gate_archive(run):
 run=_no_links(run);receipt=json.loads((run/'pass.json').read_bytes())
 if (receipt.get('schema_version')!='cvw_ahb_startup_gate_pass.v1'
     or receipt.get('grade')!='actual_generated_native_observation_only'
     or any(receipt.get(key) is not False for key in ('source_authority','retirement_verified','protocol_completion_certified'))):
  raise ValueError('gate archive declaration differs')
 for name in ('first','fresh'):
  path=_no_links(run/(name+'.json.gz'))
  if sha(path.read_bytes())!=receipt.get(name+'_sha256'):raise ValueError('gate raw archive SHA differs')
 return receipt


def execute_controller(base,*,freeze_sha256,source_map_sha256):
 """Future explicitly authorized controller; never reachable from default mode."""
 base=_no_links(base)
 if not base.is_relative_to(ALLOWED_ROOT) or base==ALLOWED_ROOT:
  raise ValueError('controller base outside allowed independent root')
 project=base/'project';control=base/'control'
 if not project.is_dir() or not control.is_dir() or (base/'run').exists():
  raise ValueError('new independent prepared controller layout required')
 claim_state(control/'operation.claim.json',dict(controller_pid=os.getpid(),phase='preflight',
    gate_heavy_lock_owner='gate_only_once_nonblocking'))
 before=None;before_tools=None;child=None;error=None;collection_errors=[];terminal=None
 try:
  validate_environment(base,os.environ)
  from scripts import verify_cvw_ahb_startup as gate
  if Path(gate.__file__).resolve()!=project/'scripts/verify_cvw_ahb_startup.py':
   raise ValueError('source-first gate module came from another checkout')
  freeze=control/'source-freeze.json';raw=freeze.read_bytes()
  if sha(raw)!=freeze_sha256:raise ValueError('reviewed host freeze SHA mismatch')
  gate.verify_freeze(project,json.loads(raw))
  expected_raw=(control/'source-map.json').read_bytes()
  if sha(expected_raw)!=source_map_sha256:raise ValueError('reviewed complete snapshot map SHA mismatch')
  expected=json.loads(expected_raw);validate_git_metadata(project);verify_source_map(project,expected)
  for profile in ('configs/cpus/cvw/component_profile.json',
                  'configs/peripherals/caliptra_sha256/component_profile.json'):
   profile_read_set(project,profile)
  before=source_map(project);_write_gzip(control/'before-source-map.json.gz',before)
  tools=['/root/fanzehui/system-20261016/bin/c++',
         '/root/fanzehui/myfuzz/.tools/verilator-5.051-e413e67/bin/verilator']
  before_tools=tool_file_map(tools)
  claim_state(control/'before-tools.json',dict(files=before_tools,
    environment_dependency_only={'AR':'/usr/bin/x86_64-linux-gnu-ar','file_not_read':True},
    selection_authority='actual generated build manifests; these are prior approved wrapper bytes only',
    environment={key:os.environ.get(key) for key in ('PATH','CXX','LINK','AR','VERILATOR_ROOT',
       'PYTHONPATH','PYTHONOPTIMIZE','PYTHONDONTWRITEBYTECODE','TMPDIR')}))
  command=[sys.executable,str(project/'scripts/verify_cvw_ahb_startup.py'),'--run-native',
    '--repo',str(project),'--output',str(base/'run'),'--heavy-lock',LOCK,
    '--freeze',str(freeze),'--freeze-sha256',freeze_sha256]
  child=run_child_once(control,command,cwd=project,environment=dict(os.environ))
  if child['actual_exit']!=0:raise ValueError('actual gate child exited nonzero')
  validate_gate_archive(base/'run')
 except BaseException as exc:error=exc
 finally:
  after=None;after_tools=None;after_sha=None;output_sha=None;changes=None
  try:
   after=source_map(project);after_sha=_write_gzip(control/'after-source-map.json.gz',after)
   if before is not None:
    changes=source_differences(before,after);require_code_unchanged(before,after)
  except Exception as exc:collection_errors.append(dict(stage='source_after',type=type(exc).__name__,detail=str(exc)))
  if before_tools is not None:
   try:
    after_tools=tool_file_map(tools);claim_state(control/'after-tools.json',after_tools)
    if before_tools!=after_tools:raise ValueError('allowed tool wrapper bytes changed')
   except Exception as exc:collection_errors.append(dict(stage='tools_after',type=type(exc).__name__,detail=str(exc)))
  try:
   outputs=source_map(base/'run') if (base/'run').is_dir() else {}
   output_sha=_write_gzip(control/'output-map.json.gz',outputs)
   if child is None and (control/'controller.terminal.json').is_file():
    child=json.loads((control/'controller.terminal.json').read_bytes())
  except Exception as exc:collection_errors.append(dict(stage='output_after',type=type(exc).__name__,detail=str(exc)))
  terminal=dict(schema_version='cvw_ahb_gate_controller_terminal.v1',
      controller_pid=os.getpid(),child=child,
      status='complete' if error is None and not collection_errors else 'failed',
      error=None if error is None else dict(type=type(error).__name__,detail=str(error)),
      collection_errors=collection_errors,full_before_after_changes=changes,
      tools_unchanged=None if before_tools is None or after_tools is None else before_tools==after_tools,
      after_source_map_sha256=after_sha,output_map_sha256=output_sha,
      source_authority=False,retirement_verified=False,
      note='Actual native evidence, if any, is exclusively the original gate archives.')
  claim_state(control/'operation.terminal.json',terminal)
 if error is not None:raise error
 if collection_errors:raise ValueError('controller post-run collection/immutability check failed')
 return terminal


def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--write-plan',type=Path)
 parser.add_argument('--execute',action='store_true')
 parser.add_argument('--base',type=Path,default=BASE)
 parser.add_argument('--freeze-sha256');parser.add_argument('--source-map-sha256')
 args=parser.parse_args(argv)
 if args.execute:
  if args.write_plan or not args.freeze_sha256 or not args.source_map_sha256:
   parser.error('explicit execution requires exact reviewed host freeze and complete snapshot map hashes')
  execute_controller(args.base,freeze_sha256=args.freeze_sha256,source_map_sha256=args.source_map_sha256)
  return 0
 document=prepare_plan()
 if args.write_plan:claim_state(args.write_plan,document)
 else:print(encoded(document).decode(),end='')
 return 0

if __name__=='__main__':raise SystemExit(main())
