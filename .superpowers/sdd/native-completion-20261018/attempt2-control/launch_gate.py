"""Root-selected one actual native observation gate; never restarts on timeout."""
import datetime,hashlib,json,shlex,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
argv=['bash','/root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt2/launch-native-gate.sh',
 '3c287137bfa7e98c6b28444b20b26fa2e6ab25d6a01c2262594408fa380e44be',
 '35704ba49d94e5a6e2ed59d60e365a618445a8687f18dd47530845ddfae11080',
 '861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36']
remote=' '.join(shlex.quote(x) for x in argv)
ssh=['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote(remote)]
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
record=dict(schema_version='native_completion_actual_gate_root_launch.v1',argv=argv,started_at=now(),source_freeze=argv[2],source_revision='68f81b6adfb72d201a47804b26ca57a78a3d1fba',restart_policy='never_restart_on_observation_timeout')
with (HERE/'gate-launch.stdout').open('xb') as out,(HERE/'gate-launch.stderr').open('xb') as err:
 p=subprocess.Popen(ssh,stdin=subprocess.DEVNULL,stdout=out,stderr=err)
 record['ssh_pid']=p.pid
 primary=None
 try:
  with (HERE/'gate-launch-start.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
 except BaseException as error:primary=error
 finally:
  while True:
   try:record['returncode']=p.wait(timeout=30);break
   except subprocess.TimeoutExpired:continue
   except BaseException as error:
    if primary is None:primary=error
record['ended_at']=now()
if primary is not None:record['primary_error']=repr(primary)
for name in ('gate-launch.stdout','gate-launch.stderr'):
 data=(HERE/name).read_bytes();record[name]=dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
with (HERE/'gate-launch-terminal.json').open('x') as f:json.dump(record,f,sort_keys=True,indent=2)
print(json.dumps(record,sort_keys=True))
if primary is not None:raise primary
raise SystemExit(record['returncode'])
