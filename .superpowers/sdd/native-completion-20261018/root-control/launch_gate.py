"""Root-selected one actual native observation gate; never restarts on timeout."""
import datetime,hashlib,json,shlex,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
argv=['bash','/root/fanzehui/myfuzz/operations/p6-native-completion-inputs-20261018-attempt1/launch-native-gate.sh',
 '94de100ab2ab50f3674f179378c9138d73cec873c68ae401bc43f9cb63e76cd1',
 '3efbfeb6c6e84169e9230d360478ca6a7d9613c39f76a38652013cc8b6293003',
 '861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36']
remote=' '.join(shlex.quote(x) for x in argv)
ssh=['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote(remote)]
now=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat()
record=dict(schema_version='native_completion_actual_gate_root_launch.v1',argv=argv,started_at=now(),source_freeze=argv[2],source_revision='acc47fe9a2b169e56e873821e27968a47e80ed08',restart_policy='never_restart_on_observation_timeout')
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
