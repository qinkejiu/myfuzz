"""Read-only terminal artifact fetch, never a launcher or model invocation."""
from pathlib import Path
import subprocess,shlex,hashlib,json,sys
BASE='/root/fanzehui/cvw-ahb-observer-20261017-attempt1'
code=r'''
from pathlib import Path
import json,sys,tarfile
base=Path('/root/fanzehui/cvw-ahb-observer-20261017-attempt1')
control=base/'control'
claim=json.loads((control/'controller.claim.json').read_bytes())
started=json.loads((control/'child.started.json').read_bytes())
terminal=json.loads((control/'controller.terminal.json').read_bytes())
operation=json.loads((control/'operation.terminal.json').read_bytes())
assert claim['controller_pid']==started['controller_pid']==terminal['controller_pid']==operation['controller_pid']==272511
assert started['child_pid']==terminal['child_pid']==272523
assert terminal['actual_exit'] is not None
paths=[path for path in sorted(base.iterdir()) if path.name not in ('project','prepared-source-control.tar.gz')]
with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz',compresslevel=1,dereference=False) as archive:
 for path in paths:archive.add(path,arcname=path.name,recursive=True)
'''
if sys.argv[1:]!=['--fetch']:
 print('Prepared only; --fetch requires already observed terminal for same controller272511/child272523.')
 raise SystemExit(0)
root=Path('/home/qinkejiu/myfuzz/docs/reports/evidence/cvw-ahb-native-20261017');root.mkdir()
archive=root/'terminal-originals.tar.gz'
command='cd '+BASE+' && '+shlex.join(['python3','-c',code])
with archive.open('xb') as output:
 process=subprocess.Popen(['ssh','jumpserver','ssh root@192.168.5.70 '+shlex.quote(command)],stdout=output,stderr=subprocess.PIPE)
 error=process.communicate()[1]
(root/'archive-fetch.stderr').write_bytes(error)
receipt={'archive':archive.name,'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'actual_ssh_exit':process.returncode,'remote_base':BASE,'bound_controller_pid':272511,'bound_child_pid':272523,'operation':'read_only_terminal_archive_fetch','excluded_preserved_originals':['project','prepared-source-control.tar.gz']}
(root/'archive-fetch-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt),flush=True)
raise SystemExit(process.returncode)
