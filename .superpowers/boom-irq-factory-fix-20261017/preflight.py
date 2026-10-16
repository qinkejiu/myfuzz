"""Read-only unused-state/hash preflight. No recovery or package imports."""
import hashlib,json,sys
from pathlib import Path
BASE=Path('/root/fanzehui/boom-irq-factory-fix-20261017')
EXPECTED='20ad6eb738b67db8640f7e21299259fbc04f017f948960eddfa306e1dee0d211'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
if sys.flags.optimize!=0:raise ValueError('PYTHONOPTIMIZE must be0')
if sha(BASE/'ready.json')!=EXPECTED:raise ValueError('root approved ready SHA differs')
ready=json.loads((BASE/'ready.json').read_text())
for name,value in ready['control_hashes'].items():
 p=BASE/name
 if any(x.is_symlink() for x in (p,*p.parents)) or sha(p)!=value:raise ValueError('control receipt drift: '+name)
for name in ('state/PID','state/launcher-PID','state/worker.exit','state/operation.claim','state/stage','state/imports.json','project-finalized','artifact-finalized'):
 p=BASE/name
 if p.exists() or p.is_symlink():raise ValueError('metadata state already used: '+name)
print(json.dumps(dict(ready_sha256=EXPECTED,all_control_hashes_match=True,operation_unused=True,optimize=sys.flags.optimize,
    future_metadata_stage_version_query=True,model_executed=False)))
