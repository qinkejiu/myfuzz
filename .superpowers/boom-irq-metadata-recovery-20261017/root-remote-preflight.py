import hashlib,json
from pathlib import Path
base=Path("/root/fanzehui/boom-irq-metadata-recovery-20261017")
expected_ready='566b4c8be6bbe50e4a6ff52d340e243ee5c700022c430772ab3419c8344e0017'
assert hashlib.sha256((base/"ready.json").read_bytes()).hexdigest()==expected_ready
r=json.loads((base/"ready.json").read_text())
for n,h in r["control_hashes"].items():
 p=base/n
 assert not any(v.is_symlink() for v in (p,*p.parents)),n
 assert hashlib.sha256(p.read_bytes()).hexdigest()==h,n
for n in ("state/PID","state/launcher-PID","state/worker.exit","state/operation.claim","project-finalized","artifact-finalized"):
 p=base/n
 assert not p.exists() and not p.is_symlink(),n
print(json.dumps({"ready_sha256":expected_ready,"control_hashes_match":True,"claimed_or_started":False,"future_destinations_absent":True,"model_executed":False}))
