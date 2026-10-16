import hashlib,json
from pathlib import Path
base=Path('/root/fanzehui/boom-irq-factory-fix-20261017')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
manifest=base/'artifact-finalized/irq-session-artifact.json'
binary=base/'artifact-finalized/obj/VBoomTile'
factory=base/'project-finalized/src/myfuzz/scenario/boom_gpio_irq_runner.py'
assert sha(manifest)=='3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d'
assert sha(binary)=='6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90'
assert sha(factory)=='0af5037e8282c232c672a0251e2c8f579d4f1f6edde793bc51e20854f8f1e77e'
assert (base/'state/worker.exit').read_text().strip()=='0'
assert not (base/'artifact-finalized/.recovery-incomplete.json').exists()
assert not (base/'artifact-finalized/.irq-session-artifact.pending').exists()
print(json.dumps({'actual_new_manifest_sha256':sha(manifest),'actual_new_binary_sha256':sha(binary),'actual_host_factory_sha256':sha(factory),'worker_exit':0,'incomplete_and_pending_absent':True}))
