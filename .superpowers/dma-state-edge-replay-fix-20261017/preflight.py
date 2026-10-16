import hashlib
import json
from pathlib import Path

root = Path('/root/fanzehui/system-20261016/dma-continuous-verification-20261017')
old, new = root / 'attempt4-project', root / 'attempt5-project'
receipt = json.loads((root / 'attempt5/root-fix-receipt.json').read_text())


def hashes(project):
    return {str(p.relative_to(project)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((project / 'src/myfuzz').rglob('*.py'))}


before, after = hashes(old), hashes(new)
changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
assert changed == ['src/myfuzz/integration/dma_uart_rx_runtime.py'], changed
for name, expected in receipt['source_sha256'].items():
    assert not (new / name).is_symlink()
    assert hashlib.sha256((new / name).read_bytes()).hexdigest() == expected, name
assert (old / changed[0]).stat().st_ino != (new / changed[0]).stat().st_ino
report = dict(scope='independent snapshot with only reviewed DMA module overlay',
              source_files=after, changed_source_files=changed,
              test_sha256=receipt['source_sha256']['tests/integration/test_dma_uart_rx_replay_state_edges.py'],
              worker_sha256=hashlib.sha256((root / 'attempt5/worker.sh').read_bytes()).hexdigest(),
              source_commit='9125484', pass_preflight=True)
(root / 'attempt5/source-preflight.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps({'pass': True, 'source_files': len(after), 'changed': changed,
                  'worker_sha256': report['worker_sha256']}))
