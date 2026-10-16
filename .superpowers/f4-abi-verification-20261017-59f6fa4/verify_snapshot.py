from pathlib import Path
from hashlib import sha256
import json,sys
base=Path(__file__).resolve().parent;root=base/'project'
expected=json.loads((base/'source_manifest.json').read_text())
actual={str(p.relative_to(root)):sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob('*')) if p.is_file() and '__pycache__' not in p.parts
        and '.pytest_cache' not in p.parts}
links={str(p.relative_to(root)):str(p.readlink()) for p in sorted(root.rglob('*')) if p.is_symlink()}
wrong=sorted(k for k in set(actual)|set(expected['files']) if actual.get(k)!=expected['files'].get(k))
result=dict(matches=not wrong and links==expected['symlinks'],mismatches=wrong,
    symlinks_match=links==expected['symlinks'],file_count=len(actual))
print(json.dumps(result,sort_keys=True))
if not result['matches']:raise SystemExit(2)
