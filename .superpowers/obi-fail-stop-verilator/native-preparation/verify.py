import hashlib,json
from pathlib import Path
base=Path('/root/fanzehui/obi-fail-stop-verilator-20261017-434a4e8')
expected=json.loads((base/'source-manifest.json').read_text())
actual={}
for rel,digest in expected.items():
 p=base/'project'/rel
 assert not any(v.is_symlink() for v in (p,*p.parents)),rel
 assert p.stat().st_nlink==1,rel
 actual[rel]=hashlib.sha256(p.read_bytes()).hexdigest()
assert actual==expected,(actual,expected)
print(json.dumps({'source_match':True,'files':actual,'native_executed':False}))
