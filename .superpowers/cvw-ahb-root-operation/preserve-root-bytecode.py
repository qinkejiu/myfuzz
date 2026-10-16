import hashlib,json,shutil
from pathlib import Path
base=Path('/root/fanzehui/cvw-ahb-observer-20261017-attempt1')
p=base/'control/__pycache__/cvw_ahb_gate_control.cpython-312.pyc'
assert p.is_relative_to(base) and all(not q.is_symlink() for q in (p,*p.parents)) and p.stat().st_nlink==1
raw=p.read_bytes();assert hashlib.sha256(raw).hexdigest()=='2479a0e049dccb20f13c216a41adf6ef871074dc322eb3bcfe0ba6e727d51238'
out=base/'root-preflight-bytecode';out.mkdir()
shutil.copy2(p,out/p.name);assert (out/p.name).read_bytes()==raw
receipt=dict(origin='root independent stdlib import omitted dont_write_bytecode before import',file=str(p),sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),preserved=str(out/p.name),model_executed=False)
with (out/'receipt.json').open('x') as f:json.dump(receipt,f,indent=2)
p.unlink();p.parent.rmdir();print(json.dumps(receipt))
