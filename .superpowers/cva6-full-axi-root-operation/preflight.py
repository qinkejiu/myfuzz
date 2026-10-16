import hashlib,json
from pathlib import Path
base=Path('/root/fanzehui/cva6-full-axi-observer-20261017-attempt1')
pins={'control/run-native.sh':'011524eefcacc41b09dd7646bcadd93154a09390b14555534fd194412bf4adfd',
'control/source-freeze.json':'9f2c0510e7430b8f4f11f3ef5ff058f329d586004359d88521e55557b025c130',
'project/scripts/verify_cva6_full_axi_observer.py':'4a60dd527ab412472d9d866ded9d492a870875130bd7d0fdccce9040fdd16a49'}
for n,h in pins.items():
 p=base/n
 assert not any(x.is_symlink() for x in (p,*p.parents)),n
 assert hashlib.sha256(p.read_bytes()).hexdigest()==h,n
freeze=json.loads((base/'control/source-freeze.json').read_text())
for n,h in freeze['files'].items():
 p=base/'project'/n
 assert not any(x.is_symlink() for x in (p,*p.parents)),n
 assert p.resolve().is_relative_to(base/'project'),n
 assert hashlib.sha256(p.read_bytes()).hexdigest()==h,n
assert not (base/'run').exists()
print(json.dumps({'status':'source_preflight_pass','source_files':len(freeze['files']),'pins':pins,'native_executed':False}))
