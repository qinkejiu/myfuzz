import sys
sys.dont_write_bytecode=True
import hashlib,json,importlib.util
from pathlib import Path
p=Path('/root/fanzehui/cvw-ahb-observer-20261017-attempt1/control');r=json.loads((p/'ready.json').read_bytes())
spec=importlib.util.spec_from_file_location('c',p/'cvw_ahb_gate_control.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
a=c.source_map(p);a.pop('ready.json')
print(json.dumps({n:{'expected':r['control_before'].get(n),'actual':a.get(n)} for n in set(a)|set(r['control_before']) if a.get(n)!=r['control_before'].get(n)},indent=2))
