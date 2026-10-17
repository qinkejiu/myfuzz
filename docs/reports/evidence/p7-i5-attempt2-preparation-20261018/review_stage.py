import subprocess,tarfile,json,hashlib
from pathlib import Path
b=Path('/tmp/p7-i5-root-control-20261018')
with (b/'remote-stage-control.tar.gz').open('xb') as f:r=subprocess.run(['ssh','jumpserver','ssh root@192.168.5.70 tar -C /root/fanzehui/myfuzz/operations/p7-i5-independent-601964f-20261018-attempt2/control -czf - .'],stdout=f,stderr=subprocess.PIPE)
(b/'stage-download.stderr').write_bytes(r.stderr)
if r.returncode:raise SystemExit(r.returncode)
with tarfile.open(b/'remote-stage-control.tar.gz','r:gz') as t:d={m.name.removeprefix('./'):t.extractfile(m).read() for m in t.getmembers() if m.isfile()}
x=json.loads(d['selection-v2.json']);old=json.loads(Path('/tmp/myfuzz-independent-preparation-20261018/ready-freeze.json').read_bytes());prep=Path('/home/qinkejiu/myfuzz/scripts/prepare_p7_i5_snapshot.py');old['scripts/prepare_p7_i5_snapshot.py']={'bytes':prep.stat().st_size,'mode':420,'sha256':hashlib.sha256(prep.read_bytes()).hexdigest()}
if x['files']!=old:raise ValueError('actual-plan-file-map-not-reviewed-overlay')
if x['schema_version']!='p7_i5_snapshot_selection.v2' or x['generated_files'] or x['generated_directories']:raise ValueError('unexpected-selection-schema-or-generation')
source=json.loads(d['stage-plan-source-before-directories.json']);repairs=json.loads((b/'directory-repairs.json').read_bytes());expected={**source,**{k:{'mode':v['mode']} for k,v in repairs.items()}}
if expected!=x['directories']:raise ValueError('directory-repair-layout-differs')
for kind in ('files','directories'):
 if d['stage-plan-source-before-'+kind+'.json']!=d['stage-plan-source-after-'+kind+'.json']:raise ValueError('original-source-drift')
sha=hashlib.sha256(d['selection-v2.json']).hexdigest()
if sha!='1227ac39a03200b6646bbc1ca91a24ae748c6c8600cd2cf6675530f82b333e55':raise ValueError('reported-selection-SHA-differs')
report={'status':'selection_reviewed_for_explicit_preparation','selection_sha256':sha,'files':len(x['files']),'directories':len(x['directories']),'bytes':sum(v['bytes'] for v in x['files'].values()),'source':x['source'],'destination':x['destination'],'git_head_files':x['git_head_files'],'original_source_unchanged':True,'formal_p7_complete':False}
(b/'stage-independent-review.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
