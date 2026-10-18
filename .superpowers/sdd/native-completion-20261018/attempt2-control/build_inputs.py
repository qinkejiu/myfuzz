"""Freeze local file bytes and construct reviewed pure-copy inputs; no imports of project."""
import ast, gzip, hashlib, io, json, os, stat, subprocess, tarfile
from pathlib import Path
ROOT=Path('/home/qinkejiu/myfuzz')
CONTROL=ROOT/'.superpowers/sdd/native-completion-20261018'
OUT=Path(__file__).resolve().parent
REFERENCE=OUT/'references'
BASE=json.loads((REFERENCE/'baseline-files.json').read_bytes())
DIRS=json.loads((REFERENCE/'baseline-directories.json').read_bytes())

def encoded(value):return json.dumps(value,sort_keys=True,indent=2).encode()+b'\n'
def digest(data):return hashlib.sha256(data).hexdigest()
def file_row(p):
 st=p.lstat()
 if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1:raise ValueError('not-owned-regular:'+str(p))
 data=p.read_bytes()
 return data,dict(bytes=len(data),mode=stat.S_IMODE(st.st_mode),sha256=digest(data))

all_files={};content={}
for prefix in ('src','scripts'):
 for folder,dirs,names in os.walk(ROOT/prefix,followlinks=False):
  dirs[:]=[name for name in dirs if name!='__pycache__']
  if any((Path(folder)/name).is_symlink() for name in dirs):raise ValueError('directory-symlink')
  for name in names:
   p=Path(folder)/name
   if p.suffix in ('.pyc','.pyo'):continue
   data,row=file_row(p);key=p.relative_to(ROOT).as_posix()
   all_files[key]=row;content[key]=data
old={p for p in BASE if p.startswith(('src/','scripts/'))}
if old-set(all_files):raise ValueError('unreviewed-baseline-extra-files')
overlay={p:row for p,row in all_files.items() if BASE.get(p)!=row}
overlay_dirs={}
for name in overlay:
 for parent in Path(name).parents:
  key=parent.as_posix()
  if key!='.':overlay_dirs[key]=DIRS.get(key,dict(mode=0o755))
metadata={}
for node in ast.parse(content['src/myfuzz/scenario/host_identity.py']).body:
 if isinstance(node,ast.Assign):
  for target in node.targets:
   if isinstance(target,ast.Name) and target.id in ('HOST_SOURCE_PATHS','HARNESS_HOST_SOURCE_PATHS'):
    v=node.value
    metadata[target.id]=(metadata['HOST_SOURCE_PATHS']+ast.literal_eval(v.right)
      if isinstance(v,ast.BinOp) else ast.literal_eval(v))
if len(metadata['HOST_SOURCE_PATHS'])!=34 or len(metadata['HARNESS_HOST_SOURCE_PATHS'])!=69:raise ValueError('host-count')
if len(set(metadata['HARNESS_HOST_SOURCE_PATHS']))!=69:raise ValueError('host-duplicate')
for p in metadata['HARNESS_HOST_SOURCE_PATHS']:
 if p not in all_files:raise ValueError('missing-host-file:'+p)
revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
record=dict(schema_version='native_completion_local_copy_selection.v1',source_revision=revision,
 scope='complete current src/scripts bytes over independently frozen P6 baseline; no baseline extras',
 file_count=len(all_files),overlay_count=len(overlay),host_path_count=69,
 baseline_file_map_sha256=digest((REFERENCE/'baseline-files.json').read_bytes()),
 overlay_paths=sorted(overlay),host_files={p:all_files[p] for p in metadata['HARNESS_HOST_SOURCE_PATHS']})
artifacts={'local-current-src-scripts.json':encoded(all_files),'overlay-paths.json':encoded(sorted(overlay)),
 'overlay-map.json':encoded(dict(files=dict(sorted(overlay.items())),directories=dict(sorted(overlay_dirs.items())))),
 'selection.json':encoded(record)}
for name,data in artifacts.items():
 with (OUT/name).open('xb') as f:f.write(data)
payload=dict(artifacts)
payload.update({'baseline-files.json':(REFERENCE/'baseline-files.json').read_bytes(),
 'baseline-directories.json':(REFERENCE/'baseline-directories.json').read_bytes(),
 'prepare_copy.py':(OUT/'prepare_copy.py').read_bytes()})
for name in overlay:payload['overlay/'+name]=content[name]
archive=OUT/'copy-inputs.tar.gz'
with archive.open('xb') as raw:
 with gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as gz:
  with tarfile.open(fileobj=gz,mode='w|') as tar:
   for name,row in sorted(overlay_dirs.items()):
    info=tarfile.TarInfo('overlay/'+name);info.type=tarfile.DIRTYPE;info.mode=row['mode'];tar.addfile(info)
   for name,data in sorted(payload.items()):
    info=tarfile.TarInfo(name);info.size=len(data);info.mode=(overlay[name[8:]]['mode'] if name.startswith('overlay/') else 0o644)
    tar.addfile(info,io.BytesIO(data))
pins={name:dict(bytes=len(data),sha256=digest(data)) for name,data in payload.items()}
pins['copy-inputs.tar.gz']=dict(bytes=archive.stat().st_size,sha256=digest(archive.read_bytes()))
with (OUT/'input-pins.json').open('xb') as f:f.write(encoded(pins))
print(json.dumps(dict(revision=revision,files=len(all_files),overlay_count=len(overlay),archive=pins['copy-inputs.tar.gz'],overlay_map_sha256=pins['overlay-map.json']['sha256'],overlay_paths_sha256=pins['overlay-paths.json']['sha256']),sort_keys=True))
