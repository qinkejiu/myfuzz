"""UNEXECUTED collector source: read-only terminal capture, no Git/tool calls.

Streams a tar.gz on stdout. Do not invoke before review/explicit authorization.
All new clean/stage metadata, including every .rev/info object-store file,
are retained. Old quarantine/source trees are inventoried but never archived.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

CONTROLLER = 'fc5faa4abc0bccd561a6ebfea2e779b32b8cdde09ef534bed75c0013ce4ff276'
SOURCES = {'opentitan':'third_party/soc-opentitan','ibex':'third_party/rfuzz/upstream/ibex'}
ALLOWED = Path('/root/fanzehui')


def safe(path):
    assert path.is_absolute() and path.is_relative_to(ALLOWED) and '..' not in path.parts
    assert not any(p.is_symlink() for p in (path,*path.parents))
    return path


def file_sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def maps(root, working=True):
    safe(root); files,dirs={},{}
    for folder,children,names in os.walk(root,followlinks=False):
        for name in list(children):
            path=Path(folder)/name; info=path.lstat()
            if stat.S_ISLNK(info.st_mode):children.remove(name);names.append(name)
            else:
                assert stat.S_ISDIR(info.st_mode)
                dirs[path.relative_to(root).as_posix()]=dict(mode=stat.S_IMODE(info.st_mode))
        for name in names:
            path=Path(folder)/name;info=path.lstat();relative=path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                assert working and relative!='.git' and not relative.startswith('.git/')
                raw=os.fsencode(os.readlink(path))
                files[relative]=dict(kind='symlink',bytes=len(raw),mode=stat.S_IMODE(info.st_mode),
                                     linkbytes_hex=raw.hex(),sha256=hashlib.sha256(raw).hexdigest())
            else:
                assert stat.S_ISREG(info.st_mode)
                files[relative]=dict(kind='regular',bytes=info.st_size,mode=stat.S_IMODE(info.st_mode),sha256=file_sha(path))
    return files,dirs


def read_json(path):return json.loads(path.read_bytes())


def collect(component,base,inputs):
    safe(base);safe(inputs)
    assert base.parent==inputs.parent==Path('/root/fanzehui/myfuzz/operations')
    assert base.name.startswith('p8-source-'+component+'-metadata-') and inputs.name.startswith('p8-source-metadata-inputs-')
    parent=read_json(base/'control/parent-terminal.json')
    assert parent['returncode']==0 and parent['component']==component and parent['controller_sha256']==CONTROLLER
    assert file_sha(safe(inputs/'materialize_snapshot_reconstructed.py'))==CONTROLLER
    source=ALLOWED/'myfuzz/project'/SOURCES[component];stage=base/'stage';clean=base/'clean.git'
    source_files,source_dirs=maps(source);stage_files,stage_dirs=maps(stage);clean_files,clean_dirs=maps(clean,False)
    control=base/'control'
    assert source_files==read_json(control/'source-before-files.json')==read_json(control/'source-after-files.json')
    assert source_dirs==read_json(control/'source-before-directories.json')==read_json(control/'source-after-directories.json')
    assert stage_files==read_json(control/'stage-files.json') and stage_dirs==read_json(control/'stage-directories.json')
    final=read_json(control/'missing-pinned-files-reconstruction.json')
    missing=set(read_json(control/'missing-pinned-files-plan.json'))
    assert set(final)==missing
    # The independent auditor later re-derives this selection from binary trees.
    captured={};regular_payloads=[];synthetic={}
    for name in sorted(missing):
        relative=PurePosixPath(name)
        assert relative.parts and not relative.is_absolute() and '..' not in relative.parts and str(relative)==name
        path=stage/name;safe(path.parent);row=stage_files[name];captured[name]=row
        if row['kind']=='symlink':
            info=path.lstat();assert stat.S_ISLNK(info.st_mode)
            raw=os.fsencode(os.readlink(path));assert raw.hex()==row['linkbytes_hex']
            synthetic['recovered-stage-bytes/'+name]=raw
        else:
            safe(path);assert path.stat().st_size==row['bytes'] and file_sha(path)==row['sha256']
            regular_payloads.append(('recovered-stage-bytes/'+name,path))
    children=[read_json(path) for path in sorted(control.glob('child-*.terminal.json'))]
    assert len(children)==parent['children'] and all(row['returncode']==0 for row in children)
    observation=dict(collected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        remote_operation=str(base),remote_inputs=str(inputs),component=component,parent_pid=parent['pid'],
        parent_proc_present=Path('/proc',str(parent['pid'])).exists(),actual_children=len(children),
        actual_source_matches_beforeafter=True,actual_stage_matches_saved=True,
        current_clean_store_inventoried=True,missing_stage_payloads_captured=len(captured),
        link_targets_followed=False,remote_read_only=True,git_models_or_network_fallback_reexecuted=False)
    for name,value in {'source-files':source_files,'source-directories':source_dirs,'stage-files':stage_files,
                       'stage-directories':stage_dirs,'clean-files':clean_files,'clean-directories':clean_dirs,
                       'collection':observation,'recovered-stage-captures':captured}.items():
        synthetic['observed/'+name+'.json']=json.dumps(value,sort_keys=True,indent=2).encode()+b'\n'
    members=[]
    for prefix,root in (('control',control),('metadata/clean',clean),('metadata/stage-git',stage/'.git')):
        safe(root)
        for path in [root,*sorted(root.rglob('*'))]:
            safe(path);info=path.lstat();assert stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            suffix=path.relative_to(root).as_posix()
            members.append((prefix+('/'+suffix if suffix!='.' else ''),path))
    for name in ('materialize_snapshot_reconstructed.py','selected-launch.json','parent.stdout','parent.stderr'):
        members.append(('inputs/'+name,safe(inputs/name)))
    members+=regular_payloads
    with tarfile.open(fileobj=sys.stdout.buffer,mode='w|gz') as tar:
        seen=set()
        for name,path in members:
            assert name not in seen;seen.add(name);info=tar.gettarinfo(str(path),arcname=name)
            assert info.isfile() or info.isdir()
            if info.isfile():
                with path.open('rb') as stream:tar.addfile(info,stream)
            else:tar.addfile(info)
        for name,raw in synthetic.items():
            assert name not in seen;seen.add(name);info=tarfile.TarInfo(name);info.size=len(raw);tar.addfile(info,io.BytesIO(raw))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component',choices=sorted(SOURCES),required=True)
    parser.add_argument('--operation',type=Path,required=True)
    parser.add_argument('--inputs',type=Path,required=True)
    args=parser.parse_args();collect(args.component,args.operation,args.inputs)
