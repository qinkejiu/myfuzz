"""Narrow, pinned attempt2 metadata recovery. Never builds or executes a model.

Archive pins bind local historical integrity; they are not signed provenance,
source authority, instruction retirement evidence, or an IRQ runtime gate.
"""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import tempfile

from .boom_irq_contract import validate_probe_inventory

ARCHIVES = {
    'attempt2-evidence.tar.gz':'559b5faf59607120ffabb59dc1ada694da9cf365b263e967d3cac154d3fee58a',
    'attempt2-build-closure.tar.gz':'e9a019a75fa4518cd620dc0519ce680b70d9c8c5ab5ba9c12ef1fbcc39082577',
    'attempt2-command-tool.tar.gz':'0fa6d68c4e70195e382a01e255a84952a5e200aea29c20c96cebe2e47a1133ec',
}
OLD_OUTPUT=Path('/root/fanzehui/boom-irq-verification-20261017/artifact')
RTL=('EICG_wrapper.v','chipyard.TestHarness.SmallBoomConfig.top.mems.v',
     'chipyard.TestHarness.SmallBoomConfig.top.v','plusarg_reader.v')
INPUTS=('driver.cpp','tl_ram.h',*RTL,'boom_irq_probes.h','boom_irq_probe_specs.h',
        'passive_probes.vlt','irq-profile.json','probe_contract.json','irq-interface.json')
RECEIPTS=tuple('recovery-receipts/'+name for name in ARCHIVES)
SCOPES=('src','configs','tests','third_party/soc-pulp-apb-gpio')


def sha(data): return hashlib.sha256(data).hexdigest()
def encoded(value): return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def unlinked(path):
    path=Path(path).absolute()
    if any(part.is_symlink() for part in (path,*path.parents)):
        raise ValueError('recovery path contains a symlink')
    return path.resolve()


def build_argv(output):
    return ['verilator','--vpi',str(output/'passive_probes.vlt'),'--cc','--exe','--build',
        '--top-module','BoomTile','--Mdir',str(output/'obj'),'-Wno-fatal','--output-split',
        '20000','--output-split-cfuncs','20000','-j','2','-CFLAGS','-std=c++17 -O1',
        *[str(output/name) for name in RTL],str(output/'driver.cpp')]


def check_command(command,output):
    if command != build_argv(output):
        raise ValueError('effective build flags/tool/path slots differ')


def load_origin(directory):
    files={}
    for name,expected in ARCHIVES.items():
        data=unlinked(Path(directory)/name).read_bytes()
        if sha(data)!=expected: raise ValueError('pinned recovery archive mismatch')
        with tarfile.open(fileobj=io.BytesIO(data),mode='r:gz') as archive:
            for member in archive:
                parts=PurePosixPath(member.name).parts
                if member.name.startswith('/') or '..' in parts:
                    raise ValueError('unsafe recovery archive path')
                if member.isdir(): continue
                if not member.isfile() or member.size>30000000:
                    raise ValueError('unsupported recovery archive entry')
                content=archive.extractfile(member).read()
                if member.name in files and files[member.name]!=content:
                    raise ValueError('conflicting recovery archive entries')
                files[member.name]=content
    for path,expected in (('artifact/build.exit',0),('artifact/probe-describe.exit',0),
                          ('attempt2/state/launch.exit',1),('attempt2/state/build-and-probes.exit',1)):
        if files[path].strip()!=str(expected).encode(): raise ValueError('historical exit mismatch')
    inventory=json.loads(files['artifact/probe-describe.stdout'])
    validate_probe_inventory(inventory)
    if json.loads(files['artifact/generated-probes.json'])!=inventory:
        raise ValueError('actual descriptor crosslink mismatch')
    command=files['artifact/obj/VBoomTile__verFiles.dat'].decode().splitlines()[1]
    if command != 'C "'+' '.join(build_argv(OLD_OUTPUT)[1:])+'"':
        raise ValueError('actual recorded build command mismatch')
    source=json.loads(files['source-manifest.json'])
    old_python={name:digest for name,digest in source['files'].items()
                if name in ('src/myfuzz/local_harness/boom_irq_generation.py',
                            'src/myfuzz/local_harness/boom_irq_cpu_session.py')}
    for name,digest in old_python.items():
        if sha(files['project/'+name])!=digest: raise ValueError('old Python identity mismatch')
    inputs={name:sha(files['artifact/'+name]) for name in INPUTS}
    origin={'schema_version':'boom_irq_attempt2_origin.v1','archives':dict(ARCHIVES),
        'build_exit':0,'probe_exit':0,'failed_stage_exit':1,
        'binary_sha256':sha(files['artifact/obj/VBoomTile']),
        'source_manifest_sha256':sha(files['source-manifest.json']),
        'original_python_hashes':old_python,'effective_inputs':inputs,
        'inventory':inventory,'tool_identity':json.loads(files['attempt2/tool-identity.json']),
        'recorded_build_command':command,
        'historical_receipt_hashes':{name:sha(data) for name,data in files.items()
            if name.startswith('artifact/') or name.startswith('attempt2/state/')}}
    return files,origin


def _metadata(artifact,origin):
    for name,digest in origin['original_python_hashes'].items():
        if artifact['implementation_source_hashes'].get(Path(name).name)==digest:
            raise ValueError('old build Python identity conflated with new metadata')
    return {'schema_version':'boom_irq_metadata_finalization.v1',
        'helper_sha256':sha(Path(__file__).read_bytes()),
        'build_origin_sha256':sha(encoded(origin)),
        'current_python_hashes':artifact['implementation_source_hashes'],
        'reused_binary':True,'new_cpp_build':False,'runtime_verified':False,
        'source_authority':False}


def validate_recovery_origin(output,artifact):
    if 'build_origin' not in artifact and 'metadata_finalization' not in artifact: return ()
    files,origin=load_origin(output/'recovery-receipts')
    if encoded(artifact.get('build_origin'))!=encoded(origin) or encoded(artifact.get('metadata_finalization'))!=encoded(_metadata(artifact,origin)):
        raise ValueError('recovery origin/metadata contract mismatch')
    if artifact.get('runtime_verified') is not False or artifact.get('source_authority') is not False:
        raise ValueError('recovery cannot grant runtime or source authority')
    expected={name:sha(data) for name,data in files.items() if name.startswith('artifact/')}
    for name in (path.removeprefix('artifact/') for path in expected):
        value=expected.get('artifact/'+name)
        if value is None or artifact['session_files'].get(name)!=value or sha(unlinked(output/name).read_bytes())!=value:
            raise ValueError('reused build closure crosslink mismatch')
    for name,expected_hash in ARCHIVES.items():
        if artifact['session_files'].get('recovery-receipts/'+name)!=expected_hash:
            raise ValueError('recovery receipt manifest crosslink mismatch')
    if artifact.get('command')!=build_argv(OLD_OUTPUT) or artifact.get('simulator')!=origin['tool_identity']['version']:
        raise ValueError('recovery effective command/tool crosslink mismatch')
    if artifact['generated_probes']!=origin['inventory']:
        raise ValueError('recovery inventory mismatch')
    return (*RECEIPTS,*(path.removeprefix('artifact/') for path in expected))


def _tool_identity(recorded):
    wrapper=shutil.which('verilator')
    if wrapper!=recorded['tools']['verilator']['path']:
        raise ValueError('current Verilator executable path differs')
    for info in recorded['tools'].values():
        path=Path(info['path'])
        if not path.resolve().is_relative_to('/root/fanzehui'):
            raise ValueError('tool receipt outside allowed root')
        if str(path.resolve())!=info['resolved_path'] or sha(path.read_bytes())!=info['sha256']:
            raise ValueError('current tool identity differs')


def _tree_files(root):
    unlinked(root)
    for file in root.rglob('*'):
        unlinked(file)
        if file.is_file() and '__pycache__' not in file.parts and file.suffix!='.pyc': yield file


def _copy_file(source,target):
    unlinked(source);unlinked(target)
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copy2(source,target)
    if target.stat().st_nlink != 1 or os.path.samestat(source.stat(),target.stat()) or sha(source.read_bytes())!=sha(target.read_bytes()):
        raise ValueError('copy is shared or changed')


def recover_metadata(*,repo,original_output,project_destination,output_destination,archives):
    """Create independent copies and one metadata manifest; no model invocation.

    A failed attempt retains its incomplete marker. Existing destinations are
    refused before mutation, even if empty. Canonical generation may query the
    Verilator version; it never elaborates, builds, or executes the model.
    """
    from .boom_irq_generation import generate_irq, generated_symbol_files, AUXILIARY
    repo,original_output,project_destination,output_destination=(unlinked(path) for path in
        (repo,original_output,project_destination,output_destination))
    for destination in (project_destination,output_destination):
        if destination.exists(): raise ValueError('recovery destination must be new')
        if any(destination.is_relative_to(source) or source.is_relative_to(destination)
               for source in (repo,original_output)):
            raise ValueError('recovery destination overlaps original input')
    if project_destination.is_relative_to(output_destination) or output_destination.is_relative_to(project_destination):
        raise ValueError('recovery destinations overlap')
    output_destination.mkdir(parents=True,exist_ok=False)
    marker=output_destination/'.recovery-incomplete.json'
    marker.write_bytes(encoded({'stage':'checking_originals','runtime_verified':False}))
    try:
        files,origin=load_origin(archives)
        # Verify originals before copying anything; failure marker is already exclusive.
        for name,data in files.items():
            if name.startswith('artifact/'):
                actual=unlinked(original_output/name.removeprefix('artifact/'))
                if not actual.is_file() or sha(actual.read_bytes())!=sha(data):
                    raise ValueError('original build receipt/input changed: '+name)
        if (original_output/'irq-session-artifact.json').exists():
            raise ValueError('original already finalized')
        source_files=[file for scope in SCOPES for file in _tree_files(repo/scope)]
        output_files=list(_tree_files(original_output))
        _tool_identity(origin['tool_identity'])
        project_destination.mkdir(parents=True,exist_ok=False)
        for file in source_files: _copy_file(file,project_destination/file.relative_to(repo))
        for file in output_files: _copy_file(file,output_destination/file.relative_to(original_output))
        with tempfile.TemporaryDirectory(prefix='irq-canonical-',dir=project_destination.parent) as temporary:
            temporary=Path(temporary)
            artifact=generate_irq(project_destination,temporary)
            check_command(artifact['command'],temporary)
            if artifact['simulator']!=origin['tool_identity']['version']:
                raise ValueError('recorded tool version differs')
            for name in INPUTS:
                if sha((temporary/name).read_bytes())!=origin['effective_inputs'][name]:
                    raise ValueError('effective compiled input differs: '+name)
        for name,data in files.items():
            if name.startswith('artifact/') and sha((output_destination/name.removeprefix('artifact/')).read_bytes())!=sha(data):
                raise ValueError('copied original receipt/input changed')
        symbols=generated_symbol_files(output_destination)
        artifact.update(generated_symbol_files=list(symbols),generated_probes=origin['inventory'],
            probes_runtime_confirmed=True,runtime_verified=False,source_authority=False,
            build_origin=origin)
        receipt_dir=output_destination/'recovery-receipts';receipt_dir.mkdir()
        for name in ARCHIVES: _copy_file(Path(archives)/name,receipt_dir/name)
        names=sorted({'driver.cpp','tl_ram.h','obj/VBoomTile',*RTL,*AUXILIARY,
               'generated-probes.json',*symbols,*RECEIPTS,
               *(name.removeprefix('artifact/') for name in files if name.startswith('artifact/'))})
        artifact['session_files']={name:sha((output_destination/name).read_bytes()) for name in names}
        artifact['metadata_finalization']=_metadata(artifact,origin)
        # Preserve the actual original effective argv, not temporary generation paths.
        artifact['command']=build_argv(OLD_OUTPUT)
        validate_recovery_origin(output_destination,artifact)
        pending=output_destination/'.irq-session-artifact.pending'
        with pending.open('xb') as stream:
            stream.write(encoded(artifact));stream.flush();os.fsync(stream.fileno())
        final=output_destination/'irq-session-artifact.json'
        os.link(pending,final)  # atomic exclusive publication; no overwrite
        pending.unlink()
        validate_recovery_origin(output_destination,json.loads(final.read_text()))
        marker.unlink()
        return artifact
    except BaseException as error:
        marker.write_bytes(encoded({'stage':'failed','error':str(error),'runtime_verified':False}))
        raise
