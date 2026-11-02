"""Build existing component models and run one in-process C++ loop."""
from hashlib import sha256
from pathlib import Path
import fcntl
import json
import os
import shutil
import tempfile
import subprocess
import time

from myfuzz.local_harness.build import build_local_harness_with_receipt, _toolchain


def _link_key(command, cpp, output, objects, archives, include, toolchain):
    """Key actual model/header/runtime/compiler bytes, independent of run paths."""
    roots=[output, cpp.parent, *objects, include]
    files=[('cpp', cpp), ('compiler', Path(toolchain['cxx']['path']))]
    files += [(f'archive/{index}', path) for index,path in enumerate(archives)]
    for index,directory in enumerate(roots):
        files += [(f'include/{index}/'+str(path.relative_to(directory)), path)
                  for path in sorted(directory.rglob('*')) if path.is_file()
                  and (path.suffix in ('.h','.hpp','.hh','.hxx','.inc')
                       or index==len(roots)-1 and path.suffix=='.cpp')]
    normalized=[*command[:-1], '{executable}']
    for index,directory in enumerate(roots):
        normalized=[arg.replace(str(directory.resolve()), f'{{include{index}}}') for arg in normalized]
    identity=dict(command=normalized,toolchain=toolchain,
                  files=[(name,sha256(path.read_bytes()).hexdigest()) for name,path in files])
    return sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def _cached_link(command, key, cache, output, current_key):
    directory=cache/'inprocess-links'/key
    directory.mkdir(parents=True,exist_ok=True)
    binary=directory/'inprocess-spike'
    receipt=directory/'binary.sha256'
    with (directory/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        hit=(binary.is_file() and receipt.is_file()
             and sha256(binary.read_bytes()).hexdigest()==receipt.read_text())
        if not hit:
            with tempfile.TemporaryDirectory(prefix='.link-',dir=directory) as temporary:
                target=Path(temporary)/'inprocess-spike'
                (output/'link.log').write_text('$ '+' '.join(
                    str(part) for part in [*command[:-1],str(target)])+'\n')
                build=subprocess.run([*command[:-1],str(target)],capture_output=True,text=True)
                (output/'link.log').write_text(
                    (output/'link.log').read_text()+build.stdout+build.stderr)
                if build.returncode: raise RuntimeError('in-process link failed; see link.log')
                if current_key()!=key:
                    raise RuntimeError('in-process link inputs changed during compilation')
                digest=sha256(target.read_bytes()).hexdigest()
                os.replace(target,binary)
                receipt.write_text(digest)
        else:
            (output/'link.log').write_text('link cache hit: '+key+'\n')
        if current_key()!=key:
            raise RuntimeError('in-process link inputs changed before execution')
        shutil.copy2(binary,output/'inprocess-spike')
        return hit


def build_axi4_adapter(rtl, output, *, module='axi4_processor_memory_adapter',
                       params=('-GADDRESS_WIDTH=64', '-GDATA_WIDTH=64',
                               '-GID_WIDTH=4', '-GUSER_WIDTH=64'), jobs=2):
    """Verilate the repository's AXI4 processor-side adapter beside a run.

    The adapter is an RTL model, not a generated component artifact, so it is not
    part of the component cache.  Its build products live under the run output
    and its archive/include are passed to the link step explicitly.
    """
    output, rtl = Path(output), Path(rtl)
    directory = output / 'axi4-adapter'
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    dummy = directory / 'adapter-dummy-main.cpp'
    dummy.write_text('int main() { return 0; }\n')
    toolchain = _toolchain()
    verilator = toolchain['verilator']['path']
    command = [verilator, '--cc', '--exe', '--build', '-j', str(jobs),
               '--top-module', module, '-Wno-fatal', *params,
               '--Mdir', str(directory), '-o', 'adapter-dummy',
               str(rtl), str(dummy)]
    completed = subprocess.run(command, capture_output=True, text=True)
    (output / 'axi4-adapter-build.log').write_text(completed.stdout + completed.stderr)
    if completed.returncode:
        raise RuntimeError('AXI4 adapter Verilator build failed; see axi4-adapter-build.log')
    archive = directory / ('V' + module + '__ALL.a')
    if not archive.is_file():
        raise RuntimeError('AXI4 adapter archive was not produced: ' + str(archive))
    return dict(include=str(directory), archive=str(archive), module=module)


def build_link_run(artifacts, cpp, output, cache, argv, *, root, runner=None,
                   extra_archives=(), extra_includes=()):
    output,cache,root=Path(output),Path(cache),Path(root)
    cpp=Path(cpp).resolve()
    builds=[build_local_harness_with_receipt(artifact,base_dir=root,cache_dir=cache)
            for artifact in artifacts]
    objects=[result.validate_current(artifact,base_dir=root,cache_dir=cache).parent/'obj'
             for result,artifact in zip(builds,artifacts)]
    archives=[directory/('V'+artifact.runtime_document['module_name']+'__ALL.a')
              for directory,artifact in zip(objects,artifacts)]
    if not all(path.is_file() for path in archives):
        raise ValueError('generated model archives unavailable in cache; rebuild in a fresh cache')
    toolchain=_toolchain();include=Path(toolchain['verilator']['runtime_root'])/'include'
    extra_includes=[Path(path) for path in extra_includes]
    extra_archives=[Path(path) for path in extra_archives]
    all_archives=[*archives,*extra_archives]
    all_includes=[*objects,*extra_includes]
    executable=output/'inprocess-spike'
    # A model built with Verilator --timing (a profile that declares
    # ``verilator_timing_mode: timing``) links the timing runtime, which is the
    # only piece that needs the coroutine support its generated tasks use.  An
    # untimed build adds neither the source nor the flag, so its link command -
    # and therefore its link cache key - is byte-identical to before.
    timed=[artifact for artifact in artifacts
           if 'driver_timing' in artifact.runtime_document]
    timing_sources=[str(include/'verilated_timing.cpp')] if timed else []
    timing_flags=['-fcoroutines'] if timed else []
    command=[toolchain['cxx']['path'],'-std=c++17','-O2',*timing_flags,
             '-I'+str(output.resolve()),*('-I'+str(path) for path in all_includes),
             '-I'+str(include),'-I'+str(include/'vltstd'),str(cpp),
             *(str(path) for path in all_archives),str(include/'verilated.cpp'),
             *timing_sources,
             str(include/'verilated_threads.cpp'),'-pthread','-latomic','-o',str(executable)]
    linked=time.monotonic()
    current_key=lambda: _link_key(command,cpp,output.resolve(),all_includes,
                                  all_archives,include,toolchain)
    key=current_key()
    link_cache_hit=_cached_link(command,key,cache,output,current_key)
    link_seconds=time.monotonic()-linked
    started=time.monotonic()
    command=[str(executable.resolve()),*(str(value) for value in argv)]
    if runner is None:
        result=subprocess.run(command,capture_output=True,text=True)
        (output/'run.log').write_text(result.stdout+result.stderr)
        returncode=result.returncode
    else:
        returncode=runner(command,output/'run.log')
    run_seconds=time.monotonic()-started
    return dict(status='observations_passed' if returncode==0 else 'failed',
        returncode=returncode,link_seconds=link_seconds,run_seconds=run_seconds,
        link_cache_hit=link_cache_hit,link_cache_key=key,
        builds=[row.observation_document() for row in builds],
        archives=[dict(path=str(path),sha256=sha256(path.read_bytes()).hexdigest(),
                       scope='observed archive hash; not covered by existing executable receipt')
                  for path in archives])
