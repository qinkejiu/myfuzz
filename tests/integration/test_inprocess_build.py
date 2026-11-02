"""Software-only link-cache checks using a real tiny C++ executable."""
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import inprocess_build as build


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    compiler = shutil.which('g++')
    if not compiler:
        pytest.skip('C++ compiler unavailable')
    source = tmp_path/'source'
    source.mkdir()
    cpp = source/'spike.cpp'
    cpp.write_text('#include "binding.h"\n#include "shared.h"\nint main(){return VALUE+EXTRA;}\n')
    (source/'shared.h').write_text('#define EXTRA 0\n')
    include = tmp_path/'runtime/include'
    include.mkdir(parents=True)
    for name in ('verilated.cpp', 'verilated_threads.cpp'):
        (include/name).write_text('// runtime double\n')
    objects = []
    artifacts = []
    for name in ('cpu', 'ip'):
        obj = tmp_path/name/'obj'
        obj.mkdir(parents=True)
        # An empty valid GNU archive: the test executable requires no models.
        (obj/('V'+name+'__ALL.a')).write_bytes(b'!<arch>\n')
        objects.append(obj)
        artifacts.append(SimpleNamespace(runtime_document={'module_name':name}))
    monkeypatch.setattr(build, '_toolchain', lambda: {'cxx':{'path':compiler},
        'verilator':{'runtime_root':str(include.parent)}})
    def prepared(artifact, **kwargs):
        obj = objects[['cpu','ip'].index(artifact.runtime_document['module_name'])]
        return SimpleNamespace(validate_current=lambda *a, **kw: obj.parent/'harness',
            observation_document=lambda: {})
    monkeypatch.setattr(build, 'build_local_harness_with_receipt', prepared)
    def run(value=0):
        output = tmp_path/('run'+str(len(list(tmp_path.glob('run*')))))
        output.mkdir()
        (output/'binding.h').write_text('#define VALUE '+str(value)+'\n')
        return build.build_link_run(artifacts, cpp, output, tmp_path/'cache', [], root=tmp_path), output
    return SimpleNamespace(run=run, source=source, include=include, objects=objects)


def test_identical_binding_reuses_link_across_output_directories(inputs):
    first, _ = inputs.run()
    second, _ = inputs.run()
    assert first['link_cache_hit'] is False
    assert second['link_cache_hit'] is True
    assert first['link_cache_key'] == second['link_cache_key']


def test_changed_binding_never_runs_previous_executable(inputs):
    first, _ = inputs.run(0)
    changed, _ = inputs.run(7)
    assert changed['returncode'] == 7
    assert changed['link_cache_hit'] is False
    assert changed['link_cache_key'] != first['link_cache_key']


@pytest.mark.parametrize('changed', ['shared', 'runtime', 'archive', 'model_header'])
def test_actual_content_changes_invalidate_link(inputs, changed):
    before, _ = inputs.run()
    path = {'shared':inputs.source/'shared.h', 'runtime':inputs.include/'verilated.cpp',
        'archive':inputs.objects[0]/'Vcpu__ALL.a', 'model_header':inputs.objects[0]/'Vcpu.h'}[changed]
    if changed == 'archive':
        source = path.parent/'added.cpp'
        source.write_text('int archive_content_change;\n')
        subprocess.run([shutil.which('g++'), '-c', str(source), '-o', str(path.parent/'added.o')], check=True)
        subprocess.run(['ar', 'rcs', str(path), str(path.parent/'added.o')], check=True)
    else:
        path.write_bytes((path.read_bytes() if path.exists() else b'') + b'\n')
    after, _ = inputs.run()
    assert after['link_cache_hit'] is False
    assert after['link_cache_key'] != before['link_cache_key']


def test_corrupted_cached_executable_is_relinked(inputs):
    first, output = inputs.run()
    binary = output.parent/'cache/inprocess-links'/first['link_cache_key']/'inprocess-spike'
    binary.write_bytes(b'corrupt')
    rebuilt, _ = inputs.run()
    assert rebuilt['returncode'] == 0
    assert rebuilt['link_cache_hit'] is False
    assert rebuilt['link_cache_key'] == first['link_cache_key']


def test_compiler_bytes_and_flags_participate_in_key(tmp_path):
    cpp = tmp_path/'spike.cpp'
    cpp.write_text('int main(){}')
    compiler = tmp_path/'compiler'
    compiler.write_text('compiler-v1')
    toolchain = {'cxx': {'path':str(compiler)}}
    def key(flag):
        return build._link_key([str(compiler),flag,'-o','a.out'],cpp,tmp_path,[],[],tmp_path,toolchain)
    before = key('-O2')
    assert key('-O1') != before
    compiler.write_text('compiler-v2')
    assert key('-O2') != before
