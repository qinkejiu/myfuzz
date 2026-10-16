"""Call-scoped host closure reuse must observe bytes and absent candidates."""
import os
from pathlib import Path
import pytest
from myfuzz.local_harness import build


@pytest.fixture
def tree(tmp_path,monkeypatch):
    seeds=('src/myfuzz/scenario/uart_consumption.py','src/myfuzz/local_harness/build.py',
        'src/myfuzz/local_harness/driver_renderer.py','src/myfuzz/local_harness/wire.py',
        'src/myfuzz/local_harness/native_session.py','scripts/verify_soc_sources.py')
    for name in seeds:
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('# seed\n')
    monkeypatch.setattr(build,'_IMPLEMENTATION_ROOT',tmp_path)
    return tmp_path


def write(root,name,text):
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    return path


def scope():
    return build.host_source_discovery_scope()


def test_same_size_changed_bytes_with_restored_stat_are_rejected(tree):
    name='src/myfuzz/local_harness/wire.py';path=tree/name
    with scope():
        build._host_sources();stat=path.stat()
        path.write_text('# edit\n');os.utime(path,ns=(stat.st_atime_ns,stat.st_mtime_ns))
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


@pytest.mark.parametrize('new_name',[
    'src/myfuzz/new_optional.py','src/myfuzz/new_optional/__init__.py'])
def test_previously_absent_import_candidate_appearing_is_rejected(tree,new_name):
    write(tree,'src/myfuzz/local_harness/wire.py','from myfuzz.new_optional import value\n')
    with scope():
        first=build._host_sources();assert new_name not in first
        write(tree,new_name,'value=1\n')
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


def test_previously_absent_optional_session_seed_appearing_is_rejected(tree):
    name='src/myfuzz/local_harness/timer_session.py'
    with scope():
        assert name not in build._host_sources()
        write(tree,name,'# new optional session\n')
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


def test_included_file_disappearance_is_rejected(tree):
    with scope():
        build._host_sources();(tree/'src/myfuzz/local_harness/wire.py').unlink()
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


def test_scope_cleanup_discovers_new_bytes_and_new_candidates(tree):
    name='src/myfuzz/local_harness/wire.py'
    with scope():first=build._host_sources()
    write(tree,name,'import myfuzz.later\n');write(tree,'src/myfuzz/later.py','later=1\n')
    with scope():
        second=build._host_sources()
        assert second[name]!=first[name]
        assert second['src/myfuzz/later.py']==b'later=1\n'


def test_returned_source_mapping_cannot_poison_reused_closure(tree):
    name='src/myfuzz/local_harness/wire.py'
    with scope():
        first=build._host_sources();first[name]=b'# caller saved bytes\n';first['outside.py']=b'forged\n'
        second=build._host_sources()
        assert second[name]==(tree/name).read_bytes() and 'outside.py' not in second


def test_ast_parser_method_replacement_cannot_reuse_previous_discovery(tree,monkeypatch):
    with scope():
        build._host_sources()
        original=build.ast.parse
        monkeypatch.setattr(build.ast,'parse',lambda *args,**kwargs:None)
        try:
            with pytest.raises(build.LocalHarnessBuildError):build._host_sources()
        finally:
            monkeypatch.setattr(build.ast,'parse',original)


def test_default_without_scope_still_rediscovers_source_changes(tree):
    name='src/myfuzz/local_harness/wire.py';first=build._host_sources()
    write(tree,name,'# current bytes\n')
    second=build._host_sources()
    assert second[name]!=first[name]


def test_exception_leaving_scope_does_not_leave_cached_authority(tree):
    name='src/myfuzz/local_harness/wire.py'
    with pytest.raises(RuntimeError,match='caller stopped'):
        with scope():
            build._host_sources()
            raise RuntimeError('caller stopped')
    write(tree,name,'# changed after exception\n')
    with scope():assert build._host_sources()[name]==b'# changed after exception\n'


def test_nested_scope_does_not_replace_outer_scope_snapshot(tree):
    name='src/myfuzz/local_harness/wire.py'
    with scope():
        build._host_sources()
        write(tree,name,'# nested bytes\n')
        with scope():assert build._host_sources()[name]==b'# nested bytes\n'
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


@pytest.mark.parametrize('binding',['_HOST_SOURCE_ACCESS','_HOST_SOURCE_CONTEXT'])
def test_prepare_rejects_saved_map_accessor_before_prepared_cache(tree,monkeypatch,binding):
    """A valid admission prefix must check the live accessor before fast return."""
    import hashlib
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    from myfuzz.local_harness.renderer import _sha
    cpp='int main() {}';rtl='module fixture; endmodule'
    document=dict(status='driver_generated',driver_status='generated',
        driver_schema_version='local_driver_generation.v1',
        cpp_sha256=hashlib.sha256(cpp.encode()).hexdigest(),
        runtime_sv_sha256=hashlib.sha256(rtl.encode()).hexdigest())
    document['artifact_digest']=_sha(document)
    artifact=LocalRuntimeArtifact(None,None,{},rtl,cpp,document)
    calls=[]
    def prepared(*args):
        calls.append('prepared-cache')
        return ({'saved':'identity'},{'saved':'inputs'})
    monkeypatch.setattr(build,'_prepared_if_current',prepared)
    with scope():
        saved=build._host_sources();original=getattr(build,binding)
        from contextvars import ContextVar
        replacement=(lambda:dict(saved)) if binding=='_HOST_SOURCE_ACCESS' else ContextVar('forged_prepare_context',default=None)
        monkeypatch.setattr(build,binding,replacement)
        try:
            with pytest.raises(build.LocalHarnessBuildError):
                build._prepare(artifact,base_dir=tree)
            assert calls==[]
        finally:
            monkeypatch.setattr(build,binding,original)


@pytest.mark.parametrize('name',['_HOST_SOURCE_SCOPE','_HOST_SOURCE_CONTEXT'])
def test_replacing_context_provider_cannot_fall_back_to_unscoped_discovery(tree,monkeypatch,name):
    from contextvars import ContextVar
    with scope():
        build._host_sources();original=getattr(build,name)
        monkeypatch.setattr(build,name,ContextVar('forged_host_scope',default=None))
        try:
            with pytest.raises(build.LocalHarnessBuildError):build._host_sources()
        finally:
            monkeypatch.setattr(build,name,original)


def test_previously_absent_from_package_import_submodule_appearing_is_rejected(tree):
    write(tree,'src/myfuzz/local_harness/wire.py',
        'try:\n from myfuzz.bundle import later\nexcept ImportError:\n pass\n')
    write(tree,'src/myfuzz/bundle/__init__.py','# package\n')
    with scope():
        first=build._host_sources();assert 'src/myfuzz/bundle/__init__.py' in first
        write(tree,'src/myfuzz/bundle/later.py','later=1\n')
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


@pytest.mark.parametrize('name',['src/myfuzz/bundle/later.py','src/myfuzz/bundle/later/__init__.py'])
def test_existing_from_package_alias_module_is_included_and_its_bytes_are_guarded(tree,name):
    write(tree,'src/myfuzz/local_harness/wire.py','from myfuzz.bundle import later\n')
    write(tree,'src/myfuzz/bundle/__init__.py','# package\n')
    path=write(tree,name,'value=1\n')
    with scope():
        first=build._host_sources();assert first.get(name)==b'value=1\n'
        path.write_text('value=2\n')
        with pytest.raises(build.LocalHarnessBuildError):build._host_sources()


@pytest.mark.parametrize('scoped',[False,True])
@pytest.mark.parametrize('candidate',['optional_seed','from_package_alias'])
def test_preexisting_prepared_cache_cannot_skip_new_candidate_present_before_scope(tree,monkeypatch,scoped,candidate):
    """Cache-prefix fixture: a miss must regenerate, not return stale identity."""
    from copy import deepcopy
    from types import SimpleNamespace
    from contextlib import nullcontext
    import hashlib
    from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
    from myfuzz.local_harness.renderer import _sha
    if candidate=='from_package_alias':
        write(tree,'src/myfuzz/local_harness/wire.py',
            'try:\n from myfuzz.bundle import later\nexcept ImportError:\n pass\n')
        write(tree,'src/myfuzz/bundle/__init__.py','# package\n')
        name='src/myfuzz/bundle/later.py'
    else:name='src/myfuzz/local_harness/timer_session.py'
    cpp='int main() {}';rtl='module fixture; endmodule'
    document=dict(status='driver_generated',driver_status='generated',
        driver_schema_version='local_driver_generation.v1',
        cpp_sha256=hashlib.sha256(cpp.encode()).hexdigest(),
        runtime_sv_sha256=hashlib.sha256(rtl.encode()).hexdigest())
    document['artifact_digest']=_sha(document)
    artifact=LocalRuntimeArtifact(SimpleNamespace(profile=SimpleNamespace(component_id='cache_prefix_fixture')),None,{},rtl,cpp,document)
    snapshots=build._host_sources()
    identity=dict(toolchain={},host_sources=dict(files=[dict(path=path,
        sha256=hashlib.sha256(raw).hexdigest()) for path,raw in sorted(snapshots.items())]))
    monkeypatch.setattr(build,'_toolchain',lambda:{})
    entry=(artifact,deepcopy(artifact),tree,build._preparation_stamp(),deepcopy(identity),dict(snapshots))
    monkeypatch.setattr(build,'_PREPARED_CACHE',{id(artifact):entry})
    assert build._prepared_if_current(artifact,tree)[0]==identity
    write(tree,name,'# new source before this discovery scope\n')
    class RegenerationReached(Exception):pass
    def checkpoint(*args,**kwargs):raise RegenerationReached('strict regeneration reached')
    # Only observe the cold-path branch. No malformed fixture error is prescribed.
    monkeypatch.setattr(build,'verify_local_source_lock',checkpoint)
    # Its hook identity is part of the preparation stamp; refresh that component
    # before testing source freshness, without modifying any captured source bytes.
    entry=(artifact,deepcopy(artifact),tree,build._preparation_stamp(),deepcopy(identity),dict(snapshots))
    build._PREPARED_CACHE[id(artifact)]=entry
    with scope() if scoped else nullcontext():
        current=build._host_sources();assert name in current
        assert all((tree/path).read_bytes()==raw for path,raw in snapshots.items())
        assert build._prepared_if_current(artifact,tree) is None
        with pytest.raises(RegenerationReached):build._prepare(artifact,base_dir=tree)
