"""Real prepared-cache validator and regeneration checkpoint; no RTL authority."""
from contextlib import nullcontext
from copy import deepcopy
from types import SimpleNamespace
import hashlib
import pytest
from myfuzz.local_harness import build
from myfuzz.local_harness.runtime_artifact import LocalRuntimeArtifact
from myfuzz.local_harness.renderer import _sha
from tests.local_harness.test_host_source_reuse_boundaries import tree,write


class RegenerationReached(Exception):pass


def cached(tree,monkeypatch):
    cpp='int main() {}';rtl='module fixture; endmodule'
    doc=dict(status='driver_generated',driver_status='generated',driver_schema_version='local_driver_generation.v1',cpp_sha256=hashlib.sha256(cpp.encode()).hexdigest(),runtime_sv_sha256=hashlib.sha256(rtl.encode()).hexdigest());doc['artifact_digest']=_sha(doc)
    artifact=LocalRuntimeArtifact(SimpleNamespace(profile=SimpleNamespace(component_id="fixture")),None,{},rtl,cpp,doc)
    snapshots=build._host_sources()
    identity=dict(toolchain={},host_sources=dict(schema_version='local_harness_host_sources.v1',files=[dict(path=n,sha256=hashlib.sha256(raw).hexdigest()) for n,raw in sorted(snapshots.items())]))
    def regenerate(*a,**kw):raise RegenerationReached()
    monkeypatch.setattr(build,'_toolchain',lambda:{})
    monkeypatch.setattr(build,'verify_local_source_lock',regenerate)
    entry=(artifact,deepcopy(artifact),tree,build._preparation_stamp(),deepcopy(identity),dict(snapshots))
    monkeypatch.setattr(build,'_PREPARED_CACHE',{id(artifact):entry})
    assert build._prepared_if_current(artifact,tree)[0]==identity
    assert build._prepare(artifact,tree)[0]==identity
    return artifact,identity,snapshots


@pytest.mark.parametrize('scoped',[False,True])
@pytest.mark.parametrize('new_name',['src/myfuzz/local_harness/timer_session.py','src/myfuzz/bundle/later.py','src/myfuzz/bundle/later/__init__.py'])
def test_new_host_candidate_invalidates_real_cache_and_reaches_regeneration(tree,monkeypatch,scoped,new_name):
    write(tree,'src/myfuzz/bundle/__init__.py','')
    write(tree,'src/myfuzz/local_harness/wire.py','from myfuzz.bundle import later\n')
    artifact,identity,snapshots=cached(tree,monkeypatch)
    write(tree,new_name,'VALUE=1\n')
    with build.host_source_discovery_scope() if scoped else nullcontext():
        current=build._host_sources();assert new_name in current
        assert all((tree/name).read_bytes()==raw for name,raw in snapshots.items())
        assert build._prepared_if_current(artifact,tree) is None
        with pytest.raises(RegenerationReached):build._prepare(artifact,tree)


@pytest.mark.parametrize('scoped',[False,True])
def test_cached_host_rows_must_cover_current_map_and_match_snapshots(tree,monkeypatch,scoped):
    artifact,identity,snapshots=cached(tree,monkeypatch)
    entry=list(build._PREPARED_CACHE[id(artifact)]);entry[4]['host_sources']['files'].pop()
    build._PREPARED_CACHE[id(artifact)]=tuple(entry)
    with build.host_source_discovery_scope() if scoped else nullcontext():
        assert build._prepared_if_current(artifact,tree) is None
        with pytest.raises(RegenerationReached):build._prepare(artifact,tree)


@pytest.mark.parametrize('scoped',[False,True])
@pytest.mark.parametrize('mutation',['same_length_source','duplicate_host_row','snapshot_disagreement'])
def test_current_bytes_and_complete_cached_rows_are_not_subset_checks(tree,monkeypatch,scoped,mutation):
    import os
    artifact,identity,snapshots=cached(tree,monkeypatch)
    entry=build._PREPARED_CACHE[id(artifact)]
    if mutation=='same_length_source':
        path=tree/'src/myfuzz/local_harness/wire.py';stat=path.stat()
        path.write_bytes(b'# edit\n');os.utime(path,ns=(stat.st_atime_ns,stat.st_mtime_ns))
    elif mutation=='duplicate_host_row':
        rows=entry[4]['host_sources']['files'];rows.append(deepcopy(rows[0]))
    else:
        entry[5]['src/myfuzz/local_harness/wire.py']=b'not actual bytes'
    with build.host_source_discovery_scope() if scoped else nullcontext():
        assert build._prepared_if_current(artifact,tree) is None
        with pytest.raises(RegenerationReached):build._prepare(artifact,tree)

@pytest.mark.parametrize('mutation',['identity','snapshots','host_sources','files'])
def test_malformed_private_cached_shapes_are_misses_not_exceptions(tree,monkeypatch,mutation):
    artifact,identity,snapshots=cached(tree,monkeypatch)
    entry=list(build._PREPARED_CACHE[id(artifact)])
    if mutation=='identity':entry[4]=[]
    elif mutation=='snapshots':entry[5]=[]
    elif mutation=='host_sources':entry[4]['host_sources']=[]
    else:entry[4]['host_sources']['files']={}
    build._PREPARED_CACHE[id(artifact)]=tuple(entry)
    assert build._prepared_if_current(artifact,tree) is None
    with pytest.raises(RegenerationReached):build._prepare(artifact,tree)
