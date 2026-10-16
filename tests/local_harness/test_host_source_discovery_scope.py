"""Invocation-scoped discovery, current bytes and filesystem probes stay strict."""
import sys
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import pytest
from myfuzz.local_harness import build


@contextmanager
def count_parses():
    class Count:
        call_count=0
    count=Count();code=build.ast.parse.__code__;prior=sys.getprofile()
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code:count.call_count+=1
    sys.setprofile(profile)
    try:yield count
    finally:sys.setprofile(prior)


def test_real_discovery_parses_once_and_returns_detached_current_bytes():
    original=build.ast.parse
    with count_parses() as parse:
        with build.host_source_discovery_scope():
            first=build._host_sources();count=parse.call_count
            second=build._host_sources()
            assert count>0 and parse.call_count==count
            assert first==second and first is not second
            first.clear();assert build._host_sources()==second
        build._host_sources();assert parse.call_count>count


def test_scope_rejects_changed_source_and_exits_cleanly():
    original=Path.read_bytes
    with build.host_source_discovery_scope():
        sources=build._host_sources();chosen=next(iter(sources))
        def changed(path):
            raw=original(path)
            return raw+b'\n# changed' if path==build._IMPLEMENTATION_ROOT/chosen else raw
        with patch.object(Path,'read_bytes',changed):
            with pytest.raises(build.LocalHarnessBuildError,match='host-source.*drift'):
                build._host_sources()
    assert build._host_sources()


def test_scope_rejects_changed_candidate_existence_and_method():
    original=Path.is_file
    with build.host_source_discovery_scope():
        build._host_sources()
        absent=build._IMPLEMENTATION_ROOT/'src/myfuzz/local_harness/session/__init__.py'
        with patch.object(Path,'is_file',lambda p:True if p==absent else original(p)):
            with pytest.raises(build.LocalHarnessBuildError,match='host-source.*drift'):
                build._host_sources()
    with build.host_source_discovery_scope():
        build._host_sources()
        with patch.object(build,'_discover_host_sources',return_value={}):
            with pytest.raises(build.LocalHarnessBuildError,match='host-source.*method'):
                build._host_sources()


def test_nested_scope_and_exception_do_not_leak_outer_cache():
    original=build.ast.parse
    with count_parses() as parse:
        with build.host_source_discovery_scope():
            build._host_sources();before=parse.call_count
            with pytest.raises(RuntimeError):
                with build.host_source_discovery_scope():
                    build._host_sources();raise RuntimeError('exit')
            after=parse.call_count;assert after>before
            build._host_sources();assert parse.call_count==after
        build._host_sources();assert parse.call_count>after


def mini_root(tmp_path,statement):
    names=('src/myfuzz/scenario/uart_consumption.py','src/myfuzz/local_harness/build.py',
           'src/myfuzz/local_harness/driver_renderer.py','src/myfuzz/local_harness/wire.py',
           'src/myfuzz/local_harness/native_session.py','scripts/verify_soc_sources.py',
           'src/myfuzz/bundle/__init__.py')
    for name in names:
        path=tmp_path/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
    (tmp_path/'src/myfuzz/bundle/__init__.py').write_text(statement)
    (tmp_path/'src/myfuzz/local_harness/native_session.py').write_text('import myfuzz.bundle\n')
    return tmp_path/'src/myfuzz/bundle/later.py'


@pytest.mark.parametrize('statement',['from myfuzz.bundle import later\n','from . import later\n'])
def test_from_package_existing_alias_is_discovered(tmp_path,statement):
    path=mini_root(tmp_path,statement);path.write_text('VALUE=1\n')
    with patch.object(build,'_IMPLEMENTATION_ROOT',tmp_path):
        with build.host_source_discovery_scope():
            assert build._host_sources()['src/myfuzz/bundle/later.py']==b'VALUE=1\n'


def test_from_named_package_missing_alias_appearance_is_rejected(tmp_path):
    path=mini_root(tmp_path,'from myfuzz.bundle import later\n')
    with patch.object(build,'_IMPLEMENTATION_ROOT',tmp_path):
        with build.host_source_discovery_scope():
            assert 'src/myfuzz/bundle/later.py' not in build._host_sources()
            path.write_text('VALUE=1\n')
            with pytest.raises(build.LocalHarnessBuildError,match='probe-drift'):
                build._host_sources()
