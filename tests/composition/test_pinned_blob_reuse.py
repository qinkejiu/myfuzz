"""Pinned blobs are shared only inside one execution validation scope."""
import subprocess
from unittest.mock import patch

import pytest

from myfuzz.composition.interface_description import SourceLocator
from myfuzz.composition.source_crawler import SourceCrawlError, _pinned_source_reader
from myfuzz.local_harness.execution_validation import execution_validation_scope


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


def pinned(tmp_path, name='rtl', content=b'module top; endmodule\n'):
    root = tmp_path / name
    root.mkdir()
    source = root / 'top.sv'
    source.write_bytes(content)
    git(root, 'init', '-q')
    git(root, 'add', 'top.sv')
    git(root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
        'commit', '-qm', 'fixture')
    locator = SourceLocator(name, 'git:' + git(root, 'rev-parse', 'HEAD'), 'top')
    return locator, source


def read(locator, source, base):
    return _pinned_source_reader(locator, base_dir=base)[2](source)


def blob_calls(run):
    return [call for call in run.call_args_list if 'cat-file' in call.args[0]]


def test_reuses_blob_across_readers_only_within_execution(tmp_path):
    locator, source = pinned(tmp_path)
    with patch('myfuzz.composition.source_crawler.subprocess.run', wraps=subprocess.run) as run:
        with execution_validation_scope(revalidate=False):
            assert read(locator, source, tmp_path) == source.read_bytes()
            assert read(locator, source, tmp_path) == source.read_bytes()
            assert len(blob_calls(run)) == 1
        with execution_validation_scope(revalidate=False):
            read(locator, source, tmp_path)
        assert len(blob_calls(run)) == 2
        read(locator, source, tmp_path)
        read(locator, source, tmp_path)
        assert len(blob_calls(run)) == 4


def test_reused_blob_still_compares_current_working_bytes(tmp_path):
    locator, source = pinned(tmp_path)
    with execution_validation_scope(revalidate=False):
        read(locator, source, tmp_path)
        source.write_bytes(b'changed')
        with pytest.raises(SourceCrawlError, match='git-content-mismatch'):
            read(locator, source, tmp_path)


def test_distinct_repository_owners_have_distinct_blobs(tmp_path):
    first, source = pinned(tmp_path, 'one')
    second, other = pinned(tmp_path, 'two', b'module other; endmodule\n')
    with execution_validation_scope(revalidate=False):
        assert read(first, source, tmp_path) == source.read_bytes()
        assert read(second, other, tmp_path) == other.read_bytes()


def test_scope_exit_rechecks_working_bytes(tmp_path):
    from myfuzz.local_harness.execution_validation import ExecutionValidationError

    locator, source = pinned(tmp_path)
    with pytest.raises(ExecutionValidationError, match='git-content-mismatch'):
        with execution_validation_scope():
            read(locator, source, tmp_path)
            source.write_bytes(b'changed after last read')


def test_new_revision_in_same_repository_has_distinct_blob(tmp_path):
    locator, source = pinned(tmp_path)
    with execution_validation_scope(revalidate=False):
        read(locator, source, tmp_path)
        source.write_bytes(b'module revised; endmodule\n')
        git(source.parent, 'add', 'top.sv')
        git(source.parent, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
            'commit', '-qm', 'revised')
        revised = SourceLocator('rtl', 'git:' + git(source.parent, 'rev-parse', 'HEAD'), 'top')
        assert read(revised, source, tmp_path) == source.read_bytes()


def test_nested_repository_uses_its_own_pin_and_tree_path(tmp_path):
    from myfuzz.composition.interface_description import RepositoryPin

    _, source = pinned(tmp_path)
    nested, child = pinned(source.parent, 'child', b'module child; endmodule\n')
    git(source.parent, 'update-index', '--add', '--cacheinfo',
        '160000,' + nested.revision[4:] + ',child')
    git(source.parent, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
        'commit', '-qm', 'nested repository')
    locator = SourceLocator(
        'rtl', 'git:' + git(source.parent, 'rev-parse', 'HEAD'), 'top',
        repositories=(RepositoryPin('child', nested.revision),),
    )
    with patch('myfuzz.composition.source_crawler.subprocess.run', wraps=subprocess.run) as run:
        with execution_validation_scope(revalidate=False):
            assert read(locator, source, tmp_path) == source.read_bytes()
            assert read(locator, child, tmp_path) == child.read_bytes()
            assert read(locator, child, tmp_path) == child.read_bytes()
        assert len(blob_calls(run)) == 2
