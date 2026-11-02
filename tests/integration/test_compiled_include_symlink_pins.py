"""Include-root link pins are distinct from direct source-file admission."""
import json
import os

import pytest

from myfuzz.integration.compiled_execution_files import _hashes, _source_paths, _unchanged


@pytest.fixture
def source_tree(tmp_path):
    root = tmp_path / 'rtl'
    (root / 'inc').mkdir(parents=True)
    (root / 'top.sv').write_text('module top; endmodule\n')
    (root / 'inc' / 'target.svh').write_text('// one\n')
    (root / 'inc' / 'alias.svh').symlink_to('target.svh')
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'scripts' / 'run_compiled_dataflow.py').write_text('# fixture\n')
    (tmp_path / 'src' / 'myfuzz').mkdir(parents=True)
    profile = tmp_path / 'profile.json'
    profile.write_text(json.dumps({'source': {'root': 'rtl', 'revision': 'sha256:' + '0' * 64,
        'top_module': 'top', 'files': ['top.sv'], 'include_roots': ['inc']}}))
    request = tmp_path / 'request.json'
    request.write_text(json.dumps({'profile_path': 'profile.json'}))
    compose = tmp_path / 'compose.json'
    compose.write_text(json.dumps({'cpu': {'request': 'request.json'}, 'devices': []}))
    supplement = tmp_path / 'supplement.json'; supplement.write_text('{}')
    cap = tmp_path / 'capability.json'; cap.write_text('{}')
    args = (tmp_path, compose, (cap,), supplement, None)
    return root, profile, args


def test_include_file_symlink_pins_literal_target_and_bytes(source_tree):
    root, _profile, args = source_tree
    paths = _source_paths(*args)
    pins = _hashes(paths)
    alias = pins[str(root / 'inc' / 'alias.svh')]
    assert alias['link_target'] == 'target.svh'
    assert alias['resolved_path'] == str(root / 'inc' / 'target.svh')
    _unchanged(paths, pins, args)
    (root / 'inc' / 'target.svh').write_text('// changed\n')
    with pytest.raises(ValueError, match='source-input-changed'):
        _unchanged(paths, pins, args)


@pytest.mark.parametrize('change', ['retarget', 'remove', 'add'])
def test_include_symlink_and_directory_set_changes_are_rejected(source_tree, change):
    root, _profile, args = source_tree
    paths = _source_paths(*args); pins = _hashes(paths)
    alias = root / 'inc' / 'alias.svh'
    if change == 'retarget':
        alias.unlink(); alias.symlink_to('./target.svh')
    elif change == 'remove':
        alias.unlink()
    else:
        (root / 'inc' / 'new.svh').write_text('// added\n')
    with pytest.raises(ValueError, match='source-input-changed'):
        _unchanged(paths, pins, args)


@pytest.mark.parametrize('kind', ['escape', 'dangling', 'directory', 'chain', 'direct'])
def test_untrusted_symlink_shapes_are_refused(source_tree, tmp_path, kind):
    root, profile, args = source_tree
    alias = root / 'inc' / 'alias.svh'; alias.unlink()
    if kind == 'escape':
        outside = tmp_path / 'outside.svh'; outside.write_text('// outside\n')
        alias.symlink_to(outside)
    elif kind == 'dangling': alias.symlink_to('missing.svh')
    elif kind == 'directory': alias.symlink_to(root / 'inc', target_is_directory=True)
    elif kind == 'chain':
        (root / 'inc' / 'other.svh').symlink_to('target.svh')
        alias.symlink_to('other.svh')
    else:
        alias.symlink_to('target.svh')
        document = json.loads(profile.read_text()); document['source']['files'] = ['inc/alias.svh']
        profile.write_text(json.dumps(document))
    with pytest.raises(ValueError, match='symlink'):
        _source_paths(*args)


def test_empty_include_directories_are_pinned_and_changes_rejected(source_tree):
    root, _profile, args = source_tree
    empty = root / 'inc' / 'empty'; empty.mkdir()
    paths = _source_paths(*args); pins = _hashes(paths)
    assert pins[str(empty)]['kind'] == 'directory'
    _unchanged(paths, pins, args)
    empty.rmdir()
    with pytest.raises(ValueError, match='source-input-changed'):
        _unchanged(paths, pins, args)
    empty.mkdir()
    (root / 'inc' / 'another-empty').mkdir()
    with pytest.raises(ValueError, match='source-input-changed'):
        _unchanged(paths, pins, args)


def test_include_member_type_change_is_rejected(source_tree):
    root, _profile, args = source_tree
    member = root / 'inc' / 'member'; member.write_text('data')
    paths = _source_paths(*args); pins = _hashes(paths)
    member.unlink(); member.mkdir()
    with pytest.raises(ValueError, match='source-input-changed'):
        _unchanged(paths, pins, args)


def test_include_fifo_is_refused_instead_of_ignored(source_tree):
    root, _profile, args = source_tree
    os.mkfifo(root / 'inc' / 'unexpected_fifo')
    with pytest.raises(ValueError, match='source-special-file'):
        _source_paths(*args)
