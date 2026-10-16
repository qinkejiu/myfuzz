"""Direct elaboration must enforce the same source pins as the crawler."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.composition.component_profile import (
    ComponentProfileError, elaborate_profile, load_component_profile)


ROOT = Path(__file__).resolve().parents[2]


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def pinned_profile(tmp_path):
    root = tmp_path / 'rtl'
    root.mkdir()
    source = root / 'top.sv'
    source.write_text('module top(input logic clk); endmodule\n')
    git(root, 'init', '-q')
    git(root, 'add', 'top.sv')
    git(root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
        'commit', '-qm', 'source fixture')
    document = json.loads((ROOT / 'examples/soc_generation/profiles/novagpio.json').read_text())
    document['source'] = dict(root='rtl', revision='git:' + git(root, 'rev-parse', 'HEAD'),
                              top_module='top', files=['top.sv'])
    return document, root, source


@pytest.mark.parametrize('fault', ('revision', 'content', 'untracked'))
def test_direct_rejects_bad_git_pin_before_launch(pinned_profile, tmp_path, fault):
    document, root, source = pinned_profile
    document = deepcopy(document)
    if fault == 'revision':
        document['source']['revision'] = 'git:' + '0' * 40
        reason = 'git-revision-mismatch'
    elif fault == 'content':
        source.write_text('module top(input logic changed); endmodule\n')
        reason = 'git-content-mismatch'
    else:
        (root / 'new.sv').write_text('module new_top; endmodule\n')
        document['source']['files'].append('new.sv')
        reason = 'git-content-mismatch'
    profile = load_component_profile(document)
    with patch('myfuzz.composition.component_profile.shutil.which') as tool:
        with pytest.raises(ComponentProfileError, match=reason):
            elaborate_profile(profile, base_dir=tmp_path, mode='direct')
        tool.assert_not_called()


@pytest.mark.parametrize('revision_kind', ('git', 'sha256'))
def test_direct_rechecks_source_bytes_after_frontend(pinned_profile, tmp_path, monkeypatch, revision_kind):
    document, root, source = pinned_profile
    if revision_kind == 'sha256':
        from myfuzz.composition.source_crawler import _content_hash
        document['source']['revision'] = _content_hash({'top.sv': source.read_bytes()})
    actual_run = subprocess.run

    def frontend(command, **kwargs):
        if '--json-only' not in command:
            return actual_run(command, **kwargs)
        Path(command[command.index('--json-only-output') + 1]).write_text('{}')
        Path(command[command.index('--json-only-meta-output') + 1]).write_text(json.dumps(
            {'files': {'top': {'filename': str(source), 'realpath': str(source)}}}))
        source.write_text('module top(input logic changed_during_compile); endmodule\n')
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(subprocess, 'run', frontend)
    monkeypatch.setattr('myfuzz.composition.source_elaboration.extract_physical_ports',
                        lambda *a, **kw: {'ports': []})
    with pytest.raises(ComponentProfileError, match='elaboration-source-changed'):
        elaborate_profile(load_component_profile(document), base_dir=tmp_path, mode='direct')


@pytest.mark.parametrize('fault', ('dirty', 'untracked'))
def test_direct_git_authenticates_include_files_before_launch(pinned_profile, tmp_path, fault):
    document, root, source = pinned_profile
    header = root / 'defs.svh'
    header.write_text('`define WIDTH 1\n')
    source.write_text('`include "defs.svh"\nmodule top(input logic [`WIDTH-1:0] clk); endmodule\n')
    git(root, 'add', 'top.sv', 'defs.svh')
    git(root, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.test',
        'commit', '-qm', 'include fixture')
    document['source']['revision'] = 'git:' + git(root, 'rev-parse', 'HEAD')
    document['source']['include_roots'] = ['.']
    if fault == 'dirty':
        header.write_text('`define WIDTH 8\n')
    else:
        (root / 'untracked.svh').write_text('`define EXTRA 8\n')
    with patch('myfuzz.composition.component_profile.shutil.which') as tool:
        with pytest.raises(ComponentProfileError, match='git-content-mismatch:'):
            elaborate_profile(load_component_profile(document), base_dir=tmp_path, mode='direct')
        tool.assert_not_called()


def test_direct_sha_explicit_pin_rejects_unpinned_actual_include(pinned_profile, tmp_path):
    from myfuzz.composition.source_crawler import _content_hash
    document, root, source = pinned_profile
    (root / 'defs.svh').write_text('`define WIDTH 8\n')
    source.write_text('`include "defs.svh"\nmodule top(input logic [`WIDTH-1:0] clk); endmodule\n')
    document['source']['revision'] = _content_hash({'top.sv': source.read_bytes()})
    document['source']['include_roots'] = ['.']
    with pytest.raises(ComponentProfileError, match='outside source closure'):
        elaborate_profile(load_component_profile(document), base_dir=tmp_path, mode='direct')
