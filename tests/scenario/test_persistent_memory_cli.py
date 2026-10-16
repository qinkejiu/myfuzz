"""CLI admission and forwarding only; no RTL execution."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def cli():
    script = Path(__file__).resolve().parents[2] / 'scripts/run_ibex_pulp_online.py'
    spec = importlib.util.spec_from_file_location('_persistent_memory_cli', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('enabled', [False, True])
def test_cli_trusted_memory_mode_is_explicit_and_forwarded(cli, tmp_path, monkeypatch, enabled):
    observed = []
    def runtime(**kwargs):
        observed.append(kwargs)
        return SimpleNamespace(executor=object())
    monkeypatch.setattr(cli, 'make_ibex_pulp_online_runtime', runtime)
    monkeypatch.setattr(cli, 'run_scenario_rfuzz_live', lambda **kwargs: SimpleNamespace(
        output_dir=tmp_path / 'new', tests=1, statuses={}, elapsed_seconds=1,
        effective_search_seconds=1))
    args = ['run', '--client-binary', '/tmp/client', '--cache-dir', str(tmp_path / 'cache'),
            '--output', str(tmp_path / 'new')]
    if enabled:
        args += ['--memory-commit', '--persistent-memory-prerequisites']
    assert cli.main(args) == 0
    assert observed[0].get('persistent_memory_prerequisites', False) is enabled
    if not enabled:
        assert 'persistent_memory_prerequisites' not in observed[0]


def test_cli_missing_commit_rejects_before_runtime_construction(cli, tmp_path, monkeypatch, capsys):
    def forbidden(**kwargs):
        pytest.fail('invalid CLI combination constructed runtime')
    monkeypatch.setattr(cli, 'make_ibex_pulp_online_runtime', forbidden)
    assert cli.main(['run', '--client-binary', '/tmp/client', '--cache-dir', str(tmp_path),
        '--output', str(tmp_path / 'new'), '--persistent-memory-prerequisites']) == 1
    assert 'requires --memory-commit' in capsys.readouterr().err
    assert not (tmp_path / 'new').exists()
