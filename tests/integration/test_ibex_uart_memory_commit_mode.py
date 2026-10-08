"""Saved UART replay selects the explicit host-memory commit stream mode."""
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.integration.ibex_uart_online import (
    _saved_memory_commit_mode, _saved_memory_readback_mode)
from myfuzz.scenario.ibex_uart_online import make_ibex_uart_online_factory


def _saved(tmp_path, contract=None, readback=None):
    identity = {}
    if contract is not None:
        identity['memory_commit_stream'] = contract
    if readback is not None:
        identity['memory_read_issuance'] = readback
    raw = json.dumps({'runner': {'sessions': {'cpu': {'identity': identity}}}}).encode()
    (tmp_path / 'online_session_manifest.json').write_bytes(raw)
    verified = {'artifacts': {
        'online_session_manifest.json': hashlib.sha256(raw).hexdigest()}}
    return verified


def test_saved_memory_commit_mode_requires_verified_exact_contract(tmp_path):
    assert _saved_memory_commit_mode(tmp_path, _saved(tmp_path)) is False
    contract = {'schema_version': 'memory_write_commit_stream.v1', 'capacity': 256}
    assert _saved_memory_commit_mode(tmp_path, _saved(tmp_path, contract)) is True
    with pytest.raises(ValueError):
        _saved_memory_commit_mode(tmp_path,
            _saved(tmp_path, {'schema_version': 'memory_write_commit_stream.v1',
                              'capacity': True}))
    raw = json.dumps({'runner': {'sessions': {'cpu': {'identity': {
        'memory_commit_stream': None}}}}}).encode()
    (tmp_path / 'online_session_manifest.json').write_bytes(raw)
    verified = {'artifacts': {
        'online_session_manifest.json': hashlib.sha256(raw).hexdigest()}}
    with pytest.raises(ValueError):
        _saved_memory_commit_mode(tmp_path, verified)


def test_memory_commit_mode_requires_native_uart_probes(tmp_path):
    with pytest.raises(ValueError):
        make_ibex_uart_online_factory(tmp_path, memory_commit=True)


def test_readback_mode_requires_live_commit_and_verified_identity(tmp_path):
    with pytest.raises(ValueError):
        make_ibex_uart_online_factory(tmp_path, memory_readback=True)
    assert _saved_memory_readback_mode(tmp_path, _saved(tmp_path)) is False
    contract = {'schema_version': 'memory_read_authority.v1', 'capacity': 256}
    assert _saved_memory_readback_mode(tmp_path,
        _saved(tmp_path, readback=contract)) is True
    with pytest.raises(ValueError):
        _saved_memory_readback_mode(tmp_path,
            _saved(tmp_path, readback={'schema_version': 'memory_read_authority.v1',
                                       'capacity': True}))


def test_cli_forwards_explicit_memory_commit_flag(tmp_path):
    script = Path(__file__).resolve().parents[2] / 'scripts/run_ibex_uart_online.py'
    spec = importlib.util.spec_from_file_location('uart_memory_commit_cli_test', script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    result = SimpleNamespace(output_dir=tmp_path / 'new', tests=0,
        statuses={}, elapsed_seconds=0, effective_search_seconds=0)
    args = ['run', '--client-binary', '/tmp/client', '--cache-dir', '/tmp/cache',
        '--output', str(tmp_path / 'new'), '--cpu-retirement', '--uart-fifo',
        '--memory-commit']
    with patch.object(module, 'make_ibex_uart_online_runtime',
            return_value=SimpleNamespace(executor=object())) as runtime, \
         patch.object(module, 'run_scenario_rfuzz_live', return_value=result), \
         patch('builtins.print'):
        assert module.main(args) == 0
    assert runtime.call_args.kwargs['memory_commit'] is True
