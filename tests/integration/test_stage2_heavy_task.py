from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.experiments.resource_policy import ResourceProfileError

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT/'scripts'/'run_stage2_heavy_task.py'
GIB = 1024**3


def _load_cli(monkeypatch):
    import importlib.util
    from myfuzz.experiments import resource_policy
    spec = importlib.util.spec_from_file_location('stage2_heavy_task_test_cli', CLI)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(resource_policy, 'available_process_memory', lambda: 5*GIB)
    return module


def test_stage2_heavy_entry_creates_one_shared_cache_and_fresh_run(tmp_path, monkeypatch):
    run = tmp_path/'run-a'
    cache = tmp_path/'cache'
    command = [sys.executable, '-c',
               'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text("artifact"); print(p)',
               '{run_dir}/payload.txt']
    module = _load_cli(monkeypatch)
    assert module.main(['--output-dir', str(run), '--cache-dir', str(cache),
                        '--', *command]) == 0
    assert (run/'payload.txt').read_text() == 'artifact'
    receipt = json.loads((run/'stage2_heavy_task_receipt.json').read_text())
    assert receipt['status'] == 'complete'
    assert receipt['resource']['workers'] == 1
    assert receipt['build_cache'] == str(cache.resolve())
    assert receipt['command'][3] == str(run.resolve())+'/payload.txt'
    assert receipt['stdout_sha256'] == hashlib.sha256((run/'stdout.log').read_bytes()).hexdigest()
    assert receipt['stderr_sha256'] == hashlib.sha256((run/'stderr.log').read_bytes()).hexdigest()


def test_stage2_heavy_entry_refuses_existing_run_and_preserves_receipt(tmp_path, monkeypatch):
    run = tmp_path/'run'
    run.mkdir()
    (run/'stage2_heavy_task_receipt.json').write_text('old receipt')
    module = _load_cli(monkeypatch)
    assert module.main(['--output-dir', str(run), '--', sys.executable, '-c', 'pass']) == 1
    assert (run/'stage2_heavy_task_receipt.json').read_text() == 'old receipt'


def test_stage2_heavy_entry_persists_child_failure(tmp_path, monkeypatch):
    run = tmp_path/'run'
    module = _load_cli(monkeypatch)
    assert module.main(['--output-dir', str(run), '--', sys.executable, '-c',
                        'raise SystemExit(7)']) == 7
    receipt = json.loads((run/'stage2_heavy_task_receipt.json').read_text())
    assert receipt['status'] == 'command_failed'
    assert receipt['command_exit_code'] == 7
    assert receipt['resource']['dut_finding'] is False


def test_stage2_heavy_entry_persists_process_launch_failure(tmp_path, monkeypatch):
    run = tmp_path/'run'
    module = _load_cli(monkeypatch)
    missing = tmp_path/'missing-command'
    assert module.main(['--output-dir', str(run), '--', str(missing)]) == 1
    receipt = json.loads((run/'stage2_heavy_task_receipt.json').read_text())
    assert receipt['status'] == 'launch_failed'
    assert receipt['command_exit_code'] is None
    assert receipt['resource']['status'] == 'launch_failed'
    assert receipt['resource']['dut_finding'] is False
    assert (run/'stdout.log').is_file()
    assert (run/'stderr.log').is_file()


def test_stage2_heavy_entry_persists_startup_resource_refusal(tmp_path, monkeypatch):
    module = _load_cli(monkeypatch)
    def refuse(*args, **kwargs):
        error = ResourceProfileError('insufficient memory for heavy task')
        error.resource_receipt = {'status': 'startup_refused', 'dut_finding': False}
        raise error
    monkeypatch.setattr(module, 'run_budgeted_process', refuse)
    run = tmp_path/'run'
    assert module.main(['--output-dir', str(run), '--', sys.executable, '-c', 'pass']) == 1
    receipt = json.loads((run/'stage2_heavy_task_receipt.json').read_text())
    assert receipt['status'] == 'startup_refused'
    assert receipt['resource']['dut_finding'] is False


def test_stage2_heavy_entry_rejects_jvm_without_heap_before_launch(tmp_path, monkeypatch):
    run = tmp_path/'run'
    module = _load_cli(monkeypatch)
    assert module.main(['--output-dir', str(run), '--', 'java', '-jar',
                        'generator.jar']) == 1
    receipt = json.loads((run/'stage2_heavy_task_receipt.json').read_text())
    assert receipt['status'] == 'startup_refused'
    assert 'explicit JVM heap' in receipt['error']
