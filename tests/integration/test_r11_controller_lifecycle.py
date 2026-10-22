"""Pure software lifecycle fixtures; no native three-branch acceptance is claimed.

These tests enter claimed_run directly, bypassing frozen-package preflight. The
only controller patch redirects protected-root inventories to owned tmp trees.
All output gzip bytes are produced by a real dummy Python child, not a gate.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys

import pytest


CONTROLLER = Path(__file__).resolve().parents[2] / "scripts/task5_native_completion_r11/r11-one-shot-controller.v1.py"

DUMMY = r'''
import gzip, json, os, pathlib, sys, time
config = json.loads(sys.argv[1])
start = pathlib.Path(config['start'])
deadline = time.monotonic() + 10
while not start.exists():
    if time.monotonic() > deadline:
        raise RuntimeError('controller did not publish gate-start')
    time.sleep(.001)
receipt = json.loads(start.read_text())
assert receipt['pid'] == os.getpid()
if config['mode'] == 'observation':
    release = pathlib.Path(config['output'] + '.release')
    while not release.exists():
        if time.monotonic() > deadline:
            raise RuntimeError('observation did not release child')
        time.sleep(.001)
if config['mutate']:
    pathlib.Path(config['mutate']).write_text('drift')
print('dummy stdout', flush=True)
print('dummy stderr', file=sys.stderr, flush=True)
if config['mode'] != 'missing':
    output = pathlib.Path(config['output'])
    output.mkdir()
    statuses = {}
    for branch in ('positive', 'controlled-response', 'native-source-refusal'):
        status = ('native_source_completion_refusal_gate_passed' if branch ==
                  'native-source-refusal' else 'bounded_directed_gate_passed')
        statuses[branch] = status
        leaf = output / branch
        leaf.mkdir()
        doc = dict(gate_run_id=config['id'], gate_branch=branch,
                   gate_pid=os.getpid(), status=status)
        (leaf / 'result.json.gz').write_bytes(gzip.compress(json.dumps(doc).encode()))
    summary = dict(gate_run_id=config['id'], gate_pid=os.getpid(),
        schema_version='native_online_directed_gate.v1',
        positive_status=statuses['positive'], controlled_status=statuses['controlled-response'],
        native_source_refusal_status=statuses['native-source-refusal'],
        native_completion_observation=True, native_source_binding=True,
        native_source_completion=True, script_sha256=config['script_sha'])
    summary.update(config['claims'])
    (output / 'summary.json.gz').write_bytes(gzip.compress(json.dumps(summary).encode()))
sys.exit(7 if config['mode'] == 'nonzero' else 0)
'''


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@pytest.fixture
def lifecycle(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('r11_lifecycle_software', CONTROLLER)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    workspace = tmp_path / 'software-workspace'
    operation = workspace / 'operations' / 'software-only'
    (operation / 'control').mkdir(parents=True)
    project = operation / 'project'
    (project / 'module').mkdir(parents=True)
    (project / 'source').write_text('source')
    (project / 'module' / 'member').write_text('member')
    protected = workspace / 'software-protected'
    protected.mkdir()
    (protected / 'baseline').write_text('baseline')
    lock = workspace / 'lock'
    lock.write_text('lock')
    evidence = workspace / 'dummy-evidence'

    def scan(path):
        fd = controller.open_dir(str(path))
        try:
            return controller.scan_tree(fd)
        finally:
            os.close(fd)

    def protected_map():
        return {'schema_version': 'r11_protected_baselines_map.v1',
                'roots': [{'path': str(protected), 'entries': scan(protected)}]}

    # Isolate only the hard-coded remote protected map; retain genuine scans.
    monkeypatch.setattr(controller, 'protected_map_preflight', protected_map)
    rows = scan(project)
    selected = [row for row in rows if row['path'] == 'module' or row['path'].startswith('module/')]
    submodules = {'schema_version': 'r11_submodule_runtime_map.v1', 'entries': [{
        'path': 'module', 'tracked_mode': '160000', 'gitlink_commit': 'a' * 40,
        'checked_out': True, 'checked_out_head': 'a' * 40,
        'selected_entries_sha256': controller.digest(controller.canonical_ascii(selected)),
        'selected_entries_count': len(selected)}]}
    preflight = controller.Preflight(str(operation), rows, 'b' * 64,
                                     protected_map(), submodules)
    preflight.output_absent = True
    preflight.sole_authorized_writer = True
    opfd = controller.open_dir(str(operation))
    wsfd = controller.open_dir(str(workspace))
    preflight.write_preflight(opfd)
    frozen = {name: {'sha256': hashlib.sha256(name.encode()).hexdigest()}
              for name in ('plan', 'intent', 'controller', 'stage2_manifest',
                           'gate_script', 'source_manifest')}
    claim = {'pid': os.getpid()}
    run_id = 'c' * 64
    controller.write_json(opfd, controller.OUTPUTS['claim'],
                          dict(claim, gate_run_id=run_id))

    def invoke(mode='success', drift=None, owned=True):
        targets = {'source': project / 'source', 'submodule': project / 'module' / 'member',
                   'protected': protected / 'baseline', 'lock': lock}
        config = dict(start=str(operation / controller.OUTPUTS['gate_start']),
                      output=str(evidence), id=run_id, mode=mode,
                      script_sha=frozen['gate_script']['sha256'], claims=controller.CLAIMS,
                      mutate=str(targets[drift]) if drift else None)
        run = dict(argv=['python3', '-B', '-c', DUMMY, json.dumps(config)],
                   cwd=str(project), cache_dir=str(operation / 'native-cache'),
                   heavy_lock=str(lock))
        preflight.sole_authorized_writer = owned
        before = controller.lock_identity(wsfd, str(lock), str(workspace))
        error = None
        try:
            controller.claimed_run(opfd, wsfd, str(operation), str(evidence),
                str(workspace), run, run_id, frozen, dict(os.environ),
                str(workspace / 'absent-python') if mode == 'spawn' else sys.executable,
                preflight, before, claim)
        except (controller.Refusal, OSError) as exc:
            error = exc
        end = json.loads((operation / controller.OUTPUTS['gate_end']).read_text())
        post = json.loads((operation / controller.OUTPUTS['post_run_integrity']).read_text())
        return error, end, post

    yield controller, invoke, operation, evidence, run_id
    os.close(opfd)
    os.close(wsfd)


def test_real_dummy_child_success_and_disk_digest_joins(lifecycle):
    controller, invoke, operation, evidence, run_id = lifecycle
    error, end, post = invoke()
    assert error is None
    assert end['terminal_status'] == 'gate_process_completed'
    assert post['terminal_status'] == 'completed'
    assert end['reaped_by_wait'] is True
    assert end['process_group_gone'] is True
    assert controller.group_gone(end['process_group_id']) is True
    with pytest.raises(ChildProcessError):
        os.waitpid(end['pid'], os.WNOHANG)
    assert end['pid'] == end['process_group_id']
    assert end['gate_run_id'] == post['gate_run_id'] == run_id
    assert end['claims'] == post['claims'] == controller.CLAIMS
    assert post['gate_end'] == end
    assert post['gate_end_sha256'] == sha(operation / controller.OUTPUTS['gate_end'])
    for stream in ('stdout', 'stderr'):
        assert end[stream + '_sha256'] == sha(operation / controller.OUTPUTS['gate_' + stream])
    for branch in controller.BRANCHES:
        assert end['branch_result_sha256'][branch] == sha(evidence / branch / 'result.json.gz')
    assert end['summary_sha256'] == sha(evidence / 'summary.json.gz')
    for receipt in post['postflight_receipts'].values():
        assert receipt['sha256'] == sha(receipt['path'])
    assert all(post[key] is True for key in ('output_created_by_gate',
        'source_tree_matches_preflight', 'protected_baselines_match_preflight',
        'submodules_match_preflight', 'canonical_lock_matches_preflight'))


@pytest.mark.parametrize('mode', ['nonzero', 'missing', 'spawn'])
def test_failed_child_lifecycle_is_terminal_failure(lifecycle, mode):
    controller, invoke, operation, evidence, run_id = lifecycle
    error, end, post = invoke(mode)
    assert error is not None
    assert end['terminal_status'] == post['terminal_status'] == 'failed'
    assert end['gate_run_id'] == post['gate_run_id'] == run_id
    if mode == 'spawn':
        assert end['failure_stage'] == 'spawn'
        assert end['reaped_by_wait'] is False
        assert 'pid' not in end
    else:
        assert end['reaped_by_wait'] is end['process_group_gone'] is True
        assert controller.group_gone(end['process_group_id'])
        assert end['returncode'] == (7 if mode == 'nonzero' else 0)
    if mode == 'missing':
        assert not evidence.exists()
        assert post['output_created_by_gate'] is False


@pytest.mark.parametrize('drift,field', [
    ('source', 'source_tree_matches_preflight'),
    ('submodule', 'submodules_match_preflight'),
    ('protected', 'protected_baselines_match_preflight'),
    ('lock', 'canonical_lock_matches_preflight'),
])
def test_real_postflight_drift_refuses_completion(lifecycle, drift, field):
    controller, invoke, operation, evidence, run_id = lifecycle
    error, end, post = invoke(drift=drift)
    assert error is not None
    assert end['terminal_status'] == 'gate_process_completed'
    assert post['terminal_status'] == 'failed'
    assert post[field] is False
    assert end['reaped_by_wait'] is end['process_group_gone'] is True
    assert controller.group_gone(end['process_group_id'])


def test_output_ownership_requires_exclusive_writer_receipt(lifecycle):
    _, invoke, _, _, _ = lifecycle
    error, end, post = invoke(owned=False)
    assert error is not None
    assert end['terminal_status'] == post['terminal_status'] == 'failed'
    assert post['output_created_by_gate'] is False



def test_observation_write_error_keeps_same_real_child_until_reaped(lifecycle, monkeypatch):
    controller, invoke, operation, evidence, _ = lifecycle
    real_popen = controller.subprocess.Popen
    real_write = controller.write_json
    children = []
    waits = []
    failures = []

    def tracked_popen(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        real_wait = child.wait

        def tracked_wait(*wait_args, **wait_kwargs):
            waits.append(child.pid)
            return real_wait(*wait_args, **wait_kwargs)

        child.wait = tracked_wait
        return child

    def write_with_observation_failure(opfd, relative, value):
        if relative.startswith('control/observation-'):
            failures.append(value)
            # The genuine child cannot exit before this failed observation.
            Path(str(evidence) + '.release').write_text('release')
            raise OSError('software observation receipt failure')
        return real_write(opfd, relative, value)

    monkeypatch.setattr(controller, 'WAIT_INTERVAL', .01)
    monkeypatch.setattr(controller.subprocess, 'Popen', tracked_popen)
    monkeypatch.setattr(controller, 'write_json', write_with_observation_failure)
    error, end, post = invoke('observation')
    assert error is not None
    assert len(children) == 1
    assert failures and len(waits) >= 2
    assert set(waits) == {children[0].pid} == {end['pid']}
    assert end['returncode'] == children[0].returncode == 0
    assert end['reaped_by_wait'] is end['process_group_gone'] is True
    assert controller.group_gone(end['process_group_id'])
    assert end['terminal_status'] == post['terminal_status'] == 'failed'
    assert any('software observation receipt failure' in item for item in end['observation_errors'])
    with pytest.raises(ChildProcessError):
        os.waitpid(children[0].pid, os.WNOHANG)


@pytest.mark.parametrize('observation', ['error', 'still-live'])
def test_group_observation_refusal_never_grants_completion(lifecycle, monkeypatch, observation):
    controller, invoke, operation, _, _ = lifecycle
    observed = []

    def controlled_observe(pgid, deadline):
        observed.append(pgid)
        if observation == 'error':
            raise OSError('software group observation error')
        return False

    # Fault injection covers refusal control flow, not actual live descendants.
    monkeypatch.setattr(controller, 'observe_group', controlled_observe)
    error, end, post = invoke()
    assert error is not None
    assert observed and set(observed) == {end['pid']}
    assert end['failure_stage'] == 'process-group-observation'
    assert end['terminal_status'] == post['terminal_status'] == 'failed'
    assert end['reaped_by_wait'] is True
    assert end['returncode'] == 0
    assert controller.group_gone(end['process_group_id']) is True
    assert 'output_created_by_gate' not in post
    assert not (operation / controller.OUTPUTS['source_postflight']).exists()
    if observation == 'error':
        assert 'process_group_observation_error' in end
        assert 'process_group_gone' not in end
    else:
        assert end['process_group_gone'] is post['process_group_gone'] is False
    with pytest.raises(ChildProcessError):
        os.waitpid(end['pid'], os.WNOHANG)
