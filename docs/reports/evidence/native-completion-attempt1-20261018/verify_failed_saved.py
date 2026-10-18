"""Pure saved-control audit of the failed first attempt, not a DUT checker."""
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
sha = lambda data: hashlib.sha256(data).hexdigest()
with tarfile.open(ROOT / 'remote-terminal-controls.tar.gz') as archive:
    contents, members = {}, []
    for member in archive.getmembers():
        p = Path(member.name)
        assert not p.is_absolute() and '..' not in p.parts
        assert member.isfile() or member.isdir()
        assert member.name not in contents
        data = archive.extractfile(member).read() if member.isfile() else None
        contents[member.name] = data
        members.append(dict(path=member.name, kind='file' if data is not None else 'directory',
                            bytes=len(data) if data is not None else 0,
                            sha256=sha(data) if data is not None else None))
load = lambda name: json.loads(contents[name])
parent = load('gate-control/parent-terminal.json')
child = load('gate-control/native-directed-gate.terminal.json')
observation = load('readonly-terminal-observation.json')
assert parent['pid'] == 3107064 and parent['returncode'] == parent['gate_returncode'] == 1
assert parent['status'] == 'failed' and parent['errors'] == []
assert child['pid'] == 3130216 and child['returncode'] == 1 and child['error'] is None
assert not any(observation['specified_pid_presence'].values())
assert observation['cache']['files'] == observation['cache']['directories'] == {}
assert observation['run_directed']['files'] == {}
assert set(observation['run_directed']['directories']) == {'positive'}
assert contents['run-directed/positive'] is None
for kind, pinned in (('files', '94de100ab2ab50f3674f179378c9138d73cec873c68ae401bc43f9cb63e76cd1'),
                     ('directories', '861e192518e1d809231b676b91b17c149466000f83138969eac6cbfaff68fb36')):
    assert contents[f'gate-control/before-{kind}.json'] == contents[f'gate-control/after-{kind}.json']
    assert sha(contents[f'gate-control/before-{kind}.json']) == pinned
assert contents['gate-control/before-tools.json'] == contents['gate-control/after-tools.json']
tools = load('gate-control/before-tools.json')
assert tools['environment_sha256'] == '9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c'
assert tools['inventory_sha256'] == '9672f2b6ab65a587c8533e574851cf8990ead9867e0d089d0c3f030af1470d10'
assert len(tools['verilator_share']) == 115 and len(tools['pythonlib_files']) == 581
for name in [row['name'] for row in parent['git_metadata']] + ['native-directed-gate']:
    terminal = load(f'gate-control/{name}.terminal.json')
    assert terminal['returncode'] == (1 if name == 'native-directed-gate' else 0)
    for stream in ('stdout', 'stderr'):
        assert sha(contents[f'gate-control/{name}.{stream}']) == terminal[f'{stream}_sha256']
for stream in ('stdout', 'stderr'):
    assert sha(contents[f'gate-parent.{stream}']) == parent[f'{stream}_sha256']
assert contents['gate-control/git-root-head.stdout'].decode().strip() == '6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941'
assert sha(contents['inputs/run_native_gate.py']) == parent['controller_sha256']
error = contents['gate-control/native-directed-gate.stderr'].decode()
assert "raise ValueError('native-physical-observation-protocol-unsupported')" in error
assert 'plan.py", line 212' in error
assert not any(name.endswith(('first.json.gz', 'fresh-comparison.json.gz', 'result.json.gz', 'summary.json.gz')) for name in contents)
print(json.dumps(dict(schema_version='native_completion_failed_attempt_saved_audit.v1',
    status='actual_failed_planning_attempt_confirmed', parent_pid=parent['pid'], gate_pid=child['pid'],
    parent_returncode=1, gate_returncode=1, git_returncodes=[r['returncode'] for r in parent['git_metadata']],
    no_saved_cases_or_model_receipts=True, cache_empty=True, positive_directory_empty=True,
    specified_parent_and_child_gone=True, source_files_directories_unchanged=True,
    tools_environment_unchanged=True, failure='native-physical-observation-protocol-unsupported',
    failure_source='frozen src/myfuzz/local_harness/plan.py:212',
    frontend_elaboration_may_have_occurred=True, native_gate_pass=False,
    native_completion_observed=False, full_fresh_pass=False, formal_p6_complete=False,
    observation=observation, members=members), sort_keys=True, indent=2))
