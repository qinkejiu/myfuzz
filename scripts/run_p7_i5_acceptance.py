#!/usr/bin/env python3
"""Explicit, one-shot P7 I5 evidence collection from a caller-frozen snapshot."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True


NEGATIVES = (
    ('N1', 'tests/integration/test_compiled_artifact_admission.py::test_similarly_named_cpu_profile_cannot_borrow_loaded_cpu'),
    ('N2', 'tests/integration/test_auto_harness_test.py::test_an_explicit_capability_sidecar_is_matched_by_component_id'),
    ('N3', 'tests/onboarding/test_p7_n3_forced_apb3.py::test_forced_apb3_gpio_without_input_owner_emits_no_harness'),
    ('N4', 'tests/integration/test_compiled_f4_storage_producer.py::test_wrong_register_offset_width_mask_or_address_refused'),
    ('N5', 'tests/integration/test_generated_factory_consumption.py::test_supplied_artifact_kind_and_instance_are_checked_before_consumption'),
    ('N6', 'tests/local_harness/test_harness_set.py::test_an_undeclared_endpoint_is_refused_by_name'),
    ('N7', 'tests/integration/test_compiled_artifact_admission.py::test_uncompiled_physical_source_is_refused_instead_of_silently_added'),
    ('N8', 'tests/integration/test_auto_harness_test.py::test_a_composition_that_does_not_satisfy_the_family_is_refused'),
)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def source_map(root):
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError('snapshot-directory-symlink')
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('snapshot-link-or-special-file:' + str(path))
            result[path.relative_to(root).as_posix()] = {
                'sha256': digest(path), 'bytes': info.st_size,
                'mode': stat.S_IMODE(info.st_mode)}
    return dict(sorted(result.items()))


def child(argv, *, name, root, output, env):
    """Never kill or replace a child when its observation interval expires."""
    record = {'argv': [str(arg) for arg in argv], 'cwd': str(root),
              'started_unix': time.time(), 'returncode': None}
    with (output / (name + '.stdout')).open('xb') as stdout, \
            (output / (name + '.stderr')).open('xb') as stderr, \
            (output / (name + '.observations.jsonl')).open('x') as observations:
        process = subprocess.Popen(record['argv'], cwd=root, env=env,
                                   stdout=stdout, stderr=stderr, stdin=subprocess.DEVNULL)
        primary = None
        try:
            record['pid'] = process.pid
            write(output / (name + '.process.json'), record)
        except BaseException as error:
            primary = error
        finally:
            # All resources were opened before spawn. Even receipt-write errors
            # and interruptions after spawn must await this actual child.
            while True:
                try:
                    code = process.wait(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    try:
                        observations.write(json.dumps({'pid': process.pid,
                            'observed_unix': time.time(), 'poll': process.poll()}) + '\n')
                        observations.flush()
                    except BaseException as error:
                        if primary is None:
                            primary = error
                except BaseException as error:
                    if primary is None:
                        primary = error
            try:
                record.update(returncode=code, ended_unix=time.time(),
                              stdout_sha256=digest(output / (name + '.stdout')),
                              stderr_sha256=digest(output / (name + '.stderr')),
                              collection_error=repr(primary) if primary else None)
                write(output / (name + '.process.json'), record)
            except BaseException as error:
                if primary is None:
                    primary = error
            if primary is not None:
                raise primary
    return record


def git_state(root, output, env, phase):
    result = {}
    for key, args in [('commit', ['rev-parse', 'HEAD']),
                      ('dirty', ['status', '--porcelain=v1', '--untracked-files=all']),
                      ('submodules', ['submodule', 'status', '--recursive'])]:
        name = phase + '-git-' + key
        receipt = child(['git', '-C', root, *args], name=name,
                        root=root, output=output, env=env)
        if receipt['returncode'] != 0:
            raise ValueError('git-receipt-failed:' + name)
        result[key] = (output / (name + '.stdout')).read_text()
    write(output / (phase + '-git.json'), result)
    return result


def check_junit(path, selector):
    root = ET.parse(path).getroot()
    cases = list(root.iter('testcase'))
    expected = selector.split('::')[-1]
    if not cases or any(not row.attrib.get('name', '').split('[')[0] == expected for row in cases):
        raise ValueError('negative-fixture-not-executed:' + selector)
    if any(list(case) and any(node.tag in ('failure', 'error', 'skipped') for node in case)
           for case in cases) or any(True for _ in root.iter('error')):
        raise ValueError('negative-fixture-failed-or-skipped:' + selector)
    return {'executed': len(cases), 'failures': 0, 'errors': 0, 'skips': 0}


def check_real_gate(directory):
    from myfuzz.scenario.compiled_paths import compiled_document_sha256

    def load(name):
        return json.loads((directory / name).read_bytes())
    summary = load('run-summary.json')
    fresh = load('fresh-verification.json')
    join = load('compiled_receipt_join.v1.json')
    if summary.get('status') != 'complete' or summary.get('absences'):
        raise ValueError('real-gate-incomplete')
    session = summary['stages']['session']
    if session.get('status') != 'ok' or session.get('transport', {}).get('client_returncode') != 0:
        raise ValueError('real-client-not-successful')
    if fresh.get('matches') is not True or fresh.get('verification_scope') != 'full':
        raise ValueError('full-fresh-replay-not-matching')
    if 'first_difference' not in fresh or fresh['first_difference'] is not None:
        raise ValueError('fresh-first-difference-not-explicitly-null')
    for key in ('prefix_sha256', 'semantic_hash'):
        if not fresh.get('expected_' + key) or fresh['expected_' + key] != fresh.get('actual_' + key):
            raise ValueError('fresh-digest-mismatch:' + key)
    identities = fresh.get('original_process_identities', {})
    replay = fresh.get('fresh_process_identities', {})
    if set(identities) != {'processor', 'peripheral'} or set(replay) != set(identities):
        raise ValueError('missing-actual-process-identities')
    for component, original in identities.items():
        other = replay[component]
        if (type(original.get('pid')) is not int or original['pid'] <= 0
                or type(other.get('pid')) is not int or other['pid'] <= 0
                or original['pid'] == other['pid']
                or not original.get('execution_nonce')
                or not other.get('execution_nonce')
                or original['execution_nonce'] == other['execution_nonce']
                or not original.get('artifact_digest')
                or original['artifact_digest'] != other.get('artifact_digest')):
            raise ValueError('fresh-process-identity-not-distinct:' + component)
    receipts_path = directory / 'session/receipts.jsonl'
    receipts = [json.loads(line) for line in receipts_path.read_text().splitlines()]
    if (not receipts or join.get('status') != 'ok' or join.get('rows') != len(receipts)
            or join.get('status_counts') != {'certified': len(receipts)}
            or join.get('receipts_sha256') != digest(receipts_path)
            or join.get('compiled_sha256') != compiled_document_sha256(load('compiled_paths.v1.json'))
            or any(row.get('status') != 'certified' for row in receipts)
            or any(row.get('path_id') != 'F4:ram.image'
                   or row.get('source_id') != 'peripheral.TIMER0_CTRL.value.mmio'
                   for row in receipts)
            or join.get('source_id') != 'peripheral.TIMER0_CTRL.value.mmio'
            or join.get('path_id') != 'F4:ram.image'):
        raise ValueError('noncertified-or-unjoined-receipts')
    return {'status': 'structural_checks_passed_pending_independent_audit',
            'certified_receipts': len(receipts)}


def evidence_map(root):
    """Preserve output links as documentary links without following them."""
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            path = Path(directory) / name
            key = path.relative_to(root).as_posix()
            if path.is_symlink():
                result[key] = {'kind': 'symlink', 'target': os.readlink(path)}
            elif path.is_file():
                result[key] = {'kind': 'file', 'sha256': digest(path), 'bytes': path.stat().st_size}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base-dir', 'freeze-map', 'output', 'client-binary', 'lock-file', 'tool-freeze'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--client-sha256', required=True)
    parser.add_argument('--tool-freeze-sha256', required=True)
    parser.add_argument('--pythonlib', type=Path,
                        help='explicit external dependency directory after snapshot imports')
    parser.add_argument('--expected-commit', required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    root = args.base_dir.resolve(strict=True)
    output = args.output.absolute()
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(root):
        parser.error('--output must be new and outside the frozen source')
    if args.lock_file.resolve().is_relative_to(root):
        parser.error('--lock-file must be outside the frozen source')
    plan = {'schema_version': 'p7_i5_gate_runner.v1', 'execute': args.execute,
            'base_dir': str(root), 'expected_commit': args.expected_commit,
            'freeze_sha256': args.freeze_sha256, 'output': str(output),
            'client_binary': str(args.client_binary.absolute()),
            'client_sha256': args.client_sha256,
            'tool_freeze': str(args.tool_freeze.absolute()),
            'tool_freeze_sha256': args.tool_freeze_sha256,
            'pythonlib': str(args.pythonlib.absolute()) if args.pythonlib else None,
            'lock_file': str(args.lock_file.absolute()),
            'negative_selectors': dict(NEGATIVES),
            'native_gate': 'CV32E20+PULP_timer compiled-f4-rfuzz',
            'formal_p7_complete': False}
    if not args.execute:
        print(json.dumps(plan, indent=2))
        return 0
    if sys.flags.optimize or Path(__file__).resolve() != root / 'scripts/run_p7_i5_acceptance.py':
        parser.error('run the frozen snapshot runner with nonoptimized Python')
    sys.path[:0] = [str(root / 'src'), str(root)]
    if digest(args.freeze_map) != args.freeze_sha256:
        parser.error('freeze map digest mismatch')
    if digest(args.tool_freeze) != args.tool_freeze_sha256:
        parser.error('tool freeze digest mismatch')
    expected = json.loads(args.freeze_map.read_bytes())
    tools = json.loads(args.tool_freeze.read_bytes())
    if not {'git', 'verilator', 'c++', 'ar'} <= set(tools):
        parser.error('tool freeze must include git, verilator, c++, ar')
    for name, pin in tools.items():
        path = Path(pin['path']).resolve(strict=True)
        selected = shutil.which(name)
        if (selected is None or Path(selected).resolve() != path
                or digest(path) != pin['sha256'] or not os.access(path, os.X_OK)):
            parser.error('selected tool does not match freeze: ' + name)
    if args.pythonlib and not args.pythonlib.resolve(strict=True).is_dir():
        parser.error('pythonlib is not a directory')
    if digest(args.client_binary.resolve(strict=True)) != args.client_sha256:
        parser.error('client freeze mismatch')
    with args.lock_file.open('a+b') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('canonical heavy worker lock occupied; no queued execution')
        output.mkdir(parents=True, exist_ok=False)
        write(output / 'plan.json', plan)
        write(output / 'tool-freeze.json', tools)
        write(output / 'interpreter.json', {'executable': sys.executable,
              'resolved': str(Path(sys.executable).resolve()),
              'sha256': digest(Path(sys.executable).resolve()), 'version': sys.version})
        (output / 'tmp').mkdir()
        env = dict(os.environ, PYTHONPATH=str(root / 'src') + ':' + str(root),
                   PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='0',
                   GIT_OPTIONAL_LOCKS='0', TMPDIR=str(output / 'tmp'))
        if args.pythonlib:
            env['PYTHONPATH'] += ':' + str(args.pythonlib.resolve(strict=True))
        env.pop('PYTEST_ADDOPTS', None)
        env['PYTEST_DISABLE_PLUGIN_AUTOLOAD'] = '1'
        for override in ('CC', 'CXX', 'AR', 'MAKEFLAGS', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS'):
            env.pop(override, None)
        # No ambient foreign-source PYTHONPATH is inherited.
        result = {'status': 'failed', 'formal_p7_complete': False, 'negative_results': {}}
        before = None
        try:
            before = source_map(root)
            write(output / 'source-before.json', before)
            if before != expected:
                raise ValueError('whole-source-freeze-mismatch')
            git_before = git_state(root, output, env, 'before')
            if git_before['commit'].strip() != args.expected_commit:
                raise ValueError('expected-commit-mismatch')
            client = args.client_binary.resolve(strict=True)
            if digest(client) != args.client_sha256:
                raise ValueError('client-freeze-mismatch')
            write(output / 'client-before.json', {'path': str(client), 'sha256': digest(client)})
            for label, selector in NEGATIVES:
                junit = output / (label + '.xml')
                record = child([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider',
                                '--junitxml=' + str(junit), selector], name=label,
                               root=root, output=output, env=env)
                if record['returncode'] != 0:
                    raise ValueError('negative-child-failed:' + label)
                result['negative_results'][label] = check_junit(junit, selector)
            run = output / 'real-run'
            # The production CLI requires an existing external cache directory
            # before session admission. This operation owns a new empty cache;
            # its existence does not claim prebuilt artifacts or native success.
            native_cache = output / 'native-cache'
            native_cache.mkdir(exist_ok=False)
            scenario = root / 'configs/scenarios/compiled-f4-obi-apb-timer-cve2'
            argv = [sys.executable, root / 'scripts/auto_harness_test.py',
                    '--base-dir', root, '--cpu', root / 'configs/cpus/cv32e20/component_profile.json',
                    '--ip', root / 'configs/peripherals/pulp_timer/component_profile.json',
                    '--ip-capability', scenario / 'test_capability.json', '--compose', scenario / 'compose.json',
                    '--executor', 'compiled-f4-rfuzz', '--client-binary', client,
                    '--budget-seconds', '60', '--max-tests', '8', '--rounds-per-case', '32',
                    '--output', run, '--cache-dir', native_cache]
            record = child(argv, name='real-gate', root=root, output=output, env=env)
            if record['returncode'] != 0:
                raise ValueError('real-gate-child-failed')
            result['real_gate'] = check_real_gate(run)
            if digest(client) != json.loads((output / 'client-before.json').read_bytes())['sha256']:
                raise ValueError('client-mutated')
            result['status'] = 'collected_pending_independent_audit'
        except Exception as error:
            result['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            try:
                tools_after = {}
                for name, pin in tools.items():
                    tools_after[name] = {'path': pin['path'], 'sha256': digest(Path(pin['path']).resolve(strict=True))}
                    if tools_after[name]['sha256'] != pin['sha256']:
                        result['status'] = 'failed'
                        result['tool_mutation'] = True
                write(output / 'tools-after.json', tools_after)
                client_path = args.client_binary.resolve(strict=True)
                client_after = digest(client_path)
                write(output / 'client-after.json', {'path': str(client_path), 'sha256': client_after})
                if client_after != args.client_sha256:
                    result['status'] = 'failed'
                    result['client_mutation'] = True
                after = source_map(root)
                write(output / 'source-after.json', after)
                result['source_unchanged'] = before is not None and before == after
                git_state(root, output, env, 'after')
                if not result['source_unchanged']:
                    result['status'] = 'failed'
                    result['source_mutation'] = True
            except Exception as error:
                result['status'] = 'failed'
                result['collection_error'] = type(error).__name__ + ': ' + str(error)
            write(output / 'result.json', result)
            write(output / 'output-file-map.json', evidence_map(output))
        return 0 if result['status'] == 'collected_pending_independent_audit' else 1


if __name__ == '__main__':
    raise SystemExit(main())
