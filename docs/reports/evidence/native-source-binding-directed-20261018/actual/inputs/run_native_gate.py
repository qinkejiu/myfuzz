"""Explicit native-completion parent controller. Preparing this file runs nothing."""
import sys
sys.dont_write_bytecode = True
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

BASE = Path('/root/fanzehui/myfuzz/operations/p6-native-source-binding-20261018-attempt1')
ROOT = BASE / 'project'
CONTROL = BASE / 'gate-control'
COPY = BASE / 'control'
ENVBASE = Path('/root/fanzehui/myfuzz/operations/environment-20261018-attempt3')
LOCK = Path('/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock')
INVENTORY = Path('/root/fanzehui/myfuzz/operations/p7-i5-independent-6b40ef4-20261018-attempt1/control/tool-inventory.json')
GATE_SHA = '00401f20c9ec4ea098086557969b9e610a9b7268b67118978da06bfe803c3bb7'
ENV_SHA = '9141ae65b8af8a0a1fdd891b64afb6bfc1cf4497a686bf14e35f0d926574f15c'
TOOLS_SHA = '6591a2023be5c4564d72d4a224d8c6c4b543fd811884f540355273eefbd63b4b'
INVENTORY_SHA = '9672f2b6ab65a587c8533e574851cf8990ead9867e0d089d0c3f030af1470d10'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(name, document):
    with (CONTROL / name).open('x') as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def no_links(path):
    require(path.is_absolute() and path.is_relative_to('/root/fanzehui'), 'path-outside-authorized-root')
    for part in (path, *path.parents):
        require(not part.is_symlink(), 'symlink-path:' + str(part))


def snapshot(root):
    no_links(root)
    files, directories = {}, {}
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(parent) / name
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode), 'directory-link-or-special:' + str(path))
            directories[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            path = Path(parent) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'file-link-or-special:' + str(path))
            files[path.relative_to(root).as_posix()] = dict(bytes=info.st_size,
                mode=stat.S_IMODE(info.st_mode), sha256=sha(path))
    return dict(sorted(files.items())), dict(sorted(directories.items()))


def child(name, argv):
    record = dict(argv=[str(x) for x in argv], cwd=str(ROOT), started_unix=time.time(), returncode=None)
    primary = None
    proc = None
    with (CONTROL / (name + '.stdout')).open('xb') as out, (CONTROL / (name + '.stderr')).open('xb') as err:
        try:
            proc = subprocess.Popen(record['argv'], cwd=ROOT, env=os.environ.copy(),
                stdin=subprocess.DEVNULL, stdout=out, stderr=err)
            record['pid'] = proc.pid
            write(name + '.launch.json', record)
        except BaseException as error:
            primary = error
        finally:
            if proc is not None:
                while True:
                    try:
                        record['returncode'] = proc.wait(timeout=30)
                        break
                    except subprocess.TimeoutExpired:
                        continue
                    except BaseException as error:
                        if primary is None:
                            primary = error
    record['ended_unix'] = time.time()
    for stream_name in ('stdout', 'stderr'):
        try:
            record[stream_name + '_sha256'] = sha(CONTROL / (name + '.' + stream_name))
        except BaseException as error:
            if primary is None:
                primary = error
    record['error'] = repr(primary) if primary else None
    try:
        write(name + '.terminal.json', record)
    except BaseException as error:
        if primary is None:
            primary = error
    if primary is not None:
        raise primary
    return record['returncode']


def layout(phase, expected_files, expected_dirs):
    actual_files, actual_dirs = snapshot(ROOT)
    write(phase + '-files.json', actual_files)
    write(phase + '-directories.json', actual_dirs)
    require(actual_files == expected_files, phase + '-file-layout-drift')
    require(actual_dirs == expected_dirs, phase + '-directory-layout-drift')
    write(phase + '-layout.json', dict(status='verified_files_and_directories',
        files=len(actual_files), directories=len(actual_dirs)))


def tool_check(phase):
    # Recheck metadata identities every phase, rather than trusting preloaded dicts.
    no_links(ENVBASE)
    no_links(INVENTORY)
    require(sha(ENVBASE / 'tool-freeze.json') == TOOLS_SHA, 'tool-manifest-drift')
    require(sha(ENVBASE / 'environment.sh') == ENV_SHA, 'environment-drift')
    require(sha(INVENTORY) == INVENTORY_SHA, 'inventory-drift')
    tools = json.loads((ENVBASE / 'tool-freeze.json').read_bytes())
    inventory = json.loads(INVENTORY.read_bytes())
    for name, pin in tools.items():
        selected = shutil.which(name)
        require(selected is not None and str(Path(selected).resolve()) == pin['path']
                and sha(Path(selected).resolve()) == pin['sha256'], 'selected-tool-drift:' + name)
    require(str(Path(sys.executable).resolve()) == tools['python3']['path']
            and sha(Path(sys.executable).resolve()) == tools['python3']['sha256'], 'interpreter-drift')
    for section in ('verilator_share', 'system_entrypoints'):
        for name, pin in inventory[section].items():
            require(sha(Path(pin['resolved'])) == pin['sha256'], 'tool-dependency-drift:' + name)
    def content_map(root):
        no_links(root)
        result = {}
        for parent, dirs, names in os.walk(root, followlinks=False):
            for name in dirs:
                require(not (Path(parent) / name).is_symlink(), 'dependency-directory-link')
            for name in names:
                path = Path(parent) / name
                require(path.is_file() and not path.is_symlink(), 'dependency-file-link')
                result[path.relative_to(root).as_posix()] = dict(bytes=path.stat().st_size, sha256=sha(path))
        return result
    share = content_map(Path('/root/fanzehui/myfuzz/tools/verilator-5.051/share/verilator'))
    expected_share = {str(Path(k).relative_to('share/verilator')):
                      {field: v[field] for field in ('bytes', 'sha256')}
                      for k, v in inventory['verilator_share'].items()}
    require(len(share) == 115 and share == expected_share, 'verilator-share-set-drift')
    library = content_map(Path('/root/fanzehui/myfuzz/pythonlib'))
    require(len(library) == 581 and library == inventory['pythonlib_files'], 'pythonlib-set-drift')
    write(phase + '-tools.json', dict(entrypoints=tools, system_entrypoints=inventory['system_entrypoints'],
        environment_sha256=ENV_SHA, inventory_sha256=INVENTORY_SHA,
        verilator_share=share, pythonlib_files=library))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--freeze-sha256', required=True)
    parser.add_argument('--receipt-sha256', required=True)
    parser.add_argument('--directories-file-sha256', required=True)
    args = parser.parse_args()
    no_links(BASE)
    CONTROL.mkdir(exist_ok=False)
    parent = dict(schema_version='native_completion_gate_parent.v1', pid=os.getpid(),
        started_unix=time.time(), argv=sys.argv, cwd=str(Path.cwd()),
        controller_sha256=sha(Path(__file__)), formal_p6_complete=False)
    primary = None
    errors = []
    gate_rc = None
    expected_files = expected_dirs = None
    metadata = []
    def failure(error, phase):
        nonlocal primary
        if primary is None:
            primary = error
        errors.append(dict(phase=phase, error=repr(error)))
    try:
        write('parent-start.json', parent)
        no_links(LOCK)
        no_links(ENVBASE)
        no_links(INVENTORY)
        for name, pin in (('final-file-freeze.json', args.freeze_sha256),
                          ('copy-receipt.json', args.receipt_sha256),
                          ('final-directories.json', args.directories_file_sha256)):
            no_links(COPY / name)
            require(sha(COPY / name) == pin, 'caller-pin-mismatch:' + name)
        expected_files = json.loads((COPY / 'final-file-freeze.json').read_bytes())
        expected_dirs = json.loads((COPY / 'final-directories.json').read_bytes())
        receipt = json.loads((COPY / 'copy-receipt.json').read_bytes())
        require(receipt['status'] == 'prepared_pending_independent_review_no_execution'
                and receipt['source_unchanged'] is True and receipt['native_run'] is False
                and receipt['destination'] == str(ROOT) and receipt['host_paths'] == 70
                and receipt['files'] == len(expected_files) and receipt['directories'] == len(expected_dirs)
                and receipt['freeze_sha256'] == args.freeze_sha256, 'copy-receipt-invalid')
        require(sha(ROOT / 'scripts/verify_picorv32_native_online.py') == GATE_SHA, 'gate-script-drift')
        layout('before', expected_files, expected_dirs)
        tool_check('before')
        no_links(LOCK)
        with LOCK.open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            commands = [('git-root-head', ['git', 'rev-parse', 'HEAD']),
                        ('git-closures-tracked', ['git', 'ls-files', '--error-unmatch',
                         'configs/soc/closures/picorv32.json', 'configs/soc/closures/pulp_gpio.json'])]
            for component in ('picorv32_upstream_reference', 'soc-pulp-apb-gpio'):
                commands.append(('git-' + component + '-connectivity', ['git', '-C',
                    ROOT / 'third_party' / component, 'fsck', '--connectivity-only', '--no-dangling']))
            for name, argv in commands:
                rc = child(name, argv)
                metadata.append(dict(name=name, returncode=rc))
                require(rc == 0, 'git-preflight-failed:' + name)
            require((CONTROL / 'git-root-head.stdout').read_text().strip()
                    == '6b40ef4a5c13f01d50a1103dabbdffd2dd4c8941', 'root-head-drift')
        # The gate takes the same canonical lock itself, once and nonblocking.
        # Releasing this preflight lock avoids self-deadlock; contention at gate
        # start fails there without running a second worker.
        no_links(BASE / 'cache-native')
        require(not (BASE / 'run-directed').exists(), 'output-already-exists')
        (BASE / 'cache-native').mkdir(exist_ok=False)
        gate_rc = child('native-directed-gate', [sys.executable,
            ROOT / 'scripts/verify_picorv32_native_online.py', '--output', BASE / 'run-directed',
            '--cache-dir', BASE / 'cache-native', '--heavy-lock', LOCK,
            '--native-completion-observation', '--native-source-binding'])
    except BaseException as error:
        failure(error, 'operation')
    finally:
        # Each collection is independent: failed layout must not skip tool check.
        try:
            if expected_files is not None and expected_dirs is not None:
                layout('after', expected_files, expected_dirs)
            else:
                files, dirs = snapshot(ROOT)
                write('after-files.json', files)
                write('after-directories.json', dirs)
        except BaseException as error:
            failure(error, 'layout-after')
        try:
            tool_check('after')
        except BaseException as error:
            failure(error, 'tools-after')
        try:
            for name, pin in (('final-file-freeze.json', args.freeze_sha256),
                              ('copy-receipt.json', args.receipt_sha256),
                              ('final-directories.json', args.directories_file_sha256)):
                require(sha(COPY / name) == pin, 'after-caller-pin-mismatch:' + name)
        except BaseException as error:
            failure(error, 'copy-pins-after')
        try:
            sys.stdout.flush()
            sys.stderr.flush()
            parent['stdout_sha256'] = sha(BASE / 'gate-parent.stdout')
            parent['stderr_sha256'] = sha(BASE / 'gate-parent.stderr')
        except BaseException as error:
            failure(error, 'parent-output-hashes')
        parent.update(ended_unix=time.time(), gate_returncode=gate_rc, git_metadata=metadata,
            status='collected_pending_independent_audit' if primary is None and gate_rc == 0 else 'failed',
            errors=errors, returncode=0 if primary is None and gate_rc == 0 else 1)
        try:
            write('parent-terminal.json', parent)
        except BaseException as error:
            failure(error, 'parent-terminal-write')
            parent['returncode'] = 1
            parent['status'] = 'failed'
    # Errors are retained in the terminal receipt. Do not append a traceback
    # after hashing the parent's own final stdout/stderr bytes.
    return 1 if primary is not None else parent['returncode']


if __name__ == '__main__':
    raise SystemExit(main())
