#!/usr/bin/env python3
"""Explicit pure preparation controller; never launches tests, builds or tools."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ALLOWED = Path('/root/fanzehui')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def safe(path):
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(ALLOWED):
        raise ValueError('path-outside-authorized-root:' + str(path))
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('path-symlink:' + str(path))
    return path


def relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or str(path) != name or name == '.':
        raise ValueError('noncanonical-relative-path')
    return path


def maps(root):
    files, directories = {}, {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('directory-symlink-or-special')
            directories[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('file-link-or-special')
            files[path.relative_to(root).as_posix()] = {
                'sha256': sha(path), 'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode)}
    return dict(sorted(files.items())), dict(sorted(directories.items()))


def map_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def copy_file(source, target, pin):
    with source.open('rb') as reader, target.open('xb') as writer:
        while chunk := reader.read(1024 * 1024):
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    target.chmod(pin['mode'])
    if sha(source) != pin['sha256'] or sha(target) != pin['sha256']:
        raise ValueError('copy-source-or-destination-hash-drift')


def child(argv, control, name, env):
    receipt = {'argv': [str(arg) for arg in argv], 'started_unix': time.time()}
    primary = None
    with (control / (name + '.stdout')).open('xb') as stdout, \
            (control / (name + '.stderr')).open('xb') as stderr:
        process = subprocess.Popen(receipt['argv'], env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        try:
            receipt['pid'] = process.pid
            write(control / (name + '.launch.json'), receipt)
        except BaseException as error:
            primary = error
        finally:
            while True:
                try:
                    code = process.wait(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    pass
                except BaseException as error:
                    if primary is None:
                        primary = error
            receipt.update(returncode=code, ended_unix=time.time(),
                           collection_error=repr(primary) if primary else None)
            try:
                write(control / (name + '.terminal.json'), receipt)
            except BaseException as error:
                if primary is None:
                    primary = error
            if primary is not None:
                raise primary
    if code:
        raise ValueError('preparer-child-nonzero:' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'source-freeze', 'new-operation', 'directory-repairs', 'preparer-overlay'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('source-freeze-sha256', 'directory-repairs-sha256', 'preparer-overlay-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--prepare-reviewed-hash')
    args = parser.parse_args()
    source, freeze, base, repair_path, overlay = [safe(path) for path in (
        args.source, args.source_freeze, args.new_operation, args.directory_repairs, args.preparer_overlay)]
    if base.is_relative_to(source) or source.is_relative_to(base):
        raise ValueError('operation-and-original-cannot-overlap')
    for path, expected in [(freeze, args.source_freeze_sha256),
                           (repair_path, args.directory_repairs_sha256),
                           (overlay, args.preparer_overlay_sha256)]:
        if sha(path) != expected:
            raise ValueError('reviewed-control-input-hash-mismatch:' + str(path))
    expected_files = json.loads(freeze.read_bytes())
    repairs = json.loads(repair_path.read_bytes())
    control, staging, project = base / 'control', base / 'staging', base / 'project'
    before_files, before_dirs = maps(source)
    if before_files != expected_files:
        raise ValueError('attempt1-source-no-longer-matches-original-freeze')
    # A repair never creates or changes HEAD, refs files, objects or source.
    # The separately reviewed evidence must support every essential directory.
    ibex_git = 'third_party/rfuzz/upstream/ibex/.git'
    exact_repairs = {ibex_git + '/refs', ibex_git + '/refs/heads', ibex_git + '/refs/tags'}
    if set(repairs) != exact_repairs:
        raise ValueError('only-three-evidenced-Ibex-refs-directories-may-be-repaired')
    for name, pin in repairs.items():
        p = relative(name)
        if (not pin.get('evidence') or pin.get('mode') != 0o755
                or ibex_git + '/HEAD' not in before_files):
            raise ValueError('unsupported-or-unevidenced-directory-repair:' + name)
        if name in before_dirs:
            raise ValueError('repair-must-only-create-a-missing-directory:' + name)
    phase = 'prepare' if args.prepare_reviewed_hash else 'stage-plan'
    if args.prepare_reviewed_hash:
        raise ValueError('controller-is-stage-plan-only-use-separate-reviewed-v2-prepare-CLI')
    if phase == 'stage-plan':
        base.mkdir(parents=True, exist_ok=False)
        control.mkdir()
        staging.mkdir()
    elif not control.is_dir() or not staging.is_dir() or project.exists():
        raise ValueError('reviewed-plan-layout-missing-or-final-project-already-exists')
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', PYTHONOPTIMIZE='0',
               PYTHONPATH='', PYTHONNOUSERSITE='1')
    primary = None
    try:
        write(control / (phase + '-source-before-files.json'), before_files)
        write(control / (phase + '-source-before-directories.json'), before_dirs)
        if phase == 'stage-plan':
            final_dirs = {**before_dirs, **{name: {'mode': pin['mode']} for name, pin in repairs.items()}}
            for name in sorted(final_dirs, key=lambda x: (len(PurePosixPath(x).parts), x)):
                (staging / name).mkdir(exist_ok=False)
            for name, pin in before_files.items():
                copy_file(source / name, staging / name, pin)
            target = staging / 'scripts/prepare_p7_i5_snapshot.py'
            old_sha = sha(target)
            target.write_bytes(overlay.read_bytes())
            target.chmod(0o644)
            for name in sorted(final_dirs, key=lambda x: len(PurePosixPath(x).parts), reverse=True):
                (staging / name).chmod(final_dirs[name]['mode'])
            stage_files, stage_dirs = maps(staging)
            expected_stage = dict(before_files)
            expected_stage['scripts/prepare_p7_i5_snapshot.py'] = {
                'sha256': args.preparer_overlay_sha256, 'bytes': overlay.stat().st_size, 'mode': 0o644}
            if stage_files != expected_stage or stage_dirs != final_dirs:
                raise ValueError('staging-transform-exceeds-reviewed-overlay-and-directory-repairs')
            write(control / 'staging-files.json', stage_files)
            write(control / 'staging-directories.json', stage_dirs)
            write(control / 'explicit-transform.json', {
                'directory_repairs': repairs, 'overlay': {'path': 'scripts/prepare_p7_i5_snapshot.py',
                'before_sha256': old_sha, 'after_sha256': args.preparer_overlay_sha256},
                'directory_sha256': map_digest(stage_dirs)})
        else:
            stage_files, stage_dirs = maps(staging)
            if (stage_files != json.loads((control / 'staging-files.json').read_bytes())
                    or stage_dirs != json.loads((control / 'staging-directories.json').read_bytes())):
                raise ValueError('staging-changed-since-reviewed-plan')
        common = [sys.executable, staging / 'scripts/prepare_p7_i5_snapshot.py',
                  '--source', staging, '--destination', project,
                  '--manifest', control / 'selection-v2.json',
                  '--freeze-map', control / 'final-file-freeze.json',
                  '--receipt', control / 'final-copy-receipt.json']
        if phase == 'stage-plan':
            includes = sorted(path.name for path in staging.iterdir())
            argv = [*common, *[token for name in includes for token in ('--include', name)]]
        else:
            if sha(control / 'selection-v2.json') != args.prepare_reviewed_hash:
                raise ValueError('operator-reviewed-selection-hash-mismatch')
            argv = [*common, '--prepare', '--manifest-sha256', args.prepare_reviewed_hash]
        child(argv, control, phase, env)
        result = {'status': 'planned_pending_review' if phase == 'stage-plan' else 'copied_pending_tools_and_execution',
                  'native_run': False, 'original_source_unchanged': None,
                  'selection_sha256': sha(control / 'selection-v2.json')}
        if phase == 'prepare':
            actual_files, actual_dirs = maps(project)
            receipt = json.loads((control / 'final-copy-receipt.json').read_bytes())
            if (actual_files != json.loads((control / 'final-file-freeze.json').read_bytes())
                    or actual_dirs != receipt['directories']
                    or map_digest(actual_dirs) != receipt['directory_manifest_sha256']):
                raise ValueError('final-file-or-directory-freeze-mismatch')
            result.update(file_freeze_sha256=sha(control / 'final-file-freeze.json'),
                          directory_sha256=map_digest(actual_dirs), files=len(actual_files),
                          directories=len(actual_dirs))
    except BaseException as error:
        primary = error
        result = {'status': 'failed', 'native_run': False, 'error': repr(error)[:4096]}
    finally:
        try:
            after_files, after_dirs = maps(source)
            write(control / (phase + '-source-after-files.json'), after_files)
            write(control / (phase + '-source-after-directories.json'), after_dirs)
            unchanged = (after_files, after_dirs) == (before_files, before_dirs)
            result['original_source_unchanged'] = unchanged
            if not unchanged:
                result['status'] = 'failed'
                if primary is None:
                    primary = ValueError('original-attempt1-source-mutated')
            write(control / (phase + '-result.json'), result)
        except BaseException as error:
            if primary is None:
                primary = error
        if primary is not None:
            raise primary
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
