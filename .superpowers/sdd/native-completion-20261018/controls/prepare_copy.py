#!/usr/bin/env python3
"""Pure byte-copy preparation only; never launch Git, tools or hardware."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
sys.dont_write_bytecode = True
ALLOWED = Path('/root/fanzehui')
SOURCE = ALLOWED / 'myfuzz/operations/p6-native-online-c924aac-20261018-attempt2/project'
DEST = ALLOWED / 'myfuzz/operations/p6-native-completion-20261018-attempt1'
BASELINE_FILES_SHA = '50145c2408804a76c6ff651cefbb143aae17cd1be18559f79ea6386b510e2cc4'
BASELINE_DIRS_SHA = 'b16e9bd3b7cabcd0e75ebf051af9a2045ce6dfe600fd7f0cc8035f21389c7393'

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value, durable=False):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        if durable:
            os.fsync(stream.fileno())


def safe(path):
    path = path.absolute()
    if '..' in path.parts or not path.is_relative_to(ALLOWED):
        raise ValueError('path-outside-authorized-root')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('path-symlink')
    return path


def relative(name):
    p = PurePosixPath(name)
    if not p.parts or p.is_absolute() or '..' in p.parts or str(p) != name or name == '.':
        raise ValueError('noncanonical-archive-relative-path:' + name)
    return p


def maps(root):
    files, directories = {}, {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError('directory-link-or-special')
            directories[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            path = Path(directory) / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('file-link-or-special')
            files[path.relative_to(root).as_posix()] = {
                'bytes': info.st_size, 'mode': stat.S_IMODE(info.st_mode), 'sha256': sha(path)}
    return dict(sorted(files.items())), dict(sorted(directories.items()))


def copy_file(source, target, mode):
    # Full-tree maps verify every byte afterwards; no per-file fsync latency.
    with source.open('rb') as reader, target.open('xb') as writer:
        while chunk := reader.read(1024 * 1024):
            writer.write(chunk)
    target.chmod(mode)


def host_paths(root):
    declarations = {}
    for node in ast.parse((root / 'src/myfuzz/scenario/host_identity.py').read_bytes()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('HOST_SOURCE_PATHS', 'HARNESS_HOST_SOURCE_PATHS'):
                    if target.id in declarations:
                        raise ValueError('duplicate-host-declaration')
                    value = node.value
                    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                        if not isinstance(value.left, ast.Name) or value.left.id != 'HOST_SOURCE_PATHS':
                            raise ValueError('unexpected-host-expression')
                        paths = declarations['HOST_SOURCE_PATHS'] + ast.literal_eval(value.right)
                    else:
                        paths = ast.literal_eval(value)
                    if not isinstance(paths, tuple) or any(type(p) is not str for p in paths):
                        raise ValueError('invalid-host-path-tuple')
                    declarations[target.id] = paths
    if set(declarations) != {'HOST_SOURCE_PATHS', 'HARNESS_HOST_SOURCE_PATHS'}:
        raise ValueError('missing-host-declaration')
    if len(declarations['HOST_SOURCE_PATHS']) != 34:
        raise ValueError('legacy-host-path-count')
    paths = declarations['HARNESS_HOST_SOURCE_PATHS']
    if len(paths) != 69 or len(set(paths)) != 69:
        raise ValueError('expected-reviewed-69-host-paths')
    for name in paths:
        relative(name)
        if not (root / name).is_file():
            raise ValueError('missing-explicit-host-source:' + name)
    return list(paths)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline-files', 'baseline-directories', 'overlay-tree', 'overlay-map', 'overlay-paths'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('overlay-map-sha256', 'overlay-paths-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    source, base = safe(SOURCE), safe(DEST)
    frozen_files, frozen_dirs, overlay, overlay_map, overlay_paths = [safe(p) for p in (
        args.baseline_files, args.baseline_directories, args.overlay_tree,
        args.overlay_map, args.overlay_paths)]
    if base.exists() or not source.is_dir() or not overlay.is_dir():
        raise ValueError('destination-exists-or-source-missing')
    if (source.is_relative_to(overlay) or overlay.is_relative_to(source)
            or base.is_relative_to(overlay) or overlay.is_relative_to(base)):
        raise ValueError('overlay-overlaps-source-or-destination')
    for path, pin in ((frozen_files, BASELINE_FILES_SHA), (frozen_dirs, BASELINE_DIRS_SHA),
                      (overlay_map, args.overlay_map_sha256), (overlay_paths, args.overlay_paths_sha256)):
        if sha(path) != pin:
            raise ValueError('reviewed-control-input-hash-mismatch:' + str(path))
    before_files, before_dirs = maps(source)
    if (before_files != json.loads(frozen_files.read_bytes())
            or before_dirs != json.loads(frozen_dirs.read_bytes())):
        raise ValueError('baseline-full-file-or-directory-freeze-mismatch')
    overlay_files, overlay_dirs = maps(overlay)
    if json.loads(overlay_map.read_bytes()) != dict(files=overlay_files, directories=overlay_dirs):
        raise ValueError('overlay-full-map-mismatch')
    paths = json.loads(overlay_paths.read_bytes())
    if (type(paths) is not list or any(type(p) is not str for p in paths)
            or len(set(paths)) != len(paths) or set(paths) != set(overlay_files)):
        raise ValueError('root-reviewed-overlay-file-list-mismatch')
    for name in [*overlay_files, *overlay_dirs]:
        relative(name)
        if name == '.git' or '.git' in PurePosixPath(name).parts:
            raise ValueError('overlay-cannot-change-Git-metadata')
    final_files, final_dirs = {**before_files, **overlay_files}, {**before_dirs, **overlay_dirs}
    if set(final_files) & set(final_dirs):
        raise ValueError('file-directory-collision')
    for name in [*final_files, *final_dirs]:
        for parent in PurePosixPath(name).parents:
            if str(parent) != '.' and str(parent) not in final_dirs:
                raise ValueError('missing-parent-directory')
    for name, row in overlay_dirs.items():
        if name in before_dirs and row != before_dirs[name]:
            raise ValueError('overlay-cannot-change-existing-directory-mode')
    base.mkdir(exist_ok=False)
    control, stage = base / 'control', base / '.project-stage'
    control.mkdir()
    stage.mkdir()
    receipt = dict(status='failed', native_run=False, heavy_lock_acquired=False,
                   formal_p6_complete=False, source=str(source), destination=str(base / 'project'))
    primary = None
    try:
        write(control / 'source-before-files.json', before_files)
        write(control / 'source-before-directories.json', before_dirs)
        write(control / 'reviewed-overlay-files.json', overlay_files)
        write(control / 'reviewed-overlay-directories.json', overlay_dirs)
        for name in sorted(final_dirs, key=lambda n: (len(PurePosixPath(n).parts), n)):
            (stage / name).mkdir()
        for name, row in before_files.items():
            copy_file(source / name, stage / name, row['mode'])
        for name, row in overlay_files.items():
            if name in before_files:
                (stage / name).unlink()
            copy_file(overlay / name, stage / name, row['mode'])
        for name in sorted(final_dirs, key=lambda n: len(PurePosixPath(n).parts), reverse=True):
            (stage / name).chmod(final_dirs[name]['mode'])
        actual_files, actual_dirs = maps(stage)
        if (actual_files != final_files or actual_dirs != final_dirs):
            raise ValueError('staged-full-file-or-directory-map-mismatch')
        hosts = host_paths(stage)
        # Full scripts subtree equality is part of the whole-tree equality;
        # retain its explicit rows separately for independent review.
        scripts = {p: row for p, row in actual_files.items() if p.startswith('scripts/')}
        if not scripts or not any(p.startswith('.git/') for p in actual_files):
            raise ValueError('full-scripts-or-Git-metadata-missing')
        if maps(source) != (before_files, before_dirs) or maps(overlay) != (overlay_files, overlay_dirs):
            raise ValueError('source-or-overlay-drift-before-publication')
        for path, pin in ((overlay_map, args.overlay_map_sha256), (overlay_paths, args.overlay_paths_sha256)):
            if sha(path) != pin:
                raise ValueError('overlay-control-drift')
        write(control / 'final-file-freeze.json', actual_files)
        write(control / 'final-directories.json', actual_dirs)
        write(control / 'full-scripts.json', scripts)
        write(control / 'explicit-host-files.json', {p: actual_files[p] for p in hosts})
        # Operation directory is exclusively newly created. Rename publishes
        # the complete verified tree, never a partially populated project.
        stage.rename(base / 'project')
        receipt.update(status='prepared_pending_independent_review_no_execution',
                       files=len(actual_files), directories=len(actual_dirs), host_paths=len(hosts),
                       freeze_sha256=sha(control / 'final-file-freeze.json'))
    except BaseException as error:
        primary = error
        receipt['error'] = repr(error)[:4096]
    finally:
        try:
            after_files, after_dirs = maps(source)
            write(control / 'source-after-files.json', after_files)
            write(control / 'source-after-directories.json', after_dirs)
            receipt['source_unchanged'] = (before_files, before_dirs) == (after_files, after_dirs)
            if not receipt['source_unchanged']:
                receipt['status'] = 'failed'
                if primary is None:
                    primary = ValueError('baseline-source-mutated')
            write(control / 'copy-receipt.json', receipt, durable=True)
        except BaseException as error:
            if primary is None:
                primary = error
        if primary is not None:
            raise primary
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
