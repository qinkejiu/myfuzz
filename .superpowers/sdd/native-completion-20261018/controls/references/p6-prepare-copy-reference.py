#!/usr/bin/env python3
"""Pure selected-source/Pico input copy. Never runs Git, tools, tests or models."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

sys.dont_write_bytecode = True
ALLOWED = Path('/root/fanzehui')
PREFIXES = ('src', 'configs', '.git', '.gitmodules', '.gitignore', 'README.md',
            'scripts', 'third_party/soc-pulp-apb-gpio')
GATE = 'scripts/verify_picorv32_native_online.py'
PICO = 'third_party/picorv32_upstream_reference'


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


def selected(name):
    return any(name == p or name.startswith(p + '/') for p in PREFIXES)


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


def required_host_sources(source):
    """Read the two pinned tuple declarations without importing project code."""
    tree = ast.parse((source / 'src/myfuzz/scenario/host_identity.py').read_text())
    declarations = {}
    wanted = {'HOST_SOURCE_PATHS', 'HARNESS_HOST_SOURCE_PATHS'}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = {target.id for target in node.targets if isinstance(target, ast.Name)} & wanted
            for name in names:
                if name in declarations:
                    raise ValueError('duplicate-host-source-tuple:' + name)
                paths = [item.value for item in ast.walk(node.value)
                         if isinstance(item, ast.Constant) and isinstance(item.value, str)]
                if not paths:
                    raise ValueError('empty-host-source-tuple:' + name)
                for path in paths:
                    relative(path)
                declarations[name] = paths
    if set(declarations) != wanted:
        raise ValueError('required-static-host-source-tuples-missing')
    return sorted({path for paths in declarations.values() for path in paths})


def directory_sha(directories):
    raw = json.dumps(directories, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'source-freeze', 'new-operation', 'overlay-archive', 'overlay-map'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-freeze-sha256', 'overlay-archive-sha256', 'overlay-map-sha256'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    source, freeze, base, archive, manifest = [safe(p) for p in (
        args.source, args.source_freeze, args.new_operation, args.overlay_archive, args.overlay_map)]
    if source.is_relative_to(base) or base.is_relative_to(source):
        raise ValueError('new-operation-and-original-overlap')
    for path, pin in [(freeze, args.source_freeze_sha256), (archive, args.overlay_archive_sha256),
                      (manifest, args.overlay_map_sha256)]:
        if sha(path) != pin:
            raise ValueError('reviewed-input-hash-mismatch:' + str(path))
    overlay = json.loads(manifest.read_bytes())
    overlay_files = {name: {k: row[k] for k in ('bytes', 'mode', 'sha256')}
                     for name, row in overlay['files'].items()}
    overlay_dirs = overlay['directories']
    for name in [*overlay_files, *overlay_dirs]:
        relative(name)
    if any(name != GATE and not name.startswith(PICO + '/') for name in overlay_files):
        raise ValueError('overlay-file-outside-reviewed-gate-and-Pico-prefix')
    if any(name not in ('scripts', 'third_party', PICO) and not name.startswith(PICO + '/')
           for name in overlay_dirs):
        raise ValueError('overlay-directory-outside-reviewed-prefixes')
    before_files, before_dirs = maps(source)
    if before_files != json.loads(freeze.read_bytes()):
        raise ValueError('original-whole-file-freeze-mismatch')
    files = {name: row for name, row in before_files.items() if selected(name)}
    dirs = {name: row for name, row in before_dirs.items() if selected(name)}
    host_sources = required_host_sources(source)
    missing_host_sources = [name for name in host_sources if name not in files]
    if missing_host_sources:
        raise ValueError('selected-host-source-is-missing:' + ','.join(missing_host_sources))
    for prefix in PREFIXES:
        if prefix not in before_files and prefix not in before_dirs:
            raise ValueError('explicit-selected-prefix-missing:' + prefix)
    for name in [*files, *dirs]:
        for p in PurePosixPath(name).parents:
            if str(p) != '.':
                dirs[str(p)] = before_dirs[str(p)]
    if set(files) & set(overlay_files):
        raise ValueError('overlay-cannot-overwrite-selected-files')
    for name, pin in overlay_dirs.items():
        if name in dirs and dirs[name] != pin:
            raise ValueError('overlay-cannot-change-existing-directory-mode')
    final_files, final_dirs = {**files, **overlay_files}, {**dirs, **overlay_dirs}
    # Every parent must be explicit, and file/directory identities cannot alias.
    if set(final_files) & set(final_dirs):
        raise ValueError('file-directory-collision')
    for name in [*final_files, *final_dirs]:
        for p in PurePosixPath(name).parents:
            if str(p) != '.' and str(p) not in final_dirs:
                raise ValueError('unmanifested-parent-directory')
    for gitdir in ('.git', PICO + '/.git'):
        if (gitdir + '/HEAD' not in final_files or gitdir + '/objects' not in final_dirs
                or gitdir + '/refs' not in final_dirs):
            raise ValueError('essential-Git-layout-missing:' + gitdir)
    # Validate the complete archive before creating a destination or extracting.
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        names = set()
        for member in members:
            relative(member.name)
            if member.name in names or not (member.isdir() or member.isreg()):
                raise ValueError('archive-duplicate-link-or-special-entry')
            names.add(member.name)
            pins = overlay_dirs if member.isdir() else overlay_files
            if member.name not in pins or member.mode != pins[member.name]['mode']:
                raise ValueError('archive-member-mode-or-kind-not-manifested')
            if member.isreg() and member.size != pins[member.name]['bytes']:
                raise ValueError('archive-member-size-mismatch')
        if names != set(overlay_files) | set(overlay_dirs):
            raise ValueError('archive-full-member-set-mismatch')
    base.mkdir(parents=True, exist_ok=False)
    control, project = base / 'control', base / 'project'
    control.mkdir()
    project.mkdir()
    result = {'status': 'failed', 'native_run': False, 'formal_p6_complete': False}
    primary = None
    try:
        write(control / 'source-before-files.json', before_files)
        write(control / 'source-before-directories.json', before_dirs)
        for name in sorted(final_dirs, key=lambda n: (len(PurePosixPath(n).parts), n)):
            (project / name).mkdir(exist_ok=False)
        for name, pin in files.items():
            with (source / name).open('rb') as reader, (project / name).open('xb') as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
            (project / name).chmod(pin['mode'])
        with tarfile.open(archive, 'r:gz') as tar:
            seen = set()
            for member in tar.getmembers():
                relative(member.name)
                pin_set = overlay_dirs if member.isdir() else overlay_files
                if (member.name in seen or not (member.isdir() or member.isreg())
                        or member.name not in pin_set or member.mode != pin_set[member.name]['mode']
                        or (member.isreg() and member.size != pin_set[member.name]['bytes'])):
                    raise ValueError('archive-changed-or-unsafe-during-extraction')
                seen.add(member.name)
                if member.isreg():
                    with tar.extractfile(member) as reader, (project / member.name).open('xb') as writer:
                        while chunk := reader.read(1024 * 1024):
                            writer.write(chunk)
                    (project / member.name).chmod(overlay_files[member.name]['mode'])
            if seen != set(overlay_files) | set(overlay_dirs):
                raise ValueError('archive-member-set-changed-during-extraction')
        for name in sorted(final_dirs, key=lambda n: len(PurePosixPath(n).parts), reverse=True):
            (project / name).chmod(final_dirs[name]['mode'])
        actual_files, actual_dirs = maps(project)
        if (actual_files, actual_dirs) != (dict(sorted(final_files.items())), dict(sorted(final_dirs.items()))):
            raise ValueError('final-independent-file-or-directory-map-mismatch')
        if sha(archive) != args.overlay_archive_sha256 or sha(manifest) != args.overlay_map_sha256:
            raise ValueError('overlay-control-input-drift')
        write(control / 'final-file-freeze.json', actual_files)
        write(control / 'final-directories.json', actual_dirs)
        result.update(status='copied_pending_independent_review_and_execution',
            project=str(project), files=len(actual_files), bytes=sum(x['bytes'] for x in actual_files.values()),
            directories=actual_dirs, directory_manifest_sha256=directory_sha(actual_dirs),
            freeze_sha256=sha(control / 'final-file-freeze.json'),
            overlay_archive_sha256=args.overlay_archive_sha256,
            overlay_map_sha256=args.overlay_map_sha256, explicit_prefixes=PREFIXES,
            gate_sha256=actual_files[GATE]['sha256'],
            static_host_source_paths=host_sources)
    except BaseException as error:
        primary = error
        result['error'] = repr(error)[:4096]
    finally:
        try:
            after_files, after_dirs = maps(source)
            write(control / 'source-after-files.json', after_files)
            write(control / 'source-after-directories.json', after_dirs)
            result['original_source_unchanged'] = (after_files, after_dirs) == (before_files, before_dirs)
            if not result['original_source_unchanged']:
                result['status'] = 'failed'
                if primary is None:
                    primary = ValueError('immutable-original-source-mutated')
            write(control / 'copy-receipt.json', result, durable=True)
        except BaseException as error:
            if primary is None:
                primary = error
        if primary is not None:
            raise primary
    print(json.dumps({k: v for k, v in result.items() if k != 'directories'}, sort_keys=True))


if __name__ == '__main__':
    main()
