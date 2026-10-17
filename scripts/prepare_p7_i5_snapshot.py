#!/usr/bin/env python3
"""Plan or explicitly copy a reviewed P7 source selection without subprocesses."""
from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

sys.dont_write_bytecode = True
PRIVATE_LOCK = '.superpowers/sdd/stage2-heavy-worker.lock'
EMPTY_PIN = {'sha256': hashlib.sha256(b'').hexdigest(), 'bytes': 0, 'mode': 0o600}


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_new(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def relative(value):
    path = PurePosixPath(value)
    if (path.is_absolute() or not path.parts or '..' in path.parts
            or str(path) != value or value == '.'):
        raise ValueError('explicit-normalized-relative-prefix-required:' + value)
    return path


def selected(name, prefixes):
    return any(name == prefix or name.startswith(prefix + '/') for prefix in prefixes)


def no_path_links(path):
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise ValueError('path-symlink:' + str(candidate))


def file_entry(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('source-link-or-special-file:' + str(path))
    return {'sha256': sha(path), 'bytes': info.st_size,
            'mode': stat.S_IMODE(info.st_mode)}


def selection_map(root, includes, excludes):
    """Enumerate only selected prefixes; exclusions are operator declarations."""
    result = {}
    for prefix in includes:
        path = root / prefix
        no_path_links(path)
        if not path.exists():
            raise ValueError('included-path-missing:' + prefix)
        if selected(prefix, excludes):
            raise ValueError('included-prefix-itself-excluded:' + prefix)
        if path.is_file():
            result[prefix] = file_entry(path)
            continue
        for directory, dirs, files in os.walk(path, followlinks=False):
            parent = Path(directory)
            kept = []
            for name in dirs:
                child = parent / name
                key = child.relative_to(root).as_posix()
                if selected(key, excludes):
                    continue
                if child.is_symlink():
                    raise ValueError('selected-directory-symlink:' + key)
                kept.append(name)
            dirs[:] = kept
            for name in files:
                child = parent / name
                key = child.relative_to(root).as_posix()
                if not selected(key, excludes):
                    result[key] = file_entry(child)
    return dict(sorted(result.items()))


def directory_entry(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError('directory-link-or-special-file:' + str(path))
    return {'mode': stat.S_IMODE(info.st_mode)}


def selection_directories(root, includes, excludes):
    """Preserve selected empty directories and all required parent modes."""
    result = {}
    def add(path):
        while path != root:
            key = path.relative_to(root).as_posix()
            result[key] = directory_entry(path)
            path = path.parent
    for prefix in includes:
        path = root / prefix
        no_path_links(path)
        if selected(prefix, excludes):
            raise ValueError('included-prefix-itself-excluded:' + prefix)
        if path.is_file():
            add(path.parent)
            continue
        if not path.is_dir():
            raise ValueError('included-directory-missing:' + prefix)
        for directory, dirs, _ in os.walk(path, followlinks=False):
            add(Path(directory))
            dirs[:] = [name for name in dirs if not selected(
                (Path(directory) / name).relative_to(root).as_posix(), excludes)]
            for name in dirs:
                directory_entry(Path(directory) / name)
    return dict(sorted(result.items()))


def full_directories(root):
    result = {}
    for directory, dirs, _ in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            result[path.relative_to(root).as_posix()] = directory_entry(path)
    return dict(sorted(result.items()))


def validate_git(root, files, directories=None):
    """Validate copied Git topology without invoking Git or rewriting identity."""
    if '.git/HEAD' not in files:
        raise ValueError('standalone-root-git-directory-required')
    gitdirs = {root / '.git'}
    for name in files:
        path = root / name
        if path.name == '.git':
            text = path.read_text(encoding='utf-8').strip()
            if not text.startswith('gitdir: '):
                raise ValueError('git-pointer-malformed:' + name)
            target = (path.parent / text[8:]).resolve(strict=True)
            if not target.is_relative_to(root):
                raise ValueError('git-pointer-outside-snapshot:' + name)
            if (target / 'HEAD').relative_to(root).as_posix() not in files:
                raise ValueError('git-pointer-metadata-not-selected:' + name)
            gitdirs.add(target)
        if name.endswith('/.git/HEAD'):
            gitdirs.add(path.parent)
        if path.name == 'HEAD' and (path.parent / 'config').relative_to(root).as_posix() in files:
            gitdirs.add(path.parent)
        if (name.endswith('/objects/info/alternates')
                or name.endswith('/commondir')) and path.read_bytes().strip():
            raise ValueError('git-shared-object-or-worktree-store:' + name)
        if name.endswith('.promisor'):
            raise ValueError('git-promisor-pack-not-materialized:' + name)
        if path.name == 'config' and ('/.git/' in '/' + name or name.startswith('.git/')):
            config = configparser.ConfigParser(interpolation=None, strict=False)
            config.read_string(path.read_text())
            for section in config.sections():
                normalized = section.lower()
                if normalized == 'include' or normalized.startswith('includeif '):
                    raise ValueError('git-external-config-include:' + name)
                if any(key.lower() in ('promisor', 'partialclone', 'hookspath')
                       for key in config[section]):
                    raise ValueError('git-lazy-or-external-config:' + name)
    result = {}
    for directory in sorted(gitdirs):
        head = directory / 'HEAD'
        key = head.relative_to(root).as_posix()
        if (key not in files or not (directory / 'objects').is_dir()
                or not (directory / 'refs').is_dir()):
            raise ValueError('incomplete-git-metadata:' + str(directory))
        if directories is not None and any(
                (directory / name).relative_to(root).as_posix() not in directories
                for name in ('objects', 'refs')):
            raise ValueError('essential-git-directory-not-selected:' + str(directory))
        config = directory / 'config'
        if config.is_file():
            for match in re.finditer(r'^\s*worktree\s*=\s*(.+?)\s*$', config.read_text(), re.M | re.I):
                worktree = (directory / match.group(1).strip('"')).resolve()
                if not worktree.is_relative_to(root):
                    raise ValueError('git-config-worktree-outside-snapshot:' + str(config))
        result[directory.relative_to(root).as_posix()] = head.read_text().strip()
    return result


def full_map(root):
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            if (Path(directory) / name).is_symlink():
                raise ValueError('destination-directory-symlink')
        for name in files:
            path = Path(directory) / name
            result[path.relative_to(root).as_posix()] = file_entry(path)
    return dict(sorted(result.items()))


def run(args, parser):
    source = args.source.absolute()
    destination = args.destination.absolute()
    if len({path.absolute() for path in (args.manifest, args.freeze_map, args.receipt)}) != 3:
        raise ValueError('manifest-freeze-receipt-paths-must-be-distinct')
    if '..' in source.parts or '..' in destination.parts:
        parser.error('normalized source/destination paths required')
    no_path_links(source)
    no_path_links(destination)
    if not source.is_dir() or destination.exists():
        parser.error('source must exist and destination must be new')
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        parser.error('source and destination cannot contain each other')
    for path in (args.manifest, args.freeze_map, args.receipt):
        absolute = path.absolute()
        if '..' in absolute.parts:
            parser.error('normalized manifest/freeze/receipt paths required')
        no_path_links(absolute)
        if absolute.is_relative_to(source) or absolute.is_relative_to(destination):
            parser.error('manifest/freeze/receipt must be outside source and destination')
    return prepare(args, parser, source, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--freeze-map', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--include', action='append', default=[])
    parser.add_argument('--exclude', action='append', default=[])
    parser.add_argument('--prepare', action='store_true')
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args()
    try:
        return run(args, parser)
    except BaseException as primary:
        # A diagnostic failure must never replace the original preflight,
        # mkdir, copy or publication exception. One bounded write attempt only.
        try:
            receipt = args.receipt.absolute()
            no_path_links(receipt)
            if ('..' in receipt.parts or receipt.exists()
                    or receipt in {args.manifest.absolute(), args.freeze_map.absolute()}
                    or receipt.is_relative_to(args.source.absolute())
                    or receipt.is_relative_to(args.destination.absolute())):
                raise ValueError('no-safe-new-failure-receipt-path')
            write_new(receipt, {'status': 'failed', 'phase': 'planning' if not args.prepare else 'preparation',
                      'error': type(primary).__name__ + ': ' + str(primary)[:4096],
                      'source': str(args.source), 'destination': str(args.destination),
                      'manifest_sha256': args.manifest_sha256, 'native_run': False})
        except BaseException as diagnostic:
            try:
                sys.stderr.write('failure-receipt-unavailable: ' + repr(diagnostic)[:1024] + '\n')
            except BaseException:
                pass
        raise


def prepare(args, parser, source, destination):
    if not args.prepare:
        if not args.include:
            parser.error('planning requires explicit --include prefixes')
        includes = sorted({str(relative(name)) for name in args.include})
        excludes = sorted({str(relative(name)) for name in args.exclude})
        files = selection_map(source, includes, excludes)
        directories = selection_directories(source, includes, excludes)
        git_heads = validate_git(source, files, directories)
        generated = {} if PRIVATE_LOCK in files else {PRIVATE_LOCK: EMPTY_PIN}
        generated_dirs = {}
        if generated:
            for parent in PurePosixPath(PRIVATE_LOCK).parents:
                if str(parent) != '.' and str(parent) not in directories:
                    generated_dirs[str(parent)] = {'mode': 0o755}
        if PRIVATE_LOCK in files and files[PRIVATE_LOCK]['bytes'] != 0:
            raise ValueError('selected-private-lock-must-be-empty')
        document = {'schema_version': 'p7_i5_snapshot_selection.v2',
                    'source': str(source), 'destination': str(destination),
                    'includes': includes, 'excludes': excludes, 'files': files,
                    'git_head_files': git_heads, 'generated_files': generated,
                    'directories': directories, 'generated_directories': generated_dirs,
                    'closure_reviewed': False}
        write_new(args.manifest, document)
        print(json.dumps({'status': 'planned_not_copied', 'files': len(files),
                          'manifest_sha256': sha(args.manifest),
                          'bytes': sum(row['bytes'] for row in files.values())}))
        return 0
    if args.include or args.exclude:
        parser.error('prepare uses only the reviewed manifest selection')
    if not args.manifest_sha256 or sha(args.manifest) != args.manifest_sha256:
        parser.error('reviewed manifest digest required')
    document = json.loads(args.manifest.read_bytes())
    if (document.get('schema_version') != 'p7_i5_snapshot_selection.v2'
            or document.get('source') != str(source)
            or document.get('destination') != str(destination)):
        parser.error('manifest source/destination/schema mismatch')
    includes = [str(relative(name)) for name in document['includes']]
    excludes = [str(relative(name)) for name in document['excludes']]
    expected = document['files']
    expected_dirs = document['directories']
    generated_dirs = document['generated_directories']
    generated = document.get('generated_files')
    if generated not in ({}, {PRIVATE_LOCK: EMPTY_PIN}):
        parser.error('only-reviewed-empty-private-lock-generation-is-supported')
    if PRIVATE_LOCK in expected and generated:
        parser.error('private-lock-cannot-be-both-copied-and-generated')
    if PRIVATE_LOCK not in expected and PRIVATE_LOCK not in generated:
        parser.error('private-operation-lock-must-exist-before-freeze')
    if PRIVATE_LOCK in expected and expected[PRIVATE_LOCK]['bytes'] != 0:
        parser.error('selected-private-lock-must-be-empty')
    allowed_generated_dirs = {}
    if generated:
        for parent in PurePosixPath(PRIVATE_LOCK).parents:
            if str(parent) != '.' and str(parent) not in expected_dirs:
                allowed_generated_dirs[str(parent)] = {'mode': 0o755}
    if generated_dirs != allowed_generated_dirs:
        parser.error('unexpected-generated-directories')
    for name in [*expected, *expected_dirs, *generated_dirs]:
        relative(name)
    current = selection_map(source, includes, excludes)
    if (current != expected or selection_directories(source, includes, excludes) != expected_dirs
            or validate_git(source, current, expected_dirs) != document['git_head_files']):
        parser.error('selected source changed since manifest review')
    if args.freeze_map.exists() or args.receipt.exists():
        parser.error('freeze and receipt paths must be new')
    destination.mkdir(parents=True, exist_ok=False)
    receipt = {'status': 'failed', 'source': str(source), 'destination': str(destination),
               'manifest_sha256': args.manifest_sha256, 'formal_p7_complete': False}
    try:
        final_dirs = {**expected_dirs, **generated_dirs}
        for name in sorted(final_dirs, key=lambda value: (len(PurePosixPath(value).parts), value)):
            (destination / name).mkdir(exist_ok=False)
        for name, pin in expected.items():
            original = source / name
            if file_entry(original) != pin:
                raise ValueError('source-changed-before-copy:' + name)
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with original.open('rb') as reader, target.open('xb') as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            target.chmod(pin['mode'])
            if file_entry(target) != pin or file_entry(original) != pin:
                raise ValueError('copy-or-source-race:' + name)
        if selection_map(source, includes, excludes) != expected:
            raise ValueError('selected-source-changed-during-copy')
        if selection_directories(source, includes, excludes) != expected_dirs:
            raise ValueError('selected-source-directory-layout-changed-during-copy')
        for name, pin in generated.items():
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as stream:
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(pin['mode'])
        # Apply directory modes only after writing children, including empty
        # refs/objects directories that a file-only copy would omit.
        for name in sorted(final_dirs, key=lambda value: len(PurePosixPath(value).parts), reverse=True):
            (destination / name).chmod(final_dirs[name]['mode'])
        actual = full_map(destination)
        if actual != {**expected, **generated}:
            raise ValueError('whole-destination-map-differs')
        actual_dirs = full_directories(destination)
        if actual_dirs != final_dirs:
            raise ValueError('whole-destination-directory-layout-differs')
        if validate_git(destination, actual, actual_dirs) != document['git_head_files']:
            raise ValueError('copied-git-topology-differs')
        write_new(args.freeze_map, actual)
        receipt.update(status='copied_pending_closure_and_tool_review', files=len(actual),
                       bytes=sum(row['bytes'] for row in actual.values()),
                       directories=actual_dirs,
                       directory_manifest_sha256=hashlib.sha256(json.dumps(
                           actual_dirs, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                       freeze_sha256=sha(args.freeze_map), native_run=False)
    except BaseException as error:
        # main() records one best-effort failure without masking this exception.
        raise
    write_new(args.receipt, receipt)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
