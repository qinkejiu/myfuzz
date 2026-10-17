#!/usr/bin/env python3
"""Plan or explicitly copy a reviewed P7 source selection without subprocesses."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

sys.dont_write_bytecode = True


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


def validate_git(root, files):
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
        if (name.endswith('/objects/info/alternates')
                or name.endswith('/commondir')) and path.read_bytes().strip():
            raise ValueError('git-shared-object-or-worktree-store:' + name)
    result = {}
    for directory in sorted(gitdirs):
        head = directory / 'HEAD'
        key = head.relative_to(root).as_posix()
        if key not in files or not (directory / 'objects').is_dir():
            raise ValueError('incomplete-git-metadata:' + str(directory))
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
    source = args.source.absolute()
    destination = args.destination.absolute()
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
    if not args.prepare:
        if not args.include:
            parser.error('planning requires explicit --include prefixes')
        includes = sorted({str(relative(name)) for name in args.include})
        excludes = sorted({str(relative(name)) for name in args.exclude})
        files = selection_map(source, includes, excludes)
        git_heads = validate_git(source, files)
        document = {'schema_version': 'p7_i5_snapshot_selection.v1',
                    'source': str(source), 'destination': str(destination),
                    'includes': includes, 'excludes': excludes, 'files': files,
                    'git_head_files': git_heads, 'closure_reviewed': False}
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
    if (document.get('schema_version') != 'p7_i5_snapshot_selection.v1'
            or document.get('source') != str(source)
            or document.get('destination') != str(destination)):
        parser.error('manifest source/destination/schema mismatch')
    includes = [str(relative(name)) for name in document['includes']]
    excludes = [str(relative(name)) for name in document['excludes']]
    expected = document['files']
    for name in expected:
        relative(name)
    current = selection_map(source, includes, excludes)
    if current != expected or validate_git(source, current) != document['git_head_files']:
        parser.error('selected source changed since manifest review')
    if args.freeze_map.exists() or args.receipt.exists():
        parser.error('freeze and receipt paths must be new')
    destination.mkdir(parents=True, exist_ok=False)
    receipt = {'status': 'failed', 'source': str(source), 'destination': str(destination),
               'manifest_sha256': args.manifest_sha256, 'formal_p7_complete': False}
    try:
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
        actual = full_map(destination)
        if actual != expected:
            raise ValueError('whole-destination-map-differs')
        if validate_git(destination, actual) != document['git_head_files']:
            raise ValueError('copied-git-topology-differs')
        write_new(args.freeze_map, actual)
        receipt.update(status='copied_pending_closure_and_tool_review', files=len(actual),
                       bytes=sum(row['bytes'] for row in actual.values()),
                       freeze_sha256=sha(args.freeze_map), native_run=False)
    except BaseException as error:
        receipt['error'] = type(error).__name__ + ': ' + str(error)
        write_new(args.receipt, receipt)
        raise
    write_new(args.receipt, receipt)
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
