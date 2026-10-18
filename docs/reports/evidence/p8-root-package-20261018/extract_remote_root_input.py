"""Source draft: validate/extract one pinned regular-only P8 root input archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile
import time

FAN = Path('/root/fanzehui')
INBOX = FAN / 'myfuzz/operations/p8-root-input-transfer-20261018-attempt1'
DESTINATION = FAN / 'myfuzz/operations/p8-root-input-20261018-attempt1'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def safe(path):
    need(path.is_absolute() and '..' not in path.parts and path.is_relative_to(FAN), 'outside-fanzehui')
    for ancestor in (path, *path.parents):
        need(not ancestor.is_symlink(), 'symlink-path')
    return path


def digest(path):
    safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'nonregular-input')
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    path = PurePosixPath(name)
    need(name and name != '.' and not path.is_absolute() and '..' not in path.parts
         and str(path) == name and path.parts[0] in ('root', 'control'), 'noncanonical-member')
    return path


def census(root):
    safe(root)
    files, directories = {}, {}
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(parent) / name
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode), 'extracted-directory-link')
            directories[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            path = Path(parent) / name
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'extracted-file-link')
            files[path.relative_to(root).as_posix()] = dict(bytes=info.st_size,
                mode=stat.S_IMODE(info.st_mode), sha256=digest(path))
    return files, directories


def write(path, document):
    safe(path)
    with path.open('x') as stream:
        json.dump(document, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--archive-bytes', type=int, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    for path in (args.archive, args.manifest):
        safe(path)
        need(path.parent == INBOX, 'input-outside-new-inbox')
    need(args.archive != args.manifest and args.archive.stat().st_size == args.archive_bytes
         and digest(args.archive) == args.archive_sha256
         and digest(args.manifest) == args.manifest_sha256, 'transfer-input-pin')
    manifest = json.loads(args.manifest.read_bytes())
    need(manifest['schema_version'] == 'p8_root_transfer_manifest.v1', 'manifest-schema')
    files, directories = manifest['files'], manifest['directories']
    need(not (set(files) & set(directories)), 'manifest-type-collision')
    for name in [*files, *directories]:
        path = relative(name)
        need(not any(str(parent) in files for parent in path.parents if str(parent) != '.'),
             'manifest-file-ancestor')
        need(all(str(parent) in directories for parent in path.parents if str(parent) != '.'),
             'manifest-missing-parent')
    need(set(name for name in directories if '/' not in name) == {'root', 'control'}
         and all('/' in name for name in files), 'two-prefix-layout')
    safe(DESTINATION)
    need(not DESTINATION.exists(), 'destination-already-exists')
    receipt = INBOX / 'extraction-receipt.json'
    need(not receipt.exists(), 'receipt-already-exists')
    result = dict(schema_version='p8_root_remote_extraction.v1', status='failed',
        started_unix=time.time(), pid=os.getpid(), archive_sha256=args.archive_sha256,
        archive_bytes=args.archive_bytes, manifest_sha256=args.manifest_sha256,
        destination=str(DESTINATION), source_prepared=False, git_or_model_execution=False)
    primary = None
    try:
        DESTINATION.mkdir()
        for name in sorted(directories, key=lambda value: (len(PurePosixPath(value).parts), value)):
            target = safe(DESTINATION / name)
            target.mkdir(mode=0o700)
        seen = set()
        with tarfile.open(args.archive, mode='r|gz') as archive:
            for member in archive:
                name = member.name
                relative(name)
                need(name not in seen, 'duplicate-archive-member')
                seen.add(name)
                need(not member.pax_headers, 'unexpected-pax-extension')
                target = safe(DESTINATION / name)
                if member.isdir():
                    need(name in directories and member.size == 0
                         and member.mode == directories[name]['mode'], 'directory-header-mismatch')
                else:
                    need(member.isreg() and not member.issparse() and name in files,
                         'archive-link-or-special-or-unknown')
                    pin = files[name]
                    need(member.size == pin['bytes'] and member.mode == pin['mode'], 'file-header-mismatch')
                    stream = archive.extractfile(member)
                    need(stream is not None, 'archive-member-stream-missing')
                    h = hashlib.sha256()
                    total = 0
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with stream, os.fdopen(fd, 'wb') as out:
                        while block := stream.read(1024 * 1024):
                            total += len(block)
                            need(total <= pin['bytes'], 'archive-file-too-large')
                            h.update(block)
                            out.write(block)
                    need(total == pin['bytes'] and h.hexdigest() == pin['sha256'], 'file-byte-hash-mismatch')
                    target.chmod(pin['mode'])
        need(seen == set(files) | set(directories), 'archive-member-set-mismatch')
        for name, pin in sorted(directories.items(), key=lambda item: len(PurePosixPath(item[0]).parts), reverse=True):
            safe(DESTINATION / name).chmod(pin['mode'])
        actual_files, actual_dirs = census(DESTINATION)
        need(actual_files == files and actual_dirs == directories, 'complete-extracted-map-mismatch')
        root_files, root_dirs = census(DESTINATION / 'root')
        need(root_files == manifest['frozen_root_files'] and root_dirs == manifest['frozen_root_directories'],
             'independent-root-freeze-map-mismatch')
        need(digest(DESTINATION / 'control/freeze.json') == manifest['root_freeze_sha256'], 'copied-freeze-file-pin')
        need(digest(args.archive) == args.archive_sha256 and digest(args.manifest) == args.manifest_sha256,
             'input-changed-during-extraction')
        result.update(status='copied_pending_independent_remote_audit', source_prepared=True,
            files=len(actual_files), directories=len(actual_dirs), root_files=len(root_files),
            root_directories=len(root_dirs), maps_equal=True)
    except BaseException as error:
        primary = error
        result['error'] = repr(error)
    finally:
        result['ended_unix'] = time.time()
        result['returncode'] = 1 if primary else 0
        write(receipt, result)
    if primary is not None:
        raise primary


if __name__ == '__main__':
    main()
