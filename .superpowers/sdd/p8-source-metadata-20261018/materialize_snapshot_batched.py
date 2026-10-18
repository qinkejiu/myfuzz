"""Offline snapshot metadata construction. Run only after independent review."""
import argparse
import fcntl
import hashlib
import json
import os
import posixpath
from pathlib import Path
import shutil
import stat
import subprocess
import time

FAN = Path('/root/fanzehui')
SOURCE = FAN / 'myfuzz/project'
LOCK = FAN / 'system-20261016/project/.superpowers/heavy-worker.lock'
COMPONENTS = {
    'opentitan': ('third_party/soc-opentitan', 'fca045df919a26c47e71616b9dac917b1ea4fd07'),
    'zipcpu': ('third_party/soc-zipcpu', '42606d2d6ef55df313772232977621b2d72f0159'),
}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe(path):
    require(path.is_absolute() and path.is_relative_to(FAN), 'outside-fanzehui')
    for ancestor in (path, *path.parents):
        require(not ancestor.is_symlink(), 'symlink-path:' + str(ancestor))
    return path


def maps(root, *, working_tree=False):
    safe(root)
    files, dirs = {}, {}
    require(root.is_dir(), 'missing-source-directory')
    for parent, children, names in os.walk(root, followlinks=False):
        for name in list(children):
            path = Path(parent) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if (stat.S_ISLNK(info.st_mode) and working_tree
                    and relative != '.git' and not relative.startswith('.git/')):
                children.remove(name)
                raw = os.fsencode(os.readlink(path))
                files[relative] = dict(kind='symlink', bytes=len(raw),
                    mode=stat.S_IMODE(info.st_mode), linkbytes_hex=raw.hex(),
                    sha256=hashlib.sha256(raw).hexdigest())
                continue
            require(stat.S_ISDIR(info.st_mode), 'directory-not-regular:' + str(path))
            dirs[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            path = Path(parent) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if (stat.S_ISLNK(info.st_mode) and working_tree
                    and relative != '.git' and not relative.startswith('.git/')):
                raw = os.fsencode(os.readlink(path))
                files[relative] = dict(kind='symlink', bytes=len(raw),
                    mode=stat.S_IMODE(info.st_mode), linkbytes_hex=raw.hex(),
                    sha256=hashlib.sha256(raw).hexdigest())
                continue
            require(stat.S_ISREG(info.st_mode), 'file-not-regular:' + str(path))
            files[path.relative_to(root).as_posix()] = dict(kind='regular', bytes=info.st_size,
                mode=stat.S_IMODE(info.st_mode), sha256=sha(path))
    return files, dirs


def copy_tree(source, destination):
    files, dirs = maps(source)
    safe(destination)
    destination.mkdir()
    for name, row in sorted(dirs.items(), key=lambda item: (len(Path(item[0]).parts), item[0])):
        (destination / name).mkdir()
        (destination / name).chmod(row['mode'])
    for name, row in files.items():
        target = destination / name
        with (source / name).open('rb') as src, target.open('xb') as dst:
            shutil.copyfileobj(src, dst)
        target.chmod(row['mode'])
        require(target.stat().st_nlink == 1, 'copied-hardlink')
    require(maps(destination) == (files, dirs), 'copy-map-mismatch')
    return files, dirs


class Operation:
    def __init__(self, output, git):
        self.output, self.git = output, git
        self.control = output / 'control'
        self.control.mkdir()
        self.counter = 0
        self.env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
        empty = output / 'empty-gitconfig'
        empty.write_bytes(b'')
        temporary = output / 'tmp'
        temporary.mkdir()
        self.env.update(GIT_CONFIG_GLOBAL=str(empty), GIT_CONFIG_NOSYSTEM='1',
            GIT_ALLOW_PROTOCOL='', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0',
            GIT_OPTIONAL_LOCKS='0', GIT_NO_REPLACE_OBJECTS='1', PYTHONDONTWRITEBYTECODE='1',
            TMPDIR=str(temporary))

    def write(self, name, value):
        with (self.control / name).open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())

    def child(self, args, *, data=b'', input_path=None):
        # Inherited config injection is scrubbed. Explicit command policy wins
        # over ordinary repository config; no network fallback is implemented.
        argv = [str(self.git), '-c', 'protocol.allow=never', '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false',
                *[str(value) for value in args]]
        self.counter += 1
        stem = f'child-{self.counter:05d}'
        stdin = self.control / (stem + '.stdin')
        require(input_path is None or not data, 'ambiguous-child-stdin')
        with stdin.open('xb') as target:
            if input_path is None:
                target.write(data)
            else:
                safe(input_path)
                with input_path.open('rb') as source:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
        outpath, errpath = self.control / (stem + '.stdout'), self.control / (stem + '.stderr')
        row = dict(argv=argv, cwd=str(self.output), started_unix=time.time(),
                   stdin_sha256=sha(stdin), returncode=None)
        primary, process = None, None
        with stdin.open('rb') as inp, outpath.open('xb') as out, errpath.open('xb') as err:
            try:
                process = subprocess.Popen(argv, cwd=self.output, env=self.env,
                    stdin=inp, stdout=out, stderr=err)
                row['pid'] = process.pid
                self.write(stem + '.start.json', row)
            except BaseException as error:
                primary = error
            finally:
                if process is not None:
                    while True:
                        try:
                            row['returncode'] = process.wait(timeout=30)
                            break
                        except subprocess.TimeoutExpired:
                            continue
                        except BaseException as error:
                            if primary is None:
                                primary = error
        row['ended_unix'] = time.time()
        row['stdout_sha256'], row['stderr_sha256'] = sha(outpath), sha(errpath)
        row['error'] = repr(primary) if primary else None
        self.write(stem + '.terminal.json', row)
        if primary is not None:
            raise primary
        require(row['returncode'] == 0, 'git-child-failed:' + stem)
        return outpath

    def gitdir(self, store, args, *, data=b'', input_path=None):
        return self.child(['--git-dir=' + str(store), *args], data=data, input_path=input_path)


BATCH_OBJECTS = 128


def read_batch(operation, store, requests, *, retain_oids=(), retain_types=('commit', 'tree')):
    """Stream blob hashes and yield lightweight pins; retain only requested bytes."""
    requests = list(requests)
    require(len({oid for oid, _ in requests}) == len(requests), 'duplicate-batch-request')
    for start in range(0, len(requests), BATCH_OBJECTS):
        chunk = requests[start:start + BATCH_OBJECTS]
        for oid, _ in chunk:
            require(len(oid) == 40 and all(c in '0123456789abcdef' for c in oid), 'invalid-object-id')
        output = operation.gitdir(store, ['cat-file', '--batch'],
            data=''.join(oid + '\n' for oid, _ in chunk).encode())
        manifest = dict(schema_version='p8_cat_file_batch_records.v1',
            stdout_file=output.name, store=str(store), requested_objects=len(chunk),
            status='failed', records=[])
        parsed = []
        try:
            with output.open('rb') as stream:
                for oid, expected_type in chunk:
                    offset = stream.tell()
                    header = stream.readline(256)
                    require(header.endswith(b'\n'), 'truncated-batch-header')
                    parts = header[:-1].decode('ascii').split()
                    require(len(parts) == 3 and parts[0] == oid, 'missing-or-invalid-batch-object')
                    kind, size = parts[1], int(parts[2])
                    require(kind in ('commit', 'tree', 'blob') and size >= 0, 'batch-type-size')
                    payload_offset = stream.tell()
                    git_hash = hashlib.sha1(kind.encode() + b' ' + str(size).encode() + b'\0')
                    content_hash = hashlib.sha256()
                    retained = bytearray() if kind in retain_types or oid in retain_oids else None
                    remaining = size
                    while remaining:
                        block = stream.read(min(remaining, 1024 * 1024))
                        require(block, 'truncated-batch-payload')
                        remaining -= len(block)
                        git_hash.update(block)
                        content_hash.update(block)
                        if retained is not None:
                            retained.extend(block)
                    require(stream.read(1) == b'\n', 'batch-payload-terminator')
                    require(git_hash.hexdigest() == oid,
                            'object-content-hash')
                    require(expected_type is None or kind == expected_type, 'object-type-mismatch')
                    manifest['records'].append(dict(oid=oid, type=kind, bytes=size,
                        header_offset=offset, payload_offset=payload_offset,
                        record_end_offset=stream.tell(), sha256=content_hash.hexdigest(),
                        payload_retained=retained is not None))
                    pin = dict(bytes=size, sha256=content_hash.hexdigest())
                    if retained is not None:
                        pin['payload'] = bytes(retained)
                    parsed.append((oid, kind, pin))
                require(stream.read(1) == b'', 'trailing-batch-output')
            manifest['status'] = 'verified'
        except BaseException as error:
            manifest['error'] = repr(error)
            raise
        finally:
            operation.write(output.stem + '.objects.json', manifest)
        yield from parsed


def batch(operation, store, oid, expected_type=None):
    # Single-object compatibility only for the commit entry; all scalable paths
    # use bounded batches and retain their multi-record offsets/headers.
    _, kind, pin = next(read_batch(operation, store, [(oid, expected_type)], retain_oids={oid}))
    return kind, pin['payload']


def tree_entries(payload):
    """Parse actual Git tree bytes: mode SP name NUL raw20-byte SHA1."""
    offset = 0
    names = set()
    while offset < len(payload):
        space = payload.find(b' ', offset)
        end = payload.find(b'\0', space + 1)
        require(space > offset and end > space + 1 and end + 21 <= len(payload), 'binary-tree-framing')
        mode = payload[offset:space].decode('ascii')
        raw_name = payload[space + 1:end]
        name = raw_name.decode('utf-8')
        require(name not in ('', '.', '..', '.git') and '/' not in name and '\\' not in name
                and raw_name not in names, 'unsafe-or-duplicate-tree-name')
        names.add(raw_name)
        oid = payload[end + 1:end + 21].hex()
        require(mode in ('40000', '100644', '100755', '120000', '160000'), 'binary-tree-mode')
        yield ('040000' if mode == '40000' else mode), name, oid
        offset = end + 21
    require(offset == len(payload), 'binary-tree-trailing-bytes')


def closure(operation, store, revision):
    objects, paths, gitlinks = {}, {}, []
    kind, commit = batch(operation, store, revision, 'commit')
    objects[revision] = dict(type=kind, bytes=len(commit))
    roots = [line[5:].decode('ascii') for line in commit.split(b'\n\n', 1)[0].splitlines()
             if line.startswith(b'tree ')]
    require(len(roots) == 1, 'commit-root-tree')
    layer = [(roots[0], '')]
    cache, seen_paths, blob_paths = {}, set(), {}
    while layer:
        wanted = sorted({oid for oid, _ in layer} - set(cache))
        for oid, _, pin in read_batch(operation, store, [(oid, 'tree') for oid in wanted]):
            cache[oid] = pin['payload']
            objects[oid] = dict(type='tree', bytes=pin['bytes'])
        following = []
        for oid, prefix in layer:
            for mode, name, child in tree_entries(cache[oid]):
                relative = prefix + name
                require(relative not in seen_paths, 'duplicate-tree-path')
                seen_paths.add(relative)
                if mode == '040000':
                    following.append((child, relative + '/'))
                elif mode == '160000':
                    gitlinks.append(dict(path=relative, oid=child))
                else:
                    blob_paths[relative] = dict(oid=child, mode=mode)
        layer = following
    blob_pins = {}
    link_oids = {pin['oid'] for pin in blob_paths.values() if pin['mode'] == '120000'}
    for oid, _, pin in read_batch(operation, store,
            [(oid, 'blob') for oid in sorted({pin['oid'] for pin in blob_paths.values()})],
            retain_oids=link_oids):
        objects[oid] = dict(type='blob', bytes=pin['bytes'])
        blob_pins[oid] = dict(bytes=pin['bytes'], sha256=pin['sha256'])
        if oid in link_oids:
            blob_pins[oid]['linkbytes_hex'] = pin['payload'].hex()
    for name, pin in blob_paths.items():
        paths[name] = {**pin, **blob_pins[pin['oid']]}
        if pin['mode'] != '120000':
            paths[name].pop('linkbytes_hex', None)
    return objects, paths, gitlinks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=sorted(COMPONENTS), required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--git', type=Path, required=True)
    parser.add_argument('--git-sha256', required=True)
    args = parser.parse_args()
    # Tool may reside outside fanzehui; it is read/execute only and must be pinned.
    require(args.git.is_absolute() and args.git.is_file() and sha(args.git) == args.git_sha256, 'git-tool-pin')
    output = safe(args.output)
    require(output.parent == FAN / 'myfuzz/operations' and output.name.startswith('p8-source-'), 'output-policy')
    output.mkdir(exist_ok=False)
    op = Operation(output, args.git)
    relative, revision = COMPONENTS[args.component]
    source = safe(SOURCE / relative)
    original = safe(source / '.git')
    parent = dict(schema_version='p8_offline_snapshot_materialization_batched.v1',
        batch_objects=BATCH_OBJECTS,
        status='failed', started_unix=time.time(), pid=os.getpid(), component=args.component,
        revision=revision, source=str(source), git_sha256=args.git_sha256,
        controller_sha256=sha(Path(__file__)), network_allowed=False, runtime_grant=False)
    primary, before = None, None
    try:
        op.write('parent-start.json', parent)
        safe(LOCK)
        with LOCK.open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                before = maps(source, working_tree=True)
                op.write('source-before-files.json', before[0])
                op.write('source-before-directories.json', before[1])
                quarantine = output / 'quarantine.git'
                copy_tree(original, quarantine)
                # Refuse external stores/config includes in private metadata
                # before any Git command. Original promisor declarations remain.
                import configparser
                config = configparser.RawConfigParser()
                config.read_string((quarantine / 'config').read_text())
                require(not any(s.lower() == 'include' or s.lower().startswith('includeif ')
                                for s in config.sections()), 'external-config-include')
                require(not config.has_option('core', 'worktree'), 'external-worktree-config')
                for name in ('objects/info/alternates', 'commondir'):
                    require(not (quarantine / name).exists(), 'external-object-store')
                objects, paths, gitlinks = closure(op, quarantine, revision)
                op.write('snapshot-objects.json', objects)
                op.write('snapshot-paths.json', paths)
                op.write('gitlinks.json', gitlinks)
                require(not gitlinks, 'gitlinks-require-separate-reviewed-boundaries')
                working = {name: row for name, row in before[0].items() if not name.startswith('.git/')}
                require(set(working) == set(paths), 'working-tree-not-full-snapshot')
                for name, pin in paths.items():
                    require(working[name]['kind'] == ('symlink' if pin['mode'] == '120000' else 'regular')
                            and working[name]['bytes'] == pin['bytes']
                            and working[name]['sha256'] == pin['sha256'], 'working-tree-blob-mismatch:' + name)
                    if pin['mode'] == '120000':
                        raw = bytes.fromhex(working[name]['linkbytes_hex'])
                        target = os.fsdecode(raw)
                        normalized = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                        require(target and not target.startswith('/') and normalized != '..'
                                and not normalized.startswith('../') and '\x00' not in target,
                                'symlink-target-outside-component:' + name)
                        require(raw.hex() == pin['linkbytes_hex'], 'symlink-blob-bytes:' + name)
                oids = ''.join(oid + '\n' for oid in sorted(objects)).encode()
                pack = op.gitdir(quarantine, ['pack-objects', '--stdout', '--no-reuse-delta',
                                             '--no-reuse-object'], data=oids)
                clean = output / 'clean.git'
                op.child(['init', '--bare', '--template=', clean])
                op.gitdir(clean, ['index-pack', '--stdin'], input_path=pack)
                (clean / 'shallow').write_text(revision + '\n')
                op.gitdir(clean, ['update-ref', 'refs/heads/pinned', revision])
                op.gitdir(clean, ['symbolic-ref', 'HEAD', 'refs/heads/pinned'])
                require(op.gitdir(clean, ['rev-parse', 'HEAD']).read_text().strip() == revision, 'clean-head')
                op.gitdir(clean, ['fsck', '--full', '--strict', '--no-reflogs'])
                for oid, typ, pin in read_batch(op, clean,
                        [(oid, objects[oid]['type']) for oid in sorted(objects)], retain_types=()):
                    require(pin['bytes'] == objects[oid]['bytes'], 'clean-object-size')
                listed = op.gitdir(clean, ['cat-file', '--batch-all-objects',
                    '--batch-check=%(objectname) %(objecttype) %(objectsize)']).read_text().splitlines()
                actual_objects = {}
                for line in listed:
                    oid, typ, size = line.split()
                    require(oid not in actual_objects, 'duplicate-clean-object')
                    actual_objects[oid] = dict(type=typ, bytes=int(size))
                require(actual_objects == objects, 'clean-object-set-not-snapshot-only')
                for metadata_root in (clean,):
                    require(not list(metadata_root.rglob('*.promisor'))
                            and not (metadata_root / 'objects/info/alternates').exists()
                            and not (metadata_root / 'commondir').exists(), 'clean-shared-or-promisor-store')
                    clean_config = configparser.RawConfigParser()
                    clean_config.read_string((metadata_root / 'config').read_text())
                    require(not any(key.lower() in ('promisor', 'partialclone', 'worktree', 'hookspath')
                        for section in clean_config.sections() for key in clean_config[section]), 'clean-config-dependency')
                # New complete worktree, copied without old metadata.
                stage = output / 'stage'
                stage.mkdir()
                for name, pin in paths.items():
                    target = stage / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if pin['mode'] == '120000':
                        os.symlink(os.fsdecode(bytes.fromhex(working[name]['linkbytes_hex'])), target)
                        continue
                    with (source / name).open('rb') as src, target.open('xb') as dst:
                        shutil.copyfileobj(src, dst)
                    target.chmod(int(pin['mode'][-3:], 8))
                copy_tree(clean, stage / '.git')
                op.gitdir(stage / '.git', ['config', 'core.bare', 'false'])
                op.gitdir(stage / '.git', ['--work-tree=' + str(stage), 'read-tree', revision])
                status = op.child(['-C', stage, 'status', '--porcelain=v1', '--untracked-files=all'])
                require(not status.read_bytes(), 'staged-status-not-clean')
                names = sorted(paths)
                for offset in range(0, len(names), 128):
                    op.child(['-C', stage, 'ls-files', '--error-unmatch', '--', *names[offset:offset + 128]])
                staged_objects, staged_paths, staged_gitlinks = closure(op, stage / '.git', revision)
                require(staged_objects == objects and staged_paths == paths and not staged_gitlinks,
                        'staged-complete-snapshot-paths')
                path_checks = {}
                for name, pin in staged_paths.items():
                    actual = (hashlib.sha256(os.fsencode(os.readlink(stage / name))).hexdigest()
                              if pin['mode'] == '120000' else sha(stage / name))
                    require(pin['sha256'] == actual, 'stage-git-blob:' + name)
                    path_checks[name] = dict(oid=pin['oid'], mode=pin['mode'], bytes=pin['bytes'],
                        git_blob_sha256=pin['sha256'], filesystem_sha256=actual,
                        filesystem_kind='symlink' if pin['mode'] == '120000' else 'regular')
                op.write('stage-git-blob-path-checks.json', path_checks)
                op.gitdir(stage / '.git', ['fsck', '--full', '--strict', '--no-reflogs'])
                final = maps(stage, working_tree=True)
                op.write('stage-files.json', final[0])
                op.write('stage-directories.json', final[1])
                parent['status'] = 'prepared_pending_independent_audit_no_runtime_grant'
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    after = maps(source, working_tree=True)
                    op.write('source-after-files.json', after[0])
                    op.write('source-after-directories.json', after[1])
                    require(before is not None and before == after, 'original-source-drift')
                except BaseException as collection:
                    parent['source_after_error'] = repr(collection)
                    if primary is None:
                        raise
                    primary.add_note('source after collection: ' + repr(collection))
    except BaseException as error:
        primary = error
        parent.update(status='failed', error=repr(error))
    finally:
        parent.update(ended_unix=time.time(), returncode=1 if primary else 0,
                      children=op.counter)
        op.write('parent-terminal.json', parent)
    return parent['returncode']


if __name__ == '__main__':
    raise SystemExit(main())
