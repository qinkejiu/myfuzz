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

    def child(self, args, *, data=b''):
        # Inherited config injection is scrubbed. Explicit command policy wins
        # over ordinary repository config; no network fallback is implemented.
        argv = [str(self.git), '-c', 'protocol.allow=never', '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false',
                *[str(value) for value in args]]
        self.counter += 1
        stem = f'child-{self.counter:05d}'
        stdin = self.control / (stem + '.stdin')
        stdin.write_bytes(data)
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

    def gitdir(self, store, args, *, data=b''):
        return self.child(['--git-dir=' + str(store), *args], data=data)


def batch(operation, store, oid, expected_type=None):
    require(len(oid) == 40 and all(c in '0123456789abcdef' for c in oid), 'invalid-object-id')
    path = operation.gitdir(store, ['cat-file', '--batch'], data=(oid + '\n').encode())
    raw = path.read_bytes()
    header, payload = raw.split(b'\n', 1)
    parts = header.decode('ascii').split()
    require(len(parts) == 3 and parts[0] == oid, 'missing-or-invalid-batch-object')
    kind, size = parts[1], int(parts[2])
    require(kind in ('commit', 'tree', 'blob') and size >= 0
            and len(payload) == size + 1 and payload[-1:] == b'\n', 'batch-payload-size')
    payload = payload[:-1]
    require(hashlib.sha1(kind.encode() + b' ' + str(size).encode() + b'\0' + payload).hexdigest() == oid,
            'object-content-hash')
    require(expected_type is None or kind == expected_type, 'object-type-mismatch')
    return kind, payload


def closure(operation, store, revision):
    objects, paths, gitlinks = {}, {}, []
    kind, commit = batch(operation, store, revision, 'commit')
    objects[revision] = dict(type=kind, bytes=len(commit))
    headers = commit.split(b'\n\n', 1)[0].splitlines()
    trees = [line[5:].decode('ascii') for line in headers if line.startswith(b'tree ')]
    require(len(trees) == 1, 'commit-root-tree')
    queue = [(trees[0], '')]
    seen_paths = set()
    while queue:
        oid, prefix = queue.pop(0)
        _, payload = batch(operation, store, oid, 'tree')
        objects[oid] = dict(type='tree', bytes=len(payload))
        listing = operation.gitdir(store, ['ls-tree', '-z', oid]).read_bytes()
        require(not listing or listing.endswith(b'\0'), 'tree-list-framing')
        for record in listing.split(b'\0')[:-1]:
            metadata, name = record.split(b'\t', 1)
            mode, typ, child = metadata.decode('ascii').split()
            name = name.decode('utf-8')
            require(name not in ('', '.', '..', '.git') and '/' not in name and '\\' not in name,
                    'unsafe-tree-name')
            relative = prefix + name
            require(relative not in seen_paths, 'duplicate-tree-path')
            seen_paths.add(relative)
            if typ == 'tree':
                require(mode == '040000', 'tree-mode')
                queue.append((child, relative + '/'))
            elif typ == 'commit':
                require(mode == '160000', 'gitlink-mode')
                gitlinks.append(dict(path=relative, oid=child))
            else:
                require(typ == 'blob' and mode in ('100644', '100755', '120000'), 'blob-mode')
                _, content = batch(operation, store, child, 'blob')
                objects[child] = dict(type='blob', bytes=len(content))
                paths[relative] = dict(oid=child, mode=mode, bytes=len(content),
                                       sha256=hashlib.sha256(content).hexdigest())
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
    parent = dict(schema_version='p8_offline_snapshot_materialization.v1',
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
                        _, blob = batch(op, quarantine, pin['oid'], 'blob')
                        require(blob == raw, 'symlink-blob-bytes:' + name)
                oids = ''.join(oid + '\n' for oid in sorted(objects)).encode()
                pack = op.gitdir(quarantine, ['pack-objects', '--stdout', '--no-reuse-delta',
                                             '--no-reuse-object'], data=oids)
                clean = output / 'clean.git'
                op.child(['init', '--bare', '--template=', clean])
                op.gitdir(clean, ['index-pack', '--stdin'], data=pack.read_bytes())
                (clean / 'shallow').write_text(revision + '\n')
                op.gitdir(clean, ['update-ref', 'refs/heads/pinned', revision])
                op.gitdir(clean, ['symbolic-ref', 'HEAD', 'refs/heads/pinned'])
                require(op.gitdir(clean, ['rev-parse', 'HEAD']).read_text().strip() == revision, 'clean-head')
                op.gitdir(clean, ['fsck', '--full', '--strict', '--no-reflogs'])
                for oid, pin in objects.items():
                    typ, content = batch(op, clean, oid, pin['type'])
                    require(len(content) == pin['bytes'], 'clean-object-size')
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
                for name, pin in paths.items():
                    blob = op.child(['-C', stage, 'cat-file', 'blob', revision + ':' + name])
                    actual = (hashlib.sha256(os.fsencode(os.readlink(stage / name))).hexdigest()
                              if pin['mode'] == '120000' else sha(stage / name))
                    require(sha(blob) == pin['sha256'] == actual, 'stage-git-blob:' + name)
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
