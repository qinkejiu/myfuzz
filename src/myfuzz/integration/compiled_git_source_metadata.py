"""Validate and restore frozen Git metadata for declared component sources."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile


INDEX_SCHEMA = 'compiled_F6_git_source_metadata_index.v1'
INDEX_PATH = 'source-git-metadata/index.json'
ARCHIVE_PREFIX = 'source-git-metadata/repositories/'
ROW_KEYS = {'root', 'revision', 'archive', 'archive_sha256'}


def _relative(value, *, code: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(code)
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') for part in path.parts):
        raise ValueError(code)
    return path.as_posix()


def _revision(value, *, code: str) -> str:
    if type(value) is not str or len(value) != 44 or not value.startswith('git:'):
        raise ValueError(code)
    if any(char not in '0123456789abcdef' for char in value[4:]):
        raise ValueError(code)
    return value


def source_git_requirements(project_root: Path) -> dict[str, str]:
    """Return the exact unique Git roots declared by component profiles."""
    project_root = Path(project_root).resolve(strict=True)
    requirements: dict[str, str] = {}
    for parent in (project_root / 'configs/cpus', project_root / 'configs/peripherals'):
        if not parent.is_dir():
            continue
        for profile_path in sorted(parent.rglob('component_profile.json')):
            try:
                document = json.loads(profile_path.read_text(encoding='utf-8'))
            except (OSError, json.JSONDecodeError) as error:
                raise ValueError('source-metadata-profile-invalid:' +
                    profile_path.relative_to(project_root).as_posix()) from error
            if type(document) is not dict or document.get('schema_version') != 'component_profile.v1':
                continue
            source = document.get('source')
            if type(source) is not dict:
                continue
            root = _relative(source.get('root'), code='source-metadata-source-root-invalid')
            root_revision = source.get('revision')
            repositories = source.get('repositories', [])
            if type(repositories) is not list:
                raise ValueError('source-metadata-repositories-invalid:' + root)
            if type(root_revision) is not str or not root_revision.startswith('git:'):
                if repositories:
                    raise ValueError('source-metadata-repository-pin-requires-git-root:' + root)
                continue
            root_revision = _revision(root_revision, code='source-metadata-git-revision-invalid:' + root)
            _add_requirement(requirements, root, root_revision)
            for repository in repositories:
                if type(repository) is not dict:
                    raise ValueError('source-metadata-repository-pin-invalid:' + root)
                child = _relative(repository.get('path'),
                    code='source-metadata-repository-path-invalid:' + root)
                child_revision = _revision(repository.get('revision'),
                    code='source-metadata-git-revision-invalid:' + root + '/' + child)
                _add_requirement(requirements, _relative(root + '/' + child,
                    code='source-metadata-repository-path-invalid:' + root), child_revision)
    if not requirements:
        raise ValueError('source-metadata-git-repository-set-empty')
    return dict(sorted(requirements.items()))


def _add_requirement(requirements: dict[str, str], root: str, revision: str) -> None:
    previous = requirements.get(root)
    if previous is not None and previous != revision:
        raise ValueError('source-metadata-conflicting-revision:' + root)
    requirements[root] = revision


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(['git', '-C', str(root), *args],
        capture_output=True, text=True, check=False)
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        raise ValueError('source-metadata-git-command-failed:' +
            root.as_posix() + ':' + ' '.join(args) + ':' + (detail[-1] if detail else ''))
    return result.stdout.strip()


def _archive_members(data: bytes, *, root: str, revision: str):
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
    except (OSError, tarfile.TarError) as error:
        raise ValueError('source-metadata-archive-invalid:' + root) from error
    with archive:
        members = archive.getmembers()
        names = set()
        git_head = None
        shallow = None
        git_config = None
        refs = {}
        for member in members:
            path = PurePosixPath(member.name)
            if (path.is_absolute() or len(path.parts) < 2 or path.parts[0] != '.git'
                    or any(part in ('', '.', '..') for part in path.parts)):
                raise ValueError('source-metadata-archive-member-path-invalid:' + root)
            name = path.as_posix()
            if name in names:
                raise ValueError('source-metadata-archive-member-duplicate:' + root)
            names.add(name)
            if not (member.isfile() or member.isdir()):
                raise ValueError('source-metadata-archive-member-type-invalid:' + root)
            if (name in {'.git/objects/info/alternates', '.git/objects/info/http-alternates'}
                    or (name.startswith('.git/objects/pack/') and name.endswith('.promisor'))
                    or name.startswith('.git/refs/remotes/')):
                raise ValueError('source-metadata-archive-partial-clone-forbidden:' + root)
            if name == '.git/HEAD':
                if not member.isfile():
                    raise ValueError('source-metadata-archive-head-invalid:' + root)
                stream = archive.extractfile(member)
                git_head = stream.read() if stream is not None else None
            if name == '.git/shallow':
                if not member.isfile():
                    raise ValueError('source-metadata-archive-shallow-invalid:' + root)
                stream = archive.extractfile(member)
                shallow = stream.read() if stream is not None else None
            if name == '.git/config':
                if not member.isfile():
                    raise ValueError('source-metadata-archive-config-invalid:' + root)
                stream = archive.extractfile(member)
                git_config = stream.read() if stream is not None else None
            if name.startswith('.git/refs/') or name == '.git/packed-refs':
                if member.isfile():
                    stream = archive.extractfile(member)
                    refs[name] = stream.read() if stream is not None else b''
        expected_commit = revision[4:].encode('ascii')
        if '.git/HEAD' not in names or '.git/shallow' not in names:
            raise ValueError('source-metadata-archive-incomplete:' + root)
        if shallow is None or expected_commit not in shallow.splitlines():
            raise ValueError('source-metadata-archive-shallow-revision-mismatch:' + root)
        if git_config is None or b'promisor' in git_config.lower() or b'partialclone' in git_config.lower():
            raise ValueError('source-metadata-archive-partial-clone-forbidden:' + root)
        packed = refs.get('.git/packed-refs', b'').decode('ascii', errors='ignore').splitlines()
        if any(len(line.split()) == 2 and line.split()[1].startswith('refs/remotes/')
                for line in packed if not line.startswith('#')):
            raise ValueError('source-metadata-archive-partial-clone-forbidden:' + root)
        head_text = git_head.decode('ascii', errors='ignore').strip() if git_head is not None else ''
        if head_text == revision[4:]:
            # A shallow checkout may legitimately be detached at the profile pin.
            pass
        elif head_text.startswith('ref: refs/heads/'):
            branch_ref = head_text[5:]
            loose_ref = '.git/' + branch_ref
            ref_found = refs.get(loose_ref, b'').decode('ascii', errors='ignore').strip() == revision[4:]
            ref_found = ref_found or any(
                len(line.split()) == 2 and line.split()[0] == revision[4:]
                and line.split()[1] == branch_ref for line in packed if not line.startswith('#'))
            if not ref_found:
                raise ValueError('source-metadata-archive-branch-ref-missing:' + root)
        else:
            raise ValueError('source-metadata-archive-head-invalid:' + root)
        return members


def _repository_root(project_root: Path, root_name: str) -> Path:
    relative = _relative(root_name, code='source-metadata-source-root-invalid')
    root = project_root
    for part in PurePosixPath(relative).parts:
        root = root / part
        if root.is_symlink():
            raise ValueError('source-metadata-source-path-symlinked:' + relative)
    if not root.is_dir():
        raise ValueError('source-metadata-source-root-unavailable:' + relative)
    resolved = root.resolve(strict=True)
    if not resolved.is_relative_to(project_root):
        raise ValueError('source-metadata-source-root-outside-project:' + relative)
    return resolved


def validate_source_metadata(*, project_root: Path, frozen_map: dict[str, str]) -> list[dict]:
    """Validate the exact profile-to-Git-metadata closure against a frozen map."""
    project_root = Path(project_root).resolve(strict=True)
    if type(frozen_map) is not dict or any(type(k) is not str or type(v) is not str
            for k, v in frozen_map.items()):
        raise ValueError('source-metadata-frozen-map-invalid')
    expected_index_sha = frozen_map.get(INDEX_PATH)
    index_file = project_root / INDEX_PATH
    if expected_index_sha is None or not index_file.is_file() or index_file.is_symlink():
        raise ValueError('source-metadata-index-missing-from-frozen-map')
    index_bytes = index_file.read_bytes()
    if _digest_bytes(index_bytes) != expected_index_sha:
        raise ValueError('source-metadata-index-digest-mismatch')
    try:
        document = json.loads(index_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError('source-metadata-index-invalid') from error
    if (type(document) is not dict or set(document) != {'schema_version', 'repositories'}
            or document.get('schema_version') != INDEX_SCHEMA
            or type(document.get('repositories')) is not list):
        raise ValueError('source-metadata-index-schema-invalid')
    required = source_git_requirements(project_root)
    rows = document['repositories']
    by_root = {}
    previous_root = None
    for row in rows:
        if type(row) is not dict or set(row) != ROW_KEYS:
            raise ValueError('source-metadata-index-row-invalid')
        root = _relative(row.get('root'), code='source-metadata-index-root-invalid')
        revision = _revision(row.get('revision'), code='source-metadata-index-revision-invalid')
        archive_name = _relative(row.get('archive'), code='source-metadata-index-archive-invalid')
        archive_sha = row.get('archive_sha256')
        if (type(archive_sha) is not str or len(archive_sha) != 64
                or any(char not in '0123456789abcdef' for char in archive_sha)):
            raise ValueError('source-metadata-index-archive-sha-invalid:' + root)
        if root in by_root or (previous_root is not None and root <= previous_root):
            raise ValueError('source-metadata-index-order-or-duplicate:' + root)
        previous_root = root
        if archive_name != ARCHIVE_PREFIX + hashlib.sha256(root.encode('utf-8')).hexdigest() + '.tar.gz':
            raise ValueError('source-metadata-index-archive-path-invalid:' + root)
        if required.get(root) != revision:
            raise ValueError('source-metadata-index-profile-pin-mismatch:' + root)
        if archive_name not in frozen_map:
            raise ValueError('source-metadata-archive-missing-from-frozen-map:' + root)
        if frozen_map[archive_name] != archive_sha:
            raise ValueError('source-metadata-archive-frozen-hash-mismatch:' + root)
        archive_path = project_root / archive_name
        if archive_path.is_symlink() or not archive_path.is_file():
            raise ValueError('source-metadata-archive-missing:' + root)
        archive_bytes = archive_path.read_bytes()
        if _digest_bytes(archive_bytes) != archive_sha:
            raise ValueError('source-metadata-archive-digest-mismatch:' + root)
        _archive_members(archive_bytes, root=root, revision=revision)
        by_root[root] = dict(row)
    if set(by_root) != set(required):
        raise ValueError('source-metadata-index-profile-set-mismatch')
    return [by_root[root] for root in sorted(by_root)]


def _extract_git_directory(data: bytes, destination: Path, *, root: str) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive.getmembers():
            parts = PurePosixPath(member.name).parts[1:]
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, member.mode & 0o777)
                continue
            if not member.isfile():
                raise ValueError('source-metadata-archive-member-type-invalid:' + root)
            target.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('source-metadata-archive-member-unreadable:' + root)
            with stream, target.open('xb') as output:
                shutil.copyfileobj(stream, output)
            os.chmod(target, member.mode & 0o777)


def _verify_git_checkout(root: Path, expected: str, *, root_name: str, error_code: str) -> None:
    try:
        head = _git(root, 'rev-parse', 'HEAD')
        top = Path(_git(root, 'rev-parse', '--show-toplevel')).resolve(strict=True)
        object_type = _git(root, 'cat-file', '-t', expected)
        _git(root, 'fsck', '--full', '--strict', '--no-reflogs', '--no-progress')
    except (OSError, ValueError) as error:
        raise ValueError(error_code + ':' + root_name) from error
    if head != expected or top != root or object_type != 'commit':
        raise ValueError(error_code + ':' + root_name)


def materialize_source_metadata(*, project_root: Path, frozen_map: dict[str, str]) -> dict:
    """Restore absent `.git` directories from the frozen safe metadata archives."""
    project_root = Path(project_root).resolve(strict=True)
    rows = validate_source_metadata(project_root=project_root, frozen_map=frozen_map)
    pending = []
    existing = []
    # Check every pre-existing checkout before installing any missing metadata.
    # A later conflict must not leave an earlier repository partially restored.
    for row in rows:
        root_name = row['root']
        root = _repository_root(project_root, root_name)
        git_path = root / '.git'
        expected = row['revision'][4:]
        if git_path.is_symlink():
            raise ValueError('source-metadata-existing-gitlink-unsafe:' + root_name)
        if git_path.exists():
            _verify_git_checkout(root, expected, root_name=root_name,
                error_code='source-metadata-existing-git-revision-mismatch')
            existing.append(root_name)
        else:
            pending.append((row, root))

    created = []
    try:
        for row, root in pending:
            root_name = row['root']
            git_path = root / '.git'
            if git_path.exists() or git_path.is_symlink():
                raise ValueError('source-metadata-existing-git-appeared:' + root_name)
            archive_path = project_root / row['archive']
            data = archive_path.read_bytes()
            temp_parent = Path(tempfile.mkdtemp(prefix='.compiled-f6-git-metadata-', dir=root.parent))
            temp_git = temp_parent / '.git'
            installed = False
            try:
                _extract_git_directory(data, temp_git, root=root_name)
                os.replace(temp_git, git_path)
                installed = True
                _verify_git_checkout(root, row['revision'][4:], root_name=root_name,
                    error_code='source-metadata-materialized-revision-mismatch')
                created.append(root_name)
            except BaseException:
                if installed and git_path.is_dir() and not git_path.is_symlink():
                    shutil.rmtree(git_path)
                raise
            finally:
                if temp_parent.exists() and not temp_parent.is_symlink():
                    shutil.rmtree(temp_parent)
    except BaseException:
        for root_name in reversed(created):
            git_path = _repository_root(project_root, root_name) / '.git'
            if git_path.is_dir() and not git_path.is_symlink():
                shutil.rmtree(git_path)
        raise
    return {'status': 'materialized', 'created': created, 'existing': existing}
