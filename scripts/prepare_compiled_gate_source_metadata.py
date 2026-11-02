"""Freeze exact Git metadata for component-profile source revisions."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile


INDEX_SCHEMA = 'compiled_F6_git_source_metadata_index.v1'


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _git(path: Path, *args: str) -> str:
    result = subprocess.run(['git', '-C', str(path), *args],
        capture_output=True, text=True, check=False)
    if result.returncode:
        detail = result.stderr.strip().splitlines()
        raise ValueError('source-metadata-git-command-failed:' +
            str(path) + ':' + ' '.join(args) + ':' + (detail[-1] if detail else ''))
    return result.stdout.strip()


def _requirements(project_root: Path) -> dict[str, str]:
    source_dir = str(Path(__file__).resolve().parents[1] / 'src')
    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)
    from myfuzz.integration.compiled_git_source_metadata import source_git_requirements
    return source_git_requirements(project_root)


def _verify_source_checkout(project_root: Path, root_name: str, revision: str) -> Path:
    candidate = project_root
    for part in PurePosixPath(root_name).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError('source-metadata-source-path-symlinked:' + root_name)
    root = project_root / root_name
    if root.is_symlink() or not root.is_dir():
        raise ValueError('source-metadata-source-root-unavailable:' + root_name)
    resolved_root = root.resolve(strict=True)
    if not resolved_root.is_relative_to(project_root):
        raise ValueError('source-metadata-source-root-outside-project:' + root_name)
    expected = revision[4:]
    try:
        head = _git(root, 'rev-parse', 'HEAD')
        top = Path(_git(root, 'rev-parse', '--show-toplevel')).resolve(strict=True)
    except (OSError, ValueError) as error:
        raise ValueError('source-metadata-source-root-not-git:' + root_name) from error
    if head != expected or top != resolved_root:
        raise ValueError('source-metadata-revision-mismatch:' + root_name)
    return resolved_root


def _write_git_archive(git_dir: Path, target: Path) -> None:
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise ValueError('source-metadata-gitdir-invalid:' + str(git_dir))
    for forbidden in ('objects/info/alternates', 'objects/info/http-alternates'):
        if (git_dir / forbidden).exists():
            raise ValueError('source-metadata-git-alternate-forbidden:' + forbidden)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open('wb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for path in sorted(git_dir.rglob('*')):
                    if path.is_symlink():
                        raise ValueError('source-metadata-gitdir-symlink-forbidden:' +
                            path.relative_to(git_dir).as_posix())
                    relative = path.relative_to(git_dir).as_posix()
                    info = archive.gettarinfo(str(path), arcname=PurePosixPath('.git', relative).as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = ''
                    info.gname = ''
                    info.mtime = 0
                    if info.isfile():
                        with path.open('rb') as stream:
                            archive.addfile(info, stream)
                    elif info.isdir():
                        archive.addfile(info)
                    else:
                        raise ValueError('source-metadata-gitdir-special-file-forbidden:' + relative)


def _remove_remote_tracking_refs(git_dir: Path) -> None:
    for relative in ('refs/remotes', 'logs/refs/remotes'):
        path = git_dir / relative
        if path.is_symlink():
            raise ValueError('source-metadata-remote-ref-symlink-forbidden:' + relative)
        if path.exists():
            shutil.rmtree(path)
    packed_refs = git_dir / 'packed-refs'
    if packed_refs.is_symlink():
        raise ValueError('source-metadata-packed-refs-symlink-forbidden')
    if packed_refs.is_file():
        retained = []
        for line in packed_refs.read_text(encoding='ascii').splitlines(keepends=True):
            fields = line.strip().split()
            if len(fields) >= 2 and fields[1].startswith('refs/remotes/'):
                continue
            retained.append(line)
        packed_refs.write_text(''.join(retained), encoding='ascii')


def _prepare_repo_metadata(project_root: Path, root_name: str, revision: str,
                           staging_root: Path, archive_relative: str) -> str:
    source_root = _verify_source_checkout(project_root, root_name, revision)
    with tempfile.TemporaryDirectory(prefix='compiled-f6-source-metadata-') as temp_name:
        clone = Path(temp_name) / 'repository'
        clone_result = subprocess.run([
            'git', 'clone', '--quiet', '--depth', '1', '--no-tags',
            source_root.as_uri(), str(clone)], capture_output=True, text=True, check=False)
        if clone_result.returncode:
            raise ValueError('source-metadata-shallow-clone-failed:' + root_name + ':' +
                clone_result.stderr.strip().splitlines()[-1])
        expected = revision[4:]
        if _git(clone, 'rev-parse', 'HEAD') != expected:
            fetch = subprocess.run(['git', '-C', str(clone), 'fetch', '--quiet',
                '--depth=1', '--no-tags', 'origin', expected],
                capture_output=True, text=True, check=False)
            if fetch.returncode:
                detail = fetch.stderr.strip().splitlines()
                raise ValueError('source-metadata-pinned-commit-fetch-failed:' + root_name + ':' +
                    (detail[-1] if detail else ''))
            _git(clone, 'checkout', '--quiet', '--detach', '--force', expected)
        if _git(clone, 'rev-parse', 'HEAD') != expected:
            raise ValueError('source-metadata-clone-revision-mismatch:' + root_name)
        _git(clone, 'remote', 'remove', 'origin')
        git_dir = clone / '.git'
        _remove_remote_tracking_refs(git_dir)
        config = (git_dir / 'config').read_bytes().lower()
        if b'promisor' in config or b'partialclone' in config:
            raise ValueError('source-metadata-partial-clone-forbidden:' + root_name)
        fsck = subprocess.run(['git', '-C', str(clone), 'fsck', '--full', '--strict',
            '--no-reflogs', '--no-progress'], capture_output=True, text=True, check=False)
        if fsck.returncode:
            detail = (fsck.stderr + fsck.stdout).strip().splitlines()
            raise ValueError('source-metadata-git-fsck-failed:' + root_name + ':' +
                (detail[-1] if detail else ''))
        archive_path = staging_root / archive_relative
        _write_git_archive(git_dir, archive_path)
        return _sha256(archive_path)


def prepare_source_metadata(*, project_root: Path, output_root: Path) -> dict:
    project_root = Path(project_root).resolve(strict=True)
    output_root = Path(output_root)
    if not output_root.is_absolute():
        output_root = project_root / output_root
    output_root = Path(os.path.abspath(output_root))
    if not output_root.is_relative_to(project_root) or output_root == project_root:
        raise ValueError('source-metadata-output-outside-project')
    output_cursor = project_root
    for part in output_root.relative_to(project_root).parts:
        output_cursor = output_cursor / part
        if output_cursor.is_symlink():
            raise ValueError('source-metadata-output-path-symlinked')
    if output_root.exists() or output_root.is_symlink():
        raise ValueError('source-metadata-output-already-exists')
    requirements = _requirements(project_root)
    output_relative = output_root.relative_to(project_root).as_posix()
    staging = output_root.parent / ('.' + output_root.name + '.prepare-' + str(os.getpid()))
    if staging.exists() or staging.is_symlink():
        raise ValueError('source-metadata-staging-already-exists')
    staging.mkdir(parents=True, exist_ok=False)
    try:
        repositories = []
        for root_name, revision in requirements.items():
            archive_inside = PurePosixPath('repositories',
                hashlib.sha256(root_name.encode('utf-8')).hexdigest() + '.tar.gz').as_posix()
            archive_sha256 = _prepare_repo_metadata(project_root, root_name, revision,
                staging, archive_inside)
            repositories.append(dict(root=root_name, revision=revision,
                archive=PurePosixPath(output_relative, archive_inside).as_posix(),
                archive_sha256=archive_sha256))
        document = dict(schema_version=INDEX_SCHEMA, repositories=repositories)
        (staging / 'index.json').write_text(json.dumps(document, sort_keys=True, indent=2) + '\n',
            encoding='utf-8')
        staging.rename(output_root)
        return document
    except BaseException:
        if staging.exists() and not staging.is_symlink():
            shutil.rmtree(staging)
        raise


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, default=Path.cwd())
    parser.add_argument('--output-root', type=Path, default=Path('source-git-metadata'))
    args = parser.parse_args(argv)
    result = prepare_source_metadata(project_root=args.project_root, output_root=args.output_root)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
