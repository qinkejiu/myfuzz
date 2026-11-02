"""Tests for source repository metadata frozen with the F6 gate."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / 'scripts/prepare_compiled_gate_source_metadata.py'
SOURCE_METADATA = ROOT / 'src/myfuzz/integration/compiled_git_source_metadata.py'


def generator_module():
    assert GENERATOR.is_file(), 'source metadata generator is missing'
    spec = importlib.util.spec_from_file_location('compiled_f6_source_metadata_generator', GENERATOR)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_metadata_module():
    assert SOURCE_METADATA.is_file(), 'source metadata runtime is missing'
    spec = importlib.util.spec_from_file_location('compiled_f6_source_metadata_runtime', SOURCE_METADATA)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], check=True,
        capture_output=True, text=True)
    return result.stdout.strip()


def make_git_repo(root, *, files):
    root.mkdir(parents=True)
    subprocess.run(['git', 'init', '--quiet', str(root)], check=True)
    git(root, 'config', 'user.name', 'F6 source metadata test')
    git(root, 'config', 'user.email', 'f6-source-metadata@example.invalid')
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    git(root, 'add', '--all')
    git(root, 'commit', '--quiet', '-m', 'pinned source')
    return git(root, 'rev-parse', 'HEAD')


def write_profile(project, *, root, revision, repositories=()):
    profile = project / 'configs/cpus/demo/component_profile.json'
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.write_text(json.dumps({
        'schema_version': 'component_profile.v1',
        'component_id': 'demo',
        'source': {
            'root': root,
            'revision': 'git:' + revision,
            'files': ['rtl/demo.sv'],
            'repositories': [
                {'path': row[0], 'revision': 'git:' + row[1]} for row in repositories
            ],
        },
    }))


def rewrite_archive(archive_path, *, transform):
    output = io.BytesIO()
    with tarfile.open(archive_path, 'r:gz') as source:
        members = []
        for member in source.getmembers():
            payload = source.extractfile(member).read() if member.isfile() else None
            replacement = transform(member, payload)
            if replacement is not None:
                members.append(replacement)
    with tarfile.open(fileobj=output, mode='w:gz') as destination:
        for member, payload in members:
            if payload is None:
                destination.addfile(member)
            else:
                member.size = len(payload)
                destination.addfile(member, io.BytesIO(payload))
    archive_path.write_bytes(output.getvalue())


def freeze_metadata_map(project, index_path):
    index = json.loads(index_path.read_text())
    frozen_map = {index_path.relative_to(project).as_posix():
        hashlib.sha256(index_path.read_bytes()).hexdigest()}
    for row in index['repositories']:
        archive = project / row['archive']
        row['archive_sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
        frozen_map[row['archive']] = row['archive_sha256']
    index_path.write_text(json.dumps(index, sort_keys=True, indent=2) + '\n')
    frozen_map[index_path.relative_to(project).as_posix()] = hashlib.sha256(
        index_path.read_bytes()).hexdigest()
    return index, frozen_map


def rewrite_archive_from_git_directory(archive_path, git_directory):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as destination:
        for path in sorted(git_directory.rglob('*')):
            relative = path.relative_to(git_directory).as_posix()
            info = destination.gettarinfo(str(path), arcname='.git/' + relative)
            if info.isfile():
                with path.open('rb') as stream:
                    destination.addfile(info, stream)
            elif info.isdir():
                destination.addfile(info)
            else:
                raise AssertionError('unexpected Git metadata file type: ' + str(path))
    archive_path.write_bytes(output.getvalue())


def test_generator_emits_exact_shallow_git_metadata_for_root_and_nested_repositories(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    parent = project / 'third_party/demo'
    parent.mkdir(parents=True)
    git(parent, 'init', '--quiet')
    git(parent, 'config', 'user.name', 'F6 source metadata test')
    git(parent, 'config', 'user.email', 'f6-source-metadata@example.invalid')
    (parent / 'rtl').mkdir()
    (parent / 'rtl/demo.sv').write_text('module demo; endmodule\n')
    child = parent / 'nested'
    child_revision = make_git_repo(child, files={'child.sv': 'module child; endmodule\n'})
    git(parent, 'add', 'rtl')
    git(parent, 'update-index', '--add', '--cacheinfo', f'160000,{child_revision},nested')
    git(parent, 'commit', '--quiet', '-m', 'pinned parent')
    parent_revision = git(parent, 'rev-parse', 'HEAD')
    write_profile(project, root='third_party/demo', revision=parent_revision,
        repositories=[('nested', child_revision)])

    result = generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')

    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    assert result == index
    assert index['schema_version'] == 'compiled_F6_git_source_metadata_index.v1'
    assert [row['root'] for row in index['repositories']] == [
        'third_party/demo', 'third_party/demo/nested']
    for row in index['repositories']:
        archive_path = project / row['archive']
        assert row['revision'] in ('git:' + parent_revision, 'git:' + child_revision)
        assert hashlib.sha256(archive_path.read_bytes()).hexdigest() == row['archive_sha256']
        with tarfile.open(archive_path, 'r:gz') as archive:
            members = archive.getmembers()
            assert members
            assert all(member.name.startswith('.git/') for member in members)
            assert all(member.isfile() or member.isdir() for member in members)
            assert {member.name for member in members} >= {'.git/HEAD', '.git/shallow'}
            assert not any(member.name.startswith('.git/refs/remotes/') for member in members)
            assert not any(member.name.endswith('.promisor') for member in members)
            config = archive.extractfile('.git/config').read().lower()
            assert b'promisor' not in config and b'partialclone' not in config
        extracted = tmp_path / ('fsck-' + hashlib.sha256(row['root'].encode()).hexdigest())
        source_metadata_module()._extract_git_directory(archive_path.read_bytes(),
            extracted / '.git', root=row['root'])
        fsck = subprocess.run(['git', '--git-dir=' + str(extracted / '.git'), 'fsck',
            '--full', '--strict', '--no-reflogs', '--no-progress'],
            capture_output=True, text=True, check=False)
        assert fsck.returncode == 0, fsck.stderr + fsck.stdout


def test_generator_refuses_a_profile_revision_that_does_not_match_the_checkout(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    actual = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    mismatched = '0' * 40 if actual != '0' * 40 else '1' * 40
    write_profile(project, root='third_party/demo', revision=mismatched)

    with pytest.raises(ValueError, match='source-metadata-revision-mismatch'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=project / 'source-git-metadata')


def test_generator_refuses_a_missing_pinned_source_root(tmp_path):
    project = tmp_path / 'project'
    project.mkdir()
    write_profile(project, root='third_party/missing', revision='a' * 40)

    with pytest.raises(ValueError, match='source-metadata-source-root-unavailable'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=project / 'source-git-metadata')


def test_generator_refuses_conflicting_revisions_for_one_repository_root(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    second = project / 'configs/peripherals/demo/component_profile.json'
    second.parent.mkdir(parents=True)
    second.write_text(json.dumps({
        'schema_version': 'component_profile.v1',
        'source': {'root': 'third_party/demo', 'revision': 'git:' + 'f' * 40},
    }))

    with pytest.raises(ValueError, match='source-metadata-conflicting-revision'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=project / 'source-git-metadata')


def test_generator_refuses_a_malformed_git_revision_pin(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    profile = project / 'configs/cpus/demo/component_profile.json'
    document = json.loads(profile.read_text())
    document['source']['revision'] = 'git:not-a-commit'
    profile.write_text(json.dumps(document))

    with pytest.raises(ValueError, match='source-metadata-git-revision-invalid'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=project / 'source-git-metadata')


def test_generator_refuses_a_profile_source_root_escaping_through_parent_symlink(tmp_path):
    project = tmp_path / 'project'
    outside = tmp_path / 'outside'
    source = outside / 'demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    (project / 'third_party').parent.mkdir(parents=True)
    (project / 'third_party').symlink_to(outside, target_is_directory=True)
    write_profile(project, root='third_party/demo', revision=revision)

    with pytest.raises(ValueError, match='source-metadata-source-path-symlinked'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=project / 'source-git-metadata')


def test_generator_refuses_a_source_root_hidden_behind_an_internal_symlink(tmp_path):
    project = tmp_path / 'project'
    source = project / 'real-source/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    (project / 'third_party').symlink_to(project / 'real-source', target_is_directory=True)
    write_profile(project, root='third_party/demo', revision=revision)

    with pytest.raises(ValueError, match='source-metadata-source-path-symlinked'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=project / 'source-git-metadata')
    with pytest.raises(ValueError, match='source-metadata-source-path-symlinked'):
        source_metadata_module()._repository_root(project.resolve(), 'third_party/demo')


def test_generator_refuses_output_path_with_symlinked_parent(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    outside = tmp_path / 'outside'
    outside.mkdir()
    (project / 'metadata-link').symlink_to(outside, target_is_directory=True)
    write_profile(project, root='third_party/demo', revision=revision)

    with pytest.raises(ValueError, match='source-metadata-output-path-symlinked'):
        generator_module().prepare_source_metadata(
            project_root=project, output_root=Path('metadata-link/generated'))


def test_generator_resolves_relative_output_root_from_project_root(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)

    result = generator_module().prepare_source_metadata(
        project_root=project, output_root=Path('source-git-metadata'))

    assert (project / 'source-git-metadata/index.json').is_file()
    assert result['repositories'][0]['archive'].startswith('source-git-metadata/')


def test_frozen_source_metadata_restores_exact_git_identity_without_changing_source_bytes(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    row = index['repositories'][0]
    source_bytes = (source / 'rtl/demo.sv').read_bytes()
    frozen_map = {index_path.relative_to(project).as_posix():
        hashlib.sha256(index_path.read_bytes()).hexdigest()}
    archive = project / row['archive']
    frozen_map[row['archive']] = hashlib.sha256(archive.read_bytes()).hexdigest()
    shutil.rmtree(source / '.git')

    runtime = source_metadata_module()
    validated = runtime.validate_source_metadata(project_root=project, frozen_map=frozen_map)
    result = runtime.materialize_source_metadata(project_root=project, frozen_map=frozen_map)

    assert [entry['root'] for entry in validated] == ['third_party/demo']
    assert result == {'status': 'materialized', 'created': ['third_party/demo'],
        'existing': []}
    assert (source / 'rtl/demo.sv').read_bytes() == source_bytes
    assert git(source, 'rev-parse', 'HEAD') == revision
    assert git(source, 'cat-file', 'blob', revision + ':rtl/demo.sv') == source_bytes.decode().strip()
    assert runtime.materialize_source_metadata(
        project_root=project, frozen_map=frozen_map) == {
            'status': 'materialized', 'created': [], 'existing': ['third_party/demo']}


def test_frozen_source_metadata_rejects_archive_drift_before_materialization(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    archive = project / index['repositories'][0]['archive']
    frozen_map = {index_path.relative_to(project).as_posix():
        hashlib.sha256(index_path.read_bytes()).hexdigest(),
        index['repositories'][0]['archive']:
        hashlib.sha256(archive.read_bytes()).hexdigest()}
    archive.write_bytes(archive.read_bytes() + b'altered')
    shutil.rmtree(source / '.git')

    with pytest.raises(ValueError, match='source-metadata-archive-digest-mismatch'):
        source_metadata_module().materialize_source_metadata(
            project_root=project, frozen_map=frozen_map)
    assert not (source / '.git').exists()


def test_materializer_preflights_all_existing_repositories_before_installing_any(tmp_path):
    project = tmp_path / 'project'
    parent = project / 'third_party/demo'
    parent.mkdir(parents=True)
    git(parent, 'init', '--quiet')
    git(parent, 'config', 'user.name', 'F6 source metadata test')
    git(parent, 'config', 'user.email', 'f6-source-metadata@example.invalid')
    child = parent / 'nested'
    child_revision = make_git_repo(child, files={'child.sv': 'module child; endmodule\n'})
    git(parent, 'update-index', '--add', '--cacheinfo', f'160000,{child_revision},nested')
    git(parent, 'commit', '--quiet', '-m', 'pinned parent')
    parent_revision = git(parent, 'rev-parse', 'HEAD')
    write_profile(project, root='third_party/demo', revision=parent_revision,
        repositories=[('nested', child_revision)])
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    frozen_map = {index_path.relative_to(project).as_posix():
        hashlib.sha256(index_path.read_bytes()).hexdigest()}
    for row in index['repositories']:
        archive = project / row['archive']
        frozen_map[row['archive']] = hashlib.sha256(archive.read_bytes()).hexdigest()

    shutil.rmtree(parent / '.git')
    (child / 'changed.sv').write_text('module changed; endmodule\n')
    git(child, 'add', 'changed.sv')
    git(child, 'commit', '--quiet', '-m', 'wrong child revision')

    with pytest.raises(ValueError, match='source-metadata-existing-git-revision-mismatch'):
        source_metadata_module().materialize_source_metadata(
            project_root=project, frozen_map=frozen_map)
    assert not (parent / '.git').exists()


def test_materializer_accepts_detached_head_at_the_exact_profile_revision(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    archive = project / index['repositories'][0]['archive']
    rewrite_archive(archive, transform=lambda member, payload: (
        (member, (revision + '\n').encode()) if member.name == '.git/HEAD'
        else (member, payload)))
    _, frozen_map = freeze_metadata_map(project, index_path)
    shutil.rmtree(source / '.git')

    result = source_metadata_module().materialize_source_metadata(
        project_root=project, frozen_map=frozen_map)

    assert result['created'] == ['third_party/demo']
    assert git(source, 'rev-parse', 'HEAD') == revision


def test_materializer_refuses_metadata_archive_without_pinned_commit_object(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    archive = project / index['repositories'][0]['archive']
    rewrite_archive(archive, transform=lambda member, payload: (
        None if member.name.startswith('.git/objects/') else (member, payload)))
    _, frozen_map = freeze_metadata_map(project, index_path)
    shutil.rmtree(source / '.git')

    with pytest.raises(ValueError, match='source-metadata-materialized-revision-mismatch'):
        source_metadata_module().materialize_source_metadata(
            project_root=project, frozen_map=frozen_map)
    assert not (source / '.git').exists()


def test_checkout_verifier_refuses_missing_reachable_source_blob(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    blob = git(source, 'rev-parse', revision + ':rtl/demo.sv')
    blob_path = source / '.git/objects' / blob[:2] / blob[2:]
    assert blob_path.is_file()
    blob_path.unlink()

    with pytest.raises(ValueError, match='source-metadata-existing-git-revision-mismatch'):
        source_metadata_module()._verify_git_checkout(source, revision,
            root_name='third_party/demo',
            error_code='source-metadata-existing-git-revision-mismatch')


def test_materializer_rolls_back_archive_missing_a_reachable_source_blob(tmp_path):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    blob = git(source, 'rev-parse', revision + ':rtl/demo.sv')
    write_profile(project, root='third_party/demo', revision=revision)
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    archive = project / index['repositories'][0]['archive']
    metadata_root = tmp_path / 'unpacked'
    git_directory = metadata_root / '.git'
    metadata_root.mkdir()
    runtime = source_metadata_module()
    runtime._extract_git_directory(archive.read_bytes(), git_directory,
        root='third_party/demo')
    packs = list((git_directory / 'objects/pack').glob('*.pack'))
    assert packs
    for pack in packs:
        pack_data = pack.read_bytes()
        for companion in pack.parent.glob(pack.stem + '.*'):
            companion.unlink()
        result = subprocess.run(['git', '--git-dir=' + str(git_directory),
            'unpack-objects', '--strict'], input=pack_data,
            capture_output=True, check=False)
        assert result.returncode == 0, result.stderr.decode(errors='replace')
    (git_directory / 'objects' / blob[:2] / blob[2:]).unlink()
    rewrite_archive_from_git_directory(archive, git_directory)
    _, frozen_map = freeze_metadata_map(project, index_path)
    shutil.rmtree(source / '.git')

    with pytest.raises(ValueError, match='source-metadata-materialized-revision-mismatch'):
        runtime.materialize_source_metadata(project_root=project, frozen_map=frozen_map)
    assert not (source / '.git').exists()


@pytest.mark.parametrize('unsafe_member', [
    'path-traversal', 'symlink', 'fifo', 'promisor-marker', 'partial-clone-config'])
def test_metadata_validator_rejects_unsafe_archive_members(tmp_path, unsafe_member):
    project = tmp_path / 'project'
    source = project / 'third_party/demo'
    revision = make_git_repo(source, files={'rtl/demo.sv': 'module demo; endmodule\n'})
    write_profile(project, root='third_party/demo', revision=revision)
    generator_module().prepare_source_metadata(
        project_root=project, output_root=project / 'source-git-metadata')
    index_path = project / 'source-git-metadata/index.json'
    index = json.loads(index_path.read_text())
    archive = project / index['repositories'][0]['archive']

    def corrupt(member, payload):
        if member.name != '.git/config':
            if unsafe_member == 'promisor-marker' and member.name == '.git/HEAD':
                member.name = '.git/objects/pack/malicious.promisor'
                return member, payload
            return member, payload
        if unsafe_member == 'path-traversal':
            member.name = '../escape'
            return member, payload
        if unsafe_member == 'partial-clone-config':
            return member, payload + b'\n[extensions]\npartialClone = origin\n'
        member.type = tarfile.SYMTYPE if unsafe_member == 'symlink' else tarfile.FIFOTYPE
        member.linkname = '/tmp/escape'
        member.size = 0
        return member, None

    rewrite_archive(archive, transform=corrupt)
    _, frozen_map = freeze_metadata_map(project, index_path)

    expected = (
        'source-metadata-archive-member-path-invalid' if unsafe_member == 'path-traversal'
        else 'source-metadata-archive-member-type-invalid' if unsafe_member in ('symlink', 'fifo')
        else 'source-metadata-archive-partial-clone-forbidden')
    with pytest.raises(ValueError, match=expected):
        source_metadata_module().validate_source_metadata(
            project_root=project, frozen_map=frozen_map)
