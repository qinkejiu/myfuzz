"""Safely unpack the pinned offline capture; never run the metadata auditor."""
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

HERE = Path(__file__).resolve().parent
ARCHIVE = HERE / 'actual-remote.tar.gz'
TARGET = Path('/home/qinkejiu/myfuzz/.superpowers/sdd/p8-source-metadata-20261018/offline-zipcpu-attempt2-audit2')
PIN = '9a91c2cf3366345527708a7038ba406ea696e427e3f74ea662423382ce2578b5'
SIZE = 218999928


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


started = datetime.datetime.now(datetime.timezone.utc).isoformat()
assert ARCHIVE.stat().st_size == SIZE and sha(ARCHIVE) == PIN
assert not any(p.is_symlink() for p in (TARGET, *TARGET.parents))
pins = json.loads((HERE / 'actual-members.json').read_bytes())
expected = {row['path']: row for row in pins}
assert len(expected) == len(pins)
# Inspect every path/type before creating the new destination.
with tarfile.open(ARCHIVE) as archive:
    seen = set()
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        assert path.parts and not path.is_absolute() and '..' not in path.parts and str(path) == member.name
        assert member.name not in seen and (member.isfile() or member.isdir())
        assert member.mode & ~0o777 == 0
        seen.add(member.name); row = expected[member.name]
        assert member.mode == row['mode']
        if member.isdir(): assert row.get('kind') == 'directory'
        else: assert row.get('kind') != 'directory' and member.size == row['bytes']
    assert seen == set(expected)
TARGET.mkdir(exist_ok=False)
files, byte_count = 0, 0
with tarfile.open(ARCHIVE, 'r|gz') as archive:
    for member in archive:
        target = TARGET / member.name
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(); size = 0
        with archive.extractfile(member) as source, target.open('xb') as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk); digest.update(chunk); size += len(chunk)
        row = expected[member.name]
        assert size == row['bytes'] and digest.hexdigest() == row['sha256']
        target.chmod(member.mode); files += 1; byte_count += size
binding = json.loads((HERE / 'clean-map-binding.json').read_bytes())
supplement = json.loads((HERE / 'clean-map-supplement.json').read_bytes())
assert binding['original_archive_sha256'] == PIN and binding['supplement_sha256'] == sha(HERE / 'clean-map-supplement.json')
assert binding['is_original_terminal_time_capture'] is False
checked = []
for name in binding['original_archive_metadata_file_pins_rechecked']:
    path = TARGET / 'metadata/clean' / name
    pin = supplement['files'][name]
    assert path.stat().st_size == pin['bytes'] and sha(path) == pin['sha256']
    checked.append(dict(path=name, bytes=pin['bytes'], sha256=pin['sha256']))
assert len(checked) == 6
insertions = []
for source_name, destination in (('clean-map-supplement.json', 'observed/clean-map.json'),
                                 ('clean-map-binding.json', 'observed/clean-map-binding.json')):
    source, target = HERE / source_name, TARGET / destination
    data = source.read_bytes()
    with target.open('xb') as output: output.write(data)
    assert sha(source) == sha(target)
    insertions.append(dict(source=str(source), destination=destination, sha256=sha(target),
                           separate_later_observation=True))
reverse_archive = HERE / 'reverse-index-supplement.tar.gz'
assert sha(reverse_archive) == '21b14866b43dbc4b27786fd78703bb338ada84a8790a45a9a1e7762ac5d6789c'
stage_map = json.loads((TARGET / 'control/stage-files.json').read_bytes())
reverse_files = []
with tarfile.open(reverse_archive) as archive:
    observed = json.loads(archive.extractfile('readonly-reverse-index-observation.json').read())
    for row in observed['files']:
        relative = row['relative_path']
        clean_pin = supplement['files'][relative]
        stage_pin = stage_map['.git/' + relative]
        for pin in (clean_pin, stage_pin):
            assert pin['kind'] == 'regular'
            assert {k: row[k] for k in ('bytes', 'mode', 'sha256')} == {k: pin[k] for k in ('bytes', 'mode', 'sha256')}
        name = 'metadata/' + row['store'] + '/' + relative
        member = archive.getmember(name)
        assert member.isfile() and member.mode == row['mode'] and member.size == row['bytes']
        raw = archive.extractfile(member).read()
        assert len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256']
        destination = TARGET / name
        with destination.open('xb') as output: output.write(raw)
        destination.chmod(row['mode'])
        assert destination.stat().st_size == row['bytes'] and sha(destination) == row['sha256']
        reverse_files.append(dict(destination=name, **row))
assert len(reverse_files) == 2
assert ARCHIVE.stat().st_size == SIZE and sha(ARCHIVE) == PIN
receipt = dict(schema_version='p8_safe_saved_extract.v1', started_at=started,
    ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat(), original_archive=str(ARCHIVE),
    archive_bytes=SIZE, archive_sha256=PIN, original_archive_unchanged=True,
    member_index_sha256=sha(HERE / 'actual-members.json'), target=str(TARGET),
    original_regular_files=files, original_member_count=len(expected), extracted_file_bytes=byte_count,
    link_members_refused=True, explicit_copy_without_extractall=True,
    clean_original_archive_files_independently_rechecked=checked,
    separate_supplement_collected_at=supplement['collected_at'], supplement_insertions=insertions, reverse_index_insertions=reverse_files,
    reverse_index_supplement_sha256=sha(reverse_archive), reverse_index_collected_at=observed['collected_at'],
    reverse_index_original_archive_members=False,
    reverse_index_clean_map_sha256=sha(HERE / 'clean-map-supplement.json'),
    reverse_index_original_stage_map_sha256=sha(TARGET / 'control/stage-files.json'),
    auditor_executed=False, git_or_models_executed=False)
with (HERE / 'extract2-receipt.json').open('x') as output:
    json.dump(receipt, output, sort_keys=True, indent=2); output.write('\n')
print(json.dumps(receipt, sort_keys=True))
