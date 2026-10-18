"""Independent offline Git snapshot audit. No Git/project import/network calls.

Read an unpacked capture containing control/, inputs/, metadata/{clean,stage-git}
and observed/ full typed source/stage maps. The separately captured
clean-map-supplement.json is placed at observed/clean-map.json. Only saved
bytes are interpreted. Place clean-map-binding.json beside it to retain the
separate observation time and original archive binding.
Prepare/review first; execute only after separate authorization.
"""
import argparse
from collections import deque
import configparser
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import struct

REV = '42606d2d6ef55df313772232977621b2d72f0159'
CONTROLLER = '23e3aa49cd2f498250c939cf10b751e8a669c20b3c190870784b16ec80cf6e14'
GIT = '2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668'
REMOTE = '/root/fanzehui/myfuzz/operations/p8-source-zipcpu-metadata-20261018-attempt2'
INPUTS = '/root/fanzehui/myfuzz/operations/p8-source-metadata-inputs-20261018-attempt2'
SOURCE = '/root/fanzehui/myfuzz/project/third_party/soc-zipcpu'
ARCHIVE = '9a91c2cf3366345527708a7038ba406ea696e427e3f74ea662423382ce2578b5'
POLICY = ['/usr/bin/git', '-c', 'protocol.allow=never', '-c', 'core.hooksPath=/dev/null',
          '-c', 'core.fsmonitor=false']
OID = re.compile('[0-9a-f]{40}')


def require(value, message):
    if not value: raise ValueError(message)


def load(path):
    return json.loads(path.read_bytes())


def sha(data):
    return hashlib.sha256(data).hexdigest()


def object_id(kind, data):
    return hashlib.sha1(kind.encode() + b' ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def tree_entries(data):
    """Decode raw Git binary tree bytes; ls-tree is only cross-check output."""
    offset, rows, names = 0, [], set()
    while offset < len(data):
        space = data.index(b' ', offset); nul = data.index(b'\0', space + 1)
        mode = data[offset:space].decode('ascii'); raw_name = data[space+1:nul]
        require(nul + 21 <= len(data), 'truncated-binary-tree')
        name = raw_name.decode('utf-8'); oid = data[nul+1:nul+21].hex()
        require(name and name not in ('.', '..', '.git') and '/' not in name and '\\' not in name
                and name not in names, 'unsafe-or-duplicate-binary-tree-name')
        require(mode in ('40000', '100644', '100755', '120000'), 'unsupported-tree-mode-gitlink')
        names.add(name); rows.append((mode, name, oid)); offset = nul + 21
    require(offset == len(data), 'binary-tree-tail')
    return rows


class Transcript:
    def __init__(self, root, parent):
        self.root, self.position = root, 0
        self.rows, self.child_pids = [], set()
        control = root / 'control'
        names = sorted(control.glob('child-*.terminal.json'))
        require(len(names) == parent['children'], 'terminal-child-count')
        starts = sorted(control.glob('child-*.start.json'))
        require(len(starts) == len(names), 'start-child-count')
        for index, path in enumerate(names, 1):
            stem = f'child-{index:05d}'
            require(path.name == stem + '.terminal.json', 'noncontiguous-child-records')
            row, start = load(path), load(control / (stem + '.start.json'))
            require(row['returncode'] == 0 and row['error'] is None and row['cwd'] == REMOTE
                    and type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in self.child_pids,
                    'actual-child-result-or-pid')
            require(all(start[k] == row[k] for k in start if k != 'returncode')
                    and start['returncode'] is None, 'start-terminal-binding')
            require(row['argv'][:len(POLICY)] == POLICY, 'closed-git-argv-policy')
            data = {}
            for stream in ('stdin', 'stdout', 'stderr'):
                data[stream] = (control / (stem + '.' + stream)).read_bytes()
                require(sha(data[stream]) == row[stream + '_sha256'], 'child-stream-hash')
            self.child_pids.add(row['pid']); self.rows.append((row, data))

    def take(self, args, stdin=b''):
        require(self.position < len(self.rows), 'missing-child')
        row, data = self.rows[self.position]; self.position += 1
        require(row['argv'] == POLICY + args and data['stdin'] == stdin, 'exact-offline-command-or-stdin')
        return data['stdout']

    def gitdir(self, store, args, stdin=b''):
        return self.take(['--git-dir=' + REMOTE + '/' + store, *args], stdin)

    def batch(self, store, oid, expected=None):
        require(OID.fullmatch(oid), 'invalid-requested-oid')
        raw = self.gitdir(store, ['cat-file', '--batch'], (oid + '\n').encode())
        header, payload = raw.split(b'\n', 1); parts = header.split(b' ')
        require(len(parts) == 3 and parts[0].decode() == oid, 'batch-oid-header')
        kind, size = parts[1].decode('ascii'), int(parts[2])
        require(kind in ('blob', 'tree', 'commit') and size >= 0
                and len(payload) == size + 1 and payload[-1:] == b'\n', 'batch-framing')
        content = payload[:-1]
        require(object_id(kind, content) == oid and (expected is None or kind == expected), 'independent-object-sha1-type')
        return kind, content


def metadata_check(root, label, objects, stage_files, expected_pack, expected_index=None):
    folder = root / 'metadata' / label
    require((folder / 'shallow').read_bytes() == (REV + '\n').encode(), 'single-shallow-boundary')
    require((folder / 'HEAD').read_bytes() == b'ref: refs/heads/pinned\n'
            and (folder / 'refs/heads/pinned').read_bytes() == (REV + '\n').encode(), 'official-pinned-ref-head')
    require({p.relative_to(folder / 'refs').as_posix() for p in (folder / 'refs').rglob('*') if p.is_file()}
            == {'heads/pinned'}, 'only-pinned-ref')
    cfg = configparser.RawConfigParser(); cfg.read_string((folder / 'config').read_text())
    require(cfg.getboolean('core', 'bare') is (label == 'clean'), 'bare-policy')
    for section in cfg.sections():
        require(section.lower() != 'include' and not section.lower().startswith(('includeif ', 'remote ')), 'external-config')
        for key in cfg[section]:
            require(key.lower() not in ('promisor', 'partialclone', 'worktree', 'hookspath'), 'hidden-config-dependency')
    metadata_map = ({p.removeprefix('.git/'): row for p, row in stage_files.items() if p.startswith('.git/')}
                    if label == 'stage-git' else load(root / 'observed/clean-map.json')['files'])
    if label == 'clean':
        binding = load(root / 'observed/clean-map-binding.json')
        supplement = root / 'observed/clean-map.json'
        require(binding['original_archive_sha256'] == ARCHIVE
                and binding['supplement_sha256'] == sha(supplement.read_bytes())
                and binding['supplement_remote_store'] == REMOTE + '/clean.git'
                and binding['is_original_terminal_time_capture'] is False
                and binding['supplement_collected_at'] == load(supplement)['collected_at'],
                'separate-later-clean-map-archive-binding')
    require(all(row['kind'] == 'regular' for row in metadata_map.values()), 'metadata-no-links')
    forbidden = [p for p in metadata_map if p.endswith('.promisor')
                 or p in ('objects/info/alternates', 'commondir')]
    require(not forbidden, 'promisor-alternates-shared-store')
    indexes = sorted((folder / 'objects/pack').glob('*.idx'))
    require(len(indexes) == 1 and len(list((folder / 'objects/pack').glob('*.pack'))) == 1,
            'single-materialized-pack-index')
    indexed = set()
    for index in indexes:
        raw = index.read_bytes()
        if expected_index is not None:
            require(raw == expected_index, 'clean-stage-index-identical')
        require(raw[:8] == b'\xfftOc\x00\x00\x00\x02' and hashlib.sha1(raw[:-20]).digest() == raw[-20:], 'idx-v2-checksum')
        fanout = struct.unpack('>256I', raw[8:1032]); count = fanout[-1]
        require(all(a <= b for a, b in zip(fanout, fanout[1:])), 'idx-fanout-order')
        names = [raw[1032 + i*20:1052 + i*20].hex() for i in range(count)]
        require(names == sorted(set(names)), 'idx-object-names')
        require(not indexed.intersection(names), 'duplicate-index-object')
        indexed.update(names)
        pack = index.with_suffix('.pack').read_bytes()
        require(pack == expected_pack, 'actual-pack-objects-output-to-materialized-pack')
        require(pack[:4] == b'PACK' and struct.unpack('>II', pack[4:12]) == (2, count)
                and hashlib.sha1(pack[:-20]).digest() == pack[-20:] == raw[-40:-20], 'pack-count-checksum-index-binding')
        require(index.stem == 'pack-' + pack[-20:].hex(), 'pack-filename-binding')
    require(indexed == set(objects), 'independent-index-snapshot-only-objectset')
    for path in folder.rglob('*'):
        if path.is_file():
            row = metadata_map[path.relative_to(folder).as_posix()]
            require(row['kind'] == 'regular' and row['bytes'] == path.stat().st_size
                    and row['sha256'] == sha(path.read_bytes()), 'metadata-actual-map-binding')
    require({p for p in metadata_map if p.startswith('objects/')}
            == {p.relative_to(folder).as_posix() for p in (folder / 'objects').rglob('*') if p.is_file()},
            'captured-whole-object-store-files')
    # This does not implement pack decompression. Object-byte verification uses
    # the recorded actual Git reads, independently rehashed as Git objects;
    # pack integrity uses checksum/index parsing and exact transcript binding.
    return indexes[0].read_bytes()


def audit(root):
    control = root / 'control'; parent = load(control / 'parent-terminal.json'); start = load(control / 'parent-start.json')
    require(parent['schema_version'] == 'p8_offline_snapshot_materialization.v1'
            and parent['returncode'] == 0 and parent['status'] == 'prepared_pending_independent_audit_no_runtime_grant'
            and parent['component'] == 'zipcpu' and parent['revision'] == REV and parent['source'] == SOURCE
            and parent['network_allowed'] is parent['runtime_grant'] is False
            and parent['controller_sha256'] == CONTROLLER and parent['git_sha256'] == GIT,
            'parent-policy-pin-terminal')
    require(start['pid'] == parent['pid'] and all(start[k] == parent[k] for k in start if k != 'status'), 'parent-start-binding')
    controller = (root / 'inputs/materialize_snapshot.py').read_bytes()
    require(sha(controller) == CONTROLLER, 'reviewed-controller-bytes')
    # Actual child environment was not independently journaled. This frozen
    # reviewed source enforces the scrubbed GIT_* environment; do not relabel
    # that source pin as a captured OS environment measurement.
    selected = load(root / 'inputs/selected-launch.json')
    require(selected['pid'] == parent['pid'] and selected['controller_sha256'] == CONTROLLER
            and selected['argv'] == ['/usr/bin/python3', INPUTS + '/materialize_snapshot.py',
                                     '--component', 'zipcpu', '--output', REMOTE,
                                     '--git', '/usr/bin/git', '--git-sha256', GIT], 'selected-exact-launch')
    before, after = load(control / 'source-before-files.json'), load(control / 'source-after-files.json')
    dirs = load(control / 'source-before-directories.json')
    require(before == after == load(root / 'observed/source-files.json')
            and dirs == load(control / 'source-after-directories.json') == load(root / 'observed/source-directories.json'), 'fulltyped-source-beforeafter-observed')
    stage = load(control / 'stage-files.json'); stage_dirs = load(control / 'stage-directories.json')
    require(stage == load(root / 'observed/stage-files.json')
            and stage_dirs == load(root / 'observed/stage-directories.json'), 'actual-stage-full-map')
    transcript = Transcript(root, parent)
    objects, paths, contents = {}, {}, {}
    kind, commit = transcript.batch('quarantine.git', REV, 'commit')
    objects[REV] = dict(type=kind, bytes=len(commit)); contents[REV] = commit
    header = commit.split(b'\n\n', 1)[0].splitlines(); roots = [line[5:].decode() for line in header if line.startswith(b'tree ')]
    require(len(roots) == 1, 'commit-root-tree')
    queue = deque([(roots[0], '')]); seen_paths = set()
    while queue:
        oid, prefix = queue.popleft(); kind, raw = transcript.batch('quarantine.git', oid, 'tree')
        objects[oid] = dict(type=kind, bytes=len(raw)); contents[oid] = raw
        entries = tree_entries(raw)
        listing = b''.join((f'{int(mode,8):06o} ' + ('tree' if mode == '40000' else 'blob') + ' ' + child + '\t').encode()
                           + name.encode() + b'\0' for mode, name, child in entries)
        require(transcript.gitdir('quarantine.git', ['ls-tree', '-z', oid]) == listing, 'binarytree-lstree-crosscheck')
        for mode, name, child in entries:
            path = prefix + name; require(path not in seen_paths, 'duplicate-expanded-tree-path'); seen_paths.add(path)
            if mode == '40000': queue.append((child, path + '/'))
            else:
                kind, blob = transcript.batch('quarantine.git', child, 'blob')
                objects[child] = dict(type=kind, bytes=len(blob)); contents[child] = blob
                paths[path] = dict(oid=child, mode=mode, bytes=len(blob), sha256=sha(blob))
    require(load(control / 'snapshot-objects.json') == objects
            and load(control / 'snapshot-paths.json') == paths and load(control / 'gitlinks.json') == [], 'independent-full-object-path-closure')
    working = {p: row for p, row in before.items() if not p.startswith('.git/')}
    require(set(working) == set(paths), 'complete-working-snapshot')
    symlinks = []
    for path, pin in paths.items():
        original, final = working[path], stage[path]
        expected_kind = 'symlink' if pin['mode'] == '120000' else 'regular'
        require(original['kind'] == final['kind'] == expected_kind
                and original['bytes'] == final['bytes'] == pin['bytes']
                and original['sha256'] == final['sha256'] == pin['sha256'], 'actual-path-blob-bytes')
        if expected_kind == 'symlink':
            raw = bytes.fromhex(original['linkbytes_hex'])
            require(raw == contents[pin['oid']] == bytes.fromhex(final['linkbytes_hex'])
                    and original['mode'] == final['mode'], 'exact-preserved-symlink-text-mode')
            text = raw.decode('utf-8'); target = posixpath.normpath(posixpath.join(posixpath.dirname(path), text))
            require(text and not text.startswith('/') and target != '..' and not target.startswith('../') and '\0' not in text, 'symlink-within-component')
            transcript.batch('quarantine.git', pin['oid'], 'blob'); symlinks.append(dict(path=path, text=text))
        else: require(final['mode'] == int(pin['mode'][-3:], 8), 'stage-git-file-mode')
    require({p for p in stage if not p.startswith('.git/')} == set(paths), 'no-stage-extra-files')
    oid_input = ''.join(oid + '\n' for oid in sorted(objects)).encode()
    pack = transcript.gitdir('quarantine.git', ['pack-objects', '--stdout', '--no-reuse-delta', '--no-reuse-object'], oid_input)
    transcript.take(['init', '--bare', '--template=', REMOTE + '/clean.git'])
    transcript.gitdir('clean.git', ['index-pack', '--stdin'], pack)
    transcript.gitdir('clean.git', ['update-ref', 'refs/heads/pinned', REV])
    transcript.gitdir('clean.git', ['symbolic-ref', 'HEAD', 'refs/heads/pinned'])
    require(transcript.gitdir('clean.git', ['rev-parse', 'HEAD']).strip().decode() == REV, 'actual-clean-head')
    transcript.gitdir('clean.git', ['fsck', '--full', '--strict', '--no-reflogs'])
    for oid, pin in objects.items():
        kind, raw = transcript.batch('clean.git', oid, pin['type'])
        require(raw == contents[oid], 'quarantine-clean-object-identical')
    listing = transcript.gitdir('clean.git', ['cat-file', '--batch-all-objects', '--batch-check=%(objectname) %(objecttype) %(objectsize)'])
    listed = {}
    for line in listing.decode().splitlines():
        oid, kind, size = line.split(); require(oid not in listed, 'duplicate-allobject-row')
        listed[oid] = dict(type=kind, bytes=int(size))
    require(listed == objects, 'clean-all-objectset-exact')
    transcript.gitdir('stage/.git', ['config', 'core.bare', 'false'])
    transcript.gitdir('stage/.git', ['--work-tree=' + REMOTE + '/stage', 'read-tree', REV])
    require(transcript.take(['-C', REMOTE + '/stage', 'status', '--porcelain=v1', '--untracked-files=all']) == b'', 'actual-git-status-clean')
    names = sorted(paths)
    for offset in range(0, len(names), 128):
        transcript.take(['-C', REMOTE + '/stage', 'ls-files', '--error-unmatch', '--', *names[offset:offset+128]])
    for path, pin in paths.items():
        blob = transcript.take(['-C', REMOTE + '/stage', 'cat-file', 'blob', REV + ':' + path])
        require(blob == contents[pin['oid']], 'stage-catfile-content-identity')
    transcript.gitdir('stage/.git', ['fsck', '--full', '--strict', '--no-reflogs'])
    require(transcript.position == len(transcript.rows), 'unreviewed-extra-git-commands')
    clean_index = metadata_check(root, 'clean', objects, stage, pack)
    metadata_check(root, 'stage-git', objects, stage, pack, clean_index)
    observed = load(root / 'readonly-live-review.json')
    require(observed['parent_pid'] == parent['pid'] and observed['parent_proc_present'] is False
            and observed['actual_children'] == len(transcript.rows) and observed['child_returncodes'] == [0], 'live-terminal-observation')
    return dict(schema_version='zipcpu_independent_offline_snapshot_audit.v1', status='saved_metadata_audit_passed',
                revision=REV, parent_pid=parent['pid'], child_count=len(transcript.rows),
                object_count=len(objects), tracked_paths=len(paths), symlinks=symlinks,
                complete_source_beforeafter_equal=True, actual_stage_matches_snapshot=True,
                pack_verification='checksum_index_names_exact_transcript_bytes_and_rehashed_actual_Git_object_reads_no_independent_pack_decompression',
                environment_evidence='reviewed_pinned_controller_enforcement_not_separate_OS_capture',
                runtime_grant=False, models_executed_by_audit=False, repository_network=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.evidence_dir), sort_keys=True, indent=2))
