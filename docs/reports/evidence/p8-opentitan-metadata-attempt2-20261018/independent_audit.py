"""Independent batch/reconstruction saved-byte audit. No Git or process calls.

Input layout: control/, inputs/{materialize_snapshot_reconstructed.py,
selected-launch.json}, metadata/{clean,stage-git}/, observed/{source-files.json,
source-directories.json,stage-files.json,stage-directories.json,clean-files.json,
clean-directories.json,collection.json,recovered-stage-captures.json} and
recovered-stage-bytes/<path> (ordinary files containing actual file/link bytes).
Do not execute before source review and authorization for the actual capture.
"""
import argparse
from collections import Counter, deque
import configparser
import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import struct

CONTROLLER = 'fc5faa4abc0bccd561a6ebfea2e779b32b8cdde09ef534bed75c0013ce4ff276'
GIT_SHA = '2a8c18fbf43da9f692d75474c72bea9dfd796c260b0f3dfe456376abc3bbd668'
COMPONENTS = {
    'opentitan': ('third_party/soc-opentitan', 'fca045df919a26c47e71616b9dac917b1ea4fd07'),
    'ibex': ('third_party/rfuzz/upstream/ibex', '34b0705760ef3dfa00e99637432473d2be8f22f3'),
}
POLICY = ['/usr/bin/git', '-c', 'protocol.allow=never', '-c', 'core.hooksPath=/dev/null',
          '-c', 'core.fsmonitor=false']
OID = re.compile('[0-9a-f]{40}')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def load(path):
    return json.loads(path.read_bytes())


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def relative(name):
    p = PurePosixPath(name)
    need(type(name) is str and p.parts and not p.is_absolute() and '..' not in p.parts
         and str(p) == name and '\\' not in name, 'unsafe-saved-relative-path')
    return p


def equal_files(left, right):
    if left.stat().st_size != right.stat().st_size:
        return False
    with left.open('rb') as a, right.open('rb') as b:
        while True:
            block = a.read(1024 * 1024)
            if block != b.read(1024 * 1024):
                return False
            if not block:
                return True


def tree_entries(raw):
    rows, names, offset = [], set(), 0
    while offset < len(raw):
        space = raw.find(b' ', offset); nul = raw.find(b'\0', space + 1)
        need(space > offset and nul > space + 1 and nul + 21 <= len(raw), 'binary-tree-framing')
        mode = raw[offset:space].decode('ascii'); name = raw[space+1:nul].decode('utf-8')
        need(name and name not in ('.', '..', '.git') and '/' not in name and '\\' not in name
             and name not in names, 'unsafe-or-duplicate-tree-name')
        need(mode in ('40000', '100644', '100755', '120000'), 'unsupported-tree-mode-or-gitlink')
        names.add(name); rows.append((mode, name, raw[nul+1:nul+21].hex())); offset = nul + 21
    need(offset == len(raw), 'binary-tree-tail')
    return rows


class Transcript:
    """Validate receipts once; stream raw payloads instead of retaining all blobs."""
    def __init__(self, root, remote, count):
        self.root, self.remote, self.position = root, remote, 0
        self.rows, self.pids, self.object_manifests = [], set(), set()
        self.object_material = {}
        control = root / 'control'
        terminals = sorted(control.glob('child-*.terminal.json'))
        need(len(terminals) == count and len(list(control.glob('child-*.start.json'))) == count,
             'complete-child-start-terminal-count')
        for index, path in enumerate(terminals, 1):
            stem = f'child-{index:05d}'
            need(path.name == stem + '.terminal.json', 'contiguous-child-order')
            row, start = load(path), load(control / (stem + '.start.json'))
            need(row['returncode'] == 0 and row['error'] is None and row['cwd'] == remote
                 and type(row['pid']) is int and row['pid'] > 0 and row['pid'] not in self.pids,
                 'actual-child-rc-cwd-pid')
            need(start['returncode'] is None
                 and all(row[k] == value for k, value in start.items() if k != 'returncode'),
                 'actual-child-start-terminal-binding')
            need(row['argv'][:len(POLICY)] == POLICY, 'closed-offline-git-policy')
            for stream in ('stdin', 'stdout', 'stderr'):
                need(sha(control / (stem + '.' + stream)) == row[stream + '_sha256'], 'child-stream-hash')
            self.rows.append((stem, row)); self.pids.add(row['pid'])

    def take(self, args, *, stdin=b'', stdin_path=None):
        need(self.position < len(self.rows), 'missing-child-command')
        stem, row = self.rows[self.position]; self.position += 1
        need(row['argv'] == POLICY + args, 'exact-phase-argv-' + stem)
        source = self.root / 'control' / (stem + '.stdin')
        if stdin_path is None:
            need(source.read_bytes() == stdin, 'exact-phase-stdin-' + stem)
        else:
            need(stdin == b'' and equal_files(source, stdin_path), 'exact-streamed-pack-stdin-' + stem)
        return self.root / 'control' / (stem + '.stdout')

    def gitdir(self, store, args, **kwargs):
        return self.take(['--git-dir=' + self.remote + '/' + store, *args], **kwargs)

    def batches(self, store, requests, *, retain_oids=(), retain_types=('commit', 'tree')):
        requests = list(requests)
        need(len({oid for oid, _ in requests}) == len(requests), 'duplicate-batch-requests')
        for offset in range(0, len(requests), 128):
            chunk = requests[offset:offset+128]
            need(all(type(oid) is str and OID.fullmatch(oid) for oid, _ in chunk), 'invalid-batch-oid')
            output = self.gitdir(store, ['cat-file', '--batch'],
                                 stdin=''.join(oid + '\n' for oid, _ in chunk).encode())
            record_path = output.with_suffix('.objects.json')
            manifest = load(record_path); self.object_manifests.add(record_path.name)
            need(manifest['schema_version'] == 'p8_cat_file_batch_records.v1'
                 and manifest['status'] == 'verified' and 'error' not in manifest
                 and manifest['stdout_file'] == output.name and manifest['store'] == self.remote + '/' + store
                 and manifest['requested_objects'] == len(chunk)
                 and len(manifest['records']) == len(chunk), 'batch-manifest-envelope')
            with output.open('rb') as stream:
                for index, (oid, expected_type) in enumerate(chunk):
                    header_offset = stream.tell(); header = stream.readline(256)
                    need(header.endswith(b'\n'), 'truncated-batch-header')
                    parts = header[:-1].decode('ascii').split(' ')
                    need(len(parts) == 3 and parts[0] == oid and parts[2].isdigit(), 'batch-header-identity')
                    kind, size = parts[1], int(parts[2])
                    need(kind in ('commit', 'tree', 'blob') and kind == expected_type, 'batch-type')
                    payload_offset = stream.tell()
                    git_hash = hashlib.sha1(kind.encode() + b' ' + str(size).encode() + b'\0')
                    content_hash = hashlib.sha256()
                    keep = kind in retain_types or oid in retain_oids
                    data = bytearray() if keep else None; remaining = size
                    while remaining:
                        block = stream.read(min(remaining, 1024 * 1024))
                        need(block, 'truncated-batch-object'); remaining -= len(block)
                        git_hash.update(block); content_hash.update(block)
                        if keep: data.extend(block)
                    need(stream.read(1) == b'\n' and git_hash.hexdigest() == oid, 'object-sha1-or-terminator')
                    material = (kind, size, content_hash.hexdigest())
                    need(oid not in self.object_material or self.object_material[oid] == material,
                         'same-object-material-across-stores')
                    self.object_material[oid] = material
                    independent = dict(oid=oid, type=kind, bytes=size, header_offset=header_offset,
                                       payload_offset=payload_offset, record_end_offset=stream.tell(),
                                       sha256=content_hash.hexdigest(), payload_retained=keep)
                    need(manifest['records'][index] == independent, 'independent-batch-record-offsets-hashes')
                    capture = dict(stdout_file=output.relative_to(self.root).as_posix(),
                                   payload_offset=payload_offset, bytes=size, oid=oid, type=kind,
                                   sha256=content_hash.hexdigest())
                    yield oid, kind, dict(bytes=size, sha256=content_hash.hexdigest(), capture=capture,
                                          payload=bytes(data) if keep else None)
                need(stream.read(1) == b'', 'trailing-batch-output')

    def closure(self, store, revision):
        objects, paths, gitlinks = {}, {}, []
        commit_records = list(self.batches(store, [(revision, 'commit')], retain_oids={revision}))
        need(len(commit_records) == 1, 'single-commit-record')
        oid, kind, commit = commit_records[0]
        objects[oid] = dict(type=kind, bytes=commit['bytes'])
        roots = [line[5:].decode('ascii') for line in commit['payload'].split(b'\n\n', 1)[0].splitlines()
                 if line.startswith(b'tree ')]
        need(len(roots) == 1 and OID.fullmatch(roots[0]), 'single-root-tree')
        layer, cache, names, blob_paths = [(roots[0], '')], {}, set(), {}
        while layer:
            requests = sorted({oid for oid, _ in layer} - set(cache))
            for oid, kind, pin in self.batches(store, [(oid, 'tree') for oid in requests]):
                cache[oid] = pin['payload']; objects[oid] = dict(type=kind, bytes=pin['bytes'])
            following = []
            for oid, prefix in layer:
                for mode, name, child in tree_entries(cache[oid]):
                    path = prefix + name; need(path not in names, 'duplicate-expanded-tree-path'); names.add(path)
                    if mode == '40000': following.append((child, path + '/'))
                    else: blob_paths[path] = dict(oid=child, mode=mode)
            layer = following
        links = {pin['oid'] for pin in blob_paths.values() if pin['mode'] == '120000'}
        blobs = {}
        for oid, kind, pin in self.batches(store, [(oid, 'blob') for oid in sorted({p['oid'] for p in blob_paths.values()})],
                                            retain_oids=links):
            objects[oid] = dict(type=kind, bytes=pin['bytes'])
            blobs[oid] = {k: pin[k] for k in ('bytes', 'sha256', 'capture')}
            if oid in links: blobs[oid]['linkbytes_hex'] = pin['payload'].hex()
        for path, pin in blob_paths.items():
            paths[path] = {**pin, **blobs[pin['oid']]}
            if pin['mode'] != '120000': paths[path].pop('linkbytes_hex', None)
        return objects, paths, gitlinks


def content_paths(paths):
    return {p: {k: v for k, v in pin.items() if k != 'capture'} for p, pin in paths.items()}


def capture_to_actual(root, pin, actual):
    """The independently parsed capture pointer is joined byte-for-byte."""
    ref = pin['capture']; path = relative(ref['stdout_file'])
    need(path.parent == PurePosixPath('control') and path.name.startswith('child-')
         and path.suffix == '.stdout' and ref['type'] == 'blob'
         and ref['oid'] == pin['oid'] and ref['bytes'] == pin['bytes'] and ref['sha256'] == pin['sha256'],
         'verified-capture-reference')
    git_hash = hashlib.sha1(b'blob ' + str(pin['bytes']).encode() + b'\0'); content = hashlib.sha256()
    with (root / str(path)).open('rb') as source, actual.open('rb') as target:
        source.seek(ref['payload_offset']); remaining = pin['bytes']
        while remaining:
            data = source.read(min(remaining, 1024 * 1024)); need(data, 'capture-truncation')
            need(data == target.read(len(data)), 'actual-reconstructed-stage-byte-difference')
            remaining -= len(data); git_hash.update(data); content.update(data)
        need(source.read(1) == b'\n' and target.read(1) == b'', 'capture-or-actual-tail')
    need(git_hash.hexdigest() == pin['oid'] and content.hexdigest() == pin['sha256'], 'capture-rehash')


def check_index(raw):
    need(len(raw) >= 1072 and raw[:8] == b'\xfftOc\x00\x00\x00\x02'
         and hashlib.sha1(raw[:-20]).digest() == raw[-20:], 'idx-header-checksum')
    fanout = struct.unpack('>256I', raw[8:1032]); count = fanout[-1]
    need(len(raw) >= 1072 + count * 28, 'idx-table-length')
    names = [raw[1032+i*20:1052+i*20] for i in range(count)]
    need(names == sorted(set(names)), 'idx-name-order')
    counts = Counter(name[0] for name in names); total = 0
    for index, recorded in enumerate(fanout):
        total += counts[index]; need(recorded == total, 'idx-fanout-content')
    offsets = struct.unpack('>' + str(count) + 'I', raw[1032+count*24:1032+count*28]) if count else ()
    large = sum(bool(value & 0x80000000) for value in offsets)
    need(len(raw) == 1072 + count * 28 + large * 8, 'idx-large-offset-tail')
    return [name.hex() for name in names]


def metadata(root, label, revision, objects, expected_pack, expected_index=None, expected_reverse=None):
    folder = root / 'metadata' / label
    full = (load(root / 'observed/clean-files.json') if label == 'clean' else
            {p.removeprefix('.git/'): row for p, row in load(root / 'observed/stage-files.json').items() if p.startswith('.git/')})
    directories = (load(root/'observed/clean-directories.json') if label == 'clean' else
                   {p.removeprefix('.git/'): row for p,row in load(root/'observed/stage-directories.json').items()
                    if p.startswith('.git/')})
    need(all(row['kind'] == 'regular' for row in full.values()), 'metadata-link')
    need(not [p for p in full if p.endswith('.promisor') or p in ('objects/info/alternates', 'commondir')], 'external-object-store')
    need((folder / 'shallow').read_bytes() == (revision + '\n').encode()
         and (folder / 'HEAD').read_bytes() == b'ref: refs/heads/pinned\n'
         and (folder / 'refs/heads/pinned').read_bytes() == (revision + '\n').encode(), 'official-shallow-ref-head')
    need({p for p in full if p.startswith('refs/')} == {'refs/heads/pinned'}, 'extra-ref')
    if 'packed-refs' in full:
        for line in (folder/'packed-refs').read_text().splitlines():
            if line and not line.startswith('#'):
                need(line == revision + ' refs/heads/pinned', 'extra-packed-or-peeled-ref')
    cfg = configparser.RawConfigParser(); cfg.read_string((folder / 'config').read_text())
    need(cfg.getboolean('core', 'bare') is (label == 'clean'), 'core-bare')
    for section in cfg.sections():
        need(section.lower() != 'include' and not section.lower().startswith(('includeif ', 'remote ')), 'external-config-section')
        need(not any(key.lower() in ('promisor', 'partialclone', 'worktree', 'hookspath') for key in cfg[section]), 'external-config-key')
    actual = {p.relative_to(folder).as_posix() for p in folder.rglob('*') if p.is_file()}
    need(actual == set(full), 'whole-metadata-file-capture-including-index')
    actual_directories = {p.relative_to(folder).as_posix():dict(mode=stat.S_IMODE(p.stat().st_mode))
                          for p in folder.rglob('*') if p.is_dir()}
    need(actual_directories == directories, 'whole-metadata-directory-modes')
    if label == 'stage-git':
        need(stat.S_IMODE(folder.stat().st_mode) == load(root/'observed/stage-directories.json')['.git']['mode'],
             'stage-git-root-directory-mode')
    for name in actual:
        need(name in full and (folder/name).stat().st_size == full[name]['bytes'] and sha(folder/name) == full[name]['sha256'], 'actual-metadata-map-binding')
        need(stat.S_IMODE((folder/name).stat().st_mode) == full[name]['mode'], 'actual-metadata-file-mode')
    need({p for p in actual if p.startswith('objects/')} == {p for p in full if p.startswith('objects/')}, 'whole-object-store-capture')
    indexes = sorted((folder/'objects/pack').glob('*.idx')); packs = sorted((folder/'objects/pack').glob('*.pack'))
    need(len(indexes) == len(packs) == 1 and indexes[0].stem == packs[0].stem, 'single-pack-index')
    need(equal_files(packs[0], expected_pack), 'actual-pack-stdout-to-clean-stage-pack')
    raw = indexes[0].read_bytes(); names = check_index(raw)
    need(set(names) == set(objects), 'snapshot-only-index-objectset')
    with packs[0].open('rb') as stream:
        need(stream.read(4) == b'PACK' and struct.unpack('>II', stream.read(8)) == (2, len(names)), 'pack-header-count')
        stream.seek(0); remaining = packs[0].stat().st_size - 20; checksum = hashlib.sha1()
        while remaining:
            block = stream.read(min(remaining, 1024*1024)); need(block, 'pack-truncated'); checksum.update(block); remaining -= len(block)
        trailer = stream.read(20)
    need(checksum.digest() == trailer == raw[-40:-20] and indexes[0].stem == 'pack-' + trailer.hex(), 'pack-idx-checksum')
    if expected_index is not None: need(raw == expected_index, 'clean-stage-identical-idx')
    reverse_paths = sorted((folder/'objects/pack').glob('*.rev'))
    need(len(reverse_paths) <= 1, 'multiple-reverse-indexes')
    reverse = reverse_paths[0].read_bytes() if reverse_paths else None
    if reverse is not None:
        need(reverse_paths[0].stem == indexes[0].stem and len(reverse) == 12 + 4*len(names) + 40
             and reverse[:12] == b'RIDX\x00\x00\x00\x01\x00\x00\x00\x01'
             and reverse[-40:-20] == trailer and hashlib.sha1(reverse[:-20]).digest() == reverse[-20:], 'reverse-index-framing-checksum')
        order = struct.unpack('>' + str(len(names)) + 'I', reverse[12:-40]) if names else ()
        need(sorted(order) == list(range(len(names))), 'reverse-index-permutation')
    if label == 'stage-git': need(reverse == expected_reverse, 'clean-stage-identical-reverse-index')
    return raw, reverse


def audit(root, component, remote, inputs):
    need(component in COMPONENTS, 'component')
    relative_source, revision = COMPONENTS[component]
    for path in (remote, inputs):
        p = PurePosixPath(path)
        need(p.parent == PurePosixPath('/root/fanzehui/myfuzz/operations') and '..' not in p.parts, 'remote-operation-boundary')
    need(PurePosixPath(remote).name.startswith('p8-source-' + component + '-metadata-')
         and PurePosixPath(inputs).name.startswith('p8-source-metadata-inputs-'), 'selected-operation-family')
    control = root/'control'; parent = load(control/'parent-terminal.json'); start = load(control/'parent-start.json')
    need(parent['schema_version'] == 'p8_offline_snapshot_materialization_reconstructed.v1'
         and parent['status'] == 'prepared_pending_independent_audit_no_runtime_grant' and parent['returncode'] == 0
         and parent['component'] == component and parent['revision'] == revision
         and parent['source'] == '/root/fanzehui/myfuzz/project/' + relative_source
         and parent['recover_missing_pinned_files'] is True and parent['batch_objects'] == 128
         and parent['network_allowed'] is parent['runtime_grant'] is False
         and parent['controller_sha256'] == CONTROLLER and parent['git_sha256'] == GIT_SHA,
         'parent-policy-terminal-pins')
    mutable = {'status'}
    need(all(parent[k] == value for k, value in start.items() if k not in mutable), 'parent-start-terminal')
    need(sha(root/'inputs/materialize_snapshot_reconstructed.py') == CONTROLLER, 'reviewed-controller-source')
    selected = load(root/'inputs/selected-launch.json')
    need(selected['pid'] == parent['pid'] and selected['controller_sha256'] == CONTROLLER
         and selected['argv'] == ['/usr/bin/python3', inputs + '/materialize_snapshot_reconstructed.py',
              '--component', component, '--recover-missing-pinned-files', '--output', remote,
              '--git', '/usr/bin/git', '--git-sha256', GIT_SHA], 'selected-launch-exact-argv')
    before, after = load(control/'source-before-files.json'), load(control/'source-after-files.json')
    need(before == after == load(root/'observed/source-files.json'), 'source-fulltyped-files-unchanged')
    need(load(control/'source-before-directories.json') == load(control/'source-after-directories.json')
         == load(root/'observed/source-directories.json'), 'source-directory-modes-unchanged')
    stage, stage_dirs = load(control/'stage-files.json'), load(control/'stage-directories.json')
    need(stage == load(root/'observed/stage-files.json') and stage_dirs == load(root/'observed/stage-directories.json'), 'actual-stage-typed-maps')
    transcript = Transcript(root, remote, parent['children'])
    objects, paths, gitlinks = transcript.closure('quarantine.git', revision)
    need(load(control/'snapshot-objects.json') == objects and load(control/'snapshot-paths.json') == paths
         and load(control/'gitlinks.json') == gitlinks == [], 'independent-original-closure')
    working = {p:r for p,r in before.items() if not p.startswith('.git/')}
    need(not set(working)-set(paths), 'original-working-extra-paths')
    missing = sorted(set(paths)-set(working)); plan = load(control/'missing-pinned-files-plan.json')
    final = load(control/'missing-pinned-files-reconstruction.json')
    need(set(plan) == set(final) == set(missing) and parent['missing_pinned_files'] == len(missing)
         and parent['original_working_tree_full'] is (not missing)
         and parent['staged_reconstructed_full_snapshot'] is True, 'exact-original-missing-set')
    captures = load(root/'observed/recovered-stage-captures.json')
    need(set(captures) == set(missing), 'complete-actual-recovered-captures')
    expected_receipts = set()
    for path, pin in paths.items():
        relative(path); actual = stage[path]; link = pin['mode'] == '120000'
        need(actual['kind'] == ('symlink' if link else 'regular') and actual['bytes'] == pin['bytes']
             and actual['sha256'] == pin['sha256'], 'stage-path-identity-bytes-kind')
        if link:
            text = bytes.fromhex(actual['linkbytes_hex']).decode('utf-8')
            target = posixpath.normpath(posixpath.join(posixpath.dirname(path), text))
            need(actual['linkbytes_hex'] == pin['linkbytes_hex'] and text and not text.startswith('/')
                 and target != '..' and not target.startswith('../') and '\0' not in text, 'safe-exact-symlink')
        else: need(actual['mode'] == int(pin['mode'][-3:],8), 'stage-git-mode')
        if path in working:
            original = working[path]
            need(original['kind'] == actual['kind'] and original['bytes'] == pin['bytes'] and original['sha256'] == pin['sha256'], 'present-source-blob')
            if link: need(original['linkbytes_hex'] == actual['linkbytes_hex'] and original['mode'] == actual['mode'], 'preserved-source-link')
            else: need(bool(original['mode'] & 0o111) == (pin['mode']=='100755'), 'source-executable-bit')
        else:
            need(plan[path] == {**pin,'original_lstat':'missing','reconstruction_status':'pending'}
                 and final[path] == {**pin,'original_lstat':'missing','reconstruction_status':'reconstructed_verified'}, 'reconstruction-state-and-capture-pin')
            name = 'recovered-' + hashlib.sha256(path.encode()).hexdigest() + '.json'; expected_receipts.add(name)
            need(load(control/name) == {'path':path,**final[path]}, 'per-path-recovery-receipt')
            need(captures[path] == actual, 'actual-recovery-capture-typed-map')
            capture_to_actual(root, pin, root/'recovered-stage-bytes'/path)
    need(set(p.name for p in control.glob('recovered-*.json')) == expected_receipts, 'no-extra-recovery-receipts')
    need({p for p in stage if not p.startswith('.git/')} == set(paths), 'no-stage-working-extra-files')
    pack = transcript.gitdir('quarantine.git',['pack-objects','--stdout','--no-reuse-delta','--no-reuse-object'],
                             stdin=''.join(oid+'\n' for oid in sorted(objects)).encode())
    transcript.take(['init','--bare','--template=',remote+'/clean.git'])
    transcript.gitdir('clean.git',['index-pack','--stdin'],stdin_path=pack)
    transcript.gitdir('clean.git',['update-ref','refs/heads/pinned',revision])
    transcript.gitdir('clean.git',['symbolic-ref','HEAD','refs/heads/pinned'])
    need(transcript.gitdir('clean.git',['rev-parse','HEAD']).read_bytes().strip().decode()==revision,'actual-clean-head')
    transcript.gitdir('clean.git',['fsck','--full','--strict','--no-reflogs'])
    original_blob = {pin['oid']:pin for pin in paths.values()}
    for oid, kind, pin in transcript.batches('clean.git',[(oid,objects[oid]['type']) for oid in sorted(objects)],retain_types=()):
        need(objects[oid] == dict(type=kind,bytes=pin['bytes']), 'clean-object-size-type')
        if kind=='blob': need(pin['sha256']==original_blob[oid]['sha256'],'clean-original-blob-hash')
    listing = transcript.gitdir('clean.git',['cat-file','--batch-all-objects','--batch-check=%(objectname) %(objecttype) %(objectsize)'])
    listed={}
    for line in listing.read_text().splitlines():
        oid,kind,size=line.split();need(oid not in listed,'duplicate-listed-object');listed[oid]=dict(type=kind,bytes=int(size))
    need(listed==objects,'clean-snapshot-only-objectset')
    transcript.gitdir('stage/.git',['config','core.bare','false'])
    transcript.gitdir('stage/.git',['--work-tree='+remote+'/stage','read-tree',revision])
    need(transcript.take(['-C',remote+'/stage','status','--porcelain=v1','--untracked-files=all']).read_bytes()==b'','actual-clean-status')
    names=sorted(paths)
    for offset in range(0,len(names),128):transcript.take(['-C',remote+'/stage','ls-files','--error-unmatch','--',*names[offset:offset+128]])
    stage_objects,stage_paths,stage_links=transcript.closure('stage/.git',revision)
    need(stage_objects==objects and content_paths(stage_paths)==content_paths(paths) and stage_links==[],'independent-complete-stage-closure')
    checks=load(control/'stage-git-blob-path-checks.json')
    need(set(checks)==set(paths),'stage-path-check-set')
    for path,pin in stage_paths.items():
        need(checks[path]==dict(oid=pin['oid'],mode=pin['mode'],bytes=pin['bytes'],git_blob_sha256=pin['sha256'],
                               filesystem_sha256=stage[path]['sha256'],filesystem_kind=stage[path]['kind']),'stage-path-git-filesystem-join')
    transcript.gitdir('stage/.git',['fsck','--full','--strict','--no-reflogs'])
    need(transcript.position==len(transcript.rows),'unconsumed-child-commands')
    need(transcript.object_manifests=={p.name for p in control.glob('child-*.objects.json')},'extra-or-missing-batch-manifests')
    index,reverse=metadata(root,'clean',revision,objects,pack)
    metadata(root,'stage-git',revision,objects,pack,index,reverse)
    collection=load(root/'observed/collection.json')
    need(collection['parent_pid']==parent['pid'] and collection['parent_proc_present'] is False
         and collection['remote_operation']==remote and collection['remote_inputs']==inputs
         and collection['component']==component and collection['actual_children']==len(transcript.rows)
         and collection['missing_stage_payloads_captured']==len(missing)
         and collection['actual_source_matches_beforeafter'] is True and collection['actual_stage_matches_saved'] is True,
         'independent-live-collection-binding')
    collected_at=datetime.datetime.fromisoformat(collection['collected_at'])
    need(collected_at.tzinfo is not None and collected_at.timestamp() >= parent['ended_unix'],
         'later-readonly-observation-after-actual-terminal')
    return dict(schema_version='p8_independent_reconstructed_metadata_audit.v1',status='saved_metadata_audit_passed',
                component=component,revision=revision,parent_pid=parent['pid'],actual_children=len(transcript.rows),
                objects=len(objects),tracked_paths=len(paths),original_missing_paths=len(missing),
                recovered_bytes_joined_to_actual_stage=True,full_source_unchanged=True,runtime_grant=False,
                collection_evidence='separate_later_readonly_inventory_not_terminal_time_capture',
                environment_evidence='pinned_reviewed_source_enforcement_not_independent_OS_capture',
                pack_evidence='checksum_index_reverse_framing_exact_transcript_pack_and_rehashed_actual_Git_reads_no_pack_decompression',
                git_models_or_repository_network_executed_by_audit=False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir',type=Path,required=True)
    parser.add_argument('--component',choices=sorted(COMPONENTS),required=True)
    parser.add_argument('--remote-operation',required=True)
    parser.add_argument('--remote-inputs',required=True)
    args=parser.parse_args()
    print(json.dumps(audit(args.evidence_dir,args.component,args.remote_operation,args.remote_inputs),sort_keys=True,indent=2))
