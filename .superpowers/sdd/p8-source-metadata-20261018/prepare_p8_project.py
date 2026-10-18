"""Pure-file P8 typed snapshot planner/copier. No Git, imports or model child."""
import argparse
import configparser
import hashlib
import json
import os
import posixpath
from pathlib import Path, PurePosixPath
import stat

FAN = Path('/root/fanzehui')
COMPONENTS = {'ibex': ('third_party/rfuzz/upstream/ibex', '34b0705760ef3dfa00e99637432473d2be8f22f3'),
    'opentitan': ('third_party/soc-opentitan', 'fca045df919a26c47e71616b9dac917b1ea4fd07'),
    'zipcpu': ('third_party/soc-zipcpu', '42606d2d6ef55df313772232977621b2d72f0159')}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    safe(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'hash-input-not-regular')
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def safe(path):
    need(path.is_absolute() and '..' not in path.parts and path.is_relative_to(FAN), 'outside-fanzehui')
    for part in (path, *path.parents):
        need(not part.is_symlink(), 'path-symlink:' + str(part))
    return path


def relative(name, *, dot=False):
    path = PurePosixPath(name)
    need((dot and name == '.') or (name != '.' and not path.is_absolute() and '..' not in path.parts
         and str(path) == name and bool(path.parts)), 'noncanonical-relative-path')
    return name


def selected(name, prefixes):
    return any(name == prefix or name.startswith(prefix + '/') for prefix in prefixes)


def write(path, document):
    safe(path)
    with path.open('x') as stream:
        json.dump(document, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def pinned(pin):
    need(set(pin) == {'path', 'sha256'}, 'invalid-pin')
    path = safe(Path(pin['path']))
    need(path.is_file() and sha(path) == pin['sha256'], 'input-pin-drift:' + str(path))
    return path


def census(root, includes, excludes, links):
    """Select with lstat; symlinks are terminal leaves, never traversed."""
    safe(root)
    files, directories = {}, {}
    def add_dir(path):
        while path != root:
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode), 'non-directory-parent')
            directories[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
            path = path.parent
    def add_leaf(path):
        name = path.relative_to(root).as_posix()
        info = path.lstat()
        add_dir(path.parent)
        if stat.S_ISLNK(info.st_mode):
            need(name != '.git' and '/.git/' not in '/' + name + '/' and not name.startswith('.git/'),
                 'metadata-symlink')
            raw = os.fsencode(os.readlink(path))
            pin = links.get(name)
            need(isinstance(pin, dict) and pin.get('git_mode') == '120000'
                 and pin.get('linkbytes_hex') == raw.hex()
                 and len(pin.get('git_oid', '')) == 40
                 and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == pin['git_oid'],
                 'unqualified-tracked-link:' + name)
            target = os.fsdecode(raw)
            normalized = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            need(target and not target.startswith('/') and normalized != '..'
                 and not normalized.startswith('../') and '\x00' not in target, 'link-target-escape')
            files[name] = dict(kind='symlink', mode=stat.S_IMODE(info.st_mode), bytes=len(raw),
                linkbytes_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest(), git_oid=pin['git_oid'])
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'file-link-or-special')
            files[name] = dict(kind='regular', mode=stat.S_IMODE(info.st_mode),
                               bytes=info.st_size, sha256=sha(path))
    for prefix in includes:
        relative(prefix, dot=True)
        path = root if prefix == '.' else root / prefix
        # The leaf itself may be a qualified link; its parents may not be.
        safe(path.parent if path != root else root)
        need(not selected(prefix, excludes), 'included-prefix-excluded')
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            add_leaf(path)
            continue
        for parent, dirs, names in os.walk(path, followlinks=False):
            directory = Path(parent)
            add_dir(directory)
            kept = []
            for name in dirs:
                child = directory / name
                key = child.relative_to(root).as_posix()
                if selected(key, excludes):
                    continue
                if child.is_symlink():
                    add_leaf(child)
                else:
                    need(stat.S_ISDIR(child.lstat().st_mode), 'directory-special')
                    kept.append(name)
                    add_dir(child)
            dirs[:] = kept
            for name in names:
                child = directory / name
                if not selected(child.relative_to(root).as_posix(), excludes):
                    add_leaf(child)
    need(set(links) == {name for name, row in files.items() if row['kind'] == 'symlink'},
         'tracked-link-map-set-mismatch')
    return dict(files=dict(sorted(files.items())), directories=dict(sorted(directories.items())))


def metadata(root, mapping):
    """Pure topology/config validation; object qualification is external/pinned."""
    git_roots = {'.git'}
    for name, row in mapping['files'].items():
        if name.endswith('/.git/HEAD'):
            git_roots.add(name[:-5])
        if name.endswith('/.git'):
            raise ValueError('standalone-component-metadata-required')
        if name.endswith('.promisor'):
            raise ValueError('promisor-pack')
        if name.endswith('/objects/info/alternates') or name.endswith('/commondir'):
            need(not (root / name).read_bytes().strip(), 'shared-metadata-store')
        if name.endswith('/config') and (name.startswith('.git/') or '/.git/' in name):
            config = configparser.RawConfigParser()
            config.read_string((root / name).read_text())
            for section in config.sections():
                need(not (section.lower() == 'include' or section.lower().startswith('includeif ')), 'git-config-include')
                need(not any(key.lower() in ('promisor', 'partialclone', 'hookspath', 'worktree')
                             for key in config[section]), 'external-or-partial-git-config')
    for name in git_roots:
        need(name + '/HEAD' in mapping['files'] and name + '/config' in mapping['files'], 'git-head-config-missing')
        need(all(name + '/' + child in mapping['directories'] for child in ('objects', 'refs', 'refs/heads', 'refs/tags')),
             'git-essential-directory-missing')


def load_selection(path):
    document = json.loads(path.read_bytes())
    need(document['schema_version'] == 'p8_project_selection.v1', 'selection-schema')
    inputs = document['inputs']
    need({row['id'] for row in inputs} == {'root', *COMPONENTS}, 'exact-three-components-plus-root-required')
    need(len(inputs) == 4, 'duplicate-input')
    for row in inputs:
        need(row['kind'] == ('root' if row['id'] == 'root' else 'component'), 'input-kind')
        safe(Path(row['source']))
        for name in row['includes'] + row['excludes']:
            relative(name, dot=True)
        map_path = pinned(row['qualified_map'])
        expected = json.loads(map_path.read_bytes())
        need(set(expected) == {'files', 'directories'}, 'qualified-map-schema')
        receipt = json.loads(pinned(row['audit_receipt']).read_bytes())
        need(receipt['schema_version'] == 'p8_copy_input_audit.v1'
             and receipt['status'] == 'independent_audit_passed'
             and receipt['source'] == row['source']
             and receipt['qualified_map_sha256'] == row['qualified_map']['sha256'], 'audit-not-qualified')
        if row['id'] == 'root':
            need(row['mount'] == '.' and {'src', 'scripts', 'configs', '.git', '.gitmodules'} <= set(row['includes']),
                 'incomplete-root-selection')
            need({'.git/modules', *[pair[0] for pair in COMPONENTS.values()]} <= set(row['excludes']),
                 'old-metadata-overlay-not-excluded')
            need(row['root_git_modules_policy'] == 'exclude_all_no_retained_component_pointers', 'root-module-policy')
        else:
            mount, revision = COMPONENTS[row['id']]
            need(row['mount'] == mount and row['includes'] == ['.'] and not row['excludes']
                 and receipt['revision'] == revision, 'component-qualified-snapshot-required')
        relative(row['mount'], dot=True)
    return document


def inspect(document):
    merged = dict(files={}, directories={})
    observed = {}
    for row in document['inputs']:
        actual = census(Path(row['source']), row['includes'], row['excludes'], row['tracked_links'])
        need(actual == json.loads(pinned(row['qualified_map']).read_bytes()), 'qualified-input-map-drift:' + row['id'])
        observed[row['id']] = actual
        for category in ('files', 'directories'):
            for name, pin in actual[category].items():
                key = name if row['mount'] == '.' else row['mount'] + '/' + name
                if key in merged[category]:
                    need(category == 'directories' and merged[category][key] == pin, 'overlay-collision')
                merged[category][key] = pin
        if row['mount'] != '.':
            parents = [PurePosixPath(row['mount']), *PurePosixPath(row['mount']).parents]
            for parent in parents:
                if str(parent) == '.':
                    continue
                mode = document['mount_directories'].get(str(parent))
                need(isinstance(mode, dict) and set(mode) == {'mode'}, 'mount-directory-mode-required')
                if str(parent) in merged['directories']:
                    need(merged['directories'][str(parent)] == mode, 'mount-mode-collision')
                merged['directories'][str(parent)] = mode
    for name in merged['files']:
        need(name not in merged['directories'], 'file-directory-collision')
        need(not any(str(p) in merged['files'] for p in PurePosixPath(name).parents if str(p) != '.'),
             'leaf-ancestor-collision')
    return observed, merged


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('plan', 'prepare'))
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256')
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    selection = pinned(dict(path=str(args.selection), sha256=args.selection_sha256))
    document = load_selection(selection)
    destination, receipt, plan_path = safe(args.destination), safe(args.receipt), safe(args.plan)
    stage_path = safe(destination.with_name(destination.name + '.unpublished-stage'))
    outputs = (destination, receipt, plan_path, stage_path)
    for index, left in enumerate(outputs):
        for right in outputs[index + 1:]:
            need(not left.is_relative_to(right) and not right.is_relative_to(left),
                 'output-path-overlap')
    need(not destination.exists() and not receipt.exists(), 'new-destination-and-receipt-required')
    for row in document['inputs']:
        source = Path(row['source'])
        need(all(not output.is_relative_to(source) for output in outputs), 'output-inside-source')
    before, expected = inspect(document)
    result = dict(schema_version='p8_project_copy_receipt.v1', status='failed', mode=args.mode,
                  source_prepared=False, runtime_grant=False, destination=str(destination))
    primary = None
    try:
        if args.mode == 'plan':
            write(plan_path, dict(schema_version='p8_project_copy_plan.v1', selection_sha256=args.selection_sha256,
                destination=str(destination), source_maps=before, final_map=expected))
            result['status'] = 'planned_pending_explicit_prepare'
        else:
            need(args.plan_sha256 is not None, 'reviewed-plan-pin-required')
            plan = json.loads(pinned(dict(path=str(plan_path), sha256=args.plan_sha256)).read_bytes())
            need(plan == dict(schema_version='p8_project_copy_plan.v1', selection_sha256=args.selection_sha256,
                destination=str(destination), source_maps=before, final_map=expected), 'reviewed-plan-drift')
            stage = stage_path
            need(not stage.exists(), 'stage-exists')
            stage.mkdir()
            for name, pin in sorted(expected['directories'].items(), key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])):
                path = stage / name
                safe(path.parent)
                path.mkdir()
                path.chmod(pin['mode'])
            for row in document['inputs']:
                for name, pin in before[row['id']]['files'].items():
                    key = name if row['mount'] == '.' else row['mount'] + '/' + name
                    target = stage / key
                    safe(target.parent)
                    if pin['kind'] == 'symlink':
                        os.symlink(os.fsdecode(bytes.fromhex(pin['linkbytes_hex'])), target)
                    else:
                        original = Path(row['source']) / name
                        safe(original.parent)
                        fd = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
                        with os.fdopen(fd, 'rb') as src, target.open('xb') as dst:
                            info = os.fstat(src.fileno())
                            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'copy-input-link-or-special')
                            while block := src.read(1024 * 1024):
                                dst.write(block)
                        target.chmod(pin['mode'])
            links = {name: dict(git_mode='120000', git_oid=pin['git_oid'], linkbytes_hex=pin['linkbytes_hex'])
                     for name, pin in expected['files'].items() if pin['kind'] == 'symlink'}
            actual = census(stage, ['.'], [], links)
            need(actual == expected, 'post-overlay-destination-map-drift')
            metadata(stage, actual)
            after, again = inspect(document)
            need(after == before and again == expected, 'source-drift')
            stage.rename(destination)
            result.update(status='copied_pending_independent_audit', source_prepared=True,
                          final_map=actual, source_before=before, source_after=after)
    except BaseException as error:
        primary = error
        result['error'] = repr(error)
    finally:
        try:
            after, final = inspect(document)
            result['source_before'] = before
            result['source_after'] = after
            result['source_unchanged'] = before == after and expected == final
            need(result['source_unchanged'], 'source-after-drift')
        except BaseException as error:
            result.update(status='failed', source_prepared=False, after_error=repr(error))
            if primary is None:
                primary = error
        write(receipt, result)
    if primary is not None:
        raise primary


if __name__ == '__main__':
    main()
