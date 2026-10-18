"""Source-only draft: archive exactly the frozen root plus pinned control files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tarfile

ROOT = Path('/home/qinkejiu/myfuzz-p8-root-input-20261018-attempt2')
CONTROL = Path('/home/qinkejiu/myfuzz-p8-root-control-20261018-attempt2')


def need(value, why):
    if not value:
        raise ValueError(why)


def safe(path):
    need(path.is_absolute() and '..' not in path.parts, 'noncanonical-absolute-path')
    for part in (path, *path.parents):
        need(not part.is_symlink(), 'symlink-path')
    return path


def digest(path):
    safe(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'hash-nonregular')
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def census(root):
    safe(root)
    files, directories = {}, {}
    for parent, dirs, names in os.walk(root, followlinks=False):
        for name in dirs:
            path = Path(parent) / name
            info = path.lstat()
            need(stat.S_ISDIR(info.st_mode), 'directory-link-or-special')
            directories[path.relative_to(root).as_posix()] = {'mode': stat.S_IMODE(info.st_mode)}
        for name in names:
            path = Path(parent) / name
            info = path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'file-link-or-special')
            files[path.relative_to(root).as_posix()] = dict(bytes=info.st_size,
                mode=stat.S_IMODE(info.st_mode), sha256=digest(path))
    return files, directories


def write(path, value):
    safe(path)
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--control-inputs', type=Path, required=True)
    parser.add_argument('--control-inputs-sha256', required=True)
    args = parser.parse_args()
    safe(args.control_inputs)
    need(args.control_inputs.parent == CONTROL, 'control-manifest-location')
    need(digest(args.control_inputs) == args.control_inputs_sha256, 'control-manifest-pin')
    pins = json.loads(args.control_inputs.read_bytes())
    need(pins['schema_version'] == 'p8_root_transfer_control_inputs.v1', 'control-inputs-schema')
    controls = pins['files']
    required = {'selection.json', 'freeze.json', 'prepare-receipt.json', 'launch_prepare.py',
        'prepare-launch-start.json', 'prepare-launch-terminal.json', 'selected-argv.json',
        'prepare.stdout', 'prepare.stderr', 'independent-selection-review.json',
        'independent-stage-audit.json'}
    need(required <= set(controls), 'missing-actual-reviewed-controls')
    need(pins['independent_stage_review_accepted'] is True, 'actual-stage-review-required')
    for name, pin in controls.items():
        need(name not in ('', '.', '..') and '/' not in name and '\\' not in name, 'control-member-name')
        source = safe(Path(pin['path']))
        need(source.parent == CONTROL, 'control-source-location')
        info = source.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == pin['bytes']
             and stat.S_IMODE(info.st_mode) == pin['mode'] and digest(source) == pin['sha256'], 'control-pin-drift')
    freeze = json.loads(Path(controls['freeze.json']['path']).read_bytes())
    receipt = json.loads(Path(controls['prepare-receipt.json']['path']).read_bytes())
    need(receipt['freeze_sha256'] == controls['freeze.json']['sha256']
         and receipt['destination'] == str(ROOT) and receipt['native_run'] is False
         and receipt['status'] == 'copied_pending_closure_and_tool_review', 'prepare-receipt-binding')
    audit = json.loads(Path(controls['independent-stage-audit.json']['path']).read_bytes())
    need(audit['schema_version'] == 'independent_actual_regular_root_stage_audit.v1'
         and audit['status'] == 'actual_regular_root_copy_verified' and audit['stage'] == str(ROOT)
         and audit['freeze_sha256'] == controls['freeze.json']['sha256']
         and audit['prepare_receipt_sha256'] == controls['prepare-receipt.json']['sha256']
         and audit['complete_file_and_directory_sets_modes_nlink1_sha_verified'] is True
         and audit['source_modified'] is False and audit['stage_HEAD'] == '269717b7e9cc7c92da5e427ac950bc82446b3ac6',
         'actual-stage-audit-binding')
    before_files, before_dirs = census(ROOT)
    need(before_files == freeze and before_dirs == receipt['directories']
         and len(before_files) == receipt['files'] == audit['actual_stage_files'] == 10347
         and len(before_dirs) == audit['actual_stage_directories'] == 524, 'frozen-stage-map-drift')
    archive = CONTROL / 'root-input.tar.gz'
    manifest_path = CONTROL / 'transfer-manifest.json'
    receipt_path = CONTROL / 'package-receipt.json'
    for path in (archive, manifest_path, receipt_path):
        need(not path.exists(), 'new-package-output-required')
    root_mode = stat.S_IMODE(ROOT.lstat().st_mode)
    file_map = {'root/' + name: pin for name, pin in before_files.items()}
    file_map.update({'control/' + name: {key: pin[key] for key in ('bytes', 'mode', 'sha256')}
                     for name, pin in controls.items()})
    dirs = {'root': {'mode': root_mode}, 'control': {'mode': 0o755}}
    dirs.update({'root/' + name: pin for name, pin in before_dirs.items()})
    manifest = dict(schema_version='p8_root_transfer_manifest.v1', files=file_map, directories=dirs,
        frozen_root_files=before_files, frozen_root_directories=before_dirs,
        root_freeze_sha256=controls['freeze.json']['sha256'],
        control_inputs_sha256=args.control_inputs_sha256)
    write(manifest_path, manifest)
    with archive.open('xb') as raw, tarfile.open(fileobj=raw, mode='w:gz', compresslevel=1,
            format=tarfile.USTAR_FORMAT) as target:
        for name, pin in sorted(dirs.items(), key=lambda item: (len(Path(item[0]).parts), item[0])):
            member = tarfile.TarInfo(name)
            member.type, member.mode = tarfile.DIRTYPE, pin['mode']
            target.addfile(member)
        for name, pin in sorted(file_map.items()):
            source = ROOT / name[5:] if name.startswith('root/') else Path(controls[name[8:]]['path'])
            safe(source)
            member = tarfile.TarInfo(name)
            member.size, member.mode = pin['bytes'], pin['mode']
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as stream:
                need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'archive-input-type')
                target.addfile(member, stream)
    after_files, after_dirs = census(ROOT)
    need((before_files, before_dirs) == (after_files, after_dirs), 'source-stage-changed')
    for pin in controls.values():
        need(digest(Path(pin['path'])) == pin['sha256'], 'control-changed-during-package')
    write(receipt_path, dict(schema_version='p8_root_package_receipt.v1', status='packaged_pending_archive_audit',
        archive=str(archive), archive_bytes=archive.stat().st_size, archive_sha256=digest(archive),
        manifest_sha256=digest(manifest_path), source_unchanged=True,
        root_files=len(before_files), root_directories=len(before_dirs), native_execution=False))


if __name__ == '__main__':
    main()
