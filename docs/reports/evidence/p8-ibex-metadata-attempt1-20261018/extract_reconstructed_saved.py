"""UNEXECUTED safe local extraction source; never invokes the saved-data auditor.

Hash/size pins are explicit reviewed inputs. Every original regular file is
hashed before extraction and during exclusive creation. File modes and final
directory modes are preserved. Only the small final receipt is fsynced;
per-file crash durability is not claimed.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

TARGET_ROOT = Path('/home/qinkejiu/myfuzz/.superpowers/sdd/p8-source-metadata-20261018')


def need(value, reason):
    if not value: raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def extract(archive_path, expected_sha, expected_size, target, receipt_path, index_path):
    started=datetime.datetime.now(datetime.timezone.utc).isoformat()
    need(archive_path.is_file() and not archive_path.is_symlink(),'archive-not-regular')
    need(archive_path.stat().st_size==expected_size and sha(archive_path)==expected_sha,'original-archive-pin')
    target=target.absolute()
    need(target.is_relative_to(TARGET_ROOT) and target!=TARGET_ROOT and '..' not in target.parts,'target-outside-owned-root')
    need(not any(p.is_symlink() for p in (target,*target.parents)) and not target.exists(),'exclusive-new-target')
    need(not receipt_path.exists() and not index_path.exists(),'receipt-or-index-already-exists')
    pins={};directories={};regular_bytes=0
    with tarfile.open(archive_path,'r|gz') as archive:
        for member in archive:
            path=PurePosixPath(member.name)
            need(path.parts and not path.is_absolute() and '..' not in path.parts
                 and str(path)==member.name and member.name not in pins,'unsafe-or-duplicate-member')
            need(member.isfile() or member.isdir(),'link-or-special-member')
            need(member.mode & ~0o777 == 0,'privileged-member-mode')
            if member.isdir():
                pins[member.name]=dict(kind='directory',mode=member.mode);directories[member.name]=member.mode
            else:
                with archive.extractfile(member) as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
                pins[member.name]=dict(kind='regular',bytes=member.size,mode=member.mode,sha256=digest)
                regular_bytes+=member.size
    need(pins,'empty-archive')
    for name in pins:
        for parent in PurePosixPath(name).parents:
            if str(parent)!='.':need(str(parent) not in pins or pins[str(parent)]['kind']=='directory','file-parent-collision')
    target.mkdir(exist_ok=False);seen=set();files=0
    with tarfile.open(archive_path,'r|gz') as archive:
        for member in archive:
            need(member.name in pins and member.name not in seen,'archive-member-set-drift');seen.add(member.name)
            pin=pins[member.name];destination=target/member.name
            need(member.mode==pin['mode'],'archive-mode-drift')
            if pin['kind']=='directory':
                need(member.isdir(),'archive-kind-drift');destination.mkdir(parents=True,exist_ok=True)
            else:
                need(member.isfile() and member.size==pin['bytes'],'archive-kind-or-size-drift')
                destination.parent.mkdir(parents=True,exist_ok=True);digest=hashlib.sha256();count=0
                with archive.extractfile(member) as source,destination.open('xb') as out:
                    while block:=source.read(1024*1024):out.write(block);digest.update(block);count+=len(block)
                need(count==pin['bytes'] and digest.hexdigest()==pin['sha256'],'extracted-byte-hash')
                destination.chmod(pin['mode']);files+=1
    need(seen==set(pins),'archive-member-omission')
    # Apply directory modes only after all descendant files are created.
    for name,mode in sorted(directories.items(),key=lambda row:len(PurePosixPath(row[0]).parts),reverse=True):
        (target/name).chmod(mode)
    for name,pin in pins.items():
        path=target/name;info=path.lstat()
        need(stat.S_IMODE(info.st_mode)==pin['mode'],'final-mode-mismatch')
        if pin['kind']=='regular':
            need(stat.S_ISREG(info.st_mode) and info.st_size==pin['bytes'] and sha(path)==pin['sha256'],'final-file-recheck')
        else:need(stat.S_ISDIR(info.st_mode),'final-directory-kind')
    need(archive_path.stat().st_size==expected_size and sha(archive_path)==expected_sha,'archive-after-extraction-drift')
    with index_path.open('x') as stream:json.dump(pins,stream,sort_keys=True,indent=2);stream.write('\n')
    receipt=dict(schema_version='p8_safe_complete_metadata_extract.v1',started_at=started,
        ended_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),archive=str(archive_path),
        archive_sha256=expected_sha,archive_bytes=expected_size,original_archive_unchanged=True,
        target=str(target),original_members=len(pins),regular_files=files,regular_bytes=regular_bytes,
        directory_modes_preserved=True,member_index=str(index_path),member_index_sha256=sha(index_path),
        fsync_policy='final_receipt_only_no_per_file_crash_durability_claim',
        explicit_copy_without_extractall=True,links_hardlinks_specials_refused=True,
        auditor_or_Git_or_models_executed=False)
    with receipt_path.open('x') as stream:
        json.dump(receipt,stream,sort_keys=True,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,required=True)
    parser.add_argument('--archive-sha256',required=True)
    parser.add_argument('--archive-bytes',type=int,required=True)
    parser.add_argument('--target',type=Path,required=True)
    parser.add_argument('--receipt',type=Path,required=True)
    parser.add_argument('--member-index',type=Path,required=True)
    args=parser.parse_args();extract(args.archive,args.archive_sha256,args.archive_bytes,args.target,args.receipt,args.member_index)
