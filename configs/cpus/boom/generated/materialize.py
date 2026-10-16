#!/usr/bin/env python3
"""Materialize exactly the four authenticated derived RTL inputs; no network."""
import hashlib
import io
import json
from pathlib import Path
import tarfile


def materialize(root: Path = Path(__file__).resolve().parent) -> dict:
    manifest = json.loads((root / 'source_manifest.json').read_text())
    archive = (root / manifest['archive']).read_bytes()
    if hashlib.sha256(archive).hexdigest() != manifest['archive_sha256']:
        raise ValueError('boom-rtl-archive-hash-mismatch')
    expected = {item['path']: item for item in manifest['files']}
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        members = tar.getmembers()
        if len(members) != len(expected) or {m.name for m in members} != set(expected):
            raise ValueError('boom-rtl-archive-members-mismatch')
        content = {}
        for member in members:
            if not member.isfile() or '/' in member.name or '\\' in member.name:
                raise ValueError('boom-rtl-archive-unsafe-member')
            data = tar.extractfile(member).read()
            record = expected[member.name]
            if len(data) != record['bytes'] or hashlib.sha256(data).hexdigest() != record['sha256']:
                raise ValueError('boom-rtl-member-hash-mismatch:' + member.name)
            content[member.name] = data
    # All members are authenticated before any existing RTL is replaced.
    for name, data in content.items():
        (root / name).write_bytes(data)
    return manifest


if __name__ == '__main__':
    print(json.dumps(materialize(), indent=2))
