#!/usr/bin/env python3
"""Record derived Chipyard generation artifacts without enabling CPU admission."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('generated_dir', type=Path)
    parser.add_argument('output_dir', type=Path)
    args = parser.parse_args()
    root = args.generated_dir.resolve(strict=True)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    files = sorted(p for p in root.rglob('*') if p.is_file() and p.suffix in {'.v', '.sv', '.fir', '.json', '.f'})
    manifest = {'schema_version': 'boom_generation_artifacts.v1', 'derived_source': True,
                'generated_root': str(root), 'configuration': 'chipyard.SmallBoomConfig',
                'runtime_verified': False, 'files': []}
    modules = {}
    for path in files:
        raw = path.read_bytes()
        manifest['files'].append({'path': str(path.relative_to(root)), 'bytes': len(raw),
                                  'sha256': hashlib.sha256(raw).hexdigest()})
        if path.suffix not in {'.v', '.sv'}:
            continue
        for module in re.finditer(r'\bmodule\s+(\w+)\s*\((.*?)\);', raw.decode(), re.S):
            name, header = module.groups()
            if name not in {'TestHarness', 'ChipTop', 'BoomTile', 'BoomCore'}:
                continue
            ports = []
            for decl in re.finditer(r'^\s*(input|output|inout)\s+(?:(?:wire|reg|logic)\s+)?(?:(\[[^\]]+\])\s*)?(\w+)', header, re.M):
                direction, packed_range, port_name = decl.groups()
                width = 1
                if packed_range:
                    match = re.fullmatch(r'\[(\d+)\s*:\s*(\d+)\]', packed_range)
                    width = abs(int(match[1])-int(match[2]))+1 if match else None
                ports.append({'name': port_name, 'direction': direction, 'width': width,
                              'packed_range': packed_range})
            modules[name] = {'file': str(path.relative_to(root)), 'ports': ports}
    (args.output_dir/'generated_artifact_manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (args.output_dir/'physical_ports.json').write_text(json.dumps({'derived_source': True,
        'configuration': 'chipyard.SmallBoomConfig', 'semantic_adapter_verified': False,
        'modules': modules}, indent=2)+'\n')
    rtl_files = [root/entry['path'] for entry in manifest['files'] if Path(entry['path']).suffix in {'.v', '.sv'}]
    (args.output_dir/'sources.f').write_text(''.join(str(p)+'\n' for p in rtl_files))
    print(json.dumps({'files': len(files), 'rtl_files': len(rtl_files),
                      'modules': {name: len(data['ports']) for name, data in modules.items()}}))


if __name__ == '__main__':
    main()
