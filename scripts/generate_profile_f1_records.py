#!/usr/bin/env python3
"""Generate reproducible F1 ALU or F3/F1 RAM records from a CPU profile."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    parser.add_argument('--entropy-hex', required=True,
                        help='four bytes per ALU case or RAM store/read pair')
    parser.add_argument('--mode', choices=('alu', 'ram'), default='alu',
                        help='generate F1 ALU cases or paired F3/F1 RAM cases')
    parser.add_argument('--register-dependencies', action='store_true',
                        help='allow F1 instructions to read x12..x15')
    parser.add_argument('--enable-m', action='store_true',
                        help='generate RV32M when declared; execution requires the bound CPU profile')
    parser.add_argument('--enable-c', action='store_true',
                        help='generate two compressed RV32C instructions per F1 record')
    parser.add_argument('--output', type=Path, required=True,
                        help='new JSON records file for --records-file')
    args = parser.parse_args()
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.isa.profile_program import build_f1_records, build_ram_dataflow_records
    profile_bytes = args.profile.read_bytes()
    profile = load_component_profile(args.profile)
    entropy = bytes.fromhex(args.entropy_hex)
    if args.mode == 'ram':
        if args.register_dependencies or args.enable_m or args.enable_c:
            parser.error('instruction generation options only apply to ALU mode')
        provenance = build_ram_dataflow_records(profile, entropy)
    else:
        provenance = build_f1_records(profile, entropy,
                                      register_dependencies=args.register_dependencies,
                                      enable_m=args.enable_m, enable_c=args.enable_c)
    provenance['profile'] = str(args.profile)
    provenance['profile_sha256'] = sha256(profile_bytes).hexdigest()
    provenance_path = args.output.with_name(args.output.name + '.provenance.json')
    with args.output.open('x') as out:
        json.dump(provenance['records'], out, indent=2)
        out.write('\n')
    with provenance_path.open('x') as out:
        json.dump(provenance, out, indent=2, sort_keys=True)
        out.write('\n')
    print(json.dumps({'records_file': str(args.output), 'provenance_file': str(provenance_path)}))


if __name__ == '__main__':
    main()
