#!/usr/bin/env python3
"""Inspect a descriptor without starting a native runtime."""
import argparse
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.runtime.descriptor_preflight import inspect_descriptor
from myfuzz.runtime.generic_campaign import GenericScenarioRefused, load_descriptor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--descriptor', type=Path, required=True)
    args = parser.parse_args()
    try:
        descriptor = load_descriptor(args.descriptor, base_dir=ROOT)
        with TemporaryDirectory(prefix='myfuzz-preflight-') as temp:
            report = inspect_descriptor(descriptor, base_dir=ROOT, generated_dir=Path(temp) / 'generated')
    except GenericScenarioRefused as error:
        report = dict(preparation='refused', code=error.code, pointer=error.pointer, detail=error.detail)
    print(json.dumps(report, sort_keys=True))
    return 0 if report['preparation'] == 'complete' else 2


if __name__ == '__main__':
    raise SystemExit(main())
