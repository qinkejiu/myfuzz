#!/usr/bin/env python3
"""Independently verify saved ``generic_runtime_bundle.v1`` evidence.

Reads only archived bundle bytes: no live handle, no native token, no mutable
repository and no stored ``certified`` boolean.  A missing or unreadable bundle
is a refusal (exit 2) whose JSON is still written, so the negative result is
archived rather than only printed.
"""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from myfuzz.runtime.contracts import GenericRuntimeRefused
from myfuzz.runtime.evidence.saved import (  # noqa: E402
    refusal_report,
    verify_saved_bundle,
)


def _write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(document, sort_keys=True, indent=2,
                         ensure_ascii=False, allow_nan=False) + "\n"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(payload, encoding="utf-8")
    temporary.replace(path)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Independently verify saved generic-runtime evidence.")
    parser.add_argument("--bundle", required=True, type=Path,
                        help="saved generic_runtime_bundle.v1 directory")
    parser.add_argument("--fresh-bundle", type=Path, default=None,
                        help="optional fresh replay bundle for the same plan")
    parser.add_argument("--output", required=True, type=Path,
                        help="verification report or refusal JSON path")
    arguments = parser.parse_args(argv)
    try:
        report = verify_saved_bundle(
            arguments.bundle, fresh_bundle_dir=arguments.fresh_bundle)
    except GenericRuntimeRefused as error:
        refusal = refusal_report(error, bundle=arguments.bundle,
                                 fresh_bundle=arguments.fresh_bundle)
        _write(arguments.output, refusal)
        print(json.dumps({"verdict": refusal["verdict"],
                          "refusal": refusal["refusal"]}, sort_keys=True))
        return 2
    _write(arguments.output, report)
    print(json.dumps({"verdict": report["verdict"],
                      "case_count": report["case_count"],
                      "checks": len(report["checks"]),
                      "bundle_ids": report["bundle_ids"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
