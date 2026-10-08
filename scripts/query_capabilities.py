#!/usr/bin/env python3
"""Query documented runtime evidence and limitations without starting RTL."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SRC = Path(__file__).resolve().parents[1] / 'src'
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.capabilities import query_capabilities  # noqa: E402


def configure_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--match', help='case-insensitive substring in component, evidence or level')


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    try:
        result = query_capabilities(match=args.match)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    configure_parser(parser)
    return run(parser.parse_args(argv), parser)


if __name__ == '__main__':
    raise SystemExit(main())
