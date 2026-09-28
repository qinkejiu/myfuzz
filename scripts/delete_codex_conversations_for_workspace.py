#!/usr/bin/env python3
"""Delete Codex sessions whose recorded cwd is this repository."""

import argparse
import json
import sys
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parent.parent
CODEX_DIR = Path.home() / ".codex"


def recorded_cwd(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8") as session:
            header = json.loads(session.readline())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"Skipped unreadable session {path}: {exc}", file=sys.stderr)
        return None
    if header.get("type") != "session_meta":
        return None
    return header.get("payload", {}).get("cwd")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="list matching sessions without deleting them"
    )
    args = parser.parse_args()

    count = 0
    failed = 0
    for folder in (CODEX_DIR / "sessions", CODEX_DIR / "archived_sessions"):
        if not folder.is_dir():
            continue
        for path in folder.rglob("*.jsonl"):
            if recorded_cwd(path) != str(WORKSPACE):
                continue
            if args.dry_run:
                print(f"Would delete: {path}")
                count += 1
                continue
            try:
                path.unlink()
            except OSError as exc:
                print(f"Failed to delete {path}: {exc}", file=sys.stderr)
                failed += 1
                continue
            print(f"Deleted: {path}")
            count += 1

    verb = "matched" if args.dry_run else "deleted"
    print(f"{count} session(s) {verb} for {WORKSPACE}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
