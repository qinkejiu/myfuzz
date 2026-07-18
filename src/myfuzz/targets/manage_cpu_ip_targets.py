#!/usr/bin/env python3
"""Manage CPU + IP target candidates for RFuzz experiments."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parents[1]
MATRIX_PATH = REPO_ROOT / "configs" / "cpu_ip_target_matrix" / "targets.json"


def load_matrix(path: Path = MATRIX_PATH) -> dict:
    with path.open() as infile:
        return json.load(infile)


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(root: Path, repo: dict) -> Path:
    return (root / repo["path"]).resolve()


def bundle_ids(matrix: dict) -> list[str]:
    return [bundle["id"] for bundle in matrix["bundles"]]


def select_bundles(matrix: dict, names: Iterable[str] | None, all_bundles: bool) -> list[dict]:
    bundles = list(matrix["bundles"])
    if all_bundles:
        return sorted(bundles, key=lambda item: int(item.get("priority", 999)))
    wanted = list(names or [])
    if not wanted:
        raise SystemExit("select at least one --bundle or pass --all")
    by_id = {bundle["id"]: bundle for bundle in bundles}
    missing = [name for name in wanted if name not in by_id]
    if missing:
        raise SystemExit(f"unknown bundle(s): {', '.join(missing)}")
    return [by_id[name] for name in wanted]


def repository_names(bundle: dict) -> list[str]:
    names: list[str] = []
    for key in ("cpu_repositories", "ip_repositories"):
        for name in bundle.get(key, []):
            if name not in names:
                names.append(name)
    return names


def repo_status(root: Path, repo: dict) -> dict:
    path = repo_path(root, repo)
    exists = path.exists()
    key_paths = list(repo.get("key_paths", []))
    missing_keys = [key for key in key_paths if not (path / key).exists()]
    revision = None
    if (path / ".git").exists():
        try:
            revision = subprocess.check_output(
                ["git", "-C", path.as_posix(), "rev-parse", "--short", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except subprocess.CalledProcessError:
            revision = None
    return {
        "path": relpath(path, root),
        "exists": exists,
        "revision": revision,
        "key_count": len(key_paths),
        "missing_key_paths": missing_keys,
        "ready": exists and not missing_keys,
    }


def compute_status(root: Path, matrix: dict, bundles: list[dict]) -> dict:
    repos = matrix["repositories"]
    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "root": root.as_posix(),
        "bundles": [],
    }
    for bundle in bundles:
        per_repo = {}
        for name in repository_names(bundle):
            per_repo[name] = repo_status(root, repos[name])
        ready = all(item["ready"] for item in per_repo.values())
        result["bundles"].append(
            {
                "id": bundle["id"],
                "priority": bundle.get("priority"),
                "status": bundle.get("status"),
                "cpu": bundle.get("cpu"),
                "implemented_phases": bundle.get("implemented_phases", []),
                "repositories": per_repo,
                "source_ready": ready,
            }
        )
    return result


def print_list(matrix: dict, bundles: list[dict]) -> None:
    print(f"{'priority':>8}  {'bundle':36}  {'status':16}  {'cpu':18}  ip_pool")
    for bundle in bundles:
        ip_pool = ",".join(bundle.get("initial_ip_set") or bundle.get("ip_pool") or [])
        print(
            f"{int(bundle.get('priority', 999)):8d}  "
            f"{bundle['id'][:36]:36}  "
            f"{str(bundle.get('status', ''))[:16]:16}  "
            f"{str(bundle.get('cpu', ''))[:18]:18}  "
            f"{ip_pool}"
        )


def print_status(status: dict) -> None:
    print(f"root: {status['root']}")
    print(f"{'bundle':36}  {'source':8}  {'status':16}  repositories")
    for bundle in status["bundles"]:
        repo_bits = []
        for name, repo in bundle["repositories"].items():
            if repo["ready"]:
                state = "ok"
            elif repo["exists"]:
                state = "missing_keys"
            else:
                state = "missing"
            rev = f"@{repo['revision']}" if repo.get("revision") else ""
            repo_bits.append(f"{name}:{state}{rev}")
        print(
            f"{bundle['id'][:36]:36}  "
            f"{str(bundle['source_ready']):8}  "
            f"{str(bundle.get('status', ''))[:16]:16}  "
            f"{', '.join(repo_bits)}"
        )


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def render_bundle_readme(bundle: dict, matrix: dict) -> str:
    repo_lines = []
    for name in repository_names(bundle):
        repo = matrix["repositories"][name]
        source = repo.get("url") or repo.get("provided_by") or "local"
        repo_lines.append(f"- `{name}`: `{repo['path']}` ({source})")
    phase_lines = []
    for phase in bundle.get("implemented_phases", []):
        commands = bundle.get("phase_commands", {}).get(phase, [])
        if commands:
            phase_lines.append(f"- `{phase}`:")
            phase_lines.extend(f"  - `{cmd}`" for cmd in commands)
        else:
            phase_lines.append(f"- `{phase}`: built into `src/myfuzz/targets/manage_cpu_ip_targets.py`")
    ip_pool = ", ".join(bundle.get("ip_pool", []))
    initial = ", ".join(bundle.get("initial_ip_set", []))
    return "\n".join(
        [
            f"# {bundle['id']}",
            "",
            f"- status: `{bundle.get('status', '')}`",
            f"- cpu: `{bundle.get('cpu', '')}`",
            f"- design config root: `{bundle.get('design_config_root', '')}`",
            f"- initial IP set: {initial}",
            f"- full IP pool: {ip_pool}",
            "",
            "## Repositories",
            "",
            *repo_lines,
            "",
            "## Phases",
            "",
            *phase_lines,
            "",
            "## Notes",
            "",
            bundle.get("notes", ""),
            "",
        ]
    )


def prepare_bundle(root: Path, matrix: dict, bundle: dict) -> Path:
    work_root = root / matrix.get("default_work_root", "runs/cpu_ip_target_matrix")
    bundle_dir = work_root / bundle["id"]
    bundle_dir.mkdir(parents=True, exist_ok=True)
    write_json(bundle_dir / "manifest.json", bundle)
    (bundle_dir / "README.md").write_text(render_bundle_readme(bundle, matrix))
    (bundle_dir / "source_smoke.sh").write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "cd \"$(dirname \"$0\")/../../..\"\n"
        f"python3 src/myfuzz/targets/manage_cpu_ip_targets.py source-smoke --bundle {bundle['id']}\n"
    )
    os.chmod(bundle_dir / "source_smoke.sh", 0o755)
    return bundle_dir


def clone_repository(root: Path, name: str, repo: dict) -> str:
    path = repo_path(root, repo)
    url = repo.get("url")
    if not url:
        return f"{name}: provided locally at {relpath(path, root)}"
    if path.exists():
        return f"{name}: already exists at {relpath(path, root)}"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".clone_tmp")
    if tmp.exists():
        raise RuntimeError(f"temporary clone path already exists: {tmp}")

    clone_args = list(repo.get("clone_args", ["--depth", "1", "--filter=blob:none"]))
    cmd = ["git", "clone", *clone_args, url, tmp.as_posix()]
    print("+ " + " ".join(cmd), flush=True)
    try:
        subprocess.run(cmd, cwd=root, check=True)
        sparse = list(repo.get("sparse_checkout", []))
        if sparse:
            sparse_cmd = ["git", "-C", tmp.as_posix(), "sparse-checkout", "set", *sparse]
            print("+ " + " ".join(sparse_cmd), flush=True)
            subprocess.run(sparse_cmd, cwd=root, check=True)
        tmp.rename(path)
    except Exception:
        print(f"clone failed; partial checkout is left at {tmp}", file=sys.stderr)
        raise
    return f"{name}: cloned to {relpath(path, root)}"


def clone_for_bundles(root: Path, matrix: dict, bundles: list[dict]) -> None:
    repos = matrix["repositories"]
    seen: set[str] = set()
    for bundle in bundles:
        for name in repository_names(bundle):
            if name in seen:
                continue
            seen.add(name)
            print(clone_repository(root, name, repos[name]))


def source_smoke(root: Path, matrix: dict, bundles: list[dict], allow_missing: bool) -> int:
    status = compute_status(root, matrix, bundles)
    work_root = root / matrix.get("default_work_root", "runs/cpu_ip_target_matrix")
    failures = 0
    for bundle_status in status["bundles"]:
        bundle_dir = work_root / bundle_status["id"]
        bundle_dir.mkdir(parents=True, exist_ok=True)
        write_json(bundle_dir / "source_smoke.json", bundle_status)
        if not bundle_status["source_ready"]:
            failures += 1
            print(f"FAIL {bundle_status['id']}")
            for name, repo in bundle_status["repositories"].items():
                if not repo["exists"]:
                    print(f"  missing repo {name}: {repo['path']}")
                for key in repo["missing_key_paths"]:
                    print(f"  missing key {name}:{key}")
        else:
            print(f"OK   {bundle_status['id']}")
    return 0 if allow_missing or failures == 0 else 1


def run_phase(root: Path, matrix: dict, bundles: list[dict], phase: str) -> int:
    rc = 0
    for bundle in bundles:
        commands = bundle.get("phase_commands", {}).get(phase, [])
        if not commands:
            print(f"SKIP {bundle['id']}: no command for phase {phase}")
            continue
        for command in commands:
            print(f"RUN  {bundle['id']}: {command}", flush=True)
            completed = subprocess.run(command, cwd=root, shell=True)
            if completed.returncode != 0:
                rc = completed.returncode
                print(f"FAIL {bundle['id']}: {command} returned {completed.returncode}")
                return rc
    return rc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--matrix", type=Path, default=MATRIX_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_select_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--bundle", action="append", choices=bundle_ids(load_matrix()), help="Bundle id. Repeatable.")
        p.add_argument("--all", action="store_true", help="Select all bundles.")

    p_list = sub.add_parser("list")
    add_select_args(p_list)

    p_status = sub.add_parser("status")
    add_select_args(p_status)
    p_status.add_argument("--json", action="store_true")

    p_prepare = sub.add_parser("prepare")
    add_select_args(p_prepare)

    p_clone = sub.add_parser("clone")
    add_select_args(p_clone)

    p_smoke = sub.add_parser("source-smoke")
    add_select_args(p_smoke)
    p_smoke.add_argument("--allow-missing", action="store_true")

    p_run = sub.add_parser("run-phase")
    add_select_args(p_run)
    p_run.add_argument("--phase", required=True)

    args = parser.parse_args()
    root = args.root.resolve()
    matrix = load_matrix(args.matrix)
    selected = select_bundles(matrix, args.bundle, args.all)

    if args.cmd == "list":
        print_list(matrix, selected)
        return 0
    if args.cmd == "status":
        status = compute_status(root, matrix, selected)
        if args.json:
            print(json.dumps(status, indent=2, sort_keys=True))
        else:
            print_status(status)
        return 0
    if args.cmd == "prepare":
        for bundle in selected:
            path = prepare_bundle(root, matrix, bundle)
            print(f"prepared {bundle['id']}: {relpath(path, root)}")
        return 0
    if args.cmd == "clone":
        clone_for_bundles(root, matrix, selected)
        return 0
    if args.cmd == "source-smoke":
        return source_smoke(root, matrix, selected, args.allow_missing)
    if args.cmd == "run-phase":
        return run_phase(root, matrix, selected, args.phase)
    raise AssertionError(args.cmd)


if __name__ == "__main__":
    raise SystemExit(main())
