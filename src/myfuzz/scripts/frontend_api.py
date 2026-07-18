#!/usr/bin/env python3
"""Project-local myfuzz frontend component API wrapper."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path


_FRONTEND_ENVIRONMENT_KEYS = frozenset({
    "MYFUZZ_FRONTEND_VERILATOR_ROOT",
    "VERILATOR_ROOT",
})


def default_frontend_library(root: Path) -> Path:
    env = os.environ.get("MYFUZZ_FRONTEND_LIBRARY")
    if env:
        return Path(env).resolve()
    return root / "src" / "myfuzz" / "frontend" / "build" / "libmyfuzz_frontend.so"


def frontend_args(cfg: dict, flist: Path) -> list[str]:
    return [
        "--lint-only",
        "-Wno-fatal",
        *cfg.get("verilator_args", []),
        "-f",
        flist.as_posix(),
        "--top-module",
        cfg["top"],
    ]


class FrontendLibrary:
    def __init__(self, path: Path):
        self.path = path
        self.lib = ctypes.CDLL(path.as_posix())
        self.lib.myfuzz_frontend_manifest_json.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_char_p),
        ]
        self.lib.myfuzz_frontend_manifest_json.restype = ctypes.c_void_p
        self.lib.myfuzz_frontend_free.argtypes = [ctypes.c_void_p]
        self.lib.myfuzz_frontend_free.restype = None
        self.lib.myfuzz_frontend_last_error.argtypes = []
        self.lib.myfuzz_frontend_last_error.restype = ctypes.c_char_p

    def manifest(self, args: list[str], cwd: Path) -> dict:
        old_cwd = Path.cwd()
        old_verilator_root = os.environ.get("VERILATOR_ROOT")
        encoded = [item.encode() for item in args]
        argv = (ctypes.c_char_p * len(encoded))(*encoded)
        os.chdir(cwd)
        ptr = None
        try:
            ptr = self.lib.myfuzz_frontend_manifest_json(len(encoded), argv)
            if not ptr:
                raw = self.lib.myfuzz_frontend_last_error()
                message = raw.decode(errors="replace") if raw else "unknown frontend error"
                raise RuntimeError(message)
            data = ctypes.string_at(ptr).decode()
            return json.loads(data)
        finally:
            if ptr:
                self.lib.myfuzz_frontend_free(ptr)
            if old_verilator_root is None:
                os.environ.pop("VERILATOR_ROOT", None)
                os.unsetenv("VERILATOR_ROOT")
            else:
                os.environ["VERILATOR_ROOT"] = old_verilator_root
            os.chdir(old_cwd)


def isolated_frontend_manifest(
    library: Path, args: list[str], cwd: Path, *, environment: dict[str, str] | None = None,
    timeout: int = 300,
) -> dict:
    worker = Path(__file__).with_name("frontend_worker.py")
    request = json.dumps({
        "library": library.resolve().as_posix(),
        "args": args,
        "cwd": cwd.resolve().as_posix(),
    }, sort_keys=True, separators=(",", ":"))
    requested = environment or {}
    unknown = set(requested) - _FRONTEND_ENVIRONMENT_KEYS
    if unknown:
        raise ValueError(f"unsupported frontend environment key(s): {', '.join(sorted(unknown))}")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        raise ValueError("frontend timeout must be a positive integer")
    package_root = Path(__file__).resolve().parents[2]
    env = {
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONNOUSERSITE": "1",
        "PYTHONPATH": package_root.as_posix(),
    }
    env.update(requested)
    try:
        completed = subprocess.run(
            [sys.executable, worker.as_posix()],
            input=request,
            text=True,
            capture_output=True,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"frontend worker exceeded {timeout} seconds") from exc
    if completed.returncode:
        message = completed.stderr.strip() or completed.stdout.strip() or "unknown frontend worker error"
        raise RuntimeError(message)
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"frontend worker returned invalid JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise RuntimeError("frontend worker returned a non-object manifest")
    return result


def run_frontend_manifest(
    root: Path,
    cfg: dict,
    paths: dict,
    *,
    frontend_library: Path | None = None,
    write_debug_json: bool = True,
) -> dict:
    args = frontend_args(cfg, paths["flist"])
    library = frontend_library or default_frontend_library(root)
    if not library.exists():
        raise FileNotFoundError(
            f"myfuzz frontend library not built: {library}. "
            "Build it with src/myfuzz/frontend/scripts/build_frontend.sh"
        )

    os.environ.setdefault(
        "MYFUZZ_FRONTEND_VERILATOR_ROOT",
        (root / "src" / "myfuzz" / "frontend" / "vendor" / "verilator").as_posix(),
    )
    manifest = FrontendLibrary(library).manifest(args, paths["project_root"])

    if write_debug_json:
        paths["frontend_json"].parent.mkdir(parents=True, exist_ok=True)
        paths["frontend_json"].write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest
