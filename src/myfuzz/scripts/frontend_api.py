#!/usr/bin/env python3
"""Project-local myfuzz frontend component API wrapper."""

from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path


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
        self.lib.myfuzz_frontend_facts_json.argtypes = [
            ctypes.c_int,
            ctypes.POINTER(ctypes.c_char_p),
        ]
        self.lib.myfuzz_frontend_facts_json.restype = ctypes.c_void_p
        self.lib.myfuzz_frontend_free.argtypes = [ctypes.c_void_p]
        self.lib.myfuzz_frontend_free.restype = None
        self.lib.myfuzz_frontend_last_error.argtypes = []
        self.lib.myfuzz_frontend_last_error.restype = ctypes.c_char_p

    def _json_call(self, symbol: str, args: list[str], cwd: Path) -> dict:
        old_cwd = Path.cwd()
        old_verilator_root = os.environ.get("VERILATOR_ROOT")
        encoded = [item.encode() for item in args]
        argv = (ctypes.c_char_p * len(encoded))(*encoded)
        os.chdir(cwd)
        ptr = None
        try:
            ptr = getattr(self.lib, symbol)(len(encoded), argv)
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

    def manifest(self, args: list[str], cwd: Path) -> dict:
        return self._json_call("myfuzz_frontend_manifest_json", args, cwd)

    def facts(self, args: list[str], cwd: Path) -> dict:
        return self._json_call("myfuzz_frontend_facts_json", args, cwd)


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
