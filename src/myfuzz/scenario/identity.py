"""Source identity for repeatable local RTL scenario replay."""

from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess


def bundle_identity(root, paths):
    base = Path(root).resolve()
    files = []
    seen = set()
    for path in paths:
        selected = Path(path).resolve()
        try:
            relative = selected.relative_to(base).as_posix()
        except ValueError as exc:
            raise ValueError("source path is outside workspace root") from exc
        if not selected.is_file():
            raise ValueError(f"source file is missing: {relative}")
        if relative in seen:
            continue
        seen.add(relative)
        files.append({"path": relative,
                      "sha256": hashlib.sha256(selected.read_bytes()).hexdigest()})
    return {"schema_version": "source_bundle.v1",
            "files": sorted(files, key=lambda item: item["path"])}


def toolchain_identity() -> dict:
    """Capture the actual local simulator/compiler identity before replay."""
    tools = {}
    for name in ("verilator", "c++"):
        executable = shutil.which(name)
        if executable is None:
            tools[name] = {"available": False}
            continue
        result = subprocess.run((executable, "--version"),
                                capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError(f"cannot identify {name} toolchain")
        tools[name] = {"available": True,
                       "version": (result.stdout or result.stderr).splitlines()[0]}
    return tools
