"""Shared inputs for the automatic-composition tests.

The example designs under ``examples/soc_generation`` are first-time inputs:
they appear in no myfuzz model table, so every test that uses them is exercising
the profile-driven path rather than a registered component.
"""
from __future__ import annotations

import functools
from pathlib import Path
import subprocess

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_composition import build_composition

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/soc_generation"
PROFILE_NAMES = ("novacore", "novauart", "novagpio")


def profile_paths() -> tuple[Path, ...]:
    return tuple(EXAMPLE / "profiles" / f"{name}.json" for name in PROFILE_NAMES)


def request_path() -> Path:
    return EXAMPLE / "request.json"


@functools.lru_cache(maxsize=1)
def example_profiles() -> dict:
    profiles = {}
    for path in profile_paths():
        profile = load_component_profile(path)
        profiles[str(path.relative_to(ROOT))] = profile
        profiles.setdefault(profile.component_id, profile)
    return profiles


@functools.lru_cache(maxsize=1)
def example_request():
    return load_composition_request(str(request_path()), profiles=example_profiles())


@functools.lru_cache(maxsize=1)
def example_plan():
    return build_composition(example_request(), base_dir=ROOT)


def tools_available() -> bool:
    import shutil

    return shutil.which("verilator") is not None


def profile_tools_available() -> bool:
    """Return whether the profile builder's pinned RFuzz tool is usable."""
    from myfuzz.rfuzz_compat import resolve_rfuzz_verilator, validate_rfuzz_verilator_version

    try:
        tool = resolve_rfuzz_verilator(ROOT, environment={})
        validate_rfuzz_verilator_version(subprocess.check_output(
            [tool, "--version"], text=True, stderr=subprocess.STDOUT))
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return True


__all__ = [
    "EXAMPLE",
    "PROFILE_NAMES",
    "ROOT",
    "example_plan",
    "example_profiles",
    "example_request",
    "profile_paths",
    "profile_tools_available",
    "request_path",
    "tools_available",
]
