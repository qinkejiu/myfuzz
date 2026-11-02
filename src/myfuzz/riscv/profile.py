"""Read the minimal RISC-V facts declared by a CPU component profile.

Only the ``cpu`` object is inspected: ``xlen``, ``extensions``,
``instruction_alignment`` and ``reset_vector``.  Register width is derived
(RV32E has 16 registers, every other profile 32).  No ISA/certificate layer is
imported so the module stays usable on its own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

_BASE_EXTENSIONS = ("I", "E")


class ProfileError(ValueError):
    """The profile does not describe a RISC-V CPU this module can target."""


@dataclass(frozen=True, slots=True)
class RiscvProfile:
    """The profile facts instruction generation depends on."""

    xlen: int
    extensions: frozenset[str]
    instruction_alignment: int
    register_count: int
    reset_vector: int
    component_id: str | None = None

    def has(self, extension: str) -> bool:
        """Return whether ``extension`` is declared (upper-case comparison)."""
        return extension.upper() in self.extensions


def _normalize_extensions(raw: object) -> frozenset[str]:
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ProfileError("cpu.extensions must be a list of strings")
    # Unknown future extensions are kept but simply unused by the catalog.
    normalized = frozenset(item.strip().upper() for item in raw if item.strip())
    if not normalized & frozenset(_BASE_EXTENSIONS):
        raise ProfileError("cpu.extensions must declare I or E")
    if len(normalized & frozenset(_BASE_EXTENSIONS)) > 1:
        raise ProfileError("cpu.extensions cannot declare both I and E")
    return normalized


def profile_from_mapping(data: object) -> RiscvProfile:
    """Build a :class:`RiscvProfile` from one decoded component profile."""
    if not isinstance(data, dict):
        raise ProfileError("component profile must be a JSON object")
    cpu = data.get("cpu")
    if not isinstance(cpu, dict):
        raise ProfileError("component profile has no cpu object")
    xlen = cpu.get("xlen")
    if type(xlen) is not int or xlen not in (32, 64):
        raise ProfileError("cpu.xlen must be 32 or 64")
    extensions = _normalize_extensions(cpu.get("extensions", []))
    if "E" in extensions and xlen != 32:
        raise ProfileError("RV32E requires cpu.xlen 32")
    default_alignment = 2 if "C" in extensions else 4
    alignment = cpu.get("instruction_alignment", default_alignment)
    if type(alignment) is not int or alignment not in (2, 4):
        raise ProfileError("cpu.instruction_alignment must be 2 or 4")
    if "C" in extensions and alignment != 2:
        raise ProfileError("the C extension requires instruction_alignment 2")
    reset_vector = cpu.get("reset_vector", 0)
    if type(reset_vector) is not int or not 0 <= reset_vector < 1 << xlen:
        raise ProfileError("cpu.reset_vector must fit cpu.xlen")
    component_id = data.get("component_id")
    return RiscvProfile(
        xlen=xlen,
        extensions=extensions,
        instruction_alignment=alignment,
        register_count=16 if "E" in extensions else 32,
        reset_vector=reset_vector,
        component_id=component_id if isinstance(component_id, str) else None,
    )


def load_profile(path: str | Path) -> RiscvProfile:
    """Load and validate one CPU component profile JSON file."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise ProfileError(f"cannot read profile {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise ProfileError(f"profile {path} is not valid JSON: {error}") from error
    return profile_from_mapping(data)
