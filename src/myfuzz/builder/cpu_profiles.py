"""Qualified CPU execution profiles for generated AXI-Lite systems."""

from __future__ import annotations

import hashlib

from .contracts import CpuExecutionProfile, RomInstallBackend
from .input_model import InputValidationError


RESET_VECTOR = 0x00002000
ROM_WINDOW = {"base": 0x00000000, "size": 0x00010000}
MAILBOX_WINDOW = {"base": 0x10000000, "size": 0x00001000}
WATCHDOG_WINDOW = {"base": 0x10001000, "size": 0x00001000}

_COMMON_STARTUP = "rv32i-level1-entry-v1: set sp; poll mailbox; execute word access; repeat"


def _fragment_digest(cpu_id: str) -> str:
    return hashlib.sha256(f"{_COMMON_STARTUP}:{cpu_id}".encode("ascii")).hexdigest()


def picorv32_execution_profile() -> CpuExecutionProfile:
    return CpuExecutionProfile(
        cpu_id="picorv32",
        isa="rv32i",
        data_width=32,
        address_width=32,
        reset_vector=RESET_VECTOR,
        rom_window=ROM_WINDOW,
        mailbox_window=MAILBOX_WINDOW,
        watchdog_window=WATCHDOG_WINDOW,
        reset={
            "port": "resetn",
            "active": 0,
            "assertion": "asynchronous",
            "minimum_cycles": 4,
            "execution_domain": "soc",
        },
        rom_install_backend=RomInstallBackend(
            kind="external_rom",
            loader_interface="cpu_initiator_axi_lite_read_only_window",
            verification="sha256_binary_and_first_fetch",
        ).to_dict(),
        startup_fragment_digest=_fragment_digest("picorv32"),
    )


def ultra_riscv_execution_profile() -> CpuExecutionProfile:
    return CpuExecutionProfile(
        cpu_id="ultra_riscv",
        isa="rv32i",
        data_width=32,
        address_width=32,
        reset_vector=RESET_VECTOR,
        rom_window=ROM_WINDOW,
        mailbox_window=MAILBOX_WINDOW,
        watchdog_window=WATCHDOG_WINDOW,
        reset={
            "port": "reset",
            "active": 1,
            "assertion": "asynchronous",
            "minimum_cycles": 4,
            "execution_domain": "soc_and_cpu",
            "loader_requires_cpu_reset": True,
        },
        rom_install_backend=RomInstallBackend(
            kind="pre_reset_tcm_loader",
            loader_interface="axi4_target_single_beat_32",
            verification="axi_readback_and_sha256_binary",
        ).to_dict(),
        startup_fragment_digest=_fragment_digest("ultra_riscv"),
    )


def builtin_cpu_execution_profile(cpu_id: str) -> CpuExecutionProfile:
    factories = {
        "picorv32": picorv32_execution_profile,
        "ultra_riscv": ultra_riscv_execution_profile,
    }
    try:
        return factories[cpu_id]()
    except KeyError as exc:
        raise InputValidationError(f"unknown qualified CPU execution profile {cpu_id!r}") from exc


def builtin_cpu_execution_profiles() -> tuple[CpuExecutionProfile, ...]:
    return tuple(builtin_cpu_execution_profile(cpu_id) for cpu_id in ("picorv32", "ultra_riscv"))
