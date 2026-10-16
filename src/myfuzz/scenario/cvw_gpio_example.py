"""Static directed CVW-to-PULP GPIO fixture; no online instruction admission.

The complete trusted initial image is installed before session construction.
Unlike an online fragment, this boot program includes branch and halt opcodes.
Code and speculative I-cache line fills stay far below the MMIO carveout.
"""
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.integration.cvw_pulp_online import cvw_pulp_gpio_wiring
from .memory import PersistentMemory
from .router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[3]
BOOT_BASE = 0xC0000000
BOOT_BYTES = 256
RESULT = BOOT_BASE + 0x400


def _addi(rd, rs1, value):
    return (value & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _sw(rs2, rs1, offset):
    return ((offset >> 5) & 127) << 25 | rs2 << 20 | rs1 << 15 | 2 << 12 | (offset & 31) << 7 | 0x23


def _lw(rd, rs1, offset):
    return offset << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _bne(rs1, rs2, offset):
    value = offset & 0x1fff
    return ((value >> 12) & 1) << 31 | ((value >> 5) & 63) << 25 | rs2 << 20 | rs1 << 15 | 1 << 12 | ((value >> 1) & 15) << 8 | ((value >> 11) & 1) << 7 | 0x63


def cvw_gpio_program(*, gpio_base=0xCFFF0000) -> bytes:
    """Two output readbacks and one external input gate the success store."""
    if type(gpio_base) is not int or gpio_base < 0 or gpio_base > 0xfffff000 or gpio_base % 0x1000:
        raise ValueError('GPIO program base must be aligned RV32 address')
    words = [
        gpio_base | 1 << 7 | 0x37,  # lui x1, GPIO page
        BOOT_BASE | 8 << 7 | 0x37,
        _addi(8, 8, 0x400), _addi(2, 0, -1),
        _sw(2, 1, 0), _sw(2, 1, 4),  # PADDIR, GPIOEN
        _addi(2, 0, 0x35), _sw(2, 1, 12),
        _lw(3, 1, 12), _sw(3, 8, 0), _bne(3, 2, (23-10)*4),
        _addi(2, 0, 0x6A), _sw(2, 1, 12),
        _lw(3, 1, 12), _sw(3, 8, 4), _bne(3, 2, (23-15)*4),
        _lw(5, 1, 8), _sw(5, 8, 12),
        _addi(2, 0, 0xA5), _bne(5, 2, (23-19)*4),
        _addi(4, 0, 1), _sw(4, 8, 8), 0x0000006F,
        _addi(4, 0, -1), _sw(4, 8, 8), 0x0000006F,
    ]
    words += [0x00000013] * (BOOT_BYTES // 4 - len(words))
    return b''.join(word.to_bytes(4, 'little') for word in words)


def _artifact(profile, instance, *, physical_observations=False):
    request = load_local_harness_request(dict(schema_version=('local_harness.v2'
        if physical_observations else 'local_harness.v1'),
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16,
        **({'tuning': {'raw_tick_stream': [{'sampling': 'pre_post'}]}}
           if physical_observations else {})))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def make_cvw_gpio_chain(*, cache_dir: Path, gpio_base=None):
    """Return unstarted real sessions/router/memory with complete static boot.

    gpio_base=0 is reserved for the negative old-layout control. The positive
    layout is read from the repaired family declaration.
    """
    wiring = cvw_pulp_gpio_wiring()
    base = wiring.window_base if gpio_base is None else gpio_base
    cpu_art = _artifact(wiring.cpu_profile, 'cpu')
    gpio_art = _artifact(wiring.gpio_profile, 'gpio', physical_observations=True)
    memory = PersistentMemory(regions=wiring.memory_regions,
        initialization_seed=17, max_initialized_bytes=0x10000)
    # This is an initial-image interface, not the online ISA fragment interface.
    # All four padded cache lines exist before the boot word can be released.
    memory.preload(BOOT_BASE, cvw_gpio_program(gpio_base=base))
    memory.preload(RESULT, bytes(16))
    gpio = GeneratedPulpGpioSession(gpio_art, base_dir=ROOT, cache_dir=cache_dir)
    router = DataflowRouter((DeviceWindow('gpio', base, wiring.window_size, gpio),))
    cpu = GeneratedAhbMemorySession(cpu_art, base_dir=ROOT, cache_dir=cache_dir,
                                     memory=memory, router=router)
    return cpu, gpio, router, memory
