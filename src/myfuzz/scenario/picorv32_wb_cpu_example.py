"""Directed PicoRV32 Wishbone / OpenTitan GPIO custom0 IRQ scenario.

This fixture preserves the existing real RTL acceptance program and ownership.
It supplies a single directed case, not a persistent online campaign.
"""
from __future__ import annotations

from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.opentitan_gpio_session import GeneratedOpentitanGpioSession
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from .genome import Action, MemoryImage, ScenarioGenome, Trigger
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, OwnershipMap, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

ROOT = Path(__file__).resolve().parents[3]
CPU_PROFILE = 'configs/cpus/picorv32_wb_irq/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/opentitan_gpio_local/component_profile.json'
GPIO_BASE = 0x40000000
RESULT = 0x200


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def _addi(rd: int, rs1: int, immediate: int) -> int:
    return (immediate & 0xfff) << 20 | rs1 << 15 | rd << 7 | 0x13


def _lui(rd: int, upper: int) -> int:
    return upper << 12 | rd << 7 | 0x37


def _lw(rd: int, rs1: int, offset: int) -> int:
    return (offset & 0xfff) << 20 | rs1 << 15 | 2 << 12 | rd << 7 | 0x03


def _sw(rs2: int, rs1: int, offset: int) -> int:
    return (((offset >> 5) & 0x7f) << 25 | rs2 << 20 | rs1 << 15 |
            2 << 12 | (offset & 0x1f) << 7 | 0x23)


def _image(words: tuple[int, ...]) -> str:
    return b''.join(word.to_bytes(4, 'little') for word in words).hex()


def _beq(rs1, rs2, offset):
    value = offset & 0x1fff
    return (((value >> 12) & 1) << 31 | ((value >> 5) & 0x3f) << 25 |
            rs2 << 20 | rs1 << 15 |
            ((value >> 1) & 0xf) << 8 | ((value >> 11) & 1) << 7 | 0x63)


def make_picorv32_wb_gpio_irq_genome() -> ScenarioGenome:
    # Custom0 ABI from pinned firmware/custom_ops.S, as exercised by the
    # Wishbone timer acceptance: getq x5,q1; maskirq x0,x1; retirq.
    # q0 holds the return PC; q1 holds the pending vector. No CSR trap ABI.
    words = [0x0800006f] + [0x00000013] * 3  # jal x0,0x80
    words += [
        0x0000c28b,                         # getq x5,q1
        _lw(3, 1, 0x00), _lw(4, 1, 0x10),
        _sw(3, 8, 0), _sw(4, 8, 4), _sw(5, 8, 8),
        _addi(6, 0, 1), _sw(6, 1, 0x00),  # real GPIO W1C
        _lw(7, 1, 0x00), _sw(7, 8, 12),
        _addi(6, 0, 0x55), _sw(6, 8, 16),
        # LATCHED_IRQ defaults to all ones. Mask the one-shot interrupt
        # after clearing GPIO so an IRQ retained during ISR cannot re-enter
        # and overwrite the accepted first observation with zero status.
        _addi(6, 0, -1), 0x0603600b,         # maskirq x0,x6
        0x0400000b,                         # retirq through saved q0
    ]
    words += [0x00000013] * (32 - len(words))
    words += [
        _addi(1, 0, -9), 0x0600e00b,        # enable only custom IRQ bit 3
        _lui(1, GPIO_BASE >> 12), _addi(8, 0, RESULT), _addi(2, 0, 1),
        _sw(2, 1, 0x04),                    # INTR_ENABLE[0]
        _sw(2, 1, 0x2c),                    # INTR_CTRL_EN_RISING[0]
        _sw(2, 1, 0x20),                    # DIRECT_OE[0]
        _sw(2, 1, 0x14),                    # DIRECT_OUT[0] admits pin action
        _lw(2, 8, 16), _beq(2, 0, -4),     # wait for handler completion
        _addi(2, 0, 0x66), _sw(2, 8, 20),  # only after retirq
        0x0000006f,
    ]
    return ScenarioGenome(
        testcase_id='pico-wb-opentitan-gpio-custom-irq', direction='IP_TO_CPU',
        path_id='external-pins-gpio-irq-pico-custom-handler-ram',
        schedule_order=('gpio', 'cpu'), max_steps=1300,
        actions=(Action('external-pin-vector', 'gpio', 'gpio_in', 0x01,
            'IP_TO_CPU', Trigger('AFTER_OUTPUT', 'gpio', 'gpio_out', 1, 1),
            bit_offset=0, width=8),),
        initial_images=(MemoryImage('cpu.program', 'cpu', 0, _image(tuple(words))),
                        MemoryImage('cpu.results', 'cpu', RESULT, bytes(24).hex())))


def picorv32_wb_gpio_irq_ownership() -> OwnershipMap:
    """Return exclusive ownership: external pins and GPIO-bound custom IRQ 3."""
    return compile_ownership(
        (InputField('cpu', 'irq', 32), InputField('gpio', 'gpio_in', 32),
         InputField('gpio', 'strap_en', 1)),
        (InputOwner('cpu', 'irq', 0, 3, 'fixed', 'constant_zero'),
         InputOwner('cpu', 'irq', 3, 1, 'bound', 'gpio.irq'),
         InputOwner('cpu', 'irq', 4, 28, 'fixed', 'constant_zero'),
         InputOwner('gpio', 'gpio_in', 0, 8, 'source', 'external_gpio_pins'),
         InputOwner('gpio', 'gpio_in', 8, 24, 'fixed', 'constant_zero'),
         InputOwner('gpio', 'strap_en', 0, 1, 'fixed', 'constant_zero')))


def make_picorv32_wb_gpio_irq_runner(*, cache_dir: Path) -> ScenarioRunner:
    """Assemble fresh sessions for the pinned Wishbone/GPIO directed case."""
    cpu_art = _artifact(CPU_PROFILE, 'cpu')
    gpio_art = _artifact(GPIO_PROFILE, 'gpio')
    ownership = picorv32_wb_gpio_irq_ownership()
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
        initialization_seed=4, max_initialized_bytes=4096)
    gpio = GeneratedOpentitanGpioSession(gpio_art, base_dir=ROOT,
        cache_dir=cache_dir)
    router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
    cpu = GeneratedWishboneCpuSession(cpu_art, base_dir=ROOT,
        cache_dir=cache_dir, memory=memory, router=router, defer_mmio=True)
    runner = ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
        ownership=ownership,
        bindings=(Binding('gpio', 'irq', 'cpu', 'irq', 1,
                          target_bit_offset=3),))
    return runner
