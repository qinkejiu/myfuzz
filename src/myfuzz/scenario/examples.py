"""Importable reference factories for reproducible local RTL evidence."""

from __future__ import annotations

from .gpio_session import OpenTitanGpioSession
from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner


def make_opentitan_gpio_runner() -> ScenarioRunner:
    ownership = compile_ownership(
        (InputField("gpio", "gpio_in", 32),),
        (InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins"),))
    return ScenarioRunner(sessions={"gpio": OpenTitanGpioSession()},
                          ownership=ownership, bindings=())


def make_ibex_two_gpio_runner() -> ScenarioRunner:
    """Independent real Ibex, GPIO A and GPIO B with declared dataflow only."""
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=47, max_initialized_bytes=0x20000)
    gpio_a, gpio_b = OpenTitanGpioSession(), OpenTitanGpioSession()
    router = DataflowRouter((
        DeviceWindow("gpio_a", 0x40001000, 0x1000, gpio_a),
        DeviceWindow("gpio_b", 0x40000000, 0x1000, gpio_b)))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
         InputField("gpio_b", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
         InputOwner("gpio_b", "gpio_in", 0, 8, "bound", "gpio_a.gpio_out"),
         InputOwner("gpio_b", "gpio_in", 8, 24, "fixed", "constant_zero")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "gpio_a": gpio_a, "gpio_b": gpio_b},
        ownership=ownership,
        bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 8),
                  Binding("gpio_b", "irq", "cpu", "irq", 1)))
