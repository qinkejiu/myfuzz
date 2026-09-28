"""Independent CVA6 and OpenTitan GPIO local harnesses with an IRQ binding."""

from __future__ import annotations

from .cva6_session import Cva6CpuSession
from .gpio_session import OpenTitanGpioSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner


def make_cva6_gpio_irq_runner() -> ScenarioRunner:
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
        initialization_seed=24, max_initialized_bytes=0x10000)
    gpio = OpenTitanGpioSession()
    router = DataflowRouter((DeviceWindow(
        "gpio", 0x40000000, 0x1000, gpio),))
    cpu = Cva6CpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("gpio", "gpio_in", 0, 32, "source", "external_pins")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "gpio": gpio}, ownership=ownership,
        bindings=(Binding("gpio", "irq", "cpu", "irq", 1),))


def make_cva6_two_gpio_runner() -> ScenarioRunner:
    """Independent CVA6 and two GPIO RTL instances with declared routing."""
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0x80000000, 0x10000),),
        initialization_seed=24, max_initialized_bytes=0x10000)
    gpio_a, gpio_b = OpenTitanGpioSession(), OpenTitanGpioSession()
    router = DataflowRouter((
        DeviceWindow("gpio_a", 0x40001000, 0x1000, gpio_a),
        DeviceWindow("gpio_b", 0x40000000, 0x1000, gpio_b)))
    cpu = Cva6CpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
         InputField("gpio_b", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
         InputOwner("gpio_b", "gpio_in", 0, 8, "bound", "gpio_a.gpio_out"),
         InputOwner("gpio_b", "gpio_in", 8, 24, "source", "external_b")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "gpio_a": gpio_a, "gpio_b": gpio_b},
        ownership=ownership,
        bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 8),
                  Binding("gpio_b", "irq", "cpu", "irq", 1)))
