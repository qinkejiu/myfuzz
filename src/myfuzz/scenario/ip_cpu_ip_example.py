"""Reference external GPIO B → Ibex → GPIO A independent RTL scenario."""

from __future__ import annotations

from .gpio_session import OpenTitanGpioSession
from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner


def make_external_gpio_ibex_gpio_runner() -> ScenarioRunner:
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=53, max_initialized_bytes=0x20000)
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
         InputOwner("gpio_a", "gpio_in", 0, 32, "fixed", "constant_zero"),
         InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_b")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "gpio_a": gpio_a, "gpio_b": gpio_b},
        ownership=ownership,
        bindings=(Binding("gpio_b", "irq", "cpu", "irq", 1),))
