"""Independent Ibex, OpenTitan UART and GPIO RTL joined by dataflow routing."""

from __future__ import annotations

from .gpio_session import OpenTitanGpioSession
from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .uart_session import OpenTitanUartSession


def make_ibex_uart_rx_gpio_runner() -> ScenarioRunner:
    """Route real UART IRQ/RDATA to Ibex and its real MMIO writes to GPIO."""
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=79, max_initialized_bytes=0x20000)
    uart, gpio = OpenTitanUartSession(), OpenTitanGpioSession()
    router = DataflowRouter((
        DeviceWindow("uart", 0x40000000, 0x1000, uart),
        DeviceWindow("gpio", 0x40001000, 0x1000, gpio)))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("uart", "uart_rx", 1),
         InputField("gpio", "gpio_in", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "uart.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("uart", "uart_rx", 0, 1, "source", "external_uart_rx"),
         InputOwner("gpio", "gpio_in", 0, 32, "fixed", "constant_zero")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "uart": uart, "gpio": gpio},
        ownership=ownership,
        bindings=(Binding("uart", "irq", "cpu", "irq", 1),))
