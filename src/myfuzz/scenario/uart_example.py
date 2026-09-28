"""Independent Ibex and OpenTitan UART harnesses joined only by event routing."""

from __future__ import annotations

from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .uart_session import OpenTitanUartSession


def make_ibex_uart_runner() -> ScenarioRunner:
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=73, max_initialized_bytes=0x20000)
    uart = OpenTitanUartSession()
    router = DataflowRouter((DeviceWindow("uart", 0x40000000, 0x1000, uart),))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2), InputField("uart", "uart_rx", 1)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "uart.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("uart", "uart_rx", 0, 1, "source", "external_uart_rx")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "uart": uart}, ownership=ownership,
        bindings=(Binding("uart", "irq", "cpu", "irq", 1),))
