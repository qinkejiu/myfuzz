"""Independent Ibex and real OpenTitan RV Timer joined by MMIO and IRQ."""

from __future__ import annotations

from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .rv_timer_session import OpenTitanRvTimerSession


def make_ibex_timer_runner() -> ScenarioRunner:
    """Connect Ibex data OBI to the RV Timer and its IRQ to Ibex."""
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=89, max_initialized_bytes=0x20000)
    timer = OpenTitanRvTimerSession()
    router = DataflowRouter((DeviceWindow("timer", 0x40000000, 0x1000, timer),))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2),),
        (InputOwner("cpu", "irq", 0, 1, "bound", "timer.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "timer": timer}, ownership=ownership,
        bindings=(Binding("timer", "irq", "cpu", "irq", 1),))
