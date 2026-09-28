"""Independent Ibex and real OpenTitan I2C joined by MMIO and IRQ."""

from __future__ import annotations

from typing import Mapping

from .i2c_peer import I2cPeer
from .i2c_session import OpenTitanI2cSession
from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner


class _FuzzableI2cSession(OpenTitanI2cSession):
    """Queue source bytes once, leaving bus timing to the real peer and RTL."""

    def __init__(self) -> None:
        super().__init__()
        self.peer = I2cPeer()
        self.attach_peer(self.peer)
        self._queued_ports: set[str] = set()

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if set(inputs) - {"peer_payload_1", "peer_payload_2"}:
            raise ValueError("undeclared I2C peer input")
        for port in ("peer_payload_1", "peer_payload_2"):
            if port in inputs and port not in self._queued_ports:
                value = inputs[port]
                if type(value) is not int or not 0 <= value <= 0xff:
                    raise ValueError("I2C peer payload must be one byte")
                self.peer.queue_payload(bytes((value,)))
                self._queued_ports.add(port)
        return super().step_local({})

    def reset_local(self) -> dict[str, int]:
        self.peer.reset_case(payload=b"")
        outcome = super().reset_local()
        self._queued_ports.clear()
        return outcome


def make_ibex_i2c_runner() -> ScenarioRunner:
    """Connect Ibex data OBI to I2C and real Controller IRQ to Ibex."""
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=89, max_initialized_bytes=0x20000)
    i2c = _FuzzableI2cSession()
    router = DataflowRouter((DeviceWindow("i2c", 0x40000000, 0x1000, i2c),))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2),
         InputField("i2c", "peer_payload_1", 8),
         InputField("i2c", "peer_payload_2", 8)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "i2c.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("i2c", "peer_payload_1", 0, 8, "source", "external_i2c_peer"),
         InputOwner("i2c", "peer_payload_2", 0, 8, "source", "external_i2c_peer")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "i2c": i2c}, ownership=ownership,
        bindings=(Binding("i2c", "irq", "cpu", "irq", 1,
                          source_bit_offset=9),))
