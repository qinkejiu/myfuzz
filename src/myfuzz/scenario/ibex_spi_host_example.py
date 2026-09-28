"""Independent Ibex and real OpenTitan SPI Host joined by MMIO and IRQ."""

from __future__ import annotations

from typing import Mapping

from .ibex_session import IbexCpuSession
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .spi_host_session import OpenTitanSpiHostSession
from .spi_peer import SpiPeer


class _FuzzableSpiHostSession(OpenTitanSpiHostSession):
    """Queue each source action once as four peer bytes in wire order."""

    def __init__(self) -> None:
        super().__init__()
        self.peer = SpiPeer()
        self.attach_peer(self.peer)
        self._queued_ports: set[str] = set()

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if set(inputs) - {"peer_payload_1", "peer_payload_2"}:
            raise ValueError("undeclared SPI peer input")
        for port in ("peer_payload_1", "peer_payload_2"):
            if port in inputs and port not in self._queued_ports:
                value = inputs[port]
                if type(value) is not int or not 0 <= value < (1 << 32):
                    raise ValueError("SPI peer payload must be a 32-bit word")
                self.peer.queue_payload(value.to_bytes(4, "little"))
                self._queued_ports.add(port)
        return super().step_local({})

    def reset_local(self) -> dict[str, int]:
        outcome = super().reset_local()
        # Runner.reset_all discards source inputs at the same barrier. Clear
        # the peer's queued source bytes so a later action starts a new epoch.
        self.peer.reset_case(b"")
        self._spi_sd_i = self.peer.sd_i
        self._queued_ports.clear()
        return outcome


def make_ibex_spi_host_runner() -> ScenarioRunner:
    """Connect Ibex data OBI to the Host and Host event IRQ to Ibex."""
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=89, max_initialized_bytes=0x20000)
    spi = _FuzzableSpiHostSession()
    router = DataflowRouter((DeviceWindow("spi", 0x40000000, 0x1000, spi),))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2),
         InputField("spi", "peer_payload_1", 32),
         InputField("spi", "peer_payload_2", 32)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "spi.irq_event"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("spi", "peer_payload_1", 0, 32, "source", "external_spi_peer"),
         InputOwner("spi", "peer_payload_2", 0, 32, "source", "external_spi_peer")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "spi": spi}, ownership=ownership,
        bindings=(Binding("spi", "irq_event", "cpu", "irq", 1),))
