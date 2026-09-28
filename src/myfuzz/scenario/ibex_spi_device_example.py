"""Independent Ibex and real OpenTitan SPI Device joined at MMIO and IRQ."""

from __future__ import annotations

from typing import Mapping

from .ibex_session import IbexCpuSession
from .identity import bundle_identity
from .memory import MemoryRegion, PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .spi_device_session import OpenTitanSpiDeviceSession, ROOT


class _FuzzableSpiDeviceSession(OpenTitanSpiDeviceSession):
    """Turn a source action into one external SPI write frame exactly once."""

    max_local_ticks_per_step = 1000

    def __init__(self) -> None:
        super().__init__()
        self._sent_ports: set[str] = set()
        self._last_jedec_read: int | None = None

    def begin_case(self, testcase_id: str) -> None:
        self._sent_ports.clear()
        self._last_jedec_read = None
        super().begin_case(testcase_id)

    def identity_document(self) -> dict:
        document = super().identity_document()
        document["scenario_adapter"] = bundle_identity(
            ROOT, (ROOT / "src/myfuzz/scenario/ibex_spi_device_example.py",))
        return document

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if set(inputs) - {"frame_1", "frame_2", "read_jedec"}:
            raise ValueError("undeclared SPI Device source input")
        for port in ("frame_1", "frame_2", "read_jedec"):
            if port not in inputs or port in self._sent_ports:
                continue
            value = inputs[port]
            if port == "read_jedec":
                if value != 1:
                    raise ValueError("JEDEC read source must request one frame")
                received = self.transfer_bytes(bytes((0x9f,)), read_count=3)
                self._last_jedec_read = int.from_bytes(received, "big")
                self._sent_ports.add(port)
                break
            if type(value) is not int or not 0 <= value < (1 << 32):
                raise ValueError("SPI Device source frame must be 32 bits")
            address = (value >> 8) & 0xffffff
            payload = value & 0xff
            self.transfer_bytes(bytes((0x02, (address >> 16) & 0xff,
                                       (address >> 8) & 0xff, address & 0xff,
                                       payload)))
            self._sent_ports.add(port)
            # The runner retains source inputs. Send another pending frame on
            # its next local step so the declared per-step clock bound holds.
            break
        result = dict(super().step_local({}))
        if self._last_jedec_read is not None:
            result["jedec_read"] = self._last_jedec_read
        return result

    def reset_local(self) -> dict[str, int]:
        outcome = super().reset_local()
        self._sent_ports.clear()
        return outcome


def make_ibex_spi_device_runner() -> ScenarioRunner:
    memory = PersistentMemory(
        regions=(MemoryRegion("ram", 0, 0x20000),),
        initialization_seed=89, max_initialized_bytes=0x20000)
    device = _FuzzableSpiDeviceSession()
    router = DataflowRouter((DeviceWindow("spi_device", 0x40000000,
                                          0x2000, device),))
    cpu = IbexCpuSession(memory=memory, router=router)
    ownership = compile_ownership(
        (InputField("cpu", "irq", 2),
         InputField("spi_device", "frame_1", 32),
         InputField("spi_device", "frame_2", 32),
         InputField("spi_device", "read_jedec", 1)),
        (InputOwner("cpu", "irq", 0, 1, "bound", "spi_device.irq"),
         InputOwner("cpu", "irq", 1, 1, "fixed", "constant_zero"),
         InputOwner("spi_device", "frame_1", 0, 32, "source", "external_spi_master"),
         InputOwner("spi_device", "frame_2", 0, 32, "source", "external_spi_master"),
         InputOwner("spi_device", "read_jedec", 0, 1, "source", "external_spi_master")))
    return ScenarioRunner(
        sessions={"cpu": cpu, "spi_device": device}, ownership=ownership,
        bindings=(Binding("spi_device", "irq", "cpu", "irq", 1),))
