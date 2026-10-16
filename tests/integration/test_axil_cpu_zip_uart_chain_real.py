"""Row 3: an AXI4-Lite CPU drives the real ZipCPU axiluart through the router.

This is the path-1 integration for P6 row 3.  Both sides already existed but had
never been connected:

* the CPU side (``picorv32_axi``) now has ``router`` support on
  ``GeneratedAxiLiteMemorySession`` (previous increment), and
* the IP side is ``GeneratedAxiLiteUartSession``, which already implements the
  router's ``RegisterTarget`` protocol (``write_register`` / ``read_register``)
  and drives real AXI4-Lite channel handshakes against the pinned RTL.

The chain pinned here is: a CPU beat whose address falls inside the declared
device window is routed to the real UART target, the target performs a real
AXI4-Lite register transaction, and the observable effect is the RTL's own
result — a TX byte the serial peer decodes, and a read value that comes from the
device rather than from RAM.

These tests build and run pinned RTL.  They do NOT claim a persistent multi-case
session, feedback-driven search, or an ISR path (see the P6 checklist).
"""

import tempfile
import unittest
from pathlib import Path

from myfuzz.local_harness import (
    load_local_harness_request,
    plan_local_harness,
    render_local_harness,
    render_local_runtime,
    verify_local_source_lock,
)
from myfuzz.local_harness.axil_uart_session import GeneratedAxiLiteUartSession
from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/picorv32_axi/component_profile.json'
UART_PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'

UART_BASE = 0x40000
UART_SIZE = 0x1000
# axiluart register window: SETUP=0, FIFO_STATUS=4, RX=8, TX/BREAK=12
UART_SETUP = 0
UART_RX = 8
UART_TX = 12
# The pinned SETUP word this fixture accepts, and one decodable TX byte.
SETUP_25 = 25
TX_BYTE = 0x41


def _artifact(profile: str, instance: str):
    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=profile, instance_id=instance,
        reset_assert_ticks=8, reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class AxiLiteCpuToZipUartChain(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-axil-cpu-uart-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.cpu_artifact = _artifact(CPU_PROFILE, 'cpu')
        cls.uart_artifact = _artifact(UART_PROFILE, 'uart')
        build_local_harness(cls.cpu_artifact, base_dir=ROOT, cache_dir=cls.cache)
        build_local_harness(cls.uart_artifact, base_dir=ROOT, cache_dir=cls.cache)

    def _chain(self):
        """Build the two independent harnesses wired by one router."""
        uart = GeneratedAxiLiteUartSession(self.uart_artifact, base_dir=ROOT,
            cache_dir=self.cache, source=None, cpu_routed_mode=True)
        router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, uart),))
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
            initialization_seed=7, max_initialized_bytes=0x10000)
        cpu = GeneratedAxiLiteMemorySession(self.cpu_artifact, base_dir=ROOT,
            cache_dir=self.cache, memory=memory, router=router)
        return cpu, uart, router

    @staticmethod
    def _key(sequence: int) -> TransactionKey:
        return TransactionKey('exec', 'case', 'cpu', 0, 'data', sequence)

    def test_cpu_side_is_really_the_axi4_lite_artifact(self):
        """Guard the premise: this is the AXI4-Lite CPU, not the OBI one."""
        document = self.cpu_artifact.runtime_document
        self.assertEqual('axi4_lite_cpu', document['kind'])
        self.assertIn('axi4_lite_processor_memory_adapter', self.cpu_artifact.runtime_sv)

    def test_ip_side_exposes_the_register_target_protocol(self):
        """The real UART session must satisfy what the router will call."""
        _, uart, _ = self._chain()
        for method in ('write_register', 'read_register'):
            self.assertTrue(callable(getattr(uart, method, None)), method)

    def test_routed_cpu_write_reaches_real_uart_and_decodes_on_the_wire(self):
        """CPU beat -> router -> real UART RTL -> a byte the peer decodes."""
        cpu, uart, router = self._chain()
        cpu._case_id = 'case'
        uart.begin_case('axil-cpu-uart-real')
        try:
            self.assertTrue(router.owns(UART_BASE + UART_TX))
            # The router delivers to the real target, which performs the real
            # AXI4-Lite register write on the pinned RTL.
            response = cpu._service_accepted_request(
                self._key(1), UART_BASE + UART_TX, True, 1, TX_BYTE)
            self.assertEqual(0, response, 'a routed write must acknowledge')
            self.assertEqual(1, cpu.mmio_write_count)
            # The observable effect is the RTL's own serial output, so the frame
            # has to be clocked out through the target's own local ticks.
            for _ in range(780):
                uart.step_local({'uart_rx_byte': 0x00})
            self.assertEqual([TX_BYTE], list(uart.peer.captured),
                'the routed byte must appear on the real UART TX wire')
        finally:
            uart.end_case()

    def test_routed_cpu_read_returns_device_data_not_ram(self):
        """CPU read -> router -> real UART RTL -> device value (not memory)."""
        cpu, uart, router = self._chain()
        cpu._case_id = 'case'
        uart.begin_case('axil-cpu-uart-read')
        try:
            value = cpu._service_accepted_request(
                self._key(1), UART_BASE + UART_RX, False, 0, 0)
            self.assertEqual(1, cpu.mmio_read_count)
            # RAM holds nothing at that address; the value came from the device.
            self.assertIsInstance(value, int)
            self.assertTrue(0 <= value < 1 << 32)
            self.assertEqual([UART_RX], [row['offset'] for row in router.deliveries])
        finally:
            uart.end_case()

    def test_memory_beat_never_reaches_the_device(self):
        """The window must not capture RAM addresses (no accidental MMIO)."""
        cpu, uart, router = self._chain()
        cpu._case_id = 'case'
        uart.begin_case('axil-cpu-uart-ram')
        try:
            ram_address = 0x10000
            cpu._service_accepted_request(self._key(1), ram_address, True, 15, 0x1234)
            self.assertEqual(0x1234, cpu._service_accepted_request(
                self._key(2), ram_address, False, 0, 0))
            self.assertEqual(0, cpu.mmio_write_count)
            self.assertEqual(0, cpu.mmio_read_count)
            for _ in range(780):
                uart.step_local({'uart_rx_byte': 0x00})
            self.assertEqual([], list(uart.peer.captured))
        finally:
            uart.end_case()


if __name__ == '__main__':
    unittest.main()
