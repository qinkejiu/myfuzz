"""The CPU -> AXI4-Lite -> real IP chain with the IP driven generically.

The earlier chain test wires the real peripheral through its own
``GeneratedAxiLiteUartSession``.  This one keeps the same CPU and the same
pinned RTL but replaces the IP side with the component-neutral register member
(``axi4lite_register_observe``), which is the artifact kind a v2 plan produces
for any AXI4-Lite slave.  Two things are therefore established at once:

* the CPU side is unchanged and still routes real MMIO beats into the device
  window while leaving RAM addresses alone, and
* the device the CPU reaches is the *generic* member, so the transaction is
  projected by the component-neutral protocol-event layer rather than by an
  IP-specific shell.

What this deliberately does not claim: decoding the serial TX pin through the
generic path.  That needs the generic layer to derive a serial peer from the
declared pins, which is a separate increment; here the device is used as a
register-mapped peripheral.
"""
from __future__ import annotations

import collections
import tempfile
import unittest
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                  render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.axi_lite_session import GeneratedAxiLiteMemorySession
from myfuzz.local_harness.axi4lite_register_session import (
    GeneratedAxi4LiteRegisterSession)
from myfuzz.local_harness.build import build_local_harness
from myfuzz.local_harness.axi4lite_uart_peer_session import (
    GeneratedAxi4LiteUartPeerSession)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.generated_register_factory import (
    create_generated_register_session)
from myfuzz.scenario.ip_protocol_checker import IpProtocolChecker
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/picorv32_axi/component_profile.json'
UART_PROFILE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'

UART_BASE = 0x40000
UART_SIZE = 0x1000
UART_SETUP = 0
UART_RX = 8
UART_TX = 12
TWENTY_FIVE = 25
WRITTEN = 0x41
RAM_ADDRESS = 0x10000


def _cpu_artifact():
    request = load_local_harness_request(dict(
        schema_version='local_harness.v1', profile_path=CPU_PROFILE,
        instance_id='cpu', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def _generic_ip_artifact():
    """The v2 plan whose IP side is the generic AXI4-Lite register member."""
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=UART_PROFILE,
        instance_id='generic_ip', reset_assert_ticks=8, reset_release_ticks=8,
        max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id='uart.bus',
                    template_id='target.axi4-lite', template_version='1',
                    variant_id='single-outstanding-error-codes',
                    max_outstanding=1)],
                'fixed_inputs': [dict(endpoint_id='uart.pins', role='cts_n',
                                      value=0),
                                 dict(endpoint_id='uart.pins', role='rx',
                                      value=1)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class GenericIpCpuChainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-generic-cpu-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.cpu_artifact = _cpu_artifact()
        cls.ip_artifact = _generic_ip_artifact()
        build_local_harness(cls.cpu_artifact, base_dir=ROOT, cache_dir=cls.cache)
        build_local_harness(cls.ip_artifact, base_dir=ROOT, cache_dir=cls.cache)
        cls.trace = cls.ip_artifact.runtime_document['base_protocol_trace']

    def chain(self):
        """Build both harnesses; the IP side is the generic register member."""
        ip = GeneratedAxi4LiteRegisterSession(self.ip_artifact, base_dir=ROOT,
                                             cache_dir=self.cache)
        router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, ip),))
        memory = PersistentMemory(regions=(MemoryRegion('ram', RAM_ADDRESS, 0x20000),),
                                  initialization_seed=7,
                                  max_initialized_bytes=0x10000)
        cpu = GeneratedAxiLiteMemorySession(self.cpu_artifact, base_dir=ROOT,
                                           cache_dir=self.cache, memory=memory,
                                           router=router)
        return cpu, ip, router

    @staticmethod
    def key(sequence):
        return TransactionKey('exec', 'case', 'cpu', 0, 'data', sequence)

    def project(self, ip):
        """Project the generic member's own samples into generic events."""
        normalizer = IpProtocolEventNormalizer(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=self.trace)
        checker = IpProtocolChecker(component_id='zipcpu_axiluart',
            instance_id='uart0', protocol_trace=self.trace)
        events, violations = [], []
        for index, sample in enumerate(ip.drain_tick_samples(), 1):
            for phase in ('pre', 'post'):
                raw = {'event_id': index, 'kind': 'local_tick_sample',
                       'component': 'uart0', 'local_tick': sample['local_tick'],
                       'phase': phase, 'outputs': sample[phase]}
                if phase == 'pre':
                    events.extend(normalizer.consume_local_tick(
                        raw, reset_epoch=ip.reset_epoch))
                violations.extend(checker.consume_local_tick(
                    raw, reset_epoch=ip.reset_epoch))
        return events, violations

    # -- the premise -------------------------------------------------------
    def test_the_ip_side_really_is_the_generic_member(self):
        self.assertEqual('axi4lite_register_observe',
                         self.ip_artifact.runtime_document['kind'])
        self.assertEqual('axi4-lite', self.trace['protocol'])

    # -- the chain ---------------------------------------------------------
    def test_cpu_write_reaches_the_generic_member_and_is_projected(self):
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('generic-ip-cpu-write')
        try:
            self.assertTrue(router.owns(UART_BASE + UART_TX))
            response = cpu._service_accepted_request(
                self.key(1), UART_BASE + UART_TX, True, 1, WRITTEN)
            self.assertEqual(0, response, 'a routed write must acknowledge')
            self.assertEqual(1, cpu.mmio_write_count)
            for _ in range(4):
                ip.step_local({})
            events, violations = self.project(ip)
        finally:
            ip.end_case()
        writes = [row['payload'] for row in events
                  if row['event_type'] == 'transaction_response'
                  and row['payload']['direction'] == 'write']
        self.assertEqual(1, len(writes), 'the routed write must be projected once')
        self.assertEqual(UART_TX, writes[0]['awaddr'])
        self.assertEqual(WRITTEN, writes[0]['wdata'])
        self.assertEqual([], [row['payload']['violation_code']
                              for row in violations])

    def test_cpu_read_returns_the_devices_own_answer_through_the_generic_member(self):
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('generic-ip-cpu-read')
        try:
            # SETUP first, so the device is in a known configuration, then read
            # the RX register whose value only the RTL can produce.
            setup = cpu._service_accepted_request(
                self.key(1), UART_BASE + UART_SETUP, True, 15, TWENTY_FIVE)
            self.assertEqual(0, setup)
            first = cpu._service_accepted_request(
                self.key(2), UART_BASE + UART_RX, False, 0, 0)
            second = cpu._service_accepted_request(
                self.key(3), UART_BASE + UART_RX, False, 0, 0)
            for _ in range(4):
                ip.step_local({})
            events, _ = self.project(ip)
        finally:
            ip.end_case()
        self.assertEqual(2, cpu.mmio_read_count)
        reads = [row['payload'] for row in events
                 if row['event_type'] == 'transaction_response'
                 and row['payload']['direction'] == 'read']
        self.assertEqual(2, len(reads))
        for row, observed in zip(reads, (first, second)):
            self.assertEqual(UART_RX, row['araddr'])
            self.assertEqual(observed, row['rdata'],
                             'the projected read must be the device answer')
        self.assertEqual([UART_SETUP, UART_RX, UART_RX],
                         [row['offset'] for row in router.deliveries])

    def test_a_ram_address_never_reaches_the_generic_member(self):
        """The window must not capture RAM, so the device stays untouched."""
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('generic-ip-cpu-ram')
        try:
            cpu._service_accepted_request(self.key(1), RAM_ADDRESS, True, 15, 0x1234)
            self.assertEqual(0x1234, cpu._service_accepted_request(
                self.key(2), RAM_ADDRESS, False, 0, 0))
            self.assertEqual(0, cpu.mmio_write_count)
            self.assertEqual(0, cpu.mmio_read_count)
            for _ in range(4):
                ip.step_local({})
            events, _ = self.project(ip)
        finally:
            ip.end_case()
        self.assertEqual([], [row for row in events
                              if row['event_type'].startswith('transaction_')],
                         'no device transaction may be projected for a RAM beat')

    def test_the_projected_transactions_name_the_generic_components_endpoint(self):
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('generic-ip-cpu-identity')
        try:
            cpu._service_accepted_request(self.key(1), UART_BASE + UART_TX,
                                          True, 1, WRITTEN)
            for _ in range(4):
                ip.step_local({})
            events, _ = self.project(ip)
        finally:
            ip.end_case()
        self.assertTrue(events)
        for row in events:
            self.assertEqual('uart.bus', row['endpoint_id'])
            self.assertEqual('zipcpu_axiluart', row['component_id'])


def _generic_ip_peer_artifact():
    """The generic member with a declared 8N1 peer on the device's own pins."""
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=UART_PROFILE,
        instance_id='generic_ip_peer', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id='uart.bus',
                    template_id='target.axi4-lite', template_version='1',
                    variant_id='single-outstanding-error-codes',
                    max_outstanding=1)],
                'fixed_inputs': [dict(endpoint_id='uart.pins', role='cts_n',
                                      value=0)],
                'environment_bindings': [dict(endpoint_id='uart.pins', role='rx',
                                              source_id='serial_rx_frame')],
                'uart_8n1_peers': [dict(endpoint_id='uart.pins', rx_role='rx',
                                        tx_role='tx', source_id='serial_rx_frame',
                                        format='8N1', clocks_per_bit=25,
                                        idle_bits=17)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    runtime = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


class GenericSerialIpCpuChainTests(unittest.TestCase):
    """The CPU reaches the device, and the device's *serial* pins are generic.

    The IP side is the component-neutral member with a declared 8N1 peer, so
    both the RX waveform driven into the device and the TX decoding out of it
    come from declared facts rather than an IP-specific shell.
    """

    RX_BYTE = 0x5a
    FRAME_TICKS = 900

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-generic-serial-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.cache = Path(cls.directory.name) / 'cache'
        cls.cpu_artifact = _cpu_artifact()
        cls.ip_artifact = _generic_ip_peer_artifact()
        build_local_harness(cls.cpu_artifact, base_dir=ROOT, cache_dir=cls.cache)
        build_local_harness(cls.ip_artifact, base_dir=ROOT, cache_dir=cls.cache)

    @staticmethod
    def key(sequence):
        return TransactionKey('exec', 'case', 'cpu', 0, 'data', sequence)

    def chain(self):
        ip = create_generated_register_session(self.ip_artifact, base_dir=ROOT,
                                               cache_dir=self.cache)
        self.assertIsInstance(ip, GeneratedAxi4LiteUartPeerSession)
        router = DataflowRouter((DeviceWindow('uart', UART_BASE, UART_SIZE, ip),))
        memory = PersistentMemory(
            regions=(MemoryRegion('ram', RAM_ADDRESS, 0x20000),),
            initialization_seed=7, max_initialized_bytes=0x10000)
        cpu = GeneratedAxiLiteMemorySession(self.cpu_artifact, base_dir=ROOT,
                                           cache_dir=self.cache, memory=memory,
                                           router=router)
        return cpu, ip, router

    def test_the_serial_peer_is_declared_not_named_in_python(self):
        document = self.ip_artifact.runtime_document
        self.assertEqual('axi4lite_register_uart_8n1_peer',
                         document['functional_scope'])
        peer = document['serial_peer']
        self.assertEqual('8N1', peer['format'])
        # The driven pin is owned by the declared frame source, so no Python
        # code had to know which pin of this device is its receive line.
        self.assertEqual('serial_rx_frame', peer['source_id'])

    def test_cpu_write_reaches_the_wire_and_is_decoded_generically(self):
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('cpu-generic-serial-tx')
        try:
            self.assertTrue(router.owns(UART_BASE + UART_TX))
            self.assertEqual(0, cpu._service_accepted_request(
                self.key(1), UART_BASE + UART_TX, True, 1, WRITTEN))
            for _ in range(self.FRAME_TICKS):
                ip.step_local({'uart_rx_byte': self.RX_BYTE})
        finally:
            ip.end_case()
        self.assertIn(WRITTEN, list(ip.peer.captured),
                      'the byte the CPU wrote must be decoded off the real pin')

    def test_an_rx_frame_reaches_the_cpu_through_the_generic_member(self):
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('cpu-generic-serial-rx')
        try:
            for _ in range(self.FRAME_TICKS):
                ip.step_local({'uart_rx_byte': self.RX_BYTE})
            value = cpu._service_accepted_request(
                self.key(1), UART_BASE + UART_RX, False, 0, 0)
        finally:
            ip.end_case()
        self.assertEqual(self.RX_BYTE, value & 0xff,
                         'the supplied frame must reach the CPU as device data')
        self.assertEqual([UART_RX], [row['offset'] for row in router.deliveries])

    def test_both_directions_in_one_case_over_one_connection(self):
        cpu, ip, router = self.chain()
        cpu._case_id = 'case'
        ip.begin_case('cpu-generic-serial-both')
        try:
            self.assertEqual(0, cpu._service_accepted_request(
                self.key(1), UART_BASE + UART_TX, True, 1, WRITTEN))
            for _ in range(self.FRAME_TICKS):
                ip.step_local({'uart_rx_byte': self.RX_BYTE})
            received = cpu._service_accepted_request(
                self.key(2), UART_BASE + UART_RX, False, 0, 0)
        finally:
            ip.end_case()
        self.assertIn(WRITTEN, list(ip.peer.captured))
        self.assertEqual(self.RX_BYTE, received & 0xff)


if __name__ == '__main__':
    unittest.main()
