"""Generated Wishbone UART target with a measured 8N1 serial peer."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from copy import deepcopy
import re

from myfuzz.scenario.uart_peer import Uart8N1Peer

from .session import GeneratedLocalSession


class GeneratedWishboneUartSession(GeneratedLocalSession):
    artifact_kind = 'wishbone_uart'

    def __init__(self, artifact, *, base_dir, cache_dir,
                 source: bytes | None = b'', startup_writes: tuple[tuple[int, int, int], ...] = (),
                 read_rx_after_source: bool = False, cpu_routed_mode: bool = False,
                 **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated Wishbone UART artifact required')
        if source is not None and (not isinstance(source, bytes) or len(source) > 1):
            raise ValueError('UART peer supports at most one source byte')
        if (type(startup_writes) is not tuple or len(startup_writes) > 4
                or any(type(row) is not tuple or len(row) != 3
                       or row not in ((0, 25, 15),)
                       and not (type(row[0]) is int and row[0] == 12
                                and type(row[1]) is int and 0 <= row[1] <= 255
                                and type(row[2]) is int and row[2] == 1)
                       for row in startup_writes)):
            raise ValueError('invalid Wishbone UART startup writes')
        if (type(read_rx_after_source) is not bool
                or read_rx_after_source and source == b''):
            raise ValueError('UART RX read requires a serial source')
        if (type(cpu_routed_mode) is not bool
                or cpu_routed_mode and (source is not None or startup_writes
                                        or read_rx_after_source)):
            raise ValueError('CPU-routed UART requires genome RX and CPU MMIO setup')
        self.source = source
        self.source_mode = 'genome' if source is None else 'constructor'
        self.startup_writes = startup_writes
        self.read_rx_after_source = read_rx_after_source
        self.cpu_routed_mode = cpu_routed_mode
        self.peer = Uart8N1Peer(source or b'')
        self._started = False
        self._rx_read = False
        self._rx_word = 0
        self._samples: deque[dict] = deque()
        self.local_transactions: list[dict[str, int]] = []
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = (1 + (len(startup_writes)
            + int(read_rx_after_source)) * self.max_local_ticks_per_register_access)
        self._dma_target_events: list[dict] = []
        self._dma_target_poisoned = False
        self._dma_target_identity_pin = None

    def identity_document(self):
        return {**super().identity_document(),
                'wb_uart_service_schema_version': ('generated_wb_uart_8n1.v3'
                    if self.cpu_routed_mode else 'generated_wb_uart_8n1.v2'
                    if self.source_mode == 'genome' else 'generated_wb_uart_8n1.v1'),
                'source_component': self.artifact.plan.request.instance_id,
                'source_hex': (self.source or b'').hex(),
                **({'cpu_routed_mode': True} if self.cpu_routed_mode else {}),
                **({'source_mode': 'genome'} if self.source_mode == 'genome' else {}),
                'startup_writes': [list(row) for row in self.startup_writes],
                'read_rx_after_source': self.read_rx_after_source}

    @staticmethod
    def _dma_exact_document(actual, expected):
        if type(actual) is not type(expected):
            return False
        if type(expected) is dict:
            return (set(actual) == set(expected)
                    and all(GeneratedWishboneUartSession._dma_exact_document(
                        actual[name], wanted) for name, wanted in expected.items()))
        if type(expected) in (list, tuple):
            return (len(actual) == len(expected)
                    and all(GeneratedWishboneUartSession._dma_exact_document(
                        left, right) for left, right in zip(actual, expected)))
        return actual == expected

    def _dma_target_identity_components(self):
        """Resolve and validate the artifact-pinned native bus and TX pin."""
        self._check_artifact_stable()
        document = self._artifact_document
        plan = getattr(self.artifact, 'plan', None)
        request = getattr(plan, 'request', None)
        profile = getattr(plan, 'profile', None)
        capabilities = getattr(profile, 'capabilities', None)
        address_profile = getattr(profile, 'address', None)
        digest = document.get('artifact_digest')
        instance_id = getattr(request, 'instance_id', None)
        plan_document = document.get('plan')
        if (document.get('kind') != self.artifact_kind
                or type(digest) is not str
                or re.fullmatch(r'[0-9a-f]{64}', digest) is None
                or type(instance_id) is not str or not instance_id
                or type(plan_document) is not dict
                or plan_document.get('instance_id') != instance_id
                or type(capabilities) is not dict
                or getattr(address_profile, 'window_size', None) != 16):
            raise ValueError('ZipCPU UART DMA provider requires its pinned artifact')
        expected_capabilities = {
            'address_width': 2, 'data_width': 32, 'byte_enable': True,
            'partial_write': True, 'has_error': False,
            'has_address_port': True, 'address_units': 'word',
            'sel_implemented': True, 'wishbone_flavour': 'registered-ack',
            'ack_requires_cyc': True, 'max_outstanding': 1,
        }
        if any(type(capabilities.get(name)) is not type(expected)
               or capabilities.get(name) != expected
               for name, expected in expected_capabilities.items()):
            raise ValueError('ZipCPU UART DMA provider capability identity mismatch')

        if getattr(self, 'startup_writes', None) != ((0, 25, 15),):
            raise ValueError('ZipCPU UART DMA provider requires SETUP 25 startup write')
        if getattr(getattr(self, 'peer', None), 'clocks_per_bit', None) != 25:
            raise ValueError('ZipCPU UART DMA provider requires 25 clocks per bit')

        exports = document.get('physical_exports')
        if type(exports) is not list:
            raise ValueError('ZipCPU UART DMA provider requires physical exports')
        trace = document.get('base_protocol_trace')
        if (type(trace) is not dict
                or trace.get('schema_version') != 'ip_protocol_trace.v1'
                or trace.get('protocol') != 'wishbone'
                or trace.get('endpoint_id') != 'uart.bus'
                or type(trace.get('signals')) is not dict
                or type(trace.get('signal_widths')) is not dict):
            raise ValueError('ZipCPU UART DMA provider requires the pinned Wishbone protocol trace')
        bus_roles = {
            'cyc': 1, 'stb': 1, 'we': 1, 'adr': 2,
            'dat_w': 32, 'sel': 4, 'ack': 1,
        }
        signal_map = trace['signals']
        signal_widths = trace['signal_widths']
        bus_exports = {}
        for role, width in bus_roles.items():
            runtime_name = signal_map.get(role)
            if (type(runtime_name) is not str or not runtime_name
                    or type(signal_widths.get(role)) is not int
                    or signal_widths[role] != width):
                raise ValueError('ZipCPU UART DMA provider Wishbone trace is invalid: ' + role)
            bus_exports[role] = runtime_name
        if len(set(bus_exports.values())) != len(bus_exports):
            raise ValueError('ZipCPU UART DMA provider bus trace signal map is ambiguous')

        pin_rows = [row for row in exports
                    if type(row) is dict and row.get('endpoint_id') == 'uart.pins'
                    and row.get('role') == 'tx']
        if len(pin_rows) != 1:
            raise ValueError('ZipCPU UART DMA provider TX pin export is ambiguous')
        pin = pin_rows[0]
        pin_name = pin.get('runtime_name')
        if (type(pin_name) is not str or not pin_name
                or pin.get('direction') != 'output'
                or type(pin.get('width')) is not int or pin['width'] != 1
                or pin.get('disposition') != 'external'):
            raise ValueError('ZipCPU UART DMA provider TX pin export is invalid')
        if pin_name in bus_exports.values():
            raise ValueError('ZipCPU UART DMA provider signal map reuses a runtime name')
        return document, instance_id, bus_exports, pin_name

    def dma_master_target_provider_identity_document(self):
        """Return the closed identity for one full-word TXREG DMA target."""
        document, instance_id, bus_exports, tx_pin = (
            self._dma_target_identity_components())
        identity = {
            'schema_version': 'zipcpu_uart_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'zipcpu_wbuart_txreg_wishbone_serial.v1',
            'artifact_digest': document['artifact_digest'],
            'instance_id': instance_id,
            'endpoint_id': 'uart.bus',
            'txreg': {
                'operation': 'write', 'offset': 12,
                'accepted_write_values': {
                    'kind': 'range', 'start': 0, 'stop': 256, 'step': 1,
                },
                'byte_enable': 15,
            },
            'startup_writes': [[0, 25, 15]],
            'serial': {
                'endpoint_id': 'uart.pins', 'role': 'tx', 'format': '8N1',
                'clocks_per_bit': 25, 'runtime_name': tx_pin,
            },
            'wishbone_signals': dict(bus_exports),
        }
        pin = getattr(self, '_dma_target_identity_pin', None)
        if pin is None:
            self._dma_target_identity_pin = deepcopy(identity)
        elif not self._dma_exact_document(identity, pin):
            raise ValueError('ZipCPU UART DMA provider identity changed')
        return deepcopy(identity)

    def _dma_target_require_ready(self, source_transaction, *, address, offset,
                                  write, value, byte_enable, delivery_context,
                                  identity):
        from dataclasses import asdict
        from myfuzz.scenario.ledger import TransactionKey

        if type(source_transaction) is not TransactionKey:
            raise ValueError('invalid ZipCPU UART DMA transaction key')
        if (type(write) is not bool or not write
                or type(offset) is not int or offset != 12
                or type(value) is not int or not 0 <= value < 256
                or type(byte_enable) is not int or byte_enable != 15
                or type(address) is not int or address < 0
                or address > 0xffffffff or address % 4):
            raise ValueError('ZipCPU UART DMA provider supports only low-byte TXREG writes')
        if (source_transaction.testcase_id != self._case_id
                or self._case_id is None):
            raise ValueError('ZipCPU UART DMA testcase identity mismatch')
        if type(delivery_context) is not dict:
            raise ValueError('ZipCPU UART DMA delivery context is invalid')
        base = delivery_context.get('window_base')
        size = delivery_context.get('window_size')
        expected_context = {
            'source_transaction': asdict(source_transaction),
            'device_id': identity['instance_id'],
            'address': address, 'offset': offset, 'write': True,
            'value': value, 'be': byte_enable,
            'window_base': base, 'window_size': 16,
        }
        if (type(base) is not int or base < 0 or base > 0xffffffff
                or base % 16 or type(size) is not int or size != 16
                or address != base + offset or address + 4 > base + size
                or not self._dma_exact_document(delivery_context, expected_context)):
            raise ValueError('ZipCPU UART DMA delivery context mismatch')
        if (getattr(self, '_started', False) is not True
                or getattr(self, 'startup_writes', None) != ((0, 25, 15),)
                or not self._dma_exact_document(
                    getattr(self, 'local_transactions', None),
                    [{'offset': 0, 'write_value': 25, 'byte_enable': 15}])
                or getattr(self.peer, 'clocks_per_bit', None) != 25
                or getattr(self.peer, 'captured', None) != []
                or getattr(self.peer, 'start_tick', None) is not None):
            raise ValueError('ZipCPU UART DMA provider requires initialized idle UART')

    def _dma_target_backend_values(self, sample, signal_map, *, phase):
        phase_row = sample.get(phase) if type(sample) is dict else None
        backend = phase_row.get('backend') if type(phase_row) is dict else None
        if type(backend) is not dict:
            raise ValueError('ZipCPU UART DMA tick lacks protocol trace observations')
        widths = {'cyc': 1, 'stb': 1, 'we': 1, 'adr': 2,
                  'dat_w': 32, 'sel': 4, 'ack': 1}
        values = {}
        for role, runtime_name in signal_map.items():
            value = backend.get(runtime_name)
            if (type(value) is not int
                    or not 0 <= value < (1 << widths[role])):
                raise ValueError('ZipCPU UART DMA tick lacks typed Wishbone trace: ' + role)
            values[role] = value
        return values

    def _dma_target_check_uart_pin(self, samples, tx_runtime_name):
        for sample in samples:
            for phase in ('pre', 'post'):
                phase_row = sample.get(phase)
                physical = phase_row.get('physical') if type(phase_row) is dict else None
                value = physical.get(tx_runtime_name) if type(physical) is dict else None
                if type(value) is not int or value not in (0, 1):
                    raise ValueError('ZipCPU UART DMA tick lacks the pinned TX pin')
                if phase == 'post' and value != phase_row.get('uart_tx'):
                    raise ValueError('ZipCPU UART DMA decoder pin differs from artifact TX export')

    def dma_master_target_access(self, source_transaction, *, address, offset,
                                 write, value, byte_enable, delivery_context):
        """Complete one keyed DMA write through TXREG and one measured 8N1 byte."""
        from dataclasses import asdict

        if getattr(self, '_dma_target_poisoned', False):
            raise ValueError('ZipCPU UART DMA target provider is poisoned')
        identity = self.dma_master_target_provider_identity_document()
        self._dma_target_require_ready(source_transaction, address=address,
            offset=offset, write=write, value=value, byte_enable=byte_enable,
            delivery_context=delivery_context, identity=identity)
        events = getattr(self, '_dma_target_events', None)
        if type(events) is not list:
            raise ValueError('ZipCPU UART DMA target event store is unavailable')
        if len(events) >= 65536:
            raise ValueError('ZipCPU UART DMA target evidence capacity exhausted')

        key_document = asdict(source_transaction)
        request = {
            'address': address, 'offset': offset, 'write': True,
            'value': value, 'byte_enable': byte_enable,
        }
        sequence = self._sequence + 1
        access_id = (f'zipcpu-uart-wb:{identity["instance_id"]}:'
                     f'{self._execution}:{self.reset_epoch}:{sequence}')
        command_issued = False
        try:
            sample_start = len(self._samples)
            command_issued = True
            reply = self.command('ACCESS_WB_UART',
                (1, 0, 1, offset, value, byte_enable))
            result = self._take(reply, operation='ACCESS_WB_UART')
            if (type(result) is not dict
                    or type(result.get('rdata')) is not int
                    or result['rdata'] != 0
                    or type(result.get('error')) is not int
                    or result['error'] != 0):
                raise RuntimeError('ZipCPU UART DMA target response was not successful')
            samples = list(self._samples)[sample_start:]
            if not samples:
                raise ValueError('ZipCPU UART DMA target returned no native samples')
            self._dma_target_check_uart_pin(samples, identity['serial']['runtime_name'])

            backend_rows = [sample.get('pre', {}).get('backend')
                            for sample in samples]
            if (any(type(row) is not dict
                    or type(row.get('uart_target_stb')) is not int
                    or row['uart_target_stb'] not in (0, 1)
                    for row in backend_rows)
                    or sum(row['uart_target_stb'] for row in backend_rows) != 1):
                raise ValueError('ZipCPU UART DMA target received duplicate or missing strobe')

            request_rows = []
            ack_rows = []
            for index, sample in enumerate(samples):
                tick = sample.get('local_tick')
                if type(tick) is not int or tick < 0:
                    raise ValueError('ZipCPU UART DMA Wishbone tick identity is invalid')
                pins = self._dma_target_backend_values(
                    sample, identity['wishbone_signals'], phase='pre')
                if pins['cyc'] == 1:
                    if (pins['we'] != 1 or pins['adr'] != 3
                            or pins['dat_w'] != value or pins['sel'] != 15):
                        raise ValueError('ZipCPU UART DMA Wishbone cycle differs from TXREG write')
                elif pins['stb'] == 1 or pins['ack'] == 1:
                    raise ValueError('ZipCPU UART DMA Wishbone STB/ACK is outside CYC')
                if pins['stb'] == 1:
                    if pins['cyc'] != 1:
                        raise ValueError('ZipCPU UART DMA Wishbone STB is outside CYC')
                    request_rows.append((index, tick, pins))
                if pins['ack'] == 1:
                    if pins['cyc'] != 1:
                        raise ValueError('ZipCPU UART DMA Wishbone ACK is outside CYC')
                    ack_rows.append((index, tick, pins))

            if len(request_rows) != 1 or len(ack_rows) != 1:
                raise ValueError('ZipCPU UART DMA Wishbone request or ACK is missing or ambiguous')
            request_index, request_tick, request_pins = request_rows[0]
            response_index, response_tick, response_pins = ack_rows[0]
            if (request_index >= response_index or request_tick >= response_tick
                    or request_pins['we'] != 1 or request_pins['adr'] != 3
                    or request_pins['dat_w'] != value or request_pins['sel'] != 15
                    or response_pins['we'] != 1 or response_pins['adr'] != 3
                    or response_pins['dat_w'] != value or response_pins['sel'] != 15):
                raise ValueError('ZipCPU UART DMA Wishbone ACK does not complete selected TXREG request')

            captured_before = len(self.peer.captured)
            if captured_before != 0:
                raise ValueError('ZipCPU UART DMA serial peer already has TX frames')
            serial_start_tick = self.peer.start_tick
            serial_end_tick = None
            first_frame_tick = None
            max_steps = 2 * 10 * self.peer.clocks_per_bit + self.max_local_ticks_per_register_access + 4
            for _ in range(max_steps):
                sample_before = len(self._samples)
                self.step_local({})
                step_samples = list(self._samples)[sample_before:]
                if len(step_samples) != 1:
                    raise ValueError('ZipCPU UART DMA serial step did not produce one sample')
                self._dma_target_check_uart_pin(
                    step_samples, identity['serial']['runtime_name'])
                if serial_start_tick is None and self.peer.start_tick is not None:
                    serial_start_tick = self.peer.start_tick
                if len(self.peer.captured) > 1:
                    raise ValueError('ZipCPU UART DMA serial peer observed duplicate TX frames')
                if len(self.peer.captured) == 1 and first_frame_tick is None:
                    first_frame_tick = self.peer.last_observed_tick
                    serial_end_tick = self.peer.last_observed_tick
                if (first_frame_tick is not None
                        and self.local_ticks >= first_frame_tick
                            + 10 * self.peer.clocks_per_bit + 1):
                    break
            if (first_frame_tick is None or serial_start_tick is None
                    or serial_end_tick is None or len(self.peer.captured) != 1
                    or self.peer.captured[0] != value
                    or self.peer.start_tick is not None):
                raise ValueError('ZipCPU UART DMA serial byte is missing, duplicate, or mismatched')

            target_request = {
                'schema_version': 'zipcpu_uart_wishbone_dma_request.v1',
                'status': 'observed', 'source_transaction': deepcopy(key_document),
                'access_id': access_id, 'local_tick': request_tick,
                'backend': deepcopy(request_pins),
            }
            target_response = {
                'schema_version': 'zipcpu_uart_wishbone_dma_ack.v1',
                'status': 'observed', 'source_transaction': deepcopy(key_document),
                'access_id': access_id, 'local_tick': response_tick,
                'backend': deepcopy(response_pins),
            }
            target_access = {
                'schema_version': 'zipcpu_uart_dma_target_access.v1',
                'status': 'observed', 'source_transaction': deepcopy(key_document),
                'access_id': access_id,
                'instance_id': identity['instance_id'],
                'endpoint_id': 'uart.bus', 'register': 'TXREG',
                'address': address, 'offset': offset, 'write': True,
                'value': value, 'byte_enable': byte_enable,
                'target_request': deepcopy(target_request),
                'target_response': deepcopy(target_response),
            }
            target_effect = {
                'schema_version': 'zipcpu_uart_txreg_serial_effect.v1',
                'status': 'observed', 'effect': 'txreg_byte_serialized',
                'proof_scope': 'wishbone_ack_and_observed_8n1_tx',
                'source_transaction': deepcopy(key_document),
                'request': deepcopy(request), 'access_id': access_id,
                'endpoint_id': 'uart.pins', 'role': 'tx',
                'serial_byte': value, 'serial_start_tick': serial_start_tick,
                'serial_end_tick': serial_end_tick, 'serial_format': '8N1',
                'clocks_per_bit': self.peer.clocks_per_bit,
            }
            receipt = {
                'schema_version': 'dma_master_target_access.v1',
                'status': 'observed', 'source_transaction': deepcopy(key_document),
                'request': request,
                'response': {'rdata': result['rdata'], 'error': 0},
                'target_access_id': access_id,
                'target_access': target_access,
                'target_request': target_request,
                'target_response': target_response,
                'target_effect': target_effect,
            }
            self._dma_target_events.append(deepcopy(receipt))
            return receipt
        except BaseException as error:
            if command_issued:
                self._dma_target_poisoned = True
                self._dma_target_events.append({
                    'schema_version': 'zipcpu_uart_dma_target_terminal.v1',
                    'kind': 'zipcpu_uart_dma_target_terminal',
                    'status': 'uncertain',
                    'source_transaction': deepcopy(key_document),
                    'request': deepcopy(request),
                    'delivery_context': deepcopy(delivery_context),
                    'command_sequence': sequence, 'access_id': access_id,
                    'error': type(error).__name__ + ': ' + str(error),
                })
            raise

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self.peer.reset_case()
        if self.source_mode == 'genome':
            self.peer.source = b''
        self._started = False
        self._rx_read = False
        self._rx_word = 0
        self._samples.clear()
        self.local_transactions.clear()

    def max_transaction_events_for_step(self, inputs: Mapping[str, int]) -> int:
        if not self._started:
            return len(self.startup_writes)
        return int(self.read_rx_after_source and not self._rx_read
                   and self.local_ticks + 1 >= self.peer.source_end_tick + 50)

    @property
    def pending_responses(self):
        return 0

    @property
    def pending_events(self):
        if not self._started:
            return len(self.startup_writes) + (1 if self.source_mode == 'genome'
                                               else len(self.source))
        return (max(0, self.peer.source_end_tick - self.local_ticks)
                + int((self.read_rx_after_source or self.cpu_routed_mode)
                      and not self._rx_read))

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated Wishbone UART process is not running')

    def _take(self, reply, *, operation):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated Wishbone UART protocol error: '
                               + str(reply.error_code))
        payload = reply.payload
        samples = payload.get('samples')
        if (not isinstance(samples, list) or not 1 <= len(samples) <=
                self.max_local_ticks_per_register_access
                or len(self._samples) + len(samples) > 65536):
            raise ValueError('invalid UART driver tick evidence')
        if operation == 'STEP_WB_UART' and len(samples) != 1:
            raise ValueError('UART step did not advance one tick')
        for sample in samples:
            post = sample['post']
            line = post['uart_tx']
            if type(line) is not int or line not in (0, 1):
                raise ValueError('invalid physical UART TX pin')
            self.peer.observe_tx(sample['local_tick'], line)
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        if operation == 'ACCESS_WB_UART':
            if type(payload['rdata']) is not int or not 0 <= payload['rdata'] <= 0xffffffff:
                raise ValueError('invalid Wishbone UART read data')
            if type(payload['error']) is not int or not 0 <= payload['error'] <= 1:
                raise ValueError('invalid Wishbone UART response')
        return payload

    def drain_tick_samples(self):
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping):
            raise ValueError('UART inputs must be a mapping')
        if self.source_mode == 'genome':
            if (set(inputs) != {'uart_rx_byte'}
                    or type(inputs['uart_rx_byte']) is not int
                    or not 0 <= inputs['uart_rx_byte'] <= 255):
                raise ValueError('UART genome source needs one byte')
            byte = inputs['uart_rx_byte']
            if not self._started:
                self.peer.source = bytes((byte,))
            elif self.peer.source != bytes((byte,)):
                raise ValueError('UART source cannot change after serial frame starts')
        elif inputs:
            raise ValueError('UART peer source is selected at case start')
        if not self._started:
            self._started = True
            for offset, value, be in self.startup_writes:
                self.write_register(offset, value, be=be)
                self.local_transactions.append({'offset': offset, 'write_value': value,
                                                'byte_enable': be})
            # rxuart requires an idle mark for its 16-bit-cell synchronization
            # counter before accepting the first start bit after reset.
            self.peer.start_source(self.local_ticks + 17 * self.peer.clocks_per_bit + 1)
        rx = self.peer.drive_rx(self.local_ticks + 1)
        payload = self._take(self.command('STEP_WB_UART', (rx, 0)),
                             operation='STEP_WB_UART')
        if (self.read_rx_after_source and not self._rx_read
                and self.local_ticks >= self.peer.source_end_tick + 50):
            self._rx_word = self.read_register(8)
            self._rx_read = True
            self.local_transactions.append({'offset': 8, 'read_value': self._rx_word,
                                            'byte_enable': 15})
        return {name: value for name, value in payload['observations'].items()
                if name not in ('backend', 'physical')} | {
            'serial_tx_count': len(self.peer.captured),
            'serial_tx_last': self.peer.captured[-1] if self.peer.captured else 0,
            'serial_rx_read': int(self._rx_read), 'serial_rx_word': self._rx_word}

    @staticmethod
    def _offset(offset):
        if type(offset) is not int or offset not in (0, 4, 8, 12):
            raise ValueError('invalid Wishbone UART register offset')

    def _access(self, write, offset, value, be):
        self._offset(offset)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid Wishbone UART register value')
        if type(be) is not int or not 0 <= be <= 15:
            raise ValueError('invalid Wishbone UART byte strobe')
        if (self.peer.source_start_tick is not None and self.peer.source
                and self.local_ticks < self.peer.source_end_tick
                and self.local_ticks + self.max_local_ticks_per_register_access
                >= self.peer.source_start_tick):
            raise RuntimeError('Wishbone access during serial source waveform is unsupported')
        payload = self._take(self.command('ACCESS_WB_UART',
            (1, 0, int(write), offset, value, be)), operation='ACCESS_WB_UART')
        pre = [sample['pre']['backend'] for sample in payload['samples']]
        if sum(bool(row['uart_target_stb']) for row in pre) != 1:
            raise RuntimeError('Wishbone UART target received duplicate or missing strobe')
        if payload['error']:
            raise RuntimeError('Wishbone UART slave response error')
        return payload['rdata']

    def write_register(self, offset: int, value: int, *, be: int = 15):
        if not ((offset, value, be) == (0, 25, 15)
                or offset == 12 and type(value) is int and 0 <= value <= 255
                and type(be) is int and be == 1):
            raise ValueError('unsupported UART setup, break, or register write')
        self._access(True, offset, value, be)

    def read_register(self, offset: int) -> int:
        value = self._access(False, offset, 0, 15)
        if self.cpu_routed_mode and offset == 8:
            self._rx_word = value
            self._rx_read = True
        return value

    def reset_local(self):
        result = super().reset_local()
        self.peer.reset_case()
        if self.source_mode == 'genome':
            self.peer.source = b''
        self._started = False
        self._rx_read = False
        self._rx_word = 0
        self._samples.clear()
        return result
