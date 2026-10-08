from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace
import unittest
from myfuzz.local_harness.opentitan_uart_fifo_contract import (
    UART_FIFO_PROBES, uart_fifo_observation_contract)
from tests.local_harness.test_opentitan_uart_source_provenance import session


def fifo_session():
    uart = session()
    uart._artifact_document['plan'] = {'instance_id': 'uart'}
    uart._artifact_document['uart_fifo_observation_contract'] = uart_fifo_observation_contract()
    uart._artifact_document['physical_exports'].extend(
        {'physical_port': 'uart_probe_' + name, 'runtime_name': 'probe_uart_' + name}
        for name in UART_FIFO_PROBES)
    uart.uart_events = []
    uart._active_uart_access = None
    original = uart.command
    def command(operation, fields):
        reply = original(operation, fields)
        reply.execution = 'actual-parser-execution'
        reply.sequence = uart.local_ticks
        for sample in reply.payload['samples']:
            for phase in ('pre', 'post'):
                sample[phase]['physical'].update({'probe_uart_' + name: 0 for name in UART_FIFO_PROBES})
        return reply
    uart.command = command
    return uart


class UartFifoSourceReceiptTests(unittest.TestCase):
    def test_routed_identity_mismatches_reject_before_target_access(self):
        from myfuzz.scenario.ledger import TransactionKey
        key = TransactionKey('execution', 'source-case', 'cpu', 0, 'data', 1)
        address, offset = 0x40000014, 20
        expected = dict(source_transaction=asdict(key), device_id='uart',
            address=address, offset=offset, write=False, value=0, be=15,
            window_base=0x40000000, window_size=4096)
        variations = [(field, replacement) for field, replacement in
            (('source_transaction', asdict(replace(key, testcase_id='other-case'))),
             ('device_id', 'other-uart'), ('address', address + 4),
             ('offset', offset + 4), ('write', True), ('value', 1),
             ('be', 7), ('write', 0), ('be', 15.0),
             ('window_base', 0x40001000), ('window_size', 20),
             ('window_size', 4096.0))]
        variations.extend((field, replacement) for field, replacement in
                          (('unknown', 1), ('source_transaction', {})))
        for field, replacement in variations:
            uart = fifo_session()
            calls = []
            uart.read_register = lambda actual: calls.append(actual) or 0
            context = {**expected, field: replacement}
            with self.subTest(field=field, value=replacement), self.assertRaises(ValueError):
                uart.routed_register_access(key, address=address, offset=offset,
                    write=False, value=0, be=15, delivery_context=context)
            self.assertEqual([], calls)
            self.assertIsNone(getattr(uart, '_routed_uart_transaction', None))

    def test_nonempty_router_context_requires_both_actual_window_bounds(self):
        from myfuzz.scenario.ledger import TransactionKey
        key = TransactionKey('execution', 'source-case', 'cpu', 0, 'data', 1)
        context = dict(source_transaction=asdict(key), device_id='uart',
            address=0x40000014, offset=20, write=False, value=0, be=15)
        uart = fifo_session()
        uart.read_register = lambda offset: 0
        with self.assertRaises(ValueError):
            uart.routed_register_access(key, address=context['address'], offset=20,
                write=False, value=0, be=15, delivery_context=context)

    def test_actual_window_context_survives_detached_native_receipt(self):
        from myfuzz.scenario.ledger import TransactionKey
        key = TransactionKey('execution', 'source-case', 'cpu', 0, 'data', 1)
        context = dict(source_transaction=asdict(key), device_id='uart',
            address=0x4000001c, offset=28, write=True, value=0x5a, be=15,
            window_base=0x40000000, window_size=4096)
        uart = fifo_session()
        calls = []
        def command(operation, fields):
            calls.append((operation, fields))
            uart.local_ticks += 1
            physical = {'rx_pin': 1, **{'probe_uart_' + name: 0 for name in UART_FIFO_PROBES}}
            snapshot = dict(uart_tx=1, physical=physical,
                            backend=dict(uart_req_valid=1, uart_req_ready=1))
            return SimpleNamespace(status='result', execution='unit-receipt', sequence=1,
                payload=dict(samples=[dict(local_tick=1, pre=snapshot, post=deepcopy(snapshot))],
                             rdata=0, error=0))
        uart.command = command
        result = uart.routed_register_access(key, address=context['address'], offset=28,
            write=True, value=0x5a, be=15, delivery_context=context)
        self.assertEqual({'rdata': 0}, result)
        self.assertEqual([('ACCESS_TLUL_UART', (1, 1, 28, 0x5a, 15))], calls)
        access = uart.uart_events[0]['access']
        self.assertEqual('router', access['route_context_mode'])
        self.assertEqual(context, access['delivery_context'])
        self.assertEqual(context['source_transaction'], access['source_transaction'])
        self.assertEqual((0x4000001c, 0x40000000, 4096),
                         (access['address'], access['window_base'], access['window_size']))
        saved = deepcopy(uart.uart_events)
        context['source_transaction']['testcase_id'] = 'mutated'
        context['window_size'] = 4
        self.assertEqual(saved, uart.uart_events)
        self.assertIsNone(uart._routed_uart_context)

    def test_invalid_direct_address_and_transaction_shape_reject_before_access(self):
        from myfuzz.scenario.ledger import TransactionKey
        key = TransactionKey('execution', 'source-case', 'cpu', 0, 'data', 1)
        for kwargs in (
                dict(address=0x40000015), dict(address=True),
                dict(address=0x40000010), dict(offset=True),
                dict(write=0), dict(be=True), dict(be=7),
                dict(source_transaction=asdict(key)),
                dict(source_transaction=replace(key, source_component=1))):
            uart = fifo_session()
            calls = []
            uart.read_register = lambda actual: calls.append(actual) or 0
            arguments = dict(source_transaction=key, address=0x40000014, offset=20,
                             write=False, value=0, be=15, delivery_context={})
            arguments.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                uart.routed_register_access(**arguments)
            self.assertEqual([], calls)

    def test_routed_read_keeps_actual_a_and_d_capture_before_trailing_reply_tick(self):
        from myfuzz.scenario.ledger import TransactionKey
        uart = fifo_session()
        def command(operation, fields):
            samples = []
            for index in range(3):
                uart.local_ticks += 1
                pre = {'rx_pin': 1, **{'probe_uart_' + name: 0 for name in UART_FIFO_PROBES}}
                post = deepcopy(pre)
                if index == 0:
                    pre.update(probe_uart_a_accept=1, probe_uart_tl_a_opcode=4,
                        probe_uart_reg_rdata_re=1, probe_uart_reg_addr=24,
                        probe_uart_fifo_head=0x5a, probe_uart_fifo_rvalid=1)
                    post.update(probe_uart_captured_rdata=0x5a, probe_uart_captured_source=3)
                if index == 1:
                    pre.update(probe_uart_d_accept=1, probe_uart_tl_d_data=0x5a,
                               probe_uart_tl_d_source=3)
                samples.append({'local_tick': uart.local_ticks,
                    'pre': {'uart_tx': 1, 'physical': pre, 'backend': {
                        'uart_req_valid': int(index == 0), 'uart_req_ready': 1}},
                    'post': {'uart_tx': 1, 'physical': post}})
            return SimpleNamespace(status='result', execution='actual-execution', sequence=7,
                payload={'samples': samples, 'rdata': 0x5a, 'error': 0})
        uart.command = command
        key = TransactionKey('execution', 'source-case', 'cpu', 0, 'data', 1)
        result = uart.routed_register_access(key, address=0x40000018, offset=24,
            write=False, value=0, be=15, delivery_context={})
        self.assertEqual(0x5a, result['rdata'])
        fact = next(e for e in uart.uart_events if e['kind'] == 'uart_rdata_access')
        self.assertEqual((1, 2), (fact['request_tick'], fact['response_tick']))
        self.assertEqual(key.source_sequence, fact['source_transaction']['source_sequence'])
        ticks = [e for e in uart.uart_events if e['kind'] == 'uart_tick_observation']
        self.assertEqual(3, ticks[-1]['local_tick'])
        self.assertEqual(fact['access_id'], ticks[0]['access']['access_id'])
        self.assertEqual(0x5a, fact['read_capture']['pre']['probe_uart_fifo_head'])
        self.assertEqual(0x40000018, fact['address'])
        self.assertEqual(0x40000000, fact['window_base'])
        self.assertEqual('direct', fact['route_context_mode'])
        self.assertEqual({}, fact['delivery_context'])

    def test_full_frame_receipts_retain_every_actual_pin_sample(self):
        uart = fifo_session()
        uart.admit_source_event('uart_rx_byte', 0x5a, bit_offset=0, width=8, action_id='original')
        uart.step_local({'uart_rx_byte': 0x5a})
        while uart.local_ticks < uart.peer.source_end_tick:
            uart.step_local({'uart_rx_byte': 0x5a})
        terminals = [e for e in uart.uart_events if e['kind'] == 'uart_frame_validation']
        self.assertEqual(1, len(terminals))
        terminal = terminals[0]
        self.assertTrue(terminal['waveform_matched'])
        self.assertEqual(320, len(terminal['source_drive_refs']))
        ticks = {e['local_tick']: e for e in uart.uart_events if e['kind'] == 'uart_tick_observation'}
        for ref in terminal['source_drive_refs']:
            tick = ticks[ref['drive_tick']]
            self.assertEqual(ref, tick['physical_rx_ref'])
            self.assertEqual(ref['bit_value'], tick['pre']['cio_rx_i'])
            self.assertEqual(ref['bit_value'], tick['post']['cio_rx_i'])
            self.assertEqual(tick['receipt_id'], ref['receipt_id'])
            self.assertIsNone(ref['admission_id'])
        self.assertEqual(10, len(uart.source_events[-1]['bit_witness']))
        saved = deepcopy(terminal)
        uart._artifact_document['physical_exports'][0]['runtime_name'] = 'changed'
        self.assertEqual(saved, terminal)


if __name__ == '__main__': unittest.main()
