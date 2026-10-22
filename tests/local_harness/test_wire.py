"""Strict host parsing of versioned generated-driver receipts."""
import json
import unittest
from copy import deepcopy

from myfuzz.local_harness.wire import parse_driver_ready, parse_driver_receipt


EXECUTION = '0123456789abcdef0123456789abcdef'
DIGEST = 'a' * 64
NATIVE_TAPS = {
    'cpu_native_trace_valid': 1, 'cpu_native_trace_addr': 32,
    'cpu_native_trace_wdata': 32, 'cpu_native_trace_wstrb': 4,
    'cpu_native_trace_ready': 1, 'cpu_native_trace_rdata': 32,
}


def result_payload(ticks=(1,)):
    return {
        'schema_version': 'local_driver_result.v1', 'kind': 'apb_gpio',
        'samples': [{'local_tick': tick, 'pre': {}, 'post': {}} for tick in ticks],
        'observations': {}, 'pre_backend': {}, 'rdata': 0, 'error': 0,
    }


def result_line(payload, before=0, after=1):
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return f'RESULT {EXECUTION} 1 {before:x} {after:x} {raw.hex()}'


class GeneratedWireTests(unittest.TestCase):
    def test_native_tap_contract_accepts_exact_pre_and_post_values(self):
        payload = result_payload()
        payload['kind'] = 'native_memory_cpu'
        taps = {name: (1 << width) - 1 for name, width in NATIVE_TAPS.items()}
        for phase in ('pre', 'post'):
            payload['samples'][0][phase]['protocol_taps'] = dict(taps)
        receipt = parse_driver_receipt(result_line(payload), execution=EXECUTION,
            sequence=1, current_tick=0, kind='native_memory_cpu', native_taps=NATIVE_TAPS)
        self.assertEqual(taps, receipt.payload['samples'][0]['pre']['protocol_taps'])

    def test_native_tap_contract_refuses_missing_extra_or_invalid_values_in_each_phase(self):
        payload = result_payload()
        payload['kind'] = 'native_memory_cpu'
        for phase in ('pre', 'post'):
            payload['samples'][0][phase]['protocol_taps'] = {name: 0 for name in NATIVE_TAPS}
        mutations = (
            lambda taps: taps.pop('cpu_native_trace_ready'),
            lambda taps: taps.update(cpu_native_trace_alias=0),
            lambda taps: taps.update(cpu_native_trace_valid=True),
            lambda taps: taps.update(cpu_native_trace_valid=2),
            lambda taps: taps.update(cpu_native_trace_addr=1 << 32),
            lambda taps: taps.update(cpu_native_trace_wstrb=16),
            lambda taps: taps.update(cpu_native_trace_rdata='0'),
        )
        for phase in ('pre', 'post'):
            for mutation in mutations:
                broken = deepcopy(payload)
                mutation(broken['samples'][0][phase]['protocol_taps'])
                with self.subTest(phase=phase, mutation=mutation), self.assertRaises(ValueError):
                    parse_driver_receipt(result_line(broken), execution=EXECUTION,
                        sequence=1, current_tick=0, kind='native_memory_cpu',
                        native_taps=NATIVE_TAPS)
            broken = deepcopy(payload)
            del broken['samples'][0][phase]['protocol_taps']
            with self.subTest(phase=phase, mutation='group absent'), self.assertRaises(ValueError):
                parse_driver_receipt(result_line(broken), execution=EXECUTION,
                    sequence=1, current_tick=0, kind='native_memory_cpu',
                    native_taps=NATIVE_TAPS)

    def test_native_tap_contract_preserves_legacy_and_error_receipts(self):
        payload = result_payload()
        payload['kind'] = 'native_memory_cpu'
        parse_driver_receipt(result_line(payload), execution=EXECUTION, sequence=1,
            current_tick=0, kind='native_memory_cpu')
        parse_driver_receipt(result_line(result_payload()), execution=EXECUTION,
            sequence=1, current_tick=0, kind='apb_gpio')
        receipt = parse_driver_receipt(
            f'ERROR {EXECUTION} 1 0 protocol_environment driver_fault',
            execution=EXECUTION, sequence=1, current_tick=0,
            kind='native_memory_cpu', native_taps=NATIVE_TAPS)
        self.assertEqual('error', receipt.status)

    def test_ready_requires_exact_artifact_and_reset_ticks(self):
        receipt = parse_driver_ready(f'READY local_driver.v1 {DIGEST} 8 4',
                                     digest=DIGEST, assert_ticks=8, release_ticks=4)
        self.assertEqual((8, 4), (receipt.assert_ticks, receipt.release_ticks))
        for line in (f'READY local_driver.v1 {"b"*64} 8 4',
                     f'READY local_driver.v1 {DIGEST} 7 4',
                     f'READY local_driver.v1 {DIGEST} 8 4 extra',
                     f'READY local_driver.v2 {DIGEST} 8 4'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                parse_driver_ready(line, digest=DIGEST, assert_ticks=8, release_ticks=4)

    def test_result_checks_identity_ticks_schema_and_canonical_json(self):
        receipt = parse_driver_receipt(result_line(result_payload()),
                                       execution=EXECUTION, sequence=1,
                                       current_tick=0, kind='apb_gpio')
        self.assertEqual((0, 1), (receipt.tick_before, receipt.tick_after))
        self.assertEqual(1, len(receipt.payload['samples']))
        self.assertEqual('result', receipt.status)
        bad = [result_line(result_payload(ticks=()), after=1),
               result_line(result_payload(ticks=(2,)), after=1),
               result_line({**result_payload(), 'kind': 'obi_cpu'}),
               result_line({**result_payload(), 'schema_version': 'other'}),
               result_line(result_payload(), before=1, after=2),
               result_line(result_payload()).replace(f' {EXECUTION} ', f' {"b"*32} ')]
        for line in bad:
            with self.subTest(line=line[:100]), self.assertRaises(ValueError):
                parse_driver_receipt(line, execution=EXECUTION, sequence=1,
                                     current_tick=0, kind='apb_gpio')
        unsorted = json.dumps(result_payload(), separators=(',', ':')).encode().hex()
        with self.assertRaisesRegex(ValueError, 'canonical'):
            parse_driver_receipt(f'RESULT {EXECUTION} 1 0 1 {unsorted}',
                                 execution=EXECUTION, sequence=1,
                                 current_tick=0, kind='apb_gpio')

    def test_error_receipt_keeps_tick_and_identity(self):
        receipt = parse_driver_receipt(f'ERROR {EXECUTION} 2 5 protocol_environment driver_fault',
                                       execution=EXECUTION, sequence=2,
                                       current_tick=5, kind='apb_gpio')
        self.assertEqual(('error', 'protocol_environment', 5),
                         (receipt.status, receipt.error_code, receipt.tick_after))
        for line in (f'ERROR {EXECUTION} 2 4 protocol_environment driver_fault',
                     f'ERROR {EXECUTION} 3 5 protocol_environment driver_fault',
                     f'ERROR {EXECUTION} 2 5 bad code extra'):
            with self.assertRaises(ValueError):
                parse_driver_receipt(line, execution=EXECUTION, sequence=2,
                                     current_tick=5, kind='apb_gpio')

    def test_cached_reply_does_not_advance_current_ticks(self):
        line = result_line(result_payload(), before=0, after=1)
        receipt = parse_driver_receipt(line, execution=EXECUTION, sequence=1,
                                       current_tick=3, kind='apb_gpio', cached=True)
        self.assertEqual(0, receipt.new_ticks)
        with self.assertRaises(ValueError):
            parse_driver_receipt(line, execution=EXECUTION, sequence=1,
                                 current_tick=3, kind='apb_gpio')

    def test_multiclock_trace_requires_exact_per_domain_rising_edge_counts(self):
        schedule = {
            'schema_version': 'local_clock_schedule.v1',
            'startup_fast_ticks': 1,
            'clocks': [
                {'domain': 'core', 'ratio': 1, 'first_rising_fast_tick': 1},
                {'domain': 'aon', 'ratio': 4, 'first_rising_fast_tick': 2},
            ],
        }
        payload = result_payload()
        payload['samples'][0]['clock_edges'] = {'core': 1, 'aon': 1}
        line = result_line(payload)
        parsed = parse_driver_receipt(line, execution=EXECUTION, sequence=1,
            current_tick=0, kind='apb_gpio', clock_schedule=schedule)
        self.assertEqual({'core': 1, 'aon': 1},
                         parsed.payload['samples'][0]['clock_edges'])

        payload['samples'][0]['clock_edges']['aon'] = 0
        with self.assertRaisesRegex(ValueError, 'edge-count-mismatch'):
            parse_driver_receipt(result_line(payload), execution=EXECUTION,
                sequence=1, current_tick=0, kind='apb_gpio', clock_schedule=schedule)

    def test_single_clock_schedule_keeps_legacy_sample_wire_shape(self):
        schedule = {
            'schema_version': 'local_clock_schedule.v1',
            'startup_fast_ticks': 8,
            'clocks': [
                {'domain': 'core', 'ratio': 1, 'first_rising_fast_tick': 1},
            ],
        }
        receipt = parse_driver_receipt(result_line(result_payload()),
            execution=EXECUTION, sequence=1, current_tick=0,
            kind='apb_gpio', clock_schedule=schedule)
        self.assertEqual({'local_tick', 'pre', 'post'},
                         set(receipt.payload['samples'][0]))

    def test_nonfinite_duplicate_and_negative_signal_values_refuse(self):
        bad_payloads = [
            {**result_payload(), 'observations': {'signal': float('nan')}},
            {**result_payload(), 'observations': {'signal': -1}},
            {**result_payload(), 'observations': {'signal': True}},
        ]
        for payload in bad_payloads:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_driver_receipt(result_line(payload), execution=EXECUTION,
                                     sequence=1, current_tick=0, kind='apb_gpio')
        duplicate = (b'{"error":0,"error":0,"kind":"apb_gpio","observations":{},'
                     b'"pre_backend":{},"rdata":0,"samples":[{"local_tick":1,'
                     b'"post":{},"pre":{}}],"schema_version":"local_driver_result.v1"}').hex()
        with self.assertRaises(ValueError):
            parse_driver_receipt(f'RESULT {EXECUTION} 1 0 1 {duplicate}',
                                 execution=EXECUTION, sequence=1,
                                 current_tick=0, kind='apb_gpio')
