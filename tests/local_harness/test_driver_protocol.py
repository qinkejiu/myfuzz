"""Compile a real C++ driver to check the generated v1 protocol boundary."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'src/myfuzz/local_harness/rtl/local_driver_v1.h'
EXECUTION = '0123456789abcdef0123456789abcdef'
OTHER = '11111111111111111111111111111111'
DRIVER = r'''
#include "local_driver_v1.h"
#include <iostream>
#include <string>
using namespace myfuzz::local_driver_v1;
int main(int argc, char **argv) {
  const std::size_t capacity = std::stoull(argv[1]);
  const bool oversize = argc > 2 && std::string(argv[2]) == "oversize";
  const bool terminal_error = argc > 2 && std::string(argv[2]) == "error";
  std::size_t reservation = 256;
  BoundedReplay replay(capacity, 512);
  std::uint64_t ticks = 0;
  std::string line;
  while (std::getline(std::cin, line)) {
    if (line.rfind("ACK ", 0) == 0) {
      const auto acknowledgement = parse_ack(line);
      if (!acknowledgement.ok) {
        std::cout << error_reply(acknowledgement.execution, acknowledgement.sequence,
            ticks, acknowledgement.code, acknowledgement.detail) << '\n';
      } else {
        const auto result = replay.retire(acknowledgement.execution,
                                          acknowledgement.sequence);
        if (result.empty())
          std::cout << "ACKED " << acknowledgement.execution << ' '
                    << hex_integer(acknowledgement.sequence) << ' '
                    << hex_integer(ticks) << '\n';
        else
          std::cout << error_reply(acknowledgement.execution,
              acknowledgement.sequence, ticks, result, "ack_rejected") << '\n';
      }
      continue;
    }
    if (line.rfind("RESERVE ", 0) == 0) {
      reservation = std::stoull(line.substr(8));
      continue;
    }
    if (line.rfind("PAYLOAD ", 0) == 0) {
      std::istringstream options(line.substr(8));
      std::size_t size; char last;
      options >> size >> last;
      std::string encoded(size, '0');
      if (!encoded.empty()) encoded.back() = last;
      try {
        const auto decoded = decode_payload_hex(encoded);
        std::cout << "PAYLOAD " << decoded.size() << '\n';
      } catch (const std::invalid_argument &) {
        std::cout << "PAYLOAD invalid" << '\n';
      }
      continue;
    }
    if (line == "STATS") {
      std::cout << "STATE " << ticks << ' ' << replay.retained_bytes() << '\n';
      continue;
    }
    const auto parsed = parse_command(line);
    if (!parsed.ok) {
      std::cout << error_reply(parsed.command.execution, parsed.command.sequence,
                               ticks, parsed.code, parsed.detail) << '\n';
      continue;
    }
    const auto admitted = replay.accept(parsed.command, ticks, reservation);
    if (admitted.decision != Decision::Fresh) {
      std::cout << admitted.reply << '\n';
      continue;
    }
    const auto before = ticks++;
    const auto reply = terminal_error ? error_reply(parsed.command.execution,
        parsed.command.sequence, ticks, "protocol_environment", "driver_fault") : "RESULT " + parsed.command.execution + " " +
        hex_integer(parsed.command.sequence) + " " + hex_integer(before) + " " +
        hex_integer(ticks) + " 00";
    try {
      replay.finish(parsed.command.sequence, oversize ? std::string(257, 'x') : reply);
      std::cout << reply << '\n';
    } catch (const std::exception &) {
      std::cout << error_reply(parsed.command.execution, parsed.command.sequence,
          ticks, "uncertain_effect", "reply_exceeds_reservation") << '\n';
    }
  }
}
'''


def command(sequence=1, operation='STEP_GPIO', fields='0', execution=EXECUTION):
    return f'CMD {execution} {sequence:x} {operation} {fields}'


@unittest.skipUnless(shutil.which('c++'), 'C++ compiler required for protocol tests')
class LocalDriverProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='myfuzz-driver-protocol-')
        cls.addClassCleanup(cls.directory.cleanup)
        source = Path(cls.directory.name) / 'driver.cpp'
        source.write_text(DRIVER)
        cls.binary = Path(cls.directory.name) / 'driver'
        result = subprocess.run(['c++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                                 '-I', str(HEADER.parent), str(source), '-o', str(cls.binary)],
                                capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError('protocol mini-driver failed to compile:\n' + result.stderr)

    def run_driver(self, lines, capacity=4096, oversize=False, terminal_error=False):
        args = [str(self.binary), str(capacity)] + (['oversize'] if oversize else ['error'] if terminal_error else [])
        result = subprocess.run(args, input='\n'.join(lines) + '\n',
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual('', result.stderr)
        return result.stdout.splitlines()

    def test_old_cached_command_after_new_command_does_not_advance_ticks(self):
        lines = self.run_driver([command(), command(2, fields='a5'), command(), 'STATS'])
        self.assertEqual(lines[0], lines[2])
        self.assertEqual(f'RESULT {EXECUTION} 1 0 1 00', lines[0])
        self.assertEqual(f'RESULT {EXECUTION} 2 1 2 00', lines[1])
        self.assertEqual('2', lines[-1].split()[1])

    def test_ack_retires_completed_prefix_and_never_reexecutes_old_sequence(self):
        rows = self.run_driver([command(), command(2), f'ACK {EXECUTION} 1',
                                command(), command(2), command(3), 'STATS'],
                               capacity=410)
        self.assertEqual(f'ACKED {EXECUTION} 1 2', rows[2])
        self.assertEqual(f'ERROR {EXECUTION} 1 2 retired_command replay_rejected', rows[3])
        self.assertEqual(rows[1], rows[4])
        self.assertTrue(rows[5].startswith(f'RESULT {EXECUTION} 3 2 3'))
        self.assertEqual('3', rows[-1].split()[1])

    def test_ack_rejects_unfinished_future_and_wrong_execution(self):
        rows = self.run_driver([f'ACK {EXECUTION} 1', command(),
                                f'ACK {OTHER} 1', f'ACK {EXECUTION} 2',
                                f'ACK {EXECUTION} 1', f'ACK {EXECUTION} 1',
                                command(), 'STATS'])
        self.assertIn('stale_execution', rows[0])
        self.assertIn('stale_execution', rows[2])
        self.assertIn('ack_out_of_order', rows[3])
        self.assertEqual(f'ACKED {EXECUTION} 1 1', rows[4])
        self.assertEqual(rows[4], rows[5])
        self.assertIn('retired_command', rows[6])
        self.assertEqual('STATE 1 0', rows[-1])

    def test_incomplete_receipt_cannot_be_acked_or_reexecuted(self):
        rows = self.run_driver([command(), f'ACK {EXECUTION} 1', command(),
                                'STATS'], oversize=True)
        self.assertIn('uncertain_effect reply_exceeds_reservation', rows[0])
        self.assertIn('ack_incomplete ack_rejected', rows[1])
        self.assertIn('uncertain_effect replay_rejected', rows[2])
        self.assertEqual('1', rows[-1].split()[1])

    def test_malformed_ack_has_no_retirement_effect(self):
        rows = self.run_driver([command(), f'ACK {EXECUTION} 1 ',
                                f'ACK {EXECUTION} 0', command(), 'STATS'])
        self.assertIn('invalid_ack invalid_grammar', rows[1])
        self.assertIn('invalid_sequence invalid_identity', rows[2])
        self.assertEqual(rows[0], rows[3])
        self.assertEqual('1', rows[-1].split()[1])

    def test_conflict_stale_and_out_of_order_errors_have_v1_identity(self):
        lines = self.run_driver([command(), command(fields='1'),
                                 command(2, execution=OTHER), command(3), 'STATS'])
        self.assertEqual(f'ERROR {EXECUTION} 1 1 identity_conflict replay_rejected', lines[1])
        self.assertEqual(f'ERROR {OTHER} 2 1 stale_execution replay_rejected', lines[2])
        self.assertEqual(f'ERROR {EXECUTION} 3 1 out_of_order_command replay_rejected', lines[3])
        self.assertEqual('1', lines[-1].split()[1])

    def test_malformed_lexical_tokens_never_advance(self):
        bad = [command(fields=value) for value in
               ('A', '0x1', '+1', '-1', '100000000', '', '0 extra', '0\t', '0 ')]
        bad += [command(execution='a' * 31), command(execution='A' * 32),
                command(execution='g' * 32), command().replace(' 1 ', ' 0 '),
                command().replace(' 1 ', ' 10000000000000000 '),
                ' ' + command(), command().replace('CMD ', 'CMD  '),
                command(operation='END'), command(fields='0\x00')]
        lines = self.run_driver(bad + ['STATS'])
        self.assertTrue(all(row.startswith('ERROR ') for row in lines[:-1]))
        self.assertEqual('STATE 0 0', lines[-1])
        self.assertIn('ERROR - 0 0 invalid_execution invalid_identity', lines)

    def test_operation_arity_and_field_ranges(self):
        bad = [command(operation='STEP_CPU', fields='0 0 0 0 0 0 0 0'),
               command(operation='STEP_CPU', fields='2 0 0 0 0 0 0 0 0'),
               command(operation='STEP_CPU', fields='0 2 0 0 0 0 0 0 0'),
               command(operation='STEP_CPU', fields='0 0 0 ffffffff 0 0 0 100000000 0'),
               command(operation='ACCESS_GPIO', fields='0 2 0 0 f'),
               command(operation='ACCESS_GPIO', fields='0 1 1000 0 f'),
               command(operation='ACCESS_GPIO', fields='0 1 2 0 f'),
               command(operation='ACCESS_GPIO', fields='0 1 0 0 10')]
        rows = self.run_driver(bad + [command(operation='STEP_CPU',
            fields='1 1 1 ffffffff 1 1 1 ffffffff 1'),
            command(2, operation='ACCESS_GPIO', fields='ffffffff 1 ffc ffffffff f'), 'STATS'])
        self.assertTrue(all(row.startswith('ERROR ') for row in rows[:len(bad)]))
        self.assertTrue(all(row.startswith('RESULT ') for row in rows[len(bad):-1]))
        self.assertEqual('2', rows[-1].split()[1])

    def test_capacity_is_reserved_before_effect_and_rejections_do_not_consume_sequence(self):
        # Original command 1 remains cached; only its actual request+reply bytes remain.
        rows = self.run_driver([command(), 'STATS', command(2), command(), 'STATS'], capacity=360)
        self.assertEqual(f'ERROR {EXECUTION} 2 1 resource_limit replay_capacity', rows[2])
        self.assertEqual(rows[0], rows[3])
        self.assertEqual(rows[1], rows[4])
        rows = self.run_driver([command(), command(), 'STATS'], capacity=1)
        self.assertEqual(rows[0], rows[1])
        self.assertEqual('STATE 0 0', rows[-1])

    def test_oversize_reply_retains_uncertain_entry_and_never_reexecutes(self):
        rows = self.run_driver([command(), command(), 'STATS'], oversize=True)
        self.assertIn('uncertain_effect reply_exceeds_reservation', rows[0])
        self.assertEqual(f'ERROR {EXECUTION} 1 1 uncertain_effect replay_rejected', rows[1])
        self.assertEqual('1', rows[-1].split()[1])

    def test_terminal_error_receipt_is_cached_verbatim(self):
        rows = self.run_driver([command(), command(), 'STATS'], terminal_error=True)
        self.assertEqual(f'ERROR {EXECUTION} 1 1 protocol_environment driver_fault', rows[0])
        self.assertEqual(rows[0], rows[1])
        self.assertEqual('1', rows[-1].split()[1])

    def test_exact_capacity_and_retry_with_smaller_reservation(self):
        capacity = len(command()) + 256
        rows = self.run_driver([command(), command(2), 'RESERVE 64', command(2), 'STATS'],
                               capacity=capacity)
        self.assertTrue(rows[0].startswith('RESULT '))
        self.assertIn('resource_limit replay_capacity', rows[1])
        self.assertEqual(f'RESULT {EXECUTION} 2 1 2 00', rows[2])
        self.assertEqual('2', rows[-1].split()[1])
        rows = self.run_driver(['RESERVE 513', command(), 'STATS'])
        self.assertIn('resource_limit replay_capacity', rows[0])
        self.assertEqual('STATE 0 0', rows[-1])

    def test_payload_hex_limit_matches_one_mib_decoded_limit(self):
        size = 2 * 1024 * 1024
        rows = self.run_driver([f'PAYLOAD {size} f', f'PAYLOAD {size + 2} 0',
                                f'PAYLOAD {size - 1} 0', 'PAYLOAD 2 A',
                                'PAYLOAD 2 g', 'PAYLOAD 0 0'])
        self.assertEqual('PAYLOAD 1048576', rows[0])
        self.assertEqual(['PAYLOAD invalid'] * 5, rows[1:])

    def test_overlong_command_is_rejected_without_allocating_replay_entry(self):
        rows = self.run_driver([command(fields='0' * 4096), 'STATS'])
        self.assertIn('command_too_long', rows[0])
        self.assertEqual('STATE 0 0', rows[-1])


if __name__ == '__main__':
    unittest.main()
