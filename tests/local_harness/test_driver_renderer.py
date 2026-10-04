"""Generated C++ driver against original CVE2 and PULP GPIO RTL."""
from dataclasses import replace
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from myfuzz.local_harness import load_local_harness_request, plan_local_harness, render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.driver_renderer import render_local_driver

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = Path(os.environ.get('MYFUZZ_LOCAL_SOURCE_ROOT', ROOT)).resolve()
EXECUTION = '0123456789abcdef0123456789abcdef'
# The worktree can consume source checkout bytes without copying vendored RTL.
# Load its host wire parser for an independent encoder/decoder integration gate.
_wire_path = SOURCE_ROOT / 'src/myfuzz/local_harness/wire.py'
_wire_spec = importlib.util.spec_from_file_location('_generated_driver_wire_test', _wire_path)
WIRE = importlib.util.module_from_spec(_wire_spec)
sys.modules[_wire_spec.name] = WIRE
_wire_spec.loader.exec_module(WIRE)



def make_top(profile, instance):
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile, instance_id=instance, reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=SOURCE_ROOT)
    return render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=SOURCE_ROOT), base_dir=SOURCE_ROOT)


def cmd(sequence, operation, *fields):
    return f'CMD {EXECUTION} {sequence:x} {operation} ' + ' '.join(f'{field:x}' for field in fields)


def result(line):
    tokens = line.split()
    if tokens[0] != 'RESULT':
        raise AssertionError(line)
    raw = bytes.fromhex(tokens[5]).decode('utf-8')
    payload = json.loads(raw)
    if json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False) != raw:
        raise AssertionError('noncanonical payload')
    receipt = WIRE.parse_driver_receipt(line, execution=tokens[1], sequence=int(tokens[2], 16),
        current_tick=int(tokens[3], 16), kind=payload['kind'])
    return receipt.tick_before, receipt.tick_after, receipt.payload


class DriverRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu = make_top('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
        cls.gpio = make_top('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')

    def test_deterministic_generation_and_header_identity(self):
        for top in (self.cpu, self.gpio):
            driver = render_local_driver(top, base_dir=SOURCE_ROOT)
            self.assertEqual(driver, render_local_driver(top, base_dir=SOURCE_ROOT))
            self.assertEqual('driver_generated', driver.runtime_document['status'])
            self.assertEqual('generated', driver.runtime_document['driver_status'])
            self.assertEqual('local_driver_generation.v1', driver.runtime_document['driver_schema_version'])
            self.assertEqual(top.runtime_sv, driver.runtime_sv)
            self.assertEqual(top.structural, driver.structural)
            self.assertEqual(hashlib.sha256(driver.cpp_text.encode()).hexdigest(), driver.runtime_document['cpp_sha256'])
            for row in driver.runtime_document['driver_header_sources']:
                self.assertEqual(hashlib.sha256((SOURCE_ROOT / row['path']).read_bytes()).hexdigest(), row['sha256'])
            doc = dict(driver.runtime_document)
            digest = doc.pop('artifact_digest')
            self.assertEqual(digest, hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest())
            self.assertIn('BoundedReplay', driver.cpp_text)
            self.assertIn('MYFUZZ_ARTIFACT_DIGEST', driver.cpp_text)

    def test_ready_reports_reset_edges_counted_by_tick(self):
        driver = render_local_driver(self.gpio, base_dir=SOURCE_ROOT)
        self.assertIn('++asserted_ticks;', driver.cpp_text)
        self.assertIn('++released_ticks;', driver.cpp_text)
        self.assertIn('hex_integer(asserted_ticks)', driver.cpp_text)
        self.assertIn('hex_integer(released_ticks)', driver.cpp_text)

    def test_rejects_tampered_or_already_generated_artifacts(self):
        for changed in (replace(self.gpio, runtime_sv=self.gpio.runtime_sv + '// forged'),
                        replace(self.gpio, runtime_document=dict(self.gpio.runtime_document, kind='fake'))):
            with self.assertRaises(ValueError):
                render_local_driver(changed, base_dir=SOURCE_ROOT)
        with self.assertRaises(ValueError):
            render_local_driver(render_local_driver(self.gpio, base_dir=SOURCE_ROOT), base_dir=SOURCE_ROOT)

    def build_driver(self, top, directory):
        artifact = render_local_driver(top, base_dir=SOURCE_ROOT)
        directory = Path(directory)
        structural = directory / 'structural.sv'; structural.write_text(artifact.structural.wrapper_sv)
        runtime = directory / 'runtime.sv'; runtime.write_text(artifact.runtime_sv)
        cpp = directory / 'driver.cpp'; cpp.write_text(artifact.cpp_text)
        argv = list(artifact.runtime_document['lint_argv'])
        argv[argv.index('--lint-only')] = '--cc'
        argv += ['--exe', '--build', '-j', '1', '--Mdir', str(directory / 'obj'),
                 '-CFLAGS', '-std=c++17 -DMYFUZZ_ARTIFACT_DIGEST=' + artifact.runtime_document['artifact_digest'] +
                 ' -I' + str(SOURCE_ROOT / 'src/myfuzz/local_harness/rtl'),
                 str(structural), str(runtime), str(cpp)]
        built = subprocess.run(argv, cwd=SOURCE_ROOT, text=True, capture_output=True, timeout=180)
        self.assertEqual(0, built.returncode, (built.stdout + built.stderr)[-8000:])
        return artifact, directory / 'obj' / ('V' + artifact.runtime_document['module_name'])

    def run_driver(self, binary, commands):
        run = subprocess.run([str(binary)], input='\n'.join(commands + ['END']) + '\n',
                             text=True, capture_output=True, timeout=15)
        self.assertEqual(0, run.returncode, run.stderr)
        self.assertEqual('', run.stderr)
        return run.stdout.splitlines()

    @unittest.skipUnless(shutil.which('verilator') and shutil.which('c++'), 'real Verilator/C++ required')
    def test_real_gpio_access_pulses_wide_values_and_cached_ticks(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-generated-driver-gpio-') as directory:
            artifact, binary = self.build_driver(self.gpio, directory)
            commands = [cmd(1, 'ACCESS_GPIO', 0, 1, 0x0c, 0xa5, 15),
                        cmd(2, 'ACCESS_GPIO', 0, 0, 0x0c, 0, 15),
                        cmd(1, 'ACCESS_GPIO', 0, 1, 0x0c, 0xa5, 15),
                        cmd(3, 'ACCESS_GPIO', 0, 1, 0x04, 1, 15),
                        cmd(4, 'ACCESS_GPIO', 0, 1, 0x18, 1, 15),
                        cmd(5, 'ACCESS_GPIO', 0, 1, 0x1c, 1, 15),
                        cmd(6, 'STEP_GPIO', 1), cmd(7, 'ACCESS_GPIO', 1, 0, 0x24, 0, 15),
                        cmd(8, 'ACCESS_GPIO', 1, 0, 0x24, 0, 15),
                        cmd(9, 'ACCESS_GPIO', 1, 1, 0x0c, 0xffffffff, 1),
                        cmd(10, 'ACCESS_GPIO', 1, 0, 0x0c, 0, 15),
                        cmd(11, 'STEP_CPU', *([0] * 9)), cmd(11, 'STEP_GPIO', 1)]
            lines = self.run_driver(binary, commands)
            self.assertEqual(f"READY local_driver.v1 {artifact.runtime_document['artifact_digest']} 8 8", lines[0])
            replies = lines[1:]
            WIRE.parse_driver_ready(lines[0], digest=artifact.runtime_document['artifact_digest'],
                                    assert_ticks=8, release_ticks=8)
            self.assertEqual(replies[0], replies[2])
            cached = WIRE.parse_driver_receipt(replies[2], execution=EXECUTION, sequence=1,
                current_tick=result(replies[1])[1], kind='apb_gpio', cached=True)
            self.assertEqual(0, cached.new_ticks)
            self.assertEqual(0xa5, result(replies[1])[2]['rdata'])
            self.assertEqual(0xa5, result(replies[10])[2]['rdata'])
            self.assertEqual(1, result(replies[9])[2]['error'])
            self.assertEqual(1, result(replies[7])[2]['rdata'])
            self.assertEqual(0, result(replies[8])[2]['rdata'])  # prior access cleared status
            samples = result(replies[7])[2]['samples']
            self.assertTrue(any(sample[phase]['interrupt'] for sample in samples for phase in ('pre', 'post')))
            for index in (0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 12):
                before, after, payload = result(replies[index])
                self.assertEqual(after - before, len(payload['samples']))
                self.assertEqual(list(range(before + 1, after + 1)), [item['local_tick'] for item in payload['samples']])
                self.assertEqual(32, len(payload['observations']['gpio_padcfg']))
            self.assertIn('invalid_operation wrong_runtime_kind', replies[11])
            self.assertEqual(result(replies[10])[1], result(replies[12])[0])

    @unittest.skipUnless(shutil.which('verilator') and shutil.which('c++'), 'real Verilator/C++ required')
    def test_real_cpu_request_and_unsolicited_response_receipts(self):
        with tempfile.TemporaryDirectory(prefix='myfuzz-generated-driver-cpu-') as directory:
            artifact, binary = self.build_driver(self.cpu, directory)
            rows = self.run_driver(binary, [cmd(1, 'STEP_CPU', 0, 1, 0, 0, 0, 1, 0, 0, 0),
                                           cmd(2, 'STEP_CPU', 0, 0, 0, 0, 0, 0, 1, 0, 0)])
            self.assertEqual(f"READY local_driver.v1 {artifact.runtime_document['artifact_digest']} 8 8", rows[0])
            before, after, payload = result(rows[1])
            self.assertEqual((0, 1), (before, after))
            self.assertEqual(1, payload['pre_backend']['i_req_valid'])
            self.assertEqual(0x10000, payload['pre_backend']['i_req_addr'])
            self.assertTrue(any(isinstance(value, str) and len(value) > 16 for value in payload['observations']['physical'].values()))
            self.assertIn(f'ERROR {EXECUTION} 2 1 protocol_environment unsolicited_response', rows[2])


if __name__ == '__main__':
    unittest.main()
