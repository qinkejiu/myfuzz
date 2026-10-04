from dataclasses import replace
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from myfuzz.local_harness import load_local_harness_request, plan_local_harness

ROOT = Path(__file__).resolve().parents[2]


def request(path, instance):
    return load_local_harness_request({
        'schema_version': 'local_harness.v1', 'profile_path': path,
        'instance_id': instance, 'reset_assert_ticks': 8,
        'reset_release_ticks': 8, 'max_wait_cycles': 16,
    })


class LocalHarnessPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu_request = request('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
        cls.gpio_request = request('configs/peripherals/pulp_gpio/component_profile.json', 'gpio_a')
        cls.cpu = plan_local_harness(cls.cpu_request, base_dir=ROOT)
        cls.gpio = plan_local_harness(cls.gpio_request, base_dir=ROOT)

    def test_cve2_plan_is_full_and_deterministic(self):
        second = plan_local_harness(self.cpu_request, base_dir=ROOT)
        self.assertEqual(self.cpu.document(), second.document())
        self.assertEqual(self.cpu.facts.selection, 'all')
        self.assertEqual(self.cpu.profile.component_id, 'cv32e20')
        self.assertEqual(self.cpu.document()['scope'], 'single_component')
        self.assertEqual(
            self.cpu.document()['profile_sha256'],
            hashlib.sha256((ROOT / self.cpu_request.profile_path).read_bytes()).hexdigest())
        self.assertEqual(
            self.cpu.document()['protocol_endpoint_ids'],
            ['processor.data', 'processor.instruction'])
        targets = {row['target'] for row in self.cpu.document()['ports']}
        self.assertTrue(targets.isdisjoint({'fabric_target', 'processor_adapter',
            'interrupt_controller', 'clock_reset', 'soc_top'}))

    def test_pulp_gpio_plan_exposes_environment_pin(self):
        self.assertEqual(self.gpio.facts.selection, 'all')
        self.assertEqual(self.gpio.binding.field('gpio.pins', 'in').port, 'gpio_in')
        self.assertEqual(self.gpio.document()['protocol_endpoint_ids'], ['gpio.bus'])
        self.assertTrue(any(row['target'] == 'environment_pin'
                            for row in self.gpio.document()['ports']))

    def test_preserves_full_bit_ledger_and_returns_fresh_documents(self):
        for plan in (self.cpu, self.gpio):
            rows = plan.document()['ports']
            for entry, row in zip(plan.dispositions, rows):
                expected = entry.document()
                del expected['target']
                self.assertEqual(expected, {key: value for key, value in row.items() if key != 'target'})
            for fact in plan.facts.ports:
                bits = [bit for row in rows if row['port'] == fact.name
                        for bit in range(row['bits']['lo'], row['bits']['hi'] + 1)]
                self.assertEqual(sorted(bits), list(range(fact.width)))
            rows[0]['bits']['lo'] = -1
            self.assertGreaterEqual(plan.document()['ports'][0]['bits']['lo'], 0)

    def test_rejects_profile_path_outside_configs(self):
        with self.assertRaises((ValueError, FileNotFoundError)):
            plan_local_harness(self.gpio_request, base_dir=ROOT / 'tests')

    def test_rejects_symlink_escape(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'configs/peripherals/pulp_gpio').mkdir(parents=True)
            (root / self.gpio_request.profile_path).symlink_to(ROOT / self.gpio_request.profile_path)
            with self.assertRaisesRegex(ValueError, 'invalid-profile-path'):
                plan_local_harness(self.gpio_request, base_dir=root)

    def test_profile_identity_uses_the_loaded_byte_snapshot(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / self.gpio_request.profile_path
            path.parent.mkdir(parents=True)
            original = (ROOT / self.gpio_request.profile_path).read_bytes()
            path.write_bytes(original)

            def change_after_load(profile, *, base_dir):
                path.write_bytes(b'{"changed":true}')
                return self.gpio.facts

            with patch('myfuzz.local_harness.plan.elaborate_profile',
                       side_effect=change_after_load):
                plan = plan_local_harness(self.gpio_request, base_dir=root)
            self.assertEqual(plan.profile_sha256, hashlib.sha256(original).hexdigest())

    def test_rejects_declared_only_ibex_top(self):
        with self.assertRaisesRegex(ValueError, 'full-top-required'):
            plan_local_harness(request('configs/cpus/ibex/component_profile.json', 'cpu_0'), base_dir=ROOT)

    def test_rejects_unknown_disposition_target(self):
        entries = (replace(self.gpio.dispositions[0], target='future_target'),)
        with patch('myfuzz.local_harness.plan.elaborate_profile', return_value=self.gpio.facts), \
             patch('myfuzz.local_harness.plan.build_port_dispositions', return_value=entries):
            with self.assertRaisesRegex(ValueError, 'unsupported-local-target'):
                plan_local_harness(self.gpio_request, base_dir=ROOT)

    def test_unclassified_and_overlapping_inputs_fail_closed(self):
        for actions, message in (((), 'undisposed-port-bits'),
                                (self.cpu.profile.port_actions * 2, 'duplicate-port-action')):
            profile = replace(self.cpu.profile, port_actions=actions)
            with patch('myfuzz.local_harness.plan.load_component_profile', return_value=profile), \
                 patch('myfuzz.local_harness.plan.elaborate_profile', return_value=self.cpu.facts):
                with self.assertRaisesRegex(ValueError, message):
                    plan_local_harness(self.cpu_request, base_dir=ROOT)
