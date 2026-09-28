"""Pinned source and independent native TL-UL I2C elaboration boundary."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / 'third_party/soc-opentitan'
PROFILE = ROOT / 'configs/peripherals/opentitan_i2c/component_profile.json'
CLOSURE = ROOT / 'configs/soc/closures/opentitan_i2c.json'
LOCK = ROOT / 'configs/soc/sources.lock.json'

class I2cClosureTests(unittest.TestCase):
    def test_pinned_native_elaboration_closure(self):
        profile = json.loads(PROFILE.read_text())
        closure = json.loads(CLOSURE.read_text())
        lock = json.loads(LOCK.read_text())
        source = profile['source']
        self.assertEqual('i2c', source['top_module'])
        self.assertEqual('i2c', closure['top_module'])
        self.assertEqual(0, closure['lint']['exit_code'])
        self.assertEqual(0, closure['lint']['errors'])
        self.assertFalse(closure['boundary']['generated_soc_fabric'])
        self.assertEqual(source['files'], closure['source_files'])
        self.assertEqual(len(source['files']), len(set(source['files'])))
        component = next(c for c in lock['components'] if c['id'] == 'opentitan_i2c')
        self.assertEqual(source['files'], component['source']['files'])
        pinned = {(entry['root'], entry['path']): entry['sha256'] for entry in closure['closure_files']}
        self.assertEqual(len(pinned), len(closure['closure_files']))
        artifacts = {entry['path']: entry['sha256'] for entry in component['artifacts']}
        for relative in source['files']:
            digest = hashlib.sha256((VENDOR / relative).read_bytes()).hexdigest()
            self.assertEqual(digest, pinned[(source['root'], relative)])
            self.assertEqual(digest, artifacts[relative])
        for entry in closure['closure_files']:
            path = ROOT / entry['root'] / entry['path']
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), entry['sha256'])
        wrapper = ROOT / profile['elaboration_boundary']['wrapper']
        digest = hashlib.sha256(wrapper.read_bytes()).hexdigest()
        self.assertEqual(digest, profile['elaboration_boundary']['wrapper_sha256'])
        self.assertEqual(digest, closure['wrapper_elaboration']['sha256'])
        self.assertIn('i2c u_i2c', wrapper.read_text())
        for forbidden in ('crossbar', 'plic', 'soc_bus'):
            self.assertNotIn(forbidden, wrapper.read_text().lower())

if __name__ == '__main__':
    unittest.main()
