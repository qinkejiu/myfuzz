"""A new source-locked profile can generate reviewable local harness files."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/generate_local_harness.py'


class GenerationCliTests(unittest.TestCase):
    def test_generates_deterministic_independent_artifact(self):
        request = dict(schema_version='local_harness.v1',
            profile_path='configs/peripherals/pulp_gpio/component_profile.json',
            instance_id='cli_gpio', reset_assert_ticks=8,
            reset_release_ticks=8, max_wait_cycles=16)
        with tempfile.TemporaryDirectory(prefix='myfuzz-generation-cli-') as directory:
            root = Path(directory)
            request_path = root / 'request.json'
            request_path.write_text(json.dumps(request))
            outputs = []
            for suffix, entry in (
                    ('first', (sys.executable, str(SCRIPT))),
                    ('second', (sys.executable, '-m', 'myfuzz', 'harness', 'generate'))):
                output = root / suffix
                subprocess.run((*entry, '--request',
                    str(request_path), '--output', str(output)),
                    cwd=ROOT, env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
                    check=True, capture_output=True, text=True)
                outputs.append(output)
            names = {'wrapper.sv', 'runtime.sv', 'driver.cpp', 'artifact.json',
                     'abi.json', 'source_verification.json'}
            self.assertEqual(names, {p.name for p in outputs[0].iterdir()})
            self.assertEqual(names, {p.name for p in outputs[1].iterdir()})
            for name in names:
                self.assertEqual((outputs[0] / name).read_bytes(),
                                 (outputs[1] / name).read_bytes())
            artifact = json.loads((outputs[0] / 'artifact.json').read_text())
            self.assertEqual('apb_gpio', artifact['kind'])
            self.assertEqual('driver_generated', artifact['status'])
            self.assertEqual(hashlib.sha256((outputs[0] / 'driver.cpp').read_bytes()).hexdigest(),
                             artifact['cpp_sha256'])
            self.assertEqual(hashlib.sha256((outputs[0] / 'runtime.sv').read_bytes()).hexdigest(),
                             artifact['runtime_sv_sha256'])
            self.assertNotIn('Crossbar', (outputs[0] / 'runtime.sv').read_text())
            rejected = subprocess.run((sys.executable, str(SCRIPT), '--request',
                str(request_path), '--output', str(outputs[0])),
                cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(0, rejected.returncode)
            self.assertEqual(names, {p.name for p in outputs[0].iterdir()})


if __name__ == '__main__':
    unittest.main()
