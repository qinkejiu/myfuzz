from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from myfuzz.composition.protocol_manifest import load_protocol_composition
from myfuzz.composition.registry import default_component_registry
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.composition.protocol_manifest import validate_protocol_composition


ROOT = Path(__file__).resolve().parents[2]
DESIGN = ROOT / "configs/designs/ibex_protocol_composition"
MANIFEST = DESIGN / "manifest.json"
CHECKER = DESIGN / "scripts/check_local.py"
PLUGIN_DIR = ROOT / "src/myfuzz/protocols/plugins"


class IbexProtocolCompositionConfigTests(unittest.TestCase):
    def test_fixture_declares_the_approved_target_components_protocols_and_runtime(self) -> None:
        document = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(document["schema_version"], "protocol_composition.v1")
        self.assertEqual(document["target"]["kind"], "ibex_core")

        manifest = load_protocol_composition(MANIFEST)
        validate_protocol_composition(
            manifest,
            load_protocol_catalog(PLUGIN_DIR),
            default_component_registry(ROOT),
        )

        self.assertEqual(
            [component.component_id for component in manifest.components],
            ["gpio0", "ram0", "spi0", "timer0", "uart0"],
        )
        self.assertEqual(
            {
                component.component_type for component in manifest.components
            },
            {"ram", "timer", "gpio", "uart", "spi"},
        )
        self.assertEqual(
            {
                (component.protocol_id, component.protocol_version)
                for component in manifest.components
            },
            {("apb", "4"), ("axi4-lite", "1"), ("tl-ul", "1")},
        )
        self.assertEqual(
            {
                component.component_id: (component.base, component.size)
                for component in manifest.components
            },
            {
                "ram0": (0x00000000, 0x10000),
                "timer0": (0x80010000, 0x1000),
                "gpio0": (0x80020000, 0x1000),
                "uart0": (0x80030000, 0x1000),
                "spi0": (0x80040000, 0x1000),
            },
        )
        self.assertEqual(manifest.seed, 7)
        self.assertEqual(manifest.duration_seconds, 3600)
        self.assertEqual(manifest.checkpoint_seconds, 30)

    def test_local_checker_reports_missing_upstream_as_dependency_unavailable(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        upstream = ROOT / "third_party/rfuzz/upstream/ibex"
        if upstream.is_dir():
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn("ok:", result.stdout)
        else:
            self.assertEqual(2, result.returncode, result.stdout + result.stderr)
            self.assertIn(
                "dependency-unavailable: third_party/rfuzz/upstream/ibex",
                result.stdout,
            )


if __name__ == "__main__":
    unittest.main()
