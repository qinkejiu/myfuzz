from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from myfuzz.composition.protocol_composer import (
    compose_protocol_composition,
    write_protocol_composition,
)
from myfuzz.composition.protocol_manifest import (
    load_protocol_composition,
    validate_protocol_composition,
)
from myfuzz.composition.registry import default_component_registry
from myfuzz.protocols.catalog import load_protocol_catalog
from tests.composition.test_protocol_manifest import approved_manifest


ROOT = Path(__file__).resolve().parents[2]
PLUGIN_DIR = ROOT / "src" / "myfuzz" / "protocols" / "plugins"


class ProtocolComposerTests(unittest.TestCase):
    def materialize_root(self, directory: Path, *, upstream: bool = True) -> Path:
        for relative_path in (
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_ram.sv",
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_timer.sv",
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_gpio.sv",
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_uart.sv",
            "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_spi.sv",
            "src/myfuzz/protocols/rtl/apb4_mmio_bridge.sv",
            "src/myfuzz/protocols/rtl/apb4_mmio_target.sv",
            "src/myfuzz/protocols/rtl/axi4_lite_mmio_bridge.sv",
            "src/myfuzz/protocols/rtl/axi4_lite_mmio_target.sv",
            "src/myfuzz/protocols/rtl/tl_ul_mmio_bridge.sv",
            "src/myfuzz/protocols/rtl/tl_ul_mmio_target.sv",
        ):
            destination = directory / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative_path, destination)
        shutil.copytree(PLUGIN_DIR, directory / "src/myfuzz/protocols/plugins")
        if upstream:
            source_list = directory / "third_party/rfuzz/upstream/ibex/sources.f"
            source_list.parent.mkdir(parents=True, exist_ok=True)
            source_list.write_text("# test Ibex source list\n", encoding="utf-8")
        return directory

    def write_manifest(self, directory: Path, document: dict | None = None) -> Path:
        path = directory / "manifest.json"
        path.write_text(
            json.dumps(approved_manifest() if document is None else document, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return path

    def load_manifest(self, path: Path, root: Path = ROOT):
        manifest = load_protocol_composition(path)
        validate_protocol_composition(
            manifest,
            load_protocol_catalog(root / "src/myfuzz/protocols/plugins"),
            default_component_registry(root),
        )
        return manifest

    def test_composes_stable_path_free_ir_and_wrapper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_root(root)
            manifest_path = self.write_manifest(root)
            output_one = root / "out-one"
            output_two = root / "out-two"
            manifest = self.load_manifest(manifest_path, root)

            first = compose_protocol_composition(manifest, output_one, root=root)
            second = compose_protocol_composition(manifest, output_two, root=root)

            self.assertEqual(first.ir, second.ir)
            self.assertEqual(first.content_hash, second.content_hash)
            self.assertEqual(first.source_hash, second.source_hash)
            self.assertEqual(
                first.wrapper_path.read_bytes(),
                second.wrapper_path.read_bytes(),
            )
            first_source_list = first.source_list_path.read_text(encoding="utf-8")
            second_source_list = second.source_list_path.read_text(encoding="utf-8")
            self.assertEqual(
                first_source_list.replace(output_one.as_posix(), "<output>"),
                second_source_list.replace(output_two.as_posix(), "<output>"),
            )
            self.assertEqual(first.ir["schema_version"], "composition_ir.v1")
            self.assertEqual(len(first.ir["instances"]), 5)
            self.assertEqual(len(first.ir["address_regions"]), 5)
            self.assertEqual(
                {item["kind"] for item in first.ir["adapters"]},
                {"apb4", "axi4-lite", "tl-ul"},
            )
            self.assertEqual(len(first.ir["clock_domains"]), 1)
            self.assertEqual(len(first.ir["reset_domains"]), 1)
            self.assertEqual(
                [item["component_id"] for item in first.ir["endpoint_bindings"]],
                ["gpio0", "ram0", "spi0", "timer0", "uart0"],
            )

            wrapper = first.wrapper_path.read_text(encoding="utf-8")
            self.assertIn("module ibex_protocol_composition_top", wrapper)
            self.assertIn("ibex_core", wrapper)
            for module in (
                "ibex_mcip_ram",
                "ibex_mcip_timer",
                "ibex_mcip_gpio",
                "ibex_mcip_uart",
                "ibex_mcip_spi",
                "apb4_mmio_bridge",
                "apb4_mmio_target",
                "axi4_lite_mmio_bridge",
                "axi4_lite_mmio_target",
                "tl_ul_mmio_bridge",
                "tl_ul_mmio_target",
            ):
                self.assertIn(module, wrapper)
            self.assertIn("irq_external =", wrapper)
            self.assertIn("32'h8001_0000", wrapper)
            self.assertIn("32'h8004_0000", wrapper)
            self.assertIn("addi", wrapper)
            self.assertIn("32'hfd1f_f06f", wrapper)
            declarations = re.findall(
                r"^\s*logic\b(?:\s+\[[^;\n]+\])?\s+([A-Za-z_]\w*)"
                r"(?:\s*\[[^;\n]+\])?;\s*$",
                wrapper,
                flags=re.MULTILINE,
            )
            self.assertEqual(
                len(declarations),
                len(set(declarations)),
                sorted(name for name in set(declarations) if declarations.count(name) > 1),
            )

            source_list = first.source_list_path.read_text(encoding="utf-8")
            self.assertIn(
                (root / "src/myfuzz/protocols/rtl/apb4_mmio_bridge.sv").as_posix(),
                source_list,
            )
            self.assertIn(
                (root / "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_ram.sv").as_posix(),
                source_list,
            )
            self.assertIn(
                (root / "third_party/rfuzz/upstream/ibex/sources.f").as_posix(),
                source_list,
            )
            self.assertIn(
                (output_one / "ibex_protocol_composition_top.sv").as_posix(),
                source_list,
            )
            self.assertNotIn(str(ROOT), source_list)

            def assert_path_free(value: object) -> None:
                if isinstance(value, dict):
                    for key, item in value.items():
                        assert_path_free(key)
                        assert_path_free(item)
                elif isinstance(value, list):
                    for item in value:
                        assert_path_free(item)
                elif isinstance(value, str):
                    self.assertFalse(os.path.isabs(value), value)

            assert_path_free(first.ir)
            self.assertNotIn(str(output_one), json.dumps(first.ir, sort_keys=True))

    def test_write_helper_publishes_summary_and_reuses_manifest_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_root(root)
            manifest_path = self.write_manifest(root)
            output = root / "generated"

            summary = write_protocol_composition(manifest_path, output, root=root)

            self.assertEqual(summary["schema_version"], "composition_ir.v1")
            self.assertTrue(summary["complete"])
            self.assertRegex(summary["manifest_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(summary["content_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertRegex(summary["source_hash"], r"^sha256:[0-9a-f]{64}$")
            self.assertEqual(Path(summary["ir_path"]), output / "composition_ir.json")
            self.assertEqual(Path(summary["wrapper_path"]), output / "ibex_protocol_composition_top.sv")
            self.assertEqual(Path(summary["source_list_path"]), output / "sources.f")
            json.loads((output / "composition_ir.json").read_text(encoding="utf-8"))

    def test_generation_requires_exactly_one_of_each_first_stage_component(self) -> None:
        cases = (
            ("missing", lambda document: document["components"].pop(0)),
            (
                "duplicate",
                lambda document: document["components"].append(
                    {
                        **document["components"][1],
                        "component_id": "ram1",
                        "base": 0x10000,
                    }
                ),
            ),
        )
        for label, mutate in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.materialize_root(root)
                document = approved_manifest()
                mutate(document)
                manifest_path = self.write_manifest(root, document)
                manifest = self.load_manifest(manifest_path, root)
                with self.assertRaisesRegex(ValueError, "exactly one"):
                    compose_protocol_composition(manifest, root / "generated", root=root)

    def test_generation_fails_closed_when_upstream_source_list_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.materialize_root(root, upstream=False)
            manifest_path = self.write_manifest(root)
            manifest = self.load_manifest(manifest_path, root)

            with self.assertRaisesRegex(ValueError, "missing-source-list"):
                compose_protocol_composition(manifest, root / "generated", root=root)


if __name__ == "__main__":
    unittest.main()
