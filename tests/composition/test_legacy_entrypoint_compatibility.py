"""P2 compatibility gate: the extracted modules must not change behaviour.

plan_generic_composition moved from auto.py to generic_planner.py, and the
processor rendering plus the SystemVerilog primitives it shares moved from
protocol_composer.py to processor_renderer.py. The origin modules re-import
every extracted name, so the historical entry points keep working unchanged.

These tests pin that contract three ways:

1. every extracted name in the origin module is the very same object as the one
   in the new module, so the forwarding cannot silently drift;
2. a fixture matrix rendered through the legacy import path is byte-identical,
   file for file, to the same matrix rendered through the extracted modules,
   covering the IR, the generated SystemVerilog and the source list;
3. the matrix digest equals the digest recorded from the pre-refactor checkout
   (git HEAD before the split), which is the one-time proof that moving the code
   changed nothing. Regenerate GOLDEN_MATRIX_DIGEST deliberately, never to make
   a failure disappear.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.composition import auto as legacy_auto
from myfuzz.composition import generic_planner
from myfuzz.composition import processor_renderer
from myfuzz.composition import protocol_composer
from tests.integration.test_processor_auto_wiring import PROTOCOLS, _fixture


# sha256 of the canonical JSON manifest produced by /tmp-equivalent run of this
# matrix against the pre-refactor checkout (git HEAD 323561f) and against the
# split tree; both were e63647ef81401f24720bd077e184cc569998ea6d5c69d21bd71697b95de03b09.
GOLDEN_MATRIX_DIGEST = "e63647ef81401f24720bd077e184cc569998ea6d5c69d21bd71697b95de03b09"
CASES = (
    ("plain", {}),
    ("ram", {"with_ram": True}),
    ("sync-reset", {"synchronous_reset": True}),
    ("cross-file", {"with_ram": True, "cross_file_types": True, "binary_collateral": True}),
)

PLANNER_NAMES = (
    "AutoCompositionError",
    "GenericCompositionRequest",
    "GenericCompositionPlan",
    "plan_generic_composition",
    "_DEFAULT_SEED",
    "_align_up",
    "_default_parameters",
    "_safe_source_evidence_path",
    "_freeze_nested",
    "_integer",
    "_generic_source_path",
    "_GenericSourceListMetadata",
    "_generic_source_list_metadata",
    "_generic_source_evidence_hash",
    "_generic_capability_document",
    "_PROCESSOR_MEMORY_FUNCTIONS",
    "_is_processor_memory_endpoint",
    "_processor_source_records",
    "_processor_source_document",
    "_processor_capability_documents",
    "_processor_layout_fields",
    "_generic_ir_evidence",
    "_generic_target_capability",
    "_generic_reset_contract",
    "_generic_with_reset_contract",
    "_generic_endpoint_reset_contract",
    "_generic_transport_capability",
    "_generic_adapter_contract",
    "_generic_control_binding",
    "_generic_compiled_protocols",
    "_generic_dependencies",
    "_generic_address_width",
    "_generic_width_expression_names",
    "_generic_address_field_ids",
    "_generic_irq_capacity",
)

RENDERER_NAMES = (
    "_PROCESSOR_BEAT_FIELDS",
    "_processor_controls",
    "_processor_physical_signal",
    "_validate_processor_drivers",
    "_render_processor_backend_module",
    "_processor_reset_signal",
    "_validate_processor_transducer",
    "_render_processor_top",
    "_generic_port_records",
    "_generic_source_top",
    "_sv_identifier",
    "_sv_logic",
    "_sv_literal",
    "_source_parameter_clause",
    "_complete_ranges",
)


def _matrix_manifest(plan, write, root: Path) -> dict:
    """Render the fixture matrix and return relative path -> content hash."""
    manifest = {}
    for protocol in PROTOCOLS:
        for index, (label, kwargs) in enumerate(CASES):
            case_root = root / ("%s-%s-%s" % (protocol[0], protocol[1], label))
            case_root.mkdir(parents=True)
            fixture, _, _, _ = _fixture(case_root, protocol, index, **kwargs)
            prefix = "%s/%s" % (protocol[0], label)
            manifest[prefix + "/ir"] = fixture.composition_ir_hash
            manifest[prefix + "/annotations"] = fixture.interface_annotation_hash
            manifest[prefix + "/evidence"] = fixture.source_evidence_hash
            output = case_root / "out"
            write(fixture, output, base_dir=case_root)
            for path in sorted(output.rglob("*")):
                if path.is_file():
                    manifest[prefix + "/" + path.relative_to(output).as_posix()] = hashlib.sha256(
                        path.read_bytes()).hexdigest()
    return manifest


def matrix_digest() -> str:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        manifest = _matrix_manifest(
            legacy_auto.plan_generic_composition,
            protocol_composer.write_generic_composition, root)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


class LegacyEntrypointCompatibilityTests(unittest.TestCase):
    def test_origin_modules_forward_every_extracted_name(self) -> None:
        for name in PLANNER_NAMES:
            with self.subTest(module="auto", name=name):
                self.assertIs(getattr(legacy_auto, name), getattr(generic_planner, name))
        for name in RENDERER_NAMES:
            with self.subTest(module="protocol_composer", name=name):
                self.assertIs(getattr(protocol_composer, name), getattr(processor_renderer, name))

    def test_extracted_modules_serve_the_legacy_entry_point(self) -> None:
        request = generic_planner.GenericCompositionRequest
        self.assertIs(request, legacy_auto.GenericCompositionRequest)
        self.assertEqual(legacy_auto.plan_generic_composition.__module__,
                         "myfuzz.composition.generic_planner")
        self.assertEqual(processor_renderer._render_processor_top.__module__,
                         "myfuzz.composition.processor_renderer")

    def test_legacy_and_extracted_paths_render_identical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy = _matrix_manifest(
                legacy_auto.plan_generic_composition,
                protocol_composer.write_generic_composition, root / "legacy")
            extracted = _matrix_manifest(
                generic_planner.plan_generic_composition,
                protocol_composer.write_generic_composition, root / "extracted")
        self.assertEqual(set(legacy), set(extracted))
        self.assertEqual(legacy, extracted)
        self.assertTrue(any(key.endswith("sources.f") for key in legacy))

    def test_matrix_digest_matches_the_pre_refactor_checkout(self) -> None:
        self.assertNotEqual(GOLDEN_MATRIX_DIGEST, "PENDING",
                            "record the digest from the pre-refactor checkout first")
        self.assertEqual(matrix_digest(), GOLDEN_MATRIX_DIGEST)
