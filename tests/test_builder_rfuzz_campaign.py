import json
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.rfuzz_campaign import (  # noqa: E402
    RFUZZ_COVERAGE_MAGIC, RFUZZ_INPUT_MAGIC, emit_rfuzz_toml,
    encode_rfuzz_coverage_buffer, parse_rfuzz_input_buffer, rfuzz_geometry,
    run_rfuzz_conformance_smoke, run_rfuzz_timed_campaign,
)
from myfuzz.builder import (  # noqa: E402
    HarnessPort, InputValidationError, PortDirection, build_constraint_ir,
    build_rawbits_layout, build_verilator_target, emit_dual_mode_harness,
)
from myfuzz.builder.contracts import CoverageABIV2, build_elaboration_manifest  # noqa: E402


SOC_V2 = """\
module rfuzz_smoke_soc(
 input logic clk, input logic resetn, input logic pin,
 input logic [63:0] coverage_epoch_i, output logic seen,
 output logic [0:0] __vi_coverage
);
 logic [63:0] hit_epoch;
 always_ff @(posedge clk or negedge resetn) begin
  if (!resetn) begin seen<=0; hit_epoch<=0; end
  else begin seen<=pin; if (pin) hit_epoch<=coverage_epoch_i; end
 end
 assign __vi_coverage[0]=(hit_epoch==coverage_epoch_i);
endmodule
"""


def target_evidence(soc_path):
    return {
        "original_soc_rtl": soc_path,
        "rfuzz_config": {"format": "RFUZZ RawBits v2"},
        "address_graph": {"windows": []},
        "connection_graph": {"edges": []},
        "port_bindings": {"pin": "direct_fuzz"},
        "instrumentation_manifest": {"required": ["rfuzz_smoke_soc"], "skipped": []},
        "generation_report": {"status": "conformance_fixture"},
    }


class RFuzzCampaignBridgeTest(unittest.TestCase):
    def _build_v2_target(self, root):
        source_root = root / "instrumented"
        source_root.mkdir()
        soc = source_root / "rfuzz_smoke_soc.sv"
        soc.write_text(SOC_V2)
        manifest = build_elaboration_manifest(
            top_module="rfuzz_smoke_soc", rtl_files=(soc,), allow_roots=(source_root,),
            tools={"verilator": subprocess.check_output(["verilator", "--version"], text=True).strip()},
        )
        layout = build_rawbits_layout((
            {"target": "pin", "width": 1, "purpose": "input", "provenance": "test"},
        ))
        constraints = build_constraint_ir(layout, (
            {"target": "pin", "primitive": "DIRECT", "provenance": "test"},
        ))
        point = {
            "point_id": "rfuzz-smoke-hit", "component_id": "cpu.main", "component_path": "",
            "node_id": "smoke", "module": "rfuzz_smoke_soc", "kind": "if",
            "subtype": "true", "process_kind": "always_ff", "source_id": "fixture",
            "source_line": 8, "included": True, "offset": 0, "source_offset": 0,
            "exclusion_reason": None,
        }
        abi = CoverageABIV2(
            hashlib.sha256(b"rfuzz-smoke-abi").hexdigest(), "__vi_coverage", 1, 64,
            (point,), transport_width=1,
        )
        harness = emit_dual_mode_harness(
            "rfuzz_smoke_soc", layout, constraints, (
                HarnessPort("clk", PortDirection.INPUT, 1, "clock"),
                HarnessPort("resetn", PortDirection.INPUT, 1, "reset"),
                HarnessPort("pin", PortDirection.INPUT, 1),
                HarnessPort("seen", PortDirection.OUTPUT, 1),
            ), module_name="rfuzz_smoke_harness", reset_cycles=1, drain_cycles=1,
            coverage_abi=abi,
        )
        return build_verilator_target(
            root / "targets", manifest=manifest, source_root=source_root, harness=harness,
            layout=layout, constraint_ir=constraints, coverage_abi=abi,
            evidence=target_evidence(soc), jobs=1,
        )

    def test_geometry_matches_upstream_word_alignment(self):
        pico = rfuzz_geometry(968, 363)
        self.assertEqual(pico.raw_bytes_per_cycle, 121)
        self.assertEqual(pico.aligned_input_bytes, 128)
        self.assertEqual(pico.coverage_payload_bytes, 366)
        self.assertEqual(pico.coverage_item_bytes, 368)
        ultra = rfuzz_geometry(1103, 97)
        self.assertEqual(ultra.raw_bytes_per_cycle, 138)
        self.assertEqual(ultra.aligned_input_bytes, 144)
        self.assertEqual(ultra.coverage_payload_bytes, 102)
        self.assertEqual(ultra.coverage_item_bytes, 104)

    def test_input_parser_strips_only_alignment_padding_and_preserves_lsb0_bytes(self):
        geometry = rfuzz_geometry(9, 3)
        cycle0 = bytes((0xA5, 0x01)) + bytes((7, 0, 0, 0, 0, 0))
        cycle1 = bytes((0x5A, 0x00)) + bytes(6)
        payload = struct.pack(">IIHHHHQ", RFUZZ_INPUT_MAGIC, 17, 1, 0, 0, 0, 2)
        buffer_id, tests = parse_rfuzz_input_buffer(payload + cycle0 + cycle1, geometry)
        self.assertEqual(buffer_id, 17)
        self.assertEqual(tests[0].cycles, 2)
        self.assertEqual(tests[0].rawbits, bytes((0xA5, 0x01, 0x5A, 0x00)))
        self.assertEqual(tests[0].ignored_padding_nonzero_bytes, 1)

    def test_coverage_encoder_expands_lsb0_bitset_to_byte_counters(self):
        geometry = rfuzz_geometry(8, 9)
        encoded = encode_rfuzz_coverage_buffer(3, ((5, bytes((0b10000001, 0b1))),), geometry)
        self.assertEqual(struct.unpack_from(">IIH", encoded), (RFUZZ_COVERAGE_MAGIC, 3, 5))
        counters = encoded[10:10 + geometry.coverage_payload_bytes]
        self.assertEqual(counters[:9], bytes((1, 0, 0, 0, 0, 0, 0, 1, 1)))
        self.assertEqual(counters[9:], bytes(len(counters) - 9))

    def test_parser_rejects_reserved_control_bits(self):
        geometry = rfuzz_geometry(8, 1)
        payload = struct.pack(">IIHHHH", RFUZZ_INPUT_MAGIC, 0, 0, 1, 0, 0)
        with self.assertRaisesRegex(InputValidationError, "reserved"):
            parse_rfuzz_input_buffer(payload, geometry)

    def test_toml_maps_dense_points_to_eight_bit_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            (target / "bin").mkdir(parents=True)
            (target / "evidence").mkdir()
            executable = target / "bin/myfuzz_target"
            executable.write_bytes(b"target")
            completion = {
                "schema": "myfuzz.target-completion/v1", "target_digest": "a" * 64,
                "coverage_width": 2,
                "coverage_abi_digest": "b" * 64,
                "executable_sha256": __import__("hashlib").sha256(b"target").hexdigest(),
            }
            (target / "completion_manifest.json").write_text(json.dumps(completion))
            (target / "evidence/bit_layout.json").write_text(json.dumps({
                "schema": "myfuzz.rawbits-layout/v2", "cycle_width": 9,
                "bytes_per_cycle": 2, "digest": "c" * 64,
            }))
            (target / "evidence/coverage_abi.json").write_text(json.dumps({
                "schema": "myfuzz.coverage-abi/v2", "width": 2,
                "port_name": "coverage_o", "points": [
                    {"included": True, "offset": 0, "point_id": "p0",
                     "component_id": "cpu.main", "source_line": 12},
                    {"included": True, "offset": 1, "point_id": "p1",
                     "component_id": "ip.gpio0", "source_line": 23},
                ],
            }))
            (target / "evidence/elaboration_manifest.json").write_text(json.dumps({
                "schema": "myfuzz.elaboration-manifest/v1", "top_module": "top",
            }))
            output = Path(directory) / "rfuzz.toml"
            report = emit_rfuzz_toml(target, output)
            text = output.read_text()
            self.assertEqual(text.count("[[coverage]]"), 2)
            self.assertEqual(text.count("[[counter]]"), 2)
            self.assertIn("width = 9", text)
            self.assertIn("index = 1", text)
            self.assertEqual(report["geometry"]["aligned_input_bytes"], 8)

    def test_real_kfuzz_shared_memory_conformance_smoke(self):
        kfuzz = ROOT / "third_party/rfuzz/upstream/target/release/kfuzz"
        self.assertTrue(kfuzz.is_file(), "pinned kfuzz binary is required for conformance")
        before = self._shared_memory_ids()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._build_v2_target(root)
            run = run_rfuzz_conformance_smoke(
                target.path, root / "smoke", kfuzz_bin=kfuzz, mode="raw",
                campaign_seed=7, seed_cycles=2, timeout_seconds=20,
            )
            self.assertGreaterEqual(run.report["event_count"], 1)
            self.assertEqual(run.report["first_event"]["cycles"], 2)
            self.assertEqual(run.report["first_event"]["coverage_point_count"], 1)
            self.assertEqual(run.report["first_event"]["mode"], "raw")
            self.assertTrue((Path(run.output_dir) / "conformance_report.json").is_file())
        self.assertEqual(self._shared_memory_ids(), before)

    def test_timed_mutation_campaign_stops_without_fifo_or_shared_memory_leaks(self):
        kfuzz = ROOT / "third_party/rfuzz/upstream/target/release/kfuzz"
        self.assertTrue(kfuzz.is_file(), "pinned kfuzz binary is required for campaign test")
        before = self._shared_memory_ids()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = self._build_v2_target(root)
            run = run_rfuzz_timed_campaign(
                target.path, root / "campaign", kfuzz_bin=kfuzz, mode="raw",
                campaign_seed=11, seed_cycles=2, wall_seconds=1,
                checkpoints=(0.25, 0.5), startup_timeout_seconds=20,
                shutdown_timeout_seconds=5,
            )
            self.assertGreater(run.report["event_count"], 1)
            self.assertFalse(run.report["forced_server_kill"])
            self.assertEqual(run.report["server_returncode"], 0)
            self.assertLess(run.report["shutdown_seconds"], 5)
            self.assertEqual([sample["wall_seconds"] for sample in run.report["checkpoints"]], [
                0.25, 0.5, 1,
            ])
            self.assertTrue((Path(run.output_dir) / "campaign_report.json").is_file())
            server_id = run.report["commands"]["server"][
                run.report["commands"]["server"].index("--server-id") + 1
            ]
            self.assertFalse((Path("/tmp/fpga") / server_id).exists())
        self.assertEqual(self._shared_memory_ids(), before)

    @staticmethod
    def _shared_memory_ids() -> set[int]:
        lines = Path("/proc/sysvipc/shm").read_text(encoding="ascii").splitlines()
        columns = lines[0].split()
        id_index = columns.index("shmid")
        return {int(line.split()[id_index]) for line in lines[1:]}


if __name__ == "__main__":
    unittest.main()
