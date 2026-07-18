import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.input_model import InputValidationError
from myfuzz.builder.contracts import (
    AccessRecord, CpuExecutionProfile, CoverageABIV2, ExperimentResult, ExperimentVariant,
    RFuzzDependencyManifest, RecordTerminalAck, RomInstallBackend, TransactionServerContract,
    build_experiment_manifest, sorted_objects, validate_contract, verify_rfuzz_dependency,
)


class ExperimentContractTest(unittest.TestCase):
    def test_locked_contracts_validate_and_reject_unknown_fields(self):
        backend = RomInstallBackend("external_rom", "axi_lite_instruction", "sha256_readback")
        profile = CpuExecutionProfile(
            "picorv32", "rv32i", 32, 32, 0, {"base": 0, "size": 4096},
            {"base": 4096, "size": 4096}, {"base": 8192, "size": 4096},
            {"active": 0, "cycles": 4}, backend.to_dict(), "a" * 64,
        )
        values = {
            "rom_install_backend_v1": backend.to_dict(),
            "cpu_execution_profile_v1": profile.to_dict(),
            "access_record_v1": AccessRecord(1, 0, 4, 0x1234).to_dict(),
            "record_terminal_ack_v1": RecordTerminalAck(1, "completed", "gpio0", 0x1004, "read", 0, 8).to_dict(),
            "experiment_variant_v1": ExperimentVariant("flat_random", False, False).to_dict(),
        }
        for name, value in values.items(): validate_contract(value, name)
        broken = dict(values["access_record_v1"], wstrb=15)
        with self.assertRaisesRegex(InputValidationError, "unknown field.*wstrb"):
            validate_contract(broken, "access_record_v1")

    def test_manifest_is_sorted_content_addressed_and_byte_reproducible(self):
        variants = tuple(ExperimentVariant(*args).to_dict() for args in (
            ("flat_random", False, False), ("generated_raw", True, False),
            ("generated_constrained", True, True)))
        components = sorted_objects(({"component_id": "ip.gpio"}, {"component_id": "cpu.main"}), "component_id")
        kwargs = dict(experiment_id="pico-large", cpu_profile={"cpu_id": "picorv32"}, variants=variants,
                      components=components, ip_instances=({"instance_id": "gpio0"},),
                      rawbits_layout_digest="b" * 64,
                      access_record_layout={"fields": ["ip_select", "read_write", "offset", "data"]},
                      coverage_abi_digest="c" * 64, transaction_slots=1024, cycle_budget=65536)
        first = build_experiment_manifest(**kwargs)
        second = build_experiment_manifest(**kwargs)
        self.assertEqual(first, second)
        validate_contract(first.to_dict(), "experiment_manifest_v1")
        self.assertEqual(first.digest, hashlib.sha256(__import__("json").dumps(
            first.payload(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest())

    def test_coverage_v2_and_result_lock_epoch_sampling_and_variant(self):
        abi = CoverageABIV2("d" * 64, "__vi_coverage", 2, 16, (
            {"point_id": "cpu.p0", "included": True, "offset": 0},
            {"point_id": "ip.p0", "included": True, "offset": 1},))
        validate_contract(abi.to_dict(), "coverage_abi_v2")
        result = ExperimentResult("e" * 64, "picorv32", "generated_raw", 0, 1, 1.0,
                                  2, 4, 1, 2, ({"seconds": 1, "hit": 1},),
                                  {"completed": 4}, ({"path": "coverage.bin", "sha256": "f" * 64},))
        validate_contract(result.to_dict(), "experiment_result_v1")

    def test_transaction_server_contract_and_dependency_preflight(self):
        server = TransactionServerContract(
            "transaction_paced", "myfuzz.rawbits/v2", "myfuzz.access-record/v1", True,
            ("fixed_replay", "coverage_guided_mutation", "corpus_replay", "minimization",
             "variable_length", "end_of_input"),
            ("completed", "target_timeout", "process_crash", "reconnected"), 16)
        validate_contract(server.to_dict(), "transaction_server_v1")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / "LICENSE").write_text("test\n"); (root / "server").write_text("bin\n")
            (root / ".myfuzz-revision").write_text("abc123\n")
            sha = lambda p: hashlib.sha256((root / p).read_bytes()).hexdigest()
            manifest = RFuzzDependencyManifest("https://example.invalid/rfuzz", "abc123", "LICENSE",
                                               sha("LICENSE"), ({"path": "server", "sha256": sha("server")},), (), ())
            validate_contract(manifest.to_dict(), "rfuzz_dependency_v1")
            self.assertEqual(verify_rfuzz_dependency(root, manifest)["status"], "verified")
            (root / ".myfuzz-revision").write_text("wrong\n")
            with self.assertRaisesRegex(InputValidationError, "revision"):
                verify_rfuzz_dependency(root, manifest)
        with self.assertRaisesRegex(InputValidationError, "missing"):
            verify_rfuzz_dependency("/definitely/missing/rfuzz", manifest)


if __name__ == "__main__": unittest.main()
