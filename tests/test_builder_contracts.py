import json
import sys
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contracts import (
    CONTRACT_SCHEMAS,
    ConflictOutcome,
    ConstraintIR,
    CoverageABI,
    ElaborationLimits,
    ManifestError,
    PortFacts,
    ProtocolBackend,
    SystemIR,
    adapt_legacy_plan,
    build_elaboration_manifest,
    derive_elaboration_manifest,
    resolve_port_conflict,
    validate_contract,
)
from myfuzz.builder import DiscoveryResult, plan_system
from myfuzz.builder.input_model import InputValidationError, PortDirection
from builder_fixtures import module_spec, rtl_module, system_spec


class ContractSchemaTest(unittest.TestCase):
    def test_all_four_locked_contracts_validate(self):
        values = {
            "system_ir_v1": SystemIR("soc", (), (), ()).to_dict(),
            "protocol_backend_v1": ProtocolBackend("axi_lite", "1", "axi_lite", ("fabric",)).to_dict(),
            "constraint_ir_v1": ConstraintIR("0" * 64, 8, ()).to_dict(),
            "coverage_abi_v1": CoverageABI("1" * 64, "__vi_coverage", 0, ()).to_dict(),
        }
        self.assertTrue(set(values).issubset(CONTRACT_SCHEMAS))
        for name, value in values.items():
            validate_contract(value, name)

        schema_dir = ROOT / "src" / "myfuzz" / "builder" / "contracts" / "schemas"
        documents = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(schema_dir.glob("*.json"))]
        self.assertEqual({document["$id"] for document in documents},
                         {definition["schema"] for definition in CONTRACT_SCHEMAS.values()})

    def test_schema_version_and_unknown_fields_fail_closed(self):
        value = SystemIR("soc", (), (), ()).to_dict()
        value["schema"] = "myfuzz.system-ir/v2"
        with self.assertRaisesRegex(InputValidationError, "expected.*v1"):
            validate_contract(value, "system_ir_v1")

    def test_legacy_plan_adapter_is_read_only_and_deterministic(self):
        modules = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        plan = plan_system(
            system_spec(modules),
            DiscoveryResult(("/cpu.sv", "/ram.sv"), (rtl_module("cpu", "initiator"), rtl_module("ram", "target"))),
        )
        first = adapt_legacy_plan(plan)
        second = adapt_legacy_plan(plan)
        self.assertEqual(first, second)
        self.assertEqual(first.name, plan.name)
        self.assertEqual(len(first.connections), len(plan.graph.connections))
        value = SystemIR("soc", (), (), ()).to_dict()
        value["surprise"] = True
        with self.assertRaisesRegex(InputValidationError, "unknown field.*surprise"):
            validate_contract(value, "system_ir_v1")


class ManifestTest(unittest.TestCase):
    def test_nested_filelist_is_content_addressed_and_deterministic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inc").mkdir()
            (root / "a.sv").write_text("module a; endmodule\n", encoding="utf-8")
            (root / "b.sv").write_text("module b; endmodule\n", encoding="utf-8")
            (root / "child.f").write_text("+incdir+inc +define+WIDTH=32 b.sv\n", encoding="utf-8")
            (root / "root.f").write_text("a.sv -f child.f\n", encoding="utf-8")
            first = build_elaboration_manifest(
                top_module="a", filelists=(root / "root.f",), allow_roots=(root,),
                parameters={"B": 2, "A": 1}, tools={"verilator": "5.0"},
            )
            second = build_elaboration_manifest(
                top_module="a", filelists=(root / "root.f",), allow_roots=(root,),
                parameters={"A": 1, "B": 2}, tools={"verilator": "5.0"},
            )
            self.assertEqual(first, second)
            self.assertEqual([Path(item.path).name for item in first.sources], ["a.sv", "b.sv"])
            self.assertEqual(first.defines, ("WIDTH=32",))
            self.assertEqual(json.dumps(first.to_dict(), sort_keys=True), json.dumps(second.to_dict(), sort_keys=True))
            with self.assertRaises(FrozenInstanceError):
                first.stage = "changed"

    def test_derived_manifest_links_parent_without_digest_equality(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "a.sv"
            source.write_text("module a; endmodule\n", encoding="utf-8")
            base = build_elaboration_manifest(top_module="a", rtl_files=(source,), allow_roots=(root,))
            child = derive_elaboration_manifest(base, stage="soc", top_module="generated_soc_top")
            self.assertEqual(child.parent_digest, base.digest)
            self.assertNotEqual(child.digest, base.digest)
            self.assertEqual(child.stage, "soc")

    def test_escape_symlink_cycle_and_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "outside.sv"
            external.write_text("module outside; endmodule\n", encoding="utf-8")
            (root / "escape.sv").symlink_to(external)
            with self.assertRaisesRegex(ManifestError, "escapes allowlist"):
                build_elaboration_manifest(top_module="x", rtl_files=(root / "escape.sv",), allow_roots=(root,))

            (root / "one.f").write_text("-f two.f\n", encoding="utf-8")
            (root / "two.f").write_text("-f one.f\n", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "cycle"):
                build_elaboration_manifest(top_module="x", filelists=(root / "one.f",), allow_roots=(root,))

            source = root / "large.sv"
            source.write_text("12345", encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "size 5 exceeds limit 4"):
                build_elaboration_manifest(
                    top_module="x", rtl_files=(source,), allow_roots=(root,),
                    limits=ElaborationLimits(max_file_bytes=4),
                )


class ConflictMatrixTest(unittest.TestCase):
    def test_direction_role_shape_and_width_conflicts_reject(self):
        base = PortFacts(PortDirection.INPUT, 32, (), False, "target")
        cases = (
            PortFacts(PortDirection.OUTPUT, 32, (), False, "target"),
            PortFacts(PortDirection.INPUT, 32, (), False, "initiator"),
            PortFacts(PortDirection.INPUT, 32, (4,), False, "target"),
            PortFacts(PortDirection.INPUT, 64, (), False, "target"),
        )
        for expected in cases:
            self.assertEqual(resolve_port_conflict(rtl=base, expected=expected).outcome, ConflictOutcome.REJECT)

    def test_only_declared_address_and_payload_adapters_are_accepted(self):
        narrow = PortFacts(PortDirection.INPUT, 12)
        wide = PortFacts(PortDirection.INPUT, 32)
        self.assertEqual(
            resolve_port_conflict(rtl=narrow, expected=wide, allow_low_address_truncation=True).outcome,
            ConflictOutcome.ADAPT_LOW_ADDRESS,
        )
        signed = PortFacts(PortDirection.INPUT, 32, signed=True)
        unsigned = PortFacts(PortDirection.INPUT, 32, signed=False)
        self.assertEqual(
            resolve_port_conflict(rtl=signed, expected=unsigned, bitwise_payload=True).outcome,
            ConflictOutcome.IGNORE_PAYLOAD_SIGNEDNESS,
        )
        self.assertEqual(resolve_port_conflict(rtl=signed, expected=unsigned).outcome, ConflictOutcome.REJECT)


if __name__ == "__main__":
    unittest.main()
