import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from builder_fixtures import system_spec  # noqa: E402
from myfuzz.builder import (  # noqa: E402
    DiscoveryResult, PortDirection, RawBitsV4Lane, RawBitsV4Submode,
    build_generated_pipeline_v4, build_soc_ir_v2, emit_soc_ir_v4,
    encode_rawbits_v4_testcase, plan_system, run_protocol_verilator_target_v4,
)
from myfuzz.builder.contracts import build_elaboration_manifest  # noqa: E402
from test_builder_generated_soc_v2 import AXI, _module  # noqa: E402


def _component_stubs() -> str:
    stubs = []
    for name, role in (("pipeline_cpu_v4", "initiator"), ("pipeline_ip_v4", "target")):
        def direction(value):
            if role != "initiator":
                return value
            return PortDirection.OUTPUT if value == PortDirection.INPUT else PortDirection.INPUT

        declarations = ", ".join(
            f"{direction(item_direction).value} logic [{width-1}:0] {physical}"
            if width > 1 else f"{direction(item_direction).value} logic {physical}"
            for physical, item_direction, width in AXI.values()
        )
        stubs.append(f"module {name}({declarations}); endmodule")
    return "\n".join(stubs)


class GeneratedPipelineV4Test(unittest.TestCase):
    def test_builds_instruments_and_replays_unseen_axi_lite_components(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            specs, facts = zip(
                _module("pipeline_cpu_v4", "initiator", "axi_lite"),
                _module("pipeline_ip_v4", "target", "axi_lite", 0x24000000),
            )
            specification = system_spec(list(specs))
            discovery = DiscoveryResult(
                ("/pipeline_cpu_v4.sv", "/pipeline_ip_v4.sv"), facts,
            )
            plan = plan_system(specification, discovery)
            self.assertTrue(plan.valid, plan.validation_issues)
            ir = build_soc_ir_v2(
                specification,
                discovery,
                plan,
                source_digests={
                    "pipeline_cpu_v4": "1" * 64,
                    "pipeline_ip_v4": "2" * 64,
                },
                analysis_manifest_digest="3" * 64,
            )
            soc = emit_soc_ir_v4(ir, module_name="pipeline_soc_v4")

            source_root = root / "source"
            source_root.mkdir()
            components = source_root / "components.sv"
            components.write_text(_component_stubs(), encoding="utf-8")
            source_manifest = build_elaboration_manifest(
                top_module="pipeline_cpu_v4",
                rtl_files=(components,),
                allow_roots=(source_root,),
            )
            built = build_generated_pipeline_v4(
                root / "pipeline",
                source_manifest=source_manifest,
                source_root=source_root,
                soc=soc,
                hierarchy_component_roots={
                    "fabric.main": ("pipeline_soc_v4.i_fabric",),
                },
            )
            included = tuple(
                point for point in built.coverage_abi.points if point["included"]
            )
            self.assertTrue(included)
            self.assertEqual(
                {point["component_id"] for point in included}, {"fabric.main"}
            )
            transport = encode_rawbits_v4_testcase(
                built.harness.layout,
                lane=RawBitsV4Lane.RAW_ESCAPE,
                submode=RawBitsV4Submode.RAW_LITERAL,
                logical_testcase_id=1,
                records=(0,),
            )
            replay = run_protocol_verilator_target_v4(
                built.target.path,
                transport,
                layout_digest=built.harness.layout.digest,
                coverage_abi=built.coverage_abi,
                coverage_epoch=1,
            )
            self.assertGreater(replay.dut_cycles, 0)
            report = json.loads(Path(built.report_path).read_text(encoding="utf-8"))
            self.assertFalse(report["baseline_a_affected"])
            self.assertIsNone(report["cpu_profile_digest"])
            self.assertIsNone(built.environment_plan)


if __name__ == "__main__":
    unittest.main()
