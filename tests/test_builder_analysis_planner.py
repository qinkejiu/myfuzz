import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from builder_fixtures import module_spec, rtl_module, system_spec
from myfuzz.builder import InputValidationError, plan_analyzed_system
from myfuzz.builder.rtl_analysis import normalize_frontend_manifest


def analysis_for(modules, limitations=(), memories=None):
    memories = memories or {}
    raw_modules = []
    for source in modules:
        raw_modules.append({
            "name": source.name,
            "origName": source.name,
            "top": source.name == modules[0].name,
            "level": 1 if source.name == modules[0].name else 2,
            "file": source.source_file,
            "parameters": [],
            "ports": [
                {
                    "name": port.name, "direction": port.direction.value,
                    "width": port.width, "packedWidth": port.width,
                    "unpackedRanges": [], "signed": False,
                }
                for port in source.ports
            ],
            "instances": [],
            "memories": memories.get(source.name, []),
            "dependencies": [],
        })
    return normalize_frontend_manifest({
        "schema": "myfuzz.frontend.v1",
        "source": "verilator-frontend-ast",
        "topModule": modules[0].name,
        "modules": raw_modules,
        "limitations": list(limitations),
    }, "a" * 64)


class AnalysisPlannerTest(unittest.TestCase):
    def test_ast_analysis_is_adapted_to_deterministic_system_ir(self):
        specs = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        result = plan_analyzed_system(
            system_spec(specs), analysis_for(
                [rtl_module("cpu", "initiator"), rtl_module("ram", "target")],
                memories={"ram": [{"name": "mem", "wordWidth": 32, "depth": 64,
                                    "unpackedRanges": [[0, 63]]}]},
            ),
        )
        self.assertEqual(result.analysis_manifest_digest, "a" * 64)
        self.assertEqual(result.system_ir.schema, "myfuzz.system-ir/v1")
        self.assertEqual(len(result.system_ir.connections), 6)
        self.assertEqual(result.plan.address_plan.windows[0].size, 256)

    def test_v1_rejects_multiple_masters_and_mixed_protocols(self):
        specs = [
            module_spec("cpu", "cpu", "initiator"),
            module_spec("dma", "dma", "initiator"),
            module_spec("ram", "ram", "target"),
        ]
        with self.assertRaisesRegex(InputValidationError, "exactly one protocol initiator"):
            plan_analyzed_system(
                system_spec(specs),
                analysis_for([
                    rtl_module("cpu", "initiator"), rtl_module("dma", "initiator"), rtl_module("ram", "target"),
                ]),
            )
        specs = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        specs[1]["interfaces"][0]["protocol"] = "other_bus"
        with self.assertRaisesRegex(InputValidationError, "mixed protocols"):
            plan_analyzed_system(
                system_spec(specs), analysis_for([rtl_module("cpu", "initiator"), rtl_module("ram", "target")]),
            )

    def test_non_provable_critical_signal_is_rejected_before_planning(self):
        specs = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        analysis = analysis_for(
            [rtl_module("cpu", "initiator"), rtl_module("ram", "target")],
            [{"module": "cpu", "signals": ["addr_o"], "construct": "force",
              "reason": "force semantics are not modeled"}],
        )
        with self.assertRaisesRegex(InputValidationError, "protocol planning.*force"):
            plan_analyzed_system(system_spec(specs), analysis)

    def test_memory_window_inference_rejects_ambiguous_or_non_byte_words(self):
        specs = [module_spec("cpu", "cpu", "initiator"), module_spec("ram", "ram", "target")]
        modules = [rtl_module("cpu", "initiator"), rtl_module("ram", "target")]
        with self.assertRaisesRegex(InputValidationError, "exactly one proven fixed memory"):
            plan_analyzed_system(system_spec(specs), analysis_for(modules))
        with self.assertRaisesRegex(InputValidationError, "cannot define a byte address window"):
            plan_analyzed_system(
                system_spec(specs),
                analysis_for(modules, memories={"ram": [{"name": "bits", "wordWidth": 1, "depth": 64,
                                                          "unpackedRanges": [[0, 63]]}]}),
            )


if __name__ == "__main__":
    unittest.main()
