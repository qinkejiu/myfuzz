import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    Evidence,
    EvidenceState,
    InputValidationError,
    PortDirection,
    RTLModule,
    RTLPort,
    build_compose_v5_scheme_a_rawbits_layout,
    emit_compose_v5_scheme_a_flat_shell,
    emit_compose_v5_scheme_a_rawbits_harness,
)


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")


def _port(name: str, direction: str, width: int) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, KNOWN)


def _module(name: str, ports: tuple[RTLPort, ...]) -> RTLModule:
    return RTLModule(
        name=name,
        original_name=name,
        source_file=f"{name}.sv",
        top=True,
        level=0,
        parameters=(),
        ports=ports,
        instances=(),
        memories=(),
        dependencies=(),
        evidence=KNOWN,
    )


class ComposeV5HarnessTest(unittest.TestCase):
    def test_scheme_a_harness_binds_every_rawbits_field_to_flat_input(self) -> None:
        cpu = _module("cpu", (
            _port("clk_i", "input", 1),
            _port("instr_i", "input", 8),
            _port("done_o", "output", 1),
        ))
        ip = _module("ip", (
            _port("pins_i", "input", 4),
            _port("irq_o", "output", 1),
        ))
        modules = {"cpu0": cpu, "ip0": ip}
        layout = build_compose_v5_scheme_a_rawbits_layout(modules)
        flat = emit_compose_v5_scheme_a_flat_shell(modules)

        harness = emit_compose_v5_scheme_a_rawbits_harness(
            flat,
            layout,
            module_name="scheme_a_harness_fixture",
        )

        self.assertEqual(harness.rawbits_width, 13)
        self.assertEqual(harness.observe_width, 2)
        self.assertEqual(
            {item["owner"] for item in harness.input_bindings},
            {"cpu0.clk_i", "cpu0.instr_i", "ip0.pins_i"},
        )
        self.assertEqual(
            {item["owner"] for item in harness.observations},
            {"cpu0.done_o", "ip0.irq_o"},
        )
        self.assertIn("module scheme_a_harness_fixture (", harness.rtl)
        self.assertIn("input logic [12:0] rawbits_i", harness.rtl)
        self.assertIn("output logic [1:0] observe_o", harness.rtl)
        self.assertIn("assign cpu0__clk_i = rawbits_i[0 +: 1];", harness.rtl)
        self.assertIn("assign cpu0__instr_i = rawbits_i[1 +: 8];", harness.rtl)
        self.assertIn("assign ip0__pins_i = rawbits_i[9 +: 4];", harness.rtl)
        self.assertIn("assign observe_o[0 +: 1] = cpu0__done_o;", harness.rtl)
        self.assertIn("assign observe_o[1 +: 1] = ip0__irq_o;", harness.rtl)
        self.assertIn("compose_v5_scheme_a_flat_top i_flat (", harness.rtl)

    def test_scheme_a_harness_rejects_unused_rawbits_fields(self) -> None:
        module = _module("cpu", (
            _port("clk_i", "input", 1),
            _port("done_o", "output", 1),
        ))
        flat = emit_compose_v5_scheme_a_flat_shell({"cpu0": module})
        layout = build_compose_v5_scheme_a_rawbits_layout({
            "cpu0": module,
            "unused0": _module("unused", (_port("stray_i", "input", 1),)),
        })

        with self.assertRaisesRegex(InputValidationError, "unused rawbits field"):
            emit_compose_v5_scheme_a_rawbits_harness(flat, layout)


if __name__ == "__main__":
    unittest.main()
