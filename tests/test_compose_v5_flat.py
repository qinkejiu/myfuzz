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
    emit_compose_v5_scheme_a_flat_shell,
)


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")
NON_PROVABLE = Evidence(EvidenceState.NON_PROVABLE, "fixture", "fixture fact")


def _port(name: str, direction: str, width: int, evidence: Evidence = KNOWN) -> RTLPort:
    return RTLPort(name, PortDirection(direction), width, width, (), False, evidence)


def _module(
    *,
    name: str,
    ports: tuple[RTLPort, ...],
    original_name: str | None = None,
    parameters: tuple[tuple[str, str], ...] = (),
    evidence: Evidence = KNOWN,
) -> RTLModule:
    return RTLModule(
        name=name,
        original_name=original_name or name,
        source_file=f"{name}.sv",
        top=True,
        level=0,
        parameters=parameters,
        ports=ports,
        instances=(),
        memories=(),
        dependencies=(),
        evidence=evidence,
    )


class ComposeV5FlatTest(unittest.TestCase):
    def test_emits_flat_top_from_real_ports(self) -> None:
        cpu = _module(
            name="cpu_param_0",
            original_name="cpu_core",
            parameters=(("XLEN", "32"),),
            ports=(
                _port("clk_i", "input", 1),
                _port("instr_i", "input", 32),
                _port("done_o", "output", 1),
            ),
        )
        ip = _module(
            name="ip",
            ports=(
                _port("irq_o", "output", 1),
                _port("pins_i", "input", 4),
            ),
        )

        emitted = emit_compose_v5_scheme_a_flat_shell(
            {"cpu0": cpu, "ip0": ip},
            module_name="scheme_a_fixture_top",
        )

        self.assertEqual(emitted.module_name, "scheme_a_fixture_top")
        self.assertEqual(emitted.instances, ("cpu0", "ip0"))
        self.assertIn("module scheme_a_fixture_top (", emitted.rtl)
        self.assertIn("input logic [31:0] cpu0__instr_i", emitted.rtl)
        self.assertIn("output logic cpu0__done_o", emitted.rtl)
        self.assertIn("cpu_core #(", emitted.rtl)
        self.assertIn(".XLEN(32)", emitted.rtl)
        self.assertIn(") cpu0 (", emitted.rtl)
        self.assertIn(".instr_i(cpu0__instr_i)", emitted.rtl)
        self.assertIn("ip ip0 (", emitted.rtl)
        self.assertIn(".pins_i(ip0__pins_i)", emitted.rtl)
        external = {item["name"]: item for item in emitted.external_ports}
        self.assertTrue(external["cpu0__clk_i"]["fuzz_control"])
        self.assertFalse(external["cpu0__done_o"]["fuzz_control"])

    def test_rejects_inout_ports(self) -> None:
        module = _module(
            name="ip",
            ports=(
                _port("clk_i", "input", 1),
                _port("pad_io", "inout", 1),
            ),
        )

        with self.assertRaisesRegex(InputValidationError, "rejects inout port"):
            emit_compose_v5_scheme_a_flat_shell({"ip0": module})

    def test_rejects_non_provable_ports(self) -> None:
        module = _module(
            name="ip",
            ports=(
                _port("clk_i", "input", 1),
                _port("opaque_i", "input", 1, evidence=NON_PROVABLE),
            ),
        )

        with self.assertRaisesRegex(InputValidationError, "not fully provable"):
            emit_compose_v5_scheme_a_flat_shell({"ip0": module})

    def test_rejects_unsafe_parameter_literals(self) -> None:
        module = _module(
            name="ip",
            ports=(_port("clk_i", "input", 1),),
            parameters=(("INIT", '"path.hex"'),),
        )

        with self.assertRaisesRegex(InputValidationError, "safe numeric Verilog parameter literal"):
            emit_compose_v5_scheme_a_flat_shell({"ip0": module})


if __name__ == "__main__":
    unittest.main()
