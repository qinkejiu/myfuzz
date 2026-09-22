"""Behavioural RTL tests for the generic external peers of the profile-driven
SoC path.

Three models are covered, each with its own self-checking bench inside
``tests/fixtures/rtl/soc_peers_tb.sv`` (one file, three bench modules, selected
with ``iverilog -s``):

* ``soc_uart_peer`` -- transmit framing at the declared baud divisor, reception
  of a byte the bench drives on the line, a missing stop bit, an idle line, and
  the documented absence of a glitch filter;
* ``soc_spi_peer`` -- a byte shifting in on the declared edge for every
  supported CPOL/CPHA combination, MISO changing only while selected and only on
  the declared edge, an unarmed selection, a clock edge while deselected, a
  partial byte, and two whole bytes inside one selection;
* ``soc_gpio_peer`` -- input read, output drive, direction change, one side
  driving, agreement, contention, and the default level of an undriven pin.

This module only compiles a bench together with the peer under test using
``iverilog``, runs it with ``vvp`` and asserts on the single ``RESULT: ...``
line the bench prints.  Every parameterization is a separate process, and the
bench echoes its parameters and the scenario suite it ran, so a lost or
misspelled override cannot silently reduce coverage.

Three failure controls keep the harness honest: ``NEGATIVE_CONTROL=1`` corrupts
exactly one expectation inside each bench (the transmitted stop-bit level for
UART, the pre-clock MISO bit of a CPHA=0 SPI selection, and the "agreement is
not a contention" flags for GPIO), the invalid-parameter cases check that a
configuration outside the frozen limits is rejected instead of silently
accepted, and the tool-free class below checks the result-line parser itself.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RTL_DIR = ROOT / "src" / "myfuzz" / "protocols" / "rtl"
TESTBENCH = ROOT / "tests" / "fixtures" / "rtl" / "soc_peers_tb.sv"

UART_TOP = "soc_uart_peer_tb"
SPI_TOP = "soc_spi_peer_tb"
GPIO_TOP = "soc_gpio_peer_tb"

COMPILE_TIMEOUT_SECONDS = 60
RUN_TIMEOUT_SECONDS = 120

#: Bench top -> (peer RTL source, suite the bench reports, bench defaults).
BENCHES = {
    UART_TOP: {
        "source": RTL_DIR / "soc_uart_peer.sv",
        "suite": "uart",
        "defaults": {
            "DATA_WIDTH": 8,
            "BAUD_DIV": 1,
            "STOP_BITS": 1,
            "IDLE_LEVEL": 1,
            "TIMEOUT_BITS": 4,
            "NEGATIVE_CONTROL": 0,
        },
    },
    SPI_TOP: {
        "source": RTL_DIR / "soc_spi_peer.sv",
        "suite": "spi",
        "defaults": {
            "BITS": 8,
            "CPOL": 0,
            "CPHA": 0,
            "CS_ACTIVE_LOW": 1,
            "NEGATIVE_CONTROL": 0,
        },
    },
    GPIO_TOP: {
        "source": RTL_DIR / "soc_gpio_peer.sv",
        "suite": "gpio",
        "defaults": {
            "PINS": 1,
            "DEFAULT_INPUT_LEVEL": 0,
            "CONTENTION_IS_ERROR": 0,
            "NEGATIVE_CONTROL": 0,
        },
    },
}

#: label, top, overrides that must pass
PARAMETERIZATIONS = (
    # UART: two different baud divisors, an odd one, both idle levels, a
    # one-bit frame and a timeout window of a single bit period.
    ("uart_div1", UART_TOP, {}),
    ("uart_div2", UART_TOP, {"BAUD_DIV": 2}),
    ("uart_div5", UART_TOP, {"BAUD_DIV": 5, "DATA_WIDTH": 7, "STOP_BITS": 2, "TIMEOUT_BITS": 3}),
    ("uart_idle_low", UART_TOP, {"BAUD_DIV": 3, "IDLE_LEVEL": 0, "TIMEOUT_BITS": 3}),
    ("uart_single_data_bit", UART_TOP, {"DATA_WIDTH": 1, "TIMEOUT_BITS": 2}),
    ("uart_two_stop_bits", UART_TOP, {"STOP_BITS": 2, "TIMEOUT_BITS": 1}),
    # SPI: all four modes, one- and two-bit frames, and both chip-select
    # polarities.
    ("spi_mode0", SPI_TOP, {}),
    ("spi_mode1", SPI_TOP, {"CPHA": 1}),
    ("spi_mode2", SPI_TOP, {"CPOL": 1}),
    ("spi_mode3", SPI_TOP, {"CPOL": 1, "CPHA": 1}),
    ("spi_bits1_mode0", SPI_TOP, {"BITS": 1}),
    ("spi_bits1_mode3", SPI_TOP, {"BITS": 1, "CPOL": 1, "CPHA": 1}),
    ("spi_bits4_mode3", SPI_TOP, {"BITS": 4, "CPOL": 1, "CPHA": 1}),
    ("spi_cs_active_high_mode0", SPI_TOP, {"CS_ACTIVE_LOW": 0}),
    ("spi_cs_active_high_bits3_mode3", SPI_TOP, {"CS_ACTIVE_LOW": 0, "BITS": 3, "CPOL": 1, "CPHA": 1}),
    # GPIO: one pin, a whole port, the other default level, and both contention
    # policies.
    ("gpio_pins1", GPIO_TOP, {}),
    ("gpio_pins4_default_high_error", GPIO_TOP, {"PINS": 4, "DEFAULT_INPUT_LEVEL": 1, "CONTENTION_IS_ERROR": 1}),
    ("gpio_pins8", GPIO_TOP, {"PINS": 8}),
    ("gpio_pins2_default_high", GPIO_TOP, {"PINS": 2, "DEFAULT_INPUT_LEVEL": 1}),
    ("gpio_pins16_default_high_error", GPIO_TOP, {"PINS": 16, "DEFAULT_INPUT_LEVEL": 1, "CONTENTION_IS_ERROR": 1}),
)

#: label, top, overrides that must be rejected (compile, elaboration or $fatal)
INVALID_PARAMETERIZATIONS = (
    ("uart_data_width_zero", UART_TOP, {"DATA_WIDTH": 0}),
    ("uart_baud_div_zero", UART_TOP, {"BAUD_DIV": 0}),
    ("uart_baud_div_negative", UART_TOP, {"BAUD_DIV": -1}),
    ("uart_stop_bits_zero", UART_TOP, {"STOP_BITS": 0}),
    ("uart_idle_level_above_range", UART_TOP, {"IDLE_LEVEL": 2}),
    ("uart_idle_level_below_range", UART_TOP, {"IDLE_LEVEL": -1}),
    ("uart_timeout_bits_zero", UART_TOP, {"TIMEOUT_BITS": 0}),
    ("uart_timeout_bits_negative", UART_TOP, {"TIMEOUT_BITS": -2}),
    ("spi_bits_zero", SPI_TOP, {"BITS": 0}),
    ("spi_cpol_above_range", SPI_TOP, {"CPOL": 2}),
    ("spi_cpol_below_range", SPI_TOP, {"CPOL": -1}),
    ("spi_cpha_above_range", SPI_TOP, {"CPHA": 2}),
    ("spi_cpha_below_range", SPI_TOP, {"CPHA": -1}),
    ("spi_cs_active_low_above_range", SPI_TOP, {"CS_ACTIVE_LOW": 2}),
    ("spi_cs_active_low_below_range", SPI_TOP, {"CS_ACTIVE_LOW": -1}),
    ("gpio_pins_zero", GPIO_TOP, {"PINS": 0}),
    ("gpio_pins_negative", GPIO_TOP, {"PINS": -4}),
    ("gpio_default_level_above_range", GPIO_TOP, {"DEFAULT_INPUT_LEVEL": 2}),
    ("gpio_default_level_below_range", GPIO_TOP, {"DEFAULT_INPUT_LEVEL": -1}),
    ("gpio_contention_error_above_range", GPIO_TOP, {"CONTENTION_IS_ERROR": 2}),
    ("gpio_contention_error_below_range", GPIO_TOP, {"CONTENTION_IS_ERROR": -1}),
)

#: label, top, overrides, the message the corrupted expectation must produce.
#: The SPI hook only bites for a CPHA=0 mode, which is why mode 0 is used here.
NEGATIVE_CONTROLS = (
    (
        "uart_negative_control",
        UART_TOP,
        {"BAUD_DIV": 2},
        "S1 the transmitted stop bits are held at the idle level",
    ),
    (
        "spi_negative_control",
        SPI_TOP,
        {"CPOL": 0, "CPHA": 0},
        "S2 a CPHA=0 selection presents the armed byte first bit before the first clock edge",
    ),
    (
        "gpio_negative_control",
        GPIO_TOP,
        {"PINS": 4},
        "S4 both sides driving the same value is not a contention",
    ),
)


def result_lines(stdout: str) -> list[str]:
    """Every bench-produced result line, in order."""
    return [line.strip() for line in stdout.splitlines() if line.strip().startswith("RESULT:")]


def assert_simulation_passed(
    case: unittest.TestCase, result: subprocess.CompletedProcess[str], label: str
) -> None:
    """A run passes only with a zero exit status and exactly one PASS line."""
    case.assertEqual(0, result.returncode, f"{label}: vvp exit status\n{result.stdout}{result.stderr}")
    case.assertEqual(["RESULT: PASS"], result_lines(result.stdout), f"{label}: bench result line\n{result.stdout}")


def parameter_echo(top: str, parameters: dict[str, int]) -> str:
    """The NOTE line the bench prints for the effective parameterization."""
    effective = dict(BENCHES[top]["defaults"])
    effective.update(parameters)
    return " ".join(f"{key}={effective[key]}" for key in BENCHES[top]["defaults"])


def compile_and_run(
    directory: Path, top: str, label: str, parameters: dict[str, int]
) -> tuple[subprocess.CompletedProcess[str], subprocess.CompletedProcess[str] | None]:
    """Compile one peer plus the bench with iverilog and run it with vvp."""
    iverilog, vvp = shutil.which("iverilog"), shutil.which("vvp")
    if iverilog is None or vvp is None:  # pragma: no cover - guarded by skipUnless
        raise unittest.SkipTest("Icarus Verilog is not installed")
    executable = directory / f"{top}_{label}.vvp"
    overrides = [token for key, value in parameters.items() for token in ("-P", f"{top}.{key}={value}")]
    compiled = subprocess.run(
        [
            iverilog,
            "-g2012",
            "-s",
            top,
            *overrides,
            "-o",
            str(executable),
            str(BENCHES[top]["source"]),
            str(TESTBENCH),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=COMPILE_TIMEOUT_SECONDS,
    )
    if compiled.returncode != 0:
        return compiled, None
    executed = subprocess.run(
        [vvp, str(executable)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=RUN_TIMEOUT_SECONDS,
    )
    return compiled, executed


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class SocPeersRtlTests(unittest.TestCase):
    def test_peers_behaviour_passes_for_every_parameterization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, top, parameters in PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executed = compile_and_run(root, top, label, parameters)
                    self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    assert_simulation_passed(self, executed, label)
                    self.assertIn(f"NOTE: {top} {parameter_echo(top, parameters)}", executed.stdout)
                    self.assertIn(f"NOTE: suite={BENCHES[top]['suite']}", executed.stdout)

    def test_deliberately_broken_expectation_is_detected(self) -> None:
        """Negative control: a corrupted expectation must not report PASS."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, top, parameters, message in NEGATIVE_CONTROLS:
                with self.subTest(parameterization=label):
                    parameters = dict(parameters, NEGATIVE_CONTROL=1)
                    compiled, executed = compile_and_run(root, top, label, parameters)
                    self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    self.assertNotEqual(0, executed.returncode, "a failing bench must exit non-zero")
                    self.assertNotIn("RESULT: PASS", executed.stdout)
                    self.assertIn("RESULT: FAIL:", executed.stdout)
                    self.assertIn(message, executed.stdout)

    def test_invalid_parameters_are_rejected(self) -> None:
        """The peers must fail closed outside the frozen parameter limits."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for label, top, parameters in INVALID_PARAMETERIZATIONS:
                with self.subTest(parameterization=label):
                    compiled, executed = compile_and_run(root, top, f"invalid_{label}", parameters)
                    if compiled.returncode != 0:
                        continue  # Elaboration rejection is also a valid fail-closed outcome.
                    self.assertIsNotNone(executed)
                    assert executed is not None
                    self.assertNotEqual(0, executed.returncode, "Invalid configuration was silently accepted")
                    self.assertNotIn("RESULT: PASS", executed.stdout)


class SocPeersHarnessNegativeControls(unittest.TestCase):
    """Cheap, tool-free checks that the result parsing really can fail."""

    def test_result_line_parsing_is_strict(self) -> None:
        self.assertEqual(["RESULT: PASS"], result_lines("NOTE: x\nRESULT: PASS\nvvp: $finish called at 1\n"))
        self.assertEqual(["RESULT: FAIL: nope"], result_lines("RESULT: FAIL: nope\nFATAL: x\n"))
        self.assertEqual([], result_lines("nothing to report\n"))

    def test_pass_assertion_rejects_missing_or_extra_results(self) -> None:
        passing = subprocess.CompletedProcess([], 0, "RESULT: PASS\n", "")
        assert_simulation_passed(self, passing, "synthetic")  # must not raise
        for stdout in ("no result line\n", "RESULT: FAIL: broken\n", "RESULT: PASS\nRESULT: FAIL: late\n", ""):
            with self.subTest(stdout=stdout):
                with self.assertRaises(AssertionError):
                    assert_simulation_passed(self, subprocess.CompletedProcess([], 0, stdout, ""), "synthetic")
        with self.assertRaises(AssertionError):
            assert_simulation_passed(self, subprocess.CompletedProcess([], 1, "RESULT: PASS\n", ""), "synthetic")

    def test_parameter_echo_covers_every_frozen_parameter(self) -> None:
        self.assertEqual(
            "DATA_WIDTH=8 BAUD_DIV=2 STOP_BITS=1 IDLE_LEVEL=1 TIMEOUT_BITS=4 NEGATIVE_CONTROL=0",
            parameter_echo(UART_TOP, {"BAUD_DIV": 2}),
        )
        self.assertEqual(
            "BITS=4 CPOL=1 CPHA=1 CS_ACTIVE_LOW=0 NEGATIVE_CONTROL=0",
            parameter_echo(SPI_TOP, {"BITS": 4, "CPOL": 1, "CPHA": 1, "CS_ACTIVE_LOW": 0}),
        )
        self.assertEqual(
            "PINS=4 DEFAULT_INPUT_LEVEL=1 CONTENTION_IS_ERROR=1 NEGATIVE_CONTROL=1",
            parameter_echo(GPIO_TOP, {"PINS": 4, "DEFAULT_INPUT_LEVEL": 1, "CONTENTION_IS_ERROR": 1, "NEGATIVE_CONTROL": 1}),
        )

    def test_every_bench_is_covered_by_the_frozen_tables(self) -> None:
        """No bench may be reachable only through a negative control."""
        covered = {top for _, top, _ in PARAMETERIZATIONS}
        self.assertEqual(set(BENCHES), covered)
        self.assertEqual(set(BENCHES), {top for _, top, _, _ in NEGATIVE_CONTROLS})
        for top, bench in BENCHES.items():
            self.assertTrue(bench["source"].is_file(), bench["source"])
            self.assertIn("NEGATIVE_CONTROL", bench["defaults"], top)
        self.assertTrue(TESTBENCH.is_file(), TESTBENCH)


if __name__ == "__main__":
    unittest.main()
