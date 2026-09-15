"""Real-PicoRV32 runtime benches for the two new CPU-side protocol adapters.

The same PicoRV32 core, the same assembled boot image and the same beat-level
RAM model are used twice, so the only difference between the two runs is the
initiator protocol in front of the adapter under test:

    picorv32_axi -> axi4_lite_processor_memory_adapter   (AXI4-Lite)
    picorv32_wb  -> wishbone_processor_memory_adapter    (classic Wishbone)

Both benches are ``tests/integration/rtl/soc_picorv32_*_tb.sv``.  They are not
"the CPU did not crash" smoke tests: the retired instruction stream is compared
against the committed image word for word and PC for PC through PicoRV32's RVFI
port, the byte and halfword stores are checked as whole words (so an adapter
that widened a one-byte store into a four-byte store fails), and the number of
writes that reached RAM must equal the number of stores the CPU reports
retiring.

The always-runnable part of this module pins the committed image to its
assembly source and to a hand-verified table of RV32I encodings.  The
simulations are opt-in behind ``MYFUZZ_SOC_REAL=1`` for the same reason the
Ibex boundary is: they need a PicoRV32 checkout under ``third_party`` that is
not part of this repository, plus Icarus Verilog.  A source checkout being
present is a prerequisite, not the acceptance evidence; the acceptance evidence
is the printed ``SOC_PICORV32_*_REAL_OK`` line with its accounting.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests/fixtures"
BOOT_SOURCE = FIXTURES / "soc_picorv32_boot.S"
BOOT_IMAGE = FIXTURES / "soc_picorv32_boot.hex"
PICORV32_SOURCE = ROOT / "third_party/picorv32_upstream_reference/picorv32.v"

ADAPTER_RTL = ROOT / "src/myfuzz/protocols/rtl"
BACKEND = ADAPTER_RTL / "processor_memory_backend.sv"
RAM_MODEL = ROOT / "tests/integration/rtl/soc_cpu_beat_ram.sv"
RVFI_CHECKER = ROOT / "tests/integration/rtl/soc_cpu_rvfi_checker.sv"

# The committed program, with the mnemonic each word must decode to.  These
# encodings were checked by hand against the RV32I specification, and the
# benches check them again from the other side: every word the CPU retires is
# compared with this image, so a wrong word here cannot pass unnoticed.
#
# t2 holds 0xdeadbea5 on purpose.  Its upper bytes are non-zero, so the byte and
# halfword stores of t2 must leave 0x000000a5 and 0x0000bea5 behind: an adapter
# that widened either store into a four-byte store would leave 0xdeadbea5 and
# fail.  A store value with zero upper bytes would have made that check vacuous.
PROGRAM = (
    (0x10000293, "addi t0, x0, 0x100     # data base"),
    (0x5a5a6337, "lui  t1, 0x5a5a6"),
    (0xa5a30313, "addi t1, t1, -0x5a6    # t1 = 0x5a5a5a5a"),
    (0x0062a023, "sw   t1, 0(t0)         # 0x100 full word"),
    (0xdeadc3b7, "lui  t2, 0xdeadc"),
    (0xea538393, "addi t2, t2, -0x15b    # t2 = 0xdeadbea5"),
    (0x0072a223, "sw   t2, 4(t0)         # 0x104 full word"),
    (0x00728423, "sb   t2, 8(t0)         # 0x108 one byte: 0x000000a5"),
    (0x00729623, "sh   t2, 12(t0)        # 0x10c halfword: 0x0000bea5"),
    (0x0002ae03, "lw   t3, 0(t0)         # read back"),
    (0x01c2a823, "sw   t3, 16(t0)        # 0x110 load-back"),
    (0x00c29e83, "lh   t4, 12(t0)        # signed read back: 0xffffbea5"),
    (0x01d2aa23, "sw   t4, 20(t0)        # 0x114 load-back"),
    (0x00001f37, "lui  t5, 0x1"),
    (0xff0f0f13, "addi t5, t5, -0x10     # t5 = 0xff0"),
    (0x00100f93, "addi t6, x0, 1"),
    (0x01ff2023, "sw   t6, 0(t5)         # 0xff0 completion marker"),
    (0x0000006f, "j    .                 # spin after the marker"),
)

# The two benches and the adapter each one is here to exercise.
BENCHES = {
    "axilite": {
        "top": "soc_picorv32_axilite_tb",
        "tb": ROOT / "tests/integration/rtl/soc_picorv32_axilite_tb.sv",
        "adapter": ADAPTER_RTL / "axi4_lite_processor_memory_adapter.sv",
        "adapter_module": "axi4_lite_processor_memory_adapter",
        "ok_line": "SOC_PICORV32_AXILITE_REAL_OK",
    },
    "wishbone": {
        "top": "soc_picorv32_wishbone_tb",
        "tb": ROOT / "tests/integration/rtl/soc_picorv32_wishbone_tb.sv",
        "adapter": ADAPTER_RTL / "wishbone_processor_memory_adapter.sv",
        "adapter_module": "wishbone_processor_memory_adapter",
        "ok_line": "SOC_PICORV32_WISHBONE_REAL_OK",
    },
}

# Instructions, stores and loads in the committed image.  Every one of these is
# part of the evidence the benches print.
PROGRAM_LENGTH = len(PROGRAM)
PROGRAM_STORES = 7
PROGRAM_LOADS = 2
MARKER_WORD = 0x0FF0 // 4
DATA_WORDS = {
    0x100 // 4: 0x5A5A5A5A,
    0x104 // 4: 0xDEADBEA5,
    # The byte and halfword stores must land in their own lanes only; a widened
    # store would leave 0xdeadbea5 in these two words.
    0x108 // 4: 0x000000A5,
    0x10C // 4: 0x0000BEA5,
    0x110 // 4: 0x5A5A5A5A,
    0x114 // 4: 0xFFFFBEA5,   # signed halfword load of 0xbea5
    MARKER_WORD: 0x00000001,
}


def _read_image(path: Path) -> list[int]:
    words: list[int] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        words.append(int(stripped, 16))
    return words


def _assemble(source: Path, directory: Path) -> list[int]:
    """Assemble the committed RV32I source with clang and return its words.

    The toolchain is inside clang (``--target=riscv32``) plus lld; no external
    RISC-V toolchain is needed, and the ELF text section is read back with
    readelf, which is architecture independent.
    """
    elf = directory / "boot.elf"
    assemble = subprocess.run(
        [str(shutil.which("clang")), "--target=riscv32", "-march=rv32i",
         "-mabi=ilp32", "-nostdlib", "-fuse-ld=lld", "-Wl,-Ttext=0",
         "-Wl,--no-relax", "-o", str(elf), str(source)],
        cwd=ROOT, text=True, capture_output=True, timeout=120,
    )
    if assemble.returncode != 0:
        raise AssertionError(assemble.stdout + assemble.stderr)
    dump = subprocess.run(
        [str(shutil.which("readelf")), "-x", ".text", str(elf)],
        cwd=ROOT, text=True, capture_output=True, timeout=60,
    )
    if dump.returncode != 0:
        raise AssertionError(dump.stdout + dump.stderr)
    words: list[int] = []
    for line in dump.stdout.splitlines():
        match = re.match(r"^\s+0x[0-9a-f]+\s+((?:[0-9a-f]{8}\s+)+)", line)
        if not match:
            continue
        for group in match.group(1).split():
            # readelf prints bytes in memory order; the image is little endian.
            words.append(int(group[6:8] + group[4:6] + group[2:4] + group[0:2], 16))
    return words


def _toolchain_available() -> bool:
    return all(shutil.which(tool) for tool in ("clang", "ld.lld", "readelf"))


def _picorv32_available() -> bool:
    return PICORV32_SOURCE.is_file()


def _nice() -> list[str]:
    nice = shutil.which("nice")
    return [nice, "-n15"] if nice else []


class Picorv32BootImageTests(unittest.TestCase):
    """Always runnable: the committed image is the program the benches claim."""

    def test_committed_image_is_the_hand_verified_program(self):
        words = _read_image(BOOT_IMAGE)
        self.assertEqual([word for word, _ in PROGRAM], words)
        self.assertEqual(PROGRAM_LENGTH, len(words))
        # Anchors that would break first if the source or the image drifted.
        self.assertEqual(0x10000293, words[0], "program must start at the data base setup")
        self.assertEqual(0x0000006F, words[-1], "program must end in a self jump")

    def test_committed_image_matches_its_assembly_source(self):
        if not _toolchain_available():
            self.skipTest("clang with the riscv32 target and readelf are required")
        with tempfile.TemporaryDirectory() as directory:
            words = _assemble(BOOT_SOURCE, Path(directory))
        self.assertEqual(_read_image(BOOT_IMAGE), words,
                         "soc_picorv32_boot.hex is stale: regenerate it from the .S source")

    def test_store_and_load_counts_match_what_the_benches_assert(self):
        words = _read_image(BOOT_IMAGE)
        stores = sum(1 for word in words if (word & 0x7F) == 0x23)
        loads = sum(1 for word in words if (word & 0x7F) == 0x03)
        self.assertEqual(PROGRAM_STORES, stores)
        self.assertEqual(PROGRAM_LOADS, loads)

    def test_benches_agree_with_the_image_they_run(self):
        def require(text: str, needle: str, message: str) -> None:
            if needle not in text:
                self.fail(f"{message}: {needle!r} is missing from the bench")

        for name, bench in BENCHES.items():
            with self.subTest(bench=name):
                text = bench["tb"].read_text(encoding="utf-8")
                require(text, f"localparam integer PROGRAM_LENGTH = {PROGRAM_LENGTH};",
                        "the bench must agree with the committed image length")
                require(text, f"localparam integer MARKER_WORD    = {MARKER_WORD};",
                        "the bench must agree with the completion marker address")
                require(text, bench["adapter_module"],
                        "the bench must instantiate the adapter it is named for")
                require(text, "myfuzz_processor_memory_backend",
                        "the bench must run the real generic beat backend")
                require(text, "soc_cpu_beat_ram", "the bench must use the shared RAM model")
                require(text, "soc_cpu_rvfi_checker",
                        "the bench must check the retirement trace, not just side effects")
                for address, value in DATA_WORDS.items():
                    symbol = "MARKER_WORD" if address == MARKER_WORD else str(address)
                    require(text, f"check_word({symbol}, 32'h{value:08x}"
                                  if address == MARKER_WORD
                                  else f"check_word({symbol},  32'h{value:08x}",
                            f"the bench must check memory word {address}")

    def test_the_adapter_under_test_is_the_registered_one(self):
        from myfuzz.composition.processor_adapters import resolve_processor_adapter

        for name, bench in BENCHES.items():
            with self.subTest(bench=name):
                self.assertTrue(bench["adapter"].is_file())
                self.assertIn(bench["adapter_module"],
                              bench["adapter"].read_text(encoding="utf-8"))
        # The registry must still route these two protocols to these modules.
        from tests.composition.test_processor_adapters import (
            _axi4_lite_memory, _wishbone_memory,
        )

        self.assertIn("axi4_lite_processor_memory_adapter",
                      resolve_processor_adapter(_axi4_lite_memory()).rtl_module)
        self.assertIn("wishbone_processor_memory_adapter",
                      resolve_processor_adapter(_wishbone_memory()).rtl_module)


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 for the real PicoRV32 runtime boundary")
class RealPicorv32RuntimeTests(unittest.TestCase):
    """Opt-in: real PicoRV32 silicon RTL executing through the adapter."""

    def _simulate(self, bench: dict) -> dict[str, str]:
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        self.assertIsNotNone(iverilog, "Icarus Verilog is required")
        self.assertIsNotNone(vvp, "vvp is required")
        self.assertTrue(_picorv32_available(),
                        f"missing {PICORV32_SOURCE.relative_to(ROOT)}")
        sources = [
            PICORV32_SOURCE, bench["adapter"], BACKEND, RAM_MODEL, RVFI_CHECKER,
            bench["tb"],
        ]
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "sim.vvp"
            # RISCV_FORMAL is what makes PicoRV32 publish the RVFI retirement
            # trace the benches turn into instruction-level evidence.
            compile_command = [
                *_nice(), str(iverilog), "-g2012", "-DRISCV_FORMAL",
                "-s", bench["top"], "-o", str(binary),
                *(str(source) for source in sources),
            ]
            compiled = subprocess.run(
                compile_command, cwd=ROOT, text=True, capture_output=True, timeout=900,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            run = subprocess.run(
                [str(vvp), str(binary), f"+boot_image={BOOT_IMAGE}"],
                cwd=ROOT, text=True, capture_output=True, timeout=600,
            )
        output = run.stdout + run.stderr
        self.assertEqual(0, run.returncode, output)
        self.assertIn(bench["ok_line"], output, output)
        evidence: dict[str, str] = {}
        for line in output.splitlines():
            if not line.startswith(bench["ok_line"]):
                continue
            for key, value in re.findall(r"(\w+)=(\S+)", line):
                evidence[key] = value
        return evidence

    def _assert_evidence(self, evidence: dict[str, str]) -> None:
        self.assertEqual(str(PROGRAM_LENGTH), evidence["retired"],
                         "the CPU must retire exactly the committed program")
        self.assertEqual(str(PROGRAM_STORES), evidence["stores"])
        self.assertEqual(str(PROGRAM_LOADS), evidence["loads"])
        self.assertEqual(evidence["stores"], evidence["ram_writes"],
                         "every store the CPU retired must have reached memory once")
        self.assertEqual(f"{DATA_WORDS[0x100 // 4]:08x}", evidence["data"],
                         "the loaded-back word must match what was stored")

    def test_real_picorv32_axilite_runtime(self):
        self._assert_evidence(self._simulate(BENCHES["axilite"]))

    def test_real_picorv32_wishbone_runtime(self):
        self._assert_evidence(self._simulate(BENCHES["wishbone"]))


if __name__ == "__main__":
    unittest.main()
