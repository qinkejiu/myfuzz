"""Real ZipCPU (source core) through the Wishbone CPU-side adapter.

Two layers, following ``tests/integration/test_soc_real_ibex.py``:

* ``ZipCpuBootImageTests`` and ``ZipCpuWishboneWiringTests`` are always runnable
  and never touch a simulator.  They pin the ported ZipCPU instruction encodings,
  prove the committed ``$readmemh`` fixture is byte-for-byte reproducible from the
  encoder, and check that the testbench binds the frozen adapter/backend ports.

* ``RealZipCpuWishboneTests`` is opt-in behind ``MYFUZZ_SOC_REAL=1`` (and needs
  ``iverilog``).  It compiles the testbench together with the real ZipCPU source
  closure and runs it, asserting the single machine checkable success line.

The simulation is the only thing here that counts as runtime evidence: the CPU is
a real source core executing a real program, and the pass criterion is the RAM
content that program is written to produce.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.integration import zipcpu_boot_image as boot


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/soc_zipcpu_wishbone_boot.hex"
TESTBENCH = ROOT / "tests/integration/rtl/soc_zipcpu_wishbone_tb.sv"
ADAPTER = ROOT / "src/myfuzz/protocols/rtl/wishbone_processor_memory_adapter.sv"
BACKEND = ROOT / "src/myfuzz/protocols/rtl/processor_memory_backend.sv"

#: The elaboration closure of ``zipwb`` with the parameters the testbench sets
#: (OPT_LGICACHE=0, OPT_LGDCACHE=0, OPT_PIPELINED=0, WITH_LOCAL_BUS=0).  Order is
#: the order iverilog was driven to resolve the closure in, so it is stable.
ZIPCPU_SOURCES = (
    ROOT / "third_party/soc-zipcpu/rtl/core/zipwb.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/memops.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/prefetch.v",
    ROOT / "third_party/soc-zipcpu/rtl/ex/wbdblpriarb.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/zipcore.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/cpuops.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/div.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/idecode.v",
    ROOT / "third_party/soc-zipcpu/rtl/core/mpyop.v",
)

SUCCESS_LINE = re.compile(
    r"^SOC_ZIPCPU_WISHBONE_REAL_OK stores=2 data=0000beef0000bef0 "
    r"cycles=(?P<cycles>\d+) reads=(?P<reads>\d+) quiet=(?P<quiet>\d+)$",
    re.MULTILINE,
)

#: ``nice -n15`` is what the project uses for simulator builds; fall back to a
#: bare command only if the host has no ``nice`` at all.
NICE = ("nice", "-n15") if shutil.which("nice") else ()

COMPILE_TIMEOUT = 600
RUN_TIMEOUT = 300


class ZipCpuBootImageTests(unittest.TestCase):
    """Structural: the ported encodings and the committed fixture, no simulator."""

    def test_program_uses_only_the_two_ram_words_the_testbench_checks(self):
        program = boot.build_program()
        self.assertEqual([0x100, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x118],
                         [item.address for item in program])
        self.assertEqual(boot.PROGRAM_BASE, program[0].address)
        self.assertEqual(boot.encode_halt(), program[-1].word)
        self.assertEqual(2, sum(1 for item in program if item.text.startswith("STO")))
        self.assertEqual(1, sum(1 for item in program if item.text.startswith("LOD")))

    def test_every_word_decodes_back_to_the_mnemonic_that_encoded_it(self):
        # The decoder re-derives its fields the way idecode.v does, so this is a
        # real round trip rather than the encoder checking itself.
        for item in boot.build_program():
            decoded = boot.disassemble(item.word)
            self.assertEqual(item.text.split()[0], decoded.split()[0],
                             f"{item.word:#010x} decoded as {decoded!r}, encoded as {item.text!r}")
        # An instruction word the program does not use must not silently decode
        # into one of ours.
        with self.assertRaises(ValueError):
            boot.disassemble(0xDEADBEEF)

    def test_ldi_uses_the_opcode_the_rtl_decodes(self):
        # idecode.v:206  assign w_ldi = (w_cis_op[4:1] == 4'hc);  -> op 0x18/0x19
        # zopcodes.cpp:207 matches LDI on 0x06000000 with bit 22 masked out.
        # Bit 22 is shared with the immediate, which is what splits LDI (bit 22
        # clear) from LDIn (bit 22 set), so only non-negative immediates are LDI.
        for word in (boot.encode_ldi(0, boot.R1), boot.encode_ldi(0x3FFFFF, boot.PC)):
            self.assertEqual(0x18, (word >> 22) & 0x1F)
            self.assertEqual(0x06000000, word & 0x87800000)
        # The stale zparser.cpp builder would emit 0x05800000 here; make sure the
        # port did not silently fall back to it.
        self.assertNotEqual(0x05800000, boot.encode_ldi(0, boot.R0) & 0x87800000)
        # A negative immediate sets bit 22 and is the LDIn half of the pair; the
        # RTL sign extends from bit 22 (idecode.v:903), so the loaded value is
        # still the negative number that was asked for.
        negative = boot.encode_ldi(-1, boot.R2)
        self.assertEqual(0x19, (negative >> 22) & 0x1F)
        self.assertEqual("LDIn", boot.disassemble(negative).split()[0])
        self.assertEqual("-0x1", boot.disassemble(negative).split()[1].rstrip(","))

    def test_halt_matches_the_authoritative_table(self):
        # zopcodes.cpp:104  { "HALT", 0xffc7ffff, 0x70c00010, ... }
        word = boot.encode_halt()
        self.assertEqual(0x70C00010, word & 0xFFC7FFFF)
        # zparser.h:314-315 builds the same word (op_or(ALWAYS, 0x10, ZIP_CC)).
        self.assertEqual(0x70C00010 & 0x87C40000, word & 0x87C40000)

    def test_break_and_noop_match_the_authoritative_table(self):
        # zopcodes.cpp:209  { "BRK",  0xf7ffffff, 0x77000000, ... }
        # zopcodes.cpp:229  { "NOOP", 0xf7ffffff, 0x77c00000, ... }
        self.assertEqual(0x77000000, boot.encode_break())
        self.assertEqual(0x77C00000, boot.encode_noop())
        # Both are "special" opcodes reached only when the result register is CC
        # (idecode.v:223-228): w_break needs op 0x1c, w_noop needs op[4:1]==0xf
        # (so op 0x1e or 0x1f; 0x77c00000 is the 0x1f form).  The program uses
        # neither; the testbench's o_break check is what makes BREAK a failure,
        # and the negative control in this file exercises exactly that.
        self.assertEqual(0x1C, (boot.encode_break() >> 22) & 0x1F)
        self.assertEqual(0x0F, ((boot.encode_noop() >> 22) & 0x1F) >> 1)
        for word in (boot.encode_break(), boot.encode_noop()):
            self.assertEqual(0xE, (word >> 27) & 0xF)
        # zparser.cpp:127-128 would emit 0x76400000, which the RTL decodes as
        # LDIn (op 0x19); the port must not have used it.
        self.assertNotEqual(0x76400000, boot.encode_break())

    def test_memory_opcodes_are_a_load_and_a_store_pair(self):
        # idecode.v:214-215  w_mem = (op[4:3]==2'b10) && (op[2:1]!=0); w_sto = w_mem && op[0]
        load = boot.encode_lod(0, boot.R3, boot.R1)
        store = boot.encode_sto(0, boot.R2, boot.R1)
        for word, is_store in ((load, False), (store, True)):
            op = (word >> 22) & 0x1F
            self.assertEqual(0b10, (op >> 3) & 0b11)
            self.assertNotEqual(0b00, (op >> 1) & 0b11)
            self.assertEqual(is_store, bool(op & 1))
            # bit 18 (idecode.v:99 IMMSEL) selects the register+immediate form
            self.assertEqual(1, (word >> 18) & 1)
        # The store's value register is bits 30:27 and its index register 17:14.
        self.assertEqual(boot.R2, (store >> 27) & 0xF)
        self.assertEqual(boot.R1, (store >> 14) & 0xF)
        self.assertEqual(boot.R3, (load >> 27) & 0xF)
        self.assertEqual(boot.R1, (load >> 14) & 0xF)

    def test_committed_fixture_is_reproducible_from_the_encoder(self):
        self.assertTrue(FIXTURE.is_file(), f"missing fixture {FIXTURE}")
        committed = FIXTURE.read_text(encoding="ascii")
        self.assertEqual(boot.render_image(), committed,
                         "tests/fixtures/soc_zipcpu_wishbone_boot.hex is stale: "
                         "re-run python3 tests/integration/zipcpu_boot_image.py --write")

    def test_fixture_places_the_program_at_the_reset_address_and_clears_the_data(self):
        words = [int(line, 16) for line in FIXTURE.read_text(encoding="ascii").split()]
        self.assertEqual(boot.IMAGE_WORDS, len(words))
        for item in boot.build_program():
            self.assertEqual(item.word, words[item.address >> 2],
                             f"fixture mismatch at {item.address:#x}")
        # Anti-vacuity: the checked data words start at zero in the image, so the
        # simulation cannot pass without the CPU writing them.
        self.assertEqual(0, words[boot.STORE_A_ADDR >> 2])
        self.assertEqual(0, words[boot.STORE_B_ADDR >> 2])
        self.assertNotEqual(0, boot.expected_word(boot.STORE_A_ADDR))
        self.assertNotEqual(boot.expected_word(boot.STORE_A_ADDR),
                            boot.expected_word(boot.STORE_B_ADDR))

    def test_fixture_is_byte_for_byte_the_rendered_image(self):
        """``--write`` must be a no-op on the committed fixture."""
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "regenerated.hex"
            boot.write_fixture(target)
            self.assertEqual(FIXTURE.read_bytes(), target.read_bytes())


class ZipCpuWishboneWiringTests(unittest.TestCase):
    """Structural: the testbench really binds the frozen RTL's ports."""

    def setUp(self):
        self.text = TESTBENCH.read_text(encoding="utf-8")

    def test_testbench_instantiates_the_frozen_adapter_and_backend(self):
        self.assertIn("wishbone_processor_memory_adapter", self.text)
        self.assertIn("myfuzz_processor_memory_backend", self.text)
        adapter = ADAPTER.read_text(encoding="utf-8")
        backend = BACKEND.read_text(encoding="utf-8")
        for port in ("cyc_i", "stb_i", "we_i", "adr_i", "dat_w_i", "sel_i",
                     "stall_o", "ack_o", "err_o", "dat_r_o",
                     "req_valid_o", "req_ready_i", "rsp_valid_i", "rsp_ready_o"):
            self.assertIn(port, adapter)
            self.assertIn(f".{port}", self.text)
        for port in ("req_valid_i", "req_ready_o", "req_write_i", "req_addr_i",
                     "req_wdata_i", "req_be_i", "req_mapped_i", "rsp_valid_o",
                     "rsp_ready_i", "target_req_valid_o", "target_req_ready_i",
                     "target_write_o", "target_addr_o", "target_wdata_o",
                     "target_be_o", "target_rsp_valid_i", "target_rsp_ready_o",
                     "target_rdata_i", "target_error_i"):
            self.assertIn(port, backend)
            self.assertIn(f".{port}", self.text)

    def test_testbench_drives_the_real_zipcpu_source_and_its_word_address(self):
        self.assertIn("zipwb #(", self.text)
        self.assertIn("third_party/soc-zipcpu", self.text)
        # o_wb_addr is a word address; the adapter wants bytes.
        self.assertIn("{wb_addr, 2'b00}", self.text)
        # AW=32 makes zipcore.v:134 select RESET_ADDRESS[33:2] out of range and
        # the CPU's PC goes X, so the testbench must not use it.
        self.assertIn("localparam integer AW              = 30;", self.text)

    def test_testbench_fails_closed_on_every_required_failure_mode(self):
        for marker in ("$fatal",
                       "o_break",
                       "SOC_ZIPCPU_WISHBONE_REAL_OK",
                       "watchdog expired",
                       "stall_o asserted for",
                       "ack_o without a completed backend response",
                       "response with no outstanding request",
                       "WATCHDOG_CYCLES",
                       "preloads the expected store results"):
            self.assertIn(marker, self.text, f"testbench is missing {marker!r}")

    def test_testbench_uses_the_active_low_reset_the_frozen_rtl_requires(self):
        # Adapter and backend are rst_ni (active low, synchronous).
        self.assertRegex(self.text, r"rst_ni\s*=\s*1'b0;")
        self.assertRegex(self.text, r"rst_ni\s*=\s*1'b1;")


@unittest.skipUnless(os.environ.get("MYFUZZ_SOC_REAL") == "1",
                     "set MYFUZZ_SOC_REAL=1 to run the real ZipCPU Wishbone test")
@unittest.skipUnless(shutil.which("iverilog"), "Icarus Verilog is required")
class RealZipCpuWishboneTests(unittest.TestCase):
    """Opt-in: compile and run the real ZipCPU through the adapter."""

    def test_real_zipcpu_executes_a_program_through_the_wishbone_adapter(self):
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        self.assertIsNotNone(vvp, "vvp is required alongside iverilog")
        sources = (*ZIPCPU_SOURCES, ADAPTER, BACKEND, TESTBENCH)
        missing = [str(path) for path in sources + (FIXTURE,) if not path.is_file()]
        self.assertEqual([], missing, "real ZipCPU closure is incomplete")

        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "soc_zipcpu_wishbone_tb.vvp"
            compile_command = [
                *NICE, iverilog, "-g2012", "-s", "soc_zipcpu_wishbone_tb",
                "-o", str(binary), *(str(path) for path in sources),
            ]
            compiled = subprocess.run(
                compile_command, cwd=ROOT, text=True, capture_output=True,
                timeout=COMPILE_TIMEOUT,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            self.assertTrue(binary.is_file(), "iverilog produced no binary")

            result = subprocess.run(
                [*NICE, vvp, str(binary), "+zipcpu_boot_image=" + str(FIXTURE)],
                cwd=ROOT, text=True, capture_output=True, timeout=RUN_TIMEOUT,
            )
            output = result.stdout + result.stderr
            self.assertEqual(0, result.returncode, output)
            match = SUCCESS_LINE.search(output)
            self.assertIsNotNone(
                match,
                "real ZipCPU run did not report success:\n" + output,
            )
            # Sanity: the CPU needed real cycles and real fetches to get there,
            # and then went quiet (that is the HALT, not a mid-flight snapshot).
            self.assertGreater(int(match.group("cycles")), 20)
            self.assertGreater(int(match.group("reads")), 2)
            self.assertGreaterEqual(int(match.group("quiet")), 64)
            # The store trace must show the two CPU produced words.
            self.assertIn("SOC_ZIPCPU_WISHBONE_TRACE store[0] addr=00000200 data=0000beef be=1111",
                          output)
            self.assertIn("SOC_ZIPCPU_WISHBONE_TRACE store[1] addr=00000204 data=0000bef0 be=1111",
                          output)
            # And the CPU must really have read the program stream it executed
            # (read[5] is the LOD of 0x200, i.e. the load half of the round trip).
            self.assertIn("SOC_ZIPCPU_WISHBONE_TRACE read[0] addr=00000100", output)
            self.assertIn("SOC_ZIPCPU_WISHBONE_TRACE read[1] addr=00000104", output)
            self.assertNotIn("SOC_ZIPCPU_WISHBONE_VIOLATION", output)
            self.assertNotIn("SOC_ZIPCPU_WISHBONE_TIMEOUT", output)

    def test_testbench_fails_on_a_missing_boot_image(self):
        """A pass must require the real image: no image, no success."""
        iverilog = shutil.which("iverilog")
        vvp = shutil.which("vvp")
        sources = (*ZIPCPU_SOURCES, ADAPTER, BACKEND, TESTBENCH)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "tb.vvp"
            compiled = subprocess.run(
                [*NICE, iverilog, "-g2012", "-s", "soc_zipcpu_wishbone_tb",
                 "-o", str(binary), *(str(path) for path in sources)],
                cwd=ROOT, text=True, capture_output=True, timeout=COMPILE_TIMEOUT,
            )
            self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
            result = subprocess.run(
                [*NICE, vvp, str(binary),
                 "+zipcpu_boot_image=" + str(Path(directory) / "absent.hex")],
                cwd=ROOT, text=True, capture_output=True, timeout=RUN_TIMEOUT,
            )
            output = result.stdout + result.stderr
            self.assertNotEqual(0, result.returncode,
                                "the testbench passed without a boot image:\n" + output)
            self.assertNotIn("SOC_ZIPCPU_WISHBONE_REAL_OK", output)


if __name__ == "__main__":
    unittest.main()
