"""Focused Task 13 regression for nonzero RISC-V boot image placement."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

from myfuzz.integration.riscv_execution import (
    RiscvExecutionFacts,
    RiscvExecutionProvenance,
    build_minimal_boot_image,
)


ROOT = Path(__file__).resolve().parents[2]
RAM = ROOT / "src/myfuzz/integration/rtl/riscv_boot_memory.sv"


class NonzeroBootMappingTests(unittest.TestCase):
    def test_images_are_loaded_at_reset_vector_for_32_and_64_bit_ram(self) -> None:
        iverilog = shutil.which("iverilog") or str(Path.home() / ".local/bin/iverilog")
        vvp = shutil.which("vvp") or str(Path.home() / ".local/bin/vvp")
        if not Path(iverilog).is_file() or not Path(vvp).is_file():
            self.skipTest("Icarus Verilog is not installed")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for width, isa, module in (
                (32, "rv32imc", "riscv_boot_memory_32"),
                (64, "rv64imafdc", "riscv_boot_memory_64"),
            ):
                with self.subTest(width=width):
                    image = build_minimal_boot_image(RiscvExecutionFacts(
                        isa=isa, xlen=width, reset_vector=0x80,
                        pass_address=0x400, pass_value=0x600DCAFE,
                        protocol=("obi", "1") if width == 32 else ("axi4", "1"),
                        max_cycles=400,
                        provenance=RiscvExecutionProvenance(
                            source_identity="fixture-source", source_hash="sha256:" + "1" * 64,
                            profile_identity="fixture-profile", profile_hash="sha256:" + "2" * 64,
                            interface_identity="fixture-interface", interface_hash="sha256:" + "3" * 64,
                            isa=isa, xlen=width, reset_vector=0x80,
                        ),
                    ), root / f"rv{width}")
                    self.assertEqual(0x80, image.load_base)
                    self.assertEqual(0x80, image.reset_vector)
                    self.assertEqual("@00000080", image.memory_hex_path.read_text().splitlines()[0])

                    expected = int.from_bytes(
                        image.binary_path.read_bytes()[: width // 8], "little"
                    )
                    bench = root / f"ram{width}_tb.sv"
                    executable = root / f"ram{width}.vvp"
                    bench.write_text(textwrap.dedent(f"""
                        module tb;
                          logic clock=0, reset=0, flush=0, req_valid=0, req_ready;
                          logic write=0, rsp_valid, rsp_ready=1, error;
                          logic [{width-1}:0] addr=0, wdata=0, rdata;
                          logic [{width//8-1}:0] be='0;
                          always #1 clock=~clock;
                          {module} dut(.*);
                          task tick; begin @(posedge clock); #1; end endtask
                          task read_check(input [{width-1}:0] address,
                                          input [{width-1}:0] expected);
                            begin
                              addr=address; req_valid=1; tick(); req_valid=0;
                              while (!rsp_valid) tick();
                              if (error || rdata !== expected)
                                $fatal(1,"address %h returned %h expected %h",address,rdata,expected);
                              tick();
                            end
                          endtask
                          task write_full(input [{width-1}:0] address,
                                          input [{width-1}:0] value);
                            begin
                              addr=address; wdata=value; be='1; write=1; req_valid=1; tick();
                              req_valid=0; write=0;
                              while (!rsp_valid) tick();
                              if (error) $fatal(1,"valid write errored at %h",address);
                              tick();
                            end
                          endtask
                          task expect_error(input write_value, input [{width-1}:0] address,
                                            input [{width-1}:0] value);
                            begin
                              addr=address; wdata=value; be='1; write=write_value; req_valid=1; tick();
                              req_valid=0; write=0;
                              while (!rsp_valid) tick();
                              if (!error) $fatal(1,"crossing request accepted at %h",address);
                              tick();
                            end
                          endtask
                          initial begin
                            tick(); reset=1; tick();
                            read_check({width}'h0, {width}'h0);
                            read_check({width}'h80, {width}'h{expected:0{width//4}x});
                            write_full({width}'d{4092 if width == 32 else 4088}, {width}'h{0x11223344 if width == 32 else 0x0807060504030201:0{width//4}x});
                            expect_error(1, {width}'d{4094 if width == 32 else 4090}, {width}'h{0xaabbccdd if width == 32 else 0xaaaaaaaaaaaaaaaa:0{width//4}x});
                            expect_error(0, {width}'d{4094 if width == 32 else 4090}, '0);
                            read_check({width}'d{4092 if width == 32 else 4088}, {width}'h{0x11223344 if width == 32 else 0x0807060504030201:0{width//4}x});
                            $display("PASS width={width} load_base=00000080 data=%h",rdata);
                            $finish;
                          end
                        endmodule
                    """), encoding="ascii")
                    compiled = subprocess.run(
                        (iverilog, "-g2012", "-s", "tb", "-o", str(executable),
                         str(RAM), str(bench)),
                        cwd=ROOT, text=True, capture_output=True, timeout=20,
                    )
                    self.assertEqual(0, compiled.returncode, compiled.stdout + compiled.stderr)
                    simulated = subprocess.run(
                        (vvp, str(executable), f"+riscv_boot_image={image.memory_hex_path}"),
                        cwd=ROOT, text=True, capture_output=True, timeout=20,
                    )
                    self.assertEqual(0, simulated.returncode, simulated.stdout + simulated.stderr)
                    self.assertIn(f"PASS width={width} load_base=00000080", simulated.stdout)


if __name__ == "__main__":
    unittest.main()
