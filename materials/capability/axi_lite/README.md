# Scaled AXI-Lite Capability Systems

This frozen, non-acceptance capability set builds two directly comparable SoCs.
They use different native AXI-Lite CPUs and the same eight IP instances. The
four IP implementations are each instantiated twice so the experiment grows
the instrumentation denominator without changing the workload mix:

- PicoRV32 `picorv32_axi` CPU, approximately 3k source lines
- UltraEmbedded RISC-V CPU/TCM subsystem, approximately 8.5k source lines
- 2 x verilog-axi single-port RAM
- 2 x verilog-axi dual-port RAM wrapper
- 2 x PULP `axi_lite_regs`
- 2 x PULP `axi_lite_lfsr`

The formal Slice H qualification denominator remains unchanged. This case is a
supplemental integration check and must not be reported as holdout acceptance.

Regenerate or verify the offline content lock:

```sh
PYTHONPATH=src python3 materials/capability/axi_lite/freeze_manifest.py
PYTHONPATH=src python3 materials/capability/axi_lite/freeze_manifest.py --check
```

Build, instrument, compile, and execute paired RAW/CONSTRAINED runs:

```sh
PYTHONPATH=src python3 materials/capability/axi_lite/run_capability.py \
  --output build/capability/axi_lite_scale --jobs 2
```

The output includes generated SoC/fabric/binding RTL, verified SystemIR,
address and connection graphs, port decisions, instrumentation provenance, a
compiled Verilator target, RawBits v2 input, per-cycle coverage traces, and
`capability_report.json`.

To measure the effect of the generated AXI-Lite harness constraints, use the
separate controlled A/B experiment:

```sh
PYTHONPATH=src python3 materials/capability/axi_lite/run_constraint_effect.py \
  --output build/capability/axi_lite_constraint_effect --jobs 2 \
  --cycles 256 --seeds 1,2,3,4,5
```

Both modes replay the same RawBits testcase against the same compiled SoC and
coverage ABI. RAW maps random bits directly to AXI-Lite wires. CONSTRAINED uses
the generated protocol FSM to select mapped addresses, hold requests stable
until handshake, and wait for write/read responses.

## Address Map

| IP | Base | Size |
| --- | ---: | ---: |
| verilog-axi RAM 0 | `0x0000_0000` | 64 KiB |
| verilog-axi RAM 1 | `0x0001_0000` | 64 KiB |
| verilog-axi dual-port RAM 0 | `0x0002_0000` | 4 KiB |
| verilog-axi dual-port RAM 1 | `0x0002_1000` | 4 KiB |
| PULP AXI-Lite registers 0 | `0x0002_2000` | 4 KiB |
| PULP AXI-Lite registers 1 | `0x0002_3000` | 4 KiB |
| PULP AXI-Lite LFSR 0 | `0x0002_4000` | 4 KiB |
| PULP AXI-Lite LFSR 1 | `0x0002_5000` | 4 KiB |

The directory also retains frozen ZipCPU WB2AXIP compatibility candidates.
They elaborate as AXI-Lite peripherals, but the current source-branch
instrumenter exports no internal points for those traditional-Verilog modules,
so they are deliberately excluded from this coverage-scale denominator.
