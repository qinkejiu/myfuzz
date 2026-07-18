# Quickstart

## Verify frozen A/v2/v3 artifacts

The preserved baseline inventory can be checked without reconstructing its
original path-selection command. This is a read-only path/size/SHA-256 check:

```sh
python3 src/myfuzz/scripts/freeze_artifact_inventory.py \
  --root . \
  --label a-v2-v3-baseline-20260715 \
  --output build/inventory/a-v2-v3-baseline-20260715.json \
  --check
```

Any missing file, symlink replacement, size change, content change, root
mismatch, malformed entry, or inventory digest mismatch fails closed. The
command does not rewrite the inventory or any preserved experiment artifact.

## Read v4 legality diagnostics

Each generated v4 target freezes `evidence/protocol_legality_rules.json`.
Campaign reports keep the scheduler choice in `declared_lane_counts` separate
from the waveform monitor result in `observed_classification_counts`. A raw
testcase can therefore remain classified as `raw` while still recording a
protocol violation.

`violation_rule_counts` counts all monitored violations.
`first_violation_points` keeps only the earliest testcase and cycle for each
rule, including its declared lane and observed classification. Its memory use
is bounded by the fixed rule table rather than by campaign duration.

## Generic RawBits v4 CPU/IP smoke

Build a system directly from its structure document, then serially exercise every
declared address target through both a CPU RV32I fragment and protocol-level
RawBits records:

```bash
python3 src/myfuzz/scripts/protocol_system_builder_v4.py \
  --spec examples/protocol_system_v2/ultra_riscv_holdout_2ip.json \
  --project-root . \
  --output-dir build/protocol_system_v4_ultra_2ip \
  --cpu-profile ultra_riscv \
  --protocol-testcases 500 \
  --records-per-testcase 16 \
  --wall-seconds 30 \
  --timeout-seconds 30 \
  --jobs 1
```

The command writes `command_report.json` and `smoke_report.json`. A passing smoke
requires each declared target component to gain CPU-driven branch coverage over
an idle control and to be reached by the protocol-waveform campaign. The command
does not modify or invoke baseline A.

The same generic command is exercised against three structurally different
two-target holdouts. Replace `--spec` and `--cpu-profile` with one row below;
all other arguments stay unchanged and every run remains `--jobs 1`.

| Spec | CPU profile | Declared target components |
| --- | --- | --- |
| `ultra_riscv_holdout_2ip.json` | `ultra_riscv` | `ip.regs0`, `ip.lfsr0` |
| `picorv32_wb2axip_holdout_2ip.json` | `picorv32` | `ip.gpio_bank`, `ip.apb_regs` |
| `picorv32_wb2axip_holdout_narrow_2ip.json` | `picorv32` | `ip.register_file`, `ip.empty_device` |

These names occur only in input specifications and tests. The builder derives
source ownership, ports, address windows, target widths, and connections from
the supplied structure document; it has no per-holdout module-name branch.

## Generate A Protocol-Driven System

```sh
python3 src/myfuzz/scripts/protocol_system_builder.py \
  --spec examples/materials_simple_system.json \
  --project-root . \
  --output-dir /tmp/myfuzz_materials_system \
  --wrapper \
  --rfuzz \
  --rfuzz-cycles 64 \
  --rfuzz-seed 1
```

The input declares source ownership, module kinds, protocol interfaces, clock
and reset domains, address requests, parameters, and policies for otherwise
unknown ports. User declarations are authoritative; profile inference fills in
only undeclared signals. See `examples/minimal_system.json` for a compact input
and `examples/materials_simple_system.json` for a complete local integration.

Inspect `generation_report.json` first. It summarizes classifications,
inference evidence, address and connection counts, unknown-port decisions,
wrapper status, RFUZZ outputs, and any validation failure.

To instrument the same source project as part of generation, add:

```sh
  --instrument-output /tmp/myfuzz_instrumented \
  --instrument-force
```

Use `--instrument-filelist <sources.f>` when the preserved instrumenter should
also emit an instrumented filelist.

## Instrument Verilog/SystemVerilog

```sh
python3 src/myfuzz/instrumentation/source_branch_instrumenter.py \
  --project-root <rtl-root> \
  --out-dir /tmp/myfuzz_instrumented \
  --flist <sources.f> \
  --top-module <top> \
  --force
```

This copies the RTL tree, inserts branch coverage signals where supported, and
writes `instrumentation.json` plus an instrumented filelist when `--flist` is
provided.

## Generate RFUZZ Input Bytes

```sh
python3 src/myfuzz/rfuzz/input_generator.py \
  --generated-dir <harness-metadata-dir> \
  --output-dir /tmp/myfuzz_rfuzz \
  --cycles 1024 \
  --seed 1
```

The output is a `.bin` byte stream and a `.json` action trace. The byte stream
preserves the old RFUZZ-style 0/1 driving capability while allowing the harness
to interpret action classes such as WAIT, UART, PIN, MMIO, and scenarios.

## Use Materials

Keep protocol/IP/CPU source materials under `materials/`. Legacy generated
cases remain reusable inputs, not active generation logic.
