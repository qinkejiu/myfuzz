# Independent-component dataflow runtime

The host coordinates independent CPU and peripheral RTL harnesses and carries
their transactions and memory state between them. It does not instantiate a
SoC. A scenario descriptor selects the component profiles, wiring and flow
sources. A mixed campaign prepares these once and executes the ordered cases in
one persistent session.

For the existing OBI CPU and APB timer descriptor, a short directed run is:

```sh
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json \
  --flow mixed --mode original --case /tmp/myfuzz-example \
  --cache /tmp/myfuzz-cache --rounds 32 --record-local-commands \
  --record F1:13000000 --record F3:78563412 \
  --record F4:55000000 --record F2:04100040
```

The records are little-endian hexadecimal bytes. F1 currently accepts one
supported non-memory 32-bit instruction; F3 accepts one 32-bit store value;
F4 writes the timer register and F2 reads its configured address. The round
count controls the number of component advances per case, so a shorter run is
not equivalent to the descriptor's default budget. The original run also
replays the sequence on newly started component processes. Inspect the
per-case certificates for observations and unknowns; submission alone does not
prove instruction retirement or all source-to-effect causality.

To replay a sequence exported by another tool, put an ordered JSON array such
as `["F4:55000000", "F2:04100040"]` in a file and pass
`--records-file PATH` in place of the `--record` options. Each entry must use
the same flow and byte encoding expected by this scenario; malformed or
unsupported records are rejected before component execution. This measures
the exported inputs in this system's harness, not the other tool's own online
coverage or throughput.

`original/local_commands.json` contains the optional bounded wire trace. Its
session identity includes the build digest. Use that digest to select the
corresponding cache directory and replay one component with Verilator line/block
instrumentation:

```sh
python3 scripts/measure_local_coverage.py \
  --trace /tmp/myfuzz-example/original/local_commands.json \
  --component peripheral --cache /tmp/myfuzz-cache/BUILD_DIGEST \
  --output /tmp/myfuzz-peripheral-coverage
```

The tool requires the original and instrumented binaries to produce identical
responses, including the recorded responses. It currently accepts at most 512
commands from a complete trace. `coverage.json`, `coverage-points.json` and
`coverage.dat` retain the measurement and point universe. To compare two
measurements from the same component build:

```sh
python3 scripts/compare_local_harness_coverage.py \
  --cache /tmp/myfuzz-cache/BUILD_DIGEST \
  /tmp/myfuzz-peripheral-coverage /tmp/other-peripheral-coverage
```

These are Verilator line/block points, not source-branch or semantic coverage.
A fair comparison with another fuzzer additionally requires a compatible
measurement for that tool and documented time, execution, seed and reset
budgets; the comparator does not infer them.

F5 uses the existing independent Ibex and PULP GPIO sessions. Its descriptor
exposes GPIO B bit 8, fixes unrelated inputs and declares the real pulse IRQ.
Run a rising input and record the actual commands:

```sh
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f5-ibex-pulp-gpio/generic_scenario.json \
  --flow F5 --mode original --case /tmp/myfuzz-f5-example \
  --cache /tmp/myfuzz-cache --record-local-commands \
  --record F5:0000000100000000
```

F5 currently uses exactly 32 advance rounds per case. In its inherited
eight-byte encoding, the low bit of the fourth byte selects GPIO B bit 8's
level. Raw receipts append to `receipts.jsonl`; `receipts.json` contains compact
case summaries. Observations include GPIO input, physical IRQ and CPU IRQ input; retirement
and ISR causality remain unknown. A full original/fresh native replay and CPU
and GPIO coverage measurement passed under `/tmp/myfuzz-generic-f5-trace-run2`.

F6 has a separate CPU/DMA backend and its admission can use prepared provider
credentials. Run it through the same CLI with its own descriptor:

```sh
python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f6-ibex-wbdmac/generic_scenario.json \
  --flow F6 --mode original --case /tmp/myfuzz-f6-example \
  --cache /tmp/myfuzz-cache --record-local-commands \
  --record F6:0110c00008000000
```

The F6 descriptor defaults to 256 advance rounds per case. An unfinished
transfer is a failure, and a partial prefix cannot be accepted as a fresh
replay. Use `--rounds` explicitly for a different budget (up to 4096); large
budgets can be expensive when a required completion condition never appears.

The F5 and F6 backends are standalone. Both modes run an independent invocation and
replay that invocation; `--mode fresh` does not compare a previous invocation's
directory. Reports state `replay_scope=within_invocation` and their evidence
directory. Their original and fresh commands are recorded separately in
`local_commands.json` and `fresh_local_commands.json`, with observed execution
nonce, PID and binary identity. These files use the same measurement CLI above.
All three execution paths now save `summary.json`. F5 and shared F1–F4 also
reuse one cleanup routine, including child-process cleanup after a partial
start or an early finalization failure. F5/F6 share their command exporter;
F6's audited build, binary, PID and artifact checks remain required.

F5 assembly still uses the shipped Ibex/PULP CPU-and-two-GPIO configuration,
including its pin-8 source and initialization. Supporting another composition
currently requires replacing that assembly with component adapters; changing
the descriptor alone does not yet make an arbitrary CPU/IP combination work.

The recorded F5 run measured 51/189 DUT line/block points in GPIO B and
504/1655 in its CPU; the F6 recorded run measured 163/188 in the DMA. Each
instrumented replay matched both the original binary's response stream and the
actual session recording. These are directed-input measurements, not a fuzzer
ranking. The comparison tool also completed a same-build CPU comparison of two
different input sequences (412 versus 418 of 1655 points); equal seed/time
budgets and an actual external-tool experiment remain to be established.

Its original and fresh native runs matched in
`/tmp/myfuzz-f6-live-run9` (235.57 seconds), including all four cross-component
edges; independent saved semantic projections also passed. This evidence
belongs to that recorded source snapshot. The unified CLI was separately
verified under `/tmp/myfuzz-generic-f6-run1` with full replay matching. The
generic F6 plan and shared execution are not connected yet, and the complete
supervisor-based saved acceptance remains outstanding.

The continuation fixed two actual final-case failures: park is now an
unmaterialized instruction boundary, and the next case's first request can
retain its exact prior-case observation roots while all typed transaction and
physical-handshake checks remain mandatory. Two native cases and full fresh
replay passed in 138.26 seconds at 256 rounds per case under
`/tmp/myfuzz-f6-two-case-fixed`; both cases passed all five observation groups.
The original run advanced the CPU to tick 285 and DMA to tick 323.
A [compact run summary](reports/evidence/dataflow-continuation-20261027-summary.json)
retains the source hashes, per-case results and command counts; the full raw
events remain in the run directory.

For fast entry, firmware and coverage-tool feedback, run:

```sh
PYTHONPATH=src:. python3 -m pytest -q \
  tests/runtime/test_generic_f5_entry.py \
  tests/runtime/test_generic_f6_entry.py \
  tests/runtime/test_external_sequence_cli.py \
  tests/runtime/test_generic_campaign_cleanup.py \
  tests/runtime/test_recorded_commands.py \
  tests/integration/test_compiled_f6_firmware.py \
  tests/integration/test_measure_local_coverage.py \
  tests/integration/test_compare_local_harness_coverage.py
```

These software checks do not replace a native original/fresh run after a
change to scheduling, bindings or physical handshakes.

After the common cleanup changes, a fresh four-case F1/F3/F4/F2 native run and
full replay passed in 108.41 seconds under
`/tmp/myfuzz-common-execution-core`. Both component processes exited normally
and were reaped. F1/F3 remained `submitted`; F4/F2 were `effective`, with the
read observing the prior write of 85. See the
[common-execution summary](reports/evidence/dataflow-common-execution-20261027-summary.json).

The `/tmp` locations above identify historical runs; those artifacts are not
bundled with this checkout. Re-run the commands to obtain evidence for the
current source snapshot.
