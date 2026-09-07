# Shared native bus Task 1 evidence

Status: implemented and locally verified; independent main review remains an integration gate.
Implementation SHA: `ab2eaa6999c58f264aae852ab901e16ea7283276`.
This report is committed separately so the implementation SHA is exact, not self-referential.
Worktree: `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`.
Requirements read: plan Global Constraints and Task 1 only; approved design was not reopened.

## Changes and ownership

- `auto.py`: permits reuse only for APB3, APB4 and Wishbone Classic, after existing capability/ambiguity checks.
- `protocol_composer.py`: validates route groups and renders one native adapter per shared endpoint; widened unsigned decode bounds represent an exclusive end of `2**address_width`.
- `shared_native_bus.py`: deterministic grouping derived from validated IR routes, not cached metadata. One existing protocol-native adapter holds global address/payload and owns phase/timeout/abort state. Downstream fanout translates each address, gates both request controls, and multiplexes only the selected target response. Unmapped requests complete through a native error default target. No CPU-name dispatch.
- `test_shared_native_bus.py`: source-backed three-target fixture, rejection tests and six real Icarus simulations.
- No usage guide, RFuzz implementation, source annotations, existing native adapters or user-owned files edited. The dirty `task-2-report.md`, `third_party/`, and concurrent RFuzz work were not staged by this worker.

## RED

Exact command (worktree above):

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.integration.test_shared_native_bus
```

Before production edits, `test_three_targets_one_source` caught `AutoCompositionError` and called `self.fail(str(error))`. All three protocol subtests failed with:

```text
AssertionError: generic:adapter:single-target-source:bus
Ran 1 test in 0.044s
FAILED (failures=3)
```

Initial GREEN with the same command:

```text
Ran 1 test in 0.322s
OK
```

## Final GREEN

Same shared-only command, after all bench assertions and runtime supervision:

```text
......
----------------------------------------------------------------------
Ran 6 tests in 1.266s

OK
```

Exact combined regression command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.integration.test_shared_native_bus tests.integration.test_native_protocol_composition tests.integration.test_axi_lite_native_composition tests.integration.test_generic_composition
```

Final result:

```text
Ran 58 tests in 3.136s
OK
```

The existing generic CLI negative test deliberately prints argparse usage and `generate_composition.py: error: generic options require --interface-description`; its success-path mock also prints the existing JSON publication result. These are expected test output, not test failures. `git diff --check` exited 0 with no output.

Baseline before production edits: native APB/WB plus AXI-Lite modules, 19 tests in 1.062s, OK.

One intermediate harness-only run produced six errors: the RSS supervisor's `last_output_line` is `None` for plain-text PASS lines because it retains recognized JSON metrics only. Each simulator had already exited 0. The test now reads the actual Icarus text log (`vvp -l`); no synthetic coverage metric was introduced. The subsequent 58-test runs passed.

## Real RTL coverage and resources

Icarus: `14.0 (devel) (f493076)`. Every shared runtime compiles the generated top, source host and three distinct register modules using real `iverilog -g2012 -s tb`; it runs real `vvp`. Cases cover APB3/APB4/WB Classic, each with ordinary windows and a region ending at 65536 for a 16-bit address bus.

- Write/read all three targets; translated local address selects delayed/error/never-ready behavior.
- APB back-to-back different regions with PSEL continuously asserted; setup/access phases; setup abort and setup timeout.
- Wishbone Classic completion, STB drop with CYC held, and reissue; no pipelined STALL support.
- Target waits and errors, access timeout, unmapped 768 and highest unmapped 65535; highest mapped 65535 with exclusive end 65536.
- Live source address/data changed during a waiting write; downstream held selection/payload checked through readback.
- Inactive targets deliberately assert completion/data; per-tick assertions reject request-control leakage. Exact write counters reject duplicate/cross-target writes.
- Abort a stalled write, recover on another target; reset during a stalled transfer and verify all three read back zero.
- Source-backed reset polarity, address width and direction mismatches fail closed. Shared control/contract/field mismatches fail closed; ambiguous compatible masters remain rejected; shared AXI-Lite remains rejected.

Sequential tests, JOBS=1, nice15, no waveform calls/files. Each final shared VVP run uses the existing `run_supervised_command`, a new owned process group, 20-second duration bound, 1-second checkpoints and default 512/768 MiB soft/hard group-RSS limits. Tests assert completed status, zero exit code and no soft-limit crossing. Builds are small sequential Icarus/lint invocations, with explicit subprocess timeouts; no large CPU builds were performed. Earlier characterization runs used subprocess timeouts before runtime RSS supervision was added.

## Limitations / main review handoff

- Evidence is synthetic source-backed RTL with testbench-driven host bus pins, not actual CPU instruction execution and not live RFuzz feedback. Task 2 remains independently owned by main.
- Existing native adapter latency and recovery rules are retained: APB setup timeout drains until PSEL drops; WB completion/timeout drains until CYC or STB drops. No arbitration, pipelining, shared AXI, opaque-protocol sharing, clock crossing or IRQ fan-in was added.
- Structural groups support arbitrary target counts; behavioral tests exercise exactly three targets. Unknown structs/parameters still rely on existing fail-closed source validation.
- Independent reviewer tools were unavailable in this worker. Local code inspection and regressions were performed, but are not represented as independent review. Main must independently review before broader protocol support/integration.
