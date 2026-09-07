# Task 2 simulator portion: implementation evidence

Implementation SHA: `4783f1184aafabadbab75bc077d7d294d4966f2b`.
Task 1 review-hardening SHA: `af348c395e9d488a165f1a05e7734ae39e793a30`.
Status: simulator portion implemented and locally verified; main owns live client/wire/projection/IPC integration and independent review.
This report is a separate commit so the implementation SHA is exact.

## Scope / interfaces

Only `src/myfuzz/integration/rfuzz_simulator.py` and the main-authored RED fixture
`tests/integration/test_rfuzz_simulator.py` were included in the simulator commit.
The separate Task 1 commit modified only its test and existing evidence report.
No main-owned wire, runtime projection, FIFO, shared-memory, vendor, or dirty
Task 2 report files were changed/staged by this worker.

`build_simulator(plan, output_dir, *, base_dir, coverage_ports)`:

- Revalidates source-backed plan freshness. Rejects existing output directories
  and symlinks. Generic composition is published in fresh `output/composition`.
- Derives external ports by excluding all validated route fields, then excludes
  semantic clock/reset pins from the input ABI. Retains remaining layout field
  constraints, encoding, provenance and relative field order, repacking offsets
  and hashing the runtime layout independently.
- Derives clock/reset from semantic field bindings, then proves reset polarity
  and synchrony through the existing HDL verifier. Does not branch on CPU names
  or infer semantics from renamed physical pin spellings.
- Rejects unbound declared protocol fields, multiple clock/reset domains,
  ambiguous input bindings, empty/oversized input layouts, unrepresentable
  projection constraints, missing/input/out-of-range/duplicate observations.
- Returns `SimulatorArtifact.layout`, `.transport`, `.executable`,
  `.coverage_ports`, `.projector` and explicit `.coverage_kind`.
- Writes `runtime_layout.json`, `runtime_transport.json`, `observations.json`,
  `live_tb.sv`, `sim.vvp`, and separately supervised build diagnostics.

`RtlSimulator(artifact, *, timeout_seconds=5.0)` is a context manager with
`run_test(records)` and idempotent `close()`. One private persistent Icarus child
accepts a per-test cycle count followed by raw hex samples on stdin. Each test
resets the DUT for two clock cycles, drives one projected sample per cycle,
samples selected output bits after the driven edge, and returns ordered bytes.
The existing transport codec unpacks each byte record; main's `RuntimeProjector`
is applied to every unpacked raw word before it reaches RTL. Transport padding
does not drive inputs.

Counter meaning is **sampled-output-bit-events-u8-saturating**, not branch,
toggle, line, instruction, or inferred Python coverage. Each counter increments
when its explicitly selected output bit is asserted after a sample cycle and
saturates at 255. X or Z observations fail closed. No synthetic coverage metrics
are submitted to the campaign supervisor.

## RED / GREEN

All commands ran in `/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`.

Initial exact RED command, before simulator implementation:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.integration.test_rfuzz_simulator
```

Main's two tests both failed in `setUp`:

```text
AssertionError: unexpectedly None : live layout-to-RTL simulator missing
Ran 2 tests in 0.000s
FAILED (failures=2)
```

Initial GREEN with the same command:

```text
Ran 2 tests in 0.682s
OK
```

Additional targeted RED:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.integration.test_rfuzz_simulator.RfuzzSimulatorTests.test_unknown_observation_fails_closed_and_cleans_up
```

```text
FAIL ... (unknown='z')
AssertionError: (<class 'ValueError'>, <class 'RuntimeError'>) not raised
Ran 1 test in 0.400s
FAILED (failures=1)
```

The bench originally rejected X only; case-inequality checks now reject both X
and Z. The subsequent reset-matrix test exposed three unsupported cases:
active-high asynchronous and both synchronous polarities. Inspection showed
that the crawler's inferred control bundle was empty while explicit semantic
bindings remained valid. The simulator now binds those declared controls before
invoking the existing source verifier. No crawler/projection changes were made.

Final focused GREEN (same shared simulator command above):

```text
..........
----------------------------------------------------------------------
Ran 10 tests in 4.047s

OK
```

Exact combined regression command:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest tests.integration.test_rfuzz_simulator tests.integration.test_shared_native_bus tests.integration.test_native_protocol_composition tests.integration.test_axi_lite_native_composition tests.integration.test_generic_composition tests.composition.test_rfuzz_transport tests.composition.test_runtime_projection
```

```text
Ran 79 tests in 7.160s
OK
```

Existing generic CLI negative tests print expected argparse usage and
`generic options require --interface-description`; the existing publication
mock prints its JSON result. These are not regressions. `git diff --check`
exited zero without output.

## Behavioral / resource evidence

- Real generated RTL and real Icarus compilation/execution, not a mock simulator.
- Renamed and original pin fixtures replay the same two-cycle counter trajectory
  `01 01 01`; an intervening zero-input test yields `00 00 00` and replay matches.
- All four reset polarity/synchrony combinations replay deterministically using
  renamed controls and source-verified reset semantics.
- 300 observation cycles saturate at `ff`; counters and DUT reset on the next
  test. The child PID remains unchanged across valid tests.
- A real three-target shared APB composition exposes only its extra 8-bit fuzz
  input in the runtime layout, excluding every routed bus field and clock/reset.
- A real RuntimeProjector alignment constraint changes 3 to 2 per sample; RTL
  sees states 2 and 4 and returns `00 01 01`.
- Invalid record size, zero/excessive cycle counts, invalid observations,
  unbound protocol, multiple clocks and unsupported constraints are rejected.
- SIGSTOP of the owned VVP process tests both blocked-read (one sample) and
  blocked-write (65536 samples) deadlines. Both raise TimeoutError, close the
  simulator and reap its child. Normal context exit is also verified.
- Runtime stdin/stdout are nonblocking with a shared per-exchange deadline;
  reply length/framing are bounded. Maximum 65536 cycles, 8 MiB encoded sample
  IO, 65536 raw bits and 4096 observation bits. Deadlines are finite and at most
  60 seconds; cleanup uses owned-group TERM then KILL and bounded waits.
- Builds are serial, JOBS=1, nice15 (or lower inherited priority), with the
  existing 30-second build supervisor and 512/768 MiB group-RSS policy. Runtime
  polls owned-group RSS during exchanges and conservatively closes at the
  512 MiB soft ceiling, before the 768 MiB hard ceiling. No waveform generation.

## Main handoff / limitations

This is synthetic source-backed RTL event-counter evidence. It is not actual
CPU execution, upstream RFuzz mutation/corpus acceptance, or branch coverage.
Main still owns the real-client campaign and its acceptance gates.

The simulator imports main-owned `runtime_projection.py`; main must integrate
that module alongside this commit. No wire/FIFO/shared-memory protocol is
implemented here. The runtime record ABI is `artifact.transport`, not the
unfiltered composition-level layout that also contains dedicated controls.

The source reset verifier intentionally accepts only its existing provable HDL
forms. Only one verified physical clock/reset domain is supported. The runtime
is sequential, not a concurrent request server. Failed build output is retained
for inspection and will not be silently overwritten on retry. Unexpected DUT
stdout, X/Z observations, malformed framing, IO failure or deadline closes the
child rather than returning guessed counters.

Local code review and regressions were performed. No independent reviewer-agent
tool was available in this worker; main review remains required for this new
simulator portion. Main already reported Task 1 review PASS before its separate
test-only PENABLE/STB hardening commit.
