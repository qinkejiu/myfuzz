# Bug Fixes and Concise CLI Design

Date: 2026-09-15

## Goal

Fix the four reproduced correctness gaps in SoC campaign acceptance and RTL,
then provide one concise, backward-compatible entry point:

```text
python -m myfuzz check
python -m myfuzz preflight [options]
python -m myfuzz run [options]
```

Existing scripts remain supported.

## Design

### Campaign evidence

A campaign may report `completed` only when the requested fuzz duration was
actually reached, completed FIFO receipts are valid, RTL coverage and
source/target transaction evidence are non-zero, the retained corpus has a
verified manifest, cleanup is clean, and rebuild/replay passed. Interrupted
client termination uses the same evidence gate. Matrix effective budget is
computed from accepted measured task durations, never from planned duration.

The matrix runner supplies a production rebuild callback to every task. The
existing `--rebuild-replay` option becomes an explicit replay operation rather
than a path probe; invalid or failed replay keeps the matrix incomplete.

### Matrix validation

The matrix loader requires exactly the six CPU/family cells plus one mixed cell
per CPU. It cross-checks cell metadata with the referenced configuration and
derives the distinct peripheral count instead of trusting a declared number.

### RTL fixes

`soc_router` quarantines an abandoned downstream response when reset occurs in
either `WAIT_RSP` or `CAPTURE_RSP`.

The AXI4 adapter advances an INCR burst by `2**ARSIZE` bytes. Tests cover a
two-beat 32-bit transfer on a 64-bit data bus, where the second address is
`first + 4`, not `first + 8`.

### CLI

Add `src/myfuzz/__main__.py` with three commands:

- `check`: run the fast campaign/matrix contract tests and return their status.
- `preflight`: invoke the existing matrix runner in preflight mode.
- `run`: invoke the real matrix runner; retain the existing opt-in and
  300-second minimum.

Shared options are limited to `--matrix`, `--output`, `--seconds`, and `--seed`.
`run` additionally accepts `--client`. Help text and README examples remain
short; advanced users can continue using the underlying scripts.

## Error handling and compatibility

All failures return a non-zero exit status and preserve the existing structured
reports. No command silently downgrades a real run to preflight. Existing
Python APIs and script command lines remain available.

## Testing

Each reproduced bug receives a regression test that is observed failing before
the implementation changes. CLI tests cover help, argument forwarding, exit
codes, and the opt-in boundary. Verification runs focused suites first, then
the complete unittest suite.
