# P0-2 CPU-only route with real DUT assertions (Ibex)

Date: 2026-11-02. Scope: agent C, CPU-only mode plus DUT assertion capture.

## Result

A standalone CPU-only route now builds and runs **one pinned Ibex RVFI CPU**
from the existing local-harness cache with host RAM and no target IP or DMA. The
same pinned CPU is also built with the upstream developer assertions enabled; a
declared spurious data response makes Ibex's own
`NoMemResponseWithoutPendingAccess` and `PendingAccessTrackingCorrect`
assertions fire. Assertions are captured from a child process with exact source
file/line and the current case/input, and a bus/case timeout is classified as an
environment failure instead of an assertion.

## Files and shared hunk

New: `scripts/inprocess_cpu_only.py`, `scripts/inprocess_cpu_only_host.cpp`,
`scripts/run_cpu_only.py`, `configs/scenarios/p0-cpu-only-ibex.json`,
`tests/integration/test_p0_cpu_only.py`, `runs/p0-cpu-only/*`, this report.

Shared file hunk (additive only) in `src/myfuzz/local_harness/build.py`:

- `ASSERTION_VERILATOR_FLAGS = ('--assert',)`
- `assertion_build_flags(*, rtl_assertions=False)` which appends `-UVERILATOR`
  only when the caller asks for upstream `prim_assert` standard macros.

No existing build argv or cache key changes. `scripts/run_inprocess_f1f6.py` was
not edited.

## Exact commands

```bash
python3 scripts/run_cpu_only.py --records 0x1,0x2,0x3,0x100,0xffffffff \
  --output runs/p0-cpu-only/normal
python3 scripts/run_cpu_only.py --fuzz 16 --seed 1 --output runs/p0-cpu-only/fuzz
python3 scripts/run_cpu_only.py --fault --output runs/p0-cpu-only/assertion
python3 scripts/run_cpu_only.py --records 0x1 --max-ticks 1 \
  --output runs/p0-cpu-only/environment-bus-timeout
python3 -m pytest tests/integration/test_p0_cpu_only.py -q
```

## Evidence

| Run | Status | Cases | Ticks/retires | Wall |
| --- | --- | --- | --- | --- |
| normal fixed records | `observations_passed` | 5 | 69 / 23 | 0.004141 s |
| seeded fuzz | `observations_passed` | 16 | 179 / 67 | 0.004439 s |
| declared fault | `assertion_failed` (exit 3) | 1 | 30 / 5 | 0.004411 s |
| bus/case timeout | `environment_failed` (exit 4) | 1 | 18 / 3 | 0.004406 s |
| second CPU (CV32E40P) | `observations_passed` | 3 | 50 / unknown | 0.004372 s |

Normal program: `lui`, `lw`, `addi`, `sw`, `jal`; each case loads the mailbox
word, adds one and stores the result. Per-case host wall (from the `case` lines)
is 23, 6, 5, 5, 5 microseconds for the five-record batch. The host preloads a sentinel different from
the expected result, so the `0xffffffff -> 0` wrap case still requires a real
CPU store.

Assertion events (`runs/p0-cpu-only/assertion/result.json`):

- `ibex_top.sv:1472`, `PendingAccessTrackingCorrect`
- `ibex_core.sv:1391`, `NoMemResponseWithoutPendingAccess`

Both are captured from the child's Verilator report with `case=0`,
`fault=spurious-data-rvalid`, `tick=30`; the declared fault tick is 30 and the
host runs an instruction-only `jal x0, 0` program, so the spurious
`data_rvalid_i` is not a legitimate load/store response.

Second CPU: `configs/scenarios/p0-cpu-only-cv32e40p.json` uses the pinned
CV32E40P profile/cache and the same host with no composition change. Its
`result.json` reports `signal_status.retirement='unknown'` and `trap='unknown'`
(no RVFI pair is exported), and every case prints `retires=unknown`, never
`retires=0`. The Ibex config requires RVFI; a config requiring an absent signal
is refused with `cpu-only-required-observation-missing` before a model build.
Multi-domain or non-unit-ratio CPU clock schedules are refused with
`cpu-only-clock-shape-unsupported`; a missing instruction/data bus role is
refused with `cpu-only-bus-shape-unsupported`. The CPU-only host owns exactly one
clock and one normalized reset, so it does not pretend to serve a timed or
multi-clock model.
A fault request on a scenario with no declared fault is refused with
`cpu-only-fault-not-declared`.

Archive evidence: each build's `archives` list has one entry,
`Vlocal_cpu__ALL.a`, `kind=cpu`, `module=local_cpu`; the host link command names
only that archive plus host sources and the Verilator runtime. See
`runs/p0-cpu-only/model-archives.{txt,json}`.

## Assertion capture mechanism

`--assert` is passed explicitly. The assertion build additionally passes
`-UVERILATOR`, because Ibex's `prim_assert.sv` selects dummy macros whenever
Verilator predefines that tool macro; the standard macro header is read from the
same pinned Ibex tree. The host sets
`VerilatedContext::fatalOnError(false)` before evaluation, so a failed assertion
prints the Verilator `%Error: ... Assertion failed` text and sets
`gotError()/gotFinish()` without terminating the process. The host emits
`assertion tick=... case=... got_error=1 got_finish=1` and exits 3. The Python
runner launches the host as a child process and keeps stdout/stderr, so the
text/file/line survive even if a future model aborts. A per-case timeout is
emitted as `environment_error reason=case_timeout` and exits 4; it produces no
assertion event.

## Scope boundary

Items 1 (mixed APB3+TL-UL targets), 2 (IRQ topology), 3 (DMA routing to
TL-UL/Wishbone/AXI4-Lite) and 5 (arbitrary profile behavior) are not claimed by
this CPU-only route and were not edited here; they belong to the P0-1/P0-2
protocol, IRQ and DMA owners. Item 4/6 are addressed only in the CPU-only sense:
one CPU at a time, host RAM, real CPU bus, required-signal refusal, and a second
pinned CPU profile. No normal bus success is promoted to retirement, trap, IRQ,
coverage or certificate evidence.

## Limitations (declared, not hidden)

The baseline normal batch uses the pinned CPU's default Verilator assertion
macro selection (dummy Ibex assertions). The assertion build is used for the
negative case. This is deliberate: the upstream Ibex RF-write SVA
(`RFWriteFromOneSourceOnly`, `NoMemRFWriteWithoutPendingLoad`) false-fires under
Verilator's post-edge sampling when the host returns a load response. No
normal-run assertion coverage is claimed for the baseline model, and no
coverage/certificate/replay claim is made for any run. A fetch/RVFI event is an
observation, not a retirement certificate.

## Reproduce

The pinned CPU artifact is
`runs/stage2-stepD2-cache/007450f9afee9d36d42052b4da76d0f29715787c42ccbed9dcfcde988f2b8f0c`
(profile `configs/cpus/ibex_rvfi_local/component_profile.json`). Model/host
cache is `runs/p0-cpu-only/cache`; re-running the commands above is a cache hit.
