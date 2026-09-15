# Bug Fixes and Concise CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the reproduced SoC acceptance and RTL correctness gaps and add a concise `python -m myfuzz` CLI without breaking existing scripts.

**Architecture:** Keep campaign truth in `soc_campaign.py`, matrix truth in `run_soc_campaigns.py`, and protocol behavior in the existing RTL modules. The new module CLI delegates to those APIs instead of duplicating planning or execution logic. Every behavior change is introduced by a failing regression test.

**Tech Stack:** Python 3 standard library, `unittest`, SystemVerilog, Icarus Verilog, existing RFuzz/Verilator integration.

## Global Constraints

- Preserve existing scripts and Python APIs unless a new optional argument is added.
- Never report planned time as effective fuzz time.
- A completed campaign requires verified corpus evidence and successful rebuild/replay.
- Real execution still requires `MYFUZZ_SOC_REAL=1`; matrix tasks remain serial and at least 300 seconds each.
- Do not overwrite existing output directories or user-modified files.
- Commit steps are conditional: never stage a pre-existing user hunk merely because the same file is touched by this plan.

---

### Task 1: Make campaign completion evidence fail closed

**Files:**
- Modify: `tests/integration/test_soc_rfuzz_live.py`
- Modify: `tests/integration/test_soc_rfuzz_build.py`
- Modify: `src/myfuzz/integration/soc_campaign.py`

**Interfaces:**
- Consumes: `run_soc_campaign(config, output, ..., builder, runner, rebuilder)` and runner result mappings.
- Produces: `_campaign_evidence_gaps(...) -> list[str]` and completion reports whose `effective_fuzz_seconds` and replay state are verified.

- [ ] **Step 1: Write failing evidence-gate tests**

Add table-driven tests whose runner independently returns zero duration, zero coverage, no source transactions, no target transactions, an unverified corpus, an invalid receipt status/transport, or no rebuilder. Each must assert `status == "incomplete-evidence"` and the matching name in `evidence_missing`. Keep one fully evidenced case with a mocked successful rebuild/replay.

```python
for field, expected_gap in cases:
    with self.subTest(field=field):
        result = run_campaign_with(field)
        self.assertEqual("incomplete-evidence", result["status"])
        self.assertIn(expected_gap, result["evidence_missing"])
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.integration.test_soc_rfuzz_live tests.integration.test_soc_rfuzz_build -v
```

Expected: the new cases fail because the current gate accepts incomplete evidence.

- [ ] **Step 3: Implement one shared evidence gate**

Validate completed receipt semantics, measured fuzz duration, positive coverage, positive observed source/target transactions, verified corpus manifest, clean cleanup, and a successful non-empty rebuild replay. Use the time at the deadline interrupt when present; otherwise use the runner duration.

```python
effective = run_result.get("interrupt_elapsed_seconds",
                           run_result.get("duration_seconds", 0))
if effective < normal["duration_seconds"]:
    gaps.append("requested_fuzz_duration")
if report["replay"].get("status") != "passed":
    gaps.append("rebuild_replay")
```

If no explicit `rebuilder` is supplied, reuse the callable build hook to build into `output/rebuild`; an artifact-only campaign remains incomplete because it cannot prove independent rebuild.

- [ ] **Step 4: Verify GREEN**

Run the command from Step 2. Expected: all tests pass, including interrupted-run policy tests.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/integration/soc_campaign.py tests/integration/test_soc_rfuzz_live.py tests/integration/test_soc_rfuzz_build.py
git commit -m "fix: require complete SoC campaign evidence"
```

### Task 2: Validate matrix shape and report measured budget

**Files:**
- Modify: `tests/integration/test_soc_campaign_matrix.py`
- Modify: `scripts/run_soc_campaigns.py`

**Interfaces:**
- Consumes: matrix JSON and per-task `soc_result.v1` reports.
- Produces: strict `load_matrix`, measured `effective_budget_seconds`, and automatic per-task rebuild/replay through `run_soc_campaign`.

- [ ] **Step 1: Write failing matrix tests**

Add tests that reject eight unique rows all describing `ibex/pulp`, reject a mixed cell missing one family, reject mismatched cell/config CPU metadata, and prove a failed or short task contributes zero measured budget. Assert a matrix cannot become `completed` when any task replay is not `passed`.

```python
self.assertRaisesRegex(ValueError, "six CPU/family cells", load_matrix, bad_path)
self.assertEqual(0, result["effective_budget_seconds"])
self.assertEqual("incomplete", result["status"])
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.integration.test_soc_campaign_matrix -v
```

Expected: malformed grids are accepted and planned time is reported as effective time.

- [ ] **Step 3: Implement strict shape/config checks and measured accounting**

Require the exact set below and cross-check each referenced cell configuration:

```python
required = {(cpu, family) for cpu in ("ibex", "cva6")
            for family in ("opentitan", "pulp", "zipcpu")}
mixed = {("ibex", "mixed"), ("cva6", "mixed")}
```

Compute effective budget only from task reports whose status is accepted and whose measured `effective_fuzz_seconds` reaches the task requirement. Require `replay.status == "passed"` for every accepted row.

- [ ] **Step 4: Turn `--rebuild-replay` into an operation**

For an existing matrix directory, reconstruct every task config from its manifest, build a fresh artifact under a new output directory, run `replay_corpus` on that task's retained `live/corpus`, and emit one row per task. Any missing corpus, build failure, identity mismatch, or replay failure produces non-zero status; the option must never return `available-not-executed`.

- [ ] **Step 5: Verify GREEN**

Run the command from Step 2 and a temporary-directory replay fixture. Expected: all matrix tests pass.

- [ ] **Step 6: Commit**

```bash
git add scripts/run_soc_campaigns.py tests/integration/test_soc_campaign_matrix.py
git commit -m "fix: validate and measure SoC campaign matrices"
```

### Task 3: Quarantine router responses across CAPTURE_RSP reset

**Files:**
- Modify: `tests/protocols/test_soc_fabric_rtl.py`
- Modify: `src/myfuzz/protocols/rtl/soc_router.sv`

**Interfaces:**
- Consumes: router state and downstream ready/valid response.
- Produces: `stale_pending=1` after reset in either response-wait state when downstream targets are not reset.

- [ ] **Step 1: Add the failing RTL regression**

Drive a response valid while the router is in `WAIT_RSP`, advance it to `CAPTURE_RSP`, assert router-only reset before the response handshake edge, then assert that the old response is quarantined and a new request is not accepted.

```systemverilog
check(t_rsp_valid[0] && t_rsp_ready[0], "router entered CAPTURE_RSP");
reset = 1'b1; tick(); reset = 1'b0; #1;
check(stale_pending && !req_ready,
      "reset quarantines the response exposed during CAPTURE_RSP");
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_soc_fabric_rtl.SocFabricRtlTests.test_reset_during_capture_quarantines_old_response -v
```

Expected: failure with `stale_pending=0` and `req_ready=1`.

- [ ] **Step 3: Implement the minimal state fix**

```systemverilog
else if ((state_q == WAIT_RSP) || (state_q == CAPTURE_RSP)) begin
    stale_q <= 1'b1;
    stale_target_q <= target_q;
end
```

- [ ] **Step 4: Verify GREEN and the fabric suite**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_soc_fabric_rtl -v
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols/rtl/soc_router.sv tests/protocols/test_soc_fabric_rtl.py
git commit -m "fix: quarantine router response across capture reset"
```

### Task 4: Advance AXI INCR bursts by ARSIZE

**Files:**
- Modify: `tests/protocols/test_axi4_processor_memory_adapter_rtl.py`
- Modify: `src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv`

**Interfaces:**
- Consumes: accepted `ARADDR`, `ARLEN`, and `ARSIZE`.
- Produces: backend beat addresses incremented by `1 << ARSIZE` for legal INCR bursts.

- [ ] **Step 1: Add the failing 64-bit narrow-burst test**

Instantiate `DATA_WIDTH=64`, issue `ARLEN=1`, `ARSIZE=2`, `ARBURST=INCR` at address `0x100`, and require backend addresses `0x100` then `0x104` with byte enables `0x0f` then `0xf0` as appropriate for the two transfer addresses.

```systemverilog
check(req_addr_o == 32'h0000_0104,
      "narrow INCR advances by four bytes, not the eight-byte bus width");
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_axi4_processor_memory_adapter_rtl.Axi4ProcessorMemoryAdapterRtlTests.test_narrow_two_beat_read_uses_arsize_stride -v
```

Expected: the second request is `0x108` and the test fails.

- [ ] **Step 3: Latch ARSIZE and use its stride**

Add `read_size_q`, clear it on reset, latch it with AR, derive `read_next_addr`, and recompute the byte-enable mask from that address before issuing the next backend request.

```systemverilog
wire [ADDRESS_WIDTH-1:0] read_next_addr =
    read_addr_q + (ADDRESS_WIDTH'(1) << read_size_q);

read_addr_q <= read_next_addr;
read_be_q <= read_be_from_axi(read_size_q, read_next_addr[2:0]);
```

- [ ] **Step 4: Verify GREEN and the adapter suite**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.protocols.test_axi4_processor_memory_adapter_rtl -v
```

Expected: all tests pass for full-width and narrow bursts.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv tests/protocols/test_axi4_processor_memory_adapter_rtl.py
git commit -m "fix: honor AXI read burst transfer size"
```

`tests/protocols/test_axi4_processor_memory_adapter_rtl.py` already contains an
uncommitted user hunk. Do not stage the file wholesale; commit only an exactly
isolated new hunk, or leave this task uncommitted for user review.

### Task 5: Add the concise module CLI and documentation

**Files:**
- Create: `src/myfuzz/__main__.py`
- Create: `tests/test_cli.py`
- Modify: `README.md`
- Modify: `scripts/run_soc_campaigns.py`

**Interfaces:**
- Produces: `python -m myfuzz {check,preflight,run}`.
- Delegates: `preflight` and `run` to `scripts.run_soc_campaigns.run_matrix`.

- [ ] **Step 1: Write failing CLI tests**

Test top-level help, `check`, preflight argument forwarding, `run --client` propagation, output-exists errors, and missing real opt-in. Use temporary outputs and mocks for `run`; do not launch a real campaign.

```python
process = subprocess.run(
    [sys.executable, "-m", "myfuzz", "--help"],
    env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    capture_output=True, text=True,
)
self.assertEqual(0, process.returncode)
self.assertIn("{check,preflight,run}", process.stdout)
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.test_cli -v
```

Expected: `No module named myfuzz.__main__`.

- [ ] **Step 3: Implement the module entry point**

Use `argparse` with three subparsers. `check` runs the focused contract/RTL test modules in a child Python process. `preflight` and `run` call `run_matrix`; `run --client PATH` passes an explicit client without mutating global environment. Errors print one concise line to stderr and return 2.

```python
commands = parser.add_subparsers(dest="command", required=True)
commands.add_parser("check", help="run fast correctness checks")
```

- [ ] **Step 4: Add concise README usage**

Add only:

````markdown
## CLI

```bash
PYTHONPATH=src python3 -m myfuzz check
PYTHONPATH=src python3 -m myfuzz preflight --output runs/preflight
MYFUZZ_SOC_REAL=1 PYTHONPATH=src python3 -m myfuzz run \
  --client runs/rfuzz_client_native_build/target/debug/kfuzz \
  --output runs/soc-acceptance/run-1
```
````

- [ ] **Step 5: Verify GREEN**

Run:

```bash
PYTHONPATH=src python3 -m unittest tests.test_cli tests.integration.test_soc_campaign_matrix -v
PYTHONPATH=src python3 -m myfuzz --help
PYTHONPATH=src python3 -m myfuzz check
```

Expected: all tests pass and help remains compact.

- [ ] **Step 6: Commit**

```bash
git add src/myfuzz/__main__.py tests/test_cli.py README.md scripts/run_soc_campaigns.py
git commit -m "feat: add concise myfuzz CLI"
```

### Task 6: Final verification

**Files:**
- Verify only; modify a task's files only if its regression exposes a related defect.

**Interfaces:**
- Produces: fresh verification evidence for the complete change set.

- [ ] **Step 1: Run focused suites**

```bash
PYTHONPATH=src python3 -m unittest \
  tests.integration.test_soc_rfuzz_live \
  tests.integration.test_soc_rfuzz_build \
  tests.integration.test_soc_campaign_matrix \
  tests.protocols.test_soc_fabric_rtl \
  tests.protocols.test_axi4_processor_memory_adapter_rtl \
  tests.test_cli -v
```

- [ ] **Step 2: Run the complete suite**

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py'
```

Expected: zero failures; report the exact test and skip counts.

- [ ] **Step 3: Check formatting and scope**

```bash
git diff --check HEAD~5..HEAD
git status --short
```

Confirm only planned files plus pre-existing user changes are present.

- [ ] **Step 4: Record the verification commit if documentation changed**

```bash
git add README.md
git commit -m "docs: document verified myfuzz CLI"
```

Skip this commit when README was already included in Task 5 and no further change is needed.
