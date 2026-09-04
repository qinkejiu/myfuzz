# Ibex Low-Resource Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a supervised, checkpointed, single-worker Ibex campaign that runs the generated composition through the existing instrument/Verilator/RFuzz flow and publishes an atomic evidence report.

**Architecture:** A small campaign controller performs preflight and composition generation, then starts the requested child command in a new process group. A polling supervisor reads `/proc/<pid>/status`, enforces the conservative RSS limits, captures JSON-lines metrics, writes checkpoints atomically, and archives crashes or resource termination before bounded restart attempts.

**Tech Stack:** Python 3 standard library (`subprocess`, `/proc`, `os.killpg`), existing `run_design_flow.py`, JSON reports, unittest.

## Global Constraints

- Default execution is one build slot and one RFuzz worker.
- Default memory policy is 512 MiB soft, 768 MiB hard, and 64 MiB token budget.
- VCD and waveform output are disabled by the campaign config.
- RSS supervision must be available before starting the child; otherwise startup fails closed.
- Hard-limit termination targets the child process group, not the parent process.
- Checkpoints and reports use atomic replacement and never publish partial success.
- Invalid protocol samples increment error counters and do not terminate the complete campaign.
- Default campaign duration is 3600 seconds; development runs use an explicit shorter duration.
- A crash seed and replay command are included whenever a child exits abnormally.

---

### Task 1: Implement the RSS/process-group supervisor

**Files:**
- Create: `src/myfuzz/integration/campaign.py`
- Modify: `src/myfuzz/integration/__init__.py`
- Test: `tests/integration/test_campaign_supervisor.py`

**Interfaces:**
- `CampaignLimits(soft_memory_bytes: int = 512 * 1024 * 1024, hard_memory_bytes: int = 768 * 1024 * 1024, max_restarts: int = 2)`.
- `CampaignOptions(command: tuple[str, ...], output_dir: Path, duration_seconds: int = 3600, seed: int = 0, checkpoint_seconds: int = 30, limits: CampaignLimits = CampaignLimits(), env: Mapping[str, str] = field(default_factory=dict))`.
- `run_supervised_command(options: CampaignOptions) -> Mapping[str, object]`.
- Internal `read_rss_bytes(pid: int) -> int` raises `CampaignError` when `/proc/<pid>/status` is unavailable or malformed.

- [ ] **Step 1: Write failing supervisor tests**

Use a short Python child that emits JSON-line metrics and sleeps. Assert the result records duration, peak RSS, process return code, and parsed metrics. Add a child that allocates above a small test hard limit and assert the process group is terminated, a checkpoint is persisted, and the result status is `resource-terminated`.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_campaign_supervisor -v
```

Expected: import failure.

- [ ] **Step 3: Implement process-group and RSS supervision**

Launch with `subprocess.Popen(..., start_new_session=True, stdout=PIPE, stderr=STDOUT, text=True)`. Poll at 100 ms, parse only bounded JSON lines containing `transactions`, `protocol`, `component`, `coverage`, or `error`, track peak RSS, send `SIGTERM` then `SIGKILL` to `os.getpgid(pid)` at the hard limit, and close all descriptors. Verify `/proc` support before launch and return a structured startup error when unavailable.

- [ ] **Step 4: Run focused and regression tests**

Expected: supervisor tests pass and the existing integration suite remains green.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/integration/campaign.py src/myfuzz/integration/__init__.py tests/integration/test_campaign_supervisor.py
git commit -m "feat: supervise low-resource campaign processes"
```

### Task 2: Add checkpoints, crash archives, and atomic evidence reports

**Files:**
- Modify: `src/myfuzz/integration/campaign.py`
- Create: `src/myfuzz/integration/campaign_report.py`
- Test: `tests/integration/test_campaign_report.py`

**Interfaces:**
- `CampaignState` stores `seed`, `iterations`, `transactions`, `protocol_transactions`, `component_transactions`, `coverage`, `errors`, `peak_rss_bytes`, `checkpoint_count`, and `last_output_line`.
- `write_checkpoint(path: Path, state: CampaignState) -> None` writes a bounded JSON document through a same-directory temporary file and `os.replace`.
- `build_campaign_report(options: CampaignOptions, state: CampaignState, status: str, replay_command: Sequence[str] | None) -> dict[str, object]`.
- `publish_campaign_report(path: Path, document: Mapping[str, object]) -> None` rejects documents over 64 MiB and publishes atomically.

- [ ] **Step 1: Write failing report tests**

Assert checkpoints are parseable after replacement, reports include composition hash/seed/duration/iterations/throughput/RSS/protocol and component counts, crash reports include a replay command, oversized output is rejected, and an interrupted run does not leave a success report.

- [ ] **Step 2: Run focused tests and verify failure**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_campaign_report -v
```

Expected: missing report module or function failure.

- [ ] **Step 3: Implement bounded state aggregation and atomic publication**

Cap stored output lines at 1024 and each line at 64 KiB, aggregate counters by protocol/component, calculate `iterations / max(duration, 1e-9)`, persist `checkpoint.json` after every configured interval, and publish `report.json` only for `completed`, `crashed`, or `resource-terminated` terminal states with explicit status.

- [ ] **Step 4: Run focused tests and regression tests**

Expected: report tests and all existing integration tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/myfuzz/integration/campaign.py src/myfuzz/integration/campaign_report.py tests/integration/test_campaign_report.py
git commit -m "feat: persist campaign checkpoints and reports"
```

### Task 3: Create the campaign entrypoint and low-resource target config

**Files:**
- Create: `configs/designs/ibex_protocol_composition/campaign.json`
- Create: `scripts/run_ibex_protocol_campaign.py`
- Modify: `src/myfuzz/integration/campaign.py`
- Test: `tests/integration/test_ibex_protocol_campaign_cli.py`

**Interfaces:**
- CLI options: `--config`, `--output-dir`, `--duration-seconds`, `--seed`, `--checkpoint-seconds`, `--command`, `--dry-run`, `--max-restarts`.
- `build_ibex_campaign_command(root: Path, config_path: Path, output_dir: Path, duration_seconds: int, seed: int) -> tuple[str, ...]` returns a command invoking `src/myfuzz/scripts/run_design_flow.py` with `--stage all`, `--jobs 1`, `--fuzz-seconds`, `--seed`, and the generated composition manifest.
- `run_ibex_campaign(...) -> dict[str, object]` performs config validation, preflight, command execution, and report publication.

- [ ] **Step 1: Write failing CLI/config tests**

Assert the default config contains one worker, disabled VCD, the three memory limits, 3600 seconds, 30-second checkpoints, and the approved composition manifest. Assert command construction contains no parallel-build flag and rejects duration `0`, worker count other than `1`, and hard memory below soft memory.

- [ ] **Step 2: Implement config and CLI**

Use `argparse`, resolve paths beneath the repository root, merge only explicit CLI overrides, support `--dry-run` without starting a child, and print one sorted JSON summary. The normal path invokes `run_supervised_command` and writes the report below the requested output directory.

- [ ] **Step 3: Run CLI tests and dry-run**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_campaign_cli -v
python3 scripts/run_ibex_protocol_campaign.py --config configs/designs/ibex_protocol_composition/campaign.json --dry-run --duration-seconds 10
```

Expected: tests pass and dry-run prints a command containing `--jobs 1` and `--fuzz-seconds 10`.

- [ ] **Step 4: Commit**

```bash
git add configs/designs/ibex_protocol_composition/campaign.json scripts/run_ibex_protocol_campaign.py src/myfuzz/integration/campaign.py tests/integration/test_ibex_protocol_campaign_cli.py
git commit -m "feat: add Ibex low-resource campaign entrypoint"
```

### Task 4: Run the real short campaign boundary and verify failure reporting

**Files:**
- Modify: `configs/designs/ibex_protocol_composition/README.md`
- Create: `tests/integration/test_ibex_protocol_campaign_smoke.py`

- [ ] **Step 1: Add a deterministic local smoke command**

Use the supervisor with a local Python JSON-line producer when upstream Ibex is unavailable; the smoke must emit at least one transaction per `tl-ul`, `apb`, and `axi4-lite`, one event for each of `ram`, `timer`, `gpio`, `uart`, and `spi`, and one coverage point. This checks campaign accounting without claiming RTL compilation.

- [ ] **Step 2: Run the 10-second smoke**

```bash
python3 scripts/run_ibex_protocol_campaign.py --config configs/designs/ibex_protocol_composition/campaign.json --duration-seconds 10 --dry-run
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_campaign_smoke -v
```

Expected: the dry-run is dependency-safe; the local smoke report is parseable, nonzero, and records the missing-upstream condition separately from protocol counters.

- [ ] **Step 3: Document remote real-target command**

Document the command using the prepared Ibex source list and state that a 10–60 second real RFuzz run is required before the 3600-second command. Include the exact report fields and the reproduction command format.

- [ ] **Step 4: Commit**

```bash
git add configs/designs/ibex_protocol_composition/README.md tests/integration/test_ibex_protocol_campaign_smoke.py
git commit -m "test: add bounded Ibex campaign smoke"
```
