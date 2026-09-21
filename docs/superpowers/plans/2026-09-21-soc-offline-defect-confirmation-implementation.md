# SoC Offline Defect Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confirm the known injected SPI component fault only after the verifier itself re-runs the SoC, structure audits, and standalone APB comparison.

**Architecture:** Keep online `classify_boundary` at `component_candidate`. Add a focused offline verifier that consumes actual builds, a mutant EvidencePackage and a declarative Icarus isolation fixture; derive every status from files and newly executed runs. Deprecate the caller-asserted mapping gate so it cannot produce a production confirmation.

**Tech Stack:** Python 3 `unittest`, existing Verilator `RuntimeBuild`/`RunResult`, `EvidencePackage`/`replay_package`, `soc_structure_audit`, Icarus `iverilog`/`vvp`.

## Global Constraints

- Approved design: [`../specs/2026-09-21-soc-offline-defect-confirmation-design.md`](../specs/2026-09-21-soc-offline-defect-confirmation-design.md).
- No profile-supplied shell command. Compile isolation with an argv list and `shell=False`.
- Never use peer/component counters to determine the SPI expected MOSI byte.
- Any missing, truncated, stale or unverified evidence remains `component_candidate`/`undiagnosed`, never `component_confirmed`.
- Preserve the dirty shared tree. Do not stage or commit unrelated files.

---

### Task 1: Bind SoC Builds and Recompute the Source-Only Differential

**Files:** Create `src/myfuzz/composition/soc_offline_defect_confirmation.py`; create `tests/integration/test_soc_offline_defect_confirmation.py`.

**Interfaces:** `IsolationFixture(testbench: Path, top_module: str, marker: str, source_name: str)`; `OfflineConfirmation(status: str, reason: str, evidence: Mapping[str, object])`; `confirm_component_offline(package: EvidencePackage, *, plan: CompositionPlan, baseline: RuntimeBuild, mutant: RuntimeBuild, fixture: IsolationFixture, criterion: Mapping[str, object], base_dir: Path, include_roots: Sequence[str] = (), timeout_seconds: int = 600) -> OfflineConfirmation`.

The new module's public types are frozen dataclasses. The build differential is produced only from fresh file bytes:

```python
@dataclass(frozen=True, slots=True)
class IsolationFixture:
    testbench: Path
    top_module: str
    marker: str
    source_name: str

@dataclass(frozen=True, slots=True)
class OfflineConfirmation:
    status: str
    reason: str
    evidence: Mapping[str, object]

def file_hash(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
```

- [ ] **Step 1: Write failing tests.** In `test_soc_offline_defect_confirmation.py`, construct temporary `RuntimeBuild` records using `dataclasses.replace` and one candidate package from `tests.integration.test_soc_failure_evidence._package`. Assert non-candidate is returned unchanged; assert mismatched mutant top hash and two changed source hashes do not confirm. A pure helper `build_differential(baseline, mutant) -> Mapping[str, object]` must report `top_equal`, `testbench_equal`, `boot_equal`, and exactly one removed/added SHA-256 source hash. Use actual temporary file bytes, not only caller strings.
- [ ] **Step 2: Run red test.** `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_offline_defect_confirmation`; expect import failure.
- [ ] **Step 3: Implement file-based binding.** Use `hashlib.sha256(path.read_bytes())`, `Counter(build.source_hashes.values())` after recomputing each `build.sources` file against `base_dir`, and `identity_mismatches(package, mutant)`. Reject missing files, content drift since build, more than one changed source, changed generated top/testbench/boot, mismatched raw-width/slot/layout/build-record identity or independent criterion hash. Return a reason naming the first failed field; do not use `source_only_mutation` supplied by caller.
- [ ] **Step 4: Run green test.** Run `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_offline_defect_confirmation`; expect the new build-binding tests to pass. The old gate's tests are migrated in Task 4.

### Task 2: Re-run and Independently Audit Both SoCs

**Files:** Modify `src/myfuzz/composition/soc_offline_defect_confirmation.py`; expand `tests/integration/test_soc_offline_defect_confirmation.py`.

**Interfaces:** `confirm_component_offline` calls `replay_package(package, mutant)`, `run_sample(baseline, package.sample())`, `run_sample(mutant, package.sample())`, and `audit_structure(plan, top_text=..., source_files=..., base_dir=..., include_roots=...)` for both builds. Pure helper `spi_wire_verdict(result: RunResult) -> tuple[str, object, object]` reads `result.peer_oracle["checks"]` check `spi-transfer-wire`.

The check extractor must not read peer counters:

```python
def spi_wire_verdict(result: RunResult) -> tuple[str, object, object]:
    checks = (result.peer_oracle or {}).get("checks", ())
    matches = [item for item in checks if item.get("check_id") == "spi-transfer-wire"]
    if len(matches) != 1:
        return "not_assessed", None, None
    check = matches[0]
    return str(check.get("status")), check.get("expected"), check.get("observed")
```

- [ ] **Step 1: Write failing tests.** Patch the four imported execution functions at the module boundary. A replay divergence, audit failure, baseline SPI mismatch, mutant SPI pass, truncated request/wire trace, or mutant observed MOSI different from `package.anomaly["observed"]` must each block confirmation with a distinct reason. The positive double should supply a real `ReplayResult(status="agreement", ...)` and two complete `RunResult` objects, not caller boolean flags.
- [ ] **Step 2: Run red test.** Run `python3 -m unittest -q tests.integration.test_soc_offline_defect_confirmation`; expect the new negative cases to fail.
- [ ] **Step 3: Implement reruns.** Require exactly one saved sample and one saved result, replay agreement, complete real results, identical actual CPU TXDATA write/peer arm records across baseline and mutant, `pass`/`mismatch` SPI wire verdicts, and expected/observed values agreeing with the independent criterion. Recompute both structure audits and save their summary + top hashes; classify a failed audit as `composition_defect`. Catch tool/timeout/elaboration failures as `undiagnosed` with a stable reason.
- [ ] **Step 4: Run green test.** Run the offline verifier tests plus `tests.integration.test_soc_boundary_replay` and `tests.integration.test_soc_spi_wire_oracle`; expect all pass.

### Task 3: Recompile and Re-run the Standalone Isolation Fixture

**Files:** Modify `src/myfuzz/composition/soc_offline_defect_confirmation.py`; expand `tests/integration/test_soc_offline_defect_confirmation.py`; migrate `tests/integration/test_soc_defect_injection_real.py`.

**Interfaces:** `run_isolation(fixture: IsolationFixture, *, baseline_source: Path, mutant_source: Path, output_dir: Path, timeout_seconds: int) -> Mapping[str, object]` compiles `iverilog -g2012 -s <top> -o <output> <bench> <source>` separately and executes each output with `vvp`, using `subprocess.run([...], shell=False, capture_output=True, timeout=...)`. Parse exactly one line beginning with `fixture.marker`, containing numeric `bits` and `mosi` fields.

The runner's command shape is fixed, with no command string from the profile:

```python
compile_result = subprocess.run(
    [iverilog, "-g2012", "-s", fixture.top_module, "-o", str(executable),
     str(fixture.testbench), str(source)],
    capture_output=True, text=True, check=False, timeout=timeout_seconds)
run_result = subprocess.run(
    [vvp, str(executable)], capture_output=True, text=True,
    check=False, timeout=timeout_seconds)
```

- [ ] **Step 1: Write failing tests.** Use a temporary miniature SystemVerilog source/bench to show baseline expected value and mutant wrong value; reject no marker, duplicate marker, timeout, compile failure and same wrong value in baseline. Assert the fixture hash is part of `OfflineConfirmation.evidence` and replacing the bench changes it.
- [ ] **Step 2: Run red test.** Run the offline verifier module; expect absent `run_isolation`/negative checks to fail.
- [ ] **Step 3: Implement the fixed runner and real migration.** Resolve both source paths from the verified changed-hash pair; resolve the fixture testbench and hash its bytes; do not accept a command string from profile or isolation mapping. In the existing `MYFUZZ_SOC_REAL=1` injected SPI test, stop assembling the caller-status `isolation` dictionary. Pass both existing builds, their `plan`, the mutant package, `IsolationFixture(testbench=ISOLATION_TB, top_module="novaspi_isolation_tb", marker="MYFUZZ_ISOLATED_SPI", source_name="novaspi")`, criterion and include roots to `confirm_component_offline`. Only this new result may assert `component_confirmed`.
- [ ] **Step 4: Run green real test.** `MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q tests.integration.test_soc_defect_injection_real tests.integration.test_soc_multi_latch_fault`; expect known baseline/variant confirmation in the SPI fixture and connection-fault nonconfirmation in the multi-latch fixture.

### Task 4: Remove the Self-Reported Confirmation Route and Persist Accurate Results

**Files:** Modify `src/myfuzz/composition/soc_defect_confirmation.py`, `src/myfuzz/composition/soc_offline_defect_confirmation.py`, `tests/integration/test_soc_defect_confirmation.py`, `tests/integration/test_soc_defect_injection_real.py`, `docs/reports/soc-remaining-implementation-20260921.md`, `docs/reports/soc-capability-matrix-20260921.md`, `docs/reports/soc-design-acceptance-20260921.md`, `docs/reports/soc-research-scope-20260921.md`.

**Interfaces:** The old `confirm_component_defect(..., isolation: Mapping)` returns `component_candidate` with reason `offline-verification-required` whenever `classify_boundary` yields a candidate; `record_component_confirmation` stores that nonconfirming result. New `record_offline_confirmation(package, result: OfflineConfirmation) -> EvidencePackage` persists the actual verifier's evidence and its content hash. A saved report check verifies record integrity only; it never claims to re-run external tools.

The old path fails closed before reading caller assertions:

```python
def confirm_component_defect(package, *, isolation, criterion):
    boundary, reason = classify_boundary(package)
    if boundary != COMPONENT_CANDIDATE:
        return boundary, reason
    return COMPONENT_CANDIDATE, "offline-verification-required"
```

- [ ] **Step 1: Write failing tests.** Change the old unit test so a fully synthetic `_ISOLATION` cannot yield `component_confirmed`; tamper cases must remain rejected. Test that a new record stores audit/replay/isolation/build hashes. A serialized result object is not intrinsically trustworthy: checking a saved JSON report must say `record-integrity-only` unless `confirm_component_offline` is rerun on the referenced artifacts.
- [ ] **Step 2: Run red test.** Run `python3 -m unittest -q tests.integration.test_soc_defect_confirmation tests.integration.test_soc_offline_defect_confirmation`; expect old mapping test to fail before migration.
- [ ] **Step 3: Implement minimal migration.** Keep `classify_boundary` unchanged, make the old mapping gate fail closed for candidates, add an offline-result recorder, and update report wording to distinguish controlled verified injection from natural bug discovery. Do not silently reinterpret old saved `component_confirmation.v1` or a merely deserialized `OfflineConfirmation` as a new offline proof.
- [ ] **Step 4: Verify.** Run the two pure modules, real SPI injection, real multi-latch fault and SPI wire suites; run `git diff --check`. Record exact pass/skip counts and any external-tool blockers in the four reports. Stage only files touched by this plan if a commit is safe; otherwise leave them uncommitted and report the dirty shared tree.
