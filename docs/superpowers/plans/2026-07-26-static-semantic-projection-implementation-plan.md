# Static Semantic Projection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, evaluate, freeze, and validate a target-independent combinational semantic projection that improves RFuzz coverage without materially reducing throughput.

**Architecture:** Add a pure-data static-policy compiler beside the existing temporal projection code, emit combinational SystemVerilog through the existing harness compiler, and reuse the published experiment planner/runner/report boundary for screening and promotion. Training uses the checked-in real Ibex + OpenTitan and RVX targets; after freezing, held-out APB and AXI-Lite targets use pinned upstream RTL without changing policy code or parameters.

**Tech Stack:** Python 3.12 standard library, immutable dataclasses, SystemVerilog, existing MyFuzz/RFuzz integration APIs, Verilator 5.020, `unittest`.

## Global Constraints

- Policy inputs are limited to numeric port/component/field IDs, explicit protocol IDs, widths, directions, address regions, legal values, semantic roles, and dependency declarations.
- Policy code must not read DUT hierarchy, coverage bits, source paths, module/instance/port display names, target IDs, or DUT outputs.
- Static projection is combinational: emitted candidate RTL contains no `always_ff`, state register, counter, clocked block, or output-feedback expression.
- Baseline and candidate preserve identical raw width and raw-bit geometry, coverage universe, mutation settings, seed, and budget.
- Portfolio parameters are generic and shared by all targets: direct-pass-through ratio, event rarity, legal-set strength, and mutual-exclusion policy.
- Screening uses 60 seconds and one fixed seed. Survivors use 600 seconds on seeds `1`, `7`, and `19`; frozen validation uses 3600 seconds on the same seeds.
- Screening rejects abnormal exit, coverage loss over 5 percent, or throughput below 85 percent of baseline.
- Promotion requires at least 10 percent median coverage improvement on both training targets, no paired loss over 2 percent, and median throughput at least 90 percent of baseline.
- Heavy Verilator builds use one worker and every heavy process uses the existing memory gate.
- No coverage result is accepted if reset entry, event reachability, artifact parity, nonzero tests, nonempty expected coverage, process return codes, or FIFO cleanup preconditions fail.
- Held-out sources are pinned to `pulp-platform/apb_timer@03eba2e6965f5363df12621882bc70498c551a73` (Solderpad 0.51) and `ZipCPU/wb2axip@2e8d3bc2d26ddc33d1881022a2a2b9d3f0c16b9b` (Apache-2.0).
- Once a policy is frozen, held-out target work may add only source provenance, ABI/protocol/semantic declarations, wrappers, and experiment manifests; policy source and frozen parameters cannot change.

---

### Task 1: Finish Training-Target Correctness Preconditions

**Files:**
- Modify: `configs/designs/ibex_opentitan_real_ip/programs/link.ld`
- Modify: `configs/designs/ibex_opentitan_real_ip/programs/build_hex.py`
- Generate: `configs/designs/ibex_opentitan_real_ip/programs/mmio_exerciser.hex`
- Modify: `configs/designs/ibex_opentitan_real_ip/harness/ibex_ot_depaware_projection_harness.sv`
- Modify: `configs/designs/ibex_multicomponent_ip/scripts/prepare_remote_sources.py`
- Generate: `configs/designs/ibex_multicomponent_ip/rtl/generated_remote_sources.f`
- Modify: `tests/test_ibex_opentitan_real_ip_target.py`
- Modify: `tests/test_ibex_remote_sources.py`

**Interfaces:**
- Consumes: Ibex reset vector `0x80`, RFuzz maximum per-test cycle budget, pinned source trees.
- Produces: reset-entry firmware image, reachable declared event windows, deterministic repository-relative source lists.

- [ ] **Step 1: Preserve and run the already-written failing regression tests**

The tests must assert the first executable instruction is word 32 in the hex image and that the debug event compares only a bounded 8-bit cycle window:

```python
self.assertEqual(words[:32], ["00000013"] * 32)
self.assertNotEqual(words[32], "00000013")
self.assertIn("cycle_q[7:0] == {2'b00, rfuzz_input_bits[247:242]}", source)
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target tests.test_ibex_remote_sources -v`

Expected before the existing working-tree fix: FAIL on reset entry, event reachability, or portable source closure.

- [ ] **Step 2: Complete the minimal reset-entry and reachability implementation**

Keep the linker origin and binary padding explicit:

```ld
. = 0x80;
```

```python
RESET_ENTRY_BYTES = 0x80
image = b"\x13\x00\x00\x00" * (RESET_ENTRY_BYTES // 4) + binary.read_bytes()
```

Use an event comparison whose entire range is reachable within the configured server budget; do not add sequential projection state.

- [ ] **Step 3: Regenerate artifacts and verify focused tests**

Run: `python3 configs/designs/ibex_opentitan_real_ip/programs/build_hex.py`

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target tests.test_ibex_remote_sources -v`

Expected: PASS.

- [ ] **Step 4: Verify the complete current baseline and commit**

Run: `PYTHONPATH=src:. python3 -m unittest discover -v`

Run: `git diff --check`

```bash
git add configs/designs/ibex_opentitan_real_ip configs/designs/ibex_multicomponent_ip tests/test_ibex_opentitan_real_ip_target.py tests/test_ibex_remote_sources.py
git commit -m "fix: satisfy static projection preconditions"
```

### Task 2: Define the Target-Independent Static Policy Model

**Files:**
- Create: `src/myfuzz/harness/static_policy.py`
- Create: `tests/harness/test_static_policy.py`
- Modify: `src/myfuzz/harness/__init__.py`

**Interfaces:**
- Consumes: `RawBitAbi`, explicit semantic declarations, and protocol plugin fields.
- Produces: immutable `StaticPolicyPlan` with canonical hash and ordered `StaticAction` records.

- [ ] **Step 1: Write failing policy-model tests**

```python
def test_plan_is_deterministic_name_invariant_and_preserves_geometry(self):
    first = compile_static_policy(self.abi, self.declarations, BALANCED_POLICY)
    renamed = compile_static_policy(self.abi, rename_diagnostics(self.declarations), BALANCED_POLICY)
    self.assertEqual(first, renamed)
    self.assertEqual(first.raw_abi.raw_width, self.abi.raw_width)
    self.assertEqual(first.raw_abi.uses, self.abi.uses)

def test_policy_rejects_forbidden_metadata_and_output_dependencies(self):
    for key in ("module_name", "target_id", "coverage_bits", "dut_output"):
        with self.subTest(key=key), self.assertRaises(ValueError):
            compile_static_policy(self.abi, {key: "forbidden"}, BALANCED_POLICY)
```

Add one test for each allowed primitive: `mask_align`, `legal_set`, `dependency_gate`, `mutual_exclusion`, `rarity_fold`, and `entropy_mix`.

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_static_policy -v`

Expected: FAIL because the module does not exist.

- [ ] **Step 2: Implement immutable parameter and action types**

```python
@dataclass(frozen=True, slots=True)
class StaticPolicyParameters:
    direct_ratio: int
    event_rarity: int
    legal_set_strength: int
    mutual_exclusion: Literal["none", "one_hot", "priority"]

@dataclass(frozen=True, slots=True)
class StaticAction:
    action_id: int
    kind: str
    destination_id: int
    raw_lo: int
    raw_hi: int
    parameters: tuple[tuple[str, int | str | tuple[int, ...]], ...]

@dataclass(frozen=True, slots=True)
class StaticPolicyPlan:
    raw_abi: RawBitAbi
    parameters: StaticPolicyParameters
    actions: tuple[StaticAction, ...]
    plan_hash: str
```

Validate all integers as bounded non-boolean values. Canonicalize unordered declarations by numeric stable IDs and reject unknown keys before compiling actions.

- [ ] **Step 3: Implement compilation only from declared semantics**

```python
def compile_static_policy(
    raw_abi: RawBitAbi,
    declarations: Mapping[str, object],
    parameters: StaticPolicyParameters,
) -> StaticPolicyPlan:
    semantic = validate_static_declarations(declarations, raw_abi)
    actions = tuple(sorted(_compile_actions(semantic, parameters), key=_action_key))
    document = {"raw_abi": abi_document(raw_abi), "parameters": asdict(parameters), "actions": action_documents(actions)}
    return StaticPolicyPlan(raw_abi, parameters, actions, content_hash(document))
```

The direct-pass-through branch must remain available for every transformed destination.

- [ ] **Step 4: Run focused and identifier-policy tests, then commit**

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_static_policy tests.harness.test_identifier_opacity tests.integration.test_identifier_policy -v`

Run: `python3 scripts/check_identifier_policy.py --paths src/myfuzz/harness src/myfuzz/protocols`

Run: `git diff --check`

```bash
git add src/myfuzz/harness/static_policy.py src/myfuzz/harness/__init__.py tests/harness/test_static_policy.py
git commit -m "feat: define static semantic projection policy"
```

### Task 3: Emit and Evaluate Purely Combinational Projection RTL

**Files:**
- Create: `src/myfuzz/harness/static_projection.py`
- Create: `tests/harness/test_static_projection.py`
- Modify: `src/myfuzz/harness/compiler.py`
- Modify: `tests/harness/test_compiler.py`

**Interfaces:**
- Consumes: `StaticPolicyPlan` plus one raw sample.
- Produces: projected destination values and a SystemVerilog harness mode `candidate-static`.

- [ ] **Step 1: Write failing evaluator and RTL tests**

```python
def test_projection_outputs_have_declared_width_and_legal_membership(self):
    for raw in property_samples(self.plan.raw_abi.raw_width):
        values = project_static_sample(self.plan, raw)
        self.assertEqual(set(values), self.destination_ids)
        self.assertIn(values[self.opcode_id], self.legal_opcodes)

def test_emitted_rtl_is_combinational_and_retains_direct_samples(self):
    rtl = emit_static_projection(self.manifest, self.plan)
    self.assertNotIn("always_ff", rtl)
    self.assertNotIn("projection_state", rtl)
    self.assertNotRegex(rtl, r"dut\s*\.")
    self.assertIn("rfuzz_input_bits", rtl)
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_static_projection -v`

Expected: FAIL because the evaluator/emitter do not exist.

- [ ] **Step 2: Implement each combinational primitive once**

```python
def _apply(action: StaticAction, raw_slice: int, raw_value: int) -> int:
    if action.kind == "mask_align":
        return raw_slice & _parameter(action, "mask")
    if action.kind == "legal_set":
        values = _tuple_parameter(action, "values")
        return values[raw_slice % len(values)]
    if action.kind == "dependency_gate":
        return raw_slice if _raw_bit(raw_value, _parameter(action, "gate_bit")) else 0
    if action.kind == "rarity_fold":
        return int(_fold(raw_value, action) == 0)
    return _apply_selection_or_entropy(action, raw_slice, raw_value)
```

Mirror the same operations in emitted constant-width SV expressions. Derive all slices from `RawBitAbi`; do not allocate new raw bits.

- [ ] **Step 3: Integrate a distinct compiler mode without changing legacy modes**

```python
if mode == "candidate-static":
    plan = compile_static_policy(candidate_abi, static_declarations, static_parameters)
    artifact = emit_static_harness(manifest, plan)
```

Require the direct and static artifacts to have equal `raw_width`, `abi_hash`, candidate identity, and coverage universe identity.

- [ ] **Step 4: Verify RED-GREEN, lint generated RTL, and commit**

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_static_projection tests.harness.test_compiler tests.harness.test_flow_integration -v`

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_static_projection.StaticProjectionTest.test_generated_fixture_passes_verilator_lint -v`

Run: `git diff --check`

```bash
git add src/myfuzz/harness/static_projection.py src/myfuzz/harness/compiler.py tests/harness/test_static_projection.py tests/harness/test_compiler.py
git commit -m "feat: emit combinational static projections"
```

### Task 4: Build the Generic Portfolio and Promotion Gate

**Files:**
- Create: `src/myfuzz/experiments/static_portfolio.py`
- Create: `tests/experiments/test_static_portfolio.py`
- Modify: `src/myfuzz/experiments/__init__.py`

**Interfaces:**
- Consumes: paired baseline/candidate run summaries from existing reports.
- Produces: canonical portfolio, screening decisions, promotion ranking, and immutable frozen policy JSON.

- [ ] **Step 1: Write failing threshold and ranking tests**

```python
def test_screen_rejects_abnormal_loss_and_low_throughput(self):
    self.assertEqual(screen(abnormal_pair()).reason, "abnormal_exit")
    self.assertEqual(screen(pair(coverage_ratio=.94)).reason, "coverage_loss")
    self.assertEqual(screen(pair(throughput_ratio=.849)).reason, "throughput")

def test_promotion_requires_both_targets_and_ranks_worst_target_first(self):
    decisions = promote(self.training_results)
    self.assertEqual([item.policy_id for item in decisions], ["policy-3", "policy-1"])
```

Include exact boundary tests for 5, 85, 10, 2, and 90 percent; missing/nonfinite/zero denominators must fail closed.

Run: `PYTHONPATH=src:. python3 -m unittest tests.experiments.test_static_portfolio -v`

Expected: FAIL because the module does not exist.

- [ ] **Step 2: Define one deterministic generic portfolio**

```python
PORTFOLIO = tuple(
    StaticPolicyParameters(direct, rarity, strength, exclusion)
    for direct in (1, 2, 4)
    for rarity in (2, 4, 8)
    for strength in (1, 2)
    for exclusion in ("none", "one_hot", "priority")
)
```

Deduplicate by canonical plan hash. The values above are global and cannot be overridden per target.

- [ ] **Step 3: Implement exact paired metrics and freeze publication**

Use `statistics.median`. Calculate improvement as `(candidate - baseline) / baseline`, throughput ratio as `candidate / baseline`, and order by `(min_target_improvement, mean_improvement, median_throughput, policy_id)` descending except the final stable ID tie-break.

Write the frozen policy atomically with:

```json
{
  "schema_version": "static-policy-freeze.v1",
  "policy_id": "...",
  "plan_hash": "...",
  "parameters": {},
  "training_evidence_hash": "..."
}
```

- [ ] **Step 4: Run tests and commit**

Run: `PYTHONPATH=src:. python3 -m unittest tests.experiments.test_static_portfolio tests.experiments.test_report tests.experiments.test_planner -v`

Run: `git diff --check`

```bash
git add src/myfuzz/experiments/static_portfolio.py src/myfuzz/experiments/__init__.py tests/experiments/test_static_portfolio.py
git commit -m "feat: add static policy promotion gates"
```

### Task 5: Integrate Both Training Targets and Campaign Runner

**Files:**
- Create: `configs/experiments/static_projection_training.json`
- Create: `configs/designs/ibex_opentitan_real_ip/static_projection/config.json`
- Create: `configs/designs/rvx_multicomponent/static_projection/config.json`
- Create: `scripts/runs/run_static_projection_campaign.py`
- Create: `tests/test_static_projection_campaign.py`

**Interfaces:**
- Consumes: the existing target source lists, baseline configs, portfolio compiler, `run_experiment_matrix`, RFuzz adapter, and memory gate.
- Produces: screening, promotion, and frozen-validation reports with paired provenance.

- [ ] **Step 1: Write failing campaign contract tests**

```python
def test_campaign_uses_exact_training_budgets_and_seeds(self):
    config = load_campaign(CONFIG)
    self.assertEqual(config.screen.seconds, 60)
    self.assertEqual(config.promotion.seconds, 600)
    self.assertEqual(config.validation.seconds, 3600)
    self.assertEqual(config.promotion.seeds, (1, 7, 19))

def test_pair_validation_rejects_any_fairness_mismatch(self):
    for field in ("coverage_identity", "raw_width", "mutation", "seed", "budget"):
        with self.subTest(field=field), self.assertRaises(ValueError):
            validate_training_pair(mismatch(field))
```

Also test abnormal/early exit, zero tests, empty expected coverage, inconsistent artifact hashes, and leftover FIFO rejection.

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_static_projection_campaign -v`

Expected: FAIL because the runner/configs do not exist.

- [ ] **Step 2: Add target declarations without target policy constants**

Each target config supplies only its existing ABI, protocol bindings, declared address regions/legal sets/semantic roles, and artifact paths. Both reference the same portfolio object and contain no policy parameter override.

- [ ] **Step 3: Compose existing build/run/report APIs**

```python
def run_campaign(config: CampaignConfig, *, runner: Runner) -> CampaignReport:
    preflight = verify_preconditions(config, runner=runner)
    screened = run_screening(preflight, runner=runner)
    promoted = run_promotion(screened, runner=runner)
    frozen = freeze_policy(promoted)
    validation = run_frozen_validation(frozen, runner=runner)
    return build_campaign_report(preflight, screened, promoted, frozen, validation)
```

Every stage must call existing `run_experiment_matrix`; do not implement another scheduler, lease manager, RFuzz parser, or report aggregator.

- [ ] **Step 4: Run synthetic integration tests and real build smoke**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_static_projection_campaign tests.integration.test_experiment_matrix tests.test_ibex_opentitan_real_ip_target tests.test_rvx_multicomponent_target -v`

Build each baseline/static server sequentially under `scripts/memory_gate.py`, then run a bounded server handshake that proves nonzero expected coverage and FIFO cleanup.

- [ ] **Step 5: Commit**

Run: `git diff --check`

```bash
git add configs/experiments/static_projection_training.json configs/designs/ibex_opentitan_real_ip/static_projection configs/designs/rvx_multicomponent/static_projection scripts/runs/run_static_projection_campaign.py tests/test_static_projection_campaign.py
git commit -m "feat: integrate static projection training campaign"
```

### Task 6: Execute Screening, Promotion, and Frozen Long Runs

**Files:**
- Generate under ignored `runs/static_projection/`: build artifacts, raw reports, and logs.
- Create: `docs/STATIC_PROJECTION_TRAINING_RESULTS_20260726.md`
- Create when promoted: `configs/experiments/static_projection_frozen.json`

**Interfaces:**
- Consumes: the Task 5 campaign entry point and real RFuzz toolchain.
- Produces: empirical promotion decision and, only when thresholds pass, a frozen policy.

- [ ] **Step 1: Run all 60-second screening pairs**

Run: `python3 scripts/memory_gate.py --claim build --memory-mib 3072 --owner static-screen --exec python3 scripts/runs/run_static_projection_campaign.py --stage screen --out runs/static_projection/screen`

Expected: every retained candidate has normal exits, coverage ratio at least `0.95`, and throughput ratio at least `0.85` on both targets.

- [ ] **Step 2: Run 10-minute paired promotion jobs**

Run the same command with `--stage promotion --screen-report ... --out runs/static_projection/promotion`.

Expected: exact seeds `1,7,19`, 600-second paired budgets, equal fairness identities, and a deterministic decision.

- [ ] **Step 3: Freeze only a qualifying policy**

If no policy qualifies, publish the negative result with all raw evidence and stop before held-out acquisition; that is the specified scientific outcome, not a reason to retune per target. If one qualifies, atomically write `configs/experiments/static_projection_frozen.json` and prove a second decision run is byte-identical.

- [ ] **Step 4: Run one-hour frozen validation on both training targets**

Run with `--stage frozen --frozen-policy configs/experiments/static_projection_frozen.json --out runs/static_projection/frozen`.

Expected: 12 paired jobs (2 targets x 3 seeds x 2 harnesses), each 3600 seconds, with raw sets, overlap, candidate-only, baseline-only, throughput, RSS, hashes, and return codes.

- [ ] **Step 5: Publish evidence and commit**

Document commands, exact artifact hashes, thresholds, promotion result, and any invalid runs without copying large artifacts into Git.

```bash
git add docs/STATIC_PROJECTION_TRAINING_RESULTS_20260726.md configs/experiments/static_projection_frozen.json
git commit -m "experiment: freeze static projection policy"
```

### Task 7: Add Pinned APB and AXI-Lite Held-Out Targets

**Files:**
- Modify: `.gitmodules`
- Add submodule: `external_designs/apb_timer`
- Add submodule: `external_designs/wb2axip`
- Create: `configs/designs/heldout_apb_timer/**`
- Create: `configs/designs/heldout_axilxbar/**`
- Create: `configs/experiments/static_projection_heldout.json`
- Create: `tests/test_static_projection_heldout_targets.py`

**Interfaces:**
- Consumes: frozen policy, pinned upstream RTL, explicit APB/AXI-Lite declarations.
- Produces: two buildable baseline/static RFuzz pairs without policy changes.

- [ ] **Step 1: Write failing provenance, license, and freeze tests**

```python
def test_heldout_sources_are_pinned_and_licensed(self):
    self.assertEqual(git_head(APB_ROOT), "03eba2e6965f5363df12621882bc70498c551a73")
    self.assertEqual(git_head(AXIL_ROOT), "2e8d3bc2d26ddc33d1881022a2a2b9d3f0c16b9b")
    self.assertIn("SOLDERPAD HARDWARE LICENSE version 0.51", read(APB_ROOT / "LICENSE"))
    self.assertIn("Apache License", read(AXIL_ROOT / "rtl/axilxbar.v"))

def test_heldout_targets_use_frozen_policy_without_overrides(self):
    self.assertEqual(apb.policy_hash, frozen.plan_hash)
    self.assertEqual(axil.policy_hash, frozen.plan_hash)
    self.assertNotIn("policy_parameters", apb.target_document)
    self.assertNotIn("policy_parameters", axil.target_document)
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_static_projection_heldout_targets -v`

Expected: FAIL because sources/configs do not exist.

- [ ] **Step 2: Add and pin upstream sources**

```bash
git submodule add https://github.com/pulp-platform/apb_timer.git external_designs/apb_timer
git -C external_designs/apb_timer checkout 03eba2e6965f5363df12621882bc70498c551a73
git submodule add https://github.com/ZipCPU/wb2axip.git external_designs/wb2axip
git -C external_designs/wb2axip checkout 2e8d3bc2d26ddc33d1881022a2a2b9d3f0c16b9b
```

- [ ] **Step 3: Build declarations and thin environment wrappers**

APB uses upstream `src/timer.sv` and `src/apb_timer.sv` with explicit APB3 field IDs. AXI-Lite uses upstream `rtl/axilxbar.v` with explicit AXI4-Lite channel field IDs. Wrappers may provide clock/reset, legal static parameters, bounded response endpoints, and coverage plumbing; they may not encode register sequences or policy parameters.

- [ ] **Step 4: Verify source, ABI, freeze, and Verilator builds**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_static_projection_heldout_targets tests.harness.test_static_policy tests.harness.test_static_projection -v`

Run both baseline/static builds sequentially through the memory gate with `-j 1`.

Run: `git diff --check`

- [ ] **Step 5: Commit**

```bash
git add .gitmodules external_designs/apb_timer external_designs/wb2axip configs/designs/heldout_apb_timer configs/designs/heldout_axilxbar configs/experiments/static_projection_heldout.json tests/test_static_projection_heldout_targets.py
git commit -m "feat: add held-out APB and AXI-Lite targets"
```

### Task 8: Execute Held-Out Validation and Finalize Evidence

**Files:**
- Generate under ignored `runs/static_projection/heldout/`: raw reports and logs.
- Create: `docs/STATIC_PROJECTION_HELDOUT_RESULTS_20260726.md`
- Modify: `docs/PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md`

**Interfaces:**
- Consumes: frozen policy and held-out experiment manifest.
- Produces: generalization report that cannot alter the frozen policy.

- [ ] **Step 1: Prove the policy tree is unchanged**

Record `git hash-object src/myfuzz/harness/static_policy.py src/myfuzz/harness/static_projection.py configs/experiments/static_projection_frozen.json` before held-out runs and assert the same hashes afterward.

- [ ] **Step 2: Run held-out 60-second and 10-minute stages**

Run: `python3 scripts/memory_gate.py --claim build --memory-mib 3072 --owner static-heldout --exec python3 scripts/runs/run_static_projection_campaign.py --stage heldout --config configs/experiments/static_projection_heldout.json --frozen-policy configs/experiments/static_projection_frozen.json --out runs/static_projection/heldout`

Expected: both stages retain paired coverage sets, throughput, RSS, hashes, return codes, and cleanup evidence. A threshold failure is reported and does not trigger retuning.

- [ ] **Step 3: Write the held-out and artifact-index reports**

Include exact repository commits/licenses, build commands, policy hash, all validity checks, paired metrics, and the unchanged-policy hash proof.

- [ ] **Step 4: Run final verification**

Run: `PYTHONPATH=src:. python3 -m unittest discover -v`

Run: `python3 scripts/check_identifier_policy.py --paths src/myfuzz/composition src/myfuzz/protocols src/myfuzz/harness src/myfuzz/experiments src/myfuzz/integration`

Run: `git diff --check`

Audit with `ps` and the run directory that no RFuzz/Verilator process or FIFO remains.

- [ ] **Step 5: Commit**

```bash
git add docs/STATIC_PROJECTION_HELDOUT_RESULTS_20260726.md docs/PROJECT_SUMMARY_AND_ARTIFACT_INDEX_20260615.md
git commit -m "docs: publish static projection evaluation"
```
