# Compiled APB3 F4 Execution Binding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make compiled F4 admission identity explicit and prove the existing registered APB3 executor on CV32E40P OBI plus PULP timer APB3.

**Architecture:** Derive a canonical execution binding from the admitted D3 F4 path, generated artifacts, OBI error/trace contract, candidate layout and code-owned APB producer binding. Recompute it before each case and carry it through checker identity, certificates, prefix and fresh replay. Keep source-specific semantics in closed reviewed producer contracts.

**Tech Stack:** Python 3, pytest, generated Verilator harnesses, RFuzz client, JSON evidence.

## Global Constraints

- Follow `agent.md`; remote project writes are only allowed under `/root/fanzehui/**`.
- Do not clean, reset, stage or commit the shared dirty worktree.
- The compiled executor is selected without `--runtime`; it must not fall back to a named runtime family.
- Unknown CPU/IP source, protocol/template, address-window, layout, prerequisite or assertion shapes fail closed.
- The generic APB storage producer remains limited to its registered reviewed source contract; do not claim arbitrary APB3 semantic inference.
- Keep P6/P7/P8 overall open and preserve all existing evidence identities.

---

### Task 1: Add canonical F4 execution binding tests

**Files:**
- Test: `tests/integration/test_compiled_f4_execution_binding.py`
- Test: `tests/integration/test_compiled_f4_storage_producer.py`

**Interfaces:**
- Consumes the existing `timer_generated` fixture and `CompiledF4Runtime` admission path.
- Produces expected `compiled_F4_execution_binding.v1` identity behavior.

- [x] Add a unit test requiring the binding to identify the selected compiled F4 path, D3 digest, CPU and target artifact digests and generated-file hashes, candidate layout, OBI policy, producer binding, target APB3 template/window, prerequisites and assertions.
- [x] Run the one test and confirm it fails because no execution binding exists.
- [x] Add mutation cases for assertion/path, artifact bytes, producer source, target window and endpoint template. Refusal happens before any native process can start; producer-specific offset/protocol negatives remain covered by the existing storage-producer suite.
- [x] Run the focused identity tests and confirm the new assertions fail against the baseline.

### Task 2: Implement binding lifecycle and truthful proof scope

**Files:**
- Modify: `src/myfuzz/integration/compiled_f4.py`
- Modify: `src/myfuzz/integration/generated_storage_consumer.py`
- Test: `tests/integration/test_compiled_f4_storage_producer.py`

**Interfaces:**
- Add one canonical execution-binding builder over already admitted documents; do not accept caller-supplied binding JSON as authority.
- `CompiledF4Runtime.online_identity_configuration()`, certificates, `finish()` and `replay()` consume the same recomputed binding.

- [x] Implement a builder that hashes the exact selected F4 path, D3 document, generated artifact file bytes, candidate layout, CPU OBI/error identity and closed APB storage producer binding.
- [x] Recompute and compare the binding in `_stable()` alongside existing input and producer checks.
- [x] Include the binding document/digest in online checker identity, every certified case, prefix and full-fresh comparison.
- [x] Derive APB proof scope from the selected producer row and register identity.
- [x] Run the failing unit tests from Task 1, then the focused F4 admission/producer tests.

### Task 3: Add the CV32E40P sibling configuration and wrong-shape refusal

**Files:**
- Create: `configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/README.md`
- Create: `configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/compose.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/requests/processor.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/requests/peripheral.json`
- Create: `configs/scenarios/compiled-f4-obi-apb-timer-cv32e40p/test_capability.json`
- Test: `tests/integration/test_compiled_f4_storage_producer.py`

**Interfaces:**
- Reuse the registered PULP `TIMER0_CTRL` source contract and APB3 full-word template.
- Use `configs/cpus/cv32e40p/component_profile.json` for the processor in both compose and CPU request.

- [x] Add the sibling configuration by copying declarations as ordinary new files and setting the CV32E40P processor request/profile; keep the timer target, capability, window, memory and candidate declaration exact.
- [x] Add software negatives for a similarly named target, altered window/assertion, and wrong APB template. Add a combined similarly named profile + wrong-template case that asserts template-specific refusal and proves `subprocess.Popen` is never called.
- [x] Run D1–D3 configuration generation without a native session: status complete, zero absence, one registered F4 projection selected, no runtime family.

### Task 4: Run the real sibling F4 gate and record exact evidence

**Files:**
- Create: `docs/reports/p7-f4-cv32e40p-apb3-sibling-20261020.md`
- Create: `docs/reports/evidence/p7-f4-cv32e40p-apb3-sibling-current-20261020/`
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/LOCAL_HARNESS_RUNTIME.md`
- Modify: `docs/reports/README.md`
- Modify: `docs/superpowers/plans/README.md`

- [x] Run `scripts/auto_harness_test.py` with CV32E40P + PULP timer, `--executor compiled-f4-rfuzz`, no `--runtime`, the local RFuzz client, and a fresh output directory. The final run revalidated after review fixes.
- [x] Require complete stage status, zero absence, four certified receipts, distinct fresh process identities, and `fresh-verification.json` with `matches=true` and `verification_scope=full`.
- [x] Preserve the command, actual run summary, execution binding, compiled digest, candidate layout, producer binding, receipt join and fresh replay documents under the evidence directory.
- [x] Record tests, commands, exit codes and the bounded scope. State explicitly that this adds a second CPU instance but not a second APB source contract or arbitrary APB3 support.
- [x] Run scoped software tests and `git diff --check`; no repository-wide suite was run.

## Self-review

- The execution binding covers the complete declared path and exact live artifact/producer identities.
- A caller cannot replace the binding without the runtime recomputing a mismatch.
- Fresh replay constructs the binding again and still checks distinct native processes and complete semantic prefix equality.
- The negative case is rejected before a process starts.
- No report upgrades P7 overall or overstates APB3 source coverage.
