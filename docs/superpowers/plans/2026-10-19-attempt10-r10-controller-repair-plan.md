# Attempt10 r10 Controller Repair Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the Attempt10 controller’s repeated JSON decode while preserving the reviewed r9 package and producing a separately reviewed r10 P6 gate run.

**Architecture:** Keep the existing Attempt10 operation and evidence roots, source snapshot, tool snapshot, and runtime receipt names. Create r10 siblings for every frozen Stage1 and Stage2 artifact whose bytes or path contracts change; update the controller, runner, and auditor to point to the r10 seal, plan, and intent. Do not modify or remove any r9 artifact. Launch only through the external r10 bootstrap contract after independent review of the exact Stage1 and Stage2 identities.

**Tech Stack:** Python 3.12.3 static artifact generation, SHA-256 and canonical JSON identity checks, remote SSH through `jumpserver`.

## Global Constraints

- The r9 Stage1 package digest remains `a1774182853c1885f7a37f27e54a12f747224e744f022ba0b0df950fe74d11a8` and its files remain unchanged.
- The r9 Stage2 package digest remains `94503fcd8bb9a4c1293fc98fe4a72967fcc122943bb74c6f404252bf0808a2b2` and its files remain unchanged.
- All target-machine reads and writes remain under `/root/fanzehui/**`; `/root/fanzehui/system-20261016/**` remains read-only.
- No controller, gate, runner, auditor, project module, or test may execute until two independent reviewers accept the exact r10 Stage1 package and two independent reviewers accept the exact r10 Stage2 package.
- The correction is exactly `strict_json(read_regular(Path(env["tool_freeze"]), 0o600))`; `strict_json()` keeps its bytes input and owns UTF-8 decoding.
- Reuse the existing Attempt10 source manifest, source receipts, tool freeze, private Verilator snapshot, canonical-lock observation, project snapshot, evidence destination, and absent runtime receipt paths.
- Do not add or run tests. The authorized frozen P6 controller/gate/audit chain is the final verification path.
- Preserve false values for `coverage_guided_search`, `formal_p6_complete`, `retirement_authority`, and `source_authority` unless the frozen independent auditor establishes otherwise.

---

### Task 1: Build a corrected Stage1 r10 package

**Files:**
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/attempt10-plan-schema-v17-r10.json`
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/attempt10-source-byte-bootstrap-v1-r10.py`
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/attempt10-post-gate-audit-runner-v17-r10.py`
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/independent_audit_task5.attempt10.v17-r10.py`
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/task5-attempt10-run-controller-v17-r10.py`
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/attempt10-external-launch-contract-v17-r10.json`
- Create: `/tmp/attempt10-v17-stage1-freeze-r10/static-code-manifest.v17-r10.json`

- [x] Copy the seven r9 Stage1 artifacts into a new r10 staging directory; preserve r9 bytes and modes.
- [x] Change the controller call at the r9 `strict_json(read_regular(...).decode("utf-8"))` site to pass the bytes directly to `strict_json()`.
- [x] Rename all seven Stage1 artifact references to their r10 siblings and update the bootstrap target paths, embedded bootstrap source, schema contracts, runner/auditor pins, and external launch vector in dependency order.
- [x] Rename Stage2 seal, plan, and intent references inside the new controller, runner, auditor, and schema to `attempt10-freeze-seal-v17-r10.json`, `attempt10-run-plan-v17-r10.json`, and `attempt10-run-plan-intent-v17-r10.json`.
- [x] Recompute each static SHA and the Stage1 manifest canonical digest; confirm the source contains the bytes-only `strict_json()` call and that no r9 artifact changed.
- [x] Obtain two independent ACCEPT reviews for the exact Stage1 r10 package digest. Do not upload or execute it before both reviews agree on that digest.

### Task 2: Build and review the Stage2 r10 package

**Files:**
- Create: `/tmp/attempt10-v17-stage2-freeze-r10/attempt10-freeze-seal-v17-r10.json`
- Create: `/tmp/attempt10-v17-stage2-freeze-r10/attempt10-run-plan-v17-r10.json`
- Create: `/tmp/attempt10-v17-stage2-freeze-r10/attempt10-run-plan-intent-v17-r10.json`
- Create: `/tmp/attempt10-v17-stage2-freeze-r10/attempt10-stage2-static-package-manifest-v17-r10.json`

- [x] Generate the seal → plan → intent chain against the accepted Stage1 r10 manifest and the existing source/environment receipts. Keep `gate_started=false` and `gate_executed=false`.
- [x] Produce a canonical manifest over sorted unique static entries; the Stage2 package manifest itself stays outside its own entries digest.
- [x] Check the new Stage2 paths are absent remotely and all prelaunch evidence/runtime paths remain absent.
- [x] Obtain two independent ACCEPT reviews for the exact Stage2 r10 package digest; resolve all findings and repeat both reviews if any byte changes.

### Task 3: Upload and verify the reviewed r10 static artifacts

**Files:**
- Create remotely under `/root/fanzehui/myfuzz/operations/p6-native-instruction-bus-completion-v1-20261019-attempt10/`: the seven Stage1 r10 files listed in Task 1 and the four Stage2 r10 files listed in Task 2.

- [x] Use exclusive, no-follow creation with mode `0600`; write and fsync each file and its parent directory. Then apply the reviewed final package modes (`0700` for controller/runner, `0600` for the other nine files) and fsync the files.
- [x] Read each file back and verify exact bytes, SHA-256, size, regular-file type, uid/gid `0:0`, its declared final mode, and `nlink=1`.
- [x] Obtain two independent read-only post-upload ACCEPTs for the same Stage2 r10 digest and verify the r9 files remain unchanged.

### Task 4: Run the frozen r10 gate and audits

**Files:**
- Create remotely under `/root/fanzehui/myfuzz/evidence/p6-native-instruction-bus-completion-v1-20261019-attempt10/` only through the frozen controller/gate process.
- Create remotely under the Attempt10 operation directory only the runtime receipts declared in the r10 plan.

- [ ] Invoke the exact controller `argv`, `cwd`, and complete `env` from `attempt10-external-launch-contract-v17-r10.json`, transporting the exact bootstrap UTF-8 source as the sole `-c` argument.
- [ ] Wait for the controller’s terminal receipt. Record any failure without altering claims or retrying one-shot paths.
- [ ] Only after a terminal gate receipt exists, invoke the planned r10 post-gate runner; invoke its independent auditor only through the frozen bound launch.
- [ ] Verify controller, gate, runner, and auditor identities and receipt joins before describing the P6 result.

### Task 5: Reconcile the progress documents

**Files:**
- Modify: `docs/CURRENT_PROGRESS.md`
- Modify: `docs/reports/README.md`
- Create: `docs/reports/p6-attempt10-r10-controller-repair-20261019.md`

- [x] Record the r9 prelaunch failure, its exact one-line root cause, the r10 package digests, the two-stage review/upload state, and why execution is still pending.
- [x] Keep P6 marked open; do not promote a source-transfer completion result into decode, retirement, semantic-consumption, or formal-completion authority.
- [ ] Append the terminal gate/audit outcome after the frozen run is authorized and the independent audit completes.
