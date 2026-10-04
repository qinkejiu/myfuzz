# Four CPU Source Lock and Elaboration Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add independently replayable source and full elaboration closure evidence for CVE2 and the three PicoRV32 tops.

**Architecture:** Treat each top as a separate component record, even when several share one source file. Derive selected bytes from the final component profiles, record the files Verilator actually read through its dependency report, pin every byte to the upstream git revision, then run the repository's verifier both normally and with elaboration replay.

**Tech Stack:** Python 3, Verilator 5.051, Git submodule pins, `soc_sources.v1` and `soc_elaboration_closure.v1` JSON.

## Global Constraints

- Four records are required: `cv32e20`, `picorv32`, `picorv32_axi`, `picorv32_wb`; each closure `component` and `top_module` must match its own record.
- Reuse exact source revision, ordered files, include roots, defines and parameters from each merged profile. Do not substitute a profile snapshot or guessed source list for actual Verilator dependency read set.
- Closure files must be git blobs at the pinned upstream revision; generated/local-modified source bytes cannot be declared verified.
- All four records remain `runtime_status="runtime_unverified"`. Source and lint evidence is not a generated harness or real CPU execution.
- Do not change existing component lock records, old closure documents or old scenario evidence identities.

---

## File Structure

- Modify `configs/soc/sources.lock.json`: append four source records.
- Create `configs/soc/closures/cv32e20.json`, `picorv32.json`, `picorv32_axi.json`, `picorv32_wb.json`: four independent lint read sets.
- Create `docs/reports/generated-harness-cpu-source-lock-20261004.md`: actual counts and verifier results.

### Task 1: Generate candidate source and closure records from final profiles

**Files:**
- Modify: `configs/soc/sources.lock.json`
- Create: `configs/soc/closures/cv32e20.json`
- Create: `configs/soc/closures/picorv32.json`
- Create: `configs/soc/closures/picorv32_axi.json`
- Create: `configs/soc/closures/picorv32_wb.json`

**Interfaces:**
- Consumes: final profile `source` objects and `scripts.verify_soc_sources.selected_paths`.
- Produces: four `soc_sources.v1` records whose source hashes and closure documents can pass `verify_soc_sources.py`.

- [ ] **Step 1: Inspect exact profile inputs and toolchain**

```bash
PYTHONPATH=src python3 - <<'PY'
import json
from pathlib import Path
for name in ("cv32e20", "picorv32", "picorv32_axi", "picorv32_wb"):
    path = Path("configs/cpus") / name / "component_profile.json"
    source = json.loads(path.read_text())["source"]
    print(name, source["revision"], source["top_module"], len(source["files"]))
PY
verilator --version
```

Expected: four actual git revisions matching the two parent gitlinks; the Verilator version string is saved exactly, not normalized.

- [ ] **Step 2: Compute selected artifacts and selected-content hash with repository helpers**

```python
import json
from pathlib import Path
from hashlib import sha256
from scripts.verify_soc_sources import selected_paths
from myfuzz.composition.source_crawler import source_tree_hash

base = Path.cwd()
component_id = "cv32e20"
source = json.loads(
    (base / "configs/cpus" / component_id / "component_profile.json").read_text()
)["source"]
root, selected = selected_paths(source, base)
selected_content_hash = source_tree_hash(root, [root / name for name in selected])
license_path = "LICENSE" if component_id == "cv32e20" else "COPYING"
artifacts = [
    {"path": name, "sha256": sha256((root / name).read_bytes()).hexdigest(),
     "kind": "source"}
    for name in selected
]
artifacts.append({"path": license_path,
                  "sha256": sha256((root / license_path).read_bytes()).hexdigest(),
                  "kind": "license"})
```

Expected: all selected source/filelist/header input paths appear in `artifacts`, plus a git-owned license. The hash has `sha256:` prefix and uses framed relative paths/bytes, not a raw file digest.

- [ ] **Step 3: Run a native-top lint with Verilator dependency recording**

```python
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess

command = ["verilator", "--lint-only", "-Wno-fatal", "--top-module",
           source["top_module"]]
command += ["-I" + source["root"] + "/" + path
            for path in source.get("include_roots", [])]
command += ["-D" + item["name"] + "=" + str(item["value"])
            for item in source.get("elaboration", {}).get("defines", [])]
command += ["-G" + item["name"] + "=" + str(item["value"])
            for item in source.get("elaboration", {}).get("parameters", [])]
command += [source["root"] + "/" + path for path in source["files"]]
with TemporaryDirectory() as work:
    result = subprocess.run(command + ["--MMD", "--Mdir", work],
                            text=True, capture_output=True, check=False)
    assert result.returncode == 0 and "%Error" not in result.stderr + result.stdout
    reports = list(Path(work).glob("*.d"))
    assert len(reports) == 1
    _, _, dependency_text = reports[0].read_text().replace("\\\n", " ").partition(":")
    read_set = {Path(token.replace("\\ ", " ")).resolve()
                for token in dependency_text.split()}
```

Expected: one dependency report and no Verilator errors. Normalize paths against repository root if Verilator emits relative paths; closure entries must name **exactly** this actual read set. Record nonfatal warning count from the tool output, including its exact log in the report.

- [ ] **Step 4: Assemble each closure document and lock record**

Repeat Steps 2–3 with `component_id` set to each of `cv32e20`, `picorv32`, `picorv32_axi`, `picorv32_wb`. For each component write the closure fields `schema_version`, `component`, `root`, `top_module`, `tool={name,version,frontend}`, `command`, `include_roots`, `defines`, `parameters`, `closure_files=[{root,path,sha256}]`, `status="elaboration_verified"`, `lint={errors:0,warnings:warning_count,exit_code:0}` where `warning_count` is the number of actual Verilator warning diagnostics. `command` is the reproducible workspace-relative command without temporary `--Mdir`; the verifier appends its own dependency flags on replay. Every closure file must lie under the component's declared source root and match `git cat-file blob <revision>:<path>`.

Append one lock record per top with `id`, matching `source`, `artifacts`, `selected_content_hash`, `closure_status="selected"`, `source_status="source_verified"`, `elaboration_status="elaboration_verified"`, `runtime_status="runtime_unverified"`, `defines`, `typed_parameters`, `generator={status:"not_invoked",tool_version:null,name:"none for selected checked-in files"}`, `dependencies=[]`, and `elaboration` block containing `status`, `top_module`, matching `tool`, workspace-relative `evidence`, exact serialized `evidence_sha256`, `closure_files` count and matching `lint`. CVE2/Pico old official descriptions may be referenced with `interface_description` and exact SHA only if their current bytes pass the verifier.

### Task 2: Verify all four source records and replayed read sets

**Files:**
- Read: new lock entries and closure documents.
- Create: `docs/reports/generated-harness-cpu-source-lock-20261004.md`

**Interfaces:**
- Consumes: Task 1 JSON records.
- Produces: actual source and elaboration gate evidence.

- [ ] **Step 1: Stage evidence before verification**

```bash
git add configs/soc/sources.lock.json configs/soc/closures/cv32e20.json configs/soc/closures/picorv32.json configs/soc/closures/picorv32_axi.json configs/soc/closures/picorv32_wb.json
PYTHONPATH=src python3 scripts/verify_soc_sources.py
PYTHONPATH=src python3 scripts/verify_soc_sources.py --elaborate
```

Expected: both commands exit 0. The verifier deliberately rejects untracked closure evidence, so stage it first. Four new records show `source_verified`, `elaboration_verified`, `runtime_unverified`; replay shows `read_set_matches_closure=true` for each. Existing records continue to pass unchanged.

- [ ] **Step 2: Record measured counts and limitations**

Write the report with the four component IDs, source pins, selected path counts, closure read counts, actual lint warnings, Verilator version, verifier command exit codes and replay status. State that no generated harness or real CPU execution has been proven and that Pico AXI/Wishbone reduced response signals still need declared local transactor variants.

- [ ] **Step 3: Commit exact evidence and source lock**

```bash
git diff --cached --check
git add docs/reports/generated-harness-cpu-source-lock-20261004.md
git commit -m "build: pin CVE2 and Pico elaboration closures"
```

Expected: one commit containing only the four lock entries, four closure documents and report. Running the two verifier commands again after commit still exits 0.
