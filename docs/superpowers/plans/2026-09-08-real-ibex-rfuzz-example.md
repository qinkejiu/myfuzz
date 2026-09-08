# Real Ibex RFuzz Example Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a runnable Chinese-language real-Ibex example with separate automatic-composition, bounded RFuzz-test, and result-inspection commands.

**Architecture:** A thin example CLI imports the existing `build_candidate`, `run_live`, and `replay_corpus` APIs. A versioned JSON document selects one source-backed peripheral and declares processor, ISA, protocol, controls, and randomizable fields; the guide explains all generated evidence without duplicating production logic.

**Tech Stack:** Python 3 standard library, unittest, JSON, Bash, Verilator, upstream RFuzz `kfuzz` client.

## Global Constraints

- Reuse production protocol matching, composition, constraint, simulator, feedback, corpus, and replay code.
- Resolve relative input paths against the repository root.
- Ordinary tests must not build real Ibex or launch RFuzz.
- Preserve non-overwriting output behavior and nonzero failure exits.
- Label the 5-second example as a smoke test, not three-by-300-second acceptance.
- Keep BOOM and the formal long-run gate explicitly unaccepted.
- Never stage `.superpowers/sdd/task-2-report.md` or untracked `third_party/` content.

---

### Task 1: Example CLI and Input Contract

**Files:**
- Create: `examples/real_ibex_rfuzz/run_example.py`
- Create: `examples/real_ibex_rfuzz/input/ibex-scratch.json`
- Create: `tests/examples/__init__.py`
- Create: `tests/examples/test_real_ibex_rfuzz_example.py`

**Interfaces:**
- Consumes: `build_candidate(root, output, config, personality)`, `run_live(artifact, client, output_dir, duration_seconds=..., seed_cycles=...)`, `replay_corpus(artifact, corpus_dir)`.
- Produces: `load_example(path, root) -> tuple[dict, dict]`, `compose_example(root, input_path, output) -> dict`, `test_example(root, input_path, client, output, seconds) -> dict`, `inspect_example(output) -> dict`.

- [x] **Step 1: Write failing contract tests**

Test exact schema translation, rejection of unknown keys and bad schema versions,
positive duration enforcement, missing-client rejection, mocked production call
order, summary creation, malformed-summary rejection, and CLI help. The core
translation assertion is:

```python
config, personality = module.load_example(INPUT, ROOT)
self.assertEqual(config["protocol"], ["obi", "1"])
self.assertEqual(personality["name"], "scratch-register")
self.assertEqual(personality["mode"], 0)
```

- [x] **Step 2: Run tests and confirm RED**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v \
  tests.examples.test_real_ibex_rfuzz_example
```

Expected: import/input failure because the example files do not exist.

- [x] **Step 3: Add the real-Ibex input document**

Copy the valid processor values from
`configs/campaigns/ibex-real-rfuzz.json`, replace the three-element
`peripherals` array with this single record, and add the schema version:

```json
{
  "schema_version": "real_ibex_rfuzz_example.v1",
  "personality": {
    "name": "scratch-register",
    "module": "processor_register_target",
    "source": "src/myfuzz/integration/rtl/processor_register_target.sv",
    "mode": 0
  }
}
```

The completed document must retain the campaign's exact `id`, `interface`, ISA
contract, OBI protocol, memory module, reset vector, probe cycles,
randomizable fields, and control defaults.

- [x] **Step 4: Implement the thin CLI**

Find the root with `Path(__file__).resolve().parents[2]`. Validate the exact
top-level key set, schema, primitive types, personality key set, contained
source paths, and output preconditions. Translate the input by removing only
`schema_version` and `personality`.

`compose_example` calls `build_candidate` and publishes `summary.json` with
mode, status, input/output paths, execution, composition hash, layout hash, and
coverage. `test_example` validates an executable client, builds the candidate,
calls `run_live`, calls `replay_corpus` on `live/corpus`, and publishes test,
feedback, corpus, execution, identity, replay, return-code, duration, and
shared-memory results. `inspect_example` validates and returns either summary.

Expose `compose`, `test`, and `inspect` through `argparse`; print indented JSON.
Convert `ValueError`, `OSError`, and `RuntimeError` into concise parser errors.

- [x] **Step 5: Run tests and confirm GREEN**

Run Step 2. Expected: all tests pass without Verilator or RFuzz execution.

- [x] **Step 6: Commit Task 1**

```bash
git add examples/real_ibex_rfuzz/run_example.py \
  examples/real_ibex_rfuzz/input/ibex-scratch.json \
  tests/examples/__init__.py tests/examples/test_real_ibex_rfuzz_example.py
git commit -m "feat: add runnable real Ibex RFuzz example"
```

### Task 2: Capability Guide and Reference Evidence

**Files:**
- Create: `examples/real_ibex_rfuzz/README.zh-CN.md`
- Create: `examples/real_ibex_rfuzz/commands.sh`
- Create: `examples/real_ibex_rfuzz/expected/bounded-result.json`
- Modify: `README.md`
- Modify: `tests/examples/test_real_ibex_rfuzz_example.py`

**Interfaces:**
- Consumes: Task 1 CLI and input.
- Produces: copyable commands, capability explanation, and historical reference evidence.

- [x] **Step 1: Add failing documentation consistency tests**

Parse both JSON documents, run `bash -n commands.sh`, assert every documented
repository path exists, and require the guide to contain `run_example.py
compose`, `run_example.py test`, `run_example.py inspect`, `5 秒`, and `3×300
秒`. Verify the root README links to the guide.

- [x] **Step 2: Run the focused suite and confirm RED**

Run Task 1 Step 2. Expected: missing documentation/artifact failures.

- [x] **Step 3: Write the Chinese walkthrough**

Cover system capability and boundaries, automatic-composition data flow,
fail-closed checks, JSON-to-layout-to-DUT constraint projection, dependency
preparation, every input field, compose/test/inspect outputs, regression
commands, the formal long-run command, troubleshooting, process/shared-memory
cleanup, and a matrix separating implementation, fixture, real CPU, 5-second
RFuzz evidence, and 300-second acceptance.

- [x] **Step 4: Add commands and retained result**

Make `commands.sh` use `set -euo pipefail`, derive and enter the repository root,
export `PYTHONPATH=src:.` and `JOBS=1`, and show compose, 5-second test, inspect,
focused/full unittest, and formal `run_real_cpu_campaigns.py --seconds 300`.

Create `bounded-result.json` with the retained result: 15,357 RTL tests, 13,440
completed feedback receipts, 19 corpus entries, 168,927 requests/completions,
153,570 reads/progress events, 15,357 pass completions and first-fetch matches,
zero errors, return code zero, zero remaining shared-memory segments, and false
values for formal 3×300 seconds and BOOM acceptance.

- [x] **Step 5: Link the guide and validate all artifacts**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -v \
  tests.examples.test_real_ibex_rfuzz_example
bash -n examples/real_ibex_rfuzz/commands.sh
python3 -m json.tool examples/real_ibex_rfuzz/input/ibex-scratch.json >/dev/null
python3 -m json.tool examples/real_ibex_rfuzz/expected/bounded-result.json >/dev/null
```

Expected: every command exits zero.

- [x] **Step 6: Commit Task 2**

```bash
git add README.md examples/real_ibex_rfuzz/README.zh-CN.md \
  examples/real_ibex_rfuzz/commands.sh \
  examples/real_ibex_rfuzz/expected/bounded-result.json \
  tests/examples/test_real_ibex_rfuzz_example.py
git commit -m "docs: add real Ibex end-to-end walkthrough"
```

### Task 3: Regression, Live Validation, and Publication

**Files:**
- Modify only Task 1 or Task 2 files if validation exposes an in-scope defect.

**Interfaces:**
- Consumes: complete example directory.
- Produces: verified commits on the remote feature branch.

- [x] **Step 1: Verify all command help**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 examples/real_ibex_rfuzz/run_example.py --help
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 examples/real_ibex_rfuzz/run_example.py compose --help
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 examples/real_ibex_rfuzz/run_example.py test --help
```

Expected: zero exit and documented arguments.

- [x] **Step 2: Run focused and full regression**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest -v tests.examples.test_real_ibex_rfuzz_example
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. JOBS=1 nice -n15 python3 -m unittest discover -s tests -p 'test_*.py'
```

Expected: focused tests pass; full regression ends with `OK` and only known
opt-in skips.

- [x] **Step 3: Run real composition**

```bash
PYTHONPATH=src:. JOBS=1 nice -n15 python3 examples/real_ibex_rfuzz/run_example.py compose \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --output runs/examples/real-ibex-compose-20260908
```

Expected: first fetch matches, progress exceeds one, completions and pass
completions are positive, and errors are zero. Use a new named output instead
of deleting retained evidence if the path exists.

- [x] **Step 4: Run the 5-second official-client example**

```bash
PYTHONPATH=src:. JOBS=1 nice -n15 python3 examples/real_ibex_rfuzz/run_example.py test \
  --input examples/real_ibex_rfuzz/input/ibex-scratch.json \
  --client runs/task14_client_cancel_build/debug/kfuzz \
  --output runs/examples/real-ibex-rfuzz-5s-20260908 --seconds 5
```

Expected: multiple RTL tests/corpus entries, completed feedback, successful
replay, and no remaining owned segments. If the client is absent, report the
environmental limitation and retain historical evidence without claiming a
fresh pass.

- [x] **Step 5: Audit and push**

```bash
git diff --check
git status --short
git push origin feature/ibex-protocol-longrun
git ls-remote --heads origin feature/ibex-protocol-longrun
```

Expected: no whitespace errors and the remote head equals the final local
commit; user-owned report and untracked dependencies remain untouched.
