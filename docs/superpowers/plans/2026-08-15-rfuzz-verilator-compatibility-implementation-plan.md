# RFuzz Verilator Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make native RFuzz builds select and enforce the bundled Verilator 5.020 toolchain so incompatible 5.051 builds cannot enter the Task 5B campaign.

**Architecture:** Add one resolver and one version validator to `myfuzz.rfuzz_compat`. The native design-flow script and static campaign script call that shared API, while existing path/config overrides remain authoritative. Existing native input identity and artifact sidecar checks continue to bind the selected compiler to each build.

**Tech Stack:** Python 3.12 standard library, `unittest`, SystemVerilog/RFuzz native server, bundled Verilator 5.020, shell/JQ verification.

## Global Constraints

- Native RFuzz defaults to `third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator`.
- Native RFuzz requires a reported version beginning with `Verilator 5.020`.
- `MYFUZZ_SERVER_VERILATOR_BIN`, CLI server-bin arguments, and declared config paths remain explicit overrides.
- Missing bundled tooling and incompatible observed versions are hard errors; no `PATH` fallback is allowed.
- Compiler path, digest, and exact version remain part of the native input identity and build sidecar.
- The vendored RFuzz C++ runtime, RTL, candidate manifests, policy parameters, and campaign thresholds are unchanged.
- Verification requires zero server/fuzzer return codes, successful FIFO cleanup, and the expected 5.020 version before any campaign result is considered usable.

---

### Task 1: Add the Shared RFuzz Verilator Resolver

**Files:**
- Modify: `src/myfuzz/rfuzz_compat.py`
- Test: `tests/test_rfuzz_compat.py`

**Interfaces:**
- Consumes: an absolute repository `Path` and the optional `MYFUZZ_SERVER_VERILATOR_BIN` environment override.
- Produces: `resolve_rfuzz_verilator(repo_root: Path) -> str` and `validate_rfuzz_verilator_version(version: str) -> str`.

- [x] **Step 1: Write the failing resolver tests**

Add these imports and tests to `tests/test_rfuzz_compat.py`:

```python
import os
import tempfile
from unittest.mock import patch

from myfuzz.rfuzz_compat import (
    resolve_rfuzz_verilator,
    validate_rfuzz_verilator_version,
)


class RfuzzVerilatorResolverTests(unittest.TestCase):
    def test_default_uses_bundled_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundled = root / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
            bundled.parent.mkdir(parents=True)
            bundled.write_text("#!/bin/sh\n", encoding="utf-8")
            bundled.chmod(0o755)
            with patch.dict(os.environ, {}, clear=True):
                self.assertEqual(bundled.as_posix(), resolve_rfuzz_verilator(root))

    def test_explicit_environment_override_wins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.dict(
                os.environ,
                {"MYFUZZ_SERVER_VERILATOR_BIN": "/opt/validated/verilator"},
                clear=True,
            ):
                self.assertEqual(
                    "/opt/validated/verilator",
                    resolve_rfuzz_verilator(root),
                )

    def test_missing_bundled_executable_fails_without_path_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
                ValueError, "bundled RFuzz Verilator 5.020"
            ):
                resolve_rfuzz_verilator(Path(directory))

    def test_version_validator_accepts_only_rfuzz_compatible_verilator(self) -> None:
        version = "Verilator 5.020 2024-01-01 rev (Debian 5.020-1)"
        self.assertEqual(version, validate_rfuzz_verilator_version(version))
        with self.assertRaisesRegex(ValueError, "requires Verilator 5.020"):
            validate_rfuzz_verilator_version("Verilator 5.051 devel")
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_rfuzz_compat.RfuzzVerilatorResolverTests -v`

Expected: FAIL because the resolver and validator do not exist yet.

- [x] **Step 2: Implement the minimal shared resolver and validator**

Add the following constants and functions to `src/myfuzz/rfuzz_compat.py`, preserving the module's existing rendering APIs:

```python
import os
import stat

RFUZZ_VERILATOR_RELATIVE = Path(
    "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
)
RFUZZ_VERILATOR_VERSION_PREFIX = "Verilator 5.020"


def resolve_rfuzz_verilator(repo_root: Path) -> str:
    if not isinstance(repo_root, Path) or not repo_root.is_absolute():
        raise ValueError("repo_root must be an absolute pathlib.Path")
    override = os.environ.get("MYFUZZ_SERVER_VERILATOR_BIN")
    if override:
        return override
    candidate = repo_root / RFUZZ_VERILATOR_RELATIVE
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise ValueError(
            "bundled RFuzz Verilator 5.020 is missing; set "
            "MYFUZZ_SERVER_VERILATOR_BIN to an explicitly validated executable"
        ) from error
    if candidate.is_symlink() or not stat.S_ISREG(metadata.st_mode) or not os.access(candidate, os.X_OK):
        raise ValueError(
            "bundled RFuzz Verilator 5.020 is not an executable regular file; "
            "set MYFUZZ_SERVER_VERILATOR_BIN to an explicitly validated executable"
        )
    return candidate.resolve().as_posix()


def validate_rfuzz_verilator_version(version: str) -> str:
    if not isinstance(version, str) or not version.startswith(RFUZZ_VERILATOR_VERSION_PREFIX):
        raise ValueError(
            f"native RFuzz requires Verilator 5.020; observed {version!r}"
        )
    return version
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_rfuzz_compat.RfuzzVerilatorResolverTests -v`

Expected: PASS.

- [x] **Step 3: Run the complete compatibility test file and check the diff**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_rfuzz_compat -v`

Run: `git diff --check`

Expected: all compatibility tests pass and the diff has no whitespace errors.

- [x] **Step 4: Commit the shared API**

```bash
git add src/myfuzz/rfuzz_compat.py tests/test_rfuzz_compat.py
git commit -m "fix: pin native RFuzz to bundled Verilator"
```

### Task 2: Wire Both Native RFuzz Entrypoints to the Contract

**Files:**
- Modify: `src/myfuzz/scripts/run_design_flow.py`
- Modify: `scripts/runs/run_static_projection_campaign.py`
- Modify: `tests/harness/test_flow_integration.py`
- Modify: `tests/test_static_projection_campaign.py`

**Interfaces:**
- Consumes: `resolve_rfuzz_verilator()` and `validate_rfuzz_verilator_version()` from Task 1.
- Produces: identical default compiler selection in server construction and campaign identity generation, plus early rejection of Verilator 5.051.

- [x] **Step 1: Write failing call-site and version-probe tests**

Add `import os` beside the existing standard-library imports, then add these tests to `tests/harness/test_flow_integration.py`:

```python
    def test_default_server_verilator_uses_the_bundled_rfuzz_toolchain(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            expected = (
                ROOT
                / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
            ).as_posix()
            self.assertEqual(expected, run_design_flow.default_server_verilator(ROOT))

    def test_probe_rejects_an_incompatible_verilator_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "verilator"
            executable.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'Verilator 5.051 devel'\n",
                encoding="utf-8",
            )
            executable.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "requires Verilator 5.020"):
                run_design_flow.probe_verilator_version(executable.as_posix(), Path(directory))
```

Add this import and test to `tests/test_static_projection_campaign.py`:

```python
from scripts.runs.run_static_projection_campaign import _campaign_verilator_bin


    def test_campaign_uses_the_shared_bundled_verilator_resolver(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            expected = (
                ROOT
                / "third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator"
            ).as_posix()
            self.assertEqual(expected, _campaign_verilator_bin())
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_flow_integration.FlowIntegrationTest.test_default_server_verilator_uses_the_bundled_rfuzz_toolchain tests.harness.test_flow_integration.FlowIntegrationTest.test_probe_rejects_an_incompatible_verilator_version tests.test_static_projection_campaign.StaticProjectionCampaignTest.test_campaign_uses_the_shared_bundled_verilator_resolver -v`

Expected: FAIL because both production entrypoints still return the stale fallback or accept 5.051.

- [x] **Step 2: Wire the design-flow resolver and version validation**

Import the shared functions in `src/myfuzz/scripts/run_design_flow.py`, replace the current stale-path implementation with:

```python
def default_server_verilator(root: Path) -> str:
    return resolve_rfuzz_verilator(root)
```

Change the final version return in `probe_verilator_version()` to:

```python
    return validate_rfuzz_verilator_version(version[0])
```

Keep the existing explicit CLI/config selection in `main()` unchanged; it still flows through `probe_verilator_version()` during native server build and artifact validation.

- [x] **Step 3: Wire the campaign resolver and version validation**

Import the shared functions in `scripts/runs/run_static_projection_campaign.py`, replace `_campaign_verilator_bin()` with:

```python
def _campaign_verilator_bin() -> str:
    return resolve_rfuzz_verilator(ROOT)
```

Change `_campaign_verilator_version()` to return:

```python
    return validate_rfuzz_verilator_version(
        completed.stdout.strip().splitlines()[0]
    )
```

Keep the existing `native_input_identity()` call and derived-config fields unchanged so the selected path and exact version remain bound to each policy artifact.

- [x] **Step 4: Run the call-site tests and the focused RFuzz suite**

Run: `PYTHONPATH=src:. python3 -m unittest tests.harness.test_flow_integration.FlowIntegrationTest.test_default_server_verilator_uses_the_bundled_rfuzz_toolchain tests.harness.test_flow_integration.FlowIntegrationTest.test_probe_rejects_an_incompatible_verilator_version tests.test_static_projection_campaign.StaticProjectionCampaignTest.test_campaign_uses_the_shared_bundled_verilator_resolver -v`

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_rfuzz_compat tests.test_original_rfuzz_native tests.integration.test_rfuzz_runner tests.harness.test_flow_integration tests.test_static_projection_campaign -v`

Expected: all selected tests pass; the resolver reports the bundled 5.020 binary and rejects the synthetic 5.051 executable.

- [x] **Step 5: Commit the entrypoint wiring**

```bash
git add src/myfuzz/scripts/run_design_flow.py scripts/runs/run_static_projection_campaign.py tests/harness/test_flow_integration.py tests/test_static_projection_campaign.py
git commit -m "fix: enforce RFuzz Verilator compatibility at entrypoints"
```

### Task 3: Rebuild, Smoke-Test, and Resume Task 5B

**Files:**
- Modify: `.superpowers/sdd/task-5B-report.md`
- Generate: `runs/static_projection/task5b_verilator_compat_smoke_20260815/`
- Generate: `runs/static_projection/task5b_full_20260815_fixed/`

**Interfaces:**
- Consumes: the fixed native resolver, the existing fixed training config, and the real kfuzz binary.
- Produces: a verified 5.020 smoke artifact and the resumed fixed-policy campaign evidence.

- [x] **Step 1: Run the focused suite, syntax checks, and full regression suite**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.test_rfuzz_compat tests.test_original_rfuzz_native tests.integration.test_rfuzz_runner tests.harness.test_flow_integration tests.test_static_projection_campaign -v
python3 -m compileall -q src scripts tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -v
git diff --check
```

Expected: focused and full test suites pass, compileall exits 0, and diff check is clean.

- [ ] **Step 2: Run the bounded real native smoke with the fixed compiler**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/runs/run_static_projection_campaign.py \
  --stage smoke \
  --config configs/experiments/static_projection_training.json \
  --out runs/static_projection/task5b_verilator_compat_smoke_20260815
```

Expected: exit 0; every `build-input.json` under the smoke design outputs reports a version beginning with `Verilator 5.020`; every RFuzz result reports `server_returncode=0`, `fuzzer_returncode=0`, `handshake_succeeded=true`, and `fifo_cleanup_succeeded=true`.

Verify with:

```bash
find runs/static_projection/task5b_verilator_compat_smoke_20260815 -name build-input.json -print0 \
  | xargs -0 -n1 jq -e '.verilator_version | startswith("Verilator 5.020")' >/dev/null
find runs/static_projection/task5b_verilator_compat_smoke_20260815/rfuzz-results -name '*.json' -print0 \
  | xargs -0 -n1 jq -e '(.server_returncode == 0 and .fuzzer_returncode == 0 and .handshake_succeeded == true and .fifo_cleanup_succeeded == true)' >/dev/null
```

- [ ] **Step 3: Run the fixed-policy training/promotion/validation campaign**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/runs/run_static_projection_campaign.py \
  --stage training \
  --config configs/experiments/static_projection_training.json \
  --out runs/static_projection/task5b_full_20260815_fixed
```

The expected workload is 54 policies across two targets at 60 seconds for screening, followed by the configured promotion and frozen validation budgets. Monitor the published `rfuzz-results` and do not interpret the earlier 5.051 run as campaign evidence.

- [ ] **Step 4: Update the Task 5B report with verified infrastructure and campaign evidence**

Record the bundled compiler path, exact observed version, smoke return codes, artifact identities, campaign stage completion, promotion decision, and frozen validation results in `.superpowers/sdd/task-5B-report.md`. Keep the earlier failed run explicitly labeled as an infrastructure failure and do not convert it into a policy comparison.

- [ ] **Step 5: Run final verification before claiming completion**

Run:

```bash
git diff --check
git status --short
```

Confirm that all required campaign result documents exist, every accepted result passes the existing artifact/identity/FIFO gates, and the report does not claim a frozen policy unless the full configured stages completed successfully.
