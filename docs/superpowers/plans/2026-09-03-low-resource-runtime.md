# Low-Resource Runtime Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Add an opt-in conservative resource profile and a deterministic end-to-end smoke command that validates the existing protocol, harness, dependency-aware, memory-gated, and report paths without starting an external simulator.

**Architecture:** Keep the existing planner and matrix contracts unchanged. Add a pure, immutable configuration transformer in myfuzz.experiments.resource_policy, then add an integration-level smoke function that feeds the transformed planner configuration through the existing candidate pipeline and experiment matrix with a deterministic in-process runner. Expose that function through a small script and document that normal experiments are unaffected.

**Tech Stack:** Python 3, dataclasses, standard-library unittest, JSON fixtures, existing myfuzz.integration orchestration, existing memory gate, and atomic report writer.

## Global Constraints

- The profile is opt-in and must not change checked-in default experiment configurations.
- The conservative limits are: one candidate, one sorted seed, the named smoke budget, build concurrency 1, waveforms disabled, replay queue 32, event ring 512, field groups per batch 16, soft memory at most 512 MiB, hard memory at most 768 MiB, and token size at most 64 MiB.
- The transformer must deep-copy input and preserve any stricter caller-supplied limit.
- A missing smoke budget or malformed configuration must fail closed before pipeline or gate activity.
- The smoke path must use the real runtime preparation adapter and no external Verilator/RFuzz child process.
- Default smoke output is temporary; a caller-provided report path is the only persistent output.
- Verification must remain targeted and must not start a long fuzz campaign or high-concurrency build.
- Work only in /home/qinkejiu/myfuzz/.worktrees/low-resource on feature/low-resource-runtime; do not modify the dirty root worktree.

---

## File and responsibility map

| File | Responsibility |
| --- | --- |
| src/myfuzz/experiments/resource_policy.py | Validate and apply the immutable conservative planner profile. |
| src/myfuzz/experiments/__init__.py | Public exports for the profile API. |
| src/myfuzz/integration/low_resource_smoke.py | Compose runtime fixtures, actual harness preparation, matrix plan, deterministic runner, and result summary. |
| src/myfuzz/integration/__init__.py | Public export for the smoke function. |
| scripts/run_low_resource_smoke.py | CLI argument parsing and compact output only. |
| tests/experiments/test_resource_policy.py | Unit tests for profile behavior and fail-closed validation. |
| tests/integration/test_low_resource_smoke.py | End-to-end smoke test through real adapters and report generation. |
| tests/integration/test_low_resource_smoke_cli.py | Low-cost CLI process test. |
| docs/low-resource-running.md | User-facing command, resource guarantees, overrides, and limitations. |

### Task 1: Add the immutable conservative resource profile

**Files:**

- Create: tests/experiments/test_resource_policy.py
- Create: src/myfuzz/experiments/resource_policy.py
- Modify: src/myfuzz/experiments/__init__.py

**Interfaces:**

- Produces ResourceProfile, ResourceProfileError, CONSERVATIVE_PROFILE, and apply_resource_profile(config, profile=CONSERVATIVE_PROFILE) -> dict[str, object].
- Consumes an experiment.v1 planner configuration mapping such as configs/experiments/rvx.json.
- Later tasks use dataclasses.replace(CONSERVATIVE_PROFILE, soft_memory_bytes=256 * 1024 * 1024) for optional CLI memory ceilings.

- [ ] Step 1: Write the failing unit tests.

Create tests/experiments/test_resource_policy.py with these tests:

~~~python
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from myfuzz.experiments import (
    CONSERVATIVE_PROFILE,
    ResourceProfileError,
    apply_resource_profile,
)


ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / "configs" / "experiments" / "rvx.json"
MIB = 1024 * 1024


def load_config() -> dict[str, object]:
    document = json.loads(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


class ResourcePolicyTests(unittest.TestCase):
    def test_conservative_profile_is_deterministic_and_does_not_mutate_input(self) -> None:
        original = load_config()
        before = deepcopy(original)

        constrained = apply_resource_profile(original)

        self.assertEqual(before, original)
        self.assertEqual(1, constrained["candidate_selection"]["k"])
        self.assertEqual([1], constrained["candidate_pair"]["seeds"])
        self.assertEqual(
            [{"name": "smoke", "kind": "cycles", "value": 1000}],
            constrained["budgets"],
        )
        self.assertEqual(1, constrained["build_concurrency"])
        self.assertFalse(constrained["waveforms"])
        self.assertEqual(32, constrained["replay_queue_capacity"])
        self.assertEqual(512, constrained["event_ring_capacity"])
        self.assertEqual(16, constrained["field_groups_per_batch"])
        self.assertEqual(512 * MIB, constrained["soft_memory_bytes"])
        self.assertEqual(768 * MIB, constrained["hard_memory_bytes"])
        self.assertEqual(64 * MIB, constrained["token_bytes"])

    def test_profile_preserves_stricter_input_limits(self) -> None:
        config = load_config()
        config["candidate_selection"]["k"] = 1
        config["candidate_pair"]["seeds"] = [19]
        config["budgets"] = [{"name": "smoke", "kind": "cycles", "value": 100}]
        config["replay_queue_capacity"] = 4
        config["event_ring_capacity"] = 8
        config["field_groups_per_batch"] = 2
        config["soft_memory_bytes"] = 128 * MIB
        config["hard_memory_bytes"] = 256 * MIB
        config["token_bytes"] = 16 * MIB

        constrained = apply_resource_profile(config)

        self.assertEqual(1, constrained["candidate_selection"]["k"])
        self.assertEqual([19], constrained["candidate_pair"]["seeds"])
        self.assertEqual(config["budgets"], constrained["budgets"])
        self.assertEqual(4, constrained["replay_queue_capacity"])
        self.assertEqual(8, constrained["event_ring_capacity"])
        self.assertEqual(2, constrained["field_groups_per_batch"])
        self.assertEqual(128 * MIB, constrained["soft_memory_bytes"])
        self.assertEqual(256 * MIB, constrained["hard_memory_bytes"])
        self.assertEqual(16 * MIB, constrained["token_bytes"])

    def test_missing_smoke_budget_fails_closed(self) -> None:
        config = load_config()
        config["budgets"] = [{"name": "short", "kind": "seconds", "value": 30}]

        with self.assertRaisesRegex(ResourceProfileError, "smoke"):
            apply_resource_profile(config)

    def test_invalid_input_memory_policy_fails_closed(self) -> None:
        config = load_config()
        config["soft_memory_bytes"] = 256 * MIB
        config["hard_memory_bytes"] = 128 * MIB

        with self.assertRaisesRegex(ResourceProfileError, "soft_memory_bytes"):
            apply_resource_profile(config)

    def test_profile_memory_override_must_remain_ordered(self) -> None:
        with self.assertRaises(ResourceProfileError):
            replace(
                CONSERVATIVE_PROFILE,
                soft_memory_bytes=768 * MIB,
                hard_memory_bytes=512 * MIB,
            )


if __name__ == "__main__":
    unittest.main()
~~~

- [ ] Step 2: Run the new test to verify the red failure.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_resource_policy -v
~~~

Expected result: test discovery fails with ImportError or ModuleNotFoundError because the resource-policy module and exports do not exist yet. If the test passes, stop and correct the test before adding production code.

- [ ] Step 3: Implement the smallest profile transformer.

Create src/myfuzz/experiments/resource_policy.py with the following public shape and behavior:

~~~python
from __future__ import annotations

from collections.abc import Mapping, Sequence
import copy
from dataclasses import dataclass


_MIB = 1024 * 1024


class ResourceProfileError(ValueError):
    """Raised when a low-resource profile cannot be applied safely."""


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    name: str
    candidate_limit: int
    seed_limit: int
    budget_name: str
    build_concurrency: int
    waveforms: bool
    replay_queue_capacity: int
    event_ring_capacity: int
    field_groups_per_batch: int
    soft_memory_bytes: int
    hard_memory_bytes: int
    token_bytes: int

    def __post_init__(self) -> None:
        if not self.name:
            raise ResourceProfileError("profile name must not be empty")
        if not self.budget_name:
            raise ResourceProfileError("profile budget_name must not be empty")
        positive = (
            ("candidate_limit", self.candidate_limit),
            ("seed_limit", self.seed_limit),
            ("build_concurrency", self.build_concurrency),
            ("replay_queue_capacity", self.replay_queue_capacity),
            ("event_ring_capacity", self.event_ring_capacity),
            ("field_groups_per_batch", self.field_groups_per_batch),
            ("soft_memory_bytes", self.soft_memory_bytes),
            ("hard_memory_bytes", self.hard_memory_bytes),
            ("token_bytes", self.token_bytes),
        )
        for label, value in positive:
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ResourceProfileError(f"{label} must be a positive integer")
        if self.build_concurrency != 1:
            raise ResourceProfileError("low-resource build_concurrency must be 1")
        if self.waveforms is not False:
            raise ResourceProfileError("low-resource waveforms must be false")
        if self.soft_memory_bytes >= self.hard_memory_bytes:
            raise ResourceProfileError("soft_memory_bytes must be less than hard_memory_bytes")
        if self.token_bytes > self.soft_memory_bytes:
            raise ResourceProfileError("token_bytes must not exceed soft_memory_bytes")


CONSERVATIVE_PROFILE = ResourceProfile(
    name="conservative",
    candidate_limit=1,
    seed_limit=1,
    budget_name="smoke",
    build_concurrency=1,
    waveforms=False,
    replay_queue_capacity=32,
    event_ring_capacity=512,
    field_groups_per_batch=16,
    soft_memory_bytes=512 * _MIB,
    hard_memory_bytes=768 * _MIB,
    token_bytes=64 * _MIB,
)


def apply_resource_profile(
    config: Mapping[str, object],
    profile: ResourceProfile = CONSERVATIVE_PROFILE,
) -> dict[str, object]:
    """Return a detached planner config constrained by one resource profile."""
    if not isinstance(config, Mapping):
        raise ResourceProfileError("config must be an object")
    if not isinstance(profile, ResourceProfile):
        raise ResourceProfileError("profile must be a ResourceProfile")

    detached = copy.deepcopy(dict(config))
    selection = detached.get("candidate_selection")
    pair = detached.get("candidate_pair")
    budgets = detached.get("budgets")
    if not isinstance(selection, Mapping):
        raise ResourceProfileError("candidate_selection must be an object")
    if not isinstance(pair, Mapping):
        raise ResourceProfileError("candidate_pair must be an object")
    candidate_count = selection.get("k")
    if isinstance(candidate_count, bool) or not isinstance(candidate_count, int) or candidate_count <= 0:
        raise ResourceProfileError("candidate_selection.k must be a positive integer")
    seeds = pair.get("seeds")
    if not isinstance(seeds, Sequence) or isinstance(seeds, (str, bytes, bytearray)) or not seeds:
        raise ResourceProfileError("candidate_pair.seeds must be a non-empty array")
    normalized_seeds: list[int] = []
    for seed in seeds:
        if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
            raise ResourceProfileError("candidate_pair.seeds must contain non-negative integers")
        normalized_seeds.append(seed)
    if len(normalized_seeds) != len(set(normalized_seeds)):
        raise ResourceProfileError("candidate_pair.seeds must be unique")
    if not isinstance(budgets, Sequence) or isinstance(budgets, (str, bytes, bytearray)) or not budgets:
        raise ResourceProfileError("budgets must be a non-empty array")
    selected_budget: dict[str, object] | None = None
    names: set[str] = set()
    for item in budgets:
        if not isinstance(item, Mapping):
            raise ResourceProfileError("each budget must be an object")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ResourceProfileError("budget name must be a non-empty string")
        if name in names:
            raise ResourceProfileError("budget names must be unique")
        names.add(name)
        if name == profile.budget_name:
            selected_budget = copy.deepcopy(dict(item))
    if selected_budget is None:
        raise ResourceProfileError(f"required budget is missing: {profile.budget_name}")

    for item in (selected_budget,):
        kind = item.get("kind")
        value = item.get("value")
        if kind not in {"cycles", "seconds"}:
            raise ResourceProfileError("selected budget kind must be cycles or seconds")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ResourceProfileError("selected budget value must be a positive integer")

    def positive_int(label: str) -> int:
        value = detached.get(label)
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ResourceProfileError(f"{label} must be a positive integer")
        return value

    input_soft = positive_int("soft_memory_bytes")
    input_hard = positive_int("hard_memory_bytes")
    input_token = positive_int("token_bytes")
    input_build_concurrency = positive_int("build_concurrency")
    if not isinstance(detached.get("waveforms"), bool):
        raise ResourceProfileError("waveforms must be boolean")
    if input_soft >= input_hard:
        raise ResourceProfileError("soft_memory_bytes must be less than hard_memory_bytes")
    if input_token > input_soft:
        raise ResourceProfileError("token_bytes must not exceed soft_memory_bytes")

    output_selection = dict(selection)
    output_selection["k"] = min(candidate_count, profile.candidate_limit)
    output_pair = dict(pair)
    output_pair["seeds"] = sorted(normalized_seeds)[: profile.seed_limit]
    detached["candidate_selection"] = output_selection
    detached["candidate_pair"] = output_pair
    detached["budgets"] = [selected_budget]
    detached["build_concurrency"] = min(input_build_concurrency, profile.build_concurrency)
    detached["waveforms"] = profile.waveforms
    detached["replay_queue_capacity"] = min(
        positive_int("replay_queue_capacity"), profile.replay_queue_capacity
    )
    detached["event_ring_capacity"] = min(
        positive_int("event_ring_capacity"), profile.event_ring_capacity
    )
    detached["field_groups_per_batch"] = min(
        positive_int("field_groups_per_batch"), profile.field_groups_per_batch
    )
    output_soft = min(input_soft, profile.soft_memory_bytes)
    output_hard = min(input_hard, profile.hard_memory_bytes)
    if output_soft >= output_hard:
        raise ResourceProfileError("profile would make soft_memory_bytes invalid")
    detached["soft_memory_bytes"] = output_soft
    detached["hard_memory_bytes"] = output_hard
    detached["token_bytes"] = min(input_token, profile.token_bytes, output_soft)
    return detached
~~~

Modify src/myfuzz/experiments/__init__.py with:

~~~python
from .resource_policy import (
    CONSERVATIVE_PROFILE,
    ResourceProfile,
    ResourceProfileError,
    apply_resource_profile,
)
~~~

Add the same four names to __all__.

- [ ] Step 4: Run the unit tests to verify green.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.experiments.test_resource_policy -v
~~~

Expected result: all five tests pass with no warnings or errors.

- [ ] Step 5: Commit the isolated unit.

~~~bash
git diff --check
git add src/myfuzz/experiments/resource_policy.py src/myfuzz/experiments/__init__.py tests/experiments/test_resource_policy.py
git commit -m "feat: add conservative resource profile"
~~~

### Task 2: Add the real-adapter low-resource smoke function

**Files:**

- Create: tests/integration/test_low_resource_smoke.py
- Create: src/myfuzz/integration/low_resource_smoke.py
- Modify: src/myfuzz/integration/__init__.py

**Interfaces:**

- Produces run_low_resource_smoke(repo_root: Path, *, report_path: Path | None = None, profile: ResourceProfile = CONSERVATIVE_PROFILE) -> dict[str, object].
- Consumes existing run_candidate_pipeline, prepare_candidate_runtime, run_experiment_matrix, plan_experiment, protocol catalog loading, harness compiler, and memory-gate lease code.
- The deterministic smoke runner returns BuildJobResult for JobKind.BUILD and FuzzJobResult for JobKind.FUZZ.

- [ ] Step 1: Write the failing integration test.

Create tests/integration/test_low_resource_smoke.py:

~~~python
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.integration import run_low_resource_smoke


ROOT = Path(__file__).resolve().parents[2]


class LowResourceSmokeTests(unittest.TestCase):
    def test_smoke_uses_real_runtime_adapters_and_publishes_bounded_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report_path = Path(temporary) / "report.json"
            result = run_low_resource_smoke(ROOT, report_path=report_path)

            self.assertEqual("passed", result["status"])
            self.assertEqual("conservative", result["profile"])
            self.assertEqual(1, result["candidate_count"])
            self.assertEqual(1, result["build_jobs"])
            self.assertEqual(3, result["fuzz_jobs"])
            self.assertEqual(
                [{"protocol_id": "ready-valid-mmio", "version": "1"}],
                result["protocols"],
            )
            graph = result["dependency_graph"]
            self.assertGreater(graph["node_count"], 0)
            self.assertGreater(graph["edge_count"], 0)
            policy = result["runtime_policy"]
            self.assertEqual(1, policy["build_concurrency"])
            self.assertFalse(policy["waveforms"])
            self.assertEqual(32, policy["replay_queue_capacity"])
            self.assertEqual(512, policy["event_ring_capacity"])
            self.assertEqual(16, policy["field_groups_per_batch"])
            self.assertEqual(512 * 1024 * 1024, policy["soft_memory_bytes"])
            self.assertEqual(768 * 1024 * 1024, policy["hard_memory_bytes"])
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("experiment_report.v1", report["report"]["schema_version"])
            self.assertEqual([], report["execution"]["resource_terminated_job_ids"])


if __name__ == "__main__":
    unittest.main()
~~~

- [ ] Step 2: Run the integration test to verify the red failure.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_low_resource_smoke -v
~~~

Expected result: import failure because run_low_resource_smoke is not exported yet.

- [ ] Step 3: Implement the deterministic smoke orchestration.

Create src/myfuzz/integration/low_resource_smoke.py with these exact boundaries:

1. Validate repo_root and load these JSON documents:

~~~python
pipeline_config = repo_root / "configs" / "experiments" / "synthetic_opaque.json"
planner_config_path = repo_root / "configs" / "experiments" / "ibex_opentitan.json"
facts_path = repo_root / "tests" / "fixtures" / "runtime" / "hdl_facts.v2.runtime.json"
composition_path = repo_root / "tests" / "fixtures" / "runtime" / "composition_ir.v1.runtime.json"
candidate_path = repo_root / "tests" / "fixtures" / "runtime" / "candidate_manifest.v1.runtime.json"
~~~

Use apply_resource_profile on the planner document. Pass the three runtime fixture documents to prepare_candidate_runtime from the runtime_preparer callback. Pass the runtime candidate fixture through run_candidate_pipeline using top_k=1, dry_run=True, and a temporary memory_tokens.json path.

2. Use a context manager that sets MYFUZZ_MEMORY_GATE_DIR to a directory below the temporary smoke workspace and restores the previous value in finally, including the case where it was originally absent.

3. Implement the in-process runner with one sample per fuzz job and no imports or calls to subprocess, multiprocessing, Verilator, or RFuzz execution. The sample must contain these fields:

~~~python
{
    "job_id": job.job_id,
    "candidate_id": job.candidate_id,
    "harness": job.harness,
    "seed": job.seed,
    "elapsed_seconds": 0,
    "sequence": 0,
    "common_total": 0,
    "covered_point_ids": [],
    "tests_executed": 0,
    "cycles_executed": 0,
    "peak_rss_bytes": job.estimated_rss_bytes,
    "projection_count": 0,
    "correction_counts": {},
    "protocol_event_count": 0,
    "no_progress_cycles": 0,
    "generation_count": 0,
    "validation_passed": 0,
    "failure_reasons": {"dut_crash": 0, "resource_terminated": 0},
}
~~~

Return BuildJobResult(job.job_id, 1) for build jobs and FuzzJobResult(job.job_id, 1, (sample,), job.estimated_rss_bytes) for fuzz jobs. Record jobs in a list for the final summary.

4. After the pipeline returns, call plan_experiment(profiled_config, manifests) once to expose the effective runtime policy. Then call run_experiment_matrix with:

~~~python
{
    "planner_config": profiled_config,
    "candidate_manifests": manifests,
    "execution": {
        "interleaving_seed": 0,
        "max_resource_retries": 0,
        "job_timeout_seconds": 0,
    },
}
~~~

Use a temporary report path when report_path is None; create the parent of an explicitly supplied report path and pass that path unchanged to the existing atomic publisher.

5. Return a detached summary with these keys:

~~~python
{
    "status": "passed",
    "profile": profile.name,
    "candidate_count": pipeline_result["candidate_count"],
    "build_jobs": build_count,
    "fuzz_jobs": fuzz_count,
    "protocols": manifest["protocols"],
    "dependency_graph": manifest["dependency_graph"],
    "runtime_policy": {
        "build_concurrency": plan.runtime_policy.build_concurrency,
        "waveforms": plan.runtime_policy.waveforms,
        "replay_queue_capacity": plan.runtime_policy.replay_queue_capacity,
        "event_ring_capacity": plan.runtime_policy.event_ring_capacity,
        "field_groups_per_batch": plan.runtime_policy.field_groups_per_batch,
        "soft_memory_bytes": plan.runtime_policy.soft_memory_bytes,
        "hard_memory_bytes": plan.runtime_policy.hard_memory_bytes,
        "token_bytes": plan.runtime_policy.token_bytes,
    },
    "report_path": None if report_path is None else str(report_path.absolute()),
    "report": matrix_result["report"],
}
~~~

The temporary workspace must be cleaned before return. The report object is returned in memory when no persistent path is supplied.

- [ ] Step 4: Export the smoke function.

Modify src/myfuzz/integration/__init__.py:

~~~python
from .low_resource_smoke import run_low_resource_smoke
~~~

Add run_low_resource_smoke to __all__.

- [ ] Step 5: Run the new integration test to verify green.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_low_resource_smoke -v
~~~

Expected result: one test passes in a few seconds, with no Verilator/RFuzz child process and no repository output files.

- [ ] Step 6: Commit the smoke unit.

~~~bash
git diff --check
git add src/myfuzz/integration/low_resource_smoke.py src/myfuzz/integration/__init__.py tests/integration/test_low_resource_smoke.py
git commit -m "feat: add low-resource integration smoke"
~~~

### Task 3: Add the CLI and running documentation

**Files:**

- Create: tests/integration/test_low_resource_smoke_cli.py
- Create: scripts/run_low_resource_smoke.py
- Create: docs/low-resource-running.md

**Interfaces:**

- CLI entry point: python3 scripts/run_low_resource_smoke.py [--report PATH] [--soft-memory-mib N] [--hard-memory-mib N].
- CLI calls run_low_resource_smoke exactly once and never starts a simulator.
- Documentation must state that the command is a synthetic smoke, not a production RTL result.

- [ ] Step 1: Write the failing CLI test.

Create tests/integration/test_low_resource_smoke_cli.py:

~~~python
from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "run_low_resource_smoke.py"


class LowResourceSmokeCliTests(unittest.TestCase):
    def test_cli_publishes_report_and_prints_effective_profile(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONPATH"] = str(ROOT / "src")
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "cli-report.json"
            completed = subprocess.run(
                [sys.executable, str(SCRIPT), "--report", str(report)],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertIn("profile=conservative", completed.stdout)
            self.assertIn("build_jobs=1", completed.stdout)
            self.assertIn("fuzz_jobs=3", completed.stdout)
            document = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual("experiment_report.v1", document["report"]["schema_version"])


if __name__ == "__main__":
    unittest.main()
~~~

- [ ] Step 2: Run the CLI test to verify the red failure.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_low_resource_smoke_cli -v
~~~

Expected result: the script path/import fails because the CLI file does not exist yet.

- [ ] Step 3: Implement the thin CLI.

Create scripts/run_low_resource_smoke.py with this behavior:

~~~python
from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.experiments import CONSERVATIVE_PROFILE
from myfuzz.integration import run_low_resource_smoke


_MIB = 1024 * 1024


def _positive_mib(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("memory size must be positive")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the bounded MyFuzz low-resource smoke")
    parser.add_argument("--report", type=Path, help="optional persistent report path")
    parser.add_argument("--soft-memory-mib", type=_positive_mib)
    parser.add_argument("--hard-memory-mib", type=_positive_mib)
    args = parser.parse_args(argv)

    profile = CONSERVATIVE_PROFILE
    if args.soft_memory_mib is not None or args.hard_memory_mib is not None:
        profile = replace(
            profile,
            soft_memory_bytes=(
                profile.soft_memory_bytes
                if args.soft_memory_mib is None
                else args.soft_memory_mib * _MIB
            ),
            hard_memory_bytes=(
                profile.hard_memory_bytes
                if args.hard_memory_mib is None
                else args.hard_memory_mib * _MIB
            ),
        )

    result = run_low_resource_smoke(ROOT, report_path=args.report, profile=profile)
    policy = result["runtime_policy"]
    print(f"status={result['status']}")
    print(f"profile={result['profile']}")
    print(f"candidate_count={result['candidate_count']}")
    print(f"build_jobs={result['build_jobs']}")
    print(f"fuzz_jobs={result['fuzz_jobs']}")
    print(
        "memory_policy="
        f"{policy['soft_memory_bytes']}/{policy['hard_memory_bytes']} bytes, "
        f"token={policy['token_bytes']}"
    )
    if result["report_path"] is not None:
        print(f"report={result['report_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
~~~

- [ ] Step 4: Run the CLI test to verify green.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_low_resource_smoke_cli -v
~~~

Expected result: one CLI test passes and the temporary report has schema experiment_report.v1.

- [ ] Step 5: Write the user documentation.

Create docs/low-resource-running.md with:

~~~~markdown
# Low-resource smoke run

Run from the repository root:

~~~bash
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_low_resource_smoke.py
~~~

The command is opt-in and uses temporary output. To retain the report:

~~~bash
python3 scripts/run_low_resource_smoke.py --report /tmp/myfuzz-low-resource/report.json
~~~

The conservative profile selects one candidate, the first sorted seed, and the
declared smoke budget. It forces one build slot, disables waveforms, bounds
the replay/event/field queues to 32/512/16, and caps the planner memory policy
at 512 MiB soft, 768 MiB hard, and 64 MiB per token. Already smaller input
limits remain unchanged. Optional --soft-memory-mib and --hard-memory-mib
values must remain positive and ordered.

The smoke invokes the existing protocol catalog, harness compiler, dependency
graph, candidate-pipeline join, memory gate, and report publisher. Its matrix
runner is deterministic and in-process, so it does not launch Verilator, RFuzz,
or a long fuzz campaign. A successful smoke proves the integration contracts
are wired together; it is not evidence of RTL functional correctness or
production-scale performance.

Normal experiment callers and checked-in configurations are unchanged. Real
experiments continue to use their existing shared memory-gate policy.
~~~~

- [ ] Step 6: Run the command manually with a temporary report.

Run:

~~~bash
temporary_report="$(mktemp -u /tmp/myfuzz-low-resource-report.XXXXXX.json)"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/run_low_resource_smoke.py --report "$temporary_report"
test -s "$temporary_report"
~~~

Expected result: output includes status=passed, profile=conservative, build_jobs=1, and fuzz_jobs=3; the report file is non-empty. Remove only this explicitly created temporary file after inspection if desired.

- [ ] Step 7: Commit the CLI and documentation.

~~~bash
git diff --check
git add scripts/run_low_resource_smoke.py tests/integration/test_low_resource_smoke_cli.py docs/low-resource-running.md
git commit -m "feat: expose low-resource smoke command"
~~~

### Task 4: Run focused regression verification and review the branch

**Files:**

- Test: tests/experiments/test_resource_policy.py
- Test: tests/integration/test_low_resource_smoke.py
- Test: tests/integration/test_low_resource_smoke_cli.py
- Regression: tests/protocols/test_protocol_catalog.py
- Regression: tests/integration/test_pipeline.py
- Regression: tests/integration/test_experiment_matrix.py

- [ ] Step 1: Run all new and relevant existing tests together.

Run:

~~~bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest \
  tests.experiments.test_resource_policy \
  tests.integration.test_low_resource_smoke \
  tests.integration.test_low_resource_smoke_cli \
  tests.protocols.test_protocol_catalog \
  tests.integration.test_pipeline \
  tests.integration.test_experiment_matrix -v
~~~

Expected result: all tests pass; no full HDL build is started.

- [ ] Step 2: Verify the default configuration files were not changed.

Run:

~~~bash
git diff main -- configs/experiments/rvx.json configs/experiments/ibex_opentitan.json configs/experiments/synthetic_opaque.json
~~~

Expected result: no output.

- [ ] Step 3: Check the branch for accidental artifacts and whitespace errors.

Run:

~~~bash
git diff --check
git status --short --branch
~~~

Expected result: only the intentional implementation commits are present; no __pycache__, report, gate, or temporary files are tracked.

- [ ] Step 4: Review the final diff against the design.

Confirm this data flow:

~~~text
resource policy -> detached planner config -> real candidate/runtime join
                 -> protocol/harness/dependency metadata
                 -> sequential memory-gated matrix -> experiment_report.v1
~~~

The final handoff must report the exact test command and observed pass count, the smoke command result, the worktree/branch, and the fact that normal defaults were not modified.
