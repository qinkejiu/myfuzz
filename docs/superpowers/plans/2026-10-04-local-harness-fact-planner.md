# Single Component Local Harness Fact Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Accept one declarative local harness request and produce a deterministic, complete single-component port/ownership plan from pinned RTL facts.

**Architecture:** A strict request parser handles only local timing and source profile selection. The planner calls existing source elaboration, binding and full-bit disposition validation, then converts their SoC-named disposition destinations into local harness destinations in a new versioned plan document. No wrapper, C++ driver, session or SoC fabric is rendered by this milestone; that is the next plan.

**Tech Stack:** Python 3.12 standard library, existing `component_profile.v1` and Verilator JSON frontend, unittest.

## Global Constraints

- One request selects exactly one CPU or IP profile; multiple independent requests may later be combined by ScenarioRunner, never by a Bus/Crossbar/Bridge top.
- `PhysicalFacts.selection` must be `all`; unknown, overlapping or unclassified input/output bits fail closed.
- Source revision, ordered closure, physical directions, widths and aggregate-member bit spans come from the pinned RTL and existing profile tools, never from port-name guesses.
- A DUT input bound to a real upstream output must later be owned by that binding, while unbound environment inputs remain Fuzzable Source candidates; this planner exports the input classification without independently randomizing any value.
- An unexpected output is observed and reported; the planner cannot manufacture CPU/IP DONE, IRQ or read data.
- Keep existing `scenario_host_sources.v1` fixed list and old sessions/evidence unchanged. The new plan document is a separate identity input.
- This milestone proves the fact-bound planning stage, **not** Generated, RTL operational or Cross-component accepted status.

---

**完成证据（2026-10-04）：** 请求解析器提交 `4632640`，事实规划器提交 `e51d30e`，两项均经独立审查。主工作树补齐 profile 文件哈希和实际协议 endpoint 列表后，`PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_plan -q` 重跑 14/14 通过。CVE2 与 PULP GPIO 的完整顶层端口分别为 70/17，Ibex 的局部端口选择按设计被拒绝。本阶段仅是事实计划，尚无生成 RTL 或真实运行。

## File Structure

- Create `src/myfuzz/local_harness/__init__.py`: public parser/planner exports.
- Create `src/myfuzz/local_harness/request.py`: strict `local_harness.v1` data model and canonical serialization.
- Create `src/myfuzz/local_harness/plan.py`: one-profile elaboration, full disposition proof and local target mapping.
- Create `tests/local_harness/test_request.py`: parser/path/timing rejection.
- Create `tests/local_harness/test_plan.py`: CVE2/PULP GPIO real source facts, deterministic plan and fail-closed mutation cases.
- Create `docs/reports/generated-harness-fact-planner-20261004.md`: actual statuses and limitations.

### Task 1: Strict local request

**Files:**
- Create: `src/myfuzz/local_harness/request.py`
- Create: `tests/local_harness/test_request.py`
- Create: `src/myfuzz/local_harness/__init__.py`

**Interfaces:**
- Produces: `LocalHarnessRequest` frozen dataclass with fields `profile_path: str`, `instance_id: str`, `reset_assert_ticks: int`, `reset_release_ticks: int`, `max_wait_cycles: int`; `load_local_harness_request(document: Mapping[str, object]) -> LocalHarnessRequest`; `request.document() -> dict[str, object]`.
- Consumes: `local_harness.v1` object with exactly the schema and five fields above.

- [x] **Step 1: Write parser tests**

```python
import unittest
from myfuzz.local_harness.request import load_local_harness_request

GOOD = {
    "schema_version": "local_harness.v1",
    "profile_path": "configs/peripherals/pulp_gpio/component_profile.json",
    "instance_id": "gpio_a",
    "reset_assert_ticks": 8,
    "reset_release_ticks": 8,
    "max_wait_cycles": 16,
}

class LocalHarnessRequestTests(unittest.TestCase):
    def test_round_trip_is_canonical(self):
        self.assertEqual(load_local_harness_request(GOOD).document(), GOOD)

    def test_reject_unknown_field_and_escaped_path(self):
        with self.assertRaisesRegex(ValueError, "unexpected-request-fields"):
            load_local_harness_request({**GOOD, "raw_sv": "assign irq=1;"})
        with self.assertRaisesRegex(ValueError, "invalid-profile-path"):
            load_local_harness_request({**GOOD, "profile_path": "../outside.json"})

    def test_reject_bool_and_unbounded_wait(self):
        with self.assertRaisesRegex(ValueError, "invalid-reset-assert-ticks"):
            load_local_harness_request({**GOOD, "reset_assert_ticks": True})
        with self.assertRaisesRegex(ValueError, "invalid-max-wait-cycles"):
            load_local_harness_request({**GOOD, "max_wait_cycles": 0})
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request -q`. Expected before implementation: import failure.

- [x] **Step 2: Implement parser with exact validation**

Use a frozen dataclass and reject extra/missing keys. `profile_path` must be a relative `configs/.../component_profile.json` path with no empty, `.` or `..` segment and no backslash; `instance_id` must match `[A-Za-z][A-Za-z0-9_]*`. Require `reset_assert_ticks` in 1–1024, `reset_release_ticks` in 0–1024, `max_wait_cycles` in 1–1024, and reject bools. `document()` returns exactly `GOOD`'s six keys, sorted through the caller's canonical JSON layer.

- [x] **Step 3: Run focused tests and commit**

```bash
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request -q
git diff --check
git add src/myfuzz/local_harness/__init__.py src/myfuzz/local_harness/request.py tests/local_harness/test_request.py
git commit -m "feat: parse declarative local harness requests"
```

Expected: parser tests pass; only the listed files enter the commit.

### Task 2: Full source fact plan with local destinations

**Files:**
- Create: `src/myfuzz/local_harness/plan.py`
- Create: `tests/local_harness/test_plan.py`
- Modify: `src/myfuzz/local_harness/__init__.py`
- Create: `docs/reports/generated-harness-fact-planner-20261004.md`

**Interfaces:**
- Consumes: `LocalHarnessRequest`, `load_component_profile`, `elaborate_profile`, `bind_profile`, `build_port_dispositions`.
- Produces: `plan_local_harness(request: LocalHarnessRequest, *, base_dir: Path) -> LocalHarnessPlan`, with `document() -> dict[str, object]` and immutable `profile`, `facts`, `binding`, `dispositions` references. Plan schema `local_harness_plan.v1`.

- [x] **Step 1: Write real fact and deterministic plan tests**

```python
from pathlib import Path
import unittest
from myfuzz.local_harness import load_local_harness_request, plan_local_harness

ROOT = Path(__file__).resolve().parents[2]

def request(path, instance):
    return load_local_harness_request({
        "schema_version": "local_harness.v1",
        "profile_path": path, "instance_id": instance,
        "reset_assert_ticks": 8, "reset_release_ticks": 8,
        "max_wait_cycles": 16,
    })

class LocalHarnessPlanTests(unittest.TestCase):
    def test_cve2_plan_is_full_and_deterministic(self):
        item = request("configs/cpus/cv32e20/component_profile.json", "cpu_0")
        first = plan_local_harness(item, base_dir=ROOT)
        second = plan_local_harness(item, base_dir=ROOT)
        self.assertEqual(first.document(), second.document())
        self.assertEqual(first.facts.selection, "all")
        self.assertEqual(first.profile.component_id, "cv32e20")
        self.assertEqual(first.document()["scope"], "single_component")
        targets = {row["target"] for row in first.document()["ports"]}
        self.assertTrue(targets.isdisjoint(
            {"fabric_target", "processor_adapter", "interrupt_controller",
             "clock_reset", "soc_top"}))

    def test_pulp_gpio_plan_exposes_environment_pin(self):
        item = request(
            "configs/peripherals/pulp_gpio/component_profile.json", "gpio_a")
        plan = plan_local_harness(item, base_dir=ROOT)
        self.assertEqual(plan.facts.selection, "all")
        self.assertEqual(plan.binding.field("gpio.pins", "in").port, "gpio_in")
        self.assertTrue(any(row["target"] == "environment_pin"
                            for row in plan.document()["ports"]))
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_plan -q`. Expected before implementation: import failure.

- [x] **Step 2: Implement the planner's fail-closed path**

Resolve `profile_path` beneath `base_dir/configs` and reject symlink escapes; load profile, elaborate its pinned source, reject `facts.selection != "all"`, bind protocol roles, and call `build_port_dispositions` with the request instance/domain and `profile.port_actions`. Copy each disposition document to the plan, mapping `clock_reset→local_clock_reset`, `processor_adapter/fabric_target→local_protocol`, `interrupt_controller→local_interrupt`, `soc_top` with `external/fuzz→environment_pin` or `observe→observation`, `const→constant`, `peer:<id>→local_peer:<id>`, and a declared unconnected output to `null`; reject any other target. Preserve endpoint ID, role, bit span, direction, evidence and reason. The plan document contains schema, scope, component ID, instance ID, profile path, source revision/content hash, top, request timing, protocol endpoint IDs, and all port records sorted by port/bit. It must contain no generated RTL and no claimed runtime status.

- [x] **Step 3: Add negative planner tests**

```python
    def test_rejects_profile_path_outside_configs(self):
        item = request("configs/peripherals/pulp_gpio/component_profile.json", "gpio_a")
        bad_root = ROOT / "tests"
        with self.assertRaises((ValueError, FileNotFoundError)):
            plan_local_harness(item, base_dir=bad_root)

    def test_rejects_declared_only_ibex_top(self):
        item = request("configs/cpus/ibex/component_profile.json", "cpu_0")
        with self.assertRaisesRegex(ValueError, "full-top-required"):
            plan_local_harness(item, base_dir=ROOT)
```

The old Ibex profile deliberately uses selected-only top facts; refusal is the correct result for this new Generated path. Execute the focused tests again and require every positive/negative case to pass.

- [x] **Step 4: Record evidence and commit**

Write the report with the actual plan port counts and hashes for CVE2 and PULP GPIO, exact test command/result, selected-only Ibex rejection, and explicit statement that this is a fact-bound plan only. Then:

```bash
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_plan -q
git diff --check
git add src/myfuzz/local_harness/__init__.py src/myfuzz/local_harness/plan.py tests/local_harness/test_plan.py docs/reports/generated-harness-fact-planner-20261004.md
git commit -m "feat: plan one pinned local RTL harness"
```

Expected: the two local_harness suites pass and only the listed files enter the commit.
