# Deterministic Single DUT Wrapper Renderer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render a deterministic SystemVerilog wrapper for any one complete local harness plan, exposing every real protocol/environment/observation bit through a versioned ABI while preserving DUT parameters and source identity.

**Architecture:** The renderer is pure: it consumes `LocalHarnessPlan`, groups already validated dispositions by physical port, creates one backing vector per DUT port, and connects exactly one real DUT instance. Clock/reset and constants are explicit assignments; every other segment becomes a wrapper I/O with its physical span in an ABI document. A separate later plan supplies protocol-specific local C++ command drivers and Python sessions; structural lint does not claim runnable harness status.

**Tech Stack:** Python 3.12, SystemVerilog, Verilator 5.051, existing full-port disposition ledger and unittest.

## Global Constraints

- Render exactly one component top instance, with no Bus, Crossbar, Bridge, Arbiter, PLIC or SoC fabric.
- Every physical DUT port appears exactly once in the instance connection list; every input bit has exactly one declared driver and every output bit has an observation or explicit declared disposition.
- Preserve raw packed bit order. The ABI names each wrapper signal's source port, physical bit span, endpoint, role, width and direction; values wider than 64 bits are never truncated.
- Clock/reset polarity and module parameter values come from the bound profile and request; defines/include roots/ordered RTL sources remain in the build document.
- Inputs bound to protocol/environment remain wrapper inputs; the renderer does not choose random values or fabricate DUT results.
- An input marked unconnected, unsupported inout, invalid identifier, gap/overlap, or selected-only top must fail closed.
- Existing SoC renderer, legacy sessions and `scenario_host_sources.v1` are untouched.
- This milestone proves deterministic structural wrapper generation and real RTL lint only; no C++ driver/session exists, so the feature's **Generated** and runtime levels remain unproven.

---

## File Structure

- Create `src/myfuzz/local_harness/port_rendering.py`: deterministic physical-port and segment renderer.
- Create `src/myfuzz/local_harness/renderer.py`: wrapper, ABI and source/build manifest result.
- Modify `src/myfuzz/local_harness/__init__.py`: public render API.
- Create `tests/local_harness/test_renderer.py`: CVE2/PULP byte determinism, wide/aggregate coverage, deliberate invalid plan refusal and real lint.
- Create `docs/reports/generated-local-wrapper-20261004.md`: actual hashes, lint commands and evidence limits.

### Task 1: Render full physical ports and a flat ABI

**Files:**
- Create: `src/myfuzz/local_harness/port_rendering.py`
- Create: `tests/local_harness/test_renderer.py`

**Interfaces:**
- Consumes: `LocalHarnessPlan.dispositions`, `PhysicalFacts.ports`, `profile.clocks`, `profile.resets`.
- Produces: `render_port_connections(plan: LocalHarnessPlan) -> tuple[list[str], list[str], list[str], list[dict[str, object]]]`; the four values are wrapper port declarations, local declarations/assignments, DUT instance connections and ABI rows.

- [ ] **Step 1: Write structural tests against actual profiles**

```python
from pathlib import Path
import unittest
from myfuzz.local_harness import load_local_harness_request, plan_local_harness
from myfuzz.local_harness.port_rendering import render_port_connections

ROOT = Path(__file__).resolve().parents[2]

def real_plan(profile, instance):
    request = load_local_harness_request({
        "schema_version": "local_harness.v1",
        "profile_path": profile, "instance_id": instance,
        "reset_assert_ticks": 8, "reset_release_ticks": 8,
        "max_wait_cycles": 16,
    })
    return plan_local_harness(request, base_dir=ROOT)

class LocalPortRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cpu = real_plan("configs/cpus/cv32e20/component_profile.json", "cpu_0")
        cls.gpio = real_plan("configs/peripherals/pulp_gpio/component_profile.json", "gpio_a")

    def test_every_physical_port_has_one_connection_and_raw_abi_span(self):
        for plan in (self.cpu, self.gpio):
            declarations, assignments, connections, abi = render_port_connections(plan)
            self.assertEqual(len(connections), len(plan.facts.ports))
            self.assertEqual({row["physical_port"] for row in abi},
                             {entry.port for entry in plan.dispositions
                              if entry.disposition not in ("constant", "unconnected")
                              and entry.role not in ("clock", "reset")})
            self.assertTrue(declarations)
            self.assertTrue(assignments)
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_renderer -q`. Expected before implementation: import failure.

- [ ] **Step 2: Implement bit-preserving connection rendering**

Group with `port_segments(plan.dispositions)`. For each physical port in sorted name order, create internal `logic [W-1:0] dut_p_<index>;` and one connection `.<physical_port>(dut_p_<index>)`. For each disposition segment:

- `clock`: assign the backing bit to `clk`;
- `reset`: assign it to `reset` or `~reset` from its profile polarity;
- `constant`: assign exact segment width with `constant_expression(entry)`;
- `functional/external/fuzz/peer` input: declare `input logic [segment_width-1:0] lh_p_<index>_<high>_<low>`, assign it to the matching backing slice;
- `functional/external/observe/peer` output: declare an output of the same width and assign it from the backing slice;
- declared `unconnected` output: connect only to the backing vector, record disposition but do not export;
- any other case: raise `LocalPortRenderError`.

Use `[high:low]` even for width-one backing slices and preserve descending raw order; never concatenate aggregate fields by guessed type order. Emit one ABI row per exposed segment, sorted by physical port and descending high bit: `wrapper_name`, `physical_port`, `bit_lo`, `bit_hi`, `width`, `direction`, `disposition`, `endpoint_id`, `role`. Avoid component-name conditions. Require every name in the plan to be a legal unescaped SV identifier before rendering; the first version explicitly refuses an escaped name and records this limit.

- [ ] **Step 3: Add hard refusal for unsupported directions and rerun**

```python
from dataclasses import replace
from myfuzz.local_harness.port_rendering import LocalPortRenderError

    def test_rejects_illegal_unconnected_input(self):
        entry = next(item for item in self.gpio.dispositions if item.direction == "input")
        changed = tuple(replace(item, disposition="unconnected", target=None)
                        if item is entry else item for item in self.gpio.dispositions)
        with self.assertRaises(LocalPortRenderError):
            render_port_connections(replace(self.gpio, dispositions=changed))
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_renderer -q`. Expected: all structural cases pass.

### Task 2: Pure wrapper/ABI/build renderer and real lint

**Files:**
- Create: `src/myfuzz/local_harness/renderer.py`
- Modify: `src/myfuzz/local_harness/__init__.py`
- Modify: `tests/local_harness/test_renderer.py`
- Create: `docs/reports/generated-local-wrapper-20261004.md`

**Interfaces:**
- Consumes: Task 1 `render_port_connections(plan)`.
- Produces: `RenderedLocalHarness` frozen dataclass with `module_name: str`, `wrapper_sv: str`, `abi_document: dict[str, object]`, `build_document: dict[str, object]`; `render_local_harness(plan: LocalHarnessPlan) -> RenderedLocalHarness`.

- [ ] **Step 1: Add deterministic render and real lint tests**

```python
import shutil
import subprocess
from tempfile import TemporaryDirectory
from myfuzz.local_harness import render_local_harness

    def test_repeat_render_is_byte_identical_and_single_dut(self):
        for plan in (self.cpu, self.gpio):
            first = render_local_harness(plan)
            second = render_local_harness(plan)
            self.assertEqual(first.wrapper_sv, second.wrapper_sv)
            self.assertEqual(first.abi_document, second.abi_document)
            self.assertEqual(first.build_document, second.build_document)
            self.assertEqual(first.wrapper_sv.count(" u_dut ("), 1)
            self.assertEqual(first.wrapper_sv.count("module " + first.module_name), 1)

    @unittest.skipUnless(shutil.which("verilator"), "Verilator is required")
    def test_real_cve2_and_pulp_wrapper_lint(self):
        for plan in (self.cpu, self.gpio):
            rendered = render_local_harness(plan)
            with TemporaryDirectory() as directory:
                wrapper = Path(directory) / (rendered.module_name + ".sv")
                wrapper.write_text(rendered.wrapper_sv)
                command = list(rendered.build_document["lint_argv"]) + [str(wrapper)]
                result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                        text=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr[-6000:])
                self.assertNotIn("%Error", result.stderr + result.stdout)
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_renderer -q`. Expected before implementation: import failure for `render_local_harness`.

- [ ] **Step 2: Implement pure rendering and complete build identity**

Generate `module local_<instance_id> (input logic clk, reset, ...);` followed by Task 1 declarations/assignments and exactly one `<profile.source.top_module> #(.PARAM(value),...) u_dut (...)`. Render parameter overrides in sorted name order from the profile's elaboration settings; do not silently use default values. End with `endmodule`. Source text is UTF-8 with LF line endings and a final newline. The `abi_document` contains schema `local_harness_abi.v1`, plan hash, module name and Task 1 ABI rows. The `build_document` contains schema `local_harness_build.v1`, profile hash, source revision/content hash, ordered source files, include roots, defines, parameter overrides, wrapper SHA-256 and a workspace-relative `verilator --lint-only -Wno-fatal --top-module <module> ...` argv. It declares `status="structural_only"`, with no driver/session claim.

For a top whose parameter is an SV enum, emit the numeric profile value exactly and let real lint decide whether that declared setting is legal. If the CVE2 `RV32M=2` instance parameter needs a package cast, derive that cast from the elaborated parameter type/source evidence as an explicit template rule; do not omit the parameter or relax the source/profile mismatch. The build document's source list must preserve profile ordering and include every file required by lint.

- [ ] **Step 3: Run full focused suite and record actual results**

```bash
PYTHONPATH=src:. python3 -m unittest tests.local_harness.test_request tests.local_harness.test_plan tests.local_harness.test_renderer -q
git diff --check
```

Expected: parser/planner/renderer tests pass; real CVE2 and PULP wrappers compile in lint mode. The report records wrapper/ABI/build SHA-256, port/bit counts, actual lint warnings, exact source pins and the remaining C++/session work. Do not call the rendered wrapper a runnable harness.

- [ ] **Step 4: Commit renderer and evidence**

```bash
git add src/myfuzz/local_harness/port_rendering.py src/myfuzz/local_harness/renderer.py src/myfuzz/local_harness/__init__.py tests/local_harness/test_renderer.py docs/reports/generated-local-wrapper-20261004.md
git commit -m "feat: render one source-backed local DUT wrapper"
```

Expected: only renderer source/tests/report change.
