# Ibex + OpenTitan Real-IP Target Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and smoke-test a coverage target in which upstream Ibex accesses the real OpenTitan UART, GPIO, and RV timer, then compare baseline and dependency-aware RFuzz harnesses over one identical coverage universe.

**Architecture:** A deterministic RV32I MMIO exerciser runs on Ibex. Instruction and RAM data accesses terminate locally; peripheral accesses cross a bounded OBI-to-TL-UL bridge and address router into the three official OpenTitan IP tops. Two 512-bit manual harnesses wrap the exact same instrumented system top and differ only in raw-input projection.

**Tech Stack:** Python 3.12, SystemVerilog, pinned OpenTitan and Ibex git submodules, Verilator 5.020, MyFuzz instrumentation, original RFuzz/KFuzz compatibility server, `unittest`.

## Global Constraints

- OpenTitan revision is exactly `13a8919bceac625dbd1b6ad804e62f9bdeadee86`.
- Instantiate official `uart`, `gpio`, and `rv_timer` tops with their official generated register, `prim`, and `tlul` dependencies.
- Never include `ibex_mcip_uart`, `ibex_mcip_gpio`, or `ibex_mcip_timer` in the real-IP source list or hierarchy.
- Local behavioral RTL is limited to memory, OBI-to-TL-UL adaptation, routing, reset/clock plumbing, and harness logic.
- Baseline and dependency-aware variants share source revision, system top, raw width 512, instrumentation identity, campaign seeds, firmware, and runtime limits.
- Heavy Verilator builds use `-j 1`; campaigns run sequentially if available memory would fall below the runner's configured reserve.
- A failed build, server smoke, or mismatched coverage universe is not a valid comparison.

## File Map

- `configs/designs/ibex_opentitan_real_ip/scripts/prepare_sources.py`: validate the pinned submodules and emit a deterministic official-IP source closure.
- `configs/designs/ibex_opentitan_real_ip/rtl/sources.f`: stable outer file list consumed by instrumentation and Verilator.
- `configs/designs/ibex_opentitan_real_ip/rtl/opentitan_sources.f`: generated, repository-relative OpenTitan dependency closure.
- `configs/designs/ibex_opentitan_real_ip/rtl/ibex_ot_obi_to_tlul.sv`: one-outstanding OBI-to-TL-UL bridge.
- `configs/designs/ibex_opentitan_real_ip/rtl/ibex_ot_tlul_router.sv`: one-to-three request/response router.
- `configs/designs/ibex_opentitan_real_ip/rtl/ibex_ot_ram.sv`: instruction/data RAM with exerciser preload.
- `configs/designs/ibex_opentitan_real_ip/rtl/ibex_opentitan_real_ip_top.sv`: shared system top containing Ibex and the official IP instances.
- `configs/designs/ibex_opentitan_real_ip/programs/*`: RV32I MMIO exerciser source, linker script, build helper, and generated hex.
- `configs/designs/ibex_opentitan_real_ip/harness/*`: baseline and dependency-aware 512-bit manual harnesses.
- `configs/designs/ibex_opentitan_real_ip/{baseline_direct_slice,depaware_projection}/config.json`: MyFuzz configurations sharing one top and file list.
- `scripts/runs/run_ibex_opentitan_real_ip_pilot.py`: build artifact checks, sequential campaigns, and comparison report.
- `tests/test_ibex_opentitan_real_ip_target.py`: provenance, topology, parity, and no-proxy tests.

---

### Task 1: Pin and Resolve the Official OpenTitan Source Closure

**Files:**
- Create: `configs/designs/ibex_opentitan_real_ip/scripts/prepare_sources.py`
- Create: `configs/designs/ibex_opentitan_real_ip/rtl/sources.f`
- Generate: `configs/designs/ibex_opentitan_real_ip/rtl/opentitan_sources.f`
- Create: `tests/test_ibex_opentitan_real_ip_target.py`

**Interfaces:**
- Consumes: repository root and the pinned OpenTitan/Ibex submodule paths.
- Produces: `prepare_sources(repo_root: Path) -> tuple[Path, ...]` and a deterministic `opentitan_sources.f` suitable for `verilator -f`.

- [ ] **Step 1: Write failing provenance and source-closure tests**

```python
EXPECTED_OT = "13a8919bceac625dbd1b6ad804e62f9bdeadee86"

def test_real_target_uses_pinned_official_ip_sources(self):
    sources = (TARGET / "rtl/opentitan_sources.f").read_text()
    for path in (
        "external_designs/opentitan/hw/ip/uart/rtl/uart.sv",
        "external_designs/opentitan/hw/ip/gpio/rtl/gpio.sv",
        "external_designs/opentitan/hw/ip/rv_timer/rtl/rv_timer.sv",
    ):
        self.assertIn(path, sources)
    self.assertIn("/hw/ip/prim/", sources)
    self.assertIn("/hw/ip/tlul/", sources)
    self.assertNotIn("ibex_mcip_", sources)

def test_prepare_sources_rejects_wrong_revision(self):
    with self.assertRaisesRegex(RuntimeError, "OpenTitan revision"):
        prepare_sources(ROOT, revision_reader=lambda _: "0" * 40)
```

- [ ] **Step 2: Run the tests and verify the intended failures**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Expected: FAIL because the target and `prepare_sources` do not exist.

- [ ] **Step 3: Initialize only the pinned OpenTitan submodule**

Run: `git submodule update --init --depth 1 external_designs/opentitan`

Expected: `git -C external_designs/opentitan rev-parse HEAD` prints `13a8919bceac625dbd1b6ad804e62f9bdeadee86`.

- [ ] **Step 4: Implement revision validation and deterministic closure generation**

```python
EXPECTED_OPENTITAN_REVISION = "13a8919bceac625dbd1b6ad804e62f9bdeadee86"
ROOT_CORES = (
    "lowrisc:ip:uart:0.1",
    "lowrisc:ip:gpio:0.1",
    "lowrisc:ip:rv_timer:0.1",
)

def prepare_sources(repo_root: Path, revision_reader=read_revision) -> tuple[Path, ...]:
    ot_root = repo_root / "external_designs/opentitan"
    actual = revision_reader(ot_root)
    if actual != EXPECTED_OPENTITAN_REVISION:
        raise RuntimeError(
            f"OpenTitan revision {actual!r}, expected {EXPECTED_OPENTITAN_REVISION}"
        )
    files = resolve_synthesizable_core_closure(ot_root, ROOT_CORES)
    required = {"uart.sv", "gpio.sv", "rv_timer.sv"}
    if not required.issubset({path.name for path in files}):
        raise RuntimeError("official OpenTitan IP tops are incomplete")
    write_relative_flist(repo_root, files)
    return files
```

The resolver reads CAPI2 core YAML as structured data, follows `depend` edges,
selects synthesizable SystemVerilog files only, preserves package-before-module
order, and rejects missing core IDs or paths. If the pinned revision requires
generated top packages, include the checked-in generated files declared by its
cores; do not synthesize substitute packages.

- [ ] **Step 5: Generate and verify the file list**

Run: `PYTHONPATH=src:. python3 configs/designs/ibex_opentitan_real_ip/scripts/prepare_sources.py`

Expected: exits 0 and prints the pinned commit plus counts for UART, GPIO, RV timer, `prim`, and `tlul` sources.

- [ ] **Step 6: Run tests and commit**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Expected: provenance and closure tests PASS.

```bash
git add configs/designs/ibex_opentitan_real_ip tests/test_ibex_opentitan_real_ip_target.py
git commit -m "build: resolve pinned OpenTitan IP sources"
```

### Task 2: Build the Shared Ibex + OpenTitan System Top

**Files:**
- Create: `configs/designs/ibex_opentitan_real_ip/programs/mmio_exerciser.S`
- Create: `configs/designs/ibex_opentitan_real_ip/programs/link.ld`
- Create: `configs/designs/ibex_opentitan_real_ip/programs/build_hex.py`
- Generate: `configs/designs/ibex_opentitan_real_ip/programs/mmio_exerciser.hex`
- Create: `configs/designs/ibex_opentitan_real_ip/rtl/ibex_ot_ram.sv`
- Create: `configs/designs/ibex_opentitan_real_ip/rtl/ibex_ot_obi_to_tlul.sv`
- Create: `configs/designs/ibex_opentitan_real_ip/rtl/ibex_ot_tlul_router.sv`
- Create: `configs/designs/ibex_opentitan_real_ip/rtl/ibex_opentitan_real_ip_top.sv`
- Modify: `tests/test_ibex_opentitan_real_ip_target.py`

**Interfaces:**
- Consumes: official `tlul_pkg::{tl_h2d_t,tl_d2h_t}`, Ibex OBI-like data bus, and the generated MMIO hex.
- Produces: module `ibex_opentitan_real_ip_top` with clock/reset, bounded environment inputs, observation outputs, and official instances `uart u_uart`, `gpio u_gpio`, `rv_timer u_rv_timer`.

- [ ] **Step 1: Add failing hierarchy and firmware tests**

```python
def test_system_top_instantiates_only_official_peripheral_tops(self):
    top = (TARGET / "rtl/ibex_opentitan_real_ip_top.sv").read_text()
    for declaration in ("uart u_uart", "gpio u_gpio", "rv_timer u_rv_timer"):
        self.assertIn(declaration, top)
    self.assertNotIn("ibex_mcip_", top)

def test_mmio_exerciser_touches_all_regions(self):
    asm = (TARGET / "programs/mmio_exerciser.S").read_text()
    for address in ("0x40000000", "0x40010000", "0x40020000"):
        self.assertIn(address, asm)
```

- [ ] **Step 2: Run tests and verify missing-top failures**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Expected: FAIL on missing system and firmware files.

- [ ] **Step 3: Implement and build the deterministic RV32I exerciser**

The loop performs aligned writes and reads in UART, GPIO, and timer register
windows, mixes readback into the next write value, and repeats forever. Build
with:

```python
subprocess.run([
    "clang", "--target=riscv32-unknown-elf", "-march=rv32i", "-mabi=ilp32",
    "-nostdlib", str(HERE / "mmio_exerciser.S"),
    f"-Wl,-T,{HERE / 'link.ld'}", "-Wl,--oformat=binary",
    "-o", str(binary),
], check=True)
```

Run: `python3 configs/designs/ibex_opentitan_real_ip/programs/build_hex.py`

Expected: `mmio_exerciser.hex` is nonempty and reproducible on a second run.

- [ ] **Step 4: Implement the bounded bridge, router, RAM, and system top**

Use one explicit state machine per interface:

```systemverilog
typedef enum logic [1:0] {Idle, SendA, WaitD, ReturnObi} bridge_state_e;
typedef enum logic [1:0] {SelUart, SelGpio, SelTimer, SelError} route_sel_e;
```

Latch OBI address/data/write/byte-enable in `Idle`, hold a legal TL-UL A
request stable in `SendA`, accept exactly one D response in `WaitD`, then pulse
Ibex read-valid/error in `ReturnObi`. Decode `0x4000_0000`, `0x4001_0000`, and
`0x4002_0000` as non-overlapping 64-KiB UART/GPIO/timer windows. Connect the
official IPs using the exact pinned-revision port types and tie required alert,
RACL, and scan/test inputs to documented inactive values.

- [ ] **Step 5: Run structural tests and Verilator lint**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Run: `third_party/rfuzz/upstream/.tools/apt-root/usr/bin/verilator --lint-only -Wno-fatal --top-module ibex_opentitan_real_ip_top -f configs/designs/ibex_opentitan_real_ip/rtl/sources.f`

Expected: tests PASS and Verilator exits 0 with no unresolved module/package.

- [ ] **Step 6: Commit**

```bash
git add configs/designs/ibex_opentitan_real_ip tests/test_ibex_opentitan_real_ip_target.py
git commit -m "feat: integrate Ibex with real OpenTitan IP"
```

### Task 3: Add Fair Baseline and Dependency-Aware Harnesses

**Files:**
- Create: `configs/designs/ibex_opentitan_real_ip/harness/ibex_ot_baseline_direct_slice_harness.sv`
- Create: `configs/designs/ibex_opentitan_real_ip/harness/ibex_ot_depaware_projection_harness.sv`
- Create: `configs/designs/ibex_opentitan_real_ip/baseline_direct_slice/config.json`
- Create: `configs/designs/ibex_opentitan_real_ip/depaware_projection/config.json`
- Modify: `tests/test_ibex_opentitan_real_ip_target.py`

**Interfaces:**
- Consumes: shared `ibex_opentitan_real_ip_top` and 512-bit `rfuzz_input_bits`.
- Produces: manual modules `ibex_ot_baseline_direct_slice_harness` and `ibex_ot_depaware_projection_harness`, each exposing the same instrumented `__vi_coverage` port.

- [ ] **Step 1: Add failing parity and no-feedback tests**

```python
def test_harnesses_share_top_width_and_instrumentation(self):
    configs = [load_config(name) for name in ("baseline_direct_slice", "depaware_projection")]
    self.assertEqual(configs[0]["top"], configs[1]["top"])
    self.assertEqual(configs[0]["flist"], configs[1]["flist"])
    self.assertEqual(configs[0]["instrumentation"], configs[1]["instrumentation"])
    for source in harness_texts():
        self.assertIn("logic [511:0] rfuzz_input_bits", source)
        self.assertIn("ibex_opentitan_real_ip_top dut", source)

def test_depaware_projection_has_no_dut_output_feedback(self):
    source = harness_text("depaware_projection")
    self.assertNotRegex(source, r"assign\s+\w+\s*=.*dut\.")
```

- [ ] **Step 2: Run tests and verify missing-harness failures**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Expected: FAIL on missing harness/config files.

- [ ] **Step 3: Implement both mappings**

Baseline assigns fixed raw slices directly to reset-safe environment fields.
Dependency-aware uses only combinational functions of the same raw bits:

```systemverilog
assign response_latency = 3'(1 + rfuzz_input_bits[2:1] % 3);
assign mmio_addr = {rfuzz_input_bits[63:48], 14'b0, 2'b00};
assign uart_rx_valid = rfuzz_input_bits[64] & ~rfuzz_input_bits[65];
assign bus_error = rfuzz_input_bits[66] & rfuzz_input_bits[67];
```

Both instantiate the same DUT top, pass the same reset, and expose the same
coverage vector. No projection expression references a DUT output.

- [ ] **Step 4: Run parity tests and lint both harnesses**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Run each harness through Verilator with `--top-module` and the same `sources.f`.

Expected: all tests and both lint commands PASS.

- [ ] **Step 5: Commit**

```bash
git add configs/designs/ibex_opentitan_real_ip tests/test_ibex_opentitan_real_ip_target.py
git commit -m "feat: add real OpenTitan comparison harnesses"
```

### Task 4: Instrument, Build, and Smoke Both RFuzz Servers

**Files:**
- Modify if required: `scripts/runs/build_rfuzz_compat_server.py`
- Create: `scripts/runs/run_ibex_opentitan_real_ip_pilot.py`
- Modify: `tests/test_ibex_opentitan_real_ip_target.py`

**Interfaces:**
- Consumes: two target configs, MyFuzz instrumentation output, RFuzz compatibility builder, and KFuzz binary.
- Produces: two servers/TOMLs with equal coverage width and a JSON comparison summary containing provenance and resource measurements.

- [ ] **Step 1: Add failing runner contract tests**

```python
def test_pilot_rejects_different_coverage_universes(self):
    with self.assertRaisesRegex(RuntimeError, "coverage universe"):
        validate_pair({"width": 10, "identity": "a"}, {"width": 10, "identity": "b"})

def test_pilot_summary_names_real_opentitan_revision(self):
    summary = build_summary(fake_success_pair())
    self.assertEqual(summary["target"], "ibex_opentitan_real_ip")
    self.assertEqual(summary["opentitan_revision"], EXPECTED_OT)
```

- [ ] **Step 2: Run tests and verify missing-runner failures**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Expected: FAIL because runner helpers are missing.

- [ ] **Step 3: Instrument the shared top once**

Run the repository's instrumentation command with top
`ibex_opentitan_real_ip_top`, branch coverage, and `rtl/sources.f`. Persist the
instrumented file list, instrumentation JSON, width, and a stable identity hash
of the point records. Both server builds consume these same artifacts.

- [ ] **Step 4: Build both compatibility servers with bounded memory**

Invoke `scripts/runs/build_rfuzz_compat_server.py` twice with input width 512,
the shared instrumentation output, each manual harness, local Verilator 5.020,
and `-j 1`. Assert both server binaries and TOMLs exist and their coverage width
and point identity match.

- [ ] **Step 5: Run bounded smoke campaigns**

Run each server/KFuzz pair for 30 seconds with campaign seed 1 and distinct
System V server IDs. Capture return codes, covered points, tests executed,
duration, and peak process-tree RSS. Assert clean shutdown, nonzero tests, and
nonzero coverage.

- [ ] **Step 6: Run tests and commit**

Run: `PYTHONPATH=src:. python3 -m unittest tests.test_ibex_opentitan_real_ip_target -v`

Expected: PASS, including mismatch rejection and provenance fields.

```bash
git add scripts/runs/run_ibex_opentitan_real_ip_pilot.py tests/test_ibex_opentitan_real_ip_target.py
git commit -m "test: smoke real OpenTitan RFuzz target"
```

### Task 5: Run the Short Comparison and Publish Corrected Results

**Files:**
- Modify: `docs/ALL_TEST_RESULTS_MASTER.md`
- Modify: `configs/designs/ibex_multicomponent_ip/README.md`
- Produce: `runs/pilots/ibex_opentitan_real_ip_*/summary.json`
- Produce: `runs/pilots/ibex_opentitan_real_ip_*/samples.csv`

**Interfaces:**
- Consumes: verified baseline and dependency-aware servers.
- Produces: a valid short comparison and documentation that separates proxy results from real OpenTitan results.

- [ ] **Step 1: Run the short sequential comparison**

Run: `PYTHONPATH=src:. python3 scripts/runs/run_ibex_opentitan_real_ip_pilot.py --duration 300 --seed 1 --memory-reserve-mib 2048`

Expected: both jobs run for at least 300 seconds, exit cleanly, retain at least 2048 MiB available memory, and write summaries/samples.

- [ ] **Step 2: Validate the result programmatically**

```python
assert baseline["coverage_width"] == depaware["coverage_width"]
assert baseline["instrumentation_identity"] == depaware["instrumentation_identity"]
assert baseline["tests_total"] > 0 and depaware["tests_total"] > 0
assert baseline["covered"] > 0 and depaware["covered"] > 0
assert baseline["fuzzer_returncode"] == depaware["fuzzer_returncode"] == 0
assert baseline["server_returncode"] == depaware["server_returncode"] == 0
```

- [ ] **Step 3: Correct documentation scope**

Label the old `ibex_multicomponent_ip` results as local common-IP proxy results.
Add the real target's OpenTitan commit, official instance names, coverage width,
covered counts, percentages, delta, throughput, duration, and peak RSS. Do not
claim a dep-aware improvement unless the measured final covered set supports it.

- [ ] **Step 4: Run final verification**

Run: `PYTHONPATH=src:. python3 -m unittest discover -s tests`

Run: `git diff --check`

Run the full real-target Verilator lint once more from the clean generated
file list.

Expected: full suite PASS, diff check exits 0, lint exits 0, and no fuzzer/server
process remains.

- [ ] **Step 5: Commit tracked implementation and documentation**

```bash
git add configs/designs/ibex_opentitan_real_ip scripts/runs/run_ibex_opentitan_real_ip_pilot.py tests/test_ibex_opentitan_real_ip_target.py docs/ALL_TEST_RESULTS_MASTER.md configs/designs/ibex_multicomponent_ip/README.md
git commit -m "feat: validate real OpenTitan common-IP coverage target"
```
