# CVE2 and PicoRV32 Source Backed CPU Profiles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give CVE2 and all three PicoRV32 CPU top modules source pinned, fully elaborated component profiles so later local harness generation consumes facts rather than guessed port names.

**Architecture:** Build one `component_profile.v1` per top from the new gitlinks. Use `elaborate_profile` and `bind_profile` to prove port direction, width, source revision and endpoint mapping; use `build_port_dispositions` to prove every top bit has one declared treatment. Profiles record the currently supported local execution subset without claiming generated harness or real scenario runtime.

**Tech Stack:** JSON component profiles, existing Python 3 composition source crawler and Verilator JSON frontend, unittest.

## Global Constraints

- Component internal behaviour comes from real RTL; profiles cannot invent DUT output.
- The source revisions are CVE2 `d079e8c8e6a08b330940ae123876ba0612bec18d` and PicoRV32 `ef203c2b0a3fb793280f5114941416c425c5b461`.
- Every new profile must elaborate all top ports and assign every bit exactly once; `source.top_port_selection="declared"` is insufficient for Generated status.
- Missing, wrong direction, conflicting or undocumented port assignments fail closed.
- OBI is a split request/grant/response boundary; Pico `mem_ready` is completion with valid `mem_rdata`, not early acceptance.
- New CPU profiles do not by themselves satisfy RTL operational or Cross-component accepted status.
- Do not edit existing Ibex/CVA6/OpenTitan session implementations or old evidence identity files in this plan.

---

## File Structure

- Create `configs/cpus/cv32e20/component_profile.json`: CVE2 full top contract.
- Create `configs/cpus/picorv32/component_profile.json`: native ready/valid top contract.
- Create `configs/cpus/picorv32_axi/component_profile.json`: AXI4-Lite top contract.
- Create `configs/cpus/picorv32_wb/component_profile.json`: Wishbone top contract.
- Add isolated tests under `tests/composition/` for CVE2 and Pico profiles.
- The existing `configs/cpus/{cv32e20,picorv32}/official_core_interface_description.json` placeholder revisions must be corrected or retired in the same task that makes the replacement profile authoritative.

### Task 1: CVE2 complete OBI profile

**Files:**
- Create: `configs/cpus/cv32e20/component_profile.json`
- Modify: `configs/cpus/cv32e20/official_core_interface_description.json`
- Create: `tests/composition/test_cv32e20_source_profile.py`

**Interfaces:**
- Consumes: `third_party/cv32e20_upstream_reference` gitlink, `component_profile.v1`, OBI protocol plugin.
- Produces: `cv32e20` profile with `processor.instruction`, `processor.data`, `processor.interrupts` endpoints and complete port disposition.

- [ ] **Step 1: Write the source backed acceptance test**

```python
from pathlib import Path
import unittest
from myfuzz.composition.component_profile import (
    bind_profile, elaborate_profile, load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import build_port_dispositions

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/cpus/cv32e20/component_profile.json"

class CV32E20SourceProfileTests(unittest.TestCase):
    def test_complete_top_and_obi_roles(self):
        profile = load_component_profile(PROFILE)
        facts = elaborate_profile(profile, base_dir=ROOT)
        self.assertEqual(facts.selection, "all")
        binding = bind_profile(profile, facts)
        ledger = build_port_dispositions(
            "cv32e20_0", binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=profile.port_actions)
        self.assertEqual(binding.endpoint("processor.instruction").function,
                         "instruction_memory_master")
        self.assertEqual(binding.endpoint("processor.data").function,
                         "data_memory_master")
        self.assertEqual(binding.field("processor.interrupts", "external").port,
                         "irq_external_i")
        self.assertTrue(ledger)
        self.assertEqual(profile.source.revision,
                         "git:d079e8c8e6a08b330940ae123876ba0612bec18d")
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_cv32e20_source_profile -q`. Expected before implementation: fail because profile file does not exist.

- [ ] **Step 2: Create the full CVE2 profile from the pinned source**

The source object must use `top_module=cve2_top`, `top_port_selection=all`, ordered files from `cv32e20_manifest.flist` plus the actual instantiated `cve2_branch_predict.sv` and `cve2_clock_gate.sv`, and include roots `rtl`, `vendor/lowrisc_ip/ip/prim/rtl`, `vendor/lowrisc_ip/dv/sv/dv_utils`. Use exactly the five top parameters `MHPMCounterNum=10`, `MHPMCounterWidth=40`, `RV32E=0`, `RV32M=2`, `XInterface=0`; keep `RVFI=1` only if full Verilator elaboration proves those ports. The source revision is the Task 1 gitlink SHA.

The OBI instruction roles are `req/gnt/addr/rvalid/rdata/error` mapped respectively to `instr_req_o/instr_gnt_i/instr_addr_o/instr_rvalid_i/instr_rdata_i/instr_err_i`. The data roles are `req/gnt/addr/we/wdata/be/rvalid/rdata/error` mapped to `data_req_o/data_gnt_i/data_addr_o/data_we_o/data_wdata_o/data_be_o/data_rvalid_i/data_rdata_i/data_err_i`. `processor.interrupts.external` maps to `irq_external_i`. Clock is `clk_i`, reset is active-low `rst_ni`. CPU contract is RV32IMC, reset vector `0x10000`, and this core fetches exactly from that address after alignment, not the Ibex `+0x80` address.

Constant actions must cover `test_en_i=0`, `ram_cfg_i=0`, `hart_id_i=0`, `boot_addr_i=65536`, `x_issue_ready_i=0`, `x_issue_resp_i=0`, `x_result_valid_i=0`, `x_result_i=0`, `irq_software_i=0`, `irq_timer_i=0`, `irq_fast_i=0`, `irq_nm_i=0`, `debug_req_i=0`, `dm_halt_addr_i=0`, `dm_exception_addr_i=0`, `fetch_enable_i=1`. Observe actions must cover every remaining output including XIF/debug/crash/sleep and all actually elaborated RVFI ports. Each action needs a source-backed reason. Set capability `max_outstanding=1` only as the planned environment limit, not a claim about native core concurrency. If a top aggregate cannot be represented by the frontend, repair the frontend in a separate reviewed change; do not silently select only declared ports.

- [ ] **Step 3: Correct the old interface description pin and run the focused test**

Replace the zero revision in `official_core_interface_description.json` with the actual gitlink revision and reconcile its source/top/interface fields to the new profile; do not leave two contradictory authoritative descriptions. Run:

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_cv32e20_source_profile -q
git diff --check
```

Expected: test passes, full top selection, binding and disposition succeeds. If `RV32M=2` is rejected by Verilator's enum parameter typing, omit that override and record the RTL default enum in the profile evidence; do not invent a different value.

- [ ] **Step 4: Commit this independently reviewable profile**

```bash
git add configs/cpus/cv32e20/component_profile.json configs/cpus/cv32e20/official_core_interface_description.json tests/composition/test_cv32e20_source_profile.py
git commit -m "feat: pin complete CVE2 OBI source profile"
```

Expected: only the CVE2 profile, interface description and focused test change.

### Task 2: Three PicoRV32 top profiles

**Files:**
- Create: `configs/cpus/picorv32/component_profile.json`
- Create: `configs/cpus/picorv32_axi/component_profile.json`
- Create: `configs/cpus/picorv32_wb/component_profile.json`
- Modify: `configs/cpus/picorv32/official_core_interface_description.json`
- Create: `tests/composition/test_picorv32_source_profiles.py`

**Interfaces:**
- Consumes: `third_party/picorv32_upstream_reference` gitlink and `picorv32.v`.
- Produces: separate full port facts for native Ready/Valid, `picorv32_axi` AXI4-Lite and `picorv32_wb` Wishbone classic.

- [ ] **Step 1: Write focused tests that reject placeholder pins and incomplete tops**

```python
from pathlib import Path
import unittest
from myfuzz.composition.component_profile import (
    bind_profile, elaborate_profile, load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import build_port_dispositions

ROOT = Path(__file__).resolve().parents[2]
TOPS = {
    "picorv32": ("picorv32", "ready-valid-memory", "1"),
    "picorv32_axi": ("picorv32_axi", "axi4-lite", "1"),
    "picorv32_wb": ("picorv32_wb", "wishbone", "classic"),
}

class PicoRV32SourceProfileTests(unittest.TestCase):
    def test_each_variant_is_pinned_and_classifies_every_bit(self):
        for name, (top, protocol, version) in TOPS.items():
            with self.subTest(name=name):
                profile = load_component_profile(
                    ROOT / f"configs/cpus/{name}/component_profile.json")
                self.assertEqual(profile.source.revision,
                                 "git:ef203c2b0a3fb793280f5114941416c425c5b461")
                facts = elaborate_profile(profile, base_dir=ROOT)
                self.assertEqual(facts.selection, "all")
                self.assertEqual(facts.top_module, top)
                binding = bind_profile(profile, facts)
                self.assertEqual(binding.endpoint("processor.memory").protocol,
                                 (protocol, version))
                self.assertTrue(build_port_dispositions(
                    name + "_0", binding, clock_domain="core",
                    reset_domain="sys_rst",
                    profile_port_actions=profile.port_actions))
```

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_picorv32_source_profiles -q`. Expected before profiles: fail because the three profile files do not exist.

- [ ] **Step 2: Create each source-backed top profile**

All use `source.root=third_party/picorv32_upstream_reference`, `source.files=["picorv32.v"]`, `source.top_port_selection="all"`, Verilator JSON, the exact pin above, and no `RISCV_FORMAL` define in the initial profile. Native and AXI clocks use `clk` and active-low synchronous `resetn`; Wishbone uses `wb_clk_i` and active-high synchronous `wb_rst_i`. Set `cpu.family=riscv`, `xlen=32`, `extensions=["i"]`, `reset_vector=0`, `master_endpoints=["processor.memory"]`, `boot_address_required=false`; do not claim standard machine-external IRQ delivery for Pico's custom IRQ mechanism.

Declare the native endpoint `["ready-valid-memory","1"]`: `valid=mem_valid`, `ready=mem_ready`, `addr=mem_addr`, `wdata=mem_wdata`, `wstrb=mem_wstrb`, `rdata=mem_rdata`. `mem_instr` is an observed physical output, since the existing plugin has no `instruction_identity` role. Its `ready` is completion, and the profile evidence must say so.

Declare the AXI4-Lite endpoint `["axi4-lite","1"]` with every physical `mem_axi_*` channel field: `awvalid/awready/awaddr/awprot/wvalid/wready/wdata/wstrb/bvalid/bready/arvalid/arready/araddr/arprot/rvalid/rready/rdata`. The top has no `bresp` or `rresp`; no alias may be invented. Its missing response status is an explicit no-error limitation for the later local transactor.

Declare the Wishbone endpoint `["wishbone","classic"]`: `adr=wbm_adr_o`, `dat_w=wbm_dat_o`, `dat_r=wbm_dat_i`, `we=wbm_we_o`, `sel=wbm_sel_o`, `stb=wbm_stb_o`, `ack=wbm_ack_i`, `cyc=wbm_cyc_o`. The top has no `err` or `stall`; this is an explicit no-error/no-stall variant. `wbm_adr_o` is a byte address, and read `sel` behaviour must be verified in the later protocol transactor test.

For all three: constant-zero action on `pcpi_wr`, `pcpi_rd`, `pcpi_wait`, `pcpi_ready` and `irq`, with source-based reasons and `ENABLE_PCPI=0`, `ENABLE_IRQ=0` parameter evidence. Observe `trap`, `eoi`, `pcpi_valid`, `pcpi_insn`, `pcpi_rs1`, `pcpi_rs2`, `trace_valid`, `trace_data`; also observe all remaining native look-ahead outputs and `mem_instr` as physically present. The ledger must reject any missing port; add only ports actually seen in full elaboration. Set capabilities to the physical 32-bit address/data, four byte lanes, one planned outstanding request, and no physical error response. Do not assert real program execution in profile evidence.

- [ ] **Step 3: Correct the older native description and run focused tests**

Update its revision to the exact gitlink, rename `processor.memory.unified` to `processor.memory`, and remove the unsupported `instruction_identity` protocol role from its endpoint declaration; preserve `mem_instr` in the new component profile as observe. Run:

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_picorv32_source_profiles -q
git diff --check
```

Expected: all three top elaborations, protocol field direction/width bindings and complete ledgers pass. If `ENABLE_PCPI` or `ENABLE_IRQ` differs in the real top defaults, select an explicit valid parameter override and justify it from `picorv32.v`; do not mask the input instead.

- [ ] **Step 4: Commit this independently reviewable profile set**

```bash
git add configs/cpus/picorv32/component_profile.json configs/cpus/picorv32/official_core_interface_description.json configs/cpus/picorv32_axi/component_profile.json configs/cpus/picorv32_wb/component_profile.json tests/composition/test_picorv32_source_profiles.py
git commit -m "feat: pin three PicoRV32 CPU interface profiles"
```

Expected: only the three Pico profiles, corrected native interface description and focused test change.

### Task 3: Fault and capability audit before generator work

**Files:**
- Modify: `tests/composition/test_cv32e20_source_profile.py`
- Modify: `tests/composition/test_picorv32_source_profiles.py`
- Create: `docs/reports/generated-harness-cpu-profile-facts-20261004.md`

**Interfaces:**
- Consumes: Tasks 1 and 2 bound profiles and current protocol plugins.
- Produces: recorded physical coverage and rejection evidence; a clear boundary between profile facts and later generated/RTL status.

- [ ] **Step 1: Add negative tests for pin, missing input action and duplicate role**

```python
import json
from copy import deepcopy
from myfuzz.composition.component_profile import ComponentProfileError
from myfuzz.composition.soc_port_dispositions import PortDispositionError

def test_wrong_source_revision_is_rejected(self):
    document = json.loads(PROFILE.read_text())
    document["source"]["revision"] = "git:" + "0" * 40
    with self.assertRaises(ComponentProfileError):
        elaborate_profile(load_component_profile(document), base_dir=ROOT)

def test_missing_input_action_is_rejected(self):
    document = json.loads(PROFILE.read_text())
    document["port_actions"] = [
        action for action in document["port_actions"]
        if action["port"] != "fetch_enable_i"
    ]
    profile = load_component_profile(document)
    binding = bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))
    with self.assertRaises(PortDispositionError):
        build_port_dispositions(
            "cv32e20_0", binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=profile.port_actions)

def test_duplicate_physical_obi_output_is_rejected(self):
    document = json.loads(PROFILE.read_text())
    data = next(item for item in document["endpoints"]
                if item["endpoint_id"] == "processor.data")
    req = next(item for item in data["fields"] if item["role"] == "req")
    addr = next(item for item in data["fields"] if item["role"] == "addr")
    addr["aliases"] = deepcopy(req["aliases"])
    profile = load_component_profile(document)
    with self.assertRaises(ComponentProfileError):
        bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))
```

The assertions must check a distinct refusal for each mutation and restore the source document between cases; no test may accept an invented signal or selected-only top as a complete profile.

- [ ] **Step 2: Run the focused fact suite and write actual evidence**

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_cv32e20_source_profile tests.composition.test_picorv32_source_profiles -q
git diff --check
```

Expected: all positive and negative cases pass. The report must list exact tested source revisions, top modules, actual Verilator front-end result, full port counts, omissions/limitations of AXI response and Wishbone error, and explicitly mark all four as source/profile facts only.

- [ ] **Step 3: Commit the audit**

```bash
git add tests/composition/test_cv32e20_source_profile.py tests/composition/test_picorv32_source_profiles.py docs/reports/generated-harness-cpu-profile-facts-20261004.md
git commit -m "test: audit new CPU profile source facts"
```

Expected: report and focused negative assertions are reviewable separately from profile construction.
