# Ibex RVFI、Spike 参考与 RFuzz 长跑实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: use `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 将 Ibex RVFI 与独立 Spike cosim 接入 persistent profile campaign，保存 CPU/外设断言失败样本，并运行可重放的 600 秒官方 RFuzz campaign。

**Architecture:** 复用锁定 Ibex 源码树已有的 `SpikeCosim` 和 cosim DPI API，通过项目自有 wrapper 对接 profile SoC，并把上游 `$fatal` 换成每 testcase sticky mismatch feedback。CPU reference arm 只在 Spike 可独立建模的 frozen ROM/RAM 上执行；一旦 CPU 访问 GPIO/SPI MMIO，该 testcase 的 ISA 结果标为 `not_assessed`，绝不把 DUT 返回值传给 Spike 当期望值。独立的 MMIO arm 将 CPU 保持复位，由 RFuzz 驱动 APB 和 PULP 引脚，验证 GPIO/SPI checker。每个 CPU testcase 新建或完全重置 Spike 上下文，并重新载入 ROM/RAM，防止 persistent DUT 与 ISS 状态串样。

**Tech Stack:** RVFI、Ibex vendored Spike cosim C++/DPI、Verilator 5.020、官方 `kfuzz`、profile campaign/replay。

## Global Constraints

- CPU profile 是 RV32IMC、reset vector `0x10000`、实际首条取指地址 `0x10080`。
- PULP GPIO/SPI 参数及 APB3 接口保持各自 profile/source lock 声明；两个 pulse IRQ 均只观测。
- vendor Ibex/Spike 源只读；新增 glue/checker 放在 `src/myfuzz` 与 `tests`，不得修改 `third_party`。
- Verilator 5.020 是 RFuzz artifact 的唯一 bundled 版本；system 5.051 不可替代它。
- CPU reference mismatch 与 property feedback 分开报告；unsupported reference behavior 进入 `not_assessed`。
- CPU-only 与 mmio-only 是两个互补 campaign arm；首期不声称已验证同一条 CPU 指令序列与 GPIO/SPI 的端到端软件交互。
- Spike 内存只从冻结 firmware/RAM 初始镜像和 reference 自身执行的 store 更新；禁止将 DUT 的 load/RXFIFO/APB 读值写入 Spike 参考内存。
- 官方 campaign 首期运行至少 600 秒；保存完整 corpus、receipt、identity、replay 和 cleanup evidence。

---

## Dependencies and property IDs

先完成 [组合与协议计划](2026-09-25-ibex-pulp-composition-and-protocol-monitors.md)、[GPIO 检查器计划](2026-09-25-pulp-gpio-checker.md) 与 [SPI 检查器计划](2026-09-25-pulp-spi-checker.md)。本计划实现 bit 16–20：`RVFI.ORDER`, `RVFI.FETCH_IMAGE`, `RVFI.SPIKE_STEP`, `RVFI.MEMORY_TRANSACTION`, `RVFI.TRAP_POLICY`。

## File map

- Create: `src/myfuzz/cosim/ibex_profile_spike_cosim.cc` — 项目自有 DPI wrapper；通过现有 vendored `SpikeCosim` API 管理 reference 生命周期与 memory sync。
- Create: `src/myfuzz/protocols/rtl/soc_ibex_rvfi_checker.sv` — RVFI order/fetch/ISS/memory/trap property bits 16–20。
- Modify: `configs/cpus/ibex/component_profile.json`, `configs/cpus/ibex/official_core_interface_description.json` — 登记所需 RVFI observe roles，不将它们当成 CPU input stimulus。
- Modify: `src/myfuzz/composition/soc_profile_renderer.py`, `soc_runtime.py`, `soc_checker_profile.py` — 连接 RVFI 和每 testcase reset/reload lifecycle。
- Modify: `src/myfuzz/integration/soc_builder.py`, `soc_campaign.py`, `rfuzz_simulator.py` — DPI compile/link, property report, replay identity。
- Create: `scripts/run_ibex_pulp_campaign.py` — 单 campaign 配置的官方 runner，校验 arm 配置并调用 `run_soc_campaign`。
- Create: `configs/campaigns/ibex-pulp-gpio-spi-cpu.json`, `configs/campaigns/ibex-pulp-gpio-spi-mmio.json`。
- Create: `tests/integration/test_soc_ibex_rvfi_spike.py`, `tests/integration/test_soc_ibex_pulp_rfuzz_campaign.py`。

## Task 1: Expose RVFI and build a reusable Spike comparison lifecycle

**Interfaces:**

```systemverilog
module soc_ibex_rvfi_checker (
  input logic clk_i, rst_ni, test_begin_i,
  input logic rvfi_valid_i,
  input logic [63:0] rvfi_order_i,
  input logic [31:0] rvfi_insn_i, rvfi_pc_rdata_i,
  input logic rvfi_trap_i,
  input logic [3:0] rvfi_mem_rmask_i, rvfi_mem_wmask_i,
  output logic [4:0] eval_o, fail_o
);
```

The DPI wrapper creates, initializes, steps, reports and destroys one `SpikeCosim` context per testcase. It copies the frozen ROM and initial RAM image at `test_begin` using the reference memory API. The bridge reports accepted OBI data-side transaction metadata to the existing `notify_dside_access`/equivalent API; Spike independently executes the instruction and obtains load values from its own memory model. It must never seed Spike with the DUT's returned load value. CPU reference configurations reject GPIO/SPI MMIO as unsupported and mark that testcase `not_assessed`; the separate mmio-only arm exercises peripherals without claiming an ISA cosim result. A Spike error sets a sticky property bit and stores a bounded diagnostic; it never calls `$fatal`.

- [ ] **Step 1: Write failing RVFI and repeated-test lifecycle tests**

Cover sequential/unique `rvfi_order`, instruction address/data against frozen image, a known RV32IMC ROM/RAM-only trace that matches the vendored Spike reference, an altered destination value that mismatches, an attempted peripheral MMIO load that becomes `not_assessed`, and two back-to-back tests with different images proving no stale Spike registers or memory survive. Assert the Spike reference never receives DUT load data as reference memory content.

```python
@dataclass(frozen=True)
class SpikeSequenceResult:
    reference_statuses: tuple[str, ...]
    reference_image_hashes: tuple[str, ...]

def run_two_images_in_one_simulator(images: Sequence[bytes]) -> SpikeSequenceResult:
    """Run two CPU testcases through one persistent Verilated DUT process."""

def test_spike_context_reloads_each_persistent_test(self):
    result = run_two_images_in_one_simulator((IMAGE_A, IMAGE_B))
    self.assertEqual(("pass", "pass"), result.reference_statuses)
    self.assertEqual((IMAGE_A_HASH, IMAGE_B_HASH), result.reference_image_hashes)
```

- [ ] **Step 2: Run tests and confirm RVFI bridge is absent**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_rvfi_spike -v`  
Expected: import/build failure because the profile does not publish RVFI observations and no project DPI wrapper exists.

- [ ] **Step 3: Register RVFI observe roles and add the checker**

Bind `rvfi_valid/order/insn/trap/rd_addr/rd_wdata/pc_rdata/pc_wdata/mem_addr/mem_rmask/mem_wmask/mem_rdata/mem_wdata` plus the required interrupt/CSR metadata to the harness. Implement five property IDs. Add an assertion in the loader that every requested role exists at the pinned `ibex_top` elaboration.

- [ ] **Step 4: Adapt the vendored Spike cosim wrapper without modifying third_party**

Build against the locked `third_party/rfuzz/upstream/ibex/dv/cosim/SpikeCosim` sources and vendor `riscv-isa-sim` API. Use `dv/verilator/simple_system_cosim/ibex_simple_system_cosim_checker.sv` as behavioral reference only; replace its process-fatal mismatch path with `fail_o` and a per-test lifecycle. Record exact source/tool hashes in artifact provenance.

- [ ] **Step 5: Run positive, negative and two-test persistence cases**

Run: `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_rvfi_spike -v`  
Expected: golden RV32IMC trace passes, modified RVFI register result sets `RVFI.SPIKE_STEP`, test B starts from its own image/state, and unsupported traps return `not_assessed` unless explicitly declared.

- [ ] **Step 6: Commit RVFI and Spike lifecycle**

```bash
git add configs/cpus/ibex/component_profile.json configs/cpus/ibex/official_core_interface_description.json src/myfuzz/cosim/ibex_profile_spike_cosim.cc src/myfuzz/protocols/rtl/soc_ibex_rvfi_checker.sv src/myfuzz/composition/soc_profile_renderer.py src/myfuzz/composition/soc_runtime.py src/myfuzz/composition/soc_checker_profile.py src/myfuzz/integration/soc_builder.py tests/integration/test_soc_ibex_rvfi_spike.py
git commit -m "feat: compare Ibex RVFI against Spike in profile runs"
```

## Task 2: Configure target arms and report checker evidence

**Files:**

- Create: `configs/campaigns/ibex-pulp-gpio-spi-cpu.json`
- Create: `configs/campaigns/ibex-pulp-gpio-spi-mmio.json`
- Modify: `src/myfuzz/integration/soc_campaign.py`, `rfuzz_simulator.py`
- Create: `tests/integration/test_soc_ibex_pulp_rfuzz_campaign.py`

- [ ] **Step 1: Add failing campaign configuration tests**

Assert CPU arm uses `drive_profile=cpu_execute`, `mode=cpu_only`, explicit frozen firmware and legal-instruction/reference gate. GPIO/SPI MMIO accesses in this arm must become `not_assessed`; no GPIO/SPI return data may enter Spike memory. Assert MMIO arm uses `mode=mmio_only`, CPU held in reset, APB/pin inputs supplied by RFuzz, no instruction candidates used as evidence, and the same checker/source identity. Reject arm config with unknown checker bit map or wrong Verilator version.

- [ ] **Step 2: Run config tests and confirm configurations are absent**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_pulp_rfuzz_campaign -v`  
Expected: missing campaign config path.

- [ ] **Step 3: Add both campaign configurations and evidence report fields**

The report includes all 50 reserved property IDs with per-arm status (`evaluated`, `not_evaluated`, or `not_assessed`), evaluation/failure coverage, `checker_profile_hash`, source closure, boot image, layout, projection arm, RFuzz/Verilator identity, completed receipts, corpus manifest, replay outcome and cleanup outcome. CPU arm acceptance requires its CPU/OBI properties; MMIO arm acceptance requires its APB/fabric/GPIO/SPI properties. Do not require the CPU arm to evaluate peripheral-only properties or the MMIO arm to evaluate RVFI properties. The combined campaign is incomplete if any required property is not evaluated; unsupported items remain explicitly `not_assessed`.

- [ ] **Step 4: Run preflight and short real campaign acceptance**

Run: `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_pulp_rfuzz_campaign -v`  
Expected: official `kfuzz`, bundled Verilator 5.020, actual combined RTL, non-empty corpus, arm-appropriate transactions, all required checker evaluation bits for that arm, successful corpus replay, and clean shared-memory/process cleanup. The CPU arm has nonzero retired instructions and no assessed GPIO/SPI MMIO reference transactions; the MMIO arm has nonzero GPIO and SPI APB transactions while CPU reset is asserted. RFuzz client termination is accepted only by the existing complete-evidence policy.

- [ ] **Step 5: Commit campaign configuration and reporting**

```bash
git add configs/campaigns/ibex-pulp-gpio-spi-cpu.json configs/campaigns/ibex-pulp-gpio-spi-mmio.json src/myfuzz/integration/soc_campaign.py src/myfuzz/integration/rfuzz_simulator.py tests/integration/test_soc_ibex_pulp_rfuzz_campaign.py
git commit -m "feat: add RFuzz arms for Ibex and PULP peripherals"
```

## Task 3: Run 600-second official searches and replay retained evidence

- [ ] **Step 1: Run the CPU execution arm for 600 seconds**

Run: `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 scripts/run_ibex_pulp_campaign.py --config configs/campaigns/ibex-pulp-gpio-spi-cpu.json --duration-seconds 600 --output runs/ibex-pulp-gpio-spi/cpu-600s`  
Expected: official client receipts increase, RVFI reference runs on supported ROM/RAM-only tests, and checker coverage is stored separately from RTL coverage. This arm does not claim GPIO/SPI MMIO execution.

- [ ] **Step 2: Verify CPU-arm corpus and replay**

The runner writes the `run_soc_campaign` result and machine-readable replay/cleanup evidence into the output directory. Require `corpus.status == "verified"`, `replay.status == "passed"`, zero `evidence_missing`, matching input/image/layout/source/checker/tool identities, and zero remaining owned shared-memory segments. Do not start a second 600-second run merely to check these fields.

- [ ] **Step 3: Run the MMIO-only arm for 600 seconds**

Run: `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 scripts/run_ibex_pulp_campaign.py --config configs/campaigns/ibex-pulp-gpio-spi-mmio.json --duration-seconds 600 --output runs/ibex-pulp-gpio-spi/mmio-600s`  
Expected: CPU remains reset, GPIO and SPI APB transaction counts are both nonzero, peripheral oracle properties are evaluated, and no result is labeled CPU instruction fuzz.

- [ ] **Step 4: Replay MMIO corpus and classify each failure**

Require the saved MMIO report to show `corpus.status == "verified"`, `replay.status == "passed"`, zero `evidence_missing`, and clean cleanup. Inspect the saved report's candidate entries; classify each as composition/adapter, candidate, or not assessed. Upgrade to confirmed only after relevant independent isolation evidence.

- [ ] **Step 5: Publish a concise acceptance report**

Create `docs/reports/ibex-pulp-gpio-spi-rfuzz-acceptance-20260925.md` from the two machine-readable report JSONs. Include duration, completed tests, target transactions, all 50 eval/fail bits, corpus/replay/cleanup states, unassessed properties, and defect evidence links; do not count injected checker mutants as discovered IP bugs.

- [ ] **Step 6: Commit only the report and campaign code**

```bash
git add docs/reports/ibex-pulp-gpio-spi-rfuzz-acceptance-20260925.md
git commit -m "docs: record Ibex PULP RFuzz acceptance"
```

## Verification commands

```bash
PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_rvfi_spike tests.integration.test_soc_ibex_pulp_rfuzz_campaign -v
MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_pulp_rfuzz_campaign -v
```

Expected: CPU functional campaign is not marked ready without Spike cosim; both official arms save corpus/replay/cleanup evidence; only valid reference mismatches become CPU or peripheral candidates. CPU-to-peripheral software interaction remains outside this first-stage claim until an independently modeled GPIO/SPI device model is added to the Spike memory map.
