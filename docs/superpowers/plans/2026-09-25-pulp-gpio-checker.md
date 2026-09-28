# PULP GPIO 独立检查器实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: use `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为真实 PULP `apb_gpio` 编写针对分离式输入/输出引脚的独立寄存器、同步和中断状态检查器。

**Architecture:** 用 checker 自己的 APB transaction shadow state 与 GPIO 输入延迟模型计算期望；连接到 `gpio_in/out/dir/padcfg/in_sync/interrupt` 实际端口。不会 attach 不兼容的通用 GPIO electrical peer，也不会改 vendor RTL。

**Tech Stack:** Python reference oracle、SystemVerilog sidecar monitor、bundled Verilator 5.020、unittest。

## Global Constraints

- 仅覆盖 `PAD_NUM=32`、`NBIT_PADCFG=4`、`APB_ADDR_WIDTH=12`、APB3 32-bit full-word 配置。
- `gpio_in`、`gpio_out`、`gpio_dir`、`gpio_padcfg`、`gpio_in_sync` 是分离端口；本期不支持真实 `inout` pad 电气解析。
- GPIO interrupt 是待观测 pulse，不接 level-only Ibex controller；无独立依据的 source-derived alias 行为不可判为规范 pass/fail。
- 每个启用 property 都要记录可审阅的行为依据；`source_derived` 检查结果只标为 probe，不能单独确认 PULP IP 缺陷。
- 所有 GPIO property 位复用基础计划定义的 `checker_eval_o[49:0]`/`checker_fail_o[49:0]`，property map hash 进入 artifact identity。

---

## Dependency and property IDs

先执行 [Ibex + PULP 组合与协议检查器计划](2026-09-25-ibex-pulp-composition-and-protocol-monitors.md)。本计划覆盖 bit 21–35 共 15 个预留 property ID；只有在行为依据、真实信号绑定和变异校准都齐备时才启用：

`GPIO.RESET_STATE`, `GPIO.PADDIR`, `GPIO.GPIOEN`, `GPIO.PADOUT`, `GPIO.PADOUTSET`, `GPIO.PADOUTCLR`, `GPIO.PADCFG`, `GPIO.SYNC_ENABLE_GROUP`, `GPIO.IN_SYNC`, `GPIO.PADIN`, `GPIO.DIR_OUTPUT`, `GPIO.INTERRUPT_EVENT`, `GPIO.INTSTATUS_LATCH`, `GPIO.INTSTATUS_READ_CLEAR`, `GPIO.CONCURRENT_EVENT_PRIORITY`。

## File map

- Create: `src/myfuzz/composition/pulp_gpio_oracle.py` — 独立 APB/pin cycle model。
- Create: `src/myfuzz/protocols/rtl/soc_pulp_gpio_checker.sv` — generated runtime monitor，拥有 bit 21–35。
- Create: `tests/composition/test_pulp_gpio_oracle.py` — literal vector reference tests。
- Create: `tests/integration/rtl/soc_pulp_gpio_checker_tb.sv` — real component and monitor simulation bench。
- Create: `tests/integration/test_soc_pulp_gpio_checker.py` — source binding, positive/negative real RTL acceptance。
- Modify: `src/myfuzz/composition/soc_profile_renderer.py`, `src/myfuzz/composition/soc_runtime.py` — connect actual GPIO roles and record the property vector.
- Modify: `configs/soc/checkers/ibex_pulp_gpio_spi.json` — activate calibrated GPIO properties; keep unsupported behavior `not_assessed` and source-derived probes labeled accordingly.

## Task 1: Implement a pure GPIO reference model

**Interfaces:**

`PulpGpioOracle` exposes `reset() -> None`, `apb_access(*, address: int, write: bool, wdata: int) -> int | None`, and `sample_pins(gpio_in: int) -> dict[str, int]`.

The oracle accepts only aligned 32-bit accesses to documented registers. It tracks `PADDIR`, `GPIOEN`, `PADOUT`, `PADCFG`, interrupt config/status, sync stages and event pulses. Values outside the supported contract raise a named `PulpGpioOracleError` and become `not_assessed`.

- [ ] **Step 1: Write failing literal-vector tests**

Add tests for reset state; PADOUT write/read; SET and CLR bit semantics; PADDIR/GPIOEN; PADIN read-only; PADCFG; enabled group-of-four sampling; all exported synchronization stages and PADIN timing; rising/falling/both-edge event; status latch; read-clear; a new event concurrent with a status read. Keep event/status tests disabled or `not_assessed` unless their expected semantics have an independent contract citation.

```python
def test_padoutset_sets_only_one_bits(self):
    oracle = PulpGpioOracle(pins=32)
    oracle.apb_access(address=0x0C, write=True, wdata=0xA0)
    oracle.apb_access(address=0x10, write=True, wdata=0x05)
    self.assertEqual(0xA5, oracle.apb_access(address=0x0C, write=False, wdata=0))
```

- [ ] **Step 2: Run the oracle tests and confirm they fail on missing module**

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_pulp_gpio_oracle -v`  
Expected: import failure for `pulp_gpio_oracle`.

- [ ] **Step 3: Implement the independent oracle**

Implement a cycle-stepped state model with literal APB request input and independent GPIO input history. Model only register and pin semantics supported by the recorded contract; where enabled, model the three input stages, group-of-four GPIOEN sampling, and exported `gpio_in_sync`/PADIN timing. Keep expected values independent of DUT pins and internal state. Mark source-derived-only behavior as a probe or `not_assessed`, never as an independently confirmed component guarantee.

- [ ] **Step 4: Run positive and refusal tests**

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_pulp_gpio_oracle -v`  
Expected: every literal expected value matches; invalid pin width, unsupported offset semantics, subword access, and malformed cycles refuse by stable reason.

- [ ] **Step 5: Commit the oracle**

```bash
git add src/myfuzz/composition/pulp_gpio_oracle.py tests/composition/test_pulp_gpio_oracle.py
git commit -m "feat: add independent PULP GPIO reference model"
```

## Task 2: Add the PULP pin-role RTL checker

**Interfaces:**

- Monitor inputs: clock/reset, actual accepted APB transaction, `gpio_in[31:0]`, `gpio_out[31:0]`, `gpio_dir[31:0]`, flattened `gpio_padcfg[127:0]`, `gpio_in_sync[31:0]`, `interrupt`.
- Monitor outputs: `eval_o[14:0]` pulse vector, `fail_o[14:0]` sticky vector, and bounded `first_fail_id_o`.
- The generated top maps monitor bit `k` to global bit `21+k` and exports the exact same mapping in checker manifest.

- [ ] **Step 1: Add a real-RTL positive and mutant bench**

Create a bench that instantiates the locked PULP RTL and the checker. It executes a hand-coded APB sequence, toggles selected GPIO inputs at specified cycles, and checks pin outputs. Mutant phases invert a PADOUT output, suppress an input sample, suppress the interrupt pulse, and retain INTSTATUS after a read.

```systemverilog
if (fail_o !== 15'b0) $fatal(1, "PULP GPIO golden trace failed: %h", fail_o);
force dut.gpio_out[3] = ~dut.gpio_out[3];
repeat (2) @(posedge clk_i);
if (!fail_o[3]) $fatal(1, "GPIO.PADOUT did not detect the pin mutant");
```

- [ ] **Step 2: Run the real RTL test to confirm the monitor is absent**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_pulp_gpio_checker -v`  
Expected: missing monitor source/test fixture failure.

- [ ] **Step 3: Implement all 15 GPIO property bits**

Drive shadow state only from accepted APB accesses and external `gpio_in`. Compute pin/sync expectations from the reference algorithm. Do not connect `soc_gpio_peer.sv`; its role signature is intentionally incompatible with PULP `padcfg` and `in_sync` fields. Keep pulse output observed only.

- [ ] **Step 4: Connect to the combined profile runtime**

Bind via endpoint roles (`gpio.bus`, `gpio.pins`), not fixed rendered wire names. Add monitor source to `source_list`, include its content hash in artifact provenance, and require all 15 evaluation bits to be seen in the targeted golden scenario. On a checker failure, set the global sticky bit and stop only the current testcase.

- [ ] **Step 5: Run real GPIO positive and negative acceptance**

Run: `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_pulp_gpio_checker -v`  
Expected: golden RTL passes; each enabled property has positive and targeted negative calibration; unsupported properties remain `not_assessed` with a reason; source-derived-only findings remain probes; all 15 reserved IDs appear in the final property map; GPIO pulse is never wired to Ibex IRQ.

- [ ] **Step 6: Commit GPIO checker and integration**

```bash
git add configs/soc/checkers/ibex_pulp_gpio_spi.json src/myfuzz/composition/pulp_gpio_oracle.py src/myfuzz/protocols/rtl/soc_pulp_gpio_checker.sv src/myfuzz/composition/soc_profile_renderer.py src/myfuzz/composition/soc_runtime.py tests/composition/test_pulp_gpio_oracle.py tests/integration/rtl/soc_pulp_gpio_checker_tb.sv tests/integration/test_soc_pulp_gpio_checker.py
git commit -m "feat: check PULP GPIO register and pin behavior"
```

## Verification commands

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_pulp_gpio_oracle tests.integration.test_soc_ibex_pulp_dual_profile -v
MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_pulp_gpio_checker -v
```

Expected: no checker failures on the golden trace; nonzero evaluation for all supported property IDs; source-derived properties without independent requirements are reported as probes, not confirmed component violations.
