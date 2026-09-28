# PULP SPI 独立检查器实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: use `executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** 为真实 PULP APB SPI master 增加兼容其 4-lane pin roles 的 mode-0 peer、寄存器/FIFO scoreboard 和独立线级判据。

**Architecture:** 添加一个 role-signature 明确覆盖全部 PULP SPI pins 的 profile peer，首期只启用标准单线 mode 0。peer 根据 RFuzz arm 事务驱动 `spi_sdi1`，checker 独立解码 SCK/CS/MOSI/MISO 轨迹并与已接受的 APB TXFIFO/RXFIFO 事务比较。

**Tech Stack:** SystemVerilog peer/monitor、Python wire oracle、Verilator 5.020、现有 peer plan/replay/RFuzz layout。

## Global Constraints

- 仅覆盖锁定 PULP `apb_spi_master`，`BUFFER_DEPTH=10`、`APB_ADDR_WIDTH=12`、APB3 32-bit full-word。
- 首期只覆盖单线 mode 0、MSB-first、CS0、有限长度传输；不覆盖 quad/QPI、DMA 或其它参数值。
- MISO 接 `spi_sdi1`，MOSI 取 `spi_sdo0`；其它 lane 均显式绑定并观测，不允许悬空。
- `events_o` 是 pulse 并只观测，不接 level-only IRQ controller；vendor RTL 不改写。
- 每个启用 property 都记录可审阅的行为依据；`source_derived` 检查结果只标为 probe，不能单独确认 PULP IP 缺陷。
- checker property 位复用基础 plan 的 `checker_eval_o[49:0]`/`checker_fail_o[49:0]`；SPI bit 为 36–49。

---

## Dependency and property IDs

先执行 [组合与协议检查器计划](2026-09-25-ibex-pulp-composition-and-protocol-monitors.md)。本计划实现 bit 36–49：

`SPI.RESET_IDLE`, `SPI.CLKDIV_READBACK`, `SPI.TXFIFO_PUSH`, `SPI.RXFIFO_POP`, `SPI.STATUS_READBACK`, `SPI.CS_WINDOW`, `SPI.SCK_IDLE_MODE0`, `SPI.MODE0_EDGE_COUNT`, `SPI.MOSI_MSB_FIRST`, `SPI.MISO_TO_RXFIFO`, `SPI.STD_LANES`, `SPI.EOT_PULSE`, `SPI.INTSTA_READ_REARM`, `SPI.FIFO_DEPTH_BOUND`。

## File map

- Create: `src/myfuzz/protocols/rtl/soc_pulp_spi_peer.sv` — 4-lane role-compatible deterministic peer。
- Create: `src/myfuzz/protocols/rtl/soc_pulp_spi_checker.sv` — property bits 36–49。
- Create: `src/myfuzz/composition/pulp_spi_oracle.py` — strict mode-0 trajectory decoder/reference。
- Modify: `src/myfuzz/composition/soc_peer_plan.py`, `soc_profile_renderer.py`, `soc_runtime.py`, `soc_peer_replay.py` — role matching, raw arm ABI, pin mapping and replay trace.
- Create: `tests/composition/test_pulp_spi_oracle.py`, `tests/integration/rtl/soc_pulp_spi_peer_tb.sv`, `tests/integration/test_soc_pulp_spi_checker.py`。
- Modify: `configs/soc/checkers/ibex_pulp_gpio_spi.json` — activate only calibrated SPI properties; keep unsupported/source-derived-only behavior `not_assessed` or probe-labeled.

## Task 1: Add the PULP peer role signature and raw ABI

**Interfaces:**

The peer's declared role signature is exactly the PULP `spi.pins` endpoint: output `sck`, `csn0..3`, `mode`, `sdo0..3`; input `sdi0..3`. The runtime raw arm field is `spi_arm_word[31:0]` plus `spi_arm_valid`; only one frame may be armed for a transfer. `sdi1` is driven by the peer; inactive SDI lanes use declared zero constants.

- [ ] **Step 1: Add failing role match and refusal tests**

Extend `tests/integration/test_soc_peer_models.py` with one exact PULP signature match, a missing-lane refusal, a duplicate-model ambiguity refusal, and proof that name changes do not alter selection.

```python
def test_pulp_spi_role_signature_selects_the_pulp_peer(self):
    self.assertEqual(("pulp_spi",), tuple(model.peer_id for model in match_models(PULP_SPI_FIELDS)))
```

- [ ] **Step 2: Run role tests and confirm no PULP peer matches**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_peer_models.PeerModelMatchTests -v`  
Expected: exact-match test fails with `peer-role-unsupported`.

- [ ] **Step 3: Declare peer model and add the 4-lane RTL peer**

Add a `PULP_SPI_PEER` declaration in `src/myfuzz/composition/soc_peer_plan.py` and implement `soc_pulp_spi_peer.sv`. The peer checks `spi_mode==2'b00` while selected, shifts the armed 32-bit response MSB-first at the mode-0 boundary, and exports arm/shift/selection observations. It does not inspect PULP internal signals.

- [ ] **Step 4: Run role plan, rendering, and input-layout tests**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_peer_models tests.integration.test_soc_profile_rfuzz_build -v`  
Expected: the new peer's arm fields are in combined input layout, all 14 output lanes/signals have an audited disposition, and only the specified SDI lane is peer-driven.

- [ ] **Step 5: Commit role and ABI support**

```bash
git add src/myfuzz/composition/soc_peer_plan.py src/myfuzz/composition/soc_profile_renderer.py src/myfuzz/composition/soc_runtime.py src/myfuzz/protocols/rtl/soc_pulp_spi_peer.sv tests/integration/test_soc_peer_models.py
git commit -m "feat: add a role-compatible PULP SPI peer"
```

## Task 2: Add an independent wire and transaction oracle

**Interfaces:**

Public oracle API: `audit_pulp_spi_run(*, apb_transactions: Sequence[Mapping[str, object]], peer_arms: Sequence[Mapping[str, object]], wire_trace: Sequence[Mapping[str, object]], rx_reads: Sequence[Mapping[str, object]], parameters: Mapping[str, int]) -> dict[str, object]`.

The function uses accepted APB TXFIFO writes as the expected MOSI words and the independently recorded peer arm as expected MISO words. It rejects a trace that is truncated, lacks arm evidence, has wrong parameters, has partial writes, or cannot associate an RXFIFO read; it returns `not_assessed` with a stable reason rather than treating missing evidence as pass.

- [ ] **Step 1: Write failing literal-vector decoder tests**

Test valid mode-0 MSB-first transfer; inverted edge; wrong CS; wrong lane; altered MOSI bit; altered MISO bit; short frame; missing peer arm; and RXFIFO value mismatch. Every expected word is a test literal, not derived from the DUT or peer counters.

- [ ] **Step 2: Run oracle tests and confirm the module is absent**

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_pulp_spi_oracle -v`  
Expected: import failure for `pulp_spi_oracle`.

- [ ] **Step 3: Implement strict decoder and evidence result**

Reuse only the independent edge-sampling algorithm from `soc_peer_oracle.spi_wire_expectation`; constrain it to `CPOL=0`, `CPHA=0`, MSB-first, and PULP pin mapping. Validate complete CS/SCK/MOSI/MISO samples and exact APB-to-wire-to-RXFIFO association. Preserve profile/source identity and return verdict, property IDs, and `not_assessed` reason.

- [ ] **Step 4: Run all positive/negative vectors**

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_pulp_spi_oracle -v`  
Expected: all valid literals pass; each single-bit/edge/lane mutant maps to its expected property; incomplete traces refuse.

- [ ] **Step 5: Commit the oracle**

```bash
git add src/myfuzz/composition/pulp_spi_oracle.py tests/composition/test_pulp_spi_oracle.py
git commit -m "feat: add independent PULP SPI wire oracle"
```

## Task 3: Monitor PULP SPI and calibrate against real RTL

**Files:**

- Create: `src/myfuzz/protocols/rtl/soc_pulp_spi_checker.sv`
- Create: `tests/integration/rtl/soc_pulp_spi_peer_tb.sv`
- Create: `tests/integration/test_soc_pulp_spi_checker.py`
- Modify: `src/myfuzz/composition/soc_peer_replay.py`, `soc_profile_renderer.py`, `soc_runtime.py`

- [ ] **Step 1: Add a real PULP mode-0 golden trace and five mutants**

The bench configures one TXFIFO word, arms one MISO word, starts a finite transfer, checks CS0/SCK/wire/RXFIFO, then repeats with SPI lane, edge, data, EOT-pulse, and FIFO-boundary mutants. The golden case must reach every enabled property. Any property whose independent normative basis is unavailable, including conditional `SPI.INTSTA_READ_REARM`, stays `not_assessed` and is not counted as evaluated.

- [ ] **Step 2: Run the real RTL test and confirm the checker is missing**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_pulp_spi_checker -v`  
Expected: missing checker/peer source failure.

- [ ] **Step 3: Implement checker bits 36–49 and replay binding**

Shadow APB-visible register/FIFO state from accepted transactions; decode only public pins for serial expectations. Record a bounded complete trace and raw peer arm identity. Do not assert that `spi_swrst` resets controller FSM. Feed sticky mismatches into the global checker bit vector and retain each raw testcase.

- [ ] **Step 4: Run PULP checker real-RTL acceptance**

Run: `MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_pulp_spi_checker -v`  
Expected: one golden transfer returns the independently armed RX word; every enabled bit evaluates; each mutant triggers its calibrated failure mask; unsupported properties and a missing arm return `not_assessed`; source-derived-only findings remain probes.

- [ ] **Step 5: Commit the SPI checker**

```bash
git add configs/soc/checkers/ibex_pulp_gpio_spi.json src/myfuzz/composition/pulp_spi_oracle.py src/myfuzz/protocols/rtl/soc_pulp_spi_checker.sv src/myfuzz/protocols/rtl/soc_pulp_spi_peer.sv src/myfuzz/composition/soc_peer_replay.py src/myfuzz/composition/soc_profile_renderer.py src/myfuzz/composition/soc_runtime.py tests/composition/test_pulp_spi_oracle.py tests/integration/rtl/soc_pulp_spi_peer_tb.sv tests/integration/test_soc_pulp_spi_checker.py tests/integration/test_soc_peer_models.py
git commit -m "feat: check PULP SPI transfers against an independent peer"
```

## Verification commands

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_pulp_spi_oracle tests.integration.test_soc_peer_models -v
MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_pulp_spi_checker -v
```

Expected: PULP role signature is admitted without name-based selection; the actual pinned component and peer complete a fully recorded mode-0 transfer; no IRQ connection is generated.
