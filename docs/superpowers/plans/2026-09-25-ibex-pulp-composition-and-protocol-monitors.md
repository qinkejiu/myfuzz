# Ibex + PULP 组合与协议检查器实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: use `executing-plans` to implement this plan task-by-task. Steps use checkbox syntax.

**Goal:** 新增真实 Ibex + PULP GPIO + PULP SPI 组合，并让 OBI、APB3 和 fabric 契约错误进入 RFuzz 覆盖反馈。

**Architecture:** 继续使用 profile composition 和现有 RFuzz ABI。新增 checker profile 将稳定 property ID 映射到 sidecar RTL monitor；生成 top 暴露 evaluation/failure 位，persistent runtime 将其按普通反馈位采样，保持 RTL coverage 与 checker feedback 可区分。

**Tech Stack:** Python 3、SystemVerilog、Verilator 5.020、官方 `kfuzz` protocol-2、unittest。

## Global Constraints

- CPU 为 profile 声明的 RV32IMC Ibex；GPIO 参数 `PAD_NUM=32`；SPI 参数 `BUFFER_DEPTH=10`。
- GPIO/SPI 使用 APB3、12 位 target address、32 位数据、4 KiB 对齐 MMIO 窗口；两个窗口不重叠。
- 时钟为单域；复位为异步低有效；两个 PULP target 的 `PREADY=1`、`PSLVERR=0`。
- Verilator RFuzz 构建使用仓库固定的 bundled 5.020；不得依赖在 Verilator 下被清空的 vendor `ASSERT` 宏。
- 不修改 vendor RTL；没有独立规范依据的 source-derived 观察不得升级为已确认组件 bug。
- campaign 的长跑门槛为至少 600 秒，且必须保留 corpus、receipt、replay 和 cleanup 证据。

---

## Scope and dependency order

这是四份子计划中的第一份。先完成本计划的 composition、checker manifest 和共享反馈通道，再依次执行 [GPIO 检查器计划](2026-09-25-pulp-gpio-checker.md)、[SPI 检查器计划](2026-09-25-pulp-spi-checker.md)，最后执行 [Ibex reference 与 RFuzz campaign 计划](2026-09-25-ibex-rvfi-rfuzz-campaign.md)。后两份 checker 可分别验收，但都依赖本计划定义的 property bit ABI。

本项目第一批预留 50 个稳定 property ID。当前尚无任何实现；这不代表已经写好 50 条断言。每项只有在存在独立契约依据、绑定了真实信号并通过正向/变异校准后才可启用。否则保留 ID 并标记 `not_assessed`，不参加 pass/fail；不得为了凑数保留假断言。

| Bit | Property ID | 判据 |
| ---: | --- | --- |
| 0 | `OBI.INSTR.STALL_STABLE` | instruction request 未 grant 时 payload 保持稳定 |
| 1 | `OBI.INSTR.NO_ORPHAN_RSP` | instruction response 必须有已 grant 请求 |
| 2 | `OBI.INSTR.RESPONSE_ORDER` | instruction response 按接口顺序退休 |
| 3 | `OBI.DATA.STALL_STABLE` | data request 未 grant 时 payload 保持稳定 |
| 4 | `OBI.DATA.NO_ORPHAN_RSP` | data response 必须有已 grant 请求 |
| 5 | `OBI.DATA.RESPONSE_ORDER` | data response 按接口顺序退休 |
| 6 | `APB.GPIO.SETUP_ACCESS` | GPIO APB 先 setup 后 access |
| 7 | `APB.GPIO.WAIT_STABLE` | GPIO access wait 时控制载荷稳定 |
| 8 | `APB.GPIO.READY_ONE` | GPIO target 持续 ready |
| 9 | `APB.GPIO.ERROR_ZERO` | GPIO target 不报告 slave error |
| 10 | `APB.SPI.SETUP_ACCESS` | SPI APB 先 setup 后 access |
| 11 | `APB.SPI.WAIT_STABLE` | SPI access wait 时控制载荷稳定 |
| 12 | `APB.SPI.READY_ONE` | SPI target 持续 ready |
| 13 | `APB.SPI.ERROR_ZERO` | SPI target 不报告 slave error |
| 14 | `FABRIC.SELECT_UNIQUE` | MMIO 地址只能选中计划中的唯一 target |
| 15 | `FABRIC.RESPONSE_SOURCE` | 响应返回发起该事务的 master lane |
| 16 | `RVFI.ORDER` | RVFI order 连续且不重复 |
| 17 | `RVFI.FETCH_IMAGE` | 退休 PC/指令与冻结镜像一致 |
| 18 | `RVFI.SPIKE_STEP` | 每笔退休结果与 Spike reference 一致 |
| 19 | `RVFI.MEMORY_TRANSACTION` | RVFI memory commit 与已接受 CPU 总线事务一致 |
| 20 | `RVFI.TRAP_POLICY` | trap 符合 campaign 声明的策略 |
| 21 | `GPIO.RESET_STATE` | profile 支持的 GPIO reset 状态正确 |
| 22 | `GPIO.PADDIR` | PADDIR 写入/读回一致 |
| 23 | `GPIO.GPIOEN` | GPIOEN 写入/读回一致 |
| 24 | `GPIO.PADOUT` | PADOUT 写入/读回一致 |
| 25 | `GPIO.PADOUTSET` | PADOUTSET 仅置位指定 pin |
| 26 | `GPIO.PADOUTCLR` | PADOUTCLR 仅清除指定 pin |
| 27 | `GPIO.PADCFG` | PADCFG 写入/输出一致 |
| 28 | `GPIO.SYNC_ENABLE_GROUP` | GPIOEN 按 4-pin group 控制采样 |
| 29 | `GPIO.IN_SYNC` | gpio_in_sync 与独立输入延迟模型一致 |
| 30 | `GPIO.PADIN` | PADIN 与独立输入延迟模型一致 |
| 31 | `GPIO.DIR_OUTPUT` | gpio_out 与 gpio_dir 逐位匹配 |
| 32 | `GPIO.INTERRUPT_EVENT` | interrupt pulse 与已配置输入事件匹配 |
| 33 | `GPIO.INTSTATUS_LATCH` | INTSTATUS latch 符合契约 |
| 34 | `GPIO.INTSTATUS_READ_CLEAR` | INTSTATUS 读清行为符合契约 |
| 35 | `GPIO.CONCURRENT_EVENT_PRIORITY` | 并发新事件的优先级符合契约 |
| 36 | `SPI.RESET_IDLE` | SPI reset 后 SCK/CS/FIFO idle |
| 37 | `SPI.CLKDIV_READBACK` | CLKDIV 写入/读回一致 |
| 38 | `SPI.TXFIFO_PUSH` | TXFIFO full-word write 恰好 push 一项 |
| 39 | `SPI.RXFIFO_POP` | RXFIFO full-word read 恰好 pop 一项 |
| 40 | `SPI.STATUS_READBACK` | STATUS 与独立 FIFO/控制状态一致 |
| 41 | `SPI.CS_WINDOW` | CS0 在一笔传输期间正确有效 |
| 42 | `SPI.SCK_IDLE_MODE0` | mode 0 的 SCK idle 为低 |
| 43 | `SPI.MODE0_EDGE_COUNT` | SCK 采样/移位边沿数量正确 |
| 44 | `SPI.MOSI_MSB_FIRST` | MOSI 以 MSB-first 发送 TXFIFO 数据 |
| 45 | `SPI.MISO_TO_RXFIFO` | MISO 采样值进入预期 RXFIFO 字 |
| 46 | `SPI.STD_LANES` | 标准单线 mode 下使用正确 lane |
| 47 | `SPI.EOT_PULSE` | end-of-transfer event pulse 符合宽度契约 |
| 48 | `SPI.INTSTA_READ_REARM` | INTSTA read/rearm 只在有契约依据时判定 |
| 49 | `SPI.FIFO_DEPTH_BOUND` | FIFO 状态不越过声明深度 10 |

## File map

- Create `examples/soc_generation/request-ibex-pulp-gpio-spi.json`: 固定本期 CPU、外设、memory、clock/reset 和 test modes。
- Create `configs/soc/checkers/ibex_pulp_gpio_spi.json`: checker schema、50 个 bit 到 property ID 的映射、来源类别和适用参数。
- Create `src/myfuzz/composition/soc_checker_profile.py`: 验证 checker manifest、ID 唯一性、bit 连续性、target/role 绑定和哈希。
- Create `src/myfuzz/protocols/rtl/soc_obi_checker.sv`, `soc_apb3_checker.sv`, `soc_fabric_checker.sv`: 独立边界 monitor。
- Modify `src/myfuzz/composition/soc_profile_renderer.py`: 按 checker profile 预留 `checker_eval_o[49:0]` 与 sticky `checker_fail_o[49:0]` ABI；未安装 monitor 的位保持低。
- Modify `src/myfuzz/composition/soc_structure_audit.py`: accept only the two checker outputs explicitly declared by the loaded checker profile while preserving exact-port validation for every other port.
- Modify `src/myfuzz/composition/soc_runtime.py`: 把当前已启用 checker 位纳入 persistent testbench 观测和每个 testcase 的首违例 evidence。
- Modify `src/myfuzz/integration/soc_builder.py` and `src/myfuzz/integration/rfuzz_simulator.py`: 后续各 monitor task 分别加入自己的 RTL source；这里先记录 checker bit map/hash，并保留 checker feedback 标签。
- Create `tests/integration/test_soc_ibex_pulp_dual_profile.py`, `tests/composition/test_soc_checker_profile.py`, `tests/integration/rtl/soc_protocol_checkers_tb.sv`。
- Modify `tests/composition/test_soc_structure_audit.py`: verify checker outputs are admitted only at the declared 50-bit width and undeclared/wrong-width ports still fail audit.

## Task 1: Declare and compose both real PULP targets

**Files:**

- Create: `examples/soc_generation/request-ibex-pulp-gpio-spi.json`
- Create: `tests/integration/test_soc_ibex_pulp_dual_profile.py`
- Test: `tests/integration/test_soc_ibex_pulp_dual_profile.py`

**Interfaces:**

- `load_composition_request(document, profiles=profiles)` consumes three existing component profiles.
- `build_composition(request, base_dir=ROOT, drive_profile="cpu_execute")` produces the plan used by all later tasks.
- The request includes `cpu_only`, `mmio_only`, and `mixed`; declaring a mode is not acceptance evidence for that mode.

- [ ] **Step 1: Write the failing composition test**

```python
def load_dual_request():
    path = ROOT / "examples/soc_generation/request-ibex-pulp-gpio-spi.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    profiles = {}
    profile_paths = [document["cpu"]["profile"]] + [
        item["profile"] for item in document["peripherals"]]
    for profile_path in profile_paths:
        profile = load_component_profile(ROOT / profile_path)
        profiles[profile_path] = profile
        profiles.setdefault(profile.component_id, profile)
    return load_composition_request(document, profiles=profiles)

def test_request_composes_ibex_and_both_pulp_targets(self):
    request = load_dual_request()
    plan = build_composition(request, base_dir=ROOT, drive_profile="cpu_execute")
    self.assertEqual({"cpu0", "gpio0", "spi0"},
                     {instance.instance_id for instance in plan.instances})
    windows = {item["target_id"]: item
               for item in plan.plan["address_map"]["windows"]}
    gpio = windows["gpio0_win"]
    spi = windows["spi0_win"]
    self.assertEqual(4096, gpio["size"])
    self.assertEqual(4096, spi["size"])
    base_a, size_a = gpio["base"], gpio["size"]
    base_b, size_b = spi["base"], spi["size"]
    self.assertTrue(base_a + size_a <= base_b or base_b + size_b <= base_a)
```

- [ ] **Step 2: Run the new test and confirm the request is absent**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_pulp_dual_profile -v`
Expected: FAIL with the missing request path, not a skipped test.

- [ ] **Step 3: Add the composition request**

Copy the memory, address-policy, clock, reset, and Ibex declarations from `examples/soc_generation/request-ibex-pulp-spi.json`; add `gpio0` using `configs/peripherals/pulp_gpio/component_profile.json`; keep both peripheral windows at the profile-required 4 KiB alignment; declare all three modes; do not add pulse IRQ routes.

- [ ] **Step 4: Verify profile and structure invariants**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_ibex_pulp_dual_profile -v`
Expected: composition has one CPU, two APB3 targets, non-overlapping windows, no GPIO/SPI interrupt route, and deterministic `plan_hash` on a second build.

- [ ] **Step 5: Commit the request and test**

```bash
git add examples/soc_generation/request-ibex-pulp-gpio-spi.json tests/integration/test_soc_ibex_pulp_dual_profile.py
git commit -m "feat: compose Ibex with PULP GPIO and SPI"
```

## Task 2: Define the checker manifest and feedback ABI

**Files:**

- Create: `configs/soc/checkers/ibex_pulp_gpio_spi.json`
- Create: `src/myfuzz/composition/soc_checker_profile.py`
- Create: `tests/composition/test_soc_checker_profile.py`
- Modify: `src/myfuzz/composition/soc_profile_renderer.py`
- Modify: `src/myfuzz/composition/soc_runtime.py`
- Modify: `src/myfuzz/integration/soc_builder.py`
- Modify: `src/myfuzz/integration/rfuzz_simulator.py`

**Interfaces:**

`CheckerProperty` 是 frozen dataclass，字段为 `bit: int`、`property_id: str`、`status: str` (`active` 或 `not_assessed`)、`owner: str | None`、`binding: str | None`、`basis_kind: str | None`、`basis: str`、`reason: str | None`。`CheckerProfile` 是 frozen dataclass，字段为 `schema_version: str`、`request_id: str`、`properties: tuple[CheckerProperty, ...]`、`profile_hash: str`。公开入口为 `load_checker_profile(document: Mapping[str, object], plan: CompositionPlan) -> CheckerProfile`。

The loader returns an immutable ordered tuple of 50 reserved properties plus a content hash. Generated top exports `checker_eval_o[49:0]` as one-cycle evaluation bits and `checker_fail_o[49:0]` as sticky testcase failure bits. An active property must have a real signal binding and evidence basis; a `not_assessed` property has no failure binding and must keep its evaluation bit low. Each campaign arm reports its required evaluated subset; it must not require properties that its drive mode cannot exercise.

- [ ] **Step 1: Write failing manifest contract tests**

```python
def test_manifest_rejects_duplicate_ids_and_non_contiguous_bits(self):
    document = checker_document()
    document["properties"][1]["property_id"] = document["properties"][0]["property_id"]
    with self.assertRaisesRegex(CheckerProfileError, "property-id-duplicate"):
        load_checker_profile(document, composition_plan())
```

Also add tests for unknown target IDs, duplicate bits, unknown `basis_kind`, wrong checker bus widths, missing property records, and stable canonical hash.
Add an `active` case with a valid binding and an invalid empty binding; add a `not_assessed` case with a stable reason and no binding. Verify the reserved ID remains in the 50-ID map while its evaluation bit stays low and it cannot produce a pass/fail claim.

- [ ] **Step 2: Run the tests and confirm the loader is missing**

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_soc_checker_profile -v`
Expected: import failure for `soc_checker_profile`.

- [ ] **Step 3: Implement the strict manifest loader**

Accept only schema `soc_checker_profile.v1`, the exact request ID `ibex-pulp-gpio-spi`, unique IDs, unique bit positions `0..49`, known owners (`cpu0`, `fabric`, `gpio0`, `spi0`), and basis kinds `standard`, `independent_reference`, `source_derived`. An `active` record requires a valid owner, nonempty signal binding, and evidence basis; a `not_assessed` record requires a stable reason and has no active binding. Reject malformed combinations. Use `canonical_bytes` and SHA-256 for the profile hash.

- [ ] **Step 4: Wire monitor outputs into the real campaign artifact**

Render the fixed-width checker ports in the profile top. In this bootstrap task, every not-yet-implemented property is `not_assessed`, its evaluation bit remains low, and no checker RTL module is referenced. Include the manifest and hash in artifact provenance and validate that the existing sampled-output event counters can carry separately named checker evaluation/failure observations. Each later monitor task adds only its own RTL sources and replaces its assigned low placeholder bits with real bindings. Keep branch coverage and checker feedback separately named in the report.

- [ ] **Step 5: Run composition and manifest tests**

Run: `PYTHONPATH=src:. python3 -m unittest tests.composition.test_soc_checker_profile tests.composition.test_soc_structure_audit tests.integration.test_soc_ibex_pulp_dual_profile -v`
Expected: both tests pass; changing one property ID changes the checker profile and artifact identity.

- [ ] **Step 6: Commit the checker ABI**

```bash
git add configs/soc/checkers/ibex_pulp_gpio_spi.json src/myfuzz/composition/soc_checker_profile.py src/myfuzz/composition/soc_profile_renderer.py src/myfuzz/composition/soc_structure_audit.py src/myfuzz/composition/soc_runtime.py src/myfuzz/integration/soc_builder.py src/myfuzz/integration/rfuzz_simulator.py tests/composition/test_soc_checker_profile.py tests/composition/test_soc_structure_audit.py
git commit -m "feat: add SoC checker feedback ABI"
```

## Task 3: Implement and calibrate OBI, APB3 and fabric properties

**Files:**

- Create: `src/myfuzz/protocols/rtl/soc_obi_checker.sv`
- Create: `src/myfuzz/protocols/rtl/soc_apb3_checker.sv`
- Create: `src/myfuzz/protocols/rtl/soc_fabric_checker.sv`
- Create: `tests/integration/rtl/soc_protocol_checkers_tb.sv`
- Create: `tests/integration/test_soc_protocol_checkers.py`
- Modify: `configs/soc/checkers/ibex_pulp_gpio_spi.json` — activate only calibrated protocol/fabric properties and retain unsupported IDs as `not_assessed`.
- Modify: `src/myfuzz/composition/soc_profile_renderer.py`

**Property IDs:** reserved bits `0..15` from the manifest table: six OBI, eight target-specific APB3, and two fabric properties. Activate only properties that the real boundary exposes and the declared contract supports; leave unobservable response-order properties `not_assessed` instead of inferring them from transaction counts.

**Interfaces:**

- `soc_obi_checker` accepts one request/grant/response channel, address, data, byte-enable, write, and error signals; it exposes local `eval_o` and `fail_o[2:0]` for stall stability, orphan response, and ordering.
- `soc_apb3_checker` accepts `PSEL/PENABLE/PREADY/PADDR/PWRITE/PWDATA/PRDATA/PSLVERR`; it exposes four evaluation/failure properties.
- `soc_fabric_checker` accepts the composed MMIO address, target select vector, request source ID, response source ID, and response handshake.
- All monitors use sequential state and case inequality so they compile in bundled Verilator without vendor SVA macros.

- [ ] **Step 1: Add positive and mutant RTL tests**

The positive bench drives: OBI request held stable until grant, one response for each accepted request, APB SETUP then ACCESS, and unique fabric selection. Negative phases independently change a stalled address, inject an orphan response, skip APB SETUP, change APB payload while waiting, assert target `PSLVERR`, and select both targets. Each phase checks its exact property bit.

```systemverilog
if (checker_fail_o[0] !== 1'b0) $fatal(1, "good OBI trace failed");
drive_stalled_address_mutant();
if (!checker_fail_o[0]) $fatal(1, "OBI.INSTR.STALL_STABLE did not fire");
```

- [ ] **Step 2: Run the RTL test and confirm the checker modules are absent**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_protocol_checkers -v`
Expected: test fails because the monitor source files do not exist.

- [ ] **Step 3: Implement the three monitors**

Implement the supported subset of manifest properties exactly as named. The OBI outstanding counter changes only on request/grant and response handshakes; response-before-grant and FIFO underflow set sticky failure. Do not claim response ordering from counts alone if the observed boundary has no response tag or independent expected-response queue; leave that ID `not_assessed`. APB only completes on `PSEL && PENABLE && PREADY`; wait stability compares the previous ACCESS payload. The fabric checker evaluates target select at the accepted request and compares the recorded owner at response.

- [ ] **Step 4: Integrate checker binding and run positive/negative tests**

Run: `PYTHONPATH=src:. python3 -m unittest tests.integration.test_soc_protocol_checkers tests.integration.test_soc_ibex_pulp_dual_profile -v`
Expected: golden traces produce zero failure bits and nonzero evaluation bits for every enabled property; each supported single-fault mutant triggers exactly its assigned bit; unsupported/unobservable properties remain `not_assessed`; checker outputs appear in the rendered source and manifest identity.

- [ ] **Step 5: Commit the protocol monitors**

```bash
git add configs/soc/checkers/ibex_pulp_gpio_spi.json src/myfuzz/protocols/rtl/soc_obi_checker.sv src/myfuzz/protocols/rtl/soc_apb3_checker.sv src/myfuzz/protocols/rtl/soc_fabric_checker.sv src/myfuzz/composition/soc_profile_renderer.py tests/integration/rtl/soc_protocol_checkers_tb.sv tests/integration/test_soc_protocol_checkers.py
git commit -m "feat: monitor OBI APB3 and fabric contracts"
```

## Verification commands

```bash
PYTHONPATH=src:. python3 -m unittest tests.composition.test_soc_checker_profile tests.integration.test_soc_ibex_pulp_dual_profile tests.integration.test_soc_protocol_checkers -v
git diff --check
```

Expected: all targeted tests pass, `checker_fail_o` remains zero on the golden trace, and the named negative trace sets the matching sticky bit without terminating the process.
