# SoC peer 行为判据与端口边界实施计划（路线图阶段 2）

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development。每个 Task 由独立子代理实施，各自只写自己的新文件；共享源码 `src/myfuzz/composition/soc_peer_oracle.py` 由 Task 1 独占，其余 Task 不得修改它。

**Goal:** 为 UART/SPI/GPIO 三类 peer 的**已准入模式**各建独立正/负判据，把期望依据、peer RTL 内容哈希、实际事件与观测写进 replay；不声称支持的模式留 `not_assessed` 或在准入阶段拒绝。

**Architecture:** 保持 `soc_uart_peer.sv`/`soc_spi_peer.sv`/`soc_gpio_peer.sv` 与 `soc_peer_oracle.py` 的现有结构。工作集中在三处：(1) 修正 oracle 对 **raw 驱动帧**的期望来源；(2) 为 UART/SPI/GPIO 增加新的独立判据与线级证据；(3) 把判据依据与源内容哈希绑定进 replay，并让"改 peer 源/删线级轨迹"的负例无法输出 `pass`。

## Global Constraints

- 期望不得从被测外设或 peer 自己的成功计数推导。raw 驱动帧的期望必须来自 **(a) 测试自己写入的 raw 值**，或 **(b) 从 raw 输入独立解码出的事件**，不得来自 `peer_applied`/RTL 计数器。
- 未观测性质写 `not_assessed` 并给出具体 reason，不写 `pass`。
- 不使用按组件型号分支的代码；peer 选择仍由角色签名决定。
- 保留脏工作树。先写失败测试、观察失败、实现、真实 RTL 验证、再更新报告。

## 已确认的两个缺口（本阶段必须关闭）

1. **raw 驱动帧的 sent-count 判据错误。** `uart_tx_expectation` 的 `events` 取自 `sample.peer_events`；raw 驱动的帧在该列表里为空，于是 `completed_count=0`，而真实运行 `tx_sent_count_o=1`，oracle 报 `uart-tx-sent-count: mismatch`。这不是被测 RTL 的缺陷，是判据把两种驱动通道混为一谈。已被 `test_soc_input_real_rtl_gate.py::test_the_oracle_does_not_assess_the_raw_uart_route_and_says_so` 如实钉住。
2. **线级判据缺失。** `uart-rx-wire`、`uart-framing-wire`、`uart-timeout-wire`、`gpio-resolution-wire` 全部 `not_assessed`；SPI 只有单字四线判据。

---

## Task 1：raw 驱动通道的期望来源与 UART 帧判据

**Files：** 修改 `src/myfuzz/composition/soc_peer_oracle.py`（本 Task 独占）；新建 `tests/integration/test_soc_peer_uart_oracle.py`。

**Interfaces：** 新增纯函数
```python
def uart_raw_expectation(raw_values, layout, slots, *, cycles, data_width, baud_div, stop_bits) -> dict
```
它用 **`soc_peer_replay.decode_peer_raw_events`** 从 raw 记录独立解码事件，再交给现有 `uart_tx_expectation`。`audit_peer_run` 在 `sample.peer_events` 为空而 raw 记录携带该 slot 的 pulse 时改用它，并在 check 的 `note` 里写明期望来源是 raw 解码而非事件计划。

- [ ] **Step 1.1 失败测试。** 断言：raw 驱动一帧时 `uart-tx-sent-count` 为 `pass`（期望 1、观测 1），且 check 记录 `basis="soc_peer_oracle.v1:raw-decoded"`；事件计划驱动时仍走原路径；两者都为空时保持 `not_assessed`。先观察失败（当前是 `mismatch`）。
- [ ] **Step 1.2 实现。** `audit_peer_run` 需要拿到 raw 记录与 layout/slots。`RunResult` 已有 `trace`（逐周期 raw）与 `build.peer_slots`；layout 需要从 build 恢复——若 build 未携带 layout，则用 `slot["signals"]` 的 `raw_lo/raw_hi` 直接解码（`decode_peer_raw_events` 需要 layout 对象；如不可得，用等价的本地解码并注明理由）。不得为了拿 layout 修改 `soc_runtime.py`。
- [ ] **Step 1.3 新增 UART 帧判据。** 准入的接收/发送格式：起始位、数据位、可声明奇偶、停止位。用线级或总线级证据各建正/负判据：
  - 正例：`uart-rx-wire` 从组件 `uart_tx_o` 的逐周期采样重建一个完整帧，与「组件发出的字节 + 声明参数」逐位比对。
  - 负例：位翻转、错误停止位、错误波特（半周期偏移）必须 `mismatch`。
  - 缺线级轨迹时必须 `not_assessed`，不得 `pass`。
- [ ] **Step 1.4 跑绿** 并回归 `test_soc_peer_models`、`test_soc_spi_wire_oracle`、`test_soc_input_real_rtl_gate`。

**边界：** profile 声明了 oracle 不支持的模式（如非 8 位数据、2 停止位、奇偶校验）时，在准入阶段拒绝或标 `not_assessed`，不得用默认值近似。若运行时不提供逐周期 `uart_tx_o` 采样，Step 1.3 必须如实 `not_assessed` 并报告该环境缺口——不得用计数器伪造线级证据。

---

## Task 2：SPI 多字、连续 CS 与模式切换

**Files：** 新建 `tests/integration/test_soc_peer_spi_modes.py`；只读 `src/myfuzz/composition/soc_peer_oracle.py`（Task 1 在改它，本 Task 只读、不改）。

- [ ] **Step 2.1 冻结范围。** 明确首期准入：单字四线（已覆盖）、多字连续传输、连续 CS（一次 CS 拉低内多个字）、CPOL/CPHA 四种模式。对每种提供独立期望 + 完整轨迹 + 错误注入。
- [ ] **Step 2.2 失败测试。** 复用 `test_soc_spi_wire_oracle.py` 的 `spi_wire_verdict` 与 `soc_spi_peer.sv` 的真实运行（`tests/integration/test_soc_peer_models.py::SpiMode3PeerRuntimeTests` 是模式 1/1 的起点）。负例：多字之间 CS 抬高、字间时钟毛刺、位数不足、CPOL 反相。
- [ ] **Step 2.3 未准入模式写 `not_assessed`**，reason 具名。
- [ ] **Step 2.4 跑绿** 并回归 `test_soc_spi_wire_oracle`、`test_soc_peer_models`。

**边界：** 首期不宣称模式外的错误计数有正确性证明。

---

## Task 3：GPIO 输入/输出/使能/默认电平/contention 与 PULP `inout` 边界

**Files：** 新建 `tests/integration/test_soc_peer_gpio_contract.py`；只读 `src/myfuzz/composition/soc_peer_oracle.py`（Task 1 在改它）。

- [ ] **Step 3.1 失败测试（纯）。** 用现有 `gpio_resolution()` 独立电气契约逐项验证：输入采样、输出值、输出使能（`dir`）、默认电平（高/低）、contention 两种策略（`CONTENTION_IS_ERROR` 0/1）。每项正例 + 至少一个负例（错误的 dir、错误的默认电平、contention 未上报）。
- [ ] **Step 3.2 真实 RTL 验证。** 用 `test_soc_peer_models.py::GpioPeerRuntimeTests` 的既有夹具跑真实 `gpio.drive` 事件，断言 `pin_value_o`/`contention_o`/`contention_count_o`/`direction_o` 与独立契约一致。
- [ ] **Step 3.3 PULP GPIO 的真实 `inout`。** 在**生成阶段**拒绝没有电气解析模型的 `inout`/驱动冲突配置，不降级为随机单向线。写失败测试断言具名拒绝（在 `component_profile`/renderer 的准入处，找到现成的拒绝点并断言其 reason；若不存在则报告该缺口，不要在本 Task 新增源码）。
- [ ] **Step 3.4 跑绿。**

---

## Task 4：判据依据与源哈希写入 replay，删失轨迹负例不得 pass

**Files：** 新建 `tests/integration/test_soc_peer_replay_binding.py`；只读 `src/myfuzz/composition/soc_peer_oracle.py`、`soc_peer_replay.py`、`soc_failure_evidence.py`。

- [ ] **Step 4.1 失败测试。** 对 `soc_peer_oracle.v1` 记录断言：每个 check 带 `basis`（含期望来源）、peer RTL 源内容哈希进入 oracle 记录；`replay_package` 比较 oracle 与哈希。负例：(a) 改 peer 源文件 → replay 必须 `REPLAY_REFUSED` 或 oracle 哈希不匹配；(b) 删失线级轨迹（把 `peer_wire_trace` 清空、`peer_wire_status` 标 truncated）→ 相关 check 必须 `not_assessed`，整包不得输出 `pass`；(c) 篡改 oracle 记录 → 重放检测到。
- [ ] **Step 4.2 跑绿** 并回归 `test_soc_boundary_replay`、`test_soc_peer_models`。

---

## 验证命令

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_peer_uart_oracle \
  tests.integration.test_soc_peer_spi_modes \
  tests.integration.test_soc_peer_gpio_contract \
  tests.integration.test_soc_peer_replay_binding \
  tests.integration.test_soc_peer_models tests.integration.test_soc_spi_wire_oracle \
  tests.integration.test_soc_boundary_replay tests.integration.test_soc_input_real_rtl_gate
MYFUZZ_SOC_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest -q \
  tests.integration.test_soc_peer_models tests.integration.test_soc_peer_uart_oracle \
  tests.integration.test_soc_peer_spi_modes tests.integration.test_soc_peer_gpio_contract
git diff --check
```

## 验收

至少一个三类 peer 均在场的 SoC 能被 raw 输入改变、运行并重放；每个声称支持的行为都有独立正/负判据，其他行为有具名 `not_assessed` 或准入拒绝记录。

## 环境记录

- 项目 Verilator：`/home/qinkejiu/.local/bin/verilator` 5.051（sha256 `fb2cc573…fcdf`）。
- Icarus：`/home/qinkejiu/.local/bin/iverilog` 14.0（sha256 `9b3f0a69…be6a`）。
- 官方 RFuzz 客户端与 bundled Verilator 5.020：阶段 4 处理，不属于本阶段门槛。
