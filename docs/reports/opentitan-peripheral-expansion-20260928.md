# OpenTitan 外设扩展实测记录

日期：2026-09-28。范围按用户选择的顺序为 SPI Host → I2C → RV Timer。三种 IP 均使用本地固定版本的真实 OpenTitan RTL、独立持久进程和原生 TL-UL 接口；Ibex 在另一独立进程中运行。跨组件只路由真实 MMIO 事务、中断和返回数据，没有生成 Bus、Crossbar、Bridge、PLIC 或全局精确周期 SoC。

## 已接入的边界与输入所有权

| IP | Fuzzable Source | Bound Input / 真实结果 | 首期本地模式 |
|---|---|---|---|
| SPI Host | 每轮外部 peer 的四字节 MISO payload；CPU 程序与初始内存 | Host 的 SCK/CS/使能控制 peer 消耗位；真实 `RXDATA` 经 MMIO 返回 CPU；真实 `intr_spi_event_o` 送 CPU | NumCS=1，标准单线，CPOL=CPHA=0 |
| I2C | 每轮外部 target 的应答数据；CPU 程序与初始内存 | 真实开漏 SCL/SDA 使能与 peer 解析为总线电平；真实 `RDATA` 返回 CPU；`cmd_complete` IRQ 第 9 位送 CPU | Controller 模式，地址 `0x50`，单 target，无 stretch 的实测路径 |
| RV Timer | CPU 程序与初始内存；此 IP 无外部 fuzzable pin | CPU 真实写配置/比较值；真实 Timer IRQ 送 CPU；真实计数/状态读回 | hart0/timer0 |

会话只接受声明的环境端口。附着 peer 后，SPI MISO 和 I2C 线电平不能再由 Fuzzer 覆盖。两个串行 peer 都由真实 RTL 引脚逐本地周期推进；SPI pad 关闭时不会把 RTL 的原始 SCK/CS 当成外部可见活动。`pending_events` 来自真实 RTL 活动/FIFO 状态观察；SPI 的 CSAAT 保持 CS 有效时也继续算作未完成。命令通道使用 execution ID 与 sequence ID 幂等回放；重复命令不会重复推进 RTL。

## 源码身份

三种 IP 均锁定 `git:fca045df919a26c47e71616b9dac917b1ea4fd07` 的本地 OpenTitan 源码。component profile、实际 Verilator 读入闭包及源码锁位于 `configs/peripherals/`、`configs/soc/closures/`、`configs/soc/sources.lock.json`。

| IP | 有序编译输入 | 已记录的实际读入文件 | 本地 RTL 结果 |
|---|---:|---:|---|
| SPI Host | 68 | 73 | Verilator 构建、两轮接收通过 |
| I2C | 67 | 79 | Verilator 构建、两轮读取通过 |
| RV Timer | 58 | 63 | Verilator 构建、两轮中断通过 |

闭包测试和 Verilator read-set replay 检查了实际依赖。新闭包 JSON 尚未纳入 Git 跟踪，因此完整 source-lock verifier 的 tracked-evidence 门槛仍给出 `untracked-elaboration-evidence` / `elaboration_unverified`；这不影响已运行的 RTL 构建和行为测试，但在提交这些新文件前不能声称正式源码锁验收完成。

## 连续 testcase 的实测链

1. **SPI Host**：Ibex 真实写 CONTROL、CONFIGOPTS、EVENT_ENABLE、INTR_ENABLE 和两次 COMMAND。外部 peer 的两轮 payload 只在 Host 真实选中 CS 并产生 64 个采样边沿时被消耗。Host 真实 RXDATA 为 `0x78563412`、`0xf00f5aa5`，真实状态 IRQ 触发 CPU ISR；CPU 分别把同样的字写入持久 RAM `0x200`、`0x204`。FIFO 读取后 IRQ 解除，中途没有 reset。RFuzz 的一条 8 字节记录把第一轮外部源从 `0x78563412` 变异为 `0x78563413` 后，真实 RXDATA 与 CPU RAM 的第一字同步改变；切断 IRQ 后路径变为 `path_incomplete`，没有对应 RAM 收据。另有 CSAAT 保持 CS 后再续发段的测试，以及 pad 关闭时 peer 不采样的测试。
2. **I2C**：Ibex 真实写 TIMING0–4、INTR_ENABLE、CTRL，再两轮各写 START/address 与 READB/STOP。真实 SCL/SDA 驱动外部 peer 应答；两次 START、ACK、STOP 后，真实 RDATA `0x5a`、`0xa6` 经 CPU ISR 写入 RAM。IRQ 绑定使用 `irq[9]` 的 `cmd_complete`，由真实 W1C 清除。切断这条 IRQ 后没有 CPU RAM 收据。两轮处于同一 testcase，不重复 reset。
3. **RV Timer**：Ibex 真实配置计时器及比较值，Timer RTL 连续计数并两次产生真实 IRQ。CPU ISR 读取中断状态和计数、更新比较值，RAM `0x200`、`0x204` 保存递增的真实计数。切断 IRQ 后 CPU 收据消失。此链仅证明 CPU→Timer→CPU，不用它冒充 IP 外部输入→CPU 的覆盖。

三个链均将 Genome、源码身份、事务/事件与持久内存结果保存成证据，并在新进程中从初态回放匹配。每个组件的局部协议和时序由自己的 harness 执行；跨组件只保持数据与因果关系。

## Fuzzer 接入口

`myfuzz.scenario.opentitan_mutation:make_opentitan_mutation_bundle` 为 `spi`/`spi_host`、`i2c`、`timer`/`rv_timer` 返回独立 runner factory、可信的 `scenario_rfuzz_decoder.v2`、真实 CPU 中断观察 target 和种子 Genome。Dependency Path 只把已声明的外部 peer payload 与 CPU 程序位视为变异源；CPU IRQ、MMIO rdata 和 DUT 结果没有进入源集合。首期每个 CPU 种子仅开放一个保持 `ADDI` 指令合法的 immediate 位；其他 CPU 指令变异尚未扩展。

固定验收包：

- `runs/scenario/acceptance/case-ibex-opentitan-spi-host-two-rounds-v1`
- `runs/scenario/acceptance/case-ibex-opentitan-i2c-two-rounds-v1`
- `runs/scenario/acceptance/case-ibex-opentitan-rv-timer-two-rounds-v1`

三份均经 `scripts/replay_scenario.py --rebuild --compare-trace` 新进程全量回放，结果为 `matches=true`、`verification_scope=full`。

## 复现命令与结果

```bash
PYTHONPATH=src python3 -m unittest discover -s tests/scenario -p 'test_*.py'
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest \
  tests.integration.test_scenario_opentitan_spi_host_real \
  tests.integration.test_scenario_spi_host_session_real \
  tests.integration.test_scenario_ibex_spi_host_chain_real \
  tests.integration.test_scenario_opentitan_i2c_real \
  tests.integration.test_scenario_i2c_session_real \
  tests.integration.test_scenario_ibex_i2c_chain_real \
  tests.integration.test_scenario_opentitan_rv_timer_real \
  tests.integration.test_scenario_ibex_timer_chain_real
git diff --check
```

本轮通过：scenario 单元测试 329/329；上述合并的真实 RTL/闭包集成测试 16/16（SPI Host 本地 4、Ibex 链 3、闭包 1；I2C 本地 1、Ibex 链 2、闭包 1；RV Timer 本地 2、Ibex 链 2）。`git diff --check` 无输出。真实 RTL 集成测试需显式设置 `MYFUZZ_SCENARIO_REAL=1`；默认单元测试不会运行其中的 opt-in 场景。

## 范围限制

- SPI peer 目前只覆盖标准单线 mode 0；Dual、Quad、多 CS、passthrough 尚未验证。
- I2C peer 模型支持有界 clock stretch，但本轮真实 RTL 链只验证 `stretch_cycles=0`、Controller 模式和一个外部 target；Target 模式未验证。
- RV Timer 本轮只验证 hart0/timer0。
- 新增三种 IP 已具备可信 RFuzz 解码和真实 RTL 变异传播证明；本轮未运行针对这些 IP 的多种子、长时间 coverage-guided 对比 campaign，因此不宣称覆盖率或吞吐提升。
- 后续已接入 SPI Device 独立 harness，完成 flash mode 下的 JEDEC 与 upload 真实 RTL 闭环；详见 [SPI Device 后续报告](opentitan-spi-device-expansion-20260928.md)。TPM、passthrough 和多线模式尚未验证。当前本地 OpenTitan 树无 PWM RTL，标记 `skipped_unavailable`。
