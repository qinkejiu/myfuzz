# Ibex＋双 PULP GPIO 在线连续输入与重放验收

**日期：** 2026-10-05
**场景：** 一个 Ibex CPU、GPIO A、GPIO B，各自在独立生成式本地 harness 中运行。
**目的：** 验证 RTL 已启动后仍可依据已观察到的真实输出逐次提供环境输入，并将整段输入/步进历史在全新 harness 中重放。

## 场景与执行方式

CPU 程序真实配置 GPIO B 的输入方向、上升沿中断和向量，并配置 GPIO A 的输出方向。Recorder 启动三个 harness 一次，随后每次只推进一个选定的本地 harness。测试观察 Ibex 真实 `data_req_accepted` 和 `data_rsp_consumed` 输出，再决定何时向未绑定的 GPIO B `gpio_in[15:8]` 提交下一笔环境输入：

```text
CPU 的真实配置输出
→ 外部 GPIO B 输入 0x49
→ GPIO B RTL 上升沿/真实 IRQ
→ Router 与 IRQ pulse delivery
→ Ibex RTL 进入 ISR 并真实读取 PADIN
→ Ibex 将读值存入持久 RAM 并写 GPIO A
→ 外部输入拉低
→ 后续因果边界提交 0x81、0xff 并完成相同闭环
```

`0x00` 输入用于真实形成下降沿，以便后续上升沿可再次触发；三个有效输入值为 `0x49`、`0x81`、`0xff`。所有事件都由同一份 `ScenarioBatchRecorder` 逐次记录。执行期间不重建 session、不 reset，也不让 Fuzzer 写 CPU IRQ、GPIO A→B 的绑定位或 CPU 读回值。

## 验收结果

- 三个初始 MemoryImage 在 testcase 开始时加载一次；运行期间未出现 reset barrier，CPU RAM generation 保持不变。
- Ibex 真实 ISR 向 `0x20000` 写入 `0x49`、`0x81`、`0xff`；CPU 真实读取 GPIO B PADIN 得到 `0x4900`、`0x8100`、`0xff00`。
- CPU 真实向 GPIO A 写出三个字节；GPIO A RTL 的 `gpio_out` 观察到三个对应值。
- GPIO B RTL 产生三次真实 IRQ source/pulse，CPU 真实取指进入 ISR 向量三次。
- 结束后编码并解码后的 plan 完全相等；fresh replay 在新建的第二组 runner 上按相同 source-admission 与 `BatchAdvance` 调用边界运行，完整事件、各组件 local ticks 与语义摘要匹配。
- 这证明 ScenarioRunner 层支持启动后的在线逐次输入和同 testcase 状态延续。当前结果不表示 ScenarioRfuzzExecutor 或 RFuzz live FIFO slot 已接入该接口。

## 测试命令

```bash
PYTHONPATH=src:. python3 -m unittest \
  tests.scenario.test_stateful_batch \
  tests.scenario.test_replay \
  tests.scenario.test_genome_scheduler \
  tests.scenario.test_runner_continuity -v

PYTHONPATH=src:. MYFUZZ_SCENARIO_REAL=1 \
  MYFUZZ_IBEX_GPIO_CACHE=/tmp/myfuzz-ibex-obi-build \
  python3 -m unittest \
  tests.integration.test_scenario_ibex_pulp_gpio_online_batch_real -v
```

**结果：** Scenario unit/regression 30/30 通过；Ibex＋双 PULP GPIO 在线真实 RTL 闭环与 fresh replay 1/1 通过，44.435 秒。真实验收使用固定源码 revision：Ibex `34b0705760ef3dfa00e99637432473d2be8f22f3`、OpenTitan `fca045df919a26c47e71616b9dac917b1ea4fd07`、PULP GPIO `f82caeb7f7d89427f05e9af5ed31e0675efe0d83`。未更改任何子模块记录 revision。
