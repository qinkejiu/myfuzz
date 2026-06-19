# CPU + Multi-IP Component Experiment Plan

生成时间：2026-06-19

本文记录当前新实验方向：把 target 从单个 CPU core 扩展为
`CPU + 多个 IP + 简单互连/中断/外部环境`，并比较“直接切片 baseline”和
“依赖感知 bit 投影方案”。

## 1. 目标

第一阶段正式 target 是：

```text
ibex_core
  + simple address decode / response wrapper
  + instruction/data RAM
  + timer
  + GPIO
  + UART
  + SPI
```

当前目录：

```text
configs/designs/ibex_multicomponent_ip/
```

CPU 使用远程 `third_party/rfuzz/upstream/ibex` 中的真实 `ibex_core`。第一版 RAM、
timer、GPIO、UART、SPI 是轻量 common-IP 行为模型，目的是先验证 multi-component
对照框架；后续再替换成更真实的第三方 IP。

旧 `configs/designs/multicomponent_cpu_ip/` 保留为 toy CPU 原型，不作为当前初步
实验 target。RVX/CV32E40P/CORE-V/PULP 仍作为后续 target 候选。

## 2. 对照组定义

### 2.1 baseline_direct_slice

baseline 是朴素随机对照：

```text
rfuzz_input_bits
  -> fixed slice 0 -> Ibex wrapper boot/fetch/seed/latency inputs
  -> fixed slice 1 -> GPIO/UART/SPI/timer external pins
  -> fixed slice 2 -> IRQ/debug/error inputs
  -> same Ibex + RAM/timer/GPIO/UART/SPI target
```

规则：

- 不做 bit 间依赖约束；
- 不做地址 decode 后的目标 IP 选择；
- 不强制 `valid/ready/request/response` 之间的协议关系；
- 不根据 IP 状态产生 IRQ；
- 不低频化 debug/error/IRQ；
- 不使用 DUT 输出反向构造输入。

它的价值是提供“直接切割 bit 串”的干净 baseline。

### 2.2 depaware_projection

dependency-aware 方案仍然只用同一个 `rfuzz_input_bits` 作为随机源，但 harness
按源码和文档得到的依赖关系做轻量投影：

```text
rfuzz_input_bits
  -> scenario / dependency decoder
  -> address decode
  -> bus request/response projection
  -> IP-local event/status projection
  -> interrupt/debug/error priority and gating
  -> same CPU + multi-IP target
```

允许的投影：

- 地址对齐和 MMIO region 选择；
- request/response、valid/ready、grant/rvalid 关系；
- timer/GPIO/UART/SPI 状态到 status/IRQ 的关系；
- error/debug/IRQ 的低频 gate 和优先级；
- read data / status data 按目标 IP 类型生成；
- reset/fetch/boot 这类系统入口信号的基本合法化。

禁止把 depaware 方案变成 directed test：

- raw bits 仍然必须控制场景和数据；
- 不把一条固定程序或固定寄存器序列写死；
- 不用 DUT 内部信号作弊式反推输入；
- baseline 和 depaware 必须保持同一个 target 和同一个 coverage 口径。

## 3. 依赖 manifest

第一阶段先显式维护 manifest，后续再把可自动抽取的部分接到脚本里。

本地文件：

```text
configs/designs/ibex_multicomponent_ip/manifests/ibex_common_ip_dependency_manifest.json
```

manifest 记录四类信息：

```text
components:
  module instance, kind, role

connections:
  source/destination instance, ports, signal role

address_map:
  base, size, target component, access kind

dependency_rules:
  baseline slicing rule
  depaware projection rule
  fairness/coverage notes
```

依赖来源：

- 源码：module instance、port list、wire connection、层级；
- 端口命名：clk/rst/valid/ready/req/gnt/rvalid/addr/data/irq/error；
- 文档或人工检查：地址 map、register/status/IRQ 语义、外设协议；
- 实验约束：哪些关系允许 depaware 修正，哪些关系 baseline 必须保持独立随机。

## 4. 本地目录骨架

```text
configs/designs/ibex_multicomponent_ip/
  README.md
  baseline_direct_slice/
    config.json
  depaware_projection/
    config.json
  harness/
    README.md
  manifests/
    ibex_common_ip_dependency_manifest.json
  rtl/
    local_sources.f
    generated_remote_sources.f
    ibex_multicomponent_ip_top.sv
    ibex_mcip_*.sv
  scripts/
    run_local_smoke.py
    prepare_remote_sources.py
    run_remote_smoke.sh
```

`generated_remote_sources.f` 由远端脚本生成，会把 Ibex upstream filelist 展开后追加
本目录 wrapper/IP RTL。

## 5. 测试策略

本地只做：

- JSON、目录、filelist、harness 输入宽度检查；
- 不跑 RFuzz server/fuzz；
- 不跑会占用大量内存的 formal 或长流程。

正式长测必须按 agent 约定在远端运行：

```text
host: inner70
repo: /root/fanzehui/myfuzz
```

启动正式长测后必须检查：

- runner/server/kfuzz 进程；
- `free -h` 内存和 swap；
- run root、latest_sample、hourly_common_coverage、manifest；
- 完成后追加 `ALL_TEST_RESULTS_MASTER.md`。

## 6. 第一阶段里程碑

1. 完成 `ibex_multicomponent_ip` 目录和 manifest。
2. 写 Ibex wrapper + RAM/timer/GPIO/UART/SPI 轻量 IP。
3. 写 baseline direct-slice harness。
4. 写 depaware projection harness。
5. 本地只跑轻量结构检查。
6. 远端跑 frontend/instrument/toml/harness smoke，确认两条路径 coverage 口径一致。已完成：
   `instrumented HDL files=36`，`coverage points=1123`，generated harness coverage width
   为 `1194` bit，即 `IBEX_MCIP_COVERAGE_MSB=1193`。
7. 再远端跑短 fuzz，对比 baseline vs depaware。已完成 10 秒冒烟：
   baseline `queue_entries=1, crashes=0, newly_covered=122`；depaware
   `queue_entries=1, crashes=0, newly_covered=158`。该结果只作为框架 sanity check，
   不能替代正式长测。
