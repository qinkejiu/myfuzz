# Ibex 协议组合 MVP 验证报告

验证日期：2026-09-06  
工作区：`/home/qinkejiu/myfuzz/.worktrees/ibex-protocol-longrun`  
分支：`feature/ibex-protocol-longrun`

## 1. 结论

CPU/外设依赖感知自动组合、固定 RFuzz 输入 ABI、协议桥接、候选清单校验以及低资源 campaign 入口已经形成可运行的 MVP。当前工作区没有真实 Ibex/RFuzz 上游依赖，因此真实 RTL 编译和 RFuzz 执行被前置检查安全阻断，状态为 `dependency-unavailable`；本地确定性 producer 已在同一 supervisor 和资源配置下完成 60 秒长测。

这次验证不把本地 JSON producer 的结果宣称为 RTL 编译、覆盖率或真实 CPU fuzzing 结果。

## 2. 实现范围

- CPU 目录包含 Ibex、CVA6、BOOM、Rocket、PicoRV32 和 CV32E40P；实现状态与参考状态分离，只有源文件完整存在且状态为 `implemented` 的记录才能进入运行时。
- 外设目录包含 RAM、timer、GPIO、UART、SPI、PWM、I2C、DMA、CLINT、PLIC 和 Ethernet MAC，并记录协议能力、参数边界、地址/IRQ 能力及依赖关系。
- 当前可执行协议范围收敛为 APB4、AXI4-Lite 和 TileLink-UL 单拍；AXI4 全功能、完整 TileLink、AHB、Wishbone、Avalon、CHI 等只作为参考元数据，不能直接进入 RTL 运行路径。
- 自动规划器按 CPU 集成协议、外设协议、源文件、数据宽度、地址窗口、IRQ 范围和依赖图进行选择；候选 ID、地址、IRQ、诊断和内容哈希是确定性的。
- RFuzz 输入 ABI 保持不变：Ibex 使用 56 字节输入，经固定手工 harness 投影到 395 个 raw bits，没有追加随机字段。
- 默认 campaign 约束为单 build slot、单 worker、关闭波形、512 MiB soft RSS、768 MiB hard RSS、64 MiB token 预算；本地长测使用显式 60 秒时长。

## 3. 验证证据

### 3.1 全量回归

命令：

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests -p 'test*.py' -v
```

结果：`Ran 643 tests ... OK`，退出码 `0`。

### 3.2 固定清单和真实目标前置检查

命令：

```text
python3 configs/designs/ibex_protocol_composition/scripts/check_local.py
```

结果：退出码 `2`，输出：

```text
dependency-unavailable: third_party/rfuzz/upstream/ibex
```

真实 campaign dry-run：

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/run_ibex_protocol_campaign.py \
  --config configs/designs/ibex_protocol_composition/campaign.json --dry-run
```

结果为 `dependency-unavailable`，缺失项为：
`third_party/rfuzz/upstream/ibex/sources.f`。没有启动设计流子进程，也没有生成虚假的编译或 fuzz 成功状态。

### 3.3 协议桥和组合配置

- 正确的协议、catalog、桥接 RTL、manifest 和 composer 定向测试共 `54/54` 通过。
- campaign CLI 与本地 smoke 定向测试 `17/17` 通过。
- 组合配置及 flow integration 定向测试 `41/41` 通过。
- 自动规划器和 CPU catalog 定向测试 `25/25` 通过；覆盖发布前源证据复核、嵌套结果不可变、planner root 重算和不可发布地址窗口。
- 最近一次收尾定向回归 `43/43` 通过；覆盖外部 HDL/嵌套 filelist 闭包、手工 harness ABI、进程组 RSS 和旧流程兼容。
- Verilator 对 `src/myfuzz/protocols/rtl/*.sv` 执行 `--lint-only --language 1800-2012 -Wall -Wno-fatal`，退出码 `0`。仅有 MULTITOP、UNUSEDPARAM 和 UNUSEDSIGNAL 类非致命警告。

### 3.4 60 秒低资源长测

命令：

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/run_ibex_protocol_campaign.py \
  --config configs/designs/ibex_protocol_composition/campaign.json \
  --local-smoke --duration-seconds 60 --checkpoint-seconds 1 \
  --output-dir runs/ibex_protocol_campaign_soak_final_20260906
```

结果文件：

- 报告：[report.json](../../runs/ibex_protocol_campaign_soak_final_20260906/report.json)
- 检查点：[checkpoint.json](../../runs/ibex_protocol_campaign_soak_final_20260906/checkpoint.json)

关键结果：

| 项目 | 结果 |
|---|---:|
| status | `completed` |
| 实际 duration | `59.77645986699645 s` |
| iterations | `5` |
| transactions | `5` |
| errors | `0` |
| invalid metric lines | `0` |
| checkpoint count | `60` |
| peak RSS | `12,689,408 bytes`（约 12.1 MiB） |
| worker/build jobs | `1 / 1` |
| waveforms / VCD | `false / false` |
| soft/hard RSS | `512 / 768 MiB` |

协议事务计数为 `apb=2`、`axi4-lite=2`、`tl-ul=1`；组件事务计数为 `ram=1`、`timer=1`、`gpio=1`、`uart=1`、`spi=1`；coverage point 为 `local.ibex.protocol.seed-00000007`。报告同时保留了上游依赖状态 `dependency-unavailable` 和 `rtl_compilation_claimed=false`。

## 4. 变更与审查边界

本次实现的关键提交包括：

- `5355cec` / `4f5fbea`：严格 CPU/ISA catalog 及运行时源状态门控；
- `8ee4395` / `20c1626` / `bdf5fb9` / `c17bcb1` / `7a4c04e`：外设能力 catalog、路径边界和回归测试；
- `8a16d3c` / `6b09db9`：依赖感知自动组合、确定性规划及发布前证据复核；
- `524364b`：Ibex 组合 candidate、手工 395-bit harness 和低资源 campaign flow；
- `c9f4436` / `b48ec0c` / `f197b29` / `91647a3`：进程组 RSS 限制、手工 ABI/自定义组合目录校验、外部 HDL filelist 闭包和 RSS API 导出。

当前代码已通过全量回归；真实上游缺失是外部环境限制，不是用本地 smoke 结果掩盖的实现状态。

## 5. 上游依赖到位后的下一步

在包含完整 RFuzz/Ibex 上游的工作区中，先运行：

```text
python3 configs/designs/ibex_protocol_composition/scripts/check_local.py
```

确认通过后，再执行 10–60 秒真实目标验证：

```text
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 scripts/run_ibex_protocol_campaign.py \
  --config configs/designs/ibex_protocol_composition/campaign.json \
  --duration-seconds 10 --checkpoint-seconds 1 \
  --output-dir runs/ibex_protocol_campaign_real_smoke
```

真实 smoke 通过后，才应逐步扩大到小时级运行，并继续保持单 worker、无波形和 RSS 监控约束。
