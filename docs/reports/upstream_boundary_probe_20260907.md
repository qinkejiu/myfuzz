# 上游源码接入检查（2026-09-07）

本次只做浅克隆、稀疏检出和源码分析；没有初始化递归子模块，没有启动 Chipyard/JVM 构建，没有运行 CVA6/BOOM 实核，也没有启动 RFuzz。现有 Ibex 源码和其他运行进程保持不变。

## 可复现版本

| 仓库 | 固定提交 | 本地路径（工作区相对） |
|---|---|---|
| [CVA6 官方仓库](https://github.com/openhwgroup/cva6) | `2e1336dcff3d1a0b49fbe6282b97802f32ea32af` | `third_party/cva6_upstream_reference` |
| [BOOM 官方仓库](https://github.com/riscv-boom/riscv-boom) | `58ef2720eae13be26b3008c02b5a74ce29c61c44` | `third_party/boom_upstream_reference` |
| [RFuzz 作者仓库](https://github.com/ekiwi/rfuzz) | `651f28f1583e14a4aa9d8dfc624b700e6da3a143` | `third_party/rfuzz/upstream/rfuzz_reference` |

这些目录是源码参考，不替代现有 CPU profile 的运行目录，也不将 `implemented` 改为 true。源码目录未加入本项目 Git 提交；重新获取时应检出表中固定版本，而不是使用移动分支作为证据。

## CVA6：不是换一个模块名就能接入

固定版本的 `core/cva6.sv` 使用 `CVA6Cfg` 配置记录、参数类型、package 和 packed struct。实际外部存储边界是 `noc_req_t noc_req_o` / `noc_resp_t noc_resp_i`；该文件声明了 AXI 通道结构，包含 ID、burst、user、cache、qos、region，以及写地址的 atop 等字段。不能把这些字段直接当成当前 AXI4-Lite 的子集丢弃。

以该固定 Git 提交、`top_module=cva6`、`files=[core/cva6.sv]` 运行 `SourceCrawler.crawl` 的实际结果为 `SourceCrawlError:unsupported-port-width`。这是单文件边界检查，不是完整依赖编译；当前 source-only 子集不能求值 `CVA6Cfg.VLEN/XLEN`，也不提供结构体成员展开。下一步需提供可验证的 elaboration 配置、依赖闭包和类型成员映射，而非猜测位宽或编写 CPU 名称分支。

本次补强：内建整数类型不再误判为 1 位；未解析的 typedef/interface/struct 不得伪装成标量端口。复杂类型仍明确不可用。

## BOOM：需要生成 RTL 和完整互联语义

固定版本提供 Chisel/Scala 源码；其 README 明确要求通过 Chipyard 实例化，`CHIPYARD.hash` 为 `4180463d52bc0a6b4c004530601ccdabebf0ab7d`。`src/main/scala/v4/lsu/dcache.scala` 声明 TileLink client node。没有将 Scala 文本伪装成 HDL，也没有把 TL-UL 当作完整 TileLink/coherence 支持。

缺口是兼容的生成环境、选定 BOOM 配置产生的 RTL、完整端点注释和适配器能力。为避免大规模依赖构建占用机器，本次未启动生成。

## RFuzz：补通输入运输格式，运行工具仍有缺口

官方固定版本 `fuzzer/src/config.rs` 的 `determine_test_size` 按字节数向上对齐到 word；`fuzzer/src/main.rs` 的 `WORD_SIZE=8`。`harness/src/rfuzz/VerilatorHarness.scala` 按输入字节索引顺序拼接，取拼接结果的高 `inputBits` 位。对应规则为：

```text
byte_count = ceil(raw_width / 64) * 8
padding_bits = byte_count * 8 - raw_width
record = big_endian_bytes(raw_bits << padding_bits, byte_count)
raw_bits = big_endian_integer(record) >> padding_bits
```

因此 395 位对应 56 字节、末尾 53 位填充；其他位宽必须动态推导。填充位被模糊器变异时不影响 DUT，不能误算成有效字段或输入约束覆盖。

新增 `myfuzz.composition.rfuzz_transport` 提供布局驱动的逐周期编解码、带布局哈希的运输格式描述和组合逻辑 RTL。它只负责字节到 raw bits，不负责 ISA 合法性、跨周期握手、覆盖率采集或模糊器启动。这些义务仍由相应上层执行。

原项目运行路径依赖 `third_party/rfuzz/rfuzz_flow/tools/verilog_instrumentation/generate_rfuzz_harness.py`、`build_rfuzz_server.py` 等额外工具。官方固定版本中没有该 `tools` 树。不能仅把官方仓库重命名为 `rfuzz_flow` 就宣称现有运行流程可用；需要显式实现或恢复该集成层，并测试覆盖率反馈与 corpus 回放。

## 本轮实现和验证结果

- 泛化端口类型检查：内建整数宽度/符号性、方向省略时的继承、import 头部；未知类型和非法维度拒绝。独立审查通过。
- 通用 AXI4-Lite 原生适配：AW/W 任意先后、独立 AW/AR 地址检查、单个未完成事务、背压保持、非法地址 DECERR、超时 SLVERR 后隔离到共享复位。16 次定向 RTL 仿真；另有地址空间末尾区间的顶层生成/发布回归。独立审查通过。
- 动态 RFuzz 字节映射：Python 编解码及 13/64/65/395 位 RTL 对照测试；发布附属 JSON/SV，并绑定布局哈希。独立审查通过。附属模块尚未接入 DUT 模糊测试 harness。
- 最终代码提交 `f8e83e1`：全量 **853 项测试通过，18.111 秒**。验证使用单 worker、`nice -n 15`、无波形；保留原有负向 CLI 测试的预期输出。

本轮没有重复执行先前的三组 300 秒合成总线激励测试。系统总目标仍未完成，尤其是实核接入、结构体/参数 elaboration、完整 AXI4/TileLink、多目标共享总线，以及实际 RFuzz 覆盖率反馈执行。
