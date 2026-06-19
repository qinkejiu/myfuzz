# Ibex 41 路 pre/post 对比实验与 baseline harness 说明

日期：2026-06-16

## 1. 原始 baseline harness 位置

Ibex 原始 baseline 对应 `scheme1_baseline`。它没有手写约束 harness，配置文件里也没有 `manual_harness` 字段。

baseline 配置：

```text
/home/qinkejiu/test/myfuzz/configs/designs/ibex/config.json
```

baseline 的 RFuzz 自动生成 harness：

```text
/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv
```

baseline 的 RFuzz 输入映射 TOML：

```text
/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core.rfuzz.toml
```

远程服务器上的对应位置：

```text
/root/fanzehui/myfuzz/configs/designs/ibex/config.json
/root/fanzehui/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv
/root/fanzehui/myfuzz/runs/designs/ibex/harness/ibex_core.rfuzz.toml
```

在 managed run 里，`scheme1_baseline/harness` 通常是指向通用 baseline harness 目录的软链接。例如本地 smoke run 中：

```text
/home/qinkejiu/test/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_smoke_5s_5s_20260616_023500/slices/slice_0000/designs/scheme1_baseline/harness
  -> /home/qinkejiu/test/myfuzz/runs/designs/ibex/harness
```

所以要看 baseline 的真实 harness 源码，应看：

```text
/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv
```

这个文件头部写明：

```text
Generated from ibex_core.toml by generate_rfuzz_harness.py.
Byte-level Verilator harness compatible with the original rfuzz fuzzer.
```

## 2. baseline harness 做了什么

baseline harness 是 RFuzz 自动生成的 direct top-level harness：

- 顶层模块是 `ibex_core`。
- RFuzz 提供 56 个输入 byte：`io_input_bytes_0` 到 `io_input_bytes_55`。
- 这些 byte 被拼成 padded input，再切出 395-bit `rfuzz_input_bits`。
- `rfuzz_input_bits` 直接按 TOML 映射到 Ibex 顶层输入端口。
- 不做协议修正，不做指令合法化，不做低频事件 shaping。

例子：

```text
/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv:1195
assign rfuzz_input_padded = {io_input_bytes_0, ..., io_input_bytes_55};

/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv:1199
assign ic_data_rdata_i[0] = rfuzz_input_bits[394 -: 64];

/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv:1211
assign instr_rdata_i = rfuzz_input_bits[126 -: 32];
```

对应输入顺序可以从 TOML 看：

```text
/home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core.rfuzz.toml
```

其中开头包括：

```text
ic_data_rdata_i: 128 bit
ic_tag_rdata_i: 44 bit
boot_addr_i: 32 bit
data_rdata_i: 32 bit
hart_id_i: 32 bit
instr_rdata_i: 32 bit
...
```

## 3. 41 路 pre/post 实验位置

远程 6h run root：

```text
/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
```

本地归档结果：

```text
/home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453
```

运行脚本：

```text
/home/qinkejiu/test/myfuzz/scripts/runs/run_ibex_all_bit_constraint_variants_pre_post_6h_resume.py
```

结果文件：

```text
/home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453/summary.json
/home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453/latest_sample.json
/home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453/hourly_common_coverage.csv
/home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453/manifest.json
```

总汇总文档入口：

```text
/home/qinkejiu/test/myfuzz/docs/ALL_TEST_RESULTS_MASTER.md
section 15: Ibex all bit-only variants pre/post 6h remote run
```

## 4. pre/post 的含义

这次实验共 41 路：

- 1 路 baseline。
- 20 个 bit-only 约束变体的 `_pre` 版本。
- 20 个对应 `_post` 对照版本。

定义：

| 类型 | fuzzer 变异对象 | harness 行为 | 研究意义 |
|---|---|---|---|
| baseline | Ibex 顶层 395-bit 输入向量 | RFuzz 自动 harness 直接映射，不修正 | 原始随机顶层 fuzz 参考线 |
| `_pre` | 修正前 raw 395-bit `rfuzz_input_bits` | 手写 harness 先接收 raw bits，再把部分 bit 组合修正/投影到 DUT 输入 | 符合原始目标：约束 0/1 输入 bit 串，让随机输入更容易进入正确状态 |
| `_post` | 修正后的 395-bit DUT 输入向量 | 复用 baseline direct harness，不经过变体 harness 的修正层 | after-correction 对照：看“直接变异已修正输入”是否更好 |

脚本中的定义在：

```text
/home/qinkejiu/test/myfuzz/scripts/runs/run_ibex_all_bit_constraint_variants_pre_post_6h_resume.py
```

关键逻辑：

```text
*_pre: RFuzz mutates raw 395-bit input, then the variant harness projects/corrects those bits before driving ibex_core.
*_post: RFuzz mutates the 395-bit DUT input vector directly, representing mutation after the variant's correction layer.
```

## 5. 6h 最终排名摘要

统计口径：

- common coverage indices `0..1057`
- common_total = 1058
- 每路 fuzz 时间 6h
- 41 路全部 `returncode=0`

| rank | scheme | tests_total | cycles_total | common coverage | discoveries |
|---:|---|---:|---:|---:|---:|
| 1 | `scheme5_pre` | 63,508 | 211,543 | 506/1058 = 47.83% | 178 |
| 2 | `scheme6_relaxed_pre` | 63,508 | 210,920 | 487/1058 = 46.03% | 165 |
| 3 | `scheme6_low2_mixed25_pre` | 63,508 | 212,004 | 462/1058 = 43.67% | 162 |
| 4 | `scheme6_handshake_only_pre` | 63,508 | 211,658 | 460/1058 = 43.48% | 158 |
| 5 | `scheme6_opcode_mixed_post` | 63,508 | 211,232 | 459/1058 = 43.38% | 153 |
| 6 | `scheme6_low2_opcode_mixed25_post` | 63,508 | 211,844 | 459/1058 = 43.38% | 151 |
| 7 | `scheme6_minlegal_pre` | 63,508 | 211,222 | 458/1058 = 43.29% | 154 |
| 8 | `scheme6_low2_mixed50_post` | 63,508 | 211,143 | 458/1058 = 43.29% | 147 |
| 9 | `scheme6_fetch_only_post` | 63,508 | 211,415 | 457/1058 = 43.19% | 148 |
| 10 | `scheme6_opcode_only_post` | 63,508 | 211,029 | 457/1058 = 43.19% | 147 |
| 11 | `scheme6_handshake_only_post` | 63,508 | 210,227 | 455/1058 = 43.01% | 156 |
| 12 | `scheme5_post` | 63,508 | 210,684 | 455/1058 = 43.01% | 149 |
| 13 | `scheme6_fetch_handshake_pre` | 63,508 | 211,747 | 454/1058 = 42.91% | 152 |
| 14 | `scheme6_opcode_mixed75_post` | 63,508 | 211,244 | 454/1058 = 42.91% | 153 |
| 15 | `scheme1_baseline` | 63,508 | 212,658 | 453/1058 = 42.82% | 148 |

## 6. 每个变体的 pre/post 成对对比

baseline：`453/1058`。

| variant | pre | post | pre-post | pre-baseline | post-baseline |
|---|---:|---:|---:|---:|---:|
| `scheme5` | 506/1058 | 455/1058 | +51 | +53 | +2 |
| `scheme6_fetch_handshake` | 454/1058 | 453/1058 | +1 | +1 | +0 |
| `scheme6_fetch_only` | 450/1058 | 457/1058 | -7 | -3 | +4 |
| `scheme6_handshake_only` | 460/1058 | 455/1058 | +5 | +7 | +2 |
| `scheme6_low2_mixed25` | 462/1058 | 441/1058 | +21 | +9 | -12 |
| `scheme6_low2_mixed50` | 436/1058 | 458/1058 | -22 | -17 | +5 |
| `scheme6_low2_opcode_mixed25` | 450/1058 | 459/1058 | -9 | -3 | +6 |
| `scheme6_ls_misalign_mixed50` | 407/1058 | 449/1058 | -42 | -46 | -4 |
| `scheme6_ls_misalign_mixed75` | 383/1058 | 428/1058 | -45 | -70 | -25 |
| `scheme6_ls_opcode_mixed50` | 403/1058 | 449/1058 | -46 | -50 | -4 |
| `scheme6_ls_opcode_mixed75` | 388/1058 | 448/1058 | -60 | -65 | -5 |
| `scheme6_ls_word_mixed50` | 408/1058 | 447/1058 | -39 | -45 | -6 |
| `scheme6_minlegal` | 458/1058 | 447/1058 | +11 | +5 | -6 |
| `scheme6_opcode_minlegal` | 415/1058 | 450/1058 | -35 | -38 | -3 |
| `scheme6_opcode_mixed12` | 431/1058 | 445/1058 | -14 | -22 | -8 |
| `scheme6_opcode_mixed25` | 440/1058 | 448/1058 | -8 | -13 | -5 |
| `scheme6_opcode_mixed75` | 434/1058 | 454/1058 | -20 | -19 | +1 |
| `scheme6_opcode_mixed` | 439/1058 | 459/1058 | -20 | -14 | +6 |
| `scheme6_opcode_only` | 414/1058 | 457/1058 | -43 | -39 | +4 |
| `scheme6_relaxed` | 487/1058 | 449/1058 | +38 | +34 | -4 |

## 7. 结论

1. 原始 baseline 没有手写约束 harness，使用的是 RFuzz 自动生成的 `ibex_core_VHarness.sv`。
2. 对原始研究目标而言，关键结果是 `_pre`，因为它让 fuzzer 变异修正前 raw 0/1 bit 串，再由 harness 做组合约束/投影。
3. `scheme5_pre` 是 41 路里最强的结果：`506/1058`，比 baseline 多 53 个 common coverage 点。
4. `scheme6_relaxed_pre` 是第二强：`487/1058`，比 baseline 多 34 点。
5. `_post` 是必要对照，但不是主要研究对象；它表示直接变异修正后的 DUT 输入向量。当前结果里，最强的 `_post` 只有 `459/1058`，低于 `scheme5_pre` 和 `scheme6_relaxed_pre`。
6. 这轮实验支持的判断是：在 Ibex 上，保留 raw-bit-before-correction 的约束模式比直接变异修正后信号更符合目标，也能取得更高覆盖率。

## 8. 快速查看命令

本地查看 baseline harness：

```bash
sed -n '1,80p' /home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core_VHarness.sv
sed -n '1,80p' /home/qinkejiu/test/myfuzz/runs/designs/ibex/harness/ibex_core.rfuzz.toml
```

本地查看 41 路结果：

```bash
python3 -m json.tool /home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453/summary.json
cat /home/qinkejiu/test/myfuzz/archives/ibex_schemes_archive_20260616/remote_results/ibex_all_variants_pre_post_6h_6h_20260616_032453/hourly_common_coverage.csv
```

远程查看原始 run：

```bash
ssh inner70
cd /root/fanzehui/myfuzz
RUN=/root/fanzehui/myfuzz/runs/managed_runs/ibex_all_variants_pre_post_6h_6h_20260616_032453
cat $RUN/summary.json
cat $RUN/hourly_common_coverage.csv
ls -la /root/fanzehui/myfuzz/runs/designs/ibex/harness
```
