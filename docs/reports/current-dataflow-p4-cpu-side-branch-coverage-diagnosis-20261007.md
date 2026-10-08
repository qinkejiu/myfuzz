# P4 CPU 侧分支覆盖 0/64 的根因诊断：观测配额整段落在一个未被综合的 generate 分支上

日期：2026-10-07。承接 `docs/reports/current-dataflow-p4-rtl-branch-coverage-20261007.md`（该报告已证明 IP 侧内部分支覆盖可用，并把"全部 28 个 run 中 CPU 侧恒为 0/64"记为关键边界）。本报告只读复算既有 artifact，给出这 0/64 的**根因**、逐点归类与一条预备好的 real-RTL gate。**本轮未运行 Verilator / 任何真实 RTL，也未声称获得任何新的 RTL 覆盖。**

## 一句话结论

CPU 侧的 0/64 **不是搜索质量问题，而是结构性零**。`coverage_observation_plan` 按原始 bit 下标升序取 CPU 配额，而插桩器把各子实例的覆盖向量按源码顺序"先声明者占高位"拼接；于是 `u_cpu0` 切片最低的 64 位正好是两个被 `localparam` 常量关闭的 generate 分支——`ibex_top.sv:873 if (Lockstep)`（`Lockstep = SecureIbex = 1'b0`）与 `ibex_top.sv:1275 if (BaseIsa == BaseIsaRV32IorCHERIoT)`（`BaseIsa = BaseIsaRV32I`，默认值 `ibex_top.sv:16`）。这两个分支的覆盖子向量在编译出来的 Verilator 模型里只是"声明但无人驱动"的 wire，任何激励都不可能让它变成 1。同一批 run 里 CPU 明明在退休指令（RVFI opcode 计数非零），因此 0/64 与"CPU 没跑"无关。

## 交付物

| 文件 | 作用 |
|---|---|
| `scripts/rtl_cpu_side_observation_diagnosis.py`（新增） | 逐点把观测到的分支点分成 `elaborated-lit` / `elaborated-unexercised` / `unelaborated-bound` / `probe-unreadable` / `elaboration-unknown`，只用 run 自带 artifact（`report.json`、`soc_coverage_plan.json`、`instrumentation.json`、`build/obj_dir/*___024root.h`） |
| `tests/scenario/test_rtl_cpu_side_observation_diagnosis.py`（新增，17 tests） | 合成正负例钉住三分类与 fail-closed；真实 artifact 钉住 50/128 与 0/64 的精确数字与两棵死子树 |
| `scripts/run_p4_cpu_side_branch_gate.py`（新增，**未执行**） | 预备的 real-RTL gate：`plan` / `verify` / `execute` 三种模式，逐条判据 PASS/FAIL，退出码 PASS=0 / FAIL=1 / BLOCKED=3 / INCONCLUSIVE=4 |
| `docs/reports/current-dataflow-p4-cpu-side-branch-coverage-diagnosis-20261007.md`（本文件） | 证据表、逐点分类计数、边界与下一步命令 |

## 一、64 个 CPU 点精确映射到什么（来自插桩器自己的 manifest）

映射来源：`runs/<run>/build/soc_coverage_plan.json` 的 `observed[64..127]`（`category == "cpu"`，观测向量第 64..127 位）与 `runs/<run>/build/instrumentation/instrumented/instrumentation.json` 的 `coverage_bits[621..684]`（`bit` 键一一对应）。`branch_coverage_ports[i][1] == observed[i]["bit"]` 在全部 28 个 run 中逐元素成立（28/28，见下文第四节），所以"计数器位置 → bit → 信号"这条链是闭合的。

代表 run `runs/ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926`（`mode=mmio_only`，整体 50/128）：

| bit | CPU 切片内偏移 | instance（去掉顶层与 `myfuzz_soc_top/` 前缀） | module | file | line | kind | subtype | signal |
|---:|---:|---|---|---|---:|---|---|---|
| 621 | 0 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 395 | if | true | `__vi_branch_cov_1792` |
| 622 | 1 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 393 | if | true | `__vi_branch_cov_1791` |
| 623 | 2 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 390 | if | false | `__vi_branch_cov_1790` |
| 624 | 3 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 390 | if | true | `__vi_branch_cov_1789` |
| 625 | 4 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 251 | if | true | `__vi_branch_cov_1788` |
| 626 | 5 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 248 | if | false | `__vi_branch_cov_1787` |
| 627 | 6 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 248 | if | true | `__vi_branch_cov_1786` |
| 628 | 7 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 240 | if | true | `__vi_branch_cov_1785` |
| 629 | 8 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 237 | if | false | `__vi_branch_cov_1784` |
| 630 | 9 | `u_cpu0/i_ibex_trvk` | ibex_trvk | `…/ibex_trvk.sv` | 237 | if | true | `__vi_branch_cov_1783` |
| 631 | 10 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 288 | if | true | `__vi_branch_cov_1758` |
| 632 | 11 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 286 | if | true | `__vi_branch_cov_1757` |
| 633 | 12 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 266 | if | true | `__vi_branch_cov_1756` |
| 634 | 13 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 264 | if | true | `__vi_branch_cov_1755` |
| 635 | 14 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 202 | if | true | `__vi_branch_cov_1754` |
| 636 | 15 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 200 | if | true | `__vi_branch_cov_1753` |
| 637 | 16 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 179 | if | true | `__vi_branch_cov_1752` |
| 638 | 17 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 177 | if | true | `__vi_branch_cov_1751` |
| 639 | 18 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 168 | if | true | `__vi_branch_cov_1750` |
| 640 | 19 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 166 | if | true | `__vi_branch_cov_1749` |
| 641 | 20 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 136 | if | true | `__vi_branch_cov_1748` |
| 642 | 21 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 134 | if | true | `__vi_branch_cov_1747` |
| 643 | 22 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 121 | if | true | `__vi_branch_cov_1746` |
| 644 | 23 | `u_cpu0/u_ibex_lockstep/register_file_shadow_i` | ibex_register_file_ff | `…/ibex_register_file_ff.sv` | 119 | if | true | `__vi_branch_cov_1745` |
| 645 | 24 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 211 | case | default | `__vi_branch_cov_1736` |
| 646 | 25 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 207 | case | item | `__vi_branch_cov_1735` |
| 647 | 26 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 206 | case | item | `__vi_branch_cov_1734` |
| 648 | 27 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 205 | case | item | `__vi_branch_cov_1733` |
| 649 | 28 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 204 | case | item | `__vi_branch_cov_1732` |
| 650 | 29 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 145 | if | true | `__vi_branch_cov_1731` |
| 651 | 30 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 85 | if | false | `__vi_branch_cov_1730` |
| 652 | 31 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 85 | if | true | `__vi_branch_cov_1729` |
| 653 | 32 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 82 | case | default | `__vi_branch_cov_1728` |
| 654 | 33 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 79 | case | item | `__vi_branch_cov_1727` |
| 655 | 34 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 77 | case | item | `__vi_branch_cov_1726` |
| 656 | 35 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 74 | case | item | `__vi_branch_cov_1725` |
| 657 | 36 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 70 | case | item | `__vi_branch_cov_1724` |
| 658 | 37 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 66 | if | false | `__vi_branch_cov_1723` |
| 659 | 38 | `u_cpu0/u_ibex_lockstep/u_shadow_core/pmp_i` | ibex_pmp | `…/ibex_pmp.sv` | 66 | if | true | `__vi_branch_cov_1722` |
| 660 | 39 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_part_csr` | ibex_csr | `…/ibex_csr.sv` | 44 | if | true | `__vi_branch_cov_995` |
| 661 | 40 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_part_csr` | ibex_csr | `…/ibex_csr.sv` | 42 | if | true | `__vi_branch_cov_994` |
| 662 | 41 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_part_csr` | ibex_csr | `…/ibex_csr.sv` | 31 | if | true | `__vi_branch_cov_993` |
| 663 | 42 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_part_csr` | ibex_csr | `…/ibex_csr.sv` | 29 | if | true | `__vi_branch_cov_992` |
| 664 | 43 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_ic_scr_key_valid_q_csr` | ibex_csr | `…/ibex_csr.sv` | 44 | if | true | `__vi_branch_cov_995` |
| 665 | 44 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_ic_scr_key_valid_q_csr` | ibex_csr | `…/ibex_csr.sv` | 42 | if | true | `__vi_branch_cov_994` |
| 666 | 45 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_ic_scr_key_valid_q_csr` | ibex_csr | `…/ibex_csr.sv` | 31 | if | true | `__vi_branch_cov_993` |
| 667 | 46 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_cpuctrlsts_ic_scr_key_valid_q_csr` | ibex_csr | `…/ibex_csr.sv` | 29 | if | true | `__vi_branch_cov_992` |
| 668 | 47 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_value_csr` | ibex_csr | `…/ibex_csr.sv` | 44 | if | true | `__vi_branch_cov_995` |
| 669 | 48 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_value_csr` | ibex_csr | `…/ibex_csr.sv` | 42 | if | true | `__vi_branch_cov_994` |
| 670 | 49 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_value_csr` | ibex_csr | `…/ibex_csr.sv` | 31 | if | true | `__vi_branch_cov_993` |
| 671 | 50 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_value_csr` | ibex_csr | `…/ibex_csr.sv` | 29 | if | true | `__vi_branch_cov_992` |
| 672 | 51 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_control_csr` | ibex_csr | `…/ibex_csr.sv` | 44 | if | true | `__vi_branch_cov_995` |
| 673 | 52 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_control_csr` | ibex_csr | `…/ibex_csr.sv` | 42 | if | true | `__vi_branch_cov_994` |
| 674 | 53 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_control_csr` | ibex_csr | `…/ibex_csr.sv` | 31 | if | true | `__vi_branch_cov_993` |
| 675 | 54 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tmatch_control_csr` | ibex_csr | `…/ibex_csr.sv` | 29 | if | true | `__vi_branch_cov_992` |
| 676 | 55 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tselect_csr` | ibex_csr | `…/ibex_csr.sv` | 44 | if | true | `__vi_branch_cov_995` |
| 677 | 56 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tselect_csr` | ibex_csr | `…/ibex_csr.sv` | 42 | if | true | `__vi_branch_cov_994` |
| 678 | 57 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tselect_csr` | ibex_csr | `…/ibex_csr.sv` | 31 | if | true | `__vi_branch_cov_993` |
| 679 | 58 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_tselect_csr` | ibex_csr | `…/ibex_csr.sv` | 29 | if | true | `__vi_branch_cov_992` |
| 680 | 59 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_mcounteren_csr` | ibex_csr | `…/ibex_csr.sv` | 44 | if | true | `__vi_branch_cov_995` |
| 681 | 60 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_mcounteren_csr` | ibex_csr | `…/ibex_csr.sv` | 42 | if | true | `__vi_branch_cov_994` |
| 682 | 61 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_mcounteren_csr` | ibex_csr | `…/ibex_csr.sv` | 31 | if | true | `__vi_branch_cov_993` |
| 683 | 62 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/u_mcounteren_csr` | ibex_csr | `…/ibex_csr.sv` | 29 | if | true | `__vi_branch_cov_992` |
| 684 | 63 | `u_cpu0/u_ibex_lockstep/u_shadow_core/cs_registers_i/mcounters_variable_i` | ibex_counter | `…/ibex_counter.sv` | 77 | if | false | `__vi_branch_cov_813` |

分布：`ibex_csr` 24、`ibex_pmp` 15、`ibex_register_file_ff` 14、`ibex_trvk` 10、`ibex_counter` 1；按实例分：`u_ibex_lockstep/u_shadow_core/pmp_i` 15、`u_ibex_lockstep/register_file_shadow_i` 14、`i_ibex_trvk` 10、`u_ibex_lockstep/u_shadow_core/cs_registers_i/*` 6×4=24、`.../mcounters_variable_i` 1。**64 个点无一例外全部落在 `u_cpu0/u_ibex_lockstep/**`（54 个）或 `u_cpu0/i_ibex_trvk`（10 个）之内。**

## 二、编译模型证据：这些点绑定的信号根本没被综合出来（类别 a）

五路互相独立的证据，全部只读：

| # | 证据 | 精确位置 | 结论 |
|---|---|---|---|
| 1 | 生成/插桩后的顶层确实把 CPU 子向量并进了覆盖端口 | `build/instrumentation/instrumented/myfuzz_soc_top.sv:60` `output wire [3925:0] __vi_coverage`；`:65` `wire [3286:0] __vi_cov_child_u_cpu0_2;`；`:84` 拼接赋值；`:309` `.__vi_coverage(__vi_cov_child_u_cpu0_2)` | 端口路径本身是通的，问题不在读数链路 |
| 2 | 插桩后的 `ibex_top` 把两个死分支的子向量一起声明并拼接 | `…/instrumented/third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv:210` `output wire [3286:0] __vi_coverage`；`:243` `wire [1628:0] __vi_cov_child_u_ibex_lockstep_3;`；`:244` `wire [9:0] __vi_cov_child_i_ibex_trvk_4;`；`:245` 拼接；`:1282`/`:1369` 子端口连接 | 子向量**声明在模块作用域**，而连接写在被关掉的 generate 块里 |
| 3 | 关闭条件是常量，且顶层 `u_cpu0` 没有任何参数覆盖 | `third_party/rfuzz/upstream/ibex/rtl/ibex_top.sv:39` `parameter bit SecureIbex = 1'b0`；`:212` `localparam bit Lockstep = SecureIbex;`；`:873` `if (Lockstep) begin : gen_lockstep`；`:16` `BaseIsa = ibex_pkg::BaseIsaRV32I`；`:1275` `if (BaseIsa == BaseIsaRV32IorCHERIoT) begin : gen_cheriot_trvk`；`:1281` `) i_ibex_trvk (`；`build/myfuzz_soc_top.sv:213` `ibex_top u_cpu0 (`（无 `#(...)`） | 两个分支在本次构建中恒为假 |
| 4 | 编译模型里只有声明、没有任何驱动 | `build/obj_dir/Vmyfuzz_live_tb___024root.h:1501` `VlWide<51>/*1628:0*/ …u_cpu0__DOT_____05Fvi_cov_child_u_ibex_lockstep_3;`；全模型唯一一次写入是 `Vmyfuzz_live_tb___024root__DepSet_h26be3174__1__Slow.cpp:4719` `VL_RAND_RESET_W(1629, …)`；按 LHS 赋值正则 `lockstep_3\[[0-9xa-fU]+\] *=[^=]` 全模型命中 **0** 次 | 该 wire 无驱动，计数器恒为 0 |
| 5 | 作用域层面：活的核心在，死的两个不在 | `Vmyfuzz_live_tb___024root.h` 中 `u_ibex_core__DOT__` 命中 1127 次、`register_file_i__DOT__` 33 次；`u_ibex_lockstep__DOT__` **0** 次、`u_shadow_core__DOT__` **0** 次、`i_ibex_trvk__DOT__` **0** 次（同一判据在 28/28 个 run 的 `build/obj_dir/` 上一致） | 两棵子树未被 elaborate |

诊断器把第 5 条做成可复算的探针：`scripts/rtl_cpu_side_observation_diagnosis.py` 用插桩器自己的 instance path 生成 Verilator 的成员名前缀（`/`→`__DOT__`，前导 `_`→`__05F`，末尾补 `__DOT__`），在 `build/obj_dir/*___024root.h` 里做**存在性**判定；模型缺失时一律 `elaboration-unknown`，绝不默认"已武装"。每个 run 的文档里同时记录 `reference_scopes`：`cpu-active-core` 存在、`cpu-lockstep-branch` 与 `cpu-cheriot-trvk-branch` 不存在。

**探针方向性（如实声明）**：`present ⇒ 该实例被综合、覆盖 wire 有驱动` 是可靠方向；`absent ⇒ 不采纳`是**保守**方向——Verilator 也可能把极小实例内联而不生成成员，此时会少采纳一个本可观测的点，但绝不会把无人驱动的 wire 当成覆盖。本报告对那 64 个点的"未综合"结论另由第 3、4 条独立佐证，不单靠探针。

## 三、为什么恰好是这 64 个：位算术

1. `_instrument_coverage` 用 `universe_from_instance_bits(bits, cpu_instance="u_cpu0", …)` + `coverage_observation_plan(universe, bits, COUNTER_LIMIT)` 产出观测集，`COUNTER_LIMIT = 128`（`src/myfuzz/integration/soc_builder.py:90`、`:2439-2442`）。
2. 选择规则（`src/myfuzz/integration/soc_coverage.py:340-355`）：CPU 与 IP 各自成队，`queue.sort()` 按 `(rank, bit, point_id)` 排序后**按 bit 升序逐个取**，CPU/IP 一对一交错，直到 128 个配额用尽。
3. 拼接顺序：`ibex_top` 的 `__vi_coverage` 是 `{自身 24 位, core_clock_gate, u_ibex_core, register_file_i, u_ibex_lockstep, i_ibex_trvk}`，即**源码中先出现的子实例占高位**。因此 CPU 切片最低位 = 最后声明的子实例。
4. 实测（`runs/ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926`）：`u_cpu0` 子树 = bit **621..3907**（3287 = `__vi_cov_child_u_cpu0_2` 宽度）；
   - 未综合区 = bit **621..2259**（1639 = 1629 lockstep + 10 trvk，连续）；
   - 已综合区 = bit **2260..3907**（1648 = 1609 `u_ibex_core` + 14 `register_file_i` + 24 `ibex_top` 自身 + 1 `core_clock_gate`，连续）；
   - 被选中的 CPU 配额 = bit **621..684**，正好是未综合区的前 64 位（10 trvk + 54 lockstep）。

即：**64 个配额一个不剩地花在了编译期就被删掉的分支上**，而 1648 个真正可观测的 CPU 点（bit 2260 起）全部落在配额之外。`soc_builder.py:2753-2759` 的 testbench 按 `coverage_ports` 的**位置**读 `dut.__vi_coverage[bit]`，所以这 64 个位置的计数器只能一直读到 0。

## 四、逐点分类计数（三类归属）

分类口径：
- **(a) `unelaborated-bound`**：实例作用域不在编译模型里 → 绑定的信号不存在/无驱动，**永远不会亮**；
- **(b) `elaborated-unexercised`**：实例在编译模型里、计数器为 0 → 真正的搜索质量陈述；
- **(c) `probe-unreadable`**：该点在读数向量里没有计数器槽位（越界/向量缺失）；
- 另有 `elaborated-lit`（已综合且点亮）与 `elaboration-unknown`（无编译模型，fail-closed）。

全工作区 28 个带插桩分支证据的 run（`PYTHONPATH=src python3 scripts/rtl_cpu_side_observation_diagnosis.py --runs-root runs`）：

| 口径 | 计数 |
|---|---:|
| 观测点总数 | 3584（= 28 × 128） |
| `elaborated-lit` | 809 |
| `elaborated-unexercised`（b） | 983 |
| `unelaborated-bound`（a） | **1792 = 28 × 64** |
| `probe-unreadable`（c） | **0** |
| `elaboration-unknown` | 0 |
| 自相矛盾（未综合却点亮） | 0 |
| CPU 侧点亮 | **0 / 1792（28 个 run 每个都是 0/64）** |
| CPU 侧 (a) | 1792/1792 = **全部** |

两个代表 run 的明细（`diagnose_run` 文档字段）：

| run | mode | 整体点亮 | IP (b) | IP 点亮 | CPU (a) | CPU 点亮 | (c) | 矛盾 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926` | `mmio_only` | 50/128 | 14 | 50 | 64 | 0 | 0 | 0 |
| `ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926` | `cpu_only` | 18/128 | 46 | 18 | 64 | 0 | 0 | 0 |

第二个 run 是回答"CPU 到底跑没跑"的关键：(a) 的 64 个点一个没亮，但同一 run 的 RVFI opcode 计数器（`checker_feedback.rvfi_opcode_coverage_counter_range = [228, 239]`）读出 `[5,0,4,0,0,0,1,8,2,0,0,0]`（LUI 5、JAL 4、STORE 1、OP_IMM 8、OP 2，合计 20），即 CPU **确实取指、执行并退休了指令**。全部 28 个 run 中有 11 个（全部 `cpu_only`）出现 RVFI 退休，这 11 个的 CPU 侧仍然是 0/64。因此 0/64 既不是"CPU 没跑"，也不是"激励不够"。

## 五、边界：已证明 vs 未知

**已证明**
- 64 个 CPU 观测点在 28/28 个 run 中逐点绑定到 `u_ibex_lockstep/**`（54）与 `i_ibex_trvk`（10）的插桩信号，位下标、文件、行号、kind/subtype、signal 名见第一节表。
- 这两棵子树在该构建配置下未被 elaborate：generate 条件为常量假、顶层无参数覆盖、编译模型无作用域成员、覆盖子向量无任何赋值。
- 因此这 64 个点全部是 (a) 类结构性零；(b) 类在 CPU 侧计数为 0；(c) 类计数为 0——读数链路对 128 个观测点是完整的位置映射（`branch_coverage_ports[i][1] == observed[i]["bit"]`，28/28 全部成立）。
- 既有报告的"50/128"数字本身正确，但它把 50 与 0 并列时无法区分"搜索质量"与"结构零"；本次诊断补上这一区分。

**未知（不得据本报告推断）**
- 修好选择后 CPU 侧**究竟能亮多少**：本报告只能证明"1648 个已综合的 CPU 候选点存在，且同一 run 内机器在退休指令"，不能证明它们会被点亮；这正是 gate 要跑出来的东西。
- `first_seen` 依旧不可用（沿用前一份报告的结论，本轮未改变）。
- 其他 cell / 其他 CPU（cva6、cv32e40p、zipcpu）是否有同类"低位落在未综合分支"问题，未逐一复算；本诊断脚本可直接对任何带 `build/obj_dir/` 的 run 复用。

## 六、分析侧修复（已实施，TDD）

分析侧的缺陷是**可证的**：既有 report/消费者把"激励没到"与"信号不在设计里"合并成同一个 0，没有任何 artifact 能把两者分开。修复不改任何既有文件，只新增消费侧：

- `scripts/rtl_cpu_side_observation_diagnosis.py`：纯函数 `classify_observed_points(points, maxima, model_text)` + 加载器 `diagnose_run(run_dir)` + CLI（`--run` / `--runs-root` / `--json` / `--out` / `--quiet` / `--require-model`）。退出码 0=干净、3=存在 (a) 类观测点、1=不可读。fail-closed：编译模型缺失 → `elaboration-unknown`；缺 `client_result`、或 `observed` 与 `branch_coverage_ports` 位置不一致，直接报错，绝不猜测。
- 测试：`tests/scenario/test_rtl_cpu_side_observation_diagnosis.py`（17 tests）。
- RED → GREEN：先写测试再写实现。RED = `ModuleNotFoundError: No module named 'scripts.rtl_cpu_side_observation_diagnosis'`（collection error；随后据此把两个合成 fixture 的模型文本改成与真实成员名一致）；GREEN = `17 passed in 0.83s`。

## 七、预备的 real-RTL gate（**本轮未执行**）

`scripts/run_p4_cpu_side_branch_gate.py`，三种模式：

- `plan`（只读，已实测）：打印需要、但**本 workspace 不允许实施**的生产改动，要跑的确切命令，以及逐条判据；`--reference-run` 顺带对既有 run 给出 BLOCKED/READY。
- `verify --run <dir>`（只读，已实测）：对单个 run 逐条判定。
- `execute --campaign-command '…' --output … --i-understand-this-runs-rtl`（会启动 Verilator 与 RFuzz 客户端，**本轮未执行**）。

判据（全部满足才 PASS）：
1. `run-artifact`：`report.json` 可解析且带 `client_result.branch_coverage_ports`；
2. `coverage-identity`：`scripts/report_rtl_branch_coverage.py --run <dir>` 退出 0、`status=verified`、`external_binding.passed=true`；
3. `cpu-stimulus`（前置条件）：RVFI opcode 计数器至少一个非零——否则 CPU 没退休，0 不能归因于映射，判 INCONCLUSIVE；
4. `no-dead-counters`：`unelaborated-bound == 0`；
5. `cpu-side-observable`：CPU 的 `elaborated-lit >= --min-cpu-points`（默认 1；建议按 `--min-cpu-points 8` 设更硬的期望）；
6. `readback-integrity`：`probe-unreadable == elaboration-unknown == contradictions == 0`。

只读实测结论（证明 gate 有区分力，且不需要任何新 RTL）：
- `verify --run runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926` → 判据 1/2/3/6 PASS、4/5 FAIL、`verdict=BLOCKED`、退出码 3；
- `verify --run runs/ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926` → 判据 3 FAIL（CPU 未退休）+ 4/5 FAIL、`verdict=INCONCLUSIVE`、退出码 4。

### gate 要求、但本轮不允许实施的生产改动

> **已被第十节取代（2026-10-07 第二轮）**：下面这条生产改动**已经实施**，见第十节"生产侧修复"。本节保留为诊断当时的原始记录，不改写历史。

`src/myfuzz/integration/soc_coverage.py::coverage_observation_plan`（312-359 行）只按 bit 升序取配额，不知道实例是否被 elaborate；选择发生在编译之前，所以拿不到编译模型。最小改动：在插桩后的设计编译成功后，用第六节的探针检查观测点的实例作用域，若有缺失就**排除这些实例重新规划观测集并重建一次 testbench**；插入点在 `src/myfuzz/integration/soc_builder.py` 编译成功处（约 1769 行 `executable = build / "obj_dir" / "Vmyfuzz_live_tb"`），复用其上 1737-1768 行的端口 / `live_tb.sv` / 编译块。**不需要改 RTL、harness 或读数链路**：插桩树、`__vi_coverage` 端口与按位置读计数器的 testbench（`soc_builder.py:2753-2759`）都是正确的，问题只在"选哪 128 个"。

替代（更弱）方案：把 `coverage_observation_plan` 的 CPU 队列改成按 bit 降序或均匀抽样。它在本 cell 上也能避开死区（最高位是 `ibex_top` 自身与 `u_ibex_core`），但只是启发式，不构成"已武装"的证明，因此 gate 不以它作为判据来源。

## 八、给 root 的确切下一步命令

不改生产代码、先确认诊断（只读，可立刻跑）：

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 scripts/rtl_cpu_side_observation_diagnosis.py \
    --run runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926
PYTHONPATH=src python3 scripts/run_p4_cpu_side_branch_gate.py plan \
    --reference-run runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926
PYTHONPATH=src python3 -m pytest tests/scenario/test_rtl_cpu_side_observation_diagnosis.py \
    -q -p no:randomly
```

要真正点亮 CPU 侧：先按第七节实施生产改动，再用**产出 `runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926` 的同一条命令**（`mode=cpu_only`，CPU 才会退休）产出新 run，然后跑：

```bash
PYTHONPATH=src python3 scripts/run_p4_cpu_side_branch_gate.py verify \
    --run <new-run> --min-cpu-points 8
```

退出码 0 才算 CPU 侧可观测；3 = 仍是结构零；4 = 该 run 的 CPU 没退休，判据不成立。

## 九、声明

本轮未运行 Verilator、未运行任何真实 RTL、未运行 fuzz；所有数字来自既有 artifact 的只读复算与新增消费侧脚本。生产文件（`src/myfuzz/**`、`configs/`、`rtl/`、`third_party/`、既有 `scripts/*`）**一字未改**；本报告只新增了第一节列出的脚本与测试。

> **该声明只适用于第一轮（诊断）**。第二轮实施了生产修复并新增/修改了四个文件，见第十节；第二轮同样未运行任何 RTL。

## 十、生产侧修复（第二轮，已实施，软件 TDD；仍未运行任何 RTL）

> 本节取代第七节末尾"gate 要求、但本轮不允许实施的生产改动"。修复的目标是让"一个编译过的 run 永远不再报告一个不可能点亮的观测点"。
> **本轮同样未运行 Verilator、未运行任何真实 RTL、未运行 fuzz，不声称任何新的 RTL 覆盖。**

### 10.1 改了哪些文件

| 文件 | 状态 | 改动 |
|---|---|---|
| `src/myfuzz/elaboration_probe.py` | **新增** | 共享探针：`verilated_scope_chain`（实例路径 → Verilator 成员名前缀）、`read_compiled_model`（读并摘要 `build/obj_dir/*___024root.h`，缺失/超限/空/不可读都有具名原因）、`classify_planned_points`（每点 `elaborated` / `unelaborated_scope` / `elaboration_unknown` + reason）、`replan_observations`（排除→重规划→记录，返回 `changed` / 新 plan / elaboration 文档） |
| `src/myfuzz/integration/soc_builder.py` | 修改 | `_instrument_coverage` 额外返回原始 `bits`；新增 `_plan_observations_with_elaboration_probe`（编译 → 探针 → 重规划 → **至多一次**重建 → 重建后复探、不一致即失败）与 `_cached_observation_is_armed`（缓存必须自证已武装）；profile 与 legacy 两条构建路径都接入；`soc_coverage_plan.json` 写 `elaboration`，构建文档写 `observation_elaboration` |
| `scripts/rtl_cpu_side_observation_diagnosis.py` | 修改（新文件，非冻结） | 删除本地探针副本，改为复用共享模块（`verilated_scope_chain` 等仍从本模块 re-export，既有导入路径不变）；文档新增 `recorded_elaboration` |
| `scripts/run_p4_cpu_side_branch_gate.py` | 修改（新文件，非冻结） | 新增判据 `elaboration-attested`、`exclusions-reported`（都从 run 自带 artifact 复算，不信自述）；`plan` 输出改为"已实施 + 复核 + 真实命令 + 失败定义"；`plan`/`verify` 仍只读 |
| `tests/scenario/test_soc_observation_elaboration.py` | **新增** | 23 tests，见 10.4 |
| `tests/scenario/test_rtl_cpu_side_observation_diagnosis.py` | 未改 | 17 个既有测试在修复后仍全绿（re-export 保持兼容） |
| `src/myfuzz/integration/soc_coverage.py` | **未改** | 选择器本身无需修改：把"不可点亮"的实例从候选 `bits` 里过滤掉再调用同一个 `coverage_observation_plan` 即可完成重规划 |

未触碰：`configs/`、`rtl/`、`third_party/`、`src/myfuzz/scenario/**`、`ibex_pulp_online/scenario_rfuzz/scenario_rfuzz_live/rfuzz_fifo/ibex_uart_online`、既有 28 个 run 的任何 artifact（全部只读复算）。

### 10.2 一次全新 instrumented run 的确切行为差异（含实测的探针覆盖面）

以产出 `runs/ibex-pulp-gpio-spi-mmio-tx-rx-gpio-3600s-20260926` 的同一 cell 为例。下表数字**不是估计**：它们由 `tests/scenario/test_soc_observation_elaboration.py::test_real_run_replans_the_cpu_quota_onto_elaborated_bits` 在该 run 自带的 `instrumentation.json` + `soc_coverage_plan.json` + `obj_dir/*___024root.h` 上只读复算并逐条钉住（未编译、未运行 RTL）。

| 阶段 | 修复前 | 修复后（实测） |
|---|---|---|
| 首次观测集 | cpu 配额 = bit **621..684**（10 `i_ibex_trvk` + 54 `u_ibex_lockstep/**`），ip 配额 = bit **162..225** | 完全一样（首次计划不变） |
| 编译 | 1 次 | 第 1 次编译后探针在 `build/obj_dir/Vmyfuzz_live_tb___024root.h` 中逐点判定：首次计划 **64/128 未综合** |
| 候选集 | 3926 个 bit 全部可选 | 探针按轮次发现并排除 **65 个未综合实例**（含 `u_cpu0/i_ibex_trvk`、`u_cpu0/u_ibex_lockstep` 及其全部 shadow 子实例），共 **1716** 个候选 bit 退出候选；剩余候选 2210；IP 候选不受影响 |
| 重规划 | — | 同一 128 配额重规划。**关键实测**：Verilator 只给一部分实例生成具名作用域，较小的实例会被**内联（flatten）**，因此需要 **16 轮**迭代才能把所有"配额走进去的未综合实例"全部排除（`MAX_REPLAN_ROUNDS=64`，见 10.3）；最终 cpu 配额 = **1295 个作用域可证 CPU 点中最低的 64 个** = bit **2289..2292、2309..2336、2361..2400**（全部在 `u_cpu0/u_ibex_core/cs_registers_i/**`：`u_cpuctrlsts_part_csr`、各 `u_*csr`、`mcycle_counter_i`、`minstret_counter_i`），ip 仍为 162..225 |
| 重建 | — | **仅一次**：重写 `live_tb.sv` + `soc_coverage_plan.json` 后再编译一次，并复探第二次模型确认 128/128 均为 `elaborated`（16 轮重规划都在**同一个**编译模型上做，因为读哪些计数器不改变设计被综合的内容） |
| artifact | `plan.observed` = 死点；无任何分类信息 | `plan.elaboration`（status=`replanned`、model sha256、逐轮 rounds、`excluded` 的 **912** 条被拒观测槽逐点带 `classification=unelaborated_scope` + reason、`excluded_instances` 带 `candidate_bits`、`observations` 每点标 `elaborated`）；构建文档新增 `observation_elaboration`（含 `post_rebuild_confirmation`）；`plan.unobserved_count` 仍按全量 3926 计（3926−128=3798），并新增 `eligible_candidate_count=2210` / `excluded_candidate_count=1716` |
| CPU 侧计数 | 结构零（不可能亮） | 读的是**已证明被综合**的 CPU 实例的计数器——**能亮多少由真实 run 决定，本报告不做预测、不声称任何覆盖** |

**必须如实记录的探针覆盖面（本轮实测，修正第二节的隐含假设）**：该 cell 的 3926 个插桩点里，只有 **1916** 个的实例作用域出现在编译模型中（其中 CPU 点 **1295** 个）；其余 2010 个点的实例被 Verilator **内联展开**（`register_file_i`、`u_ibex_core/pmp_i`、`if_stage_i`、`id_stage_i`、`alu_i` …），它们的计数器**可能是活的**（属于已综合模块）但作用域探针**无法证明**，因此**一律不采纳**。这正是第二节声明的保守方向（"`absent ⇒ 不采纳`"，可能少采纳一个本可观测的点），本轮把它从定性变成了定量：第二节所说"1648 个已综合 CPU 候选点"是**按拼接位宽**得出的（`u_ibex_core` 1609 + `register_file_i` 14 + `ibex_top` 自身 24 + `core_clock_gate` 1），其中只有 1295 个能被作用域证明；修复后的 CPU 配额因此从 bit 2289 起，而不是 2260。**修复的安全性质不变**：被报告的每一个点都可证已综合；它只是不声称那些被内联的计数器。（要回收这部分点需要一个基于"子覆盖向量是否有驱动"的探针，即第二节证据 4 在全模型 `.cpp` 上的赋值检测——本轮未实施，列为后续工作。）

### 10.3 fail-closed 的选择与理由

**选择：拒绝（refuse），不是"全部标 unknown 后继续"。** 探针无法执行或输出无法解析时（模型头缺失/超限/为空/不可读），构建直接失败并给出具名原因：`<cell>:profile-coverage-elaboration-probe-failed:compiled-model-header-missing|…`；重规划后重建的模型仍缺少新观测集中某个作用域时同样失败：`…:rebuild-still-binds-unelaborated-scope:<instance@bit>`。理由：构建是这个 run 唯一能证明"计数器已武装"的地方；如果拿不到证明却仍然发布计数器向量，下游（RFuzz feedback、`report_rtl_branch_coverage.py`、gate）会把一组未证明的计数器当成 branch coverage——这正是本次要修的缺陷本身。点级无法探（实例路径没有子作用域，例如点挂在 SoC top 自身）不会被升级成构建失败，而是归为 `elaboration_unknown` 并**一并排除**、带 reason 记录，因此"已发布的观测点"始终可证。

**重规划轮数上限**：`MAX_REPLAN_ROUNDS=64`（原设计 16 在原 cell 上会被顶到，见 10.2 的 16 轮实测）。每轮至少排除一个实例、且排除集合单调增长，因此收敛性有保证；触顶仍是 fail-closed 拒绝，不会带着死点发布。

兼容性：该失败路径只在探针**真的不可用**时触发；真实构建中 Verilator 必然在 `obj_dir` 写出模型头（28/28 个既有 run 都有），所以"一切正常"的路径（10.2 的默认分支）计划不变、只编译一次，既有测试全部保持通过。

### 10.4 软件测试证明了什么（RED → GREEN）

RED（先写测试）：

```
$ cd /home/qinkejiu/myfuzz && PYTHONPATH=src python3 -m pytest \
      tests/scenario/test_soc_observation_elaboration.py -q -p no:randomly
ImportError while importing test module ...
E   ModuleNotFoundError: No module named 'myfuzz.elaboration_probe'
ERROR tests/scenario/test_soc_observation_elaboration.py
!!!!!!!!!!!!!!!!!!!! Interrupted: 1 error during collection !!!!!!!!!!!!!!!!!!!!
1 error in 0.11s
```

GREEN：

```
$ PYTHONPATH=src python3 -m pytest \
      tests/scenario/test_soc_observation_elaboration.py \
      tests/scenario/test_rtl_cpu_side_observation_diagnosis.py \
      tests/integration/test_soc_coverage.py -q -p no:randomly
53 passed in 1.46s
```

（追加真实 run 只读复算测试后为 **23 tests / 54 passed**；见下。）

`tests/scenario/test_soc_observation_elaboration.py`（23 tests，合成模型文本 + 编译回调，**不启动 Verilator/RFuzz/run**）钉住：

1. **重规划排除未综合点**：首次计划 cpu={0,1,2}（死）→ 重规划后 cpu={100,101,102}（活）、ip 不变、`observed_by_category={"cpu":3,"ip":3}`、limit 不变；
2. **每个排除都有分类与理由**：`excluded` 每行 `classification=unelaborated_scope`、`reason=instance-scope-absent-from-compiled-model`、`scope_chain` 与实例路径一致；`excluded_instances` 的 `candidate_bits` 与候选总数一致；`observations` 每行 `elaborated`；`unobserved_count` 仍按全量计（不因排除而缩水）；
3. **收敛**：第二轮才发现的死子树也会被排除（rounds=3，第 3 轮 0 排除），且**只重建一次**（编译回调被调用次数 = 2）；
4. **默认路径**：模型包含全部作用域时 `changed=False`、观测集逐元素不变、不重建（回调调用 1 次）、输入 plan 对象不被就地修改、status=`verified`、`excluded=[]`；
5. **fail-closed**：模型不可用 → `ElaborationUnavailable`；构建层 → `SocBuildError` 且消息含 `profile-coverage-elaboration-probe-failed` 与具体原因；空模型头 → `compiled-model-header-empty`；重建后的模型缺少新观测点的作用域 → `rebuild-still-binds-unelaborated-scope`；挂载在 top 自身的点 → `elaboration_unknown` + `instance-path-has-no-subtree` 且被排除；
6. **真实 cell 只读复算**：上面 10.2 的全部数字（1916/1295 作用域可证点、最终 cpu bit 集合、16 轮收敛、65 个被排除实例、每个被报告点的作用域都在模型里）都在这一个测试里被独立重算并钉住；
7. **gate 判据有区分力**：既有 run（无探针记录）`elaboration-attested=False`、`exclusions-reported=False` 且 verdict 仍 BLOCKED；合成"已记录探针"的 run 两条判据 PASS；篡改模型摘要 / 删除 reason / 改坏 candidate_bits 都会被判 FAIL。

只读复算未变：`scripts/rtl_cpu_side_observation_diagnosis.py --runs-root runs` 仍是 28 runs / 3584 points / lit 809 / unexercised 983 / **unelaborated-bound 1792** / unreadable 0 / unknown 0（与第四节逐位一致），说明探针重构没有改变对既有 artifact 的判定。

### 10.5 root 要跑的真实 RTL 命令序列与判据

**第 0 步（只读，可先跑，确认修复已就位且 gate 能区分新证据）：**

```bash
cd /home/qinkejiu/myfuzz
PYTHONPATH=src python3 -m pytest tests/scenario/test_soc_observation_elaboration.py \
    tests/scenario/test_rtl_cpu_side_observation_diagnosis.py -q -p no:randomly
PYTHONPATH=src python3 scripts/rtl_cpu_side_observation_diagnosis.py \
    --run runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926   # 旧 run：仍 exit 3
PYTHONPATH=src python3 scripts/run_p4_cpu_side_branch_gate.py plan \
    --reference-run runs/ibex-pulp-gpio-spi-cpu-gpio-write-600s-160c-20260926
```

**第 1 步（真正跑 RTL；必须用产出 CPU 会退休的 run 的同一条命令，`mode=cpu_only`）：**

```bash
MYFUZZ_SOC_REAL=1 PYTHONPATH=src:. python3 -m myfuzz compat soc run \
    --matrix configs/soc/matrix.json --output runs/<new-run> \
    --seconds 600 --seed 20260926 --client <kfuzz>
```

注意：修复后该 run 的构建会**多编译一次**（总编译 2 次；探针在第一次编译后重规划，第二次编译才固化观测集），需要给足构建时间/内存预算；不需要改任何 RTL/harness 源码。

**第 2 步（只读判定）：**

```bash
PYTHONPATH=src python3 scripts/run_p4_cpu_side_branch_gate.py verify \
    --run runs/<new-run> --min-cpu-points 8
PYTHONPATH=src python3 scripts/report_rtl_branch_coverage.py --run runs/<new-run>
PYTHONPATH=src python3 scripts/rtl_cpu_side_observation_diagnosis.py --run runs/<new-run>
PYTHONPATH=src python3 -c "import json;d=json.load(open('runs/<new-run>/build/soc_coverage_plan.json'));e=d['elaboration'];print(e['status'],e['counts']);print([r['instance_id'] for r in e['excluded'][:3]])"
```

**成功判据（gate 全部 8 条 PASS，退出码 0）**：`run-artifact`、`coverage-identity`（`status=verified` 且 `external_binding.passed=true`）、`cpu-stimulus`（RVFI opcode 至少一个 bin 非零）、`elaboration-attested`（plan 记录探针、每个被报告的点都是 `elaborated`、记录里的 model sha256 == 磁盘上的模型头）、`exclusions-reported`（每个被拒绝观测的点都有 classification+reason，`excluded_instances.candidate_bits` 与 instrumentation manifest 逐实例一致，且这些实例不再出现在 `observed`）、`no-dead-counters`（`unelaborated-bound=0`）、`cpu-side-observable`（CPU `elaborated-lit ≥ 8`）、`readback-integrity`（`probe-unreadable=elaboration-unknown=contradictions=0`）。

补充期望（人工核对，基于 10.2 的实测）：`plan.elaboration.status == "replanned"`、`counts.observed_points == counts.elaborated == 128`、`counts.refused_planned_points == counts.unelaborated_scope` 且每条 `excluded` 都有 classification+reason、`excluded_instances` 含 `u_cpu0/i_ibex_trvk` 与 `u_cpu0/u_ibex_lockstep`、新 CPU 观测位下界为 **2289**（同一 cell 应完全一致；其他 cell 会不同）。

**判据的分工（重要，避免误判）**：`no-dead-counters` + `elaboration-attested` + `exclusions-reported` 回答的是**映射问题**（"发布的计数器是否已武装"）；`cpu-side-observable ≥ 8` 回答的是**搜索质量问题**（"这些已武装的 CPU 分支里有多少真的被激励到"）。修复保证前者；后者首次跑如果没到 8，那是真实结论，可以用 `--min-cpu-points 1` 再判定映射是否已修好，但不能因此把映射问题误报成失败或反之。本 cell 的新 CPU 配额里包含 `mcycle_counter_i` / `minstret_counter_i` 的计数器分支（CPU 运行时每周期都会走到），但**本报告不对点亮数量做任何承诺**。

**失败定义（出现任意一条都算失败，不得解释为"覆盖不够"）**：

1. 构建以 `*-coverage-elaboration-probe-failed:*` 结束 → 探针无法证明计数器已武装，**什么都没发布**（fail-closed 生效，但修复未产出可用 run）；
2. `verify` 退出码 1（FAIL）→ run 发布了探针未证明的点，或 coverage identity 未通过；
3. `verify` 退出码 3（BLOCKED）→ 观测集仍绑定在未综合实例上（修复未生效）；
4. `verify` 退出码 4（INCONCLUSIVE）→ CPU 没退休或没有编译模型，该 run 不能回答这个问题（需换 `cpu_only` 且足够时长的 run），**不是 PASS**；
5. `plan.elaboration` 缺失、`status` 非法、或任一被排除点缺 classification/reason → 等于回到了"静默丢弃"，判 FAIL；
6. 新 run 的 `plan.elaboration` 缺失但 run 本身成功 → 说明走的不是本轮的构建路径（例如命中了修复前写入的 build cache），同样是失败。

### 10.6 边界（本轮不声称的东西）

- 本轮的软件证据只证明"观测集里不再有无法点亮的点、排除被显式记录、探针不可用时构建拒绝"；**不证明 CPU 侧能亮多少**，也不声称任何新的 RTL 覆盖。
- 探针方向性不变（见第二节），且本轮已定量：该 cell 3926 个点里只有 1916 个（CPU 1295）能被作用域证明，其余被 Verilator 内联的实例一律不采纳（保守方向）。要回收这部分点需要"子覆盖向量是否有驱动"的探针（扫描生成的 `.cpp` 赋值），本轮未实施。
- 修复只改"观测哪些 bit"与"如何记录拒绝"，不改插桩树、`__vi_coverage` 端口、按位置读计数器的 testbench、RFuzz ABI 或任何 RTL；因此 `report_rtl_branch_coverage.py` 的 identity 校验口径不变（`branch_coverage_ports` 仍是 `coverage_ports` 的前缀且位宽合法）。
- 其他 cell / 其他 CPU（cva6、cv32e40p、zipcpu）是否有同类"低位落在未综合分支"问题仍未逐一复算；修复对它们是通用的（同一构建路径 + 同一探针），但需要各自的真实 run 才能给出数字。
